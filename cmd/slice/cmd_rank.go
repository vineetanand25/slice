package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/noperator/raink/pkg/raink"
	"github.com/noperator/slice/pkg/llm"
	"github.com/openai/openai-go"
)

var (
	rankInputFile   string
	rankPromptFile  string
	rankModel       string
	rankRuns        int
	rankBatchSize   int
	rankRatio       float64
)


func formatResultForRanking(result llm.UnifiedResult) string {
	var parts []string
	
	if result.CodeQLResult.FreeFunctionFile != "" && result.CodeQLResult.FreeLine > 0 {
		parts = append(parts, fmt.Sprintf("File: %s:%d", result.CodeQLResult.FreeFunctionFile, result.CodeQLResult.FreeLine))
	}
	
	for key, dynamicResult := range result.DynamicResults {
		if resultMap, ok := dynamicResult.(map[string]interface{}); ok {
			if validValue, hasValid := resultMap["valid"]; hasValid {
				if validBool, ok := validValue.(bool); ok {
					parts = append(parts, fmt.Sprintf("%s_valid: %s", key, getVerdictStatus(validBool)))
				}
			}
			if summary, hasSummary := resultMap["summary"]; hasSummary {
				if summaryStr, ok := summary.(string); ok && summaryStr != "" {
					parts = append(parts, fmt.Sprintf("%s_summary: %s", key, summaryStr))
				}
			}
			if reasoning, hasReasoning := resultMap["reasoning"]; hasReasoning {
				if reasoningStr, ok := reasoning.(string); ok && reasoningStr != "" {
					parts = append(parts, fmt.Sprintf("%s_reasoning: %s", key, reasoningStr))
				}
			}
		}
	}
	
	return strings.Join(parts, " | ")
}

func getVerdictStatus(isVulnerable bool) string {
	if isVulnerable {
		return "vulnerable"
	}
	return "not vulnerable"
}

var rankCmd = &cobra.Command{
	Use:   "rank [flags]",
	Short: "Rank validated vulnerability findings by criticality",
	Long: `Rank validated vulnerability findings using LLM-based comparative ranking.

This command takes vulnerability processing results and ranks them based on factors like:
- Likelihood/confidence of being a true positive
- Exploitability and attack complexity
- Impact if successfully exploited  
- Whether the vulnerability is in a critical code path

The ranking is performed using the raink library, which uses pairwise comparisons
to establish relative rankings of findings.

Examples:
  # Rank filtered results using default UAF ranking prompt
  slice filter -i query.json -p spec/uaf/custom.tmpl | slice rank -p spec/uaf/rank.tmpl

  # Rank with custom parameters  
  slice rank -i filtered.json -m gpt-4o -r 20 -s 5 --ratio 0.7`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var decoder *json.Decoder
		if rankInputFile == "" {
			decoder = json.NewDecoder(os.Stdin)
		} else {
			file, err := os.Open(rankInputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer file.Close()
			decoder = json.NewDecoder(file)
		}
		var inputResults llm.UnifiedOutput
		if err := decoder.Decode(&inputResults); err != nil {
			return fmt.Errorf("failed to decode input JSON: %w", err)
		}

		if len(inputResults.Results) == 0 {
			return fmt.Errorf("no results to rank")
		}

		promptBytes, err := os.ReadFile(rankPromptFile)
		if err != nil {
			return fmt.Errorf("failed to read prompt file: %w", err)
		}
		prompt := strings.TrimSpace(string(promptBytes))

		items := make([]string, len(inputResults.Results))
		for i, result := range inputResults.Results {
			items[i] = formatResultForRanking(result)
		}

		analyzerConfig := llm.Config{
			APIKey:          "",
			BaseURL:         "",
			Model:           rankModel,
			Temperature:     0.1,
			MaxTokens:       8000,
			ReasoningEffort: "medium",
		}

		pipeline := &llm.Pipeline{}
		if err := pipeline.LoadEnvironmentConfig(&analyzerConfig); err != nil {
			return fmt.Errorf("failed to load environment config: %w", err)
		}

		config := &raink.Config{
			InitialPrompt:   prompt,
			BatchSize:       rankBatchSize,
			NumRuns:         rankRuns,
			OpenAIModel:     openai.ChatModel(analyzerConfig.Model),
			TokenLimit:      analyzerConfig.MaxTokens,
			RefinementRatio: rankRatio,
			OpenAIKey:       analyzerConfig.APIKey,
			OpenAIAPIURL:    analyzerConfig.BaseURL,
			Encoding:        "o200k_base", 
			BatchTokens:     analyzerConfig.MaxTokens,
		}

		ranker, err := raink.NewRanker(config)
		if err != nil {
			return fmt.Errorf("failed to create ranker: %w", err)
		}

		objects := make([]map[string]interface{}, len(items))
		jsonToIndex := make(map[string]int)
		for i, item := range items {
			objects[i] = map[string]interface{}{
				"id":    fmt.Sprintf("result_%d", i),
				"value": item,
			}
			jsonBytes, _ := json.Marshal(objects[i])
			marshaledContent := string(jsonBytes)
			jsonToIndex[marshaledContent] = i
			_ = raink.ShortDeterministicID(marshaledContent, 8)
		}

		tempFile, err := os.CreateTemp("", "rank_*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tempFile.Name())
		defer tempFile.Close()

		tempEncoder := json.NewEncoder(tempFile)
		if err := tempEncoder.Encode(objects); err != nil {
			return fmt.Errorf("failed to write temp file: %w", err)
		}
		tempFile.Close()

		results, err := ranker.RankFromFile(tempFile.Name(), "", true)
		if err != nil {
			return fmt.Errorf("ranking failed: %w", err)
		}


		indexToRankInfo := make(map[int]llm.RankInfo)
		for pos, result := range results {
			for jsonContent, index := range jsonToIndex {
				expectedID := raink.ShortDeterministicID(jsonContent, 8)
				if expectedID == result.Key {
					indexToRankInfo[index] = llm.RankInfo{
						Score:    result.Score,
						Exposure: result.Exposure,
						Pos:      pos + 1, // 1-based ranking (1 = highest priority)
					}
					break
				}
			}
		}

		matchedCount := 0
		for i := range inputResults.Results {
			if rankInfo, exists := indexToRankInfo[i]; exists {
				inputResults.Results[i].Rank = &rankInfo
				matchedCount++
			}
		}

		sort.Slice(inputResults.Results, func(i, j int) bool {
			if inputResults.Results[i].Rank == nil {
				return false
			}
			if inputResults.Results[j].Rank == nil {
				return true
			}
			return inputResults.Results[i].Rank.Pos < inputResults.Results[j].Rank.Pos
		})

		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(inputResults); err != nil {
			return fmt.Errorf("failed to encode output JSON: %w", err)
		}

		return nil
	},
}

func init() {
	rankCmd.Flags().StringVarP(&rankInputFile, "input", "i", "", "Input file containing processed results (if not provided, reads from stdin)")
	rankCmd.Flags().StringVarP(&rankModel, "model", "m", "gpt-4", "Model to use for ranking")
	rankCmd.Flags().StringVarP(&rankPromptFile, "prompt", "p", "spec/uaf/rank.tmpl", "Path to ranking prompt file")
	rankCmd.Flags().IntVarP(&rankRuns, "runs", "r", 10, "Number of ranking runs")
	rankCmd.Flags().IntVarP(&rankBatchSize, "batch-size", "s", 10, "Batch size for ranking")
	rankCmd.Flags().Float64Var(&rankRatio, "ratio", 0.5, "Refinement ratio")

	rootCmd.AddCommand(rankCmd)
}