package llm

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReadUnifiedResultsFromFile reads UnifiedOutput from a JSON file
func ReadUnifiedResultsFromFile(filename string) (*UnifiedOutput, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var results UnifiedOutput
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to parse UnifiedOutput from %s: %w", filename, err)
	}

	return &results, nil
}

// ReadUnifiedResultsFromStdin reads UnifiedOutput from stdin
func ReadUnifiedResultsFromStdin() (*UnifiedOutput, error) {
	var results UnifiedOutput
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to parse UnifiedOutput from stdin: %w", err)
	}

	return &results, nil
}

// WriteUnifiedResultsToFile writes UnifiedOutput to a JSON file
func WriteUnifiedResultsToFile(results *UnifiedOutput, filename string) error {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal UnifiedOutput: %w", err)
	}

	if err := os.WriteFile(filename, output, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}

// WriteUnifiedResultsToStdout writes UnifiedOutput to stdout
func WriteUnifiedResultsToStdout(results *UnifiedOutput) error {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal UnifiedOutput: %w", err)
	}

	fmt.Println(string(output))
	return nil
}