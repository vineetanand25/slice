package main

import (
	"encoding/json"
	"fmt"

	"github.com/noperator/slice/pkg/parser"
	"github.com/spf13/cobra"
)

var parseCmd = &cobra.Command{
	Use:   "parse <directory>",
	Short: "Parse code and extract function information",
	Long: `Parse source code in the specified directory and extract detailed function information
including signatures, parameters, variables, function calls, and definitions.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		directory := args[0]

		result, err := parser.GetCachedAnalysisResult(directory)
		if err != nil {
			return fmt.Errorf("failed to analyze directory: %w", err)
		}

		output, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Println(string(output))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(parseCmd)
}
