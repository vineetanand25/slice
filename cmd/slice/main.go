package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "slice",
	Short: "SAST + LLM Interprocedural Context Extractor",
	Long: `Slice: SAST + LLM Interprocedural Context Extractor
Uses CodeQL, Tree-Sitter, and LLMs to discover vulnerabilities across complex call graphs.
Intended flow is query -> filter -> rank.`,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
