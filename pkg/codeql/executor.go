package codeql

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Executor struct {
	CodeQLBin string
}

func NewExecutor(codeqlBin string) (*Executor, error) {
	if codeqlBin == "" {
		var err error
		codeqlBin, err = exec.LookPath("codeql")
		if err != nil {
			return nil, fmt.Errorf("codeql binary not found in PATH: %w", err)
		}
	}
	
	if _, err := os.Stat(codeqlBin); os.IsNotExist(err) {
		return nil, fmt.Errorf("codeql binary not found at path: %s", codeqlBin)
	}
	
	return &Executor{
		CodeQLBin: codeqlBin,
	}, nil
}

func (e *Executor) RunQuery(database, query string) ([]CodeQLResult, error) {
	if _, err := os.Stat(database); os.IsNotExist(err) {
		return nil, fmt.Errorf("database not found: %s", database)
	}
	
	if _, err := os.Stat(query); os.IsNotExist(err) {
		return nil, fmt.Errorf("query file not found: %s", query)
	}
	
	tempBQRS, err := e.createTempBQRSFile()
	if err != nil {
		return nil, fmt.Errorf("failed to create temp BQRS file: %w", err)
	}
	defer os.Remove(tempBQRS)
	
	if err := e.runCodeQLQuery(database, query, tempBQRS); err != nil {
		return nil, fmt.Errorf("failed to run CodeQL query: %w", err)
	}
	
	results, err := e.decodeBQRSToCSV(tempBQRS)
	if err != nil {
		return nil, fmt.Errorf("failed to decode BQRS results: %w", err)
	}
	
	return results, nil
}

func (e *Executor) createTempBQRSFile() (string, error) {
	timestamp := time.Now().Unix()
	tempFile := fmt.Sprintf("%d.bqrs", timestamp)
	return tempFile, nil
}

func (e *Executor) runCodeQLQuery(database, query, outputBQRS string) error {
	cmd := exec.Command(e.CodeQLBin, "query", "run", 
		fmt.Sprintf("--database=%s", database),
		fmt.Sprintf("--output=%s", outputBQRS),
		query)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codeql query run failed: %w\nOutput: %s", err, string(output))
	}
	
	return nil
}

func (e *Executor) decodeBQRSToCSV(bqrsFile string) ([]CodeQLResult, error) {
	cmd := exec.Command(e.CodeQLBin, "bqrs", "decode", "--format=csv", bqrsFile)
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("codeql bqrs decode failed: %w", err)
	}
	
	return e.parseCSVOutput(string(output))
}

func (e *Executor) parseCSVOutput(csvData string) ([]CodeQLResult, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}
	
	if len(records) == 0 {
		return []CodeQLResult{}, nil
	}
	
	header := records[0]
	headerMap := make(map[string]int)
	for i, col := range header {
		headerMap[col] = i
	}
	
	requiredFields := []string{"object", "free_func", "free_file", "free_func_def_ln", "free_ln", 
		"use_func", "use_file", "use_func_def_ln", "use_ln"}
	
	for _, field := range requiredFields {
		if _, exists := headerMap[field]; !exists {
			return nil, fmt.Errorf("required field '%s' not found in CSV header", field)
		}
	}
	
	var results []CodeQLResult
	for i := 1; i < len(records); i++ {
		record := records[i]
		
		ffDefLine, err := strconv.Atoi(record[headerMap["free_func_def_ln"]])
		if err != nil {
			return nil, fmt.Errorf("invalid ffDefLine value: %s", record[headerMap["free_func_def_ln"]])
		}
		
		freeLine, err := strconv.Atoi(record[headerMap["free_ln"]])
		if err != nil {
			return nil, fmt.Errorf("invalid freeLine value: %s", record[headerMap["free_ln"]])
		}
		
		fuDefLine, err := strconv.Atoi(record[headerMap["use_func_def_ln"]])
		if err != nil {
			return nil, fmt.Errorf("invalid fuDefLine value: %s", record[headerMap["use_func_def_ln"]])
		}
		
		useLine, err := strconv.Atoi(record[headerMap["use_ln"]])
		if err != nil {
			return nil, fmt.Errorf("invalid use_ln value: %s", record[headerMap["use_ln"]])
		}
		
		result := CodeQLResult{
			ObjName:   record[headerMap["object"]],
			FreeFunctionName:    record[headerMap["free_func"]],
			FreeFunctionFile:    record[headerMap["free_file"]],
			FreeFunctionDefLine: ffDefLine,
			FreeLine:  freeLine,
			UseFunctionName:    record[headerMap["use_func"]],
			UseFunctionFile:    record[headerMap["use_file"]],
			UseFunctionDefLine: fuDefLine,
			UseLine:   useLine,
		}
		
		results = append(results, result)
	}
	
	return results, nil
}

func (e *Executor) CheckCodeQLAvailable() error {
	cmd := exec.Command(e.CodeQLBin, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("codeql command failed: %w", err)
	}
	return nil
}