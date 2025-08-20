package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_c "github.com/tree-sitter/tree-sitter-c/bindings/go"
)

type Variable struct {
	Name   string `json:"name"`
	Origin string `json:"origin"`
	Type   string `json:"type"`
}

type Callee struct {
	Name    string   `json:"name"`
	Args    []string `json:"args"`
	Line    int      `json:"line"`
	Snippet string   `json:"snippet"`
}

type Parameter struct {
	Snippet string `json:"snippet"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

type Function struct {
	ID                            string      `json:"id"`
	Filename                      string      `json:"file"`
	Name                          string      `json:"name"`
	StartLine                     int         `json:"start"`
	EndLine                       int         `json:"end"`
	Signature                     string      `json:"sig"`
	Definition                    string      `json:"def"`
	DefinitionWithLineNumbers     string      `json:"def_ln"`
	Length                        int         `json:"len"`
	Params                        []Parameter `json:"params"`
	Callees                       []Callee    `json:"callees"`
	Vars                          []Variable  `json:"vars"`
}


type AnalysisResult struct {
	Functions []Function `json:"functions"`
}


func analyzeDirectory(dir string) (*AnalysisResult, error) {
	result := &AnalysisResult{Functions: []Function{}}
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if strings.HasSuffix(path, ".c") || strings.HasSuffix(path, ".h") {
			functions, err := analyzeCFile(path)
			if err != nil {
				return nil
			}
			result.Functions = append(result.Functions, functions...)
		}
		
		return nil
	})
	
	return result, err
}

func analyzeCFile(filename string) ([]Function, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	parser := sitter.NewParser()
	language := sitter.NewLanguage(tree_sitter_c.Language())
	err = parser.SetLanguage(language)
	if err != nil {
		return nil, err
	}
	
	tree := parser.Parse(content, nil)
	if tree == nil {
		return nil, fmt.Errorf("failed to parse file: %s", filename)
	}
	
	root := tree.RootNode()
	var functions []Function
	
	functions = append(functions, findFunctionDefinitions(root, content, filename)...)
	
	return functions, nil
}

func findFunctionDefinitions(node *sitter.Node, content []byte, filename string) []Function {
	var functions []Function
	
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Kind() == "function_definition" {
			function := analyzeFunctionDefinition(child, content, filename)
			if function != nil {
				functions = append(functions, *function)
			}
		}
		functions = append(functions, findFunctionDefinitions(child, content, filename)...)
	}
	
	return functions
}

func analyzeFunctionDefinition(node *sitter.Node, content []byte, filename string) *Function {
	startPoint := node.StartPosition()
	endPoint := node.EndPosition()
	
	defText := getNodeText(node, content)
	function := &Function{
		Filename:  filename,
		StartLine: int(startPoint.Row) + 1,
		EndLine:   int(endPoint.Row) + 1,
		Definition:                    defText,
		DefinitionWithLineNumbers:     addLineNumbers(defText, int(startPoint.Row)+1),
		Length:                        len(defText),
		Params:    []Parameter{},
		Callees:   []Callee{},
		Vars:      []Variable{},
	}
	
	// Extract function signature and parameters
	declarator := findChildByType(node, "function_declarator")
	if declarator == nil {
		return nil
	}
	
	// Get function name
	identifier := findChildByType(declarator, "identifier")
	if identifier != nil {
		functionName := getNodeText(identifier, content)
		function.Name = functionName
		
		// Generate function ID: <file>:<startline>:<funcname>
		function.ID = fmt.Sprintf("%s:%d:%s", filename, function.StartLine, functionName)
		
		// Build signature - get return type
		returnType := ""
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.Kind() != "function_declarator" && child.Kind() != "compound_statement" {
				returnType += getNodeText(child, content) + " "
			} else if child.Kind() == "function_declarator" {
				break
			}
		}
		
		// Get parameters
		paramList := findChildByType(declarator, "parameter_list")
		if paramList != nil {
			function.Params = extractParameters(paramList, content)
		}
		
		// Build full signature
		var paramStrings []string
		for _, param := range function.Params {
			paramStrings = append(paramStrings, param.Snippet)
		}
		function.Signature = strings.TrimSpace(returnType) + " " + functionName + "(" + strings.Join(paramStrings, ", ") + ")"
	}
	
	// Find function body
	body := findChildByType(node, "compound_statement")
	if body != nil {
		// Extract function calls
		function.Callees = findFunctionCalls(body, content)
		
		// Extract variables
		function.Vars = findVariables(body, content, function.Params)
	}
	
	return function
}

func findChildByType(node *sitter.Node, nodeType string) *sitter.Node {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Kind() == nodeType {
			return child
		}
	}
	return nil
}

func getNodeText(node *sitter.Node, content []byte) string {
	startByte := node.StartByte()
	endByte := node.EndByte()
	return string(content[startByte:endByte])
}

func extractParameters(paramList *sitter.Node, content []byte) []Parameter {
	var params []Parameter
	
	for i := uint(0); i < paramList.ChildCount(); i++ {
		child := paramList.Child(i)
		if child.Kind() == "parameter_declaration" {
			paramText := getNodeText(child, content)
			paramText = strings.TrimSpace(paramText)
			
			// Parse the parameter into components
			param := parseParameterDeclaration(paramText)
			if param != nil {
				params = append(params, *param)
			}
		}
	}
	
	return params
}

func parseParameterDeclaration(paramText string) *Parameter {
	if paramText == "" {
		return nil
	}
	
	// Split the parameter text into words
	words := strings.Fields(paramText)
	if len(words) == 0 {
		return nil
	}
	
	// The last word (possibly with * prefix) is the variable name
	lastWord := words[len(words)-1]
	
	// Extract the variable name by removing pointer indicators
	varName := strings.TrimLeft(lastWord, "*&")
	
	// The type is everything except the variable name
	var typeWords []string
	if len(words) > 1 {
		typeWords = words[:len(words)-1]
		
		// If the last word had pointer indicators, add them to the type
		if strings.HasPrefix(lastWord, "*") || strings.HasPrefix(lastWord, "&") {
			starCount := 0
			ampCount := 0
			for _, char := range lastWord {
				if char == '*' {
					starCount++
				} else if char == '&' {
					ampCount++
				} else {
					break
				}
			}
			
			if starCount > 0 {
				typeWords = append(typeWords, strings.Repeat("*", starCount))
			}
			if ampCount > 0 {
				typeWords = append(typeWords, strings.Repeat("&", ampCount))
			}
		}
	} else {
		// Single word parameter - treat as just the type
		typeWords = []string{lastWord}
		varName = ""
	}
	
	paramType := strings.Join(typeWords, " ")
	
	return &Parameter{
		Snippet: paramText,
		Name:    varName,
		Type:    strings.TrimSpace(paramType),
	}
}

func findFunctionCalls(node *sitter.Node, content []byte) []Callee {
	var callees []Callee
	
	// Recursively search for function calls
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Kind() == "call_expression" {
			callee := analyzeFunctionCall(child, content)
			if callee != nil {
				callees = append(callees, *callee)
			}
		}
		// Recurse into child nodes
		callees = append(callees, findFunctionCalls(child, content)...)
	}
	
	return callees
}

func analyzeFunctionCall(node *sitter.Node, content []byte) *Callee {
	// Get function name
	functionNode := node.Child(0)
	if functionNode == nil {
		return nil
	}
	
	functionName := getNodeText(functionNode, content)
	lineNum := int(node.StartPosition().Row) + 1
	
	// Get arguments
	var args []string
	argList := findChildByType(node, "argument_list")
	if argList != nil {
		for i := uint(0); i < argList.ChildCount(); i++ {
			child := argList.Child(i)
			if child.Kind() != "," && child.Kind() != "(" && child.Kind() != ")" {
				argText := getNodeText(child, content)
				args = append(args, strings.TrimSpace(argText))
			}
		}
	}
	
	// Try to get the full statement by looking at parent context
	// Walk up the tree to find the statement containing this call
	snippet := getNodeText(node, content) // Default to just the call expression
	
	// Try to find the parent statement node
	parent := node.Parent()
	for parent != nil {
		parentKind := parent.Kind()
		if parentKind == "expression_statement" || 
		   parentKind == "assignment_expression" ||
		   parentKind == "declaration" ||
		   parentKind == "init_declarator" ||
		   parentKind == "return_statement" ||
		   parentKind == "if_statement" ||
		   parentKind == "while_statement" ||
		   parentKind == "for_statement" {
			// Found a statement context - use its text
			snippet = strings.TrimSpace(getNodeText(parent, content))
			break
		}
		parent = parent.Parent()
	}
	
	return &Callee{
		Name:    functionName,
		Args:    args,
		Line:    lineNum,
		Snippet: snippet,
	}
}

func findVariables(node *sitter.Node, content []byte, params []Parameter) []Variable {
	varMap := make(map[string]*Variable)
	
	// Add function parameters as variables
	for _, param := range params {
		if param.Name != "" {
			varMap[param.Name] = &Variable{
				Name:   param.Name,
				Origin: "param",
				Type:   param.Type,
			}
		}
	}
	
	// Find basic local variable declarations
	findLocalVariableDeclarations(node, content, varMap)
	
	// Convert map to slice
	var variables []Variable
	for _, v := range varMap {
		variables = append(variables, *v)
	}
	
	return variables
}

// findLocalVariableDeclarations finds basic local variable declarations
func findLocalVariableDeclarations(node *sitter.Node, content []byte, varMap map[string]*Variable) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		
		if child.Kind() == "declaration" {
			// Extract basic variable declarations without complex analysis
			extractBasicVariableDeclaration(child, content, varMap)
		}
		
		// Recurse into child nodes
		findLocalVariableDeclarations(child, content, varMap)
	}
}

// extractBasicVariableDeclaration extracts simple variable declarations
func extractBasicVariableDeclaration(node *sitter.Node, content []byte, varMap map[string]*Variable) {
	var typeParts []string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Kind() == "primitive_type" || child.Kind() == "type_identifier" || 
		   child.Kind() == "struct_specifier" || child.Kind() == "storage_class_specifier" {
			typeParts = append(typeParts, getNodeText(child, content))
		}
	}
	
	declarationType := "unknown"
	if len(typeParts) > 0 {
		declarationType = strings.Join(typeParts, " ")
	}
	
	// Find declarators
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.Kind() == "init_declarator" || child.Kind() == "identifier" {
			varName := ""
			if child.Kind() == "identifier" {
				varName = getNodeText(child, content)
			} else {
				// init_declarator - find the identifier
				identifier := findChildByType(child, "identifier")
				if identifier != nil {
					varName = getNodeText(identifier, content)
				}
			}
			
			if varName != "" && varMap[varName] == nil {
				varMap[varName] = &Variable{
					Name:   varName,
					Origin: "local",
					Type:   declarationType,
				}
			}
		}
	}
}



// addLineNumbers adds right-aligned, zero-padded line numbers to each line of text
// Format: "NNNNN  CCC..." where N is the line number (5 digits, space-padded), followed by two spaces, followed by code
func addLineNumbers(text string, startLine int) string {
	lines := strings.Split(text, "\n")
	var result strings.Builder
	
	for i, line := range lines {
		lineNum := startLine + i
		// Format line number as right-aligned, space-padded 5-digit number
		result.WriteString(fmt.Sprintf("%5d  %s", lineNum, line))
		
		// Add newline except for the last line (to preserve original text structure)
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}
	
	return result.String()
}

// Simple cache for parsed analysis results
var (
	cache      = make(map[string]*AnalysisResult)
	cacheMutex sync.RWMutex
)

// GetCachedAnalysisResult returns cached analysis result for a directory, parsing if needed
func GetCachedAnalysisResult(directory string) (*AnalysisResult, error) {
	cacheMutex.RLock()
	if result, exists := cache[directory]; exists {
		cacheMutex.RUnlock()
		return result, nil
	}
	cacheMutex.RUnlock()

	// Parse the directory
	result, err := analyzeDirectory(directory)
	if err != nil {
		return nil, err
	}
	
	// Cache the results
	cacheMutex.Lock()
	cache[directory] = result
	cacheMutex.Unlock()
	
	return result, nil
}


// FindFunctionByID finds a function by its ID in cached results
func FindFunctionByID(directory, functionID string) (*Function, error) {
	result, err := GetCachedAnalysisResult(directory)
	if err != nil {
		return nil, err
	}
	
	for i := range result.Functions {
		if result.Functions[i].ID == functionID {
			return &result.Functions[i], nil
		}
	}
	
	return nil, fmt.Errorf("function not found: %s", functionID)
}


