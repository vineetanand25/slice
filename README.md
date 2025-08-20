# Slice: SAST + LLM Interprocedural Context Extractor

### Built with

- CodeQL
- Tree-Sitter
- OpenAI API

## Getting started

### Prerequisites

Only tested on Ubuntu 24.04.2 LTS.

### Install

```
go install github.com/noperator/slice/cmd/slice@latest
```

### Configure

Install CodeQL CLI, install pack, and build database.

```
codeql pack install
codeql database create <DB_NAME> \
    --language=cpp \
    --source-root=<SRC_DIR> \
    --build-mode=none
```

### Usage

```
$ slice -h
Slice: SAST + LLM Interprocedural Context Extractor
Uses CodeQL, Tree-Sitter, and LLMs to discover vulnerabilities across complex call graphs.
Intended flow is query -> filter -> rank.

Available Commands:
  parse       Parse code and extract function information
  query       Run CodeQL queries and enrich results with source code
  filter      Filter CodeQL vulnerability results using LLM processing
  rank        Rank validated vulnerability findings by criticality

$ slice parse -h
Parse source code in the specified directory and extract detailed function information
including signatures, parameters, variables, function calls, and definitions.

Usage:
  slice parse <directory>


$ slice parse -h
Run CodeQL queries against a database and enrich the vulnerability findings
with full source code context using TreeSitter parsing.

This command integrates CodeQL-based vulnerability detection with the existing
TreeSitter parsing infrastructure to provide comprehensive vulnerability reports.

Flags:
  -c, --call-depth int      Maximum call chain depth (-1 = no limit) (default -1)
  -b, --codeql-bin string   Path to CodeQL CLI binary (default: resolve from PATH)
  -j, --concurrency int     Number of concurrent workers for result processing (0 = auto-detect based on CPU cores)
  -d, --database string     Path to CodeQL database (required)
      --no-validate         Disable call chain validation
  -q, --query string        Path to CodeQL query file (.ql) (required)
  -s, --source string       Path to source code directory (required)


$ slice filter -h
Filter CodeQL vulnerability detection results using a Large Language Model.

This command processes vulnerability findings using a template-driven approach.
The template determines the behavior, output structure, and processing parameters.

By default, only valid/vulnerable results are output.

Flags:
  -a, --all                       Output all results regardless of validity (default: only output valid/vulnerable results)
  -b, --base-url string           Base URL for OpenAI-compatible API (optional, or set OPENAI_API_BASE env var)
  -j, --concurrency int           Number of concurrent LLM API calls (default 10)
  -t, --max-tokens int            Maximum tokens in response (default 64000)
  -m, --model string              Model to use (or set OPENAI_API_MODEL env var) (default "gpt-4")
  -p, --prompt-template string    Path to custom prompt template file (optional)
  -r, --reasoning-effort string   Reasoning effort for GPT-5 models: minimal, low, medium, high (default "high")
      --temperature float32       Temperature for response generation (default 0.1)
      --timeout int               Timeout in seconds (adjusted automatically based on template type) (default 300)


$ slice rank -h
Rank validated vulnerability findings using LLM-based comparative ranking.

The ranking is performed using the raink library, which uses listwise comparisons
to establish relative rankings of findings.

Flags:
  -s, --batch-size int   Batch size for ranking (default 10)
  -i, --input string     Input file containing processed results (if not provided, reads from stdin)
  -m, --model string     Model to use for ranking (default "gpt-4")
  -p, --prompt string    Path to ranking prompt file (default "spec/uaf/rank.tmpl")
      --ratio float      Refinement ratio (default 0.5)
  -r, --runs int         Number of ranking runs (default 10)
```

## Back matter

### Legal disclaimer

Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

### See also

- https://noperator.dev/posts/slice

### License

This project is licensed under the [MIT License](LICENSE).
