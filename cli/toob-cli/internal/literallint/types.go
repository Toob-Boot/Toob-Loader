package literallint

import "time"

// LintReport captures the full outcome of a literal-ban lint scan.
type LintReport struct {
	Timestamp  time.Time       `json:"timestamp"`
	Paths      []string        `json:"paths"`
	Mode       string          `json:"mode"` // "regex" or "hybrid"
	Passed     bool            `json:"passed"`
	Violations []LintViolation `json:"violations"`
	Stats      LintStats       `json:"stats"`
}

// LintViolation represents a single banned numeric literal finding.
type LintViolation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Literal string `json:"literal"`
	Context string `json:"context"` // Full source line for human review
	Source  string `json:"source"`  // "regex" or "clang-query"
}

// LintStats summarises the scan scope and outcome.
type LintStats struct {
	FilesScanned int `json:"files_scanned"`
	LinesScanned int `json:"lines_scanned"`
	Violations   int `json:"violations"`
	Suppressed   int `json:"suppressed"`
}

// LintConfig controls the scanner behaviour.
type LintConfig struct {
	Paths        []string // Root directories to scan
	Extensions   []string // File extensions to include (default: .c, .h)
	IncludePaths []string // Header search paths for clang-query deep mode
	DeepMode     bool     // Enable clang-query AST analysis
}

// DefaultConfig returns a LintConfig for scanning the given paths
// with the standard C/H extension set.
func DefaultConfig(paths ...string) LintConfig {
	return LintConfig{
		Paths:      paths,
		Extensions: []string{".c", ".h"},
	}
}
