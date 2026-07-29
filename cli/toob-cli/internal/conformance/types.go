package conformance

import "time"

// ConformanceReport represents the outcome of a HAL conformance audit.
type ConformanceReport struct {
	Timestamp       time.Time             `json:"timestamp"`
	PackageName     string                `json:"package_name"`
	PackagePath     string                `json:"package_path"`
	Trait           string                `json:"trait"`
	AbiVersion      string                `json:"abi_version"`
	Passed          bool                  `json:"passed"`
	Checks          []ConformanceCheck    `json:"checks"`
	MockEquivalence *MockEquivalenceCheck `json:"mock_equivalence,omitempty"`
}

// ConformanceCheck represents an individual trait contract check.
type ConformanceCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// MockEquivalenceCheck captures Mock vs. Real implementation parity.
type MockEquivalenceCheck struct {
	Passed      bool     `json:"passed"`
	Divergences []string `json:"divergences,omitempty"`
}
