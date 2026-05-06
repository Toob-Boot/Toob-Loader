package abi

import (
	"testing"
)

func TestDetermineBump(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		expected BumpType
	}{
		{
			name:     "Perfect Match (0)",
			exitCode: 0,
			expected: BumpPatch,
		},
		{
			name:     "Error Invoking Tool (1)",
			exitCode: 1,
			expected: Error,
		},
		{
			name:     "Usage Error (2)",
			exitCode: 2,
			expected: Error,
		},
		{
			name:     "Minor ABI Addition (4)",
			exitCode: 4,
			expected: BumpMinor,
		},
		{
			name:     "Incompatible Break (8)",
			exitCode: 8,
			expected: BumpMajor,
		},
		{
			name:     "Incompatible Break + Additions (12)",
			exitCode: 12, // 8 | 4
			expected: BumpMajor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineBump(tt.exitCode)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for exit code %d", tt.expected, result, tt.exitCode)
			}
		})
	}
}
