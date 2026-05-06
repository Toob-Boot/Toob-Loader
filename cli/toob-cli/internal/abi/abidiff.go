package abi

import (
	"bytes"
	"fmt"
	"os/exec"
)

// BumpType represents the semantic versioning bump recommendation.
type BumpType string

const (
	BumpMajor BumpType = "MAJOR"
	BumpMinor BumpType = "MINOR"
	BumpPatch BumpType = "PATCH"
	BumpNone  BumpType = "NONE"
	Error     BumpType = "ERROR"
)

// DiffResult holds the outcome of an abidiff operation.
type DiffResult struct {
	BumpType    BumpType
	Report      string
	IsSupported bool
}

// CheckDependencies verifies if libabigail (abidiff, abidw) is installed on the system.
func CheckDependencies() error {
	_, err := exec.LookPath("abidiff")
	if err != nil {
		return fmt.Errorf("abidiff not found in PATH. Please install libabigail (e.g., 'sudo apt-get install libabigail-tools')")
	}
	_, err = exec.LookPath("abidw")
	if err != nil {
		return fmt.Errorf("abidw not found in PATH. Please install libabigail")
	}
	return nil
}

// Compare uses abidiff to compare two ELF or XML baseline files.
func Compare(oldFile, newFile string) (*DiffResult, error) {
	cmd := exec.Command("abidiff", oldFile, newFile)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	
	res := &DiffResult{
		Report:      stdout.String(),
		IsSupported: true,
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode := exitError.ExitCode()
			res.BumpType = determineBump(exitCode)
			
			// If stderr contains content, it might be an invocation error rather than ABI diff
			if exitCode >= 128 || stderr.Len() > 0 {
				if stderr.Len() > 0 {
					return nil, fmt.Errorf("abidiff execution error (code %d): %s", exitCode, stderr.String())
				}
			}
			return res, nil
		}
		return nil, fmt.Errorf("failed to run abidiff: %w", err)
	}

	// Exit code 0 means perfect ABI compatibility (PATCH or NONE)
	res.BumpType = BumpPatch
	return res, nil
}

// GenerateBaseline uses abidw to generate an XML baseline representation of an ELF file.
func GenerateBaseline(binaryFile, outputFile string) error {
	cmd := exec.Command("abidw", binaryFile, "--out-file", outputFile)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to generate ABI baseline (abidw): %w\n%s", err, stderr.String())
	}
	return nil
}

// determineBump translates abidiff exit codes into SemVer bumps.
// abidiff exit codes are bitmasks:
// Bit 0 (1) : Error
// Bit 1 (2) : Usage error
// Bit 2 (4) : ABI change detected (some changes)
// Bit 3 (8) : Incompatible ABI change (Breaking -> Major)
func determineBump(exitCode int) BumpType {
	if (exitCode & 8) != 0 {
		// Bit 3 is set: Incompatible ABI change (e.g. size changed, func removed)
		return BumpMajor
	}
	if (exitCode & 4) != 0 {
		// Bit 2 is set, but not Bit 3: Compatible ABI change (e.g. new func added)
		return BumpMinor
	}
	if (exitCode & 1) != 0 || (exitCode & 2) != 0 {
		// Error invoking tool
		return Error
	}
	
	if exitCode == 0 {
		return BumpPatch
	}
	
	// Should theoretically not be reached if exit code > 0 and no bits matched, 
	// but default to Major to be safe.
	return BumpMajor
}
