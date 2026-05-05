package manifest

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

func CheckBudget(tomlPath, binPath, stage string) error {
	var dt DeviceToml
	if _, err := toml.DecodeFile(tomlPath, &dt); err != nil {
		return fmt.Errorf("BUDGET CHECK ERROR: Could not read %s: %w", tomlPath, err)
	}

	budget := uint32(0)
	switch stage {
	case "stage0":
		budget = dt.Partitions.Stage0Size
		if budget == 0 {
			budget = 16384
		}
	case "stage1":
		budget = dt.Partitions.Stage1Size
		if budget == 0 {
			budget = 28672
		}
	default:
		return fmt.Errorf("invalid stage %s", stage)
	}

	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("BUDGET CHECK ERROR: Could not read binary %s: %w", binPath, err)
	}
	actualSize := uint32(info.Size())

	if actualSize > budget {
		return fmt.Errorf("FATAL [BUDGET_EXCEEDED]: %s is %d bytes, which exceeds the budget of %d bytes!", stage, actualSize, budget)
	}

	fmt.Printf("BUDGET SUCCESS: %s (%d bytes) fits into budget (%d bytes).\n", stage, actualSize, budget)
	return nil
}
