package manifest

import (
	"fmt"
	"os"

	"github.com/toob-boot/toob/internal/ui"
)

func CheckBudget(tomlPath, binPath, stage string) error {
	dt, err := ParseToml(tomlPath)
	if err != nil {
		return fmt.Errorf("BUDGET CHECK ERROR: Could not read/parse %s: %w", tomlPath, err)
	}

	budget := uint32(0)
	switch stage {
	case "stage0":
		budget = dt.Partitions.Stage0Size
		if budget == 0 {
			return fmt.Errorf("FATAL [BUDGET_001]: stage0_size is mandatory in [partitions] of device.toml")
		}
	case "stage1":
		budget = dt.Partitions.Stage1Size
		if budget == 0 {
			return fmt.Errorf("FATAL [BUDGET_002]: stage1_size is mandatory in [partitions] of device.toml")
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

	ui.Success("BUDGET SUCCESS: %s (%d bytes) fits into budget (%d bytes).", stage, actualSize, budget)
	return nil
}
