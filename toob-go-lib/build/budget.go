package build

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
)

// stage1SignedEnvelopeBytes is the 20-byte toob_image_header_t + 64-byte trailing
// Ed25519 signature added around a raw Stage-1 binary by `toob sign --stage1`.
const stage1SignedEnvelopeBytes uint32 = 84

// BudgetReport is the outcome of a successful budget check.
type BudgetReport struct {
	Stage  string
	Size   uint32
	Budget uint32
}

// CheckBudget verifies that a compiled stage binary fits its partition budget.
func CheckBudget(tomlPath, binPath, stage string) (*BudgetReport, error) {
	dt, err := ParseToml(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("BUDGET CHECK ERROR: Could not read/parse %s: %w", tomlPath, err)
	}

	budget, err := stageBudget(dt, stage)
	if err != nil {
		return nil, err
	}
	return checkBinaryAgainstBudget(binPath, stage, budget)
}

// CheckBudgetWithLayout verifies that binPath fits the resolved PartitionLayout
// slot budget (including sector/MMU alignment rounding and swapmove spare sector).
func CheckBudgetWithLayout(layout *PartitionLayout, binPath, stage string) (*BudgetReport, error) {
	if layout == nil {
		return nil, errors.New("BUDGET CHECK ERROR: PartitionLayout must not be nil")
	}
	budget, err := layoutStageBudget(layout, stage)
	if err != nil {
		return nil, err
	}
	return checkBinaryAgainstBudget(binPath, stage, budget)
}

func checkBinaryAgainstBudget(binPath, stage string, budget uint32) (*BudgetReport, error) {
	info, err := os.Stat(binPath)
	if err != nil {
		return nil, fmt.Errorf("BUDGET CHECK ERROR: Could not read binary %s: %w", binPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("BUDGET CHECK ERROR: %s is not a regular file", binPath)
	}
	rawSize := info.Size()
	if rawSize <= 0 {
		return nil, fmt.Errorf("BUDGET CHECK ERROR: binary %s is empty (%d bytes)", binPath, rawSize)
	}
	if rawSize > math.MaxUint32 {
		return nil, fmt.Errorf("FATAL [BUDGET_OVERFLOW]: binary %s size %d exceeds 32-bit limits", binPath, rawSize)
	}
	size := uint32(rawSize)

	normStage := strings.ToLower(strings.TrimSpace(stage))
	if normStage == "stage1" || normStage == "stage1a" || normStage == "stage1b" {
		aligned, err := alignUp(size, 4)
		if err != nil {
			return nil, fmt.Errorf("FATAL [BUDGET_OVERFLOW]: %s size %d alignment overflow: %w", stage, size, err)
		}
		signedTotal := uint64(aligned) + uint64(stage1SignedEnvelopeBytes)
		if signedTotal > uint64(budget) {
			return nil, fmt.Errorf("FATAL [BUDGET_EXCEEDED]: %s is %d bytes (%d bytes with 84-byte signed envelope), which exceeds the budget of %d bytes",
				stage, size, signedTotal, budget)
		}
		return &BudgetReport{Stage: stage, Size: size, Budget: budget}, nil
	}

	if size > budget {
		return nil, fmt.Errorf("FATAL [BUDGET_EXCEEDED]: %s is %d bytes, which exceeds the budget of %d bytes", stage, size, budget)
	}
	return &BudgetReport{Stage: stage, Size: size, Budget: budget}, nil
}

func layoutStageBudget(l *PartitionLayout, stage string) (uint32, error) {
	var budget uint32
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "stage0":
		budget = l.Stage0.Budget
	case "stage1", "stage1a":
		budget = l.Stage1A.Budget
	case "stage1b":
		budget = l.Stage1B.Budget
	case "recovery", "recovery_os":
		budget = l.Recovery.Budget
	case "app":
		budget = l.App.Budget
		if (l.Transport == TransportSwapMove || l.Transport == TransportSwapOffset) && l.Staging.Budget > 0 {
			budget = l.Staging.Budget
		}
	case "staging":
		budget = l.Staging.Budget
	case "netcore", "netcore_slot":
		budget = l.NetCore.Budget
	default:
		return 0, fmt.Errorf("invalid stage '%s' (supported: stage0, stage1, recovery, app, staging, netcore)", stage)
	}
	if budget == 0 {
		return 0, fmt.Errorf("FATAL [BUDGET_UNCONFIGURED]: stage '%s' has zero resolved partition budget", stage)
	}
	return budget, nil
}

// stageBudget returns the configured partition budget of a stage.
func stageBudget(dt *DeviceToml, stage string) (uint32, error) {
	p := &dt.Partitions
	var budget uint32
	var code, field string
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "stage0":
		budget, code, field = p.Stage0Size, "BUDGET_001", "stage0_size"
	case "stage1", "stage1a", "stage1b":
		budget, code, field = p.Stage1Size, "BUDGET_002", "stage1_size"
	case "recovery", "recovery_os":
		budget, code, field = p.RecoverySize, "BUDGET_003", "recovery_size"
	case "app", "staging":
		budget, code, field = p.AppSize, "BUDGET_004", "app_size"
	case "netcore", "netcore_slot":
		budget, code, field = p.NetcoreSize, "BUDGET_005", "netcore_size"
	default:
		return 0, fmt.Errorf("invalid stage '%s' (supported: stage0, stage1, recovery, app, staging, netcore)", stage)
	}
	if budget == 0 {
		return 0, fmt.Errorf("FATAL [%s]: %s is not configured in [partitions] of device.toml", code, field)
	}
	return budget, nil
}
