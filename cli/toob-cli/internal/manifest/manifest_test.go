package manifest

import (
	"os"
	"path/filepath"
	"testing"

	build "github.com/Toob-Boot/Toob-Loader/toob-go-lib/build"
)

func TestManifestFacade(t *testing.T) {
	if ParseToml == nil || CheckBudget == nil || CheckBudgetWithLayout == nil || Generate == nil {
		t.Fatal("manifest compiler functions not properly wired to toob-go-lib/build")
	}
	var _ build.Logger = uiLogger{}
	var _ *PartitionLayout
	var _ *Result
}

func TestLoadBindsLogger(t *testing.T) {
	if _, err := Load(Inputs{}); err == nil || err.Error() != "build.Load: Inputs.Device must not be nil" {
		t.Fatalf("expected library input validation error, got %v", err)
	}
	if _, err := LoadSilent(Inputs{}); err == nil || err.Error() != "build.Load: Inputs.Device must not be nil" {
		t.Fatalf("expected library input validation error from LoadSilent, got %v", err)
	}
}

func TestCheckBudgetWithLayoutFacade(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "stage0.bin")
	if err := os.WriteFile(binPath, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	layout := &PartitionLayout{
		Stage0: PartitionSlot{Name: "Stage 0", Addr: 0, Budget: 4096, Kind: SlotBoot},
	}
	rep, err := CheckBudgetWithLayout(layout, binPath, "stage0")
	if err != nil {
		t.Fatalf("CheckBudgetWithLayout failed: %v", err)
	}
	if rep.Size != 1024 || rep.Budget != 4096 {
		t.Fatalf("unexpected BudgetReport: %+v", rep)
	}
}
