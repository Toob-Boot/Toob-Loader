package build

import (
	"strings"
	"testing"
)

func TestPlanLayoutMixedSectorSizes(t *testing.T) {
	ctx := testContext(t)
	ctx.Hardware.Flash.Size = 0x300000
	ctx.Hardware.Flash.Regions = []FlashRegion{
		{Type: "writable", Base: 0x00000, SectorSize: 16384, Count: 4},
		{Type: "writable", Base: 0x10000, SectorSize: 65536, Count: 1},
		{Type: "writable", Base: 0x20000, SectorSize: 131072, Count: 23},
	}
	_, layout := testLayout(t, ctx)

	if layout.MaxSectorSize != 131072 {
		t.Fatalf("expected a 128 KB maximum sector, got %d", layout.MaxSectorSize)
	}
	if layout.Stage0.Addr != 0 || layout.Stage0.Budget != 0x4000 || layout.Stage0.SectorSize != 16384 {
		t.Errorf("a 16 KB Stage 0 must occupy one 16 KB local sector, got 0x%X/0x%X (sector=%d)", layout.Stage0.Addr, layout.Stage0.Budget, layout.Stage0.SectorSize)
	}
	if layout.Stage1A.Budget != layout.Stage1B.Budget {
		t.Errorf("Stage 1 banks must have symmetric budgets: %+v / %+v", layout.Stage1A, layout.Stage1B)
	}
	for _, r := range layout.regions() {
		if r.slot.Budget == 0 {
			continue
		}
		sec, err := layout.SectorSizeAt(r.slot.Addr)
		if err != nil || sec == 0 || r.slot.Addr%sec != 0 {
			t.Errorf("%s starts at 0x%X, which is not aligned to local sector %d (%v)", r.slot.Name, r.slot.Addr, sec, err)
		}
	}
}

func TestPartitionLayoutValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PartitionLayout)
		wantErr string // empty = must pass
	}{
		{"baseline", func(*PartitionLayout) {}, ""},
		{"unaligned start", func(l *PartitionLayout) { l.Stage0.Addr += l.MaxSectorSize / 2 }, "LAYOUT_001"},
		{"partial unit size", func(l *PartitionLayout) { l.App.Budget += l.MaxSectorSize / 2 }, "LAYOUT_002"},
		{"unequal banks", func(l *PartitionLayout) { l.Staging.Budget += l.MaxSectorSize }, "LAYOUT_003"},
		{"unsplittable mailbox", func(l *PartitionLayout) { l.Mailbox.Budget += l.MaxSectorSize }, "LAYOUT_004"},
		{"sector-granular WAL", func(l *PartitionLayout) { l.Wal.Budget = l.MaxSectorSize / 2 }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, layout := testLayout(t, testContext(t))
			c.mutate(layout)
			err := layout.validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}
