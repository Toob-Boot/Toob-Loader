package build

import (
	"strings"
	"testing"
)

func TestCheckFlashGeometry(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Context)
		wantErr string // empty = must pass
	}{
		{"baseline", func(*Context) {}, ""},
		{"write alignment not power of two", func(c *Context) { c.Hardware.Flash.WriteAlignment = 12 }, "write_alignment 12 is not a power of two"},
		{"app alignment not power of two", func(c *Context) { c.Hardware.Flash.AppAlignment = 3000 }, "app_alignment 3000 is not a power of two"},
		{"write alignment above sector", func(c *Context) { c.Hardware.Flash.WriteAlignment = 8192 }, "exceeds the smallest sector size"},
		{"sector size not power of two", func(c *Context) { c.Hardware.Flash.Regions[1].SectorSize = 3000 }, "not a power of two"},
		{"base not sector aligned", func(c *Context) { c.Hardware.Flash.Regions[1].Base += 1024 }, "not a multiple of its sector_size"},
		{"region beyond flash", func(c *Context) { c.Hardware.Flash.Size -= 4096 }, "beyond the flash size"},
		{"writable overlap", func(c *Context) {
			c.Hardware.Flash.Regions = append(c.Hardware.Flash.Regions, FlashRegion{Type: "writable", Base: 0x80000, SectorSize: 4096, Count: 4})
		}, "overlap"},
		{"gap in the middle (dual-bank)", func(c *Context) { c.Hardware.Flash.Regions[0].Size = 0x30000 }, ""},
		{"uncovered tail", func(c *Context) { c.Hardware.Flash.Size += 4096 }, ""},
		{"physical flash.base dual-bank", func(c *Context) {
			c.Hardware.Flash.Base = 0x08000000
			c.Hardware.Flash.Size = 0x00200000
			c.Hardware.Flash.Regions = []FlashRegion{
				{Type: "writable", Base: 0x08000000, SectorSize: 0x2000, Count: 64},
				{Type: "writable", Base: 0x08100000, SectorSize: 0x2000, Count: 64},
			}
		}, ""},
		{"region below flash.base", func(c *Context) {
			c.Hardware.Flash.Base = 0x08000000
			c.Hardware.Flash.Regions = []FlashRegion{
				{Type: "writable", Base: 0x07FF0000, SectorSize: 4096, Count: 4},
			}
		}, "below flash base"},
		{"unsafe region name", func(c *Context) { c.Hardware.Flash.Regions[0].Name = "rom */ evil" }, "FLASH_004"},
		{"reserved without size", func(c *Context) {
			c.Hardware.Flash.Regions = append(c.Hardware.Flash.Regions, FlashRegion{Type: "reserved", Base: 0x400000, Size: 0})
		}, "must specify 'size'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := testContext(t)
			c.mutate(ctx)
			err := checkFlashGeometry(ctx)
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
