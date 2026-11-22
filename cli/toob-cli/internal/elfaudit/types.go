package elfaudit

import (
	"math"
	"time"
)

const (
	// ProfileProduction enforces full anti-mock poison-pill verification.
	ProfileProduction = "production"
	// ProfileDev permits mock symbols/sections for development builds.
	ProfileDev = "dev"
)

// ELFAuditReport captures the full outcome of a post-link ELF binary audit.
type ELFAuditReport struct {
	Timestamp  time.Time    `json:"timestamp"`
	BinaryPath string       `json:"binary_path"`
	Profile    string       `json:"profile"`
	Passed     bool         `json:"passed"`
	Checks     []AuditCheck `json:"checks"`
	Violations []AuditCheck `json:"-"`
}

// AuditCheck represents a single audit assertion result.
type AuditCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// MemoryRegion describes an address range, used for ELF sections, target flash
// bounds, and reserved hardware regions parsed from hardware.json.
type MemoryRegion struct {
	Name string
	Base uint64
	Size uint64
}

// End returns the exclusive upper bound of the region, saturating at MaxUint64.
func (r MemoryRegion) End() uint64 {
	if r.Size > math.MaxUint64-r.Base {
		return math.MaxUint64
	}
	return r.Base + r.Size
}

// ContainsRegion returns true when other lies completely within r.
func (r MemoryRegion) ContainsRegion(other MemoryRegion) bool {
	if other.Size == 0 {
		return true
	}
	if r.Size == 0 {
		return false
	}
	return other.Base >= r.Base && other.End() <= r.End()
}

// Overlaps returns true if this region intersects with other.
func (r MemoryRegion) Overlaps(other MemoryRegion) bool {
	if r.Size == 0 || other.Size == 0 {
		return false
	}
	return r.Base < other.End() && other.Base < r.End()
}

// ELFAuditConfig supplies all external parameters the auditor needs.
type ELFAuditConfig struct {
	Profile          string         // "production" or "dev" (validated fail-closed)
	ReservedRegions  []MemoryRegion // from hardware.json reserved_ram_regions
	FlashBounds      *MemoryRegion  // optional target flash/partition LMA window
	Stage1MaxBytes   uint64         // maximum loadable flash footprint budget (0 = skip check)
	SegmentedBootrom bool           // true only for multi-segment RAM BootROM Stage-0 ELFs
}
