package elfaudit

import "time"

// ELFAuditReport captures the full outcome of a post-link ELF binary audit.
type ELFAuditReport struct {
	Timestamp  time.Time      `json:"timestamp"`
	BinaryPath string         `json:"binary_path"`
	Profile    string         `json:"profile"`
	Passed     bool           `json:"passed"`
	Checks     []AuditCheck   `json:"checks"`
	Violations []AuditCheck   `json:"-"`
}

// AuditCheck represents a single audit assertion result.
type AuditCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// MemoryRegion describes an address range, used both for ELF sections
// and reserved hardware regions parsed from hardware.json.
type MemoryRegion struct {
	Name string
	Base uint64
	Size uint64
}

// End returns the exclusive upper bound of the region.
func (r MemoryRegion) End() uint64 {
	return r.Base + r.Size
}

// Overlaps returns true if this region intersects with other.
func (r MemoryRegion) Overlaps(other MemoryRegion) bool {
	return r.Base < other.End() && other.Base < r.End()
}

// ELFAuditConfig supplies all external parameters the auditor needs.
type ELFAuditConfig struct {
	Profile         string         // "production" or "sandbox"
	ReservedRegions []MemoryRegion // from hardware.json reserved_ram_regions
	Stage1MaxBytes  uint64         // maximum loadable footprint budget (0 = skip check)
}
