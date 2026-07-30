// Package resolver implements the pure, side-effect-free, deterministic device resolution engine
// for update assignment (§6 in plan7.md, UPD-021 in plan8.md).
package resolver

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// Reason taxonomy describing why an update was resolved or rejected.
type Reason string

const (
	ReasonResolved               Reason = "RESOLVED"
	ReasonDeviceQuarantined      Reason = "DEVICE_QUARANTINED"
	ReasonNoCandidatesAvailable Reason = "NO_CANDIDATES_AVAILABLE"
	ReasonIncompatibleHW         Reason = "INCOMPATIBLE_HW_REV"
	ReasonIncompatibleStaging    Reason = "INCOMPATIBLE_STAGING_CAPACITY"
	ReasonIncompatibleReader     Reason = "INCOMPATIBLE_BOOTLOADER_READER"
	ReasonAlreadyUpToDate        Reason = "ALREADY_UP_TO_DATE"
	ReasonRollbackProhibited     Reason = "ROLLBACK_PROHIBITED"
	ReasonExcludedByRamp         Reason = "EXCLUDED_BY_CANARY_RAMP"
)

func (r Reason) String() string {
	return string(r)
}

// Device attributes required for resolution.
type Device struct {
	ID              []byte // 32-byte device_id
	Product         string
	VendorID        uint16
	ProductID       uint16
	ProductHWRev    uint16
	StagingCapacity uint32
	ReaderMajor     uint16
	ReaderMinor     uint16
	Channel         string
	Health          string // "ok", "suspect", "quarantined"
}

// ObservedState holds telemetry reported by the device on checkin.
type ObservedState struct {
	ReportedSVN     uint32
	ReportedBuild   uint32
	BootedPartition uint8 // 0 = SlotApp, 2 = SlotRecovery
}

// Artifact candidate from the catalog.
type Artifact struct {
	ID             string
	Product        string
	BuildNumber    uint32
	Kind           string // "full" or "delta"
	BaseBuild      *int32
	DigestHex      string
	SizeBytes      uint32
	SVN            uint32
	Stage1SVN      uint32
	KeyIndex       uint8
	HWRevMin       uint16
	HWRevMax       uint16
	MinReaderMajor uint16
	MinReaderMinor uint16
	TargetSlot     uint8
}

// Options for resolution (pinning and canary rollout ramps).
type Options struct {
	PinnedArtifactID string
	RampBPS          uint32 // 0..10000 basis points (0 = 0%, 10000 = 100%). If 0 and PinnedArtifactID is empty, treated as 10000.
}

// Resolve executes the 7-step resolution cascade in a strictly prioritized,
// 100% deterministic manner based on device attributes, telemetry, and candidate artifacts.
//
// Returns:
//   - (*Artifact, ReasonResolved, nil) if a suitable update is found.
//   - (nil, reason, nil) if no update should be offered (e.g. up-to-date, excluded by ramp, incompatible).
//   - (nil, "", err) on invalid input parameters.
func Resolve(dev Device, obs ObservedState, candidates []Artifact, opts Options) (*Artifact, Reason, error) {
	// Step 1: Health Guard — Quarantined devices receive NO updates (return 204)
	if strings.EqualFold(dev.Health, "quarantined") {
		return nil, ReasonDeviceQuarantined, nil
	}

	if len(candidates) == 0 {
		return nil, ReasonNoCandidatesAvailable, nil
	}

	// Default RampBPS to 10000 (100%) if not explicitly specified
	rampBPS := opts.RampBPS
	if rampBPS == 0 && opts.PinnedArtifactID == "" {
		rampBPS = 10000
	}

	// Step 2: Pinning Priority (`assignments.source = 'pin'`)
	// If a pin is requested, it overrides channel releases. Must be compatible.
	if opts.PinnedArtifactID != "" {
		for i := range candidates {
			art := &candidates[i]
			if art.ID == opts.PinnedArtifactID {
				reason, admissible := evaluateAdmissibility(dev, obs, art)
				if !admissible {
					return nil, reason, nil
				}
				return art, ReasonResolved, nil
			}
		}
		return nil, ReasonNoCandidatesAvailable, nil
	}

	// Step 3: Filter & Evaluate Candidates
	// Filter candidates for admissibility (Compatibility + Progress + Anti-Rollback)
	var admissible []Artifact
	var lastRejectReason Reason = ReasonAlreadyUpToDate

	for i := range candidates {
		art := &candidates[i]
		reason, ok := evaluateAdmissibility(dev, obs, art)
		if ok {
			admissible = append(admissible, *art)
		} else {
			lastRejectReason = reason
		}
	}

	if len(admissible) == 0 {
		return nil, lastRejectReason, nil
	}

	// Step 4: Delta Preference Strategy
	// If a Delta artifact exists matching observed.ReportedBuild, prefer it over Full
	var selected *Artifact
	for i := range admissible {
		art := &admissible[i]
		if art.Kind == "delta" && art.BaseBuild != nil && uint32(*art.BaseBuild) == obs.ReportedBuild {
			selected = art
			break
		}
	}

	// Fallback to Full artifact if no matching Delta is found
	if selected == nil {
		for i := range admissible {
			art := &admissible[i]
			if art.Kind == "full" {
				selected = art;
				break
			}
		}
	}

	// If only Deltas existed but none matched base_build, take first admissible
	if selected == nil && len(admissible) > 0 {
		selected = &admissible[0]
	}

	// Step 5: Deterministic Canary Rollout Gate (RampBPS)
	// Must be 100% deterministic based on SHA-256(device_id ‖ artifact_id) mod 10000
	if rampBPS < 10000 {
		if !evaluateCanaryRamp(dev.ID, selected.ID, rampBPS) {
			return nil, ReasonExcludedByRamp, nil
		}
	}

	return selected, ReasonResolved, nil
}

// evaluateAdmissibility checks Hardware Compatibility, Bootloader Version,
// Monotonic SVN Anti-Rollback, and Build Progress.
func evaluateAdmissibility(dev Device, obs ObservedState, art *Artifact) (Reason, bool) {
	// 1. Hardware Revision Check: hw_rev BETWEEN hw_rev_min AND hw_rev_max
	if dev.ProductHWRev < art.HWRevMin || dev.ProductHWRev > art.HWRevMax {
		return ReasonIncompatibleHW, false
	}

	// 2. Staging Capacity Check: size_bytes <= staging_capacity
	if art.SizeBytes > dev.StagingCapacity {
		return ReasonIncompatibleStaging, false
	}

	// 3. Bootloader Reader Version Gate: min_reader_* <= dev.reader_*
	if art.MinReaderMajor > dev.ReaderMajor ||
		(art.MinReaderMajor == dev.ReaderMajor && art.MinReaderMinor > dev.ReaderMinor) {
		return ReasonIncompatibleReader, false
	}

	// 4. Anti-Rollback Guard: artifact.SVN >= obs.ReportedSVN (NO DOWNGRADE!)
	if art.SVN < obs.ReportedSVN {
		return ReasonRollbackProhibited, false
	}

	// 5. Build Progress Check: artifact.BuildNumber != obs.ReportedBuild
	// Do not re-offer an installed build unless SVN is higher or slot differs
	if art.BuildNumber == obs.ReportedBuild && art.SVN == obs.ReportedSVN {
		return ReasonAlreadyUpToDate, false
	}

	return ReasonResolved, true
}

// evaluateCanaryRamp computes SHA-256(device_id ‖ artifact_id) mod 10000.
// Returns true if the device falls within [0 .. rampBPS-1].
func evaluateCanaryRamp(deviceID []byte, artifactID string, rampBPS uint32) bool {
	h := sha256.New()
	h.Write(deviceID)
	h.Write([]byte(artifactID))
	digest := h.Sum(nil)

	// Take first 4 bytes of SHA-256 hash as uint32 for bucket calculation
	val := binary.BigEndian.Uint32(digest[0:4])
	bucket := val % 10000

	return bucket < rampBPS
}
