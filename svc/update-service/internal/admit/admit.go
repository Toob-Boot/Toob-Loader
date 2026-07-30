package admit

import (
	"encoding/binary"
	"fmt"

	"github.com/toob-boot/update-service/pkg/tbm1"
)

// ---- Parsed header types ----

// TBM1Header holds the admission-relevant fields extracted from a raw
// TBM1 manifest buffer. Only fields needed by the admission rules and
// the artifact DB record are included.
type TBM1Header struct {
	TotalLen       uint32
	VendorID       uint16
	ProductID      uint16
	HWRevMin       uint16
	HWRevMax       uint16
	KeyIndex       uint8
	ImageCount     uint8
	MinReaderMajor uint16
	MinReaderMinor uint16
	SVN            uint32
	Stage1SVN      uint32
	KeyEpoch       uint32
	BuildNumber    uint32
	FWVerMajor     uint16
	FWVerMinor     uint16
	FWVerPatch     uint16
	SBOMDigest     [32]byte
	TargetSlot     uint8 // primary image's target_slot
	Images         [tbm1.MaxImages]ImageDesc
}

// ImageDesc holds per-image fields from the TBM1 image descriptor array.
type ImageDesc struct {
	ImageType      uint8
	TargetSlot     uint8
	CompressionAlg uint8
	DeltaAlg       uint8
	DataOff        uint32
	StoredSize     uint32
	InstalledSize  uint32
}

// Fixed-header field offsets matching boot_tbm1.h
const (
	offTotalLen       = 8
	offVendorID       = 16
	offProductID      = 18
	offHWRevMin       = 20
	offHWRevMax       = 22
	offKeyIndex       = 24
	offImageCount     = 25
	offMinReaderMajor = 28
	offMinReaderMinor = 30
	offSVN            = 32
	offStage1SVN      = 36
	offKeyEpoch       = 40
	offBuildNumber    = 44
	offFWVerMajor     = 48
	offFWVerMinor     = 50
	offFWVerPatch     = 52
	offSBOMDigest     = 56
	offImages         = 184

	imgDescSize         = 44
	imgOffImageType     = 0
	imgOffTargetSlot    = 1
	imgOffCompressionAlg = 2
	imgOffDeltaAlg      = 3
	imgOffDataOff       = 4
	imgOffStoredSize    = 8
	imgOffInstalledSize = 12
)

// parseTBM1Header extracts admission-relevant fields from a validated buffer.
// Precondition: buf has passed ValidateCReader (len >= 512, CRC OK, fields bounded).
func parseTBM1Header(buf []byte) TBM1Header {
	le := binary.LittleEndian
	h := TBM1Header{
		TotalLen:       le.Uint32(buf[offTotalLen:]),
		VendorID:       le.Uint16(buf[offVendorID:]),
		ProductID:      le.Uint16(buf[offProductID:]),
		HWRevMin:       le.Uint16(buf[offHWRevMin:]),
		HWRevMax:       le.Uint16(buf[offHWRevMax:]),
		KeyIndex:       buf[offKeyIndex],
		ImageCount:     buf[offImageCount],
		MinReaderMajor: le.Uint16(buf[offMinReaderMajor:]),
		MinReaderMinor: le.Uint16(buf[offMinReaderMinor:]),
		SVN:            le.Uint32(buf[offSVN:]),
		Stage1SVN:      le.Uint32(buf[offStage1SVN:]),
		KeyEpoch:       le.Uint32(buf[offKeyEpoch:]),
		BuildNumber:    le.Uint32(buf[offBuildNumber:]),
		FWVerMajor:     le.Uint16(buf[offFWVerMajor:]),
		FWVerMinor:     le.Uint16(buf[offFWVerMinor:]),
		FWVerPatch:     le.Uint16(buf[offFWVerPatch:]),
	}
	copy(h.SBOMDigest[:], buf[offSBOMDigest:offSBOMDigest+32])

	count := int(h.ImageCount)
	if count > tbm1.MaxImages {
		count = tbm1.MaxImages
	}
	for i := 0; i < count; i++ {
		base := offImages + i*imgDescSize
		h.Images[i] = ImageDesc{
			ImageType:      buf[base+imgOffImageType],
			TargetSlot:     buf[base+imgOffTargetSlot],
			CompressionAlg: buf[base+imgOffCompressionAlg],
			DeltaAlg:       buf[base+imgOffDeltaAlg],
			DataOff:        le.Uint32(buf[base+imgOffDataOff:]),
			StoredSize:     le.Uint32(buf[base+imgOffStoredSize:]),
			InstalledSize:  le.Uint32(buf[base+imgOffInstalledSize:]),
		}
	}

	if count > 0 {
		h.TargetSlot = h.Images[0].TargetSlot
	}

	return h
}

// ---- Admission result ----

// Result is the outcome of the admission gate.
type Result struct {
	Accepted bool
	Header   TBM1Header // only meaningful when Accepted == true

	// Rejection details (only meaningful when Accepted == false)
	CReaderReject tbm1.RejectCode // non-zero if the C-Reader rejected
	Rule          string          // name of the Go-side rule that rejected
	Reason        string          // human-readable rejection reason
}

// ---- Channel profile (caller populates from DB) ----

// ChannelProfile carries the fleet-derived constraints that the C-Reader
// cannot check (it has no DB context). The caller queries these from the
// devices and products tables before calling Admit.
type ChannelProfile struct {
	StagingCap uint32 // smallest staging_capacity across all devices in the channel

	// Set to true if the channel has enrolled devices. When false, rules
	// that depend on device fleet metadata (reader version, capacity) are skipped.
	HasDevices         bool
	MinReaderMajor     uint16 // lowest reader_major across all channel devices
	MinReaderMinor     uint16 // lowest reader_minor across all channel devices
	MinStagingCapacity uint32 // smallest staging_capacity in the channel
}

// ---- Admission gate ----

// Admit runs the full admission pipeline on a raw TBM1 blob:
//  1. C-Reader structural validation (boot_tbm1.c via CGo)
//  2. Recovery-slot prohibition
//  3. Stage1 SVN sanity
//  4. Reader version compatibility
//  5. Staging capacity check
//
// A rejected artifact must not be stored or made assignable.
func Admit(blob []byte, profile ChannelProfile) Result {
	// Step 1: C-Reader — identical validation to what runs on the device.
	cap := profile.StagingCap
	if cap == 0 {
		cap = uint32(len(blob))
	}

	rc := tbm1.ValidateCReader(blob, cap)
	if rc != tbm1.RejectOK {
		return Result{
			CReaderReject: rc,
			Rule:          "c_reader",
			Reason:        fmt.Sprintf("C-Reader rejected: %s", rc),
		}
	}

	hdr := parseTBM1Header(blob)

	// Rule 1: No image may target the Recovery slot.
	for i := 0; i < int(hdr.ImageCount); i++ {
		if hdr.Images[i].TargetSlot == tbm1.SlotRecovery {
			return Result{
				Rule:   "no_recovery_slot",
				Reason: fmt.Sprintf("image[%d].target_slot is RECOVERY (factory-locked, always rejected by stage_swap)", i),
			}
		}
	}

	// Rule 2: Stage1 images must have stage1_svn > 0.
	for i := 0; i < int(hdr.ImageCount); i++ {
		if hdr.Images[i].TargetSlot == tbm1.SlotStage1 && hdr.Stage1SVN == 0 {
			return Result{
				Rule:   "stage1_svn_nonzero",
				Reason: "stage1_svn must be > 0 for Stage1 images (Core rejects 0 with BOOT_ERR_INVALID_ARG)",
			}
		}
	}

	// Rules 3 + 4 require enrolled devices in the target channel.
	if profile.HasDevices {
		if hdr.MinReaderMajor > profile.MinReaderMajor ||
			(hdr.MinReaderMajor == profile.MinReaderMajor &&
				hdr.MinReaderMinor > profile.MinReaderMinor) {
			return Result{
				Rule: "reader_version",
				Reason: fmt.Sprintf(
					"min_reader %d.%d exceeds channel minimum %d.%d",
					hdr.MinReaderMajor, hdr.MinReaderMinor,
					profile.MinReaderMajor, profile.MinReaderMinor),
			}
		}

		if hdr.TotalLen > profile.MinStagingCapacity {
			return Result{
				Rule: "staging_capacity",
				Reason: fmt.Sprintf(
					"artifact size %d exceeds channel min staging_capacity %d",
					hdr.TotalLen, profile.MinStagingCapacity),
			}
		}
	}

	return Result{Accepted: true, Header: hdr}
}
