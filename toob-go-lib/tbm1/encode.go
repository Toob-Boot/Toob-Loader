package tbm1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/heatshrink"
	"github.com/Toob-Boot/Toob-Loader/toob-go-lib/tds1"
)

// ---- Tuning constants ---------------------------------------------------

const (
	// hashStripeBytes is roughly how much payload one worker claims per trip
	// through the shared cursor. Large enough that the atomic is noise, small
	// enough that the tail imbalance stays below a millisecond.
	hashStripeBytes = 256 << 10

	// digestsPerLine × DigestLen = 128 B, the widest cache line in current use
	// (Apple silicon, some ARM server parts). Stripe boundaries are multiples of
	// it, so two workers never write to the same line.
	digestsPerLine = 4

	// minParallelBytes is the payload size below which spreading the work costs
	// more than it saves.
	minParallelBytes = 1 << 20

	// defaultScratchLimit caps the total chunk-sized scratch buffers allocated
	// for streamed payloads.
	defaultScratchLimit = 32 << 20

	// sbomCopyBuffer is the read size for the SBOM pass over a streamed image.
	sbomCopyBuffer = 128 << 10
)

// ---- Input types --------------------------------------------------------

// Image describes one component of an update bundle.
//
// The installed image can be supplied either in memory (Installed) or as a
// random-access source (InstalledAt). Exactly one of the two must be set. The
// streaming form keeps the encoder's footprint at a few chunk-sized buffers
// instead of the whole firmware, which matters when a backend builds several
// bundles concurrently.
type Image struct {
	Type       uint8 `json:"type"`
	TargetSlot uint8 `json:"target_slot"`
	CompAlg    uint8 `json:"compression_alg"`
	DeltaAlg   uint8 `json:"delta_alg"`

	// Installed is the post-decompress/patch image. Chunk hashes,
	// installed_size and num_chunks all derive from it.
	Installed []byte `json:"installed,omitempty"`
	// InstalledAt is the streaming alternative to Installed. ReadAt must be
	// safe for concurrent use, as io.ReaderAt already requires; *os.File and
	// *bytes.Reader both qualify.
	InstalledAt io.ReaderAt `json:"-"`
	// InstalledSize is required with InstalledAt and optional (but checked)
	// with Installed.
	InstalledSize uint32 `json:"installed_size,omitempty"`

	// Stored is what lands in staging (the compressed or delta payload). The
	// encoder reads nothing but its length — see StoredSize.
	Stored []byte `json:"stored,omitempty"`
	// StoredSize replaces Stored when the payload is not in memory. Zero means
	// "same as the installed image", i.e. a raw, uncompressed staging copy.
	StoredSize uint32 `json:"stored_size,omitempty"`

	// Base is the base image used to automatically generate a TDS1 patch
	// if DeltaAlg == DeltaTDS1 and Stored is not pre-computed.
	Base []byte `json:"base,omitempty"`

	// PayloadOffset and TailGap allow configuring custom gap offsets in staging
	// (useful for swapoffset T2B).
	PayloadOffset uint32 `json:"payload_offset,omitempty"`
	TailGap       uint32 `json:"tail_gap,omitempty"`

	ChunkSize uint32 `json:"chunk_size,omitempty"` // 0 → DefaultChunkSize
	BaseSVN   uint32 `json:"base_svn,omitempty"`

	VerMajor        uint16 `json:"ver_major,omitempty"`
	VerMinor        uint16 `json:"ver_minor,omitempty"`
	VerPatch        uint16 `json:"ver_patch,omitempty"`
	BaseFingerprint []byte `json:"base_fingerprint,omitempty"` // 0 or 8 bytes
}

// ReverseDelta describes a rollback patch stored in staging and described in Region 6.
type ReverseDelta struct {
	TargetSlot     uint8       `json:"target_slot"`
	DeltaAlg       uint8       `json:"delta_alg"` // TBM1_DELTA_TDS1 = 3
	Data           []byte      `json:"data,omitempty"`
	DataAt         io.ReaderAt `json:"-"`
	StoredSize     uint32      `json:"stored_size,omitempty"`
	RestoredSize   uint32      `json:"restored_size,omitempty"`
	RestoredSHA256 [32]byte    `json:"restored_sha256,omitempty"`

	// OldImage allows automatic derivation of RestoredSize, RestoredSHA256
	// and TDS1 reverse delta data.
	OldImage []byte `json:"old_image,omitempty"`
}

// Manifest is the full input for one TBM1 package.
type Manifest struct {
	VendorID  uint16 `json:"vendor_id"`
	ProductID uint16 `json:"product_id"`
	HWRevMin  uint16 `json:"hw_rev_min"`
	HWRevMax  uint16 `json:"hw_rev_max"`

	KeyIndex    uint8  `json:"key_index"`
	KeyEpoch    uint32 `json:"key_epoch,omitempty"`
	SVN         uint32 `json:"svn"`
	Stage1SVN   uint32 `json:"stage1_svn,omitempty"`
	BuildNumber uint32 `json:"build_number,omitempty"`

	FwVerMajor uint16 `json:"fw_ver_major,omitempty"`
	FwVerMinor uint16 `json:"fw_ver_minor,omitempty"`
	FwVerPatch uint16 `json:"fw_ver_patch,omitempty"`

	BootRetryLimit uint16 `json:"boot_retry_limit,omitempty"`
	MinReaderMajor uint16 `json:"min_reader_major,omitempty"`
	MinReaderMinor uint16 `json:"min_reader_minor,omitempty"`

	SBOMDigest []byte `json:"sbom_digest,omitempty"` // 0 or 32 bytes
	// AutoSBOM derives the digest as SHA-256 over images[0]'s installed image.
	// That is a second full pass over the payload, as expensive as every chunk
	// hash combined — set SBOMDigest directly if the build system already
	// knows it.
	AutoSBOM bool `json:"auto_sbom,omitempty"`

	DeviceBind []byte `json:"device_bind,omitempty"` // 0 or 32 bytes → InfoDeviceBind
	PQCSig     []byte `json:"pqc_sig,omitempty"`     // must be paired with PQCPubkey
	PQCPubkey  []byte `json:"pqc_pubkey,omitempty"`

	// ReverseDeltas are encoded into Region 6 for rollback support.
	ReverseDeltas []ReverseDelta `json:"reverse_deltas,omitempty"`

	// TrailerLayout places image[0] at slot offset 0 and appends the signed TBM1
	// envelope + 16-byte TrailerLocator after the payloads for true Zero-Copy XIP/bank-swap.
	TrailerLayout bool `json:"trailer_layout,omitempty"`

	SectorSize uint32  `json:"sector_size,omitempty"` // power of two; 0 → DefaultSectorSize
	Images     []Image `json:"images"`
}

// PayloadInfo holds layout metadata for one staging payload.
type PayloadInfo struct {
	TargetSlot uint8  `json:"target_slot"`
	Offset     uint32 `json:"offset"`
	Length     uint32 `json:"length"`
	Data       []byte `json:"-"`
	IsRDelta   bool   `json:"is_rdelta"`
}

// Package is the assembled manifest block plus derived metadata.
type Package struct {
	// Block is header(512) + regions + signature(64). After BuildUnsigned the
	// trailing 64 bytes are zero; Sign / SetSignature fill them.
	Block []byte `json:"-"`

	TotalLen      uint32        `json:"total_len"`
	SignedLen     uint32        `json:"signed_len"` // TotalLen - 64
	DataOff       []uint32      `json:"data_off"`   // per-image staging offset (flat layout)
	StoredLen     []uint32      `json:"stored_len"` // per-image stored size, as recorded in the header
	Payloads      []PayloadInfo `json:"payloads,omitempty"`
	SectorSize    uint32        `json:"sector_size"`
	TrailerLayout bool          `json:"trailer_layout,omitempty"`
	TrailerOffset uint32        `json:"trailer_offset,omitempty"`
	Signed        bool          `json:"signed"`
}

// Encoder holds the knobs a host backend wants control over. The zero value is
// usable and is what the package-level helpers use.
type Encoder struct {
	// Parallelism caps the goroutines used for hashing. Zero means
	// runtime.GOMAXPROCS(0). One keeps everything on the calling goroutine,
	// which is usually right for a server that already runs one build per
	// request and would rather not have a single request monopolise the CPU.
	Parallelism int

	// ScratchLimit caps the chunk-sized buffers allocated for streamed
	// payloads (Image.InstalledAt). Zero means 32 MiB.
	ScratchLimit int
}

// BuildUnsigned assembles a manifest block with the default encoder.
func BuildUnsigned(m Manifest) (*Package, error) { return (&Encoder{}).BuildUnsigned(m) }

// ---- Payload access -----------------------------------------------------

// chunkSource is the encoder's read-only view of one installed image. Exactly
// one of the two fields is set.
type chunkSource struct {
	mem []byte
	at  io.ReaderAt
}

func (s chunkSource) streamed() bool { return s.mem == nil }

// read returns the bytes of [off, off+n). For an in-memory source this is a
// sub-slice; otherwise the data lands in scratch, which the caller owns.
func (s chunkSource) read(scratch []byte, off uint64, n uint32) ([]byte, error) {
	if s.mem != nil {
		return s.mem[off : off+uint64(n)], nil
	}
	if off > math.MaxInt64 {
		return nil, fmt.Errorf("%w: offset %d exceeds int64", ErrLayoutOverflow, off)
	}
	buf := scratch[:n]
	got, err := s.at.ReadAt(buf, int64(off))
	// ReadAt is allowed to report io.EOF together with a full read.
	if err != nil && (!errors.Is(err, io.EOF) || got != len(buf)) {
		return nil, fmt.Errorf("%w: ReadAt(off=%d, n=%d): %w", ErrPayload, off, n, err)
	}
	if got != len(buf) {
		return nil, fmt.Errorf("%w: short read at %d: %d of %d bytes", ErrPayload, off, got, n)
	}
	return buf, nil
}

// ---- Internal planning types --------------------------------------------

// imagePlan is the derived, fully validated geometry of one image.
type imagePlan struct {
	src           chunkSource
	installedLen  uint32
	storedLen     uint32
	chunkSize     uint32
	numChunks     uint32
	hashOff       uint64 // byte offset of this image's digests inside the region
	payloadOffset uint32
	tailGap       uint32
	storedData    []byte

	// Descriptor metadata, copied out of the caller's Image so the encoder
	// never re-reads a struct the caller might mutate mid-build.
	typ, targetSlot, compAlg, deltaAlg uint8
	baseSVN                            uint32
	verMajor, verMinor, verPatch       uint16
	baseFP                             [8]byte
}

type regionSpec struct {
	id   uint16
	size uint64
	data []byte // nil ⇒ filled in place afterwards (chunk hashes)
}

type regionPlan struct {
	id       uint16
	off, len uint32
	data     []byte
}

// ---- Build --------------------------------------------------------------

// BuildUnsigned assembles the manifest block with a zeroed signature slot. It
// re-runs the reader's checks, so a successful build cannot produce a manifest
// that tbm1_validate would reject.
func (e *Encoder) BuildUnsigned(m Manifest) (*Package, error) {
	sector, err := validateManifest(&m)
	if err != nil {
		return nil, err
	}

	// Prepare Reverse Deltas if requested
	for i := range m.ReverseDeltas {
		rd := &m.ReverseDeltas[i]
		if rd.OldImage != nil {
			oldLen := len(rd.OldImage)
			if oldLen < 0 || oldLen > math.MaxUint32 {
				return nil, fmt.Errorf("%w: reverse delta OldImage size %d exceeds uint32", ErrLayoutOverflow, oldLen)
			}
			rd.RestoredSize = uint32(oldLen)
			rd.RestoredSHA256 = sha256.Sum256(rd.OldImage)
			if rd.Data == nil && len(m.Images) > 0 {
				var targetInstalled []byte
				for j := range m.Images {
					if m.Images[j].TargetSlot == rd.TargetSlot && m.Images[j].Installed != nil {
						targetInstalled = m.Images[j].Installed
						break
					}
				}
				if targetInstalled == nil {
					return nil, fmt.Errorf("cannot derive reverse delta: no installed image for slot %d", rd.TargetSlot)
				}
				rdelta, rErr := tds1.GenerateDelta(targetInstalled, rd.OldImage)
				if rErr != nil {
					return nil, fmt.Errorf("generate reverse delta: %w", rErr)
				}
				recon, aErr := tds1.Apply(targetInstalled, rdelta)
				if aErr != nil || !bytes.Equal(recon, rd.OldImage) {
					return nil, errors.New("reverse delta roundtrip verification failed")
				}
				rdeltaLen := len(rdelta)
				if rdeltaLen < 0 || rdeltaLen > math.MaxUint32 {
					return nil, fmt.Errorf("%w: reverse delta size %d exceeds uint32", ErrLayoutOverflow, rdeltaLen)
				}
				rd.Data = rdelta
				rd.StoredSize = uint32(rdeltaLen)
				rd.DeltaAlg = DeltaTDS1
			}
		}
		if rd.StoredSize == 0 && rd.Data != nil {
			rdLen := len(rd.Data)
			if rdLen < 0 || rdLen > math.MaxUint32 {
				return nil, fmt.Errorf("%w: reverse delta data size %d exceeds uint32", ErrLayoutOverflow, rdLen)
			}
			rd.StoredSize = uint32(rdLen)
		}
		if rd.StoredSize == 0 {
			return nil, fmt.Errorf("reverse delta for slot %d has 0 stored size", rd.TargetSlot)
		}
		if rd.DeltaAlg == 0 {
			rd.DeltaAlg = DeltaTDS1
		}
	}

	plans, hashBytes, err := planImages(m.Images)
	if err != nil {
		return nil, err
	}

	specs := make([]regionSpec, 0, MaxRegions)
	specs = append(specs, regionSpec{RegionChunkHashes, hashBytes, nil})
	if len(m.PQCSig) > 0 {
		specs = append(specs, regionSpec{RegionPQCSignature, uint64(len(m.PQCSig)), m.PQCSig})
	}
	if len(m.PQCPubkey) > 0 {
		specs = append(specs, regionSpec{RegionPQCPubkey, uint64(len(m.PQCPubkey)), m.PQCPubkey})
	}
	if len(m.DeviceBind) > 0 {
		specs = append(specs, regionSpec{RegionDeviceBind, uint64(len(m.DeviceBind)), m.DeviceBind})
	}
	if len(m.ReverseDeltas) > 0 {
		rdeltaBytes := uint64(len(m.ReverseDeltas) * RDeltaDescSize)
		specs = append(specs, regionSpec{RegionReverseDelta, rdeltaBytes, nil})
	}

	regions, totalLen, err := layoutRegions(specs)
	if err != nil {
		return nil, err
	}

	block := make([]byte, totalLen)

	// Region descriptors occupy table slots in layout order; slot i is region i.
	for i, r := range regions {
		base := offRegions + i*regionStride
		binary.LittleEndian.PutUint16(block[base:], r.id)
		binary.LittleEndian.PutUint32(block[base+4:], r.off)
		binary.LittleEndian.PutUint32(block[base+8:], r.len)
		if r.data != nil {
			copy(block[int(r.off):int(r.off)+int(r.len)], r.data)
		}
	}

	// The expensive part. Digests are written straight into their region — no
	// intermediate buffer. specs[0] is always RegionChunkHashes, hence regions[0].
	hr := regions[0]
	autoSBOM := m.AutoSBOM && len(m.SBOMDigest) == 0
	sbom, err := e.fillDigests(block[int(hr.off):int(hr.off)+int(hr.len)], plans, autoSBOM)
	if err != nil {
		return nil, err
	}

	writeFixedHeader(block, &m, len(plans), totalLen, sbom, autoSBOM)

	dataOff, storedLen, nextCursor, err := writeImageTable(block, plans, totalLen, sector, m.TrailerLayout)
	if err != nil {
		return nil, err
	}

	trailerCursor := nextCursor
	var rdeltaPayloads []PayloadInfo
	if len(m.ReverseDeltas) > 0 {
		var rdeltaRegion *regionPlan
		for i := range regions {
			if regions[i].id == RegionReverseDelta {
				rdeltaRegion = &regions[i]
				break
			}
		}
		if rdeltaRegion == nil {
			return nil, errors.New("missing reverse delta region plan")
		}
		rdeltaBytes := make([]byte, len(m.ReverseDeltas)*RDeltaDescSize)
		rCursor := nextCursor
		for idx, rd := range m.ReverseDeltas {
			rCursor = alignUp64(rCursor, uint64(sector))
			if rCursor > math.MaxUint32 || rCursor+uint64(rd.StoredSize) > MaxImageLen {
				return nil, fmt.Errorf("%w: reverse delta %d ends at staging offset %d, past the uint32 limit",
					ErrLayoutOverflow, idx, rCursor+uint64(rd.StoredSize))
			}
			desc := RDeltaDesc{
				TargetSlot:     rd.TargetSlot,
				DeltaAlg:       rd.DeltaAlg,
				DataOff:        uint32(rCursor),
				StoredSize:     rd.StoredSize,
				RestoredSize:   rd.RestoredSize,
				RestoredSHA256: rd.RestoredSHA256,
			}
			copy(rdeltaBytes[idx*RDeltaDescSize:(idx+1)*RDeltaDescSize], desc.Serialize())
			rdeltaPayloads = append(rdeltaPayloads, PayloadInfo{
				TargetSlot: rd.TargetSlot,
				Offset:     uint32(rCursor),
				Length:     rd.StoredSize,
				Data:       rd.Data,
				IsRDelta:   true,
			})
			rCursor += uint64(rd.StoredSize)
		}
		copy(block[rdeltaRegion.off:rdeltaRegion.off+rdeltaRegion.len], rdeltaBytes)
		trailerCursor = rCursor
	}

	var trailerOffset uint32
	if m.TrailerLayout {
		aligned := alignUp64(trailerCursor, uint64(sector))
		if aligned > math.MaxUint32 || aligned+uint64(totalLen)+TrailerLocatorLen > MaxImageLen {
			return nil, fmt.Errorf("%w: trailer TBM1 offset %d overflows uint32", ErrLayoutOverflow, aligned)
		}
		trailerOffset = uint32(aligned)
	}

	binary.LittleEndian.PutUint32(block[offFixedCRC32:], headerCRC(block))

	payloads := make([]PayloadInfo, 0, len(plans)+len(rdeltaPayloads))
	for i := range plans {
		p := &plans[i]
		payloads = append(payloads, PayloadInfo{
			TargetSlot: p.targetSlot,
			Offset:     dataOff[i],
			Length:     p.storedLen,
			Data:       p.storedData,
			IsRDelta:   false,
		})
	}
	payloads = append(payloads, rdeltaPayloads...)

	pkg := &Package{
		Block:         block,
		TotalLen:      totalLen,
		SignedLen:     totalLen - SigLen,
		DataOff:       dataOff,
		StoredLen:     storedLen,
		Payloads:      payloads,
		SectorSize:    sector,
		TrailerLayout: m.TrailerLayout,
		TrailerOffset: trailerOffset,
	}
	if err := validateBlock(block); err != nil {
		return nil, fmt.Errorf("tbm1: internal self-check failed: %w", err)
	}
	return pkg, nil
}

// validateManifest checks everything that does not depend on image geometry and
// returns the effective sector size.
func validateManifest(m *Manifest) (uint32, error) {
	if n := len(m.Images); n < 1 || n > MaxImages {
		return 0, fmt.Errorf("%w: image_count %d out of [1..%d]", ErrInvalidManifest, n, MaxImages)
	}
	if l := len(m.DeviceBind); l != 0 && l != 32 {
		return 0, fmt.Errorf("%w: DeviceBind must be 0 or 32 bytes, got %d", ErrInvalidManifest, l)
	}
	if l := len(m.SBOMDigest); l != 0 && l != 32 {
		return 0, fmt.Errorf("%w: SBOMDigest must be 0 or 32 bytes, got %d", ErrInvalidManifest, l)
	}
	// A PQC signature without its public key (or vice versa) would silently
	// leave CritPQCRequired clear — a downgrade to Ed25519-only. Refuse.
	if (len(m.PQCSig) == 0) != (len(m.PQCPubkey) == 0) {
		return 0, fmt.Errorf("%w: PQCSig and PQCPubkey must both be set or both be empty", ErrInvalidManifest)
	}
	if m.HWRevMin > m.HWRevMax {
		return 0, fmt.Errorf("%w: hw_rev range [%d..%d] is empty", ErrInvalidManifest, m.HWRevMin, m.HWRevMax)
	}
	// Demanding a reader newer than the format we emit bricks the update path.
	if m.MinReaderMajor > VersionMajor ||
		(m.MinReaderMajor == VersionMajor && m.MinReaderMinor > VersionMinor) {
		return 0, fmt.Errorf("%w: min_reader %d.%d exceeds emitted format %d.%d",
			ErrInvalidManifest, m.MinReaderMajor, m.MinReaderMinor, VersionMajor, VersionMinor)
	}

	sector := m.SectorSize
	if sector == 0 {
		sector = DefaultSectorSize
	}
	if !isPow2U32(sector) || sector > MaxSectorSize {
		return 0, fmt.Errorf("%w: sector_size %d must be a power of two ≤ %d",
			ErrInvalidManifest, sector, MaxSectorSize)
	}
	return sector, nil
}

// planImages validates every image and derives its chunk geometry.
func planImages(images []Image) ([]imagePlan, uint64, error) {
	plans := make([]imagePlan, len(images))
	var slotUsed [SlotStage1 + 1]bool
	var hashBytes uint64

	for i := range images {
		im := &images[i]

		src, installedLen, err := resolveInstalled(im, i)
		if err != nil {
			return nil, 0, err
		}
		storedLen, err := resolveStored(im, installedLen, i)
		if err != nil {
			return nil, 0, err
		}
		if l := len(im.BaseFingerprint); l != 0 && l != 8 {
			return nil, 0, fmt.Errorf("%w: image %d BaseFingerprint must be 0 or 8 bytes, got %d",
				ErrInvalidManifest, i, l)
		}
		if im.TargetSlot > SlotStage1 || im.CompAlg > CompLZ4 || im.DeltaAlg > DeltaTDS1 {
			return nil, 0, fmt.Errorf("%w: image %d has an out-of-range slot/alg field", ErrInvalidManifest, i)
		}
		if slotUsed[im.TargetSlot] {
			return nil, 0, fmt.Errorf("%w: two images target slot %d", ErrInvalidManifest, im.TargetSlot)
		}
		slotUsed[im.TargetSlot] = true

		cs := im.ChunkSize
		if cs == 0 {
			cs = DefaultChunkSize
		}
		if cs < MinChunkSize || cs > MaxChunkSize {
			return nil, 0, fmt.Errorf("%w: image %d chunk_size %d outside [%d..%d]",
				ErrInvalidManifest, i, cs, MinChunkSize, MaxChunkSize)
		}

		numChunks := ceilDivU32(installedLen, cs)
		plans[i] = imagePlan{
			src:           src,
			installedLen:  installedLen,
			storedLen:     storedLen,
			chunkSize:     cs,
			numChunks:     numChunks,
			hashOff:       hashBytes,
			payloadOffset: im.PayloadOffset,
			tailGap:       im.TailGap,
			storedData:    im.Stored,

			typ:        im.Type,
			targetSlot: im.TargetSlot,
			compAlg:    im.CompAlg,
			deltaAlg:   im.DeltaAlg,
			baseSVN:    im.BaseSVN,
			verMajor:   im.VerMajor,
			verMinor:   im.VerMinor,
			verPatch:   im.VerPatch,
		}
		copy(plans[i].baseFP[:], im.BaseFingerprint)

		hashBytes += uint64(numChunks) * DigestLen
		if hashBytes > MaxManifestLen-FixedLen-SigLen {
			return nil, 0, fmt.Errorf("%w: chunk-hash region would need %d bytes", ErrLayoutOverflow, hashBytes)
		}
	}
	return plans, hashBytes, nil
}

// resolveInstalled picks the in-memory or the streaming source and returns the
// installed length. Exactly one of the two must be supplied.
func resolveInstalled(im *Image, i int) (chunkSource, uint32, error) {
	inMem := im.Installed != nil
	streamed := im.InstalledAt != nil
	switch {
	case inMem == streamed:
		return chunkSource{}, 0, fmt.Errorf(
			"%w: image %d must set exactly one of Installed and InstalledAt", ErrInvalidManifest, i)

	case inMem:
		instLen := len(im.Installed)
		if instLen == 0 {
			return chunkSource{}, 0, fmt.Errorf("%w: image %d has an empty installed image", ErrInvalidManifest, i)
		}
		if instLen < 0 || instLen > math.MaxUint32 {
			return chunkSource{}, 0, fmt.Errorf("%w: image %d installed size exceeds uint32", ErrLayoutOverflow, i)
		}
		n := uint32(instLen)
		if im.InstalledSize != 0 && im.InstalledSize != n {
			return chunkSource{}, 0, fmt.Errorf("%w: image %d InstalledSize %d != len(Installed) %d",
				ErrInvalidManifest, i, im.InstalledSize, n)
		}
		return chunkSource{mem: im.Installed}, n, nil

	default:
		if im.InstalledSize == 0 {
			return chunkSource{}, 0, fmt.Errorf("%w: image %d needs InstalledSize alongside InstalledAt",
				ErrInvalidManifest, i)
		}
		return chunkSource{at: im.InstalledAt}, im.InstalledSize, nil
	}
}

// resolveStored derives the staged payload size. Only the size is ever needed
// during encoding, so a caller may pass StoredSize and keep the compressed
// bytes out of this process entirely.
func resolveStored(im *Image, installedLen uint32, i int) (uint32, error) {
	if im.Stored != nil {
		storedLen := len(im.Stored)
		if storedLen < 0 || storedLen > math.MaxUint32 {
			return 0, fmt.Errorf("%w: image %d stored size exceeds uint32", ErrLayoutOverflow, i)
		}
		n := uint32(storedLen)
		if im.StoredSize != 0 && im.StoredSize != n {
			return 0, fmt.Errorf("%w: image %d StoredSize %d != len(Stored) %d",
				ErrInvalidManifest, i, im.StoredSize, n)
		}
		if im.DeltaAlg == DeltaTDS1 {
			tdsHdr, err := tds1.ParseHeader(im.Stored)
			if err != nil {
				return 0, fmt.Errorf("%w: image %d invalid TDS1 header: %w", ErrInvalidManifest, i, err)
			}
			if tdsHdr.ExpectedTargetSize != installedLen {
				return 0, fmt.Errorf("%w: image %d TDS1 target size %d != installed size %d",
					ErrInvalidManifest, i, tdsHdr.ExpectedTargetSize, installedLen)
			}
			if len(im.BaseFingerprint) == 0 {
				im.BaseFingerprint = append([]byte(nil), tdsHdr.BaseFingerprint[:]...)
			} else if !bytes.Equal(im.BaseFingerprint, tdsHdr.BaseFingerprint[:]) {
				return 0, fmt.Errorf("%w: image %d BaseFingerprint does not match TDS1 header", ErrInvalidManifest, i)
			}
		}
		return n, nil
	}

	// Auto-compression with Heatshrink
	if im.CompAlg == CompHeatshrink && im.Installed != nil {
		comp, err := heatshrink.Compress(im.Installed)
		if err != nil {
			return 0, fmt.Errorf("compress image %d: %w", i, err)
		}
		decomp, err := heatshrink.Decompress(comp)
		if err != nil || !bytes.Equal(decomp, im.Installed) {
			return 0, fmt.Errorf("heatshrink roundtrip verification failed for image %d", i)
		}
		compLen := len(comp)
		if compLen < 0 || compLen > math.MaxUint32 {
			return 0, fmt.Errorf("%w: compressed image %d exceeds uint32", ErrLayoutOverflow, i)
		}
		im.Stored = comp
		im.StoredSize = uint32(compLen)
		return im.StoredSize, nil
	}

	// Auto-delta with TDS1
	if im.DeltaAlg == DeltaTDS1 && im.Installed != nil && im.Base != nil {
		delta, err := tds1.GenerateDelta(im.Base, im.Installed)
		if err != nil {
			return 0, fmt.Errorf("generate delta for image %d: %w", i, err)
		}
		recon, err := tds1.Apply(im.Base, delta)
		if err != nil || !bytes.Equal(recon, im.Installed) {
			return 0, fmt.Errorf("tds1 roundtrip verification failed for image %d", i)
		}
		deltaLen := len(delta)
		if deltaLen < 0 || deltaLen > math.MaxUint32 {
			return 0, fmt.Errorf("%w: delta image %d exceeds uint32", ErrLayoutOverflow, i)
		}
		im.Stored = delta
		im.StoredSize = uint32(deltaLen)
		if len(im.BaseFingerprint) == 0 {
			h := sha256.Sum256(im.Base)
			im.BaseFingerprint = append([]byte(nil), h[:8]...)
		}
		return im.StoredSize, nil
	}

	if im.StoredSize != 0 {
		return im.StoredSize, nil
	}
	return installedLen, nil // raw staging copy
}

// layoutRegions assigns ascending, 8-byte-aligned offsets. The alignment gaps
// stay inside the signed area, so they cost nothing security-wise but let the
// C reader cast region payloads without unaligned loads.
func layoutRegions(specs []regionSpec) ([]regionPlan, uint32, error) {
	if len(specs) > MaxRegions {
		return nil, 0, fmt.Errorf("%w: %d regions exceed max %d", ErrInvalidManifest, len(specs), MaxRegions)
	}
	regions := make([]regionPlan, len(specs))
	cursor := uint64(FixedLen)
	for i, s := range specs {
		off := alignUp64(cursor, 8)
		cursor = off + s.size
		if off > math.MaxUint32 || s.size > math.MaxUint32 || cursor+SigLen > MaxManifestLen {
			return nil, 0, fmt.Errorf("%w: manifest block would exceed %d bytes", ErrLayoutOverflow, MaxManifestLen)
		}
		regions[i] = regionPlan{id: s.id, off: uint32(off), len: uint32(s.size), data: s.data}
	}
	totalBlockLen := cursor + SigLen
	if totalBlockLen > math.MaxUint32 {
		return nil, 0, fmt.Errorf("%w: manifest block exceeds uint32", ErrLayoutOverflow)
	}
	return regions, uint32(totalBlockLen), nil
}

// writeFixedHeader fills the 512-byte fixed header except the trailing CRC.
func writeFixedHeader(block []byte, m *Manifest, imageCount int, totalLen uint32, sbom [32]byte, useSBOM bool) {
	hdr := block[:FixedLen] // constant-bound slice: no repeated bounds checks
	le := binary.LittleEndian

	var flagsCritical, flagsInfo uint16
	if len(m.PQCSig) > 0 && len(m.PQCPubkey) > 0 {
		flagsCritical |= CritPQCRequired
	}
	if m.TrailerLayout {
		flagsCritical |= CritTrailerLayout
	}
	if len(m.DeviceBind) == 32 {
		flagsInfo |= InfoDeviceBind
	}

	le.PutUint32(hdr[offMagic:], Magic)
	hdr[offVersionMajor] = VersionMajor
	hdr[offVersionMinor] = VersionMinor
	le.PutUint16(hdr[offFixedLen:], FixedLen)
	le.PutUint32(hdr[offTotalLen:], totalLen)
	le.PutUint16(hdr[offFlagsCritical:], flagsCritical)
	le.PutUint16(hdr[offFlagsInfo:], flagsInfo)
	le.PutUint16(hdr[offVendorID:], m.VendorID)
	le.PutUint16(hdr[offProductID:], m.ProductID)
	le.PutUint16(hdr[offHWRevMin:], m.HWRevMin)
	le.PutUint16(hdr[offHWRevMax:], m.HWRevMax)
	hdr[offKeyIndex] = m.KeyIndex
	if imageCount >= 0 && imageCount <= math.MaxUint8 {
		hdr[offImageCount] = uint8(imageCount)
	}
	le.PutUint16(hdr[offBootRetryLimit:], m.BootRetryLimit)
	le.PutUint16(hdr[offMinReaderMajor:], m.MinReaderMajor)
	le.PutUint16(hdr[offMinReaderMinor:], m.MinReaderMinor)
	le.PutUint32(hdr[offSVN:], m.SVN)
	le.PutUint32(hdr[offStage1SVN:], m.Stage1SVN)
	le.PutUint32(hdr[offKeyEpoch:], m.KeyEpoch)
	le.PutUint32(hdr[offBuildNumber:], m.BuildNumber)
	le.PutUint16(hdr[offFwVerMajor:], m.FwVerMajor)
	le.PutUint16(hdr[offFwVerMinor:], m.FwVerMinor)
	le.PutUint16(hdr[offFwVerPatch:], m.FwVerPatch)

	// An explicit digest always wins over AutoSBOM.
	switch {
	case len(m.SBOMDigest) == 32:
		copy(hdr[offSBOMDigest:offSBOMDigest+32], m.SBOMDigest)
	case useSBOM:
		copy(hdr[offSBOMDigest:offSBOMDigest+32], sbom[:])
	}
}

// writeImageTable fills the image descriptors and returns the staging layout.
// Payload areas start after the signed block and are sector-aligned so a flash
// driver can erase and program them independently.
func writeImageTable(block []byte, plans []imagePlan, totalLen, sector uint32, trailerLayout bool) (dataOff, storedLen []uint32, nextCursor uint64, err error) {
	le := binary.LittleEndian
	dataOff = make([]uint32, len(plans))
	storedLen = make([]uint32, len(plans))

	cursor := alignUp64(uint64(totalLen), uint64(sector))
	if trailerLayout {
		cursor = 0
	}
	for i := range plans {
		p := &plans[i]
		if trailerLayout && i == 0 {
			if p.compAlg == CompNone && p.deltaAlg == DeltaNone {
				if p.payloadOffset > 0 {
					return nil, nil, 0, fmt.Errorf("%w: trailer-layout raw primary image must have payload_offset == 0", ErrInvalidManifest)
				}
			} else if p.payloadOffset == 0 {
				cursor = alignUp64(uint64(p.installedLen), uint64(sector))
			}
		}
		if p.payloadOffset > 0 {
			cursor = alignUp64(cursor+uint64(p.payloadOffset), uint64(sector))
		}
		// The reader adds data_off + stored_len in uint32 arithmetic, so the
		// payload *end* — not just its start — has to stay below 2^32.
		end := cursor + uint64(p.storedLen)
		if end > MaxImageLen {
			return nil, nil, 0, fmt.Errorf("%w: image %d ends at staging offset %d, past the uint32 limit",
				ErrLayoutOverflow, i, end)
		}
		base := offImages + i*imageStride
		e := block[base : base+imageStride]

		e[imgType] = p.typ
		e[imgTargetSlot] = p.targetSlot
		e[imgCompAlg] = p.compAlg
		e[imgDeltaAlg] = p.deltaAlg
		le.PutUint32(e[imgDataOff:], uint32(cursor))
		le.PutUint32(e[imgStoredLen:], p.storedLen)
		le.PutUint32(e[imgInstalled:], p.installedLen)
		le.PutUint32(e[imgChunkSize:], p.chunkSize)
		le.PutUint32(e[imgNumChunks:], p.numChunks)
		le.PutUint32(e[imgBaseSVN:], p.baseSVN)
		le.PutUint16(e[imgVerMajor:], p.verMajor)
		le.PutUint16(e[imgVerMinor:], p.verMinor)
		le.PutUint16(e[imgVerPatch:], p.verPatch)
		copy(e[imgBaseFP:imgBaseFP+8], p.baseFP[:])

		dataOff[i] = uint32(cursor)
		storedLen[i] = p.storedLen
		cursor = alignUp64(end, uint64(sector))
		if p.tailGap > 0 {
			cursor = alignUp64(cursor+uint64(p.tailGap), uint64(sector))
		}
	}
	return dataOff, storedLen, cursor, nil
}

// ---- Digest phase -------------------------------------------------------

// errBox collects the first error out of a set of workers and lets the others
// notice they should stop.
type errBox struct {
	flag atomic.Bool
	mu   sync.Mutex
	err  error
}

func (b *errBox) set(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()
	b.flag.Store(true)
}

func (b *errBox) failed() bool { return b.flag.Load() }

func (b *errBox) get() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// fillDigests writes every chunk digest into region and, when asked, computes
// the SBOM digest over the first image.
//
// The SBOM pass is a second full SHA-256 over that image — on its own as
// expensive as all the chunk hashes together — so it runs concurrently with
// them whenever more than one goroutine is allowed.
func (e *Encoder) fillDigests(region []byte, plans []imagePlan, wantSBOM bool) ([32]byte, error) {
	var (
		box  errBox
		sbom [32]byte
		wg   sync.WaitGroup
	)
	concurrentSBOM := wantSBOM && e.maxGoroutines() > 1
	if concurrentSBOM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := sbomDigest(plans[0].src, plans[0].installedLen)
			if err != nil {
				box.set(err)
				return
			}
			sbom = d
		}()
	}

	for i := range plans {
		p := &plans[i]
		lo := p.hashOff
		hi := lo + uint64(p.numChunks)*DigestLen
		e.hashImage(region[lo:hi], p, &box)
		if box.failed() {
			break
		}
	}
	wg.Wait()

	if err := box.get(); err != nil {
		return sbom, err
	}
	if wantSBOM && !concurrentSBOM {
		return sbomDigest(plans[0].src, plans[0].installedLen)
	}
	return sbom, nil
}

// hashImage fills dst with the SHA-256 of each chunk of p, dst[k] covering
// chunk k.
//
// Work is handed out dynamically through a shared cursor rather than
// partitioned up front. A static split by chunk index is only balanced when
// every chunk costs the same, which stops being true the moment two images use
// different chunk sizes, and it cannot react to the host process competing for
// CPU. The dynamic split bounds the imbalance by a single stripe instead.
func (e *Encoder) hashImage(dst []byte, p *imagePlan, box *errBox) {
	workers := e.hashWorkers(p)
	if workers <= 1 {
		if err := hashRange(dst, p, p.newScratch(), 0, uint64(p.numChunks)); err != nil {
			box.set(err)
		}
		return
	}
	stripe := stripeChunks(p, workers)

	var (
		next atomic.Uint64
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scratch := p.newScratch()
			for {
				lo := next.Add(stripe) - stripe
				if lo >= uint64(p.numChunks) || box.failed() {
					return
				}
				hi := lo + stripe
				if hi > uint64(p.numChunks) {
					hi = uint64(p.numChunks)
				}
				if err := hashRange(dst, p, scratch, lo, hi); err != nil {
					box.set(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// newScratch returns a private chunk buffer, or nil for in-memory payloads,
// which are hashed straight out of the caller's slice.
func (p *imagePlan) newScratch() []byte {
	if p.src.streamed() {
		return make([]byte, p.chunkSize)
	}
	return nil
}

// hashRange hashes chunks [lo, hi) of one image.
func hashRange(dst []byte, p *imagePlan, scratch []byte, lo, hi uint64) error {
	size := uint64(p.installedLen)
	for g := lo; g < hi; g++ {
		off := g * uint64(p.chunkSize)
		n := uint64(p.chunkSize)
		if off+n > size { // the tail chunk is short unless chunkSize divides size
			n = size - off
		}
		if n > math.MaxUint32 {
			return fmt.Errorf("%w: chunk size %d overflows uint32", ErrLayoutOverflow, n)
		}
		buf, err := p.src.read(scratch, off, uint32(n))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(buf)
		copy(dst[g*DigestLen:(g+1)*DigestLen], sum[:])
	}
	return nil
}

// stripeChunks sizes one hand-out. Two forces pull against each other:
//
//	too large  — the last stripe becomes the tail that everyone waits for, and
//	             with fewer stripes than workers some workers get nothing;
//	too small  — the shared cursor turns into the bottleneck.
//
// So aim for hashStripeBytes of payload, but never take more than a quarter of
// one worker's share, which leaves at least four hand-outs per worker to
// balance with. The cache-line rounding is applied only when the stripe is
// already that big; buying alignment at the price of parallelism would be a bad
// trade, since false sharing costs one line per boundary and nothing more.
func stripeChunks(p *imagePlan, workers int) uint64 {
	if workers < 1 {
		workers = 1
	}
	s := uint64(ceilDivU32(hashStripeBytes, p.chunkSize))
	if fair := uint64(p.numChunks) / uint64(4*workers); fair < s {
		s = fair
	}
	if s < 1 {
		s = 1
	}
	if s >= digestsPerLine {
		s = alignUp64(s, digestsPerLine)
	}
	return s
}

func (e *Encoder) maxGoroutines() int {
	if e.Parallelism > 0 {
		return e.Parallelism
	}
	return runtime.GOMAXPROCS(0)
}

// hashWorkers decides how many goroutines this image is worth, bounded by the
// available work, the caller's budget and the scratch-memory limit.
func (e *Encoder) hashWorkers(p *imagePlan) int {
	if uint64(p.installedLen) < minParallelBytes {
		return 1
	}
	w := e.maxGoroutines()

	if p.src.streamed() { // one chunk-sized buffer per worker
		limit := e.ScratchLimit
		if limit <= 0 {
			limit = defaultScratchLimit
		}
		if affordable := limit / int(p.chunkSize); affordable < w {
			w = affordable
		}
	}
	if w < 1 {
		w = 1
	}
	if uint64(w) > uint64(p.numChunks) {
		w = int(p.numChunks)
	}
	if w < 1 {
		w = 1
	}
	return w
}

// sbomDigest is SHA-256 over a whole installed image.
func sbomDigest(src chunkSource, size uint32) ([32]byte, error) {
	h := sha256.New()
	if src.mem != nil {
		_, _ = h.Write(src.mem) // hash.Hash.Write never returns an error
	} else {
		buf := make([]byte, sbomCopyBuffer)
		if _, err := io.CopyBuffer(h, io.NewSectionReader(src.at, 0, int64(size)), buf); err != nil {
			return [32]byte{}, fmt.Errorf("%w: SBOM pass: %w", ErrPayload, err)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ---- Package operations -------------------------------------------------

// SignedMessage is the exact byte range the Ed25519 signature covers. Send this
// (or the whole unsigned Block) to a remote signer.
func (p *Package) SignedMessage() []byte { return p.Block[:p.SignedLen] }

// Signature returns the 64-byte signature slot, zero until the package is signed.
func (p *Package) Signature() []byte { return p.Block[p.SignedLen:p.TotalLen] }

// SetSignature writes a 64-byte signature into the trailing slot.
func (p *Package) SetSignature(sig []byte) error {
	if len(sig) != SigLen {
		return fmt.Errorf("tbm1: signature must be %d bytes, got %d", SigLen, len(sig))
	}
	copy(p.Block[p.SignedLen:p.TotalLen], sig)
	p.Signed = true
	return nil
}

// flatSize validates the payload sizes against the header and returns the size
// of the assembled staging image (including any Region 6 reverse-delta streams).
func (p *Package) flatSize(sizes []uint64) (uint64, error) {
	if !p.Signed {
		return 0, ErrUnsigned
	}
	if len(sizes) != len(p.DataOff) {
		return 0, fmt.Errorf("tbm1: got %d payloads, want %d", len(sizes), len(p.DataOff))
	}
	end := uint64(p.TotalLen)
	for i, n := range sizes {
		if n != uint64(p.StoredLen[i]) {
			return 0, fmt.Errorf("tbm1: image %d payload is %d bytes, header says %d", i, n, p.StoredLen[i])
		}
		if uint64(p.DataOff[i]) < end {
			return 0, fmt.Errorf("tbm1: image %d payload overlaps the preceding region", i)
		}
		end = uint64(p.DataOff[i]) + n
	}
	for _, pay := range p.Payloads {
		if !pay.IsRDelta {
			continue
		}
		if uint64(len(pay.Data)) != uint64(pay.Length) {
			return 0, fmt.Errorf("%w: reverse-delta payload for slot %d is %d bytes, header says %d",
				ErrPayload, pay.TargetSlot, len(pay.Data), pay.Length)
		}
		if uint64(pay.Offset) < end {
			return 0, fmt.Errorf("%w: reverse-delta payload at %d overlaps preceding data ending at %d",
				ErrLayoutOverflow, pay.Offset, end)
		}
		end = uint64(pay.Offset) + uint64(pay.Length)
	}
	return end, nil
}

func blobSizes(stored [][]byte) []uint64 {
	sizes := make([]uint64, len(stored))
	for i, b := range stored {
		sizes[i] = uint64(len(b))
	}
	return sizes
}

// AssembleFlat produces the full staging image in memory: signed block, then
// each image's stored bytes at its data_off (plus any Region 6 reverse-delta
// payloads). stored[i] pairs with image i and must match the size recorded in
// the header; alignment gaps are zero-filled.
//
// Prefer StreamFlat for anything large — this allocates the whole bundle.
func (p *Package) AssembleFlat(stored [][]byte) ([]byte, error) {
	end, err := p.flatSize(blobSizes(stored))
	if err != nil {
		return nil, err
	}
	if end > uint64(maxInt) {
		return nil, fmt.Errorf("%w: flat image of %d bytes exceeds addressable memory", ErrLayoutOverflow, end)
	}
	out := make([]byte, end)
	copy(out, p.Block)
	for i, blob := range stored {
		copy(out[p.DataOff[i]:], blob)
	}
	for _, pay := range p.Payloads {
		if pay.IsRDelta {
			copy(out[pay.Offset:], pay.Data)
		}
	}
	return out, nil
}

// AssembleTrailer produces a Zero-Copy TrailerLayout bundle in memory:
// [image 0][sub-images...][reverse-deltas...][sector-aligned signed TBM1 block][16B TrailerLocator].
func (p *Package) AssembleTrailer(stored [][]byte) ([]byte, error) {
	if !p.Signed {
		return nil, ErrUnsigned
	}
	if !p.TrailerLayout {
		return nil, fmt.Errorf("%w: Package was not built with TrailerLayout", ErrInvalidManifest)
	}
	if len(stored) != len(p.DataOff) {
		return nil, fmt.Errorf("tbm1: got %d payloads, want %d", len(stored), len(p.DataOff))
	}
	var end uint64
	for i, blob := range stored {
		if uint64(len(blob)) != uint64(p.StoredLen[i]) {
			return nil, fmt.Errorf("tbm1: image %d payload is %d bytes, header says %d", i, len(blob), p.StoredLen[i])
		}
		if uint64(p.DataOff[i]) < end {
			return nil, fmt.Errorf("tbm1: image %d payload overlaps preceding payload", i)
		}
		end = uint64(p.DataOff[i]) + uint64(len(blob))
	}
	for _, pay := range p.Payloads {
		if !pay.IsRDelta {
			continue
		}
		if uint64(len(pay.Data)) != uint64(pay.Length) {
			return nil, fmt.Errorf("%w: reverse-delta payload for slot %d is %d bytes, header says %d",
				ErrPayload, pay.TargetSlot, len(pay.Data), pay.Length)
		}
		if uint64(pay.Offset) < end {
			return nil, fmt.Errorf("%w: reverse-delta payload at %d overlaps preceding payload ending at %d",
				ErrLayoutOverflow, pay.Offset, end)
		}
		end = uint64(pay.Offset) + uint64(pay.Length)
	}
	if uint64(p.TrailerOffset) < end {
		return nil, fmt.Errorf("%w: trailer offset %d overlaps payloads ending at %d", ErrLayoutOverflow, p.TrailerOffset, end)
	}
	totalBundle := uint64(p.TrailerOffset) + uint64(p.TotalLen) + TrailerLocatorLen
	if totalBundle > uint64(maxInt) {
		return nil, fmt.Errorf("%w: trailer bundle of %d bytes exceeds addressable memory", ErrLayoutOverflow, totalBundle)
	}
	out := make([]byte, totalBundle)
	for i, blob := range stored {
		copy(out[p.DataOff[i]:], blob)
	}
	for _, pay := range p.Payloads {
		if pay.IsRDelta {
			copy(out[pay.Offset:], pay.Data)
		}
	}
	copy(out[p.TrailerOffset:], p.Block)
	loc := EncodeTrailerLocator(p.TrailerOffset, p.TotalLen)
	copy(out[uint64(p.TrailerOffset)+uint64(p.TotalLen):], loc[:])
	return out, nil
}

// WriteFlat writes the same layout as AssembleFlat without materialising it.
func (p *Package) WriteFlat(w io.Writer, stored [][]byte) (int64, error) {
	if _, err := p.flatSize(blobSizes(stored)); err != nil {
		return 0, err
	}
	readers := make([]io.Reader, len(stored))
	for i, b := range stored {
		readers[i] = bytes.NewReader(b)
	}
	return p.StreamFlat(w, readers)
}

// StreamFlat writes the staging image, pulling each payload from a reader. It
// is the memory-clean path: nothing larger than the manifest block and a
// padding buffer is ever held. Each reader must yield exactly the stored_len
// recorded for its image — too few bytes is an error, extra bytes are ignored.
func (p *Package) StreamFlat(w io.Writer, payloads []io.Reader) (int64, error) {
	if len(payloads) != len(p.DataOff) {
		return 0, fmt.Errorf("tbm1: got %d payloads, want %d", len(payloads), len(p.DataOff))
	}
	sizes := make([]uint64, len(p.StoredLen))
	for i, n := range p.StoredLen {
		sizes[i] = uint64(n)
	}
	if _, err := p.flatSize(sizes); err != nil {
		return 0, err
	}

	written, err := w.Write(p.Block)
	total := int64(written)
	if err != nil {
		return total, err
	}
	for i, src := range payloads {
		target := int64(p.DataOff[i])
		gap := target - total
		if gap < 0 { // flatSize proved this cannot happen; belt and braces
			return total, fmt.Errorf("%w: image %d starts before the write cursor", ErrLayoutOverflow, i)
		}
		pad, err := writeZeros(w, uint64(gap))
		total += pad
		if err != nil {
			return total, err
		}
		want := int64(p.StoredLen[i])
		got, err := io.CopyN(w, src, want)
		total += got
		if err != nil {
			return total, fmt.Errorf("%w: image %d payload: %w", ErrPayload, i, err)
		}
		if got != want {
			return total, fmt.Errorf("%w: image %d yielded %d of %d bytes", ErrPayload, i, got, want)
		}
	}
	for _, pay := range p.Payloads {
		if !pay.IsRDelta {
			continue
		}
		target := int64(pay.Offset)
		gap := target - total
		if gap < 0 {
			return total, fmt.Errorf("%w: reverse-delta payload starts before the write cursor", ErrLayoutOverflow)
		}
		pad, err := writeZeros(w, uint64(gap))
		total += pad
		if err != nil {
			return total, err
		}
		nw, err := w.Write(pay.Data)
		total += int64(nw)
		if err != nil {
			return total, fmt.Errorf("%w: reverse-delta payload: %w", ErrPayload, err)
		}
	}
	return total, nil
}

var zeroPad [4096]byte

func writeZeros(w io.Writer, n uint64) (int64, error) {
	var written int64
	for n > 0 {
		step := uint64(len(zeroPad))
		if n < step {
			step = n
		}
		c, err := w.Write(zeroPad[:step])
		if c < 0 || uint64(c) > n {
			return written, io.ErrShortWrite
		}
		written += int64(c)
		if err != nil {
			return written, err
		}
		if c == 0 { // a Writer that neither progresses nor errors would spin here
			return written, io.ErrShortWrite
		}
		n -= uint64(c)
	}
	return written, nil
}
