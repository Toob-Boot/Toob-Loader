// Package tbm1 encodes and signs TBM1 v2 fixed-format boot manifests.
//
// It is designed to be driven as an API, not a CLI. Three layers, smallest to
// largest:
//
//	Library   — BuildUnsigned / Package / validateBlock: pure, no key, no I/O.
//	Signer    — an interface over "sign 64-byte Ed25519 over these bytes", so
//	            the private key can live in memory, a KMS, or an HSM. The build
//	            step never needs it (key-custody split).
//	HTTP       — NewHandler(Signer) exposes /build (keyless), /sign (key-holding),
//	            /package (both) and /verify as a mountable http.Handler.
//
// Every layout constant mirrors boot_tbm1.h byte-for-byte; the shared golden
// vectors exist to catch drift between this writer and the C reader.
//
// Flat on-flash package (as libtoob streams it into staging):
//
//	[ Fixed Header 512 ][ Variable Regions … ][ Ed25519 Signature 64 ][ Image Data … ]
//	                    \______ signed: [0 .. total_len-64) ______/
//
// The signature covers header + regions (chunk hashes, PQC blobs, device bind),
// NOT the raw image payload — payload integrity comes from the signed chunk hashes.
package tbm1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
)

// ---- Layout constants (mirror boot_tbm1.h) ------------------------------

const (
	Magic        = 0x314D4254 // 'TBM1' little-endian
	VersionMajor = 2
	VersionMinor = 0
	FixedLen     = 512
	SigLen       = 64
	MaxImages    = 4
	MaxRegions   = 8
	CRCLen       = FixedLen - 4
	DigestLen    = 32 // SHA-256 per chunk

	DefaultChunkSize  = 4096
	DefaultSectorSize = 4096
)

// Region IDs.
const (
	RegionNone         = 0
	RegionChunkHashes  = 1
	RegionPQCSignature = 2
	RegionPQCPubkey    = 3
	RegionDeviceBind   = 4
	RegionDeltaScript  = 5
)

// Compression / delta enums.
const (
	CompNone       = 0
	CompHeatshrink = 1
	CompLZ4        = 2

	DeltaNone    = 0
	DeltaBSDiff  = 1
	DeltaDETools = 2
)

// Target slots.
const (
	SlotApp      = 0
	SlotNetcore  = 1
	SlotRecovery = 2
	SlotStage1   = 3
)

// flags_critical / flags_info bits.
const (
	CritPQCRequired = 1 << 0
	InfoDeviceBind  = 1 << 0
)

// Fixed-header field offsets.
const (
	offMagic          = 0
	offVersionMajor   = 4
	offVersionMinor   = 5
	offFixedLen       = 6
	offTotalLen       = 8
	offFlagsCritical  = 12
	offFlagsInfo      = 14
	offVendorID       = 16
	offProductID      = 18
	offHWRevMin       = 20
	offHWRevMax       = 22
	offKeyIndex       = 24
	offImageCount     = 25
	offBootRetryLimit = 26
	offMinReaderMajor = 28
	offMinReaderMinor = 30
	offSVN            = 32
	offStage1SVN      = 36
	offKeyEpoch       = 40
	offBuildNumber    = 44
	offFwVerMajor     = 48
	offFwVerMinor     = 50
	offFwVerPatch     = 52
	offSBOMDigest     = 56
	offRegions        = 88
	offImages         = 184
	offReservedTail   = 360
	offFixedCRC32     = 508

	regionStride = 12
	imageStride  = 44
)

// ---- Public input types (also serve as JSON DTOs) -----------------------

// Image describes one component of an update bundle.
type Image struct {
	Type       uint8 `json:"type"`
	TargetSlot uint8 `json:"target_slot"`
	CompAlg    uint8 `json:"compression_alg"`
	DeltaAlg   uint8 `json:"delta_alg"`

	// Installed is the post-decompress/patch image; chunk hashes,
	// installed_size and num_chunks derive from it. Required.
	Installed []byte `json:"installed"`
	// Stored is what lands in staging (compressed/delta payload). nil = raw.
	Stored    []byte `json:"stored,omitempty"`

	ChunkSize uint32 `json:"chunk_size,omitempty"` // 0 → DefaultChunkSize
	BaseSVN   uint32 `json:"base_svn,omitempty"`

	VerMajor        uint16 `json:"ver_major,omitempty"`
	VerMinor        uint16 `json:"ver_minor,omitempty"`
	VerPatch        uint16 `json:"ver_patch,omitempty"`
	BaseFingerprint []byte `json:"base_fingerprint,omitempty"` // 0 or 8 bytes
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
	AutoSBOM   bool   `json:"auto_sbom,omitempty"`   // SBOM = SHA-256(images[0].Installed)

	DeviceBind []byte `json:"device_bind,omitempty"` // 0 or 32 bytes → InfoDeviceBind
	PQCSig     []byte `json:"pqc_sig,omitempty"`
	PQCPubkey  []byte `json:"pqc_pubkey,omitempty"`

	SectorSize uint32  `json:"sector_size,omitempty"` // data_off alignment; 0 → DefaultSectorSize
	Images     []Image `json:"images"`
}

// Package is the assembled manifest block plus derived metadata.
type Package struct {
	// Block is header(512) + regions + signature(64). After BuildUnsigned the
	// trailing 64 bytes are zero; Sign / SetSignature fill them.
	Block []byte `json:"-"`

	TotalLen  uint32   `json:"total_len"`
	SignedLen uint32   `json:"signed_len"` // TotalLen - 64
	DataOff   []uint32 `json:"data_off"`   // per-image staging offset (flat layout)
	Signed    bool     `json:"signed"`

	sectorSize uint32
}

// ---- Encoder (library, key-free) ----------------------------------------

func ceilDivU32(a, b uint32) uint32 {
	q := a / b
	if a%b != 0 {
		q++
	}
	return q // overflow-safe: never a+b-1
}

func alignUp(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

// BuildUnsigned assembles the manifest block with a zeroed signature slot.
// It re-runs the reader's checks, so a successful build cannot produce a
// manifest that tbm1_validate would reject.
func BuildUnsigned(m Manifest) (*Package, error) {
	n := len(m.Images)
	if n < 1 || n > MaxImages {
		return nil, fmt.Errorf("tbm1: image_count %d out of [1..%d]", n, MaxImages)
	}
	if l := len(m.DeviceBind); l != 0 && l != 32 {
		return nil, errors.New("tbm1: DeviceBind must be 32 bytes")
	}
	if l := len(m.SBOMDigest); l != 0 && l != 32 {
		return nil, errors.New("tbm1: SBOMDigest must be 32 bytes")
	}
	sector := m.SectorSize
	if sector == 0 {
		sector = DefaultSectorSize
	}

	type derived struct{ installed, stored, chunk, num uint32 }
	dv := make([]derived, n)
	var chunkHashes []byte

	for i := range m.Images {
		im := &m.Images[i]
		if len(im.Installed) == 0 {
			return nil, fmt.Errorf("tbm1: image %d empty Installed", i)
		}
		if len(im.BaseFingerprint) != 0 && len(im.BaseFingerprint) != 8 {
			return nil, fmt.Errorf("tbm1: image %d BaseFingerprint must be 8 bytes", i)
		}
		if im.TargetSlot > SlotStage1 || im.CompAlg > CompLZ4 || im.DeltaAlg > DeltaDETools {
			return nil, fmt.Errorf("tbm1: image %d bad slot/alg field", i)
		}
		cs := im.ChunkSize
		if cs == 0 {
			cs = DefaultChunkSize
		}
		stored := im.Stored
		if stored == nil {
			stored = im.Installed
		}
		installed := uint32(len(im.Installed))
		for off := uint32(0); off < installed; off += cs {
			end := off + cs
			if end > installed {
				end = installed
			}
			h := sha256.Sum256(im.Installed[off:end])
			chunkHashes = append(chunkHashes, h[:]...)
		}
		dv[i] = derived{installed, uint32(len(stored)), cs, ceilDivU32(installed, cs)}
	}

	// Regions, ascending offsets, 8-byte aligned starts (crypto-friendly;
	// the gaps stay inside the signed area, so they cost nothing security-wise).
	type region struct {
		id       uint16
		off, len uint32
		data     []byte
	}
	var regions []region
	cursor := uint32(FixedLen)
	add := func(id uint16, data []byte) {
		off := alignUp(cursor, 8)
		regions = append(regions, region{id, off, uint32(len(data)), data})
		cursor = off + uint32(len(data))
	}
	add(RegionChunkHashes, chunkHashes)
	if len(m.PQCSig) > 0 {
		add(RegionPQCSignature, m.PQCSig)
	}
	if len(m.PQCPubkey) > 0 {
		add(RegionPQCPubkey, m.PQCPubkey)
	}
	if len(m.DeviceBind) > 0 {
		add(RegionDeviceBind, m.DeviceBind)
	}
	if len(regions) > MaxRegions {
		return nil, fmt.Errorf("tbm1: %d regions exceed max %d", len(regions), MaxRegions)
	}

	totalLen := cursor + SigLen
	signedLen := totalLen - SigLen

	flagsCritical := uint16(0)
	flagsInfo := uint16(0)
	if len(m.PQCSig) > 0 && len(m.PQCPubkey) > 0 {
		flagsCritical |= CritPQCRequired
	}
	if len(m.DeviceBind) == 32 {
		flagsInfo |= InfoDeviceBind
	}

	sbom := m.SBOMDigest
	if len(sbom) == 0 && m.AutoSBOM {
		d := sha256.Sum256(m.Images[0].Installed)
		sbom = d[:]
	}

	block := make([]byte, totalLen)
	le := binary.LittleEndian
	le.PutUint32(block[offMagic:], Magic)
	block[offVersionMajor] = VersionMajor
	block[offVersionMinor] = VersionMinor
	le.PutUint16(block[offFixedLen:], FixedLen)
	le.PutUint32(block[offTotalLen:], totalLen)
	le.PutUint16(block[offFlagsCritical:], flagsCritical)
	le.PutUint16(block[offFlagsInfo:], flagsInfo)
	le.PutUint16(block[offVendorID:], m.VendorID)
	le.PutUint16(block[offProductID:], m.ProductID)
	le.PutUint16(block[offHWRevMin:], m.HWRevMin)
	le.PutUint16(block[offHWRevMax:], m.HWRevMax)
	block[offKeyIndex] = m.KeyIndex
	block[offImageCount] = uint8(n)
	le.PutUint16(block[offBootRetryLimit:], m.BootRetryLimit)
	le.PutUint16(block[offMinReaderMajor:], m.MinReaderMajor)
	le.PutUint16(block[offMinReaderMinor:], m.MinReaderMinor)
	le.PutUint32(block[offSVN:], m.SVN)
	le.PutUint32(block[offStage1SVN:], m.Stage1SVN)
	le.PutUint32(block[offKeyEpoch:], m.KeyEpoch)
	le.PutUint32(block[offBuildNumber:], m.BuildNumber)
	le.PutUint16(block[offFwVerMajor:], m.FwVerMajor)
	le.PutUint16(block[offFwVerMinor:], m.FwVerMinor)
	le.PutUint16(block[offFwVerPatch:], m.FwVerPatch)
	copy(block[offSBOMDigest:offSBOMDigest+32], sbom)

	for i, r := range regions {
		base := offRegions + i*regionStride
		le.PutUint16(block[base:], r.id)
		le.PutUint32(block[base+4:], r.off)
		le.PutUint32(block[base+8:], r.len)
		copy(block[r.off:r.off+r.len], r.data)
	}

	dataOff := make([]uint32, n)
	dataCursor := alignUp(totalLen, sector) // image payload begins after the signed block
	for i := range m.Images {
		im := &m.Images[i]
		d := dv[i]
		base := offImages + i*imageStride
		block[base+0] = im.Type
		block[base+1] = im.TargetSlot
		block[base+2] = im.CompAlg
		block[base+3] = im.DeltaAlg
		le.PutUint32(block[base+4:], dataCursor)
		le.PutUint32(block[base+8:], d.stored)
		le.PutUint32(block[base+12:], d.installed)
		le.PutUint32(block[base+16:], d.chunk)
		le.PutUint32(block[base+20:], d.num)
		le.PutUint32(block[base+24:], im.BaseSVN)
		le.PutUint16(block[base+28:], im.VerMajor)
		le.PutUint16(block[base+30:], im.VerMinor)
		le.PutUint16(block[base+32:], im.VerPatch)
		copy(block[base+36:base+44], im.BaseFingerprint)
		dataOff[i] = dataCursor
		dataCursor = alignUp(dataCursor+d.stored, sector)
	}

	le.PutUint32(block[offFixedCRC32:], crc32.ChecksumIEEE(block[:CRCLen]))

	pkg := &Package{Block: block, TotalLen: totalLen, SignedLen: signedLen, DataOff: dataOff, sectorSize: sector}
	if err := validateBlock(block); err != nil {
		return nil, fmt.Errorf("tbm1: internal self-check failed: %w", err)
	}
	return pkg, nil
}

// SignedMessage is the exact byte range the Ed25519 signature covers.
// Send this (or the whole unsigned Block) to a remote signer.
func (p *Package) SignedMessage() []byte { return p.Block[:p.SignedLen] }

// SetSignature writes a 64-byte signature into the trailing slot.
func (p *Package) SetSignature(sig []byte) error {
	if len(sig) != SigLen {
		return fmt.Errorf("tbm1: signature must be %d bytes, got %d", SigLen, len(sig))
	}
	copy(p.Block[p.SignedLen:p.TotalLen], sig)
	p.Signed = true
	return nil
}

// Sign fills the signature using a Signer (local or remote).
func (p *Package) Sign(s Signer) error {
	sig, err := s.Sign(p.SignedMessage())
	if err != nil {
		return err
	}
	return p.SetSignature(sig)
}

// AssembleFlat produces the full staging image: signed block, then each image's
// stored bytes placed at its data_off (sector-aligned). stored[i] pairs with
// image i. Requires the package to be signed.
func (p *Package) AssembleFlat(stored [][]byte) ([]byte, error) {
	if !p.Signed {
		return nil, errors.New("tbm1: cannot assemble an unsigned package")
	}
	if len(stored) != len(p.DataOff) {
		return nil, fmt.Errorf("tbm1: got %d stored blobs, want %d", len(stored), len(p.DataOff))
	}
	end := p.TotalLen
	for i := range stored {
		if e := p.DataOff[i] + uint32(len(stored[i])); e > end {
			end = e
		}
	}
	out := make([]byte, end)
	copy(out, p.Block)
	for i, blob := range stored {
		copy(out[p.DataOff[i]:], blob)
	}
	return out, nil
}

// ---- Signer abstraction (key custody) -----------------------------------

// Signer is the only thing that touches the private key. Implement it over a
// KMS/HSM in production; LocalSigner is for tests and self-hosted signing.
type Signer interface {
	Public() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

// LocalSigner holds an Ed25519 private key in process memory.
type LocalSigner struct{ priv ed25519.PrivateKey }

// NewLocalSigner wraps a raw 64-byte Ed25519 private key.
func NewLocalSigner(priv ed25519.PrivateKey) (*LocalSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("tbm1: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	return &LocalSigner{priv: priv}, nil
}

func (s *LocalSigner) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s *LocalSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// SignBlock validates an unsigned block is a well-formed TBM1 manifest, then
// signs it. This is the custody-safe primitive: the signer never signs bytes
// that are not a valid manifest — it is NOT a generic Ed25519 oracle.
func SignBlock(unsigned []byte, s Signer) ([]byte, error) {
	if err := validateBlock(unsigned); err != nil {
		return nil, fmt.Errorf("tbm1: refusing to sign malformed manifest: %w", err)
	}
	total := binary.LittleEndian.Uint32(unsigned[offTotalLen:])
	signedLen := total - SigLen
	sig, err := s.Sign(unsigned[:signedLen])
	if err != nil {
		return nil, err
	}
	if len(sig) != SigLen {
		return nil, fmt.Errorf("tbm1: signer returned %d bytes, want %d", len(sig), SigLen)
	}
	out := make([]byte, len(unsigned))
	copy(out, unsigned)
	copy(out[signedLen:total], sig)
	return out, nil
}

// Build is BuildUnsigned + Sign for callers that co-locate the key.
func Build(m Manifest, s Signer) (*Package, error) {
	pkg, err := BuildUnsigned(m)
	if err != nil {
		return nil, err
	}
	if err := pkg.Sign(s); err != nil {
		return nil, err
	}
	return pkg, nil
}

// ---- validateBlock: reader mirror, panic-safe on untrusted input --------

func validateBlock(b []byte) error {
	if len(b) < FixedLen {
		return errors.New("block shorter than fixed header")
	}
	le := binary.LittleEndian
	if le.Uint32(b[offMagic:]) != Magic {
		return errors.New("bad magic")
	}
	if le.Uint16(b[offFixedLen:]) != FixedLen {
		return errors.New("bad fixed_len")
	}
	if b[offVersionMajor] != VersionMajor {
		return errors.New("bad version_major")
	}
	total := le.Uint32(b[offTotalLen:])
	if total < FixedLen+SigLen {
		return errors.New("total_len too small")
	}
	if int(total) != len(b) {
		return fmt.Errorf("total_len %d != block length %d", total, len(b))
	}
	if le.Uint32(b[offFixedCRC32:]) != crc32.ChecksumIEEE(b[:CRCLen]) {
		return errors.New("crc mismatch")
	}
	sigStart := total - SigLen
	prevEnd := uint32(FixedLen)
	var seen uint16
	for i := 0; i < MaxRegions; i++ {
		base := offRegions + i*regionStride
		id := le.Uint16(b[base:])
		if id == RegionNone {
			continue
		}
		if id < 16 {
			bit := uint16(1) << id
			if seen&bit != 0 {
				return fmt.Errorf("duplicate region %d", id)
			}
			seen |= bit
		}
		off := le.Uint32(b[base+4:])
		ln := le.Uint32(b[base+8:])
		if off > sigStart || ln > sigStart-off {
			return fmt.Errorf("region %d out of bounds", id)
		}
		if off < prevEnd {
			return fmt.Errorf("region %d not ascending", id)
		}
		prevEnd = off + ln
	}
	nImg := int(b[offImageCount])
	if nImg < 1 || nImg > MaxImages {
		return fmt.Errorf("image_count %d out of range", nImg)
	}
	var chLen uint32
	foundCh := false
	for i := 0; i < MaxRegions; i++ {
		base := offRegions + i*regionStride
		if le.Uint16(b[base:]) == RegionChunkHashes {
			chLen = le.Uint32(b[base+8:])
			foundCh = true
			break
		}
	}
	if !foundCh {
		return errors.New("missing chunk-hash region")
	}
	var acc uint64
	for i := 0; i < nImg; i++ {
		base := offImages + i*imageStride
		installed := le.Uint32(b[base+12:])
		cs := le.Uint32(b[base+16:])
		nc := le.Uint32(b[base+20:])
		if cs == 0 || nc != ceilDivU32(installed, cs) {
			return fmt.Errorf("image %d chunk math", i)
		}
		acc += uint64(nc) * DigestLen
	}
	if acc != uint64(chLen) {
		return errors.New("chunk-hash length cross-check failed")
	}
	return nil
}

// ---- HTTP service layer (thin adapter over the library) -----------------

// NewHandler returns a mountable http.Handler exposing the encoder as an API:
//
//	POST /v1/package/build  {Manifest}          → {unsigned_block, total_len, signed_len, data_off}
//	POST /v1/package/sign   {unsigned_block}    → {signed_block, public_key}   (holds the key)
//	POST /v1/package        {Manifest}          → {signed_block, public_key, total_len, data_off}
//	POST /v1/verify         {block}             → {valid, reason}
//	GET  /v1/pubkey                             → {public_key}
//
// Pass signer=nil to run a build-only node (sign/package/pubkey then 501).
func NewHandler(signer Signer) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/package/build", func(w http.ResponseWriter, r *http.Request) {
		if !requirePOST(w, r) {
			return
		}
		var m Manifest
		if !decode(w, r, &m) {
			return
		}
		pkg, err := BuildUnsigned(m)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"unsigned_block": pkg.Block,
			"total_len":      pkg.TotalLen,
			"signed_len":     pkg.SignedLen,
			"data_off":       pkg.DataOff,
		})
	})

	mux.HandleFunc("/v1/package/sign", func(w http.ResponseWriter, r *http.Request) {
		if !requirePOST(w, r) || !requireSigner(w, signer) {
			return
		}
		var req struct {
			UnsignedBlock []byte `json:"unsigned_block"`
		}
		if !decode(w, r, &req) {
			return
		}
		signed, err := SignBlock(req.UnsignedBlock, signer)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"signed_block": signed,
			"public_key":   []byte(signer.Public()),
		})
	})

	mux.HandleFunc("/v1/package", func(w http.ResponseWriter, r *http.Request) {
		if !requirePOST(w, r) || !requireSigner(w, signer) {
			return
		}
		var m Manifest
		if !decode(w, r, &m) {
			return
		}
		pkg, err := Build(m, signer)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"signed_block": pkg.Block,
			"public_key":   []byte(signer.Public()),
			"total_len":    pkg.TotalLen,
			"data_off":     pkg.DataOff,
		})
	})

	mux.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		if !requirePOST(w, r) {
			return
		}
		var req struct {
			Block []byte `json:"block"`
		}
		if !decode(w, r, &req) {
			return
		}
		reason, valid := "", true
		if err := validateBlock(req.Block); err != nil {
			reason, valid = err.Error(), false
		} else if signer != nil {
			total := binary.LittleEndian.Uint32(req.Block[offTotalLen:])
			msg := req.Block[:total-SigLen]
			sig := req.Block[total-SigLen : total]
			if !ed25519.Verify(signer.Public(), msg, sig) {
				reason, valid = "signature does not verify against service key", false
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"valid": valid, "reason": reason})
	})

	mux.HandleFunc("/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("GET only"))
			return
		}
		if !requireSigner(w, signer) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"public_key": []byte(signer.Public())})
	})

	return mux
}

// ---- HTTP helpers -------------------------------------------------------

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return false
	}
	return true
}

func requireSigner(w http.ResponseWriter, s Signer) bool {
	if s == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("this node has no signer configured"))
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)) // 64 MiB cap
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad request body: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}