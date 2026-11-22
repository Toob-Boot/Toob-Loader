package build

import (
	"cmp"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"path/filepath"
	"slices"
	"strings"
)

const (
	BootromLayoutFlat      = "flat"
	BootromLayoutSegmented = "segmented"
	maxBootromImageSpan    = 64 << 20
	maxELFSectionHeaders   = 4096
	elfSHTArmExidx         = elf.SectionType(0x70000001)
)

type bootromSegment struct {
	addr uint32
	data []byte
}

type bootromEvalCtx struct {
	entryPoint   uint32
	segmentCount uint32
	imageSize    uint32
	segmentAddr  uint32
	segmentSize  uint32
	flashSize    uint32
}

// PackStage0FromHardwareJSON parses hardwareJSONPath, resolves any shared
// soc/ base profile referenced via bootrom_image.extends, and packs elfPath
// into a BootROM-loadable binary image using purely declarative primitives.
func PackStage0FromHardwareJSON(elfPath, hardwareJSONPath string) ([]byte, error) {
	hw, err := ParseHardwareJSON(hardwareJSONPath)
	if err != nil {
		return nil, err
	}
	packagesRoot := chipHalRoot(filepath.Dir(hardwareJSONPath), "")
	return PackStage0ELFWithPackagesDir(elfPath, hw, packagesRoot)
}

// PackStage0ELF packs elfPath according to hw.BootromImage when no external
// extends resolution is required (or when Extends is already merged).
func PackStage0ELF(elfPath string, hw *HardwareJson) ([]byte, error) {
	return PackStage0ELFWithPackagesDir(elfPath, hw, "")
}

func hexUint32ToByte(v HexUint32, field string) (uint8, error) {
	u := uint32(v)
	if u > math.MaxUint8 {
		return 0, fmt.Errorf("bootrom: %s 0x%X exceeds uint8", field, u)
	}
	return uint8(u), nil
}

func checkedIntToUint32(n int, field string) (uint32, error) {
	if n < 0 || int64(n) > math.MaxUint32 {
		return 0, fmt.Errorf("bootrom: %s (%d) overflows uint32", field, n)
	}
	return uint32(n), nil
}

// PackStage0ELFWithPackagesDir resolves any bootrom_image.extends profile
// beneath packagesDir and packs elfPath into a BootROM-loadable binary.
func PackStage0ELFWithPackagesDir(elfPath string, hw *HardwareJson, packagesDir string) ([]byte, error) {
	if hw == nil {
		return nil, errors.New("bootrom: nil HardwareJson")
	}

	spec, err := resolveBootromSpec(hw.BootromImage, packagesDir)
	if err != nil {
		return nil, err
	}
	execMode := strings.ToLower(strings.TrimSpace(hw.Flash.Stage0ExecMode))
	if err := validateRawBootromSpec(spec, execMode); err != nil {
		return nil, fmt.Errorf("bootrom: %w", err)
	}

	layout := BootromLayoutFlat
	if spec != nil && strings.TrimSpace(spec.Layout) != "" {
		layout = strings.ToLower(strings.TrimSpace(spec.Layout))
	}

	switch layout {
	case BootromLayoutFlat:
		return packBootromFlat(elfPath, hw, spec)
	case BootromLayoutSegmented:
		return packBootromSegmented(elfPath, hw, spec)
	default:
		return nil, fmt.Errorf("bootrom: unsupported bootrom_image.layout %q for chip_family %q", layout, hw.ChipFamily)
	}
}

func resolveBootromSpec(spec *BootromImageSpec, packagesDir string) (*BootromImageSpec, error) {
	if spec == nil || strings.TrimSpace(spec.Extends) == "" {
		return spec, nil
	}
	ext := strings.TrimSpace(spec.Extends)
	if strings.TrimSpace(packagesDir) == "" {
		return nil, fmt.Errorf("bootrom: bootrom_image.extends %q requires a packages directory", ext)
	}
	if err := validateRelPath("bootrom_image.extends", ext); err != nil {
		return nil, fmt.Errorf("bootrom: %w", err)
	}
	if !strings.HasSuffix(ext, ".json") {
		return nil, fmt.Errorf("bootrom: extends path %q must end with '.json'", ext)
	}
	basePath, err := containPath(packagesDir, ext)
	if err != nil {
		return nil, fmt.Errorf("bootrom: invalid extends path %q: %w", ext, err)
	}

	base, err := decodeJSONFile[BootromImageSpec](basePath, true)
	if err != nil {
		return nil, fmt.Errorf("bootrom: parse extends profile %s: %w", ext, err)
	}
	if strings.TrimSpace(base.Extends) != "" {
		return nil, fmt.Errorf("bootrom: nested extends in %s is not permitted", ext)
	}

	return mergeBootromSpecs(base, spec), nil
}

func mergeBootromSpecs(base, over *BootromImageSpec) *BootromImageSpec {
	merged := *base
	merged.Extends = ""
	if over.Layout != "" {
		merged.Layout = over.Layout
	}
	if over.FillByte != nil {
		merged.FillByte = over.FillByte
	}
	if over.MinSize != 0 {
		merged.MinSize = over.MinSize
	}
	if over.Provenance != nil {
		merged.Provenance = over.Provenance
	}
	if over.Header != nil {
		if merged.Header == nil {
			hdr := *over.Header
			merged.Header = &hdr
		} else {
			hdr := *merged.Header
			if over.Header.Size != 0 {
				hdr.Size = over.Header.Size
			}
			if over.Header.FillByte != nil {
				hdr.FillByte = over.Header.FillByte
			}
			hdr.Fields = mergeBootromFields(merged.Header.Fields, over.Header.Fields)
			merged.Header = &hdr
		}
	}
	if over.Segments != nil {
		if merged.Segments == nil {
			seg := *over.Segments
			merged.Segments = &seg
		} else {
			seg := *merged.Segments
			if over.Segments.Align != 0 {
				seg.Align = over.Segments.Align
			}
			if over.Segments.MaxCount != 0 {
				seg.MaxCount = over.Segments.MaxCount
			}
			if over.Segments.HeaderSize != 0 {
				seg.HeaderSize = over.Segments.HeaderSize
			}
			if len(over.Segments.HeaderFields) > 0 {
				seg.HeaderFields = mergeBootromFields(merged.Segments.HeaderFields, over.Segments.HeaderFields)
			}
			merged.Segments = &seg
		}
	}
	if len(over.Patches) > 0 {
		merged.Patches = slices.Clone(over.Patches)
	}
	if len(over.Trailer) > 0 {
		merged.Trailer = slices.Clone(over.Trailer)
	}
	return &merged
}

func mergeBootromFields(base, over []BootromFieldSpec) []BootromFieldSpec {
	out := slices.Clone(base)
	for _, f := range over {
		idx := slices.IndexFunc(out, func(existing BootromFieldSpec) bool {
			return existing.Offset == f.Offset
		})
		if idx >= 0 {
			out[idx] = f
		} else {
			out = append(out, f)
		}
	}
	return out
}

func isLoadableStage0Section(sec *elf.Section) bool {
	if (sec.Flags&elf.SHF_ALLOC) == 0 || sec.Size == 0 {
		return false
	}
	switch sec.Type {
	case elf.SHT_PROGBITS, elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY, elf.SHT_PREINIT_ARRAY, elfSHTArmExidx:
		return true
	default:
		return false
	}
}

func resolveELFSectionLMA(f *elf.File, sec *elf.Section) (uint64, error) {
	if sec.Size > math.MaxUint64-sec.Offset || sec.Size > math.MaxUint64-sec.Addr {
		return 0, fmt.Errorf("bootrom: section %s offset/VMA overflows uint64", sec.Name)
	}
	secOffEnd := sec.Offset + sec.Size
	secVmaEnd := sec.Addr + sec.Size

	var fallback *elf.Prog
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz == 0 {
			continue
		}
		if p.Filesz > math.MaxUint64-p.Off || p.Memsz > math.MaxUint64-p.Vaddr || p.Filesz > math.MaxUint64-p.Paddr {
			return 0, errors.New("bootrom: ELF PT_LOAD program header overflows uint64")
		}
		offMatch := sec.Offset >= p.Off && secOffEnd <= p.Off+p.Filesz
		vmaMatch := sec.Addr >= p.Vaddr && secVmaEnd <= p.Vaddr+p.Memsz
		if offMatch && vmaMatch {
			return p.Paddr + (sec.Addr - p.Vaddr), nil
		}
		if offMatch && fallback == nil {
			fallback = p
		}
	}
	if fallback != nil {
		return fallback.Paddr + (sec.Offset - fallback.Off), nil
	}
	return sec.Addr, nil
}

func loadELFProgbits(elfPath string, useLMA bool) (uint32, []bootromSegment, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return 0, nil, fmt.Errorf("bootrom: open ELF: %w", err)
	}
	defer func() { _ = f.Close() }()

	if f.Class != elf.ELFCLASS32 {
		return 0, nil, fmt.Errorf("bootrom: expected 32-bit ELF, got %s", f.Class)
	}
	if len(f.Sections) > maxELFSectionHeaders {
		return 0, nil, fmt.Errorf("bootrom: ELF has %d sections (exceeds limit %d)", len(f.Sections), maxELFSectionHeaders)
	}
	if f.Entry > math.MaxUint32 {
		return 0, nil, fmt.Errorf("bootrom: ELF entry point 0x%X exceeds 32-bit address space", f.Entry)
	}

	var segs []bootromSegment
	var totalLoaded uint64
	for _, sec := range f.Sections {
		if !isLoadableStage0Section(sec) {
			continue
		}
		if sec.Name == ".toob_mock_section" {
			continue
		}
		if sec.Size > maxBootromImageSpan {
			return 0, nil, fmt.Errorf("bootrom: section %s size %d exceeds 64 MiB safety bound", sec.Name, sec.Size)
		}
		raw, err := io.ReadAll(io.LimitReader(sec.Open(), maxBootromImageSpan+1))
		if err != nil {
			return 0, nil, fmt.Errorf("bootrom: read section %s: %w", sec.Name, err)
		}
		if len(raw) > maxBootromImageSpan {
			return 0, nil, fmt.Errorf("bootrom: decompressed section %s exceeds 64 MiB safety bound", sec.Name)
		}
		if len(raw) == 0 {
			continue
		}
		totalLoaded += uint64(len(raw))
		if totalLoaded > maxBootromImageSpan {
			return 0, nil, errors.New("bootrom: cumulative ELF loadable payload exceeds 64 MiB safety bound")
		}
		addr64 := sec.Addr
		if useLMA {
			addr64, err = resolveELFSectionLMA(f, sec)
			if err != nil {
				return 0, nil, err
			}
		}
		if addr64 > math.MaxUint32 {
			return 0, nil, fmt.Errorf("bootrom: section %s address 0x%X exceeds 32-bit space", sec.Name, addr64)
		}
		segs = append(segs, bootromSegment{addr: uint32(addr64), data: raw})
	}
	if len(segs) == 0 {
		return 0, nil, errors.New("bootrom: ELF contains no loadable SHT_PROGBITS sections")
	}

	slices.SortFunc(segs, func(a, b bootromSegment) int {
		return cmp.Compare(a.addr, b.addr)
	})
	return uint32(f.Entry), segs, nil
}

func resolveFlatBootromOrigin(hw *HardwareJson, firstSegAddr uint32) (uint64, error) {
	physBase, _, err := resolveFlashBase(&hw.Flash)
	if err != nil {
		return 0, err
	}
	var xipVal uint64
	if strings.TrimSpace(hw.Flash.XipBase) != "" {
		xipVal, err = parseU64Literal(hw.Flash.XipBase)
		if err != nil {
			return 0, fmt.Errorf("bootrom: invalid flash.xip_base: %w", err)
		}
	}
	hasExplicitOrigin := hw.Flash.Base != 0 || strings.TrimSpace(hw.Flash.BaseAddr) != "" || xipVal > 0
	if !hasExplicitOrigin {
		return uint64(firstSegAddr), nil
	}
	expected := uint64(physBase)
	if xipVal > 0 && uint64(firstSegAddr) >= xipVal && (physBase == 0 || uint64(firstSegAddr) < uint64(physBase) || xipVal >= uint64(physBase)) {
		if uint64(firstSegAddr)-xipVal <= uint64(max(hw.Flash.Size, 1)) {
			expected = xipVal
		}
	}
	if uint64(firstSegAddr) < expected {
		return 0, fmt.Errorf("bootrom: flat ELF segment at 0x%08X starts below Stage-0 flash origin 0x%08X",
			firstSegAddr, expected)
	}
	return expected, nil
}

func verifySentinelOverwrite(img []byte, progbitsMask []bool, p BootromPatchSpec, fill uint8) error {
	overlapsCode := false
	for idx := p.Offset; idx < p.Offset+p.Size; idx++ {
		if idx < len(progbitsMask) && progbitsMask[idx] {
			overlapsCode = true
			break
		}
	}
	if !overlapsCode {
		return nil
	}
	slice := img[p.Offset : p.Offset+p.Size]
	allMatch := func(sentinel byte) bool {
		for _, b := range slice {
			if b != sentinel {
				return false
			}
		}
		return true
	}
	if allMatch(fill) || allMatch(0xFF) || allMatch(0x00) {
		return nil
	}
	return fmt.Errorf("target range [0x%X..0x%X) overwrites non-sentinel SHT_PROGBITS bytes (expected 0xFF, 0x00, or fill_byte 0x%02X)",
		p.Offset, p.Offset+p.Size, fill)
}

func packBootromFlat(elfPath string, hw *HardwareJson, spec *BootromImageSpec) ([]byte, error) {
	entry, segs, err := loadELFProgbits(elfPath, true)
	if err != nil {
		return nil, err
	}

	base := uint64(segs[0].addr)
	if spec != nil && (len(spec.Patches) > 0 || spec.MinSize > 0) {
		base, err = resolveFlatBootromOrigin(hw, segs[0].addr)
		if err != nil {
			return nil, err
		}
	}

	var end uint64
	segPayloads := make([][]byte, 0, len(segs))
	for i, s := range segs {
		sStart := uint64(s.addr)
		sEnd := sStart + uint64(len(s.data))
		if sEnd > 0x100000000 {
			return nil, fmt.Errorf("bootrom: segment [0x%08X..0x%X) exceeds 32-bit address space", sStart, sEnd)
		}
		if i > 0 {
			prevEnd := uint64(segs[i-1].addr) + uint64(len(segs[i-1].data))
			if sStart < prevEnd {
				return nil, fmt.Errorf("bootrom: flat ELF segments overlap at 0x%08X", s.addr)
			}
		}
		end = max(end, sEnd)
		segPayloads = append(segPayloads, s.data)
	}
	if end < base || end-base > maxBootromImageSpan {
		return nil, fmt.Errorf("bootrom: flat ELF span [0x%08X..0x%08X) exceeds 64 MiB safety bound", base, end)
	}

	fill := uint8(0xFF)
	if spec != nil && spec.FillByte != nil {
		fill, err = hexUint32ToByte(*spec.FillByte, "fill_byte")
		if err != nil {
			return nil, err
		}
	}

	targetLen := int(end - base)
	if spec != nil && spec.MinSize > 0 {
		if spec.MinSize > maxBootromImageSpan {
			return nil, fmt.Errorf("bootrom: min_size %d exceeds 64 MiB safety bound", spec.MinSize)
		}
		if targetLen < spec.MinSize {
			targetLen = spec.MinSize
		}
	}

	out := make([]byte, targetLen)
	for i := range out {
		out[i] = fill
	}
	progbitsMask := make([]bool, targetLen)
	for _, s := range segs {
		off := uint64(s.addr) - base
		copy(out[off:], s.data)
		for k := range uint64(len(s.data)) {
			progbitsMask[off+k] = true
		}
	}

	if spec == nil {
		return out, nil
	}

	imgSz32, err := checkedIntToUint32(len(out), "image_size")
	if err != nil {
		return nil, err
	}
	eval := bootromEvalCtx{
		entryPoint: entry,
		imageSize:  imgSz32,
		flashSize:  hw.Flash.Size,
	}
	for i, p := range spec.Patches {
		if p.Offset < 0 || p.Size <= 0 || p.Offset > len(out) || p.Size > len(out)-p.Offset {
			return nil, fmt.Errorf("bootrom: patch[%d] (%s): patch [offset=%d, size=%d] out of bounds for %d-byte image",
				i, p.Op, p.Offset, p.Size, len(out))
		}
		if sErr := verifySentinelOverwrite(out, progbitsMask, p, fill); sErr != nil {
			return nil, fmt.Errorf("bootrom: patch[%d] (%s): %w", i, p.Op, sErr)
		}
		if pErr := applyBootromPatch(out, p, eval); pErr != nil {
			return nil, fmt.Errorf("bootrom: patch[%d] (%s): %w", i, p.Op, pErr)
		}
	}
	out, err = applyBootromTrailer(out, segPayloads, spec.Trailer)
	if err != nil {
		return nil, err
	}
	if spec.MinSize > 0 && len(out) < spec.MinSize {
		return nil, fmt.Errorf("bootrom: image size %d bytes is smaller than required min_size %d", len(out), spec.MinSize)
	}
	return out, nil
}

func packBootromSegmented(elfPath string, hw *HardwareJson, spec *BootromImageSpec) ([]byte, error) {
	if spec == nil || spec.Header == nil || spec.Segments == nil {
		return nil, errors.New("bootrom: segmented layout requires both header and segments specifications")
	}
	if spec.Header.Size <= 0 || spec.Header.Size > 65536 {
		return nil, fmt.Errorf("bootrom: invalid header.size %d (must be in [1..65536])", spec.Header.Size)
	}
	if spec.Segments.HeaderSize <= 0 || spec.Segments.HeaderSize > 1024 {
		return nil, fmt.Errorf("bootrom: invalid segments.header_size %d (must be in [1..1024])", spec.Segments.HeaderSize)
	}
	if spec.Segments.MaxCount < 0 {
		return nil, fmt.Errorf("bootrom: invalid segments.max_count %d", spec.Segments.MaxCount)
	}

	entry, rawSegs, err := loadELFProgbits(elfPath, false)
	if err != nil {
		return nil, err
	}

	segAlign := spec.Segments.Align
	if segAlign < 0 {
		return nil, fmt.Errorf("bootrom: invalid segments.align %d", segAlign)
	}
	if segAlign == 0 {
		segAlign = 1
	}
	if !isPowerOfTwo(uint64(segAlign)) || segAlign > (1<<20) {
		return nil, fmt.Errorf("bootrom: invalid segments.align %d (must be power of two <= 1 MiB)", segAlign)
	}
	aligned := make([]bootromSegment, 0, len(rawSegs))
	var totalBytes uint64
	for i, s := range rawSegs {
		if i > 0 {
			prevEnd := uint64(rawSegs[i-1].addr) + uint64(len(rawSegs[i-1].data))
			if uint64(s.addr) < prevEnd {
				return nil, fmt.Errorf("bootrom: segmented ELF sections overlap at 0x%08X", s.addr)
			}
		}
		data := s.data
		if pad := (segAlign - (len(data) % segAlign)) % segAlign; pad > 0 {
			if uint64(s.addr)+uint64(len(data))+uint64(pad) > 0x100000000 {
				return nil, fmt.Errorf("bootrom: segment padding at 0x%08X exceeds 32-bit address space", s.addr)
			}
			padded := make([]byte, len(data)+pad)
			copy(padded, data)
			data = padded
		}
		totalBytes += uint64(len(data))
		if totalBytes > maxBootromImageSpan {
			return nil, errors.New("bootrom: segmented ELF payload exceeds 64 MiB safety bound")
		}
		aligned = append(aligned, bootromSegment{addr: s.addr, data: data})
	}

	merged := make([]bootromSegment, 0, len(aligned))
	for _, s := range aligned {
		if n := len(merged); n > 0 {
			prevEnd := uint64(merged[n-1].addr) + uint64(len(merged[n-1].data))
			if uint64(s.addr) < prevEnd {
				return nil, fmt.Errorf("bootrom: padded ELF segments overlap at 0x%08X", s.addr)
			}
			if prevEnd == uint64(s.addr) {
				merged[n-1].data = append(merged[n-1].data, s.data...)
				continue
			}
		}
		merged = append(merged, s)
	}
	if spec.Segments.MaxCount > 0 && len(merged) > spec.Segments.MaxCount {
		return nil, fmt.Errorf("bootrom: ELF has %d merged segments (max_count is %d)", len(merged), spec.Segments.MaxCount)
	}

	hdrFill := uint8(0x00)
	if spec.Header.FillByte != nil {
		hdrFill, err = hexUint32ToByte(*spec.Header.FillByte, "header.fill_byte")
		if err != nil {
			return nil, err
		}
	}

	preTrailerBytes := uint64(spec.Header.Size)
	for _, s := range merged {
		preTrailerBytes += uint64(spec.Segments.HeaderSize) + uint64(len(s.data))
	}
	if preTrailerBytes > maxBootromImageSpan {
		return nil, errors.New("bootrom: segmented container exceeds 64 MiB safety bound")
	}

	segCount32, err := checkedIntToUint32(len(merged), "segment_count")
	if err != nil {
		return nil, err
	}
	imgSz32, err := checkedIntToUint32(int(preTrailerBytes), "image_size")
	if err != nil {
		return nil, err
	}

	hdrBuf := make([]byte, spec.Header.Size)
	for i := range hdrBuf {
		hdrBuf[i] = hdrFill
	}

	eval := bootromEvalCtx{
		entryPoint:   entry,
		segmentCount: segCount32,
		imageSize:    imgSz32,
		flashSize:    hw.Flash.Size,
	}
	for i, f := range spec.Header.Fields {
		if fErr := writeBootromField(hdrBuf, f, eval); fErr != nil {
			return nil, fmt.Errorf("bootrom: header.fields[%d]: %w", i, fErr)
		}
	}

	out := make([]byte, 0, int(preTrailerBytes))
	out = append(out, hdrBuf...)

	segPayloads := make([][]byte, 0, len(merged))
	for _, s := range merged {
		shdr := make([]byte, spec.Segments.HeaderSize)
		segEval := eval
		segEval.segmentAddr = s.addr
		segSz32, szErr := checkedIntToUint32(len(s.data), "segment_size")
		if szErr != nil {
			return nil, szErr
		}
		segEval.segmentSize = segSz32
		for i, f := range spec.Segments.HeaderFields {
			if fErr := writeBootromField(shdr, f, segEval); fErr != nil {
				return nil, fmt.Errorf("bootrom: segments.header_fields[%d]: %w", i, fErr)
			}
		}
		out = append(out, shdr...)
		out = append(out, s.data...)
		segPayloads = append(segPayloads, s.data)
	}

	for i, p := range spec.Patches {
		if pErr := applyBootromPatch(out, p, eval); pErr != nil {
			return nil, fmt.Errorf("bootrom: patch[%d] (%s): %w", i, p.Op, pErr)
		}
	}

	out, err = applyBootromTrailer(out, segPayloads, spec.Trailer)
	if err != nil {
		return nil, err
	}
	if spec.MinSize > 0 && len(out) < spec.MinSize {
		return nil, fmt.Errorf("bootrom: segmented image size %d bytes is smaller than required min_size %d", len(out), spec.MinSize)
	}
	return out, nil
}

func evalFieldValue(f BootromFieldSpec, ctx bootromEvalCtx) (uint32, error) {
	var raw uint32
	switch strings.ToLower(strings.TrimSpace(f.Source)) {
	case "const":
		raw = uint32(f.Value)
	case "segment_count":
		raw = ctx.segmentCount
	case "entry_point":
		raw = ctx.entryPoint
	case "image_size":
		raw = ctx.imageSize
	case "segment_addr":
		raw = ctx.segmentAddr
	case "segment_size":
		raw = ctx.segmentSize
	case "flash_size_log2_mib":
		const oneMiB = 1 << 20
		if ctx.flashSize < oneMiB || (ctx.flashSize&(ctx.flashSize-1)) != 0 {
			return 0, fmt.Errorf("flash.size %d must be a power-of-two multiple of 1 MiB", ctx.flashSize)
		}
		tz, err := checkedIntToUint32(bits.TrailingZeros32(ctx.flashSize/oneMiB), "flash_size_log2_mib")
		if err != nil {
			return 0, err
		}
		raw = tz
	default:
		return 0, fmt.Errorf("unsupported field source %q", f.Source)
	}

	if f.Shift < 0 || f.Shift >= 32 {
		return 0, fmt.Errorf("invalid bit shift %d", f.Shift)
	}
	shifted := (uint64(raw) << uint(f.Shift)) | uint64(f.OrMask)
	if shifted > math.MaxUint32 {
		return 0, fmt.Errorf("shifted field value 0x%X overflows uint32", shifted)
	}
	return uint32(shifted), nil
}

func putUintEndian(dst []byte, size int, endian string, val uint32) error {
	big := strings.EqualFold(strings.TrimSpace(endian), "big")
	if !big && endian != "" && !strings.EqualFold(strings.TrimSpace(endian), "little") {
		return fmt.Errorf("unsupported endian %q (expected little or big)", endian)
	}
	switch size {
	case 1:
		if val > math.MaxUint8 {
			return fmt.Errorf("value 0x%X overflows 1-byte field", val)
		}
		dst[0] = uint8(val)
	case 2:
		if val > math.MaxUint16 {
			return fmt.Errorf("value 0x%X overflows 2-byte field", val)
		}
		if big {
			binary.BigEndian.PutUint16(dst[:2], uint16(val))
		} else {
			binary.LittleEndian.PutUint16(dst[:2], uint16(val))
		}
	case 4:
		if big {
			binary.BigEndian.PutUint32(dst[:4], val)
		} else {
			binary.LittleEndian.PutUint32(dst[:4], val)
		}
	default:
		return fmt.Errorf("unsupported integer field size %d (expected 1, 2, or 4)", size)
	}
	return nil
}

func writeBootromField(buf []byte, f BootromFieldSpec, ctx bootromEvalCtx) error {
	if f.Offset < 0 || f.Size <= 0 || f.Offset > len(buf) || f.Size > len(buf)-f.Offset {
		return fmt.Errorf("field [offset=%d, size=%d] out of bounds for %d-byte buffer", f.Offset, f.Size, len(buf))
	}
	val, err := evalFieldValue(f, ctx)
	if err != nil {
		return err
	}
	return putUintEndian(buf[f.Offset:f.Offset+f.Size], f.Size, f.Endian, val)
}

func resolvePatchSlice(buf []byte, start, end int) ([]byte, error) {
	if end == 0 {
		end = len(buf)
	}
	if start < 0 || end < start || end > len(buf) {
		return nil, fmt.Errorf("range [%d..%d) out of bounds for %d-byte image", start, end, len(buf))
	}
	return buf[start:end], nil
}

func computeGenericCRC32(data []byte, poly, initVal, xorOut uint32, reflectBits bool) uint32 {
	crc := initVal
	if reflectBits {
		refPoly := bits.Reverse32(poly)
		for _, b := range data {
			crc ^= uint32(b)
			for range 8 {
				if (crc & 1) != 0 {
					crc = (crc >> 1) ^ refPoly
				} else {
					crc >>= 1
				}
			}
		}
		return crc ^ xorOut
	}
	for _, b := range data {
		crc ^= uint32(b) << 24
		for range 8 {
			if (crc & 0x80000000) != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ xorOut
}

func applyBootromPatch(img []byte, p BootromPatchSpec, ctx bootromEvalCtx) error {
	if p.Offset < 0 || p.Size <= 0 || p.Offset > len(img) || p.Size > len(img)-p.Offset {
		return fmt.Errorf("patch [offset=%d, size=%d] out of bounds for %d-byte image", p.Offset, p.Size, len(img))
	}
	dst := img[p.Offset : p.Offset+p.Size]

	switch strings.ToLower(strings.TrimSpace(p.Op)) {
	case "crc32":
		if p.Size != 4 {
			return fmt.Errorf("crc32 patch requires size=4, got %d", p.Size)
		}
		span, err := resolvePatchSlice(img, p.RangeStart, p.RangeEnd)
		if err != nil {
			return err
		}
		crc := computeGenericCRC32(span, uint32(p.Poly), uint32(p.Init), uint32(p.XorOut), p.Reflect)
		return putUintEndian(dst, 4, p.Endian, crc)

	case "sum32", "neg_sum32":
		if p.Size != 4 {
			return fmt.Errorf("%s patch requires size=4, got %d", p.Op, p.Size)
		}
		span, err := resolvePatchSlice(img, p.RangeStart, p.RangeEnd)
		if err != nil || len(span)%4 != 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("%s range length %d must be a multiple of 4 bytes", p.Op, len(span))
		}
		big := strings.EqualFold(strings.TrimSpace(p.Endian), "big")
		sum := uint32(p.Init)
		for i := 0; i < len(span); i += 4 {
			if big {
				sum += binary.BigEndian.Uint32(span[i : i+4])
			} else {
				sum += binary.LittleEndian.Uint32(span[i : i+4])
			}
		}
		if strings.EqualFold(p.Op, "neg_sum32") {
			sum = -sum
		}
		return putUintEndian(dst, 4, p.Endian, sum)

	case "sha256":
		if p.Size != 32 {
			return fmt.Errorf("sha256 patch requires size=32, got %d", p.Size)
		}
		span, err := resolvePatchSlice(img, p.RangeStart, p.RangeEnd)
		if err != nil {
			return err
		}
		d := sha256.Sum256(span)
		copy(dst, d[:])
		return nil

	case "entry_point":
		return putUintEndian(dst, p.Size, p.Endian, ctx.entryPoint)
	case "image_size":
		return putUintEndian(dst, p.Size, p.Endian, ctx.imageSize)
	case "const":
		return putUintEndian(dst, p.Size, p.Endian, uint32(p.Value))
	default:
		return fmt.Errorf("unsupported patch op %q", p.Op)
	}
}

func applyBootromTrailer(out []byte, segPayloads [][]byte, ops []BootromTrailerOp) ([]byte, error) {
	for i, op := range ops {
		switch strings.ToLower(strings.TrimSpace(op.Op)) {
		case "pad":
			if op.Align <= 0 || op.Align > (1<<20) || op.Reserve < 0 || op.Reserve > maxBootromImageSpan {
				return nil, fmt.Errorf("bootrom: trailer[%d] invalid pad align=%d reserve=%d", i, op.Align, op.Reserve)
			}
			padByte, err := hexUint32ToByte(op.Byte, fmt.Sprintf("trailer[%d] pad byte", i))
			if err != nil {
				return nil, err
			}
			align64 := uint64(op.Align)
			rem := (uint64(len(out)) + uint64(op.Reserve)) % align64
			padLen := (align64 - rem) % align64
			for range padLen {
				out = append(out, padByte)
			}

		case "xor8":
			acc, err := hexUint32ToByte(op.Seed, fmt.Sprintf("trailer[%d] xor8 seed", i))
			if err != nil {
				return nil, err
			}
			switch strings.ToLower(strings.TrimSpace(op.Scope)) {
			case "", "segment_data":
				for _, seg := range segPayloads {
					for _, b := range seg {
						acc ^= b
					}
				}
			case "image":
				for _, b := range out {
					acc ^= b
				}
			default:
				return nil, fmt.Errorf("bootrom: trailer[%d] unsupported xor8 scope %q", i, op.Scope)
			}
			out = append(out, acc)

		case "crc32":
			var data []byte
			switch strings.ToLower(strings.TrimSpace(op.Scope)) {
			case "", "image":
				data = out
			case "segment_data":
				for _, seg := range segPayloads {
					data = append(data, seg...)
				}
			default:
				return nil, fmt.Errorf("bootrom: trailer[%d] unsupported crc32 scope %q", i, op.Scope)
			}
			crc := computeGenericCRC32(data, uint32(op.Poly), uint32(op.Init), uint32(op.XorOut), op.Reflect)
			var buf [4]byte
			if err := putUintEndian(buf[:], 4, op.Endian, crc); err != nil {
				return nil, err
			}
			out = append(out, buf[:]...)

		case "sha256":
			var digest [32]byte
			switch strings.ToLower(strings.TrimSpace(op.Scope)) {
			case "", "image":
				digest = sha256.Sum256(out)
			case "segment_data":
				h := sha256.New()
				for _, seg := range segPayloads {
					h.Write(seg)
				}
				copy(digest[:], h.Sum(nil))
			default:
				return nil, fmt.Errorf("bootrom: trailer[%d] unsupported sha256 scope %q", i, op.Scope)
			}
			out = append(out, digest[:]...)

		default:
			return nil, fmt.Errorf("bootrom: trailer[%d] unsupported op %q", i, op.Op)
		}
		if len(out) > maxBootromImageSpan {
			return nil, fmt.Errorf("bootrom: trailer[%d] (%s) grows image past 64 MiB safety bound", i, op.Op)
		}
	}
	return out, nil
}
