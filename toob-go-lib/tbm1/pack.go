package tbm1

import "errors"

// PackOptions configures single-step assembly of a signed TBM1 v2 update bundle
// (full image, Heatshrink-compressed image, or TDS1 forward delta, plus an
// optional Region 6 TDS1 reverse delta) in either Zero-Copy TrailerLayout or
// Flat streaming layout.
type PackOptions struct {
	Installed     []byte
	TargetSlot    uint8
	Base          []byte
	BaseSVN       uint32
	Compress      bool
	ReverseOld    []byte
	TrailerLayout bool
	VendorID      uint16
	ProductID     uint16
	HWRevMin      uint16
	HWRevMax      uint16
	SVN           uint32
	VerMajor      uint16
	VerMinor      uint16
	VerPatch      uint16
	KeyIndex      uint8
}

// PackBundle encodes, signs, and assembles a complete on-wire / on-flash TBM1
// bundle from in-memory firmware images without touching the filesystem.
func PackBundle(opts PackOptions, signer Signer) ([]byte, error) {
	if len(opts.Installed) == 0 {
		return nil, errors.New("tbm1: PackBundle requires non-empty Installed image")
	}
	if len(opts.Base) > 0 && opts.Compress {
		return nil, errors.New("tbm1: Base (TDS1 delta) and Compress (Heatshrink) are mutually exclusive")
	}

	img := Image{
		TargetSlot: opts.TargetSlot,
		CompAlg:    CompNone,
		DeltaAlg:   DeltaNone,
		Installed:  opts.Installed,
		VerMajor:   opts.VerMajor,
		VerMinor:   opts.VerMinor,
		VerPatch:   opts.VerPatch,
	}
	if len(opts.Base) > 0 {
		img.DeltaAlg = DeltaTDS1
		img.Base = opts.Base
		img.BaseSVN = opts.BaseSVN
	} else if opts.Compress {
		img.CompAlg = CompHeatshrink
	}

	var rdeltas []ReverseDelta
	if len(opts.ReverseOld) > 0 {
		rdeltas = append(rdeltas, ReverseDelta{
			TargetSlot: opts.TargetSlot,
			DeltaAlg:   DeltaTDS1,
			OldImage:   opts.ReverseOld,
		})
	}

	manifest := Manifest{
		KeyIndex:      opts.KeyIndex,
		VendorID:      opts.VendorID,
		ProductID:     opts.ProductID,
		HWRevMin:      opts.HWRevMin,
		HWRevMax:      opts.HWRevMax,
		SVN:           opts.SVN,
		FwVerMajor:    opts.VerMajor,
		FwVerMinor:    opts.VerMinor,
		FwVerPatch:    opts.VerPatch,
		AutoSBOM:      true,
		TrailerLayout: opts.TrailerLayout,
		Images:        []Image{img},
		ReverseDeltas: rdeltas,
	}

	pkg, err := Build(manifest, signer)
	if err != nil {
		return nil, err
	}

	storedPrimary := opts.Installed
	if len(pkg.Payloads) > 0 && pkg.Payloads[0].Data != nil {
		storedPrimary = pkg.Payloads[0].Data
	}

	if opts.TrailerLayout {
		return pkg.AssembleTrailer([][]byte{storedPrimary})
	}
	return pkg.AssembleFlat([][]byte{storedPrimary})
}
