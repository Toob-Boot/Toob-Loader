package build

import (
	"errors"
	"fmt"
	"strings"
)

// Transport identifies the slot update strategy compiled into Stage 1.
// Values mirror the TOOB_TRANSPORT_* enum in core/include/boot_transport.h.
type Transport string

const (
	TransportPointer     Transport = "pointer"
	TransportOneway      Transport = "oneway"
	TransportSwapScratch Transport = "swapscratch"
	TransportSwapMove    Transport = "swapmove"
	TransportSwapOffset  Transport = "swapoffset"
)

// BackupMode selects the rollback backup strategy of the oneway transport.
// Values mirror the TOOB_ONEWAY_BACKUP_* enum in core/include/boot_transport.h.
type BackupMode string

const (
	BackupUnset        BackupMode = ""
	BackupNone         BackupMode = "none"
	BackupFull         BackupMode = "full"
	BackupReverseDelta BackupMode = "reverse_delta"
)

func (t Transport) valid() bool {
	switch t {
	case TransportPointer, TransportOneway, TransportSwapScratch, TransportSwapMove, TransportSwapOffset:
		return true
	}
	return false
}

func (b BackupMode) valid() bool {
	switch b {
	case BackupNone, BackupFull, BackupReverseDelta:
		return true
	case BackupUnset:
		return false
	default:
		return false
	}
}

func (t Transport) cMacro() string  { return "TOOB_TRANSPORT_" + strings.ToUpper(string(t)) }
func (b BackupMode) cMacro() string { return "TOOB_ONEWAY_BACKUP_" + strings.ToUpper(string(b)) }

// needsDedicatedScratch reports whether a dedicated 3rd scratch partition must
// be allocated in addition to the App/Staging slots (HIGH-17).
func needsDedicatedScratch(t Transport, b BackupMode, slotCount int) bool {
	if t == TransportSwapScratch {
		return true
	}
	if t == TransportOneway && b == BackupFull {
		return slotCount < 2
	}
	return false
}

// needsDeltaScratch reports whether forward TDS1 delta updates require a
// dedicated scratch partition on the selected transport (HIGH-33). Only the
// remappable 'pointer' transport streams deltas directly into the inactive slot.
func needsDeltaScratch(t Transport, enableDeltas bool) bool {
	return enableDeltas && t != TransportPointer
}

// isRemappable reports whether the execution model can switch the active slot
// without copying images, which enables pointer transport and scratch-less deltas.
func isRemappable(execModel string) bool {
	switch execModel {
	case "xip_remap", "bank_swap", "relocatable":
		return true
	}
	return false
}

// autoSelectTransport picks the safest strategy the chip can support.
// When delta or compression extraction is explicitly requested on a 1-slot
// chip with scratch, it selects oneway (BackupFull) rather than swapscratch
// so stage_extract never aliases the swap scratch buffer (HIGH-49).
func autoSelectTransport(caps *SlotCapabilities, avoidSwapScratch bool) Transport {
	switch {
	case caps.SlotCount >= 2 && isRemappable(caps.ExecModel):
		return TransportPointer
	case caps.SlotCount >= 2:
		return TransportOneway
	case caps.HasScratch && avoidSwapScratch:
		return TransportOneway
	case caps.HasScratch:
		return TransportSwapScratch
	default:
		return TransportSwapMove
	}
}

// resolveTransport derives the effective transport and backup mode from the
// device configuration and the chip's declared slot capabilities.
func resolveTransport(ctx *Context) (Transport, BackupMode, error) {
	dt := ctx.Device
	var caps *SlotCapabilities
	if ctx.Chip != nil {
		caps = ctx.Chip.SlotCapabilities
	}

	explicitComp := dt.Features.Compression != nil && *dt.Features.Compression
	t := Transport(strings.ToLower(strings.TrimSpace(dt.BootConfig.TransportProvider)))
	switch {
	case t == "" && caps == nil:
		return "", "", errors.New("FATAL: boot_config.transport_provider must be set explicitly " +
			"because the chip manifest declares no slot_capabilities")
	case t == "":
		t = autoSelectTransport(caps, dt.Partitions.EnableDeltas || explicitComp)
		ctx.Log.Info("Auto-selected transport provider '%s' based on chip capabilities", t)
	case !t.valid():
		return "", "", fmt.Errorf("FATAL: unknown transport provider '%s' "+
			"(must be pointer, oneway, swapscratch, swapmove or swapoffset)", dt.BootConfig.TransportProvider)
	}

	if t == TransportSwapScratch {
		if dt.Partitions.EnableDeltas {
			return "", "", errors.New("FATAL [REG-003]: transport provider 'swapscratch' cannot be combined with partitions.enable_deltas = true (scratch alias corruption); use 'oneway' or 'swapmove'")
		}
		if explicitComp {
			return "", "", errors.New("FATAL: transport provider 'swapscratch' cannot be combined with features.compression = true (scratch alias corruption); use 'oneway' or 'swapmove'")
		}
	}

	b := BackupMode(strings.ToLower(strings.TrimSpace(dt.BootConfig.BackupMode)))
	switch {
	case b != BackupUnset && t != TransportOneway:
		return "", "", fmt.Errorf("FATAL: boot_config.backup_mode applies only to the oneway transport, "+
			"but transport is '%s'", t)
	case b != BackupUnset && !b.valid():
		return "", "", fmt.Errorf("FATAL: unknown backup mode '%s' for oneway transport "+
			"(must be 'none', 'full' or 'reverse_delta')", dt.BootConfig.BackupMode)
	case t == TransportOneway && b == BackupUnset:
		b = BackupFull
	}

	if caps == nil {
		if t == TransportPointer {
			return "", "", errors.New("FATAL: transport provider 'pointer' requires chip slot_capabilities with slot_count >= 2 and remappable exec_model")
		}
		if t == TransportOneway && (b == BackupNone || b == BackupReverseDelta) {
			return "", "", fmt.Errorf("FATAL: transport provider 'oneway' with '%s' backup requires chip slot_capabilities with slot_count >= 2", b)
		}
		if (t == TransportSwapScratch || (t == TransportOneway && b == BackupFull)) && dt.Partitions.ScratchSize == 0 {
			return "", "", fmt.Errorf("FATAL: transport provider '%s' without chip slot_capabilities requires partitions.scratch_size > 0", t)
		}
		if dt.Partitions.EnableDeltas && t != TransportPointer && dt.Partitions.ScratchSize == 0 {
			return "", "", fmt.Errorf("FATAL [REG-003]: enable_deltas = true with transport '%s' requires partitions.scratch_size > 0", t)
		}
		ctx.Log.Warn("Chip declares no slot_capabilities; transport '%s' validated against explicit partition sizes", t)
		return t, b, nil
	}
	if err := checkTransportCapabilities(t, b, caps, dt.Partitions.ScratchSize); err != nil {
		return "", "", err
	}
	if dt.Partitions.EnableDeltas && t != TransportPointer && !caps.HasScratch && dt.Partitions.ScratchSize == 0 {
		return "", "", fmt.Errorf("FATAL [REG-003]: enable_deltas = true with transport '%s' requires a scratch partition "+
			"(has_scratch = true or partitions.scratch_size > 0); scratch-less deltas require transport 'pointer'", t)
	}
	return t, b, nil
}

// checkTransportCapabilities rejects transports the chip cannot execute safely.
func checkTransportCapabilities(t Transport, b BackupMode, caps *SlotCapabilities, scratchSize uint32) error {
	switch t {
	case TransportPointer:
		if caps.SlotCount < 2 {
			return fmt.Errorf("FATAL: transport provider 'pointer' requires slot_count >= 2, but chip has %d", caps.SlotCount)
		}
		if !isRemappable(caps.ExecModel) {
			return fmt.Errorf("FATAL: transport provider 'pointer' requires a remappable, bank-swappable "+
				"or relocatable execution model, but chip has '%s'", caps.ExecModel)
		}
	case TransportOneway:
		if (b == BackupNone || b == BackupReverseDelta) && caps.SlotCount < 2 {
			return fmt.Errorf("FATAL: transport provider 'oneway' with '%s' backup requires slot_count >= 2, "+
				"but chip has %d", b, caps.SlotCount)
		}
		if b == BackupFull && caps.SlotCount < 2 && scratchSize == 0 && !caps.HasScratch {
			return fmt.Errorf("FATAL: transport provider 'oneway' with full backup requires slot_count >= 2 "+
				"or a configured scratch partition, but chip has %d slots and scratch size is 0", caps.SlotCount)
		}
	case TransportSwapScratch:
		if !caps.HasScratch && scratchSize == 0 {
			return errors.New("FATAL: transport provider 'swapscratch' requires a scratch partition, " +
				"but the chip has no scratch and scratch_size is 0")
		}
	case TransportSwapMove, TransportSwapOffset:
		// In-place / tail-gap mechanics work on any flash layout.
	}
	return nil
}
