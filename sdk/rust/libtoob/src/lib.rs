#![no_std]

pub mod ota;

pub use libtoob_sys as sys;
pub use ota::{Done, Idle, OtaSession, Receiving};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ToobError {
    NotFound,
    WalFull,
    WalLocked,
    FlashFailure,
    InvalidArg,
    VerificationFailure,
    RequiresReset,
    CounterExhausted,
    FlashHardwareFailure,
    InvalidState,
    Timeout,
    NotSupported,
    Unknown(u32),
}

pub type Error = ToobError;
pub type Result<T> = core::result::Result<T, ToobError>;

impl ToobError {
    pub const fn to_status(self) -> sys::ToobStatus {
        match self {
            ToobError::NotFound => sys::TOOB_ERR_NOT_FOUND,
            ToobError::WalFull => sys::TOOB_ERR_WAL_FULL,
            ToobError::WalLocked => sys::TOOB_ERR_WAL_LOCKED,
            ToobError::FlashFailure => sys::TOOB_ERR_FLASH,
            ToobError::InvalidArg => sys::TOOB_ERR_INVALID_ARG,
            ToobError::VerificationFailure => sys::TOOB_ERR_VERIFY,
            ToobError::RequiresReset => sys::TOOB_ERR_REQUIRES_RESET,
            ToobError::CounterExhausted => sys::TOOB_ERR_COUNTER_EXHAUSTED,
            ToobError::FlashHardwareFailure => sys::TOOB_ERR_FLASH_HW,
            ToobError::InvalidState => sys::TOOB_ERR_STATE,
            ToobError::Timeout => sys::TOOB_ERR_TIMEOUT,
            ToobError::NotSupported => sys::TOOB_ERR_NOT_SUPPORTED,
            ToobError::Unknown(code) => {
                if code == sys::TOOB_OK.0 {
                    sys::TOOB_ERR_VERIFY
                } else {
                    sys::ToobStatus(code)
                }
            }
        }
    }
}

impl ToobStatusExt for sys::ToobStatus {
    fn to_result(self) -> Result<()> {
        match self {
            sys::TOOB_OK => Ok(()),
            sys::TOOB_ERR_NOT_FOUND => Err(ToobError::NotFound),
            sys::TOOB_ERR_WAL_FULL => Err(ToobError::WalFull),
            sys::TOOB_ERR_WAL_LOCKED => Err(ToobError::WalLocked),
            sys::TOOB_ERR_FLASH => Err(ToobError::FlashFailure),
            sys::TOOB_ERR_INVALID_ARG => Err(ToobError::InvalidArg),
            sys::TOOB_ERR_VERIFY => Err(ToobError::VerificationFailure),
            sys::TOOB_ERR_REQUIRES_RESET => Err(ToobError::RequiresReset),
            sys::TOOB_ERR_COUNTER_EXHAUSTED => Err(ToobError::CounterExhausted),
            sys::TOOB_ERR_FLASH_HW => Err(ToobError::FlashHardwareFailure),
            sys::TOOB_ERR_STATE => Err(ToobError::InvalidState),
            sys::TOOB_ERR_TIMEOUT => Err(ToobError::Timeout),
            sys::TOOB_ERR_NOT_SUPPORTED => Err(ToobError::NotSupported),
            sys::ToobStatus(code) => Err(ToobError::Unknown(code)),
        }
    }
}

pub(crate) trait ToobStatusExt {
    fn to_result(self) -> Result<()>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Partition {
    App,
    Recovery,
}

impl Partition {
    pub const fn to_tdr1_wire(self) -> u8 {
        match self {
            Partition::App => sys::TOOB_TDR1_PARTITION_APP,
            Partition::Recovery => sys::TOOB_TDR1_PARTITION_RECOVERY,
        }
    }
}

impl TryFrom<u32> for Partition {
    type Error = ToobError;

    fn try_from(raw: u32) -> Result<Self> {
        match sys::ToobPartition(raw) {
            sys::TOOB_PARTITION_APP => Ok(Partition::App),
            sys::TOOB_PARTITION_RECOVERY => Ok(Partition::Recovery),
            _ => Err(ToobError::VerificationFailure),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResetReason {
    Unknown,
    PowerOn,
    Pin,
    Watchdog,
    Brownout,
    Software,
    HardFault,
}

impl ResetReason {
    pub const fn to_wire(self) -> u8 {
        match self {
            ResetReason::Unknown => sys::TOOB_RESET_UNKNOWN.0 as u8,
            ResetReason::PowerOn => sys::TOOB_RESET_POWER_ON.0 as u8,
            ResetReason::Pin => sys::TOOB_RESET_PIN.0 as u8,
            ResetReason::Watchdog => sys::TOOB_RESET_WATCHDOG.0 as u8,
            ResetReason::Brownout => sys::TOOB_RESET_BROWNOUT.0 as u8,
            ResetReason::Software => sys::TOOB_RESET_SOFTWARE.0 as u8,
            ResetReason::HardFault => sys::TOOB_RESET_HARD_FAULT.0 as u8,
        }
    }
}

impl TryFrom<u32> for ResetReason {
    type Error = ToobError;

    fn try_from(raw: u32) -> Result<Self> {
        match sys::ToobResetReason(raw) {
            sys::TOOB_RESET_UNKNOWN => Ok(ResetReason::Unknown),
            sys::TOOB_RESET_POWER_ON => Ok(ResetReason::PowerOn),
            sys::TOOB_RESET_PIN => Ok(ResetReason::Pin),
            sys::TOOB_RESET_WATCHDOG => Ok(ResetReason::Watchdog),
            sys::TOOB_RESET_BROWNOUT => Ok(ResetReason::Brownout),
            sys::TOOB_RESET_SOFTWARE => Ok(ResetReason::Software),
            sys::TOOB_RESET_HARD_FAULT => Ok(ResetReason::HardFault),
            _ => Err(ToobError::VerificationFailure),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BootState {
    Committed,
    Tentative,
}

impl BootState {
    pub const fn to_wire(self) -> u8 {
        match self {
            BootState::Committed => sys::TOOB_TDR1_BOOT_STATE_COMMITTED,
            BootState::Tentative => sys::TOOB_TDR1_BOOT_STATE_TENTATIVE,
        }
    }
}

impl TryFrom<u8> for BootState {
    type Error = ToobError;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            sys::TOOB_TDR1_BOOT_STATE_COMMITTED => Ok(BootState::Committed),
            sys::TOOB_TDR1_BOOT_STATE_TENTATIVE => Ok(BootState::Tentative),
            _ => Err(ToobError::VerificationFailure),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    None,
    Applied,
    Rejected,
    Reverted,
    Deferred,
}

impl UpdateOutcome {
    pub const fn to_wire(self) -> u8 {
        match self {
            UpdateOutcome::None => sys::TOOB_TDR1_OUTCOME_NONE,
            UpdateOutcome::Applied => sys::TOOB_TDR1_OUTCOME_APPLIED,
            UpdateOutcome::Rejected => sys::TOOB_TDR1_OUTCOME_REJECTED,
            UpdateOutcome::Reverted => sys::TOOB_TDR1_OUTCOME_REVERTED,
            UpdateOutcome::Deferred => sys::TOOB_TDR1_OUTCOME_DEFERRED,
        }
    }
}

impl TryFrom<u8> for UpdateOutcome {
    type Error = ToobError;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            sys::TOOB_TDR1_OUTCOME_NONE => Ok(UpdateOutcome::None),
            sys::TOOB_TDR1_OUTCOME_APPLIED => Ok(UpdateOutcome::Applied),
            sys::TOOB_TDR1_OUTCOME_REJECTED => Ok(UpdateOutcome::Rejected),
            sys::TOOB_TDR1_OUTCOME_REVERTED => Ok(UpdateOutcome::Reverted),
            sys::TOOB_TDR1_OUTCOME_DEFERRED => Ok(UpdateOutcome::Deferred),
            _ => Err(ToobError::VerificationFailure),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Tdr1Frame {
    pub booted_partition: Partition,
    pub diag_major: u8,
    pub boot_state: BootState,
    pub active_slot: u8,
    pub reset_reason: ResetReason,
    pub fallback_occurred: bool,
    pub wipe_requested: bool,
    pub last_update_outcome: UpdateOutcome,
    pub last_update_reject: u8,
    pub active_key_index: u16,
    pub reader_major: u16,
    pub reader_minor: u16,
    pub fw_ver_major: u16,
    pub fw_ver_minor: u16,
    pub fw_ver_patch: u16,
    pub checkin_seq: u64,
    pub current_svn: u32,
    pub build_number: u32,
    pub installed_app_svn: u32,
    pub installed_stage1_svn: u32,
    pub monotonic_counter: u32,
    pub boot_duration_ms: u32,
    pub verify_time_ms: u32,
    pub last_error_code: u32,
    pub vendor_error: u32,
    pub hardware_fault_record: u32,
    pub edge_recovery_events: u32,
    pub recovery_failure_events: u32,
    pub net_search_accum_ms: u32,
    pub wdt_kicks: u32,
    pub sbom_digest: [u8; 32],
    pub boot_session_id: u32,
    pub ext_health: Option<ExtHealth>,
}

impl Tdr1Frame {
    /// Serializes `self` into a canonical Little-Endian `TDR1` wire frame (136 B or 152 B).
    pub fn encode(&self, out_buf: &mut [u8]) -> Result<usize> {
        let diag_major = if self.diag_major == 0 {
            sys::TOOB_TDR1_MIN_DIAG_MAJOR
        } else {
            self.diag_major
        };
        if diag_major < sys::TOOB_TDR1_MIN_DIAG_MAJOR || self.active_slot > 1 {
            return Err(ToobError::VerificationFailure);
        }

        let (frame_len, flags) = if self.ext_health.is_some() {
            (sys::TOOB_TDR1_MAX_SIZE, sys::TOOB_TDR1_FLAG_EXT_HEALTH)
        } else {
            (sys::TOOB_TDR1_MIN_FRAME_SIZE, 0u16)
        };
        if out_buf.len() < frame_len {
            return Err(ToobError::InvalidArg);
        }

        let buf = &mut out_buf[..frame_len];
        buf.fill(0);

        buf[0..4].copy_from_slice(&sys::TOOB_TDR1_MAGIC.to_le_bytes());
        buf[4] = sys::TOOB_TDR1_VERSION;
        buf[5] = self.booted_partition.to_tdr1_wire();
        buf[6..8].copy_from_slice(&flags.to_le_bytes());
        buf[8..10].copy_from_slice(&(sys::TOOB_TDR1_HDR_SIZE as u16).to_le_bytes());
        buf[10] = diag_major;
        buf[11] = self.boot_state.to_wire();
        buf[12] = self.active_slot;
        buf[13] = self.reset_reason.to_wire();
        buf[14] = u8::from(self.fallback_occurred);
        buf[15] = u8::from(self.wipe_requested);
        buf[16] = self.last_update_outcome.to_wire();
        buf[17] = self.last_update_reject;
        buf[18..20].copy_from_slice(&self.active_key_index.to_le_bytes());
        buf[20..22].copy_from_slice(&self.reader_major.to_le_bytes());
        buf[22..24].copy_from_slice(&self.reader_minor.to_le_bytes());
        buf[24..26].copy_from_slice(&self.fw_ver_major.to_le_bytes());
        buf[26..28].copy_from_slice(&self.fw_ver_minor.to_le_bytes());
        buf[28..30].copy_from_slice(&self.fw_ver_patch.to_le_bytes());
        buf[30..32].copy_from_slice(&0u16.to_le_bytes());
        buf[32..40].copy_from_slice(&self.checkin_seq.to_le_bytes());
        buf[40..44].copy_from_slice(&self.current_svn.to_le_bytes());
        buf[44..48].copy_from_slice(&self.build_number.to_le_bytes());
        buf[48..52].copy_from_slice(&self.installed_app_svn.to_le_bytes());
        buf[52..56].copy_from_slice(&self.installed_stage1_svn.to_le_bytes());
        buf[56..60].copy_from_slice(&self.monotonic_counter.to_le_bytes());
        buf[60..64].copy_from_slice(&self.boot_duration_ms.to_le_bytes());
        buf[64..68].copy_from_slice(&self.verify_time_ms.to_le_bytes());
        buf[68..72].copy_from_slice(&self.last_error_code.to_le_bytes());
        buf[72..76].copy_from_slice(&self.vendor_error.to_le_bytes());
        buf[76..80].copy_from_slice(&self.hardware_fault_record.to_le_bytes());
        buf[80..84].copy_from_slice(&self.edge_recovery_events.to_le_bytes());
        buf[84..88].copy_from_slice(&self.recovery_failure_events.to_le_bytes());
        buf[88..92].copy_from_slice(&self.net_search_accum_ms.to_le_bytes());
        buf[92..96].copy_from_slice(&self.wdt_kicks.to_le_bytes());
        buf[96..128].copy_from_slice(&self.sbom_digest);
        buf[128..132].copy_from_slice(&self.boot_session_id.to_le_bytes());

        if let Some(ext) = &self.ext_health {
            let base = sys::TOOB_TDR1_HDR_SIZE;
            buf[base..base + 4].copy_from_slice(&ext.wal_erase_count.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&ext.app_slot_erase_count.to_le_bytes());
            buf[base + 8..base + 12].copy_from_slice(&ext.staging_slot_erase_count.to_le_bytes());
            buf[base + 12..base + 16].copy_from_slice(&ext.swap_buffer_erase_count.to_le_bytes());
        }

        let crc_off = frame_len - sys::TOOB_TDR1_CRC_TRAILER_SIZE;
        let crc = unsafe { sys::toob_lib_crc32(buf.as_ptr(), crc_off) };
        buf[crc_off..frame_len].copy_from_slice(&crc.to_le_bytes());

        Ok(frame_len)
    }

    /// Decodes and validates a canonical Little-Endian `TDR1` frame, verifying its trailing CRC-32.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        if frame.len() < sys::TOOB_TDR1_MIN_FRAME_SIZE {
            return Err(ToobError::InvalidArg);
        }
        let payload_len = frame.len() - sys::TOOB_TDR1_CRC_TRAILER_SIZE;
        let stored_crc = u32::from_le_bytes([
            frame[payload_len],
            frame[payload_len + 1],
            frame[payload_len + 2],
            frame[payload_len + 3],
        ]);
        let calc_crc = unsafe { sys::toob_lib_crc32(frame.as_ptr(), payload_len) };
        if stored_crc != calc_crc {
            return Err(ToobError::VerificationFailure);
        }

        let le16 = |off: usize| u16::from_le_bytes([frame[off], frame[off + 1]]);
        let le32 = |off: usize| {
            u32::from_le_bytes([frame[off], frame[off + 1], frame[off + 2], frame[off + 3]])
        };

        if le32(0) != sys::TOOB_TDR1_MAGIC || frame[4] != sys::TOOB_TDR1_VERSION {
            return Err(ToobError::VerificationFailure);
        }
        let booted_partition = match frame[5] {
            sys::TOOB_TDR1_PARTITION_APP => Partition::App,
            sys::TOOB_TDR1_PARTITION_RECOVERY => Partition::Recovery,
            _ => return Err(ToobError::VerificationFailure),
        };
        let flags = le16(6);
        if (flags & !sys::TOOB_TDR1_KNOWN_FLAGS_MASK) != 0 {
            return Err(ToobError::VerificationFailure);
        }
        let header_size = le16(8) as usize;
        if header_size < sys::TOOB_TDR1_HDR_SIZE
            || !(header_size - sys::TOOB_TDR1_HDR_SIZE).is_multiple_of(8)
        {
            return Err(ToobError::VerificationFailure);
        }
        let ext_len = if (flags & sys::TOOB_TDR1_FLAG_EXT_HEALTH) != 0 {
            sys::TOOB_TDR1_EXT_HEALTH_SIZE
        } else {
            0
        };
        if header_size
            .checked_add(ext_len)
            .and_then(|n| n.checked_add(sys::TOOB_TDR1_CRC_TRAILER_SIZE))
            != Some(frame.len())
        {
            return Err(ToobError::VerificationFailure);
        }
        let diag_major = frame[10];
        if diag_major < sys::TOOB_TDR1_MIN_DIAG_MAJOR {
            return Err(ToobError::VerificationFailure);
        }
        let boot_state = BootState::try_from(frame[11])?;
        let active_slot = frame[12];
        if active_slot > 1 {
            return Err(ToobError::VerificationFailure);
        }
        let reset_reason = ResetReason::try_from(frame[13] as u32)?;
        if frame[14] > 1 || frame[15] > 1 {
            return Err(ToobError::VerificationFailure);
        }
        let last_update_outcome = UpdateOutcome::try_from(frame[16])?;
        if le16(30) != 0 {
            return Err(ToobError::VerificationFailure);
        }

        let checkin_seq = (le32(32) as u64) | ((le32(36) as u64) << 32);
        let mut sbom_digest = [0u8; 32];
        sbom_digest.copy_from_slice(&frame[96..128]);

        let ext_health = if ext_len != 0 {
            Some(ExtHealth {
                wal_erase_count: le32(header_size),
                app_slot_erase_count: le32(header_size + 4),
                staging_slot_erase_count: le32(header_size + 8),
                swap_buffer_erase_count: le32(header_size + 12),
            })
        } else {
            None
        };

        Ok(Self {
            booted_partition,
            diag_major,
            boot_state,
            active_slot,
            reset_reason,
            fallback_occurred: frame[14] != 0,
            wipe_requested: frame[15] != 0,
            last_update_outcome,
            last_update_reject: frame[17],
            active_key_index: le16(18),
            reader_major: le16(20),
            reader_minor: le16(22),
            fw_ver_major: le16(24),
            fw_ver_minor: le16(26),
            fw_ver_patch: le16(28),
            checkin_seq,
            current_svn: le32(40),
            build_number: le32(44),
            installed_app_svn: le32(48),
            installed_stage1_svn: le32(52),
            monotonic_counter: le32(56),
            boot_duration_ms: le32(60),
            verify_time_ms: le32(64),
            last_error_code: le32(68),
            vendor_error: le32(72),
            hardware_fault_record: le32(76),
            edge_recovery_events: le32(80),
            recovery_failure_events: le32(84),
            net_search_accum_ms: le32(88),
            wdt_kicks: le32(92),
            sbom_digest,
            boot_session_id: le32(128),
            ext_health,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Handoff {
    pub magic: u32,
    pub struct_version: u32,
    pub boot_nonce: u64,
    pub booted_partition: Partition,
    pub reset_reason: ResetReason,
    pub boot_failure_count: u32,
    pub net_search_accum_ms: u32,
    pub resume_offset: u32,
    pub device_id: [u8; 32],
    pub wipe_requested: bool,
    pub active_slot: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExtHealth {
    pub wal_erase_count: u32,
    pub app_slot_erase_count: u32,
    pub staging_slot_erase_count: u32,
    pub swap_buffer_erase_count: u32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BootDiagnostics {
    pub struct_version: u32,
    pub boot_duration_ms: u32,
    pub verify_time_ms: u32,
    pub last_error_code: u32,
    pub vendor_error: u32,
    pub hardware_fault_record: u32,
    pub active_key_index: u32,
    pub current_svn: u32,
    pub build_number: u32,
    pub edge_recovery_events: u32,
    pub wdt_kicks: u32,
    pub fw_ver_major: u16,
    pub fw_ver_minor: u16,
    pub fw_ver_patch: u16,
    pub fallback_occurred: bool,
    pub last_update_outcome: u8,
    pub installed_app_svn: u32,
    pub installed_stage1_svn: u32,
    pub reader_major: u16,
    pub reader_minor: u16,
    pub monotonic_counter: u32,
    pub last_update_reject: u8,
    pub boot_session_id: u32,
    pub sbom_digest: [u8; 32],
    pub ext_health: Option<ExtHealth>,
}

pub type BootDiag = BootDiagnostics;

/// Validates that the .noinit handoff structure is valid.
pub fn validate_handoff() -> Result<()> {
    unsafe { sys::toob_validate_handoff().to_result() }
}

/// Retrieves a validated copy of the handoff structure.
pub fn get_handoff() -> Result<Handoff> {
    let mut handoff = unsafe { core::mem::zeroed() };
    unsafe {
        sys::toob_get_handoff(&mut handoff).to_result()?;
    }
    if handoff.active_slot > 1 || handoff.wipe_requested > 1 {
        return Err(ToobError::VerificationFailure);
    }
    Ok(Handoff {
        magic: handoff.magic,
        struct_version: handoff.struct_version,
        boot_nonce: handoff.boot_nonce,
        booted_partition: Partition::try_from(handoff.booted_partition)?,
        reset_reason: ResetReason::try_from(handoff.reset_reason)?,
        boot_failure_count: handoff.boot_failure_count,
        net_search_accum_ms: handoff.net_search_accum_ms,
        resume_offset: handoff.resume_offset,
        device_id: handoff.device_id,
        wipe_requested: handoff.wipe_requested != 0,
        active_slot: handoff.active_slot,
    })
}

/// Confirms the current boot sequence as successful.
pub fn confirm_boot() -> Result<()> {
    unsafe { sys::toob_confirm_boot().to_result() }
}

/// Signal to bootloader that recovery has completed successfully.
pub fn recovery_resolved() -> Result<()> {
    unsafe { sys::toob_recovery_resolved().to_result() }
}

/// Extracts raw hardware metrics (Diag v3).
pub fn get_boot_diag() -> Result<BootDiagnostics> {
    let mut diag = unsafe { core::mem::zeroed() };
    unsafe {
        sys::toob_get_boot_diag(&mut diag).to_result()?;
    }
    Ok(BootDiagnostics {
        struct_version: diag.struct_version,
        boot_duration_ms: diag.boot_duration_ms,
        verify_time_ms: diag.verify_time_ms,
        last_error_code: diag.last_error_code,
        vendor_error: diag.vendor_error,
        hardware_fault_record: diag.hardware_fault_record,
        active_key_index: diag.active_key_index,
        current_svn: diag.current_svn,
        build_number: diag.build_number,
        edge_recovery_events: diag.edge_recovery_events,
        wdt_kicks: diag.wdt_kicks,
        fw_ver_major: diag.fw_ver_major,
        fw_ver_minor: diag.fw_ver_minor,
        fw_ver_patch: diag.fw_ver_patch,
        fallback_occurred: diag.fallback_occurred != 0,
        last_update_outcome: diag.last_update_outcome,
        installed_app_svn: diag.installed_app_svn,
        installed_stage1_svn: diag.installed_stage1_svn,
        reader_major: diag.reader_major,
        reader_minor: diag.reader_minor,
        monotonic_counter: diag.monotonic_counter,
        last_update_reject: diag.last_update_reject,
        boot_session_id: diag.boot_session_id,
        sbom_digest: diag.sbom_digest,
        ext_health: if diag.ext_health_present != 0 {
            Some(ExtHealth {
                wal_erase_count: diag.ext_health.wal_erase_count,
                app_slot_erase_count: diag.ext_health.app_slot_erase_count,
                staging_slot_erase_count: diag.ext_health.staging_slot_erase_count,
                swap_buffer_erase_count: diag.ext_health.swap_buffer_erase_count,
            })
        } else {
            None
        },
    })
}

/// Serializes boot diagnostics into the deterministic Little-Endian `TDR1` binary wire format.
pub fn get_boot_diag_wire(out_buf: &mut [u8]) -> Result<usize> {
    get_boot_diag_wire_seq(out_buf, 0)
}

/// Serializes boot diagnostics into `TDR1` bound to the caller's monotonic `checkin_seq` (`X-Toob-Seq`).
pub fn get_boot_diag_wire_seq(out_buf: &mut [u8], checkin_seq: u64) -> Result<usize> {
    if out_buf.len() < sys::TOOB_TDR1_MIN_FRAME_SIZE {
        return Err(ToobError::InvalidArg);
    }
    let mut out_len = 0usize;
    unsafe {
        sys::toob_get_boot_diag_wire_seq(
            out_buf.as_mut_ptr(),
            out_buf.len(),
            checkin_seq,
            &mut out_len,
        )
        .to_result()?;
    }
    if out_len > out_buf.len() {
        return Err(ToobError::VerificationFailure);
    }
    Ok(out_len)
}

/// Safely extracts the 32-byte DICE Device ID.
pub fn get_device_id() -> Result<[u8; 32]> {
    let mut id = [0u8; 32];
    unsafe {
        sys::toob_get_device_id(id.as_mut_ptr(), id.len()).to_result()?;
    }
    Ok(id)
}

/// Registers update intent in Mailbox.
pub fn set_next_update(manifest_flash_addr: u32) -> Result<()> {
    unsafe { sys::toob_set_next_update(manifest_flash_addr).to_result() }
}

/// Submits a signed TCC1 envelope to the cloud command slot.
pub fn submit_cloud_command(envelope: &[u8]) -> Result<()> {
    if envelope.is_empty() {
        return Err(ToobError::InvalidArg);
    }
    let len = u32::try_from(envelope.len()).map_err(|_| ToobError::InvalidArg)?;
    unsafe { sys::toob_submit_cloud_command(envelope.as_ptr(), len).to_result() }
}

/// Registers or clears the swap lifecycle notification callback.
pub fn set_swap_notifier(cb: sys::toob_swap_notify_fn) {
    unsafe { sys::toob_set_swap_notifier(cb) }
}

pub trait PlatformHooks {
    fn flash_read(addr: u32, buf: &mut [u8]) -> Result<()>;
    fn flash_write(addr: u32, buf: &[u8]) -> Result<()>;
    fn flash_erase(addr: u32, len: u32) -> Result<()>;

    fn sha256_init(ctx: &mut [u8; 128]) -> Result<()>;
    fn sha256_update(ctx: &mut [u8; 128], data: &[u8]) -> Result<()>;
    fn sha256_finalize(ctx: &mut [u8; 128], out_hash: &mut [u8; 32]) -> Result<()>;

    /// Acquire critical-section mutex protecting flash/mailbox/checkpoint state.
    fn lock() {}

    /// Release critical-section mutex protecting flash/mailbox/checkpoint state.
    fn unlock() {}

    /// Write and read-back verify the 64-bit boot confirmation nonce in RTC/retained RAM.
    fn confirm_rtc_write(_nonce: u64) -> Result<()> {
        Err(ToobError::NotSupported)
    }

    /// Read a key-value blob from OS-managed non-volatile storage, returning bytes read.
    fn nvs_read(_key: &str, _buf: &mut [u8]) -> Result<usize> {
        Err(ToobError::NotSupported)
    }

    /// Persist a non-empty key-value blob into OS-managed non-volatile storage.
    fn nvs_write(_key: &str, _buf: &[u8]) -> Result<()> {
        Err(ToobError::NotSupported)
    }
}

#[macro_export]
macro_rules! define_platform {
    ($t:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_read(
            addr: u32,
            buf: *mut u8,
            len: u32,
        ) -> $crate::sys::ToobStatus {
            if buf.is_null() {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let slice = if len == 0 {
                &mut [][..]
            } else {
                let Ok(len_usize) = usize::try_from(len) else {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                };
                if len_usize > (isize::MAX as usize)
                    || buf.addr().checked_add(len_usize).is_none()
                {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                }
                unsafe { core::slice::from_raw_parts_mut(buf, len_usize) }
            };
            match <$t as $crate::PlatformHooks>::flash_read(addr, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_write(
            addr: u32,
            buf: *const u8,
            len: u32,
        ) -> $crate::sys::ToobStatus {
            if buf.is_null() {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let slice = if len == 0 {
                &[][..]
            } else {
                let Ok(len_usize) = usize::try_from(len) else {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                };
                if len_usize > (isize::MAX as usize)
                    || buf.addr().checked_add(len_usize).is_none()
                {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                }
                unsafe { core::slice::from_raw_parts(buf, len_usize) }
            };
            match <$t as $crate::PlatformHooks>::flash_write(addr, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_erase(
            addr: u32,
            len: u32,
        ) -> $crate::sys::ToobStatus {
            match <$t as $crate::PlatformHooks>::flash_erase(addr, len) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_init(
            ctx: *mut $crate::sys::toob_os_sha256_ctx_t,
        ) -> $crate::sys::ToobStatus {
            if ctx.is_null()
                || !ctx.is_aligned()
                || ctx
                    .addr()
                    .checked_add(core::mem::size_of::<$crate::sys::toob_os_sha256_ctx_t>())
                    .is_none()
            {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let context = unsafe { &mut *ctx };
            match <$t as $crate::PlatformHooks>::sha256_init(&mut context.opaque) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_update(
            ctx: *mut $crate::sys::toob_os_sha256_ctx_t,
            data: *const u8,
            len: u32,
        ) -> $crate::sys::ToobStatus {
            if ctx.is_null() || !ctx.is_aligned() || (data.is_null() && len > 0) {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let ctx_start = ctx.addr();
            let Some(ctx_end) =
                ctx_start.checked_add(core::mem::size_of::<$crate::sys::toob_os_sha256_ctx_t>())
            else {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            let slice = if len == 0 {
                &[][..]
            } else {
                let Ok(len_usize) = usize::try_from(len) else {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                };
                let data_start = data.addr();
                let Some(data_end) = data_start.checked_add(len_usize) else {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                };
                if len_usize > (isize::MAX as usize)
                    || (data_start < ctx_end && ctx_start < data_end)
                {
                    return $crate::sys::TOOB_ERR_INVALID_ARG;
                }
                unsafe { core::slice::from_raw_parts(data, len_usize) }
            };
            let context = unsafe { &mut *ctx };
            match <$t as $crate::PlatformHooks>::sha256_update(&mut context.opaque, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_finalize(
            ctx: *mut $crate::sys::toob_os_sha256_ctx_t,
            out_hash: *mut u8,
        ) -> $crate::sys::ToobStatus {
            if ctx.is_null() || !ctx.is_aligned() || out_hash.is_null() {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let ctx_start = ctx.addr();
            let out_start = out_hash.addr();
            let (Some(ctx_end), Some(out_end)) = (
                ctx_start.checked_add(core::mem::size_of::<$crate::sys::toob_os_sha256_ctx_t>()),
                out_start.checked_add(32),
            ) else {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            if out_start < ctx_end && ctx_start < out_end {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let context = unsafe { &mut *ctx };
            let hash_slice = unsafe { &mut *(out_hash as *mut [u8; 32]) };
            match <$t as $crate::PlatformHooks>::sha256_finalize(&mut context.opaque, hash_slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_lock() {
            <$t as $crate::PlatformHooks>::lock();
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_unlock() {
            <$t as $crate::PlatformHooks>::unlock();
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_confirm_rtc_write(
            nonce: u64,
        ) -> $crate::sys::ToobStatus {
            match <$t as $crate::PlatformHooks>::confirm_rtc_write(nonce) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_nvs_read(
            key: *const core::ffi::c_char,
            buf: *mut u8,
            len: *mut usize,
        ) -> $crate::sys::ToobStatus {
            if key.is_null() || buf.is_null() || len.is_null() || !len.is_aligned() {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let len_start = len.addr();
            let Some(len_end) = len_start.checked_add(core::mem::size_of::<usize>()) else {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            let cap = unsafe { *len };
            if cap > (u32::MAX as usize) || cap > (isize::MAX as usize) {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let buf_start = buf.addr();
            let Some(buf_end) = buf_start.checked_add(cap) else {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            if cap > 0 && len_start < buf_end && buf_start < len_end {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let key_cstr = unsafe { core::ffi::CStr::from_ptr(key) };
            let key_start = key.addr();
            let Some(key_end) = key_start.checked_add(key_cstr.to_bytes_with_nul().len()) else {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            if (cap > 0 && key_start < buf_end && buf_start < key_end)
                || (key_start < len_end && len_start < key_end)
            {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let Ok(key_str) = key_cstr.to_str() else {
                unsafe { *len = 0 };
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            let slice = if cap == 0 {
                &mut [][..]
            } else {
                unsafe { core::slice::from_raw_parts_mut(buf, cap) }
            };
            match <$t as $crate::PlatformHooks>::nvs_read(key_str, slice) {
                Ok(n) if n <= cap => {
                    unsafe { *len = n };
                    $crate::sys::TOOB_OK
                }
                Ok(_) => {
                    unsafe { *len = 0 };
                    $crate::sys::TOOB_ERR_INVALID_ARG
                }
                Err(e) => {
                    unsafe { *len = 0 };
                    e.to_status()
                }
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_nvs_write(
            key: *const core::ffi::c_char,
            buf: *const u8,
            len: usize,
        ) -> $crate::sys::ToobStatus {
            if key.is_null()
                || buf.is_null()
                || len == 0
                || len > (u32::MAX as usize)
                || len > (isize::MAX as usize)
                || buf.addr().checked_add(len).is_none()
            {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            }
            let Ok(key_str) = (unsafe { core::ffi::CStr::from_ptr(key) }).to_str() else {
                return $crate::sys::TOOB_ERR_INVALID_ARG;
            };
            let slice = unsafe { core::slice::from_raw_parts(buf, len) };
            match <$t as $crate::PlatformHooks>::nvs_write(key_str, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(e) => e.to_status(),
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyPlatform;
    impl PlatformHooks for DummyPlatform {
        fn flash_read(_addr: u32, _buf: &mut [u8]) -> Result<()> {
            Ok(())
        }
        fn flash_write(_addr: u32, _buf: &[u8]) -> Result<()> {
            Ok(())
        }
        fn flash_erase(_addr: u32, _len: u32) -> Result<()> {
            Ok(())
        }
        fn sha256_init(_ctx: &mut [u8; 128]) -> Result<()> {
            Ok(())
        }
        fn sha256_update(_ctx: &mut [u8; 128], _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn sha256_finalize(_ctx: &mut [u8; 128], _out_hash: &mut [u8; 32]) -> Result<()> {
            Ok(())
        }
    }

    define_platform!(DummyPlatform);

    #[test]
    fn platform_macro_rejects_null_pointers_and_handles_zero_len() {
        let mut byte = 0u8;
        let mut sha_ctx = sys::toob_os_sha256_ctx_t { opaque: [0u8; 128] };
        let mut out_hash = [0u8; 32];
        let mut nvs_len = 1usize;

        unsafe {
            assert_eq!(
                toob_os_flash_read(0, core::ptr::null_mut(), 0),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(toob_os_flash_read(0, &mut byte, 0), sys::TOOB_OK);

            assert_eq!(
                toob_os_flash_write(0, core::ptr::null(), 0),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(toob_os_flash_write(0, &byte, 0), sys::TOOB_OK);

            assert_eq!(
                toob_os_sha256_init(core::ptr::null_mut()),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_sha256_update(core::ptr::null_mut(), &byte, 1),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_sha256_update(&mut sha_ctx, core::ptr::null(), 1),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_sha256_update(&mut sha_ctx, core::ptr::null(), 0),
                sys::TOOB_OK
            );
            assert_eq!(
                toob_os_sha256_finalize(&mut sha_ctx, core::ptr::null_mut()),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_sha256_finalize(&mut sha_ctx, out_hash.as_mut_ptr()),
                sys::TOOB_OK
            );

            toob_os_lock();
            toob_os_unlock();
            assert_eq!(
                toob_os_confirm_rtc_write(0x1122_3344_5566_7788),
                sys::TOOB_ERR_NOT_SUPPORTED
            );

            assert_eq!(
                toob_os_nvs_read(core::ptr::null(), &mut byte, &mut nvs_len),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_read(c"k".as_ptr(), core::ptr::null_mut(), &mut nvs_len),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_read(c"k".as_ptr(), &mut byte, core::ptr::null_mut()),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_read(c"k".as_ptr(), &mut byte, &mut nvs_len),
                sys::TOOB_ERR_NOT_SUPPORTED
            );
            assert_eq!(nvs_len, 0);

            assert_eq!(
                toob_os_nvs_write(core::ptr::null(), &byte, 1),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_write(c"k".as_ptr(), core::ptr::null(), 1),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_write(c"k".as_ptr(), &byte, 0),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(
                toob_os_nvs_write(c"k".as_ptr(), &byte, 1),
                sys::TOOB_ERR_NOT_SUPPORTED
            );
        }
    }

    #[test]
    fn status_roundtrip_covers_all_codes() {
        let cases = [
            (sys::TOOB_ERR_NOT_FOUND, ToobError::NotFound),
            (sys::TOOB_ERR_WAL_FULL, ToobError::WalFull),
            (sys::TOOB_ERR_WAL_LOCKED, ToobError::WalLocked),
            (sys::TOOB_ERR_FLASH, ToobError::FlashFailure),
            (sys::TOOB_ERR_INVALID_ARG, ToobError::InvalidArg),
            (sys::TOOB_ERR_VERIFY, ToobError::VerificationFailure),
            (sys::TOOB_ERR_REQUIRES_RESET, ToobError::RequiresReset),
            (sys::TOOB_ERR_COUNTER_EXHAUSTED, ToobError::CounterExhausted),
            (sys::TOOB_ERR_FLASH_HW, ToobError::FlashHardwareFailure),
            (sys::TOOB_ERR_STATE, ToobError::InvalidState),
            (sys::TOOB_ERR_TIMEOUT, ToobError::Timeout),
            (sys::TOOB_ERR_NOT_SUPPORTED, ToobError::NotSupported),
        ];
        for (raw, expected) in cases {
            assert_eq!(raw.to_result(), Err(expected));
            assert_eq!(expected.to_status(), raw);
        }
        assert_eq!(sys::TOOB_OK.to_result(), Ok(()));
        assert_ne!(ToobError::Unknown(sys::TOOB_OK.0).to_status(), sys::TOOB_OK);
        assert_eq!(
            ToobError::Unknown(0xDEAD_BEEF).to_status(),
            sys::ToobStatus(0xDEAD_BEEF)
        );
    }
}
