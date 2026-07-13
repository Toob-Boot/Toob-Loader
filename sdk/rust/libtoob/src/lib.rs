#![no_std]

pub mod ota;

pub use libtoob_sys as sys;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ToobError {
    NotFound,
    WalFull,
    WalLocked,
    FlashFailure,
    InvalidArg,
    VerificationFailure,
    RequiresReset,
    FlashHardwareFailure,
    Unknown(u32),
}

pub type Result<T> = core::result::Result<T, ToobError>;

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
            sys::TOOB_ERR_FLASH_HW => Err(ToobError::FlashHardwareFailure),
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
    pub boot_session_id: u32,
    pub sbom_digest: [u8; 32],
    pub ext_health: Option<ExtHealth>,
}

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
    Ok(Handoff {
        magic: handoff.magic,
        struct_version: handoff.struct_version,
        boot_nonce: handoff.boot_nonce,
        booted_partition: match sys::ToobPartition(handoff.booted_partition) {
            sys::TOOB_PARTITION_APP => Partition::App,
            _ => Partition::Recovery,
        },
        reset_reason: match sys::ToobResetReason(handoff.reset_reason) {
            sys::TOOB_RESET_POWER_ON => ResetReason::PowerOn,
            sys::TOOB_RESET_PIN => ResetReason::Pin,
            sys::TOOB_RESET_WATCHDOG => ResetReason::Watchdog,
            sys::TOOB_RESET_BROWNOUT => ResetReason::Brownout,
            sys::TOOB_RESET_SOFTWARE => ResetReason::Software,
            sys::TOOB_RESET_HARD_FAULT => ResetReason::HardFault,
            _ => ResetReason::Unknown,
        },
        boot_failure_count: handoff.boot_failure_count,
        net_search_accum_ms: handoff.net_search_accum_ms,
        resume_offset: handoff.resume_offset,
        device_id: handoff.device_id,
        wipe_requested: handoff.wipe_requested != 0,
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

/// Extracts raw hardware metrics.
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

/// Extracts diagnostics formatted as CBOR.
pub fn get_boot_diag_cbor(out_buf: &mut [u8]) -> Result<usize> {
    let mut out_len = 0;
    unsafe {
        sys::toob_get_boot_diag_cbor(out_buf.as_mut_ptr(), out_buf.len(), &mut out_len).to_result()?;
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

/// Registers update intent in WAL.
pub fn set_next_update(manifest_flash_addr: u32) -> Result<()> {
    unsafe { sys::toob_set_next_update(manifest_flash_addr).to_result() }
}

/// Submits an envelope to the cloud command slot.
pub fn submit_cloud_command(envelope: &[u8]) -> Result<()> {
    unsafe { sys::toob_submit_cloud_command(envelope.as_ptr(), envelope.len() as u32).to_result() }
}

pub trait PlatformHooks {
    fn flash_read(addr: u32, buf: &mut [u8]) -> Result<()>;
    fn flash_write(addr: u32, buf: &[u8]) -> Result<()>;
    fn flash_erase(addr: u32, len: u32) -> Result<()>;
    
    fn sha256_init(ctx: &mut [u8; 128]) -> Result<()>;
    fn sha256_update(ctx: &mut [u8; 128], data: &[u8]) -> Result<()>;
    fn sha256_finalize(ctx: &mut [u8; 128], out_hash: &mut [u8; 32]) -> Result<()>;
}

#[macro_export]
macro_rules! define_platform {
    ($t:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_read(addr: u32, buf: *mut u8, len: u32) -> $crate::sys::ToobStatus {
            let slice = core::slice::from_raw_parts_mut(buf, len as usize);
            match <$t as $crate::PlatformHooks>::flash_read(addr, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_write(addr: u32, buf: *const u8, len: u32) -> $crate::sys::ToobStatus {
            let slice = core::slice::from_raw_parts(buf, len as usize);
            match <$t as $crate::PlatformHooks>::flash_write(addr, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_flash_erase(addr: u32, len: u32) -> $crate::sys::ToobStatus {
            match <$t as $crate::PlatformHooks>::flash_erase(addr, len) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_init(ctx: *mut $crate::sys::toob_os_sha256_ctx_t) -> $crate::sys::ToobStatus {
            let context = unsafe { &mut *ctx };
            match <$t as $crate::PlatformHooks>::sha256_init(&mut context.opaque) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_update(ctx: *mut $crate::sys::toob_os_sha256_ctx_t, data: *const u8, len: u32) -> $crate::sys::ToobStatus {
            let context = unsafe { &mut *ctx };
            let slice = unsafe { core::slice::from_raw_parts(data, len as usize) };
            match <$t as $crate::PlatformHooks>::sha256_update(&mut context.opaque, slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn toob_os_sha256_finalize(ctx: *mut $crate::sys::toob_os_sha256_ctx_t, out_hash: *mut u8) -> $crate::sys::ToobStatus {
            let context = unsafe { &mut *ctx };
            let hash_slice = unsafe { &mut *(out_hash as *mut [u8; 32]) };
            match <$t as $crate::PlatformHooks>::sha256_finalize(&mut context.opaque, hash_slice) {
                Ok(()) => $crate::sys::TOOB_OK,
                Err(_) => $crate::sys::TOOB_ERR_FLASH,
            }
        }
    };
}
