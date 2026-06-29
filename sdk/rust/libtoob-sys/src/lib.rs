#![no_std]

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ToobStatus(pub u32);

pub const TOOB_OK: ToobStatus = ToobStatus(0x55AA55AA);
pub const TOOB_ERR_NOT_FOUND: ToobStatus = ToobStatus(0xE1101CAE);
pub const TOOB_ERR_WAL_FULL: ToobStatus = ToobStatus(0xE2201CAE);
pub const TOOB_ERR_WAL_LOCKED: ToobStatus = ToobStatus(0xE3301CAE);
pub const TOOB_ERR_FLASH: ToobStatus = ToobStatus(0xE4401CAE);
pub const TOOB_ERR_INVALID_ARG: ToobStatus = ToobStatus(0xE5501CAE);
pub const TOOB_ERR_VERIFY: ToobStatus = ToobStatus(0xE6601CAE);
pub const TOOB_ERR_REQUIRES_RESET: ToobStatus = ToobStatus(0xE7701CAE);
pub const TOOB_ERR_FLASH_HW: ToobStatus = ToobStatus(0xE9901CAE);

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ToobPartition(pub u32);
pub const TOOB_PARTITION_APP: ToobPartition = ToobPartition(0x0000000A);
pub const TOOB_PARTITION_RECOVERY: ToobPartition = ToobPartition(0x0000000B);

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ToobResetReason(pub u32);
pub const TOOB_RESET_UNKNOWN: ToobResetReason = ToobResetReason(0);
pub const TOOB_RESET_POWER_ON: ToobResetReason = ToobResetReason(1);
pub const TOOB_RESET_PIN: ToobResetReason = ToobResetReason(2);
pub const TOOB_RESET_WATCHDOG: ToobResetReason = ToobResetReason(3);
pub const TOOB_RESET_BROWNOUT: ToobResetReason = ToobResetReason(4);
pub const TOOB_RESET_SOFTWARE: ToobResetReason = ToobResetReason(5);
pub const TOOB_RESET_HARD_FAULT: ToobResetReason = ToobResetReason(6);

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct toob_handoff_t {
    pub magic: u32,
    pub struct_version: u32,
    pub boot_nonce: u64,
    pub booted_partition: u32,
    pub reset_reason: u32,
    pub boot_failure_count: u32,
    pub net_search_accum_ms: u32,
    pub resume_offset: u32,
    pub device_id: [u8; 32],
    pub wipe_requested: u8,
    pub _padding: [u8; 7],
    pub crc32_trailer: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct toob_ext_health_t {
    pub wal_erase_count: u32,
    pub app_slot_erase_count: u32,
    pub staging_slot_erase_count: u32,
    pub swap_buffer_erase_count: u32,
}

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct toob_boot_diag_t {
    pub struct_version: u32,
    pub boot_duration_ms: u32,
    pub verify_time_ms: u32,
    pub last_error_code: u32,
    pub vendor_error: u32,
    pub active_key_index: u32,
    pub current_svn: u32,
    pub edge_recovery_events: u32,
    pub sbom_digest: [u8; 32],
    pub ext_health_present: u8,
    pub _padding: [u8; 3],
    pub ext_health: toob_ext_health_t,
    pub crc32_trailer: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct toob_os_sha256_ctx_t {
    pub opaque: [u8; 128],
}

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct toob_ota_ctx_t {
    pub state: u8,
    pub is_verified: u8,
    pub _reserved: [u8; 2],
    pub write_cursor: u32,
    pub total_size: u32,
    pub bytes_queued: u32,
    pub buf_len: u32,
    pub align_buf: [u8; 256],
    pub expected_sha256: [u8; 32],
    pub sha_ctx: toob_os_sha256_ctx_t,
}

// Compile-time checks matching C asserts exactly
const _: () = {
    assert!(core::mem::size_of::<toob_handoff_t>() == 80);
    assert!(core::mem::align_of::<toob_handoff_t>() == 8);
    assert!(core::mem::size_of::<toob_boot_diag_t>() == 88);
    assert!(core::mem::align_of::<toob_boot_diag_t>() == 8);
    assert!(core::mem::size_of::<toob_ota_ctx_t>() == 440);
    assert!(core::mem::align_of::<toob_ota_ctx_t>() == 8);
};

extern "C" {
    pub fn toob_validate_handoff() -> ToobStatus;
    pub fn toob_get_handoff(out_handoff: *mut toob_handoff_t) -> ToobStatus;
    pub fn toob_confirm_boot() -> ToobStatus;
    pub fn toob_recovery_resolved() -> ToobStatus;
    pub fn toob_accumulate_net_search(active_search_ms: u32) -> ToobStatus;
    pub fn toob_get_boot_diag(diag: *mut toob_boot_diag_t) -> ToobStatus;
    pub fn toob_get_boot_diag_cbor(out_buf: *mut u8, max_len: usize, out_len: *mut usize) -> ToobStatus;
    pub fn toob_set_next_update(manifest_flash_addr: u32) -> ToobStatus;
    pub fn toob_submit_cloud_command(envelope: *const u8, len: u32) -> ToobStatus;
    pub fn toob_get_device_id(out_id: *mut u8, id_len: usize) -> ToobStatus;
    
    pub fn toob_ota_ctx_init(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
    pub fn toob_ota_begin(ctx: *mut toob_ota_ctx_t, total_size: u32) -> ToobStatus;
    pub fn toob_ota_begin_verified(ctx: *mut toob_ota_ctx_t, total_size: u32, expected_sha256: *const u8) -> ToobStatus;
    pub fn toob_ota_resume(ctx: *mut toob_ota_ctx_t, total_size: u32, resume_offset: *mut u32) -> ToobStatus;
    pub fn toob_ota_resume_verified(ctx: *mut toob_ota_ctx_t, total_size: u32, expected_sha256: *const u8, resume_offset: *mut u32) -> ToobStatus;
    pub fn toob_ota_abort(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
    pub fn toob_ota_process_chunk(ctx: *mut toob_ota_ctx_t, chunk: *const u8, len: u32) -> ToobStatus;
    pub fn toob_ota_finalize(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
}
