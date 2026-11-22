#![no_std]

use core::ffi::c_char;
use core::mem::{align_of, offset_of, size_of};

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
pub const TOOB_ERR_COUNTER_EXHAUSTED: ToobStatus = ToobStatus(0xE8801CAE);
pub const TOOB_ERR_FLASH_HW: ToobStatus = ToobStatus(0xE9901CAE);
pub const TOOB_ERR_STATE: ToobStatus = ToobStatus(0xEAA01CAE);
pub const TOOB_ERR_TIMEOUT: ToobStatus = ToobStatus(0xEBB01CAE);
pub const TOOB_ERR_NOT_SUPPORTED: ToobStatus = ToobStatus(0xECC01CAE);

pub const TOOB_STATE_TENTATIVE: u32 = 0xAAAA5555;
pub const TOOB_STATE_COMMITTED: u32 = 0x55AA55AA;
pub const TOOB_HANDOFF_STRUCT_VERSION: u32 = 0x02000000;
pub const TOOB_DIAG_STRUCT_VERSION: u32 = 0x03000000;
pub const TOOB_OTA_RESUME_MAGIC: u32 = 0x544F4F42;
pub const TOOB_OTA_BUF_SIZE: usize = 256;
pub const TOOB_TBM1_TRAILER_MAGIC: u32 = 0x544D_4254;

// TDR1 wire constants (common/include/toob_checkin_wire.h)
pub const TOOB_TDR1_MAGIC: u32 = 0x3152_4454;
pub const TOOB_TDR1_VERSION: u8 = 1;
pub const TOOB_TDR1_MIN_DIAG_MAJOR: u8 = 3;
pub const TOOB_TDR1_HDR_SIZE: usize = 132;
pub const TOOB_TDR1_EXT_HEALTH_SIZE: usize = 16;
pub const TOOB_TDR1_CRC_TRAILER_SIZE: usize = 4;
pub const TOOB_TDR1_MIN_FRAME_SIZE: usize = TOOB_TDR1_HDR_SIZE + TOOB_TDR1_CRC_TRAILER_SIZE;
pub const TOOB_TDR1_MAX_SIZE: usize =
    TOOB_TDR1_HDR_SIZE + TOOB_TDR1_EXT_HEALTH_SIZE + TOOB_TDR1_CRC_TRAILER_SIZE;
pub const TOOB_TDR1_FLAG_EXT_HEALTH: u16 = 0x0001;
pub const TOOB_TDR1_KNOWN_FLAGS_MASK: u16 = TOOB_TDR1_FLAG_EXT_HEALTH;
pub const TOOB_TDR1_PARTITION_APP: u8 = 0;
pub const TOOB_TDR1_PARTITION_RECOVERY: u8 = 2;
pub const TOOB_TDR1_BOOT_STATE_COMMITTED: u8 = 0;
pub const TOOB_TDR1_BOOT_STATE_TENTATIVE: u8 = 1;
pub const TOOB_TDR1_MAX_RESET_REASON: u8 = 6;
pub const TOOB_TDR1_OUTCOME_NONE: u8 = 0;
pub const TOOB_TDR1_OUTCOME_APPLIED: u8 = 1;
pub const TOOB_TDR1_OUTCOME_REJECTED: u8 = 2;
pub const TOOB_TDR1_OUTCOME_REVERTED: u8 = 3;
pub const TOOB_TDR1_OUTCOME_DEFERRED: u8 = 4;
pub const TOOB_TDR1_MAX_OUTCOME: u8 = 4;

// TCI1 wire constants (common/include/toob_checkin_wire.h)
pub const TOOB_TCI1_MAGIC: u32 = 0x3149_4354;
pub const TOOB_TCI1_VERSION: u8 = 1;
pub const TOOB_TCI1_HDR_SIZE: usize = 88;
pub const TOOB_TCI1_AUTH_TAG_LEN: usize = 16;
pub const TOOB_TCI1_MIN_FRAME_SIZE: usize = TOOB_TCI1_HDR_SIZE + TOOB_TCI1_AUTH_TAG_LEN;
pub const TOOB_TCI1_ROTATED_TOKEN_LEN: usize = 32;
pub const TOOB_TCI1_ASSIGNMENT_ID_LEN: usize = 16;
pub const TOOB_TCI1_MAX_BLOB_PATH_LEN: usize = 120;
pub const TOOB_TCI1_MIN_CLOUD_CMD_LEN: usize = 128;
pub const TOOB_TCI1_MAX_CLOUD_CMD_LEN: usize = 400;
pub const TOOB_TCI1_MAX_FRAME_SIZE: usize = 512;
pub const TOOB_TCI1_MIN_TBM1_TOTAL_SIZE: u32 = 576;
pub const TOOB_TCI1_MAX_RETRY_AFTER_SEC: u32 = 604_800;
pub const TOOB_TCI1_SLOT_APP: u8 = 0;
pub const TOOB_TCI1_SLOT_NETCORE: u8 = 1;
pub const TOOB_TCI1_SLOT_STAGE1: u8 = 3;
pub const TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN: u16 = 0x0001;
pub const TOOB_TCI1_FLAG_HAS_CLOUD_CMD: u16 = 0x0002;
pub const TOOB_TCI1_KNOWN_FLAGS_MASK: u16 =
    TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN | TOOB_TCI1_FLAG_HAS_CLOUD_CMD;

// TCC1 wire constants (common/include/toob_cloud_cmd_wire.h & boot_types.h)
pub const TOOB_CLOUD_CMD_MAGIC: u32 = 0x3143_4354;
pub const TOOB_CLOUD_CMD_VERSION: u8 = 1;
pub const TOOB_CLOUD_CMD_HDR_SIZE: usize = 64;
pub const TOOB_CLOUD_CMD_SIG_SIZE: usize = 64;
pub const TOOB_CLOUD_CMD_MIN_SIZE: usize = 128;
pub const TOOB_CLOUD_CMD_MAX_SIZE: usize = 1792;
pub const TOOB_CLOUD_CMD_ALIGN: usize = 16;
pub const TOOB_CLOUD_CMD_MAX_PARAMS: usize = TOOB_CLOUD_CMD_MAX_SIZE - TOOB_CLOUD_CMD_MIN_SIZE;
pub const TOOB_CLOUD_CMD_HDR_CRC_LEN: usize = 56;

pub const TOOB_CMD_NOP: u8 = 0x00;
pub const TOOB_CMD_FORCE_UPDATE: u8 = 0x01;
pub const TOOB_CMD_KILLSWITCH: u8 = 0x02;
pub const TOOB_CMD_UNLOCK: u8 = 0x03;
pub const TOOB_CMD_ROTATE_KEY: u8 = 0x04;
pub const TOOB_CMD_WIPE: u8 = 0x05;
pub const TOOB_CMD_REVOKE: u8 = 0x06;

// Mailbox wire constants (common/include/toob_mailbox_wire.h)
pub const TOOB_MAILBOX_MAGIC: u32 = 0x5842_4D54;
pub const TOOB_MAILBOX_VERSION: u16 = 2;
pub const TOOB_MAILBOX_SLOTS: usize = 2;
pub const TOOB_MAILBOX_CRC_LEN: usize = 24;
pub const TOOB_REQ_NONE: u16 = 0x0000;
pub const TOOB_REQ_UPDATE_PENDING: u16 = 0x0001;
pub const TOOB_REQ_CONFIRM: u16 = 0x0002;
pub const TOOB_REQ_RECOVERY_RESOLVED: u16 = 0x0004;
pub const TOOB_REQ_ALL_MASK: u16 = 0x0007;

#[allow(non_camel_case_types)]
pub type toob_req_t = u16;

// Swap event constants (common/include/toob_swap_event_wire.h)
pub const TOOB_SWAP_EVENT_ABI_VERSION: u16 = 1;
pub const TOOB_SWAP_PHASE_PREPARE: u16 = 0;
pub const TOOB_SWAP_PHASE_SWAPPING: u16 = 1;
pub const TOOB_SWAP_PHASE_DONE: u16 = 2;
pub const TOOB_SWAP_PHASE_RESUMED: u16 = 3;
pub const TOOB_SWAP_PHASE_RECOVERY: u16 = 4;

// WAL wire constants (common/include/toob_wal_wire.h)
pub const TOOB_WAL_ENTRY_MAGIC: u32 = 0xB007_BEEF;
pub const TOOB_WAL_SECTOR_MAGIC_LEGACY: u32 = 0x5741_4C02;
pub const TOOB_WAL_SECTOR_MAGIC_CURRENT: u32 = 0x5741_4C03;
pub const TOOB_WAL_SECTOR_MAGIC: u32 = TOOB_WAL_SECTOR_MAGIC_CURRENT;
pub const TOOB_WAL_HEADER_SIZE: usize = 128;

pub const TOOB_WAL_INTENT_NONE: u32 = 0;
pub const TOOB_WAL_INTENT_TXN_BEGIN: u32 = 1;
pub const TOOB_WAL_INTENT_UPDATE_PENDING: u32 = 2;
pub const TOOB_WAL_INTENT_TXN_COMMIT: u32 = 3;
pub const TOOB_WAL_INTENT_CONFIRM_COMMIT: u32 = 4;
pub const TOOB_WAL_INTENT_RECOVERY_RESOLVED: u32 = 5;
pub const TOOB_WAL_INTENT_TXN_ROLLBACK: u32 = 6;
pub const TOOB_WAL_INTENT_DEPRECATED_NONCE: u32 = 7;
pub const TOOB_WAL_INTENT_NET_SEARCH_ACCUM: u32 = 8;
pub const TOOB_WAL_INTENT_SLEEP_BACKOFF: u32 = 9;
pub const TOOB_WAL_INTENT_TXN_ROLLBACK_PENDING: u32 = 10;
pub const TOOB_WAL_INTENT_DOWNLOAD_CHECKPOINT: u32 = 11;
pub const TOOB_WAL_INTENT_CLOUD_CMD: u32 = 12;
pub const TOOB_WAL_INTENT_DEVICE_LOCKED: u32 = 13;

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
    pub active_slot: u8,
    pub _padding: [u8; 6],
    pub crc32_trailer: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
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
    pub hardware_fault_record: u32,
    pub active_key_index: u32,
    pub current_svn: u32,
    pub build_number: u32,
    pub edge_recovery_events: u32,
    pub wdt_kicks: u32,
    pub fw_ver_major: u16,
    pub fw_ver_minor: u16,
    pub fw_ver_patch: u16,
    pub fallback_occurred: u8,
    pub last_update_outcome: u8,
    pub installed_app_svn: u32,
    pub installed_stage1_svn: u32,
    pub reader_major: u16,
    pub reader_minor: u16,
    pub monotonic_counter: u32,
    pub last_update_reject: u8,
    pub _padding_v3: [u8; 3],
    pub boot_session_id: u32,
    pub sbom_digest: [u8; 32],
    pub ext_health_present: u8,
    pub _padding: [u8; 3],
    pub ext_health: toob_ext_health_t,
    pub crc32_trailer: u32,
    pub _padding_end: [u8; 4],
}

#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct toob_ota_resume_state_t {
    pub magic: u32,
    pub bytes_staged: u32,
    pub artifact_sha256: [u8; 32],
    pub assignment_id: [u8; 16],
    pub target_addr: u32,
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
    pub erased_sectors: u16,
    pub write_cursor: u32,
    pub total_size: u32,
    pub bytes_queued: u32,
    pub buf_len: u32,
    pub align_buf: [u8; TOOB_OTA_BUF_SIZE],
    pub expected_sha256: [u8; 32],
    pub sha_ctx: toob_os_sha256_ctx_t,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_swap_event_t {
    pub abi_version: u16,
    pub phase: u16,
    pub sectors_done: u32,
    pub sectors_total: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_tbm1_trailer_locator_t {
    pub magic: u32,
    pub tbm1_off: u32,
    pub tbm1_len: u32,
    pub crc32: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_tdr1_wire_hdr_t {
    pub magic: u32,
    pub version: u8,
    pub booted_partition: u8,
    pub flags: u16,
    pub header_size: u16,
    pub diag_major: u8,
    pub boot_state: u8,
    pub active_slot: u8,
    pub reset_reason: u8,
    pub fallback_occurred: u8,
    pub wipe_requested: u8,
    pub last_update_outcome: u8,
    pub last_update_reject: u8,
    pub active_key_index: u16,
    pub reader_major: u16,
    pub reader_minor: u16,
    pub fw_ver_major: u16,
    pub fw_ver_minor: u16,
    pub fw_ver_patch: u16,
    pub _reserved0: u16,
    pub checkin_seq_lo: u32,
    pub checkin_seq_hi: u32,
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
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct toob_tdr1_wire_ext_health_t {
    pub wal_erase_count: u32,
    pub app_slot_erase_count: u32,
    pub staging_slot_erase_count: u32,
    pub swap_buffer_erase_count: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_tci1_wire_hdr_t {
    pub magic: u32,
    pub version: u8,
    pub target_slot: u8,
    pub flags: u16,
    pub header_size: u16,
    pub blob_path_len: u16,
    pub cloud_cmd_len: u16,
    pub _reserved0: u16,
    pub remote_svn: u32,
    pub total_size: u32,
    pub sha256: [u8; 32],
    pub assignment_id: [u8; 16],
    pub seq_echo_lo: u32,
    pub seq_echo_hi: u32,
    pub remote_build: u32,
    pub retry_after_sec: u32,
}

#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_cloud_cmd_hdr_t {
    pub magic: u32,
    pub version: u8,
    pub command: u8,
    pub flags: u16,
    pub counter_min: u32,
    pub issued_at: u32,
    pub params_len: u32,
    pub total_len: u32,
    pub device_id: [u8; 32],
    pub crc32: u32,
    pub _reserved: u32,
}

#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_mailbox_t {
    pub magic: u32,
    pub version: u16,
    pub request: u16,
    pub seq: u32,
    pub tbm1_addr: u32,
    pub nonce: u64,
    pub crc32: u32,
    pub _reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct toob_wal_entry_payload_t {
    pub magic: u32,
    pub intent: u32,
    pub expected_nonce: u64,
    pub update_deadline: u16,
    pub transport_id: u8,
    pub _pad_txn: u8,
    pub transfer_bitmap: [u32; 8],
    pub delta_chunk_id: u32,
    pub offset: u32,
    pub crc32_trailer: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct toob_wal_sector_header_t {
    pub sector_magic: u32,
    pub sequence_id: u32,
    pub erase_count: u32,
    pub _reserved_tmr_space: [u8; 112],
    pub header_crc32: u32,
}

#[allow(non_camel_case_types)]
pub type toob_swap_notify_fn = Option<unsafe extern "C" fn(ev: *const toob_swap_event_t)>;

// Compile-time ABI layout & offset checks verified on both 32-bit MCU and 64-bit host targets
const _: () = {
    #[cfg(target_pointer_width = "32")]
    {
        assert!(size_of::<usize>() == 4);
        assert!(align_of::<usize>() == 4);
    }

    assert!(size_of::<c_char>() == 1);
    assert!(align_of::<c_char>() == 1);

    assert!(size_of::<ToobStatus>() == 4);
    assert!(align_of::<ToobStatus>() == 4);

    assert!(size_of::<toob_handoff_t>() == 80);
    assert!(align_of::<toob_handoff_t>() == 8);
    assert!(offset_of!(toob_handoff_t, magic) == 0);
    assert!(offset_of!(toob_handoff_t, struct_version) == 4);
    assert!(offset_of!(toob_handoff_t, boot_nonce) == 8);
    assert!(offset_of!(toob_handoff_t, booted_partition) == 16);
    assert!(offset_of!(toob_handoff_t, reset_reason) == 20);
    assert!(offset_of!(toob_handoff_t, boot_failure_count) == 24);
    assert!(offset_of!(toob_handoff_t, net_search_accum_ms) == 28);
    assert!(offset_of!(toob_handoff_t, resume_offset) == 32);
    assert!(offset_of!(toob_handoff_t, device_id) == 36);
    assert!(offset_of!(toob_handoff_t, wipe_requested) == 68);
    assert!(offset_of!(toob_handoff_t, active_slot) == 69);
    assert!(offset_of!(toob_handoff_t, _padding) == 70);
    assert!(offset_of!(toob_handoff_t, crc32_trailer) == 76);

    assert!(size_of::<toob_ext_health_t>() == 16);
    assert!(align_of::<toob_ext_health_t>() == 4);
    assert!(offset_of!(toob_ext_health_t, wal_erase_count) == 0);
    assert!(offset_of!(toob_ext_health_t, app_slot_erase_count) == 4);
    assert!(offset_of!(toob_ext_health_t, staging_slot_erase_count) == 8);
    assert!(offset_of!(toob_ext_health_t, swap_buffer_erase_count) == 12);

    assert!(size_of::<toob_boot_diag_t>() == 136);
    assert!(align_of::<toob_boot_diag_t>() == 8);
    assert!(offset_of!(toob_boot_diag_t, struct_version) == 0);
    assert!(offset_of!(toob_boot_diag_t, boot_duration_ms) == 4);
    assert!(offset_of!(toob_boot_diag_t, verify_time_ms) == 8);
    assert!(offset_of!(toob_boot_diag_t, last_error_code) == 12);
    assert!(offset_of!(toob_boot_diag_t, vendor_error) == 16);
    assert!(offset_of!(toob_boot_diag_t, hardware_fault_record) == 20);
    assert!(offset_of!(toob_boot_diag_t, active_key_index) == 24);
    assert!(offset_of!(toob_boot_diag_t, current_svn) == 28);
    assert!(offset_of!(toob_boot_diag_t, build_number) == 32);
    assert!(offset_of!(toob_boot_diag_t, edge_recovery_events) == 36);
    assert!(offset_of!(toob_boot_diag_t, wdt_kicks) == 40);
    assert!(offset_of!(toob_boot_diag_t, fw_ver_major) == 44);
    assert!(offset_of!(toob_boot_diag_t, fw_ver_minor) == 46);
    assert!(offset_of!(toob_boot_diag_t, fw_ver_patch) == 48);
    assert!(offset_of!(toob_boot_diag_t, fallback_occurred) == 50);
    assert!(offset_of!(toob_boot_diag_t, last_update_outcome) == 51);
    assert!(offset_of!(toob_boot_diag_t, installed_app_svn) == 52);
    assert!(offset_of!(toob_boot_diag_t, installed_stage1_svn) == 56);
    assert!(offset_of!(toob_boot_diag_t, reader_major) == 60);
    assert!(offset_of!(toob_boot_diag_t, reader_minor) == 62);
    assert!(offset_of!(toob_boot_diag_t, monotonic_counter) == 64);
    assert!(offset_of!(toob_boot_diag_t, last_update_reject) == 68);
    assert!(offset_of!(toob_boot_diag_t, _padding_v3) == 69);
    assert!(offset_of!(toob_boot_diag_t, boot_session_id) == 72);
    assert!(offset_of!(toob_boot_diag_t, sbom_digest) == 76);
    assert!(offset_of!(toob_boot_diag_t, ext_health_present) == 108);
    assert!(offset_of!(toob_boot_diag_t, _padding) == 109);
    assert!(offset_of!(toob_boot_diag_t, ext_health) == 112);
    assert!(offset_of!(toob_boot_diag_t, crc32_trailer) == 128);
    assert!(offset_of!(toob_boot_diag_t, _padding_end) == 132);

    assert!(size_of::<toob_ota_resume_state_t>() == 64);
    assert!(align_of::<toob_ota_resume_state_t>() == 8);
    assert!(offset_of!(toob_ota_resume_state_t, magic) == 0);
    assert!(offset_of!(toob_ota_resume_state_t, bytes_staged) == 4);
    assert!(offset_of!(toob_ota_resume_state_t, artifact_sha256) == 8);
    assert!(offset_of!(toob_ota_resume_state_t, assignment_id) == 40);
    assert!(offset_of!(toob_ota_resume_state_t, target_addr) == 56);
    assert!(offset_of!(toob_ota_resume_state_t, crc32_trailer) == 60);

    assert!(size_of::<toob_os_sha256_ctx_t>() == 128);
    assert!(align_of::<toob_os_sha256_ctx_t>() == 1);

    assert!(size_of::<toob_ota_ctx_t>() == 440);
    assert!(align_of::<toob_ota_ctx_t>() == 8);
    assert!(offset_of!(toob_ota_ctx_t, state) == 0);
    assert!(offset_of!(toob_ota_ctx_t, is_verified) == 1);
    assert!(offset_of!(toob_ota_ctx_t, erased_sectors) == 2);
    assert!(offset_of!(toob_ota_ctx_t, write_cursor) == 4);
    assert!(offset_of!(toob_ota_ctx_t, total_size) == 8);
    assert!(offset_of!(toob_ota_ctx_t, bytes_queued) == 12);
    assert!(offset_of!(toob_ota_ctx_t, buf_len) == 16);
    assert!(offset_of!(toob_ota_ctx_t, align_buf) == 20);
    assert!(offset_of!(toob_ota_ctx_t, expected_sha256) == 276);
    assert!(offset_of!(toob_ota_ctx_t, sha_ctx) == 308);

    assert!(size_of::<toob_swap_event_t>() == 16);
    assert!(align_of::<toob_swap_event_t>() == 4);
    assert!(offset_of!(toob_swap_event_t, abi_version) == 0);
    assert!(offset_of!(toob_swap_event_t, phase) == 2);
    assert!(offset_of!(toob_swap_event_t, sectors_done) == 4);
    assert!(offset_of!(toob_swap_event_t, sectors_total) == 8);
    assert!(offset_of!(toob_swap_event_t, flags) == 12);

    assert!(size_of::<toob_tbm1_trailer_locator_t>() == 16);
    assert!(align_of::<toob_tbm1_trailer_locator_t>() == 4);
    assert!(offset_of!(toob_tbm1_trailer_locator_t, magic) == 0);
    assert!(offset_of!(toob_tbm1_trailer_locator_t, tbm1_off) == 4);
    assert!(offset_of!(toob_tbm1_trailer_locator_t, tbm1_len) == 8);
    assert!(offset_of!(toob_tbm1_trailer_locator_t, crc32) == 12);

    assert!(size_of::<toob_tdr1_wire_hdr_t>() == TOOB_TDR1_HDR_SIZE);
    assert!(align_of::<toob_tdr1_wire_hdr_t>() == 4);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, magic) == 0);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, version) == 4);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, booted_partition) == 5);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, flags) == 6);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, header_size) == 8);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, diag_major) == 10);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, boot_state) == 11);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, active_slot) == 12);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, reset_reason) == 13);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, fallback_occurred) == 14);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, wipe_requested) == 15);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, last_update_outcome) == 16);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, last_update_reject) == 17);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, active_key_index) == 18);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, reader_major) == 20);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, reader_minor) == 22);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, fw_ver_major) == 24);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, fw_ver_minor) == 26);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, fw_ver_patch) == 28);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, _reserved0) == 30);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, checkin_seq_lo) == 32);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, checkin_seq_hi) == 36);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, current_svn) == 40);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, build_number) == 44);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, installed_app_svn) == 48);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, installed_stage1_svn) == 52);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, monotonic_counter) == 56);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, boot_duration_ms) == 60);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, verify_time_ms) == 64);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, last_error_code) == 68);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, vendor_error) == 72);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, hardware_fault_record) == 76);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, edge_recovery_events) == 80);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, recovery_failure_events) == 84);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, net_search_accum_ms) == 88);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, wdt_kicks) == 92);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, sbom_digest) == 96);
    assert!(offset_of!(toob_tdr1_wire_hdr_t, boot_session_id) == 128);

    assert!(size_of::<toob_tdr1_wire_ext_health_t>() == TOOB_TDR1_EXT_HEALTH_SIZE);
    assert!(align_of::<toob_tdr1_wire_ext_health_t>() == 4);
    assert!(offset_of!(toob_tdr1_wire_ext_health_t, wal_erase_count) == 0);
    assert!(offset_of!(toob_tdr1_wire_ext_health_t, app_slot_erase_count) == 4);
    assert!(offset_of!(toob_tdr1_wire_ext_health_t, staging_slot_erase_count) == 8);
    assert!(offset_of!(toob_tdr1_wire_ext_health_t, swap_buffer_erase_count) == 12);

    assert!(size_of::<toob_tci1_wire_hdr_t>() == TOOB_TCI1_HDR_SIZE);
    assert!(align_of::<toob_tci1_wire_hdr_t>() == 4);
    assert!(offset_of!(toob_tci1_wire_hdr_t, magic) == 0);
    assert!(offset_of!(toob_tci1_wire_hdr_t, version) == 4);
    assert!(offset_of!(toob_tci1_wire_hdr_t, target_slot) == 5);
    assert!(offset_of!(toob_tci1_wire_hdr_t, flags) == 6);
    assert!(offset_of!(toob_tci1_wire_hdr_t, header_size) == 8);
    assert!(offset_of!(toob_tci1_wire_hdr_t, blob_path_len) == 10);
    assert!(offset_of!(toob_tci1_wire_hdr_t, cloud_cmd_len) == 12);
    assert!(offset_of!(toob_tci1_wire_hdr_t, _reserved0) == 14);
    assert!(offset_of!(toob_tci1_wire_hdr_t, remote_svn) == 16);
    assert!(offset_of!(toob_tci1_wire_hdr_t, total_size) == 20);
    assert!(offset_of!(toob_tci1_wire_hdr_t, sha256) == 24);
    assert!(offset_of!(toob_tci1_wire_hdr_t, assignment_id) == 56);
    assert!(offset_of!(toob_tci1_wire_hdr_t, seq_echo_lo) == 72);
    assert!(offset_of!(toob_tci1_wire_hdr_t, seq_echo_hi) == 76);
    assert!(offset_of!(toob_tci1_wire_hdr_t, remote_build) == 80);
    assert!(offset_of!(toob_tci1_wire_hdr_t, retry_after_sec) == 84);

    assert!(size_of::<toob_cloud_cmd_hdr_t>() == TOOB_CLOUD_CMD_HDR_SIZE);
    assert!(align_of::<toob_cloud_cmd_hdr_t>() == 8);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, magic) == 0);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, version) == 4);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, command) == 5);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, flags) == 6);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, counter_min) == 8);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, issued_at) == 12);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, params_len) == 16);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, total_len) == 20);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, device_id) == 24);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, crc32) == TOOB_CLOUD_CMD_HDR_CRC_LEN);
    assert!(offset_of!(toob_cloud_cmd_hdr_t, _reserved) == 60);

    assert!(size_of::<toob_mailbox_t>() == 32);
    assert!(align_of::<toob_mailbox_t>() == 8);
    assert!(offset_of!(toob_mailbox_t, magic) == 0);
    assert!(offset_of!(toob_mailbox_t, version) == 4);
    assert!(offset_of!(toob_mailbox_t, request) == 6);
    assert!(offset_of!(toob_mailbox_t, seq) == 8);
    assert!(offset_of!(toob_mailbox_t, tbm1_addr) == 12);
    assert!(offset_of!(toob_mailbox_t, nonce) == 16);
    assert!(offset_of!(toob_mailbox_t, crc32) == TOOB_MAILBOX_CRC_LEN);
    assert!(offset_of!(toob_mailbox_t, _reserved) == 28);

    assert!(size_of::<toob_wal_entry_payload_t>() == 64);
    assert!(offset_of!(toob_wal_entry_payload_t, magic) == 0);
    assert!(offset_of!(toob_wal_entry_payload_t, intent) == 4);
    assert!(offset_of!(toob_wal_entry_payload_t, expected_nonce) == 8);
    assert!(offset_of!(toob_wal_entry_payload_t, update_deadline) == 16);
    assert!(offset_of!(toob_wal_entry_payload_t, transport_id) == 18);
    assert!(offset_of!(toob_wal_entry_payload_t, _pad_txn) == 19);
    assert!(offset_of!(toob_wal_entry_payload_t, transfer_bitmap) == 20);
    assert!(offset_of!(toob_wal_entry_payload_t, delta_chunk_id) == 52);
    assert!(offset_of!(toob_wal_entry_payload_t, offset) == 56);
    assert!(offset_of!(toob_wal_entry_payload_t, crc32_trailer) == 60);

    assert!(size_of::<toob_wal_sector_header_t>() == TOOB_WAL_HEADER_SIZE);
    assert!(align_of::<toob_wal_sector_header_t>() == 4);
    assert!(offset_of!(toob_wal_sector_header_t, sector_magic) == 0);
    assert!(offset_of!(toob_wal_sector_header_t, sequence_id) == 4);
    assert!(offset_of!(toob_wal_sector_header_t, erase_count) == 8);
    assert!(offset_of!(toob_wal_sector_header_t, _reserved_tmr_space) == 12);
    assert!(offset_of!(toob_wal_sector_header_t, header_crc32) == 124);
};

extern "C" {
    pub static mut toob_handoff_state: toob_handoff_t;
    pub static mut toob_diag_state: toob_boot_diag_t;
    pub static mut g_toob_ota_resume_state: toob_ota_resume_state_t;

    pub fn toob_lib_crc32(data: *const u8, length: usize) -> u32;
    pub fn toob_mailbox_session_reset_for_test();

    pub fn toob_validate_handoff() -> ToobStatus;
    pub fn toob_get_handoff(out_handoff: *mut toob_handoff_t) -> ToobStatus;
    pub fn toob_confirm_boot() -> ToobStatus;
    pub fn toob_recovery_resolved() -> ToobStatus;
    pub fn toob_get_boot_diag(diag: *mut toob_boot_diag_t) -> ToobStatus;
    pub fn toob_get_boot_diag_wire(
        out_buf: *mut u8,
        max_len: usize,
        out_len: *mut usize,
    ) -> ToobStatus;
    pub fn toob_get_boot_diag_wire_seq(
        out_buf: *mut u8,
        max_len: usize,
        checkin_seq: u64,
        out_len: *mut usize,
    ) -> ToobStatus;
    pub fn toob_set_next_update(manifest_flash_addr: u32) -> ToobStatus;
    pub fn toob_submit_cloud_command(envelope: *const u8, len: u32) -> ToobStatus;
    pub fn toob_get_device_id(out_id: *mut u8, id_len: usize) -> ToobStatus;
    pub fn toob_set_swap_notifier(cb: toob_swap_notify_fn);

    pub fn toob_mailbox_set_update(manifest_flash_addr: u32) -> ToobStatus;
    pub fn toob_mailbox_set_confirm(nonce: u64) -> ToobStatus;
    pub fn toob_mailbox_set_recovery_resolved() -> ToobStatus;

    pub fn toob_ota_ctx_init(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
    pub fn toob_ota_begin(
        ctx: *mut toob_ota_ctx_t,
        total_size: u32,
        expected_sha256: *const u8,
    ) -> ToobStatus;
    pub fn toob_ota_begin_assigned(
        ctx: *mut toob_ota_ctx_t,
        total_size: u32,
        expected_sha256: *const u8,
        assignment_id: *const u8,
    ) -> ToobStatus;
    pub fn toob_ota_resume(
        ctx: *mut toob_ota_ctx_t,
        total_size: u32,
        expected_sha256: *const u8,
        resume_offset: *mut u32,
    ) -> ToobStatus;
    pub fn toob_ota_resume_assigned(
        ctx: *mut toob_ota_ctx_t,
        total_size: u32,
        expected_sha256: *const u8,
        expected_assignment_id: *const u8,
        resume_offset: *mut u32,
    ) -> ToobStatus;
    pub fn toob_ota_pause(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
    pub fn toob_ota_abort(ctx: *mut toob_ota_ctx_t) -> ToobStatus;
    pub fn toob_ota_trim_total_size(ctx: *mut toob_ota_ctx_t, exact_total_size: u32)
        -> ToobStatus;
    pub fn toob_ota_process_chunk(
        ctx: *mut toob_ota_ctx_t,
        chunk: *const u8,
        len: u32,
    ) -> ToobStatus;
    pub fn toob_ota_finalize(ctx: *mut toob_ota_ctx_t) -> ToobStatus;

    pub fn toob_ota_checkpoint_save(bytes_staged: u32, sha256: *const u8);
    pub fn toob_ota_checkpoint_save_bound(
        bytes_staged: u32,
        target_addr: u32,
        sha256: *const u8,
    );
    pub fn toob_ota_checkpoint_save_bound_ex(
        bytes_staged: u32,
        target_addr: u32,
        sha256: *const u8,
        assignment_id: *const u8,
    );
    pub fn toob_ota_checkpoint_clear();

    pub fn toob_os_flash_read(addr: u32, buf: *mut u8, len: u32) -> ToobStatus;
    pub fn toob_os_flash_write(addr: u32, buf: *const u8, len: u32) -> ToobStatus;
    pub fn toob_os_flash_erase(addr: u32, len: u32) -> ToobStatus;
    pub fn toob_os_sha256_init(ctx: *mut toob_os_sha256_ctx_t) -> ToobStatus;
    pub fn toob_os_sha256_update(
        ctx: *mut toob_os_sha256_ctx_t,
        data: *const u8,
        len: u32,
    ) -> ToobStatus;
    pub fn toob_os_sha256_finalize(
        ctx: *mut toob_os_sha256_ctx_t,
        out_hash: *mut u8,
    ) -> ToobStatus;
    pub fn toob_os_lock();
    pub fn toob_os_unlock();
    pub fn toob_os_confirm_rtc_write(nonce: u64) -> ToobStatus;
    pub fn toob_os_nvs_read(key: *const c_char, buf: *mut u8, len: *mut usize) -> ToobStatus;
    pub fn toob_os_nvs_write(key: *const c_char, buf: *const u8, len: usize) -> ToobStatus;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of;

    #[test]
    fn verify_abi_offsets_and_crc32_link() {
        let diag = unsafe { core::mem::zeroed::<toob_boot_diag_t>() };
        let base = addr_of!(diag).addr();
        assert_eq!(addr_of!(diag.struct_version).addr() - base, 0);
        assert_eq!(addr_of!(diag.fw_ver_major).addr() - base, 44);
        assert_eq!(addr_of!(diag.fallback_occurred).addr() - base, 50);
        assert_eq!(addr_of!(diag.last_update_outcome).addr() - base, 51);
        assert_eq!(addr_of!(diag.installed_app_svn).addr() - base, 52);
        assert_eq!(addr_of!(diag.installed_stage1_svn).addr() - base, 56);
        assert_eq!(addr_of!(diag.reader_major).addr() - base, 60);
        assert_eq!(addr_of!(diag.reader_minor).addr() - base, 62);
        assert_eq!(addr_of!(diag.monotonic_counter).addr() - base, 64);
        assert_eq!(addr_of!(diag.last_update_reject).addr() - base, 68);
        assert_eq!(addr_of!(diag.boot_session_id).addr() - base, 72);
        assert_eq!(addr_of!(diag.sbom_digest).addr() - base, 76);
        assert_eq!(addr_of!(diag.ext_health_present).addr() - base, 108);
        assert_eq!(addr_of!(diag.ext_health).addr() - base, 112);
        assert_eq!(addr_of!(diag.crc32_trailer).addr() - base, 128);

        let resume = unsafe { core::mem::zeroed::<toob_ota_resume_state_t>() };
        let rbase = addr_of!(resume).addr();
        assert_eq!(addr_of!(resume.target_addr).addr() - rbase, 56);
        assert_eq!(addr_of!(resume.crc32_trailer).addr() - rbase, 60);

        let ota = unsafe { core::mem::zeroed::<toob_ota_ctx_t>() };
        let obase = addr_of!(ota).addr();
        assert_eq!(addr_of!(ota.erased_sectors).addr() - obase, 2);
        assert_eq!(addr_of!(ota.write_cursor).addr() - obase, 4);

        let crc = unsafe { toob_lib_crc32(b"123456789".as_ptr(), 9) };
        assert_eq!(crc, 0xCBF4_3926);
    }
}
