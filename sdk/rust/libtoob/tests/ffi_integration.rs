use core::mem::offset_of;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use libtoob::{
    confirm_boot, define_platform, get_boot_diag, get_boot_diag_wire, get_boot_diag_wire_seq,
    get_device_id, get_handoff, recovery_resolved, set_next_update, set_swap_notifier,
    submit_cloud_command, sys, validate_handoff, BootState, ExtHealth, OtaSession, Partition,
    PlatformHooks, ResetReason, Result, Tdr1Frame, ToobError, UpdateOutcome,
};

// Geometry matching sdk/libtoob/include/libtoob_config_sandbox.h
const FLASH_SIZE: usize = 0x10_0000;
const FLASH_WRITE_ALIGN: u32 = 8;
const FLASH_SECTOR_SIZE: u32 = 0x4000;
const STAGING_ADDR: u32 = 0x0008_0000;
const STAGING_SIZE: u32 = 0x0006_0000;
const CLOUD_CMD_ADDR: u32 = 0x000E_C000;
const MAILBOX_ADDR: u32 = 0x000F_4000;
const MAILBOX_SLOT_SIZE: u32 = 0x0000_4000;

const TMBX_MAGIC: u32 = 0x5842_4D54;
const TOOB_REQ_UPDATE_PENDING: u16 = 0x0001;
const TOOB_REQ_CONFIRM: u16 = 0x0002;
const TOOB_REQ_RECOVERY_RESOLVED: u16 = 0x0004;

const TCC1_MAGIC: u32 = 0x3143_4354;
const TBMT_MAGIC: u32 = 0x544D_4254;

static SERIAL_TEST_GUARD: Mutex<()> = Mutex::new(());
static MOCK_FLASH: Mutex<[u8; FLASH_SIZE]> = Mutex::new([0xFF; FLASH_SIZE]);
static MOCK_NVS: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

static LOCK_CALLS: AtomicU32 = AtomicU32::new(0);
static UNLOCK_CALLS: AtomicU32 = AtomicU32::new(0);
static LOCK_DEPTH: AtomicU32 = AtomicU32::new(0);
static MAX_LOCK_DEPTH: AtomicU32 = AtomicU32::new(0);

static RTC_NONCE: AtomicU64 = AtomicU64::new(0);
static RTC_CALLS: AtomicU32 = AtomicU32::new(0);
static FAIL_RTC_VERIFY: AtomicBool = AtomicBool::new(false);
static FAIL_FLASH_WRITE: AtomicBool = AtomicBool::new(false);

static SWAP_NOTIFY_COUNT: AtomicU32 = AtomicU32::new(0);
static SWAP_NOTIFY_PHASE: AtomicU32 = AtomicU32::new(0xFFFF);

// ============================================================================
// Alignment-free FIPS 180-4 SHA-256 stored inside opaque [u8; 128]
//   [0..32]   : state H0..H7 (8 x u32 LE)
//   [32..40]  : total_bytes (u64 LE)
//   [40..104] : block buffer (64 bytes)
//   [104..108]: block_len (u32 LE)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256_oneshot(data: &[u8]) -> [u8; 32] {
    let mut ctx = [0u8; 128];
    let mut out = [0u8; 32];
    MockPlatform::sha256_init(&mut ctx).unwrap();
    MockPlatform::sha256_update(&mut ctx, data).unwrap();
    MockPlatform::sha256_finalize(&mut ctx, &mut out).unwrap();
    out
}

struct MockPlatform;

impl PlatformHooks for MockPlatform {
    fn flash_read(addr: u32, buf: &mut [u8]) -> Result<()> {
        let start = addr as usize;
        let end = start.checked_add(buf.len()).ok_or(ToobError::FlashFailure)?;
        let flash = MOCK_FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        buf.copy_from_slice(&flash[start..end]);
        Ok(())
    }

    fn flash_write(addr: u32, buf: &[u8]) -> Result<()> {
        if FAIL_FLASH_WRITE.load(Ordering::SeqCst) {
            return Err(ToobError::FlashFailure);
        }
        let write_len = u32::try_from(buf.len()).map_err(|_| ToobError::FlashFailure)?;
        if !addr.is_multiple_of(FLASH_WRITE_ALIGN) || !write_len.is_multiple_of(FLASH_WRITE_ALIGN) {
            return Err(ToobError::FlashFailure);
        }
        let start = addr as usize;
        let end = start.checked_add(buf.len()).ok_or(ToobError::FlashFailure)?;
        let mut flash = MOCK_FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        // NOR 1 -> 0 bit-programming semantics
        for (dst, &src) in flash[start..end].iter_mut().zip(buf.iter()) {
            *dst &= src;
        }
        Ok(())
    }

    fn flash_erase(addr: u32, len: u32) -> Result<()> {
        if !addr.is_multiple_of(FLASH_SECTOR_SIZE) || !len.is_multiple_of(FLASH_SECTOR_SIZE) {
            return Err(ToobError::FlashFailure);
        }
        let start = addr as usize;
        let end = start.checked_add(len as usize).ok_or(ToobError::FlashFailure)?;
        let mut flash = MOCK_FLASH.lock().unwrap();
        if end > flash.len() {
            return Err(ToobError::FlashFailure);
        }
        flash[start..end].fill(0xFF);
        Ok(())
    }

    fn sha256_init(ctx: &mut [u8; 128]) -> Result<()> {
        ctx.fill(0);
        let init: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        for (i, word) in init.into_iter().enumerate() {
            ctx[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }

    fn sha256_update(ctx: &mut [u8; 128], data: &[u8]) -> Result<()> {
        let mut state = [0u32; 8];
        for i in 0..8 {
            state[i] = u32::from_le_bytes(ctx[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut total_bytes = u64::from_le_bytes(ctx[32..40].try_into().unwrap());
        let mut block_len = u32::from_le_bytes(ctx[104..108].try_into().unwrap()) as usize;

        total_bytes = total_bytes.wrapping_add(data.len() as u64);
        let mut pos = 0usize;

        while pos < data.len() {
            let space = 64 - block_len;
            let take = (data.len() - pos).min(space);
            ctx[40 + block_len..40 + block_len + take].copy_from_slice(&data[pos..pos + take]);
            block_len += take;
            pos += take;

            if block_len == 64 {
                let block: [u8; 64] = ctx[40..104].try_into().unwrap();
                sha256_compress(&mut state, &block);
                block_len = 0;
            }
        }

        for (i, word) in state.into_iter().enumerate() {
            ctx[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        ctx[32..40].copy_from_slice(&total_bytes.to_le_bytes());
        ctx[104..108].copy_from_slice(&(block_len as u32).to_le_bytes());
        Ok(())
    }

    fn sha256_finalize(ctx: &mut [u8; 128], out_hash: &mut [u8; 32]) -> Result<()> {
        let mut state = [0u32; 8];
        for i in 0..8 {
            state[i] = u32::from_le_bytes(ctx[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let total_bytes = u64::from_le_bytes(ctx[32..40].try_into().unwrap());
        let mut block_len = u32::from_le_bytes(ctx[104..108].try_into().unwrap()) as usize;
        let mut block: [u8; 64] = ctx[40..104].try_into().unwrap();

        block[block_len] = 0x80;
        block_len += 1;

        if block_len > 56 {
            block[block_len..64].fill(0);
            sha256_compress(&mut state, &block);
            block.fill(0);
        } else {
            block[block_len..56].fill(0);
        }

        let bit_len = total_bytes.wrapping_mul(8);
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut state, &block);

        for (i, word) in state.into_iter().enumerate() {
            out_hash[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        ctx.fill(0);
        Ok(())
    }

    fn lock() {
        LOCK_CALLS.fetch_add(1, Ordering::SeqCst);
        let depth = LOCK_DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
        MAX_LOCK_DEPTH.fetch_max(depth, Ordering::SeqCst);
    }

    fn unlock() {
        UNLOCK_CALLS.fetch_add(1, Ordering::SeqCst);
        let prev = LOCK_DEPTH.fetch_sub(1, Ordering::SeqCst);
        assert!(prev >= 1, "toob_os_unlock called without matching lock");
    }

    fn confirm_rtc_write(nonce: u64) -> Result<()> {
        RTC_CALLS.fetch_add(1, Ordering::SeqCst);
        if FAIL_RTC_VERIFY.load(Ordering::SeqCst) {
            return Err(ToobError::VerificationFailure);
        }
        RTC_NONCE.store(nonce, Ordering::SeqCst);
        Ok(())
    }

    fn nvs_read(key: &str, buf: &mut [u8]) -> Result<usize> {
        let guard = MOCK_NVS.lock().unwrap();
        let Some(map) = guard.as_ref() else {
            return Err(ToobError::NotFound);
        };
        let Some(val) = map.get(key) else {
            return Err(ToobError::NotFound);
        };
        if buf.len() < val.len() {
            return Err(ToobError::InvalidArg);
        }
        buf[..val.len()].copy_from_slice(val);
        Ok(val.len())
    }

    fn nvs_write(key: &str, buf: &[u8]) -> Result<()> {
        let mut guard = MOCK_NVS.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(key.to_owned(), buf.to_vec());
        Ok(())
    }
}

define_platform!(MockPlatform);

unsafe extern "C" fn test_swap_notifier(ev: *const sys::toob_swap_event_t) {
    if let Some(ev_ref) = unsafe { ev.as_ref() } {
        SWAP_NOTIFY_COUNT.fetch_add(1, Ordering::SeqCst);
        SWAP_NOTIFY_PHASE.store(ev_ref.phase as u32, Ordering::SeqCst);
    }
}

fn reset_harness() {
    MOCK_FLASH.lock().unwrap().fill(0xFF);
    *MOCK_NVS.lock().unwrap() = Some(HashMap::new());
    LOCK_CALLS.store(0, Ordering::SeqCst);
    UNLOCK_CALLS.store(0, Ordering::SeqCst);
    LOCK_DEPTH.store(0, Ordering::SeqCst);
    MAX_LOCK_DEPTH.store(0, Ordering::SeqCst);
    RTC_NONCE.store(0, Ordering::SeqCst);
    RTC_CALLS.store(0, Ordering::SeqCst);
    FAIL_RTC_VERIFY.store(false, Ordering::SeqCst);
    FAIL_FLASH_WRITE.store(false, Ordering::SeqCst);
    SWAP_NOTIFY_COUNT.store(0, Ordering::SeqCst);
    SWAP_NOTIFY_PHASE.store(0xFFFF, Ordering::SeqCst);
    set_swap_notifier(None);

    unsafe {
        sys::toob_handoff_state = core::mem::zeroed();
        sys::toob_diag_state = core::mem::zeroed();
        sys::toob_ota_checkpoint_clear();
        sys::toob_mailbox_session_reset_for_test();
    }
    LOCK_CALLS.store(0, Ordering::SeqCst);
    UNLOCK_CALLS.store(0, Ordering::SeqCst);
    MAX_LOCK_DEPTH.store(0, Ordering::SeqCst);
}

fn seed_handoff(magic: u32, nonce: u64, part: u32, reason: u32, slot: u8, device_id: [u8; 32]) {
    unsafe {
        let mut h = core::mem::zeroed::<sys::toob_handoff_t>();
        h.magic = magic;
        h.struct_version = sys::TOOB_HANDOFF_STRUCT_VERSION;
        h.boot_nonce = nonce;
        h.booted_partition = part;
        h.reset_reason = reason;
        h.boot_failure_count = 1;
        h.net_search_accum_ms = 2500;
        h.resume_offset = 512;
        h.device_id = device_id;
        h.wipe_requested = 1;
        h.active_slot = slot;
        h._padding = [0xAA; 6];
        let crc_len = offset_of!(sys::toob_handoff_t, crc32_trailer);
        h.crc32_trailer = sys::toob_lib_crc32(core::ptr::addr_of!(h).cast::<u8>(), crc_len);
        sys::toob_handoff_state = h;
    }
}

fn read_freshest_mailbox() -> Option<(u16, u32, u32, u64)> {
    let flash = MOCK_FLASH.lock().unwrap();
    let mut best: Option<(u16, u32, u32, u64)> = None;
    for slot in 0..2u32 {
        let base = (MAILBOX_ADDR + slot * MAILBOX_SLOT_SIZE) as usize;
        let rec = &flash[base..base + 32];
        let magic = u32::from_le_bytes(rec[0..4].try_into().unwrap());
        if magic != TMBX_MAGIC {
            continue;
        }
        let stored_crc = u32::from_le_bytes(rec[24..28].try_into().unwrap());
        let calc_crc = unsafe { sys::toob_lib_crc32(rec.as_ptr(), 24) };
        if stored_crc != calc_crc {
            continue;
        }
        let request = u16::from_le_bytes(rec[6..8].try_into().unwrap());
        let seq = u32::from_le_bytes(rec[8..12].try_into().unwrap());
        let tbm1_addr = u32::from_le_bytes(rec[12..16].try_into().unwrap());
        let nonce = u64::from_le_bytes(rec[16..24].try_into().unwrap());
        if best.is_none_or(|(_, prev_seq, _, _)| seq > prev_seq) {
            best = Some((request, seq, tbm1_addr, nonce));
        }
    }
    best
}

#[test]
fn ffi_handoff_and_device_id_validation() {
    let _g = SERIAL_TEST_GUARD.lock().unwrap();
    reset_harness();

    // Uninitialized / zeroed .noinit fails closed with VerificationFailure
    assert_eq!(validate_handoff(), Err(ToobError::VerificationFailure));
    assert_eq!(get_handoff(), Err(ToobError::VerificationFailure));
    assert_eq!(get_device_id(), Err(ToobError::VerificationFailure));

    let mut expected_id = [0u8; 32];
    for (i, b) in expected_id.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(0x13);
    }

    seed_handoff(
        sys::TOOB_STATE_TENTATIVE,
        0x0102_0304_0506_0708,
        sys::TOOB_PARTITION_RECOVERY.0,
        sys::TOOB_RESET_WATCHDOG.0,
        1,
        expected_id,
    );

    validate_handoff().expect("valid handoff");
    let h = get_handoff().expect("get_handoff");
    assert_eq!(h.magic, sys::TOOB_STATE_TENTATIVE);
    assert_eq!(h.struct_version, sys::TOOB_HANDOFF_STRUCT_VERSION);
    assert_eq!(h.boot_nonce, 0x0102_0304_0506_0708);
    assert_eq!(h.booted_partition, Partition::Recovery);
    assert_eq!(h.reset_reason, ResetReason::Watchdog);
    assert_eq!(h.boot_failure_count, 1);
    assert_eq!(h.net_search_accum_ms, 2500);
    assert_eq!(h.resume_offset, 512);
    assert_eq!(h.device_id, expected_id);
    assert!(h.wipe_requested);
    assert_eq!(h.active_slot, 1);

    assert_eq!(get_device_id().expect("get_device_id"), expected_id);

    // Flip 1 bit in .noinit RAM -> CRC32 guard rejects immediately
    unsafe {
        sys::toob_handoff_state.active_slot ^= 1;
    }
    assert_eq!(validate_handoff(), Err(ToobError::VerificationFailure));
    assert_eq!(get_device_id(), Err(ToobError::VerificationFailure));
}

#[test]
fn ffi_confirm_boot_rtc_and_cumulative_mailbox_hooks() {
    let _g = SERIAL_TEST_GUARD.lock().unwrap();
    reset_harness();

    // 1. Already COMMITTED handoff -> zero flash wear & zero RTC writes
    seed_handoff(
        sys::TOOB_STATE_COMMITTED,
        0xDEAD_BEEF_CAFE_0001,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_POWER_ON.0,
        0,
        [0x11; 32],
    );
    confirm_boot().expect("committed boot is no-op");
    assert_eq!(RTC_CALLS.load(Ordering::SeqCst), 0);
    assert!(read_freshest_mailbox().is_none());

    // 2. TENTATIVE with zero nonce -> rejected fail-closed
    seed_handoff(
        sys::TOOB_STATE_TENTATIVE,
        0,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_SOFTWARE.0,
        0,
        [0x11; 32],
    );
    assert_eq!(confirm_boot(), Err(ToobError::VerificationFailure));

    // 3. TENTATIVE with RTC verification failure -> aborts before writing Mailbox
    let nonce = 0x8877_6655_4433_2211;
    seed_handoff(
        sys::TOOB_STATE_TENTATIVE,
        nonce,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_SOFTWARE.0,
        0,
        [0x22; 32],
    );
    FAIL_RTC_VERIFY.store(true, Ordering::SeqCst);
    assert_eq!(confirm_boot(), Err(ToobError::VerificationFailure));
    assert_eq!(RTC_CALLS.load(Ordering::SeqCst), 1);
    assert!(read_freshest_mailbox().is_none());

    // 4. TENTATIVE with healthy RTC + Mailbox -> writes both & invokes lock/unlock
    FAIL_RTC_VERIFY.store(false, Ordering::SeqCst);
    confirm_boot().expect("confirm_boot tentative");
    assert_eq!(RTC_NONCE.load(Ordering::SeqCst), nonce);
    assert!(LOCK_CALLS.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        LOCK_CALLS.load(Ordering::SeqCst),
        UNLOCK_CALLS.load(Ordering::SeqCst)
    );
    assert_eq!(LOCK_DEPTH.load(Ordering::SeqCst), 0);
    assert_eq!(MAX_LOCK_DEPTH.load(Ordering::SeqCst), 1);

    let (req1, seq1, _, mbx_nonce) = read_freshest_mailbox().expect("mailbox slot written");
    assert_eq!(req1, TOOB_REQ_CONFIRM);
    assert_eq!(seq1, 1);
    assert_eq!(mbx_nonce, nonce);

    // 5. set_next_update + recovery_resolved merge cumulatively across A/B slots
    let manifest_addr = STAGING_ADDR + 0x1000;
    set_next_update(manifest_addr).expect("set_next_update");
    recovery_resolved().expect("recovery_resolved");

    let (req3, seq3, tbm1_addr, mbx_nonce3) = read_freshest_mailbox().expect("merged mailbox");
    assert_eq!(
        req3,
        TOOB_REQ_CONFIRM | TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED
    );
    assert_eq!(seq3, 3);
    assert_eq!(tbm1_addr, manifest_addr);
    assert_eq!(mbx_nonce3, nonce);

    // Reject Stage-0 immutable boot firewall & unaligned / out-of-slot addresses
    assert_eq!(set_next_update(0x0000_1000), Err(ToobError::InvalidArg));
    assert_eq!(set_next_update(STAGING_ADDR + 4), Err(ToobError::InvalidArg));
    assert_eq!(
        set_next_update(STAGING_ADDR + STAGING_SIZE - 256),
        Err(ToobError::InvalidArg)
    );
}

#[test]
fn ffi_boot_diag_and_tdr1_wire_encoding() {
    let _g = SERIAL_TEST_GUARD.lock().unwrap();
    reset_harness();

    assert_eq!(get_boot_diag(), Err(ToobError::VerificationFailure));
    assert_eq!(get_boot_diag_wire(&mut []), Err(ToobError::InvalidArg));

    let sbom = [0x5A; 32];
    unsafe {
        let mut d = core::mem::zeroed::<sys::toob_boot_diag_t>();
        d.struct_version = sys::TOOB_DIAG_STRUCT_VERSION;
        d.boot_duration_ms = 42;
        d.verify_time_ms = 11;
        d.last_error_code = 0;
        d.vendor_error = 7;
        d.hardware_fault_record = 0x1234;
        d.active_key_index = 1;
        d.current_svn = 9;
        d.build_number = 104;
        d.edge_recovery_events = 2;
        d.wdt_kicks = 5;
        d.fw_ver_major = 2;
        d.fw_ver_minor = 4;
        d.fw_ver_patch = 8;
        d.fallback_occurred = 1;
        d.last_update_outcome = 1;
        d.installed_app_svn = 9;
        d.installed_stage1_svn = 3;
        d.reader_major = 1;
        d.reader_minor = 2;
        d.monotonic_counter = 15;
        d.last_update_reject = 0;
        d.boot_session_id = 77;
        d.sbom_digest = sbom;
        d.ext_health_present = 1;
        d.ext_health = sys::toob_ext_health_t {
            wal_erase_count: 10,
            app_slot_erase_count: 20,
            staging_slot_erase_count: 30,
            swap_buffer_erase_count: 40,
        };
        let crc_len = offset_of!(sys::toob_boot_diag_t, crc32_trailer);
        d.crc32_trailer = sys::toob_lib_crc32(core::ptr::addr_of!(d).cast::<u8>(), crc_len);
        sys::toob_diag_state = d;
    }

    let diag = get_boot_diag().expect("get_boot_diag");
    assert_eq!(diag.struct_version, sys::TOOB_DIAG_STRUCT_VERSION);
    assert_eq!(diag.boot_duration_ms, 42);
    assert_eq!(diag.verify_time_ms, 11);
    assert_eq!(diag.fw_ver_major, 2);
    assert_eq!(diag.fw_ver_minor, 4);
    assert_eq!(diag.fw_ver_patch, 8);
    assert!(diag.fallback_occurred);
    assert_eq!(diag.installed_app_svn, 9);
    assert_eq!(diag.installed_stage1_svn, 3);
    assert_eq!(diag.boot_session_id, 77);
    assert_eq!(diag.sbom_digest, sbom);
    assert_eq!(
        diag.ext_health,
        Some(ExtHealth {
            wal_erase_count: 10,
            app_slot_erase_count: 20,
            staging_slot_erase_count: 30,
            swap_buffer_erase_count: 40,
        })
    );

    let mut tiny = [0u8; 8];
    assert_eq!(get_boot_diag_wire(&mut tiny), Err(ToobError::InvalidArg));

    let mut wire = [0u8; 256];
    // TDR1-06: Unseeded / corrupted handoff MUST fail closed instead of fabricating App/Slot0
    assert_eq!(
        get_boot_diag_wire(&mut wire),
        Err(ToobError::VerificationFailure)
    );

    seed_handoff(
        sys::TOOB_STATE_TENTATIVE,
        0xCAFE_BABE_0000_0001,
        sys::TOOB_PARTITION_RECOVERY.0,
        sys::TOOB_RESET_WATCHDOG.0,
        1,
        [0x77; 32],
    );

    let seq = 0x1122_3344_5566_7788u64;
    let n = get_boot_diag_wire_seq(&mut wire, seq).expect("get_boot_diag_wire_seq");
    assert_eq!(n, sys::TOOB_TDR1_MAX_SIZE);
    assert_eq!(
        u32::from_le_bytes(wire[0..4].try_into().unwrap()),
        sys::TOOB_TDR1_MAGIC
    );
    assert_eq!(wire[4], sys::TOOB_TDR1_VERSION);
    assert_eq!(
        u16::from_le_bytes(wire[8..10].try_into().unwrap()) as usize,
        sys::TOOB_TDR1_HDR_SIZE
    );
    assert_eq!(&wire[96..128], &sbom);
    assert_eq!(u32::from_le_bytes(wire[128..132].try_into().unwrap()), 77);
    let stored_crc = u32::from_le_bytes(wire[n - 4..n].try_into().unwrap());
    let calc_crc = unsafe { sys::toob_lib_crc32(wire.as_ptr(), n - 4) };
    assert_eq!(stored_crc, calc_crc);

    let decoded = Tdr1Frame::decode(&wire[..n]).expect("Tdr1Frame::decode");
    assert_eq!(decoded.booted_partition, Partition::Recovery);
    assert_eq!(decoded.boot_state, BootState::Tentative);
    assert_eq!(decoded.active_slot, 1);
    assert_eq!(decoded.reset_reason, ResetReason::Watchdog);
    assert!(decoded.fallback_occurred);
    assert!(decoded.wipe_requested);
    assert_eq!(decoded.last_update_outcome, UpdateOutcome::Applied);
    assert_eq!(decoded.checkin_seq, seq);
    assert_eq!(decoded.recovery_failure_events, 1);
    assert_eq!(decoded.net_search_accum_ms, 2500);
    assert_eq!(decoded.sbom_digest, sbom);
    assert_eq!(decoded.boot_session_id, 77);
    assert_eq!(decoded.ext_health, diag.ext_health);
}

#[test]
fn ffi_submit_cloud_command_and_nvs_hooks() {
    let _g = SERIAL_TEST_GUARD.lock().unwrap();
    reset_harness();

    // Build a valid 144-byte TCC1 envelope (64B header + 16B padded params + 64B signature)
    let mut env = [0u8; 144];
    let env_len = env.len() as u32;
    env[0..4].copy_from_slice(&TCC1_MAGIC.to_le_bytes());
    env[4] = 1; // version
    env[5] = 2; // command
    env[8..12].copy_from_slice(&5u32.to_le_bytes()); // counter_min
    env[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // issued_at
    env[16..20].copy_from_slice(&10u32.to_le_bytes()); // params_len (aligned up to 16)
    env[20..24].copy_from_slice(&env_len.to_le_bytes()); // total_len = 144
    env[24..56].copy_from_slice(&[0x33; 32]); // device_id
    let hdr_crc = unsafe { sys::toob_lib_crc32(env.as_ptr(), 56) };
    env[56..60].copy_from_slice(&hdr_crc.to_le_bytes());
    env[64..74].copy_from_slice(b"param-data");
    env[80..144].copy_from_slice(&[0xEE; 64]); // Ed25519 signature bytes

    // TCI1-08: Unseeded handoff or mismatched device_id MUST reject BEFORE erasing flash
    assert_eq!(
        submit_cloud_command(&env),
        Err(ToobError::VerificationFailure)
    );
    seed_handoff(
        sys::TOOB_STATE_COMMITTED,
        0x1111_2222_3333_4444,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_POWER_ON.0,
        0,
        [0x99; 32],
    );
    assert_eq!(
        submit_cloud_command(&env),
        Err(ToobError::VerificationFailure)
    );

    seed_handoff(
        sys::TOOB_STATE_COMMITTED,
        0x1111_2222_3333_4444,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_POWER_ON.0,
        0,
        [0x33; 32],
    );

    let locks_before = LOCK_CALLS.load(Ordering::SeqCst);
    submit_cloud_command(&env).expect("submit_cloud_command");
    assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), locks_before + 1);
    assert_eq!(
        LOCK_CALLS.load(Ordering::SeqCst),
        UNLOCK_CALLS.load(Ordering::SeqCst)
    );

    let flash = MOCK_FLASH.lock().unwrap();
    assert_eq!(
        &flash[CLOUD_CMD_ADDR as usize..CLOUD_CMD_ADDR as usize + env.len()],
        &env[..]
    );
    drop(flash);

    // Corrupted header CRC -> VerificationFailure
    let mut bad_crc = env;
    bad_crc[56] ^= 0xFF;
    assert_eq!(
        submit_cloud_command(&bad_crc),
        Err(ToobError::VerificationFailure)
    );

    // Unaligned length -> InvalidArg
    assert_eq!(
        submit_cloud_command(&env[..130]),
        Err(ToobError::InvalidArg)
    );

    // Exercise NVS read/write callbacks directly via C ABI symbols
    let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x42];
    unsafe {
        assert_eq!(
            sys::toob_os_nvs_write(c"toob_sys/cred".as_ptr(), payload.as_ptr(), payload.len()),
            sys::TOOB_OK
        );

        let mut out = [0u8; 16];
        let mut out_len = out.len();
        assert_eq!(
            sys::toob_os_nvs_read(c"toob_sys/cred".as_ptr(), out.as_mut_ptr(), &mut out_len),
            sys::TOOB_OK
        );
        assert_eq!(out_len, payload.len());
        assert_eq!(&out[..out_len], &payload);

        let mut missing_len = out.len();
        assert_eq!(
            sys::toob_os_nvs_read(
                c"toob_sys/missing".as_ptr(),
                out.as_mut_ptr(),
                &mut missing_len
            ),
            sys::TOOB_ERR_NOT_FOUND
        );
        assert_eq!(missing_len, 0);
    }
}

#[test]
fn ffi_ota_verified_trailer_pause_resume_and_abort() {
    let _g = SERIAL_TEST_GUARD.lock().unwrap();
    reset_harness();

    // Sanity check NIST FIPS 180-4 "abc" vector on our pure-Rust SHA-256 engine
    let abc_hash = sha256_oneshot(b"abc");
    assert_eq!(
        abc_hash,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ]
    );

    seed_handoff(
        sys::TOOB_STATE_COMMITTED,
        0x1234_5678_9ABC_DEF0,
        sys::TOOB_PARTITION_APP.0,
        sys::TOOB_RESET_POWER_ON.0,
        0,
        [0x44; 32],
    );

    // Construct a 1020-byte TrailerLayout OTA stream:
    //   [0..428]    : simulated firmware payload (428B)
    //   [428..1004] : 576B TBM1 envelope at tbm1_off = 428 (8B-aligned: let's use 432!)
    // Let's use total_len = 1028:
    //   [0..432]     : payload (432B, 8-byte aligned)
    //   [432..1008]  : TBM1 envelope (576B)
    //   [1008..1024] : extra 4B + 16B TBMT trailer locator at tail -> let's make total_len = 1024:
    //   [0..432]     : payload (432B)
    //   [432..1008]  : TBM1 envelope (576B)
    //   [1008..1024] : 16B toob_tbm1_trailer_locator_t! (432 + 576 + 16 = 1024; let's also test unaligned tail: 432 + 576 + 3 + 16 = 1027 -> pad test!)
    // Wait: let's make total_len = 1027 bytes so finalize() ALSO exercises residual 8-byte 0xFF padding flush!
    //   tbm1_off = 432 (multiple of 8!), tbm1_len = 576, 3 pad bytes, 16B TBMT locator at [1011..1027]!
    let total_len = 1027usize;
    let tbm1_off = 432u32;
    let tbm1_len = 576u32;
    let mut bundle = vec![0u8; total_len];
    for (i, b) in bundle[..1011].iter_mut().enumerate() {
        *b = ((i * 31 + 17) & 0xFF) as u8;
    }
    let mut loc = [0u8; 16];
    loc[0..4].copy_from_slice(&TBMT_MAGIC.to_le_bytes());
    loc[4..8].copy_from_slice(&tbm1_off.to_le_bytes());
    loc[8..12].copy_from_slice(&tbm1_len.to_le_bytes());
    let loc_crc = unsafe { sys::toob_lib_crc32(loc.as_ptr(), 12) };
    loc[12..16].copy_from_slice(&loc_crc.to_le_bytes());
    bundle[1011..1027].copy_from_slice(&loc);

    let expected_sha = sha256_oneshot(&bundle);
    let assignment_a = [0xA1; 16];
    let assignment_b = [0xB2; 16];
    set_swap_notifier(Some(test_swap_notifier));

    // Phase A: Stream 600 bytes (flushes 512 bytes = 2 x 256B buffers, buffers 88B in RAM), then pause()!
    let mut rx = OtaSession::new()
        .expect("OtaSession::new")
        .begin_assigned(bundle.len() as u32, &expected_sha, &assignment_a)
        .expect("begin_assigned");

    for chunk in bundle[..600].chunks(113) {
        rx.process_chunk(chunk).expect("process_chunk pre-pause");
    }
    let _idle_after_pause = rx.pause();

    // Phase B: Resume in a fresh OtaSession -> returns flushed checkpoint offset 512,
    // re-reads & re-hashes [0..512) from Staging Flash, then ingests [512..1027) and finalizes!
    let (mut resumed, offset) = OtaSession::new()
        .expect("OtaSession::new")
        .resume_assigned(bundle.len() as u32, &expected_sha, &assignment_a)
        .expect("resume_assigned");
    assert_eq!(offset, 512);

    for chunk in bundle[offset as usize..].chunks(97) {
        resumed
            .process_chunk(chunk)
            .expect("process_chunk post-resume");
    }
    let _done = resumed.finalize().expect("finalize verified OTA");

    // Swap notifier was invoked with TOOB_SWAP_PHASE_PREPARE (0)
    assert_eq!(SWAP_NOTIFY_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(SWAP_NOTIFY_PHASE.load(Ordering::SeqCst), 0);

    // Verify staged flash image matches exact bundle bytes + 0xFF alignment padding
    let flash = MOCK_FLASH.lock().unwrap();
    assert_eq!(
        &flash[STAGING_ADDR as usize..STAGING_ADDR as usize + bundle.len()],
        &bundle[..]
    );
    assert_eq!(
        &flash[STAGING_ADDR as usize + bundle.len()..STAGING_ADDR as usize + 1032],
        &[0xFF; 5]
    );
    drop(flash);

    // Verify Mailbox registered UPDATE_PENDING pointing directly to STAGING_ADDR + tbm1_off!
    let (req, _, mbx_tbm1_addr, _) = read_freshest_mailbox().expect("OTA mailbox");
    assert_eq!(req, TOOB_REQ_UPDATE_PENDING);
    assert_eq!(mbx_tbm1_addr, STAGING_ADDR + tbm1_off);

    // TCI1-05: Mismatched assignment_id rejects cross-campaign resume and purges stale checkpoint
    let mut rx_reassigned = OtaSession::new()
        .unwrap()
        .begin_assigned(bundle.len() as u32, &expected_sha, &assignment_a)
        .unwrap();
    rx_reassigned.process_chunk(&bundle[..300]).unwrap();
    let _ = rx_reassigned.pause();
    assert!(matches!(
        OtaSession::new().unwrap().resume_assigned(
            bundle.len() as u32,
            &expected_sha,
            &assignment_b
        ),
        Err(ToobError::NotFound)
    ));
    assert!(matches!(
        OtaSession::new().unwrap().resume_assigned(
            bundle.len() as u32,
            &expected_sha,
            &assignment_a
        ),
        Err(ToobError::NotFound)
    ));

    // Phase C: Verified SHA-256 mismatch is caught fail-closed in finalize()
    let mut wrong_sha = expected_sha;
    wrong_sha[0] ^= 0x01;
    let mut bad_rx = OtaSession::new()
        .unwrap()
        .begin_verified(bundle.len() as u32, &wrong_sha)
        .unwrap();
    bad_rx.process_chunk(&bundle).unwrap();
    assert!(matches!(
        bad_rx.finalize(),
        Err(ToobError::VerificationFailure)
    ));

    // Phase D: Unverified begin() + trim_total_size() + abort() wipes resume checkpoint
    let mut unv = OtaSession::new().unwrap().begin(2048).unwrap();
    assert_eq!(unv.process_chunk(&[]), Err(ToobError::InvalidArg));
    unv.process_chunk(&bundle).unwrap();
    assert_eq!(unv.trim_total_size(300), Err(ToobError::InvalidArg));
    unv.trim_total_size(bundle.len() as u32).unwrap();
    let _done_trimmed = unv.finalize().unwrap();

    let mut unv2 = OtaSession::new().unwrap().begin(600).unwrap();
    unv2.process_chunk(&bundle[..300]).unwrap();
    let _aborted = unv2.abort();
    assert!(matches!(
        OtaSession::new().unwrap().resume(600),
        Err(ToobError::NotFound)
    ));
}
