use core::mem::offset_of;
use core::ptr::{addr_of, NonNull};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use libtoob::{
    define_platform, get_boot_diag_wire_seq, sys, BootState, ExtHealth, Partition, PlatformHooks,
    ResetReason, Result, Tdr1Frame, ToobError, UpdateOutcome,
};

static SERIAL_GUARD: Mutex<()> = Mutex::new(());

// Mode selector for testing hook contract edge cases inside define_platform! trampolines:
//   0 = normal Ok
//   1 = return Err(ToobError::Unknown(sys::TOOB_OK.0)) (hostile status inversion attempt)
//   2 = nvs_read returns Ok(buf.len() + 1) (out-of-bounds read count contract breach)
static HOOK_MODE: AtomicU8 = AtomicU8::new(0);

struct FuzzPlatform;

impl PlatformHooks for FuzzPlatform {
    fn flash_read(_addr: u32, buf: &mut [u8]) -> Result<()> {
        if HOOK_MODE.load(Ordering::SeqCst) == 1 {
            return Err(ToobError::Unknown(sys::TOOB_OK.0));
        }
        buf.fill(0xA5);
        Ok(())
    }

    fn flash_write(_addr: u32, _buf: &[u8]) -> Result<()> {
        if HOOK_MODE.load(Ordering::SeqCst) == 1 {
            return Err(ToobError::Unknown(sys::TOOB_OK.0));
        }
        Ok(())
    }

    fn flash_erase(_addr: u32, _len: u32) -> Result<()> {
        if HOOK_MODE.load(Ordering::SeqCst) == 1 {
            return Err(ToobError::Unknown(sys::TOOB_OK.0));
        }
        Ok(())
    }

    fn sha256_init(ctx: &mut [u8; 128]) -> Result<()> {
        ctx.fill(0x11);
        Ok(())
    }

    fn sha256_update(ctx: &mut [u8; 128], data: &[u8]) -> Result<()> {
        for (i, &b) in data.iter().enumerate() {
            ctx[i & 127] ^= b;
        }
        Ok(())
    }

    fn sha256_finalize(ctx: &mut [u8; 128], out_hash: &mut [u8; 32]) -> Result<()> {
        out_hash.copy_from_slice(&ctx[..32]);
        Ok(())
    }

    fn nvs_read(_key: &str, buf: &mut [u8]) -> Result<usize> {
        match HOOK_MODE.load(Ordering::SeqCst) {
            1 => Err(ToobError::Unknown(sys::TOOB_OK.0)),
            2 => Ok(buf.len().saturating_add(1)),
            _ => {
                let n = buf.len().min(4);
                buf[..n].fill(0x5C);
                Ok(n)
            }
        }
    }

    fn nvs_write(_key: &str, _buf: &[u8]) -> Result<()> {
        if HOOK_MODE.load(Ordering::SeqCst) == 1 {
            return Err(ToobError::Unknown(sys::TOOB_OK.0));
        }
        Ok(())
    }
}

define_platform!(FuzzPlatform);

/// Deterministic SplitMix64 PRNG (zero external crate bloat).
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

fn resign_tdr1_crc(frame: &mut [u8]) {
    let payload_len = frame.len() - sys::TOOB_TDR1_CRC_TRAILER_SIZE;
    let crc = unsafe { sys::toob_lib_crc32(frame.as_ptr(), payload_len) };
    frame[payload_len..].copy_from_slice(&crc.to_le_bytes());
}

fn random_valid_tdr1(rng: &mut SplitMix64, with_ext: bool) -> Tdr1Frame {
    let booted_partition = if rng.next_bool() {
        Partition::App
    } else {
        Partition::Recovery
    };
    let diag_major = 3u8.saturating_add(rng.next_u8() % 250);
    let boot_state = if rng.next_bool() {
        BootState::Committed
    } else {
        BootState::Tentative
    };
    let active_slot = rng.next_u8() & 1;
    let reset_reason = ResetReason::try_from((rng.next_u8() % 7) as u32).unwrap();
    let last_update_outcome = UpdateOutcome::try_from(rng.next_u8() % 5).unwrap();
    let mut sbom_digest = [0u8; 32];
    rng.fill_bytes(&mut sbom_digest);
    let ext_health = if with_ext {
        Some(ExtHealth {
            wal_erase_count: rng.next_u32(),
            app_slot_erase_count: rng.next_u32(),
            staging_slot_erase_count: rng.next_u32(),
            swap_buffer_erase_count: rng.next_u32(),
        })
    } else {
        None
    };

    Tdr1Frame {
        booted_partition,
        diag_major,
        boot_state,
        active_slot,
        reset_reason,
        fallback_occurred: rng.next_bool(),
        wipe_requested: rng.next_bool(),
        last_update_outcome,
        last_update_reject: rng.next_u8(),
        active_key_index: rng.next_u16(),
        reader_major: rng.next_u16(),
        reader_minor: rng.next_u16(),
        fw_ver_major: rng.next_u16(),
        fw_ver_minor: rng.next_u16(),
        fw_ver_patch: rng.next_u16(),
        checkin_seq: rng.next_u64(),
        current_svn: rng.next_u32(),
        build_number: rng.next_u32(),
        installed_app_svn: rng.next_u32(),
        installed_stage1_svn: rng.next_u32(),
        monotonic_counter: rng.next_u32(),
        boot_duration_ms: rng.next_u32(),
        verify_time_ms: rng.next_u32(),
        last_error_code: rng.next_u32(),
        vendor_error: rng.next_u32(),
        hardware_fault_record: rng.next_u32(),
        edge_recovery_events: rng.next_u32(),
        recovery_failure_events: rng.next_u32(),
        net_search_accum_ms: rng.next_u32(),
        wdt_kicks: rng.next_u32(),
        sbom_digest,
        boot_session_id: rng.next_u32(),
        ext_health,
    }
}

#[test]
fn tdr1_encode_parse_encode_bijection_50k() {
    let mut rng = SplitMix64::new(0x5444_5231_B1EC_7100);
    let mut wire1 = [0u8; sys::TOOB_TDR1_MAX_SIZE];
    let mut wire2 = [0u8; sys::TOOB_TDR1_MAX_SIZE];

    // 50,000 deterministic property iterations across 136B and 152B TDR1 frames
    for iter in 0..50_000usize {
        let with_ext = !iter.is_multiple_of(2);
        let mut frame = random_valid_tdr1(&mut rng, with_ext);

        // Periodically exercise diag_major == 0 canonicalization to TOOB_TDR1_MIN_DIAG_MAJOR (3)
        let expected_diag_major = if iter.is_multiple_of(17) {
            frame.diag_major = 0;
            sys::TOOB_TDR1_MIN_DIAG_MAJOR
        } else {
            frame.diag_major
        };

        let expected_len = if with_ext {
            sys::TOOB_TDR1_MAX_SIZE
        } else {
            sys::TOOB_TDR1_MIN_FRAME_SIZE
        };

        let n1 = frame.encode(&mut wire1).expect("encode valid Tdr1Frame");
        assert_eq!(n1, expected_len);

        let decoded = Tdr1Frame::decode(&wire1[..n1]).expect("decode valid Tdr1Frame");
        let mut expected_frame = frame;
        expected_frame.diag_major = expected_diag_major;
        assert_eq!(decoded, expected_frame);

        let n2 = decoded
            .encode(&mut wire2)
            .expect("re-encode decoded Tdr1Frame");
        assert_eq!(n2, n1);
        assert_eq!(&wire1[..n1], &wire2[..n2], "TDR1 bijection drift at {iter}");
    }

    // Undersized output buffers must reject fail-closed without panicking
    let f_min = random_valid_tdr1(&mut rng, false);
    let mut short_min = [0u8; sys::TOOB_TDR1_MIN_FRAME_SIZE - 1];
    assert_eq!(f_min.encode(&mut short_min), Err(ToobError::InvalidArg));

    let f_ext = random_valid_tdr1(&mut rng, true);
    let mut short_ext = [0u8; sys::TOOB_TDR1_MAX_SIZE - 1];
    assert_eq!(f_ext.encode(&mut short_ext), Err(ToobError::InvalidArg));

    // Invalid encode-side domain values must reject fail-closed
    let mut bad_diag = f_min;
    bad_diag.diag_major = 2;
    assert_eq!(
        bad_diag.encode(&mut wire1),
        Err(ToobError::VerificationFailure)
    );

    let mut bad_slot = f_min;
    bad_slot.active_slot = 2;
    assert_eq!(
        bad_slot.encode(&mut wire1),
        Err(ToobError::VerificationFailure)
    );
}

#[test]
fn tdr1_c_ffi_to_rust_wire_bijection_10k() {
    let _g = SERIAL_GUARD.lock().unwrap();
    let mut rng = SplitMix64::new(0xC0FF_EE11_2233_4455);
    let mut wire_c = [0u8; sys::TOOB_TDR1_MAX_SIZE];
    let mut wire_rs = [0u8; sys::TOOB_TDR1_MAX_SIZE];

    for iter in 0..10_000usize {
        let with_ext = !iter.is_multiple_of(2);
        let f = random_valid_tdr1(&mut rng, with_ext);

        unsafe {
            let mut h = core::mem::zeroed::<sys::toob_handoff_t>();
            h.magic = match f.boot_state {
                BootState::Committed => sys::TOOB_STATE_COMMITTED,
                BootState::Tentative => sys::TOOB_STATE_TENTATIVE,
            };
            h.struct_version = sys::TOOB_HANDOFF_STRUCT_VERSION;
            h.boot_nonce = rng.next_u64() | 1;
            h.booted_partition = match f.booted_partition {
                Partition::App => sys::TOOB_PARTITION_APP.0,
                Partition::Recovery => sys::TOOB_PARTITION_RECOVERY.0,
            };
            h.reset_reason = f.reset_reason.to_wire() as u32;
            h.boot_failure_count = f.recovery_failure_events;
            h.net_search_accum_ms = f.net_search_accum_ms;
            h.resume_offset = rng.next_u32();
            rng.fill_bytes(&mut h.device_id);
            h.wipe_requested = u8::from(f.wipe_requested);
            h.active_slot = f.active_slot;
            let h_crc_len = offset_of!(sys::toob_handoff_t, crc32_trailer);
            h.crc32_trailer = sys::toob_lib_crc32(addr_of!(h).cast::<u8>(), h_crc_len);
            sys::toob_handoff_state = h;

            let mut d = core::mem::zeroed::<sys::toob_boot_diag_t>();
            d.struct_version = sys::TOOB_DIAG_STRUCT_VERSION;
            d.boot_duration_ms = f.boot_duration_ms;
            d.verify_time_ms = f.verify_time_ms;
            d.last_error_code = f.last_error_code;
            d.vendor_error = f.vendor_error;
            d.hardware_fault_record = f.hardware_fault_record;
            d.active_key_index = f.active_key_index as u32;
            d.current_svn = f.current_svn;
            d.build_number = f.build_number;
            d.edge_recovery_events = f.edge_recovery_events;
            d.wdt_kicks = f.wdt_kicks;
            d.fw_ver_major = f.fw_ver_major;
            d.fw_ver_minor = f.fw_ver_minor;
            d.fw_ver_patch = f.fw_ver_patch;
            d.fallback_occurred = u8::from(f.fallback_occurred);
            d.last_update_outcome = f.last_update_outcome.to_wire();
            d.installed_app_svn = f.installed_app_svn;
            d.installed_stage1_svn = f.installed_stage1_svn;
            d.reader_major = f.reader_major;
            d.reader_minor = f.reader_minor;
            d.monotonic_counter = f.monotonic_counter;
            d.last_update_reject = f.last_update_reject;
            d.boot_session_id = f.boot_session_id;
            d.sbom_digest = f.sbom_digest;
            if let Some(ext) = f.ext_health {
                d.ext_health_present = 1;
                d.ext_health = sys::toob_ext_health_t {
                    wal_erase_count: ext.wal_erase_count,
                    app_slot_erase_count: ext.app_slot_erase_count,
                    staging_slot_erase_count: ext.staging_slot_erase_count,
                    swap_buffer_erase_count: ext.swap_buffer_erase_count,
                };
            }
            let d_crc_len = offset_of!(sys::toob_boot_diag_t, crc32_trailer);
            d.crc32_trailer = sys::toob_lib_crc32(addr_of!(d).cast::<u8>(), d_crc_len);
            sys::toob_diag_state = d;
        }

        let n_c = get_boot_diag_wire_seq(&mut wire_c, f.checkin_seq)
            .expect("C toob_get_boot_diag_wire_seq");
        let parsed = Tdr1Frame::decode(&wire_c[..n_c]).expect("Rust Tdr1Frame::decode");
        let mut expected = f;
        expected.diag_major = sys::TOOB_TDR1_MIN_DIAG_MAJOR;
        assert_eq!(parsed, expected);

        let n_rs = parsed.encode(&mut wire_rs).expect("Rust Tdr1Frame::encode");
        assert_eq!(n_c, n_rs);
        assert_eq!(
            &wire_c[..n_c],
            &wire_rs[..n_rs],
            "C <-> Rust TDR1 wire mismatch at iteration {iter}"
        );
    }
}

#[test]
fn tdr1_exhaustive_bitflip_and_hostile_fuzz_60k() {
    let mut rng = SplitMix64::new(0xDEAD_BEEF_1357_9BDF);

    // 1. Exhaustive 1-bit flip across ALL 1,088 bits (136B) and ALL 1,216 bits (152B)
    for with_ext in [false, true] {
        let base_frame = random_valid_tdr1(&mut rng, with_ext);
        let mut canonical = [0u8; sys::TOOB_TDR1_MAX_SIZE];
        let len = base_frame.encode(&mut canonical).unwrap();

        for byte_idx in 0..len {
            for bit in 0..8u8 {
                let mut mutated = canonical;
                mutated[byte_idx] ^= 1u8 << bit;
                assert!(
                    Tdr1Frame::decode(&mutated[..len]).is_err(),
                    "1-bit flip at byte {byte_idx} bit {bit} (len={len}) was not rejected!"
                );
            }
        }
    }

    // 2. Targeted structural & domain fuzzing WITH recomputed CRC-32 trailer
    //    (proves every field check inside Tdr1Frame::decode rejects fail-closed
    //     even if an adversary or transport bug recomputes the CRC-32!)
    for with_ext in [false, true] {
        let base_frame = random_valid_tdr1(&mut rng, with_ext);
        let mut clean = [0u8; sys::TOOB_TDR1_MAX_SIZE];
        let len = base_frame.encode(&mut clean).unwrap();

        // 2a. Every 1-bit flip in magic [0..4] + valid CRC-32
        for i in 0..32u32 {
            let mut buf = clean;
            let m = sys::TOOB_TDR1_MAGIC ^ (1u32 << i);
            buf[0..4].copy_from_slice(&m.to_le_bytes());
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2b. Every invalid version != 1 + valid CRC-32
        for ver in 0..=255u8 {
            if ver == sys::TOOB_TDR1_VERSION {
                continue;
            }
            let mut buf = clean;
            buf[4] = ver;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2c. Every invalid booted_partition (all values outside {0, 2}, including 1, 0x0A, 0x0B)
        for part in 0..=255u8 {
            if part == sys::TOOB_TDR1_PARTITION_APP || part == sys::TOOB_TDR1_PARTITION_RECOVERY {
                continue;
            }
            let mut buf = clean;
            buf[5] = part;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2d. Every 1-bit flip in flags [6..8] + valid CRC-32
        //     Bit 0 flip breaks frame length vs ext_health; bits 1..15 are unknown flags!
        let orig_flags = u16::from_le_bytes([clean[6], clean[7]]);
        for bit in 0..16u16 {
            let mut buf = clean;
            let f = orig_flags ^ (1u16 << bit);
            buf[6..8].copy_from_slice(&f.to_le_bytes());
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2e. Every 1-bit flip in header_size [8..10] + boundary values + valid CRC-32
        for bit in 0..16u16 {
            let mut buf = clean;
            let hs = (sys::TOOB_TDR1_HDR_SIZE as u16) ^ (1u16 << bit);
            buf[8..10].copy_from_slice(&hs.to_le_bytes());
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }
        for bad_hs in [0u16, 1, 128, 131, 133, 136, 140, 148, 0xFFF8, u16::MAX] {
            let mut buf = clean;
            buf[8..10].copy_from_slice(&bad_hs.to_le_bytes());
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2f. Invalid diag_major (0, 1, 2) + valid CRC-32
        for dm in 0..sys::TOOB_TDR1_MIN_DIAG_MAJOR {
            let mut buf = clean;
            buf[10] = dm;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2g. Every out-of-range boot_state (2..=255) + valid CRC-32
        for bs in 2..=255u8 {
            let mut buf = clean;
            buf[11] = bs;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2h. Every out-of-range active_slot (2..=255) + valid CRC-32
        for slot in 2..=255u8 {
            let mut buf = clean;
            buf[12] = slot;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2i. Every out-of-range reset_reason (7..=255) + valid CRC-32
        for rr in (sys::TOOB_TDR1_MAX_RESET_REASON + 1)..=255u8 {
            let mut buf = clean;
            buf[13] = rr;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2j. Every non-canonical boolean in fallback_occurred [14] and wipe_requested [15]
        for bval in 2..=255u8 {
            let mut buf = clean;
            buf[14] = bval;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );

            let mut buf2 = clean;
            buf2[15] = bval;
            resign_tdr1_crc(&mut buf2[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf2[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2k. Every out-of-range last_update_outcome (5..=255) + valid CRC-32
        for out in (sys::TOOB_TDR1_MAX_OUTCOME + 1)..=255u8 {
            let mut buf = clean;
            buf[16] = out;
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }

        // 2l. Every 1-bit flip in _reserved0 [30..32] + valid CRC-32
        for bit in 0..16u16 {
            let mut buf = clean;
            let rsv = 1u16 << bit;
            buf[30..32].copy_from_slice(&rsv.to_le_bytes());
            resign_tdr1_crc(&mut buf[..len]);
            assert_eq!(
                Tdr1Frame::decode(&buf[..len]),
                Err(ToobError::VerificationFailure)
            );
        }
    }

    // 3. Truncated and non-canonical frame lengths (0..260 bytes)
    let valid_base = random_valid_tdr1(&mut rng, true);
    let mut scratch = [0u8; 260];
    let _ = valid_base.encode(&mut scratch[..sys::TOOB_TDR1_MAX_SIZE]).unwrap();
    for bad_len in 0..sys::TOOB_TDR1_MIN_FRAME_SIZE {
        assert_eq!(
            Tdr1Frame::decode(&scratch[..bad_len]),
            Err(ToobError::InvalidArg)
        );
    }
    for bad_len in (sys::TOOB_TDR1_MIN_FRAME_SIZE + 1)..260 {
        if bad_len == sys::TOOB_TDR1_MAX_SIZE {
            continue;
        }
        let mut candidate = scratch;
        resign_tdr1_crc(&mut candidate[..bad_len]);
        assert_eq!(
            Tdr1Frame::decode(&candidate[..bad_len]),
            Err(ToobError::VerificationFailure)
        );
    }

    // 4. 60,000 iterations of hostile pseudo-random mutations & raw fuzz buffers
    let mut fuzz_buf = [0u8; 256];
    for iter in 0..60_000usize {
        if iter.is_multiple_of(3) {
            // Pure random bytes of random length 0..=256 (plus occasional forced CRC match)
            let len = (rng.next_u32() as usize) % (fuzz_buf.len() + 1);
            rng.fill_bytes(&mut fuzz_buf[..len]);
            if iter.is_multiple_of(6) && len >= sys::TOOB_TDR1_MIN_FRAME_SIZE {
                resign_tdr1_crc(&mut fuzz_buf[..len]);
            }
            if let Ok(parsed) = Tdr1Frame::decode(&fuzz_buf[..len]) {
                // Any accepted frame MUST satisfy every domain invariant and re-encode identically
                // when header_size == 132!
                assert!(parsed.diag_major >= sys::TOOB_TDR1_MIN_DIAG_MAJOR);
                assert!(parsed.active_slot <= 1);
            }
        } else {
            // Start from a valid 136B or 152B frame and inject hostile corruption
            let with_ext = !iter.is_multiple_of(2);
            let f = random_valid_tdr1(&mut rng, with_ext);
            let len = f.encode(&mut fuzz_buf).unwrap();

            if iter.is_multiple_of(2) {
                // Flip 1..=3 distinct bits across the frame without fixing CRC
                let flips = 1 + ((rng.next_u8() as usize) % 3);
                let first_pos = (rng.next_u32() as usize) % (len * 8);
                fuzz_buf[first_pos / 8] ^= 1u8 << (first_pos % 8);
                for k in 1..flips {
                    let pos = (first_pos + k * 13 + 7) % (len * 8);
                    fuzz_buf[pos / 8] ^= 1u8 << (pos % 8);
                }
                assert!(
                    Tdr1Frame::decode(&fuzz_buf[..len]).is_err(),
                    "corrupted CRC frame accepted at iter {iter}"
                );
            } else {
                // Corrupt a constrained header field and RE-SIGN CRC-32!
                match rng.next_u8() % 11 {
                    0 => fuzz_buf[0] ^= 1u8 << (rng.next_u8() % 8),
                    1 => fuzz_buf[4] ^= 1u8 << (rng.next_u8() % 8),
                    2 => {
                        let cand = rng.next_u8();
                        fuzz_buf[5] = if cand == sys::TOOB_TDR1_PARTITION_APP
                            || cand == sys::TOOB_TDR1_PARTITION_RECOVERY
                        {
                            1
                        } else {
                            cand
                        };
                    }
                    3 => fuzz_buf[6] |= 0x02,
                    4 => fuzz_buf[8] ^= 0x04,
                    5 => fuzz_buf[10] = rng.next_u8() % 3,
                    6 => fuzz_buf[11] = 2u8.saturating_add(rng.next_u8()),
                    7 => fuzz_buf[12] = 2u8.saturating_add(rng.next_u8()),
                    8 => fuzz_buf[13] = 7u8.saturating_add(rng.next_u8()),
                    9 => fuzz_buf[16] = 5u8.saturating_add(rng.next_u8()),
                    _ => fuzz_buf[30] |= 1u8 << (rng.next_u8() % 8),
                }
                resign_tdr1_crc(&mut fuzz_buf[..len]);
                assert_eq!(
                    Tdr1Frame::decode(&fuzz_buf[..len]),
                    Err(ToobError::VerificationFailure),
                    "re-signed invalid domain frame accepted at iter {iter}"
                );
            }
        }
    }
}

#[test]
fn define_platform_trampolines_null_zero_oversized_and_aliasing_safety() {
    let _g = SERIAL_GUARD.lock().unwrap();
    HOOK_MODE.store(0, Ordering::SeqCst);

    let mut byte = 0u8;
    let dangling_mut: *mut u8 = NonNull::<u8>::dangling().as_ptr();
    let dangling_const: *const u8 = NonNull::<u8>::dangling().as_ptr();
    let mut sha_ctx = sys::toob_os_sha256_ctx_t { opaque: [0u8; 128] };
    let mut out_hash = [0u8; 32];

    unsafe {
        // 1. NULL + 0-length & dangling non-null + 0-length across all slice trampolines
        assert_eq!(
            toob_os_flash_read(0, core::ptr::null_mut(), 0),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_flash_read(0, core::ptr::null_mut(), 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(toob_os_flash_read(0, dangling_mut, 0), sys::TOOB_OK);

        assert_eq!(
            toob_os_flash_write(0, core::ptr::null(), 0),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_flash_write(0, core::ptr::null(), 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(toob_os_flash_write(0, dangling_const, 0), sys::TOOB_OK);

        assert_eq!(
            toob_os_sha256_update(&mut sha_ctx, core::ptr::null(), 0),
            sys::TOOB_OK
        );
        assert_eq!(
            toob_os_sha256_update(&mut sha_ctx, dangling_const, 0),
            sys::TOOB_OK
        );
        assert_eq!(
            toob_os_sha256_update(&mut sha_ctx, core::ptr::null(), 4),
            sys::TOOB_ERR_INVALID_ARG
        );

        let mut zero_cap = 0usize;
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), core::ptr::null_mut(), &mut zero_cap),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), dangling_mut, &mut zero_cap),
            sys::TOOB_OK
        );
        assert_eq!(zero_cap, 0);

        assert_eq!(
            toob_os_nvs_write(c"k".as_ptr(), core::ptr::null(), 0),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_nvs_write(c"k".as_ptr(), dangling_const, 0),
            sys::TOOB_ERR_INVALID_ARG
        );

        // 2. Oversized len > u32::MAX (on 64-bit) and len > isize::MAX / usize::MAX without UB!
        #[cfg(target_pointer_width = "64")]
        {
            let over_u32 = (u32::MAX as usize) + 1;
            let mut cap = over_u32;
            assert_eq!(
                toob_os_nvs_read(c"k".as_ptr(), &mut byte, &mut cap),
                sys::TOOB_ERR_INVALID_ARG
            );
            assert_eq!(cap, 0);

            assert_eq!(
                toob_os_nvs_write(c"k".as_ptr(), &byte, over_u32),
                sys::TOOB_ERR_INVALID_ARG
            );
        }

        let over_isize = (isize::MAX as usize) + 1;
        let mut cap_isize = over_isize;
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), &mut byte, &mut cap_isize),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(cap_isize, 0);

        let mut cap_umax = usize::MAX;
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), &mut byte, &mut cap_umax),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(cap_umax, 0);

        assert_eq!(
            toob_os_nvs_write(c"k".as_ptr(), &byte, over_isize),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_nvs_write(c"k".as_ptr(), &byte, usize::MAX),
            sys::TOOB_ERR_INVALID_ARG
        );

        // 3. Address-space wrap pointers near usize::MAX rejected before slice::from_raw_parts
        let near_top_mut = core::ptr::without_provenance_mut::<u8>(usize::MAX - 4);
        let near_top_const = core::ptr::without_provenance::<u8>(usize::MAX - 4);
        assert_eq!(
            toob_os_flash_read(0, near_top_mut, 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_flash_write(0, near_top_const, 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_sha256_init(
                core::ptr::without_provenance_mut::<sys::toob_os_sha256_ctx_t>(usize::MAX - 16)
            ),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_sha256_update(&mut sha_ctx, near_top_const, 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(
            toob_os_sha256_finalize(&mut sha_ctx, near_top_mut),
            sys::TOOB_ERR_INVALID_ARG
        );
        let mut wrap_cap = 16usize;
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), near_top_mut, &mut wrap_cap),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(wrap_cap, 0);
        assert_eq!(
            toob_os_nvs_write(c"k".as_ptr(), near_top_const, 16),
            sys::TOOB_ERR_INVALID_ARG
        );

        // 4. Unaligned `*mut usize` length pointer in toob_os_nvs_read rejected before dereference
        let mut raw_unaligned = [0u8; 16];
        let unaligned_len_ptr = raw_unaligned.as_mut_ptr().add(1).cast::<usize>();
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), &mut byte, unaligned_len_ptr),
            sys::TOOB_ERR_INVALID_ARG
        );

        // 5. Overlapping aliasing pointer pairs rejected fail-closed (no `&mut` aliasing UB)
        let ctx_aliasing_data = sha_ctx.opaque.as_ptr().add(8);
        assert_eq!(
            toob_os_sha256_update(&mut sha_ctx, ctx_aliasing_data, 16),
            sys::TOOB_ERR_INVALID_ARG
        );
        let ctx_aliasing_hash = sha_ctx.opaque.as_mut_ptr().add(16);
        assert_eq!(
            toob_os_sha256_finalize(&mut sha_ctx, ctx_aliasing_hash),
            sys::TOOB_ERR_INVALID_ARG
        );

        let mut shared_key_buf = *b"toob_sys/cred\0\0\0";
        let mut alias_cap = shared_key_buf.len();
        assert_eq!(
            toob_os_nvs_read(
                shared_key_buf.as_ptr().cast::<core::ffi::c_char>(),
                shared_key_buf.as_mut_ptr(),
                &mut alias_cap
            ),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(alias_cap, 0);

        // 6. Invalid UTF-8 in C key string rejected cleanly
        let bad_utf8_key = [0xFFu8, 0xFE, 0x00];
        let mut utf8_cap = 8usize;
        assert_eq!(
            toob_os_nvs_read(
                bad_utf8_key.as_ptr().cast::<core::ffi::c_char>(),
                out_hash.as_mut_ptr(),
                &mut utf8_cap
            ),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(utf8_cap, 0);
        assert_eq!(
            toob_os_nvs_write(
                bad_utf8_key.as_ptr().cast::<core::ffi::c_char>(),
                out_hash.as_ptr(),
                4
            ),
            sys::TOOB_ERR_INVALID_ARG
        );

        // 7. Hook returning Ok(n > cap) is clamped/rejected fail-closed
        HOOK_MODE.store(2, Ordering::SeqCst);
        let mut over_rep_cap = 8usize;
        assert_eq!(
            toob_os_nvs_read(c"k".as_ptr(), out_hash.as_mut_ptr(), &mut over_rep_cap),
            sys::TOOB_ERR_INVALID_ARG
        );
        assert_eq!(over_rep_cap, 0);

        // 8. Hook returning Err(ToobError::Unknown(TOOB_OK.0)) NEVER leaks TOOB_OK across FFI
        HOOK_MODE.store(1, Ordering::SeqCst);
        assert_ne!(toob_os_flash_read(0, &mut byte, 1), sys::TOOB_OK);
        assert_ne!(toob_os_flash_write(0, &byte, 1), sys::TOOB_OK);
        assert_ne!(toob_os_flash_erase(0, 4096), sys::TOOB_OK);
        let mut inv_cap = 4usize;
        assert_ne!(
            toob_os_nvs_read(c"k".as_ptr(), out_hash.as_mut_ptr(), &mut inv_cap),
            sys::TOOB_OK
        );
        assert_eq!(inv_cap, 0);
        assert_ne!(
            toob_os_nvs_write(c"k".as_ptr(), out_hash.as_ptr(), 4),
            sys::TOOB_OK
        );
        HOOK_MODE.store(0, Ordering::SeqCst);
    }
}
