/**
 * @file test_core_pipeline.c
 * @brief End-to-End Host SIL Integration Test for Toob-Loader Core Pipeline (HIGH-08).
 *
 * Compiled WITHOUT TOOB_MOCK_TEST against the real production Core C modules,
 * real Monocypher Ed25519 verification, real software SHA-256 Merkle streaming,
 * real K4 journal MAC chains, and Dual-Slot XIP Remap (POINTER) transport.
 *
 * Verifies:
 *   1. Cold boot baseline & ARCH-T01 bus-matrix/I-cache barriers before OS jump.
 *   2. HIGH-22 active-slot bounds defense on TBM1 update requests.
 *   3. Signed Zero-Copy Trailer-TBM1 update + HIGH-09 single-flush TMR coalescing
 *      (<= 3 WAL sector erases per boot) + CRIT-25 tentative nonce handoff.
 *   4. CRIT-25 zero-nonce rejection, v2 mailbox confirm -> TOOB_STATE_COMMITTED,
 *      and direct warm-boot RTC-RAM confirm from WAL_INTENT_TXN_COMMIT.
 *   5. Pre-Auth TCC1 binary Cloud Command pipeline (tampered sig zero-OTP-burn
 *      rejection, KILLSWITCH + sticky lock, anti-replay rejection, UNLOCK, and
 *      FORCE_UPDATE auto-discovery on inactive slot).
 *   6. CRIT-24 cumulative v2 mailbox bitmasks:
 *      - Recovery OS: TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED
 *      - Active OS:   TOOB_REQ_CONFIRM | TOOB_REQ_UPDATE_PENDING
 */

#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generated_boot_config.h"
#include "boot_cloud_cmd.h"
#include "boot_crc32.h"
#include "boot_diag.h"
#include "boot_flash_guard.h"
#include "boot_hal.h"
#include "boot_identity.h"
#include "boot_journal.h"
#include "boot_main.h"
#include "boot_panic.h"
#include "boot_proof.h"
#include "boot_rstore.h"
#include "boot_slot_caps.h"
#include "boot_tbm1.h"
#include "crypto_monocypher.h"
#include "crypto_sha256.h"
#if defined(TOOB_PQC_ENABLED) && TOOB_PQC_ENABLED
#include "crypto_pqc.h"
#endif
#include "monocypher-ed25519.h"
#include "sha256.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_mailbox_wire.h"

extern toob_handoff_t toob_handoff_state;

/* ============================================================================
 * Panic / Terminal-Halt Trap Harness (replaces boot_panic.c for host SIL)
 * ============================================================================ */

static jmp_buf s_panic_jmp;
static bool s_expect_panic = false;
static boot_status_t s_last_panic_reason = BOOT_OK;
static uint16_t s_last_halt_site = 0U;

_Noreturn void boot_terminal_halt(const boot_platform_t *platform,
                                  boot_status_t reason,
                                  uint16_t site_id) {
    (void)platform;
    s_last_panic_reason = reason;
    s_last_halt_site = site_id;
    if (s_expect_panic) {
        longjmp(s_panic_jmp, 1);
    }
    fprintf(stderr, "FAIL: Unexpected boot_terminal_halt(reason=0x%08X, site=%u)\n",
            (unsigned)reason, (unsigned)site_id);
    abort();
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    boot_terminal_halt(platform, reason, 0U);
}

/* ============================================================================
 * Instrumented Hardware Simulation (4 MB NOR Flash, XIP MMU, RTC, OTP, SoC)
 * ============================================================================ */

static uint8_t s_flash[CHIP_FLASH_TOTAL_SIZE];
static uint32_t s_wal_sector_erases = 0U;
static uint32_t s_total_sector_erases = 0U;

static uint32_t s_tick_ms = 100U;
static reset_reason_t s_reset_reason = RESET_REASON_POWER_ON;

static uint64_t s_rtc_confirm_nonce = 0ULL;
static uint32_t s_rtc_backup_regs[8];

static uint32_t s_otp_counter = 0U;
static uint8_t s_dslc_state = 0x01U; /* Provisioned field device */
static uint32_t s_rng_state = 0x9E3779B9U;

static uint8_t s_root_sk[64];
static uint8_t s_root_pk[32];
static uint8_t s_cloud_sk[64];
static uint8_t s_cloud_pk[32];

static uint32_t s_active_hw_slot = 0U;
static uint32_t s_mapped_xip_src_addr = CHIP_APP_SLOT_ABS_ADDR;

static uint32_t s_flush_bus_calls = 0U;
static uint32_t s_icache_inv_calls = 0U;
static uint32_t s_lockdown_calls = 0U;
static boot_status_t s_lockdown_status = BOOT_OK;

/* --- Flash HAL --- */
static boot_status_t sim_flash_init(void) { return BOOT_OK; }
static void sim_flash_deinit(void) {}

static boot_status_t sim_flash_read(uint32_t addr, void *buf, size_t len) {
    if (!buf || addr > sizeof(s_flash) || len > sizeof(s_flash) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    memcpy(buf, &s_flash[addr], len);
    return BOOT_OK;
}

static boot_status_t sim_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (!buf || addr > sizeof(s_flash) || len > sizeof(s_flash) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
        (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        if ((~s_flash[addr + i] & src[i]) != 0U) {
            return BOOT_ERR_FLASH_HW;
        }
        s_flash[addr + i] &= src[i];
    }
    return BOOT_OK;
}

static boot_status_t sim_flash_erase_sector(uint32_t addr) {
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
        addr + CHIP_FLASH_MAX_SECTOR_SIZE > sizeof(s_flash)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    memset(&s_flash[addr], 0xFF, CHIP_FLASH_MAX_SECTOR_SIZE);
    s_total_sector_erases++;
    if (addr >= CHIP_WAL_ABS_ADDR && addr < (CHIP_WAL_ABS_ADDR + CHIP_WAL_SIZE)) {
        s_wal_sector_erases++;
    }
    return BOOT_OK;
}

static boot_status_t sim_flash_get_sector_size(uint32_t addr, size_t *size_out) {
    if (!size_out || addr >= sizeof(s_flash)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    *size_out = CHIP_FLASH_MAX_SECTOR_SIZE;
    return BOOT_OK;
}

static boot_status_t sim_flash_get_supply_mv(uint32_t *mv_out) {
    if (!mv_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    *mv_out = 3300U;
    return BOOT_OK;
}

static const flash_hal_t s_sim_flash_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_flash_init,
    .deinit = sim_flash_deinit,
    .read = sim_flash_read,
    .write = sim_flash_write,
    .erase_sector = sim_flash_erase_sector,
    .get_sector_size = sim_flash_get_sector_size,
    .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .max_erase_cycles = 100000U,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = 0xFFU,
    .erase_time_us_max = 45000U,
    .write_time_us_page = 50U,
    .get_supply_mv = sim_flash_get_supply_mv,
};

/* --- Clock HAL --- */
static boot_status_t sim_clock_init(void) { return BOOT_OK; }
static void sim_clock_deinit(void) {}
static uint32_t sim_clock_get_tick_ms(void) {
    s_tick_ms += 1U;
    return s_tick_ms;
}
static reset_reason_t sim_clock_get_reset_reason(void) { return s_reset_reason; }

static const clock_hal_t s_sim_clock_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_clock_init,
    .deinit = sim_clock_deinit,
    .get_tick_ms = sim_clock_get_tick_ms,
    .get_reset_reason = sim_clock_get_reset_reason,
};

/* --- WDT HAL --- */
static boot_status_t sim_wdt_init(uint32_t timeout_ms) {
    (void)timeout_ms;
    return BOOT_OK;
}
static void sim_wdt_deinit(void) {}
static void sim_wdt_kick(void) {}
static void sim_wdt_suspend(void) {}
static void sim_wdt_resume(void) {}

static const wdt_hal_t s_sim_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_wdt_init,
    .deinit = sim_wdt_deinit,
    .kick = sim_wdt_kick,
    .suspend_for_critical_section = sim_wdt_suspend,
    .resume = sim_wdt_resume,
};

/* --- Confirm HAL (mirrors drivers/rtc/esp_rtc_mem/confirm.c CRIT-25 behavior) --- */
static boot_status_t sim_confirm_init(void) { return BOOT_OK; }
static void sim_confirm_deinit(void) {}
static bool sim_confirm_check_ok(uint64_t expected_nonce) {
    if (expected_nonce == 0ULL) {
        return false;
    }
    if ((s_rtc_confirm_nonce ^ expected_nonce) == 0ULL) {
        s_rtc_confirm_nonce = 0ULL;
        return true;
    }
    return false;
}
static boot_status_t sim_confirm_clear(void) {
    s_rtc_confirm_nonce = 0ULL;
    return BOOT_OK;
}

static const confirm_hal_t s_sim_confirm_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_confirm_init,
    .deinit = sim_confirm_deinit,
    .check_ok = sim_confirm_check_ok,
    .clear = sim_confirm_clear,
};

/* --- SoC HAL --- */
static boot_status_t sim_soc_init(void) { return BOOT_OK; }
static void sim_soc_deinit(void) {}
static void sim_soc_assert_sec_reset(void) {}
static void sim_soc_flush_bus_matrix(void) { s_flush_bus_calls++; }
static void sim_soc_invalidate_icache(void) { s_icache_inv_calls++; }
static boot_status_t sim_soc_read_rtc_backup(uint8_t slot, uint32_t *val) {
    if (!val || slot >= 8U) {
        return BOOT_ERR_INVALID_ARG;
    }
    *val = s_rtc_backup_regs[slot];
    return BOOT_OK;
}
static boot_status_t sim_soc_write_rtc_backup(uint8_t slot, uint32_t val) {
    if (slot >= 8U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_rtc_backup_regs[slot] = val;
    return BOOT_OK;
}
static boot_status_t sim_soc_lockdown_before_handoff(void) {
    s_lockdown_calls++;
    return s_lockdown_status;
}

static const soc_hal_t s_sim_soc_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = sim_soc_init,
    .deinit = sim_soc_deinit,
    .assert_secondary_cores_reset = sim_soc_assert_sec_reset,
    .flush_bus_matrix = sim_soc_flush_bus_matrix,
    .invalidate_icache = sim_soc_invalidate_icache,
    .read_rtc_backup = sim_soc_read_rtc_backup,
    .write_rtc_backup = sim_soc_write_rtc_backup,
    .lockdown_before_handoff = sim_soc_lockdown_before_handoff,
};

/* --- Crypto HAL (Real Monocypher Ed25519 + Real Software SHA-256 + OTP Mock) --- */
static boot_status_t sim_crypto_random(uint8_t *buf, size_t len) {
    if (!buf) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < len; i++) {
        s_rng_state ^= s_rng_state << 13;
        s_rng_state ^= s_rng_state >> 17;
        s_rng_state ^= s_rng_state << 5;
        buf[i] = (uint8_t)(s_rng_state & 0xFFU);
    }
    /* Guarantee non-zero random output for 64-bit boot_nonce generation */
    if (len >= 8U) {
        uint64_t check = 0ULL;
        memcpy(&check, buf, sizeof(check));
        if (check == 0ULL) {
            buf[0] = 0xA5U;
        }
    }
    return BOOT_OK;
}

static boot_status_t sim_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    if (!key || key_len < 32U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (key_index == 0U) {
        memcpy(key, s_root_pk, 32U);
        return BOOT_OK;
    }
    return BOOT_ERR_NOT_FOUND;
}

static boot_status_t sim_read_chip_uid(uint8_t *buf, size_t max_len, size_t *out_len) {
    static const uint8_t k_uid[16] = {
        0xC6U, 0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU,
        0xEFU, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U
    };
    if (!buf || !out_len || max_len < sizeof(k_uid)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(buf, k_uid, sizeof(k_uid));
    *out_len = sizeof(k_uid);
    return BOOT_OK;
}

static boot_status_t sim_read_dslc(uint8_t *buf, size_t *len) {
    if (!buf || !len || *len < 1U) {
        return BOOT_ERR_INVALID_ARG;
    }
    buf[0] = s_dslc_state;
    *len = 1U;
    return BOOT_OK;
}

static boot_status_t sim_write_dslc(const uint8_t *val, size_t len) {
    if (!val || len != 1U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_dslc_state |= val[0];
    return BOOT_OK;
}

static boot_status_t sim_read_monotonic(uint32_t *ctr) {
    if (!ctr) {
        return BOOT_ERR_INVALID_ARG;
    }
    *ctr = s_otp_counter;
    return BOOT_OK;
}

static boot_status_t sim_advance_monotonic(void) {
    s_otp_counter++;
    return BOOT_OK;
}

static boot_status_t sim_read_device_secret(uint8_t *secret_out, size_t max_len, size_t *actual_len) {
    static const uint8_t k_huk[32] = {
        0x31U, 0x42U, 0x53U, 0x64U, 0x75U, 0x86U, 0x97U, 0xA8U,
        0xB9U, 0xCAU, 0xDBU, 0xECU, 0xFDU, 0x0EU, 0x1FU, 0x20U,
        0x12U, 0x23U, 0x34U, 0x45U, 0x56U, 0x67U, 0x78U, 0x89U,
        0x9AU, 0xABU, 0xBCU, 0xCDU, 0xDEU, 0xEFU, 0xF0U, 0x01U
    };
    if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(secret_out, k_huk, sizeof(k_huk));
    *actual_len = sizeof(k_huk);
    return BOOT_OK;
}

static const crypto_hal_t s_sim_crypto_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init = crypto_monocypher_init,
    .deinit = crypto_monocypher_deinit,
    .hash_init = crypto_sha256_init,
    .hash_update = crypto_sha256_update,
    .hash_finish = crypto_sha256_finish,
    .get_hash_ctx_size = crypto_sha256_get_ctx_size,
    .verify_signature = crypto_monocypher_verify_signature,
    .verify_signature_ph = crypto_monocypher_verify_signature_ph,
#if defined(TOOB_PQC_ENABLED) && TOOB_PQC_ENABLED
    .verify_pqc = crypto_ml_dsa_65_verify_pqc,
    .is_pqc_enforced = crypto_ml_dsa_65_is_pqc_enforced,
#else
    .verify_pqc = NULL,
    .is_pqc_enforced = NULL,
#endif
};

static const entropy_hal_t s_sim_entropy_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .random = sim_crypto_random,
    .is_hardware_trng = true,
};

static const keystore_hal_t s_sim_keystore_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .read_pubkey = sim_read_pubkey,
    .read_chip_uid = sim_read_chip_uid,
    .read_dslc = sim_read_dslc,
    .write_dslc = sim_write_dslc,
    .read_monotonic_counter = sim_read_monotonic,
    .advance_monotonic_counter = sim_advance_monotonic,
    .read_device_secret = sim_read_device_secret,
};

/* --- Dual-Slot XIP Remap Slot Caps (mirrors esp_mmu_remap) --- */
static boot_status_t sim_xip_remap_commit(uint32_t active_slot_src_addr) {
    if ((active_slot_src_addr % CHIP_MMU_PAGE_SIZE) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    if (active_slot_src_addr == CHIP_APP_SLOT_ABS_ADDR) {
        s_active_hw_slot = 0U;
        s_mapped_xip_src_addr = active_slot_src_addr;
        return BOOT_OK;
    }
    if (active_slot_src_addr == CHIP_STAGING_SLOT_ABS_ADDR) {
        s_active_hw_slot = 1U;
        s_mapped_xip_src_addr = active_slot_src_addr;
        return BOOT_OK;
    }
    return BOOT_ERR_FLASH_BOUNDS;
}

static boot_status_t sim_xip_get_active_slot(uint32_t *slot_index_out) {
    if (!slot_index_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    *slot_index_out = s_active_hw_slot;
    return BOOT_OK;
}

static const slot_caps_t s_sim_slot_caps = {
    .exec_model = SLOT_EXEC_XIP_REMAP,
    .commit_persistence = SLOT_COMMIT_VOLATILE,
    .slot_count = 2U,
    .has_scratch = false,
    .scratch_size = 0U,
    .ops.xip_remap = {
        .xip_remap_commit = sim_xip_remap_commit,
    },
    .get_active_slot = sim_xip_get_active_slot,
};

const slot_caps_t *boot_get_slot_caps(void) {
    return &s_sim_slot_caps;
}

static const boot_platform_t s_sim_platform = {
    .flash = &s_sim_flash_hal,
    .confirm = &s_sim_confirm_hal,
    .wdt = &s_sim_wdt_hal,
    .crypto = &s_sim_crypto_hal,
    .clock = &s_sim_clock_hal,
    .console = NULL,
    .soc = &s_sim_soc_hal,
    .slot_caps = &s_sim_slot_caps,
    .entropy = &s_sim_entropy_hal,
    .keystore = &s_sim_keystore_hal,
};

static const uint32_t k_seal_key[4] = {
    0xA55A1234U, 0xC33C5678U, 0x96699ABCU, 0xF00FDEF0U
};

/* ============================================================================
 * Cryptographic Fixture Builders (Real Ed25519 + SHA-256 + KDM + TBM1 + TCC1)
 * ============================================================================ */

static void sha256_once(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

static void erase_flash_range(uint32_t base, uint32_t size) {
    for (uint32_t off = 0U; off < size; off += CHIP_FLASH_MAX_SECTOR_SIZE) {
        memset(&s_flash[base + off], 0xFF, CHIP_FLASH_MAX_SECTOR_SIZE);
    }
}

static void write_raw_bootable_image(uint32_t slot_base, uint32_t total_img_size, uint8_t fill_byte) {
    const uint32_t min_size =
        (uint32_t)(sizeof(toob_image_header_t) + sizeof(toob_img_sig_trailer_t));
    assert(total_img_size >= min_size);
    assert((total_img_size % CHIP_FLASH_WRITE_ALIGNMENT) == 0U);
    uint8_t *buf = &s_flash[slot_base];
    memset(buf, fill_byte, total_img_size);

    toob_image_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TOOB_MAGIC_HEADER;
    hdr.image_size = total_img_size;
    hdr.entry_point = 0x100U;
    memcpy(buf, &hdr, sizeof(hdr));

    uint32_t signed_len = total_img_size - (uint32_t)sizeof(toob_img_sig_trailer_t);
    uint8_t digest[32];
    sha256_once(buf, signed_len, digest);

    toob_img_sig_trailer_t trailer;
    memset(&trailer, 0, sizeof(trailer));
    trailer.magic = TOOB_IMG_SIG_MAGIC;
    trailer.key_index = 0U;
    trailer.flags = TOOB_IMG_SIG_FLAG_SHA256;
    trailer.reserved = 0U;
    crypto_ed25519_sign(trailer.sig_ed25519, s_root_sk, digest, sizeof(digest));
    memcpy(buf + signed_len, &trailer, sizeof(trailer));
}

/**
 * Stages a real Ed25519-signed Zero-Copy Trailer-TBM1 bundle into `slot_base`
 * and returns the absolute flash address of the TBM1 manifest (`slot_base + 4096`).
 */
static uint32_t stage_signed_trailer_tbm1(uint32_t slot_base,
                                          uint32_t slot_size,
                                          uint32_t svn,
                                          uint8_t fill_byte,
                                          bool corrupt_sig) {
    erase_flash_range(slot_base, slot_size);

    const uint32_t img_size = 4096U;
    const uint32_t chunk_size = 4096U;
    const uint32_t num_chunks = 1U;
    write_raw_bootable_image(slot_base, img_size, fill_byte);

    uint8_t chunk_digest[32];
    sha256_once(&s_flash[slot_base], img_size, chunk_digest);

    const uint32_t tbm1_addr = slot_base + 4096U;
    const uint32_t hashes_off = TBM1_FIXED_LEN;
    const uint32_t hashes_len = num_chunks * 32U;
    const uint32_t total_len = TBM1_FIXED_LEN + hashes_len + TBM1_SIG_LEN;

    uint8_t tbm1_buf[1024] __attribute__((aligned(8)));
    memset(tbm1_buf, 0, sizeof(tbm1_buf));

    tbm1_header_t *hdr = (tbm1_header_t *)tbm1_buf;
    hdr->magic = TBM1_MAGIC;
    hdr->version_major = TBM1_VERSION_MAJOR;
    hdr->version_minor = TBM1_VERSION_MINOR;
    hdr->fixed_len = TBM1_FIXED_LEN;
    hdr->total_len = total_len;
    hdr->flags_critical = TBM1_CRIT_TRAILER_LAYOUT;
    hdr->flags_info = 0U;
    hdr->vendor_id = TOOB_DEVICE_VENDOR_ID;
    hdr->product_id = TOOB_DEVICE_PRODUCT_ID;
    hdr->hw_rev_min = 0U;
    hdr->hw_rev_max = 10U;
    hdr->key_index = 0U;
    hdr->image_count = 1U;
    hdr->boot_retry_limit = BOOT_CONFIG_MAX_RETRIES;
    hdr->min_reader_major = TBM1_VERSION_MAJOR;
    hdr->min_reader_minor = 0U;
    hdr->svn = svn;
    hdr->stage1_svn = 0U;
    hdr->key_epoch = 0U;
    hdr->build_number = 100U + svn;
    hdr->fw_ver_major = 1U;
    hdr->fw_ver_minor = (uint16_t)svn;
    hdr->fw_ver_patch = 0U;

    hdr->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
    hdr->regions[0].off = hashes_off;
    hdr->regions[0].len = hashes_len;

    hdr->images[0].image_type = 0U;
    hdr->images[0].target_slot = TBM1_SLOT_APP;
    hdr->images[0].compression_alg = TBM1_COMP_NONE;
    hdr->images[0].delta_alg = TBM1_DELTA_NONE;
    hdr->images[0].data_off = 0U;
    hdr->images[0].stored_size = img_size;
    hdr->images[0].installed_size = img_size;
    hdr->images[0].chunk_size = chunk_size;
    hdr->images[0].num_chunks = num_chunks;
    hdr->images[0].ver_major = 1U;
    hdr->images[0].ver_minor = (uint16_t)svn;

    hdr->fixed_crc32 = compute_boot_crc32(tbm1_buf, TBM1_CRC_LEN);
    memcpy(tbm1_buf + hashes_off, chunk_digest, sizeof(chunk_digest));

    uint8_t *sig_dst = tbm1_buf + total_len - TBM1_SIG_LEN;
    crypto_ed25519_sign(sig_dst, s_root_sk, tbm1_buf, total_len - TBM1_SIG_LEN);
    if (corrupt_sig) {
        sig_dst[0] ^= 0x01U;
    }

    memcpy(&s_flash[tbm1_addr], tbm1_buf, total_len);
    return tbm1_addr;
}

static void write_v2_mailbox(uint16_t req_flags, uint32_t seq, uint32_t tbm1_addr, uint64_t nonce) {
    uint32_t slot_idx = seq % TOOB_MAILBOX_SLOTS;
    uint32_t slot_addr = CHIP_MAILBOX_ABS_ADDR + (slot_idx * CHIP_FLASH_MAX_SECTOR_SIZE);
    memset(&s_flash[slot_addr], 0xFF, CHIP_FLASH_MAX_SECTOR_SIZE);

    toob_mailbox_t mbx;
    memset(&mbx, 0, sizeof(mbx));
    mbx.magic = TOOB_MAILBOX_MAGIC;
    mbx.version = TOOB_MAILBOX_VERSION;
    mbx.request = req_flags;
    mbx.seq = seq;
    mbx.tbm1_addr = tbm1_addr;
    mbx.nonce = nonce;
    mbx._reserved = 0U;
    mbx.crc32 = compute_boot_crc32((const uint8_t *)&mbx, TOOB_MAILBOX_CRC_LEN);

    memcpy(&s_flash[slot_addr], &mbx, sizeof(mbx));
}

static void write_signed_tcc1_cmd(uint8_t cmd,
                                  uint32_t counter_min,
                                  uint32_t issued_at,
                                  const uint8_t *params,
                                  uint32_t params_len,
                                  bool corrupt_sig) {
    memset(&s_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], 0xFF, CHIP_CLOUD_CMD_SLOT_SIZE);

    uint8_t device_id[32];
    assert(boot_derive_device_id(&s_sim_platform, device_id) == BOOT_OK);

    uint32_t aligned_plen = TOOB_CLOUD_CMD_ALIGN_UP(params_len);
    uint32_t total_len = TOOB_CLOUD_CMD_HDR_SIZE + aligned_plen + TOOB_CLOUD_CMD_SIG_SIZE;
    assert(total_len >= TOOB_CLOUD_CMD_MIN_SIZE && total_len <= TOOB_CLOUD_CMD_MAX_SIZE);

    uint8_t env[TOOB_CLOUD_CMD_MAX_SIZE] __attribute__((aligned(8)));
    memset(env, 0, sizeof(env));

    toob_cloud_cmd_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TOOB_CLOUD_CMD_MAGIC;
    hdr.version = TOOB_CLOUD_CMD_VERSION;
    hdr.command = cmd;
    hdr.flags = 0U;
    hdr.counter_min = counter_min;
    hdr.issued_at = issued_at;
    hdr.params_len = params_len;
    hdr.total_len = total_len;
    memcpy(hdr.device_id, device_id, sizeof(device_id));
    hdr._reserved = 0U;
    hdr.crc32 = compute_boot_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);

    memcpy(env, &hdr, sizeof(hdr));
    if (params_len > 0U && params != NULL) {
        memcpy(env + TOOB_CLOUD_CMD_HDR_SIZE, params, params_len);
    }

    uint8_t *sig_ptr = env + total_len - TOOB_CLOUD_CMD_SIG_SIZE;
    crypto_ed25519_sign(sig_ptr, s_cloud_sk, env, total_len - TOOB_CLOUD_CMD_SIG_SIZE);
    if (corrupt_sig) {
        sig_ptr[7] ^= 0x80U;
    }

    memcpy(&s_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], env, total_len);
}

static void provision_device_fixtures(void) {
    memset(s_flash, 0xFF, sizeof(s_flash));
    memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
    memset(&toob_diag_state, 0, sizeof(toob_diag_state));
    memset(s_rtc_backup_regs, 0, sizeof(s_rtc_backup_regs));

    s_wal_sector_erases = 0U;
    s_total_sector_erases = 0U;
    s_rtc_confirm_nonce = 0ULL;
    s_otp_counter = 0U;
    s_dslc_state = 0x00U; /* Factory unprovisioned during initial WAL formatting (CRIT-69) */
    s_active_hw_slot = 0U;
    s_mapped_xip_src_addr = CHIP_APP_SLOT_ABS_ADDR;
    s_reset_reason = RESET_REASON_POWER_ON;
    s_flush_bus_calls = 0U;
    s_icache_inv_calls = 0U;
    s_lockdown_calls = 0U;
    s_lockdown_status = BOOT_OK;

    uint8_t root_seed[32];
    uint8_t cloud_seed[32];
    for (size_t i = 0; i < 32U; i++) {
        root_seed[i] = (uint8_t)(0x11U + i * 3U);
        cloud_seed[i] = (uint8_t)(0x99U - i * 2U);
    }
    crypto_ed25519_key_pair(s_root_sk, s_root_pk, root_seed);
    crypto_ed25519_key_pair(s_cloud_sk, s_cloud_pk, cloud_seed);

    /* Sign & write Key Delegation Manifest (KDM) into 3-way quorum store */
    static const uint32_t kdm_addrs[3] = {
        CHIP_KDM_QUORUM_ABS_ADDR,
        CHIP_KDM_QUORUM_ABS_ADDR + CHIP_FLASH_MAX_SECTOR_SIZE,
        CHIP_KDM_QUORUM_ABS_ADDR + 2U * CHIP_FLASH_MAX_SECTOR_SIZE
    };
    static const size_t kdm_sizes[3] = {
        CHIP_FLASH_MAX_SECTOR_SIZE,
        CHIP_FLASH_MAX_SECTOR_SIZE,
        CHIP_FLASH_MAX_SECTOR_SIZE
    };
    const boot_rstore_desc_t kdm_desc = {
        .slot_addrs = kdm_addrs,
        .slot_sizes = kdm_sizes,
        .slot_count = 3U,
        .record_size = sizeof(toob_kdm_t),
        .magic = 0x4B444D51U,
    };

    toob_kdm_t kdm;
    memset(&kdm, 0, sizeof(kdm));
    kdm.sequence_number = 1U;
    memcpy(kdm.new_cloud_pubkey, s_cloud_pk, sizeof(s_cloud_pk));
    crypto_ed25519_sign(kdm.signature_ed25519, s_root_sk,
                        (const uint8_t *)&kdm,
                        offsetof(toob_kdm_t, signature_ed25519));
    assert(boot_rstore_write(&s_sim_platform, &kdm_desc, &kdm) == BOOT_OK);

    /* Factory baseline App in Slot 0 + immutable Recovery OS */
    write_raw_bootable_image(CHIP_APP_SLOT_ABS_ADDR, 4096U, 0xA0U);
    write_raw_bootable_image(CHIP_RECOVERY_OS_ABS_ADDR, 4096U, 0xE0U);

    /* Initialize blank WAL while DSLC == 0x00 (CRIT-69), then transition to deployed (DSLC == 0x01) */
    assert(boot_journal_init(&s_sim_platform) == BOOT_OK);
    s_dslc_state = 0x01U;
}

/* ============================================================================
 * Main End-to-End Pipeline Test Suite
 * ============================================================================ */

int main(void) {
    printf("================================================================\n");
    printf("  Toob-Boot End-to-End Core Pipeline SIL Suite (No Mock Bypass)\n");
    printf("================================================================\n\n");

    provision_device_fixtures();
    uint32_t mbx_seq = 0U;
    boot_target_config_t target;

    /* ----------------------------------------------------------------------
     * [1] Cold Boot Baseline + ARCH-T01 Cache/Bus Barrier Verification
     * ---------------------------------------------------------------------- */
    printf("[1] Cold boot baseline + ARCH-T01 barrier verification...\n");
    s_flush_bus_calls = 0U;
    s_icache_inv_calls = 0U;
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 0U);
    assert(target.boot_recovery_os == false);
    assert(target.is_tentative_boot == false);
    assert(target.proof.image_addr == CHIP_APP_SLOT_ABS_ADDR);
    assert(boot_proof_verify(&target.proof, k_seal_key) == BOOT_OK);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    assert(toob_handoff_state.boot_nonce == 0ULL);
    assert(toob_handoff_state.active_slot == 0U);
    assert(toob_handoff_state.booted_partition == TOOB_PARTITION_APP);
    assert(s_flush_bus_calls >= 2U);
    assert(s_icache_inv_calls >= 1U);
    assert(s_lockdown_calls == 1U);
    printf("    -> Cold boot COMMITTED on Slot 0, ARCH-T01 barriers & lockdown hook verified (passed)\n");

    /* ----------------------------------------------------------------------
     * [2] HIGH-22 Active-Slot Bounds Defense (Reject Update Pointing at Active Slot)
     * ---------------------------------------------------------------------- */
    printf("\n[2] HIGH-22 active-slot bounds defense...\n");
    s_reset_reason = RESET_REASON_SOFTWARE;
    write_v2_mailbox(TOOB_REQ_UPDATE_PENDING, ++mbx_seq, CHIP_APP_SLOT_ABS_ADDR, 0ULL);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 0U);
    assert(target.is_tentative_boot == false);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    printf("    -> Active-slot tbm1_addr rejected cleanly; Slot 0 preserved (passed)\n");

    /* ----------------------------------------------------------------------
     * [3] Signed Trailer-TBM1 Update (Slot 0 -> Slot 1) + HIGH-09 TMR Wear Audit
     * ---------------------------------------------------------------------- */
    printf("\n[3] Signed TBM1 update (svn=2, Slot 1) + HIGH-09 single-flush TMR audit...\n");
    /* First verify corrupted Ed25519 TBM1 signature is rejected without switching slots */
    uint32_t bad_tbm1 = stage_signed_trailer_tbm1(
        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, 2U, 0xB1U, true);
    write_v2_mailbox(TOOB_REQ_UPDATE_PENDING, ++mbx_seq, bad_tbm1, 0ULL);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 0U);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    printf("    -> Tampered TBM1 signature rejected; remained on Slot 0 (passed)\n");

    /* Now stage authentic Ed25519-signed TBM1 (svn=2) in inactive Slot 1 */
    uint32_t tbm1_v2 = stage_signed_trailer_tbm1(
        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, 2U, 0xB2U, false);
    write_v2_mailbox(TOOB_REQ_UPDATE_PENDING, ++mbx_seq, tbm1_v2, 0ULL);

    s_wal_sector_erases = 0U;
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 1U);
    assert(target.is_tentative_boot == true);
    assert(target.proof.image_addr == CHIP_STAGING_SLOT_ABS_ADDR);
    assert(s_mapped_xip_src_addr == CHIP_STAGING_SLOT_ABS_ADDR);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    assert(toob_handoff_state.boot_nonce != 0ULL);
    assert(toob_handoff_state.active_slot == 1U);
    assert(toob_diag_state.current_svn == 2U);
    /* HIGH-09: Coalesced TMR updates must incur at most 1 TMR rotation (<= 3 WAL erases) */
    assert(s_wal_sector_erases <= 3U);
    printf("    -> Slot 1 active in TENTATIVE state; WAL erases=%u (<= 3) (passed)\n",
           (unsigned)s_wal_sector_erases);

    /* ----------------------------------------------------------------------
     * [4] CRIT-25 Nonce Authorization, Mailbox Confirm & Direct RTC Confirm
     * ---------------------------------------------------------------------- */
    printf("\n[4] CRIT-25 zero-nonce defense, mailbox confirm, and warm RTC confirm...\n");
    assert(s_sim_confirm_hal.check_ok(0ULL) == false);

    /* Reject mailbox TOOB_REQ_CONFIRM with nonce == 0ULL */
    write_v2_mailbox(TOOB_REQ_CONFIRM, ++mbx_seq, 0U, 0ULL);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    uint64_t valid_nonce = toob_handoff_state.boot_nonce;
    assert(valid_nonce != 0ULL);
    printf("    -> Zero-nonce mailbox confirm rejected; remained TENTATIVE (passed)\n");

    /* Confirm with exact boot_nonce via v2 mailbox -> must seal TOOB_STATE_COMMITTED! */
    write_v2_mailbox(TOOB_REQ_CONFIRM, ++mbx_seq, 0U, valid_nonce);
    s_wal_sector_erases = 0U;
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 1U);
    assert(target.is_tentative_boot == false);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    assert(toob_handoff_state.boot_nonce == 0ULL);
    assert(s_wal_sector_erases <= 3U);
    printf("    -> Valid mailbox confirm healed to TOOB_STATE_COMMITTED; WAL erases=%u (passed)\n",
           (unsigned)s_wal_sector_erases);

    /* Ping-pong update (Slot 1 -> Slot 0, svn=3) + direct RTC-RAM confirm from TXN_COMMIT */
    uint32_t tbm1_v3 = stage_signed_trailer_tbm1(
        CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, 3U, 0xC3U, false);
    write_v2_mailbox(TOOB_REQ_UPDATE_PENDING, ++mbx_seq, tbm1_v3, 0ULL);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 0U);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    assert(toob_handoff_state.boot_nonce != 0ULL);

    /* Confirm via RTC-RAM ONLY (no mailbox write -> WAL stays WAL_INTENT_TXN_COMMIT!) */
    s_rtc_confirm_nonce = toob_handoff_state.boot_nonce;
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 0U);
    assert(target.is_tentative_boot == false);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    assert(toob_handoff_state.boot_nonce == 0ULL);
    printf("    -> Warm RTC-only confirm from WAL_INTENT_TXN_COMMIT healed to COMMITTED (passed)\n");

    /* ----------------------------------------------------------------------
     * [5] Pre-Auth TCC1 Cloud Command Pipeline (Auth, Killswitch, Replay, Unlock, Force Update)
     * ---------------------------------------------------------------------- */
    printf("\n[5] Pre-Auth TCC1 Cloud Command pipeline verification...\n");
    uint32_t otp_before = s_otp_counter;

    /* 5a. Tampered Ed25519 signature MUST fail pre-auth without burning OTP bits */
    write_signed_tcc1_cmd((uint8_t)TOOB_CMD_KILLSWITCH, otp_before + 1U, 1000U, NULL, 0U, true);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(s_otp_counter == otp_before);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    printf("    -> Pre-auth tampered TCC1 rejected with zero OTP burn (passed)\n");

    /* 5b. Authentic TCC1 KILLSWITCH -> burns OTP + traps into BOOT_ERR_DEVICE_LOCKED */
    write_signed_tcc1_cmd((uint8_t)TOOB_CMD_KILLSWITCH, otp_before + 1U, 1001U, NULL, 0U, false);
    s_expect_panic = true;
    s_last_panic_reason = BOOT_OK;
    if (setjmp(s_panic_jmp) == 0) {
        (void)boot_main(&s_sim_platform, &target, k_seal_key);
        assert(!"KILLSWITCH must trap into boot_panic(BOOT_ERR_DEVICE_LOCKED)");
    }
    s_expect_panic = false;
    assert(s_last_panic_reason == BOOT_ERR_DEVICE_LOCKED);
    assert(s_otp_counter == otp_before + 1U);
    printf("    -> TCC1 KILLSWITCH authenticated, OTP advanced, trapped BOOT_ERR_DEVICE_LOCKED (passed)\n");

    /* 5c. Sticky Lock + Replay Defense: spoofed RTC confirm & replayed counter_min stay locked */
    s_rtc_confirm_nonce = 0x1122334455667788ULL;
    write_signed_tcc1_cmd((uint8_t)TOOB_CMD_UNLOCK, s_otp_counter, 1002U, NULL, 0U, false);
    s_expect_panic = true;
    s_last_panic_reason = BOOT_OK;
    if (setjmp(s_panic_jmp) == 0) {
        (void)boot_main(&s_sim_platform, &target, k_seal_key);
        assert(!"Replayed TCC1 UNLOCK must be rejected and keep device locked");
    }
    s_expect_panic = false;
    assert(s_last_panic_reason == BOOT_ERR_DEVICE_LOCKED);
    printf("    -> Sticky Lock & TCC1 counter_min anti-replay enforced (passed)\n");

    /* 5d. Authentic TCC1 UNLOCK with higher counter_min & issued_at unlocks cleanly */
    write_signed_tcc1_cmd((uint8_t)TOOB_CMD_UNLOCK, s_otp_counter + 1U, 1003U, NULL, 0U, false);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    assert(target.active_slot == 0U);
    printf("    -> TCC1 UNLOCK restored normal COMMITTED boot (passed)\n");

    /* 5e. Authentic TCC1 FORCE_UPDATE auto-discovers Trailer-TBM1 in inactive Slot 1 */
    (void)stage_signed_trailer_tbm1(
        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, 10U, 0xD4U, false);
    write_signed_tcc1_cmd((uint8_t)TOOB_CMD_FORCE_UPDATE, s_otp_counter + 1U, 1004U, NULL, 0U, false);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 1U);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    assert(toob_diag_state.current_svn == 10U);

    /* Confirm svn=10 on Slot 1 */
    write_v2_mailbox(TOOB_REQ_CONFIRM, ++mbx_seq, 0U, toob_handoff_state.boot_nonce);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    printf("    -> TCC1 FORCE_UPDATE auto-discovered & applied svn=10 on Slot 1 (passed)\n");

    /* ----------------------------------------------------------------------
     * [6] CRIT-24 Cumulative v2 Mailbox Bitmask Verification
     * ---------------------------------------------------------------------- */
    printf("\n[6] CRIT-24 cumulative mailbox bitmasks (Recovery & OS sessions)...\n");

    /* 6a. Induce persistent OS watchdog crashes until Recovery OS boots */
    s_reset_reason = RESET_REASON_WATCHDOG;
    for (uint32_t i = 0U; i <= BOOT_CONFIG_MAX_RETRIES; i++) {
        assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    }
    assert(target.boot_recovery_os == true);
    assert(toob_handoff_state.booted_partition == TOOB_PARTITION_RECOVERY);
    printf("    -> Persistent crashes routed to Recovery OS after %u retries (passed)\n",
           (unsigned)BOOT_CONFIG_MAX_RETRIES);

    /* Stage svn=11 into inactive Slot 0 and emit SINGLE cumulative mailbox record:
     * TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED */
    uint32_t tbm1_v11 = stage_signed_trailer_tbm1(
        CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, 11U, 0xE5U, false);
    write_v2_mailbox((uint16_t)(TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED),
                     ++mbx_seq, tbm1_v11, 0ULL);
    s_reset_reason = RESET_REASON_SOFTWARE;

    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.boot_recovery_os == false);
    assert(target.active_slot == 0U);
    assert(target.is_tentative_boot == true);
    assert(toob_handoff_state.booted_partition == TOOB_PARTITION_APP);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    assert(toob_diag_state.current_svn == 11U);
    printf("    -> Cumulative UPDATE_PENDING | RECOVERY_RESOLVED healed & booted svn=11 (passed)\n");

    /* 6b. While Slot 0 (svn=11) is TENTATIVE, confirm AND stage svn=12 in Slot 1
     * in a SINGLE cumulative mailbox record: TOOB_REQ_CONFIRM | TOOB_REQ_UPDATE_PENDING */
    uint64_t tentative_nonce_v11 = toob_handoff_state.boot_nonce;
    assert(tentative_nonce_v11 != 0ULL);
    uint32_t tbm1_v12 = stage_signed_trailer_tbm1(
        CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE, 12U, 0xF6U, false);
    write_v2_mailbox((uint16_t)(TOOB_REQ_CONFIRM | TOOB_REQ_UPDATE_PENDING),
                     ++mbx_seq, tbm1_v12, tentative_nonce_v11);

    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.boot_recovery_os == false);
    assert(target.active_slot == 1U);
    assert(target.is_tentative_boot == true);
    assert(toob_handoff_state.magic == TOOB_STATE_TENTATIVE);
    assert(toob_diag_state.current_svn == 12U);

    /* Final confirm of svn=12 */
    write_v2_mailbox(TOOB_REQ_CONFIRM, ++mbx_seq, 0U, toob_handoff_state.boot_nonce);
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(target.active_slot == 1U);
    assert(toob_handoff_state.magic == TOOB_STATE_COMMITTED);
    assert(toob_diag_state.current_svn == 12U);
    printf("    -> Cumulative CONFIRM | UPDATE_PENDING applied svn=12 without erasing staging (passed)\n");

    /* ----------------------------------------------------------------------
     * [7] Stage-0 Immutable Boot Write-Firewall & Pre-Handoff Lockdown Fail-Closed
     * ---------------------------------------------------------------------- */
    printf("\n[7] Stage-0 immutable boot write-firewall & lockdown_before_handoff fail-closed...\n");
    assert(CHIP_FLASH_IMMUTABLE_BOOT_END > 0U);
    memset(&s_flash[CHIP_STAGE0_ABS_ADDR], 0x55U, 64U);
    uint8_t zero_block[32] = {0};
    assert(boot_flash_write_guarded(&s_sim_flash_hal, CHIP_STAGE0_ABS_ADDR,
                                    zero_block, sizeof(zero_block)) == BOOT_ERR_FLASH_BOUNDS);
    assert(boot_flash_write_guarded(&s_sim_flash_hal, 0U,
                                    zero_block, sizeof(zero_block)) == BOOT_ERR_FLASH_BOUNDS);
    assert(boot_flash_erase_sector_guarded(&s_sim_flash_hal, CHIP_STAGE0_ABS_ADDR) ==
           BOOT_ERR_FLASH_BOUNDS);
    assert(boot_flash_erase_sector_guarded(&s_sim_flash_hal, 0U) ==
           BOOT_ERR_FLASH_BOUNDS);
    for (size_t i = 0U; i < 64U; i++) {
        assert(s_flash[CHIP_STAGE0_ABS_ADDR + i] == 0x55U);
    }
    printf("    -> boot_flash_write_guarded & boot_flash_erase_sector_guarded blocked < CHIP_FLASH_IMMUTABLE_BOOT_END (passed)\n");

    uint32_t locks_before = s_lockdown_calls;
    s_lockdown_status = BOOT_ERR_VERIFY;
    s_expect_panic = true;
    s_last_panic_reason = BOOT_OK;
    if (setjmp(s_panic_jmp) == 0) {
        (void)boot_main(&s_sim_platform, &target, k_seal_key);
        assert(!"Failed lockdown_before_handoff must trap into boot_panic!");
    }
    s_expect_panic = false;
    assert(s_lockdown_calls == locks_before + 1U);
    assert(s_last_panic_reason == BOOT_ERR_VERIFY);

    s_lockdown_status = BOOT_OK;
    assert(boot_main(&s_sim_platform, &target, k_seal_key) == BOOT_OK);
    assert(s_lockdown_calls == locks_before + 2U);
    printf("    -> soc->lockdown_before_handoff invoked before OS jump & fails closed on error (passed)\n");

    printf("\n================================================================\n");
    printf("  ALL END-TO-END CORE PIPELINE SIL TESTS PASSED SUCCESSFULLY!\n");
    printf("================================================================\n");
    return 0;
}
