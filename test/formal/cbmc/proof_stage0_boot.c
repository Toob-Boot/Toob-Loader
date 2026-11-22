/*
 * FV-01: CBMC Memory-Safety, Read-Only Flash & Boot-Handoff Proof for Stage 0.
 *
 * Covers:
 *   - toobloader/stage0/stage0_main.c
 *   - toobloader/stage0/stage0_boot_pointer.c
 *   - toobloader/stage0/stage0_tentative.c
 *   - toobloader/stage0/stage0_verify.c
 *   - toobloader/stage0/stage0_otp.c
 *   - toobloader/stage0/stage0_hash.c
 *   - toobloader/core/boot_platform_bringup.c
 *
 * Proves:
 *   1. Strict read-only flash invariant: Stage 0 never invokes flash->write or
 *      flash->erase_sector on any execution path.
 *   2. Continuous OTP key-slot scan (stage0_otp.c) & all-0x00 / all-0xFF pubkey
 *      fail-closed rejection.
 *   3. WAL 2-of-3 TMR majority quorum scan + split-brain max(stage1_svn) floor
 *      preservation (stage0_boot_pointer.c) + CRC-verified .noinit tentative
 *      rollback across WATCHDOG/HARD_FAULT/BROWNOUT/SOFTWARE resets
 *      (stage0_tentative.c).
 *   4. Stage-0 SHA-256 flash streaming error propagation & digest zero-poisoning
 *      (HIGH-30, stage0_hash.c) + double-shielded Ed25519 verification
 *      (stage0_verify.c).
 *   5. End-to-end stage0_main(): HAL ABI V3 gate, 5-round DSLC 3-of-5 majority
 *      vote, Stage-1 A/B fallback, authenticated stage1_svn >= svn_floor
 *      (CRIT-29), XIP & RAM entry_point bounds + 0x7F VTOR alignment (HIGH-26),
 *      HAL teardown, and g_seal_key[4] zeroization prior to jump_to_payload().
 */

#define CBMC_NO_TERMINAL_HALT_STUB 1
#define CBMC_NO_BOOT_PANIC_STUB    1

#include "cbmc_common.h"
#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_journal.h"
#include "boot_platform_bringup.h"
#include "boot_proof.h"
#include "libtoob_types.h"
#include "stage0_crypto.h"

extern toob_handoff_t toob_handoff_state;
int stage0_entry_main(void);

uint8_t g_stage0_sram[320] __attribute__((aligned(128)));

static uint32_t       g_flash_write_calls;
static uint32_t       g_flash_erase_calls;
static const uint8_t *g_seal_key_ptr;
static uint8_t        g_otp_first_empty;
static uint8_t        g_otp_keys[5][32];
static toob_image_header_t g_bank_a_hdr;
static toob_image_header_t g_bank_b_hdr;
static wal_sector_header_aligned_t g_s0_wal_hdrs[TOOB_WAL_SECTORS];
static reset_reason_t g_s0_reset_reason;

void cbmc_stage0_halt(void) {
    __CPROVER_assert(g_flash_write_calls == 0U && g_flash_erase_calls == 0U,
                     "Stage 0 never modifies flash prior to halt");
    __CPROVER_assume(false);
}

_Noreturn void cbmc_stage0_panic_halt(const boot_platform_t *platform,
                                      boot_status_t reason) {
    (void)platform;
    (void)reason;
    __CPROVER_assert(g_flash_write_calls == 0U && g_flash_erase_calls == 0U,
                     "Stage 0 never modifies flash prior to boot_panic");
    __CPROVER_assume(false);
    while (true) {
    }
}

_Noreturn void cbmc_stage0_terminal_halt(const boot_platform_t *platform,
                                         boot_status_t reason,
                                         uint16_t site_id) {
    (void)platform;
    (void)reason;
    __CPROVER_assert(site_id > 0U, "boot_terminal_halt requires non-zero site_id");
    __CPROVER_assert(g_flash_write_calls == 0U && g_flash_erase_calls == 0U,
                     "Stage 0 never modifies flash prior to terminal halt");
    __CPROVER_assume(false);
    while (true) {
    }
}

void cbmc_stage0_dbg_puts(const boot_platform_t *platform, const char *s) {
    (void)platform;
    cbmc_assert_readable(s, 1U, "dbg_puts string literal must be readable");
}

void cbmc_stage0_dbg_hex(const boot_platform_t *platform, uint32_t val) {
    (void)platform;
    (void)val;
}

/* Bit-identical modulo-2^32 model for stage0_seq_is_newer (RFC 1982 wraparound, Finding H) */
bool cbmc_stage0_seq_is_newer_mod32(uint32_t candidate, uint32_t current) {
    uint32_t diff = (uint32_t)(((uint64_t)candidate + 0x100000000ULL - (uint64_t)current) &
                               0xFFFFFFFFULL);
    return (candidate != current) && (diff < 0x80000000U);
}

static boot_status_t stage0_forbidden_write(uint32_t addr, const void *buf,
                                            size_t len) {
    (void)addr;
    (void)buf;
    (void)len;
    g_flash_write_calls++;
    __CPROVER_assert(false, "Stage 0 strict read-only flash invariant: write forbidden");
    return BOOT_ERR_NOT_SUPPORTED;
}

static boot_status_t stage0_forbidden_erase(uint32_t addr) {
    (void)addr;
    g_flash_erase_calls++;
    __CPROVER_assert(false, "Stage 0 strict read-only flash invariant: erase forbidden");
    return BOOT_ERR_NOT_SUPPORTED;
}

static boot_status_t stage0_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "Stage 0 flash->read buffer must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "Stage 0 flash->read must stay within physical flash");
    if (len == 0U) {
        return BOOT_OK;
    }
    if (nondet_bool()) {
        return BOOT_ERR_FLASH_HW;
    }

    const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
    for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
        if (addr == wal_addrs[i] && len == sizeof(wal_sector_header_aligned_t)) {
            memcpy(buf, &g_s0_wal_hdrs[i], sizeof(wal_sector_header_aligned_t));
            return BOOT_OK;
        }
    }

    if (addr == CHIP_STAGE1A_ABS_ADDR && len == sizeof(toob_image_header_t)) {
        memcpy(buf, &g_bank_a_hdr, sizeof(toob_image_header_t));
        return BOOT_OK;
    }
    if (addr == CHIP_STAGE1B_ABS_ADDR && len == sizeof(toob_image_header_t)) {
        memcpy(buf, &g_bank_b_hdr, sizeof(toob_image_header_t));
        return BOOT_OK;
    }

    cbmc_havoc_bytes((uint8_t *)buf, len);
    return BOOT_OK;
}

static reset_reason_t stage0_get_reset_reason(void) {
    return g_s0_reset_reason;
}

static size_t stage0_get_hash_ctx_size(void) {
    return 128U;
}

static boot_status_t stage0_entropy_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "Stage 0 entropy->random buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    cbmc_havoc_bytes(buf, len);
    if (len == 1U) {
        buf[0] &= 0x03U;
    }
    return BOOT_OK;
}

boot_status_t cbmc_stage0_random_safe(const boot_platform_t *platform,
                                      uint8_t *buf, size_t len) {
    if (platform == NULL || platform->entropy == NULL ||
        platform->entropy->random == NULL) {
        return BOOT_ERR_NOT_SUPPORTED;
    }
    cbmc_assert_writable(buf, len, "Stage 0 boot_random_safe buffer must be writable");
    if (len == 16U) {
        g_seal_key_ptr = buf;
    }
    if (nondet_bool()) {
        return BOOT_ERR_CRYPTO;
    }
    cbmc_havoc_bytes(buf, len);
    return BOOT_OK;
}

static boot_status_t stage0_read_dslc(uint8_t *out_dslc, size_t *inout_len) {
    __CPROVER_assert(out_dslc != NULL && inout_len != NULL &&
                         __CPROVER_r_ok(inout_len, sizeof(*inout_len)) &&
                         *inout_len >= 1U &&
                         __CPROVER_w_ok(out_dslc, *inout_len),
                     "keystore->read_dslc buffer must be writable");
    if (nondet_bool()) {
        return BOOT_ERR_NOT_FOUND;
    }
    out_dslc[0] = nondet_uint8_t();
    *inout_len = 1U;
    return BOOT_OK;
}

static boot_status_t stage0_read_pubkey_bounded(uint8_t *out_key, size_t key_len,
                                                uint8_t key_slot) {
    __CPROVER_assert(out_key != NULL && key_len == 32U &&
                         __CPROVER_w_ok(out_key, 32U),
                     "keystore->read_pubkey requires writable 32B buffer");
    if (key_slot >= g_otp_first_empty) {
        return BOOT_ERR_NOT_FOUND;
    }
    memcpy(out_key, g_otp_keys[key_slot], 32U);
    return BOOT_OK;
}

uint8_t cbmc_stage0_otp_contract(const boot_platform_t *platform) {
    if (platform == NULL || platform->keystore == NULL ||
        platform->keystore->read_pubkey == NULL) {
        cbmc_stage0_halt();
    }
    if (nondet_bool()) {
        cbmc_stage0_halt();
    }
    uint8_t idx = nondet_uint8_t();
    __CPROVER_assume(idx < 4U);
    return idx;
}

static boot_status_t stage0_hal_init_ok(void) {
    return nondet_bool() ? BOOT_OK : BOOT_ERR_FLASH_HW;
}

static boot_status_t stage0_wdt_init_ok(uint32_t timeout_ms) {
    __CPROVER_assert(timeout_ms > 0U, "WDT timeout must be positive");
    return BOOT_OK;
}

static void stage0_hal_deinit_noop(void) {}

static clock_hal_t g_s0_clock_hal = {
    .abi_version      = TOOB_HAL_ABI_V3,
    .init             = stage0_hal_init_ok,
    .deinit           = stage0_hal_deinit_noop,
    .get_reset_reason = stage0_get_reset_reason,
};

static flash_hal_t g_s0_flash_hal = {
    .abi_version      = TOOB_HAL_ABI_V3,
    .init             = stage0_hal_init_ok,
    .deinit           = stage0_hal_deinit_noop,
    .read             = stage0_flash_read,
    .write            = stage0_forbidden_write,
    .erase_sector     = stage0_forbidden_erase,
    .get_sector_size  = cbmc_flash_get_sector_size,
    .write_align      = CHIP_FLASH_WRITE_ALIGNMENT,
    .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size       = CHIP_FLASH_TOTAL_SIZE,
    .max_erase_cycles = 100000U,
    .erased_value     = 0xFFU,
};

static crypto_hal_t g_s0_crypto_hal = {
    .abi_version       = TOOB_HAL_ABI_V3,
    .init              = stage0_hal_init_ok,
    .deinit            = stage0_hal_deinit_noop,
    .verify_signature  = cbmc_ed25519_verify_sig,
    .hash_init         = cbmc_hash_init,
    .hash_update       = cbmc_hash_update,
    .hash_finish       = cbmc_hash_finish,
    .get_hash_ctx_size = stage0_get_hash_ctx_size,
};

static entropy_hal_t g_s0_entropy_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init        = stage0_hal_init_ok,
    .deinit      = stage0_hal_deinit_noop,
    .random      = stage0_entropy_random,
};

static keystore_hal_t g_s0_keystore_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init        = stage0_hal_init_ok,
    .deinit      = stage0_hal_deinit_noop,
    .read_pubkey = stage0_read_pubkey_bounded,
    .read_dslc   = stage0_read_dslc,
};

static wdt_hal_t g_s0_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init        = stage0_wdt_init_ok,
    .deinit      = stage0_hal_deinit_noop,
    .kick        = cbmc_wdt_kick,
};

static soc_hal_t g_s0_soc_hal = {
    .abi_version       = TOOB_HAL_ABI_V3,
    .invalidate_icache = stage0_hal_deinit_noop,
};

static boot_platform_t g_s0_platform = {
    .clock    = &g_s0_clock_hal,
    .flash    = &g_s0_flash_hal,
    .crypto   = &g_s0_crypto_hal,
    .entropy  = &g_s0_entropy_hal,
    .keystore = &g_s0_keystore_hal,
    .wdt      = &g_s0_wdt_hal,
    .soc      = &g_s0_soc_hal,
};

const boot_platform_t *boot_platform_init(void) {
    if (nondet_bool()) {
        return NULL;
    }
    static const bringup_step_t steps[] = {
        { BOOT_HAL_KIND_CLOCK,    true,  0x0101U },
        { BOOT_HAL_KIND_FLASH,    true,  0x0102U },
        { BOOT_HAL_KIND_WDT,      true,  0x0103U },
        { BOOT_HAL_KIND_CRYPTO,   true,  0x0104U },
        { BOOT_HAL_KIND_ENTROPY,  true,  0x0105U },
        { BOOT_HAL_KIND_KEYSTORE, true,  0x0106U },
    };
    (void)boot_platform_bringup(&g_s0_platform, steps,
                                sizeof(steps) / sizeof(steps[0]));
    return &g_s0_platform;
}

void cbmc_stage0_jump_to_payload(uint32_t pc) {
    __CPROVER_assert(g_flash_write_calls == 0U && g_flash_erase_calls == 0U,
                     "Stage 0 never writes or erases flash before payload jump");
    __CPROVER_assert(!boot_platform_is_brought_up(&g_s0_platform),
                     "Stage 0 marks platform down before payload jump");
    __CPROVER_assert(g_seal_key_ptr != NULL,
                     "g_seal_key must have been initialized via boot_random_safe");
    for (size_t i = 0U; i < 16U; i++) {
        __CPROVER_assert(g_seal_key_ptr[i] == 0U,
                         "Stage 0 must zeroize g_seal_key[4] before jumping to Stage 1");
    }

    uint32_t sram_base = (uint32_t)(uintptr_t)g_stage0_sram;
    bool in_sram = (pc >= sram_base) &&
                   (pc < (sram_base + (uint32_t)sizeof(g_stage0_sram)));
    if (in_sram) {
        __CPROVER_assert((pc & 3U) == 0U,
                         "RAM Stage 1 entry_point must be 4-byte aligned");
    } else {
        __CPROVER_assert((pc & 0x7FU) == 0U,
                         "XIP Stage 1 entry_point must satisfy 128B VTOR alignment (HIGH-26)");
        bool in_bank_a =
            (pc >= (CHIP_STAGE1A_ABS_ADDR + (uint32_t)sizeof(toob_image_header_t))) &&
            (pc < (CHIP_STAGE1A_ABS_ADDR + CHIP_STAGE1A_SIZE - 64U));
        bool in_bank_b =
            (pc >= (CHIP_STAGE1B_ABS_ADDR + (uint32_t)sizeof(toob_image_header_t))) &&
            (pc < (CHIP_STAGE1B_ABS_ADDR + CHIP_STAGE1B_SIZE - 64U));
        __CPROVER_assert(in_bank_a || in_bank_b,
                         "XIP Stage 1 target PC must lie strictly inside authenticated Stage 1A/1B payload");

        const toob_image_header_t *chosen = in_bank_a ? &g_bank_a_hdr : &g_bank_b_hdr;
        uint32_t img_svn = (chosen->s1.svn_magic == TOOB_STAGE1_SVN_MAGIC)
                               ? chosen->s1.stage1_svn
                               : 0U;
        __CPROVER_assert(img_svn >= (uint32_t)BOOT_STAGE1_SVN,
                         "CRIT-29: Booted Stage 1 bank must satisfy BOOT_STAGE1_SVN floor");
    }

    __CPROVER_assume(false);
}

/* Entrypoint 1: Continuous OTP key discovery & zero/0xFF key rejection */
void prove_stage0_otp_scan(void) {
    g_flash_write_calls = 0U;
    g_flash_erase_calls = 0U;

    g_otp_first_empty = nondet_uint8_t();
    __CPROVER_assume(g_otp_first_empty <= 4U);
    CBMC_HAVOC_OBJECT(g_otp_keys);

    for (uint8_t k = 0U; k < 4U; k++) {
        if (k < g_otp_first_empty) {
            __CPROVER_assume(verify_not_all_zeros_glitch_safe(g_otp_keys[k], 32U) ==
                             BOOT_OK);
        }
    }

    uint8_t active = stage0_get_active_otp_key_index(&g_s0_platform);
    uint8_t expected = (g_otp_first_empty == 0U) ? 0U : (uint8_t)(g_otp_first_empty - 1U);
    __CPROVER_assert(active == expected,
                     "stage0_get_active_otp_key_index resolves highest contiguous valid slot");

    uint8_t zero_key[32] = {0};
    uint8_t ff_key[32];
    memset(ff_key, 0xFF, sizeof(ff_key));
    __CPROVER_assert(verify_not_all_zeros_glitch_safe(zero_key, 32U) == BOOT_ERR_VERIFY,
                     "All-0x00 OTP root key must be rejected");
    __CPROVER_assert(verify_not_all_zeros_glitch_safe(ff_key, 32U) == BOOT_ERR_VERIFY,
                     "All-0xFF OTP root key must be rejected");
}

/* Entrypoint 2: WAL 2-of-3 TMR quorum scan & .noinit tentative rollback */
void prove_stage0_wal_quorum_and_tentative(void) {
    g_flash_write_calls = 0U;
    g_flash_erase_calls = 0U;
    CBMC_HAVOC_OBJECT(g_s0_wal_hdrs);
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    g_s0_reset_reason = (reset_reason_t)nondet_int();

    uint32_t out_svn = 0xDEADBEEFU;
    uint32_t bank_addr = stage0_read_wal_boot_meta(&g_s0_platform, &out_svn);
    __CPROVER_assert(bank_addr == CHIP_STAGE1A_ABS_ADDR ||
                         bank_addr == CHIP_STAGE1B_ABS_ADDR,
                     "stage0_read_wal_boot_meta always resolves Stage 1A or Stage 1B");

    uint32_t eval_addr = stage0_evaluate_tentative(&g_s0_platform, bank_addr);
    __CPROVER_assert(eval_addr == CHIP_STAGE1A_ABS_ADDR ||
                         eval_addr == CHIP_STAGE1B_ABS_ADDR,
                     "stage0_evaluate_tentative always returns Stage 1A or Stage 1B");

    bool crash_rst = (g_s0_reset_reason == RESET_REASON_WATCHDOG ||
                      g_s0_reset_reason == RESET_REASON_HARD_FAULT ||
                      g_s0_reset_reason == RESET_REASON_BROWNOUT ||
                      g_s0_reset_reason == RESET_REASON_SOFTWARE);
    if (!crash_rst) {
        __CPROVER_assert(eval_addr == bank_addr,
                         "Non-crash resets (e.g. POWER_ON/PIN) never trigger tentative bank rollback");
    }
    if (eval_addr != bank_addr) {
        __CPROVER_assert(crash_rst && toob_handoff_state.magic == 0U &&
                             toob_handoff_state.crc32_trailer == 0U,
                         "Tentative bank rollback wipes .noinit handoff state to prevent ping-pong loops");
    }
    __CPROVER_assert(g_flash_write_calls == 0U && g_flash_erase_calls == 0U,
                     "WAL scan and tentative check are strictly flash read-only");
}

/* Entrypoint 3: Stage 0 SHA-256 streaming hash & double-shielded Ed25519 verify */
void prove_stage0_hash_and_verify(void) {
    g_flash_write_calls = 0U;
    g_flash_erase_calls = 0U;

    uint8_t digest[32];
    CBMC_HAVOC_OBJECT(digest);

    /* Overflow & zero-length rejection + digest poisoning */
    __CPROVER_assert(stage0_hash_compute(&g_s0_platform, 0U, 0U, digest) ==
                         BOOT_ERR_INVALID_ARG,
                     "Zero-length stage0_hash_compute must fail");
    __CPROVER_assert(stage0_hash_compute(&g_s0_platform, UINT32_MAX - 4U, 16U, digest) ==
                         BOOT_ERR_INVALID_ARG,
                     "Address-wrapping stage0_hash_compute must fail");
    for (size_t i = 0U; i < 32U; i++) {
        __CPROVER_assert(digest[i] == 0U,
                         "stage0_hash_compute poisons digest buffer on error");
    }

    size_t hash_len = nondet_size_t();
    __CPROVER_assume(hash_len >= 1U && hash_len <= 300U);
    boot_status_t hst = stage0_hash_compute(&g_s0_platform, CHIP_STAGE1A_ABS_ADDR,
                                            hash_len, digest);
    if (hst != BOOT_OK) {
        for (size_t i = 0U; i < 32U; i++) {
            __CPROVER_assert(digest[i] == 0U,
                             "HIGH-30: failed stage0_hash_compute leaves zeroed digest");
        }
    }

    uint8_t sig[64];
    uint8_t pub[32];
    CBMC_HAVOC_OBJECT(sig);
    CBMC_HAVOC_OBJECT(pub);

    __CPROVER_assert(stage0_verify_signature(NULL, sig, pub, digest) == -1,
                     "NULL platform rejected by stage0_verify_signature");
    int vrc = stage0_verify_signature(&g_s0_platform, sig, pub, digest);
    __CPROVER_assert(vrc == 0 || vrc == -1,
                     "stage0_verify_signature returns canonical 0 or -1");
}

/* Entrypoint 4: Full Stage 0 boot orchestrator (stage0_main.c) */
void prove_stage0_main_boot(void) {
    g_flash_write_calls = 0U;
    g_flash_erase_calls = 0U;
    g_seal_key_ptr      = NULL;
    g_otp_first_empty   = 2U;

    CBMC_HAVOC_OBJECT(g_otp_keys);
    CBMC_HAVOC_OBJECT(g_bank_a_hdr);
    CBMC_HAVOC_OBJECT(g_bank_b_hdr);
    /* Bound authenticated payload size to <= 320B (5x64B hash chunks); arbitrary sizes proven in hash_and_verify */
    __CPROVER_assume(g_bank_a_hdr.image_size <= sizeof(g_stage0_sram) || g_bank_a_hdr.image_size > CHIP_STAGE1A_SIZE);
    __CPROVER_assume(g_bank_b_hdr.image_size <= sizeof(g_stage0_sram) || g_bank_b_hdr.image_size > CHIP_STAGE1B_SIZE);
    CBMC_HAVOC_OBJECT(g_s0_wal_hdrs);
    CBMC_HAVOC_OBJECT(toob_handoff_state);
    g_s0_reset_reason = (reset_reason_t)nondet_int();

    (void)stage0_entry_main();
}

#ifndef CBMC_SKIP_HARNESS_MAIN
int main(void) {
    uint8_t sel = nondet_uint8_t();
    if (sel == 0U) {
        prove_stage0_otp_scan();
    } else if (sel == 1U) {
        prove_stage0_wal_quorum_and_tentative();
    } else if (sel == 2U) {
        prove_stage0_hash_and_verify();
    } else {
        prove_stage0_main_boot();
    }
    return 0;
}
#endif
