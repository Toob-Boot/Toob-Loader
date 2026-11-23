#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOOB_MOCK_TEST 1

#include "../../toobloader/core/boot_state.c"
#include "../../toobloader/core/utils/boot_crc32.c"
#include "../../toobloader/core/utils/boot_delay.c"
#include "../../toobloader/core/utils/boot_diag.c"
#include "../../toobloader/core/utils/boot_energy.c"
#include "../../toobloader/core/utils/boot_identity.c"
#include "../../toobloader/core/utils/boot_secure_zeroize_host.c"
#include "../../toobloader/core/boot_effect.c"
#include "../../toobloader/core/boot_journal.c"
#include "../../toobloader/core/boot_tbm1.c"

/* External software SHA-256 package from toob_crypto */
#include "crypto_sha256.h"

/* Minimal stubs for unused boot_state_run sub-modules in TOOB_MOCK_TEST mode */
_Noreturn void boot_panic(const boot_platform_t *p, boot_status_t r) {
    (void)p;
    fprintf(stderr, "Unexpected boot_panic(0x%08X)\n", (unsigned)r);
    abort();
}
_Noreturn void boot_terminal_halt(const boot_platform_t *p, boot_status_t r, uint16_t s) {
    (void)p;
    fprintf(stderr, "Unexpected boot_terminal_halt(0x%08X, %u)\n", (unsigned)r, (unsigned)s);
    abort();
}
boot_status_t boot_cloud_cmd_evaluate_flash(const boot_platform_t *p, uint8_t *a, toob_cloud_cmd_t *c) {
    (void)p; (void)a; (void)c; return BOOT_ERR_NOT_FOUND;
}
boot_status_t boot_mailbox_consume(const boot_platform_t *p) { (void)p; return BOOT_OK; }
boot_status_t boot_verify_manifest_envelope(const boot_platform_t *p, const boot_verify_envelope_t *e, uint8_t *w, size_t l) {
    (void)p; (void)e; (void)w; (void)l; return BOOT_OK;
}
boot_status_t boot_verify_slot_image(const boot_platform_t *p, uint32_t sa, uint32_t ss, const toob_image_header_t *h, uint8_t *a, size_t al) {
    (void)p; (void)sa; (void)ss; (void)h; (void)a; (void)al; return BOOT_OK;
}
boot_status_t boot_rollback_verify_svn(const boot_platform_t *p, uint32_t s, rollback_target_t t) {
    (void)p; (void)s; (void)t; return BOOT_OK;
}
boot_status_t boot_rollback_evaluate_os(const boot_platform_t *p, const wal_tmr_payload_t *t, bool *r) {
    (void)p; (void)t; if (r) *r = false; return BOOT_OK;
}
boot_status_t boot_decomp_apply(const boot_platform_t *p, uint32_t sa, size_t ss, uint32_t da, size_t dm, uint32_t ei, wal_entry_payload_t *o, uint8_t *a, size_t al) {
    (void)p; (void)sa; (void)ss; (void)da; (void)dm; (void)ei; (void)o; (void)a; (void)al; return BOOT_OK;
}
boot_status_t boot_delta_apply(const boot_platform_t *p, uint32_t pa, size_t ps, uint32_t da, size_t dm, uint32_t ba, size_t bm, wal_entry_payload_t *o, uint8_t *a, size_t al) {
    (void)p; (void)pa; (void)ps; (void)da; (void)dm; (void)ba; (void)bm; (void)o; (void)a; (void)al; return BOOT_OK;
}
boot_status_t boot_merkle_verify_stream(const boot_platform_t *p, uint32_t fa, uint32_t tl, uint32_t cs, const uint8_t *eh, uint32_t hl, uint32_t nc, uint8_t *s, size_t ss) {
    (void)p; (void)fa; (void)tl; (void)cs; (void)eh; (void)hl; (void)nc; (void)s; (void)ss; return BOOT_OK;
}
boot_status_t boot_multiimage_apply(const boot_platform_t *p, uint32_t sb, const boot_component_t *c, uint32_t n, const boot_allowed_region_t *w, uint32_t wc, wal_entry_payload_t *o, uint8_t *a, size_t al) {
    (void)p; (void)sb; (void)c; (void)n; (void)w; (void)wc; (void)o; (void)a; (void)al; return BOOT_OK;
}
boot_status_t boot_swap_erase_safe(const boot_platform_t *p, uint32_t a, size_t l, uint8_t *ar, size_t al) {
    (void)p; (void)a; (void)l; (void)ar; (void)al; return BOOT_OK;
}
const slot_caps_t *boot_get_slot_caps(void) { return NULL; }
const slot_transport_t *boot_transport_active(void) { return NULL; }
const slot_transport_t *boot_transport_by_id(uint8_t id) { (void)id; return NULL; }
boot_status_t boot_transport_resolve_active(const boot_platform_t *p, uint8_t *s, uint32_t *a) {
    (void)p; if (s) *s = 0U; if (a) *a = CHIP_APP_SLOT_ABS_ADDR; return BOOT_OK;
}
boot_status_t boot_transport_reassert(const boot_platform_t *p, uint8_t s) { (void)p; (void)s; return BOOT_OK; }

/* ============================================================================
 * Self-Contained 4 MB NOR Flash + Crypto/WDT Mock for Host Verification
 * ============================================================================ */

static uint8_t s_flash_mem[CHIP_FLASH_TOTAL_SIZE];
static uint32_t s_supply_mv = 3300U;
static uint32_t s_otp_epoch = 0U;
static uint8_t s_dslc_state = 0x00U;

static void mock_flash_reset(void) {
    memset(s_flash_mem, 0xFF, sizeof(s_flash_mem));
    s_supply_mv = 3300U;
    s_otp_epoch = 0U;
    s_dslc_state = 0x00U;
    wal_initialized = false;
    tmr_defer_enabled = false;
    tmr_dirty = false;
    journal_key_valid = false;
}

static void mock_flash_set_supply_mv(uint32_t mv) {
    s_supply_mv = mv;
}

static boot_status_t mock_flash_init(void) { return BOOT_OK; }
static void mock_flash_deinit(void) {}

static boot_status_t mock_flash_read(uint32_t addr, void *buf, size_t len) {
    if (!buf || addr > sizeof(s_flash_mem) || len > sizeof(s_flash_mem) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    memcpy(buf, &s_flash_mem[addr], len);
    return BOOT_OK;
}

static boot_status_t mock_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (!buf || addr > sizeof(s_flash_mem) || len > sizeof(s_flash_mem) - addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        /* NOR flash semantics: 1->0 bit transitions only without erase */
        if ((~s_flash_mem[addr + i] & src[i]) != 0U) {
            return BOOT_ERR_FLASH_HW;
        }
        s_flash_mem[addr + i] &= src[i];
    }
    return BOOT_OK;
}

static boot_status_t mock_flash_erase_sector(uint32_t addr) {
    if ((addr % 4096U) != 0U || addr + 4096U > sizeof(s_flash_mem)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    memset(&s_flash_mem[addr], 0xFF, 4096U);
    return BOOT_OK;
}

static boot_status_t mock_flash_get_sector_size(uint32_t addr, size_t *size_out) {
    if (!size_out || addr >= sizeof(s_flash_mem)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    *size_out = 4096U;
    return BOOT_OK;
}

static boot_status_t mock_flash_get_supply_mv(uint32_t *mv_out) {
    if (!mv_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    *mv_out = s_supply_mv;
    return BOOT_OK;
}

static const flash_hal_t s_mock_flash_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .max_sector_size = 4096U,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = 0xFFU,
    .max_erase_cycles = 100000U,
    .erase_time_us_max = 45000U,
    .write_time_us_page = 50U,
    .get_supply_mv = mock_flash_get_supply_mv,
    .init = mock_flash_init,
    .deinit = mock_flash_deinit,
    .read = mock_flash_read,
    .write = mock_flash_write,
    .erase_sector = mock_flash_erase_sector,
    .get_sector_size = mock_flash_get_sector_size,
    .set_otfdec_mode = NULL,
};

static boot_status_t mock_wdt_init(uint32_t timeout_ms) { (void)timeout_ms; return BOOT_OK; }
static void mock_wdt_deinit(void) {}
static void mock_wdt_kick(void) {}

static const wdt_hal_t s_mock_wdt_hal = {
    .abi_version = TOOB_HAL_ABI_V2,
    .init = mock_wdt_init,
    .deinit = mock_wdt_deinit,
    .kick = mock_wdt_kick,
};

static boot_status_t mock_read_chip_uid(uint8_t *uid_out, size_t max_len, size_t *actual_len) {
    static const uint8_t k_uid[16] = {
        0x10U, 0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U,
        0x98U, 0xA9U, 0xBAU, 0xCBU, 0xDCU, 0xEDU, 0xFEU, 0x0FU
    };
    if (!uid_out || !actual_len || max_len < sizeof(k_uid)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(uid_out, k_uid, sizeof(k_uid));
    *actual_len = sizeof(k_uid);
    return BOOT_OK;
}

static boot_status_t mock_read_pubkey(uint8_t *pubkey_out, size_t buf_len, uint8_t key_index) {
    if (!pubkey_out || buf_len < 32U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (key_index > 1U) {
        return BOOT_ERR_NOT_FOUND;
    }
    for (size_t i = 0; i < 32U; i++) {
        pubkey_out[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 7U + key_index));
    }
    return BOOT_OK;
}

static boot_status_t mock_read_device_secret(uint8_t *secret_out, size_t max_len, size_t *actual_len) {
    static const uint8_t k_huk[32] = {
        0x71U, 0x62U, 0x53U, 0x44U, 0x35U, 0x26U, 0x17U, 0x08U,
        0x81U, 0x72U, 0x63U, 0x54U, 0x45U, 0x36U, 0x27U, 0x18U,
        0x91U, 0x82U, 0x73U, 0x64U, 0x55U, 0x46U, 0x37U, 0x28U,
        0xA1U, 0x92U, 0x83U, 0x74U, 0x65U, 0x56U, 0x47U, 0x38U
    };
    if (!secret_out || !actual_len || max_len < sizeof(k_huk)) {
        return BOOT_ERR_INVALID_ARG;
    }
    memcpy(secret_out, k_huk, sizeof(k_huk));
    *actual_len = sizeof(k_huk);
    return BOOT_OK;
}

static boot_status_t mock_read_monotonic_counter(uint32_t *counter_out) {
    if (!counter_out) {
        return BOOT_ERR_INVALID_ARG;
    }
    *counter_out = s_otp_epoch;
    return BOOT_OK;
}

static boot_status_t mock_crypto_init(void) { return BOOT_OK; }
static void mock_crypto_deinit(void) {}

static boot_status_t mock_random(uint8_t *buf, size_t len) {
    if (!buf && len > 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    for (size_t i = 0U; i < len; i++) {
        buf[i] = (uint8_t)(0x5AU ^ (uint8_t)(i * 13U));
    }
    return BOOT_OK;
}

static boot_status_t mock_read_dslc(uint8_t *buffer, size_t *len) {
    if (!buffer || !len || *len < 1U) {
        return BOOT_ERR_INVALID_ARG;
    }
    buffer[0] = s_dslc_state;
    *len = 1U;
    return BOOT_OK;
}

static boot_status_t mock_write_dslc(const uint8_t *value, size_t len) {
    if (!value || len < 1U) {
        return BOOT_ERR_INVALID_ARG;
    }
    s_dslc_state = value[0];
    return BOOT_OK;
}

static const crypto_hal_t s_mock_crypto_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init = mock_crypto_init,
    .deinit = mock_crypto_deinit,
    .hash_init = crypto_sha256_init,
    .hash_update = crypto_sha256_update,
    .hash_finish = crypto_sha256_finish,
    .get_hash_ctx_size = crypto_sha256_get_ctx_size,
};

static const entropy_hal_t s_mock_entropy_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init = mock_crypto_init,
    .deinit = mock_crypto_deinit,
    .random = mock_random,
    .is_hardware_trng = false,
};

static const keystore_hal_t s_mock_keystore_hal = {
    .abi_version = TOOB_HAL_ABI_V3,
    .init = mock_crypto_init,
    .deinit = mock_crypto_deinit,
    .read_chip_uid = mock_read_chip_uid,
    .read_pubkey = mock_read_pubkey,
    .read_dslc = mock_read_dslc,
    .write_dslc = mock_write_dslc,
    .read_monotonic_counter = mock_read_monotonic_counter,
    .read_device_secret = mock_read_device_secret,
};

static const boot_platform_t s_mock_platform = {
    .flash = &s_mock_flash_hal,
    .wdt = &s_mock_wdt_hal,
    .crypto = &s_mock_crypto_hal,
    .entropy = &s_mock_entropy_hal,
    .keystore = &s_mock_keystore_hal,
};

static const intent_row_t *find_transition(wal_intent_t cur, boot_event_t ev) {
    const intent_row_t *found = NULL;
    size_t matches = 0U;
    for (size_t t = 0; t < sizeof(INTENT_TABLE) / sizeof(INTENT_TABLE[0]); t++) {
        if (INTENT_TABLE[t].cur == cur && INTENT_TABLE[t].ev == ev) {
            found = &INTENT_TABLE[t];
            matches++;
        }
    }
    /* Determinism invariant: at most 1 row per (intent, event) pair */
    assert(matches <= 1U);
    return found;
}

void test_energy_admission(void);
void test_boot_proof(void);
void test_journal_chain(void);
void test_tbm1_layout(void);

int main(void) {
    printf("==================================================\n");
    printf("   Toob-Boot K6-T4 Intent Totality Verification\n");
    printf("==================================================\n\n");

    wal_intent_t intents[] = {
        WAL_INTENT_NONE,
        WAL_INTENT_TXN_BEGIN,
        WAL_INTENT_UPDATE_PENDING,
        WAL_INTENT_TXN_COMMIT,
        WAL_INTENT_CONFIRM_COMMIT,
        WAL_INTENT_RECOVERY_RESOLVED,
        WAL_INTENT_TXN_ROLLBACK,
        WAL_INTENT_TXN_ROLLBACK_PENDING,
        WAL_INTENT_DEVICE_LOCKED
    };
    size_t num_intents = sizeof(intents) / sizeof(intents[0]);

    boot_event_t events[] = {
        EV_NONE,
        EV_CONFIRM_OK,
        EV_CRASH,
        EV_CLOUD_UNLOCK,
        EV_CLOUD_LOCK,
        EV_CLOUD_UPDATE
    };
    size_t num_events = sizeof(events) / sizeof(events[0]);

    printf("[1] Checking transitions totality & determinism...\n");
    mock_flash_reset();
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);

    size_t covered_rows = 0U;
    for (size_t i = 0; i < num_intents; i++) {
        for (size_t e = 0; e < num_events; e++) {
            const intent_row_t *match = find_transition(intents[i], events[e]);
            if (match != NULL) {
                covered_rows++;
                printf("    Intent %u + Event %u -> Intent %u (Action %u)\n",
                       (unsigned)intents[i], (unsigned)events[e],
                       (unsigned)match->next, (unsigned)match->action);
            } else {
                /* Unlisted (intent, event) pairs must be total, side-effect-free no-ops */
                wal_entry_payload_t probe_txn;
                wal_tmr_payload_t probe_tmr;
                boot_target_config_t probe_cfg;
                uint8_t probe_arena[64];
                memset(&probe_txn, 0, sizeof(probe_txn));
                memset(&probe_tmr, 0, sizeof(probe_tmr));
                memset(&probe_cfg, 0, sizeof(probe_cfg));
                probe_txn.intent = (uint32_t)intents[i];

                boot_status_t st = evaluate_transition(
                    &s_mock_platform, &probe_txn, &probe_tmr, events[e],
                    &probe_cfg, probe_arena, sizeof(probe_arena));
                assert(st == BOOT_OK);
                assert(probe_txn.intent == (uint32_t)intents[i]);
            }
        }
    }
    /* Every row in INTENT_TABLE must belong to the verified (intents x events) domain */
    assert(covered_rows == (sizeof(INTENT_TABLE) / sizeof(INTENT_TABLE[0])));
    printf("    -> Totality & determinism verified across all %zu pairs (%zu explicit rows).\n",
           num_intents * num_events, covered_rows);

    printf("\n[2] Checking specific security invariants...\n");
    const intent_row_t *lock_confirm = find_transition(WAL_INTENT_DEVICE_LOCKED, EV_CONFIRM_OK);
    assert(lock_confirm != NULL);
    assert(lock_confirm->next == WAL_INTENT_DEVICE_LOCKED);
    assert(lock_confirm->action == ACT_PANIC_LOCKED);

    const intent_row_t *lock_unlock = find_transition(WAL_INTENT_DEVICE_LOCKED, EV_CLOUD_UNLOCK);
    assert(lock_unlock != NULL);
    assert(lock_unlock->next == WAL_INTENT_NONE);
    assert(lock_unlock->action == ACT_APPEND);

    /* CRIT-25: Both WAL_INTENT_TXN_COMMIT and WAL_INTENT_CONFIRM_COMMIT must heal on EV_CONFIRM_OK */
    const intent_row_t *txn_confirm = find_transition(WAL_INTENT_TXN_COMMIT, EV_CONFIRM_OK);
    assert(txn_confirm != NULL);
    assert(txn_confirm->next == WAL_INTENT_NONE);
    assert(txn_confirm->action == ACT_HEAL_COUNTER);

    const intent_row_t *mbx_confirm = find_transition(WAL_INTENT_CONFIRM_COMMIT, EV_CONFIRM_OK);
    assert(mbx_confirm != NULL);
    assert(mbx_confirm->next == WAL_INTENT_NONE);
    assert(mbx_confirm->action == ACT_HEAL_COUNTER);

    const intent_row_t *rec_confirm = find_transition(WAL_INTENT_RECOVERY_RESOLVED, EV_CONFIRM_OK);
    assert(rec_confirm != NULL);
    assert(rec_confirm->next == WAL_INTENT_NONE);
    assert(rec_confirm->action == ACT_HEAL_COUNTER);

    const intent_row_t *cloud_lock = find_transition(WAL_INTENT_NONE, EV_CLOUD_LOCK);
    assert(cloud_lock != NULL);
    assert(cloud_lock->next == WAL_INTENT_DEVICE_LOCKED);
    assert(cloud_lock->action == ACT_APPEND);

    const intent_row_t *cloud_upd = find_transition(WAL_INTENT_NONE, EV_CLOUD_UPDATE);
    assert(cloud_upd != NULL);
    assert(cloud_upd->next == WAL_INTENT_UPDATE_PENDING);
    assert(cloud_upd->action == ACT_APPEND);

    printf("    -> Sticky Lock, Cloud Unlock/Lock, and CRIT-25 Confirm Heal invariants passed.\n");

    /* K7-T4: Run Energy and Wear Admission tests */
    test_energy_admission();

    /* K1-T1: Run Boot Proof verification tests */
    test_boot_proof();

    /* K4-T2: Run Journal Chain & Cryptographic Tamper Verification tests */
    test_journal_chain();

    /* K2-T1: Run TBM1 Fixed-Format Manifest layout tests */
    test_tbm1_layout();

    printf("\n==================================================\n");
    printf("   INTENT TOTALITY CHECK PASSED SUCCESSFULLY!\n");
    printf("==================================================\n");
    return 0;
}

void test_energy_admission(void) {
    printf("\n[3] Checking energy and wear admission control (E-K7)...\n");

    wal_tmr_payload_t tmr;
    memset(&tmr, 0, sizeof(tmr));
    tmr.app_slot_erase_counter = 100U;
    tmr.staging_slot_erase_counter = 200U;
    tmr.swap_buffer_erase_counter = 50U;

    /* Base case: healthy voltage, low wear */
    mock_flash_set_supply_mv(3300U);
    boot_status_t stat = boot_effect_admit_or_defer(&s_mock_platform, &tmr, 65536U, NULL, 0U, true);
    assert(stat == BOOT_OK);
    printf("    -> Healthy voltage: BOOT_OK (passed)\n");

    /* Case: low voltage, high costs (should defer) */
    mock_flash_set_supply_mv(2500U);
    stat = boot_effect_admit_or_defer(&s_mock_platform, &tmr, 65536U, NULL, 0U, true);
    assert(stat == BOOT_ERR_DEFER);
    printf("    -> Low voltage (2500mV): BOOT_ERR_DEFER (passed)\n");

    /* Case: wear counter at limit */
    mock_flash_set_supply_mv(3300U);
    tmr.app_slot_erase_counter = 100000U; /* Limit is 100000 */
    stat = boot_effect_admit_or_defer(&s_mock_platform, &tmr, 4096U, NULL, 0U, true);
    assert(stat == BOOT_ERR_COUNTER_EXHAUSTED);
    printf("    -> App wear counter exhausted: BOOT_ERR_COUNTER_EXHAUSTED (passed)\n");

    mock_flash_set_supply_mv(3300U);
}

void test_boot_proof(void) {
    printf("\n[4] Checking proof-carrying boot handles (E-K1)...\n");

    uint32_t key[4] = {0xAA55AA55U, 0x12345678U, 0x9ABCDEF0U, 0xFEEDFACEU};
    uint32_t wrong_key[4] = {0xAA55AA55U, 0x12345678U, 0x9ABCDEF0U, 0xBADBEEF0U};

    boot_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    proof.image_addr = 0x10000U;
    proof.image_size = 0x20000U;
    proof.entry_point = 0x100U;
    proof.svn = 5U;

    boot_proof_seal(&proof, key);
    boot_status_t stat = boot_proof_verify(&proof, key);
    assert(stat == BOOT_OK);
    printf("    -> Valid proof: BOOT_OK (passed)\n");

    stat = boot_proof_verify(&proof, wrong_key);
    assert(stat == BOOT_ERR_VERIFY);
    printf("    -> Key mismatch: BOOT_ERR_VERIFY (passed)\n");

    proof.image_addr = 0x20000U;
    stat = boot_proof_verify(&proof, key);
    assert(stat == BOOT_ERR_VERIFY);
    printf("    -> Modified field: BOOT_ERR_VERIFY (passed)\n");
}

void test_journal_chain(void) {
    printf("\n[5] Checking journal chain & K4 cryptographic MAC mechanics (E-K4)...\n");

    /* 1. Security-bearing intent classification */
    assert(wal_intent_is_security_bearing(WAL_INTENT_DEVICE_LOCKED));
    assert(wal_intent_is_security_bearing(WAL_INTENT_CONFIRM_COMMIT));
    assert(wal_intent_is_security_bearing(WAL_INTENT_TXN_COMMIT));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_NONE));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_TXN_BEGIN));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_UPDATE_PENDING));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_RECOVERY_RESOLVED));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_TXN_ROLLBACK));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_NET_SEARCH_ACCUM));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_SLEEP_BACKOFF));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_TXN_ROLLBACK_PENDING));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_DOWNLOAD_CHECKPOINT));
    assert(!wal_intent_is_security_bearing(WAL_INTENT_CLOUD_CMD));
    printf("    -> Security-bearing intent classification verified (passed)\n");

    /* 2. ABI size invariants */
    assert(sizeof(wal_tmr_payload_t) == TMR_PAYLOAD_SLOT_BYTES);
    assert(sizeof(wal_sector_header_aligned_t) == 128U);
    assert(sizeof(wal_entry_payload_t) == 64U);
    printf("    -> ABI size invariants hold (passed)\n");

    /* 3. Real K4 cryptographic TMR MAC + security-bearing entry MAC verification */
    mock_flash_reset();
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);
    s_dslc_state = 0x01U;
    assert(journal_key_valid == true);

    wal_tmr_payload_t tmr;
    memset(&tmr, 0, sizeof(tmr));
    assert(boot_journal_get_tmr(&s_mock_platform, &tmr) == BOOT_OK);
    uint8_t zero_tag[WAL_CHAIN_TAG_BYTES] = {0};
    assert(tmr.chain_entry_count == 1U);
    assert(memcmp(tmr.chain_tag, zero_tag, WAL_CHAIN_TAG_BYTES) != 0);

    /* Update TMR and verify chain_entry_count advances and chain_tag rotates */
    uint8_t initial_tag[WAL_CHAIN_TAG_BYTES];
    memcpy(initial_tag, tmr.chain_tag, WAL_CHAIN_TAG_BYTES);
    tmr.app_svn = 2U;
    tmr.active_nonce_lo = 0x12345678U;
    tmr.active_nonce_hi = 0xCAFEBABEU;
    assert(boot_journal_update_tmr(&s_mock_platform, &tmr) == BOOT_OK);

    wal_tmr_payload_t sealed_tmr;
    assert(boot_journal_get_tmr(&s_mock_platform, &sealed_tmr) == BOOT_OK);
    assert(sealed_tmr.chain_entry_count == 2U);
    assert(memcmp(sealed_tmr.chain_tag, zero_tag, WAL_CHAIN_TAG_BYTES) != 0);
    assert(memcmp(sealed_tmr.chain_tag, initial_tag, WAL_CHAIN_TAG_BYTES) != 0);

    /* Append security-bearing entry (WAL_INTENT_CONFIRM_COMMIT) and reconstruct across reboot */
    wal_entry_payload_t confirm_entry;
    memset(&confirm_entry, 0, sizeof(confirm_entry));
    confirm_entry.intent = (uint32_t)WAL_INTENT_CONFIRM_COMMIT;
    confirm_entry.expected_nonce = 0xCAFEBABE12345678ULL;
    assert(boot_journal_append(&s_mock_platform, &confirm_entry) == BOOT_OK);

    /* Reboot simulation: re-run boot_journal_init + boot_journal_reconstruct_txn */
    wal_initialized = false;
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);
    wal_entry_payload_t rec_entry;
    memset(&rec_entry, 0, sizeof(rec_entry));
    assert(boot_journal_reconstruct_txn(&s_mock_platform, &rec_entry, NULL, NULL) == BOOT_OK);
    assert(rec_entry.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT);
    assert(rec_entry.expected_nonce == 0xCAFEBABE12345678ULL);
    printf("    -> Authenticated K4 TMR & entry MAC round-trip verified (passed)\n");

    /* 4. Tamper Test A: Offline SPI forgery of security-bearing WAL entry WITH valid CRC32 */
    uint32_t entry_flash_addr = wal_sector_addrs[active_wal_index] +
                                (uint32_t)sizeof(wal_sector_header_aligned_t);
    wal_entry_aligned_t forged_entry;
    memcpy(&forged_entry, &s_flash_mem[entry_flash_addr], sizeof(forged_entry));
    assert(forged_entry.data.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT);
    forged_entry.data.expected_nonce = 0xDEADBEEFULL; /* Attacker alters nonce */
    forged_entry.data.crc32_trailer = entry_crc(&forged_entry.data); /* Recomputes valid CRC32! */
    memcpy(&s_flash_mem[entry_flash_addr], &forged_entry, sizeof(forged_entry));

    wal_initialized = false;
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);
    assert(boot_journal_reconstruct_txn(&s_mock_platform, &rec_entry, NULL, NULL) == BOOT_ERR_VERIFY);
    printf("    -> Offline SPI WAL entry forgery (with valid CRC32) rejected with BOOT_ERR_VERIFY (passed)\n");

    /* 5. Tamper Test B: Offline SPI TMR quorum forgery WITH valid header CRC32 across all sectors */
    mock_flash_reset();
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);
    s_dslc_state = 0x01U;
    memset(&tmr, 0, sizeof(tmr));
    tmr.app_svn = 7U;
    assert(boot_journal_update_tmr(&s_mock_platform, &tmr) == BOOT_OK);

    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        wal_sector_header_aligned_t hdr;
        memcpy(&hdr, &s_flash_mem[wal_sector_addrs[i]], sizeof(hdr));
        if (hdr.data.sector_magic == WAL_ABI_VERSION_MAGIC_CURRENT) {
            hdr.data.tmr_data.app_svn = 1U; /* Attacker downgrades app_svn in all TMR copies */
            hdr.data.header_crc32 = sector_hdr_crc(&hdr.data);
            memcpy(&s_flash_mem[wal_sector_addrs[i]], &hdr, sizeof(hdr));
        }
    }
    wal_initialized = false;
    assert(boot_journal_init(&s_mock_platform) == BOOT_ERR_VERIFY);
    printf("    -> Offline SPI TMR quorum downgrade (with valid CRC32) rejected with BOOT_ERR_VERIFY (passed)\n");

    /* 6. Tamper Test C: Full flash image replay after >= 2 OTP monotonic counter burns */
    mock_flash_reset();
    assert(boot_journal_init(&s_mock_platform) == BOOT_OK);
    s_dslc_state = 0x01U;
    s_otp_epoch = 1U;
    memset(&tmr, 0, sizeof(tmr));
    tmr.app_svn = 3U;
    assert(boot_journal_update_tmr(&s_mock_platform, &tmr) == BOOT_OK);

    /* Hardware OTP advances by +2 while attacker replays old flash dump */
    s_otp_epoch = 3U;
    wal_initialized = false;
    assert(boot_journal_init(&s_mock_platform) == BOOT_ERR_VERIFY);
    printf("    -> Stale flash snapshot replay across OTP epoch advance rejected with BOOT_ERR_VERIFY (passed)\n");
}

void test_tbm1_layout(void) {
    printf("\n[6] Checking TBM1 fixed-format manifest layout (E-K2 v2)...\n");

    assert(sizeof(tbm1_image_desc_t) == 44U);
    assert(sizeof(tbm1_header_t) == 512U);
    printf("    -> Struct sizes: image_desc=44, header=512 (passed)\n");

    assert(offsetof(tbm1_header_t, magic) == 0U);
    assert(offsetof(tbm1_header_t, version_major) == 4U);
    assert(offsetof(tbm1_header_t, version_minor) == 5U);
    assert(offsetof(tbm1_header_t, fixed_len) == 6U);
    assert(offsetof(tbm1_header_t, total_len) == 8U);
    assert(offsetof(tbm1_header_t, flags_critical) == 12U);
    assert(offsetof(tbm1_header_t, flags_info) == 14U);
    assert(offsetof(tbm1_header_t, vendor_id) == 16U);
    assert(offsetof(tbm1_header_t, product_id) == 18U);
    assert(offsetof(tbm1_header_t, hw_rev_min) == 20U);
    assert(offsetof(tbm1_header_t, hw_rev_max) == 22U);
    assert(offsetof(tbm1_header_t, key_index) == 24U);
    assert(offsetof(tbm1_header_t, image_count) == 25U);
    assert(offsetof(tbm1_header_t, boot_retry_limit) == 26U);
    assert(offsetof(tbm1_header_t, min_reader_major) == 28U);
    assert(offsetof(tbm1_header_t, min_reader_minor) == 30U);
    assert(offsetof(tbm1_header_t, svn) == 32U);
    assert(offsetof(tbm1_header_t, stage1_svn) == 36U);
    assert(offsetof(tbm1_header_t, key_epoch) == 40U);
    assert(offsetof(tbm1_header_t, build_number) == 44U);
    assert(offsetof(tbm1_header_t, fw_ver_major) == 48U);
    assert(offsetof(tbm1_header_t, fw_ver_minor) == 50U);
    assert(offsetof(tbm1_header_t, fw_ver_patch) == 52U);
    assert(offsetof(tbm1_header_t, _rsvd0) == 54U);
    assert(offsetof(tbm1_header_t, sbom_digest) == 56U);
    assert(offsetof(tbm1_header_t, regions) == 88U);
    assert(offsetof(tbm1_header_t, images) == 184U);
    assert(offsetof(tbm1_header_t, _reserved_tail) == 360U);
    assert(offsetof(tbm1_header_t, fixed_crc32) == 508U);
    printf("    -> All header field offsets verified (passed)\n");

    assert(offsetof(tbm1_image_desc_t, image_type) == 0U);
    assert(offsetof(tbm1_image_desc_t, target_slot) == 1U);
    assert(offsetof(tbm1_image_desc_t, compression_alg) == 2U);
    assert(offsetof(tbm1_image_desc_t, delta_alg) == 3U);
    assert(offsetof(tbm1_image_desc_t, data_off) == 4U);
    assert(offsetof(tbm1_image_desc_t, stored_size) == 8U);
    assert(offsetof(tbm1_image_desc_t, installed_size) == 12U);
    assert(offsetof(tbm1_image_desc_t, chunk_size) == 16U);
    assert(offsetof(tbm1_image_desc_t, num_chunks) == 20U);
    assert(offsetof(tbm1_image_desc_t, base_svn) == 24U);
    assert(offsetof(tbm1_image_desc_t, ver_major) == 28U);
    assert(offsetof(tbm1_image_desc_t, ver_minor) == 30U);
    assert(offsetof(tbm1_image_desc_t, ver_patch) == 32U);
    assert(offsetof(tbm1_header_t, _rsvd0) == 54U);
    assert(offsetof(tbm1_image_desc_t, _rsvd) == 34U);
    assert(offsetof(tbm1_image_desc_t, base_fingerprint) == 36U);
    printf("    -> All image descriptor offsets verified (passed)\n");

    assert(offsetof(tbm1_region_t, region_id) == 0U);
    assert(offsetof(tbm1_region_t, _rsvd) == 2U);
    assert(offsetof(tbm1_region_t, off) == 4U);
    assert(offsetof(tbm1_region_t, len) == 8U);
    printf("    -> Region entry offsets verified (passed)\n");

    assert(TBM1_MAGIC == 0x314D4254U);
    assert(TBM1_CRIT_PQC_REQUIRED == 1U);
    assert(TBM1_INFO_DEVICE_BIND == 1U);

    tbm1_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
    hdr.regions[0].off = 512U;
    hdr.regions[0].len = 128U;
    hdr.regions[1].region_id = TBM1_REGION_DEVICE_BIND;
    hdr.regions[1].off = 640U;
    hdr.regions[1].len = 32U;

    const tbm1_region_t *r1 = tbm1_find_region(&hdr, TBM1_REGION_CHUNK_HASHES);
    assert(r1 != NULL && r1->off == 512U && r1->len == 128U);
    const tbm1_region_t *r2 = tbm1_find_region(&hdr, TBM1_REGION_DEVICE_BIND);
    assert(r2 != NULL && r2->off == 640U && r2->len == 32U);
    assert(tbm1_find_region(&hdr, 99U) == NULL);

    hdr.total_len = 1024U;
    assert(tbm1_signed_len(&hdr) == 960U);
    hdr.total_len = 100U;
    assert(tbm1_signed_len(&hdr) == 0U);
    hdr.total_len = 0U;
    assert(tbm1_signed_len(&hdr) == 0U);
    printf("    -> Region finder & signed length bounds verified (passed)\n");
}
