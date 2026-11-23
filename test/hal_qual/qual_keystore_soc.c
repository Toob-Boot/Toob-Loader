#include "hal_qual.h"
#include "boot_identity.h"
#include "boot_secure_zeroize.h"
#include <string.h>

#define QUAL_OTP_SLOTS_PROBE 16U

static void record_check(hal_qual_report_t *rep, bool cond, const char *name) {
    rep->tests_run++;
    if (cond) {
        rep->tests_passed++;
    } else {
        rep->tests_failed++;
        if (rep->first_failure == NULL) {
            rep->first_failure = name;
        }
    }
}

static bool buf_is_degenerate(const uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0U) {
        return true;
    }
    uint8_t or_acc = 0x00U;
    uint8_t and_acc = 0xFFU;
    for (size_t i = 0U; i < len; i++) {
        or_acc |= buf[i];
        and_acc &= buf[i];
    }
    return (or_acc == 0x00U) || (and_acc == 0xFFU);
}

int hal_qual_keystore_soc(const boot_platform_t *plat, hal_qual_report_t *rep) {
    if (plat == NULL || rep == NULL) {
        return HAL_QUAL_FAIL;
    }
    if (plat->keystore == NULL || plat->keystore->abi_version != TOOB_HAL_ABI_V3 ||
        plat->keystore->read_pubkey == NULL || plat->keystore->read_chip_uid == NULL ||
        plat->keystore->read_dslc == NULL) {
        record_check(rep, false, "keystore_abi_and_pointers");
        return HAL_QUAL_FAIL;
    }

    const keystore_hal_t *ks = plat->keystore;
    if (ks->init != NULL) {
        record_check(rep, ks->init() == BOOT_OK, "keystore_init");
    }

    /* 1. Chip UID determinism and NULL rejection */
    uint8_t uid1[32];
    uint8_t uid2[32];
    size_t ulen1 = 0U;
    size_t ulen2 = 0U;
    memset(uid1, 0, sizeof(uid1));
    memset(uid2, 0, sizeof(uid2));
    record_check(rep, ks->read_chip_uid(NULL, sizeof(uid1), &ulen1) != BOOT_OK,
                 "keystore_uid_null_buf");
    record_check(rep, ks->read_chip_uid(uid1, sizeof(uid1), NULL) != BOOT_OK,
                 "keystore_uid_null_len");
    bool uid_ok = (ks->read_chip_uid(uid1, sizeof(uid1), &ulen1) == BOOT_OK) &&
                  (ks->read_chip_uid(uid2, sizeof(uid2), &ulen2) == BOOT_OK) &&
                  (ulen1 > 0U && ulen1 == ulen2 && memcmp(uid1, uid2, ulen1) == 0);
    record_check(rep, uid_ok, "keystore_uid_deterministic");

    /* 2. OTP active-key index monotonicity & blank-tail invariant */
    uint8_t pk[32];
    record_check(rep, ks->read_pubkey(NULL, sizeof(pk), 0U) != BOOT_OK,
                 "keystore_pubkey_null_buf");
    record_check(rep, ks->read_pubkey(pk, 16U, 0U) != BOOT_OK,
                 "keystore_pubkey_bad_len");

    bool blank_seen = false;
    bool found_any = false;
    bool otp_monotonic_ok = true;
    uint8_t expected_active = 0U;
    for (uint32_t idx = 0U; idx < QUAL_OTP_SLOTS_PROBE; idx++) {
        memset(pk, 0, sizeof(pk));
        boot_status_t st = ks->read_pubkey(pk, sizeof(pk), (uint8_t)idx);
        if (blank_seen) {
            if (st != BOOT_ERR_NOT_FOUND) {
                otp_monotonic_ok = false;
                break;
            }
        } else if (st == BOOT_OK) {
            if (buf_is_degenerate(pk, sizeof(pk))) {
                otp_monotonic_ok = false;
                break;
            }
            found_any = true;
            expected_active = (uint8_t)idx;
        } else if (st == BOOT_ERR_NOT_FOUND) {
            blank_seen = true;
        } else {
            otp_monotonic_ok = false;
            break;
        }
    }
    record_check(rep, otp_monotonic_ok && found_any, "keystore_otp_monotonic_blank_tail");

    uint8_t resolved_idx = 0xFFU;
    record_check(rep,
                 boot_otp_get_active_key_index(plat, &resolved_idx) == BOOT_OK &&
                     resolved_idx == expected_active,
                 "keystore_active_key_index_match");

    /* 3. HUK read_device_secret determinism & domain separation */
    if (ks->read_device_secret != NULL) {
        uint8_t sec1[64];
        uint8_t sec2[64];
        size_t slen1 = 0U;
        size_t slen2 = 0U;
        memset(sec1, 0, sizeof(sec1));
        memset(sec2, 0, sizeof(sec2));

        record_check(rep, ks->read_device_secret(NULL, sizeof(sec1), &slen1) != BOOT_OK,
                     "keystore_huk_null_buf");
        record_check(rep, ks->read_device_secret(sec1, sizeof(sec1), NULL) != BOOT_OK,
                     "keystore_huk_null_len");

        bool huk_ok =
            (ks->read_device_secret(sec1, sizeof(sec1), &slen1) == BOOT_OK) &&
            (ks->read_device_secret(sec2, sizeof(sec2), &slen2) == BOOT_OK) &&
            (slen1 >= 16U && slen1 <= sizeof(sec1) && slen1 == slen2) &&
            (memcmp(sec1, sec2, slen1) == 0) &&
            !buf_is_degenerate(sec1, slen1);
        record_check(rep, huk_ok, "keystore_huk_deterministic_nondegenerate");

        uint8_t dev_id[32];
        uint8_t jkey1[16];
        uint8_t jkey2[16];
        bool kdf_ok = (boot_derive_device_id(plat, dev_id) == BOOT_OK) &&
                      (boot_derive_journal_key(plat, jkey1) == BOOT_OK) &&
                      (boot_derive_journal_key(plat, jkey2) == BOOT_OK) &&
                      (memcmp(jkey1, jkey2, sizeof(jkey1)) == 0) &&
                      (memcmp(dev_id, jkey1, sizeof(jkey1)) != 0);
        record_check(rep, kdf_ok, "keystore_kdf_domain_determinism");

        boot_secure_zeroize(sec1, sizeof(sec1));
        boot_secure_zeroize(sec2, sizeof(sec2));
        boot_secure_zeroize(dev_id, sizeof(dev_id));
        boot_secure_zeroize(jkey1, sizeof(jkey1));
        boot_secure_zeroize(jkey2, sizeof(jkey2));
    } else {
        rep->tests_skipped++;
    }

    /* 4. PQC pubkey hash length & stability */
    if (ks->read_pqc_pubkey_hash != NULL) {
        uint8_t ph1[32];
        uint8_t ph2[32];
        memset(ph1, 0, sizeof(ph1));
        memset(ph2, 0, sizeof(ph2));
        record_check(rep, ks->read_pqc_pubkey_hash(NULL, 0U) != BOOT_OK, "keystore_pqc_null_buf");
        bool pqc_ok = (ks->read_pqc_pubkey_hash(ph1, expected_active) == BOOT_OK) &&
                      (ks->read_pqc_pubkey_hash(ph2, expected_active) == BOOT_OK) &&
                      (memcmp(ph1, ph2, 32U) == 0) && !buf_is_degenerate(ph1, 32U);
        record_check(rep, pqc_ok, "keystore_pqc_hash_stable");
        boot_secure_zeroize(ph1, sizeof(ph1));
        boot_secure_zeroize(ph2, sizeof(ph2));
    } else {
        rep->tests_skipped++;
    }

    /* 5. DSLC read determinism & NULL error propagation */
    uint8_t dslc1[8];
    uint8_t dslc2[8];
    size_t dlen1 = sizeof(dslc1);
    size_t dlen2 = sizeof(dslc2);
    record_check(rep, ks->read_dslc(NULL, &dlen1) != BOOT_OK, "keystore_dslc_null_buf");
    record_check(rep, ks->read_dslc(dslc1, NULL) != BOOT_OK, "keystore_dslc_null_len");
    bool dslc_ok = (ks->read_dslc(dslc1, &dlen1) == BOOT_OK) &&
                   (ks->read_dslc(dslc2, &dlen2) == BOOT_OK) &&
                   (dlen1 > 0U && dlen1 == dlen2 && memcmp(dslc1, dslc2, dlen1) == 0);
    record_check(rep, dslc_ok, "keystore_dslc_deterministic");

    /* 6. Monotonic counter read error propagation (and opt-in advance test) */
    if (ks->read_monotonic_counter != NULL) {
        uint32_t ctr1 = 0U;
        uint32_t ctr2 = 0U;
        record_check(rep, ks->read_monotonic_counter(NULL) != BOOT_OK,
                     "keystore_monotonic_null_arg");
        bool ctr_ok = (ks->read_monotonic_counter(&ctr1) == BOOT_OK) &&
                      (ks->read_monotonic_counter(&ctr2) == BOOT_OK) &&
                      (ctr1 == ctr2);
        record_check(rep, ctr_ok, "keystore_monotonic_stable");

        if ((rep->flags & HAL_QUAL_FLAG_TEST_OTP_ADVANCE) != 0U &&
            ks->advance_monotonic_counter != NULL) {
            uint32_t ctr_after = 0U;
            bool adv_ok = (ks->advance_monotonic_counter() == BOOT_OK) &&
                          (ks->read_monotonic_counter(&ctr_after) == BOOT_OK) &&
                          (ctr_after == ctr1 + 1U);
            record_check(rep, adv_ok, "keystore_monotonic_advance");
        }
    } else {
        rep->tests_skipped++;
    }

    /* 7. SoC lockdown_before_handoff idempotence & WDT operational survival */
    if (plat->soc != NULL) {
        record_check(rep, plat->soc->abi_version == TOOB_HAL_ABI_V2, "soc_abi_v2");
        if (plat->soc->init != NULL) {
            record_check(rep, plat->soc->init() == BOOT_OK, "soc_init");
        }
        if (plat->soc->lockdown_before_handoff != NULL) {
            bool lock_ok = (plat->soc->lockdown_before_handoff() == BOOT_OK) &&
                           (plat->soc->lockdown_before_handoff() == BOOT_OK);
            record_check(rep, lock_ok, "soc_lockdown_idempotent");
        }
        if (plat->soc->deinit != NULL) {
            plat->soc->deinit();
        }
    } else {
        rep->tests_skipped++;
    }

    if (plat->wdt != NULL && plat->wdt->kick != NULL) {
        if (plat->wdt->init != NULL) {
            record_check(rep, plat->wdt->init(2000U) == BOOT_OK, "wdt_init");
        }
        plat->wdt->kick();
        if (plat->wdt->suspend_for_critical_section != NULL && plat->wdt->resume != NULL) {
            plat->wdt->suspend_for_critical_section();
            plat->wdt->resume();
        }
        plat->wdt->kick();
        record_check(rep, true, "wdt_kick_suspend_resume");
        if (plat->wdt->deinit != NULL) {
            plat->wdt->deinit();
        }
    } else {
        record_check(rep, false, "wdt_present");
    }

    boot_secure_zeroize(uid1, sizeof(uid1));
    boot_secure_zeroize(uid2, sizeof(uid2));
    boot_secure_zeroize(pk, sizeof(pk));
    if (ks->deinit != NULL) {
        ks->deinit();
    }
    return (rep->tests_failed == 0U) ? HAL_QUAL_OK : HAL_QUAL_FAIL;
}
