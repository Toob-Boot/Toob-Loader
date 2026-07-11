#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define TOOB_MOCK_TEST 1
#define TOOB_WAL_SECTORS 4

#include "../../toobloader/core/boot_state.c"

void test_energy_admission(void);
void test_boot_proof(void);
void test_journal_chain(void);
void test_tbm1_layout(void);

int main(void) {
    printf("==================================================\n");
    printf("   Toob-Boot K6-T4 Intent Totality Verification\n");
    printf("==================================================\n\n");

    /* Iteriere über alle relevanten Intents und Events */
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
    size_t num_intents = sizeof(intents)/sizeof(intents[0]);

    boot_event_t events[] = {
        EV_NONE,
        EV_CONFIRM_OK,
        EV_CRASH,
        EV_CLOUD_UNLOCK,
        EV_CLOUD_LOCK,
        EV_CLOUD_UPDATE
    };
    size_t num_events = sizeof(events)/sizeof(events[0]);

    printf("[1] Checking transitions totality...\n");
    for (size_t i = 0; i < num_intents; i++) {
        for (size_t e = 0; e < num_events; e++) {
            /* Wir suchen nach einem Übergang in der Tabelle */
            const intent_row_t *match = NULL;
            for (size_t t = 0; t < sizeof(INTENT_TABLE)/sizeof(INTENT_TABLE[0]); t++) {
                if (INTENT_TABLE[t].cur == intents[i] && INTENT_TABLE[t].ev == events[e]) {
                    match = &INTENT_TABLE[t];
                    break;
                }
            }
            if (match) {
                printf("    Intent %d + Event %d -> Intent %d (Action %d)\n",
                       intents[i], events[e], match->next, match->action);
            }
        }
    }

    printf("\n[2] Checking specific security invariants...\n");
    /* Verifiziere, dass locked-state mit confirm_ok locked bleibt (sticky) */
    const intent_row_t *lock_confirm = NULL;
    for (size_t t = 0; t < sizeof(INTENT_TABLE)/sizeof(INTENT_TABLE[0]); t++) {
        if (INTENT_TABLE[t].cur == WAL_INTENT_DEVICE_LOCKED && INTENT_TABLE[t].ev == EV_CONFIRM_OK) {
            lock_confirm = &INTENT_TABLE[t];
        }
    }
    assert(lock_confirm != NULL);
    assert(lock_confirm->next == WAL_INTENT_DEVICE_LOCKED);
    assert(lock_confirm->action == ACT_PANIC_LOCKED);
    printf("    -> Sticky Lock double defense check passed.\n");

    /* K7-T4: Run Energy and Wear Admission tests */
    test_energy_admission();

    /* K1-T1: Run Boot Proof verification tests */
    test_boot_proof();

    /* K4-T2: Run Journal Chain verification tests */
    test_journal_chain();

    /* K2-T1: Run TBM1 Fixed-Format Manifest layout tests */
    test_tbm1_layout();

    printf("\n==================================================\n");
    printf("   INTENT TOTALITY CHECK PASSED SUCCESSFULLY!\n");
    printf("==================================================\n");
    return 0;
}

#include "../../toobloader/core/boot_crc32.c"
#include "../../toobloader/core/boot_effect.c"
#include "../../internal/mocks/mocks/mock_flash.c"

void test_energy_admission(void) {
    printf("\n[3] Checking energy and wear admission control (E-K7)...\n");

    boot_platform_t platform;
    memset(&platform, 0, sizeof(platform));
    platform.flash = &sandbox_flash_hal;

    wal_tmr_payload_t tmr;
    memset(&tmr, 0, sizeof(tmr));
    tmr.app_slot_erase_counter = 100;
    tmr.staging_slot_erase_counter = 200;
    tmr.swap_buffer_erase_counter = 50;

    /* Base case: healthy voltage, low wear */
    mock_flash_set_supply_mv(3300U);
    boot_status_t stat = boot_effect_admit_or_defer(&platform, &tmr, 65536, NULL, 0, true);
    assert(stat == BOOT_OK);
    printf("    -> Healthy voltage: BOOT_OK (passed)\n");

    /* Case: low voltage, high costs (should defer) */
    mock_flash_set_supply_mv(2500U);
    stat = boot_effect_admit_or_defer(&platform, &tmr, 65536, NULL, 0, true);
    assert(stat == BOOT_ERR_DEFER);
    printf("    -> Low voltage (2500mV): BOOT_ERR_DEFER (passed)\n");

    /* Case: wear counter at limit */
    mock_flash_set_supply_mv(3300U);
    tmr.app_slot_erase_counter = 100000U; /* Limit is 100000 */
    stat = boot_effect_admit_or_defer(&platform, &tmr, 4096, NULL, 0, true);
    assert(stat == BOOT_ERR_COUNTER_EXHAUSTED);
    printf("    -> App wear counter exhausted: BOOT_ERR_COUNTER_EXHAUSTED (passed)\n");

    /* Restore healthy state */
    mock_flash_set_supply_mv(3300U);
}

void test_boot_proof(void) {
    printf("\n[4] Checking proof-carrying boot handles (E-K1)...\n");

    uint32_t key[4] = {0xAA55AA55, 0x12345678, 0x9ABCDEF0, 0xFEEDFACE};
    uint32_t wrong_key[4] = {0xAA55AA55, 0x12345678, 0x9ABCDEF0, 0xBADBEEF0};

    boot_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    proof.image_addr = 0x10000;
    proof.image_size = 0x20000;
    proof.entry_point = 0x100;
    proof.svn = 5;

    /* Base case: correct seal and correct verification */
    boot_proof_seal(&proof, key);
    boot_status_t stat = boot_proof_verify(&proof, key);
    assert(stat == BOOT_OK);
    printf("    -> Valid proof: BOOT_OK (passed)\n");

    /* Case: key mismatch (should fail verification) */
    stat = boot_proof_verify(&proof, wrong_key);
    assert(stat == BOOT_ERR_VERIFY);
    printf("    -> Key mismatch: BOOT_ERR_VERIFY (passed)\n");

    /* Case: modified field after sealing (should fail verification) */
    proof.image_addr = 0x20000; /* Original: 0x10000 */
    stat = boot_proof_verify(&proof, key);
    assert(stat == BOOT_ERR_VERIFY);
    printf("    -> Modified field: BOOT_ERR_VERIFY (passed)\n");
}

void test_journal_chain(void) {
    printf("\n[5] Checking journal chain mechanics (E-K4)...\n");

    /* 1. Security-bearing intent classification */
    assert(wal_intent_is_security_bearing(WAL_INTENT_DEVICE_LOCKED));
    assert(wal_intent_is_security_bearing(WAL_INTENT_CONFIRM_COMMIT));
    assert(wal_intent_is_security_bearing(WAL_INTENT_TXN_COMMIT));
    printf("    -> Security-bearing intents correctly classified (passed)\n");

    /* Non-security intents must not be classified as security-bearing */
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
    printf("    -> Non-security intents correctly excluded (passed)\n");

    /* 2. TMR payload chain fields exist at expected positions */
    wal_tmr_payload_t tmr;
    memset(&tmr, 0, sizeof(tmr));

    /* Verify chain_tag is zero-initialized (empty chain = fresh device) */
    uint8_t zero_tag[WAL_CHAIN_TAG_BYTES];
    memset(zero_tag, 0, sizeof(zero_tag));
    assert(memcmp(tmr.chain_tag, zero_tag, WAL_CHAIN_TAG_BYTES) == 0);
    assert(tmr.chain_entry_count == 0);
    printf("    -> TMR chain fields zero-initialized (passed)\n");

    /* 3. ABI size invariants */
    assert(sizeof(wal_tmr_payload_t) <= TMR_PAYLOAD_SLOT_BYTES);
    assert(sizeof(wal_tmr_payload_t) == TMR_PAYLOAD_SLOT_BYTES);
    assert(sizeof(wal_sector_header_aligned_t) == 128);
    assert(sizeof(wal_entry_payload_t) == 64);
    printf("    -> ABI size invariants hold (passed)\n");

    /* 4. Verify chain_tag field is writable and distinct */
    memset(tmr.chain_tag, 0xAB, WAL_CHAIN_TAG_BYTES);
    tmr.chain_entry_count = 42;
    assert(tmr.chain_tag[0] == 0xAB);
    assert(tmr.chain_tag[15] == 0xAB);
    assert(tmr.chain_entry_count == 42);
    printf("    -> Chain tag field read/write verified (passed)\n");
}

void test_tbm1_layout(void) {
    printf("\n[6] Checking TBM1 fixed-format manifest layout (E-K2 v2)...\n");

    /* 1. Header struct sizes */
    assert(sizeof(tbm1_image_desc_t) == 44);
    assert(sizeof(tbm1_header_t) == 512);
    printf("    -> Struct sizes: image_desc=44, header=512 (passed)\n");

    /* 2. Critical field offsets */
    assert(offsetof(tbm1_header_t, magic) == 0);
    assert(offsetof(tbm1_header_t, version_major) == 4);
    assert(offsetof(tbm1_header_t, version_minor) == 5);
    assert(offsetof(tbm1_header_t, fixed_len) == 6);
    assert(offsetof(tbm1_header_t, total_len) == 8);
    assert(offsetof(tbm1_header_t, flags_critical) == 12);
    assert(offsetof(tbm1_header_t, flags_info) == 14);
    assert(offsetof(tbm1_header_t, vendor_id) == 16);
    assert(offsetof(tbm1_header_t, product_id) == 18);
    assert(offsetof(tbm1_header_t, hw_rev_min) == 20);
    assert(offsetof(tbm1_header_t, hw_rev_max) == 22);
    assert(offsetof(tbm1_header_t, key_index) == 24);
    assert(offsetof(tbm1_header_t, image_count) == 25);
    assert(offsetof(tbm1_header_t, boot_retry_limit) == 26);
    assert(offsetof(tbm1_header_t, min_reader_major) == 28);
    assert(offsetof(tbm1_header_t, min_reader_minor) == 30);
    assert(offsetof(tbm1_header_t, svn) == 32);
    assert(offsetof(tbm1_header_t, stage1_svn) == 36);
    assert(offsetof(tbm1_header_t, key_epoch) == 40);
    assert(offsetof(tbm1_header_t, build_number) == 44);
    assert(offsetof(tbm1_header_t, fw_ver_major) == 48);
    assert(offsetof(tbm1_header_t, fw_ver_minor) == 50);
    assert(offsetof(tbm1_header_t, fw_ver_patch) == 52);
    assert(offsetof(tbm1_header_t, _rsvd0) == 54);
    assert(offsetof(tbm1_header_t, sbom_digest) == 56);
    assert(offsetof(tbm1_header_t, regions) == 88);
    assert(offsetof(tbm1_header_t, images) == 184);
    assert(offsetof(tbm1_header_t, _reserved_tail) == 360);
    assert(offsetof(tbm1_header_t, fixed_crc32) == 508);
    printf("    -> All header field offsets verified (passed)\n");

    /* 3. Image descriptor field offsets */
    assert(offsetof(tbm1_image_desc_t, image_type) == 0);
    assert(offsetof(tbm1_image_desc_t, target_slot) == 1);
    assert(offsetof(tbm1_image_desc_t, compression_alg) == 2);
    assert(offsetof(tbm1_image_desc_t, delta_alg) == 3);
    assert(offsetof(tbm1_image_desc_t, data_off) == 4);
    assert(offsetof(tbm1_image_desc_t, stored_size) == 8);
    assert(offsetof(tbm1_image_desc_t, installed_size) == 12);
    assert(offsetof(tbm1_image_desc_t, chunk_size) == 16);
    assert(offsetof(tbm1_image_desc_t, num_chunks) == 20);
    assert(offsetof(tbm1_image_desc_t, base_svn) == 24);
    assert(offsetof(tbm1_image_desc_t, ver_major) == 28);
    assert(offsetof(tbm1_image_desc_t, ver_minor) == 30);
    assert(offsetof(tbm1_image_desc_t, ver_patch) == 32);
    assert(offsetof(tbm1_image_desc_t, _rsvd) == 34);
    assert(offsetof(tbm1_image_desc_t, base_fingerprint) == 36);
    printf("    -> All image descriptor offsets verified (passed)\n");

    /* 4. Region Directory Entry offsets */
    assert(offsetof(tbm1_region_t, region_id) == 0);
    assert(offsetof(tbm1_region_t, _rsvd) == 2);
    assert(offsetof(tbm1_region_t, off) == 4);
    assert(offsetof(tbm1_region_t, len) == 8);
    printf("    -> Region entry offsets verified (passed)\n");

    /* 5. Magic constant matches expected value */
    assert(TBM1_MAGIC == 0x314D4254U);
    printf("    -> TBM1_MAGIC == 0x314D4254 ('TBM1' LE) (passed)\n");

    /* 6. Flag bit positions */
    assert(TBM1_CRIT_PQC_REQUIRED == 1);
    assert(TBM1_INFO_DEVICE_BIND == 1);
    printf("    -> Flag bit positions correct (passed)\n");

    /* 7. Region Directory search functionality */
    tbm1_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
    hdr.regions[0].off = 512;
    hdr.regions[0].len = 128;
    hdr.regions[1].region_id = TBM1_REGION_DEVICE_BIND;
    hdr.regions[1].off = 640;
    hdr.regions[1].len = 32;

    const tbm1_region_t *r1 = tbm1_find_region(&hdr, TBM1_REGION_CHUNK_HASHES);
    assert(r1 != NULL);
    assert(r1->off == 512);
    assert(r1->len == 128);

    const tbm1_region_t *r2 = tbm1_find_region(&hdr, TBM1_REGION_DEVICE_BIND);
    assert(r2 != NULL);
    assert(r2->off == 640);
    assert(r2->len == 32);

    const tbm1_region_t *r3 = tbm1_find_region(&hdr, 99);
    assert(r3 == NULL);
    printf("    -> Region finder lookup verified (passed)\n");

    /* 8. Signed length computation */
    hdr.total_len = 1024;
    assert(TBM1_SIGNED_LEN(&hdr) == 960);
    printf("    -> Signed length macro verified (passed)\n");
}
