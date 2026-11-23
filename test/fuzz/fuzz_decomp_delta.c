#include "fuzz_common.h"

#include "boot_crc32.h"
#include "boot_decomp.h"
#include "boot_delta.h"
#include "boot_journal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x44454C54ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();
    fuzz_keystore_set_dslc(0x01U);
    fuzz_keystore_set_monotonic(0U);

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        if (boot_journal_init(plat) == BOOT_OK) {
            size_t staging_wr = (size > CHIP_STAGING_SLOT_SIZE) ? CHIP_STAGING_SLOT_SIZE : size;
            if (staging_wr > 0U) {
                fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR, data, staging_wr);
            }

            /* Populate deterministic base firmware in App Slot for delta COPY_BASE / fingerprint checks. */
            static const uint8_t base_pattern[64] = "TOOB_BASE_IMAGE_V1_REFERENCE_PAYLOAD_0123456789ABCDEF0123456789";
            for (uint32_t off = 0U; off < 4096U; off += (uint32_t)sizeof(base_pattern)) {
                fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR + off, base_pattern,
                                     sizeof(base_pattern));
            }

            wal_entry_payload_t txn;
            memset(&txn, 0, sizeof(txn));
            txn.magic = WAL_ENTRY_MAGIC;
            txn.intent = WAL_INTENT_UPDATE_PENDING;

            /* 1. Heatshrink compressed payload decompression bounds & zip-bomb cap. */
            uint32_t expected_installed = 256U;
            if (size >= 4U) {
                uint32_t raw_sz = 0U;
                memcpy(&raw_sz, data, sizeof(raw_sz));
                if ((data[0] & 0x03U) == 0U) {
                    expected_installed = raw_sz; /* Exercises 0 and overflow bounds! */
                } else {
                    expected_installed = (raw_sz % 4096U) + 1U;
                }
            }
            (void)boot_decomp_apply(plat, CHIP_STAGING_SLOT_ABS_ADDR, staging_wr,
                                    CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                                    expected_installed, &txn, crypto_arena,
                                    BOOT_CRYPTO_ARENA_SIZE);

            /* 2. TDS1 Streaming Delta VM: raw fuzz header/instructions + CRC-repaired header pass. */
            memset(&txn, 0, sizeof(txn));
            txn.magic = WAL_ENTRY_MAGIC;
            txn.intent = WAL_INTENT_UPDATE_PENDING;
            fuzz_flash_fill_erased(CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE);

            (void)boot_delta_apply(plat, CHIP_STAGING_SLOT_ABS_ADDR, staging_wr,
                                   CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                                   CHIP_APP_SLOT_ABS_ADDR, 4096U, &txn, crypto_arena,
                                   BOOT_CRYPTO_ARENA_SIZE);

            /* Pass B: repair TDS header CRC (and instruction CRCs if present) to penetrate deep VM ops. */
            if (staging_wr >= sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t)) {
                toob_tds_header_t tds_hdr;
                memcpy(&tds_hdr, data, sizeof(tds_hdr));
                tds_hdr.magic = TOOB_TDS_MAGIC;
                tds_hdr.header_crc32 = compute_boot_crc32(
                    (const uint8_t *)(const void *)&tds_hdr,
                    offsetof(toob_tds_header_t, header_crc32));
                fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR,
                                     (const uint8_t *)(const void *)&tds_hdr, sizeof(tds_hdr));

                memset(&txn, 0, sizeof(txn));
                txn.magic = WAL_ENTRY_MAGIC;
                txn.intent = WAL_INTENT_UPDATE_PENDING;
                (void)boot_delta_apply(plat, CHIP_STAGING_SLOT_ABS_ADDR, staging_wr,
                                       CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE,
                                       CHIP_APP_SLOT_ABS_ADDR, 4096U, &txn, crypto_arena,
                                       BOOT_CRYPTO_ARENA_SIZE);
            }
        }
    }
    g_fuzz_trap_active = 0;

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("decomp_delta")
