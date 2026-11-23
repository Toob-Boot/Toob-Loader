#include "fuzz_common.h"

#include "boot_crc32.h"
#include "boot_journal.h"

static void populate_wal_sectors(const uint8_t *data, size_t size) {
    static const uint32_t wal_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
    static const size_t wal_sizes[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;

    for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
        fuzz_flash_fill_erased(wal_addrs[i], wal_sizes[i]);
    }

    if (size == 0U) {
        return;
    }

    if (size > 4096U) {
        /* Direct physical sector mapping for full multi-sector snapshots. */
        size_t off = 0U;
        for (uint32_t i = 0U; i < TOOB_WAL_SECTORS && off < size; i++) {
            size_t chunk = size - off;
            if (chunk > wal_sizes[i]) {
                chunk = wal_sizes[i];
            }
            fuzz_flash_write_raw(wal_addrs[i], &data[off], chunk);
            off += chunk;
        }
    } else {
        /* Compact stride mapping so small fuzz inputs populate multiple sectors (TMR quorum). */
        size_t per_sec = size / TOOB_WAL_SECTORS;
        if (per_sec < sizeof(wal_sector_header_aligned_t)) {
            size_t wr = (size > wal_sizes[0]) ? wal_sizes[0] : size;
            fuzz_flash_write_raw(wal_addrs[0], data, wr);
        } else {
            size_t off = 0U;
            for (uint32_t i = 0U; i < TOOB_WAL_SECTORS; i++) {
                size_t rem = size - off;
                size_t wr = (i == (TOOB_WAL_SECTORS - 1U)) ? rem : per_sec;
                if (wr > wal_sizes[i]) {
                    wr = wal_sizes[i];
                }
                if (wr > 0U) {
                    fuzz_flash_write_raw(wal_addrs[i], &data[off], wr);
                    off += wr;
                }
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x57414C33ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();

    /* Exercise both provisioned (dslc=0x01, epoch>=0) and blank-unprovisioned (dslc=0x00) gates. */
    uint8_t dslc = (size > 0U && (data[0] & 0x01U) != 0U) ? 0x00U : 0x01U;
    uint32_t epoch = (size > 1U) ? (uint32_t)(data[1] & 0x03U) : 0U;
    fuzz_keystore_set_dslc(dslc);
    fuzz_keystore_set_monotonic(epoch);

    populate_wal_sectors(data, size);

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        boot_status_t st = boot_journal_init(plat);
        if (st == BOOT_OK) {
            wal_tmr_payload_t tmr;
            wal_entry_payload_t txn;
            wal_entry_payload_t heal;
            uint32_t net_accum = 0U;
            uint32_t resume_off = 0U;
            bool heal_found = false;

            (void)boot_journal_get_tmr(plat, &tmr);
            (void)boot_journal_reconstruct_txn(plat, &txn, &net_accum, &resume_off);
            (void)boot_journal_reconstruct_aux_heal(plat, &heal, &heal_found);

            wal_entry_payload_t append_ev;
            memset(&append_ev, 0, sizeof(append_ev));
            append_ev.magic = WAL_ENTRY_MAGIC;
            append_ev.intent = WAL_INTENT_SLEEP_BACKOFF;
            (void)boot_journal_append(plat, &append_ev);

            boot_journal_set_tmr_defer(true);
            (void)boot_journal_update_tmr(plat, &tmr);
            (void)boot_journal_flush_tmr(plat);
            boot_journal_set_tmr_defer(false);
        }
    }
    g_fuzz_trap_active = 0;

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("wal_journal")
