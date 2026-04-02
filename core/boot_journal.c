/*
 * Toob-Boot Core File: boot_journal.c
 * Relevant Spec-Dateien:
 * - docs/wal_internals.md (WAL, CRC-32)
 * - docs/structure_plan.md
 */

#include "boot_journal.h"
#include "boot_config_mock.h"
#include <string.h>

/**
 * @brief Static Cache for the WAL bounds and states to avoid runtime allocation and constant recalculation.
 */
static uint32_t active_wal_index = 0;
static uint32_t wal_sector_addrs[8]; /* Max 8 sectors according to architectual spec */
static wal_sector_header_t current_active_header;
static bool wal_initialized = false;

/**
 * @brief Table-less CRC-32 (O(L) in Datenlänge)
 */
static uint32_t compute_wal_crc32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

/**
 * @brief Validates the CRC-32 of a Sector Header
 */
static bool verify_header_crc(const wal_sector_header_aligned_t *aligned_header) {
    if (aligned_header->data.sector_magic != WAL_ABI_VERSION_MAGIC) return false;
    size_t crc_len = sizeof(wal_sector_header_t) - sizeof(uint32_t);
    uint32_t calc_crc = compute_wal_crc32((const uint8_t*)&aligned_header->data, crc_len);
    return (calc_crc == aligned_header->data.header_crc32);
}

/**
 * @brief Handles Sequence-ID wrap-around konsequent
 * Invariant: Works safely for distances < 2^31.
 */
static bool is_newer_sequence(uint32_t new_seq, uint32_t old_seq) {
    if (new_seq == old_seq) return false;
    int32_t diff = (int32_t)(new_seq - old_seq);
    return diff > 0;
}

static uint32_t cached_write_offset = 0;

/**
 * @brief Findet den am wenigsten abgenutzten physischen Sektor (Globales Wear-Leveling).
 * Schützt die letzten 3 TMR-Iterationen vor dem Überschreiben.
 */
static uint32_t get_best_wear_leveling_sector(const boot_platform_t *platform, uint32_t highest_seq) {
    uint32_t best_idx = 0;
    uint32_t min_erase = 0xFFFFFFFF;
    
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        if (i == active_wal_index) continue;
        
        wal_sector_header_aligned_t hdr;
        if (platform->flash->read(wal_sector_addrs[i], &hdr, sizeof(hdr)) != BOOT_OK) continue;
        
        if (verify_header_crc(&hdr)) {
            /* Protect the most recent TMR history (active, active-1, active-2) */
            if (!is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
                uint32_t diff = highest_seq - hdr.data.sequence_id;
                if (diff < 3) continue; /* Protected */
            }
            if (hdr.data.erase_count < min_erase) {
                min_erase = hdr.data.erase_count;
                best_idx = i;
            }
        } else {
            /* Zerstörter oder leerer Sektor ist ideal zum Überschreiben */
            return i;
        }
    }
    return best_idx;
}

boot_status_t boot_journal_init(const boot_platform_t *platform) {
    if (!platform || !platform->flash || !platform->wdt) return BOOT_ERR_INVALID_ARG;
    if (TOOB_WAL_SECTORS < 4 || TOOB_WAL_SECTORS > 8) return BOOT_ERR_INVALID_ARG;

    /* 1. Calculate boundaries dynamically to support asymmetric flash (GAP-C01) */
    uint32_t current_addr = TOOB_WAL_BASE_ADDR;
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        wal_sector_addrs[i] = current_addr;
        size_t sec_size = 0;
        boot_status_t status = platform->flash->get_sector_size(current_addr, &sec_size);
        if (status != BOOT_OK) return status;
        current_addr += (uint32_t)sec_size;
    }

    /* 2. Scan all sectors for valid Headers to find highest sequence (O(n) Sektoren) */
    uint32_t highest_seq = 0;
    int32_t highest_idx = -1;
    wal_sector_header_aligned_t hdr;
    
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        /* P10 Rule: Safe initialization */
        memset(&hdr, 0, sizeof(hdr));
        if (platform->flash->read(wal_sector_addrs[i], &hdr, sizeof(hdr)) != BOOT_OK) continue;
        
        if (verify_header_crc(&hdr)) {
            if (highest_idx == -1 || is_newer_sequence(hdr.data.sequence_id, highest_seq)) {
                highest_seq = hdr.data.sequence_id;
                highest_idx = (int32_t)i;
            }
        }
    }

    /* 3. Factory Blank Initialization or Majority Vote Recovery */
    if (highest_idx == -1) {
        /* Factory Blank: Initialize Sector 0 */
        active_wal_index = 0;
        memset(&current_active_header, 0, sizeof(current_active_header));
        current_active_header.sector_magic = WAL_ABI_VERSION_MAGIC;
        current_active_header.sequence_id = 1;
        current_active_header.erase_count = 1;
        
        /* WDT kick and Erase */
        platform->wdt->kick();
        platform->flash->erase_sector(wal_sector_addrs[0]);
        
        current_active_header.header_crc32 = compute_wal_crc32((const uint8_t*)&current_active_header, sizeof(wal_sector_header_t) - sizeof(uint32_t));
        
        wal_sector_header_aligned_t write_hdr;
        memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));
        memcpy(&write_hdr.data, &current_active_header, sizeof(wal_sector_header_t));
        
        platform->flash->write(wal_sector_addrs[0], &write_hdr, sizeof(write_hdr));
        
        wal_sector_header_aligned_t verify_hdr;
        if (platform->flash->read(wal_sector_addrs[0], &verify_hdr, sizeof(verify_hdr)) != BOOT_OK ||
            memcmp(&write_hdr, &verify_hdr, sizeof(write_hdr)) != 0) {
            return BOOT_ERR_FLASH;
        }
    } else {
        /* Active Index Restored */
        active_wal_index = (uint32_t)highest_idx;
        
        /* Read highest index again to fill RAM Cache */
        if (platform->flash->read(wal_sector_addrs[highest_idx], &hdr, sizeof(hdr)) != BOOT_OK) return BOOT_ERR_FLASH;
        current_active_header = hdr.data;
        
        /* GAP-C01 Majority Vote TMR with Strict Sequence Continuity */
        wal_tmr_payload_t tmr_candidates[3];
        tmr_candidates[0] = current_active_header.tmr_data;
        int num_candidates = 1;
        
        for (uint32_t step = 1; step <= 2; step++) {
            uint32_t target_seq = highest_seq - step;
            bool found_contiguous = false;
            
            for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
                if (platform->flash->read(wal_sector_addrs[i], &hdr, sizeof(hdr)) == BOOT_OK) {
                    if (verify_header_crc(&hdr) && hdr.data.sequence_id == target_seq) {
                        tmr_candidates[num_candidates++] = hdr.data.tmr_data;
                        found_contiguous = true;
                        break;
                    }
                }
            }
            if (!found_contiguous) break; /* Stop collection if logic chain breaks */
        }
        
        if (num_candidates >= 2) {
            wal_tmr_payload_t *c0 = &tmr_candidates[0];
            wal_tmr_payload_t *c1 = &tmr_candidates[1];
            wal_tmr_payload_t *c2 = (num_candidates == 3) ? &tmr_candidates[2] : NULL;
            
            #define TMR_VOTE(field) \
                ((c0->field == c1->field) ? c0->field : \
                 (c2 != NULL && c0->field == c2->field) ? c0->field : \
                 (c2 != NULL && c1->field == c2->field) ? c1->field : c0->field)

            current_active_header.tmr_data.primary_slot_id = TMR_VOTE(primary_slot_id);
            current_active_header.tmr_data.boot_failure_counter = TMR_VOTE(boot_failure_counter);
            current_active_header.tmr_data.svn_recovery_counter = TMR_VOTE(svn_recovery_counter);
            current_active_header.tmr_data.app_slot_erase_counter = TMR_VOTE(app_slot_erase_counter);
            current_active_header.tmr_data.staging_slot_erase_counter = TMR_VOTE(staging_slot_erase_counter);
            current_active_header.tmr_data.swap_buffer_erase_counter = TMR_VOTE(swap_buffer_erase_counter);
            
            #undef TMR_VOTE
        } else {
            /* Falls extreme Korruption 2 von 3 Headern zerstört hat, nutzen wir den letzten überlebenden Stand (Highest Sequence). */
            current_active_header.tmr_data = tmr_candidates[0];
        }
    }
    
    wal_initialized = true;
    return BOOT_OK;
}

boot_status_t boot_journal_append(const boot_platform_t *platform, const wal_entry_payload_t *new_entry) {
    if (!platform || !platform->flash || !new_entry) return BOOT_ERR_INVALID_ARG;
    if (!wal_initialized) return BOOT_ERR_STATE;

    size_t sec_size = 0;
    platform->flash->get_sector_size(wal_sector_addrs[active_wal_index], &sec_size);

    uint32_t current_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    uint32_t target_offset = 0;
    bool needs_rotation = false;

    /* O(N) Suche nach der unbeschriebenen Front ("Erased Frontier") */
    uint32_t erased_32 = (uint32_t)platform->flash->erased_value | ((uint32_t)platform->flash->erased_value << 8) | 
                         ((uint32_t)platform->flash->erased_value << 16) | ((uint32_t)platform->flash->erased_value << 24);

    if (cached_write_offset > 0 && cached_write_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
        target_offset = cached_write_offset;
        uint32_t magic = 0;
        if (platform->flash->read(wal_sector_addrs[active_wal_index] + target_offset, &magic, sizeof(magic)) != BOOT_OK || magic != erased_32) {
            target_offset = 0; /* Invalidated cache */
        }
    }

    if (target_offset == 0) {
        uint32_t current_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
        while (current_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
            platform->wdt->kick();
            
            uint32_t magic = 0;
            if (platform->flash->read(wal_sector_addrs[active_wal_index] + current_offset, &magic, sizeof(magic)) != BOOT_OK) {
                needs_rotation = true;
                break;
            }
            
            if (magic == erased_32) {
                target_offset = current_offset;
                break;
            }

            if (magic != WAL_ENTRY_MAGIC) {
                needs_rotation = true;
                break;
            }
            current_offset += (uint32_t)sizeof(wal_entry_aligned_t);
        }
    }

    /* Sliding Window Rotation: Sektor voll oder durch Brownout kontaminiert */
    if (needs_rotation || target_offset == 0 || target_offset + sizeof(wal_entry_aligned_t) > sec_size) {
        uint32_t new_idx = get_best_wear_leveling_sector(platform, current_active_header.sequence_id);
        
        #ifndef CHIP_FLASH_MAX_ERASE_CYCLES
        #define CHIP_FLASH_MAX_ERASE_CYCLES 100000 /* Default EOL limit */
        #endif

        if (current_active_header.erase_count >= CHIP_FLASH_MAX_ERASE_CYCLES) {
            /* Das WAL-Volume hat das physische Lebensende der Silizium-Gates erreicht.
             * Ein weiteres `erase_sector` führt statistisch zum Flash-Error / Short-Circuit.
             * Wir brechen ab und das Core wertet BOOT_ERR_COUNTER_EXHAUSTED aus,
             * was eine dauerhafte STATE_READ_ONLY Sperrung veranlasst. */
            return BOOT_ERR_COUNTER_EXHAUSTED;
        }

        platform->wdt->kick();
        boot_status_t status = platform->flash->erase_sector(wal_sector_addrs[new_idx]);
        if (status != BOOT_OK) return status;

        wal_sector_header_aligned_t write_hdr;
        memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));
        
        write_hdr.data.sector_magic = WAL_ABI_VERSION_MAGIC;
        write_hdr.data.sequence_id  = current_active_header.sequence_id + 1;
        write_hdr.data.erase_count  = current_active_header.erase_count + 1;
        /* Wir transportieren den TMR Vote-State unbeschädigt in den neuen Ring-Sektor */
        write_hdr.data.tmr_data     = current_active_header.tmr_data; 
        write_hdr.data.header_crc32 = compute_wal_crc32((const uint8_t*)&write_hdr.data, sizeof(wal_sector_header_t) - sizeof(uint32_t));

        platform->wdt->kick();
        status = platform->flash->write(wal_sector_addrs[new_idx], &write_hdr, sizeof(write_hdr));
        if (status != BOOT_OK) return status;
        
        wal_sector_header_aligned_t verify_hdr;
        if (platform->flash->read(wal_sector_addrs[new_idx], &verify_hdr, sizeof(verify_hdr)) != BOOT_OK ||
            memcmp(&write_hdr, &verify_hdr, sizeof(write_hdr)) != 0) {
            return BOOT_ERR_FLASH;
        }

        /* Window ist offiziell geslided */
        active_wal_index = new_idx;
        current_active_header.sequence_id++;
        current_active_header.erase_count++;
        target_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
        cached_write_offset = target_offset;
    }

    /* Sicheres Schreiben des neuen Intents */
    wal_entry_aligned_t entry;
    memset(&entry, platform->flash->erased_value, sizeof(entry));
    memcpy(&entry.data, new_entry, sizeof(wal_entry_payload_t));
    
    entry.data.magic = WAL_ENTRY_MAGIC;
    size_t crc_len = sizeof(wal_entry_payload_t) - sizeof(uint32_t);
    entry.data.crc32_trailer = compute_wal_crc32((const uint8_t*)&entry.data, crc_len);
    
    platform->wdt->kick();
    boot_status_t entry_status = platform->flash->write(wal_sector_addrs[active_wal_index] + target_offset, &entry, sizeof(entry));
    if (entry_status != BOOT_OK) return entry_status;

    wal_entry_aligned_t verify_entry;
    if (platform->flash->read(wal_sector_addrs[active_wal_index] + target_offset, &verify_entry, sizeof(verify_entry)) != BOOT_OK ||
        memcmp(&entry, &verify_entry, sizeof(entry)) != 0) {
        return BOOT_ERR_FLASH;
    }
    
    cached_write_offset = target_offset + (uint32_t)sizeof(wal_entry_aligned_t);
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform, const wal_tmr_payload_t *new_tmr) {
    if (!platform || !platform->flash || !platform->wdt || !new_tmr) return BOOT_ERR_INVALID_ARG;
    if (!wal_initialized) return BOOT_ERR_STATE;

    /* GAP-C01 TMR Strided Write
     * Mathematischer TMR-Beweis: Fällt der Strom nach [n+1], verliert [n+1] den Majority-Vote gegen [n] und [n-1].
     * Erst nach erfolgreichem Write von [n+2] gewinnt der neue Status die Mehrheit (2 von 3).
     * Absolut Brownout sicheres State-Commit!
     * 
     * ARCHITEKTUR-REGEL: STATEFUL SLIDE ABANDONMENT
     * Da diese Operation das WAL-Window um 3 physikalische Sektoren verschiebt,
     * gehen in der aktuellen Transaktion offene Appends für `reconstruct_txn` verloren.
     * Dies ist by-design ABSICHT: TMR-Updates (`svn_recovery`, `primary_slot`)
     * werden in Toob-Boot ausschließlich OUTSIDE einer aktiven Update-Streaming 
     * Transaktion getätigt. Es überschneidet sich niemals logisch.
     */
     
    uint32_t active_seq = current_active_header.sequence_id;
    uint32_t new_idx = active_wal_index;
    
    for (uint32_t step = 1; step <= 3; step++) {
        new_idx = get_best_wear_leveling_sector(platform, active_seq);
        active_seq++; /* Increment Sequence per Sector to maintain O(1) Sliding Window */
        
        #ifndef CHIP_FLASH_MAX_ERASE_CYCLES
        #define CHIP_FLASH_MAX_ERASE_CYCLES 100000 /* Default EOL limit */
        #endif

        if (current_active_header.erase_count >= CHIP_FLASH_MAX_ERASE_CYCLES) {
            /* Schutz vor physikalischem Flash-Burnout während TMR Übertragungen */
            return BOOT_ERR_COUNTER_EXHAUSTED;
        }

        /* WDT Kick zwingend vor schwerem Block-Erase (GAP-02) */
        platform->wdt->kick();
        
        boot_status_t status = platform->flash->erase_sector(wal_sector_addrs[new_idx]);
        if (status != BOOT_OK) return status;
        
        wal_sector_header_aligned_t write_hdr;
        memset(&write_hdr, platform->flash->erased_value, sizeof(write_hdr));
        
        write_hdr.data.sector_magic = WAL_ABI_VERSION_MAGIC;
        write_hdr.data.sequence_id  = active_seq;
        
        /* Wir bewahren den Erase Count, um das Wear-Leveling akkurat fortzuführen. */
        write_hdr.data.erase_count  = current_active_header.erase_count + step;
        write_hdr.data.tmr_data = *new_tmr;
        
        /* Safe Trailer */
        write_hdr.data.header_crc32 = compute_wal_crc32((const uint8_t*)&write_hdr.data, sizeof(wal_sector_header_t) - sizeof(uint32_t));
        
        platform->wdt->kick(); /* Nach dem Erase nochmal WDT sichern */
        status = platform->flash->write(wal_sector_addrs[new_idx], &write_hdr, sizeof(write_hdr));
        if (status != BOOT_OK) return status;
        
        wal_sector_header_aligned_t verify_hdr;
        if (platform->flash->read(wal_sector_addrs[new_idx], &verify_hdr, sizeof(verify_hdr)) != BOOT_OK ||
            memcmp(&write_hdr, &verify_hdr, sizeof(write_hdr)) != 0) {
            return BOOT_ERR_FLASH;
        }
        
        active_wal_index = new_idx; /* Immediately lock this sector via active index */
    }
    
    /* State Global aktualisieren */
    cached_write_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    active_wal_index = new_idx;
    current_active_header.sequence_id = active_seq;
    current_active_header.erase_count = current_active_header.erase_count + 3; // Nach 3 Updates
    current_active_header.tmr_data = *new_tmr;
    current_active_header.header_crc32 = compute_wal_crc32((const uint8_t*)&current_active_header, sizeof(wal_sector_header_t) - sizeof(uint32_t));
    
    return BOOT_OK;
}

boot_status_t boot_journal_reconstruct_txn(const boot_platform_t *platform, wal_entry_payload_t *out_state) {
    if (!platform || !platform->flash || !out_state) return BOOT_ERR_INVALID_ARG;
    if (!wal_initialized) return BOOT_ERR_STATE;
    
    memset(out_state, 0, sizeof(wal_entry_payload_t));

    size_t sec_size = 0;
    platform->flash->get_sector_size(wal_sector_addrs[active_wal_index], &sec_size);

    uint32_t current_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    bool read_success = false;

    uint32_t erased_32 = (uint32_t)platform->flash->erased_value | ((uint32_t)platform->flash->erased_value << 8) | 
                         ((uint32_t)platform->flash->erased_value << 16) | ((uint32_t)platform->flash->erased_value << 24);

    while (current_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
        wal_entry_aligned_t entry;
        platform->wdt->kick();
        if (platform->flash->read(wal_sector_addrs[active_wal_index] + current_offset, &entry, sizeof(entry)) != BOOT_OK) {
            break;
        }

        /* End-Of-Log Erkennung - Alles ab hier ist sauber gelöscht */
        if (entry.data.magic == erased_32) {
            break;
        }

        /* Physikalischer Abrieb / Stromausfall beim Schreiben */
        if (entry.data.magic != WAL_ENTRY_MAGIC) {
            break;
        }

        /* Kryptografischer Bit-Rot / Brownout Check (GAP) */
        size_t crc_len = sizeof(wal_entry_payload_t) - sizeof(uint32_t);
        uint32_t calc_crc = compute_wal_crc32((const uint8_t*)&entry.data, crc_len);
        if (calc_crc != entry.data.crc32_trailer) {
            break;
        }

        /* Eintrag ist zu 100% verifiziert. Wir überschreiben out_state, 
         * sodass am Ende der Schleife die finale konsequente Transaktion überlebt */
        memcpy(out_state, &entry.data, sizeof(wal_entry_payload_t));
        read_success = true;

        current_offset += (uint32_t)sizeof(wal_entry_aligned_t);
    }

    if (read_success) {
        return BOOT_OK; /* Das System kann den gefundenen Intent recovern */
    } else {
        return BOOT_ERR_STATE; /* Factory Start ohne laufende Txn */
    }
}
