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
 * @brief O(1) P10-compliant Table-less CRC-32 
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
 * @brief Handles Sequence-ID wrap-around mathematically correctly
 */
static bool is_newer_sequence(uint32_t new_seq, uint32_t old_seq) {
    if (new_seq == old_seq) return false;
    int32_t diff = (int32_t)(new_seq - old_seq);
    return diff > 0;
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

    /* 2. Scan all sectors for valid Headers to find highest sequence (O(1) Discovery) */
    uint32_t highest_seq = 0;
    int32_t highest_idx = -1;
    wal_sector_header_aligned_t headers[8]; // Max 8 sectors, ~512 bytes on stack
    
    for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++) {
        /* P10 Rule: Safe initialization */
        memset(&headers[i], 0, sizeof(headers[i]));
        platform->flash->read(wal_sector_addrs[i], &headers[i], sizeof(wal_sector_header_aligned_t));
        
        if (verify_header_crc(&headers[i])) {
            if (highest_idx == -1 || is_newer_sequence(headers[i].data.sequence_id, highest_seq)) {
                highest_seq = headers[i].data.sequence_id;
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
    } else {
        /* Active Index Restored */
        active_wal_index = (uint32_t)highest_idx;
        current_active_header = headers[highest_idx].data;
        
        /* GAP-C01 Majority Vote TMR */
        wal_tmr_payload_t tmr_candidates[3];
        int num_candidates = 0;
        
        /* Walk backwards from highest_idx to collect recent states */
        for (uint32_t step = 0; step < TOOB_WAL_SECTORS && num_candidates < 3; step++) {
            uint32_t temp_idx = ((uint32_t)highest_idx - step + TOOB_WAL_SECTORS) % TOOB_WAL_SECTORS;
            if (verify_header_crc(&headers[temp_idx])) {
                tmr_candidates[num_candidates++] = headers[temp_idx].data.tmr_data;
            }
        }
        
        if (num_candidates >= 2) {
            wal_tmr_payload_t *c0 = &tmr_candidates[0];
            wal_tmr_payload_t *c1 = &tmr_candidates[1];
            wal_tmr_payload_t *c2 = (num_candidates == 3) ? &tmr_candidates[2] : NULL;
            
            /* TMR Resolving Macro Logic (2 of 3) */
            current_active_header.tmr_data.primary_slot_id = 
                (c0->primary_slot_id == c1->primary_slot_id) ? c0->primary_slot_id :
                (c2 != NULL && c0->primary_slot_id == c2->primary_slot_id) ? c0->primary_slot_id :
                (c2 != NULL && c1->primary_slot_id == c2->primary_slot_id) ? c1->primary_slot_id : c0->primary_slot_id;

            current_active_header.tmr_data.boot_failure_counter = 
                (c0->boot_failure_counter == c1->boot_failure_counter) ? c0->boot_failure_counter :
                (c2 != NULL && c0->boot_failure_counter == c2->boot_failure_counter) ? c0->boot_failure_counter :
                (c2 != NULL && c1->boot_failure_counter == c2->boot_failure_counter) ? c1->boot_failure_counter : c0->boot_failure_counter;
                
            current_active_header.tmr_data.svn_recovery_counter = 
                (c0->svn_recovery_counter == c1->svn_recovery_counter) ? c0->svn_recovery_counter :
                (c2 != NULL && c0->svn_recovery_counter == c2->svn_recovery_counter) ? c0->svn_recovery_counter :
                (c2 != NULL && c1->svn_recovery_counter == c2->svn_recovery_counter) ? c1->svn_recovery_counter : c0->svn_recovery_counter;

            current_active_header.tmr_data.app_slot_erase_counter = 
                (c0->app_slot_erase_counter == c1->app_slot_erase_counter) ? c0->app_slot_erase_counter :
                (c2 != NULL && c0->app_slot_erase_counter == c2->app_slot_erase_counter) ? c0->app_slot_erase_counter :
                (c2 != NULL && c1->app_slot_erase_counter == c2->app_slot_erase_counter) ? c1->app_slot_erase_counter : c0->app_slot_erase_counter;
                
            current_active_header.tmr_data.staging_slot_erase_counter = 
                (c0->staging_slot_erase_counter == c1->staging_slot_erase_counter) ? c0->staging_slot_erase_counter :
                (c2 != NULL && c0->staging_slot_erase_counter == c2->staging_slot_erase_counter) ? c0->staging_slot_erase_counter :
                (c2 != NULL && c1->staging_slot_erase_counter == c2->staging_slot_erase_counter) ? c1->staging_slot_erase_counter : c0->staging_slot_erase_counter;

            current_active_header.tmr_data.swap_buffer_erase_counter = 
                (c0->swap_buffer_erase_counter == c1->swap_buffer_erase_counter) ? c0->swap_buffer_erase_counter :
                (c2 != NULL && c0->swap_buffer_erase_counter == c2->swap_buffer_erase_counter) ? c0->swap_buffer_erase_counter :
                (c2 != NULL && c1->swap_buffer_erase_counter == c2->swap_buffer_erase_counter) ? c1->swap_buffer_erase_counter : c0->swap_buffer_erase_counter;
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

    /* O(N) Suche nach der unbeschriebenen Front ("Erased Frontier") */
    uint32_t erased_32 = (uint32_t)platform->flash->erased_value | ((uint32_t)platform->flash->erased_value << 8) | 
                         ((uint32_t)platform->flash->erased_value << 16) | ((uint32_t)platform->flash->erased_value << 24);

    while (current_offset + sizeof(wal_entry_aligned_t) <= sec_size) {
        /* WDT Kick implantiert: 128KB / 64B = O(2048) blockierende Reads.
         * Verhindert asynchrone Starvation beim Brownout Boot-Resume. */
        platform->wdt->kick();
        
        uint32_t magic = 0;
        platform->flash->read(wal_sector_addrs[active_wal_index] + current_offset, &magic, sizeof(magic));
        
        if (magic == erased_32) {
            target_offset = current_offset;
            break;
        }

        if (magic != WAL_ENTRY_MAGIC) {
            /* P10 Flash Physics Rule: Der Magic ist nicht pristine 0xFF, aber auch nicht 0xBEEF.
             * Ein Brownout starb beim Append exakt hier. Es existieren logische "0" Bits.
             * Würden wir diesen Slot für das neue Append überschreiben, löst die NOR/NAND Flash Architektur
             * eine Write-Exception aus (0->1 flips ohne Block Erase unmöglich).
             * Wir erzwingen stattdessen eine sofortige Sektor-Rotation (target_offset = 0)! */
            target_offset = 0;
            break;
        }
        current_offset += (uint32_t)sizeof(wal_entry_aligned_t);
    }

    /* Sliding Window Rotation: Sektor voll oder durch Brownout kontaminiert */
    if (target_offset == 0 || target_offset + sizeof(wal_entry_aligned_t) > sec_size) {
        uint32_t new_idx = (active_wal_index + 1) % TOOB_WAL_SECTORS;
        
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

        /* Window ist offiziell geslided */
        active_wal_index = new_idx;
        current_active_header.sequence_id++;
        current_active_header.erase_count++;
        target_offset = (uint32_t)sizeof(wal_sector_header_aligned_t);
    }

    /* Sicheres Schreiben des neuen Intents */
    wal_entry_aligned_t entry;
    memset(&entry, platform->flash->erased_value, sizeof(entry));
    memcpy(&entry.data, new_entry, sizeof(wal_entry_payload_t));
    
    entry.data.magic = WAL_ENTRY_MAGIC;
    size_t crc_len = sizeof(wal_entry_payload_t) - sizeof(uint32_t);
    entry.data.crc32_trailer = compute_wal_crc32((const uint8_t*)&entry.data, crc_len);
    
    platform->wdt->kick();
    return platform->flash->write(wal_sector_addrs[active_wal_index] + target_offset, &entry, sizeof(entry));
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
        new_idx = (active_wal_index + step) % TOOB_WAL_SECTORS;
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
        write_hdr.data.erase_count  = current_active_header.erase_count + 1;
        write_hdr.data.tmr_data = *new_tmr;
        
        /* Safe Trailer */
        write_hdr.data.header_crc32 = compute_wal_crc32((const uint8_t*)&write_hdr.data, sizeof(wal_sector_header_t) - sizeof(uint32_t));
        
        platform->wdt->kick(); /* Nach dem Erase nochmal WDT sichern */
        status = platform->flash->write(wal_sector_addrs[new_idx], &write_hdr, sizeof(write_hdr));
        if (status != BOOT_OK) return status;
    }
    
    /* State Global aktualisieren */
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
        platform->flash->read(wal_sector_addrs[active_wal_index] + current_offset, &entry, sizeof(entry));

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
