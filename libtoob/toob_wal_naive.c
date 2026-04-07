#include "libtoob.h"
#include "toob_internal.h"
#include "libtoob_config_sandbox.h"
#include <string.h>

static const uint32_t wal_sector_addrs[CHIP_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
static const uint32_t wal_sector_sizes[CHIP_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;

toob_status_t toob_wal_naive_append(const toob_wal_entry_payload_t *intent) {
    toob_wal_entry_aligned_t aligned_buf;
    memset(&aligned_buf, 0xFF, sizeof(aligned_buf)); /* P10: Fill padding with Flash-Erased State Defaults */
    memcpy(&aligned_buf.data, intent, sizeof(toob_wal_entry_payload_t));
    
    /* Robustness: Force MAGIC incase the calling OS logic forgot it */
    aligned_buf.data.magic = TOOB_WAL_ENTRY_MAGIC;
    
    /* P10 Robustness: Calculate CRC32 via offsetof to eliminate ABI drift */
    size_t payload_len = offsetof(toob_wal_entry_payload_t, crc32_trailer);
    aligned_buf.data.crc32_trailer = toob_lib_crc32((const uint8_t*)&aligned_buf.data, payload_len);

    toob_wal_sector_header_aligned_t sector_header;
    toob_wal_entry_aligned_t flash_entry;

    uint32_t active_sector_addr = 0;
    uint32_t active_sector_size = 0;
    uint32_t max_seq = 0;
    bool found_active = false;

    /* Schritt 1: O(1) Discovery - Finde den aktiven Sektor mit dem HOECHSTEN sequence_id */
    /* Architektur: Asymmetrisches Flash-Layout Support durch feste Sektor-Nodes aus Config */
    for (uint32_t i = 0; i < CHIP_WAL_SECTORS; i++) {
        uint32_t sector_addr = wal_sector_addrs[i];
        
        if (toob_os_flash_read(sector_addr, (uint8_t*)&sector_header, TOOB_WAL_HEADER_SIZE) != TOOB_OK) {
            continue;
        }
        
        /* TOOB_WAL_SECTOR_MAGIC (0x57414C02) verifiziert den WAL-Sektor Header */
        if (sector_header.head.sector_magic == TOOB_WAL_SECTOR_MAGIC) {
            
            /* Sektor Header CRC vor Corruption-Manipulation durch Brownouts schuetzen */
            size_t head_crc_len = offsetof(toob_wal_sector_header_t, header_crc32);
            uint32_t calc_head_crc = toob_lib_crc32((const uint8_t*)&sector_header.head, head_crc_len);
            
            if (calc_head_crc == sector_header.head.header_crc32) {
                uint32_t seq_id = sector_header.head.sequence_id;
                
                if (!found_active || seq_id > max_seq) {
                    max_seq = seq_id;
                    active_sector_addr = sector_addr;
                    active_sector_size = wal_sector_sizes[i];
                    found_active = true;
                }
            }
        }
    }
    
    if (!found_active) {
        return TOOB_ERR_NOT_FOUND; 
    }
    
    uint32_t last_intent = TOOB_WAL_INTENT_NONE;

    /* Sanitycheck gegen Underflow bei extremen Sektorgroessen (P10) */
    if (active_sector_size < sizeof(toob_wal_entry_aligned_t) + TOOB_WAL_HEADER_SIZE) {
        return TOOB_ERR_FLASH; /* Sector is physically too small for layout */
    }

    /* Schritt 2: Aktiven Sektor scannen nach dem freien Slot (erased state) */
    for (uint32_t offset = TOOB_WAL_HEADER_SIZE; 
         offset <= active_sector_size - sizeof(toob_wal_entry_aligned_t); 
         offset += sizeof(toob_wal_entry_aligned_t)) {
         
         if (toob_os_flash_read(active_sector_addr + offset, (uint8_t*)&flash_entry, sizeof(toob_wal_entry_aligned_t)) != TOOB_OK) {
             return TOOB_ERR_FLASH;
         }
         
         /* Merke den letzten aktiven Intent, um WAL_LOCKED zu detektieren.
          * Security Eval: CRC-32 Validation ist hier ZWINGEND, ansonsten
          * taeuscht uns im Brownout-Fall eine korrupte Magic eine Lockade vor! */
         if (flash_entry.data.magic == TOOB_WAL_ENTRY_MAGIC) {
             uint32_t entry_crc = toob_lib_crc32((const uint8_t*)&flash_entry.data, payload_len);
             if (entry_crc == flash_entry.data.crc32_trailer) {
                 last_intent = flash_entry.data.intent;
             } else {
                 /* P10 RACE-CONDITION DEFENSE: CRC Fail bedeutet undefinierter Brownout.
                  * Wir sperren das WAL radikal, da der zuletzt geschriebene Intent 
                  * ggf. ein UPDATE_PENDING Lock war. (Pessimistic Locking)
                  * Requires hard bootloader reset to fix. */
                 return TOOB_ERR_REQUIRES_RESET;
             }
         } else if (flash_entry.data.magic == CHIP_FLASH_ERASURE_MAPPING) {
             /* OS-API Schutzschaltung (GAP-API): Verhindere, dass das OS ein zweites 
              * Update flusht, wenn der Journal-Ring bereits durch ein unfertiges 
              * Update blockiert ist. */
             if (aligned_buf.data.intent == TOOB_WAL_INTENT_UPDATE_PENDING) {
                 if (last_intent == TOOB_WAL_INTENT_UPDATE_PENDING || 
                     last_intent == TOOB_WAL_INTENT_TXN_BEGIN) {
                     return TOOB_ERR_WAL_LOCKED;
                 }
             }
             
             /* Freier Slot (Erased) gefunden! Naive-Append ausfuehren. 
              * Arch-Note: Dies ist "Best-Effort Durable", nicht strikt atomar
              * aufgrund minimaler C-Level Flash Write-Granularity. Brownout Protection
              * gegen Partial Writes geschieht rein durch den S1 CRC-Check beim Boot. */
             return toob_os_flash_write(active_sector_addr + offset, (const uint8_t*)&aligned_buf, sizeof(toob_wal_entry_aligned_t));
         } else {
             /* 
              * P10 PESSIMISTIC LOCKING: Magic is neither valid NOR erased. 
              * This implies a partially written chunk or sector corruption where we 
              * previously skipped a garbage entry silently. Halt operation!
              */
             return TOOB_ERR_REQUIRES_RESET;
         }
    }
    
    /* Intent kann nicht geschrieben werden, da WAL voll ist.
     * ARCHITEKTUR-BESCHLUSS: Keine Rotation durch das OS! */
    return TOOB_ERR_WAL_FULL; 
}
