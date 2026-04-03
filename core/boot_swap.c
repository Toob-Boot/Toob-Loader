/*
 * Toob-Boot Core File: boot_swap.c
 * Relevant Spec-Dateien:
 * - docs/toobfuzzer_integration.md (Fuzzing parameters, Alignment limitations)
 * - docs/structure_plan.md
 */

#include "boot_swap.h"
#include "boot_journal.h"
#include "boot_config_mock.h"
#include <string.h>

/**
 * @brief Static swap buffer used across swap and rollback operations.
 *        Guarantees avoiding dynamic allocations.
 *        Note: Consumes 4KB (or CHIP_FLASH_MAX_SECTOR_SIZE) of BSS section, 
 *        which is significant but required for atomic in-place updates.
 */
static uint8_t swap_buf[CHIP_FLASH_MAX_SECTOR_SIZE];

/**
 * @brief Performs a WDT-aware, P10-compliant erase over a range of flash.
 *        (GAP-C02): Avoids monolithic erases larger than CHIP_FLASH_MAX_SECTOR_SIZE by iterating
 *        dynamically over the specific hardware sector boundaries.
 *        Safely suspends the WDT if the hardware strictly mandates a single monolithic
 *        erase that exceeds the timeout.
 * 
 * @param platform Hardware HAL abstraction
 * @param addr     Start address to erase
 * @param length   Total length to erase (must align with sector ends)
 * @return boot_status_t BOOT_OK on success, error otherwise.
 */
static boot_status_t boot_swap_erase_safe(const boot_platform_t *platform, uint32_t addr, size_t length) {
    if (!platform || !platform->flash || !platform->flash->erase_sector || !platform->flash->get_sector_size) {
        return BOOT_ERR_INVALID_ARG;
    }

    if (length > UINT32_MAX - addr) {
        return BOOT_ERR_INVALID_ARG;
    }

    uint32_t current_addr = addr;
    uint32_t end_addr = addr + length;

    /* P10 Rule 2: Bound loops. Max erases we will ever do is Total Flash Size / Min Sector Size.
       Since we don't have access to total flash size without querying, we bound to a reasonable
       max retry limit to prevent infinite loops (e.g. 100000 sectors). */
    uint32_t loop_guard = 0;
    const uint32_t MAX_ERASE_LOOPS = 100000; 

    while (current_addr < end_addr) {
        if (loop_guard++ > MAX_ERASE_LOOPS) {
            return BOOT_ERR_FLASH_HW; /* P10 compliance guard */
        }

        size_t sec_size = 0;
        boot_status_t status = platform->flash->get_sector_size(current_addr, &sec_size);
        if (status != BOOT_OK || sec_size == 0) {
            return BOOT_ERR_FLASH_HW; /* Faulty HAL or end of flash */
        }

        if (sec_size > CHIP_FLASH_MAX_SECTOR_SIZE) {
            /* Hardware sector represents a monolithic block larger than our buffer guarantee. 
               We must suspend the WDT entirely because the erase command will exceed P10 WDT limits. */
            if (platform->wdt && platform->wdt->suspend_for_critical_section) {
                platform->wdt->suspend_for_critical_section();
            }
            
            /* platform->flash->erase_sector(addr) resolves invalid sec_size param usage */
            status = platform->flash->erase_sector(current_addr);
            
            if (platform->wdt && platform->wdt->resume) {
                platform->wdt->resume();
            }
        } else {
            /* Standard bounded erase over a known valid sector boundary */
            if (platform->wdt) {
                platform->wdt->kick();
            }
            
            /* platform->flash->erase_sector(addr) resolves invalid sec_size param usage */
            status = platform->flash->erase_sector(current_addr);
            
            if (platform->wdt) {
                platform->wdt->kick();
            }
        }

        if (status != BOOT_OK) {
            return status;
        }
        
        current_addr += sec_size;
    }
    
    return BOOT_OK;
}

typedef enum {
    SWAP_STATE_NORMAL = 0,
    SWAP_STATE_READ_ONLY = 1
} swap_state_t;

/** @brief In-memory guard for EOL survival mode (GAP-C07) */
static swap_state_t current_swap_state = SWAP_STATE_NORMAL;

/**
 * @brief (GAP-C07) Impements Swap-Buffer EOL Survival Mode.
 *        Reads the TMR data from the WAL. If the `swap_buffer_erase_counter` exceeds
 *        `platform->flash->max_erase_cycles`, the system permanently (until reboot) locks
 *        all `boot_swap` operations to prevent silicon failure.
 */
static boot_status_t boot_swap_check_eol_survival(const boot_platform_t *platform) {
    if (current_swap_state == SWAP_STATE_READ_ONLY) {
        return BOOT_ERR_COUNTER_EXHAUSTED;
    }

    if (!platform || !platform->flash) {
        return BOOT_ERR_INVALID_ARG;
    }

    /* We need to fetch the erase counter natively tracked in the WAL TMR payload */
    wal_tmr_payload_t tmr;
    boot_status_t tmr_status = boot_journal_get_tmr(platform, &tmr);
    if (tmr_status != BOOT_OK) {
        return tmr_status;
    }

    /* If the flash specifies a distinct limit, enforce it rigidly.
       Since we use a static RAM buffer for swap_buf, the actual physical flash wear 
       is primarily concentrated over the App-Slot which receives the continuous overwrites. */
    if (platform->flash->max_erase_cycles > 0) {
        if (tmr.app_slot_erase_counter >= platform->flash->max_erase_cycles) {
            current_swap_state = SWAP_STATE_READ_ONLY;
            return BOOT_ERR_COUNTER_EXHAUSTED;
        }
    }

    return BOOT_OK;
}

boot_status_t boot_swap_apply(const boot_platform_t *platform, uint32_t src_base, uint32_t dest_base, uint32_t length) {
    if (!platform || !platform->flash || !platform->flash->read || !platform->flash->write || !platform->flash->get_sector_size) {
        return BOOT_ERR_INVALID_ARG;
    }
    
    if (length > UINT32_MAX - src_base || length > UINT32_MAX - dest_base) {
        return BOOT_ERR_INVALID_ARG;
    }
    
    if (length == 0) {
        return BOOT_OK; /* Nothing to swap */
    }

    /* Validates that address and len satisfy platform->flash->write_align. */
    if (platform->flash->write_align > 0) {
        if ((src_base % platform->flash->write_align != 0) || 
            (dest_base % platform->flash->write_align != 0) || 
            (length % platform->flash->write_align != 0)) {
            return BOOT_ERR_FLASH_ALIGN;
        }
    }

    /* Check EOL survival state before beginning heavy flash operations */
    boot_status_t eol_status = boot_swap_check_eol_survival(platform);
    if (eol_status != BOOT_OK) {
        return eol_status;
    }

    uint32_t current_offset = 0;
    const uint32_t MAX_ERASE_LOOPS = 100000;
    uint32_t loop_guard = 0;
    uint32_t erased_sectors_count = 0;

    while (current_offset < length) {
        if (loop_guard++ > MAX_ERASE_LOOPS) {
            return BOOT_ERR_FLASH_HW; /* P10 compliance guard */
        }

        uint32_t current_src = src_base + current_offset;
        uint32_t current_dest = dest_base + current_offset;

        /* 1. Query get_sector_size(dest). */
        size_t dest_sec_size = 0;
        boot_status_t status = platform->flash->get_sector_size(current_dest, &dest_sec_size);
        if (status != BOOT_OK || dest_sec_size == 0) {
            return BOOT_ERR_FLASH_HW;
        }

        /* Strict runtime sector alignment check for destination.
           Protects against erasing neighbor partitions. (Source read does not mandate strict parity) */
        if (current_dest % dest_sec_size != 0) {
            return BOOT_ERR_FLASH_ALIGN;
        }

        /* Sector cannot be larger than our static swap buffer */
        if (dest_sec_size > CHIP_FLASH_MAX_SECTOR_SIZE) {
            return BOOT_ERR_FLASH_HW; 
        }

        size_t chunk_len = dest_sec_size;
        if (current_offset + chunk_len > length) {
            chunk_len = length - current_offset; 
            /* Enforce write_align for the final partial sector write */
            if (platform->flash->write_align > 0 && (chunk_len % platform->flash->write_align != 0)) {
                return BOOT_ERR_FLASH_ALIGN;
            }
        }

        /* 2. Read from src into local static swap_buf. */
        status = platform->flash->read(current_src, swap_buf, chunk_len);
        if (status != BOOT_OK) {
            return status;
        }

        /* (1) invoke WDT kick after reading into swap_buf */
        if (platform->wdt) {
            platform->wdt->kick();
        }

        /* 3. Erase dest sector (with WDT kicks via boot_swap_erase_safe). */
        status = boot_swap_erase_safe(platform, current_dest, dest_sec_size);
        if (status != BOOT_OK) {
            return status;
        }
        erased_sectors_count++;

        /* (2) invoke WDT kick after erasing the destination sector */
        if (platform->wdt) {
            platform->wdt->kick();
        }

        /* 4. Write swap_buf to dest sector. */
        status = platform->flash->write(current_dest, swap_buf, chunk_len);
        if (status != BOOT_OK) {
            return status;
        }

        /* (3) invoke WDT kick after writing the buffer to the destination. */
        if (platform->wdt) {
            platform->wdt->kick();
        }

        /* 5. Read-Back Verify (Zero allocation via 32-byte stack window).
           Detects silent write-errors or ECC weaknesses instantly. */
        uint32_t verify_offset = 0;
        uint8_t verify_buf[32];
        while (verify_offset < chunk_len) {
            /* WDT Kick to prevent starvation on very large sectors / slow flash (GAP-C02) */
            if (platform->wdt) {
                platform->wdt->kick();
            }
            
            uint32_t cmp_len = (chunk_len - verify_offset > sizeof(verify_buf)) ? sizeof(verify_buf) : (chunk_len - verify_offset);
            status = platform->flash->read(current_dest + verify_offset, verify_buf, cmp_len);
            if (status != BOOT_OK || memcmp(swap_buf + verify_offset, verify_buf, cmp_len) != 0) {
                return BOOT_ERR_FLASH_HW; /* Silent corruption detected in hardware! */
            }
            verify_offset += cmp_len;
        }

        current_offset += chunk_len;
    }

    /* GAP-C07: Wear Leveling Tracking. Update the TMR counters to reflect the physical wear on flash.
       We primarily increment the app_slot_erase_counter since boot_swap_apply() typically overwrites the App slot. */
    if (erased_sectors_count > 0) {
        wal_tmr_payload_t tmr;
        boot_status_t tmr_status = boot_journal_get_tmr(platform, &tmr);
        if (tmr_status == BOOT_OK) {
            tmr.app_slot_erase_counter += erased_sectors_count;
            
            boot_status_t update_status = boot_journal_update_tmr(platform, &tmr);
            if (update_status != BOOT_OK) {
                return update_status; /* Wear leveling desync! Bubble the error up. */
            }
        } else {
            return tmr_status;
        }
    }

    return BOOT_OK;
}
