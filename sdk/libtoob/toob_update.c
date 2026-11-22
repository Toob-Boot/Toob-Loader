/**
 * @file toob_update.c
 * @brief Update Registration — validates staging bounds and writes Mailbox request.
 */

#include "libtoob.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif
#include "toob_internal.h"

/* Fixed TBM1 header size (sizeof(tbm1_header_t) == 512 bytes) */
#define TOOB_TBM1_HDR_SIZE 512U

toob_status_t toob_set_next_update(uint32_t manifest_flash_addr) {
    if (manifest_flash_addr == 0xFFFFFFFFU ||
        (manifest_flash_addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
        toob_flash_range_hits_immutable_boot(manifest_flash_addr, TOOB_TBM1_HDR_SIZE)) {
        return TOOB_ERR_INVALID_ARG;
    }

    uint32_t target_addr = CHIP_STAGING_SLOT_ABS_ADDR;
    uint32_t target_size = CHIP_STAGING_SLOT_SIZE;

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    toob_handoff_t handoff __attribute__((aligned(8)));
    toob_status_t st = toob_get_handoff(&handoff);
    uint8_t active_slot = handoff.active_slot;
    toob_secure_zeroize(&handoff, sizeof(handoff));
    if (st != TOOB_OK || active_slot > 1U) {
        return (st != TOOB_OK) ? st : TOOB_ERR_VERIFY;
    }
    if (active_slot == 1U) {
        target_addr = CHIP_APP_SLOT_ABS_ADDR;
        target_size = CHIP_APP_SLOT_SIZE;
    }
#endif

    /* HIGH-22: Strictly require manifest_flash_addr inside inactive staging slot
     * with room for at least a full TBM1 fixed header (overflow-safe). */
    if (target_size < TOOB_TBM1_HDR_SIZE ||
        manifest_flash_addr < target_addr ||
        (manifest_flash_addr - target_addr) > (target_size - TOOB_TBM1_HDR_SIZE)) {
        return TOOB_ERR_INVALID_ARG;
    }

    return toob_mailbox_set_update(manifest_flash_addr);
}
