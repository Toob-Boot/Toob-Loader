/**
 * @file toob_update.c
 * @brief Update Registration — writes a Mailbox request for the Bootloader.
 */

#include "libtoob.h"
#include "toob_internal.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT CHIP_FLASH_WRITE_ALIGN
#endif

toob_status_t toob_set_next_update(uint32_t manifest_flash_addr) {
    if (manifest_flash_addr == 0xFFFFFFFF ||
        (manifest_flash_addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0) {
        return TOOB_ERR_INVALID_ARG;
    }
    return toob_mailbox_set_update(manifest_flash_addr);
}
