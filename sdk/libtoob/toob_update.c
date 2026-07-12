/**
 * @file toob_update.c
 * @brief Update Registration — writes a Mailbox request for the Bootloader.
 */

#include "libtoob.h"
#include "toob_internal.h"
#include "libtoob_config_sandbox.h"

toob_status_t toob_set_next_update(uint32_t manifest_flash_addr) {
    if (manifest_flash_addr == 0xFFFFFFFF ||
        (manifest_flash_addr % CHIP_FLASH_WRITE_ALIGN) != 0) {
        return TOOB_ERR_INVALID_ARG;
    }
    return toob_mailbox_set_update(manifest_flash_addr);
}
