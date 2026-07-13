/**
 * @file toob_confirm.c
 * @brief Boot Confirmation — OS-side confirm/recovery intent via Mailbox.
 *
 * Implements toob_confirm_boot() and toob_recovery_resolved().
 * Writes Mailbox records instead of WAL entries. The RTC fast-path
 * remains for hardware with backup registers.
 */

#include "libtoob.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#include "toob_internal.h"
#include <stddef.h>

#ifdef ADDR_CONFIRM_RTC_RAM
uint64_t mock_rtc_ram = 0;
#endif

toob_status_t toob_confirm_boot(void) {
    toob_handoff_t handoff __attribute__((aligned(8)));
    toob_secure_zeroize(&handoff, sizeof(handoff));

    toob_status_t status = toob_get_handoff(&handoff);

    volatile uint32_t get_shield_1 = 0, get_shield_2 = 0;
    if (status == TOOB_OK)
        get_shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (get_shield_1 == TOOB_OK && status == TOOB_OK)
        get_shield_2 = TOOB_OK;

    if (get_shield_1 != TOOB_OK || get_shield_2 != TOOB_OK ||
        get_shield_1 != get_shield_2) {
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return (status != TOOB_OK) ? status : TOOB_ERR_VERIFY;
    }

#ifdef ADDR_CONFIRM_RTC_RAM
    /* RTC fast-path: write nonce to backup register + mailbox. */
    volatile uint64_t *rtc_ptr = (volatile uint64_t *)ADDR_CONFIRM_RTC_RAM;
    *rtc_ptr = handoff.boot_nonce;

#if defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif

    uint64_t verified_nonce = *rtc_ptr;

    volatile uint32_t rtc_shield_1 = 0, rtc_shield_2 = 0;
    if (verified_nonce == handoff.boot_nonce)
        rtc_shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (rtc_shield_1 == TOOB_OK && verified_nonce == handoff.boot_nonce)
        rtc_shield_2 = TOOB_OK;

    /* Mailbox write (fire-and-forget alongside RTC). */
    (void)toob_mailbox_set_confirm(handoff.boot_nonce);

    toob_secure_zeroize(&handoff, sizeof(handoff));

    if (rtc_shield_1 != TOOB_OK || rtc_shield_2 != TOOB_OK ||
        rtc_shield_1 != rtc_shield_2) {
        return TOOB_ERR_FLASH_HW;
    }
    return TOOB_OK;
#else
    /* Mailbox-only path. */
    toob_status_t mb_stat = toob_mailbox_set_confirm(handoff.boot_nonce);

    volatile uint32_t mb_shield_1 = 0, mb_shield_2 = 0;
    if (mb_stat == TOOB_OK)
        mb_shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (mb_shield_1 == TOOB_OK && mb_stat == TOOB_OK)
        mb_shield_2 = TOOB_OK;

    toob_secure_zeroize(&handoff, sizeof(handoff));

    if (mb_shield_1 == TOOB_OK && mb_shield_2 == TOOB_OK &&
        mb_shield_1 == mb_shield_2) {
        return TOOB_OK;
    }
    return (mb_stat != TOOB_OK) ? mb_stat : TOOB_ERR_FLASH_HW;
#endif
}

toob_status_t toob_recovery_resolved(void) {
    toob_status_t status = toob_mailbox_set_recovery_resolved();

    volatile uint32_t shield_1 = 0, shield_2 = 0;
    if (status == TOOB_OK)
        shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (shield_1 == TOOB_OK && status == TOOB_OK)
        shield_2 = TOOB_OK;

    if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2)
        return TOOB_OK;
    return (status != TOOB_OK) ? status : TOOB_ERR_FLASH_HW;
}