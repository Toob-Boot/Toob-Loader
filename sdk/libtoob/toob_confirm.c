/**
 * @file toob_confirm.c
 * @brief Boot Confirmation — OS-side confirm/recovery intent via Mailbox + RTC.
 *
 * Implements toob_confirm_boot() and toob_recovery_resolved() with:
 *   - zero flash wear on already-COMMITTED boots (CRIT-25),
 *   - strict rejection of boot_nonce == 0 (CRIT-25),
 *   - mandatory error propagation of toob_mailbox_set_confirm() (CRIT-25),
 *   - weak default toob_os_confirm_rtc_write() without chip_config.h coupling (LOW-10).
 */

#include "libtoob.h"
#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#ifdef ADDR_CONFIRM_RTC_RAM
uint64_t mock_rtc_ram = 0;
#endif
#else
#include "generated_boot_config.h"
#endif

#if !defined(ADDR_CONFIRM_RTC_RAM) && defined(CHIP_REG_CONFIRM_STORAGE_BASE)
#define ADDR_CONFIRM_RTC_RAM CHIP_REG_CONFIRM_STORAGE_BASE
#endif

#include "toob_internal.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32) && !defined(__CYGWIN__)
#  define TOOB_WEAK __attribute__((weak))
#else
#  define TOOB_WEAK
#endif

#if !defined(_WIN32) || !defined(TOOB_CUSTOM_CONFIRM_RTC_WRITE)
TOOB_WEAK toob_status_t toob_os_confirm_rtc_write(uint64_t nonce) {
#if defined(ADDR_CONFIRM_RTC_RAM) && !defined(_WIN32) && !defined(__APPLE__) && \
    !defined(__linux__) && !defined(TOOB_HOST_FUZZING)
    volatile uint64_t *rtc_ptr = (volatile uint64_t *)(uintptr_t)ADDR_CONFIRM_RTC_RAM;
    *rtc_ptr = nonce;

#if defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif

    uint64_t rb1 = *rtc_ptr;
    volatile uint32_t rtc_shield_1 = 0U;
    volatile uint32_t rtc_shield_2 = 0U;
    if (rb1 == nonce) {
        rtc_shield_1 = TOOB_OK;
    }

    TOOB_GLITCH_DELAY();

    uint64_t rb2 = *rtc_ptr;
    if (rtc_shield_1 == TOOB_OK && rb2 == nonce) {
        rtc_shield_2 = TOOB_OK;
    }

    if (rtc_shield_1 == TOOB_OK && rtc_shield_2 == TOOB_OK &&
        rtc_shield_1 == rtc_shield_2) {
        return TOOB_OK;
    }
    return TOOB_ERR_VERIFY;
#else
    (void)nonce;
    return TOOB_ERR_NOT_SUPPORTED;
#endif
}
#endif

toob_status_t toob_confirm_boot(void) {
    toob_handoff_t handoff __attribute__((aligned(8)));
    toob_secure_zeroize(&handoff, sizeof(handoff));

    toob_status_t status = toob_get_handoff(&handoff);

    volatile uint32_t get_shield_1 = 0U, get_shield_2 = 0U;
    if (status == TOOB_OK) {
        get_shield_1 = TOOB_OK;
    }
    TOOB_GLITCH_DELAY();
    if (get_shield_1 == TOOB_OK && status == TOOB_OK) {
        get_shield_2 = TOOB_OK;
    }

    if (get_shield_1 != TOOB_OK || get_shield_2 != TOOB_OK ||
        get_shield_1 != get_shield_2) {
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return (status != TOOB_OK) ? status : TOOB_ERR_VERIFY;
    }

    /* CRIT-25: Already-COMMITTED boots are a verified no-op (zero flash wear). */
    volatile uint32_t comm_shield_1 = 0U, comm_shield_2 = 0U;
    if (handoff.magic == TOOB_STATE_COMMITTED) {
        comm_shield_1 = TOOB_OK;
    }
    TOOB_GLITCH_DELAY();
    if (comm_shield_1 == TOOB_OK && handoff.magic == TOOB_STATE_COMMITTED) {
        comm_shield_2 = TOOB_OK;
    }
    if (comm_shield_1 == TOOB_OK && comm_shield_2 == TOOB_OK &&
        comm_shield_1 == comm_shield_2) {
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return TOOB_OK;
    }

    /* CRIT-25: Reject zero boot_nonce on TENTATIVE boots. */
    if (handoff.boot_nonce == 0ULL) {
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return TOOB_ERR_VERIFY;
    }

    /* Optional hardware RTC fast-path (may return TOOB_ERR_NOT_SUPPORTED). */
    toob_status_t rtc_st = toob_os_confirm_rtc_write(handoff.boot_nonce);
    if (rtc_st != TOOB_OK && rtc_st != TOOB_ERR_NOT_SUPPORTED) {
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return rtc_st;
    }

    /* CRIT-25: Mandatory persistent Mailbox confirmation for Stage 0 / cold resets. */
    toob_status_t mb_stat = toob_mailbox_set_confirm(handoff.boot_nonce);

    volatile uint32_t mb_shield_1 = 0U, mb_shield_2 = 0U;
    if (mb_stat == TOOB_OK) {
        mb_shield_1 = TOOB_OK;
    }
    TOOB_GLITCH_DELAY();
    if (mb_shield_1 == TOOB_OK && mb_stat == TOOB_OK) {
        mb_shield_2 = TOOB_OK;
    }

    if (mb_shield_1 == TOOB_OK && mb_shield_2 == TOOB_OK &&
        mb_shield_1 == mb_shield_2) {
        handoff.magic = TOOB_STATE_COMMITTED;
        memset(handoff._padding, 0, sizeof(handoff._padding));
        handoff.crc32_trailer = toob_lib_crc32(
            (const uint8_t *)&handoff, offsetof(toob_handoff_t, crc32_trailer));
        toob_os_lock();
        memcpy(&toob_handoff_state, &handoff, sizeof(toob_handoff_t));
        toob_os_unlock();
        toob_secure_zeroize(&handoff, sizeof(handoff));
        return TOOB_OK;
    }
    toob_secure_zeroize(&handoff, sizeof(handoff));
    return (mb_stat != TOOB_OK) ? mb_stat : TOOB_ERR_FLASH_HW;
}

toob_status_t toob_recovery_resolved(void) {
    toob_status_t status = toob_mailbox_set_recovery_resolved();

    volatile uint32_t shield_1 = 0U, shield_2 = 0U;
    if (status == TOOB_OK) {
        shield_1 = TOOB_OK;
    }
    TOOB_GLITCH_DELAY();
    if (shield_1 == TOOB_OK && status == TOOB_OK) {
        shield_2 = TOOB_OK;
    }

    if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2) {
        return TOOB_OK;
    }
    return (status != TOOB_OK) ? status : TOOB_ERR_FLASH_HW;
}
