/**
 * @file boot_platform_bringup.h
 * @brief Core Platform Bringup Interpreter (REG-022 / REG-023)
 *
 * Provides a unified, table-driven HAL bringup procedure enforcing
 * the normative initialization order from docs/hals.md:
 * ① clock → ② flash → ③ wdt → ④ crypto → ⑤ confirm → ⑥ console → ⑦ soc
 */

#ifndef BOOT_PLATFORM_BRINGUP_H
#define BOOT_PLATFORM_BRINGUP_H

#include <stddef.h>
#include <stdbool.h>
#include "boot_hal.h"
#include "boot_panic.h"

typedef enum {
    BOOT_HAL_KIND_CLOCK = 0,
    BOOT_HAL_KIND_FLASH,
    BOOT_HAL_KIND_WDT,
    BOOT_HAL_KIND_CRYPTO,
    BOOT_HAL_KIND_CONFIRM,
    BOOT_HAL_KIND_CONSOLE,
    BOOT_HAL_KIND_SOC,
    BOOT_HAL_KIND_ENTROPY,
    BOOT_HAL_KIND_KEYSTORE,
} boot_hal_kind_t;

typedef struct {
    boot_hal_kind_t kind;
    bool            mandatory;
    uint16_t        panic_site;
} bringup_step_t;

/**
 * @brief Runs platform bringup according to the given step table.
 *
 * @param p     Assembled boot_platform_t pointer
 * @param steps Array of bringup_step_t elements
 * @param n     Number of steps in the array
 * @return BOOT_OK if all mandatory steps succeed. Panics on mandatory failure.
 */
boot_status_t boot_platform_bringup(const boot_platform_t *p,
                                    const bringup_step_t *steps,
                                    size_t n);

#endif /* BOOT_PLATFORM_BRINGUP_H */
