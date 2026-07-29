/**
 * @file boot_platform_bringup.c
 * @brief Core Platform Bringup Interpreter (REG-022 / REG-023)
 */

#include "boot_platform_bringup.h"
#include "generated_boot_config.h"

#ifndef BOOT_WDT_TIMEOUT_MS
#define BOOT_WDT_TIMEOUT_MS 2000U
#endif

#ifndef TOOB_DRIVER_UART_BAUDRATE
#define TOOB_DRIVER_UART_BAUDRATE 115200U
#endif

boot_status_t boot_platform_bringup(const boot_platform_t *p,
                                    const bringup_step_t *steps,
                                    size_t n)
{
    if (!p || !steps) {
        return BOOT_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < n; i++) {
        const bringup_step_t *step = &steps[i];
        boot_status_t status = BOOT_OK;

        switch (step->kind) {
        case BOOT_HAL_KIND_CLOCK:
            if (p->clock && p->clock->init) {
                status = p->clock->init();
            }
            break;

        case BOOT_HAL_KIND_FLASH:
            if (p->flash && p->flash->init) {
                status = p->flash->init();
            }
            break;

        case BOOT_HAL_KIND_WDT:
            if (p->wdt && p->wdt->init) {
                status = p->wdt->init(BOOT_WDT_TIMEOUT_MS);
            }
            break;

        case BOOT_HAL_KIND_CRYPTO:
            if (p->crypto && p->crypto->init) {
                status = p->crypto->init();
            }
            break;

        case BOOT_HAL_KIND_CONFIRM:
            if (p->confirm && p->confirm->init) {
                status = p->confirm->init();
            }
            break;

        case BOOT_HAL_KIND_CONSOLE:
            if (p->console && p->console->init) {
                status = p->console->init(TOOB_DRIVER_UART_BAUDRATE);
            }
            break;

        case BOOT_HAL_KIND_SOC:
            if (p->soc && p->soc->init) {
                status = p->soc->init();
            }
            break;

        case BOOT_HAL_KIND_ENTROPY:
            if (p->entropy && p->entropy->init) {
                status = p->entropy->init();
            }
            break;

        case BOOT_HAL_KIND_KEYSTORE:
            if (p->keystore && p->keystore->init) {
                status = p->keystore->init();
            }
            break;

        default:
            status = BOOT_ERR_NOT_SUPPORTED;
            break;
        }

        if (status != BOOT_OK) {
            if (step->mandatory) {
                boot_terminal_halt(p, status, step->panic_site);
            }
        }
    }

    return BOOT_OK;
}
