#ifndef BOOT_TYPES_H
#define BOOT_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Global standard error/status codes for the bootloader.
 */
typedef enum {
    BOOT_OK            = 0,
    BOOT_ERR_GENERIC   = -1,
    BOOT_ERR_FLASH     = -2,
    BOOT_ERR_MAGIC     = -3,
    BOOT_ERR_VERIFY    = -4,
    BOOT_ERR_MANIFEST  = -5,
    BOOT_ERR_NO_IMAGE  = -6,
    BOOT_ERR_WDT       = -7,
    BOOT_ERR_ROLLBACK  = -8
} boot_status_t;

/**
 * @brief Standardized Reset Reasons abstracted from proprietary HW registers.
 */
typedef enum {
    BOOT_RESET_UNKNOWN = 0,
    BOOT_RESET_POR     = 1,   /* Power-On Reset */
    BOOT_RESET_PIN     = 2,   /* HW Pin Reset (NRST) */
    BOOT_RESET_SW      = 3,   /* Software Reset (NVIC_SystemReset) */
    BOOT_RESET_WDT     = 4,   /* Hardware Watchdog Timeout */
    BOOT_RESET_BROWNOUT= 5    /* Voltage Drop */
} boot_reset_reason_t;

#endif /* BOOT_TYPES_H */
