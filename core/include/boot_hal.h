#ifndef BOOT_HAL_H
#define BOOT_HAL_H

#include "boot_types.h"
#include <stddef.h>

/* 
 * WICHTIG: Die 6 Hardware-Traits (Schicht 1) 
 * Implementiert durch chips/<chip_name>/chip_platform.c
 */

/* ========================================================================= */
/* 1. Flash HAL                                                              */
/* ========================================================================= */
typedef struct {
    boot_status_t (*init)(void);
    boot_status_t (*read)(uint32_t addr, void *buf, size_t len);
    boot_status_t (*write)(uint32_t addr, const void *buf, size_t len);
    boot_status_t (*erase_sector)(uint32_t addr);
    
    uint32_t sector_size;
    uint32_t total_size;
    uint8_t  write_align;
    uint8_t  erased_value;
} flash_hal_t;

/* ========================================================================= */
/* 2. Clock & Reset HAL                                                        */
/* ========================================================================= */
typedef struct {
    boot_status_t      (*init)(void);
    uint32_t           (*get_tick_ms)(void);
    void               (*delay_ms)(uint32_t ms);
    boot_reset_reason_t(*get_reset_reason)(void);
} clock_hal_t;

/* ========================================================================= */
/* 3. Watchdog HAL                                                             */
/* ========================================================================= */
typedef struct {
    boot_status_t (*init)(uint32_t timeout_ms);
    void          (*kick)(void);
    void          (*disable)(void); /* Nur vor Jump zum OS */
} wdt_hal_t;

/* ========================================================================= */
/* 4. Boot Confirm HAL (Handoff Flag Survival)                               */
/* ========================================================================= */
typedef struct {
    boot_status_t (*set_ok)(void);
    bool          (*check_ok)(void);
    void          (*clear)(void);
} confirm_hal_t;

/* ========================================================================= */
/* 5. Crypto HAL (Hardware Acceleration if available)                        */
/* ========================================================================= */
typedef struct {
    boot_status_t (*init)(void);
    boot_status_t (*sha256_feed)(const void *data, size_t len);
    boot_status_t (*sha256_finalize)(uint8_t hash_out[32]);
    /* ed25519 & rng will follow... */
} crypto_hal_t;

/* ========================================================================= */
/* 6. Power HAL (Optional Energy Guard)                                      */
/* ========================================================================= */
typedef struct {
    uint32_t (*get_battery_mv)(void);
    void     (*dummy_load_enable)(bool enable);
} power_hal_t;


/**
 * @brief Global Platform Registry
 */
typedef struct {
    flash_hal_t   *flash;
    clock_hal_t   *clock;
    wdt_hal_t     *wdt;
    confirm_hal_t *confirm;
    crypto_hal_t  *crypto;
    power_hal_t   *power;
} boot_platform_t;

/**
 * @brief Implemented by chips/chip_platform.c
 * @return Registered traits for the specific chip.
 */
boot_platform_t* boot_platform_init(void);

#endif /* BOOT_HAL_H */
