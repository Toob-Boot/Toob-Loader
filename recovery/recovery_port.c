/**
 * @file recovery_port.c
 * @brief Platform Porting Hooks implementation for Recovery OS (Multi-Architecture).
 */

#include "recovery_port.h"
#include "libtoob.h"
#include "boot_flash_guard.h"
#include <string.h>

#ifdef TOOB_HOST_FUZZING
#include <stdio.h>
#include <stdlib.h>

/* --- Host-side Mock Serial Console --- */

toob_status_t recovery_serial_init(void) {
    return TOOB_OK;
}

toob_status_t recovery_serial_getchar(uint8_t *out, uint32_t timeout_ms) {
    (void)timeout_ms;
    int c = getchar();
    if (c == EOF) {
        return TOOB_ERR_TIMEOUT;
    }
    *out = (uint8_t)c;
    return TOOB_OK;
}

void recovery_serial_putchar(char c) {
    putchar(c);
    fflush(stdout);
}

void recovery_serial_print(const char *str) {
    while (*str) {
        recovery_serial_putchar(*str++);
    }
}

_Noreturn void recovery_system_reboot(void) {
    recovery_serial_print("[REC] system reboot triggered (exit)\n");
    exit(0);
}

/* --- Host-side Mock Flash Implementation --- */

static uint8_t mock_flash_mem[16 * 1024 * 1024]; /* 16MB mock flash */

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    if (addr > sizeof(mock_flash_mem) || len > sizeof(mock_flash_mem) - addr) {
        return TOOB_ERR_FLASH;
    }
    memcpy(buf, &mock_flash_mem[addr], len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    if (boot_flash_range_hits_immutable_boot(addr, len) ||
        addr > sizeof(mock_flash_mem) || len > sizeof(mock_flash_mem) - addr) {
        return TOOB_ERR_FLASH;
    }
    for (uint32_t i = 0; i < len; i++) {
        mock_flash_mem[addr + i] &= buf[i];
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (boot_flash_range_hits_immutable_boot(addr, len) ||
        addr > sizeof(mock_flash_mem) || len > sizeof(mock_flash_mem) - addr) {
        return TOOB_ERR_FLASH;
    }
    memset(&mock_flash_mem[addr], 0xFF, len);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    (void)ctx;
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    (void)ctx; (void)data; (void)len;
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    (void)ctx;
    memset(out_hash, 0, 32);
    return TOOB_OK;
}

#else
/* --- Target-Independent HAL Delegation --- */
#include "boot_types.h"
#include "boot_hal.h"
#include "boot_state.h"
#include "boot_ct_utils.h"

#define REC_REBOOT_WDT_MS     5U
#define REC_GETCHAR_SLICE_MS  250U

static const boot_platform_t *g_platform = NULL;

static inline void recovery_wdt_kick(void) {
    if (g_platform && g_platform->wdt && g_platform->wdt->kick) {
        g_platform->wdt->kick();
    }
}

toob_status_t recovery_serial_init(void) {
    return TOOB_OK;
}

toob_status_t recovery_serial_getchar(uint8_t *out, uint32_t timeout_ms) {
    if (!g_platform || !g_platform->console || !g_platform->console->getchar) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    uint32_t remaining = timeout_ms;
    do {
        recovery_wdt_kick();
        uint32_t slice = (remaining > REC_GETCHAR_SLICE_MS) ? REC_GETCHAR_SLICE_MS : remaining;
        if (g_platform->console->getchar(out, slice) == BOOT_OK) {
            recovery_wdt_kick();
            return TOOB_OK;
        }
        remaining -= slice;
    } while (remaining > 0U);
    return TOOB_ERR_TIMEOUT;
}

void recovery_serial_putchar(char c) {
    if (g_platform && g_platform->console && g_platform->console->putchar) {
        g_platform->console->putchar(c);
    }
}

void recovery_serial_print(const char *str) {
    if (g_platform && g_platform->console && g_platform->console->putchar) {
        while (*str) {
            g_platform->console->putchar(*str++);
        }
    }
}

_Noreturn void recovery_system_reboot(void) {
    if (g_platform && g_platform->console && g_platform->console->flush) {
        g_platform->console->flush();
    }
    if (g_platform && g_platform->clock && g_platform->clock->deinit) {
        g_platform->clock->deinit();
    }
#if defined(__ARM_ARCH) && (__ARM_ARCH >= 6)
    /* Architectural ARMv6-M/v7-M/v8-M SCB->AIRCR SYSRESETREQ */
    *(volatile uint32_t *)(uintptr_t)0xE000ED0CU = 0x05FA0004U;
    __asm__ volatile("dsb sy" ::: "memory");
#endif
    /* Arm hardware WDT with minimum timeout to trigger clean system reset */
    if (g_platform && g_platform->wdt && g_platform->wdt->init) {
        (void)g_platform->wdt->init(REC_REBOOT_WDT_MS);
    }
    while (1) {
        BOOT_GLITCH_DELAY();
    }
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->read) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    recovery_wdt_kick();
    boot_status_t err = g_platform->flash->read(addr, buf, len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->write) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    recovery_wdt_kick();
    boot_status_t err = boot_flash_write_guarded(g_platform->flash, addr, buf, len);
    recovery_wdt_kick();
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->erase_sector || !g_platform->flash->get_sector_size) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    if (boot_flash_range_hits_immutable_boot(addr, len)) {
        return TOOB_ERR_FLASH;
    }
    uint32_t offset = 0U;
    while (offset < len) {
        size_t sector_size = 0U;
        if (UINT32_MAX - addr < offset) {
            return TOOB_ERR_FLASH;
        }
        if (g_platform->flash->get_sector_size(addr + offset, &sector_size) != BOOT_OK ||
            sector_size == 0U || sector_size > (size_t)UINT32_MAX) {
            return TOOB_ERR_FLASH;
        }
        recovery_wdt_kick();
        boot_status_t err = boot_flash_erase_sector_guarded(g_platform->flash, addr + offset);
        recovery_wdt_kick();
        if (err != BOOT_OK) {
            return TOOB_ERR_FLASH;
        }
        if (UINT32_MAX - offset < (uint32_t)sector_size) {
            break;
        }
        offset += (uint32_t)sector_size;
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
#ifdef TOOB_RECOVERY_HASH_NONE
    return TOOB_ERR_NOT_SUPPORTED;
#else
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_init) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->crypto->hash_init(ctx->opaque, sizeof(ctx->opaque));
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
#endif
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
#ifdef TOOB_RECOVERY_HASH_NONE
    (void)len;
    return TOOB_ERR_NOT_SUPPORTED;
#else
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_update) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    recovery_wdt_kick();
    boot_status_t err = g_platform->crypto->hash_update(ctx->opaque, data, len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
#endif
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
#ifdef TOOB_RECOVERY_HASH_NONE
    return TOOB_ERR_NOT_SUPPORTED;
#else
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_finish) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    size_t digest_len = 32;
    boot_status_t err = g_platform->crypto->hash_finish(ctx->opaque, out_hash, &digest_len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
#endif
}

#if !defined(TOOB_MOCK_TEST) && !defined(TOOB_HOST_FUZZING) && \
    !defined(_WIN32) && !defined(__linux__) && !defined(__APPLE__) && \
    !defined(__CPROVER__)
uintptr_t __stack_chk_guard = 0x3EC07E51U;

void __stack_chk_fail(void);

void __stack_chk_fail(void) {
    recovery_system_reboot();
}
#endif

boot_status_t boot_main(const boot_platform_t *platform, boot_target_config_t *target, const uint32_t seal_key[4]);
_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason);
_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason, uint16_t site_id);
void toob_ecc_trap(void);
void boot_secure_zeroize(void *v, size_t n);

boot_status_t boot_main(const boot_platform_t *platform, boot_target_config_t *target, const uint32_t seal_key[4]) {
    g_platform = platform;
    (void)target;
    (void)seal_key;
    extern int recovery_main(void);
    (void)recovery_main();
    recovery_system_reboot();
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)platform;
    (void)reason;
    recovery_serial_print("[REC] PANIC\r\n");
    recovery_system_reboot();
}

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason, uint16_t site_id) {
    (void)site_id;
    boot_panic(platform, reason);
}

void toob_ecc_trap(void) {
    recovery_system_reboot();
}

void boot_secure_zeroize(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}
#endif
