/**
 * @file recovery_port.c
 * @brief Platform Porting Hooks implementation for Recovery OS.
 */

#include "recovery_port.h"
#include "libtoob.h"
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
    if (addr > sizeof(mock_flash_mem) || len > sizeof(mock_flash_mem) - addr) {
        return TOOB_ERR_FLASH;
    }
    for (uint32_t i = 0; i < len; i++) {
        mock_flash_mem[addr + i] &= buf[i];
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (addr > sizeof(mock_flash_mem) || len > sizeof(mock_flash_mem) - addr) {
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
/* --- Target Independent HAL Delegation --- */
#include "boot_types.h"
#include "boot_hal.h"
#include "boot_state.h"

static const boot_platform_t *g_platform = NULL;

toob_status_t recovery_serial_init(void) {
    return TOOB_OK;
}

toob_status_t recovery_serial_getchar(uint8_t *out, uint32_t timeout_ms) {
    if (!g_platform || !g_platform->console || !g_platform->console->getchar) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->console->getchar(out, timeout_ms);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_TIMEOUT;
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
    void (*trap)(void) = NULL;
    trap();
    while (1);
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->read) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->flash->read(addr, buf, len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->write) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->flash->write(addr, buf, len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (!g_platform || !g_platform->flash || !g_platform->flash->erase_sector || !g_platform->flash->get_sector_size) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    uint32_t offset = 0;
    while (offset < len) {
        size_t sector_size = 4096;
        (void)g_platform->flash->get_sector_size(addr + offset, &sector_size);
        if (sector_size == 0) {
            sector_size = 4096;
        }
        boot_status_t err = g_platform->flash->erase_sector(addr + offset);
        if (err != BOOT_OK) {
            return TOOB_ERR_FLASH;
        }
        offset += (uint32_t)sector_size;
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx) {
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_init) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->crypto->hash_init(ctx->opaque, sizeof(ctx->opaque));
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len) {
    if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_update) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    boot_status_t err = g_platform->crypto->hash_update(ctx->opaque, data, len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]) {
    if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
    if (!g_platform || !g_platform->crypto || !g_platform->crypto->hash_finish) {
        return TOOB_ERR_NOT_SUPPORTED;
    }
    size_t digest_len = 32;
    boot_status_t err = g_platform->crypto->hash_finish(ctx->opaque, out_hash, &digest_len);
    return (err == BOOT_OK) ? TOOB_OK : TOOB_ERR_NOT_SUPPORTED;
}

boot_status_t boot_main(const boot_platform_t *platform, boot_target_config_t *target, const uint32_t seal_key[4]);
void boot_panic(const boot_platform_t *platform, boot_status_t reason);
void toob_ecc_trap(void);
void boot_secure_zeroize(void *v, size_t n);

boot_status_t boot_main(const boot_platform_t *platform, boot_target_config_t *target, const uint32_t seal_key[4]) {
    g_platform = platform;
    (void)target;
    (void)seal_key;
    extern int recovery_main(void);
    (void)recovery_main();
    while (1);
    return BOOT_OK;
}

void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)platform;
    (void)reason;
    recovery_serial_print("[REC] PANIC\r\n");
    recovery_system_reboot();
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
