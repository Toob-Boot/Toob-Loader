/**
 * @file app_main.c
 * @brief Bare-Metal ESP32-S3 (Xtensa LX7) Guest Firmware for Full-System QEMU E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS RTC RAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: RTC nonce + Flash Mailbox)
 *   - Streaming OTA ingestion (toob_ota_begin / process_chunk / finalize)
 *   - Unconfirmed firmware hang / crash for Hardware TIMG0 WDT Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "esp_common.h"
#include "chip_config.h"
#include "sha256.h"

#define TOOB_STR_H(x) #x
#define TOOB_STR(x)   TOOB_STR_H(x)
#ifndef APP_VERSION_RAW
#define APP_VERSION_RAW 1.0.0
#endif
#define APP_VERSION_STR TOOB_STR(APP_VERSION_RAW)

#ifndef APP_CRASH_ON_BOOT
#define APP_CRASH_ON_BOOT 0
#endif

typedef struct {
    char version[16];
    uint32_t crash_on_boot;
} app_rom_meta_t;

__attribute__((section(".rodata.app_meta"), used))
static const volatile app_rom_meta_t k_app_meta = {
    .version = APP_VERSION_STR,
    .crash_on_boot = (uint32_t)APP_CRASH_ON_BOOT,
};

extern uint32_t _siiram;
extern uint32_t _iram_start;
extern uint32_t _iram_end;
extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;
extern const uint32_t _app_vecbase[];

void _app_start(void);
void __attribute__((noreturn)) _app_c_init(void);

/* ============================================================================
 * Xtensa LX7 Windowed ABI Entry & IRAM Window Spill/Fill Vector Table
 * ============================================================================ */

__asm__(
    ".section .app_entry, \"ax\"\n"
    ".global _app_start\n"
    ".type _app_start, @function\n"
    ".align 4\n"
    "_app_start:\n"
    "    j .L_app_entry_init\n"
    "    .align 4\n"
    ".L_app_lit_rom_vec:\n"
    "    .word 0x40000000\n"
    ".L_app_lit_ps:\n"
    "    .word 0x0004002F\n"
    ".L_app_lit_sp:\n"
    "    .word _stack_top\n"
    ".L_app_lit_c_init:\n"
    "    .word _app_c_init\n"
    ".L_app_entry_init:\n"
    "    l32r a0, .L_app_lit_rom_vec\n"
    "    wsr a0, vecbase\n"
    "    isync\n"
    "    movi a0, 0\n"
    "    wsr a0, windowbase\n"
    "    rsync\n"
    "    movi a0, 1\n"
    "    wsr a0, windowstart\n"
    "    rsync\n"
    "    l32r a0, .L_app_lit_ps\n"
    "    wsr a0, ps\n"
    "    rsync\n"
    "    l32r a1, .L_app_lit_sp\n"
    "    l32r a4, .L_app_lit_c_init\n"
    "    callx4 a4\n"
    "1:  j 1b\n"
    ".size _app_start, . - _app_start\n"
    ".previous\n"
);

__asm__(
    ".section .iram1.vectors, \"ax\"\n"
    ".global _app_vecbase\n"
    ".balign 1024\n"
    "_app_vecbase:\n"
    "    .org _app_vecbase + 0x000\n"
    "    s32e    a0, a5, -16\n"
    "    s32e    a1, a5, -12\n"
    "    s32e    a2, a5, -8\n"
    "    s32e    a3, a5, -4\n"
    "    rfwo\n"
    "    .org _app_vecbase + 0x040\n"
    "    l32e    a0, a5, -16\n"
    "    l32e    a1, a5, -12\n"
    "    l32e    a2, a5, -8\n"
    "    l32e    a3, a5, -4\n"
    "    rfwu\n"
    "    .org _app_vecbase + 0x080\n"
    "    s32e    a0, a9, -16\n"
    "    l32e    a0, a1, -12\n"
    "    s32e    a1, a9, -12\n"
    "    s32e    a2, a9, -8\n"
    "    s32e    a3, a9, -4\n"
    "    s32e    a4, a0, -32\n"
    "    s32e    a5, a0, -28\n"
    "    s32e    a6, a0, -24\n"
    "    s32e    a7, a0, -20\n"
    "    rfwo\n"
    "    .org _app_vecbase + 0x0C0\n"
    "    l32e    a0, a9, -16\n"
    "    l32e    a1, a9, -12\n"
    "    l32e    a2, a9, -8\n"
    "    l32e    a7, a1, -12\n"
    "    l32e    a3, a9, -4\n"
    "    l32e    a4, a7, -32\n"
    "    l32e    a5, a7, -28\n"
    "    l32e    a6, a7, -24\n"
    "    l32e    a7, a7, -20\n"
    "    rfwu\n"
    "    .org _app_vecbase + 0x100\n"
    "    s32e    a0, a13, -16\n"
    "    l32e    a0, a1, -12\n"
    "    s32e    a1, a13, -12\n"
    "    s32e    a2, a13, -8\n"
    "    s32e    a3, a13, -4\n"
    "    s32e    a4, a0, -48\n"
    "    s32e    a5, a0, -44\n"
    "    s32e    a6, a0, -40\n"
    "    s32e    a7, a0, -36\n"
    "    s32e    a8, a0, -32\n"
    "    s32e    a9, a0, -28\n"
    "    s32e    a10, a0, -24\n"
    "    s32e    a11, a0, -20\n"
    "    rfwo\n"
    "    .org _app_vecbase + 0x140\n"
    "    l32e    a0, a13, -16\n"
    "    l32e    a1, a13, -12\n"
    "    l32e    a2, a13, -8\n"
    "    l32e    a11, a1, -12\n"
    "    l32e    a3, a13, -4\n"
    "    l32e    a4, a11, -48\n"
    "    l32e    a5, a11, -44\n"
    "    l32e    a6, a11, -40\n"
    "    l32e    a7, a11, -36\n"
    "    l32e    a8, a11, -32\n"
    "    l32e    a9, a11, -28\n"
    "    l32e    a10, a11, -24\n"
    "    l32e    a11, a11, -20\n"
    "    rfwu\n"
    "    .org _app_vecbase + 0x180\n"
    "1:  j 1b\n"
    "    .org _app_vecbase + 0x300\n"
    "2:  j 2b\n"
    "    .org _app_vecbase + 0x340\n"
    "3:  j 3b\n"
    "    .org _app_vecbase + 0x3C0\n"
    "4:  j 4b\n"
    "    .org _app_vecbase + 0x400\n"
    ".previous\n"
);

/* ============================================================================
 * Bare-metal UART0 + TIMG0 WDT Helpers
 * ============================================================================ */

#define UART0_FIFO_REG    (CHIP_REG_UART0_BASE + 0x00U)
#define UART0_STATUS_REG  (CHIP_REG_UART0_BASE + 0x1CU)

__attribute__((section(".iram1.text")))
static void wdt_kick(void)
{
    REG_WRITE(CHIP_REG_TIMG0_WDT_WPROTECT, CHIP_VAL_WDT_UNLOCK);
    REG_WRITE(CHIP_REG_TIMG0_WDT_FEED, 1U);
    REG_WRITE(CHIP_REG_TIMG0_WDT_WPROTECT, 0U);
}

static inline void uart_putc(char c)
{
    while (((REG_READ(UART0_STATUS_REG) >> 16) & 0xFFU) >= 120U) {
    }
    REG_WRITE(UART0_FIFO_REG, (uint32_t)(uint8_t)c);
}

static inline void uart_tx_drain(void)
{
    while (((REG_READ(UART0_STATUS_REG) >> 16) & 0xFFU) != 0U) {
    }
}

static void uart_puts(const char *s)
{
    while (*s != '\0') {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

static void uart_put_dec(uint32_t val)
{
    char buf[12];
    int idx = 0;
    if (val == 0U) {
        uart_putc('0');
        return;
    }
    while (val > 0U) {
        buf[idx++] = (char)('0' + (val % 10U));
        val /= 10U;
    }
    while (idx > 0) {
        uart_putc(buf[--idx]);
    }
}

static void uart_puts_volatile(const volatile char *s)
{
    while (*s != '\0') {
        char c = *s++;
        if (c == '\n') {
            uart_putc('\r');
        }
        uart_putc(c);
    }
}

static uint8_t uart_getc_wdt_safe(void)
{
    uint32_t spin = 0U;
    for (;;) {
        if ((REG_READ(UART0_STATUS_REG) & 0xFFU) > 0U) {
            return (uint8_t)(REG_READ(UART0_FIFO_REG) & 0xFFU);
        }
        if ((++spin & 0xFFFFU) == 0U) {
            wdt_kick();
        }
    }
}

static size_t uart_read_line(char *buf, size_t max_len)
{
    size_t pos = 0U;
    while (pos + 1U < max_len) {
        char c = (char)uart_getc_wdt_safe();
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            break;
        }
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return pos;
}

static uint32_t parse_u32_dec(const char *s)
{
    uint32_t v = 0U;
    while (*s >= '0' && *s <= '9') {
        v = (v * 10U) + (uint32_t)(*s - '0');
        s++;
    }
    return v;
}

/* ============================================================================
 * libtoob OS Porting Layer (ESP32-S3 Physical SPI Flash via BootROM)
 * ============================================================================ */

__attribute__((section(".iram1.text"), noinline))
static void app_sync_cache(uint32_t addr, uint32_t len)
{
    if (len == 0U || addr >= CHIP_FLASH_TOTAL_SIZE) {
        return;
    }
    uint32_t aligned_start = addr & ~63U;
    uint32_t aligned_end = (addr + len + 63U) & ~63U;
    if (aligned_end > CHIP_FLASH_TOTAL_SIZE) {
        aligned_end = CHIP_FLASH_TOTAL_SIZE;
    }
    if (aligned_end > aligned_start) {
        (void)esp_cache_invalidate_xip_offset(aligned_start, aligned_end - aligned_start, 100000U);
    }
}

__attribute__((section(".iram1.text"), noinline))
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
    if (buf == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return TOOB_OK;
    }
    if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }

    uint32_t bounce[16];
    while (len > 0U) {
        wdt_kick();
        if (((addr & 3U) == 0U) && ((((uintptr_t)buf) & 3U) == 0U) && (len >= 4U)) {
            uint32_t bulk = len & ~3U;
            if (bulk > 256U) {
                bulk = 256U;
            }
            if (ROM_FLASH_READ(addr, buf, bulk) != ESP_ROM_OK) {
                return TOOB_ERR_FLASH;
            }
            addr += bulk;
            buf += bulk;
            len -= bulk;
        } else {
            uint32_t aligned_addr = addr & ~3U;
            uint32_t head = addr - aligned_addr;
            uint32_t avail = (uint32_t)sizeof(bounce) - head;
            uint32_t take = (len < avail) ? len : avail;
            uint32_t rom_len = (head + take + 3U) & ~3U;
            if (ROM_FLASH_READ(aligned_addr, bounce, rom_len) != ESP_ROM_OK) {
                return TOOB_ERR_FLASH;
            }
            const uint8_t *bbytes = (const uint8_t *)bounce;
            for (uint32_t i = 0U; i < take; i++) {
                buf[i] = bbytes[head + i];
            }
            addr += take;
            buf += take;
            len -= take;
        }
    }
    return TOOB_OK;
}

__attribute__((section(".iram1.text"), noinline))
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    if (buf == NULL || len == 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }

    uint32_t bounce[64];
    uint32_t cur_addr = addr;
    uint32_t rem = len;
    const uint8_t *src = buf;

    while (rem > 0U) {
        wdt_kick();
        uint32_t chunk = (rem > 256U) ? 256U : rem;
        /* Copy into DRAM bounce buffer before calling ROM_FLASH_WRITE so MSPI is never contended */
        uint8_t *bbytes = (uint8_t *)bounce;
        for (uint32_t i = 0U; i < chunk; i++) {
            bbytes[i] = src[i];
        }
        if (ROM_FLASH_WRITE(cur_addr, bounce, chunk) != ESP_ROM_OK) {
            return TOOB_ERR_FLASH;
        }
        cur_addr += chunk;
        src += chunk;
        rem -= chunk;
    }

    app_sync_cache(addr, len);
    return TOOB_OK;
}

__attribute__((section(".iram1.text"), noinline))
toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len)
{
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }

    uint32_t first_sec = addr / CHIP_FLASH_MAX_SECTOR_SIZE;
    uint32_t num_sec = (len + CHIP_FLASH_MAX_SECTOR_SIZE - 1U) / CHIP_FLASH_MAX_SECTOR_SIZE;
    for (uint32_t i = 0U; i < num_sec; i++) {
        wdt_kick();
        if (ROM_FLASH_ERASE(first_sec + i) != ESP_ROM_OK) {
            return TOOB_ERR_FLASH;
        }
    }

    app_sync_cache(addr, num_sec * CHIP_FLASH_MAX_SECTOR_SIZE);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx)
{
    if (!ctx) return TOOB_ERR_INVALID_ARG;
    sha256_init((SHA256_CTX *)(uintptr_t)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
    sha256_update((SHA256_CTX *)(uintptr_t)ctx->opaque, data, len);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32])
{
    if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
    sha256_final((SHA256_CTX *)(uintptr_t)ctx->opaque, out_hash);
    return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *len)
{
    (void)key; (void)buf; (void)len;
    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len)
{
    (void)key; (void)buf; (void)len;
    return TOOB_OK;
}

#define RTC_CNTL_OPTIONS0_REG  (CHIP_REG_PMU_BASE + 0x0000U)
#define RTC_CNTL_SW_SYS_RST    (1U << 31)

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    uart_tx_drain();
    /* Trigger SW_SYS_RST (reset cause 3 = RESET_REASON_SOFTWARE, intentional!) */
    REG_SET_BIT(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_SW_SYS_RST);
    for (;;) {
        __asm__ volatile("nop");
    }
}

static void handle_ota_command(uint32_t total_len)
{
    static toob_ota_ctx_t ota_ctx;
    static uint8_t chunk_buf[512];

    if (toob_ota_ctx_init(&ota_ctx) != TOOB_OK) {
        uart_puts("[APP] OTA_ERR init\n");
        return;
    }
    if (toob_ota_begin(&ota_ctx, total_len, NULL) != TOOB_OK) {
        uart_puts("[APP] OTA_ERR begin\n");
        return;
    }
    (void)ROM_FLASH_UNLOCK();
    uart_puts("[APP] OTA_READY\n");

    uint32_t rx = 0U;
    while (rx < total_len) {
        uint8_t lo = uart_getc_wdt_safe();
        uint8_t hi = uart_getc_wdt_safe();
        uint16_t clen = (uint16_t)((uint16_t)lo | (uint16_t)((uint16_t)hi << 8));
        if (clen == 0U || clen > sizeof(chunk_buf) || (uint32_t)clen > (total_len - rx)) {
            toob_status_t abst = toob_ota_abort(&ota_ctx);
            (void)abst;
            uart_puts("[APP] OTA_ERR len\n");
            return;
        }
        for (uint16_t i = 0U; i < clen; i++) {
            chunk_buf[i] = uart_getc_wdt_safe();
        }
        wdt_kick();
        toob_status_t st = toob_ota_process_chunk(&ota_ctx, chunk_buf, clen);
        if (st != TOOB_OK) {
            toob_status_t abst = toob_ota_abort(&ota_ctx);
            (void)abst;
            uart_puts("[APP] OTA_ERR chunk\n");
            return;
        }
        rx += clen;
        uart_putc('K');
    }

    wdt_kick();
    toob_status_t fst = toob_ota_finalize(&ota_ctx);
    if (fst != TOOB_OK) {
        uart_puts("[APP] OTA_ERR finalize=");
        uart_put_dec((uint32_t)fst);
        uart_puts("\n");
        return;
    }

    uart_puts("\n[APP] OTA_FINALIZED status=OK\n");
    system_reboot_intentional();
}

void __attribute__((used, noreturn)) _app_c_init(void)
{
    /* Copy IRAM vectors + flash helpers directly into IRAM via 32-bit word stores */
    const uint32_t *src = &_siiram;
    uint32_t *dst = &_iram_start;
    while (dst < &_iram_end) {
        *dst++ = *src++;
    }
    __asm__ volatile("isync" ::: "memory");

    /* Switch Xtensa VECBASE to our IRAM-resident window spill/fill vector table */
    uintptr_t vec = (uintptr_t)_app_vecbase;
    __asm__ volatile("wsr %0, vecbase\n\tisync" :: "r"(vec) : "memory");

    src = &_sidata;
    dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0U;
    }

    toob_handoff_t handoff;
    memset(&handoff, 0, sizeof(handoff));
    toob_status_t hst = toob_get_handoff(&handoff);

    if (k_app_meta.crash_on_boot != 0U) {
        wdt_kick();
        uart_puts("[APP] BOOT ver=");
        uart_puts_volatile(k_app_meta.version);
        uart_puts(" slot=");
        uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : 99U);
        uart_puts(" tent=");
        uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
        uart_puts(" CRASHING_WITHOUT_CONFIRM\n");
        uart_tx_drain();
        /* Hang intentionally WITHOUT feeding TIMG0 WDT so Stage 1's hardware WDT
         * fires TG0WDT_SYS_RESET and triggers automatic rollback! */
        for (;;) {
            __asm__ volatile("nop");
        }
    }

    wdt_kick();
    (void)ROM_FLASH_UNLOCK();

    uart_puts("[APP] BOOT ver=");
    uart_puts_volatile(k_app_meta.version);
    uart_puts(" slot=");
    uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : 99U);
    uart_puts(" tent=");
    uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
    uart_puts(" handoff=");
    uart_puts((hst == TOOB_OK) ? "OK\n" : "ERR\n");

    char line[64];
    for (;;) {
        size_t n = uart_read_line(line, sizeof(line));
        if (n == 0U) {
            continue;
        }
        if (strcmp(line, "CONFIRM") == 0) {
            toob_status_t cst = toob_confirm_boot();
            if (cst == TOOB_OK) {
                uart_puts("[APP] CONFIRM status=OK\n");
            } else {
                uart_puts("[APP] CONFIRM status=ERR code=");
                uart_put_dec((uint32_t)cst);
                uart_puts("\n");
            }
        } else if (strcmp(line, "REBOOT") == 0) {
            uart_puts("[APP] REBOOTING\n");
            system_reboot_intentional();
        } else if (strncmp(line, "OTA ", 4) == 0) {
            uint32_t total_len = parse_u32_dec(line + 4);
            handle_ota_command(total_len);
        } else if (strcmp(line, "PING") == 0) {
            uart_puts("[APP] PONG ver=");
            uart_puts_volatile(k_app_meta.version);
            uart_puts("\n");
        }
    }
}
