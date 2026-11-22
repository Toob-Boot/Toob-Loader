/**
 * @file app_main.c
 * @brief Bare-Metal STM32F429 (ARM Cortex-M4F) Guest Firmware for Full-System Renode E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS LP-SRAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: RTC BKP0R/BKP1R + Flash Mailbox)
 *   - Streaming OTA ingestion across 128 KB asymmetric sectors (toob_ota_begin / process_chunk / finalize)
 *   - Stage-0 hardware nWRP non-brickability verification (TEST_WRP)
 *   - Unconfirmed firmware hang for Hardware IWDG Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "chip_config.h"
#include "boot_layout.h"
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

extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;

void _app_start(void);
static void __attribute__((used, noreturn)) _app_c_init(void);
static void __attribute__((used, noreturn)) _app_fault_trap(void);

__attribute__((used, section(".isr_vector")))
static const uintptr_t s_app_vectors[16] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    0U,
    0U,
    0U,
    0U,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    0U,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
};

#define MMIO32(addr)                (*(volatile uint32_t *)(uintptr_t)(addr))
#define MMIO8(addr)                 (*(volatile uint8_t *)(uintptr_t)(addr))

#define SCB_VTOR_REG                0xE000ED08U
#define SCB_AIRCR_REG               0xE000ED0CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U

#define USART_SR_RXNE               (1U << 5)
#define USART_SR_TC                 (1U << 6)
#define USART_SR_TXE                (1U << 7)

#define IWDG_KR_RELOAD_VAL          0x0000AAAAU
#define RCC_APB1ENR_PWREN_BIT       (1U << 28)
#define PWR_CR_DBP_BIT              (1U << 8)

#define FLASH_KEY1                  0x45670123U
#define FLASH_KEY2                  0xCDEF89ABU
#define FLASH_SR_EOP                (1U << 0)
#define FLASH_SR_WRPERR             (1U << 4)
#define FLASH_SR_ERR_MASK           0x000001F2U
#define FLASH_SR_CLEAR_ALL          (FLASH_SR_EOP | FLASH_SR_ERR_MASK)
#define FLASH_SR_BSY                (1U << 16)
#define FLASH_CR_PG                 (1U << 0)
#define FLASH_CR_SER                (1U << 1)
#define FLASH_CR_SNB_SHIFT          3U
#define FLASH_CR_PSIZE_MASK         (3U << 8)
#define FLASH_CR_PSIZE_WORD         (2U << 8)
#define FLASH_CR_STRT               (1U << 16)
#define FLASH_CR_LOCK               (1U << 31)
#define FLASH_OPTCR_S0_NWRP_MASK    0x000F0000U
#define STAGE0_WRP_PROBE_ADDR       0x08001000U

static void __attribute__((used, noreturn)) _app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("nop");
    }
}

static inline void wdt_kick(void)
{
    MMIO32(CHIP_REG_IWDG_KR) = IWDG_KR_RELOAD_VAL;
}

static inline void uart_putc(char c)
{
    while ((MMIO32(CHIP_REG_USART1_SR) & USART_SR_TXE) == 0U) {
    }
    MMIO32(CHIP_REG_USART1_DR) = (uint32_t)(uint8_t)c;
}

static inline void uart_flush(void)
{
    while ((MMIO32(CHIP_REG_USART1_SR) & USART_SR_TC) == 0U) {
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

static uint8_t uart_getc_wdt_safe(void)
{
    uint32_t spin = 0U;
    for (;;) {
        if ((MMIO32(CHIP_REG_USART1_SR) & USART_SR_RXNE) != 0U) {
            return (uint8_t)(MMIO32(CHIP_REG_USART1_DR) & 0xFFU);
        }
        if ((++spin & 0x3FFFU) == 0U) {
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
 * libtoob OS Porting Layer (STM32F429 Asymmetric Dual-Bank Flash + RTC BKP)
 * ============================================================================ */

static void enable_backup_domain(void)
{
    MMIO32(CHIP_REG_RCC_APB1ENR) |= RCC_APB1ENR_PWREN_BIT;
    (void)MMIO32(CHIP_REG_RCC_APB1ENR);
    MMIO32(CHIP_REG_PWR_CR) |= PWR_CR_DBP_BIT;
    (void)MMIO32(CHIP_REG_PWR_CR);
}

toob_status_t toob_os_confirm_rtc_write(uint64_t nonce)
{
    enable_backup_domain();
    uint32_t lo = (uint32_t)(nonce & 0xFFFFFFFFULL);
    uint32_t hi = (uint32_t)(nonce >> 32U);
    MMIO32(CHIP_REG_RTC_BKP0R) = lo;
    MMIO32(CHIP_REG_RTC_BKP1R) = hi;
    __asm__ volatile("dsb sy" ::: "memory");

    if ((MMIO32(CHIP_REG_RTC_BKP0R) != lo) || (MMIO32(CHIP_REG_RTC_BKP1R) != hi)) {
        return TOOB_ERR_VERIFY;
    }
    return TOOB_OK;
}

static bool app_flash_unlock(void)
{
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    if ((MMIO32(CHIP_REG_FLASH_CR) & FLASH_CR_LOCK) != 0U) {
        MMIO32(CHIP_REG_FLASH_KEYR) = FLASH_KEY1;
        MMIO32(CHIP_REG_FLASH_KEYR) = FLASH_KEY2;
    }
    if ((MMIO32(CHIP_REG_FLASH_CR) & FLASH_CR_LOCK) != 0U) {
        return false;
    }
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
    return true;
}

static void app_flash_lock(void)
{
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_LOCK;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
}

static void app_lookup_sector(uint32_t rel_off, uint32_t *sec_rel_out, uint32_t *sec_size_out, uint32_t *snb_out)
{
    uint32_t bank = (rel_off >= 0x00100000U) ? 1U : 0U;
    uint32_t bank_off = rel_off - (bank * 0x00100000U);
    uint32_t idx = 0U;
    uint32_t sec_in_bank = 0U;
    uint32_t sz = 0x4000U;

    if (bank_off < 0x10000U) {
        idx = bank_off / 0x4000U;
        sec_in_bank = idx * 0x4000U;
        sz = 0x4000U;
    } else if (bank_off < 0x20000U) {
        idx = 4U;
        sec_in_bank = 0x10000U;
        sz = 0x10000U;
    } else {
        uint32_t lidx = (bank_off - 0x20000U) / 0x20000U;
        idx = 5U + lidx;
        sec_in_bank = 0x20000U + (lidx * 0x20000U);
        sz = 0x20000U;
    }

    *sec_rel_out = (bank * 0x00100000U) + sec_in_bank;
    *sec_size_out = sz;
    *snb_out = (bank != 0U) ? (0x10U + idx) : idx;
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
    if (buf == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr < CHIP_FLASH_BASE_ADDR) ||
        ((addr - CHIP_FLASH_BASE_ADDR) > CHIP_FLASH_TOTAL_SIZE) ||
        (len > (CHIP_FLASH_TOTAL_SIZE - (addr - CHIP_FLASH_BASE_ADDR)))) {
        return TOOB_ERR_FLASH;
    }
    wdt_kick();
    memcpy(buf, (const void *)(uintptr_t)addr, len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    if (buf == NULL || len == 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if ((addr < CHIP_FLASH_BASE_ADDR) ||
        ((addr - CHIP_FLASH_BASE_ADDR) > CHIP_FLASH_TOTAL_SIZE) ||
        (len > (CHIP_FLASH_TOTAL_SIZE - (addr - CHIP_FLASH_BASE_ADDR)))) {
        return TOOB_ERR_FLASH;
    }

    if (!app_flash_unlock()) {
        return TOOB_ERR_FLASH;
    }

    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PSIZE_WORD | FLASH_CR_PG;
    for (uint32_t off = 0U; off < len; off += 4U) {
        if ((off & 0xFFU) == 0U) {
            wdt_kick();
        }
        uint32_t word = ((uint32_t)buf[off]) |
                        (((uint32_t)buf[off + 1U]) << 8U) |
                        (((uint32_t)buf[off + 2U]) << 16U) |
                        (((uint32_t)buf[off + 3U]) << 24U);
        MMIO32(addr + off) = word;
        __asm__ volatile("dsb sy" ::: "memory");
        while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
        }
        if ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_ERR_MASK) != 0U) {
            MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
            app_flash_lock();
            return TOOB_ERR_FLASH;
        }
        MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_EOP;
    }

    app_flash_lock();
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len)
{
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr < CHIP_FLASH_BASE_ADDR) ||
        ((addr - CHIP_FLASH_BASE_ADDR) >= CHIP_FLASH_TOTAL_SIZE) ||
        (len > (CHIP_FLASH_TOTAL_SIZE - (addr - CHIP_FLASH_BASE_ADDR)))) {
        return TOOB_ERR_FLASH;
    }

    uint32_t rel = addr - CHIP_FLASH_BASE_ADDR;
    uint32_t rel_end = rel + len;

    while (rel < rel_end) {
        uint32_t sec_rel = 0U;
        uint32_t sec_sz = 0U;
        uint32_t snb = 0U;
        app_lookup_sector(rel, &sec_rel, &sec_sz, &snb);
        if (rel != sec_rel) {
            return TOOB_ERR_FLASH;
        }

        wdt_kick();
        if (!app_flash_unlock()) {
            return TOOB_ERR_FLASH;
        }

        uint32_t cr = FLASH_CR_PSIZE_WORD | FLASH_CR_SER | (snb << FLASH_CR_SNB_SHIFT);
        MMIO32(CHIP_REG_FLASH_CR) = cr;
        MMIO32(CHIP_REG_FLASH_CR) = cr | FLASH_CR_STRT;
        __asm__ volatile("dsb sy" ::: "memory");

        while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
        }
        uint32_t sr = MMIO32(CHIP_REG_FLASH_SR);
        MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
        app_flash_lock();

        if ((sr & FLASH_SR_ERR_MASK) != 0U) {
            return TOOB_ERR_FLASH;
        }
        rel += sec_sz;
    }

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

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    uart_flush();
    __asm__ volatile("dsb sy" ::: "memory");
    MMIO32(SCB_AIRCR_REG) = SCB_AIRCR_SYSRESETREQ_VAL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        __asm__ volatile("nop");
    }
}

static void handle_test_wrp(void)
{
    wdt_kick();
    uint32_t optcr = MMIO32(CHIP_REG_FLASH_OPTCR);
    uint32_t orig_word = MMIO32(STAGE0_WRP_PROBE_ADDR);

    (void)app_flash_unlock();

    /* Attempt 1: Erase hardware-protected Stage-0 Sector 0 (SNB=0) */
    uint32_t cr = FLASH_CR_PSIZE_WORD | FLASH_CR_SER;
    MMIO32(CHIP_REG_FLASH_CR) = cr;
    MMIO32(CHIP_REG_FLASH_CR) = cr | FLASH_CR_STRT;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t erase_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    /* Attempt 2: Program 0x00000000 into hardware-protected Stage-0 @ 0x08001000 */
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PSIZE_WORD | FLASH_CR_PG;
    MMIO32(STAGE0_WRP_PROBE_ADDR) = 0x00000000U;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t write_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    app_flash_lock();

    uint32_t after_word = MMIO32(STAGE0_WRP_PROBE_ADDR);
    uint32_t optcr_locked = ((optcr & FLASH_OPTCR_S0_NWRP_MASK) == 0U) ? 1U : 0U;
    uint32_t wrperr_erase = ((erase_sr & FLASH_SR_WRPERR) != 0U) ? 1U : 0U;
    uint32_t wrperr_write = ((write_sr & FLASH_SR_WRPERR) != 0U) ? 1U : 0U;
    uint32_t intact = (after_word == orig_word) ? 1U : 0U;

    uart_puts("[APP] WRP_TEST optcr_locked=");
    uart_put_dec(optcr_locked);
    uart_puts(" wrperr_erase=");
    uart_put_dec(wrperr_erase);
    uart_puts(" wrperr_write=");
    uart_put_dec(wrperr_write);
    uart_puts(" stage0_intact=");
    uart_put_dec(intact);
    uart_puts("\n");
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
    uart_puts("[APP] OTA_READY\n");

    uint32_t rx = 0U;
    while (rx < total_len) {
        uint8_t lo = uart_getc_wdt_safe();
        uint8_t hi = uart_getc_wdt_safe();
        uint16_t clen = (uint16_t)lo | ((uint16_t)hi << 8U);
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

static void __attribute__((used, noreturn)) _app_c_init(void)
{
    MMIO32(SCB_VTOR_REG) = (uint32_t)(uintptr_t)&s_app_vectors[0];
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

    const uint32_t *src = &_sidata;
    uint32_t *dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0U;
    }

    enable_backup_domain();

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
        uart_flush();
        /* Starve hardware IWDG to trigger automatic WDT rollback */
        for (;;) {
            __asm__ volatile("wfi");
        }
    }

    wdt_kick();

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
        } else if (strcmp(line, "TEST_WRP") == 0) {
            handle_test_wrp();
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

void __attribute__((naked, noreturn, section(".app_entry"))) _app_start(void)
{
    __asm__ volatile(
        "cpsid i\n"
        "ldr r0, =_stack_top\n"
        "mov sp, r0\n"
        "b _app_c_init\n"
    );
}
