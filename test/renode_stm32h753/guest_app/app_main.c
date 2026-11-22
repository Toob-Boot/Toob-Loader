/**
 * @file app_main.c
 * @brief Bare-Metal STM32H753 (ARM Cortex-M7) Guest Firmware for Full-System Renode E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS LP-SRAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: RTC BKP0R/BKP1R + 32B-aligned Flash Mailbox)
 *   - Streaming OTA ingestion across 128 KB sectors & 256-bit (32-byte) ECC Flash-Words
 *   - Stage-0 ARMv7E-M MPU Region 0 + FLASH_WPSN1R defense-in-depth lockdown proof (TEST_WRP)
 *   - Explicit 32-Byte Flash-Word SECDED ECC Write-Once negative test (TEST_ECC_32B)
 *   - Unconfirmed firmware hang for Hardware IWDG1 Auto-Rollback
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

volatile uint32_t g_mpu_fault_count;

void _app_start(void);
void _app_memmanage_handler(void);
static void __attribute__((used, noreturn)) _app_c_init(void);
static void __attribute__((used, noreturn)) _app_fault_trap(void);

__attribute__((used, section(".isr_vector")))
static const uintptr_t s_app_vectors[16] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_memmanage_handler,
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
#define SCB_CCR_REG                 0xE000ED14U
#define SCB_SHCSR_REG               0xE000ED24U
#define SCB_DCCIMVAC_REG            0xE000EF70U
#define MPU_CTRL_REG                0xE000ED94U

#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U
#define SCB_CCR_DC_BIT              (1U << 16)
#define SCB_CCR_IC_BIT              (1U << 17)
#define SCB_SHCSR_MEMFAULTENA_BIT   (1U << 16)
#define MPU_CTRL_LOCKDOWN_VAL       0x00000005U
#define CACHE_LINE_BYTES            32U

#define USART_ISR_ERR_MASK          0x0FU
#define USART_ISR_RXNE              (1U << 5)
#define USART_ISR_TC                (1U << 6)
#define USART_ISR_TXE               (1U << 7)

#define IWDG_KR_RELOAD_VAL          0x0000AAAAU
#define RCC_APB4ENR_RTCAPBEN_BIT    (1U << 16)
#define PWR_CR1_DBP_BIT             (1U << 8)

#define FLASH_KEY1                  0x45670123U
#define FLASH_KEY2                  0xCDEF89ABU
#define FLASH_CR_LOCK               (1U << 0)
#define FLASH_CR_PG                 (1U << 1)
#define FLASH_CR_SER                (1U << 2)
#define FLASH_CR_PSIZE_64           (3U << 4)
#define FLASH_CR_START              (1U << 7)
#define FLASH_CR_SNB_SHIFT          8U
#define FLASH_SR_BUSY_MASK          0x00000007U
#define FLASH_SR_EOP                (1U << 16)
#define FLASH_SR_WRPERR             (1U << 17)
#define FLASH_SR_INCERR             (1U << 21)
#define FLASH_SR_ERR_MASK           0x07EE0000U
#define FLASH_CCR_CLEAR_ALL         (FLASH_SR_EOP | FLASH_SR_ERR_MASK)

#define STM32H7_BANK_BYTES          0x00100000U
#define STM32H7_SECTOR_BYTES        0x00020000U
#define STM32H7_FLASH_WORD_BYTES    32U
#define STM32H7_FLASH_WORD_WORDS    8U

#define STAGE0_WRP_PROBE_ADDR       0x08001000U
#define ECC_TEST_SECTOR_ADDR        0x082E0000U

static void __attribute__((used, noreturn)) _app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("nop");
    }
}

void __attribute__((naked, used)) _app_memmanage_handler(void)
{
    __asm__ volatile(
        "tst lr, #4\n"
        "ite eq\n"
        "mrseq r0, msp\n"
        "mrsne r0, psp\n"
        "ldr r1, [r0, #24]\n"
        "bic r1, r1, #1\n"
        "ldrh r2, [r1]\n"
        "movw r3, #0xE800\n"
        "cmp r2, r3\n"
        "ite hs\n"
        "addhs r1, r1, #4\n"
        "addlo r1, r1, #2\n"
        "str r1, [r0, #24]\n"
        "ldr r2, =0xE000ED28\n"
        "ldr r3, [r2]\n"
        "str r3, [r2]\n"
        "ldr r2, =g_mpu_fault_count\n"
        "ldr r3, [r2]\n"
        "add r3, r3, #1\n"
        "str r3, [r2]\n"
        "dsb sy\n"
        "isb sy\n"
        "bx lr\n"
    );
}

static inline void wdt_kick(void)
{
    MMIO32(CHIP_REG_IWDG1_KR) = IWDG_KR_RELOAD_VAL;
}

static void app_dcache_clean_invalidate_range(uint32_t addr, uint32_t len)
{
    if (((MMIO32(SCB_CCR_REG) & SCB_CCR_DC_BIT) != 0U) && (len > 0U)) {
        uint32_t cur = addr & ~(CACHE_LINE_BYTES - 1U);
        uint32_t end = addr + len;
        __asm__ volatile("dsb sy" ::: "memory");
        while (cur < end) {
            MMIO32(SCB_DCCIMVAC_REG) = cur;
            cur += CACHE_LINE_BYTES;
        }
        __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    }
}

static inline void uart_putc(char c)
{
    while ((MMIO32(CHIP_REG_USART1_ISR) & USART_ISR_TXE) == 0U) {
    }
    MMIO32(CHIP_REG_USART1_TDR) = (uint32_t)(uint8_t)c;
}

static inline void uart_flush(void)
{
    while ((MMIO32(CHIP_REG_USART1_ISR) & USART_ISR_TC) == 0U) {
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
        uint32_t isr = MMIO32(CHIP_REG_USART1_ISR);
        if ((isr & USART_ISR_RXNE) != 0U) {
            uint32_t rdr = MMIO32(CHIP_REG_USART1_RDR);
            if ((isr & USART_ISR_ERR_MASK) != 0U) {
                MMIO32(CHIP_REG_USART1_ICR) = USART_ISR_ERR_MASK;
                continue;
            }
            return (uint8_t)(rdr & 0xFFU);
        }
        if ((isr & USART_ISR_ERR_MASK) != 0U) {
            (void)MMIO32(CHIP_REG_USART1_RDR);
            MMIO32(CHIP_REG_USART1_ICR) = USART_ISR_ERR_MASK;
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
 * libtoob OS Porting Layer (STM32H753 256-Bit ECC Flash + RTC BKP)
 * ============================================================================ */

static void enable_backup_domain(void)
{
    MMIO32(CHIP_REG_RCC_APB4ENR) |= RCC_APB4ENR_RTCAPBEN_BIT;
    (void)MMIO32(CHIP_REG_RCC_APB4ENR);
    MMIO32(CHIP_REG_PWR_CR1) |= PWR_CR1_DBP_BIT;
    (void)MMIO32(CHIP_REG_PWR_CR1);
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

typedef struct {
    uint32_t keyr;
    uint32_t cr;
    uint32_t sr;
    uint32_t ccr;
} app_bank_regs_t;

static app_bank_regs_t app_select_bank(uint32_t rel_off)
{
    app_bank_regs_t r;
    if (rel_off < STM32H7_BANK_BYTES) {
        r.keyr = CHIP_REG_FLASH_KEYR1;
        r.cr   = CHIP_REG_FLASH_CR1;
        r.sr   = CHIP_REG_FLASH_SR1;
        r.ccr  = CHIP_REG_FLASH_CCR1;
    } else {
        r.keyr = CHIP_REG_FLASH_KEYR2;
        r.cr   = CHIP_REG_FLASH_CR2;
        r.sr   = CHIP_REG_FLASH_SR2;
        r.ccr  = CHIP_REG_FLASH_CCR2;
    }
    return r;
}

static bool app_bank_unlock(const app_bank_regs_t *r)
{
    while ((MMIO32(r->sr) & FLASH_SR_BUSY_MASK) != 0U) {
    }
    if ((MMIO32(r->cr) & FLASH_CR_LOCK) != 0U) {
        MMIO32(r->keyr) = FLASH_KEY1;
        MMIO32(r->keyr) = FLASH_KEY2;
        __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    }
    if ((MMIO32(r->cr) & FLASH_CR_LOCK) != 0U) {
        return false;
    }
    MMIO32(r->ccr) = FLASH_CCR_CLEAR_ALL;
    return true;
}

static void app_bank_lock(const app_bank_regs_t *r)
{
    MMIO32(r->cr) = FLASH_CR_LOCK;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
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

    for (uint32_t off = 0U; off < len; off += STM32H7_FLASH_WORD_BYTES) {
        if ((off & 0xFFU) == 0U) {
            wdt_kick();
        }
        uint32_t fw_addr = addr + off;
        uint32_t fw_rel = fw_addr - CHIP_FLASH_BASE_ADDR;
        app_bank_regs_t r = app_select_bank(fw_rel);
        if (!app_bank_unlock(&r)) {
            return TOOB_ERR_FLASH;
        }

        MMIO32(r.cr) = FLASH_CR_PSIZE_64 | FLASH_CR_PG;
        __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

        for (uint32_t w = 0U; w < STM32H7_FLASH_WORD_WORDS; w++) {
            uint32_t boff = off + (w * 4U);
            uint32_t word = ((uint32_t)buf[boff]) |
                            (((uint32_t)buf[boff + 1U]) << 8U) |
                            (((uint32_t)buf[boff + 2U]) << 16U) |
                            (((uint32_t)buf[boff + 3U]) << 24U);
            MMIO32(fw_addr + (w * 4U)) = word;
        }
        __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

        while ((MMIO32(r.sr) & FLASH_SR_BUSY_MASK) != 0U) {
        }
        uint32_t sr = MMIO32(r.sr);
        MMIO32(r.ccr) = FLASH_CCR_CLEAR_ALL;
        app_bank_lock(&r);

        if ((sr & FLASH_SR_ERR_MASK) != 0U) {
            return TOOB_ERR_FLASH;
        }
    }

    app_dcache_clean_invalidate_range(addr, len);
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
    if ((rel % STM32H7_SECTOR_BYTES) != 0U || (len % STM32H7_SECTOR_BYTES) != 0U) {
        return TOOB_ERR_FLASH;
    }
    uint32_t rel_end = rel + len;

    while (rel < rel_end) {
        wdt_kick();
        app_bank_regs_t r = app_select_bank(rel);
        uint32_t bank_rel = (rel < STM32H7_BANK_BYTES) ? rel : (rel - STM32H7_BANK_BYTES);
        uint32_t snb = (bank_rel / STM32H7_SECTOR_BYTES) & 0xFU;

        if (!app_bank_unlock(&r)) {
            return TOOB_ERR_FLASH;
        }

        uint32_t cr = FLASH_CR_PSIZE_64 | FLASH_CR_SER | (snb << FLASH_CR_SNB_SHIFT);
        MMIO32(r.cr) = cr;
        MMIO32(r.cr) = cr | FLASH_CR_START;
        __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

        while ((MMIO32(r.sr) & FLASH_SR_BUSY_MASK) != 0U) {
        }
        uint32_t sr = MMIO32(r.sr);
        MMIO32(r.ccr) = FLASH_CCR_CLEAR_ALL;
        app_bank_lock(&r);

        if ((sr & FLASH_SR_ERR_MASK) != 0U) {
            return TOOB_ERR_FLASH;
        }

        app_dcache_clean_invalidate_range(CHIP_FLASH_BASE_ADDR + rel, STM32H7_SECTOR_BYTES);
        rel += STM32H7_SECTOR_BYTES;
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
    uint32_t wpsn1 = MMIO32(CHIP_REG_FLASH_WPSN_CUR1R);
    uint32_t mpu_ctrl = MMIO32(MPU_CTRL_REG);
    uint32_t ccr = MMIO32(SCB_CCR_REG);
    uint32_t orig_word = MMIO32(STAGE0_WRP_PROBE_ADDR);

    /* 1. Verify ARMv7E-M MPU Region 0 Read-Only lockdown intercepts direct CPU write
     * (unmask PRIMASK briefly so synchronous MemManage executes rather than escalating to HardFault) */
    MMIO32(SCB_SHCSR_REG) |= SCB_SHCSR_MEMFAULTENA_BIT;
    g_mpu_fault_count = 0U;
    __asm__ volatile("dsb sy\n\tisb sy\n\tcpsie i\n\tisb sy" ::: "memory");
    MMIO32(STAGE0_WRP_PROBE_ADDR) = 0x00000000U;
    __asm__ volatile("dsb sy\n\tisb sy\n\tcpsid i\n\tisb sy" ::: "memory");
    uint32_t mpu_fault = (g_mpu_fault_count == 1U) ? 1U : 0U;

    /* 2. Verify hardware FLASH_WPSN_CUR1R blocks Sector 0 erase (SNB=0) with WRPERR */
    app_bank_regs_t b1 = app_select_bank(0U);
    (void)app_bank_unlock(&b1);

    uint32_t cr = FLASH_CR_PSIZE_64 | FLASH_CR_SER;
    MMIO32(CHIP_REG_FLASH_CR1) = cr;
    MMIO32(CHIP_REG_FLASH_CR1) = cr | FLASH_CR_START;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR1) & FLASH_SR_BUSY_MASK) != 0U) {
    }
    uint32_t erase_sr = MMIO32(CHIP_REG_FLASH_SR1);
    MMIO32(CHIP_REG_FLASH_CCR1) = FLASH_CCR_CLEAR_ALL;

    /* 3. Temporarily bypass MPU to prove hardware FLASH_WPSN_CUR1R also blocks Flash-Word writes */
    MMIO32(MPU_CTRL_REG) = 0U;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

    MMIO32(CHIP_REG_FLASH_CR1) = FLASH_CR_PSIZE_64 | FLASH_CR_PG;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    for (uint32_t w = 0U; w < STM32H7_FLASH_WORD_WORDS; w++) {
        MMIO32(STAGE0_WRP_PROBE_ADDR + (w * 4U)) = 0x00000000U;
    }
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR1) & FLASH_SR_BUSY_MASK) != 0U) {
    }
    uint32_t write_sr = MMIO32(CHIP_REG_FLASH_SR1);
    MMIO32(CHIP_REG_FLASH_CCR1) = FLASH_CCR_CLEAR_ALL;

    MMIO32(MPU_CTRL_REG) = MPU_CTRL_LOCKDOWN_VAL;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    app_bank_lock(&b1);

    uint32_t after_word = MMIO32(STAGE0_WRP_PROBE_ADDR);
    uint32_t wpsn1_locked = ((wpsn1 & 0x01U) == 0U) ? 1U : 0U;
    uint32_t mpu_locked = ((mpu_ctrl & MPU_CTRL_LOCKDOWN_VAL) == MPU_CTRL_LOCKDOWN_VAL) ? 1U : 0U;
    uint32_t wrperr_erase = ((erase_sr & FLASH_SR_WRPERR) != 0U) ? 1U : 0U;
    uint32_t wrperr_write = ((write_sr & FLASH_SR_WRPERR) != 0U) ? 1U : 0U;
    uint32_t icache_on = ((ccr & SCB_CCR_IC_BIT) != 0U) ? 1U : 0U;
    uint32_t dcache_on = ((ccr & SCB_CCR_DC_BIT) != 0U) ? 1U : 0U;
    uint32_t intact = (after_word == orig_word) ? 1U : 0U;

    uart_puts("[APP] WRP_TEST wpsn1_locked=");
    uart_put_dec(wpsn1_locked);
    uart_puts(" mpu_locked=");
    uart_put_dec(mpu_locked);
    uart_puts(" mpu_fault=");
    uart_put_dec(mpu_fault);
    uart_puts(" wrperr_erase=");
    uart_put_dec(wrperr_erase);
    uart_puts(" wrperr_write=");
    uart_put_dec(wrperr_write);
    uart_puts(" icache=");
    uart_put_dec(icache_on);
    uart_puts(" dcache=");
    uart_put_dec(dcache_on);
    uart_puts(" stage0_intact=");
    uart_put_dec(intact);
    uart_puts("\n");
}

static void handle_test_ecc_32b(void)
{
    wdt_kick();
    app_bank_regs_t b2 = app_select_bank(ECC_TEST_SECTOR_ADDR - CHIP_FLASH_BASE_ADDR);

    /* 1. Erase spare 128 KB sector 0x082E0000 cleanly */
    toob_status_t er1 = toob_os_flash_erase(ECC_TEST_SECTOR_ADDR, STM32H7_SECTOR_BYTES);

    /* 2. First 256-bit Flash-Word write: program all 0xFFFFFFFF (commits 10-bit SECDED ECC!) */
    (void)app_bank_unlock(&b2);
    MMIO32(b2.cr) = FLASH_CR_PSIZE_64 | FLASH_CR_PG;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    for (uint32_t w = 0U; w < STM32H7_FLASH_WORD_WORDS; w++) {
        MMIO32(ECC_TEST_SECTOR_ADDR + (w * 4U)) = 0xFFFFFFFFU;
    }
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    uint32_t sr_first = MMIO32(b2.sr);
    MMIO32(b2.ccr) = FLASH_CCR_CLEAR_ALL;
    app_bank_lock(&b2);

    /* 3. Second 256-bit Flash-Word write WITHOUT 128 KB sector erase: MUST trigger INCERR! */
    (void)app_bank_unlock(&b2);
    MMIO32(b2.cr) = FLASH_CR_PSIZE_64 | FLASH_CR_PG;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    for (uint32_t w = 0U; w < STM32H7_FLASH_WORD_WORDS; w++) {
        MMIO32(ECC_TEST_SECTOR_ADDR + (w * 4U)) = 0x5A5A5A5AU;
    }
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    uint32_t sr_second = MMIO32(b2.sr);
    MMIO32(b2.ccr) = FLASH_CCR_CLEAR_ALL;
    app_bank_lock(&b2);

    app_dcache_clean_invalidate_range(ECC_TEST_SECTOR_ADDR, STM32H7_FLASH_WORD_BYTES);
    uint32_t rejected_word = MMIO32(ECC_TEST_SECTOR_ADDR);

    /* 4. Erase 128 KB sector -> verify subsequent 256-bit Flash-Word write succeeds cleanly */
    toob_status_t er2 = toob_os_flash_erase(ECC_TEST_SECTOR_ADDR, STM32H7_SECTOR_BYTES);
    (void)app_bank_unlock(&b2);
    MMIO32(b2.cr) = FLASH_CR_PSIZE_64 | FLASH_CR_PG;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    for (uint32_t w = 0U; w < STM32H7_FLASH_WORD_WORDS; w++) {
        MMIO32(ECC_TEST_SECTOR_ADDR + (w * 4U)) = 0x5A5A5A5AU;
    }
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    uint32_t sr_third = MMIO32(b2.sr);
    MMIO32(b2.ccr) = FLASH_CCR_CLEAR_ALL;
    app_bank_lock(&b2);

    app_dcache_clean_invalidate_range(ECC_TEST_SECTOR_ADDR, STM32H7_FLASH_WORD_BYTES);
    uint32_t after_erase_word = MMIO32(ECC_TEST_SECTOR_ADDR);
    toob_status_t er3 = toob_os_flash_erase(ECC_TEST_SECTOR_ADDR, STM32H7_SECTOR_BYTES);

    uint32_t first_ff_ok = ((er1 == TOOB_OK) && ((sr_first & FLASH_SR_ERR_MASK) == 0U)) ? 1U : 0U;
    uint32_t second_incerr = ((sr_second & FLASH_SR_INCERR) != 0U) ? 1U : 0U;
    uint32_t second_rejected = (rejected_word == 0xFFFFFFFFU) ? 1U : 0U;
    uint32_t after_erase_ok = ((er2 == TOOB_OK) && (er3 == TOOB_OK) &&
                               ((sr_third & FLASH_SR_ERR_MASK) == 0U) &&
                               (after_erase_word == 0x5A5A5A5AU)) ? 1U : 0U;

    uart_puts("[APP] ECC_32B_TEST first_ff_ok=");
    uart_put_dec(first_ff_ok);
    uart_puts(" second_incerr=");
    uart_put_dec(second_incerr);
    uart_puts(" second_rejected=");
    uart_put_dec(second_rejected);
    uart_puts(" after_erase_ok=");
    uart_put_dec(after_erase_ok);
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
        /* Starve hardware IWDG1 to trigger automatic WDT rollback */
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
        } else if (strcmp(line, "TEST_ECC_32B") == 0) {
            handle_test_ecc_32b();
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
