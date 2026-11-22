/**
 * @file app_main.c
 * @brief Bare-Metal STM32F072 (ARM Cortex-M0 ARMv6-M, No VTOR) Guest Firmware for Renode E2E
 *
 * Links directly against production sdk/libtoob to verify:
 *   - True ARMv6-M exception/IRQ delivery without SCB->VTOR via Stage 1's 192-byte
 *     SRAM vector remap ([0x20000000..0x200000BF] aliased at 0x00000000 via SYSCFG_CFGR1.MEM_MODE=3):
 *     actively fires PendSV (vector 14), SysTick (vector 15), and NVIC IRQ0 (vector 16)!
 *   - Stage 1 -> OS LP-SRAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: RTC BKP0R/BKP1R + Flash Mailbox)
 *   - Streaming OTA ingestion over RM0091 2 KB pages & 16-bit halfword FPEC writes
 *   - Stage-0 hardware OB.WRP0..3 non-brickability negative test (TEST_WRP)
 *   - Unconfirmed firmware hang for Hardware IWDG Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "chip_config.h"
#include "generated_boot_config.h"
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

#ifndef APP_EXTRA_FEATURE_V3
#define APP_EXTRA_FEATURE_V3 0
#endif

typedef struct {
    char version[16];
    uint32_t crash_on_boot;
    uint32_t feature_table[44];
} app_rom_meta_t;

__attribute__((section(".rodata.app_meta"), used))
static const volatile app_rom_meta_t k_app_meta = {
    .version = APP_VERSION_STR,
    .crash_on_boot = (uint32_t)APP_CRASH_ON_BOOT,
#if APP_EXTRA_FEATURE_V3
    .feature_table = {
        0x31032072U, 0xA5C35A3CU, 0x13579BDFU, 0x2468ACE0U,
        0xF0720001U, 0xF0720002U, 0xF0720003U, 0xF0720004U,
        0x9E3779B9U, 0x85EBCA6BU, 0xC2B2AE35U, 0x27D4EB2FU,
        0x165667B1U, 0xD3A2646CU, 0xFD7046C5U, 0xB55A4F09U,
        0x3C6EF372U, 0xBB67AE85U, 0x6A09E667U, 0x510E527FU,
        0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U, 0x428A2F98U,
        0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU,
        0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U, 0xD807AA98U,
        0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U,
        0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U,
        0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
    },
#else
    .feature_table = { 0U },
#endif
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
static void __attribute__((used)) _app_pendsv_handler(void);
static void __attribute__((used)) _app_systick_handler(void);
static void __attribute__((used)) _app_ext_irq0_handler(void);

#define MMIO32(addr)                (*(volatile uint32_t *)(uintptr_t)(addr))
#define MMIO16(addr)                (*(volatile uint16_t *)(uintptr_t)(addr))
#define MMIO8(addr)                 (*(const volatile uint8_t *)(uintptr_t)(addr))

/* ARMv6-M Core Peripherals (Note: SCB->VTOR 0xE000ED08 does NOT exist on Cortex-M0!) */
#define SYST_CSR_REG                0xE000E010U
#define SYST_RVR_REG                0xE000E014U
#define SYST_CVR_REG                0xE000E018U
#define SYST_CSR_ENABLE             (1U << 0)
#define SYST_CSR_TICKINT            (1U << 1)
#define SYST_CSR_CLKSOURCE          (1U << 2)

#define NVIC_ISER_REG               0xE000E100U
#define NVIC_ICER_REG               0xE000E180U
#define NVIC_ISPR_REG               0xE000E200U
#define NVIC_ICPR_REG               0xE000E280U

#define SCB_ICSR_REG                0xE000ED04U
#define SCB_ICSR_PENDSVSET          (1U << 28)
#define SCB_AIRCR_REG               0xE000ED0CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U

#define USART_CR1_UE                (1U << 0)
#define USART_CR1_RE                (1U << 2)
#define USART_CR1_TE                (1U << 3)
#define USART_ISR_ERR_MASK          0x0FU
#define USART_ISR_RXNE              (1U << 5)
#define USART_ISR_TC                (1U << 6)
#define USART_ISR_TXE               (1U << 7)
#define USART_ICR_ERR_CLEAR         0x0FU
#define RCC_APB2ENR_USART1EN_BIT    (1U << 14)

#define IWDG_KR_RELOAD_VAL          0x0000AAAAU
#define RCC_APB1ENR_PWREN_BIT       (1U << 28)
#define PWR_CR_DBP_BIT              (1U << 8)

/* RM0091 FPEC Flash Controller Constants */
#define FLASH_KEY1                  0x45670123U
#define FLASH_KEY2                  0xCDEF89ABU
#define FLASH_SR_BSY                (1U << 0)
#define FLASH_SR_PGERR              (1U << 2)
#define FLASH_SR_WRPRTERR           (1U << 4)
#define FLASH_SR_EOP                (1U << 5)
#define FLASH_SR_ERR_MASK           (FLASH_SR_PGERR | FLASH_SR_WRPRTERR)
#define FLASH_SR_CLEAR_ALL          (FLASH_SR_EOP | FLASH_SR_ERR_MASK)
#define FLASH_CR_PG                 (1U << 0)
#define FLASH_CR_PER                (1U << 1)
#define FLASH_CR_STRT               (1U << 6)
#define FLASH_CR_LOCK               (1U << 7)
#define FLASH_PAGE_BYTES            2048U
#define STAGE0_WRP_PROBE_ADDR       0x08001000U
#define STAGE0_WRP_EXPECTED_MASK    0x0000007FU /* 28 KB Stage 0 = 7 x 4 KB WRP units */

static volatile uint32_t g_pendsv_irq_count = 0U;
static volatile uint32_t g_systick_irq_count = 0U;
static volatile uint32_t g_ext_irq0_count = 0U;

/* Full 48-entry (192-byte) ARMv6-M vector table copied to 0x20000000 by Stage 1 */
__attribute__((used, section(".isr_vector")))
static const uintptr_t s_app_vectors[48] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    0U,
    (uintptr_t)&_app_fault_trap,
    0U,
    0U,
    (uintptr_t)&_app_pendsv_handler,   /* Vector 14: PendSV */
    (uintptr_t)&_app_systick_handler,  /* Vector 15: SysTick */
    (uintptr_t)&_app_ext_irq0_handler, /* Vector 16: External IRQ0 */
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_trap,
};

static void __attribute__((used, noreturn)) _app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("nop");
    }
}

static void __attribute__((used)) _app_pendsv_handler(void)
{
    g_pendsv_irq_count = g_pendsv_irq_count + 1U;
}

static void __attribute__((used)) _app_systick_handler(void)
{
    g_systick_irq_count = g_systick_irq_count + 1U;
    /* Disarm SysTick after proving live hardware timer exception delivery */
    MMIO32(SYST_CSR_REG) = 0U;
}

static void __attribute__((used)) _app_ext_irq0_handler(void)
{
    g_ext_irq0_count = g_ext_irq0_count + 1U;
    MMIO32(NVIC_ICER_REG) = 1U;
    MMIO32(NVIC_ICPR_REG) = 1U;
}

static void exercise_sram_remapped_irqs(void)
{
    g_pendsv_irq_count = 0U;
    g_systick_irq_count = 0U;
    g_ext_irq0_count = 0U;

    /* 1. Trigger PendSV (vector 14 @ 0x00000038 -> SRAM 0x20000038) */
    MMIO32(SCB_ICSR_REG) = SCB_ICSR_PENDSVSET;

    /* 2. Pend external NVIC IRQ0 (vector 16 @ 0x00000040 -> SRAM 0x20000040) */
    MMIO32(NVIC_ICPR_REG) = 1U;
    MMIO32(NVIC_ISER_REG) = 1U;
    MMIO32(NVIC_ISPR_REG) = 1U;

    /* 3. Arm SysTick hardware timer IRQ (vector 15 @ 0x0000003C -> SRAM 0x2000003C) */
    MMIO32(SYST_CSR_REG) = 0U;
    MMIO32(SYST_RVR_REG) = 256U;
    MMIO32(SYST_CVR_REG) = 0U;
    MMIO32(SYST_CSR_REG) = (SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE);

    __asm__ volatile("dsb sy\n\tisb sy\n\tcpsie i" ::: "memory");

    for (uint32_t spin = 0U; spin < 200000U; spin++) {
        if ((g_pendsv_irq_count > 0U) && (g_systick_irq_count > 0U) && (g_ext_irq0_count > 0U)) {
            break;
        }
        __asm__ volatile("nop");
    }

    __asm__ volatile("cpsid i\n\tdsb sy\n\tisb sy" ::: "memory");
    MMIO32(SYST_CSR_REG) = 0U;
    MMIO32(NVIC_ICER_REG) = 1U;
}

static inline void wdt_kick(void)
{
    MMIO32(CHIP_REG_IWDG_KR) = IWDG_KR_RELOAD_VAL;
}

static void app_uart_init(void)
{
    MMIO32(CHIP_REG_RCC_APB2ENR) |= RCC_APB2ENR_USART1EN_BIT;
    (void)MMIO32(CHIP_REG_RCC_APB2ENR);
    MMIO32(CHIP_REG_USART1_CR1) = 0U;
    uint32_t brr = (CHIP_CPU_FREQ_HZ + (TOOB_DRIVER_UART_BAUDRATE / 2U)) / TOOB_DRIVER_UART_BAUDRATE;
    if (brr < 16U) {
        brr = 16U;
    }
    MMIO32(CHIP_REG_USART1_BRR) = brr;
    MMIO32(CHIP_REG_USART1_ICR) = USART_ICR_ERR_CLEAR;
    MMIO32(CHIP_REG_USART1_CR1) = (USART_CR1_UE | USART_CR1_RE | USART_CR1_TE);
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
        if ((isr & USART_ISR_ERR_MASK) != 0U) {
            MMIO32(CHIP_REG_USART1_ICR) = USART_ICR_ERR_CLEAR;
        }
        if ((isr & USART_ISR_RXNE) != 0U) {
            return (uint8_t)(MMIO32(CHIP_REG_USART1_RDR) & 0xFFU);
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
 * libtoob OS Porting Layer (STM32F072 2 KB Pages + 16-bit Halfword FPEC + RTC BKP)
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

static bool app_program_halfword(uint32_t aligned_addr, uint16_t hw)
{
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PG;
    MMIO16(aligned_addr) = hw;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t sr = MMIO32(CHIP_REG_FLASH_SR);
    if ((sr & FLASH_SR_ERR_MASK) != 0U) {
        MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
        return false;
    }
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_EOP;
    return true;
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
    if ((addr < CHIP_FLASH_BASE_ADDR) ||
        ((addr - CHIP_FLASH_BASE_ADDR) > CHIP_FLASH_TOTAL_SIZE) ||
        (len > (CHIP_FLASH_TOTAL_SIZE - (addr - CHIP_FLASH_BASE_ADDR)))) {
        return TOOB_ERR_FLASH;
    }

    if (!app_flash_unlock()) {
        return TOOB_ERR_FLASH;
    }

    uint32_t cur_addr = addr;
    uint32_t pos = 0U;
    while (pos < len) {
        if ((pos & 0xFFU) == 0U) {
            wdt_kick();
        }
        uint16_t hw = 0xFFFFU;
        uint32_t write_addr = cur_addr;
        if ((cur_addr & 1U) != 0U) {
            write_addr = cur_addr - 1U;
            hw = 0x00FFU | (uint16_t)((uint16_t)buf[pos] << 8U);
            cur_addr += 1U;
            pos += 1U;
        } else if ((len - pos) >= 2U) {
            hw = (uint16_t)buf[pos] | (uint16_t)((uint16_t)buf[pos + 1U] << 8U);
            cur_addr += 2U;
            pos += 2U;
        } else {
            hw = (uint16_t)buf[pos] | 0xFF00U;
            cur_addr += 1U;
            pos += 1U;
        }

        if (!app_program_halfword(write_addr, hw)) {
            app_flash_lock();
            return TOOB_ERR_FLASH;
        }
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
    if (((addr - CHIP_FLASH_BASE_ADDR) % FLASH_PAGE_BYTES) != 0U ||
        (len % FLASH_PAGE_BYTES) != 0U) {
        return TOOB_ERR_FLASH;
    }

    for (uint32_t off = 0U; off < len; off += FLASH_PAGE_BYTES) {
        wdt_kick();
        if (!app_flash_unlock()) {
            return TOOB_ERR_FLASH;
        }

        MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER;
        MMIO32(CHIP_REG_FLASH_AR) = addr + off;
        MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER | FLASH_CR_STRT;
        __asm__ volatile("dsb sy" ::: "memory");

        while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
        }
        uint32_t sr = MMIO32(CHIP_REG_FLASH_SR);
        MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
        app_flash_lock();

        if ((sr & FLASH_SR_ERR_MASK) != 0U) {
            return TOOB_ERR_FLASH;
        }
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
    uint32_t wrpr = MMIO32(CHIP_REG_FLASH_WRPR);
    uint32_t orig_word = MMIO32(STAGE0_WRP_PROBE_ADDR);

    (void)app_flash_unlock();

    /* Attempt 1: Erase hardware-protected Stage-0 Page 2 (@ 0x08001000) */
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER;
    MMIO32(CHIP_REG_FLASH_AR) = STAGE0_WRP_PROBE_ADDR;
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER | FLASH_CR_STRT;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t erase_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    /* Attempt 2: Program 16-bit halfword 0x0000 into protected Stage-0 @ 0x08001000 */
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PG;
    MMIO16(STAGE0_WRP_PROBE_ADDR) = 0x0000U;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t write_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    app_flash_lock();

    uint32_t after_word = MMIO32(STAGE0_WRP_PROBE_ADDR);
    uint32_t wrpr_locked = ((wrpr & STAGE0_WRP_EXPECTED_MASK) == 0U) ? 1U : 0U;
    uint32_t wrperr_erase = ((erase_sr & FLASH_SR_WRPRTERR) != 0U) ? 1U : 0U;
    uint32_t wrperr_write = ((write_sr & FLASH_SR_WRPRTERR) != 0U) ? 1U : 0U;
    uint32_t intact = (after_word == orig_word) ? 1U : 0U;

    uart_puts("[APP] WRP_TEST wrpr_locked=");
    uart_put_dec(wrpr_locked);
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
    static uint8_t chunk_buf[256];

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
    /* NOTE: Zero SCB->VTOR writes! Cortex-M0 uses Stage 1's SRAM vector remap at 0x20000000. */
    const uint32_t *src = &_sidata;
    uint32_t *dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0U;
    }

    app_uart_init();
    enable_backup_domain();
    (void)k_app_meta.feature_table[0];

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
        for (;;) {
            __asm__ volatile("wfi");
        }
    }

    wdt_kick();
    exercise_sram_remapped_irqs();
    wdt_kick();

    uint32_t mem_mode = MMIO32(CHIP_REG_SYSCFG_CFGR1) & 0x3U;

    uart_puts("[APP] BOOT ver=");
    uart_puts_volatile(k_app_meta.version);
    uart_puts(" slot=");
    uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : 99U);
    uart_puts(" tent=");
    uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
    uart_puts(" irq_systick=");
    uart_put_dec((g_systick_irq_count > 0U) ? 1U : 0U);
    uart_puts(" irq_pendsv=");
    uart_put_dec((g_pendsv_irq_count > 0U) ? 1U : 0U);
    uart_puts(" irq_ext0=");
    uart_put_dec((g_ext_irq0_count > 0U) ? 1U : 0U);
    uart_puts(" mem_mode=");
    uart_put_dec(mem_mode);
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
        "bl _app_c_init\n"
    );
}
