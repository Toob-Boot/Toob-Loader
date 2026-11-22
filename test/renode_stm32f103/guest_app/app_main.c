/**
 * @file app_main.c
 * @brief Bare-Metal STM32F103 (ARM Cortex-M3, 1 KB/16-Bit FPEC, BKP->DR1..DR4) Guest Firmware for Renode E2E
 *
 * Links directly against production sdk/libtoob to verify:
 *   - Stage 1 -> OS LP-RAM handoff & SCB->VTOR relocation to 0x08030100
 *   - 16-bit Backup Register boot confirmation (BKP->DR1..DR4 at 0x40006C04..0x40006C10,
 *     unlocked via RCC_APB1ENR PWREN|BKPEN + PWR_CR.DBP) + Flash Mailbox dual confirmation
 *   - Streaming OTA ingestion across true 1 KB (1024 B) FPEC pages & 16-bit halfword writes
 *   - Stage-0 FLASH_WRPR + Cortex-M3 PMSAv7 MPU hardware write-protection negative test (TEST_PROTECT)
 *   - True 1 KB FPEC page isolation & NOR 0->1 PGERR verification (TEST_FPEC_1KB)
 *   - Unconfirmed firmware hang for Hardware 40 kHz IWDG Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
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
    uint32_t feature_table[48];
} app_rom_meta_t;

__attribute__((section(".rodata.app_meta"), used))
static const volatile app_rom_meta_t k_app_meta = {
    .version = APP_VERSION_STR,
    .crash_on_boot = (uint32_t)APP_CRASH_ON_BOOT,
#if APP_EXTRA_FEATURE_V3
    .feature_table = {
        0x3103F103U, 0xA5C35A3CU, 0x13579BDFU, 0x2468ACE0U,
        0xF1030001U, 0xF1030002U, 0xF1030003U, 0xF1030004U,
        0x9E3779B9U, 0x85EBCA6BU, 0xC2B2AE35U, 0x27D4EB2FU,
        0x165667B1U, 0xD3A2646CU, 0xFD7046C5U, 0xB55A4F09U,
        0x3C6EF372U, 0xBB67AE85U, 0x6A09E667U, 0x510E527FU,
        0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U, 0x428A2F98U,
        0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU,
        0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U, 0xD807AA98U,
        0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U,
        0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U,
        0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
        0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU, 0x983E5152U,
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
void _app_fault_probe_entry(void);
void _app_fault_probe_c(uint32_t *frame);
static void __attribute__((used, noreturn)) _app_c_init(void);
static void __attribute__((used, noreturn)) _app_fault_trap(void);

__attribute__((used, section(".isr_vector")))
static const uintptr_t s_app_vectors[16] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&_app_fault_trap,
    (uintptr_t)&_app_fault_probe_entry, /* HardFault */
    (uintptr_t)&_app_fault_probe_entry, /* MemManage */
    (uintptr_t)&_app_fault_probe_entry, /* BusFault  */
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
#define MMIO16(addr)                (*(volatile uint16_t *)(uintptr_t)(addr))
#define RO8(addr)                   (*(const volatile uint8_t *)(uintptr_t)(addr))

#define SCB_VTOR_REG                0xE000ED08U
#define SCB_AIRCR_REG               0xE000ED0CU
#define SCB_SHCSR_REG               0xE000ED24U
#define SCB_CFSR_REG                0xE000ED28U
#define SCB_HFSR_REG                0xE000ED2CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U
#define SCB_SHCSR_MEMFAULTENA_BIT   (1U << 16)
#define SCB_HFSR_FORCED_BIT         (1U << 30)

#define RCC_APB2ENR_IOPAEN_BIT      (1U << 2)
#define RCC_APB2ENR_USART1EN_BIT    (1U << 14)
#define GPIOA_CRH_PA9_PA10_MASK     0x00000FF0U
#define GPIOA_CRH_PA9_PA10_CFG      0x000004B0U

#define USART1_SR_DATA_ERR_MASK     0x07U
#define USART1_SR_ERR_MASK          0x0FU
#define USART1_SR_RXNE              (1U << 5)
#define USART1_SR_TC                (1U << 6)
#define USART1_SR_TXE               (1U << 7)
#define USART1_CR1_RE               (1U << 2)
#define USART1_CR1_TE               (1U << 3)
#define USART1_CR1_UE               (1U << 13)

#define IWDG_KR_RELOAD_VAL          0x0000AAAAU
#define RCC_APB1ENR_BKPEN_BIT       (1U << 27)
#define RCC_APB1ENR_PWREN_BIT       (1U << 28)
#define PWR_CR_DBP_BIT              (1U << 8)
#define BKP_DR5_ADDR                0x40006C14U
#define BKP_PERSIST_CANARY          0xBEEFU

/* RM0008 / PM0075 1 KB FPEC Constants */
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
#define FLASH_PAGE_BYTES            1024U

#define STAGE0_WRP_PROBE_ADDR       0x08001000U
#define STAGE0_WRP_EXPECTED_MASK    0x000000FFU /* 32 KB Stage 0 = 8 x 4 KB OB.WRP0[7:0] units */
#define FPEC_1KB_TEST_PAGE_A        0x0807F000U
#define FPEC_1KB_TEST_PAGE_B        0x0807F400U /* Exactly +1024 bytes above Page A */

static volatile uint32_t s_expect_mpu_fault;
static volatile uint32_t s_mpu_fault_count;
static volatile uint32_t s_mpu_last_ipsr;
static volatile uint32_t s_mpu_last_cfsr;

static void __attribute__((used, noreturn)) _app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("nop");
    }
}

void __attribute__((naked, used)) _app_fault_probe_entry(void)
{
    __asm__ volatile(
        ".syntax unified\n\t"
        "tst lr, #4\n\t"
        "ite eq\n\t"
        "mrseq r0, msp\n\t"
        "mrsne r0, psp\n\t"
        "b _app_fault_probe_c\n\t"
    );
}

void __attribute__((used)) _app_fault_probe_c(uint32_t *frame)
{
    uint32_t ipsr = 0U;
    __asm__ volatile("mrs %0, ipsr" : "=r"(ipsr));
    uint32_t cfsr = MMIO32(SCB_CFSR_REG);
    MMIO32(SCB_CFSR_REG) = cfsr;
    MMIO32(SCB_HFSR_REG) = SCB_HFSR_FORCED_BIT;
    if (s_expect_mpu_fault != 0U) {
        uint16_t hw = *(const uint16_t *)(uintptr_t)(frame[6] & ~1U);
        s_expect_mpu_fault = 0U;
        s_mpu_fault_count++;
        s_mpu_last_ipsr = ipsr & 0x1FFU;
        s_mpu_last_cfsr = cfsr;
        frame[6] += (hw >= 0xE800U) ? 4U : 2U;
        return;
    }
    _app_fault_trap();
}

static inline void wdt_kick(void)
{
    MMIO32(CHIP_REG_IWDG_KR) = IWDG_KR_RELOAD_VAL;
}

static void app_uart_init(void)
{
    MMIO32(CHIP_REG_RCC_APB2ENR) |= (RCC_APB2ENR_IOPAEN_BIT | RCC_APB2ENR_USART1EN_BIT);
    (void)MMIO32(CHIP_REG_RCC_APB2ENR);
    uint32_t crh = MMIO32(CHIP_REG_GPIOA_CRH);
    MMIO32(CHIP_REG_GPIOA_CRH) = (crh & ~GPIOA_CRH_PA9_PA10_MASK) | GPIOA_CRH_PA9_PA10_CFG;

    MMIO32(CHIP_REG_USART1_CR1) = 0U;
    uint32_t brr = (CHIP_CPU_FREQ_HZ + (TOOB_DRIVER_UART_BAUDRATE / 2U)) / TOOB_DRIVER_UART_BAUDRATE;
    if (brr < 16U) {
        brr = 16U;
    }
    MMIO32(CHIP_REG_USART1_BRR) = brr;
    MMIO32(CHIP_REG_USART1_CR1) = (USART1_CR1_UE | USART1_CR1_RE | USART1_CR1_TE);
}

static inline void uart_putc(char c)
{
    while ((MMIO32(CHIP_REG_USART1_SR) & USART1_SR_TXE) == 0U) {
    }
    MMIO32(CHIP_REG_USART1_DR) = (uint32_t)(uint8_t)c;
}

static inline void uart_flush(void)
{
    while ((MMIO32(CHIP_REG_USART1_SR) & USART1_SR_TC) == 0U) {
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
        uint32_t sr = MMIO32(CHIP_REG_USART1_SR);
        if ((sr & USART1_SR_RXNE) != 0U) {
            uint8_t b = (uint8_t)(MMIO32(CHIP_REG_USART1_DR) & 0xFFU);
            if ((sr & USART1_SR_DATA_ERR_MASK) != 0U) {
                continue;
            }
            return b;
        }
        if ((sr & USART1_SR_ERR_MASK) != 0U) {
            (void)MMIO32(CHIP_REG_USART1_DR);
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
 * libtoob OS Porting Layer (STM32F103 1 KB Pages + 16-Bit FPEC + 16-Bit BKP->DR1..DR4)
 * ============================================================================ */

static void enable_backup_domain(void)
{
    MMIO32(CHIP_REG_RCC_APB1ENR) |= (RCC_APB1ENR_PWREN_BIT | RCC_APB1ENR_BKPEN_BIT);
    (void)MMIO32(CHIP_REG_RCC_APB1ENR);
    MMIO32(CHIP_REG_PWR_CR) |= PWR_CR_DBP_BIT;
    (void)MMIO32(CHIP_REG_PWR_CR);
}

toob_status_t toob_os_confirm_rtc_write(uint64_t nonce)
{
    enable_backup_domain();

    uint32_t dr1 = (uint32_t)(nonce & 0xFFFFULL);
    uint32_t dr2 = (uint32_t)((nonce >> 16U) & 0xFFFFULL);
    uint32_t dr3 = (uint32_t)((nonce >> 32U) & 0xFFFFULL);
    uint32_t dr4 = (uint32_t)((nonce >> 48U) & 0xFFFFULL);

    MMIO32(CHIP_REG_BKP_DR1) = dr1;
    MMIO32(CHIP_REG_BKP_DR2) = dr2;
    MMIO32(CHIP_REG_BKP_DR3) = dr3;
    MMIO32(CHIP_REG_BKP_DR4) = dr4;
    __asm__ volatile("dsb sy" ::: "memory");

    if (((MMIO32(CHIP_REG_BKP_DR1) & 0xFFFFU) != dr1) ||
        ((MMIO32(CHIP_REG_BKP_DR2) & 0xFFFFU) != dr2) ||
        ((MMIO32(CHIP_REG_BKP_DR3) & 0xFFFFU) != dr3) ||
        ((MMIO32(CHIP_REG_BKP_DR4) & 0xFFFFU) != dr4)) {
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
            hw = (uint16_t)RO8(write_addr) | (uint16_t)((uint16_t)buf[pos] << 8U);
            cur_addr += 1U;
            pos += 1U;
        } else if ((len - pos) >= 2U) {
            hw = (uint16_t)buf[pos] | (uint16_t)((uint16_t)buf[pos + 1U] << 8U);
            cur_addr += 2U;
            pos += 2U;
        } else {
            hw = (uint16_t)buf[pos] | (uint16_t)((uint16_t)RO8(cur_addr + 1U) << 8U);
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

static void handle_test_protect(void)
{
    wdt_kick();

    /* 1. Verify Stage 1 configured Cortex-M3 PMSAv7 MPU Region 0 [0x08000000, +32KB) as RO (AP=0b110) */
    uint32_t mpu_ctrl = MMIO32(CHIP_REG_MPU_CTRL);
    MMIO32(CHIP_REG_MPU_RNR) = 0U;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    uint32_t mpu_rbar = MMIO32(CHIP_REG_MPU_RBAR);
    uint32_t mpu_rasr = MMIO32(CHIP_REG_MPU_RASR);

    uint32_t mpu_active = (((mpu_ctrl & 0x05U) == 0x05U) &&
                           ((mpu_rbar & 0xFFFFFFE0U) == 0x08000000U) &&
                           ((mpu_rasr & 0x0700003FU) == 0x0600001DU)) ? 1U : 0U;

    uint32_t orig_word = MMIO32(STAGE0_WRP_PROBE_ADDR);

    /* 2. Prove live Privileged CPU store into Stage 0 triggers synchronous Cortex-M3 MPU fault */
    MMIO32(SCB_SHCSR_REG) |= SCB_SHCSR_MEMFAULTENA_BIT;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

    volatile uint32_t ram_scratch = 0U;
    s_mpu_fault_count = 0U;
    s_mpu_last_ipsr = 0U;
    s_mpu_last_cfsr = 0U;
    s_expect_mpu_fault = 1U;
    ram_scratch = 0xA5A55A5AU;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    uint32_t ram_ok = ((s_mpu_fault_count == 0U) && (ram_scratch == 0xA5A55A5AU)) ? 1U : 0U;

    s_expect_mpu_fault = 1U;
    uint32_t zero_val = 0U;
    uint32_t probe_addr = STAGE0_WRP_PROBE_ADDR;
    __asm__ volatile(
        ".syntax unified\n\t"
        "str.w %0, [%1]\n\t"
        "dsb sy\n\t"
        "isb sy"
        :
        : "r"(zero_val), "r"(probe_addr)
        : "memory"
    );
    s_expect_mpu_fault = 0U;

    uint32_t mpu_trapped = ((ram_ok == 1U) &&
                            (s_mpu_fault_count == 1U) &&
                            ((s_mpu_last_ipsr == 3U) || (s_mpu_last_ipsr == 4U))) ? 1U : 0U;

    /* 3. Verify Option-Byte FLASH_WRPR locks Stage 0 (OB.WRP0[7:0] = 0x00 -> 8 x 4 KB = 32 KB) */
    uint32_t wrpr = MMIO32(CHIP_REG_FLASH_WRPR);
    uint32_t wrpr_locked = ((wrpr & STAGE0_WRP_EXPECTED_MASK) == 0U) ? 1U : 0U;

    (void)app_flash_unlock();

    /* Attempt A: 1 KB FPEC Page Erase on Stage-0 Page 4 (0x08001000) */
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER;
    MMIO32(CHIP_REG_FLASH_AR) = STAGE0_WRP_PROBE_ADDR;
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PER | FLASH_CR_STRT;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t erase_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    /* Attempt B: Temporarily disable MPU ONLY to prove hardware FPEC OB.WRP rejects 16-bit halfword writes */
    MMIO32(CHIP_REG_MPU_CTRL) = 0U;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");

    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PG;
    MMIO16(STAGE0_WRP_PROBE_ADDR) = 0x0000U;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t write_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;

    MMIO32(CHIP_REG_MPU_CTRL) = mpu_ctrl;
    __asm__ volatile("dsb sy\n\tisb sy" ::: "memory");
    app_flash_lock();

    uint32_t wrperr_erase = ((erase_sr & FLASH_SR_WRPRTERR) != 0U) ? 1U : 0U;
    uint32_t wrperr_write = ((write_sr & FLASH_SR_WRPRTERR) != 0U) ? 1U : 0U;
    uint32_t intact = (MMIO32(STAGE0_WRP_PROBE_ADDR) == orig_word) ? 1U : 0U;

    uart_puts("[APP] PROTECT_TEST mpu_active=");
    uart_put_dec(mpu_active);
    uart_puts(" mpu_trapped=");
    uart_put_dec(mpu_trapped);
    uart_puts(" wrpr_locked=");
    uart_put_dec(wrpr_locked);
    uart_puts(" wrperr_erase=");
    uart_put_dec(wrperr_erase);
    uart_puts(" wrperr_write=");
    uart_put_dec(wrperr_write);
    uart_puts(" stage0_intact=");
    uart_put_dec(intact);
    uart_puts("\n");
}

static void handle_test_fpec_1kb(void)
{
    wdt_kick();

    toob_status_t er_a0 = toob_os_flash_erase(FPEC_1KB_TEST_PAGE_A, FLASH_PAGE_BYTES);
    toob_status_t er_b0 = toob_os_flash_erase(FPEC_1KB_TEST_PAGE_B, FLASH_PAGE_BYTES);

    (void)app_flash_unlock();
    bool ok_a = app_program_halfword(FPEC_1KB_TEST_PAGE_A, 0xA55AU);
    bool ok_b = app_program_halfword(FPEC_1KB_TEST_PAGE_B, 0x5AA5U);

    /* Attempt illegal 0 -> 1 NOR overwrite (0xFFFF onto 0xA55A) without erasing */
    MMIO32(CHIP_REG_FLASH_CR) = FLASH_CR_PG;
    MMIO16(FPEC_1KB_TEST_PAGE_A) = 0xFFFFU;
    __asm__ volatile("dsb sy" ::: "memory");
    while ((MMIO32(CHIP_REG_FLASH_SR) & FLASH_SR_BSY) != 0U) {
    }
    uint32_t pgerr_sr = MMIO32(CHIP_REG_FLASH_SR);
    MMIO32(CHIP_REG_FLASH_SR) = FLASH_SR_CLEAR_ALL;
    app_flash_lock();

    uint32_t pgerr_0to1 = (((pgerr_sr & FLASH_SR_PGERR) != 0U) &&
                           (MMIO16(FPEC_1KB_TEST_PAGE_A) == 0xA55AU)) ? 1U : 0U;

    /* Erase ONLY Page A (0x0807F000); Page B at +1024B (0x0807F400) MUST survive untouched! */
    toob_status_t er_a1 = toob_os_flash_erase(FPEC_1KB_TEST_PAGE_A, FLASH_PAGE_BYTES);
    uint32_t isolated = ((er_a0 == TOOB_OK) && (er_b0 == TOOB_OK) && (er_a1 == TOOB_OK) &&
                         ok_a && ok_b &&
                         (MMIO16(FPEC_1KB_TEST_PAGE_A) == 0xFFFFU) &&
                         (MMIO16(FPEC_1KB_TEST_PAGE_B) == 0x5AA5U)) ? 1U : 0U;

    toob_status_t er_b1 = toob_os_flash_erase(FPEC_1KB_TEST_PAGE_B, FLASH_PAGE_BYTES);
    if (er_b1 != TOOB_OK) {
        isolated = 0U;
    }

    uart_puts("[APP] FPEC_1KB pgerr_0to1=");
    uart_put_dec(pgerr_0to1);
    uart_puts(" page_1kb_isolated=");
    uart_put_dec(isolated);
    uart_puts("\n");
}

static void handle_test_bkp_gate_and_seed(void)
{
    enable_backup_domain();
    MMIO32(BKP_DR5_ADDR) = 0U;
    __asm__ volatile("dsb sy" ::: "memory");

    /* Clear PWR_CR.DBP and prove BKP->DR5 rejects writes when DBP=0 */
    MMIO32(CHIP_REG_PWR_CR) &= ~PWR_CR_DBP_BIT;
    __asm__ volatile("dsb sy" ::: "memory");
    MMIO32(BKP_DR5_ADDR) = 0x1234U;
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t dbp_gated = ((MMIO32(BKP_DR5_ADDR) & 0xFFFFU) == 0U) ? 1U : 0U;

    /* Re-enable DBP and write 16-bit canary 0xBEEF (plus high bits 0xDEAD0000 which BKP masks to 0!) */
    enable_backup_domain();
    MMIO32(BKP_DR5_ADDR) = 0xDEADBEEFU;
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t raw_dr5 = MMIO32(BKP_DR5_ADDR);
    uint32_t halfword_exact = (raw_dr5 == BKP_PERSIST_CANARY) ? 1U : 0U;

    uint32_t dr_confirm_any = (MMIO32(CHIP_REG_BKP_DR1) |
                               MMIO32(CHIP_REG_BKP_DR2) |
                               MMIO32(CHIP_REG_BKP_DR3) |
                               MMIO32(CHIP_REG_BKP_DR4)) & 0xFFFFU;

    uart_puts("[APP] BKP_STATUS dbp_gated=");
    uart_put_dec(dbp_gated);
    uart_puts(" dr5_16bit=");
    uart_put_dec(halfword_exact);
    uart_puts(" dr1_4_nonzero=");
    uart_put_dec((dr_confirm_any != 0U) ? 1U : 0U);
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
    uint32_t dr5_persisted = ((MMIO32(BKP_DR5_ADDR) & 0xFFFFU) == BKP_PERSIST_CANARY) ? 1U : 0U;

    uart_puts("[APP] BOOT ver=");
    uart_puts_volatile(k_app_meta.version);
    uart_puts(" slot=");
    uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : 99U);
    uart_puts(" tent=");
    uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
    uart_puts(" bkp_dr5=");
    uart_put_dec(dr5_persisted);
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
        } else if (strcmp(line, "TEST_PROTECT") == 0) {
            handle_test_protect();
        } else if (strcmp(line, "TEST_FPEC_1KB") == 0) {
            handle_test_fpec_1kb();
        } else if (strcmp(line, "TEST_BKP") == 0) {
            handle_test_bkp_gate_and_seed();
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
