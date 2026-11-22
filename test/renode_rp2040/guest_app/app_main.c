/**
 * @file app_main.c
 * @brief Bare-Metal Raspberry Pi RP2040 Guest Firmware for Headless Renode 1.17.0 E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS retained LP_RAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: WATCHDOG->SCRATCH1..2 + Flash Mailbox)
 *   - Streaming OTA ingestion over QSPI XIP (toob_ota_begin / process_chunk / finalize)
 *   - Cortex-M0+ SCB->VTOR, PMSAv6 MPU, and SPI NOR BPx+SRP0 Stage-0 non-brickability proof
 *   - Unconfirmed firmware hang for Hardware WATCHDOG (REASON.TIMER) Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated_boot_config.h"
#include "libtoob.h"
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

#define MMIO32(addr)                (*(volatile uint32_t *)(uintptr_t)(addr))

#define APP_VECTOR_ENTRIES          16U
#define APP_META_VER_LEN            16U
#define APP_DEC_BUF_LEN             12U
#define APP_DEC_RADIX               10U
#define APP_HEX_NIBBLES             8U
#define APP_HEX_SHIFT_STEP          4U
#define APP_HEX_NIBBLE_MASK         0xFU
#define APP_HEX_ALPHA_THRESHOLD     10U
#define APP_LINE_BUF_LEN            64U
#define APP_OTA_CMD_PREFIX_LEN      4U
#define APP_OTA_CHUNK_BUF_LEN       512U
#define APP_BYTE_SHIFT              8U
#define APP_BYTE_MASK               0xFFU
#define APP_SHA256_DIGEST_LEN       32U
#define APP_UNKNOWN_SLOT_ID         99U

/* PL011 UART0 (0x40034000) constants */
#define UART_FR_BUSY                (1U << 3)
#define UART_FR_RXFE                (1U << 4)
#define UART_FR_TXFF                (1U << 5)
#define UART_LCR_H_FEN              (1U << 4)
#define UART_LCR_H_WLEN_8           (3U << 5)
#define UART_CR_UARTEN              (1U << 0)
#define UART_CR_TXE                 (1U << 8)
#define UART_CR_RXE                 (1U << 9)
#define UART_IBRD_115200_125MHZ     67U
#define UART_FBRD_115200_125MHZ     52U
#define UART_TX_SPIN_LIMIT          250000U
#define UART_WDT_POLL_MASK          0xFFFFU

/* RP2040 WATCHDOG (0x40058000) constants */
#define WDT_CTRL_ENABLE_BIT         (1U << 30)
#define WDT_RELOAD_TICKS_2S         4000000U

/* RP2040 SSI (0x18000000) + XIP_CTRL (0x14000000) + W25Q16JV constants */
#define SSI_BAUDR_DIV               4U
#define SSI_CTRLR0_CMD_8BIT         0x00070000U
#define SSI_CTRLR0_XIP_32BIT        0x001F0300U
#define SSI_SPI_CTRLR0_XIP_03H      0x03000218U
#define SSI_SR_BUSY_BIT             0x01U
#define SSI_SR_TFNF_BIT             0x02U
#define SSI_SR_TFE_BIT              0x04U
#define SSI_SR_RFNE_BIT             0x08U
#define SSI_SPIN_LIMIT              250000U
#define XIP_CTRL_EN_BIT             0x01U
#define XIP_STAT_FLUSH_RDY_BIT      0x01U

#define NOR_CMD_WRSR                0x01U
#define NOR_CMD_PP                  0x02U
#define NOR_CMD_RDSR1               0x05U
#define NOR_CMD_WREN                0x06U
#define NOR_CMD_SE_4K               0x20U
#define NOR_SR1_WIP_BIT             0x01U
#define NOR_PAGE_SIZE               256U
#define NOR_WIP_SPIN_LIMIT          2000000U

/* ARMv6-M System Control Block + PMSAv6 MPU addresses */
#define SCB_VTOR_ADDR               0xE000ED08U
#define SCB_AIRCR_ADDR              0xE000ED0CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U
#define MPU_CTRL_ADDR               0xE000ED94U
#define MPU_RNR_ADDR                0xE000ED98U
#define MPU_RBAR_ADDR               0xE000ED9CU
#define MPU_RASR_ADDR               0xE000EDA0U

#define STAGE0_ATTACK_FLASH_OFF     0x00001000U
#define STAGE0_ATTACK_XIP_ADDR      (CHIP_FLASH_XIP_BASE + STAGE0_ATTACK_FLASH_OFF)

typedef struct {
    char version[APP_META_VER_LEN];
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

static volatile uint32_t g_expect_mpu_fault = 0U;
static volatile uint32_t g_mpu_fault_count = 0U;

void _app_start(void);
static void __attribute__((used, noreturn)) _app_c_init(void);
static void __attribute__((naked)) app_hardfault_entry(void);

static void __attribute__((used)) app_hardfault_c(uint32_t *frame)
{
    if (g_expect_mpu_fault != 0U) {
        g_expect_mpu_fault = 0U;
        g_mpu_fault_count++;
        /* Advance stacked ReturnAddress past the faulting 16-bit Thumb STR instruction */
        frame[6] += 2U;
        return;
    }
    for (;;) {
        __asm__ volatile("wfi");
    }
}

static void __attribute__((naked)) app_hardfault_entry(void)
{
    __asm__ volatile(
        "mrs r0, msp\n"
        "push {r4, lr}\n"
        "bl app_hardfault_c\n"
        "pop {r4, pc}\n"
    );
}

static void __attribute__((used, noreturn)) app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("wfi");
    }
}

__attribute__((used, section(".isr_vector")))
static const uintptr_t k_app_vectors[APP_VECTOR_ENTRIES] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&app_fault_trap,
    (uintptr_t)&app_hardfault_entry,
    (uintptr_t)&app_fault_trap,
    (uintptr_t)&app_fault_trap,
    (uintptr_t)&app_fault_trap,
    0U,
    0U,
    0U,
    0U,
    (uintptr_t)&app_fault_trap,
    (uintptr_t)&app_fault_trap,
    0U,
    (uintptr_t)&app_fault_trap,
    (uintptr_t)&app_fault_trap,
};

/* ============================================================================
 * Bare-Metal PL011 UART0 + RP2040 WATCHDOG Helpers
 * ============================================================================ */

static inline void wdt_kick(void)
{
    if ((MMIO32(CHIP_REG_WATCHDOG_CTRL) & WDT_CTRL_ENABLE_BIT) != 0U) {
        MMIO32(CHIP_REG_WATCHDOG_LOAD) = WDT_RELOAD_TICKS_2S;
    }
}

static void uart_init(void)
{
    MMIO32(CHIP_REG_UART0_UARTCR) = 0U;
    MMIO32(CHIP_REG_UART0_UARTIBRD) = UART_IBRD_115200_125MHZ;
    MMIO32(CHIP_REG_UART0_UARTFBRD) = UART_FBRD_115200_125MHZ;
    MMIO32(CHIP_REG_UART0_UARTLCR_H) = UART_LCR_H_WLEN_8 | UART_LCR_H_FEN;
    MMIO32(CHIP_REG_UART0_UARTCR) = UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;
}

static void uart_putc(char c)
{
    for (uint32_t spin = 0U; spin < UART_TX_SPIN_LIMIT; spin++) {
        if ((MMIO32(CHIP_REG_UART0_UARTFR) & UART_FR_TXFF) == 0U) {
            break;
        }
    }
    MMIO32(CHIP_REG_UART0_UARTDR) = (uint32_t)(uint8_t)c;
}

static void uart_flush_tx(void)
{
    for (uint32_t spin = 0U; spin < UART_TX_SPIN_LIMIT; spin++) {
        if ((MMIO32(CHIP_REG_UART0_UARTFR) & UART_FR_BUSY) == 0U) {
            break;
        }
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
    char buf[APP_DEC_BUF_LEN];
    uint32_t idx = 0U;
    if (val == 0U) {
        uart_putc('0');
        return;
    }
    while (val > 0U) {
        buf[idx++] = (char)('0' + (val % APP_DEC_RADIX));
        val /= APP_DEC_RADIX;
    }
    while (idx > 0U) {
        idx--;
        uart_putc(buf[idx]);
    }
}

static void uart_put_hex32(uint32_t val)
{
    for (uint32_t i = 0U; i < APP_HEX_NIBBLES; i++) {
        uint32_t shift = (APP_HEX_NIBBLES - 1U - i) * APP_HEX_SHIFT_STEP;
        uint32_t nib = (val >> shift) & APP_HEX_NIBBLE_MASK;
        char c = (nib < APP_HEX_ALPHA_THRESHOLD)
                     ? (char)('0' + nib)
                     : (char)('A' + (nib - APP_HEX_ALPHA_THRESHOLD));
        uart_putc(c);
    }
}

static uint8_t uart_getc_wdt_safe(void)
{
    uint32_t spin = 0U;
    for (;;) {
        if ((MMIO32(CHIP_REG_UART0_UARTFR) & UART_FR_RXFE) == 0U) {
            return (uint8_t)(MMIO32(CHIP_REG_UART0_UARTDR) & APP_BYTE_MASK);
        }
        spin++;
        if ((spin & UART_WDT_POLL_MASK) == 0U) {
            wdt_kick();
        }
    }
}

static size_t uart_read_line(char *buf, size_t max_len)
{
    size_t pos = 0U;
    while ((pos + 1U) < max_len) {
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
    while ((*s >= '0') && (*s <= '9')) {
        v = (v * APP_DEC_RADIX) + (uint32_t)(*s - '0');
        s++;
    }
    return v;
}

/* ============================================================================
 * SRAM-Resident (.data.ramfunc) QSPI SSI Flash & Stage-0 Attack Routines
 * ============================================================================ */

typedef bool (*app_ram_erase_fn_t)(uint32_t sector_addr);
typedef bool (*app_ram_prog_fn_t)(uint32_t page_addr, const uint8_t *src, uint32_t len);
typedef uint32_t (*app_ram_attack_fn_t)(uint32_t flash_off);

static inline __attribute__((always_inline)) void app_ssi_cmd_mode(void)
{
    MMIO32(CHIP_REG_SSI_SSIENR) = 0U;
    MMIO32(CHIP_REG_SSI_BAUDR) = SSI_BAUDR_DIV;
    MMIO32(CHIP_REG_SSI_CTRLR0) = SSI_CTRLR0_CMD_8BIT;
    MMIO32(CHIP_REG_SSI_CTRLR1) = 0U;
    MMIO32(CHIP_REG_SSI_SPI_CTRLR0) = 0U;
}

static inline __attribute__((always_inline)) void app_ssi_cs_begin(void)
{
    MMIO32(CHIP_REG_SSI_SSIENR) = 0U;
    MMIO32(CHIP_REG_SSI_SSIENR) = 1U;
}

static inline __attribute__((always_inline)) bool app_ssi_xfer(uint8_t tx, uint8_t *rx_out)
{
    uint32_t spin = 0U;
    while ((MMIO32(CHIP_REG_SSI_SR) & SSI_SR_TFNF_BIT) == 0U) {
        spin++;
        if (spin >= SSI_SPIN_LIMIT) {
            return false;
        }
    }
    MMIO32(CHIP_REG_SSI_DR0) = (uint32_t)tx;

    spin = 0U;
    while ((MMIO32(CHIP_REG_SSI_SR) & SSI_SR_RFNE_BIT) == 0U) {
        spin++;
        if (spin >= SSI_SPIN_LIMIT) {
            return false;
        }
    }
    uint8_t rx = (uint8_t)(MMIO32(CHIP_REG_SSI_DR0) & APP_BYTE_MASK);
    if (rx_out != NULL) {
        *rx_out = rx;
    }
    return true;
}

static inline __attribute__((always_inline)) void app_ssi_cs_end(void)
{
    for (uint32_t spin = 0U; spin < SSI_SPIN_LIMIT; spin++) {
        uint32_t sr = MMIO32(CHIP_REG_SSI_SR);
        if (((sr & SSI_SR_TFE_BIT) != 0U) && ((sr & SSI_SR_BUSY_BIT) == 0U)) {
            break;
        }
    }
    MMIO32(CHIP_REG_SSI_SSIENR) = 0U;
}

static inline __attribute__((always_inline)) bool app_ssi_wait_wip(uint8_t *sr1_out)
{
    for (uint32_t poll = 0U; poll < NOR_WIP_SPIN_LIMIT; poll++) {
        uint8_t sr1 = NOR_SR1_WIP_BIT;
        app_ssi_cs_begin();
        bool ok = app_ssi_xfer(NOR_CMD_RDSR1, NULL) && app_ssi_xfer(0U, &sr1);
        app_ssi_cs_end();
        if (!ok) {
            return false;
        }
        if ((sr1 & NOR_SR1_WIP_BIT) == 0U) {
            if (sr1_out != NULL) {
                *sr1_out = sr1;
            }
            return true;
        }
    }
    return false;
}

static inline __attribute__((always_inline)) void app_ssi_restore_xip(void)
{
    MMIO32(CHIP_REG_SSI_SSIENR) = 0U;
    MMIO32(CHIP_REG_SSI_BAUDR) = SSI_BAUDR_DIV;
    MMIO32(CHIP_REG_SSI_CTRLR0) = SSI_CTRLR0_XIP_32BIT;
    MMIO32(CHIP_REG_SSI_CTRLR1) = 0U;
    MMIO32(CHIP_REG_SSI_SPI_CTRLR0) = SSI_SPI_CTRLR0_XIP_03H;
    MMIO32(CHIP_REG_SSI_SSIENR) = 1U;

    MMIO32(CHIP_REG_XIP_CTRL_CTRL) = XIP_CTRL_EN_BIT;
    MMIO32(CHIP_REG_XIP_CTRL_FLUSH) = 1U;
    for (uint32_t spin = 0U; spin < SSI_SPIN_LIMIT; spin++) {
        if ((MMIO32(CHIP_REG_XIP_CTRL_STAT) & XIP_STAT_FLUSH_RDY_BIT) != 0U) {
            break;
        }
    }
    __asm__ volatile("dsb sy\nisb sy\n" ::: "memory");
}

static __attribute__((section(".data.ramfunc"), noinline))
bool app_ram_erase_sector_impl(uint32_t sector_addr)
{
    app_ssi_cmd_mode();

    app_ssi_cs_begin();
    bool ok = app_ssi_xfer(NOR_CMD_WREN, NULL);
    app_ssi_cs_end();

    if (ok) {
        app_ssi_cs_begin();
        ok = app_ssi_xfer(NOR_CMD_SE_4K, NULL) &&
             app_ssi_xfer((uint8_t)((sector_addr >> 16U) & APP_BYTE_MASK), NULL) &&
             app_ssi_xfer((uint8_t)((sector_addr >> 8U) & APP_BYTE_MASK), NULL) &&
             app_ssi_xfer((uint8_t)(sector_addr & APP_BYTE_MASK), NULL);
        app_ssi_cs_end();
    }
    if (ok) {
        ok = app_ssi_wait_wip(NULL);
    }

    app_ssi_restore_xip();
    return ok;
}

static __attribute__((section(".data.ramfunc"), noinline))
bool app_ram_prog_chunk_impl(uint32_t page_addr, const uint8_t *src, uint32_t len)
{
    app_ssi_cmd_mode();

    app_ssi_cs_begin();
    bool ok = app_ssi_xfer(NOR_CMD_WREN, NULL);
    app_ssi_cs_end();

    if (ok) {
        app_ssi_cs_begin();
        ok = app_ssi_xfer(NOR_CMD_PP, NULL) &&
             app_ssi_xfer((uint8_t)((page_addr >> 16U) & APP_BYTE_MASK), NULL) &&
             app_ssi_xfer((uint8_t)((page_addr >> 8U) & APP_BYTE_MASK), NULL) &&
             app_ssi_xfer((uint8_t)(page_addr & APP_BYTE_MASK), NULL);
        for (uint32_t i = 0U; ok && (i < len); i++) {
            ok = app_ssi_xfer(src[i], NULL);
        }
        app_ssi_cs_end();
    }
    if (ok) {
        ok = app_ssi_wait_wip(NULL);
    }

    app_ssi_restore_xip();
    return ok;
}

/*
 * Attempts three hostile attacks against Stage 0 from SRAM:
 *   1. SPI NOR 01h WRSR(0x00) to strip SRP0 | SEC | TB | BP2 protection
 *   2. SPI NOR 20h 4KB Sector Erase at flash_off (0x00001000)
 *   3. SPI NOR 02h Page Program of 0x00000000 at flash_off (0x00001000)
 * Returns ((pre_sr1 << 8) | post_sr1).
 */
static __attribute__((section(".data.ramfunc"), noinline))
uint32_t app_ram_stage0_attack_impl(uint32_t flash_off)
{
    app_ssi_cmd_mode();

    uint8_t pre_sr1 = 0U;
    (void)app_ssi_wait_wip(&pre_sr1);

    /* Attack 1: Try to clear Status Register 1 BPx bits via 01h WRSR(0x00) */
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_WREN, NULL);
    app_ssi_cs_end();
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_WRSR, NULL);
    (void)app_ssi_xfer(0x00U, NULL);
    app_ssi_cs_end();
    (void)app_ssi_wait_wip(NULL);

    /* Attack 2: Try 20h 4KB Sector Erase on Stage 0 sector 0x00001000 */
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_WREN, NULL);
    app_ssi_cs_end();
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_SE_4K, NULL);
    (void)app_ssi_xfer((uint8_t)((flash_off >> 16U) & APP_BYTE_MASK), NULL);
    (void)app_ssi_xfer((uint8_t)((flash_off >> 8U) & APP_BYTE_MASK), NULL);
    (void)app_ssi_xfer((uint8_t)(flash_off & APP_BYTE_MASK), NULL);
    app_ssi_cs_end();
    (void)app_ssi_wait_wip(NULL);

    /* Attack 3: Try 02h Page Program of 0x00000000 on Stage 0 offset 0x00001000 */
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_WREN, NULL);
    app_ssi_cs_end();
    app_ssi_cs_begin();
    (void)app_ssi_xfer(NOR_CMD_PP, NULL);
    (void)app_ssi_xfer((uint8_t)((flash_off >> 16U) & APP_BYTE_MASK), NULL);
    (void)app_ssi_xfer((uint8_t)((flash_off >> 8U) & APP_BYTE_MASK), NULL);
    (void)app_ssi_xfer((uint8_t)(flash_off & APP_BYTE_MASK), NULL);
    (void)app_ssi_xfer(0x00U, NULL);
    (void)app_ssi_xfer(0x00U, NULL);
    (void)app_ssi_xfer(0x00U, NULL);
    (void)app_ssi_xfer(0x00U, NULL);
    app_ssi_cs_end();

    uint8_t post_sr1 = 0U;
    (void)app_ssi_wait_wip(&post_sr1);

    app_ssi_restore_xip();
    return ((uint32_t)pre_sr1 << 8U) | (uint32_t)post_sr1;
}

static volatile app_ram_erase_fn_t s_app_erase_fn = app_ram_erase_sector_impl;
static volatile app_ram_prog_fn_t s_app_prog_fn = app_ram_prog_chunk_impl;
static volatile app_ram_attack_fn_t s_app_attack_fn = app_ram_stage0_attack_impl;

/* ============================================================================
 * libtoob OS Porting Layer (RP2040 QSPI XIP + SRAM SSI Flash Commands)
 * ============================================================================ */

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
    if (buf == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }
    wdt_kick();
    const uint8_t *src = (const uint8_t *)(uintptr_t)(CHIP_FLASH_XIP_BASE + addr);
    memcpy(buf, src, len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    if ((buf == NULL) || (len == 0U)) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) ||
        ((len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U)) {
        return TOOB_ERR_FLASH;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }

    uint32_t cur = addr;
    uint32_t rem = len;
    const uint8_t *src = buf;

    while (rem > 0U) {
        wdt_kick();
        uint32_t page_rem = NOR_PAGE_SIZE - (cur % NOR_PAGE_SIZE);
        uint32_t chunk = (rem < page_rem) ? rem : page_rem;
        if (!s_app_prog_fn(cur, src, chunk)) {
            return TOOB_ERR_FLASH;
        }
        cur += chunk;
        src += chunk;
        rem -= chunk;
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len)
{
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }

    uint32_t sectors = (len + CHIP_FLASH_MAX_SECTOR_SIZE - 1U) / CHIP_FLASH_MAX_SECTOR_SIZE;
    for (uint32_t i = 0U; i < sectors; i++) {
        wdt_kick();
        uint32_t sec_addr = addr + (i * CHIP_FLASH_MAX_SECTOR_SIZE);
        if (!s_app_erase_fn(sec_addr)) {
            return TOOB_ERR_FLASH;
        }
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx)
{
    if (ctx == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_init((SHA256_CTX *)(uintptr_t)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if ((ctx == NULL) || (data == NULL)) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_update((SHA256_CTX *)(uintptr_t)ctx->opaque, data, len);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[APP_SHA256_DIGEST_LEN])
{
    if ((ctx == NULL) || (out_hash == NULL)) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_final((SHA256_CTX *)(uintptr_t)ctx->opaque, out_hash);
    return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *len)
{
    (void)key;
    (void)buf;
    (void)len;
    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len)
{
    (void)key;
    (void)buf;
    (void)len;
    return TOOB_OK;
}

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    uart_flush_tx();
    __asm__ volatile("dsb sy" ::: "memory");
    MMIO32(SCB_AIRCR_ADDR) = SCB_AIRCR_SYSRESETREQ_VAL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/* ============================================================================
 * Interactive Test Commands (OTA + Stage-0 BPx/MPU/VTOR Proof + Scratch Status)
 * ============================================================================ */

static void handle_stage0_attack_command(void)
{
    wdt_kick();
    uint32_t vtor = MMIO32(SCB_VTOR_ADDR);
    uint32_t mpu_ctrl = MMIO32(MPU_CTRL_ADDR);
    MMIO32(MPU_RNR_ADDR) = 0U;
    uint32_t mpu_rbar = MMIO32(MPU_RBAR_ADDR);
    uint32_t mpu_rasr = MMIO32(MPU_RASR_ADDR);

    uint32_t pre_word = MMIO32(STAGE0_ATTACK_XIP_ADDR);
    uint32_t sr_pair = s_app_attack_fn(STAGE0_ATTACK_FLASH_OFF);

    /* Attack 4: Direct CPU XIP bus overwrite attempt at 0x10001000 (trapped by Cortex-M0+ MPU) */
    g_mpu_fault_count = 0U;
    g_expect_mpu_fault = 1U;
    uintptr_t probe_addr = (uintptr_t)STAGE0_ATTACK_XIP_ADDR;
    __asm__ volatile(
        "movs r0, #0\n"
        "str r0, [%0, #0]\n"
        "dsb sy\n"
        "isb sy\n"
        :
        : "l"(probe_addr)
        : "r0", "memory"
    );
    g_expect_mpu_fault = 0U;

    uint32_t post_word = MMIO32(STAGE0_ATTACK_XIP_ADDR);
    uint32_t post_sr1 = sr_pair & APP_BYTE_MASK;
    bool intact = (post_word == pre_word) && (post_word != 0U) && (post_sr1 == 0xF0U);

    uart_puts("[APP] PROTECT vtor=0x");
    uart_put_hex32(vtor);
    uart_puts(" mpu_ctrl=0x");
    uart_put_hex32(mpu_ctrl);
    uart_puts(" mpu_rbar=0x");
    uart_put_hex32(mpu_rbar);
    uart_puts(" mpu_rasr=0x");
    uart_put_hex32(mpu_rasr);
    uart_puts(" mpu_fault=");
    uart_put_dec(g_mpu_fault_count);
    uart_puts(" sr1=0x");
    uart_put_hex32(post_sr1);
    uart_puts(" pre=0x");
    uart_put_hex32(pre_word);
    uart_puts(" post=0x");
    uart_put_hex32(post_word);
    uart_puts(" status=");
    uart_puts(intact ? "PROTECTED\n" : "MODIFIED\n");
}

static void handle_scratch_status_command(void)
{
    uint32_t s1 = MMIO32(CHIP_REG_WATCHDOG_SCRATCH1);
    uint32_t s2 = MMIO32(CHIP_REG_WATCHDOG_SCRATCH2);
    uint32_t vtor = MMIO32(SCB_VTOR_ADDR);

    uart_puts("[APP] SCRATCH s1=0x");
    uart_put_hex32(s1);
    uart_puts(" s2=0x");
    uart_put_hex32(s2);
    uart_puts(" vtor=0x");
    uart_put_hex32(vtor);
    uart_puts("\n");
}

static void handle_ota_command(uint32_t total_len)
{
    static toob_ota_ctx_t ota_ctx;
    static uint8_t chunk_buf[APP_OTA_CHUNK_BUF_LEN];

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
        uint16_t clen = (uint16_t)lo | (uint16_t)((uint16_t)hi << APP_BYTE_SHIFT);
        if ((clen == 0U) || (clen > sizeof(chunk_buf)) || ((uint32_t)clen > (total_len - rx))) {
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
    const uint32_t *src = &_sidata;
    uint32_t *dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0U;
    }

    uart_init();

    toob_handoff_t handoff;
    memset(&handoff, 0, sizeof(handoff));
    toob_status_t hst = toob_get_handoff(&handoff);

    if (k_app_meta.crash_on_boot != 0U) {
        wdt_kick();
        uart_puts("[APP] BOOT ver=");
        uart_puts_volatile(k_app_meta.version);
        uart_puts(" slot=");
        uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : APP_UNKNOWN_SLOT_ID);
        uart_puts(" tent=");
        uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
        uart_puts(" CRASHING_WITHOUT_CONFIRM\n");
        uart_flush_tx();
        /* Starve RP2040 WATCHDOG so WATCHDOG->REASON.TIMER fires and triggers rollback */
        for (;;) {
            __asm__ volatile("wfi");
        }
    }

    wdt_kick();

    uart_puts("[APP] BOOT ver=");
    uart_puts_volatile(k_app_meta.version);
    uart_puts(" slot=");
    uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : APP_UNKNOWN_SLOT_ID);
    uart_puts(" tent=");
    uart_put_dec(((hst == TOOB_OK) && (handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
    uart_puts(" handoff=");
    uart_puts((hst == TOOB_OK) ? "OK\n" : "ERR\n");

    char line[APP_LINE_BUF_LEN];
    for (;;) {
        size_t n = uart_read_line(line, sizeof(line));
        if (n == 0U) {
            continue;
        }
        if (strcmp(line, "CONFIRM") == 0) {
            toob_status_t cst = toob_confirm_boot();
            uint32_t s1 = MMIO32(CHIP_REG_WATCHDOG_SCRATCH1);
            uint32_t s2 = MMIO32(CHIP_REG_WATCHDOG_SCRATCH2);
            if (cst == TOOB_OK) {
                uart_puts("[APP] CONFIRM status=OK s1=0x");
                uart_put_hex32(s1);
                uart_puts(" s2=0x");
                uart_put_hex32(s2);
                uart_puts("\n");
            } else {
                uart_puts("[APP] CONFIRM status=ERR code=");
                uart_put_dec((uint32_t)cst);
                uart_puts("\n");
            }
        } else if (strcmp(line, "REBOOT") == 0) {
            uart_puts("[APP] REBOOTING\n");
            system_reboot_intentional();
        } else if (strcmp(line, "STAGE0_ATTACK") == 0) {
            handle_stage0_attack_command();
        } else if (strcmp(line, "SCRATCH_STATUS") == 0) {
            handle_scratch_status_command();
        } else if (strncmp(line, "OTA ", APP_OTA_CMD_PREFIX_LEN) == 0) {
            uint32_t total_len = parse_u32_dec(line + APP_OTA_CMD_PREFIX_LEN);
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
        "ldr r0, =0xD0000000\n"
        "ldr r0, [r0]\n"
        "cmp r0, #0\n"
        "bne 1f\n"
        "ldr r0, =_stack_top\n"
        "mov sp, r0\n"
        "bl _app_c_init\n"
        "1:\n"
        "wfe\n"
        "b 1b\n"
    );
}

