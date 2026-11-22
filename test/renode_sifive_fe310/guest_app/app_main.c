/**
 * @file app_main.c
 * @brief Bare-Metal SiFive FE310-G002 Guest Firmware for Full-System Renode E2E Testing
 *
 * Links against production sdk/libtoob and sifive_spi_xip/flash.c to exercise:
 *   - Stage 1 -> OS DTIM .noinit handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: AON backup0..1 + Flash Mailbox)
 *   - Streaming OTA ingestion over QSPI0 XIP-toggle RAM functions (full TBM1 + TDS1 delta)
 *   - Unconfirmed firmware hang for Hardware AON Watchdog Auto-Rollback
 *   - Live M-mode Hardware PMP Stage-0 Isolation & Non-Brickability audit (PMP_TEST)
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated_boot_config.h"
#include "libtoob.h"
#include "sha256.h"
#include "sifive_spi_xip.h"

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
extern uint32_t __global_pointer$;

#define FE310_REG32(addr)        (*(volatile uint32_t *)(uintptr_t)(addr))

#define UART0_TXDATA_REG         (CHIP_REG_UART0_BASE + 0x00U)
#define UART0_RXDATA_REG         (CHIP_REG_UART0_BASE + 0x04U)
#define UART0_TXCTRL_REG         (CHIP_REG_UART0_BASE + 0x08U)
#define UART0_RXCTRL_REG         (CHIP_REG_UART0_BASE + 0x0CU)
#define UART0_DIV_REG            (CHIP_REG_UART0_BASE + 0x18U)
#define UART0_FIFO_FLAG_BIT      0x80000000U

#define AON_WDOG_FEED_REG        (CHIP_REG_AON_WDOG_BASE + 0x18U)
#define AON_WDOG_KEY_REG         (CHIP_REG_AON_WDOG_BASE + 0x1CU)
#define AON_SW_RESET_REG         (CHIP_REG_AON_WDOG_BASE + 0x150U)
#define AON_WDOG_UNLOCK_KEY      0x0051F15EU
#define AON_WDOG_FOOD_VAL        0x0D99F07EU
#define AON_SW_RESET_MAGIC       0x55AAAA55U

static inline void wdt_kick(void)
{
    FE310_REG32(AON_WDOG_KEY_REG) = AON_WDOG_UNLOCK_KEY;
    FE310_REG32(AON_WDOG_FEED_REG) = AON_WDOG_FOOD_VAL;
}

static void uart_init_115200(void)
{
    uint32_t div = ((uint32_t)CHIP_CPU_FREQ_HZ / 115200U) - 1U;
    FE310_REG32(UART0_DIV_REG) = div;
    FE310_REG32(UART0_TXCTRL_REG) = 1U;
    FE310_REG32(UART0_RXCTRL_REG) = 1U;
}

static inline void uart_putc(char c)
{
    while ((FE310_REG32(UART0_TXDATA_REG) & UART0_FIFO_FLAG_BIT) != 0U) {
    }
    FE310_REG32(UART0_TXDATA_REG) = (uint32_t)(uint8_t)c;
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

static void uart_put_hex32(uint32_t val)
{
    static const char hex[] = "0123456789ABCDEF";
    uart_puts("0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        uart_putc(hex[(val >> (uint32_t)shift) & 0xFU]);
    }
}

static uint8_t uart_getc_wdt_safe(void)
{
    uint32_t spin = 0U;
    for (;;) {
        uint32_t rx = FE310_REG32(UART0_RXDATA_REG);
        if ((rx & UART0_FIFO_FLAG_BIT) == 0U) {
            return (uint8_t)(rx & 0xFFU);
        }
        if ((++spin & 0x1FFFU) == 0U) {
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
    while ((*s >= '0') && (*s <= '9')) {
        v = (v * 10U) + (uint32_t)(*s - '0');
        s++;
    }
    return v;
}

/* ============================================================================
 * libtoob OS Porting Layer (delegated to production sifive_spi_xip/flash.c)
 * ============================================================================ */

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
    wdt_kick();
    return (sifive_spi_xip_read(addr, buf, len) == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    wdt_kick();
    boot_status_t st = sifive_spi_xip_write(addr, buf, len);
    wdt_kick();
    return (st == BOOT_OK) ? TOOB_OK : TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len)
{
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr % (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE) != 0U) {
        return TOOB_ERR_FLASH;
    }

    uint32_t num_sec = (len + (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE - 1U) /
                       (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE;
    for (uint32_t i = 0U; i < num_sec; i++) {
        wdt_kick();
        uint32_t sec_addr = addr + (i * (uint32_t)CHIP_FLASH_MAX_SECTOR_SIZE);
        if (sifive_spi_xip_erase_sector(sec_addr) != BOOT_OK) {
            return TOOB_ERR_FLASH;
        }
    }
    wdt_kick();
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

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32])
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
    FE310_REG32(AON_SW_RESET_REG) = AON_SW_RESET_MAGIC;
    for (;;) {
        __asm__ volatile("nop");
    }
}

/* ============================================================================
 * Hardware PMP Stage-0 Isolation & Non-Brickability Live Audit (PMP_TEST)
 * ============================================================================ */

static volatile uint32_t g_trap_count;
static volatile uint32_t g_last_mcause;
static volatile uint32_t g_last_mtval;

void app_pmp_trap_c_handler(void);
void app_pmp_trap_vector(void);

void app_pmp_trap_c_handler(void)
{
    uint32_t mcause = 0U;
    uint32_t mtval = 0U;
    uint32_t mepc = 0U;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));

    g_last_mcause = mcause;
    g_last_mtval  = mtval;
    g_trap_count  = g_trap_count + 1U;

    /* Advance mepc past trapping 16-bit RVC or 32-bit RV32 instruction */
    uint16_t insn_half = *(const uint16_t *)(uintptr_t)mepc;
    uint32_t step = ((insn_half & 0x3U) == 0x3U) ? 4U : 2U;
    mepc += step;
    __asm__ volatile("csrw mepc, %0" :: "r"(mepc));
}

__attribute__((naked, aligned(4)))
void app_pmp_trap_vector(void)
{
    __asm__ volatile(
        "addi sp, sp, -64\n"
        "sw ra,  0(sp)\n"
        "sw t0,  4(sp)\n"
        "sw t1,  8(sp)\n"
        "sw t2, 12(sp)\n"
        "sw a0, 16(sp)\n"
        "sw a1, 20(sp)\n"
        "sw a2, 24(sp)\n"
        "sw a3, 28(sp)\n"
        "sw a4, 32(sp)\n"
        "sw a5, 36(sp)\n"
        "sw a6, 40(sp)\n"
        "sw a7, 44(sp)\n"
        "sw t3, 48(sp)\n"
        "sw t4, 52(sp)\n"
        "sw t5, 56(sp)\n"
        "sw t6, 60(sp)\n"
        "call app_pmp_trap_c_handler\n"
        "lw ra,  0(sp)\n"
        "lw t0,  4(sp)\n"
        "lw t1,  8(sp)\n"
        "lw t2, 12(sp)\n"
        "lw a0, 16(sp)\n"
        "lw a1, 20(sp)\n"
        "lw a2, 24(sp)\n"
        "lw a3, 28(sp)\n"
        "lw a4, 32(sp)\n"
        "lw a5, 36(sp)\n"
        "lw a6, 40(sp)\n"
        "lw a7, 44(sp)\n"
        "lw t3, 48(sp)\n"
        "lw t4, 52(sp)\n"
        "lw t5, 56(sp)\n"
        "lw t6, 60(sp)\n"
        "addi sp, sp, 64\n"
        "mret\n"
    );
}

static void handle_pmp_test_command(void)
{
    wdt_kick();

    uint32_t cfg_before = 0U;
    uint32_t addr0_before = 0U;
    uint32_t addr1_before = 0U;
    __asm__ volatile("csrr %0, pmpcfg0"  : "=r"(cfg_before));
    __asm__ volatile("csrr %0, pmpaddr0" : "=r"(addr0_before));
    __asm__ volatile("csrr %0, pmpaddr1" : "=r"(addr1_before));

    uint32_t expected_addr0 = ((uint32_t)CHIP_FLASH_XIP_BASE) >> 2U;
    uint32_t expected_addr1 = ((uint32_t)CHIP_FLASH_XIP_BASE + (uint32_t)CHIP_STAGE0_SIZE) >> 2U;
    if (((cfg_before & 0xFFFFU) != 0x8880U) ||
        (addr0_before != expected_addr0) ||
        (addr1_before != expected_addr1)) {
        uart_puts("[APP] PMP_TEST FAIL initial_csr cfg=");
        uart_put_hex32(cfg_before);
        uart_puts("\n");
        return;
    }

    /* Attempt M-mode unlock/tamper of locked PMP CSRs; hardware must ignore writes */
    __asm__ volatile("csrw pmpcfg0, zero" ::: "memory");
    __asm__ volatile("csrw pmpaddr0, zero" ::: "memory");
    __asm__ volatile("csrw pmpaddr1, zero" ::: "memory");

    uint32_t cfg_after = 0U;
    uint32_t addr0_after = 0U;
    uint32_t addr1_after = 0U;
    __asm__ volatile("csrr %0, pmpcfg0"  : "=r"(cfg_after));
    __asm__ volatile("csrr %0, pmpaddr0" : "=r"(addr0_after));
    __asm__ volatile("csrr %0, pmpaddr1" : "=r"(addr1_after));

    if (((cfg_after & 0xFFFFU) != 0x8880U) ||
        (addr0_after != expected_addr0) ||
        (addr1_after != expected_addr1)) {
        uart_puts("[APP] PMP_TEST FAIL csr_unlocked cfg=");
        uart_put_hex32(cfg_after);
        uart_puts("\n");
        return;
    }

    /* Verify M-mode load & store to Stage-0 XIP [0x20000000, 0x20010000) fault synchronously */
    uint32_t saved_mtvec = 0U;
    __asm__ volatile("csrr %0, mtvec" : "=r"(saved_mtvec));
    __asm__ volatile("csrw mtvec, %0" :: "r"((uint32_t)(uintptr_t)&app_pmp_trap_vector) : "memory");

    g_trap_count  = 0U;
    g_last_mcause = 0U;
    volatile uint32_t *stage0_ptr = (volatile uint32_t *)(uintptr_t)CHIP_FLASH_XIP_BASE;
    uint32_t leaked = *stage0_ptr;
    (void)leaked;
    uint32_t load_traps  = g_trap_count;
    uint32_t load_mcause = g_last_mcause;

    g_trap_count  = 0U;
    g_last_mcause = 0U;
    *stage0_ptr   = 0xDEADBEEFU;
    uint32_t store_traps  = g_trap_count;
    uint32_t store_mcause = g_last_mcause;

    __asm__ volatile("csrw mtvec, %0" :: "r"(saved_mtvec) : "memory");

    if ((load_traps != 1U) || (load_mcause != 5U) ||
        (store_traps != 1U) || (store_mcause != 7U)) {
        uart_puts("[APP] PMP_TEST FAIL access_fault load_mcause=");
        uart_put_dec(load_mcause);
        uart_puts(" store_mcause=");
        uart_put_dec(store_mcause);
        uart_puts("\n");
        return;
    }

    /* Verify flash HAL rejects erasing/overwriting Stage 0 physical offset 0x000000 */
    uint32_t dummy_word = 0U;
    toob_status_t erase_st = toob_os_flash_erase(0U, 4096U);
    toob_status_t write_st = toob_os_flash_write(0U, (const uint8_t *)&dummy_word, sizeof(dummy_word));
    if ((erase_st == TOOB_OK) || (write_st == TOOB_OK)) {
        uart_puts("[APP] PMP_TEST FAIL flash_guard_bypassed\n");
        return;
    }

    uart_puts("[APP] PMP_TEST PASS pmpcfg0=");
    uart_put_hex32(cfg_after & 0xFFFFU);
    uart_puts(" load_mcause=");
    uart_put_dec(load_mcause);
    uart_puts(" store_mcause=");
    uart_put_dec(store_mcause);
    uart_puts(" flash_guard=BLOCKED\n");
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
        uint16_t clen = (uint16_t)lo | ((uint16_t)hi << 8);
        if ((clen == 0U) || (clen > sizeof(chunk_buf)) || ((uint32_t)clen > (total_len - rx))) {
            toob_status_t abt = toob_ota_abort(&ota_ctx);
            (void)abt;
            uart_puts("[APP] OTA_ERR len\n");
            return;
        }
        for (uint16_t i = 0U; i < clen; i++) {
            chunk_buf[i] = uart_getc_wdt_safe();
        }
        wdt_kick();
        if (toob_ota_process_chunk(&ota_ctx, chunk_buf, clen) != TOOB_OK) {
            toob_status_t abt = toob_ota_abort(&ota_ctx);
            (void)abt;
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
    __asm__ volatile("fence.i" ::: "memory");

    uart_init_115200();
    (void)sifive_spi_xip_init();

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
        /* Hang intentionally without feeding AON WDT so hardware WDT triggers rollback */
        for (;;) {
            __asm__ volatile("nop");
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
        } else if (strcmp(line, "REBOOT") == 0) {
            uart_puts("[APP] REBOOTING\n");
            system_reboot_intentional();
        } else if (strncmp(line, "OTA ", 4) == 0) {
            uint32_t total_len = parse_u32_dec(line + 4);
            handle_ota_command(total_len);
        } else if (strcmp(line, "PMP_TEST") == 0) {
            handle_pmp_test_command();
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
        ".option push\n"
        ".option norelax\n"
        "la gp, __global_pointer$\n"
        ".option pop\n"
        "la sp, _stack_top\n"
        "j _app_c_init\n"
    );
}
