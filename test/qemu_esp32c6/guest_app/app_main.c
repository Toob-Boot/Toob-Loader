/**
 * @file app_main.c
 * @brief Bare-Metal ESP32-C6 Guest Firmware for Full-System QEMU E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS LP_RAM (0x50000000) handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: LP_RAM nonce 0x50003FC0 + Flash Mailbox)
 *   - RISC-V PMP_L=1 Stage-0 XIP lockdown verification (M-mode CSR unlock + synchronous mcause=7 trap)
 *   - Streaming OTA ingestion (toob_ota_begin / process_chunk / finalize)
 *   - Unconfirmed firmware hang for Hardware TIMG0 MWDT Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "esp_common.h"
#include "chip_config.h"
#include "arch_riscv.h"
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
extern uint32_t __global_pointer$;

/* ============================================================================
 * Bare-metal UART0 + TIMG0 MWDT Helpers
 * ============================================================================ */

#define UART0_FIFO_REG    (CHIP_REG_UART0_BASE + 0x00U)
#define UART0_STATUS_REG  (CHIP_REG_UART0_BASE + 0x1CU)

static inline void wdt_kick(void)
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
 * RISC-V PMP_L=1 Stage-0 Lockdown Negative-Test Harness
 * ============================================================================ */

static volatile uint32_t s_pmp_trap_count;
static volatile uint32_t s_pmp_trap_mcause;

void __attribute__((naked, aligned(4), section(".iram_text"))) pmp_fault_trap_entry(void);
void __attribute__((naked, aligned(4), section(".iram_text"))) pmp_fault_trap_entry(void)
{
    __asm__ volatile(
        "addi sp, sp, -16\n"
        "sw   t0, 0(sp)\n"
        "sw   t1, 4(sp)\n"
        "sw   t2, 8(sp)\n"
        "csrr t0, mcause\n"
        "la   t1, s_pmp_trap_mcause\n"
        "sw   t0, 0(t1)\n"
        "la   t1, s_pmp_trap_count\n"
        "lw   t2, 0(t1)\n"
        "addi t2, t2, 1\n"
        "sw   t2, 0(t1)\n"
        "csrr t0, mepc\n"
        "lhu  t1, 0(t0)\n"
        "andi t1, t1, 3\n"
        "li   t2, 3\n"
        "addi t0, t0, 2\n"
        "bne  t1, t2, 1f\n"
        "addi t0, t0, 2\n"
        "1:\n"
        "csrw mepc, t0\n"
        "lw   t0, 0(sp)\n"
        "lw   t1, 4(sp)\n"
        "lw   t2, 8(sp)\n"
        "addi sp, sp, 16\n"
        "mret\n"
    );
}

__attribute__((section(".iram_text"), noinline))
static void run_pmp_lockdown_test(void)
{
    const uint32_t expected_addr0 = ((uint32_t)CHIP_FLASH_XIP_BASE) >> 2;
    const uint32_t expected_addr1 = (((uint32_t)CHIP_FLASH_XIP_BASE) + 0x8000U) >> 2;
    const uint32_t expected_cfg16 = 0x8D80U;

    uint32_t orig_cfg0  = csr_read(pmpcfg0);
    uint32_t orig_addr0 = csr_read(pmpaddr0);
    uint32_t orig_addr1 = csr_read(pmpaddr1);

    if (((orig_cfg0 & 0xFFFFU) != expected_cfg16) ||
        (orig_addr0 != expected_addr0) ||
        (orig_addr1 != expected_addr1)) {
        uart_puts("[APP] PMP_LOCK_ERR initial_csr\n");
        return;
    }

    /* Attempt M-mode unlock of PMP_L=1 entries; hardware MUST ignore writes */
    csr_write(pmpcfg0, 0U);
    csr_write(pmpaddr0, 0U);
    csr_write(pmpaddr1, 0U);
    __asm__ volatile("fence iorw, iorw\n\tfence.i" ::: "memory");

    uint32_t after_cfg0  = csr_read(pmpcfg0);
    uint32_t after_addr0 = csr_read(pmpaddr0);
    uint32_t after_addr1 = csr_read(pmpaddr1);
    uint32_t sticky = (((after_cfg0 & 0xFFFFU) == expected_cfg16) &&
                       (after_addr0 == expected_addr0) &&
                       (after_addr1 == expected_addr1)) ? 1U : 0U;

    /* Restore pmp2cfg open NAPOT entry in case unlocked byte 2 was cleared */
    csr_write(pmpaddr2, 0x7FFFFFFFU);
    csr_write(pmpcfg0, orig_cfg0);
    __asm__ volatile("fence iorw, iorw\n\tfence.i" ::: "memory");

    s_pmp_trap_count  = 0U;
    s_pmp_trap_mcause = 0U;

    uint32_t saved_mtvec = csr_read(mtvec);
    csr_write(mtvec, (uint32_t)(uintptr_t)&pmp_fault_trap_entry);

    uint32_t locked_xip = (uint32_t)CHIP_FLASH_XIP_BASE;
    uint32_t poison_val = 0xDEADBEEFU;
    __asm__ volatile(
        "sw %0, 0(%1)\n"
        "fence iorw, iorw\n"
        :
        : "r"(poison_val), "r"(locked_xip)
        : "memory"
    );

    csr_write(mtvec, saved_mtvec);

    uint32_t readback = *(volatile const uint32_t *)(uintptr_t)locked_xip;
    if ((sticky == 1U) &&
        (s_pmp_trap_count == 1U) &&
        (s_pmp_trap_mcause == 7U) &&
        (readback != poison_val)) {
        uart_puts("[APP] PMP_LOCK_OK mcause=7 sticky=1\n");
    } else {
        uart_puts("[APP] PMP_LOCK_ERR traps=");
        uart_put_dec(s_pmp_trap_count);
        uart_puts(" mcause=");
        uart_put_dec(s_pmp_trap_mcause);
        uart_puts(" sticky=");
        uart_put_dec(sticky);
        uart_puts("\n");
    }
}

/* ============================================================================
 * libtoob OS Porting Layer (ESP32-C6 Physical SPI Flash via BootROM)
 * ============================================================================ */

__attribute__((section(".iram_text"), noinline))
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

__attribute__((section(".iram_text"), noinline))
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
            memcpy(buf, ((const uint8_t *)bounce) + head, take);
            addr += take;
            buf += take;
            len -= take;
        }
    }
    return TOOB_OK;
}

__attribute__((section(".iram_text"), noinline))
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
        memcpy(bounce, src, chunk);
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

__attribute__((section(".iram_text"), noinline))
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

/* LP_AON_CPUCORE0_CFG (0x600B1038) bit 28 = CPU_CORE0_SW_RESET (ESP32C6_CORE_SW = 3) */
#define LP_AON_CPUCORE0_CFG_REG     (CHIP_REG_PMU_BASE + 0x1038U)
#define LP_AON_CPU_CORE0_SW_RESET   (1U << 28)

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    while (((REG_READ(UART0_STATUS_REG) >> 16) & 0xFFU) != 0U) {
    }
    REG_WRITE(LP_AON_CPUCORE0_CFG_REG, LP_AON_CPU_CORE0_SW_RESET);
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
        uint16_t clen = (uint16_t)lo | ((uint16_t)hi << 8);
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
    const uint32_t *src = &_siiram;
    uint32_t *dst = &_iram_start;
    while (dst < &_iram_end) {
        *dst++ = *src++;
    }

    src = &_sidata;
    dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0U;
    }
    __asm__ volatile("fence.i" ::: "memory");

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
        while (((REG_READ(UART0_STATUS_REG) >> 16) & 0xFFU) != 0U) {
        }
        /* Hang intentionally WITHOUT feeding TIMG0 MWDT so Stage 1's hardware WDT
         * fires ESP32C6_CORE_MWDT0 and triggers automatic rollback! */
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
        } else if (strcmp(line, "LOCKTEST") == 0) {
            run_pmp_lockdown_test();
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
        ".option push\n"
        ".option norelax\n"
        "la gp, __global_pointer$\n"
        ".option pop\n"
        "la sp, _stack_top\n"
        "j _app_c_init\n"
    );
}
