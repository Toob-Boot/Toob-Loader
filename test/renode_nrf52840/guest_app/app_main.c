/**
 * @file app_main.c
 * @brief Bare-Metal Nordic nRF52840 Guest Firmware for Headless Renode 1.17.0 E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS retained SRAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: retained SRAM nonce + Flash Mailbox)
 *   - Streaming OTA ingestion (toob_ota_begin / process_chunk / finalize)
 *   - Hardware BPROT Stage-0 non-brickability attack simulation (BPROT_ATTACK)
 *   - Unconfirmed firmware hang for Hardware WDT (POWER->RESETREAS.DOG) Auto-Rollback
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

#define UART_ENABLE_ON              4U
#define UART_TASK_TRIGGER           1U
#define UART_EVENT_CLEAR            0U
#define UART_TX_SPIN_LIMIT          200000U
#define UART_WDT_POLL_MASK          0xFFFFU

#define WDT_RUNSTATUS_RUNNING       1U

#define NVMC_READY_MASK             1U
#define NVMC_MODE_REN               0U
#define NVMC_MODE_WEN               1U
#define NVMC_MODE_EEN               2U
#define NVMC_SPIN_LIMIT             2000000U
#define NVMC_WORD_BYTES             4U
#define NVMC_ICACHE_ENABLE          1U

#define SCB_AIRCR_ADDR              0xE000ED0CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U

#define STAGE0_ATTACK_PROBE_ADDR    0x00001000U

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

void _app_start(void);
static void __attribute__((used, noreturn)) _app_c_init(void);

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
    (uintptr_t)&app_fault_trap,
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
 * Bare-Metal UART0 + WDT Helpers
 * ============================================================================ */

static inline void wdt_kick(void)
{
    if ((MMIO32(CHIP_REG_WDT_RUNSTATUS) & WDT_RUNSTATUS_RUNNING) != 0U) {
        MMIO32(CHIP_REG_WDT_RR0) = CHIP_WDT_RELOAD_MAGIC;
    }
}

static void uart_init(void)
{
    MMIO32(CHIP_REG_UART0_TASKS_STOPRX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TASKS_STOPTX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_ENABLE) = 0U;
    MMIO32(CHIP_REG_UART0_BAUDRATE) = CHIP_UART0_BAUD_115200;
    MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) = UART_EVENT_CLEAR;
    MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) = UART_EVENT_CLEAR;
    MMIO32(CHIP_REG_UART0_ENABLE) = UART_ENABLE_ON;
    MMIO32(CHIP_REG_UART0_TASKS_STARTRX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TASKS_STARTTX) = UART_TASK_TRIGGER;
}

static void uart_putc(char c)
{
    MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) = UART_EVENT_CLEAR;
    MMIO32(CHIP_REG_UART0_TASKS_STARTTX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TXD) = (uint32_t)(uint8_t)c;
    for (uint32_t spin = 0U; spin < UART_TX_SPIN_LIMIT; spin++) {
        if (MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) != 0U) {
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
        if (MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) != 0U) {
            MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) = UART_EVENT_CLEAR;
            return (uint8_t)(MMIO32(CHIP_REG_UART0_RXD) & APP_BYTE_MASK);
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
 * libtoob OS Porting Layer (nRF52840 Internal NVMC Flash)
 * ============================================================================ */

static bool nvmc_wait_ready(void)
{
    for (uint32_t spin = 0U; spin < NVMC_SPIN_LIMIT; spin++) {
        if ((MMIO32(CHIP_REG_NVMC_READY) & NVMC_READY_MASK) != 0U) {
            return true;
        }
    }
    return false;
}

static void nvmc_sync_icache(void)
{
    uint32_t cnf = MMIO32(CHIP_REG_NVMC_ICACHECNF);
    if ((cnf & NVMC_ICACHE_ENABLE) != 0U) {
        MMIO32(CHIP_REG_NVMC_ICACHECNF) = cnf & ~NVMC_ICACHE_ENABLE;
        MMIO32(CHIP_REG_NVMC_ICACHECNF) = cnf;
    }
    __asm__ volatile("dsb sy\nisb sy\n" ::: "memory");
}

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
    if (!nvmc_wait_ready()) {
        return TOOB_ERR_FLASH;
    }

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_WEN;
    if (!nvmc_wait_ready()) {
        MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
        return TOOB_ERR_FLASH;
    }

    for (uint32_t off = 0U; off < len; off += NVMC_WORD_BYTES) {
        wdt_kick();
        uint32_t word = 0U;
        memcpy(&word, &buf[off], NVMC_WORD_BYTES);
        MMIO32(CHIP_FLASH_XIP_BASE + addr + off) = word;
        if (!nvmc_wait_ready()) {
            MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
            return TOOB_ERR_FLASH;
        }
    }

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    (void)nvmc_wait_ready();
    nvmc_sync_icache();
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
    if (!nvmc_wait_ready()) {
        return TOOB_ERR_FLASH;
    }

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_EEN;
    if (!nvmc_wait_ready()) {
        MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
        return TOOB_ERR_FLASH;
    }

    uint32_t num_pages = (len + CHIP_FLASH_MAX_SECTOR_SIZE - 1U) / CHIP_FLASH_MAX_SECTOR_SIZE;
    for (uint32_t i = 0U; i < num_pages; i++) {
        wdt_kick();
        uint32_t page_addr = addr + (i * CHIP_FLASH_MAX_SECTOR_SIZE);
        MMIO32(CHIP_REG_NVMC_ERASEPAGE) = page_addr;
        if (!nvmc_wait_ready()) {
            MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
            return TOOB_ERR_FLASH;
        }
    }

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    (void)nvmc_wait_ready();
    nvmc_sync_icache();
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
    __asm__ volatile("dsb sy" ::: "memory");
    MMIO32(SCB_AIRCR_ADDR) = SCB_AIRCR_SYSRESETREQ_VAL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/* ============================================================================
 * Interactive Test Commands (OTA + Hardware BPROT Attack Probe)
 * ============================================================================ */

static void handle_bprot_attack_command(void)
{
    wdt_kick();
    uint32_t cfg0 = MMIO32(CHIP_REG_BPROT_CONFIG0);
    uint32_t pre_word = MMIO32(STAGE0_ATTACK_PROBE_ADDR);

    /* Attempt 1: Raw MMIO NVMC ERASEPAGE against Stage 0 block 1 (0x00001000) */
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_EEN;
    (void)nvmc_wait_ready();
    MMIO32(CHIP_REG_NVMC_ERASEPAGE) = STAGE0_ATTACK_PROBE_ADDR;
    (void)nvmc_wait_ready();

    /* Attempt 2: Raw MMIO NVMC WEN zero-overwrite against Stage 0 word at 0x00001000 */
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_WEN;
    (void)nvmc_wait_ready();
    MMIO32(STAGE0_ATTACK_PROBE_ADDR) = 0U;
    (void)nvmc_wait_ready();
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    (void)nvmc_wait_ready();
    nvmc_sync_icache();

    uint32_t post_word = MMIO32(STAGE0_ATTACK_PROBE_ADDR);
    bool intact = (post_word == pre_word) && (post_word != 0U);

    uart_puts("[APP] BPROT cfg0=0x");
    uart_put_hex32(cfg0);
    uart_puts(" pre=0x");
    uart_put_hex32(pre_word);
    uart_puts(" post=0x");
    uart_put_hex32(post_word);
    uart_puts(" status=");
    uart_puts(intact ? "PROTECTED\n" : "MODIFIED\n");
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
        /* Starve nRF52840 WDT so POWER->RESETREAS.DOG fires and triggers automatic rollback */
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
        } else if (strcmp(line, "BPROT_ATTACK") == 0) {
            handle_bprot_attack_command();
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
        "ldr r0, =_stack_top\n"
        "mov sp, r0\n"
        "b _app_c_init\n"
    );
}
