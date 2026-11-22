/**
 * @file app_main.c
 * @brief Bare-Metal ARM Corstone-300 (Cortex-M55 Non-Secure) Guest Firmware for QEMU TrustZone E2E
 *
 * Executes strictly in ARMv8.1-M Non-Secure Thread Mode (PC at 0x0105xxxx, SP at 0x20040000..0x2007C000)
 * after Stage 1's SAU + MPC + PPC + VTOR_NS + BXNS handoff. Exercises:
 *   - Stage 1 -> Non-Secure OS .noinit handoff verification (toob_get_handoff)
 *   - Live TrustZone Stage-0 & OTP isolation attacks (TEST_TZ_ISOLATION -> SecureFault AUVIOL=1)
 *   - Dual-channel boot confirmation (toob_confirm_boot: shared retention + Non-Secure Mailbox)
 *   - Streaming TBM1 Full & TDS1 Forward-Delta OTA over Non-Secure UART0 (0x49303000)
 *   - Unconfirmed firmware hang for Hardware S32K Watchdog Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "chip_config.h"
#include "boot_layout.h"
#include "sha256.h"

#define TOOB_STR_H(x)               #x
#define TOOB_STR(x)                 TOOB_STR_H(x)
#ifndef APP_VERSION_RAW
#define APP_VERSION_RAW             1.0.0
#endif
#define APP_VERSION_STR             TOOB_STR(APP_VERSION_RAW)

#ifndef APP_CRASH_ON_BOOT
#define APP_CRASH_ON_BOOT           0
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

#define SECURE_ALIAS_BIT            0x10000000U
#define SCB_VTOR_REG                0xE000ED08U
#define SCB_AIRCR_REG               0xE000ED0CU
#define SCB_CCR_REG                 0xE000ED14U
#define SAU_CTRL_REG                0xE000EDD0U
#define SCB_DCCIMVAC_REG            0xE000EF70U
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U
#define SCB_CCR_DC_BIT              (1U << 16)
#define CACHE_LINE_BYTES            32U

/* Non-Secure peripheral aliases permitted by Stage 1 SAU + IoTKit PPC */
#define NS_UART0_BASE               (CHIP_REG_UART0_BASE & ~SECURE_ALIAS_BIT)
#define NS_UART0_DATA               (NS_UART0_BASE + 0x00U)
#define NS_UART0_STATE              (NS_UART0_BASE + 0x04U)
#define CMSDK_UART_STATE_TXFULL     (1U << 0)
#define CMSDK_UART_STATE_RXFULL     (1U << 1)
#define CMSDK_UART_STATE_RXOVR      (1U << 3)

#define NS_S32KWDT_BASE             (CHIP_REG_S32KWDT_BASE & ~SECURE_ALIAS_BIT)
#define NS_S32KWDT_LOAD             (NS_S32KWDT_BASE + 0x000U)
#define NS_S32KWDT_INTCLR           (NS_S32KWDT_BASE + 0x00CU)
#define NS_S32KWDT_LOCK             (NS_S32KWDT_BASE + 0xC00U)
#define S32KWDT_UNLOCK_KEY          0x1ACCE551U
#define S32KWDT_DEFAULT_RELOAD      48000U

#define CORSTONE_SECTOR_BYTES       4096U
#define CORSTONE_WORD_BYTES         4U

/* Stage-0 & Secure OTP attack target addresses */
#define STAGE0_SECURE_PROBE_ADDR    0x11000000U
#define STAGE0_NS_ALIAS_PROBE_ADDR  0x01000000U
#define SECURE_OTP_PROBE_ADDR       0x3007E000U

static void __attribute__((used, noreturn)) _app_fault_trap(void)
{
    for (;;) {
        __asm__ volatile("nop");
    }
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

static inline void wdt_kick(void)
{
    uint32_t load_val = MMIO32(NS_S32KWDT_LOAD);
    if (load_val == 0U) {
        load_val = S32KWDT_DEFAULT_RELOAD;
    }
    MMIO32(NS_S32KWDT_LOCK) = S32KWDT_UNLOCK_KEY;
    MMIO32(NS_S32KWDT_INTCLR) = 1U;
    MMIO32(NS_S32KWDT_LOAD) = load_val;
    MMIO32(NS_S32KWDT_LOCK) = 0U;
}

static inline void uart_putc(char c)
{
    while ((MMIO32(NS_UART0_STATE) & CMSDK_UART_STATE_TXFULL) != 0U) {
    }
    MMIO32(NS_UART0_DATA) = (uint32_t)(uint8_t)c;
}

static inline void uart_flush(void)
{
    while ((MMIO32(NS_UART0_STATE) & CMSDK_UART_STATE_TXFULL) != 0U) {
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

static void uart_put_hex32(uint32_t val)
{
    uart_puts("0x");
    for (uint32_t shift = 32U; shift > 0U; shift -= 4U) {
        uint32_t nib = (val >> (shift - 4U)) & 0x0FU;
        uart_putc((nib < 10U) ? (char)('0' + nib) : (char)('A' + (nib - 10U)));
    }
}

static uint8_t uart_getc_wdt_safe(void)
{
    uint32_t spin = 0U;
    for (;;) {
        uint32_t st = MMIO32(NS_UART0_STATE);
        if ((st & CMSDK_UART_STATE_RXOVR) != 0U) {
            MMIO32(NS_UART0_STATE) = CMSDK_UART_STATE_RXOVR;
        }
        if ((st & CMSDK_UART_STATE_RXFULL) != 0U) {
            return (uint8_t)(MMIO32(NS_UART0_DATA) & 0xFFU);
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
 * libtoob Non-Secure OS Porting Layer (Corstone-300 SAU Non-Secure Flash & Retention)
 * ============================================================================ */

static bool ns_translate_flash_addr(uint32_t addr, uint32_t len, uint32_t *ns_addr_out)
{
    if (len > CHIP_FLASH_TOTAL_SIZE) {
        return false;
    }
    uint32_t max_off = CHIP_FLASH_TOTAL_SIZE - len;
    if ((addr >= CHIP_FLASH_BASE_ADDR) && ((addr - CHIP_FLASH_BASE_ADDR) <= max_off)) {
        *ns_addr_out = addr & ~SECURE_ALIAS_BIT;
        return true;
    }
    uint32_t ns_base = CHIP_FLASH_BASE_ADDR & ~SECURE_ALIAS_BIT;
    if ((addr >= ns_base) && ((addr - ns_base) <= max_off)) {
        *ns_addr_out = addr;
        return true;
    }
    return false;
}

toob_status_t toob_os_confirm_rtc_write(uint64_t nonce)
{
    uint32_t lo = (uint32_t)(nonce & 0xFFFFFFFFULL);
    uint32_t hi = (uint32_t)(nonce >> 32U);
    MMIO32(CHIP_REG_CONFIRM_STORAGE_BASE) = lo;
    MMIO32(CHIP_REG_CONFIRM_STORAGE_BASE + 4U) = hi;
    app_dcache_clean_invalidate_range(CHIP_REG_CONFIRM_STORAGE_BASE, 8U);

    if ((MMIO32(CHIP_REG_CONFIRM_STORAGE_BASE) != lo) ||
        (MMIO32(CHIP_REG_CONFIRM_STORAGE_BASE + 4U) != hi)) {
        return TOOB_ERR_VERIFY;
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len)
{
    if (buf == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        return TOOB_OK;
    }
    uint32_t ns_addr = 0U;
    if (!ns_translate_flash_addr(addr, len, &ns_addr)) {
        return TOOB_ERR_FLASH;
    }
    wdt_kick();
    memcpy(buf, (const void *)(uintptr_t)ns_addr, len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    if ((buf == NULL) || (len == 0U)) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr % CORSTONE_WORD_BYTES) != 0U) {
        return TOOB_ERR_FLASH;
    }
    uint32_t aligned_len = (len + (CORSTONE_WORD_BYTES - 1U)) & ~(CORSTONE_WORD_BYTES - 1U);
    uint32_t ns_addr = 0U;
    if (!ns_translate_flash_addr(addr, aligned_len, &ns_addr)) {
        return TOOB_ERR_FLASH;
    }

    for (uint32_t off = 0U; off < aligned_len; off += CORSTONE_WORD_BYTES) {
        if ((off & 0xFFU) == 0U) {
            wdt_kick();
        }
        uint8_t wb[4];
        for (uint32_t b = 0U; b < 4U; b++) {
            wb[b] = ((off + b) < len) ? buf[off + b] : 0xFFU;
        }
        uint32_t desired = 0U;
        memcpy(&desired, wb, sizeof(desired));
        uint32_t existing = MMIO32(ns_addr + off);
        if ((existing & desired) != desired) {
            return TOOB_ERR_FLASH;
        }
        uint32_t prog = existing & desired;
        MMIO32(ns_addr + off) = prog;
        if (MMIO32(ns_addr + off) != prog) {
            return TOOB_ERR_FLASH;
        }
    }

    app_dcache_clean_invalidate_range(ns_addr, aligned_len);
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len)
{
    if (len == 0U) {
        return TOOB_OK;
    }
    if (((addr % CORSTONE_SECTOR_BYTES) != 0U) || ((len % CORSTONE_SECTOR_BYTES) != 0U)) {
        return TOOB_ERR_FLASH;
    }
    uint32_t ns_addr = 0U;
    if (!ns_translate_flash_addr(addr, len, &ns_addr)) {
        return TOOB_ERR_FLASH;
    }

    for (uint32_t off = 0U; off < len; off += CORSTONE_SECTOR_BYTES) {
        wdt_kick();
        for (uint32_t w = 0U; w < CORSTONE_SECTOR_BYTES; w += CORSTONE_WORD_BYTES) {
            MMIO32(ns_addr + off + w) = 0xFFFFFFFFU;
        }
        app_dcache_clean_invalidate_range(ns_addr + off, CORSTONE_SECTOR_BYTES);
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx)
{
    if (!ctx) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_init((SHA256_CTX *)(uintptr_t)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_update((SHA256_CTX *)(uintptr_t)ctx->opaque, data, len);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32])
{
    if (!ctx || !out_hash) {
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
    uart_flush();
    __asm__ volatile("dsb sy" ::: "memory");
    MMIO32(SCB_AIRCR_REG) = SCB_AIRCR_SYSRESETREQ_VAL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        __asm__ volatile("nop");
    }
}

static uint32_t __attribute__((noinline)) tz_probe_read16_ins(uint32_t target_addr)
{
    register uint32_t r0_val __asm__("r0") = 0xDEADBEEFU;
    register uint32_t r1_ptr __asm__("r1") = target_addr;
    __asm__ volatile(
        ".syntax unified\n"
        "ldr.n r0, [r1]\n"
        : "+l"(r0_val)
        : "l"(r1_ptr)
        : "memory"
    );
    return r0_val;
}

static void __attribute__((noinline)) tz_probe_write16_ins(uint32_t target_addr, uint32_t val)
{
    register uint32_t r1_ptr __asm__("r1") = target_addr;
    register uint32_t r2_val __asm__("r2") = val;
    __asm__ volatile(
        ".syntax unified\n"
        "str.n r2, [r1]\n"
        :
        : "l"(r1_ptr), "l"(r2_val)
        : "memory"
    );
}

static void handle_test_tz_isolation(void)
{
    wdt_kick();

    uint32_t cur_pc = 0U;
    __asm__ volatile("mov %0, pc" : "=r"(cur_pc));
    uint32_t ns_pc_ok = ((cur_pc & SECURE_ALIAS_BIT) == 0U) ? 1U : 0U;

    /* SAU->CTRL (0xE000EDD0) is RAZ/WI from Non-Secure state per ARMv8.1-M architecture */
    uint32_t sau_ns_read = MMIO32(SAU_CTRL_REG);
    uint32_t sau_raz_ok = (sau_ns_read == 0U) ? 1U : 0U;

    MMIO32(CHIP_REG_TZ_FAULT_COUNTER) = 0U;
    app_dcache_clean_invalidate_range(CHIP_REG_TZ_FAULT_COUNTER, sizeof(uint32_t));

    /* Unmask PRIMASK_NS so synchronous Priority-0 SecureFault traps directly to Secure Stage 1 */
    __asm__ volatile("dsb sy\n\tisb sy\n\tcpsie i\n\tisb sy" ::: "memory");

    /* Attack 1: Attempt Non-Secure read of Secure Stage-0 Flash alias (0x11000000) */
    uint32_t leak_s0 = tz_probe_read16_ins(STAGE0_SECURE_PROBE_ADDR);
    app_dcache_clean_invalidate_range(CHIP_REG_TZ_FAULT_COUNTER, sizeof(uint32_t));
    uint32_t cnt_after_s0_read = MMIO32(CHIP_REG_TZ_FAULT_COUNTER);

    /* Attack 2: Attempt Non-Secure write to Non-Secure alias of Stage-0 Flash (0x01000000) */
    tz_probe_write16_ins(STAGE0_NS_ALIAS_PROBE_ADDR, 0x00000000U);
    app_dcache_clean_invalidate_range(CHIP_REG_TZ_FAULT_COUNTER, sizeof(uint32_t));
    uint32_t cnt_after_s0_write = MMIO32(CHIP_REG_TZ_FAULT_COUNTER);

    /* Attack 3: Attempt Non-Secure read of Secure OTP Keystore (0x3007E000) */
    uint32_t leak_otp = tz_probe_read16_ins(SECURE_OTP_PROBE_ADDR);
    app_dcache_clean_invalidate_range(CHIP_REG_TZ_FAULT_COUNTER, sizeof(uint32_t));
    uint32_t cnt_after_otp_read = MMIO32(CHIP_REG_TZ_FAULT_COUNTER);

    __asm__ volatile("dsb sy\n\tisb sy\n\tcpsid i\n\tisb sy" ::: "memory");

    uint32_t s0_read_blocked = (cnt_after_s0_read == 1U) ? 1U : 0U;
    uint32_t s0_write_blocked = (cnt_after_s0_write == 2U) ? 1U : 0U;
    uint32_t otp_read_blocked = (cnt_after_otp_read == 3U) ? 1U : 0U;
    uint32_t leak_bytes = ((leak_s0 != 0U) || (leak_otp != 0U)) ? 4U : 0U;

    uart_puts("[APP] TZ_ISOLATION ns_pc=");
    uart_put_dec(ns_pc_ok);
    uart_puts(" sau_raz=");
    uart_put_dec(sau_raz_ok);
    uart_puts(" s0_read_blocked=");
    uart_put_dec(s0_read_blocked);
    uart_puts(" s0_write_blocked=");
    uart_put_dec(s0_write_blocked);
    uart_puts(" otp_read_blocked=");
    uart_put_dec(otp_read_blocked);
    uart_puts(" leak_bytes=");
    uart_put_dec(leak_bytes);
    uart_puts(" fault_cnt=");
    uart_put_dec(cnt_after_otp_read);
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
        toob_status_t st = toob_ota_process_chunk(&ota_ctx, chunk_buf, clen);
        if (st != TOOB_OK) {
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

    app_dcache_clean_invalidate_range(CHIP_LP_RAM_BASE, CHIP_LP_RAM_SIZE);

    uint32_t cur_pc = 0U;
    __asm__ volatile("mov %0, pc" : "=r"(cur_pc));

    toob_handoff_t handoff;
    memset(&handoff, 0, sizeof(handoff));
    toob_status_t hst = toob_get_handoff(&handoff);

    if (k_app_meta.crash_on_boot != 0U) {
        wdt_kick();
        uart_puts("[APP] BOOT ver=");
        uart_puts_volatile(k_app_meta.version);
        uart_puts(" ns_pc=");
        uart_put_hex32(cur_pc);
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

    uart_puts("[APP] BOOT ver=");
    uart_puts_volatile(k_app_meta.version);
    uart_puts(" ns_pc=");
    uart_put_hex32(cur_pc);
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
        } else if (strcmp(line, "TEST_TZ_ISOLATION") == 0) {
            handle_test_tz_isolation();
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
