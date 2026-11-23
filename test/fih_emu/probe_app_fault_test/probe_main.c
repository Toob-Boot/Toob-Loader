/**
 * @file probe_main.c
 * @brief Tier 2 Bare-Metal Cortex-M4 Hardware Lockdown & Fault Probe Guest App.
 *
 * Executed after real Stage 0 -> Stage 1 verification and handoff inside Renode:
 *   1. Validates toob_get_handoff() and toob_confirm_boot().
 *   2. Attempts illegal NVMC ERASEPAGE and NVMC WEN write against immutable Stage 0.
 *   3. Verifies BPROT->CONFIG0 sticky write-1-to-set lockdown resists clearing.
 *   4. Audits MPU configuration and read-access visibility of Stage-0 / UICR OTP.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated_boot_config.h"
#include "libtoob.h"
#include "sha256.h"

#define MMIO32(addr)                (*(volatile uint32_t *)(uintptr_t)(addr))

#define PROBE_VECTOR_ENTRIES        16U
#define PROBE_DEC_BUF_LEN           12U
#define PROBE_DEC_RADIX             10U
#define PROBE_HEX_NIBBLES           8U
#define PROBE_HEX_SHIFT_STEP        4U
#define PROBE_HEX_NIBBLE_MASK       0xFU
#define PROBE_HEX_ALPHA_THRESHOLD   10U
#define PROBE_UNKNOWN_SLOT_ID       99U

#define UART_ENABLE_ON              4U
#define UART_TASK_TRIGGER           1U
#define UART_EVENT_CLEAR            0U
#define UART_TX_SPIN_LIMIT          200000U

#define WDT_RUNSTATUS_RUNNING       1U

#define NVMC_READY_MASK             1U
#define NVMC_MODE_REN               0U
#define NVMC_MODE_WEN               1U
#define NVMC_MODE_EEN               2U
#define NVMC_SPIN_LIMIT             2000000U
#define NVMC_ICACHE_ENABLE          1U

#define CORTEX_MPU_TYPE_ADDR        0xE000ED90U
#define CORTEX_MPU_CTRL_ADDR        0xE000ED94U
#define STAGE0_PROBE_OFFSET         0x00001000U
#define STAGE0_READ_PROBE_OFFSET    0x00001004U
#define STAGE0_EXPECTED_BPROT_MASK  0x000000FFU
#define UICR_DSLC_ADDR              (CHIP_REG_UICR_BASE + 0x0C0U)
#define PROBE_LINE_BUF_LEN          32U

extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;

void _app_start(void);
static void __attribute__((used, noreturn)) _probe_c_init(void);

static void uart_puts(const char *s);
static void uart_put_hex32(uint32_t val);

static void __attribute__((used, noreturn)) probe_fault_trap(void) {
    uart_puts("[PROBE] FAULT_TRAP cfsr=0x");
    uart_put_hex32(MMIO32(0xE000ED28U));
    uart_puts(" hfsr=0x");
    uart_put_hex32(MMIO32(0xE000ED2CU));
    uart_puts("\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

__attribute__((used, section(".isr_vector")))
static const uintptr_t k_probe_vectors[PROBE_VECTOR_ENTRIES] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
    0U,
    0U,
    0U,
    0U,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
    0U,
    (uintptr_t)&probe_fault_trap,
    (uintptr_t)&probe_fault_trap,
};

static inline void wdt_kick(void) {
    if ((MMIO32(CHIP_REG_WDT_RUNSTATUS) & WDT_RUNSTATUS_RUNNING) != 0U) {
        MMIO32(CHIP_REG_WDT_RR0) = CHIP_WDT_RELOAD_MAGIC;
    }
}

static void uart_init(void) {
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

static void uart_putc(char c) {
    MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) = UART_EVENT_CLEAR;
    MMIO32(CHIP_REG_UART0_TASKS_STARTTX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TXD) = (uint32_t)(uint8_t)c;
    for (uint32_t spin = 0U; spin < UART_TX_SPIN_LIMIT; spin++) {
        if (MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) != 0U) {
            break;
        }
    }
}

static void uart_puts(const char *s) {
    while (*s != '\0') {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

static void uart_put_dec(uint32_t val) {
    char buf[PROBE_DEC_BUF_LEN];
    uint32_t idx = 0U;
    if (val == 0U) {
        uart_putc('0');
        return;
    }
    while (val > 0U) {
        buf[idx++] = (char)('0' + (val % PROBE_DEC_RADIX));
        val /= PROBE_DEC_RADIX;
    }
    while (idx > 0U) {
        idx--;
        uart_putc(buf[idx]);
    }
}

static void uart_put_hex32(uint32_t val) {
    for (uint32_t i = 0U; i < PROBE_HEX_NIBBLES; i++) {
        uint32_t shift = (PROBE_HEX_NIBBLES - 1U - i) * PROBE_HEX_SHIFT_STEP;
        uint32_t nib = (val >> shift) & PROBE_HEX_NIBBLE_MASK;
        char c = (nib < PROBE_HEX_ALPHA_THRESHOLD)
                     ? (char)('0' + nib)
                     : (char)('A' + (nib - PROBE_HEX_ALPHA_THRESHOLD));
        uart_putc(c);
    }
}

static bool nvmc_wait_ready(void) {
    for (uint32_t i = 0U; i < NVMC_SPIN_LIMIT; i++) {
        if ((MMIO32(CHIP_REG_NVMC_READY) & NVMC_READY_MASK) != 0U) {
            return true;
        }
    }
    return false;
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
    if ((buf == NULL) && (len > 0U)) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }
    const volatile uint8_t *src = (const volatile uint8_t *)(uintptr_t)(CHIP_FLASH_XIP_BASE + addr);
    for (uint32_t i = 0U; i < len; i++) {
        buf[i] = src[i];
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
    if ((buf == NULL) && (len > 0U)) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if (!nvmc_wait_ready()) {
        return TOOB_ERR_FLASH;
    }
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_WEN;
    (void)nvmc_wait_ready();
    for (uint32_t off = 0U; off < len; off += CHIP_FLASH_WRITE_ALIGNMENT) {
        uint32_t word = 0U;
        memcpy(&word, &buf[off], sizeof(word));
        MMIO32(CHIP_FLASH_XIP_BASE + addr + off) = word;
        (void)nvmc_wait_ready();
    }
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    MMIO32(CHIP_REG_NVMC_ICACHECNF) = NVMC_ICACHE_ENABLE;
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (len == 0U) {
        return TOOB_OK;
    }
    if ((addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U || addr > CHIP_FLASH_TOTAL_SIZE ||
        len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }
    if (!nvmc_wait_ready()) {
        return TOOB_ERR_FLASH;
    }
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_EEN;
    (void)nvmc_wait_ready();
    uint32_t pages = (len + CHIP_FLASH_MAX_SECTOR_SIZE - 1U) / CHIP_FLASH_MAX_SECTOR_SIZE;
    for (uint32_t i = 0U; i < pages; i++) {
        wdt_kick();
        MMIO32(CHIP_REG_NVMC_ERASEPAGE) = addr + (i * CHIP_FLASH_MAX_SECTOR_SIZE);
        (void)nvmc_wait_ready();
    }
    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    MMIO32(CHIP_REG_NVMC_ICACHECNF) = NVMC_ICACHE_ENABLE;
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    if (ctx == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_init((SHA256_CTX *)(uintptr_t)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len) {
    if ((ctx == NULL) || ((data == NULL) && (len > 0U))) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len > 0U) {
        sha256_update((SHA256_CTX *)(uintptr_t)ctx->opaque, data, len);
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32]) {
    if ((ctx == NULL) || (out_hash == NULL)) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_final((SHA256_CTX *)(uintptr_t)ctx->opaque, out_hash);
    return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *len) {
    (void)key;
    (void)buf;
    (void)len;
    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len) {
    (void)key;
    (void)buf;
    (void)len;
    return TOOB_OK;
}

static void run_hardware_security_probes(void) {
    wdt_kick();

    uint32_t cfg0_before = MMIO32(CHIP_REG_BPROT_CONFIG0);
    uint32_t cfg1_before = MMIO32(CHIP_REG_BPROT_CONFIG1);
    uint32_t dbg_before = MMIO32(CHIP_REG_BPROT_DISABLEINDEBUG);

    /* Attempt to tamper BPROT by clearing CONFIG0/DISABLEINDEBUG from Guest OS */
    MMIO32(CHIP_REG_BPROT_CONFIG0) = 0U;
    MMIO32(CHIP_REG_BPROT_DISABLEINDEBUG) = 1U;
    uint32_t cfg0_after = MMIO32(CHIP_REG_BPROT_CONFIG0);
    bool bprot_mask_ok = (cfg0_before & STAGE0_EXPECTED_BPROT_MASK) == STAGE0_EXPECTED_BPROT_MASK;
    bool bprot_sticky = (cfg0_after & STAGE0_EXPECTED_BPROT_MASK) == STAGE0_EXPECTED_BPROT_MASK;

    /* Attempt illegal NVMC page erase and zero-word write into Stage-0 code */
    uint32_t probe_addr = CHIP_FLASH_XIP_BASE + STAGE0_PROBE_OFFSET;
    uint32_t pre_word = MMIO32(probe_addr);

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_EEN;
    (void)nvmc_wait_ready();
    MMIO32(CHIP_REG_NVMC_ERASEPAGE) = STAGE0_PROBE_OFFSET;
    (void)nvmc_wait_ready();

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_WEN;
    (void)nvmc_wait_ready();
    MMIO32(probe_addr) = 0U;
    (void)nvmc_wait_ready();

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    (void)nvmc_wait_ready();
    uint32_t post_word = MMIO32(probe_addr);
    bool flash_intact = (post_word == pre_word) && (post_word != 0U);

    uart_puts("[PROBE] BPROT cfg0=0x");
    uart_put_hex32(cfg0_before);
    uart_puts(" cfg1=0x");
    uart_put_hex32(cfg1_before);
    uart_puts(" dbg=0x");
    uart_put_hex32(dbg_before);
    uart_puts(" sticky=");
    uart_puts((bprot_mask_ok && bprot_sticky) ? "OK" : "FAIL");
    uart_puts("\n");

    uart_puts("[PROBE] STAGE0_WRITE_ERASE pre=0x");
    uart_put_hex32(pre_word);
    uart_puts(" post=0x");
    uart_put_hex32(post_word);
    uart_puts(" status=");
    uart_puts(flash_intact ? "PROTECTED\n" : "BREACH\n");

    /* Read MPU control & inspect Stage-0 Reset_Handler vector / UICR visibility */
    uint32_t mpu_type = MMIO32(CORTEX_MPU_TYPE_ADDR);
    uint32_t mpu_ctrl = MMIO32(CORTEX_MPU_CTRL_ADDR);
    uint32_t stage0_vec = MMIO32(CHIP_FLASH_XIP_BASE + STAGE0_READ_PROBE_OFFSET);
    uint32_t uicr_c0 = MMIO32(CHIP_REG_UICR_CUSTOMER0);
    uint32_t uicr_dslc = MMIO32(UICR_DSLC_ADDR);

    uart_puts("[PROBE] READ_AUDIT mpu_type=0x");
    uart_put_hex32(mpu_type);
    uart_puts(" mpu_ctrl=0x");
    uart_put_hex32(mpu_ctrl);
    uart_puts(" stage0_vec=0x");
    uart_put_hex32(stage0_vec);
    uart_puts(" uicr_c0=0x");
    uart_put_hex32(uicr_c0);
    uart_puts(" uicr_dslc=0x");
    uart_put_hex32(uicr_dslc);
    uart_puts("\n");
}

static void __attribute__((used, noreturn)) _probe_c_init(void) {
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
    toob_status_t cst = toob_confirm_boot();
    wdt_kick();

    uart_puts("[PROBE] BOOT slot=");
    uart_put_dec((hst == TOOB_OK) ? (uint32_t)handoff.active_slot : PROBE_UNKNOWN_SLOT_ID);
    uart_puts(" handoff=");
    uart_puts((hst == TOOB_OK) ? "OK" : "ERR");
    uart_puts(" confirm=");
    uart_puts((cst == TOOB_OK) ? "OK\n" : "ERR\n");

    run_hardware_security_probes();

    uart_puts("[PROBE] DONE\n");

    for (;;) {
        wdt_kick();
        __asm__ volatile("wfi");
    }
}

void __attribute__((naked, noreturn, section(".app_entry"))) _app_start(void) {
    __asm__ volatile(
        "cpsid i\n"
        "ldr r0, =_stack_top\n"
        "mov sp, r0\n"
        "b _probe_c_init\n"
    );
}
