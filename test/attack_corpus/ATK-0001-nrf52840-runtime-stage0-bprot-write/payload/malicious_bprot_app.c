#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "generated_boot_config.h"
#include "libtoob.h"
#include "sha256.h"

#define MMIO32(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

#define STAGE0_TARGET_OFF   0x00001000U
#define BPROT_STAGE0_MASK   0x000000FFU
#define UART_ENABLE_ON      4U
#define UART_TASK_TRIGGER   1U
#define NVMC_READY_MASK     1U
#define NVMC_MODE_REN       0U
#define NVMC_MODE_WEN       1U
#define NVMC_MODE_EEN       2U

extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;

void _app_start(void);
static void __attribute__((used, noreturn)) _atk_c_init(void);

static void uart_puts(const char *s);

static void __attribute__((used, noreturn)) fault_trap(void) {
    uart_puts("[ATK-0001] FAULT_TRAP\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

__attribute__((used, section(".isr_vector")))
static const uintptr_t k_vectors[16] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_app_start,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
    0U, 0U, 0U, 0U,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
    0U,
    (uintptr_t)&fault_trap,
    (uintptr_t)&fault_trap,
};

static inline void wdt_kick(void) {
    if ((MMIO32(CHIP_REG_WDT_RUNSTATUS) & 1U) != 0U) {
        MMIO32(CHIP_REG_WDT_RR0) = CHIP_WDT_RELOAD_MAGIC;
    }
}

static void uart_init(void) {
    MMIO32(CHIP_REG_UART0_TASKS_STOPRX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TASKS_STOPTX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_ENABLE) = 0U;
    MMIO32(CHIP_REG_UART0_BAUDRATE) = CHIP_UART0_BAUD_115200;
    MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) = 0U;
    MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) = 0U;
    MMIO32(CHIP_REG_UART0_ENABLE) = UART_ENABLE_ON;
    MMIO32(CHIP_REG_UART0_TASKS_STARTTX) = UART_TASK_TRIGGER;
}

static void uart_putc(char c) {
    MMIO32(CHIP_REG_UART0_EVENTS_TXDRDY) = 0U;
    MMIO32(CHIP_REG_UART0_TASKS_STARTTX) = UART_TASK_TRIGGER;
    MMIO32(CHIP_REG_UART0_TXD) = (uint32_t)(uint8_t)c;
    for (uint32_t spin = 0U; spin < 200000U; spin++) {
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

static void nvmc_wait_ready(void) {
    for (uint32_t i = 0U; i < 2000000U; i++) {
        if ((MMIO32(CHIP_REG_NVMC_READY) & NVMC_READY_MASK) != 0U) {
            break;
        }
    }
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
    if ((buf == NULL) && (len > 0U)) { return TOOB_ERR_INVALID_ARG; }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) { return TOOB_ERR_FLASH; }
    const volatile uint8_t *src = (const volatile uint8_t *)(uintptr_t)(CHIP_FLASH_XIP_BASE + addr);
    for (uint32_t i = 0U; i < len; i++) { buf[i] = src[i]; }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
    (void)addr; (void)buf; (void)len;
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    (void)addr; (void)len;
    return TOOB_ERR_FLASH;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    if (ctx == NULL) { return TOOB_ERR_INVALID_ARG; }
    sha256_init((SHA256_CTX *)(uintptr_t)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len) {
    if ((ctx == NULL) || ((data == NULL) && (len > 0U))) { return TOOB_ERR_INVALID_ARG; }
    if (len > 0U) { sha256_update((SHA256_CTX *)(uintptr_t)ctx->opaque, data, len); }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32]) {
    if ((ctx == NULL) || (out_hash == NULL)) { return TOOB_ERR_INVALID_ARG; }
    sha256_final((SHA256_CTX *)(uintptr_t)ctx->opaque, out_hash);
    return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *len) {
    (void)key; (void)buf; (void)len;
    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len) {
    (void)key; (void)buf; (void)len;
    return TOOB_OK;
}

static void __attribute__((used, noreturn)) _atk_c_init(void) {
    const uint32_t *src = &_sidata;
    uint32_t *dst = &_data_start;
    while (dst < &_data_end) { *dst++ = *src++; }
    dst = &_bss_start;
    while (dst < &_bss_end) { *dst++ = 0U; }

    uart_init();

    toob_handoff_t handoff;
    uint8_t *hp = (uint8_t *)&handoff;
    for (size_t i = 0U; i < sizeof(handoff); i++) { hp[i] = 0U; }

    toob_status_t hst = toob_get_handoff(&handoff);
    toob_status_t cst = toob_confirm_boot();
    wdt_kick();

    uart_puts("[ATK-0001] BOOT handoff=");
    uart_puts((hst == TOOB_OK) ? "OK" : "ERR");
    uart_puts(" confirm=");
    uart_puts((cst == TOOB_OK) ? "OK\n" : "ERR\n");

    uint32_t cfg0_pre = MMIO32(CHIP_REG_BPROT_CONFIG0);
    MMIO32(CHIP_REG_BPROT_CONFIG0) = 0U;
    MMIO32(CHIP_REG_BPROT_DISABLEINDEBUG) = 1U;
    uint32_t cfg0_post = MMIO32(CHIP_REG_BPROT_CONFIG0);
    bool sticky = ((cfg0_pre & BPROT_STAGE0_MASK) == BPROT_STAGE0_MASK) &&
                  ((cfg0_post & BPROT_STAGE0_MASK) == BPROT_STAGE0_MASK);

    uint32_t target = CHIP_FLASH_XIP_BASE + STAGE0_TARGET_OFF;
    uint32_t word_pre = MMIO32(target);

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_EEN;
    nvmc_wait_ready();
    MMIO32(CHIP_REG_NVMC_ERASEPAGE) = STAGE0_TARGET_OFF;
    nvmc_wait_ready();

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_WEN;
    nvmc_wait_ready();
    MMIO32(target) = 0xDEADBEEFU;
    nvmc_wait_ready();

    MMIO32(CHIP_REG_NVMC_CONFIG) = NVMC_MODE_REN;
    nvmc_wait_ready();
    uint32_t word_post = MMIO32(target);

    uart_puts("[ATK-0001] BPROT sticky=");
    uart_puts(sticky ? "OK" : "FAIL");
    uart_puts(" status=");
    uart_puts(((word_post == word_pre) && (word_post != 0xDEADBEEFU)) ? "PROTECTED\n" : "BREACH\n");
    uart_puts("[ATK-0001] DONE\n");

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
        "b _atk_c_init\n"
    );
}
