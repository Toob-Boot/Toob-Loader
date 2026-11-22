/**
 * @file main_freertos.c
 * @brief Multi-Task FreeRTOS Cortex-M4F Firmware with libtoob Integration on nRF52840.
 *
 * Exercises:
 *   1. Pre-scheduler libtoob & toob_os_lock safety (xTaskGetSchedulerState == NOT_STARTED).
 *   2. SCB->VTOR (+0x100) FreeRTOS vector handoff (SVC_Handler, PendSV_Handler, SysTick_Handler)
 *      verified by FreeRTOS configCHECK_HANDLER_INSTALLATION == 1.
 *   3. Concurrent preemptive Cortex-M4F tasks (TaskWatchdogHealth + TaskOtaWorker + TimerTask)
 *      with hardware VFP (s0-s31) context switching, StaticSemaphore_t toob_os_lock contention,
 *      and .noinit toob_handoff_t / toob_boot_diag_t survival across scheduler startup.
 *   4. Verified SHA-256 streaming TBM1 Full OTA over NRF_UART0 while TaskWatchdogHealth
 *      preemptively services NRF_WDT->RR[0].
 *   5. Simulated AB-BA mutex task deadlock (APP_SIMULATE_DEADLOCK=1) caught by AppSelfTest
 *      prior to toob_confirm_boot(), starving NRF_WDT to trigger Stage 1 auto-rollback.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated_boot_config.h"
#include "libtoob.h"
#include "sha256.h"

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "timers.h"

#define TOOB_STR_H(x)               #x
#define TOOB_STR(x)                 TOOB_STR_H(x)

#ifndef APP_VERSION_RAW
#define APP_VERSION_RAW             1.0.0
#endif
#define APP_VERSION_STR             TOOB_STR(APP_VERSION_RAW)

#ifndef APP_SIMULATE_DEADLOCK
#define APP_SIMULATE_DEADLOCK       0
#endif

#define MMIO32(addr)                (*(volatile uint32_t *)(uintptr_t)(addr))

/* Vector table & Cortex-M4F SCB constants */
#define APP_CORE_VECTORS            16U
#define APP_EXT_IRQ_VECTORS         48U
#define APP_TOTAL_VECTORS           (APP_CORE_VECTORS + APP_EXT_IRQ_VECTORS)
#define SCB_AIRCR_ADDR              0xE000ED0CU
#define SCB_AIRCR_SYSRESETREQ_VAL   0x05FA0004U
#define SCB_CPACR_ADDR              0xE000ED88U

/* String & numeric formatting constants */
#define APP_META_VER_LEN            16U
#define APP_DEC_BUF_LEN             12U
#define APP_DEC_RADIX               10U
#define APP_HEX_NIBBLES             8U
#define APP_HEX_SHIFT_STEP          4U
#define APP_HEX_NIBBLE_MASK         0xFU
#define APP_HEX_ALPHA_THRESHOLD     10U
#define APP_LINE_BUF_LEN            128U
#define APP_OTA_CMD_PREFIX_LEN      4U
#define APP_OTA_CHUNK_BUF_LEN       512U
#define APP_SHA256_DIGEST_LEN       32U
#define APP_SHA256_HEX_CHARS        64U
#define APP_BYTE_SHIFT              8U
#define APP_BYTE_MASK               0xFFU
#define APP_UNKNOWN_SLOT_ID         99U

/* Peripheral MMIO constants */
#define UART_ENABLE_ON              4U
#define UART_TASK_TRIGGER           1U
#define UART_EVENT_CLEAR            0U
#define UART_TX_SPIN_LIMIT          200000U
#define UART_RX_YIELD_POLL_MASK     0xFFU

#define WDT_RUNSTATUS_RUNNING       1U

#define NVMC_READY_MASK             1U
#define NVMC_MODE_REN               0U
#define NVMC_MODE_WEN               1U
#define NVMC_MODE_EEN               2U
#define NVMC_SPIN_LIMIT             2000000U
#define NVMC_WORD_BYTES             4U
#define NVMC_ICACHE_ENABLE          1U

/* FreeRTOS task & self-test parameters */
#define HEALTH_TASK_STACK_WORDS     512U
#define WORKER_TASK_STACK_WORDS     1024U
#define DEADLOCK_TASK_STACK_WORDS   256U
#define BOOT_SELFTEST_PRIO          (tskIDLE_PRIORITY + 2U)
#define WATCHDOG_SUPERVISOR_PRIO    (tskIDLE_PRIORITY + 3U)
#define HEALTH_FEED_PERIOD_MS       50U
#define SW_TIMER_PERIOD_MS          25U
#define SELFTEST_MIN_TICKS          12U
#define SELFTEST_MIN_SWITCHES       8U
#define SELFTEST_MIN_HEARTBEATS     4U
#define SELFTEST_DEADLOCK_TICKS     30U
#define DEADLOCK_STEP_DELAY_TICKS   2U
#define DEADLOCK_POLL_DELAY_TICKS   5U
#define FPU_STRESS_ROUNDS           16U
#define FPU_SEED_HEALTH             1.25f
#define FPU_SEED_WORKER             3.75f
#define FPU_STEP_DELTA              0.5f

_Static_assert(sizeof(SHA256_CTX) <= sizeof(((toob_os_sha256_ctx_t *)0)->opaque),
               "SHA256_CTX exceeds toob_os_sha256_ctx_t opaque buffer");

typedef struct {
    char version[APP_META_VER_LEN];
    uint32_t simulate_deadlock;
} app_rom_meta_t;

__attribute__((section(".rodata.app_meta"), used))
static const volatile app_rom_meta_t k_app_meta = {
    .version = APP_VERSION_STR,
    .simulate_deadlock = (uint32_t)APP_SIMULATE_DEADLOCK,
};

extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;

/* FreeRTOS ARM_CM4F port exception handlers */
extern void vPortSVCHandler(void);
extern void xPortPendSVHandler(void);
extern void xPortSysTickHandler(void);

void _app_start(void);
static void __attribute__((used, noreturn)) _app_c_init(void);

/* Shared RTOS instrumentation & self-test state */
volatile uint32_t g_rtos_context_switches = 0U;
static volatile uint32_t s_wdt_feeds = 0U;
static volatile uint32_t s_worker_heartbeats = 0U;
static volatile uint32_t s_worker_diag_calls = 0U;
static volatile uint32_t s_timer_callbacks = 0U;
static volatile uint32_t s_fpu_errors = 0U;
static volatile uint32_t s_swap_notifier_calls = 0U;
static volatile uint32_t s_boot_confirmed = 0U;
static bool s_presched_ok = false;
static toob_handoff_t s_pre_handoff;

/* Static RTOS objects */
static StaticSemaphore_t s_uart_mtx_buf;
static SemaphoreHandle_t s_uart_mtx = NULL;

static StaticTask_t s_health_tcb;
static StackType_t s_health_stack[HEALTH_TASK_STACK_WORDS];

static StaticTimer_t s_timer_buf;
static TimerHandle_t s_periodic_timer = NULL;

static StaticSemaphore_t s_deadlock_mtx_a_buf;
static StaticSemaphore_t s_deadlock_mtx_b_buf;
static SemaphoreHandle_t s_deadlock_mtx_a = NULL;
static SemaphoreHandle_t s_deadlock_mtx_b = NULL;

/* ============================================================================
 * Low-Level UART0 & Watchdog Helpers
 * ============================================================================ */

static inline void wdt_kick(void)
{
    if ((MMIO32(CHIP_REG_WDT_RUNSTATUS) & WDT_RUNSTATUS_RUNNING) != 0U) {
        MMIO32(CHIP_REG_WDT_RR0) = CHIP_WDT_RELOAD_MAGIC;
        s_wdt_feeds++;
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

static void uart_putc_raw(char c)
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

static void uart_puts_raw(const char *s)
{
    while (*s != '\0') {
        if (*s == '\n') {
            uart_putc_raw('\r');
        }
        uart_putc_raw(*s++);
    }
}

static void uart_puts_volatile_raw(const volatile char *s)
{
    while (*s != '\0') {
        char c = *s++;
        if (c == '\n') {
            uart_putc_raw('\r');
        }
        uart_putc_raw(c);
    }
}

static void uart_put_dec_raw(uint32_t val)
{
    char buf[APP_DEC_BUF_LEN];
    uint32_t idx = 0U;
    if (val == 0U) {
        uart_putc_raw('0');
        return;
    }
    while (val > 0U) {
        buf[idx++] = (char)('0' + (val % APP_DEC_RADIX));
        val /= APP_DEC_RADIX;
    }
    while (idx > 0U) {
        idx--;
        uart_putc_raw(buf[idx]);
    }
}

static void uart_lock(void)
{
    if ((s_uart_mtx != NULL) && (xTaskGetSchedulerState() == taskSCHEDULER_RUNNING)) {
        (void)xSemaphoreTake(s_uart_mtx, portMAX_DELAY);
    }
}

static void uart_unlock(void)
{
    if ((s_uart_mtx != NULL) && (xTaskGetSchedulerState() == taskSCHEDULER_RUNNING)) {
        (void)xSemaphoreGive(s_uart_mtx);
    }
}

static uint8_t uart_getc_rtos(bool yield_when_idle)
{
    uint32_t polls = 0U;
    for (;;) {
        if (MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) != 0U) {
            MMIO32(CHIP_REG_UART0_EVENTS_RXDRDY) = UART_EVENT_CLEAR;
            return (uint8_t)(MMIO32(CHIP_REG_UART0_RXD) & APP_BYTE_MASK);
        }
        polls++;
        if (yield_when_idle && ((polls & UART_RX_YIELD_POLL_MASK) == 0U)) {
            taskYIELD();
        }
    }
}

static size_t uart_read_line_rtos(char *buf, size_t max_len)
{
    size_t pos = 0U;
    while ((pos + 1U) < max_len) {
        char c = (char)uart_getc_rtos(pos == 0U);
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

static uint32_t parse_u32_dec(const char *s, const char **end_ptr)
{
    uint32_t v = 0U;
    while ((*s >= '0') && (*s <= '9')) {
        v = (v * APP_DEC_RADIX) + (uint32_t)(*s - '0');
        s++;
    }
    if (end_ptr != NULL) {
        *end_ptr = s;
    }
    return v;
}

static bool parse_hex_sha256(const char *hex, uint8_t out_hash[APP_SHA256_DIGEST_LEN])
{
    for (uint32_t i = 0U; i < APP_SHA256_DIGEST_LEN; i++) {
        uint8_t byte_val = 0U;
        for (uint32_t nib_idx = 0U; nib_idx < 2U; nib_idx++) {
            char c = hex[(i * 2U) + nib_idx];
            uint8_t nib = 0U;
            if ((c >= '0') && (c <= '9')) {
                nib = (uint8_t)(c - '0');
            } else if ((c >= 'a') && (c <= 'f')) {
                nib = (uint8_t)(APP_HEX_ALPHA_THRESHOLD + (uint32_t)(c - 'a'));
            } else if ((c >= 'A') && (c <= 'F')) {
                nib = (uint8_t)(APP_HEX_ALPHA_THRESHOLD + (uint32_t)(c - 'A'));
            } else {
                return false;
            }
            byte_val = (uint8_t)((byte_val << APP_HEX_SHIFT_STEP) | nib);
        }
        out_hash[i] = byte_val;
    }
    return true;
}

/* ============================================================================
 * Cortex-M4F Vector Table (+0x100 SCB->VTOR) & Fault / RTOS Error Hooks
 * ============================================================================ */

static void __attribute__((used, noreturn)) app_fault_trap(void)
{
    __asm__ volatile("cpsid i" ::: "memory");
    uart_puts_raw("\n[RTOS] FATAL cpu_fault\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

static void __attribute__((used)) app_default_irq_handler(void)
{
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void app_freertos_assert_failed(const char *file, int line)
{
    __asm__ volatile("cpsid i" ::: "memory");
    uart_puts_raw("\n[RTOS] FATAL configASSERT file=");
    if (file != NULL) {
        uart_puts_raw(file);
    }
    uart_puts_raw(" line=");
    uart_put_dec_raw((line > 0) ? (uint32_t)line : 0U);
    uart_puts_raw("\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    __asm__ volatile("cpsid i" ::: "memory");
    uart_puts_raw("\n[RTOS] FATAL stack_overflow task=");
    if (pcTaskName != NULL) {
        uart_puts_raw(pcTaskName);
    }
    uart_puts_raw("\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void vApplicationMallocFailedHook(void)
{
    __asm__ volatile("cpsid i" ::: "memory");
    uart_puts_raw("\n[RTOS] FATAL malloc_failed\n");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void vApplicationIdleHook(void)
{
    __asm__ volatile("wfi");
}

__attribute__((used, section(".isr_vector")))
static const uintptr_t k_app_vectors[APP_TOTAL_VECTORS] = {
    [0]  = (uintptr_t)&_stack_top,
    [1]  = (uintptr_t)&_app_start,
    [2]  = (uintptr_t)&app_fault_trap,
    [3]  = (uintptr_t)&app_fault_trap,
    [4]  = (uintptr_t)&app_fault_trap,
    [5]  = (uintptr_t)&app_fault_trap,
    [6]  = (uintptr_t)&app_fault_trap,
    [7]  = 0U,
    [8]  = 0U,
    [9]  = 0U,
    [10] = 0U,
    [11] = (uintptr_t)&vPortSVCHandler,
    [12] = (uintptr_t)&app_fault_trap,
    [13] = 0U,
    [14] = (uintptr_t)&xPortPendSVHandler,
    [15] = (uintptr_t)&xPortSysTickHandler,
    [16 ... (APP_TOTAL_VECTORS - 1U)] = (uintptr_t)&app_default_irq_handler,
};

/* ============================================================================
 * Board BSP Overrides for libtoob (Flash NVMC + SHA-256)
 * Note: toob_os_lock / toob_os_unlock & toob_os_nvs_* come directly from
 *       toob-infra/registry/packages/integrations/freertos/files/toob_hooks.c!
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
    if (len == 0U) {
        return TOOB_OK;
    }
    if (buf == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if ((addr > CHIP_FLASH_TOTAL_SIZE) || (len > (CHIP_FLASH_TOTAL_SIZE - addr))) {
        return TOOB_ERR_FLASH;
    }
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

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    __asm__ volatile(
        "cpsid i\n"
        "mov r0, #0\n"
        "msr basepri, r0\n"
        "dsb sy\n"
        ::: "r0", "memory"
    );
    MMIO32(SCB_AIRCR_ADDR) = SCB_AIRCR_SYSRESETREQ_VAL;
    __asm__ volatile("dsb sy" ::: "memory");
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/* ============================================================================
 * Hardware FPU Context-Switch Stress & Swap Notifier Callback
 * ============================================================================ */

static void fpu_stress_round(float seed)
{
    /* Exercise Cortex-M4F VFP registers across preemptive PendSV context switches.
     * Exact dyadic fractions (0.25, 0.5, 0.75) have zero IEEE-754 rounding error:
     * sum_{k=0..15} (seed + k * 0.5) = 16 * seed + 120 * 0.5 = 16 * seed + 60.0f.
     */
    volatile float acc0 = 0.0f;
    volatile float acc1 = seed;
    for (uint32_t k = 0U; k < FPU_STRESS_ROUNDS; k++) {
        float term = acc1 + ((float)k * FPU_STEP_DELTA);
        acc0 = acc0 + term;
    }
    float expected = ((float)FPU_STRESS_ROUNDS * seed) + 60.0f;
    if (acc0 != expected) {
        s_fpu_errors++;
    }
}

static void app_swap_notifier_cb(const toob_swap_event_t *ev)
{
    (void)ev;
    s_swap_notifier_calls++;
}

static void sw_timer_callback(TimerHandle_t xTimer)
{
    (void)xTimer;
    s_timer_callbacks++;
}

/* ============================================================================
 * Simulated Deadlock Peer Task (Active only when APP_SIMULATE_DEADLOCK == 1)
 * ============================================================================ */

static void task_deadlock_peer(void *arg)
{
    (void)arg;
    (void)xSemaphoreTake(s_deadlock_mtx_b, portMAX_DELAY);
    vTaskDelay(DEADLOCK_STEP_DELAY_TICKS);
    /* Classic AB-BA lock-order inversion against TaskOtaWorker */
    (void)xSemaphoreTake(s_deadlock_mtx_a, portMAX_DELAY);
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

/* ============================================================================
 * Task 1: TaskWatchdogHealth (Preemptive Health Supervisor & Boot Confirmation)
 * ============================================================================ */

static void task_watchdog_health(void *arg)
{
    (void)arg;
    bool handoff_corrupted = false;

    /* Feed WDT once on scheduler start while running bounded AppSelfTest window */
    wdt_kick();

    for (;;) {
        fpu_stress_round(FPU_SEED_HEALTH);

        toob_handoff_t rt_handoff;
        memset(&rt_handoff, 0, sizeof(rt_handoff));
        toob_status_t hst = toob_get_handoff(&rt_handoff);
        if ((hst != TOOB_OK) ||
            (rt_handoff.boot_nonce != s_pre_handoff.boot_nonce) ||
            (rt_handoff.active_slot != s_pre_handoff.active_slot) ||
            (rt_handoff.booted_partition != s_pre_handoff.booted_partition) ||
            (rt_handoff.reset_reason != s_pre_handoff.reset_reason) ||
            (rt_handoff.crc32_trailer != s_pre_handoff.crc32_trailer)) {
            handoff_corrupted = true;
        }

        TickType_t now = xTaskGetTickCount();
        if ((now >= SELFTEST_MIN_TICKS) &&
            (g_rtos_context_switches >= SELFTEST_MIN_SWITCHES) &&
            (s_worker_heartbeats >= SELFTEST_MIN_HEARTBEATS) &&
            (s_worker_diag_calls >= SELFTEST_MIN_HEARTBEATS)) {
            break;
        }
        if (now >= SELFTEST_DEADLOCK_TICKS) {
            break;
        }

        if (k_app_meta.simulate_deadlock != 0U) {
            vTaskDelay(DEADLOCK_POLL_DELAY_TICKS);
        }
    }

    uint32_t slot_val = s_presched_ok ? (uint32_t)s_pre_handoff.active_slot : APP_UNKNOWN_SLOT_ID;
    uint32_t tent_val = (s_presched_ok && (s_pre_handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U;

    if ((!s_presched_ok) || handoff_corrupted || (s_fpu_errors != 0U) ||
        (s_worker_heartbeats < SELFTEST_MIN_HEARTBEATS)) {
        if (s_periodic_timer != NULL) {
            (void)xTimerStop(s_periodic_timer, 0U);
        }
        uart_lock();
        uart_puts_raw("[RTOS] SELF_TEST_FAIL ver=");
        uart_puts_volatile_raw(k_app_meta.version);
        uart_puts_raw(" slot=");
        uart_put_dec_raw(slot_val);
        uart_puts_raw(" tent=");
        uart_put_dec_raw(tent_val);
        uart_puts_raw(" reason=TASK_DEADLOCK starving_wdt=1\n");
        uart_unlock();

        /* Refuse toob_confirm_boot() and stop feeding NRF_WDT so hardware rollback engages */
        for (;;) {
            vTaskDelay(portMAX_DELAY);
        }
    }

    /* Promote supervisor above worker tasks so WDT feeds preempt heavy flash/crypto OTA work */
    vTaskPrioritySet(NULL, WATCHDOG_SUPERVISOR_PRIO);
    wdt_kick();

    toob_status_t cst = toob_confirm_boot();
    toob_handoff_t post_handoff;
    memset(&post_handoff, 0, sizeof(post_handoff));
    toob_status_t post_hst = toob_get_handoff(&post_handoff);
    bool rtc_ok = true;
    if (tent_val != 0U) {
        uint64_t latched = *(const volatile uint64_t *)(uintptr_t)ADDR_CONFIRM_RTC_RAM;
        rtc_ok = (latched == post_handoff.boot_nonce);
    }
    bool confirm_ok = (cst == TOOB_OK) && (post_hst == TOOB_OK) && rtc_ok;

    uart_lock();
    uart_puts_raw("[RTOS] BOOT_CONFIRMED ver=");
    uart_puts_volatile_raw(k_app_meta.version);
    uart_puts_raw(" slot=");
    uart_put_dec_raw(slot_val);
    uart_puts_raw(" tent=");
    uart_put_dec_raw(tent_val);
    uart_puts_raw(" presched=OK handoff=OK confirm=");
    uart_puts_raw(confirm_ok ? "OK" : "ERR");
    uart_puts_raw(" ticks=");
    uart_put_dec_raw((uint32_t)xTaskGetTickCount());
    uart_puts_raw(" switches=");
    uart_put_dec_raw(g_rtos_context_switches);
    uart_puts_raw(" fpu=OK\n");
    uart_unlock();

    s_boot_confirmed = 1U;

    for (;;) {
        wdt_kick();
        vTaskDelay(pdMS_TO_TICKS(HEALTH_FEED_PERIOD_MS));
    }
}

/* ============================================================================
 * Task 2: TaskOtaWorker (Concurrent Diag Contention & Streaming UART OTA)
 * ============================================================================ */

static void handle_rtos_ota_command(const char *args)
{
    static toob_ota_ctx_t ota_ctx;
    static uint8_t chunk_buf[APP_OTA_CHUNK_BUF_LEN];
    uint8_t expected_hash[APP_SHA256_DIGEST_LEN];
    const uint8_t *hash_arg = NULL;

    const char *rest = NULL;
    uint32_t total_len = parse_u32_dec(args, &rest);
    if (total_len == 0U) {
        uart_lock();
        uart_puts_raw("[RTOS] OTA_ERR bad_len\n");
        uart_unlock();
        return;
    }

    while (*rest == ' ') {
        rest++;
    }
    if (*rest != '\0') {
        if ((strlen(rest) != APP_SHA256_HEX_CHARS) || !parse_hex_sha256(rest, expected_hash)) {
            uart_lock();
            uart_puts_raw("[RTOS] OTA_ERR bad_sha256\n");
            uart_unlock();
            return;
        }
        hash_arg = expected_hash;
    }

    if (toob_ota_ctx_init(&ota_ctx) != TOOB_OK) {
        uart_lock();
        uart_puts_raw("[RTOS] OTA_ERR init\n");
        uart_unlock();
        return;
    }
    if (toob_ota_begin(&ota_ctx, total_len, hash_arg) != TOOB_OK) {
        uart_lock();
        uart_puts_raw("[RTOS] OTA_ERR begin\n");
        uart_unlock();
        return;
    }

    uart_lock();
    uart_puts_raw("[RTOS] OTA_READY mode=");
    uart_puts_raw((hash_arg != NULL) ? "SHA256\n" : "RAW\n");
    uart_unlock();

    uint32_t rx = 0U;
    while (rx < total_len) {
        uint8_t lo = uart_getc_rtos(false);
        uint8_t hi = uart_getc_rtos(false);
        uint16_t clen = (uint16_t)lo | (uint16_t)((uint16_t)hi << APP_BYTE_SHIFT);
        if ((clen == 0U) || (clen > sizeof(chunk_buf)) || ((uint32_t)clen > (total_len - rx))) {
            toob_status_t abst = toob_ota_abort(&ota_ctx);
            (void)abst;
            uart_lock();
            uart_puts_raw("[RTOS] OTA_ERR chunk_len\n");
            uart_unlock();
            return;
        }
        for (uint16_t i = 0U; i < clen; i++) {
            chunk_buf[i] = uart_getc_rtos(false);
        }

        toob_status_t st = toob_ota_process_chunk(&ota_ctx, chunk_buf, clen);
        if (st != TOOB_OK) {
            toob_status_t abst = toob_ota_abort(&ota_ctx);
            (void)abst;
            uart_lock();
            uart_puts_raw("[RTOS] OTA_ERR chunk_write code=");
            uart_put_dec_raw((uint32_t)st);
            uart_puts_raw("\n");
            uart_unlock();
            return;
        }
        rx += clen;

        uart_lock();
        uart_putc_raw('K');
        uart_unlock();
    }

    toob_status_t fst = toob_ota_finalize(&ota_ctx);
    if (fst != TOOB_OK) {
        uart_lock();
        uart_puts_raw("\n[RTOS] OTA_ERR finalize code=");
        uart_put_dec_raw((uint32_t)fst);
        uart_puts_raw("\n");
        uart_unlock();
        return;
    }

    uart_lock();
    uart_puts_raw("\n[RTOS] OTA_FINALIZED status=OK notifier=");
    uart_put_dec_raw(s_swap_notifier_calls);
    uart_puts_raw(" wdt_feeds=");
    uart_put_dec_raw(s_wdt_feeds);
    uart_puts_raw("\n");
    uart_unlock();

    system_reboot_intentional();
}

static void task_ota_worker(void *arg)
{
    (void)arg;
    toob_set_swap_notifier(app_swap_notifier_cb);

    if (k_app_meta.simulate_deadlock != 0U) {
        (void)xSemaphoreTake(s_deadlock_mtx_a, portMAX_DELAY);
        vTaskDelay(DEADLOCK_STEP_DELAY_TICKS);
        /* Deadlocks forever against TaskDeadlockPeer holding s_deadlock_mtx_b */
        (void)xSemaphoreTake(s_deadlock_mtx_b, portMAX_DELAY);
    }

    /* Phase A: Concurrent FPU + toob_get_boot_diag() contention with TaskWatchdogHealth */
    toob_boot_diag_t diag;
    memset(&diag, 0, sizeof(diag));
    while (s_boot_confirmed == 0U) {
        fpu_stress_round(FPU_SEED_WORKER);
        if (toob_get_boot_diag(&diag) == TOOB_OK) {
            s_worker_diag_calls++;
        }
        s_worker_heartbeats++;
    }

    /* Phase B: Report post-confirmation boot diagnostics from .noinit + handoff */
    toob_status_t dst = toob_get_boot_diag(&diag);
    uart_lock();
    uart_puts_raw("[RTOS] DIAG ver=");
    uart_puts_volatile_raw(k_app_meta.version);
    uart_puts_raw(" status=");
    uart_puts_raw((dst == TOOB_OK) ? "OK" : "ERR");
    uart_puts_raw(" reset_reason=");
    uart_put_dec_raw(s_pre_handoff.reset_reason);
    uart_puts_raw(" outcome=");
    uart_put_dec_raw((uint32_t)diag.last_update_outcome);
    uart_puts_raw(" svn=");
    uart_put_dec_raw(diag.installed_app_svn);
    uart_puts_raw(" fw_major=");
    uart_put_dec_raw((uint32_t)diag.fw_ver_major);
    uart_puts_raw(" diag_calls=");
    uart_put_dec_raw(s_worker_diag_calls);
    uart_puts_raw(" timer_cbs=");
    uart_put_dec_raw(s_timer_callbacks);
    uart_puts_raw("\n");
    uart_unlock();

    /* Phase C: Interactive UART0 Command & Streaming OTA Worker */
    char line[APP_LINE_BUF_LEN];
    for (;;) {
        size_t n = uart_read_line_rtos(line, sizeof(line));
        if (n == 0U) {
            continue;
        }
        if (strcmp(line, "STATUS") == 0) {
            uart_lock();
            uart_puts_raw("[RTOS] STATUS ver=");
            uart_puts_volatile_raw(k_app_meta.version);
            uart_puts_raw(" ticks=");
            uart_put_dec_raw((uint32_t)xTaskGetTickCount());
            uart_puts_raw(" switches=");
            uart_put_dec_raw(g_rtos_context_switches);
            uart_puts_raw(" wdt_feeds=");
            uart_put_dec_raw(s_wdt_feeds);
            uart_puts_raw(" diag_calls=");
            uart_put_dec_raw(s_worker_diag_calls);
            uart_puts_raw("\n");
            uart_unlock();
        } else if (strcmp(line, "REBOOT") == 0) {
            uart_lock();
            uart_puts_raw("[RTOS] REBOOTING\n");
            uart_unlock();
            system_reboot_intentional();
        } else if (strncmp(line, "OTA ", APP_OTA_CMD_PREFIX_LEN) == 0) {
            handle_rtos_ota_command(line + APP_OTA_CMD_PREFIX_LEN);
        }
    }
}

/* ============================================================================
 * Pre-Scheduler C Runtime Init & FreeRTOS Kernel Launch
 * ============================================================================ */

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
    s_uart_mtx = xSemaphoreCreateMutexStatic(&s_uart_mtx_buf);

    /* Verify libtoob + toob_hooks.c pre-scheduler safety (taskSCHEDULER_NOT_STARTED) */
    bool not_started = (xTaskGetSchedulerState() == taskSCHEDULER_NOT_STARTED);
    toob_status_t init_st = toob_os_init();
    memset(&s_pre_handoff, 0, sizeof(s_pre_handoff));
    toob_status_t pre_hst = toob_get_handoff(&s_pre_handoff);
    s_presched_ok = not_started && (init_st == TOOB_OK) && (pre_hst == TOOB_OK);

    uart_puts_raw("[RTOS] SCHED_START ver=");
    uart_puts_volatile_raw(k_app_meta.version);
    uart_puts_raw(" slot=");
    uart_put_dec_raw(s_presched_ok ? (uint32_t)s_pre_handoff.active_slot : APP_UNKNOWN_SLOT_ID);
    uart_puts_raw(" tent=");
    uart_put_dec_raw((s_presched_ok && (s_pre_handoff.magic == TOOB_STATE_TENTATIVE)) ? 1U : 0U);
    uart_puts_raw(" presched=");
    uart_puts_raw(s_presched_ok ? "OK\n" : "ERR\n");

    TaskHandle_t health_handle = xTaskCreateStatic(
        task_watchdog_health,
        "TaskWatchdogHealth",
        HEALTH_TASK_STACK_WORDS,
        NULL,
        BOOT_SELFTEST_PRIO,
        s_health_stack,
        &s_health_tcb);
    configASSERT(health_handle != NULL);

    BaseType_t worker_rc = xTaskCreate(
        task_ota_worker,
        "TaskOtaWorker",
        WORKER_TASK_STACK_WORDS,
        NULL,
        BOOT_SELFTEST_PRIO,
        NULL);
    configASSERT(worker_rc == pdPASS);

    if (k_app_meta.simulate_deadlock != 0U) {
        s_deadlock_mtx_a = xSemaphoreCreateMutexStatic(&s_deadlock_mtx_a_buf);
        s_deadlock_mtx_b = xSemaphoreCreateMutexStatic(&s_deadlock_mtx_b_buf);
        configASSERT((s_deadlock_mtx_a != NULL) && (s_deadlock_mtx_b != NULL));

        BaseType_t peer_rc = xTaskCreate(
            task_deadlock_peer,
            "TaskDeadlockPeer",
            DEADLOCK_TASK_STACK_WORDS,
            NULL,
            BOOT_SELFTEST_PRIO,
            NULL);
        configASSERT(peer_rc == pdPASS);
    }

    s_periodic_timer = xTimerCreateStatic(
        "HealthTickTimer",
        pdMS_TO_TICKS(SW_TIMER_PERIOD_MS),
        pdTRUE,
        NULL,
        sw_timer_callback,
        &s_timer_buf);
    configASSERT(s_periodic_timer != NULL);
    (void)xTimerStart(s_periodic_timer, 0U);

    vTaskStartScheduler();

    for (;;) {
        __asm__ volatile("wfi");
    }
}

void __attribute__((naked, noreturn, section(".app_entry"))) _app_start(void)
{
    /* Enable Cortex-M4F CP10/CP11 VFP coprocessors before entering hard-float C code */
    __asm__ volatile(
        "cpsid i\n"
        "ldr r0, =0xE000ED88\n"
        "ldr r1, [r0]\n"
        "orr r1, r1, #(0xF << 20)\n"
        "str r1, [r0]\n"
        "dsb sy\n"
        "isb sy\n"
        "ldr r0, =_stack_top\n"
        "mov sp, r0\n"
        "b _app_c_init\n"
    );
}
