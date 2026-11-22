/**
 * @file app_main.c
 * @brief Bare-Metal ESP32-C3 Guest Firmware for Full-System QEMU E2E Testing
 *
 * Links directly against production sdk/libtoob to exercise:
 *   - Stage 1 -> OS RTC RAM handoff verification (toob_get_handoff)
 *   - Dual-channel boot confirmation (toob_confirm_boot: RTC nonce + Flash Mailbox)
 *   - Streaming OTA ingestion (toob_ota_begin / process_chunk / finalize)
 *   - Unconfirmed firmware hang / crash for Hardware TIMG0 WDT Auto-Rollback
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libtoob.h"
#include "esp_common.h"
#include "chip_config.h"
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
extern uint32_t _iram_dbus_start;
extern uint32_t _iram_dbus_end;
extern uint32_t _sidata;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;
extern uint32_t __global_pointer$;

/* ============================================================================
 * Bare-metal UART0 + TIMG0 WDT Helpers
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
 * libtoob OS Porting Layer (ESP32-C3 Physical SPI Flash + Hardware XTS-AES-128)
 * ============================================================================ */

#define APP_EFUSE_RD_REPEAT_DATA1_REG   (CHIP_REG_EFUSE_BASE + 0x034U)
#define APP_SPI_BOOT_CRYPT_CNT_SHIFT    18U
#define APP_SPI_BOOT_CRYPT_CNT_MASK     0x07U
#define APP_MMU_SCRATCH_IDX             63U
#define APP_MMU_SCRATCH_BASE            (CHIP_REG_FLASH_DROM_BASE + (APP_MMU_SCRATCH_IDX * CHIP_MMU_PAGE_SIZE))
#define APP_XTS_BLOCK_SIZE              16U
#define APP_XTS_BLOCK_WORDS             4U
#define APP_XTS_BLOCK_MASK              0x0FU
#define APP_XTS_STATE_MASK              0x03U
#define APP_XTS_STATE_BUSY              0x01U
#define APP_XTS_STATE_RELEASED          0x03U
#define APP_MANU_ENCRYPT_ENABLE_MASK    0x09U

__attribute__((section(".iram_text"), noinline))
static bool app_flash_encryption_active(void)
{
    uint32_t rdata1 = REG_READ(APP_EFUSE_RD_REPEAT_DATA1_REG);
    uint32_t cnt = (rdata1 >> APP_SPI_BOOT_CRYPT_CNT_SHIFT) & APP_SPI_BOOT_CRYPT_CNT_MASK;
    uint32_t pop = (cnt & 1U) + ((cnt >> 1U) & 1U) + ((cnt >> 2U) & 1U);
    return (pop & 1U) != 0U;
}

__attribute__((section(".iram_text"), noinline))
static bool app_hits_immutable_boot(uint32_t addr, uint32_t len)
{
    if (REG_READ(CHIP_REG_EFUSE_BASE + ESP_EFUSE_USR_DATA4_OFFSET) == ESP_EFUSE_BOOTLOCK_MAGIC) {
        uint32_t lock_end = REG_READ(CHIP_REG_EFUSE_BASE + ESP_EFUSE_USR_DATA3_OFFSET);
        if (lock_end > 0U && addr < lock_end) {
            return true;
        }
    }
    (void)len;
    return false;
}

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
static toob_status_t app_xts_write_block(uint32_t blk_addr, const uint8_t plain_bytes[APP_XTS_BLOCK_SIZE])
{
    uint32_t plain_words[APP_XTS_BLOCK_WORDS];
    for (uint32_t i = 0U; i < APP_XTS_BLOCK_WORDS; i++) {
        uint32_t base = i * 4U;
        plain_words[i] = ((uint32_t)plain_bytes[base]) |
                         (((uint32_t)plain_bytes[base + 1U]) << 8U) |
                         (((uint32_t)plain_bytes[base + 2U]) << 16U) |
                         (((uint32_t)plain_bytes[base + 3U]) << 24U);
    }

    uint32_t plain_win = CHIP_REG_XTS_AES_BASE + (blk_addr & ESP_XTS_PLAIN_WINDOW_MASK_HW);

    REG_SET_BIT(ESP_REG_EXT_MEM_ENC_CTRL, APP_MANU_ENCRYPT_ENABLE_MASK);
    REG_WRITE(CHIP_REG_XTS_AES_DESTINATION, 0U);
    REG_WRITE(CHIP_REG_XTS_AES_LINESIZE, 0U);
    REG_WRITE(CHIP_REG_XTS_AES_PHYSICAL_ADDRESS, blk_addr);

    for (uint32_t i = 0U; i < APP_XTS_BLOCK_WORDS; i++) {
        REG_WRITE(plain_win + (i * 4U), plain_words[i]);
    }

    REG_WRITE(CHIP_REG_XTS_AES_TRIGGER, 1U);
    uint32_t timeout = 100000U;
    while (((REG_READ(CHIP_REG_XTS_AES_STATE) & APP_XTS_STATE_MASK) == APP_XTS_STATE_BUSY) &&
           (timeout > 0U)) {
        timeout--;
    }
    if (timeout == 0U) {
        REG_WRITE(CHIP_REG_XTS_AES_DESTROY, 1U);
        REG_CLR_BIT(ESP_REG_EXT_MEM_ENC_CTRL, APP_MANU_ENCRYPT_ENABLE_MASK);
        return TOOB_ERR_FLASH_HW;
    }

    REG_WRITE(CHIP_REG_XTS_AES_RELEASE, 1U);
    timeout = 100000U;
    while (((REG_READ(CHIP_REG_XTS_AES_STATE) & APP_XTS_STATE_MASK) != APP_XTS_STATE_RELEASED) &&
           (timeout > 0U)) {
        timeout--;
    }
    if (timeout == 0U) {
        REG_WRITE(CHIP_REG_XTS_AES_DESTROY, 1U);
        REG_CLR_BIT(ESP_REG_EXT_MEM_ENC_CTRL, APP_MANU_ENCRYPT_ENABLE_MASK);
        return TOOB_ERR_FLASH_HW;
    }

    int rc = ROM_FLASH_WRITE(blk_addr, plain_words, APP_XTS_BLOCK_SIZE);

    for (uint32_t i = 0U; i < APP_XTS_BLOCK_WORDS; i++) {
        REG_WRITE(plain_win + (i * 4U), 0U);
        plain_words[i] = 0U;
    }
    REG_WRITE(CHIP_REG_XTS_AES_DESTROY, 1U);
    REG_CLR_BIT(ESP_REG_EXT_MEM_ENC_CTRL, APP_MANU_ENCRYPT_ENABLE_MASK);

    return (rc == ESP_ROM_OK) ? TOOB_OK : TOOB_ERR_FLASH;
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

    if (!app_flash_encryption_active()) {
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

    uint32_t saved_mmu = esp_mmu_read_raw(APP_MMU_SCRATCH_IDX);
    uint32_t mapped_page = 0xFFFFFFFFU;
    toob_status_t status = TOOB_OK;

    while (len > 0U) {
        wdt_kick();
        uint32_t blk_addr = addr & ~APP_XTS_BLOCK_MASK;
        uint32_t blk_off = addr - blk_addr;
        uint32_t avail = APP_XTS_BLOCK_SIZE - blk_off;
        uint32_t take = (len < avail) ? len : avail;

        uint32_t raw_words[APP_XTS_BLOCK_WORDS];
        if (ROM_FLASH_READ(blk_addr, raw_words, APP_XTS_BLOCK_SIZE) != ESP_ROM_OK) {
            status = TOOB_ERR_FLASH;
            break;
        }

        if (raw_words[0] == 0xFFFFFFFFU && raw_words[1] == 0xFFFFFFFFU &&
            raw_words[2] == 0xFFFFFFFFU && raw_words[3] == 0xFFFFFFFFU) {
            memset(buf, 0xFF, take);
        } else {
            uint32_t page_paddr = blk_addr & ~(CHIP_MMU_PAGE_SIZE - 1U);
            if (page_paddr != mapped_page) {
                esp_mmu_write_entry(APP_MMU_SCRATCH_IDX, page_paddr >> 16U);
                if (esp_cache_invalidate_single_vrange(APP_MMU_SCRATCH_BASE, CHIP_MMU_PAGE_SIZE, 100000U) != BOOT_OK) {
                    status = TOOB_ERR_FLASH_HW;
                    break;
                }
                mapped_page = page_paddr;
            }
            const uint8_t *vsrc = (const uint8_t *)(uintptr_t)(
                APP_MMU_SCRATCH_BASE + (blk_addr - page_paddr) + blk_off);
            memcpy(buf, vsrc, take);
        }

        addr += take;
        buf += take;
        len -= take;
    }

    if (mapped_page != 0xFFFFFFFFU) {
        esp_mmu_write_raw(APP_MMU_SCRATCH_IDX, saved_mmu);
        (void)esp_cache_invalidate_single_vrange(APP_MMU_SCRATCH_BASE, CHIP_MMU_PAGE_SIZE, 100000U);
    }
    return status;
}

__attribute__((section(".iram_text"), noinline))
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len)
{
    if (buf == NULL || len == 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (app_hits_immutable_boot(addr, len)) {
        return TOOB_ERR_FLASH;
    }
    if ((addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U || (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U) {
        return TOOB_ERR_FLASH;
    }
    if (addr > CHIP_FLASH_TOTAL_SIZE || len > (CHIP_FLASH_TOTAL_SIZE - addr)) {
        return TOOB_ERR_FLASH;
    }

    if (app_flash_encryption_active()) {
        if ((addr & APP_XTS_BLOCK_MASK) != 0U) {
            return TOOB_ERR_FLASH;
        }
        uint8_t pad_blk[APP_XTS_BLOCK_SIZE];
        uint32_t cur_addr = addr;
        uint32_t rem = len;
        const uint8_t *src = buf;

        while (rem > 0U) {
            wdt_kick();
            const uint8_t *blk_ptr = src;
            uint32_t advance = APP_XTS_BLOCK_SIZE;
            if (rem < APP_XTS_BLOCK_SIZE) {
                memset(pad_blk, 0xFF, sizeof(pad_blk));
                memcpy(pad_blk, src, rem);
                blk_ptr = pad_blk;
                advance = rem;
            }
            toob_status_t st = app_xts_write_block(cur_addr, blk_ptr);
            if (st != TOOB_OK) {
                memset(pad_blk, 0, sizeof(pad_blk));
                app_sync_cache(addr, len);
                return st;
            }
            src += advance;
            cur_addr += APP_XTS_BLOCK_SIZE;
            rem -= advance;
        }
        memset(pad_blk, 0, sizeof(pad_blk));
        app_sync_cache(addr, (len + APP_XTS_BLOCK_MASK) & ~APP_XTS_BLOCK_MASK);
        return TOOB_OK;
    }

    uint32_t bounce[64];
    uint32_t cur_addr = addr;
    uint32_t rem = len;
    const uint8_t *src = buf;

    while (rem > 0U) {
        wdt_kick();
        uint32_t chunk = (rem > 256U) ? 256U : rem;
        /* Copy via bounce buffer in DRAM so XIP DROM sources never stall MSPI */
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
    if (app_hits_immutable_boot(addr, len)) {
        return TOOB_ERR_FLASH;
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

#define RTC_CNTL_OPTIONS0_REG  (CHIP_REG_PMU_BASE + 0x0000U)
#define RTC_CNTL_SW_SYS_RST    (1U << 31)

static void __attribute__((noreturn)) system_reboot_intentional(void)
{
    /* Trigger SW_SYS_RST (reset cause 3 = RESET_REASON_SOFTWARE, intentional!) */
    REG_SET_BIT(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_SW_SYS_RST);
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
    uint32_t *dst = &_iram_dbus_start;
    while (dst < &_iram_dbus_end) {
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
        /* Hang intentionally WITHOUT feeding TIMG0 WDT so Stage 1's hardware WDT
         * fires TG0WDT_SYS_RESET and triggers automatic rollback! */
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
        } else if (strcmp(line, "REBOOT") == 0) {
            uart_puts("[APP] REBOOTING\n");
            system_reboot_intentional();
        } else if (strncmp(line, "OTA ", 4) == 0) {
            uint32_t total_len = parse_u32_dec(line + 4);
            handle_ota_command(total_len);
        } else if (strcmp(line, "BOOTLOCKTEST") == 0) {
            uint8_t dummy[16];
            memset(dummy, 0xA5, sizeof(dummy));
            bool enc = app_flash_encryption_active();
            uint32_t lock_end = REG_READ(CHIP_REG_EFUSE_BASE + ESP_EFUSE_USR_DATA3_OFFSET);
            uint32_t lock_mag = REG_READ(CHIP_REG_EFUSE_BASE + ESP_EFUSE_USR_DATA4_OFFSET);
            toob_status_t er_s0 = toob_os_flash_erase(0x0000U, CHIP_FLASH_MAX_SECTOR_SIZE);
            toob_status_t wr_s0 = toob_os_flash_write(0x0000U, dummy, sizeof(dummy));
            uart_puts("[APP] BOOTLOCK fe=");
            uart_put_dec(enc ? 1U : 0U);
            uart_puts(" end=");
            uart_put_dec(lock_end);
            uart_puts(" magic=");
            uart_puts((lock_mag == ESP_EFUSE_BOOTLOCK_MAGIC) ? "OK" : "ERR");
            uart_puts(" guard=");
            uart_puts(((er_s0 != TOOB_OK) && (wr_s0 != TOOB_OK)) ? "DENIED\n" : "ALLOWED\n");
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
