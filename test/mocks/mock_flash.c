/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Mapped Flash Implementation (POSIX/Windows via stdio)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS & GAPS:
 * 1. docs/hals.md (Flash HAL Backend)
 * 2. docs/concept_fusion.md (In-Place Swap Buffer)
 * 3. docs/merkle_spec.md (GAP-08: Stream-Hashing)
 * 4. docs/sandbox_setup.md & docs/testing_requirements.md
 */

#include "mock_flash.h"
#include "chip_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SIM_FILE "flash_sim.bin"

static FILE *flash_file = NULL;
static const char *sim_filename = DEFAULT_SIM_FILE;
static uint32_t write_count_limit = 0;
static uint32_t simulated_writes = 0;
static uint32_t simulated_vendor_error = 0;

static uint32_t bitrot_addr = 0xFFFFFFFF;
static uint8_t  bitrot_value = 0x00;

static void check_fault_injection(void) {
    if (write_count_limit > 0 && simulated_writes >= write_count_limit) {
        printf("[M-SANDBOX] BROWNOUT SIMULATED! Power loss after %u writes.\n", simulated_writes);
        fflush(stdout);
        exit(1); /* Crash! */
    }
}

static boot_status_t mock_flash_init(void) {
    const char *env_file = getenv("TOOB_FLASH_SIM_FILE");
    if (env_file != NULL) {
        sim_filename = env_file;
    }

    const char *env_fail = getenv("TOOB_FAIL_AFTER_WRITES");
    if (env_fail != NULL) {
        write_count_limit = (uint32_t)strtoul(env_fail, NULL, 10);
    }

    const char *env_bitrot_addr = getenv("TOOB_BITROT_ADDR");
    if (env_bitrot_addr != NULL) {
        bitrot_addr = (uint32_t)strtoul(env_bitrot_addr, NULL, 16);
    }

    const char *env_bitrot_val = getenv("TOOB_BITROT_VALUE");
    if (env_bitrot_val != NULL) {
        bitrot_value = (uint8_t)strtoul(env_bitrot_val, NULL, 16);
    }

    flash_file = fopen(sim_filename, "rb+");
    if (!flash_file) {
        /* File doesn't exist, create it */
        flash_file = fopen(sim_filename, "wb+");
        if (!flash_file) {
            return BOOT_ERR_STATE;
        }

        /* Initialisieren mit 0xFF (Erase Data) */
        uint8_t buffer[CHIP_FLASH_PAGE_SIZE];
        memset(buffer, CHIP_FLASH_ERASURE_MAPPING, sizeof(buffer));

        uint32_t pages = CHIP_FLASH_TOTAL_SIZE / CHIP_FLASH_PAGE_SIZE;
        for (uint32_t i = 0; i < pages; i++) {
            if (fwrite(buffer, 1, sizeof(buffer), flash_file) != sizeof(buffer)) {
                fclose(flash_file);
                flash_file = NULL;
                return BOOT_ERR_STATE;
            }
        }
    }
    fflush(flash_file);
    return BOOT_OK;
}

static void mock_flash_deinit(void) {
    if (flash_file) {
        fclose(flash_file);
        flash_file = NULL;
    }
}

static boot_status_t mock_flash_read(uint32_t addr, void *buf, size_t len) {
    if (!flash_file) return BOOT_ERR_STATE;
    if (addr + len > CHIP_FLASH_TOTAL_SIZE) return BOOT_ERR_FLASH_BOUNDS;

    if (fseek(flash_file, addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
    if (fread(buf, 1, len, flash_file) != len) return BOOT_ERR_FLASH;

    /* Bit-Rot Simulator Injection (GAP-F20) */
    if (bitrot_addr >= addr && bitrot_addr < (addr + len)) {
        uint8_t *byte_buf = (uint8_t *)buf;
        byte_buf[bitrot_addr - addr] = bitrot_value;
    }

    return BOOT_OK;
}

static boot_status_t mock_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (!flash_file) return BOOT_ERR_STATE;
    if (addr % CHIP_FLASH_WRITE_ALIGNMENT != 0 || len % CHIP_FLASH_WRITE_ALIGNMENT != 0) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    if (addr + len > CHIP_FLASH_TOTAL_SIZE) return BOOT_ERR_FLASH_BOUNDS;

#ifndef TOOB_FLASH_DISABLE_BLANK_CHECK
    /* O(1) Erase-Verify Check via 32-Bit Aligned Word-Check */
    uint32_t existing[64]; /* 256 Bytes Puffer statisch */
    size_t remaining = len;
    uint32_t current_addr = addr;
    const uint32_t erased_word = (CHIP_FLASH_ERASURE_MAPPING << 24) |
                                 (CHIP_FLASH_ERASURE_MAPPING << 16) |
                                 (CHIP_FLASH_ERASURE_MAPPING << 8)  |
                                  CHIP_FLASH_ERASURE_MAPPING;

    while (remaining > 0) {
        size_t chunk = (remaining > sizeof(existing)) ? sizeof(existing) : remaining;
        if (fseek(flash_file, current_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fread(existing, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        size_t words = chunk / 4;
        for (size_t i = 0; i < words; i++) {
            if (existing[i] != erased_word) {
                return BOOT_ERR_FLASH_NOT_ERASED;
            }
        }
        remaining -= chunk;
        current_addr += chunk;
    }
#endif

    /* Simuliere NOR-Flash Physik: Man kann Bits nur auf 0 ziehen (Logisches AND) */
    /* P10 Chunked-Loop (Kein VLA): Lese Blockweise, manipuliere und schreibe zurück */
    size_t remain_write = len;
    uint32_t wr_addr = addr;
    const uint8_t *src = (const uint8_t *)buf;

    while (remain_write > 0) {
        uint8_t buffer_chunk[256];
        size_t chunk = (remain_write > sizeof(buffer_chunk)) ? sizeof(buffer_chunk) : remain_write;

        if (fseek(flash_file, wr_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fread(buffer_chunk, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        for (size_t i = 0; i < chunk; i++) {
            buffer_chunk[i] &= *src++;
        }

        if (fseek(flash_file, wr_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fwrite(buffer_chunk, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        remain_write -= chunk;
        wr_addr += chunk;
    }

    fflush(flash_file);

    simulated_writes++;
    check_fault_injection();

    return BOOT_OK;
}

static boot_status_t mock_flash_erase_sector(uint32_t addr) {
    if (!flash_file) return BOOT_ERR_STATE;
    if (addr % CHIP_FLASH_PAGE_SIZE != 0) return BOOT_ERR_FLASH_ALIGN;
    if (addr >= CHIP_FLASH_TOTAL_SIZE) return BOOT_ERR_FLASH_BOUNDS;

    uint8_t erased_block[CHIP_FLASH_PAGE_SIZE];
    memset(erased_block, CHIP_FLASH_ERASURE_MAPPING, sizeof(erased_block));

    if (fseek(flash_file, addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
    if (fwrite(erased_block, 1, sizeof(erased_block), flash_file) != sizeof(erased_block)) {
        return BOOT_ERR_FLASH;
    }

    fflush(flash_file);

    simulated_writes++;
    check_fault_injection();

    return BOOT_OK;
}

static boot_status_t mock_flash_get_sector_size(uint32_t addr, size_t *size_out) {
    if (addr >= CHIP_FLASH_TOTAL_SIZE) return BOOT_ERR_FLASH_BOUNDS;
    if (size_out) {
        *size_out = CHIP_FLASH_PAGE_SIZE;
    }
    return BOOT_OK;
}

static boot_status_t mock_flash_set_otfdec_mode(bool enable) {
    /* Sandbox emuliert keine On-The-Fly Entschlüsselung in Software */
    (void)enable;
    return BOOT_ERR_NOT_SUPPORTED;
}

static uint32_t mock_flash_get_last_vendor_error(void) {
    uint32_t err = simulated_vendor_error;
    simulated_vendor_error = 0; /* Clear on read */
    return err;
}

/* --- Public Utilities --- */

void mock_flash_reset_to_factory(void) {
    if (flash_file) {
        fclose(flash_file);
        flash_file = NULL;
    }
    remove(sim_filename);
    simulated_writes = 0;
}

void mock_flash_set_fail_limit(uint32_t limit) {
    write_count_limit = limit;
    simulated_writes = 0;
}

void mock_flash_set_bitrot(uint32_t addr, uint8_t value) {
    bitrot_addr = addr;
    bitrot_value = value;
}

/* --- Export --- */

const flash_hal_t sandbox_flash_hal = {
    .version = 0x01000000,
    .init = mock_flash_init,
    .deinit = mock_flash_deinit,
    .read = mock_flash_read,
    .write = mock_flash_write,
    .erase_sector = mock_flash_erase_sector,
    .get_sector_size = mock_flash_get_sector_size,
    .set_otfdec_mode = mock_flash_set_otfdec_mode,
    .get_last_vendor_error = mock_flash_get_last_vendor_error,

    .max_sector_size = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size = CHIP_FLASH_TOTAL_SIZE,
    .write_align = CHIP_FLASH_WRITE_ALIGNMENT,
    .erased_value = CHIP_FLASH_ERASURE_MAPPING
};
