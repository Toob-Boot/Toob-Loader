#include "mock_flash.h"
#include "chip_config.h"
#include "chip_fault_inject.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *flash_file = NULL;
static uint32_t simulated_vendor_error = 0;

static boot_status_t mock_flash_init(void) {
    /* Zentrale Environment-Parser via Fault-Engine */
    fault_inject_init();

    flash_file = fopen(g_fault_config.flash_sim_file, "rb+");
    if (!flash_file) {
        flash_file = fopen(g_fault_config.flash_sim_file, "wb+");
        if (!flash_file) {
            return BOOT_ERR_STATE;
        }

        uint8_t buffer[CHIP_FLASH_PAGE_SIZE];
        memset(buffer, CHIP_FLASH_ERASURE_MAPPING, sizeof(buffer));

        uint32_t pages = CHIP_FLASH_TOTAL_SIZE / CHIP_FLASH_PAGE_SIZE;
        /* P10 Rule 2: Bound loop with max static pages limit */
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
    if (addr + len > CHIP_FLASH_TOTAL_SIZE || addr + len < addr) return BOOT_ERR_FLASH_BOUNDS;

    if (fseek(flash_file, addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
    if (fread(buf, 1, len, flash_file) != len) return BOOT_ERR_FLASH;

    /* Bitrot via globale Engine anwenden */
    fault_inject_apply_bitrot(addr, buf, len);

    return BOOT_OK;
}

static boot_status_t mock_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (!flash_file) return BOOT_ERR_STATE;
    if (addr % CHIP_FLASH_WRITE_ALIGNMENT != 0 || len % CHIP_FLASH_WRITE_ALIGNMENT != 0) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    if (addr + len > CHIP_FLASH_TOTAL_SIZE || addr + len < addr) return BOOT_ERR_FLASH_BOUNDS;

#ifndef TOOB_FLASH_DISABLE_BLANK_CHECK
    size_t remaining = len;
    uint32_t current_addr = addr;
    uint8_t existing[256];
    
    /* P10 Rule 2: Upper Bound = Total Size / Minimum Align */
    size_t max_iters = CHIP_FLASH_TOTAL_SIZE; 
    for (size_t iter = 0; iter < max_iters && remaining > 0; iter++) {
        size_t chunk = (remaining > sizeof(existing)) ? sizeof(existing) : remaining;
        if (fseek(flash_file, current_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fread(existing, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        /* GAP-WriteAlign: Byte-weise iterieren, um Rest-Bytes akkurat zu prüfen */
        for (size_t i = 0; i < chunk; i++) {
            if (existing[i] != CHIP_FLASH_ERASURE_MAPPING) {
                return BOOT_ERR_FLASH_NOT_ERASED;
            }
        }
        remaining -= chunk;
        current_addr += chunk;
    }
#endif

    size_t remain_write = len;
    uint32_t wr_addr = addr;
    const uint8_t *src = (const uint8_t *)buf;

    /* P10 Rule 2: Upper Bound loop */
    size_t max_write_iters = CHIP_FLASH_TOTAL_SIZE;
    for (size_t iter = 0; iter < max_write_iters && remain_write > 0; iter++) {
        uint8_t buffer_chunk[256];
        size_t chunk = (remain_write > sizeof(buffer_chunk)) ? sizeof(buffer_chunk) : remain_write;

        if (fseek(flash_file, wr_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fread(buffer_chunk, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        /* GAP-F07: NOR-Flash vs Data-Flash Emulation */
        for (size_t i = 0; i < chunk; i++) {
            if (CHIP_FLASH_ERASURE_MAPPING == 0xFF) {
                buffer_chunk[i] &= *src++;
            } else {
                buffer_chunk[i] |= *src++;
            }
        }

        /* Torn-Write Fault-Injection DIREKT vor dem fwrite! */
        fault_inject_point_flash(flash_file, buffer_chunk, chunk);

        if (fseek(flash_file, wr_addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
        if (fwrite(buffer_chunk, 1, chunk, flash_file) != chunk) return BOOT_ERR_FLASH;

        remain_write -= chunk;
        wr_addr += chunk;
    }

    fflush(flash_file);
    return BOOT_OK;
}

static boot_status_t mock_flash_erase_sector(uint32_t addr) {
    if (!flash_file) return BOOT_ERR_STATE;
    if (addr % CHIP_FLASH_PAGE_SIZE != 0) return BOOT_ERR_FLASH_ALIGN;
    if (addr >= CHIP_FLASH_TOTAL_SIZE) return BOOT_ERR_FLASH_BOUNDS;

    uint8_t erased_block[CHIP_FLASH_PAGE_SIZE];
    memset(erased_block, CHIP_FLASH_ERASURE_MAPPING, sizeof(erased_block));

    fault_inject_point_flash(flash_file, erased_block, sizeof(erased_block));

    if (fseek(flash_file, addr, SEEK_SET) != 0) return BOOT_ERR_FLASH;
    if (fwrite(erased_block, 1, sizeof(erased_block), flash_file) != sizeof(erased_block)) {
        return BOOT_ERR_FLASH;
    }

    fflush(flash_file);
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
    (void)enable;
    return BOOT_ERR_NOT_SUPPORTED;
}

static uint32_t mock_flash_get_last_vendor_error(void) {
    uint32_t err = simulated_vendor_error;
    simulated_vendor_error = 0; 
    return err;
}

void mock_flash_reset_to_factory(void) {
    if (flash_file) {
        fclose(flash_file);
        flash_file = NULL;
    }
    if (g_fault_config.flash_sim_file) {
        remove(g_fault_config.flash_sim_file);
    } else {
        remove("flash_sim.bin");
    }
    g_fault_config.simulated_writes = 0;
}

void mock_flash_set_fail_limit(uint32_t limit) {
    g_fault_config.write_count_limit = limit;
    g_fault_config.simulated_writes = 0;
}

void mock_flash_set_bitrot(uint32_t addr, uint8_t value) {
    g_fault_config.bitrot_addr = addr;
    g_fault_config.bitrot_value = value;
}

const flash_hal_t sandbox_flash_hal = {
    .abi_version = 0x01000000,
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
