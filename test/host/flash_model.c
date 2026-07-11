#include "flash_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static flash_model_t *g_model = NULL;

static boot_status_t model_init(void) {
    if (!g_model) return BOOT_ERR_STATE;

    /* Datei öffnen oder neu anlegen, falls nicht vorhanden */
    FILE *f = fopen(g_model->file_path, "rb+");
    if (!f) {
        f = fopen(g_model->file_path, "wb+");
        if (!f) return BOOT_ERR_FLASH;

        /* Flash mit erased_value initialisieren */
        uint8_t *sector_buf = malloc(g_model->sector_size);
        if (!sector_buf) {
            fclose(f);
            return BOOT_ERR_STATE;
        }
        memset(sector_buf, g_model->erased_value, g_model->sector_size);

        size_t written = 0;
        while (written < g_model->total_size) {
            size_t to_write = g_model->total_size - written;
            if (to_write > g_model->sector_size) {
                to_write = g_model->sector_size;
            }
            if (fwrite(sector_buf, 1, to_write, f) != to_write) {
                free(sector_buf);
                fclose(f);
                return BOOT_ERR_FLASH;
            }
            written += to_write;
        }
        free(sector_buf);
    }
    fclose(f);
    g_model->op_counter = 0;
    return BOOT_OK;
}

static void model_deinit(void) {
    /* Keine permanent offenen Handles, um Dateikorruption bei simulierten Abstürzen zu minimieren */
}

static boot_status_t model_read(uint32_t addr, void *buf, size_t len) {
    if (!g_model) return BOOT_ERR_STATE;
    if (addr + len > g_model->total_size || addr + len < addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }

    FILE *f = fopen(g_model->file_path, "rb");
    if (!f) return BOOT_ERR_FLASH;

    if (fseek(f, addr, SEEK_SET) != 0) {
        fclose(f);
        return BOOT_ERR_FLASH;
    }

    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return BOOT_ERR_FLASH;
    }

    fclose(f);
    return BOOT_OK;
}

static boot_status_t model_write(uint32_t addr, const void *buf, size_t len) {
    if (!g_model) return BOOT_ERR_STATE;
    if (addr % g_model->write_align != 0 || len % g_model->write_align != 0) {
        return BOOT_ERR_FLASH_ALIGN;
    }
    if (addr + len > g_model->total_size || addr + len < addr) {
        return BOOT_ERR_FLASH_BOUNDS;
    }

    g_model->op_counter++;

    /* Absturz-Simulation */
    bool inject_crash = (g_model->fail_at_op > 0 && g_model->op_counter == g_model->fail_at_op);
    size_t effective_len = len;
    if (inject_crash) {
        effective_len = g_model->torn_prefix;
        if (effective_len > len) effective_len = len;
    }

    FILE *f = fopen(g_model->file_path, "r+b");
    if (!f) return BOOT_ERR_FLASH;

    /* Blank Check & NOR-Flash Physik: Lese bestehenden Zustand */
    uint8_t *temp = malloc(len);
    if (!temp) {
        fclose(f);
        return BOOT_ERR_STATE;
    }

    if (fseek(f, addr, SEEK_SET) != 0 || fread(temp, 1, len, f) != len) {
        free(temp);
        fclose(f);
        return BOOT_ERR_FLASH;
    }

    /* Simuliere NOR-Verhalten (Bits können nur von 1 zu 0 kippen) */
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0; i < effective_len; i++) {
        /* Blank check: Wenn das alte Bit 0 war, aber das neue 1 sein soll, ist das ein Fehler */
        if ((temp[i] & src[i]) != src[i]) {
            /* Falls ein Bit auf 1 gesetzt werden soll, das bereits 0 ist */
            free(temp);
            fclose(f);
            return BOOT_ERR_FLASH_NOT_ERASED;
        }
        temp[i] &= src[i]; /* Nur Bits löschen */
    }

    if (fseek(f, addr, SEEK_SET) != 0 || fwrite(temp, 1, effective_len, f) != effective_len) {
        free(temp);
        fclose(f);
        return BOOT_ERR_FLASH;
    }

    free(temp);
    fclose(f);

    if (inject_crash) {
        return BOOT_ERR_FLASH_HW;
    }

    return BOOT_OK;
}

static boot_status_t model_erase_sector(uint32_t addr) {
    if (!g_model) return BOOT_ERR_STATE;
    if (addr % g_model->sector_size != 0) return BOOT_ERR_FLASH_ALIGN;
    if (addr >= g_model->total_size) return BOOT_ERR_FLASH_BOUNDS;

    g_model->op_counter++;

    /* Absturz-Simulation */
    if (g_model->fail_at_op > 0 && g_model->op_counter == g_model->fail_at_op) {
        return BOOT_ERR_FLASH_HW;
    }

    FILE *f = fopen(g_model->file_path, "r+b");
    if (!f) return BOOT_ERR_FLASH;

    uint8_t *erased_block = malloc(g_model->sector_size);
    if (!erased_block) {
        fclose(f);
        return BOOT_ERR_STATE;
    }
    memset(erased_block, g_model->erased_value, g_model->sector_size);

    if (fseek(f, addr, SEEK_SET) != 0 || fwrite(erased_block, 1, g_model->sector_size, f) != g_model->sector_size) {
        free(erased_block);
        fclose(f);
        return BOOT_ERR_FLASH;
    }

    free(erased_block);
    fclose(f);
    return BOOT_OK;
}

static boot_status_t model_get_sector_size(uint32_t addr, size_t *size_out) {
    if (!g_model) return BOOT_ERR_STATE;
    if (addr >= g_model->total_size) return BOOT_ERR_FLASH_BOUNDS;
    if (size_out) {
        *size_out = g_model->sector_size;
    }
    return BOOT_OK;
}

static boot_status_t model_set_otfdec_mode(bool enable) {
    (void)enable;
    return BOOT_ERR_NOT_SUPPORTED;
}

static uint32_t model_get_last_vendor_error(void) {
    return 0;
}

static const flash_hal_t hal_interface = {
    .abi_version = 0x02000000,
    .init = model_init,
    .deinit = model_deinit,
    .read = model_read,
    .write = model_write,
    .erase_sector = model_erase_sector,
    .get_sector_size = model_get_sector_size,
    .set_otfdec_mode = model_set_otfdec_mode,
    .get_last_vendor_error = model_get_last_vendor_error
};

const flash_hal_t *flash_model_get_hal(flash_model_t *model) {
    g_model = model;
    g_model->op_counter = 0;
    return &hal_interface;
}
