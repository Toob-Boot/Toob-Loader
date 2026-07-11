#include "hal_tape.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    OP_FLASH_READ = 1,
    OP_FLASH_WRITE = 2,
    OP_FLASH_ERASE = 3,
    OP_CRYPTO_RANDOM = 4,
    OP_CLOCK_TICK = 5,
    OP_CLOCK_RESET_REASON = 6,
    OP_CRYPTO_MONOTONIC = 7
} tape_op_t;

typedef struct {
    uint8_t  op;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t ret_val;
} tape_hdr_t;

static FILE *g_tape_file = NULL;
static hal_tape_mode_t g_mode = TAPE_MODE_DISABLED;
static const boot_platform_t *g_base = NULL;

static boot_platform_t g_shim_platform;
static flash_hal_t g_shim_flash;
static crypto_hal_t g_shim_crypto;
static clock_hal_t g_shim_clock;

/* --- Flash Intercepts --- */

static boot_status_t shim_flash_init(void) {
    if (g_mode == TAPE_MODE_REPLAY) return BOOT_OK;
    return g_base->flash->init();
}

static void shim_flash_deinit(void) {
    if (g_mode == TAPE_MODE_REPLAY) return;
    g_base->flash->deinit();
}

static boot_status_t shim_flash_read(uint32_t addr, void *buf, size_t len) {
    if (g_mode == TAPE_MODE_RECORD) {
        boot_status_t ret = g_base->flash->read(addr, buf, len);
        tape_hdr_t hdr = { .op = OP_FLASH_READ, .arg1 = addr, .arg2 = (uint32_t)len, .ret_val = (uint32_t)ret };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        if (ret == BOOT_OK) {
            fwrite(buf, 1, len, g_tape_file);
        }
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        if (hdr.op != OP_FLASH_READ || hdr.arg1 != addr || hdr.arg2 != len) {
            fprintf(stderr, "Tape mismatch: expected Read op=%d addr=0x%x len=%d. Got op=%d addr=0x%x len=%d\n",
                    OP_FLASH_READ, addr, (uint32_t)len, hdr.op, hdr.arg1, hdr.arg2);
            exit(1);
        }
        if (hdr.ret_val == BOOT_OK) {
            if (fread(buf, 1, len, g_tape_file) != len) return BOOT_ERR_STATE;
        }
        return (boot_status_t)hdr.ret_val;
    }
    return g_base->flash->read(addr, buf, len);
}

static boot_status_t shim_flash_write(uint32_t addr, const void *buf, size_t len) {
    if (g_mode == TAPE_MODE_RECORD) {
        boot_status_t ret = g_base->flash->write(addr, buf, len);
        tape_hdr_t hdr = { .op = OP_FLASH_WRITE, .arg1 = addr, .arg2 = (uint32_t)len, .ret_val = (uint32_t)ret };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        if (hdr.op != OP_FLASH_WRITE || hdr.arg1 != addr || hdr.arg2 != len) {
            fprintf(stderr, "Tape mismatch: expected Write op=%d addr=0x%x len=%d. Got op=%d addr=0x%x len=%d\n",
                    OP_FLASH_WRITE, addr, (uint32_t)len, hdr.op, hdr.arg1, hdr.arg2);
            exit(1);
        }
        return (boot_status_t)hdr.ret_val;
    }
    return g_base->flash->write(addr, buf, len);
}

static boot_status_t shim_flash_erase_sector(uint32_t addr) {
    if (g_mode == TAPE_MODE_RECORD) {
        boot_status_t ret = g_base->flash->erase_sector(addr);
        tape_hdr_t hdr = { .op = OP_FLASH_ERASE, .arg1 = addr, .arg2 = 0, .ret_val = (uint32_t)ret };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        if (hdr.op != OP_FLASH_ERASE || hdr.arg1 != addr) {
            fprintf(stderr, "Tape mismatch: expected Erase op=%d addr=0x%x. Got op=%d addr=0x%x\n",
                    OP_FLASH_ERASE, addr, hdr.op, hdr.arg1);
            exit(1);
        }
        return (boot_status_t)hdr.ret_val;
    }
    return g_base->flash->erase_sector(addr);
}

static boot_status_t shim_flash_get_sector_size(uint32_t addr, size_t *size_out) {
    return g_base->flash->get_sector_size(addr, size_out);
}

static boot_status_t shim_flash_set_otfdec_mode(bool enable) {
    return g_base->flash->set_otfdec_mode(enable);
}

static uint32_t shim_flash_get_last_vendor_error(void) {
    return g_base->flash->get_last_vendor_error();
}

/* --- Crypto Intercepts --- */

static boot_status_t shim_crypto_init(void) {
    if (g_mode == TAPE_MODE_REPLAY) return BOOT_OK;
    return g_base->crypto->init();
}

static void shim_crypto_deinit(void) {
    if (g_mode == TAPE_MODE_REPLAY) return;
    g_base->crypto->deinit();
}

static boot_status_t shim_crypto_hash_init(void *ctx, size_t ctx_size) {
    return g_base->crypto->hash_init(ctx, ctx_size);
}

static boot_status_t shim_crypto_hash_update(void *ctx, const void *data, size_t len) {
    return g_base->crypto->hash_update(ctx, data, len);
}

static boot_status_t shim_crypto_hash_finish(void *ctx, uint8_t *digest, size_t *digest_len) {
    return g_base->crypto->hash_finish(ctx, digest, digest_len);
}

static boot_status_t shim_crypto_verify_ed25519(const uint8_t *message, size_t msg_len, const uint8_t *sig, const uint8_t *pubkey) {
    return g_base->crypto->verify_ed25519(message, msg_len, sig, pubkey);
}

static boot_status_t shim_crypto_verify_pqc(const uint8_t *message, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len) {
    return g_base->crypto->verify_pqc(message, msg_len, sig, sig_len, pubkey, pubkey_len);
}

static boot_status_t shim_crypto_random(uint8_t *buf, size_t len) {
    if (g_mode == TAPE_MODE_RECORD) {
        boot_status_t ret = g_base->crypto->random(buf, len);
        tape_hdr_t hdr = { .op = OP_CRYPTO_RANDOM, .arg1 = (uint32_t)len, .arg2 = 0, .ret_val = (uint32_t)ret };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        if (ret == BOOT_OK) {
            fwrite(buf, 1, len, g_tape_file);
        }
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        if (hdr.op != OP_CRYPTO_RANDOM || hdr.arg1 != len) {
            fprintf(stderr, "Tape mismatch: expected Random op=%d len=%d. Got op=%d len=%d\n",
                    OP_CRYPTO_RANDOM, (uint32_t)len, hdr.op, hdr.arg1);
            exit(1);
        }
        if (hdr.ret_val == BOOT_OK) {
            if (fread(buf, 1, len, g_tape_file) != len) return BOOT_ERR_STATE;
        }
        return (boot_status_t)hdr.ret_val;
    }
    return g_base->crypto->random(buf, len);
}

static uint32_t shim_crypto_get_last_vendor_error(void) {
    return g_base->crypto->get_last_vendor_error();
}

static boot_status_t shim_crypto_read_pubkey(uint8_t *key, size_t key_len, uint8_t key_index) {
    return g_base->crypto->read_pubkey(key, key_len, key_index);
}

static boot_status_t shim_crypto_read_chip_uid(uint8_t *buf, size_t max_len, size_t *out_len) {
    return g_base->crypto->read_chip_uid(buf, max_len, out_len);
}

static boot_status_t shim_crypto_read_dslc(uint8_t *buffer, size_t *len) {
    return g_base->crypto->read_dslc(buffer, len);
}

static boot_status_t shim_crypto_write_dslc(const uint8_t *value, size_t len) {
    return g_base->crypto->write_dslc(value, len);
}

static boot_status_t shim_crypto_read_monotonic_counter(uint32_t *ctr) {
    if (g_mode == TAPE_MODE_RECORD) {
        boot_status_t ret = g_base->crypto->read_monotonic_counter(ctr);
        tape_hdr_t hdr = { .op = OP_CRYPTO_MONOTONIC, .arg1 = 0, .arg2 = 0, .ret_val = (uint32_t)ret };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        if (ret == BOOT_OK) {
            fwrite(ctr, sizeof(uint32_t), 1, g_tape_file);
        }
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        if (hdr.op != OP_CRYPTO_MONOTONIC) {
            fprintf(stderr, "Tape mismatch: expected Monotonic Counter op=%d. Got op=%d\n",
                    OP_CRYPTO_MONOTONIC, hdr.op);
            exit(1);
        }
        if (hdr.ret_val == BOOT_OK) {
            if (fread(ctr, sizeof(uint32_t), 1, g_tape_file) != 1) return BOOT_ERR_STATE;
        }
        return (boot_status_t)hdr.ret_val;
    }
    return g_base->crypto->read_monotonic_counter(ctr);
}

static boot_status_t shim_crypto_advance_monotonic_counter(void) {
    return g_base->crypto->advance_monotonic_counter();
}

static size_t shim_crypto_get_hash_ctx_size(void) {
    return g_base->crypto->get_hash_ctx_size();
}

static bool shim_crypto_is_pqc_enforced(void) {
    return g_base->crypto->is_pqc_enforced();
}

/* --- Clock Intercepts --- */

static boot_status_t shim_clock_init(void) {
    if (g_mode == TAPE_MODE_REPLAY) return BOOT_OK;
    return g_base->clock->init();
}

static void shim_clock_deinit(void) {
    if (g_mode == TAPE_MODE_REPLAY) return;
    g_base->clock->deinit();
}

static uint32_t shim_clock_get_tick_ms(void) {
    if (g_mode == TAPE_MODE_RECORD) {
        uint32_t ret = g_base->clock->get_tick_ms();
        tape_hdr_t hdr = { .op = OP_CLOCK_TICK, .arg1 = ret, .arg2 = 0, .ret_val = 0 };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return 0;
        if (hdr.op != OP_CLOCK_TICK) {
            fprintf(stderr, "Tape mismatch: expected Clock Tick op=%d. Got op=%d\n",
                    OP_CLOCK_TICK, hdr.op);
            exit(1);
        }
        return hdr.arg1;
    }
    return g_base->clock->get_tick_ms();
}

static void shim_clock_delay_ms(uint32_t ms) {
    if (g_mode == TAPE_MODE_REPLAY) return;
    g_base->clock->delay_ms(ms);
}

static reset_reason_t shim_clock_get_reset_reason(void) {
    if (g_mode == TAPE_MODE_RECORD) {
        reset_reason_t ret = g_base->clock->get_reset_reason();
        tape_hdr_t hdr = { .op = OP_CLOCK_RESET_REASON, .arg1 = (uint32_t)ret, .arg2 = 0, .ret_val = 0 };
        fwrite(&hdr, sizeof(hdr), 1, g_tape_file);
        return ret;
    } else if (g_mode == TAPE_MODE_REPLAY) {
        tape_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, g_tape_file) != 1) return RESET_REASON_UNKNOWN;
        if (hdr.op != OP_CLOCK_RESET_REASON) {
            fprintf(stderr, "Tape mismatch: expected Reset Reason op=%d. Got op=%d\n",
                    OP_CLOCK_RESET_REASON, hdr.op);
            exit(1);
        }
        return (reset_reason_t)hdr.arg1;
    }
    return g_base->clock->get_reset_reason();
}

const boot_platform_t *hal_tape_init(const char *tape_path, hal_tape_mode_t mode, const boot_platform_t *base_platform) {
    g_mode = mode;
    g_base = base_platform;

    if (g_mode == TAPE_MODE_RECORD) {
        g_tape_file = fopen(tape_path, "wb");
    } else if (g_mode == TAPE_MODE_REPLAY) {
        g_tape_file = fopen(tape_path, "rb");
    }

    /* Shim structs popluieren */
    memcpy(&g_shim_flash, g_base->flash, sizeof(flash_hal_t));
    g_shim_flash.init = shim_flash_init;
    g_shim_flash.deinit = shim_flash_deinit;
    g_shim_flash.read = shim_flash_read;
    g_shim_flash.write = shim_flash_write;
    g_shim_flash.erase_sector = shim_flash_erase_sector;
    g_shim_flash.get_sector_size = shim_flash_get_sector_size;
    g_shim_flash.set_otfdec_mode = shim_flash_set_otfdec_mode;
    g_shim_flash.get_last_vendor_error = shim_flash_get_last_vendor_error;

    memcpy(&g_shim_crypto, g_base->crypto, sizeof(crypto_hal_t));
    g_shim_crypto.init = shim_crypto_init;
    g_shim_crypto.deinit = shim_crypto_deinit;
    g_shim_crypto.hash_init = shim_crypto_hash_init;
    g_shim_crypto.hash_update = shim_crypto_hash_update;
    g_shim_crypto.hash_finish = shim_crypto_hash_finish;
    g_shim_crypto.verify_ed25519 = shim_crypto_verify_ed25519;
    g_shim_crypto.verify_pqc = shim_crypto_verify_pqc;
    g_shim_crypto.random = shim_crypto_random;
    g_shim_crypto.get_last_vendor_error = shim_crypto_get_last_vendor_error;
    g_shim_crypto.read_pubkey = shim_crypto_read_pubkey;
    g_shim_crypto.read_chip_uid = shim_crypto_read_chip_uid;
    g_shim_crypto.read_dslc = shim_crypto_read_dslc;
    g_shim_crypto.write_dslc = shim_crypto_write_dslc;
    g_shim_crypto.read_monotonic_counter = shim_crypto_read_monotonic_counter;
    g_shim_crypto.advance_monotonic_counter = shim_crypto_advance_monotonic_counter;
    g_shim_crypto.get_hash_ctx_size = shim_crypto_get_hash_ctx_size;
    g_shim_crypto.is_pqc_enforced = shim_crypto_is_pqc_enforced;

    memcpy(&g_shim_clock, g_base->clock, sizeof(clock_hal_t));
    g_shim_clock.init = shim_clock_init;
    g_shim_clock.deinit = shim_clock_deinit;
    g_shim_clock.get_tick_ms = shim_clock_get_tick_ms;
    g_shim_clock.delay_ms = shim_clock_delay_ms;
    g_shim_clock.get_reset_reason = shim_clock_get_reset_reason;

    g_shim_platform.flash = &g_shim_flash;
    g_shim_platform.confirm = g_base->confirm;
    g_shim_platform.crypto = &g_shim_crypto;
    g_shim_platform.clock = &g_shim_clock;
    g_shim_platform.wdt = g_base->wdt;
    g_shim_platform.console = g_base->console;
    g_shim_platform.soc = g_base->soc;
    g_shim_platform.provisioning = g_base->provisioning;

    return &g_shim_platform;
}

void hal_tape_deinit(void) {
    if (g_tape_file) {
        fclose(g_tape_file);
        g_tape_file = NULL;
    }
    g_mode = TAPE_MODE_DISABLED;
}
