#include "fuzz_common.h"

#include "libtoob.h"
#include "recovery_port.h"
#include "sha256.h"
#include "toob_internal.h"

#include <stdio.h>

static const uint8_t *s_xm_rx = NULL;
static size_t s_xm_len = 0U;
static size_t s_xm_pos = 0U;
static uint32_t s_xm_tick_ms = 0U;
static uint32_t s_xm_eof_polls = 0U;

toob_status_t recovery_serial_init(void) {
    return TOOB_OK;
}

toob_status_t recovery_serial_getchar(uint8_t *out, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (out == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (s_xm_rx != NULL && s_xm_pos < s_xm_len) {
        *out = s_xm_rx[s_xm_pos++];
        return TOOB_OK;
    }
    s_xm_eof_polls++;
    if (s_xm_eof_polls > 70U && g_fuzz_trap_active != 0) {
        longjmp(g_fuzz_trap_jmp, 2);
    }
    return TOOB_ERR_TIMEOUT;
}

void recovery_serial_putchar(char c) {
    (void)c;
}

void recovery_serial_print(const char *str) {
    (void)str;
}

_Noreturn void recovery_system_reboot(void) {
    if (g_fuzz_trap_active != 0) {
        longjmp(g_fuzz_trap_jmp, 1);
    }
    abort();
}

uint32_t recovery_get_tick_ms(void) {
    s_xm_tick_ms += 250U;
    return s_xm_tick_ms;
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
    if (buf == NULL && len > 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (addr > (uint32_t)sizeof(g_fuzz_flash) || len > (uint32_t)sizeof(g_fuzz_flash) - addr) {
        return TOOB_ERR_FLASH;
    }
    if (len > 0U) {
        memcpy(buf, &g_fuzz_flash[addr], len);
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
    if (buf == NULL && len > 0U) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (toob_flash_range_hits_immutable_boot(addr, len)) {
        return TOOB_ERR_FLASH;
    }
    if (addr > (uint32_t)sizeof(g_fuzz_flash) || len > (uint32_t)sizeof(g_fuzz_flash) - addr) {
        return TOOB_ERR_FLASH;
    }
    for (uint32_t i = 0U; i < len; i++) {
        g_fuzz_flash[addr + i] &= buf[i];
    }
    return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
    if (toob_flash_range_hits_immutable_boot(addr, len)) {
        return TOOB_ERR_FLASH;
    }
    if (addr > (uint32_t)sizeof(g_fuzz_flash) || len > (uint32_t)sizeof(g_fuzz_flash) - addr) {
        return TOOB_ERR_FLASH;
    }
    if (len > 0U) {
        memset(&g_fuzz_flash[addr], 0xFF, len);
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
    if (ctx == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_init((SHA256_CTX *)(void *)ctx->opaque);
    return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len) {
    if (ctx == NULL || (data == NULL && len > 0U)) {
        return TOOB_ERR_INVALID_ARG;
    }
    if (len > 0U) {
        sha256_update((SHA256_CTX *)(void *)ctx->opaque, data, len);
    }
    return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32]) {
    if (ctx == NULL || out_hash == NULL) {
        return TOOB_ERR_INVALID_ARG;
    }
    sha256_final((SHA256_CTX *)(void *)ctx->opaque, out_hash);
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

#undef TOOB_TRAP
#define TOOB_TRAP() recovery_system_reboot()

#include "../../recovery/main.c"

extern void toob_mailbox_session_reset_for_test(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x584D444DU ^ (uint64_t)size);
    toob_mailbox_session_reset_for_test();
    memset(&g_toob_ota_resume_state, 0, sizeof(g_toob_ota_resume_state));

    /* Prepare valid Recovery OS handoff so recovery_main() enters XMODEM sync/rx loop. */
    memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
    toob_handoff_state.magic = TOOB_STATE_COMMITTED;
    toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
    toob_handoff_state.boot_nonce = 0xCAFEBABE12345678ULL;
    toob_handoff_state.booted_partition = TOOB_PARTITION_RECOVERY;
    toob_handoff_state.active_slot = 0U;
    toob_handoff_state.crc32_trailer = toob_lib_crc32(
        (const uint8_t *)(const void *)&toob_handoff_state,
        offsetof(toob_handoff_t, crc32_trailer));

    s_xm_rx = data;
    s_xm_len = size;
    s_xm_pos = 0U;
    s_xm_tick_ms = 0U;
    s_xm_eof_polls = 0U;

    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        (void)recovery_main();
    }
    g_fuzz_trap_active = 0;

    s_xm_rx = NULL;
    s_xm_len = 0U;
    s_xm_pos = 0U;
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("xmodem")
