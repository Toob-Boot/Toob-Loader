#ifndef TOOB_FUZZ_COMMON_H
#define TOOB_FUZZ_COMMON_H

#if defined(_WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
#  define _CRT_SECURE_NO_WARNINGS 1
#endif

#include "boot_hal.h"
#include "boot_types.h"
#include "generated_boot_config.h"

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FUZZ_MAX_INPUT_BYTES (128U * 1024U)
#define FUZZ_DEFAULT_ITERS   1024U

extern uint8_t g_fuzz_flash[CHIP_FLASH_TOTAL_SIZE];
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

extern jmp_buf g_fuzz_trap_jmp;
extern volatile int g_fuzz_trap_active;
extern volatile int g_fuzz_uart_eof_longjmp;

extern uint8_t g_fuzz_root_sk[64];
extern uint8_t g_fuzz_root_pk[32];
extern uint8_t g_fuzz_cloud_sk[64];
extern uint8_t g_fuzz_cloud_pk[32];

void fuzz_platform_reset(uint64_t rng_seed);
const boot_platform_t *fuzz_platform_get(void);

void fuzz_flash_write_raw(uint32_t addr, const uint8_t *src, size_t len);
void fuzz_flash_fill_erased(uint32_t addr, size_t len);
void fuzz_flash_set_enforce_nor(bool enforce);

void fuzz_keystore_set_dslc(uint8_t dslc_val);
void fuzz_keystore_set_monotonic(uint32_t ctr);
uint32_t fuzz_keystore_get_monotonic(void);
void fuzz_keystore_set_key(uint8_t slot, const uint8_t *pk, bool valid);
void fuzz_keystore_set_pqc_hash(uint8_t slot, const uint8_t hash[32], bool valid);
void fuzz_clock_set_reset_reason(reset_reason_t reason);

void fuzz_uart_set_rx(const uint8_t *data, size_t len, bool eof_longjmp);
void fuzz_uart_reset_tx(void);
size_t fuzz_uart_rx_remaining(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#ifdef TOOB_FUZZ_STANDALONE

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <dirent.h>
#  include <sys/stat.h>
#endif

#define FUZZ_MAX_SEEDS     96U
#define FUZZ_MAX_SEED_SIZE (32U * 1024U)
#define FUZZ_MAX_PATH      512U

typedef struct {
    size_t len;
    uint8_t data[FUZZ_MAX_SEED_SIZE];
} fuzz_seed_slot_t;

static fuzz_seed_slot_t g_fuzz_seeds[FUZZ_MAX_SEEDS];
static size_t g_fuzz_seed_count = 0U;
static uint8_t g_fuzz_mut_buf[FUZZ_MAX_SEED_SIZE];

static uint64_t fuzz_xorshift64(uint64_t *state) {
    uint64_t x = *state;
    if (x == 0ULL) {
        x = 0x9E3779B97F4A7C15ULL;
    }
    x ^= x >> 12U;
    x ^= x << 25U;
    x ^= x >> 27U;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static int fuzz_load_one_seed(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (g_fuzz_seed_count >= FUZZ_MAX_SEEDS) {
        (void)fclose(fp);
        return 0;
    }
    size_t n = fread(g_fuzz_seeds[g_fuzz_seed_count].data, 1U, FUZZ_MAX_SEED_SIZE, fp);
    (void)fclose(fp);
    g_fuzz_seeds[g_fuzz_seed_count].len = n;
    g_fuzz_seed_count++;
    return 0;
}

static void fuzz_load_corpus_dir(const char *dir_path) {
    char pattern[FUZZ_MAX_PATH];
#if defined(_WIN32)
    int plen = snprintf(pattern, sizeof(pattern), "%s\\*", dir_path);
    if (plen <= 0 || (size_t)plen >= sizeof(pattern)) {
        return;
    }
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
            continue;
        }
        char full[FUZZ_MAX_PATH];
        int flen = snprintf(full, sizeof(full), "%s\\%s", dir_path, ffd.cFileName);
        if (flen > 0 && (size_t)flen < sizeof(full)) {
            (void)fuzz_load_one_seed(full);
        }
    } while (FindNextFileA(hFind, &ffd) != 0 && g_fuzz_seed_count < FUZZ_MAX_SEEDS);
    (void)FindClose(hFind);
#else
    (void)pattern;
    DIR *dp = opendir(dir_path);
    if (dp == NULL) {
        return;
    }
    struct dirent *ent = NULL;
    while ((ent = readdir(dp)) != NULL && g_fuzz_seed_count < FUZZ_MAX_SEEDS) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char full[FUZZ_MAX_PATH];
        int flen = snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);
        if (flen > 0 && (size_t)flen < sizeof(full)) {
            struct stat st;
            if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
                (void)fuzz_load_one_seed(full);
            }
        }
    }
    (void)closedir(dp);
#endif
}

static size_t fuzz_mutate_buffer(uint8_t *buf, size_t seed_len, uint32_t iter, uint64_t *rng) {
    static const uint32_t interesting_u32[8] = {
        0x00000000U, 0x00000001U, 0x00000100U, 0x0000FFFFU,
        0x7FFFFFFFU, 0x80000000U, 0xFFFFFFFEU, 0xFFFFFFFFU
    };
    size_t len = (seed_len > 0U) ? seed_len : 64U;
    if (len > FUZZ_MAX_SEED_SIZE) {
        len = FUZZ_MAX_SEED_SIZE;
    }
    if (seed_len == 0U) {
        for (size_t i = 0U; i < len; i++) {
            buf[i] = (uint8_t)fuzz_xorshift64(rng);
        }
    }

    uint32_t mode = iter % 6U;
    if (mode == 0U && len > 0U) {
        size_t flips = 1U + (size_t)(fuzz_xorshift64(rng) % 4U);
        for (size_t f = 0U; f < flips; f++) {
            size_t pos = (size_t)(fuzz_xorshift64(rng) % len);
            uint8_t bit = (uint8_t)(1U << (fuzz_xorshift64(rng) % 8U));
            buf[pos] ^= bit;
        }
    } else if (mode == 1U && len >= 4U) {
        size_t pos = (size_t)(fuzz_xorshift64(rng) % (len - 3U));
        uint32_t val = interesting_u32[fuzz_xorshift64(rng) % 8U];
        memcpy(&buf[pos], &val, sizeof(val));
    } else if (mode == 2U) {
        size_t new_len = (size_t)(fuzz_xorshift64(rng) % (len + 1U));
        if (new_len == 0U && (iter & 1U) != 0U) {
            new_len = 1U;
        }
        len = new_len;
    } else if (mode == 3U) {
        size_t extra = 1U + (size_t)(fuzz_xorshift64(rng) % 256U);
        if (len + extra > FUZZ_MAX_SEED_SIZE) {
            extra = FUZZ_MAX_SEED_SIZE - len;
        }
        uint8_t fill = (uint8_t)((iter & 2U) != 0U ? 0xFFU : 0x00U);
        for (size_t i = 0U; i < extra; i++) {
            buf[len + i] = ((iter & 4U) != 0U) ? (uint8_t)fuzz_xorshift64(rng) : fill;
        }
        len += extra;
    } else if (mode == 4U && g_fuzz_seed_count > 1U && len > 8U) {
        size_t other_idx = (size_t)(fuzz_xorshift64(rng) % g_fuzz_seed_count);
        const fuzz_seed_slot_t *other = &g_fuzz_seeds[other_idx];
        if (other->len > 8U) {
            size_t cut = (size_t)(fuzz_xorshift64(rng) % len);
            size_t copy_len = (other->len < len - cut) ? other->len : (len - cut);
            memcpy(&buf[cut], other->data, copy_len);
        }
    } else if (len > 0U) {
        size_t span = 1U + (size_t)(fuzz_xorshift64(rng) % ((len < 32U) ? len : 32U));
        size_t start = (size_t)(fuzz_xorshift64(rng) % len);
        if (start + span > len) {
            span = len - start;
        }
        for (size_t i = 0U; i < span; i++) {
            buf[start + i] = (uint8_t)fuzz_xorshift64(rng);
        }
    }

    return len;
}

static int fuzz_standalone_main(const char *target_name, int argc, char **argv) {
    char default_dir_repo[FUZZ_MAX_PATH];
    char default_dir_local[FUZZ_MAX_PATH];
    uint32_t iters = FUZZ_DEFAULT_ITERS;
    const char *corpus_dir = getenv("TOOB_FUZZ_CORPUS_DIR");

    const char *iters_env = getenv("TOOB_FUZZ_ITERS");
    if (iters_env != NULL && iters_env[0] != '\0') {
        unsigned long parsed = strtoul(iters_env, NULL, 10);
        if (parsed > 0UL) {
            iters = (uint32_t)parsed;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--iters=", 8U) == 0) {
            unsigned long parsed = strtoul(argv[i] + 8, NULL, 10);
            if (parsed > 0UL) {
                iters = (uint32_t)parsed;
            }
        } else if (argv[i][0] != '-') {
            corpus_dir = argv[i];
        }
    }

    if (corpus_dir != NULL) {
        fuzz_load_corpus_dir(corpus_dir);
    } else {
        (void)snprintf(default_dir_repo, sizeof(default_dir_repo), "test/fuzz/corpus/%s", target_name);
        fuzz_load_corpus_dir(default_dir_repo);
        if (g_fuzz_seed_count == 0U) {
            (void)snprintf(default_dir_local, sizeof(default_dir_local), "corpus/%s", target_name);
            fuzz_load_corpus_dir(default_dir_local);
        }
    }

    if (g_fuzz_seed_count == 0U) {
        fprintf(stderr, "FAIL: No corpus seeds loaded for target '%s'\n", target_name);
        return 1;
    }

    /* 1. Replay every seed file verbatim. */
    for (size_t s = 0U; s < g_fuzz_seed_count; s++) {
        (void)LLVMFuzzerTestOneInput(g_fuzz_seeds[s].data, g_fuzz_seeds[s].len);
    }

    /* 2. Degenerate boundary vectors. */
    static const uint8_t edge_bytes[5] = { 0x00U, 0x01U, 0x04U, 0x18U, 0xFFU };
    (void)LLVMFuzzerTestOneInput(edge_bytes, 0U);
    for (size_t e = 0U; e < sizeof(edge_bytes); e++) {
        (void)LLVMFuzzerTestOneInput(&edge_bytes[e], 1U);
    }

    /* 3. Deterministic structured mutations. */
    uint64_t rng = 0x544F4F4246555A5AULL ^ (uint64_t)g_fuzz_seed_count;
    for (uint32_t i = 0U; i < iters; i++) {
        size_t s_idx = (size_t)(i % g_fuzz_seed_count);
        size_t slen = g_fuzz_seeds[s_idx].len;
        if (slen > FUZZ_MAX_SEED_SIZE) {
            slen = FUZZ_MAX_SEED_SIZE;
        }
        if (slen > 0U) {
            memcpy(g_fuzz_mut_buf, g_fuzz_seeds[s_idx].data, slen);
        }
        size_t mlen = fuzz_mutate_buffer(g_fuzz_mut_buf, slen, i, &rng);
        (void)LLVMFuzzerTestOneInput(g_fuzz_mut_buf, mlen);
    }

    printf("FUZZ_SUMMARY target=%s seeds=%zu mutations=%u total_execs=%zu status=PASS\n",
           target_name, g_fuzz_seed_count, (unsigned)iters,
           g_fuzz_seed_count + 6U + (size_t)iters);
    return 0;
}

#define TOOB_FUZZ_DEFINE_MAIN(target_name_str) \
    int main(int argc, char **argv) { \
        return fuzz_standalone_main((target_name_str), argc, argv); \
    }

#else /* !TOOB_FUZZ_STANDALONE */

#define TOOB_FUZZ_DEFINE_MAIN(target_name_str)

#endif /* TOOB_FUZZ_STANDALONE */

#endif /* TOOB_FUZZ_COMMON_H */
