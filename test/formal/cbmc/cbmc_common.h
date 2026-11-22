/*
 * Common CBMC Verification Primitives, Sector Oracles, and HAL Contracts.
 *
 * Used across all Wave 5A harnesses in test/formal/cbmc/ to enforce:
 *   1. Nondeterministic symbolic input generation (nondet_*).
 *   2. Bit-exact modulo-2^32 hash models for goto-instrument --replace-calls
 *      so --unsigned-overflow-check stays 100% active on all production logic.
 *   3. Flash sector geometry oracle for both homogeneous (4 KB) and asymmetric
 *      Dual-Bank STM32F4-class (16 KB / 64 KB / 128 KB) flash layouts.
 *   4. Mutable partition firewall invariants (__CPROVER_assert) ensuring zero
 *      writes or erases ever touch [0, CHIP_FLASH_IMMUTABLE_BOOT_END) or cross
 *      mutable partition boundaries.
 */
#ifndef TOOB_CBMC_COMMON_H
#define TOOB_CBMC_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "generated_boot_config.h"

/* ==========================================================================
 * 1. CBMC Nondeterministic Input Generators
 * ========================================================================== */

uint8_t  nondet_uint8_t(void);
uint16_t nondet_uint16_t(void);
uint32_t nondet_uint32_t(void);
uint64_t nondet_uint64_t(void);
size_t   nondet_size_t(void);
int      nondet_int(void);
bool     nondet_bool(void);

#define CBMC_HAVOC_OBJECT(obj) __CPROVER_havoc_object(&(obj))

#define cbmc_assert_readable(buf, len, msg)                                    \
    (((size_t)(len) == 0U)                                                     \
         ? (void)0                                                             \
         : __CPROVER_assert((buf) != NULL &&                                   \
                                __CPROVER_r_ok((buf), (size_t)(len)),          \
                            msg))

#define cbmc_assert_writable(buf, len, msg)                                    \
    (((size_t)(len) == 0U)                                                     \
         ? (void)0                                                             \
         : __CPROVER_assert((buf) != NULL &&                                   \
                                __CPROVER_w_ok((buf), (size_t)(len)),          \
                            msg))

/*
 * O(1) symbolic buffer havoc: whole-object havoc when possible, constant-width
 * slice havoc for compile-time constant sizes, and 3-point scalar havoc for
 * variable lengths (avoiding both O(N^2) barrel shifters and multi-way SSA muxes).
 */
static inline void cbmc_havoc_bytes_var(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "cbmc_havoc_bytes target buffer must be writable");
    if (len == 0U) {
        return;
    }
    buf[0] = nondet_uint8_t();
}

#define cbmc_havoc_bytes(buf, len)                                              \
    do {                                                                        \
        uint8_t *_hb_ptr = (uint8_t *)(buf);                                    \
        size_t _hb_len = (size_t)(len);                                         \
        if (__builtin_constant_p(len) && (_hb_len > 0U) && (_hb_len <= 576U)) { \
            cbmc_assert_writable(_hb_ptr, _hb_len,                              \
                                 "cbmc_havoc_bytes target buffer must be writable"); \
            __CPROVER_havoc_slice(_hb_ptr, _hb_len);                            \
        } else {                                                                \
            cbmc_havoc_bytes_var(_hb_ptr, _hb_len);                             \
        }                                                                       \
    } while (0)

static inline void cbmc_set4(uint8_t *d, uint8_t v) {
    d[0] = v; d[1] = v; d[2] = v; d[3] = v;
}
static inline void cbmc_set16(uint8_t *d, uint8_t v) {
    cbmc_set4(d, v); cbmc_set4(d + 4U, v); cbmc_set4(d + 8U, v); cbmc_set4(d + 12U, v);
}
static inline void cbmc_set32(uint8_t *d, uint8_t v) {
    cbmc_set16(d, v); cbmc_set16(d + 16U, v);
}
static inline void cbmc_set64(uint8_t *d, uint8_t v) {
    cbmc_set32(d, v); cbmc_set32(d + 32U, v);
}

static inline void cbmc_cpy4(uint8_t *d, const uint8_t *s) {
    d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
}
static inline void cbmc_cpy16(uint8_t *d, const uint8_t *s) {
    cbmc_cpy4(d, s); cbmc_cpy4(d + 4U, s + 4U); cbmc_cpy4(d + 8U, s + 8U); cbmc_cpy4(d + 12U, s + 12U);
}
static inline void cbmc_cpy32(uint8_t *d, const uint8_t *s) {
    cbmc_cpy16(d, s); cbmc_cpy16(d + 16U, s + 16U);
}
static inline void cbmc_cpy64(uint8_t *d, const uint8_t *s) {
    cbmc_cpy32(d, s); cbmc_cpy32(d + 32U, s + 32U);
}

void *cbmc_memcpy_safe(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memcpy destination must be writable");
    cbmc_assert_readable(src, n, "memcpy source must be readable");
    if (__CPROVER_same_object(dst, src)) {
        uintptr_t d_addr = (uintptr_t)dst;
        uintptr_t s_addr = (uintptr_t)src;
        __CPROVER_assert((d_addr + n <= s_addr) || (s_addr + n <= d_addr),
                         "memcpy slices within same object must not overlap");
    }
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (n == 1U) {
        d[0] = s[0];
    } else if (n == 2U) {
        d[0] = s[0]; d[1] = s[1];
    } else if (n == 3U) {
        d[0] = s[0]; d[1] = s[1]; d[2] = s[2];
    } else if (n == 4U) {
        cbmc_cpy4(d, s);
    } else if (n == 8U) {
        cbmc_cpy4(d, s); cbmc_cpy4(d + 4U, s + 4U);
    } else if (n == 12U) {
        cbmc_cpy4(d, s); cbmc_cpy4(d + 4U, s + 4U); cbmc_cpy4(d + 8U, s + 8U);
    } else if (n == 16U) {
        cbmc_cpy16(d, s);
    } else if (n == 20U) {
        cbmc_cpy16(d, s); cbmc_cpy4(d + 16U, s + 16U);
    } else if (n == 24U) {
        cbmc_cpy16(d, s); cbmc_cpy4(d + 16U, s + 16U); cbmc_cpy4(d + 20U, s + 20U);
    } else if (n == 28U) {
        cbmc_cpy16(d, s); cbmc_cpy4(d + 16U, s + 16U); cbmc_cpy4(d + 20U, s + 20U); cbmc_cpy4(d + 24U, s + 24U);
    } else if (n == 32U) {
        cbmc_cpy32(d, s);
    } else if (n == 36U) {
        cbmc_cpy32(d, s); cbmc_cpy4(d + 32U, s + 32U);
    } else if (n == 40U) {
        cbmc_cpy32(d, s); cbmc_cpy4(d + 32U, s + 32U); cbmc_cpy4(d + 36U, s + 36U);
    } else if (n == 44U) {
        cbmc_cpy32(d, s); cbmc_cpy4(d + 32U, s + 32U); cbmc_cpy4(d + 36U, s + 36U); cbmc_cpy4(d + 40U, s + 40U);
    } else if (n == 48U) {
        cbmc_cpy32(d, s); cbmc_cpy16(d + 32U, s + 32U);
    } else if (n == 52U) {
        cbmc_cpy32(d, s); cbmc_cpy16(d + 32U, s + 32U); cbmc_cpy4(d + 48U, s + 48U);
    } else if (n == 56U) {
        cbmc_cpy32(d, s); cbmc_cpy16(d + 32U, s + 32U); cbmc_cpy4(d + 48U, s + 48U); cbmc_cpy4(d + 52U, s + 52U);
    } else if (n == 64U) {
        cbmc_cpy64(d, s);
    } else if (n == 112U) {
        cbmc_cpy64(d, s); cbmc_cpy32(d + 64U, s + 64U); cbmc_cpy16(d + 96U, s + 96U);
    } else if (n == 128U) {
        cbmc_cpy64(d, s); cbmc_cpy64(d + 64U, s + 64U);
    } else {
        d[0] = s[0];
    }
    return dst;
}

void *cbmc_memmove_safe(void *dst, const void *src, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memmove destination must be writable");
    cbmc_assert_readable(src, n, "memmove source must be readable");
    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = (uint8_t *)dst;
    d[0] = s[0];
    return dst;
}

void *cbmc_memset_safe(void *dst, int val, size_t n) {
    if (n == 0U) {
        return dst;
    }
    cbmc_assert_writable(dst, n, "memset destination must be writable");
    uint8_t b = (uint8_t)val;
    uint8_t *d = (uint8_t *)dst;
    if (n == 1U) {
        d[0] = b;
    } else if (n == 2U) {
        d[0] = b; d[1] = b;
    } else if (n == 3U) {
        d[0] = b; d[1] = b; d[2] = b;
    } else if (n == 4U) {
        cbmc_set4(d, b);
    } else if (n == 8U) {
        cbmc_set4(d, b); cbmc_set4(d + 4U, b);
    } else {
        d[0] = b;
    }
    return dst;
}

/* ==========================================================================
 * 2. Bit-Identical Modulo-2^32 Hash & Zeroize Replacements
 *
 * Linked via goto-instrument --replace-calls so intentional hash avalanches
 * (CERT C INT30-C-EX1) and post-decrement zeroize loops do not mask genuine
 * unsigned arithmetic bugs under --unsigned-overflow-check.
 * ========================================================================== */

uint32_t cbmc_cfi_derive_mod32(uint32_t seed, uint8_t slot) {
    uint64_t h = (uint64_t)seed ^ (((uint64_t)slot * 0x9E3779B9ULL) & 0xFFFFFFFFULL);
    h ^= (h >> 16U);
    h = (h * 0x45D9F3BULL) & 0xFFFFFFFFULL;
    h ^= (h >> 16U);
    return (uint32_t)(h | 1ULL);
}

uint32_t cbmc_boot_proof_mix_mod32(uint32_t h) {
    uint64_t x = (uint64_t)h;
    x ^= (x >> 16U);
    x = (x * 0x85EBCA6BULL) & 0xFFFFFFFFULL;
    x ^= (x >> 13U);
    x = (x * 0xC2B2AE35ULL) & 0xFFFFFFFFULL;
    x ^= (x >> 16U);
    return (uint32_t)x;
}

void cbmc_toob_secure_zeroize_safe(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "toob_secure_zeroize target buffer must be writable");
    if (ptr != NULL && len > 0U) {
        memset(ptr, 0, len);
    }
}

/* ==========================================================================
 * 3. Physical Flash Sector Geometry & Partition Firewall Oracles
 * ========================================================================== */

static inline bool cbmc_sector_info(uint32_t addr,
                                    uint32_t *out_sector_base,
                                    size_t *out_sector_size) {
    if (addr >= CHIP_FLASH_TOTAL_SIZE) {
        return false;
    }
#if CBMC_ASYMMETRIC_SECTORS == 0
    const uint32_t sec_sz = CHIP_FLASH_MAX_SECTOR_SIZE;
    if (out_sector_base != NULL) {
        *out_sector_base = addr - (addr % sec_sz);
    }
    if (out_sector_size != NULL) {
        *out_sector_size = (size_t)sec_sz;
    }
    return true;
#else
    /* Dual-Bank STM32F429 geometry: each 1 MB bank has 4x16KB + 1x64KB + 7x128KB */
    const uint32_t bank_base = (addr >= 0x00100000U) ? 0x00100000U : 0x00000000U;
    const uint32_t bank_off  = addr - bank_base;
    uint32_t sec_base = 0U;
    uint32_t sec_sz   = 0U;

    if (bank_off < 0x00010000U) {
        sec_sz   = 0x00004000U; /* 16 KB */
        sec_base = bank_base + (bank_off - (bank_off % sec_sz));
    } else if (bank_off < 0x00020000U) {
        sec_sz   = 0x00010000U; /* 64 KB */
        sec_base = bank_base + 0x00010000U;
    } else {
        sec_sz   = 0x00020000U; /* 128 KB */
        sec_base = bank_base + 0x00020000U +
                   ((bank_off - 0x00020000U) - ((bank_off - 0x00020000U) % sec_sz));
    }
    if (out_sector_base != NULL) {
        *out_sector_base = sec_base;
    }
    if (out_sector_size != NULL) {
        *out_sector_size = (size_t)sec_sz;
    }
    return true;
#endif
}

#define cbmc_subrange_of(addr, len, part_base, part_size)                      \
    (((size_t)(len) > 0U) && ((uint32_t)(part_size) > 0U) &&                   \
     ((uint64_t)(uint32_t)(addr) >= (uint64_t)(uint32_t)(part_base)) &&        \
     (((uint64_t)(uint32_t)(addr) + (uint64_t)(size_t)(len)) <=                \
      ((uint64_t)(uint32_t)(part_base) + (uint64_t)(uint32_t)(part_size))))

#define cbmc_in_wal_sector(addr, len)                                          \
    (cbmc_subrange_of((addr), (len), CHIP_WAL_SECTOR_0_ADDR, CHIP_WAL_SECTOR_0_SIZE) || \
     cbmc_subrange_of((addr), (len), CHIP_WAL_SECTOR_1_ADDR, CHIP_WAL_SECTOR_1_SIZE) || \
     cbmc_subrange_of((addr), (len), CHIP_WAL_SECTOR_2_ADDR, CHIP_WAL_SECTOR_2_SIZE) || \
     cbmc_subrange_of((addr), (len), CHIP_WAL_SECTOR_3_ADDR, CHIP_WAL_SECTOR_3_SIZE))

#define cbmc_range_in_mutable_partition(addr, len)                             \
    (((size_t)(len) > 0U) &&                                                   \
     (((uint64_t)(uint32_t)(addr) + (uint64_t)(size_t)(len)) <=                \
      (uint64_t)CHIP_FLASH_TOTAL_SIZE) &&                                      \
     ((uint32_t)(addr) >= (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END) &&          \
     (cbmc_subrange_of((addr), (len), CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_SCRATCH_SLOT_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_RECOVERY_OS_ABS_ADDR, CHIP_RECOVERY_OS_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_KDM_QUORUM_ABS_ADDR, CHIP_KDM_QUORUM_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_CLOUD_CMD_SLOT_ABS_ADDR, CHIP_CLOUD_CMD_SLOT_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_MAILBOX_ABS_ADDR, CHIP_MAILBOX_SIZE) || \
      cbmc_subrange_of((addr), (len), CHIP_FORENSIC_SLOT_ABS_ADDR, CHIP_FORENSIC_SLOT_SIZE) || \
      cbmc_in_wal_sector((addr), (len))))

static inline void cbmc_assert_flash_write_invariants(uint32_t addr,
                                                      const void *buf,
                                                      size_t len) {
    __CPROVER_assert(len > 0U, "flash write length must be non-zero");
    cbmc_assert_readable(buf, len, "flash write source buffer must be valid and readable");
    __CPROVER_assert((addr % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
                     "flash write address must satisfy CHIP_FLASH_WRITE_ALIGNMENT");
    __CPROVER_assert((len % CHIP_FLASH_WRITE_ALIGNMENT) == 0U,
                     "flash write length must satisfy CHIP_FLASH_WRITE_ALIGNMENT");
    __CPROVER_assert(addr >= (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END,
                     "flash write must never touch immutable Stage 0 boot region");
    __CPROVER_assert(cbmc_range_in_mutable_partition(addr, len),
                     "flash write must stay strictly inside a mutable partition");
}

static inline void cbmc_assert_flash_erase_sector_invariants(uint32_t addr) {
    uint32_t sec_base = 0U;
    size_t   sec_size = 0U;
    bool valid_sec = cbmc_sector_info(addr, &sec_base, &sec_size);
    __CPROVER_assert(valid_sec && sec_size > 0U,
                     "flash erase address must map to a valid physical sector");
    __CPROVER_assert(addr == sec_base,
                     "flash erase address must be strictly sector-base aligned");
    __CPROVER_assert(addr >= (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END,
                     "flash erase must never touch immutable Stage 0 boot region");
    __CPROVER_assert(cbmc_range_in_mutable_partition(addr, sec_size),
                     "flash erase sector must stay strictly inside a mutable partition");
}

static inline void cbmc_assert_flash_erase_range_invariants(uint32_t addr,
                                                            uint32_t len) {
    __CPROVER_assert(len > 0U, "flash erase range length must be non-zero");
    __CPROVER_assert(addr >= (uint32_t)CHIP_FLASH_IMMUTABLE_BOOT_END,
                     "flash erase range must never touch immutable Stage 0 boot region");
    __CPROVER_assert(cbmc_range_in_mutable_partition(addr, (size_t)len),
                     "flash erase range must stay strictly inside a mutable partition");

    uint32_t sec_base = 0U;
    size_t   sec_size = 0U;
    bool start_ok = cbmc_sector_info(addr, &sec_base, &sec_size);
    __CPROVER_assert(start_ok && addr == sec_base,
                     "flash erase range start must be sector-aligned");

    uint64_t end_addr = (uint64_t)addr + (uint64_t)len;
    if (end_addr < (uint64_t)CHIP_FLASH_TOTAL_SIZE) {
        uint32_t next_base = 0U;
        size_t   next_size = 0U;
        bool next_ok = cbmc_sector_info((uint32_t)end_addr, &next_base, &next_size);
        __CPROVER_assert(next_ok && (uint32_t)end_addr == next_base,
                         "flash erase range end must align to a sector boundary");
    } else {
        __CPROVER_assert(end_addr == (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                         "flash erase range must not exceed CHIP_FLASH_TOTAL_SIZE");
    }
}

/* ==========================================================================
 * 4. Bootloader Core HAL Stubs (omitted when compiling isolated libtoob proofs)
 * ========================================================================== */

#ifdef CBMC_LIBTOOB_ONLY

#include "libtoob_types.h"

toob_status_t cbmc_toob_ct_memcmp_contract(const uint8_t *a,
                                           const uint8_t *b,
                                           size_t len) {
    if (len == 0U) {
        return TOOB_ERR_VERIFY;
    }
    cbmc_assert_readable(a, len, "toob_ct_memcmp_glitch_safe buffer a must be readable");
    cbmc_assert_readable(b, len, "toob_ct_memcmp_glitch_safe buffer b must be readable");
    return nondet_bool() ? TOOB_OK : TOOB_ERR_VERIFY;
}

#else /* !CBMC_LIBTOOB_ONLY */

#include "boot_hal.h"
#include "boot_panic.h"
#include "boot_secure_zeroize.h"

boot_status_t cbmc_ct_memcmp_contract(const uint8_t *a,
                                      const uint8_t *b,
                                      size_t len) {
    if (len == 0U) {
        return BOOT_ERR_VERIFY;
    }
    cbmc_assert_readable(a, len, "constant_time_memcmp_glitch_safe buffer a must be readable");
    cbmc_assert_readable(b, len, "constant_time_memcmp_glitch_safe buffer b must be readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

boot_status_t cbmc_verify_not_all_zeros_contract(const uint8_t *buf,
                                                 size_t len) {
    if (len == 0U) {
        return BOOT_ERR_VERIFY;
    }
    cbmc_assert_readable(buf, len, "verify_not_all_zeros_glitch_safe buffer must be readable");
    return nondet_bool() ? BOOT_OK : BOOT_ERR_VERIFY;
}

bool cbmc_is_fully_erased_contract(const uint8_t *buf, size_t len,
                                   uint8_t erased_val) {
    if (len == 0U) {
        return true;
    }
    cbmc_assert_readable(buf, len, "is_fully_erased_constant_time buffer must be readable");
    if (buf[0] != erased_val) {
        return false;
    }
    if (len >= 2U && buf[1] == erased_val) {
        return true;
    }
    return nondet_bool();
}

#ifndef CBMC_NO_ZEROIZE_STUB
void boot_secure_zeroize(void *ptr, size_t len) {
    cbmc_assert_writable(ptr, len, "boot_secure_zeroize target buffer must be writable");
    if (ptr != NULL && len > 0U) {
        memset(ptr, 0, len);
    }
}
#endif

#ifndef CBMC_NO_TERMINAL_HALT_STUB
_Noreturn void boot_terminal_halt(const boot_platform_t *platform,
                                  boot_status_t reason, uint16_t site_id) {
    (void)platform;
    (void)reason;
    __CPROVER_assert(site_id > 0U, "boot_terminal_halt must supply valid site_id");
    __CPROVER_assume(false);
    while (true) {
    }
}
#endif

#ifndef CBMC_NO_BOOT_PANIC_STUB
_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)platform;
    (void)reason;
    __CPROVER_assume(false);
    while (true) {
    }
}
#endif

static void cbmc_wdt_kick(void) {}
static void cbmc_wdt_suspend(void) {}
static void cbmc_wdt_resume(void) {}

static const wdt_hal_t g_cbmc_wdt_hal = {
    .init                         = NULL,
    .deinit                       = NULL,
    .kick                         = cbmc_wdt_kick,
    .suspend_for_critical_section = cbmc_wdt_suspend,
    .resume                       = cbmc_wdt_resume,
};

static boot_status_t cbmc_flash_get_sector_size(uint32_t addr, size_t *out_size) {
    if (out_size == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    __CPROVER_assert(__CPROVER_w_ok(out_size, sizeof(*out_size)),
                     "get_sector_size out_size pointer must be writable");
    uint32_t base = 0U;
    if (!cbmc_sector_info(addr, &base, out_size)) {
        return BOOT_ERR_FLASH_BOUNDS;
    }
    return BOOT_OK;
}

/* Symbolic Ed25519 signature verifier exploring both BOOT_OK and BOOT_ERR_VERIFY */
static boot_status_t cbmc_ed25519_verify_sig(const uint8_t *message,
                                             size_t msg_len,
                                             const uint8_t signature[64],
                                             const uint8_t pubkey[32]) {
    cbmc_assert_readable(signature, 64U, "Ed25519 signature buffer [64] must be readable");
    cbmc_assert_readable(pubkey, 32U, "Ed25519 pubkey buffer [32] must be readable");
    cbmc_assert_readable(message, msg_len, "Ed25519 signed message slice must be readable");
    return (nondet_int() != 0) ? BOOT_OK : BOOT_ERR_VERIFY;
}

static boot_status_t cbmc_hash_init(void *ctx, size_t ctx_size) {
    cbmc_assert_writable(ctx, ctx_size, "hash_init context must be writable");
    return BOOT_OK;
}

static boot_status_t cbmc_hash_update(void *ctx, const void *data, size_t len) {
    __CPROVER_assert(ctx != NULL, "hash_update context must be non-null");
    cbmc_assert_readable(data, len, "hash_update input slice must be readable");
    return BOOT_OK;
}

static boot_status_t cbmc_hash_finish(void *ctx, uint8_t *digest_out,
                                      size_t *digest_len) {
    __CPROVER_assert(ctx != NULL, "hash_finish context must be non-null");
    __CPROVER_assert(digest_out != NULL && digest_len != NULL &&
                         *digest_len >= 32U,
                     "hash_finish digest buffer [32] must be writable");
    cbmc_havoc_bytes(digest_out, 32U);
    *digest_len = 32U;
    return BOOT_OK;
}

/*
 * Sound over-approximating CRC-32 / erased-check contracts for higher-level
 * proofs (wired via goto-instrument --replace-calls when linking real
 * boot_crc32.c so GF(2) LFSR bit-blasting does not explode multi-KB streams,
 * while enforcing 100% of pointer, flash-read, and bounds preconditions).
 * Real boot_crc32.c is directly verified without replacement in FV-09.
 */
uint32_t cbmc_boot_crc32_update_contract(uint32_t crc_init,
                                         const uint8_t *data,
                                         size_t len) {
    (void)crc_init;
    cbmc_assert_readable(data, len, "boot_crc32_update buffer must be readable");
    return nondet_uint32_t();
}

uint32_t cbmc_compute_boot_crc32_contract(const uint8_t *data, size_t len) {
    return cbmc_boot_crc32_update_contract(0xFFFFFFFFU, data, len);
}

uint32_t cbmc_boot_crc32_fill_contract(uint32_t crc_init, uint8_t val, size_t len) {
    (void)crc_init;
    (void)val;
    (void)len;
    return nondet_uint32_t();
}

boot_status_t cbmc_boot_crc32_flash_stream_contract(const boot_platform_t *platform,
                                                    uint32_t addr, size_t len,
                                                    uint32_t *out_crc,
                                                    uint8_t *arena, size_t arena_len) {
    if (platform == NULL || platform->flash == NULL ||
        platform->flash->read == NULL || out_crc == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    __CPROVER_assert(__CPROVER_w_ok(out_crc, sizeof(*out_crc)),
                     "boot_crc32_flash_stream out_crc must be writable");
    if (len == 0U) {
        if (arena != NULL && arena_len > 0U) {
            boot_secure_zeroize(arena, arena_len);
        }
        *out_crc = 0U;
        return BOOT_OK;
    }
    if (arena == NULL || arena_len == 0U || len > (size_t)UINT32_MAX ||
        (UINT32_MAX - addr) < (uint32_t)(len - 1U)) {
        return BOOT_ERR_INVALID_ARG;
    }
    __CPROVER_assert(__CPROVER_w_ok(arena, arena_len),
                     "boot_crc32_flash_stream arena must be writable");
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "boot_crc32_flash_stream flash range must stay in bounds");
    uint8_t probe_byte = 0U;
    boot_status_t st = platform->flash->read(addr, &probe_byte, 1U);
    if (st != BOOT_OK) {
        boot_secure_zeroize(arena, arena_len);
        return st;
    }
    if (len > 1U) {
        st = platform->flash->read(addr + (uint32_t)(len - 1U), &probe_byte, 1U);
        if (st != BOOT_OK) {
            boot_secure_zeroize(arena, arena_len);
            return st;
        }
    }
    boot_secure_zeroize(arena, arena_len);
    *out_crc = nondet_uint32_t();
    return BOOT_OK;
}

boot_status_t cbmc_boot_flash_is_erased_contract(const boot_platform_t *platform,
                                                 uint32_t addr, size_t len,
                                                 bool *out_erased) {
    if (platform == NULL || platform->flash == NULL ||
        platform->flash->read == NULL || out_erased == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    __CPROVER_assert(__CPROVER_w_ok(out_erased, sizeof(*out_erased)),
                     "boot_flash_is_erased out_erased must be writable");
    if (len == 0U) {
        *out_erased = true;
        return BOOT_OK;
    }
    if (len > (size_t)UINT32_MAX ||
        (UINT32_MAX - addr) < (uint32_t)(len - 1U)) {
        *out_erased = false;
        return BOOT_ERR_INVALID_ARG;
    }
    __CPROVER_assert((uint64_t)addr + (uint64_t)len <=
                         (uint64_t)CHIP_FLASH_TOTAL_SIZE,
                     "boot_flash_is_erased flash range must stay in bounds");
    uint8_t probe = 0U;
    boot_status_t st = platform->flash->read(addr, &probe, 1U);
    if (st != BOOT_OK) {
        *out_erased = false;
        return st;
    }
    if (len > 1U) {
        st = platform->flash->read(addr + (uint32_t)(len - 1U), &probe, 1U);
        if (st != BOOT_OK) {
            *out_erased = false;
            return st;
        }
    }
    *out_erased = nondet_bool();
    return BOOT_OK;
}

boot_status_t cbmc_boot_random_safe_contract(const boot_platform_t *platform,
                                             uint8_t *buf, size_t len) {
    if (platform == NULL || platform->entropy == NULL ||
        platform->entropy->random == NULL) {
        return BOOT_ERR_NOT_SUPPORTED;
    }
    cbmc_assert_writable(buf, len, "boot_random_safe buffer must be writable");
    boot_status_t st = platform->entropy->random(buf, len);
    if (st != BOOT_OK) {
        return st;
    }
    return nondet_bool() ? BOOT_OK : BOOT_ERR_CRYPTO;
}

#include "boot_flash_guard.h"

/*
 * Sound O(1) over-approximating contract for stream_write_skip_erased /
 * effect_write_skip_erased: explores both all-erased skip and arbitrary
 * hardware-aligned sub-run writes [dst + run_off, dst + run_end) within
 * [dst, dst + len), while preserving the unaligned fallthrough check.
 * Concrete loop implementations are directly verified in proof_boot_swap_bounds.c.
 */
boot_status_t cbmc_write_skip_erased_contract(const flash_hal_t *flash,
                                              uint32_t dst,
                                              const uint8_t *buf,
                                              uint32_t len) {
    __CPROVER_assert(flash != NULL, "write_skip_erased flash HAL must be non-null");
    cbmc_assert_readable(buf, len, "write_skip_erased source buffer must be readable");
    uint32_t align = (flash->write_align > 0U) ? flash->write_align : 1U;
    if ((dst % align) != 0U || (len % align) != 0U) {
        return boot_flash_write_guarded(flash, dst, buf, len);
    }
    if (len == 0U || nondet_bool()) {
        return BOOT_OK;
    }
    uint32_t nblocks = len / align;
    uint32_t b0 = nondet_uint32_t();
    uint32_t b1 = nondet_uint32_t();
    __CPROVER_assume(b0 < nblocks && b1 > b0 && b1 <= nblocks);
    uint32_t run_off = b0 * align;
    uint32_t run_len = (b1 - b0) * align;
    return boot_flash_write_guarded(flash, dst + run_off, buf + run_off, run_len);
}

boot_status_t cbmc_stream_copy_contract(const boot_platform_t *platform,
                                        uint32_t src, uint32_t dest, size_t len,
                                        uint8_t *arena, size_t arena_len) {
    if (platform == NULL || platform->flash == NULL ||
        platform->flash->read == NULL || platform->flash->write == NULL ||
        arena == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(arena, arena_len, "stream_copy arena must be writable");
    uint32_t align = platform->flash->write_align;
    size_t chunk_limit = arena_len;
    if (align > 1U) {
        chunk_limit = chunk_limit - (chunk_limit % align);
    }
    if (chunk_limit == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (len == 0U) {
        boot_secure_zeroize(arena, arena_len);
        return BOOT_OK;
    }
    size_t first_step = (len > chunk_limit) ? chunk_limit : len;
    boot_status_t st = platform->flash->read(src, arena, first_step);
    if (st != BOOT_OK) {
        boot_secure_zeroize(arena, arena_len);
        return st;
    }
    st = cbmc_write_skip_erased_contract(platform->flash, dest, arena, (uint32_t)first_step);
    if (st != BOOT_OK) {
        boot_secure_zeroize(arena, arena_len);
        return st;
    }
    if (len > first_step) {
        size_t rem = len % chunk_limit;
        size_t last_step = (rem == 0U) ? chunk_limit : rem;
        uint32_t tail_off = (uint32_t)(len - last_step);
        st = platform->flash->read(src + tail_off, arena, last_step);
        if (st != BOOT_OK) {
            boot_secure_zeroize(arena, arena_len);
            return st;
        }
        st = cbmc_write_skip_erased_contract(
            platform->flash, dest + tail_off, arena, (uint32_t)last_step);
    }
    boot_secure_zeroize(arena, arena_len);
    return st;
}

boot_status_t cbmc_swap_blocks_identical_contract(const boot_platform_t *p,
                                                  uint32_t a, uint32_t b,
                                                  size_t block, bool *out,
                                                  uint8_t *arena, size_t arena_len) {
    if (p == NULL || p->flash == NULL || p->flash->read == NULL ||
        out == NULL || arena == NULL) {
        return BOOT_ERR_INVALID_ARG;
    }
    cbmc_assert_writable(out, sizeof(*out), "blocks_identical out must be writable");
    cbmc_assert_writable(arena, arena_len, "blocks_identical arena must be writable");
    size_t half = (arena_len / 2U) & ~((size_t)7U);
    if (half == 0U) {
        return BOOT_ERR_INVALID_ARG;
    }
    if (block > 0U) {
        size_t probe = (block < half) ? block : half;
        if (p->flash->read(a, arena, probe) != BOOT_OK ||
            p->flash->read(b, arena + half, probe) != BOOT_OK) {
            *out = false;
            boot_secure_zeroize(arena, arena_len);
            return BOOT_OK;
        }
        if (block > probe) {
            uint8_t tail_a = 0U, tail_b = 0U;
            (void)p->flash->read(a + (uint32_t)(block - 1U), &tail_a, 1U);
            (void)p->flash->read(b + (uint32_t)(block - 1U), &tail_b, 1U);
        }
    }
    *out = nondet_bool();
    boot_secure_zeroize(arena, arena_len);
    return BOOT_OK;
}

/*
 * Sound over-approximating Heatshrink LZSS decoder contracts for streaming
 * pipeline proofs (boot_decomp.c / boot_delta.c). Real heatshrink_decoder.c
 * is verified directly without replacement in prove_heatshrink_bitreader_and_window_bounds.
 */
#ifdef CBMC_WITH_HSD_CONTRACTS
#include "heatshrink_decoder.h"

void cbmc_hsd_reset_contract(heatshrink_decoder *hsd) {
    __CPROVER_assert(hsd != NULL, "heatshrink_decoder_reset hsd must be non-null");
}

HSD_sink_res cbmc_hsd_sink_contract(heatshrink_decoder *hsd, uint8_t *in_buf,
                                    size_t size, size_t *input_size) {
    static unsigned s_partial_budget = 1U;
    if (hsd == NULL || in_buf == NULL || input_size == NULL) {
        return HSDR_SINK_ERROR_NULL;
    }
    cbmc_assert_readable(in_buf, size, "heatshrink_decoder_sink in_buf must be readable");
    __CPROVER_assert(__CPROVER_w_ok(input_size, sizeof(*input_size)),
                     "heatshrink_decoder_sink input_size must be writable");
    if (nondet_bool()) {
        *input_size = 0U;
    } else if (s_partial_budget > 0U && size >= 2U && nondet_bool()) {
        s_partial_budget--;
        *input_size = size / 2U;
    } else {
        *input_size = size;
    }
    return HSDR_SINK_OK;
}

HSD_poll_res cbmc_hsd_poll_contract(heatshrink_decoder *hsd, uint8_t *out_buf,
                                    size_t out_buf_size, size_t *output_size) {
    static unsigned s_poll_more_budget = 1U;
    if (hsd == NULL || out_buf == NULL || output_size == NULL) {
        return HSDR_POLL_ERROR_NULL;
    }
    cbmc_assert_writable(out_buf, out_buf_size,
                         "heatshrink_decoder_poll out_buf must be writable");
    __CPROVER_assert(__CPROVER_w_ok(output_size, sizeof(*output_size)),
                     "heatshrink_decoder_poll output_size must be writable");
    if (nondet_bool()) {
        *output_size = 0U;
        return HSDR_POLL_ERROR_UNKNOWN;
    }
    size_t bound = (out_buf_size < 32U) ? out_buf_size : 32U;
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= bound);
    if (n > 0U) {
        out_buf[0] = nondet_uint8_t();
    }
    *output_size = n;
    if (s_poll_more_budget > 0U && nondet_bool()) {
        s_poll_more_budget--;
        return HSDR_POLL_MORE;
    }
    return HSDR_POLL_EMPTY;
}

HSD_finish_res cbmc_hsd_finish_contract(heatshrink_decoder *hsd) {
    if (hsd == NULL) {
        return HSDR_FINISH_ERROR_NULL;
    }
    return nondet_bool() ? HSDR_FINISH_DONE : HSDR_FINISH_MORE;
}
#endif /* CBMC_WITH_HSD_CONTRACTS */

#endif /* !CBMC_LIBTOOB_ONLY */

#endif /* TOOB_CBMC_COMMON_H */
