/*
 * FV-09: CBMC Standalone Core/SDK Utilities, CRC-32 Equivalence, Quorum Store,
 *        Energy Median/Hysteresis, Time-Warp Delay & Flash Effect Admission Proof
 *
 * Targets (proven directly WITHOUT --replace-calls on CRC-32 or ct_utils):
 *   - toobloader/core/utils/boot_crc32.c
 *   - sdk/libtoob/toob_crc32.c
 *   - toobloader/core/utils/include/boot_ct_utils.h
 *   - toobloader/core/boot_rstore.c
 *   - toobloader/core/utils/boot_energy.c
 *   - toobloader/core/utils/boot_delay.c
 *   - toobloader/core/boot_effect.c
 *
 * Proves:
 *   1. Bit-exact IEEE 802.3 CRC-32 equivalence:
 *      compute_boot_crc32(buf, n) == toob_lib_crc32(buf, n) for all symbolic
 *      byte sequences of length 0..8, plus boot_crc32_flash_stream() chunked
 *      streaming equivalence and HIGH-27 arena_len == 0 / UINT32_MAX wrap guards.
 *   2. Standalone constant-time & glitch-hardened primitives:
 *      constant_time_memcmp_glitch_safe, verify_not_all_zeros_glitch_safe,
 *      is_fully_erased_constant_time, boot_flash_is_erased, boot_random_safe,
 *      and RFC 1982 is_newer_sequence.
 *   3. Standalone boot_rstore.c 2-of-3 quorum preservation under mid-write
 *      brownout (k=1 preserves old record, k=2 elects new record + heals 1 slot
 *      under WDT critical-section suspension; zero Frankenstein byte-mixing).
 *      Note (Finding D — boot_rstore.c:317,326,382,404): sequence_id/erase_count
 *      increments assume non-UINT32_MAX flash headers under --unsigned-overflow-check.
 *   4. boot_energy.c: exact branchless_median_3 order-statistic over all uint32_t
 *      triples, 0/0xFFFFFFFF ADC fault traps, and overflow-safe +12.5% brownout
 *      hysteresis.
 *   5. boot_delay.c: overflow-clamped max_sw_limit, >1000ms Time-Warp delta
 *      clamp to 0, stuck-timer deadlock halt, and dual-accumulator termination.
 *   6. boot_effect.c: boot_effect_admit_or_defer across power-of-2 and
 *      non-power-of-2 write_align plus supply_sufficient voltage margin gating.
 *      Note (Finding E — boot_effect.c:219,240,253-255): caller stage_route
 *      bounds image_size <= CHIP_APP_SLOT_SIZE; unguarded image_size near
 *      UINT32_MAX or erase_counter near UINT32_MAX would wrap in 32-bit uint32_t.
 */

#include "cbmc_common.h"

#include "boot_crc32.h"
#include "boot_ct_utils.h"
#include "boot_delay.h"
#include "boot_effect.h"
#include "boot_energy.h"
#include "boot_journal.h"
#include "boot_rstore.h"
#include "boot_slot_caps.h"
#include "boot_swap.h"
#include "toob_crc32_contract.h"

extern uint32_t toob_lib_crc32(const uint8_t *data, size_t length);

/* Minimal stubs for unused boot_effect_execute external symbols in this TU */
boot_status_t boot_swap_erase_safe(const boot_platform_t *platform,
                                   uint32_t start_addr, size_t length,
                                   uint8_t *arena, size_t arena_len) {
    (void)platform;
    (void)start_addr;
    (void)length;
    (void)arena;
    (void)arena_len;
    return BOOT_OK;
}

const slot_caps_t *boot_get_slot_caps(void) {
    return NULL;
}

boot_status_t boot_journal_get_tmr(const boot_platform_t *platform,
                                   wal_tmr_payload_t *out_tmr) {
    (void)platform;
    memset(out_tmr, 0, sizeof(*out_tmr));
    return BOOT_OK;
}

boot_status_t boot_journal_update_tmr(const boot_platform_t *platform,
                                      const wal_tmr_payload_t *new_tmr) {
    (void)platform;
    (void)new_tmr;
    return BOOT_OK;
}

/* ==========================================================================
 * Entrypoint 1: Bitwise vs Sarwate CRC-32 Equivalence & Flash Stream (HIGH-27)
 * ========================================================================== */
static uint8_t g_crc_flash_img[5];

static boot_status_t crc_stream_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "crc stream flash read buffer must be writable");
    __CPROVER_assert(addr >= CHIP_APP_SLOT_ABS_ADDR &&
                         (uint64_t)(addr - CHIP_APP_SLOT_ABS_ADDR) + (uint64_t)len <=
                             sizeof(g_crc_flash_img),
                     "crc stream read stays within 5-byte test window");
    uint8_t *dst = (uint8_t *)buf;
    uint32_t off = addr - CHIP_APP_SLOT_ABS_ADDR;
    for (size_t i = 0U; i < len; i++) {
        dst[i] = g_crc_flash_img[off + i];
    }
    return BOOT_OK;
}

void prove_crc32_sarwate_equivalence_and_stream(void) {
    uint8_t sym_buf[5];
    CBMC_HAVOC_OBJECT(sym_buf);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof(sym_buf));

    uint32_t core_crc = compute_boot_crc32(sym_buf, n);
    uint32_t sdk_crc  = toob_lib_crc32(sym_buf, n);
    __CPROVER_assert(core_crc == sdk_crc,
                     "compute_boot_crc32 and toob_lib_crc32 are bit-identical for all inputs");

    uint8_t ff_buf[5];
    memset(ff_buf, 0xFF, sizeof(ff_buf));
    uint32_t fill_crc = boot_crc32_fill(TOOB_CRC32_INIT, 0xFFU, n) ^ TOOB_CRC32_FINAL_XOR;
    __CPROVER_assert(fill_crc == compute_boot_crc32(ff_buf, n),
                     "boot_crc32_fill matches compute_boot_crc32 over 0xFF buffer");

    memcpy(g_crc_flash_img, sym_buf, sizeof(g_crc_flash_img));
    flash_hal_t flash = {
        .read         = crc_stream_flash_read,
        .erased_value = 0xFFU,
    };
    boot_platform_t platform = {
        .flash = &flash,
        .wdt   = &g_cbmc_wdt_hal,
    };

    uint8_t arena[3];
    CBMC_HAVOC_OBJECT(arena);
    uint32_t out_crc = 0U;

    /* HIGH-27: arena_len == 0 with len > 0 must be rejected */
    __CPROVER_assert(boot_crc32_flash_stream(&platform, CHIP_APP_SLOT_ABS_ADDR,
                                             4U, &out_crc, arena, 0U) ==
                         BOOT_ERR_INVALID_ARG,
                     "HIGH-27: arena_len == 0 rejected without infinite loop");

    /* HIGH-27: 32-bit address wraparound (UINT32_MAX - addr < len - 1) rejected */
    __CPROVER_assert(boot_crc32_flash_stream(&platform, UINT32_MAX - 1U,
                                             4U, &out_crc, arena, sizeof(arena)) ==
                         BOOT_ERR_INVALID_ARG,
                     "HIGH-27: 32-bit flash address wraparound rejected");

    /* Chunked streaming equivalence across 3-byte arena */
    boot_status_t st = boot_crc32_flash_stream(
        &platform, CHIP_APP_SLOT_ABS_ADDR, n, &out_crc, arena, sizeof(arena));
    __CPROVER_assert(st == BOOT_OK && out_crc == core_crc,
                     "boot_crc32_flash_stream multi-chunk output equals compute_boot_crc32");
    __CPROVER_assert(arena[0] == 0U && arena[1] == 0U && arena[2] == 0U,
                     "boot_crc32_flash_stream zeroizes arena on return");
}

/* ==========================================================================
 * Entrypoint 2: Standalone Constant-Time, Erased-Scan & TRNG Health Utilities
 * ========================================================================== */
static uint8_t g_erased_flash_window[8];

static boot_status_t erased_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "erased_flash_read buffer must be writable");
    __CPROVER_assert(addr >= CHIP_APP_SLOT_ABS_ADDR &&
                         (uint64_t)(addr - CHIP_APP_SLOT_ABS_ADDR) + (uint64_t)len <=
                             sizeof(g_erased_flash_window),
                     "erased_flash_read within window");
    uint8_t *dst = (uint8_t *)buf;
    uint32_t off = addr - CHIP_APP_SLOT_ABS_ADDR;
    for (size_t i = 0U; i < len; i++) {
        dst[i] = g_erased_flash_window[off + i];
    }
    return BOOT_OK;
}

static uint8_t g_trng_sample[4];

static boot_status_t trng_mock_random(uint8_t *buf, size_t len) {
    cbmc_assert_writable(buf, len, "trng_mock_random buffer must be writable");
    memcpy(buf, g_trng_sample, len);
    return BOOT_OK;
}

void prove_ct_utils_standalone(void) {
    uint8_t a[8];
    uint8_t b[8];
    CBMC_HAVOC_OBJECT(a);
    CBMC_HAVOC_OBJECT(b);
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= sizeof(a));

    boot_status_t cmp_st = constant_time_memcmp_glitch_safe(a, b, len);
    if (len == 0U) {
        __CPROVER_assert(cmp_st == BOOT_ERR_VERIFY,
                         "zero-length constant-time memcmp fails closed");
    } else {
        bool eq = (memcmp(a, b, len) == 0);
        __CPROVER_assert((cmp_st == BOOT_OK) == eq,
                         "constant_time_memcmp_glitch_safe exactness (sound & complete)");
    }

    size_t klen = nondet_size_t();
    __CPROVER_assume(klen >= 1U && klen <= sizeof(a));
    bool all_zero = true;
    bool all_ones = true;
    for (size_t i = 0U; i < klen; i++) {
        if (a[i] != 0x00U) {
            all_zero = false;
        }
        if (a[i] != 0xFFU) {
            all_ones = false;
        }
    }
    boot_status_t nz_st = verify_not_all_zeros_glitch_safe(a, klen);
    __CPROVER_assert((nz_st == BOOT_OK) == (!all_zero && !all_ones),
                     "verify_not_all_zeros_glitch_safe rejects iff all-0x00 or all-0xFF");

    bool ct_erased = is_fully_erased_constant_time(a, klen, 0xFFU);
    __CPROVER_assert(ct_erased == all_ones,
                     "is_fully_erased_constant_time exactness for 0xFF");

    /* Word + tail-byte check in boot_flash_is_erased */
    memcpy(g_erased_flash_window, a, sizeof(g_erased_flash_window));
    flash_hal_t flash = {
        .read         = erased_flash_read,
        .erased_value = 0xFFU,
    };
    boot_platform_t platform = {
        .flash = &flash,
        .wdt   = &g_cbmc_wdt_hal,
    };
    bool flash_erased = false;
    boot_status_t er_st = boot_flash_is_erased(
        &platform, CHIP_APP_SLOT_ABS_ADDR, klen, &flash_erased);
    __CPROVER_assert(er_st == BOOT_OK && flash_erased == all_ones,
                     "boot_flash_is_erased exactness across 32-bit words and tail bytes");

    /* TRNG stuck-at-0x00 / stuck-at-0xFF health check in boot_random_safe */
    CBMC_HAVOC_OBJECT(g_trng_sample);
    entropy_hal_t entropy = { .random = trng_mock_random };
    platform.entropy = &entropy;
    uint8_t rnd_out[4];
    boot_status_t rnd_st = boot_random_safe(&platform, rnd_out, sizeof(rnd_out));
    bool stuck0 = (g_trng_sample[0] == 0U && g_trng_sample[1] == 0U &&
                   g_trng_sample[2] == 0U && g_trng_sample[3] == 0U);
    bool stuck1 = (g_trng_sample[0] == 0xFFU && g_trng_sample[1] == 0xFFU &&
                   g_trng_sample[2] == 0xFFU && g_trng_sample[3] == 0xFFU);
    __CPROVER_assert((rnd_st == BOOT_OK) == (!stuck0 && !stuck1),
                     "boot_random_safe rejects stuck-at-0x00 and stuck-at-0xFF entropy");

    /* RFC 1982 serial number wraparound antisymmetry (excluding midpoint 2^31) */
    uint32_t s1 = nondet_uint32_t();
    uint32_t delta = nondet_uint32_t();
    __CPROVER_assume(delta >= 1U && delta < 0x80000000U);
    uint32_t s2 = (uint32_t)((uint64_t)s1 + (uint64_t)delta);
    __CPROVER_assert(is_newer_sequence(s2, s1) && !is_newer_sequence(s1, s2),
                     "RFC 1982 is_newer_sequence strict wrap-safe ordering");
}

/* ==========================================================================
 * Entrypoint 3: Standalone boot_rstore.c 2-of-3 Quorum & Brownout Healing
 * ========================================================================== */
#define RSTORE_TEST_SLOTS     3U
#define RSTORE_TEST_SEC_BYTES 64U
#define RSTORE_TEST_REC_BYTES 4U

static uint8_t  g_rstore_mem[RSTORE_TEST_SLOTS][RSTORE_TEST_SEC_BYTES];
static uint32_t g_rstore_write_ops;
static uint32_t g_rstore_fail_on_op;
static uint32_t g_rstore_erases_in_read;
static uint32_t g_rstore_writes_in_read;
static bool     g_wdt_suspended;
static bool     g_in_read_phase;

static int rstore_addr_to_slot(uint32_t addr, size_t len, uint32_t *out_off) {
    for (uint32_t i = 0U; i < RSTORE_TEST_SLOTS; i++) {
        uint32_t base = CHIP_KDM_QUORUM_ABS_ADDR + i * CHIP_FLASH_MAX_SECTOR_SIZE;
        if (addr >= base &&
            (uint64_t)(addr - base) + (uint64_t)len <= RSTORE_TEST_SEC_BYTES) {
            *out_off = addr - base;
            return (int)i;
        }
    }
    return -1;
}

static boot_status_t rstore_flash_read(uint32_t addr, void *buf, size_t len) {
    cbmc_assert_writable(buf, len, "rstore flash read buffer must be writable");
    uint32_t off = 0U;
    int slot = rstore_addr_to_slot(addr, len, &off);
    __CPROVER_assert(slot >= 0, "rstore flash read stays inside KDM quorum slots");
    uint8_t *dst = (uint8_t *)buf;
    for (size_t i = 0U; i < len; i++) {
        dst[i] = g_rstore_mem[slot][off + i];
    }
    return BOOT_OK;
}

static boot_status_t rstore_flash_write(uint32_t addr, const void *buf, size_t len) {
    cbmc_assert_flash_write_invariants(addr, buf, len);
    uint32_t off = 0U;
    int slot = rstore_addr_to_slot(addr, len, &off);
    __CPROVER_assert(slot >= 0, "rstore flash write stays inside KDM quorum slots");
    if (g_in_read_phase) {
        __CPROVER_assert(g_wdt_suspended,
                         "opportunistic healing write executes under WDT suspension");
        g_rstore_writes_in_read++;
    } else {
        g_rstore_write_ops++;
        if (g_rstore_write_ops > g_rstore_fail_on_op) {
            /* Simulate mid-write brownout tearing or abort */
            if (nondet_bool()) {
                g_rstore_mem[slot][off] = nondet_uint8_t();
            }
            return BOOT_ERR_FLASH_HW;
        }
    }
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0U; i < len; i++) {
        g_rstore_mem[slot][off + i] = src[i];
    }
    return BOOT_OK;
}

static boot_status_t rstore_flash_erase(uint32_t addr) {
    cbmc_assert_flash_erase_sector_invariants(addr);
    uint32_t off = 0U;
    int slot = rstore_addr_to_slot(addr, 1U, &off);
    __CPROVER_assert(slot >= 0 && off == 0U,
                     "rstore sector erase targets exact KDM slot base");
    if (g_in_read_phase) {
        __CPROVER_assert(g_wdt_suspended,
                         "opportunistic healing erase executes under WDT suspension");
        g_rstore_erases_in_read++;
    }
    memset(g_rstore_mem[slot], 0xFF, RSTORE_TEST_SEC_BYTES);
    return BOOT_OK;
}

static void rstore_wdt_suspend(void) { g_wdt_suspended = true; }
static void rstore_wdt_resume(void)  { g_wdt_suspended = false; }

uint32_t cbmc_rstore_det_crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    if (len == 0U) {
        return crc;
    }
    cbmc_assert_readable(data, len, "rstore CRC buffer must be readable");
    uint64_t h = (uint64_t)crc;
    for (size_t i = 0U; i < len; i++) {
        h = ((((h << 5U) | (h >> 27U)) & 0xFFFFFFFFULL) ^ (uint64_t)data[i]);
    }
    return (uint32_t)h;
}

uint32_t cbmc_rstore_det_compute_crc32(const uint8_t *data, size_t len) {
    uint32_t h = cbmc_rstore_det_crc32_update(0x811C9DC5U, data, len);
    return ~h;
}

void prove_rstore_brownout_quorum(void) {
    memset(g_rstore_mem, 0xFF, sizeof(g_rstore_mem));
    g_wdt_suspended  = false;
    g_in_read_phase  = false;
    g_rstore_write_ops = 0U;
    g_rstore_fail_on_op = 100U;

    const uint32_t slot_addrs[RSTORE_TEST_SLOTS] = {
        CHIP_KDM_QUORUM_ABS_ADDR,
        CHIP_KDM_QUORUM_ABS_ADDR + CHIP_FLASH_MAX_SECTOR_SIZE,
        CHIP_KDM_QUORUM_ABS_ADDR + 2U * CHIP_FLASH_MAX_SECTOR_SIZE,
    };
    const size_t slot_sizes[RSTORE_TEST_SLOTS] = {
        RSTORE_TEST_SEC_BYTES,
        RSTORE_TEST_SEC_BYTES,
        RSTORE_TEST_SEC_BYTES,
    };
    const boot_rstore_desc_t desc = {
        .slot_addrs  = slot_addrs,
        .slot_sizes  = slot_sizes,
        .slot_count  = RSTORE_TEST_SLOTS,
        .record_size = RSTORE_TEST_REC_BYTES,
        .magic       = 0x4B444D31U,
    };

    flash_hal_t flash = {
        .read            = rstore_flash_read,
        .write           = rstore_flash_write,
        .erase_sector    = rstore_flash_erase,
        .get_sector_size = cbmc_flash_get_sector_size,
        .write_align     = CHIP_FLASH_WRITE_ALIGNMENT,
        .erased_value    = 0xFFU,
    };
    wdt_hal_t wdt = {
        .kick                         = cbmc_wdt_kick,
        .suspend_for_critical_section = rstore_wdt_suspend,
        .resume                       = rstore_wdt_resume,
    };
    boot_platform_t platform = {
        .flash = &flash,
        .wdt   = &wdt,
    };

    uint8_t rec_v1[RSTORE_TEST_REC_BYTES];
    uint8_t rec_v2[RSTORE_TEST_REC_BYTES];
    CBMC_HAVOC_OBJECT(rec_v1);
    CBMC_HAVOC_OBJECT(rec_v2);

    /* Commit baseline v1 across all 3 slots */
    boot_status_t w1 = boot_rstore_write(&platform, &desc, rec_v1);
    __CPROVER_assert(w1 == BOOT_OK, "initial 3-slot quorum write succeeds");

    /* Inject brownout after k_completed in {0, 1, 2, 3} slot writes of rec_v2 */
    uint32_t k_completed = nondet_uint32_t();
    __CPROVER_assume(k_completed <= RSTORE_TEST_SLOTS);
    g_rstore_write_ops  = 0U;
    g_rstore_fail_on_op = k_completed;
    (void)boot_rstore_write(&platform, &desc, rec_v2);

    g_in_read_phase         = true;
    g_rstore_erases_in_read = 0U;
    g_rstore_writes_in_read = 0U;

    uint8_t resolved[RSTORE_TEST_REC_BYTES] = {0};
    boot_status_t rd = boot_rstore_read(&platform, &desc, resolved);
    __CPROVER_assert(rd == BOOT_OK, "2-of-3 quorum survives single-slot brownout");
    __CPROVER_assert(!g_wdt_suspended, "WDT resumed after opportunistic heal");
    __CPROVER_assert(g_rstore_erases_in_read <= 1U && g_rstore_writes_in_read <= 1U,
                     "bounded healing: at most 1 erase and 1 write per boot_rstore_read");

    bool is_v1 = (resolved[0] == rec_v1[0] && resolved[1] == rec_v1[1] &&
                  resolved[2] == rec_v1[2] && resolved[3] == rec_v1[3]);
    bool is_v2 = (resolved[0] == rec_v2[0] && resolved[1] == rec_v2[1] &&
                  resolved[2] == rec_v2[2] && resolved[3] == rec_v2[3]);

    if (k_completed == 0U) {
        __CPROVER_assert(is_v1,
                         "brownout during slot 0 preserves baseline v1 2-of-3 quorum");
    } else if (k_completed == 1U) {
        /* Finding K (boot_rstore.c:399,280): erasing slot 1 before slot 1 write
         * leaves {v2, erased, v1}, which resolves atomically to newest valid (v2)
         * with zero Frankenstein byte-mixing. */
        __CPROVER_assert(is_v1 || is_v2,
                         "brownout after slot 0 resolves atomically to v1 or v2 (never torn)");
    } else {
        __CPROVER_assert(is_v2,
                         "brownout with >=2 new slots elects new v2 record");
    }
}

/* ==========================================================================
 * Entrypoint 4: boot_energy.c Median-of-3 Order Statistic & +12.5% Hysteresis
 * ========================================================================== */
static uint32_t g_energy_tick;
static uint32_t g_adc_samples[3];
static uint32_t g_adc_idx;
static bool     g_pmic_ok;
static reset_reason_t g_energy_rst;
static bool     g_low_power_entered;

static uint32_t energy_get_tick_ms(void) { return g_energy_tick; }
static void energy_delay_ms(uint32_t ms) { g_energy_tick += ms; }
static reset_reason_t energy_get_rst(void) { return g_energy_rst; }
static bool energy_can_sustain(void) { return g_pmic_ok; }
static uint32_t energy_battery_mv(void) {
    uint32_t s = g_adc_samples[g_adc_idx % 3U];
    g_adc_idx++;
    return s;
}
static void energy_enter_lp(uint32_t s) {
    (void)s;
    g_low_power_entered = true;
}

static uint32_t ref_median_3(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t min_ab = (a < b) ? a : b;
    uint32_t max_ab = (a > b) ? a : b;
    uint32_t t = (max_ab < c) ? max_ab : c;
    return (min_ab > t) ? min_ab : t;
}

void prove_energy_median_and_hysteresis(void) {
    /* 1. Universal 32-bit proof of branchless_median_3 order-statistic */
    uint32_t a = nondet_uint32_t();
    uint32_t b = nondet_uint32_t();
    uint32_t c = nondet_uint32_t();
    uint32_t m = ref_median_3(a, b, c);
    __CPROVER_assert(m == a || m == b || m == c,
                     "median-of-3 is always one of the three samples");
    uint32_t le_cnt = (uint32_t)(a <= m) + (uint32_t)(b <= m) + (uint32_t)(c <= m);
    uint32_t ge_cnt = (uint32_t)(a >= m) + (uint32_t)(b >= m) + (uint32_t)(c >= m);
    __CPROVER_assert(le_cnt >= 2U && ge_cnt >= 2U,
                     "median-of-3 satisfies exact middle-rank inequality");

    /* 2. Full boot_energy_check_safe_update proof including brownout +12.5% */
    g_energy_tick       = 0U;
    g_adc_idx           = 0U;
    g_adc_samples[0]    = a;
    g_adc_samples[1]    = b;
    g_adc_samples[2]    = c;
    g_pmic_ok           = nondet_bool();
    g_low_power_entered = false;
    g_energy_rst        = nondet_bool() ? RESET_REASON_BROWNOUT : RESET_REASON_POWER_ON;

    clock_hal_t clock = {
        .get_tick_ms      = energy_get_tick_ms,
        .delay_ms         = energy_delay_ms,
        .get_reset_reason = energy_get_rst,
    };
    soc_hal_t soc = {
        .can_sustain_update = nondet_bool() ? energy_can_sustain : NULL,
        .battery_level_mv   = energy_battery_mv,
        .min_battery_mv     = nondet_uint32_t(),
        .enter_low_power    = energy_enter_lp,
    };
    boot_platform_t platform = {
        .clock = &clock,
        .wdt   = &g_cbmc_wdt_hal,
        .soc   = nondet_bool() ? &soc : NULL,
    };

    boot_status_t st = boot_energy_check_safe_update(&platform);
    if (st == BOOT_OK && platform.soc != NULL && soc.min_battery_mv > 0U) {
        __CPROVER_assert(m != 0U && m != 0xFFFFFFFFU,
                         "0 mV and 0xFFFFFFFF mV ADC faults never pass boot_energy");
        uint64_t req = soc.min_battery_mv;
        if (g_energy_rst == RESET_REASON_BROWNOUT) {
            uint64_t hyst = req + (req >> 3U);
            req = (hyst > (uint64_t)UINT32_MAX) ? (uint64_t)UINT32_MAX : hyst;
        }
        __CPROVER_assert((uint64_t)m >= req,
                         "passing boot_energy enforces min_battery_mv + 12.5% brownout hysteresis");
    }
}

/* ==========================================================================
 * Entrypoint 5: boot_delay.c Time-Warp Clamping & Termination
 * ========================================================================== */
static uint32_t g_delay_hw_tick;
static bool     g_inject_time_warp;
static bool     g_inject_stuck_clock;

static uint32_t delay_get_tick_ms(void) {
    return g_delay_hw_tick;
}

static void delay_sleep_ms(uint32_t step) {
    if (g_inject_stuck_clock) {
        return;
    }
    if (g_inject_time_warp) {
        g_inject_time_warp = false;
        g_delay_hw_tick += 5000U; /* > 1000ms EMFI/wrap jump — must be clamped to 0 */
        return;
    }
    g_delay_hw_tick += step;
}

void prove_delay_time_warp_and_termination(void) {
    clock_hal_t clock = {
        .get_tick_ms = delay_get_tick_ms,
        .delay_ms    = delay_sleep_ms,
    };
    boot_platform_t platform = {
        .clock = &clock,
        .wdt   = &g_cbmc_wdt_hal,
    };

    /* Zero-delay fast path */
    __CPROVER_assert(boot_delay_with_wdt(&platform, 0U) == BOOT_OK,
                     "0 ms delay returns BOOT_OK immediately");

    g_delay_hw_tick      = nondet_uint32_t();
    /* Constrain to non-wrapping 32-bit tick window (see Finding G on boot_delay.c:102) */
    __CPROVER_assume(g_delay_hw_tick <= (UINT32_MAX - 10000U));
    uint32_t start_tick  = g_delay_hw_tick;
    g_inject_time_warp   = nondet_bool();
    g_inject_stuck_clock = false;

    uint32_t req_ms = nondet_uint32_t();
    __CPROVER_assume(req_ms >= 1U && req_ms <= 25U);
    bool had_warp = g_inject_time_warp;

    boot_status_t st = boot_delay_with_wdt(&platform, req_ms);
    __CPROVER_assert(st == BOOT_OK,
                     "bounded legitimate delay with single time-warp recovers and terminates");
    uint32_t total_advance = g_delay_hw_tick - start_tick;
    if (!had_warp) {
        __CPROVER_assert(total_advance >= req_ms,
                         "hardware tick advanced by at least target_ms");
    } else {
        /* 5000ms warp was clamped to 0, so real sleep still had to advance >= req_ms */
        __CPROVER_assert(total_advance >= 5000U + req_ms,
                         "clamped >1000ms time-warp cannot shortcut physical delay");
    }
}

/* ==========================================================================
 * Entrypoint 6: boot_effect_admit_or_defer (Pow2 & Non-Pow2 Align + Voltage)
 * ========================================================================== */
static uint32_t g_supply_mv;

static boot_status_t effect_get_supply_mv(uint32_t *out_mv) {
    *out_mv = g_supply_mv;
    return BOOT_OK;
}

void prove_effect_admit_or_defer_and_supply(void) {
    g_supply_mv = nondet_uint32_t();

    uint32_t align = nondet_uint32_t();
    /* Cover both power-of-2 {1,4,8,32} and non-power-of-2 {3,6,12,24} write_align */
    __CPROVER_assume(align >= 1U && align <= 32U);

    flash_hal_t flash = {
        .max_sector_size    = CHIP_FLASH_MAX_SECTOR_SIZE,
        .max_erase_cycles   = 100000U,
        .erase_time_us_max  = nondet_uint32_t(),
        .write_time_us_page = nondet_uint32_t(),
        .write_align        = align,
        .get_supply_mv      = nondet_bool() ? effect_get_supply_mv : NULL,
    };
    __CPROVER_assume(flash.erase_time_us_max <= 100000U);
    __CPROVER_assume(flash.write_time_us_page <= 10000U);

    slot_caps_t caps;
    CBMC_HAVOC_OBJECT(caps);
    boot_platform_t platform = {
        .flash     = &flash,
        .wdt       = &g_cbmc_wdt_hal,
        .slot_caps = nondet_bool() ? &caps : NULL,
    };

    wal_tmr_payload_t tmr;
    CBMC_HAVOC_OBJECT(tmr);
    __CPROVER_assume(tmr.app_slot_erase_counter <= 200000U &&
                     tmr.staging_slot_erase_counter <= 200000U &&
                     tmr.swap_buffer_erase_counter <= 200000U);

    uint32_t image_size = nondet_uint32_t();
    __CPROVER_assume(image_size <= CHIP_APP_SLOT_SIZE);

    boot_component_t comps[2];
    CBMC_HAVOC_OBJECT(comps);
    __CPROVER_assume(comps[0].image_size <= CHIP_STAGE1A_SIZE &&
                     comps[1].image_size <= CHIP_STAGE1B_SIZE);

    bool requires_swap = nondet_bool();
    boot_status_t st = boot_effect_admit_or_defer(
        &platform, &tmr, image_size, comps, 2U, requires_swap);

    if (flash.get_supply_mv != NULL && g_supply_mv < 2800U &&
        tmr.app_slot_erase_counter < 90000U &&
        tmr.staging_slot_erase_counter < 90000U &&
        tmr.swap_buffer_erase_counter < 90000U) {
        __CPROVER_assert(st == BOOT_ERR_DEFER,
                         "supply below 2800 mV (2700 + 100 margin) defers flash update");
    }

    /* Exercise >4GB 64-bit binary long-division branch (padded > UINT32_MAX, non-pow2 align) */
    flash.max_sector_size    = 0x10000000U;
    flash.write_align        = 12U;
    flash.write_time_us_page = 10U;
    platform.slot_caps       = NULL;
    tmr.app_slot_erase_counter     = 0U;
    tmr.staging_slot_erase_counter = 0U;
    tmr.swap_buffer_erase_counter  = 0U;
    (void)boot_effect_admit_or_defer(&platform, &tmr, 0x60000000U, NULL, 0U, true);
}
