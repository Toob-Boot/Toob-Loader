/**
 * @file test_libtoob_safety.c
 * @brief Host Safety & Non-Brickability Unit Test Suite for libtoob.
 *
 * Covers:
 *   1. CRIT-23: Dual-slot POINTER resolution, fail-closed on corrupt handoff,
 *      and TOCTOU-free finalize base derivation.
 *   2. HIGH-21, MED-19, MED-21: Incremental lazy sector erase, odd-sized BLE
 *      chunk pause/resume without 0xFF gaps, brownout dirty-tail sector rollback,
 *      and pre-SHA256 chunk bounds validation.
 *   3. CRIT-24, HIGH-23: Cumulative per-boot-session mailbox bitmask intents
 *      (UPDATE_PENDING | RECOVERY_RESOLVED, CONFIRM | UPDATE_PENDING) and
 *      flash read I/O error protection without seq reset.
 *   4. CRIT-25: toob_confirm_boot no-op on COMMITTED, rejection of nonce == 0,
 *      and mandatory mailbox error propagation on TENTATIVE.
 *   5. CRIT-27, MED-24, ARCH-CBOR-01: TDR1 binary diag wire serializer,
 *      small-buffer overflow defense (*out_len == 0), and v3 padding zeroization.
 *   6. HIGH-22, HIGH-24: toob_set_next_update inactive-slot bounds enforcement
 *      and toob_submit_cloud_command TCC1 validation + unaligned DMA-safe write.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libtoob_config_sandbox.h"
#include "libtoob.h"
#include "toob_cloud_cmd_wire.h"
#include "toob_internal.h"
#include "toob_mailbox_wire.h"

extern void toob_mailbox_session_reset_for_test(void);

/* ============================================================================
 * Compact FIPS 180-4 SHA-256 Reference Implementation for Verified OTA Tests
 * ============================================================================ */

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t  data[64];
  uint32_t datalen;
} ref_sha256_ctx_t;

_Static_assert(sizeof(ref_sha256_ctx_t) <= sizeof(toob_os_sha256_ctx_t),
               "ref_sha256_ctx_t must fit inside toob_os_sha256_ctx_t");

static const uint32_t k_sha256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32U - n));
}

static void ref_sha256_transform(ref_sha256_ctx_t *c, const uint8_t data[64]) {
  uint32_t m[64];
  for (uint32_t i = 0U, j = 0U; i < 16U; i++, j += 4U) {
    m[i] = ((uint32_t)data[j] << 24U) | ((uint32_t)data[j + 1U] << 16U) |
           ((uint32_t)data[j + 2U] << 8U) | (uint32_t)data[j + 3U];
  }
  for (uint32_t i = 16U; i < 64U; i++) {
    uint32_t s0 = rotr32(m[i - 15U], 7U) ^ rotr32(m[i - 15U], 18U) ^ (m[i - 15U] >> 3U);
    uint32_t s1 = rotr32(m[i - 2U], 17U) ^ rotr32(m[i - 2U], 19U) ^ (m[i - 2U] >> 10U);
    m[i] = m[i - 16U] + s0 + m[i - 7U] + s1;
  }

  uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
  uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

  for (uint32_t i = 0U; i < 64U; i++) {
    uint32_t S1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + k_sha256[i] + m[i];
    uint32_t S0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
    uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
    uint32_t temp2 = S0 + maj;
    h = g; g = f; f = e; e = d + temp1;
    d = cc; cc = b; b = a; a = temp1 + temp2;
  }

  c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
  c->state[4] += e; c->state[5] += f; c->state[6] += g;  c->state[7] += h;
}

static void ref_sha256_init(ref_sha256_ctx_t *c) {
  c->datalen = 0U;
  c->bitlen = 0ULL;
  c->state[0] = 0x6a09e667U; c->state[1] = 0xbb67ae85U;
  c->state[2] = 0x3c6ef372U; c->state[3] = 0xa54ff53aU;
  c->state[4] = 0x510e527fU; c->state[5] = 0x9b05688cU;
  c->state[6] = 0x1f83d9abU; c->state[7] = 0x5be0cd19U;
}

static void ref_sha256_update(ref_sha256_ctx_t *c, const uint8_t *data, size_t len) {
  for (size_t i = 0U; i < len; i++) {
    c->data[c->datalen++] = data[i];
    if (c->datalen == 64U) {
      ref_sha256_transform(c, c->data);
      c->bitlen += 512ULL;
      c->datalen = 0U;
    }
  }
}

static void ref_sha256_final(ref_sha256_ctx_t *c, uint8_t hash[32]) {
  uint32_t i = c->datalen;
  if (c->datalen < 56U) {
    c->data[i++] = 0x80U;
    while (i < 56U) c->data[i++] = 0x00U;
  } else {
    c->data[i++] = 0x80U;
    while (i < 64U) c->data[i++] = 0x00U;
    ref_sha256_transform(c, c->data);
    memset(c->data, 0, 56U);
  }
  c->bitlen += (uint64_t)c->datalen * 8ULL;
  for (uint32_t b = 0U; b < 8U; b++) {
    c->data[63U - b] = (uint8_t)(c->bitlen >> (b * 8U));
  }
  ref_sha256_transform(c, c->data);
  for (i = 0U; i < 4U; i++) {
    for (uint32_t w = 0U; w < 8U; w++) {
      hash[i + w * 4U] = (uint8_t)((c->state[w] >> (24U - i * 8U)) & 0xFFU);
    }
  }
}

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  ref_sha256_ctx_t c;
  ref_sha256_init(&c);
  ref_sha256_update(&c, data, len);
  ref_sha256_final(&c, out);
}

/* ============================================================================
 * Realistic NOR Flash Mock & Fault Injection Harness
 * ============================================================================ */

#define MOCK_FLASH_SIZE 0x00200000U /* 2 MB */

static uint8_t  g_flash[MOCK_FLASH_SIZE];
static uint32_t g_erase_calls = 0U;
static uint32_t g_erased_sector_count = 0U;
static uint32_t g_write_calls = 0U;
static uint32_t g_sha_update_calls = 0U;
static int      g_fail_reads_remaining = 0;
static int      g_fail_writes_remaining = 0;

static void reset_mock_flash(void) {
  memset(g_flash, 0xFF, sizeof(g_flash));
  g_erase_calls = 0U;
  g_erased_sector_count = 0U;
  g_write_calls = 0U;
  g_sha_update_calls = 0U;
  g_fail_reads_remaining = 0;
  g_fail_writes_remaining = 0;
  toob_mailbox_session_reset_for_test();
  toob_ota_checkpoint_clear();
}

toob_status_t toob_os_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
  if (!buf || addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
    return TOOB_ERR_FLASH;
  }
  if (g_fail_reads_remaining > 0) {
    g_fail_reads_remaining--;
    return TOOB_ERR_FLASH;
  }
  memcpy(buf, &g_flash[addr], len);
  return TOOB_OK;
}

toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t *buf, uint32_t len) {
  if (!buf || len == 0U ||
      (addr % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
      (len % CHIP_FLASH_WRITE_ALIGNMENT) != 0U ||
      (((uintptr_t)buf) % 4U) != 0U || /* Enforce DMA pointer alignment! */
      addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
    return TOOB_ERR_FLASH;
  }
  if (g_fail_writes_remaining > 0) {
    g_fail_writes_remaining--;
    return TOOB_ERR_FLASH;
  }
  g_write_calls++;
  /* NOR flash physics: bits can only transition 1 -> 0 without erase! */
  for (uint32_t i = 0U; i < len; i++) {
    g_flash[addr + i] &= buf[i];
  }
  return TOOB_OK;
}

toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len) {
  if (len == 0U ||
      (addr % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
      (len % CHIP_FLASH_MAX_SECTOR_SIZE) != 0U ||
      addr > MOCK_FLASH_SIZE || len > (MOCK_FLASH_SIZE - addr)) {
    return TOOB_ERR_FLASH;
  }
  g_erase_calls++;
  g_erased_sector_count += (len / CHIP_FLASH_MAX_SECTOR_SIZE);
  memset(&g_flash[addr], 0xFF, len);
  return TOOB_OK;
}

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t *ctx) {
  if (!ctx) return TOOB_ERR_INVALID_ARG;
  ref_sha256_init((ref_sha256_ctx_t *)(void *)ctx->opaque);
  return TOOB_OK;
}

toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t *ctx, const uint8_t *data, uint32_t len) {
  if (!ctx || !data) return TOOB_ERR_INVALID_ARG;
  g_sha_update_calls++;
  ref_sha256_update((ref_sha256_ctx_t *)(void *)ctx->opaque, data, len);
  return TOOB_OK;
}

toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t *ctx, uint8_t out_hash[32]) {
  if (!ctx || !out_hash) return TOOB_ERR_INVALID_ARG;
  ref_sha256_final((ref_sha256_ctx_t *)(void *)ctx->opaque, out_hash);
  return TOOB_OK;
}

toob_status_t toob_os_nvs_read(const char *key, uint8_t *buf, size_t *len) {
  (void)key; (void)buf; (void)len;
  return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_os_nvs_write(const char *key, const uint8_t *buf, size_t len) {
  (void)key; (void)buf; (void)len;
  return TOOB_OK;
}

/* ============================================================================
 * Helpers to Seal .noinit Handoff & Diagnostics
 * ============================================================================ */

static void seal_handoff(uint32_t magic, uint64_t nonce, uint8_t active_slot) {
  memset(&toob_handoff_state, 0, sizeof(toob_handoff_state));
  toob_handoff_state.magic = magic;
  toob_handoff_state.struct_version = TOOB_HANDOFF_STRUCT_VERSION;
  toob_handoff_state.boot_nonce = nonce;
  toob_handoff_state.booted_partition = TOOB_PARTITION_APP;
  toob_handoff_state.reset_reason = TOOB_RESET_POWER_ON;
  toob_handoff_state.active_slot = active_slot;
  for (uint32_t i = 0U; i < 32U; i++) {
    toob_handoff_state.device_id[i] = (uint8_t)(0xA0U + i);
  }
  memset(toob_handoff_state._padding, 0xCC, sizeof(toob_handoff_state._padding));
  toob_handoff_state.crc32_trailer = toob_lib_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));
}

static bool read_freshest_mailbox(toob_mailbox_t *out) {
  bool found = false;
  uint32_t best_seq = 0U;
  for (uint32_t i = 0U; i < TOOB_MAILBOX_SLOTS; i++) {
    toob_mailbox_t cand;
    memcpy(&cand, &g_flash[CHIP_MAILBOX_ABS_ADDR + i * CHIP_MAILBOX_SLOT_SIZE], sizeof(cand));
    if (cand.magic == TOOB_MAILBOX_MAGIC &&
        cand.crc32 == toob_lib_crc32((const uint8_t *)&cand, TOOB_MAILBOX_CRC_LEN)) {
      if (!found || cand.seq > best_seq) {
        found = true;
        best_seq = cand.seq;
        *out = cand;
      }
    }
  }
  return found;
}

/* ============================================================================
 * Test 1: CRIT-23 Dual-Slot POINTER Resolution & Fail-Closed Handoff
 * ============================================================================ */
static void test_crit23_dual_slot_and_fail_closed(void) {
  printf("[TEST 1] CRIT-23: Dual-slot POINTER resolution & fail-closed handoff...\n");
  reset_mock_flash();

  uint8_t img[600];
  for (size_t i = 0U; i < sizeof(img); i++) {
    img[i] = (uint8_t)((i * 37U + 11U) & 0xFFU);
  }
  uint8_t sha[32];
  compute_sha256(img, sizeof(img), sha);

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  /* 1a. Corrupted handoff -> MUST fail closed without erasing Slot 1! */
  memset(&toob_handoff_state, 0xAA, sizeof(toob_handoff_state));
  /* Pre-populate Slot 1 with "active firmware" bytes to verify zero disturbance */
  memset(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], 0x5AU, 1024U);

  toob_ota_ctx_t ctx;
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(img), sha) == TOOB_ERR_VERIFY);
  assert(g_erase_calls == 0U);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR] == 0x5AU);

  /* Invalid active_slot (2) -> MUST fail closed too! */
  seal_handoff(TOOB_STATE_COMMITTED, 0x1111ULL, 2U);
  assert(toob_ota_begin(&ctx, sizeof(img), sha) == TOOB_ERR_VERIFY);
  assert(g_erase_calls == 0U);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR] == 0x5AU);

  /* 1b. active_slot == 0 -> stages into Slot 1 (CHIP_STAGING_SLOT_ABS_ADDR) */
  reset_mock_flash();
  memset(&g_flash[CHIP_APP_SLOT_ABS_ADDR], 0x33U, 1024U);
  seal_handoff(TOOB_STATE_COMMITTED, 0x2222ULL, 0U);

  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(img), sha) == TOOB_OK);
  assert(toob_ota_process_chunk(&ctx, img, sizeof(img)) == TOOB_OK);
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], img, sizeof(img)) == 0);
  assert(g_flash[CHIP_APP_SLOT_ABS_ADDR] == 0x33U); /* Active Slot 0 untouched! */

  toob_mailbox_t mbx;
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.tbm1_addr == CHIP_STAGING_SLOT_ABS_ADDR);

  /* 1c. active_slot == 1 -> stages into Slot 0 (CHIP_APP_SLOT_ABS_ADDR) */
  reset_mock_flash();
  memset(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], 0x77U, 1024U);
  seal_handoff(TOOB_STATE_COMMITTED, 0x3333ULL, 1U);

  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(img), sha) == TOOB_OK);
  assert(toob_ota_process_chunk(&ctx, img, sizeof(img)) == TOOB_OK);
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_APP_SLOT_ABS_ADDR], img, sizeof(img)) == 0);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR] == 0x77U); /* Active Slot 1 untouched! */

  assert(read_freshest_mailbox(&mbx));
  assert(mbx.tbm1_addr == CHIP_APP_SLOT_ABS_ADDR);
#else
  seal_handoff(TOOB_STATE_COMMITTED, 0x2222ULL, 0U);
  toob_ota_ctx_t ctx;
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(img), sha) == TOOB_OK);
  assert(toob_ota_process_chunk(&ctx, img, sizeof(img)) == TOOB_OK);
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], img, sizeof(img)) == 0);
#endif
}

/* ============================================================================
 * Test 2: HIGH-21, MED-19, MED-21 Incremental Erase, Pause/Resume, Dirty Tail
 * ============================================================================ */
static void test_ota_incremental_resume_and_bounds(void) {
  printf("[TEST 2] HIGH-21, MED-19, MED-21: Incremental erase, BLE pause/resume, dirty tail...\n");
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x4444ULL, 0U);

  /* 2a. MED-19: Aborted download of 300B out of 40000B erases ONLY 1 sector (not 3)! */
  static uint8_t large_img[40000];
  for (size_t i = 0U; i < sizeof(large_img); i++) {
    large_img[i] = (uint8_t)((i * 13U + 7U) & 0xFFU);
  }
  uint8_t large_sha[32];
  compute_sha256(large_img, sizeof(large_img), large_sha);

  /* Mark sector 1 & 2 with non-0xFF pattern so we can prove they are NOT erased on abort */
  memset(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR + CHIP_FLASH_MAX_SECTOR_SIZE], 0xA5, 64U);
  memset(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR + 2U * CHIP_FLASH_MAX_SECTOR_SIZE], 0x5A, 64U);

  toob_ota_ctx_t ctx;
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(large_img), large_sha) == TOOB_OK);
  assert(g_erased_sector_count == 0U); /* Zero synchronous erase in begin()! */

  assert(toob_ota_process_chunk(&ctx, large_img, 300U) == TOOB_OK);
  assert(g_erased_sector_count == 1U); /* Exactly 1 sector erased on first 256B flush! */
  assert(toob_ota_abort(&ctx) == TOOB_OK);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR + CHIP_FLASH_MAX_SECTOR_SIZE] == 0xA5U);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR + 2U * CHIP_FLASH_MAX_SECTOR_SIZE] == 0x5AU);

  /* 2b. HIGH-21: Odd-sized 137B BLE chunks + pause + resume -> zero 0xFF gap! */
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x4445ULL, 0U);

  uint8_t ble_img[2000];
  for (size_t i = 0U; i < sizeof(ble_img); i++) {
    ble_img[i] = (uint8_t)((i * 29U + 3U) & 0xFFU);
  }
  uint8_t ble_sha[32];
  compute_sha256(ble_img, sizeof(ble_img), ble_sha);

  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(ble_img), ble_sha) == TOOB_OK);

  /* Feed 5 x 137 = 685 bytes -> 512 bytes flushed, 173 bytes buffered in RAM */
  for (uint32_t k = 0U; k < 5U; k++) {
    assert(toob_ota_process_chunk(&ctx, &ble_img[k * 137U], 137U) == TOOB_OK);
  }
  assert(g_toob_ota_resume_state.bytes_staged == 512U);
  assert(g_toob_ota_resume_state.target_addr == CHIP_STAGING_SLOT_ABS_ADDR);

  /* Simulate transient BLE disconnect via toob_ota_pause() */
  /* First verify in-RAM resume fast-path rejects mismatched total_size / sha256! */
  uint32_t bad_off = 0U;
  uint8_t wrong_sha[32];
  memset(wrong_sha, 0x99, sizeof(wrong_sha));
  assert(toob_ota_resume(&ctx, sizeof(ble_img) + 16U, ble_sha, &bad_off) == TOOB_ERR_INVALID_ARG);
  assert(toob_ota_resume(&ctx, sizeof(ble_img), wrong_sha, &bad_off) == TOOB_ERR_VERIFY);

  assert(toob_ota_pause(&ctx) == TOOB_OK);
  assert(ctx.bytes_queued == 0U);
  assert(g_toob_ota_resume_state.magic == TOOB_OTA_RESUME_MAGIC);

  uint32_t resume_off = 0U;
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  /* Verify target_addr binding: if active_slot changed, stale checkpoint is rejected! */
  seal_handoff(TOOB_STATE_COMMITTED, 0x4499ULL, 1U);
  assert(toob_ota_resume(&ctx, sizeof(ble_img), ble_sha, &resume_off) == TOOB_ERR_NOT_FOUND);
  /* Re-save bound checkpoint for active_slot == 0 and restore handoff */
  toob_ota_checkpoint_save_bound(512U, CHIP_STAGING_SLOT_ABS_ADDR, ble_sha);
  seal_handoff(TOOB_STATE_COMMITTED, 0x4445ULL, 0U);
#endif
  assert(toob_ota_resume(&ctx, sizeof(ble_img), ble_sha, &resume_off) == TOOB_OK);
  assert(resume_off == 512U);

  /* Stream remaining bytes from resume_off in 137B chunks */
  uint32_t pos = resume_off;
  while (pos < sizeof(ble_img)) {
    uint32_t rem = (uint32_t)sizeof(ble_img) - pos;
    uint32_t clen = (rem > 137U) ? 137U : rem;
    assert(toob_ota_process_chunk(&ctx, &ble_img[pos], clen) == TOOB_OK);
    pos += clen;
  }
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], ble_img, sizeof(ble_img)) == 0);

  /* 2c. MED-19: Brownout dirty tail triggers sector rollback & clean resume! */
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x4446ULL, 0U);

  uint32_t total_dirty_test = 20000U;
  uint8_t dirty_sha[32];
  compute_sha256(large_img, total_dirty_test, dirty_sha);

  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, total_dirty_test, dirty_sha) == TOOB_OK);
  /* Stage 16384 + 512 = 16896 bytes (1 full sector + 512 bytes in sector 1) */
  assert(toob_ota_process_chunk(&ctx, large_img, 16896U) == TOOB_OK);
  assert(toob_ota_pause(&ctx) == TOOB_OK);
  assert(g_toob_ota_resume_state.bytes_staged == 16896U);

  /* Inject torn-write byte after the checkpointed offset inside sector 1 */
  g_flash[CHIP_STAGING_SLOT_ABS_ADDR + 16896U + 19U] = 0x12U;

  resume_off = 0U;
  assert(toob_ota_resume(&ctx, total_dirty_test, dirty_sha, &resume_off) == TOOB_OK);
  /* Must roll back cleanly to sector 1 start (16384) and re-erase sector 1! */
  assert(resume_off == CHIP_FLASH_MAX_SECTOR_SIZE);
  assert(g_flash[CHIP_STAGING_SLOT_ABS_ADDR + 16896U + 19U] == 0xFFU);

  /* Stream [16384 .. 20000) and verify SHA-256 finalize succeeds */
  assert(toob_ota_process_chunk(&ctx, &large_img[resume_off],
                                total_dirty_test - resume_off) == TOOB_OK);
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_STAGING_SLOT_ABS_ADDR], large_img, total_dirty_test) == 0);

  /* 2d. MED-21: Oversized chunk rejected BEFORE toob_os_sha256_update! */
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x4447ULL, 0U);
  uint8_t small_sha[32];
  compute_sha256(ble_img, 512U, small_sha);

  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, 512U, small_sha) == TOOB_OK);
  g_sha_update_calls = 0U;
  assert(toob_ota_process_chunk(&ctx, ble_img, 256U) == TOOB_OK);
  assert(g_sha_update_calls == 1U);

  /* Attempt OOB chunk (256 + 300 > 512): MUST NOT invoke sha256_update! */
  assert(toob_ota_process_chunk(&ctx, &ble_img[256], 300U) == TOOB_ERR_INVALID_ARG);
  assert(g_sha_update_calls == 1U);

  /* Stream remains healthy and finalizes cleanly when given exact remaining 256B! */
  assert(toob_ota_process_chunk(&ctx, &ble_img[256], 256U) == TOOB_OK);
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
}

/* ============================================================================
 * Test 3: CRIT-24 & HIGH-23 Cumulative Mailbox & Flash Read Error Resilience
 * ============================================================================ */
static void test_mailbox_cumulative_and_io_err(void) {
  printf("[TEST 3] CRIT-24 & HIGH-23: Cumulative mailbox intents & I/O error protection...\n");
  reset_mock_flash();
  seal_handoff(TOOB_STATE_TENTATIVE, 0x77770001ULL, 0U);

  uint8_t img[640];
  memset(img, 0x42, sizeof(img));
  toob_ota_ctx_t ctx;
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, sizeof(img), NULL) == TOOB_OK);
  assert(toob_ota_process_chunk(&ctx, img, sizeof(img)) == TOOB_OK);

  /* Recovery sequence: toob_ota_finalize() followed by toob_recovery_resolved() */
  assert(toob_ota_finalize(&ctx) == TOOB_OK);
  toob_mailbox_t mbx;
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.seq == 1U);
  assert(mbx.request == TOOB_REQ_UPDATE_PENDING);
  assert(mbx.tbm1_addr == CHIP_STAGING_SLOT_ABS_ADDR);

  assert(toob_recovery_resolved() == TOOB_OK);
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.seq == 2U);
  assert(mbx.request == (TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED));
  assert(mbx.tbm1_addr == CHIP_STAGING_SLOT_ABS_ADDR); /* Preserved! */

  /* HIGH-23: Transient flash read error must NOT erase or reset seq to 1! */
  uint32_t erases_before = g_erase_calls;
  g_fail_reads_remaining = 1;
  assert(toob_confirm_boot() == TOOB_ERR_FLASH);
  assert(g_erase_calls == erases_before);
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.seq == 2U);

  /* Retry after transient error clears -> seq advances to 3 and merges CONFIRM! */
  assert(toob_confirm_boot() == TOOB_OK);
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.seq == 3U);
  assert(mbx.request == (TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED | TOOB_REQ_CONFIRM));
  assert(mbx.tbm1_addr == CHIP_STAGING_SLOT_ABS_ADDR);
  assert(mbx.nonce == 0x77770001ULL);

  /* New boot session (different boot_nonce) resets accumulator while keeping seq monotonic! */
  seal_handoff(TOOB_STATE_TENTATIVE, 0x88880002ULL, 0U);
  assert(toob_confirm_boot() == TOOB_OK);
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.seq == 4U);
  assert(mbx.request == TOOB_REQ_CONFIRM);
  assert(mbx.tbm1_addr == 0U);
  assert(mbx.nonce == 0x88880002ULL);
}

/* ============================================================================
 * Test 4: CRIT-25 toob_confirm_boot Idempotence, Nonce==0, Write Error Prop
 * ============================================================================ */
static void test_crit25_confirm_boot(void) {
  printf("[TEST 4] CRIT-25: toob_confirm_boot COMMITTED no-op, nonce==0, error propagation...\n");
  reset_mock_flash();

  /* 4a. Already COMMITTED -> TOOB_OK with zero flash writes/erases! */
  seal_handoff(TOOB_STATE_COMMITTED, 0xABCDEF01ULL, 0U);
  assert(toob_confirm_boot() == TOOB_OK);
  assert(g_write_calls == 0U);
  assert(g_erase_calls == 0U);

  /* 4b. TENTATIVE with boot_nonce == 0 -> rejected with TOOB_ERR_VERIFY! */
  seal_handoff(TOOB_STATE_TENTATIVE, 0ULL, 0U);
  assert(toob_confirm_boot() == TOOB_ERR_VERIFY);
  assert(g_write_calls == 0U);

  /* 4c. TENTATIVE with valid nonce + flash write failure -> error propagated! */
  seal_handoff(TOOB_STATE_TENTATIVE, 0x123456789ABCDEF0ULL, 0U);
  g_fail_writes_remaining = 1;
  assert(toob_confirm_boot() == TOOB_ERR_FLASH);

  /* Succeeds once flash write succeeds */
  assert(toob_confirm_boot() == TOOB_OK);
  toob_mailbox_t mbx;
  assert(read_freshest_mailbox(&mbx));
  assert(mbx.request == TOOB_REQ_CONFIRM);
  assert(mbx.nonce == 0x123456789ABCDEF0ULL);
}

/* ============================================================================
 * Test 5: CRIT-27, MED-24 & ARCH-CBOR-01 TDR1 Wire Diag & Padding Zeroization
 * ============================================================================ */
static void test_diag_wire_and_padding(void) {
  printf("[TEST 5] CRIT-27, MED-24 & ARCH-CBOR-01: TDR1 wire telemetry bounds & v3 padding zeroization...\n");
  memset(&toob_diag_state, 0, sizeof(toob_diag_state));
  toob_diag_state.struct_version = TOOB_DIAG_STRUCT_VERSION;
  toob_diag_state.boot_duration_ms = 42U;
  toob_diag_state.edge_recovery_events = 1U;
  toob_diag_state.hardware_fault_record = 0U;
  toob_diag_state.vendor_error = 0U;
  toob_diag_state.wdt_kicks = 7U;
  toob_diag_state.current_svn = 12U;
  toob_diag_state.active_key_index = 2U;
  toob_diag_state.fallback_occurred = 1U;
  toob_diag_state.boot_session_id = 99U;
  memset(toob_diag_state.sbom_digest, 0xAB, 32U);
  toob_diag_state.ext_health_present = 1U;
  toob_diag_state.ext_health.wal_erase_count = 10U;
  toob_diag_state.ext_health.app_slot_erase_count = 20U;
  toob_diag_state.ext_health.staging_slot_erase_count = 30U;
  toob_diag_state.ext_health.swap_buffer_erase_count = 40U;

  /* Poison all three padding regions prior to sealing CRC */
  memset(toob_diag_state._padding_v3, 0xDE, sizeof(toob_diag_state._padding_v3));
  memset(toob_diag_state._padding, 0xAD, sizeof(toob_diag_state._padding));
  toob_diag_state.crc32_trailer = toob_lib_crc32(
      (const uint8_t *)&toob_diag_state,
      offsetof(toob_boot_diag_t, crc32_trailer));
  memset(toob_diag_state._padding_end, 0xBE, sizeof(toob_diag_state._padding_end));

  /* Verify padding zeroization in toob_get_boot_diag */
  toob_boot_diag_t out_diag;
  memset(&out_diag, 0xFF, sizeof(out_diag));
  assert(toob_get_boot_diag(&out_diag) == TOOB_OK);
  for (size_t i = 0U; i < sizeof(out_diag._padding_v3); i++) {
    assert(out_diag._padding_v3[i] == 0U);
  }
  for (size_t i = 0U; i < sizeof(out_diag._padding); i++) {
    assert(out_diag._padding[i] == 0U);
  }
  for (size_t i = 0U; i < sizeof(out_diag._padding_end); i++) {
    assert(out_diag._padding_end[i] == 0U);
  }

  /* Verify small buffer fails cleanly with *out_len == 0 and no OOB write */
  uint8_t guard_buf[32];
  memset(guard_buf, 0xEE, sizeof(guard_buf));
  size_t out_len = 0x12345678U;
  assert(toob_get_boot_diag_wire(guard_buf, 10U, &out_len) == TOOB_ERR_INVALID_ARG);
  assert(out_len == 0U);
  for (size_t i = 10U; i < sizeof(guard_buf); i++) {
    assert(guard_buf[i] == 0xEEU); /* Sentinel intact! */
  }

  /* TDR1-06: Corrupted .noinit handoff MUST fail closed instead of fabricating App/Slot0 */
  uint8_t wire_buf[256];
  memset(wire_buf, 0, sizeof(wire_buf));
  toob_handoff_state.crc32_trailer ^= 0xFFFFFFFFU;
  assert(toob_get_boot_diag_wire(wire_buf, sizeof(wire_buf), &out_len) == TOOB_ERR_VERIFY);
  assert(out_len == 0U);

  /* Reseal handoff (TENTATIVE, Slot 1) and verify canonical 152B TDR1 wire encoding + trailer CRC-32 */
  seal_handoff(TOOB_STATE_TENTATIVE, 0x123456789ABCDEF0ULL, 1U);
  toob_handoff_state.boot_failure_count = 2U;
  toob_handoff_state.net_search_accum_ms = 1500U;
  toob_handoff_state.crc32_trailer = toob_lib_crc32(
      (const uint8_t *)&toob_handoff_state,
      offsetof(toob_handoff_t, crc32_trailer));

  assert(toob_get_boot_diag_wire_seq(wire_buf, sizeof(wire_buf), 42ULL, &out_len) == TOOB_OK);
  assert(out_len == TOOB_TDR1_MAX_SIZE);
  assert(toob_wire_get_le32(&wire_buf[0]) == TOOB_TDR1_MAGIC);
  assert(wire_buf[4] == TOOB_TDR1_VERSION);
  assert(wire_buf[5] == TOOB_TDR1_PARTITION_APP);
  assert(toob_wire_get_le16(&wire_buf[6]) == TOOB_TDR1_FLAG_EXT_HEALTH);
  assert(toob_wire_get_le16(&wire_buf[8]) == TOOB_TDR1_HDR_SIZE);
  assert(wire_buf[10] == 3U);
  assert(wire_buf[11] == TOOB_TDR1_BOOT_STATE_TENTATIVE);
  assert(wire_buf[12] == 1U);
  assert(wire_buf[14] == 1U);
  assert(toob_wire_get_le64(&wire_buf[32]) == 42ULL);
  assert(toob_wire_get_le32(&wire_buf[40]) == 12U);
  assert(toob_wire_get_le32(&wire_buf[84]) == 2U);
  assert(toob_wire_get_le32(&wire_buf[88]) == 1500U);
  for (size_t i = 0U; i < 32U; i++) {
    assert(wire_buf[96U + i] == 0xABU);
  }
  assert(toob_wire_get_le32(&wire_buf[128]) == 99U);
  assert(toob_wire_get_le32(&wire_buf[132]) == 10U);
  assert(toob_wire_get_le32(&wire_buf[144]) == 40U);
  uint32_t expected_crc = toob_wire_get_le32(&wire_buf[148]);
  assert(toob_lib_crc32(wire_buf, 148U) == expected_crc);
}

/* ============================================================================
 * Test 6: HIGH-22 & HIGH-24 Staging Bounds & TCC1 Cloud Command Envelope
 * ============================================================================ */
static void test_update_bounds_and_cloud_cmd(void) {
  printf("[TEST 6] HIGH-22 & HIGH-24: Staging bounds & TCC1 cloud command submission...\n");
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x5555ULL, 0U);

  /* HIGH-22: Reject bootloader address, active slot, and tail-overflow address */
  assert(toob_set_next_update(0x00004000U) == TOOB_ERR_INVALID_ARG);
  assert(toob_set_next_update(CHIP_APP_SLOT_ABS_ADDR) == TOOB_ERR_INVALID_ARG);
  assert(toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR + CHIP_STAGING_SLOT_SIZE - 512U + 8U) ==
         TOOB_ERR_INVALID_ARG);
  /* Accept valid inactive staging base and highest valid header offset */
  assert(toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR) == TOOB_OK);
  assert(toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR + CHIP_STAGING_SLOT_SIZE - 512U) == TOOB_OK);

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  /* Flip active_slot to 1 -> Slot 1 rejected, Slot 0 accepted! */
  seal_handoff(TOOB_STATE_COMMITTED, 0x5556ULL, 1U);
  assert(toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR) == TOOB_ERR_INVALID_ARG);
  assert(toob_set_next_update(CHIP_APP_SLOT_ABS_ADDR) == TOOB_OK);
#endif

  /* HIGH-24: TCC1 Cloud Command validation & unaligned caller buffer support */
  reset_mock_flash();
  uint8_t raw_storage[2048];
  memset(raw_storage, 0, sizeof(raw_storage));
  /* Misalign caller pointer by +3 bytes to verify internal 8-aligned bounce buffer! */
  uint8_t *env = &raw_storage[3];
  uint32_t env_len = 144U; /* 64B hdr + 16B aligned params + 64B Ed25519 sig */

  toob_cloud_cmd_hdr_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic = TOOB_CLOUD_CMD_MAGIC;
  hdr.version = TOOB_CLOUD_CMD_VERSION;
  hdr.command = 1U;
  hdr.flags = 0U;
  hdr.counter_min = 7U;
  hdr.issued_at = 1700000000U;
  hdr.params_len = 10U;
  hdr.total_len = env_len;
  memset(hdr.device_id, 0xA5, 32U);
  hdr.crc32 = toob_lib_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);

  memcpy(env, &hdr, sizeof(hdr));
  memset(env + 64U, 0x11, 10U);
  memset(env + 80U, 0xEE, 64U); /* Mock Ed25519 signature */

  /* Reject undersized, oversized, unaligned-len, bad-CRC, and mismatched device_id envelopes without flash erase */
  assert(toob_submit_cloud_command(env, 64U) == TOOB_ERR_INVALID_ARG);
  assert(toob_submit_cloud_command(env, 1808U) == TOOB_ERR_INVALID_ARG);
  assert(toob_submit_cloud_command(env, 130U) == TOOB_ERR_INVALID_ARG);
  env[12] ^= 0xFFU; /* Corrupt issued_at -> header CRC mismatch */
  assert(toob_submit_cloud_command(env, env_len) == TOOB_ERR_VERIFY);
  env[12] ^= 0xFFU;
  /* TCI1-08: hdr.device_id (0xA5..A5) != handoff.device_id (0xA0..BF) -> reject BEFORE erase! */
  assert(toob_submit_cloud_command(env, env_len) == TOOB_ERR_VERIFY);
  assert(g_erase_calls == 0U);

  /* Bind hdr.device_id to local handoff.device_id + recompute header CRC -> valid TCC1 succeeds! */
  for (uint32_t i = 0U; i < 32U; i++) {
    hdr.device_id[i] = (uint8_t)(0xA0U + i);
  }
  hdr.crc32 = toob_lib_crc32((const uint8_t *)&hdr, TOOB_CLOUD_CMD_HDR_CRC_LEN);
  memcpy(env, &hdr, sizeof(hdr));
  assert(toob_submit_cloud_command(env, env_len) == TOOB_OK);
  assert(memcmp(&g_flash[CHIP_CLOUD_CMD_SLOT_ABS_ADDR], env, env_len) == 0);

  /* TCI1-05: Verify assignment_id binding across OTA pause/resume */
  seal_handoff(TOOB_STATE_COMMITTED, 0x5557ULL, 0U);
  reset_mock_flash();
  uint8_t ota_img[640];
  for (size_t i = 0U; i < sizeof(ota_img); i++) {
    ota_img[i] = (uint8_t)((i * 19U + 3U) & 0xFFU);
  }
  uint8_t ota_sha[32];
  compute_sha256(ota_img, sizeof(ota_img), ota_sha);
  uint8_t asgn_1[16];
  uint8_t asgn_2[16];
  memset(asgn_1, 0x11, sizeof(asgn_1));
  memset(asgn_2, 0x22, sizeof(asgn_2));

  toob_ota_ctx_t actx;
  assert(toob_ota_ctx_init(&actx) == TOOB_OK);
  assert(toob_ota_begin_assigned(&actx, sizeof(ota_img), ota_sha, asgn_1) == TOOB_OK);
  assert(toob_ota_process_chunk(&actx, ota_img, 300U) == TOOB_OK);
  assert(toob_ota_pause(&actx) == TOOB_OK);

  uint32_t res_off = 999U;
  assert(toob_ota_resume_assigned(&actx, sizeof(ota_img), ota_sha, asgn_1, &res_off) == TOOB_OK);
  assert(res_off == 256U);
  assert(toob_ota_pause(&actx) == TOOB_OK);

  /* Mismatched assignment_id rejects cross-campaign resume and purges stale .noinit checkpoint */
  res_off = 999U;
  assert(toob_ota_resume_assigned(&actx, sizeof(ota_img), ota_sha, asgn_2, &res_off) == TOOB_ERR_NOT_FOUND);
  assert(res_off == 0U);
  assert(toob_ota_resume_assigned(&actx, sizeof(ota_img), ota_sha, asgn_1, &res_off) == TOOB_ERR_NOT_FOUND);
  assert(toob_ota_abort(&actx) == TOOB_OK);
}

/* ============================================================================
 * Test 7: Stage-0 / Lower-Flash Immutable Boot Write-Firewall
 * ============================================================================ */
static void test_stage0_immutable_boot_firewall(void) {
  printf("[TEST 7] Stage-0 / Lower-Flash Immutable Boot Write-Firewall...\n");
  reset_mock_flash();
  seal_handoff(TOOB_STATE_COMMITTED, 0x6666ULL, 0U);

  assert(CHIP_FLASH_IMMUTABLE_BOOT_END == 0x00004000U);
  assert(toob_flash_range_hits_immutable_boot(0x00000000U, 256U) == true);
  assert(toob_flash_range_hits_immutable_boot(CHIP_FLASH_IMMUTABLE_BOOT_END - 8U, 16U) == true);
  assert(toob_flash_range_hits_immutable_boot(0xFFFFFF00U, 0x200U) == true);
  assert(toob_flash_range_hits_immutable_boot(CHIP_STAGING_SLOT_ABS_ADDR, 256U) == false);

  /* Populate Stage-0 flash with sentinel bytes to prove zero disturbance */
  memset(&g_flash[0], 0x3CU, CHIP_FLASH_IMMUTABLE_BOOT_END);

  /* 7a. toob_set_next_update rejects addresses in Stage-0 / < CHIP_FLASH_IMMUTABLE_BOOT_END */
  assert(toob_set_next_update(0x00000000U) == TOOB_ERR_INVALID_ARG);
  assert(toob_set_next_update(CHIP_FLASH_IMMUTABLE_BOOT_END - 512U) == TOOB_ERR_INVALID_ARG);
  assert(g_write_calls == 0U && g_erase_calls == 0U);

  /* 7b. OTA write/erase firewall rejects corrupted write_cursor targeting Stage-0 */
  uint8_t chunk[256];
  memset(chunk, 0xAAU, sizeof(chunk));

  toob_ota_ctx_t ctx;
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, 512U, NULL) == TOOB_OK);
  ctx.write_cursor = 0x00000000U; /* Corrupt cursor into Stage-0 region */
  assert(toob_ota_process_chunk(&ctx, chunk, sizeof(chunk)) == TOOB_ERR_FLASH);
  assert(g_write_calls == 0U && g_erase_calls == 0U);
  for (uint32_t i = 0U; i < CHIP_FLASH_IMMUTABLE_BOOT_END; i++) {
    assert(g_flash[i] == 0x3CU);
  }

  /* 7c. OTA write/erase firewall rejects cursor outside [target_addr, target_addr + target_size) */
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, 512U, NULL) == TOOB_OK);
  ctx.write_cursor = CHIP_STAGING_SLOT_ABS_ADDR + CHIP_STAGING_SLOT_SIZE;
  assert(toob_ota_process_chunk(&ctx, chunk, sizeof(chunk)) == TOOB_ERR_FLASH);
  assert(g_write_calls == 0U && g_erase_calls == 0U);

  /* 7d. OTA finalize rejects corrupted write_cursor targeting Stage-0 even with buf_len == 0 */
  assert(toob_ota_ctx_init(&ctx) == TOOB_OK);
  assert(toob_ota_begin(&ctx, 256U, NULL) == TOOB_OK);
  assert(toob_ota_process_chunk(&ctx, chunk, sizeof(chunk)) == TOOB_OK);
  uint32_t writes_after_valid = g_write_calls;
  ctx.write_cursor = 0x00000100U; /* Corrupt cursor -> derived target_addr == 0x00000000 */
  assert(toob_ota_finalize(&ctx) == TOOB_ERR_FLASH);
  assert(g_write_calls == writes_after_valid);
  for (uint32_t i = 0U; i < CHIP_FLASH_IMMUTABLE_BOOT_END; i++) {
    assert(g_flash[i] == 0x3CU);
  }
}

int main(void) {
  printf("=========================================================\n");
  printf("   libtoob Host Safety & Non-Brickability Test Suite\n");
  printf("=========================================================\n");

  test_crit23_dual_slot_and_fail_closed();
  test_ota_incremental_resume_and_bounds();
  test_mailbox_cumulative_and_io_err();
  test_crit25_confirm_boot();
  test_diag_wire_and_padding();
  test_update_bounds_and_cloud_cmd();
  test_stage0_immutable_boot_firewall();

  printf("=========================================================\n");
  printf("   ALL LIBTOOB SAFETY TESTS PASSED!\n");
  printf("=========================================================\n");
  return 0;
}
