/**
 * @file tbm1_vectors.c
 * @brief TBM1 v2 Golden Vector Test Suite (V1 + V2)
 *
 * Standalone host test — one vector per tbm1_reject_t code, plus a
 * canonical happy-path. Vectors are constructed programmatically in C
 * (self-documenting, diffable, no binary drift).
 *
 * Build: gcc -I common/include -I toobloader/core/include \
 *            -I toobloader/core/utils/include -I sdk/libtoob/include \
 *            test/host/tbm1_vectors.c -o builds/build_host/tbm1_vectors
 * Run:   ./builds/build_host/tbm1_vectors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* Activate HW-compat checks for vector 10 */
#define TOOB_DEVICE_PRODUCT_ID  0x0042U
#define TOOB_DEVICE_HW_REV     1U
#define TOOB_DEVICE_KEY_SLOTS   6U

/* Pull in the validation module + CRC (source-level inclusion for host test) */
#include "../../toobloader/core/boot_tbm1.c"
#include "../../toobloader/core/utils/boot_crc32.c"

/* ========================================================================
 * Helpers
 * ======================================================================== */

#define BUF_SIZE 1024

/**
 * @brief Fill a minimal valid TBM1 header that passes tbm1_validate().
 *
 * Layout: 512 fixed header + (chunk hashes at offset 512, len 32) + padding
 *         to total_len, trailing 64-byte signature at [total_len - 64].
 *
 * Single image: 4096 bytes installed, 4096 chunk_size → 1 chunk → 32 bytes hash.
 */
static void make_valid_header(uint8_t *buf, size_t buf_len) {
  memset(buf, 0, buf_len);
  tbm1_header_t *h = (tbm1_header_t *)buf;

  /* Identity & Version */
  h->magic         = TBM1_MAGIC;
  h->version_major = TBM1_VERSION_MAJOR;
  h->version_minor = TBM1_VERSION_MINOR;
  h->fixed_len     = TBM1_FIXED_LEN;
  h->total_len     = (uint32_t)buf_len;
  h->flags_critical = 0;
  h->flags_info     = 0;

  /* HW Compatibility (must match TOOB_DEVICE_* defines above) */
  h->vendor_id   = 0x0001;
  h->product_id  = TOOB_DEVICE_PRODUCT_ID;
  h->hw_rev_min  = 0;
  h->hw_rev_max  = 10;

  /* Security & Lifecycle */
  h->key_index        = 0;
  h->image_count      = 1;
  h->boot_retry_limit = 3;
  h->min_reader_major = 0;
  h->min_reader_minor = 0;

  /* Anti-Rollback */
  h->svn          = 1;
  h->stage1_svn   = 0;
  h->key_epoch    = 0;
  h->build_number = 100;
  h->fw_ver_major = 1;
  h->fw_ver_minor = 0;
  h->fw_ver_patch = 0;

  /* Region Directory: one entry for CHUNK_HASHES at offset 512, len 32 */
  h->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  h->regions[0]._rsvd     = 0;
  h->regions[0].off       = TBM1_FIXED_LEN;
  h->regions[0].len       = 32;  /* 1 chunk × 32 bytes */

  /* Image Descriptors: 1 image, 4096 bytes, 1 chunk of 4096 */
  h->images[0].image_type     = 0;
  h->images[0].target_slot    = TBM1_SLOT_APP;
  h->images[0].compression_alg = TBM1_COMP_NONE;
  h->images[0].delta_alg      = TBM1_DELTA_NONE;
  h->images[0].data_off       = 0;
  h->images[0].stored_size    = 4096;
  h->images[0].installed_size = 4096;
  h->images[0].chunk_size     = 4096;
  h->images[0].num_chunks     = 1;

  /* CRC32 over [0..508) — must be set LAST */
  h->fixed_crc32 = compute_boot_crc32(buf, TBM1_CRC_LEN);
}

/** Recompute fixed_crc32 after mutating header fields (for post-CRC tests). */
static void fixup_crc(uint8_t *buf) {
  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->fixed_crc32 = compute_boot_crc32(buf, TBM1_CRC_LEN);
}

/** Test wrapper: calls tbm1_validate with a stack-local out_off array. */
static tbm1_reject_t validate_buf(const uint8_t *buf, size_t cap) {
  uint32_t out_off[TBM1_MAX_IMAGES];
  return tbm1_validate(buf, cap, cap, out_off);
}

/* ========================================================================
 * V1 — Golden Vectors: one per tbm1_reject_t code
 * ======================================================================== */

static void test_happy_path(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_reject_t rc = validate_buf(buf, sizeof(buf));
  assert(rc == TBM1_OK);
  printf("  [PASS] V0  Happy-Path\n");
}

static void test_bad_magic(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->magic = 0xDEADBEEF;
  /* No CRC fixup: magic is checked before CRC */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_MAGIC);
  printf("  [PASS] V1  BAD_MAGIC\n");
}

static void test_bad_fixed_len(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->fixed_len = 256;
  /* No CRC fixup: fixed_len is checked before CRC */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_FIXED_LEN);
  printf("  [PASS] V2  BAD_FIXED_LEN\n");
}

static void test_bad_version(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->version_major = 99;
  /* No CRC fixup: version is checked before CRC */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_VERSION);
  printf("  [PASS] V3  BAD_VERSION\n");
}

static void test_bad_total_len_small(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->total_len = 100;  /* < TBM1_FIXED_LEN + TBM1_SIG_LEN (576) */
  /* No CRC fixup: total_len is checked before CRC */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_TOTAL_LEN);
  printf("  [PASS] V4a BAD_TOTAL_LEN (too small)\n");
}

static void test_bad_total_len_exceeds(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->total_len = BUF_SIZE + 1;  /* > staging capacity */
  /* No CRC fixup: total_len is checked before CRC */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_TOTAL_LEN);
  printf("  [PASS] V4b BAD_TOTAL_LEN (exceeds staging)\n");
}

static void test_bad_crc(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->fixed_crc32 ^= 1;  /* 1-bit flip → CRC mismatch */

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_CRC);
  printf("  [PASS] V5  BAD_CRC\n");
}

static void test_bad_crit_flag(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->flags_critical = 0x8000;  /* Unknown critical bit */
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_CRIT_FLAG);
  printf("  [PASS] V6  BAD_CRIT_FLAG\n");
}

static void test_bad_reader_version(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->min_reader_major = 255;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_READER_VERSION);
  printf("  [PASS] V7  BAD_READER_VERSION\n");
}

static void test_bad_image_count(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->image_count = 0;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_IMAGE_COUNT);
  printf("  [PASS] V8  BAD_IMAGE_COUNT\n");
}

static void test_bad_key_index(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->key_index = TOOB_DEVICE_KEY_SLOTS;  /* == 6, exactly one past valid range */
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_KEY_INDEX);
  printf("  [PASS] V9  BAD_KEY_INDEX\n");
}

static void test_bad_hw_compat(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->product_id = 0xBEEF;  /* Mismatch vs TOOB_DEVICE_PRODUCT_ID (0x0042) */
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_HW_COMPAT);
  printf("  [PASS] V10 BAD_HW_COMPAT\n");
}

static void test_bad_chunk_math(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  h->images[0].chunk_size = 0;  /* Division-by-zero guard */
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_CHUNK_MATH);
  printf("  [PASS] V11 BAD_CHUNK_MATH\n");
}

static void test_bad_region_bounds(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* Region offset past signed area (total_len - 64 = 960) */
  h->regions[0].off = 961;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_REGION_BOUNDS);
  printf("  [PASS] V12 BAD_REGION_BOUNDS\n");
}

static void test_bad_region_order(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* Two regions, second comes before first → non-ascending */
  h->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  h->regions[0].off = 600;
  h->regions[0].len = 32;
  h->regions[1].region_id = TBM1_REGION_DEVICE_BIND;
  h->regions[1].off = 520;  /* Before region[0] ends (600+32=632) */
  h->regions[1].len = 32;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_REGION_ORDER);
  printf("  [PASS] V13 BAD_REGION_ORDER\n");
}

static void test_bad_region_dup(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* Two regions with same ID */
  h->regions[0].region_id = TBM1_REGION_CHUNK_HASHES;
  h->regions[0].off = 512;
  h->regions[0].len = 32;
  h->regions[1].region_id = TBM1_REGION_CHUNK_HASHES;  /* Duplicate! */
  h->regions[1].off = 600;
  h->regions[1].len = 32;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_REGION_DUP);
  printf("  [PASS] V14 BAD_REGION_DUP\n");
}

static void test_bad_chunkhash_len(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* 1 chunk → expects 32 bytes, but region says 0 */
  h->regions[0].len = 0;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_CHUNKHASH_LEN);
  printf("  [PASS] V15 BAD_CHUNKHASH_LEN\n");
}

static void test_bad_region_alignment(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* Make region offset misaligned (e.g. 513 instead of 512) */
  h->regions[0].off = 513;
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_REGION_ALIGN);
  printf("  [PASS] V16 BAD_REGION_ALIGN\n");
}

/* ========================================================================
 * V2 — Encoder Interop: off-by-one chunk-hash length
 * ======================================================================== */

static void test_chunkhash_off_by_one(void) {
  uint8_t buf[BUF_SIZE] __attribute__((aligned(4)));
  make_valid_header(buf, sizeof(buf));

  tbm1_header_t *h = (tbm1_header_t *)buf;
  /* Simulate encoder bug: one byte too many in chunk-hash region */
  h->regions[0].len = 33;  /* Should be 32 (1 chunk × 32) */
  fixup_crc(buf);

  assert(validate_buf(buf, sizeof(buf)) == TBM1_BAD_CHUNKHASH_LEN);
  printf("  [PASS] V2-interop: Off-by-one chunk-hash caught\n");
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void) {
  printf("==================================================\n");
  printf("   TBM1 v2 Golden Vector Test Suite (V1 + V2)\n");
  printf("==================================================\n\n");

  printf("[V1] Structural Vectors:\n");
  test_happy_path();
  test_bad_magic();
  test_bad_fixed_len();
  test_bad_version();
  test_bad_total_len_small();
  test_bad_total_len_exceeds();
  test_bad_crc();
  test_bad_crit_flag();
  test_bad_reader_version();
  test_bad_image_count();
  test_bad_key_index();
  test_bad_hw_compat();
  test_bad_chunk_math();
  test_bad_region_bounds();
  test_bad_region_order();
  test_bad_region_dup();
  test_bad_chunkhash_len();
  test_bad_region_alignment();

  printf("\n[V2] Encoder Interop Vectors:\n");
  test_chunkhash_off_by_one();

  printf("\n==================================================\n");
  printf("   ALL %d VECTORS PASSED\n", 19);
  printf("==================================================\n");

  return 0;
}
