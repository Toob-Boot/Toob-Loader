#ifndef TOOB_BOOT_TBM1_H
#define TOOB_BOOT_TBM1_H

/**
 * @file boot_tbm1.h
 * @brief TBM1 v2 — Toob Boot Manifest Fixed-Format (K2)
 *
 * 512-byte page-aligned fixed header with Region Directory and trailing
 * Ed25519 signature. Designed as the last breaking revision — all future
 * growth is additive via the 148-byte reserved tail and new region IDs.
 *
 * Wire format: all integers little-endian, all offsets relative to TBM1 start.
 * Layout: [Fixed Header 512][Variable Regions…][Ed25519 Signature 64]
 *
 * See docs/tbm1_format.md for the wire format specification.
 *
 * NOTE: "TBM1" is the format FAMILY name, not the version number.
 * The schema version within the TBM1 family is version_major (currently 2).
 *
 * Hard format limits (exceeding requires a new major version):
 *   TBM1_MAX_IMAGES  = 4   (fixed array at fixed offset)
 *   TBM1_MAX_REGIONS = 8   (fixed array at fixed offset)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "boot_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Magic & Version --------------------------------------------------- */

/** 'TBM1' in little-endian: T=0x54, B=0x42, M=0x4D, 1=0x31 */
#define TBM1_MAGIC              0x314D4254U

#define TBM1_VERSION_MAJOR      2
#define TBM1_VERSION_MINOR      0
#define TBM1_FIXED_LEN          512
#define TBM1_SIG_LEN            64
/** Hard format ceiling — exceeding requires a major version bump. */
#define TBM1_MAX_IMAGES         4
/** Hard format ceiling — exceeding requires a major version bump. */
#define TBM1_MAX_REGIONS        8

/* ---- flags_critical bits (unknown bit → must reject) ------------------- */

#define TBM1_CRIT_PQC_REQUIRED      (1U << 0)

/** Bitmask of all flags_critical bits this reader understands. */
#define TBM1_CRIT_KNOWN_MASK        (TBM1_CRIT_PQC_REQUIRED)

/* ---- flags_info bits (unknown bit → safe to ignore) -------------------- */

#define TBM1_INFO_DEVICE_BIND       (1U << 0)

/* ---- Region Directory IDs ---------------------------------------------- */

enum {
  TBM1_REGION_NONE          = 0,
  TBM1_REGION_CHUNK_HASHES  = 1,
  TBM1_REGION_PQC_SIGNATURE = 2,
  TBM1_REGION_PQC_PUBKEY    = 3,
  TBM1_REGION_DEVICE_BIND   = 4,
  TBM1_REGION_DELTA_SCRIPT  = 5,
  /* 6..127 reserved for future standard use, 128..255 vendor-specific */
};

/* ---- Compression / Delta Algorithm Enums ------------------------------- */

enum {
  TBM1_COMP_NONE       = 0,
  TBM1_COMP_HEATSHRINK = 1,
  TBM1_COMP_LZ4        = 2,
};

enum {
  TBM1_DELTA_NONE    = 0,
  TBM1_DELTA_BSDIFF  = 1,
  TBM1_DELTA_DETOOLS = 2,
};

/* ---- Target Slot IDs --------------------------------------------------- */

enum {
  TBM1_SLOT_APP      = 0,
  TBM1_SLOT_NETCORE  = 1,
  TBM1_SLOT_RECOVERY = 2,
  TBM1_SLOT_STAGE1   = 3,
};

/* ---- Region Directory Entry -------------------------------------------- */

/**
 * @brief Uniform offset+length reference to a variable-length data region.
 *
 * All offsets are relative to TBM1 start. Validation rule (overflow-safe):
 *   off <= total_len && len <= total_len - off
 */
typedef struct __attribute__((packed)) {
  uint16_t region_id;   /**< TBM1_REGION_* enum value, 0 = empty slot */
  uint16_t _rsvd;       /**< Encoder: must set to 0. Reader: must not reject on non-zero. */
  uint32_t off;         /**< Offset from TBM1 start */
  uint32_t len;         /**< Byte length of region data */
} tbm1_region_t;

_Static_assert(sizeof(tbm1_region_t) == 12, "TBM1 region entry layout drift");

/* ---- Image Descriptor -------------------------------------------------- */

/**
 * @brief Per-component image descriptor (44 bytes).
 *
 * Unused slots (index >= image_count) must be zeroed.
 */
typedef struct __attribute__((packed)) {
  uint8_t  image_type;       /**< 0..127 standard, 128..255 vendor */
  uint8_t  target_slot;      /**< TBM1_SLOT_* — target region in flash */
  uint8_t  compression_alg;  /**< TBM1_COMP_* enum */
  uint8_t  delta_alg;        /**< TBM1_DELTA_* enum */
  uint32_t data_off;         /**< Offset of image bytes in staging area */
  uint32_t stored_size;      /**< Bytes stored in staging (compressed/delta) */
  uint32_t installed_size;   /**< Bytes after decompression/patching */
  uint32_t chunk_size;       /**< Streaming block size (typically 4096) */
  uint32_t num_chunks;       /**< ceil(installed_size / chunk_size) */
  uint32_t base_svn;         /**< Delta: expected base SVN (0 = n/a) */
  uint16_t ver_major;        /**< Semantic version of this image */
  uint16_t ver_minor;
  uint16_t ver_patch;
  uint16_t _rsvd;            /**< Encoder: must set to 0. Reader: must not reject on non-zero. */
  uint8_t  base_fingerprint[8]; /**< Delta: 8-byte truncated SHA-256 of base */
} tbm1_image_desc_t;

_Static_assert(sizeof(tbm1_image_desc_t) == 44,
               "TBM1 image descriptor layout drift");

/* ---- Main Header (Fixed Block = 512 Bytes) ----------------------------- */

/**
 * @brief TBM1 v2 main header — the "manifest" the boot path reads.
 *
 * The Ed25519 signature is the last 64 bytes of the *total block*
 * (not embedded in the fixed header). It signs [0 .. total_len - 64).
 *
 * Layout in staging:
 *   [Fixed Header 512][Variable Regions…][Ed25519 Signature 64]
 *
 * fixed_crc32 (last 4 bytes of the fixed header) is a CRC32 pre-check
 * over [0..508) — catches staging corruption before expensive Ed25519.
 */
typedef struct __attribute__((packed)) {
  /* ---- Identity & Version (16 bytes) ---- */
  uint32_t magic;                /**< TBM1_MAGIC ('TBM1' LE) */
  uint8_t  version_major;        /**< Breaking changes */
  uint8_t  version_minor;        /**< Additive changes only */
  uint16_t fixed_len;            /**< Must be TBM1_FIXED_LEN (512) */
  uint32_t total_len;            /**< Entire block: fixed + variable + sig */
  uint16_t flags_critical;       /**< Unknown bit → must reject */
  uint16_t flags_info;           /**< Unknown bit → safe to ignore */

  /* ---- Hardware Compatibility (8 bytes) ---- */
  uint16_t vendor_id;            /**< Manufacturer identifier */
  uint16_t product_id;           /**< Product family */
  uint16_t hw_rev_min;           /**< Minimum hardware revision */
  uint16_t hw_rev_max;           /**< Maximum hardware revision */

  /* ---- Security & Lifecycle (12 bytes) ---- */
  uint8_t  key_index;            /**< eFuse public key slot (0–255) */
  uint8_t  image_count;          /**< Valid image descriptors (1–4) */
  uint16_t boot_retry_limit;     /**< Max WAL error counter */
  uint16_t min_reader_major;     /**< Bootloader rejects if its major < this */
  uint16_t min_reader_minor;     /**< Bootloader rejects if major matches but minor < this */

  /* ---- Anti-Rollback & Build Info (24 bytes) ---- */
  uint32_t svn;                  /**< Security Version Number (app) */
  uint32_t stage1_svn;           /**< P7a stage-1 SVN (0 = not present) */
  uint32_t key_epoch;            /**< Required eFuse key revocation epoch */
  uint32_t build_number;         /**< CI build number for telemetry */
  uint16_t fw_ver_major;         /**< Firmware semantic version */
  uint16_t fw_ver_minor;
  uint16_t fw_ver_patch;
  uint16_t _rsvd0;               /**< Encoder: must set to 0. Reader: must not reject on non-zero. */

  /* ---- SBOM Digest (32 bytes) ---- */
  uint8_t  sbom_digest[32];      /**< EU-CRA SBOM SHA-256 */

  /* ---- Region Directory (96 bytes = 8 × 12) ---- */
  tbm1_region_t regions[TBM1_MAX_REGIONS];

  /* ---- Image Descriptors (176 bytes = 4 × 44) ---- */
  tbm1_image_desc_t images[TBM1_MAX_IMAGES];

  /* ---- Reserved Tail for Additive Growth (148 bytes) ---- */
  uint8_t  _reserved_tail[148];  /**< Additive growth area for future minor versions.
                                  *   Encoder: must zero all unused bytes.
                                  *   Reader: must NOT reject on non-zero (signed area
                                  *   guarantees only the legitimate signer fills it;
                                  *   unknown bytes are semantically ignored). */

  /* ---- CRC32 Pre-Check (4 bytes) ---- */
  uint32_t fixed_crc32;          /**< CRC32 over [0..508), fast staging check */
} tbm1_header_t;

/* ---- Compile-Time ABI Invariants --------------------------------------- */

_Static_assert(sizeof(tbm1_header_t) == 512,
               "TBM1 fixed header must be exactly 512 bytes (one flash page)");
_Static_assert(offsetof(tbm1_header_t, magic) == 0,
               "TBM1 magic offset drift");
_Static_assert(offsetof(tbm1_header_t, total_len) == 8,
               "TBM1 total_len offset drift");
_Static_assert(offsetof(tbm1_header_t, vendor_id) == 16,
               "TBM1 vendor_id offset drift");
_Static_assert(offsetof(tbm1_header_t, key_index) == 24,
               "TBM1 key_index offset drift");
_Static_assert(offsetof(tbm1_header_t, svn) == 32,
               "TBM1 svn offset drift");
_Static_assert(offsetof(tbm1_header_t, sbom_digest) == 56,
               "TBM1 sbom_digest offset drift");
_Static_assert(offsetof(tbm1_header_t, regions) == 88,
               "TBM1 region directory offset drift");
_Static_assert(offsetof(tbm1_header_t, images) == 184,
               "TBM1 image descriptors offset drift");
_Static_assert(offsetof(tbm1_header_t, _reserved_tail) == 360,
               "TBM1 reserved tail offset drift");
_Static_assert(offsetof(tbm1_header_t, fixed_crc32) == 508,
               "TBM1 CRC32 must be the last 4 bytes of the fixed header");

/* ---- Derived Constants ------------------------------------------------- */

/** CRC32 covers [0..508) — everything except the CRC32 field itself. */
#define TBM1_CRC_LEN  (TBM1_FIXED_LEN - sizeof(uint32_t))

/**
 * @brief Compute the signed region length: [0 .. total_len − 64).
 *
 * Returns 0 if total_len is too small to contain the fixed header plus
 * trailing signature — the caller must treat 0 as a reject.
 */
static inline size_t tbm1_signed_len(const tbm1_header_t *hdr) {
  if (hdr->total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) return 0;
  return (size_t)hdr->total_len - TBM1_SIG_LEN;
}

/* ---- Region Directory Accessor ----------------------------------------- */

/**
 * @brief Find a region entry by ID in the directory.
 *
 * Returns NULL if @p id is TBM1_REGION_NONE (0) — prevents accidental
 * matches against empty directory slots. Duplicate region IDs are rejected
 * during validation (see tbm1_validate in boot_state.c); this function
 * should only be called on a validated header.
 *
 * @param hdr  Pointer to a validated TBM1 header.
 * @param id   Region ID to search for (must be != 0).
 * @return Pointer to the matching region entry, or NULL.
 */
static inline const tbm1_region_t *
tbm1_find_region(const tbm1_header_t *hdr, uint16_t id) {
  if (id == TBM1_REGION_NONE) return NULL;
  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++) {
    if (hdr->regions[i].region_id == id)
      return &hdr->regions[i];
  }
  return NULL;
}

/* ---- Reject Taxonomy --------------------------------------------------- */

/**
 * @brief Distinct reject codes for TBM1 validation stages.
 *
 * Each code maps to exactly one failure mode, enabling field telemetry to
 * distinguish "staging corrupt" from "wrong product" from "too-old reader"
 * without device returns. Mapped to boot_status_t via tbm1_reject_to_boot_status().
 */
typedef enum {
  TBM1_OK = 0,
  TBM1_BAD_MAGIC,           /**< magic != TBM1_MAGIC */
  TBM1_BAD_FIXED_LEN,       /**< fixed_len != 512 */
  TBM1_BAD_VERSION,         /**< version_major != TBM1_VERSION_MAJOR */
  TBM1_BAD_TOTAL_LEN,       /**< total_len too small or exceeds staging capacity */
  TBM1_BAD_CRC,             /**< fixed_crc32 pre-check failed (staging corrupt) */
  TBM1_BAD_CRIT_FLAG,       /**< Unknown flags_critical bit set */
  TBM1_BAD_READER_VERSION,  /**< min_reader_* exceeds this reader's version */
  TBM1_BAD_IMAGE_COUNT,     /**< image_count not in [1..TBM1_MAX_IMAGES] */
  TBM1_BAD_KEY_INDEX,       /**< key_index >= provisioned key slots */
  TBM1_BAD_HW_COMPAT,       /**< product_id or hw_rev mismatch */
  TBM1_BAD_CHUNK_MATH,      /**< chunk_size==0, num_chunks mismatch, or bad slot */
  TBM1_BAD_REGION_BOUNDS,   /**< Region off/len exceeds signed area */
  TBM1_BAD_REGION_ORDER,    /**< Regions not ascending or overlapping */
  TBM1_BAD_REGION_DUP,      /**< Duplicate region_id in directory */
  TBM1_BAD_CHUNKHASH_LEN,   /**< REGION_CHUNK_HASHES len != Σ(num_chunks_i)×32 */
} tbm1_reject_t;

/* ---- Compile-Time Device Identity Defaults ----------------------------- */
/* Override via generated_boot_config.h or -D flags for production builds.   */

#ifndef TOOB_DEVICE_PRODUCT_ID
#define TOOB_DEVICE_PRODUCT_ID  0xFFFFU  /**< Unset → skip HW-compat check */
#endif

#ifndef TOOB_DEVICE_HW_REV
#define TOOB_DEVICE_HW_REV     0U
#endif

#ifndef TOOB_DEVICE_KEY_SLOTS
#define TOOB_DEVICE_KEY_SLOTS  6U  /**< ESP32-C6: 6 eFuse key blocks */
#endif

/* ---- Validation API (boot_tbm1.c) -------------------------------------- */

/** Structural pre-checks before any field is trusted. Includes CRC32. */
tbm1_reject_t tbm1_precheck(const uint8_t *buf, size_t staging_cap);

/** Region directory: overflow-safe bounds, ascending order, no duplicates. */
tbm1_reject_t tbm1_validate_regions(const tbm1_header_t *h);

/** Image descriptors: count, key_index, HW-compat, chunk math. */
tbm1_reject_t tbm1_validate_images(const tbm1_header_t *h);

/** Chunk-hash partitioning: region.len == Σ(num_chunks_i)×32. */
tbm1_reject_t tbm1_chunkhash_slices(const tbm1_header_t *h,
                                    uint32_t *out_off);

/** Top-level facade: precheck → regions → images → chunkhash. */
tbm1_reject_t tbm1_validate(const uint8_t *buf, size_t staging_cap);

/** Map tbm1_reject_t to boot_status_t for the pipeline error handler. */
boot_status_t tbm1_reject_to_boot_status(tbm1_reject_t rc);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_BOOT_TBM1_H */

