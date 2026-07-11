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
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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
#define TBM1_MAX_IMAGES         4
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
  uint16_t _rsvd;       /**< Must be zero */
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
  uint16_t _rsvd;            /**< Must be zero */
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
  uint16_t _rsvd0;               /**< Must be zero */

  /* ---- SBOM Digest (32 bytes) ---- */
  uint8_t  sbom_digest[32];      /**< EU-CRA SBOM SHA-256 */

  /* ---- Region Directory (96 bytes = 8 × 12) ---- */
  tbm1_region_t regions[TBM1_MAX_REGIONS];

  /* ---- Image Descriptors (176 bytes = 4 × 44) ---- */
  tbm1_image_desc_t images[TBM1_MAX_IMAGES];

  /* ---- Reserved Tail for Additive Growth (148 bytes) ---- */
  uint8_t  _reserved_tail[148];  /**< Must be zero; future minor-version fields */

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

/** Signed region: everything except the trailing 64-byte signature. */
#define TBM1_SIGNED_LEN(hdr) ((size_t)(hdr)->total_len - TBM1_SIG_LEN)

/** CRC32 covers [0..508) — everything except the CRC32 field itself. */
#define TBM1_CRC_LEN  (TBM1_FIXED_LEN - sizeof(uint32_t))

/* ---- Region Directory Accessor ----------------------------------------- */

/**
 * @brief Find a region entry by ID in the directory.
 * @return Pointer to the matching region, or NULL if not found.
 */
static inline const tbm1_region_t *
tbm1_find_region(const tbm1_header_t *hdr, uint16_t id) {
  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++) {
    if (hdr->regions[i].region_id == id)
      return &hdr->regions[i];
  }
  return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* TOOB_BOOT_TBM1_H */
