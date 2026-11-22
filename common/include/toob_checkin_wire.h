/**
 * @file toob_checkin_wire.h
 * @brief Canonical Fixed-Offset Binary Wire Contracts for Device Check-In:
 *        - TDR1 (Toob Diagnostic Report v1, MCU -> Cloud, 136B / 152B)
 *        - TCI1 (Toob Check-In Manifest v1, Cloud -> MCU, 88B hdr + var + 16B HMAC-128)
 *
 * All multi-byte integers are Little-Endian (LE).
 * Shared single source of truth across C17 (sdk/libtoob, sdk/os_client),
 * Rust (sdk/rust), and Go (toob-go-lib/tdr1, toob-go-lib/tci1).
 */

#ifndef TOOB_CHECKIN_WIRE_H
#define TOOB_CHECKIN_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Endianness Helpers (Alignment-Safe, Strict-Aliasing Clean, Zero UB)
 * ============================================================================ */

static inline uint16_t toob_wire_get_le16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8U));
}

static inline uint32_t toob_wire_get_le32(const uint8_t *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8U) |
         ((uint32_t)p[2] << 16U) | ((uint32_t)p[3] << 24U);
}

static inline uint64_t toob_wire_get_le64(const uint8_t *p) {
  return ((uint64_t)toob_wire_get_le32(&p[0])) |
         (((uint64_t)toob_wire_get_le32(&p[4])) << 32U);
}

static inline void toob_wire_put_le16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFFU);
  p[1] = (uint8_t)((v >> 8U) & 0xFFU);
}

static inline void toob_wire_put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFFU);
  p[1] = (uint8_t)((v >> 8U) & 0xFFU);
  p[2] = (uint8_t)((v >> 16U) & 0xFFU);
  p[3] = (uint8_t)((v >> 24U) & 0xFFU);
}

static inline void toob_wire_put_le64(uint8_t *p, uint64_t v) {
  toob_wire_put_le32(&p[0], (uint32_t)(v & 0xFFFFFFFFULL));
  toob_wire_put_le32(&p[4], (uint32_t)((v >> 32U) & 0xFFFFFFFFULL));
}

/* ============================================================================
 * TDR1: Toob Diagnostic Report v1 (MCU -> Cloud Check-In Request Body)
 *
 * Canonical Layout:
 *   [0 .. header_size)                           : Base header (132 B in v1)
 *   [header_size .. header_size + 16)            : Optional ext_health (if FLAG_EXT_HEALTH)
 *   [total_len - 4 .. total_len)                 : IEEE 802.3 CRC-32 trailer over [0 .. total_len - 4)
 *
 * Total Wire Size:
 *   - 136 B without ext_health (132 B header + 4 B CRC-32 trailer)
 *   - 152 B with    ext_health (132 B header + 16 B ext_health + 4 B CRC-32 trailer)
 * ============================================================================ */

#define TOOB_TDR1_MAGIC                0x31524454U /* "TDR1" in LE */
#define TOOB_TDR1_VERSION              1U
#define TOOB_TDR1_MIN_DIAG_MAJOR       3U
#define TOOB_TDR1_HDR_SIZE             132U
#define TOOB_TDR1_EXT_HEALTH_SIZE      16U
#define TOOB_TDR1_CRC_TRAILER_SIZE     4U
#define TOOB_TDR1_MIN_FRAME_SIZE       (TOOB_TDR1_HDR_SIZE + TOOB_TDR1_CRC_TRAILER_SIZE)
#define TOOB_TDR1_MAX_SIZE             (TOOB_TDR1_HDR_SIZE + TOOB_TDR1_EXT_HEALTH_SIZE + TOOB_TDR1_CRC_TRAILER_SIZE)

#define TOOB_TDR1_FLAG_EXT_HEALTH      (1U << 0)
#define TOOB_TDR1_KNOWN_FLAGS_MASK     (TOOB_TDR1_FLAG_EXT_HEALTH)

#define TOOB_TDR1_PARTITION_APP        0U
#define TOOB_TDR1_PARTITION_RECOVERY   2U

#define TOOB_TDR1_BOOT_STATE_COMMITTED 0U
#define TOOB_TDR1_BOOT_STATE_TENTATIVE 1U

#define TOOB_TDR1_MAX_RESET_REASON     6U

#define TOOB_TDR1_OUTCOME_NONE         0U
#define TOOB_TDR1_OUTCOME_APPLIED      1U
#define TOOB_TDR1_OUTCOME_REJECTED     2U
#define TOOB_TDR1_OUTCOME_REVERTED     3U
#define TOOB_TDR1_OUTCOME_DEFERRED     4U
#define TOOB_TDR1_MAX_OUTCOME          4U

typedef struct {
  uint32_t magic;                   /* 0..4   : 0x31524454 ("TDR1") */
  uint8_t  version;                 /* 4      : 1 */
  uint8_t  booted_partition;        /* 5      : 0=App, 2=Recovery */
  uint16_t flags;                   /* 6..8   : bit0 = ext_health present */
  uint16_t header_size;             /* 8..10  : >= 132, (header_size - 132) % 8 == 0 */
  uint8_t  diag_major;              /* 10     : struct_version >> 24 (>= 3) */
  uint8_t  boot_state;              /* 11     : 0=COMMITTED, 1=TENTATIVE */
  uint8_t  active_slot;             /* 12     : {0, 1} */
  uint8_t  reset_reason;            /* 13     : 0..6 */
  uint8_t  fallback_occurred;       /* 14     : {0, 1} */
  uint8_t  wipe_requested;          /* 15     : {0, 1} */
  uint8_t  last_update_outcome;     /* 16     : 0..4 */
  uint8_t  last_update_reject;      /* 17     : boot_status_t low byte / reason */
  uint16_t active_key_index;        /* 18..20 : Ed25519 root key slot */
  uint16_t reader_major;            /* 20..22 : TBM1 reader major */
  uint16_t reader_minor;            /* 22..24 : TBM1 reader minor */
  uint16_t fw_ver_major;            /* 24..26 : Active app SemVer major */
  uint16_t fw_ver_minor;            /* 26..28 : Active app SemVer minor */
  uint16_t fw_ver_patch;            /* 28..30 : Active app SemVer patch */
  uint16_t _reserved0;              /* 30..32 : Must be 0x0000 */
  uint32_t checkin_seq_lo;          /* 32..36 : X-Toob-Seq low 32 bits (8B aligned) */
  uint32_t checkin_seq_hi;          /* 36..40 : X-Toob-Seq high 32 bits */
  uint32_t current_svn;             /* 40..44 : Active boot SVN */
  uint32_t build_number;            /* 44..48 : Active app TBM1 build_number */
  uint32_t installed_app_svn;       /* 48..52 : Monotonic App SVN floor */
  uint32_t installed_stage1_svn;    /* 52..56 : Monotonic Stage 1 SVN floor */
  uint32_t monotonic_counter;       /* 56..60 : Anti-replay cloud cmd counter */
  uint32_t boot_duration_ms;        /* 60..64 : Stage 1 boot duration */
  uint32_t verify_time_ms;          /* 64..68 : Ed25519 + SHA-256 verify time */
  uint32_t last_error_code;         /* 68..72 : Last boot_status_t error */
  uint32_t vendor_error;            /* 72..76 : Hardware HAL sub-error */
  uint32_t hardware_fault_record;   /* 76..80 : Preserved crash fault register */
  uint32_t edge_recovery_events;    /* 80..84 : Cumulative WAL brownout recoveries */
  uint32_t recovery_failure_events; /* 84..88 : Consecutive boot_failure_count */
  uint32_t net_search_accum_ms;     /* 88..92 : Accumulated Recovery OS search ms */
  uint32_t wdt_kicks;               /* 92..96 : Stage 1 watchdog kicks */
  uint8_t  sbom_digest[32];         /* 96..128: Active SBOM SHA-256 (32B aligned) */
  uint32_t boot_session_id;         /* 128..132: Monotonic boot session counter */
} toob_tdr1_wire_hdr_t;

typedef struct {
  uint32_t wal_erase_count;         /* +0..4   */
  uint32_t app_slot_erase_count;    /* +4..8   */
  uint32_t staging_slot_erase_count;/* +8..12  */
  uint32_t swap_buffer_erase_count; /* +12..16 */
} toob_tdr1_wire_ext_health_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(toob_tdr1_wire_hdr_t) == TOOB_TDR1_HDR_SIZE,
               "toob_tdr1_wire_hdr_t must be exactly 132 bytes");
_Static_assert(sizeof(toob_tdr1_wire_ext_health_t) == TOOB_TDR1_EXT_HEALTH_SIZE,
               "toob_tdr1_wire_ext_health_t must be exactly 16 bytes");
#endif

/* ============================================================================
 * TCI1: Toob Check-In Manifest v1 (Cloud -> MCU Check-In Response Body)
 *
 * Canonical Authenticated Frame Layout:
 *   [0 .. header_size)               : Fixed 88-byte header (8B aligned)
 *   [header_size .. +blob_path_len)  : UTF-8/ASCII relative path (RFC-3986 whitelist)
 *   [.. +32)                         : Masked rotated_token (if FLAG_HAS_ROTATED_TOKEN)
 *                                      masked = raw_token XOR HMAC-SHA256(K, "TCI1-ROT-V1" || device_id[32] || le64(seq_echo))
 *   [.. +cloud_cmd_len)              : Signed TCC1 envelope (if FLAG_HAS_CLOUD_CMD)
 *   [total_len - 16 .. total_len)    : Trunc_128(HMAC-SHA256(K, "TCI1-AUTH-V1" || device_id[32] || frame[0 .. total_len - 16]))
 * ============================================================================ */

#define TOOB_TCI1_MAGIC                  0x31494354U /* "TCI1" in LE */
#define TOOB_TCI1_VERSION                1U
#define TOOB_TCI1_HDR_SIZE               88U
#define TOOB_TCI1_AUTH_TAG_LEN           16U
#define TOOB_TCI1_MIN_FRAME_SIZE         (TOOB_TCI1_HDR_SIZE + TOOB_TCI1_AUTH_TAG_LEN)
#define TOOB_TCI1_ROTATED_TOKEN_LEN      32U
#define TOOB_TCI1_ASSIGNMENT_ID_LEN      16U
#define TOOB_TCI1_MAX_BLOB_PATH_LEN      120U
#define TOOB_TCI1_MIN_CLOUD_CMD_LEN      128U
#define TOOB_TCI1_MAX_CLOUD_CMD_LEN      400U
#define TOOB_TCI1_MAX_FRAME_SIZE         512U
#define TOOB_TCI1_MIN_TBM1_TOTAL_SIZE    576U
#define TOOB_TCI1_MAX_RETRY_AFTER_SEC    604800U /* 7 days upper bound */

#define TOOB_TCI1_SLOT_APP               0U
#define TOOB_TCI1_SLOT_NETCORE           1U
#define TOOB_TCI1_SLOT_STAGE1            3U

#define TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN (1U << 0)
#define TOOB_TCI1_FLAG_HAS_CLOUD_CMD     (1U << 1)
#define TOOB_TCI1_KNOWN_FLAGS_MASK       (TOOB_TCI1_FLAG_HAS_ROTATED_TOKEN | TOOB_TCI1_FLAG_HAS_CLOUD_CMD)

#define TOOB_TCI1_AUTH_DOMAIN            "TCI1-AUTH-V1"
#define TOOB_TCI1_AUTH_DOMAIN_LEN        12U
#define TOOB_TCI1_ROT_DOMAIN             "TCI1-ROT-V1"
#define TOOB_TCI1_ROT_DOMAIN_LEN         11U

typedef struct {
  uint32_t magic;            /* 0..4   : 0x31494354 ("TCI1") */
  uint8_t  version;          /* 4      : 1 */
  uint8_t  target_slot;      /* 5      : {0=App, 1=Netcore, 3=Stage1}; 0 if control-only */
  uint16_t flags;            /* 6..8   : bit0=rotated_token, bit1=cloud_cmd */
  uint16_t header_size;      /* 8..10  : >= 88, (header_size % 8) == 0 */
  uint16_t blob_path_len;    /* 10..12 : 0 (control-only) or 2..120 (update) */
  uint16_t cloud_cmd_len;    /* 12..14 : 0 or 128..400 (16B aligned TCC1) */
  uint16_t _reserved0;       /* 14..16 : Must be 0x0000 */
  uint32_t remote_svn;       /* 16..20 : Target slot SVN (0 if control-only) */
  uint32_t total_size;       /* 20..24 : >= 576 for update; 0 for control-only */
  uint8_t  sha256[32];       /* 24..56 : Expected TBM1 SHA-256 (0x00..00 if control-only) */
  uint8_t  assignment_id[16];/* 56..72 : 16B binary UUID (0x00..00 if control-only) */
  uint32_t seq_echo_lo;      /* 72..76 : Echoed X-Toob-Seq low 32 bits (8B aligned) */
  uint32_t seq_echo_hi;      /* 76..80 : Echoed X-Toob-Seq high 32 bits */
  uint32_t remote_build;     /* 80..84 : Target TBM1 build_number (0 if control-only) */
  uint32_t retry_after_sec;  /* 84..88 : Server poll/backoff hint in seconds (<= 604800) */
} toob_tci1_wire_hdr_t;

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(toob_tci1_wire_hdr_t) == TOOB_TCI1_HDR_SIZE,
               "toob_tci1_wire_hdr_t must be exactly 88 bytes");
#endif

#ifdef __cplusplus
}
#endif

#endif /* TOOB_CHECKIN_WIRE_H */
