/**
 * @file toob_mailbox_wire.h
 * @brief Neutral OS <-> Core mailbox wire format (single source of truth).
 *
 * Contains ONLY the on-flash record and geometry contract — no status type, no
 * function declarations — so it can be included from both sides without dragging
 * in libtoob_types.h (OS) or boot_types.h (Core). Pure C17, no C++ linkage block
 * needed (data only).
 *
 * Two-sector A/B: TOOB_MAILBOX_SLOTS independent erase sectors, one record each.
 * The writer targets the stale slot and erases only that sector; the reader takes
 * the valid slot with the highest `seq`. See toob_mailbox.c (writer) and
 * boot_mailbox.c (reader).
 */

#ifndef TOOB_MAILBOX_WIRE_H
#define TOOB_MAILBOX_WIRE_H

#include <stdint.h>
#include <stddef.h>

/* 'TMBX' little-endian */
#define TOOB_MAILBOX_MAGIC   0x58424D54U
#define TOOB_MAILBOX_VERSION 2U
#define TOOB_MAILBOX_SLOTS   2U

/**
 * @brief Cumulative mailbox request bitflags (v2).
 * Orthogonal bit positions allow combining intents emitted within the same OS
 * or Recovery boot session (e.g., TOOB_REQ_UPDATE_PENDING | TOOB_REQ_CONFIRM,
 * or TOOB_REQ_UPDATE_PENDING | TOOB_REQ_RECOVERY_RESOLVED) without overwriting
 * an earlier unconsumed intent.
 */
#define TOOB_REQ_NONE              0x0000U
#define TOOB_REQ_UPDATE_PENDING    0x0001U /* (1U << 0): tbm1_addr = flat-package address */
#define TOOB_REQ_CONFIRM           0x0002U /* (1U << 1): nonce     = boot_nonce being confirmed */
#define TOOB_REQ_RECOVERY_RESOLVED 0x0004U /* (1U << 2): clear recovery latch / failure counter */
#define TOOB_REQ_ALL_MASK          0x0007U

typedef uint16_t toob_req_t;

#if defined(__GNUC__) || defined(__clang__) || defined(__ICCARM__)
#  define TOOB_MBX_ALIGN8 __attribute__((aligned(8)))
#elif defined(_MSC_VER)
#  define TOOB_MBX_ALIGN8 __declspec(align(8))
#else
#  define TOOB_MBX_ALIGN8
#endif

/**
 * @brief One mailbox record. Fixed little-endian wire format, 32 bytes.
 * Naturally aligned without non-portable `packed`; verified via _Static_assert.
 * `nonce` is naturally 8-aligned. CRC-32 covers [0 .. offsetof(crc32));
 * `_reserved` is excluded and MUST be zero.
 */
typedef struct TOOB_MBX_ALIGN8 {
  uint32_t magic;     /* 0  : TOOB_MAILBOX_MAGIC */
  uint16_t version;   /* 4  : TOOB_MAILBOX_VERSION */
  uint16_t request;   /* 6  : cumulative bitmask of TOOB_REQ_* */
  uint32_t seq;       /* 8  : monotonic; Core consumes iff seq > last_consumed */
  uint32_t tbm1_addr; /* 12 : UPDATE_PENDING flat-package address (else 0) */
  uint64_t nonce;     /* 16 : CONFIRM boot_nonce (else 0) */
  uint32_t crc32;     /* 24 : CRC-32 over [0 .. 24) */
  uint32_t _reserved; /* 28 : must be 0 */
} toob_mailbox_t;     /* 32 bytes */

_Static_assert(sizeof(toob_mailbox_t) == 32U, "toob_mailbox_t must be exactly 32 bytes");
_Static_assert(offsetof(toob_mailbox_t, crc32) == 24U, "crc32 offset drift");
_Static_assert(offsetof(toob_mailbox_t, nonce) == 16U, "nonce must be 8-byte aligned");

/* CRC-covered prefix length (one definition for writer and reader). */
#define TOOB_MAILBOX_CRC_LEN offsetof(toob_mailbox_t, crc32)

#endif /* TOOB_MAILBOX_WIRE_H */
