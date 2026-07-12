/**
 * @file toob_mailbox.h
 * @brief Shared Mailbox Wire Format — OS writes, Core reads and folds into WAL.
 *
 * Replaces the shared WAL append-log with a single-record mailbox.
 * The OS writes one request at a time; the Core consumes it at boot.
 *
 * Layout: Double-Slot (2 × 32 Bytes = 64 Bytes in a dedicated Flash sector).
 * OS writes to the inactive slot; Core reads both and picks higher valid seq.
 * Torn writes are safe: a half-written slot fails CRC and is ignored.
 */

#ifndef TOOB_MAILBOX_H
#define TOOB_MAILBOX_H

#include <stdint.h>
#include <stddef.h>

/* ===== Wire Constants ===== */

#define TOOB_MAILBOX_MAGIC   0x544D4258u  /* ASCII 'TMBX' */
#define TOOB_MAILBOX_VERSION 1
#define TOOB_MAILBOX_SLOTS   2            /* Double-Slot for torn-write safety */

/* ===== Request Types ===== */

typedef enum {
    TOOB_REQ_NONE              = 0,
    TOOB_REQ_UPDATE_PENDING    = 1,  /**< Manifest staged at tbm1_addr */
    TOOB_REQ_CONFIRM           = 2,  /**< OS confirms current boot is good */
    TOOB_REQ_RECOVERY_RESOLVED = 3   /**< Recovery OS fixed the problem */
} toob_req_t;

/* ===== Mailbox Record (32 Bytes, fixed layout) ===== */

typedef struct __attribute__((packed)) {
    uint32_t magic;        /**< Always TOOB_MAILBOX_MAGIC */
    uint16_t version;      /**< TOOB_MAILBOX_VERSION */
    uint16_t request;      /**< toob_req_t (fixed 16-bit ABI) */
    uint32_t seq;          /**< Monotonic. Core tracks last consumed seq in TMR. */
    uint32_t tbm1_addr;    /**< Manifest flash address (UPDATE_PENDING only) */
    uint64_t nonce;        /**< Anti-replay nonce for CONFIRM */
    uint8_t  _reserved[4]; /**< Future use — must be zero-filled */
    uint32_t crc32;        /**< CRC-32 over [0 .. offsetof(crc32)) */
} toob_mailbox_t;

_Static_assert(sizeof(toob_mailbox_t) == 32,
               "Mailbox ABI drift: must be exactly 32 bytes");
_Static_assert(offsetof(toob_mailbox_t, crc32) == 28,
               "Mailbox CRC field must be at offset 28");

/** Total Flash footprint: 2 slots × 32 bytes = 64 bytes (fits in any sector). */
#define TOOB_MAILBOX_FLASH_FOOTPRINT (TOOB_MAILBOX_SLOTS * sizeof(toob_mailbox_t))

#endif /* TOOB_MAILBOX_H */
