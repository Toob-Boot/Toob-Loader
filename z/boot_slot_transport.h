/**
 * @file boot_slot_transport.h
 * @brief Slot Transport Provider interface — one transaction shape, N strategies.
 *
 * Intended path: common/include/boot_slot_transport.h    (Ticket ST-011)
 *
 * The Transactional Slot Manager (boot_state.c) builds ONE slot_txn_t and calls
 * the compile-time-selected provider. Providers vary only the COST (erases,
 * writes, duration) — never the safety semantics: it always boots either the
 * old or the new VERIFIED image, never a half state, and a return path exists
 * until confirm.
 */

#ifndef BOOT_SLOT_TRANSPORT_H
#define BOOT_SLOT_TRANSPORT_H

#include <stdint.h>
#include <stdbool.h>
#include "boot_hal.h"        /* boot_platform_t, boot_status_t */
#include "boot_journal.h"    /* wal_entry_payload_t */
#include "boot_swap.h"       /* boot_dest_slot_t (migrates here when boot_swap retires) */
#include "boot_slot_caps.h"

/* ============================================================================
 * transfer_bitmap SLOT REGISTRY (collision prevention — single source of truth)
 * ============================================================================
 * wal_entry_payload_t.transfer_bitmap[8] is shared by several modules. This is
 * the authoritative allocation; every new user MUST register here:
 *
 *   [0..2]  legacy swap-scratch chunk deduction (crc_src, crc_dest, shield)
 *   [0..7]  multi-image component-completion bits (component_id 0..255)
 *   [3]     transport phase marker (oneway / swapmove)      — this header
 *   [4..5]  swapmove sub-step CRCs (cs, cp)                 — this header
 *
 * !!! KNOWN HAZARD (pre-existing, flagged for fix): the legacy app-swap writes
 * CRC values into [0..2], and boot_multiimage_apply afterwards interprets the
 * SAME words as component-completion bits — random CRC bits can silently mark
 * components 0..95 as "already flashed". The new providers therefore (a) use
 * only [3..5] and (b) CLEAR their slots with a WAL append on completion, so
 * multi-image never sees stale transport state. The swapscratch adapter also
 * clears [0..2] after a successful legacy apply for the same reason.
 * ============================================================================ */
#define TOOB_TB_SLOT_PHASE 3u
#define TOOB_TB_SLOT_AUX0  4u
#define TOOB_TB_SLOT_AUX1  5u

/* Phase magics (high hamming distance, never 0x00000000 / 0xFFFFFFFF). A stale
 * delta_chunk_id from a previous pipeline stage (e.g. the delta VM leaves it at
 * image size) is IGNORED unless the phase magic matches — this keys resume on
 * the phase, not on a raw offset, and kills a whole class of cross-stage bugs. */
#define TOOB_PHASE_ONEWAY_BACKUP  0x0FB5AA33u
#define TOOB_PHASE_ONEWAY_DEPLOY  0xF04A55CCu
#define TOOB_PHASE_ONEWAY_RBACK   0x33CA5AF0u
#define TOOB_PHASE_SWAPMOVE_MOVE  0x5AC3F00Fu
#define TOOB_PHASE_SWAPMOVE_SWAP  0xA53C0FF0u

/* Stable provider IDs — persisted into the WAL (ST-014) so a brownout resume
 * dispatches the SAME provider that began the transaction. Never renumber. */
#define TOOB_TRANSPORT_ID_NONE        0u
#define TOOB_TRANSPORT_ID_SWAPSCRATCH 1u
#define TOOB_TRANSPORT_ID_ONEWAY      2u
#define TOOB_TRANSPORT_ID_SWAPMOVE    3u
#define TOOB_TRANSPORT_ID_POINTER     4u

/* Forward-compatible transport_id persistence: becomes real with ST-014
 * (wal_entry_payload_t gains .transport_id). Until then it is a no-op, so this
 * header set compiles against today's WAL wire format. */
#ifdef TOOB_WAL_HAS_TRANSPORT_ID
#define TOOB_TXN_SET_TRANSPORT(txnp, tid) ((txnp)->transport_id = (uint8_t)(tid))
#else
#define TOOB_TXN_SET_TRANSPORT(txnp, tid) ((void)0)
#endif

/**
 * @brief One slot transaction, built by the TSM from manifest + chip config.
 *
 * Region sizes are REQUIRED (bounds proofs inside the providers); the TSM fills
 * them from generated_boot_config.h. `src_verified` is the verify-before-commit
 * gate: the TSM sets it only after the Merkle/signature pipeline passed. Every
 * provider BOOT_SECURE_REQUIREs it before any destructive operation — this
 * implements the gate today; ST-012 later migrates it into EFF_FLIP.
 */
typedef struct {
  uint32_t src_addr;           /* new image (staging raw / delta-output secondary) */
  uint32_t src_region_size;
  uint32_t dest_addr;          /* execution slot to update                        */
  uint32_t dest_region_size;
  uint32_t backup_addr;        /* where the old app is preserved; 0 = none        */
  uint32_t backup_region_size;
  uint32_t length;             /* image bytes to transport                        */
  uint8_t  dest_slot;          /* boot_dest_slot_t value (telemetry mapping)      */
  uint8_t  target_slot_index;  /* tier 0/1: logical slot to activate (0/1)        */
  uint8_t  transport_id;       /* mirrors the WAL field (ST-014)                  */
  bool     src_is_delta_output;/* src is SDVM output (routing / guard relevance)  */
  bool     src_verified;       /* set by TSM after crypto verify — the gate       */
  uint8_t  _pad[3];
} slot_txn_t;

_Static_assert(sizeof(slot_txn_t) % 4 == 0, "slot_txn_t must stay 4-aligned");

/**
 * @brief One transport strategy. `apply` moves/activates the new image
 *        (brownout-resumable via open_txn); `rollback` restores the previous
 *        image. Both must be idempotent under resume and must never weaken the
 *        TSM invariants.
 */
typedef struct {
  const char *name;
  uint8_t     tier;   /* 0/1 = zero-copy, 2 = swap-move, 3 = one-way, 4 = scratch */
  uint8_t     id;     /* TOOB_TRANSPORT_ID_*                                      */

  boot_status_t (*apply)(const boot_platform_t *platform,
                         const slot_caps_t *caps,
                         slot_txn_t *txn,
                         wal_entry_payload_t *open_txn,
                         uint8_t *arena, size_t arena_len);

  boot_status_t (*rollback)(const boot_platform_t *platform,
                            const slot_caps_t *caps,
                            slot_txn_t *txn,
                            uint8_t *arena, size_t arena_len);
} slot_transport_t;

#endif /* BOOT_SLOT_TRANSPORT_H */