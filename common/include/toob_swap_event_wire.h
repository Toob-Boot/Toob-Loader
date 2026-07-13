/**
 * @file toob_swap_event_wire.h
 * @brief Neutral OS <-> Core mailbox wire format (single source of truth).
 *
 * Contains only the memory structures and notifications layout, allowing it to
 * be included from both the bootloader core and libtoob/OS side without dependencies.
 * Adheres to standard C17 and embeds size and layout checks.
 */

#ifndef TOOB_SWAP_EVENT_WIRE_H
#define TOOB_SWAP_EVENT_WIRE_H

#include <stdint.h>
#include <stddef.h>

#define TOOB_SWAP_EVENT_ABI_VERSION 1U

/* ============================================================================
 * COMPILE-TIME FEATURE GATES (SWEV-T2)
 * Supports dynamic configuration via device.toml [driver_config].
 * ============================================================================ */

/* Map driver compiler prefix overrides if they exist */
#ifdef TOOB_DRIVER_SWAP_EVENT_STATE
#define TOOB_SWAP_EVENT_STATE TOOB_DRIVER_SWAP_EVENT_STATE
#endif

#ifdef TOOB_DRIVER_SWAP_EVENT_PROGRESS
#define TOOB_SWAP_EVENT_PROGRESS TOOB_DRIVER_SWAP_EVENT_PROGRESS
#endif

#ifdef TOOB_DRIVER_SWAP_EVENT_PHASE
#define TOOB_SWAP_EVENT_PHASE TOOB_DRIVER_SWAP_EVENT_PHASE
#endif

/* Fallback default definitions if not configured */
#ifndef TOOB_SWAP_EVENT_STATE
#define TOOB_SWAP_EVENT_STATE    1   /* 1: State change notifications (PREPARE, DONE, etc.) enabled */
#endif

#ifndef TOOB_SWAP_EVENT_PROGRESS
#define TOOB_SWAP_EVENT_PROGRESS 1   /* 1: Detailed sectors done/total progress tracking enabled */
#endif

#ifndef TOOB_SWAP_EVENT_PHASE
#define TOOB_SWAP_EVENT_PHASE    0   /* 1: Sub-phases (e.g., RESUMED) enabled */
#endif

/* ============================================================================
 * SWAP LIFECYCLE PHASES
 * ============================================================================ */
typedef enum {
  TOOB_SWAP_PHASE_PREPARE  = 0,  /* OS is running and prepping for reboot (Level A) */
  TOOB_SWAP_PHASE_SWAPPING = 1,  /* Stage 1 is in active flash swap execution (Level B) */
  TOOB_SWAP_PHASE_DONE     = 2,  /* Swap has been successfully completed */
  TOOB_SWAP_PHASE_RESUMED  = 3,  /* Swap process resumed after power loss / interruption */
  TOOB_SWAP_PHASE_RECOVERY = 4   /* Recovery OS has boot notification context (Level C) */
} toob_swap_phase_t;

/**
 * @brief Versioned progress / swap notification event. 
 * Stable 16-byte layout to prevent compiler padding or drift between OS and Core builds.
 */
typedef struct {
  uint16_t abi_version;      /* Layout version marker (TOOB_SWAP_EVENT_ABI_VERSION) */
  uint16_t phase;            /* toob_swap_phase_t value */
  uint32_t sectors_done;     /* Done count (always 0 if PROGRESS feature is compiled out) */
  uint32_t sectors_total;    /* Total count (always 0 if PROGRESS feature is compiled out) */
  uint32_t flags;            /* Future expansion / specific state flags */
} toob_swap_event_t;

_Static_assert(sizeof(toob_swap_event_t) == 16, "toob_swap_event_t must be exactly 16 bytes");
_Static_assert(offsetof(toob_swap_event_t, phase) == 2, "phase offset drift");
_Static_assert(offsetof(toob_swap_event_t, sectors_done) == 4, "sectors_done offset drift");
_Static_assert(offsetof(toob_swap_event_t, sectors_total) == 8, "sectors_total offset drift");
_Static_assert(offsetof(toob_swap_event_t, flags) == 12, "flags offset drift");

/**
 * @brief Manufacturer notification function contract.
 * Contract: MUST be non-blocking (< 1ms execution budget) and fail-safe.
 */
typedef void (*toob_swap_notify_fn)(const toob_swap_event_t *ev);

#endif /* TOOB_SWAP_EVENT_WIRE_H */
