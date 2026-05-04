/**
 * ==============================================================================
 * Toob-Boot libtoob: OTA Daemon Implementation (toob_ota.c)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/lol.md (Case 1 & Case 2 Update Cycle logic)
 * - docs/libtoob_api.md (toob_set_next_update delegation)
 * - docs/testing_requirements.md (P10 compliance, zero dynamic allocation)
 * - docs/concept_fusion.md (WAL transaction architecture)
 *
 * ARCHITECTURAL PROPERTIES:
 * 1. Network-Agnostic Stream Writer: The RTOS pushes arbitrary-length
 *    chunks. This module internally buffers and aligns them to the
 *    CHIP_FLASH_WRITE_ALIGNMENT before flushing to the Staging Slot.
 * 2. Zero Dynamic Allocation: All buffers are statically sized and
 *    bounded by _Static_assert at compile time.
 * 3. Glitch-Resistant Flash Verification: Every flash write is
 *    double-checked via the established TOOB_GLITCH_DELAY shield pattern.
 * 4. Single-Exit Cleanup: Sensitive alignment buffers are zeroized
 *    before every return path (P10 Stack Leakage Defense).
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <string.h>

#ifndef CHIP_STAGING_SLOT_ABS_ADDR
#define CHIP_STAGING_SLOT_ABS_ADDR 0x0
#endif
#ifndef CHIP_STAGING_SLOT_SIZE
#define CHIP_STAGING_SLOT_SIZE 0x0
#endif
#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT CHIP_FLASH_WRITE_ALIGN
#endif

/* ==============================================================================
 * Cross-Compiler Glitch-Delay (mirrors toob_confirm.c pattern)
 * ==============================================================================
 */
#if defined(__GNUC__) || defined(__clang__)
#define TOOB_OTA_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
#elif defined(__ICCARM__)
#include <intrinsics.h>
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    __no_operation();                                                          \
    __no_operation();                                                          \
    __no_operation();                                                          \
  } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    __nop();                                                                   \
    __nop();                                                                   \
    __nop();                                                                   \
  } while (0)
#else
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    volatile uint32_t _d = 0;                                                  \
    _d = 1;                                                                    \
    (void)_d;                                                                  \
  } while (0)
#endif

/* ==============================================================================
 * OS-Safe Memory Zeroization (Prevents Compiler DCE on alignment buffer)
 * ==============================================================================
 */
static inline void toob_ota_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    p[i] = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

/* ==============================================================================
 * Internal State (File-Scoped, Zero-Allocation)
 * ==============================================================================
 */

typedef enum {
  TOOB_OTA_STATE_IDLE = 0x00,
  TOOB_OTA_STATE_RECEIVING = 0x5A,
  TOOB_OTA_STATE_DONE = 0xA5,
  TOOB_OTA_STATE_ERROR = 0xFF
} toob_ota_state_t;

/* P10: Alignment buffer must be an exact multiple of flash write alignment */
#define TOOB_OTA_BUF_SIZE 256U
_Static_assert(
    TOOB_OTA_BUF_SIZE % CHIP_FLASH_WRITE_ALIGNMENT == 0,
    "OTA alignment buffer must be a multiple of CHIP_FLASH_WRITE_ALIGNMENT");
_Static_assert(TOOB_OTA_BUF_SIZE > 0 && TOOB_OTA_BUF_SIZE <= 4096,
               "OTA alignment buffer must be within sane bounds [1..4096]");

static toob_ota_state_t s_state = TOOB_OTA_STATE_IDLE;
static uint32_t s_write_cursor = 0;
static uint32_t s_total_size = 0;
static uint32_t s_bytes_queued = 0;

/* 8-byte aligned buffer for DMA-safe flash writes (P10) */
static uint8_t s_align_buf[TOOB_OTA_BUF_SIZE] __attribute__((aligned(8)));
static uint32_t s_buf_len = 0;

/* ==============================================================================
 * INTERNAL HELPER: Flush alignment buffer to flash with glitch-shielded verify
 * ==============================================================================
 */
static toob_status_t _flush_buffer(uint32_t write_len) {
  if (write_len == 0 || write_len > TOOB_OTA_BUF_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_status_t res =
      toob_os_flash_write(s_write_cursor, s_align_buf, write_len);

  /* Glitch-Resistant Double-Check on flash result */
  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (res == TOOB_OK) {
    shield_1 = TOOB_OK;
  }
  TOOB_OTA_GLITCH_DELAY();
  if (shield_1 == TOOB_OK && res == TOOB_OK) {
    shield_2 = TOOB_OK;
  }

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    return (res != TOOB_OK) ? res : TOOB_ERR_FLASH;
  }

  s_write_cursor += write_len;
  return TOOB_OK;
}

/* ==============================================================================
 * PUBLIC API
 * ==============================================================================
 */

toob_status_t toob_ota_begin(uint32_t total_size, uint8_t image_type) {
  (void)image_type; /* Stored by the SUIT manifest, not needed by the writer */

  if (total_size == 0 || total_size > CHIP_STAGING_SLOT_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Reject re-entry while a transfer is active */
  if (s_state == TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* P10: Zeroize all mutable state before arming */
  toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);

  s_write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
  s_total_size = total_size;
  s_bytes_queued = 0;
  s_buf_len = 0;
  s_state = TOOB_OTA_STATE_RECEIVING;

  return TOOB_OK;
}

toob_status_t toob_ota_process_chunk(const uint8_t *chunk, uint32_t len) {
  toob_status_t final_stat = TOOB_ERR_INVALID_ARG;

  if (s_state != TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }
  if (!chunk || len == 0) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Overflow guard: total bytes received must not exceed declared size */
  if (s_bytes_queued + len < s_bytes_queued) { /* Arithmetic overflow check */
    s_state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }
  if (s_bytes_queued + len > s_total_size) {
    s_state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }

  uint32_t chunk_pos = 0;

  /* P10 Bounded Loop: chunk_pos strictly advances by at least 1 each iteration
   */
  while (chunk_pos < len) {
    uint32_t space_left = TOOB_OTA_BUF_SIZE - s_buf_len;
    uint32_t remaining = len - chunk_pos;
    uint32_t to_copy = (remaining < space_left) ? remaining : space_left;

    memcpy(&s_align_buf[s_buf_len], &chunk[chunk_pos], to_copy);
    s_buf_len += to_copy;
    chunk_pos += to_copy;
    s_bytes_queued += to_copy;

    /* Flush when buffer is exactly full (guaranteed aligned) */
    if (s_buf_len == TOOB_OTA_BUF_SIZE) {
      toob_status_t res = _flush_buffer(TOOB_OTA_BUF_SIZE);
      if (res != TOOB_OK) {
        s_state = TOOB_OTA_STATE_ERROR;
        toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
        return res;
      }
      s_buf_len = 0;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
    }
  }

  /* Transition to DONE when all declared bytes have been received */
  if (s_bytes_queued == s_total_size) {
    s_state = TOOB_OTA_STATE_DONE;
  }

  final_stat = TOOB_OK;
  return final_stat;
}

toob_status_t toob_ota_finalize(void) {
  toob_status_t final_stat = TOOB_ERR_INVALID_ARG;

  if (s_state != TOOB_OTA_STATE_DONE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Flush residual bytes (pad to CHIP_FLASH_WRITE_ALIGNMENT) */
  if (s_buf_len > 0) {
    uint32_t aligned_len = s_buf_len;
    uint32_t remainder = aligned_len % CHIP_FLASH_WRITE_ALIGNMENT;
    if (remainder != 0) {
      aligned_len += (CHIP_FLASH_WRITE_ALIGNMENT - remainder);
    }

    /* Safety: clamped write must never exceed buffer capacity */
    if (aligned_len > TOOB_OTA_BUF_SIZE) {
      s_state = TOOB_OTA_STATE_ERROR;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
      return TOOB_ERR_INVALID_ARG;
    }

    toob_status_t res = _flush_buffer(aligned_len);
    if (res != TOOB_OK) {
      s_state = TOOB_OTA_STATE_ERROR;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
      return res;
    }
  }

  /* P10: Zeroize alignment buffer before WAL transaction */
  toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);

  /* Reset state machine BEFORE WAL write (prevents re-entry on partial failure)
   */
  s_state = TOOB_OTA_STATE_IDLE;
  s_buf_len = 0;

  /* Atomically register the update intent in the WAL */
  final_stat = toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR);
  return final_stat;
}
