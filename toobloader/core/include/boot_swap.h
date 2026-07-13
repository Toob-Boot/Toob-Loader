#ifndef BOOT_SWAP_H
#define BOOT_SWAP_H

/*
 * Toob-Boot Core Header: boot_swap.h
 * Relevant Spec-Dateien:
 * - docs/toobfuzzer_integration.md (Fuzzing-Aware Block Tausch, Limitierungen)
 * - docs/testing_requirements.md (Brownout Recovery)
 */

#include "boot_types.h"
#include "boot_hal.h"



/**
 * @brief Enum to selectively track erase counters in the TMR payload.
 */
typedef enum {
    BOOT_DEST_SLOT_APP = 0,
    BOOT_DEST_SLOT_STAGING = 1
} boot_dest_slot_t;

/**
 * @brief Apply a swap or copy operation from src_base to dest_base.
 *        This function safely orchestrates the in-place overwrite using a swap buffer.
 *
 * @note  Atomic Fallback is coordinated externally by the WAL_INTENT_TXN_COMMIT intent 
 *        inside boot_state.c. This function is physically destructive mid-flight and 
 *        must be guarded by transactions.
 *        Swap size is heavily restricted by the monolithic buffer (max sector size limit).
 *
 * @param platform  Hardware HAL abstraction
 * @param src_base  Source address
 * @param dest_base Destination address
 * @param length    Total length to swap (derived dynamically from Envelope)
 * @param dest_slot Which slot is written to (for TMR wear counters).
 * @return boot_status_t BOOT_OK on success, error otherwise.
 */
#include "boot_journal.h"

TOOB_IRAM_ATTR boot_status_t boot_swap_apply(const boot_platform_t *platform,
                                             uint32_t src_base, uint32_t dest_base,
                                             uint32_t length, boot_dest_slot_t dest_slot,
                                             wal_entry_payload_t *open_txn,
                                             uint8_t *arena, size_t arena_len);

TOOB_IRAM_ATTR boot_status_t boot_copy_apply(const boot_platform_t *platform,
                                             uint32_t src_base, uint32_t dest_base,
                                             uint32_t length, uint32_t phase_id,
                                             wal_entry_payload_t *open_txn,
                                             uint8_t *arena, size_t arena_len);

boot_status_t boot_swap_erase_safe(const boot_platform_t *platform,
                                   uint32_t addr, size_t len,
                                   uint8_t *arena, size_t arena_len);

#include "boot_effect.h"

TOOB_IRAM_ATTR boot_status_t boot_swap_plan_chunk(const boot_platform_t *platform,
                                                  uint32_t current_src, uint32_t current_dest,
                                                  uint32_t block_size,
                                                  uint32_t crc_src, uint32_t crc_dest,
                                                  bool run_phase_a, bool run_phase_b, bool run_phase_c,
                                                  flash_effect_t *out_fx, size_t cap, size_t *n_out);

/**
 * @brief Header of the optional splash image stored in a dedicated flash region (SWEV-T8).
 * Pack crc32 at offset 4 to allow contiguous one-pass stream validation starting from offset 8.
 */
typedef struct {
  uint32_t magic;      /* 'SPLS' magic marker */
  uint32_t crc32;      /* CRC-32 over header fields from offset 8 + pixel payload data */
  uint16_t width;      /* Display width in pixels */
  uint16_t height;     /* Display height in pixels */
  uint32_t data_size;  /* Size of the raw pixel data */
} toob_splash_header_t;

_Static_assert(sizeof(toob_splash_header_t) == 16, "toob_splash_header_t size must be exactly 16 bytes");
_Static_assert(offsetof(toob_splash_header_t, width) == 8, "width offset drift");

/**
 * @brief Verifies the integrity and safety bounds of a splash blob stored in flash.
 *
 * Checks the magic prefix, validates that the data size fits within safety bounds,
 * and verifies the contiguous CRC-32 checksum in one pass.
 *
 * @return BOOT_OK on success, error code otherwise.
 */
boot_status_t boot_splash_verify(const boot_platform_t *platform,
                                 uint32_t splash_addr, uint32_t max_size,
                                 uint8_t *arena, size_t arena_len);

#endif /* BOOT_SWAP_H */
