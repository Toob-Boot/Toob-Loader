#ifndef BOOT_SWAP_H
#define BOOT_SWAP_H

/*
 * Toob-Boot Core Header: boot_swap.h
 * Relevant Spec-Dateien:
 * - docs/toobfuzzer_integration.md (Fuzzing-Aware Block Tausch, Limitierungen)
 * - docs/testing_requirements.md (Brownout Recovery)
 */

#include "boot_effect.h"
#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"
#include "generated_boot_config.h"

/**
 * @brief Enum to selectively track erase counters in the TMR payload.
 */
typedef enum { BOOT_DEST_SLOT_APP = 0, BOOT_DEST_SLOT_STAGING = 1 } boot_dest_slot_t;

#ifndef CHIP_SCRATCH_SLOT_SIZE
#define CHIP_SCRATCH_SLOT_SIZE 0u
#endif

#ifndef CHIP_SCRATCH_SLOT_ABS_ADDR
#define CHIP_SCRATCH_SLOT_ABS_ADDR 0u
#endif

/**
 * @brief Descriptor for 3-phase swap chunk effect planning (LOW-08).
 */
typedef struct {
  uint32_t current_src;
  uint32_t current_dest;
  uint32_t scratch_addr;
  uint32_t block_size;
  uint32_t crc_src;
  uint32_t crc_dest;
  bool run_phase_a;
  bool run_phase_b;
  bool run_phase_c;
} boot_swap_chunk_desc_t;

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH
TOOB_IRAM_ATTR boot_status_t boot_swap_apply(const boot_platform_t *platform, uint32_t src_base,
                                             uint32_t dest_base, uint32_t length,
                                             boot_dest_slot_t dest_slot,
                                             wal_entry_payload_t *open_txn, uint8_t *arena,
                                             size_t arena_len);

TOOB_IRAM_ATTR boot_status_t boot_copy_apply(const boot_platform_t *platform, uint32_t src_base,
                                             uint32_t dest_base, uint32_t length, uint32_t phase_id,
                                             wal_entry_payload_t *open_txn, uint8_t *arena,
                                             size_t arena_len);

TOOB_IRAM_ATTR boot_status_t boot_swap_plan_chunk_ring(const boot_platform_t *platform,
                                                       const boot_swap_chunk_desc_t *desc,
                                                       flash_effect_t *out_fx, size_t cap,
                                                       size_t *n_out);

TOOB_IRAM_ATTR boot_status_t boot_swap_plan_chunk(const boot_platform_t *platform,
                                                  const boot_swap_chunk_desc_t *desc,
                                                  flash_effect_t *out_fx, size_t cap,
                                                  size_t *n_out);
#endif /* TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPSCRATCH */

boot_status_t boot_swap_erase_safe(const boot_platform_t *platform, uint32_t addr, size_t len,
                                   uint8_t *arena, size_t arena_len);

boot_status_t boot_swap_solve_block(const boot_platform_t *p, uint32_t src, uint32_t dst,
                                    uint32_t remaining, size_t *block_out);

boot_status_t boot_swap_blocks_identical(const boot_platform_t *p, uint32_t a, uint32_t b,
                                         size_t block, bool *out, uint8_t *arena, size_t arena_len);

boot_status_t boot_swap_copy_region_resumable(const boot_platform_t *p, uint32_t src_base,
                                              uint32_t dst_base, uint32_t length,
                                              uint32_t phase_magic, wal_entry_payload_t *txn,
                                              const boot_allowed_region_t *wl, uint32_t wl_n,
                                              uint32_t *erases_out, uint8_t *arena,
                                              size_t arena_len);

boot_status_t boot_swap_commit_wear(const boot_platform_t *p, uint32_t app_erases,
                                    uint32_t staging_erases, uint32_t scratch_erases,
                                    uint8_t *arena, size_t arena_len);

/**
 * @brief Header of the optional splash image stored in a dedicated flash region (SWEV-T8).
 * Pack crc32 at offset 4 to allow contiguous one-pass stream validation starting from offset 8.
 */
typedef struct {
  uint32_t magic;     /* 'SPLS' magic marker */
  uint32_t crc32;     /* CRC-32 over header fields from offset 8 + pixel payload data */
  uint16_t width;     /* Display width in pixels */
  uint16_t height;    /* Display height in pixels */
  uint32_t data_size; /* Size of the raw pixel data */
} toob_splash_header_t;

_Static_assert(sizeof(toob_splash_header_t) == 16,
               "toob_splash_header_t size must be exactly 16 bytes");
_Static_assert(offsetof(toob_splash_header_t, width) == 8, "width offset drift");

/**
 * @brief Verifies the integrity and safety bounds of a splash blob stored in flash.
 */
boot_status_t boot_splash_verify(const boot_platform_t *platform, uint32_t splash_addr,
                                 uint32_t max_size, uint8_t *arena, size_t arena_len);

#endif /* BOOT_SWAP_H */
