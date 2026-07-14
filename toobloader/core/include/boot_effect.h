#ifndef BOOT_EFFECT_H
#define BOOT_EFFECT_H

#include "boot_types.h"
#include "boot_hal.h"

typedef enum {
  EFF_ERASE = 1,
  EFF_COPY = 2,
  EFF_FLIP = 3
} effect_op_t;

typedef struct {
  effect_op_t op;
  uint32_t    src;       /* Only used for EFF_COPY */
  uint32_t    dst;
  uint32_t    len;
  uint32_t    post_crc;  /* Expected CRC32 value after execution */
} flash_effect_t;

_Static_assert(sizeof(flash_effect_t) % 4 == 0,
               "flash_effect_t size must be aligned to 4 bytes for MCU memory mapping");

#include "boot_journal.h"
#include "boot_multiimage.h"

boot_status_t boot_effect_execute(const boot_platform_t *platform,
                                  const flash_effect_t *fx, size_t n,
                                  const boot_allowed_region_t *whitelist, size_t wl_n,
                                  uint8_t *arena, size_t arena_len);

uint32_t boot_effect_compute_erased_crc(size_t len);

boot_status_t boot_effect_admit_or_defer(const boot_platform_t *platform,
                                         const wal_tmr_payload_t *tmr,
                                         uint32_t image_size,
                                         const boot_component_t *components,
                                         size_t num_components,
                                         bool requires_swap);

#endif /* BOOT_EFFECT_H */
