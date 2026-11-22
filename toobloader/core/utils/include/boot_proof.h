#ifndef BOOT_PROOF_H
#define BOOT_PROOF_H

#include "boot_types.h"
#include <stdint.h>

typedef struct {
  uint32_t image_addr;
  uint32_t image_size;
  uint32_t entry_point;
  uint32_t svn;
  uint32_t seal[2]; /* keyed checksum over the four fields */
} boot_proof_t;

static inline uint32_t boot_proof_mix(uint32_t h) {
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

static inline void boot_proof_seal(boot_proof_t *pr, const uint32_t seal_key[4]) {
  if (!pr || !seal_key) {
    return;
  }
  uint32_t h1 = seal_key[0] ^ pr->image_addr;
  uint32_t h2 = seal_key[1] ^ pr->image_size;

  h1 = boot_proof_mix(h1 ^ pr->entry_point ^ seal_key[2]);
  h2 = boot_proof_mix(h2 ^ pr->svn ^ seal_key[3]);

  pr->seal[0] = h1;
  pr->seal[1] = h2;
}

static inline boot_status_t boot_proof_verify(const boot_proof_t *pr, const uint32_t seal_key[4]) {
  if (!pr || !seal_key) {
    return BOOT_ERR_INVALID_ARG;
  }
  uint32_t expected_seal0 = seal_key[0] ^ pr->image_addr;
  uint32_t expected_seal1 = seal_key[1] ^ pr->image_size;

  expected_seal0 = boot_proof_mix(expected_seal0 ^ pr->entry_point ^ seal_key[2]);
  expected_seal1 = boot_proof_mix(expected_seal1 ^ pr->svn ^ seal_key[3]);

  /* Dual-accumulator glitch-hardened seal comparison */
  volatile uint32_t diff_1 = (pr->seal[0] ^ expected_seal0) | (pr->seal[1] ^ expected_seal1);
  volatile uint32_t s1 = 0U;
  volatile uint32_t s2 = 0U;
  if (diff_1 == 0U) {
    s1 = BOOT_OK;
  }
  BOOT_GLITCH_DELAY();
  volatile uint32_t diff_2 = (pr->seal[1] ^ expected_seal1) | (pr->seal[0] ^ expected_seal0);
  if (s1 == BOOT_OK && diff_2 == 0U) {
    s2 = BOOT_OK;
  }
  if (s1 == BOOT_OK && s2 == BOOT_OK && s1 == s2) {
    return BOOT_OK;
  }
  return BOOT_ERR_VERIFY;
}

#endif /* BOOT_PROOF_H */
