/**
 * @file stage0_hash.c
 * @brief Zero-Allocation Flash Hashing
 *
 * Implements hashing logic directly over flash memory with "Secure-Poisoning"
 * upon flash read failures.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "../../crypto/sha256/sha256.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"

void stage0_hash_compute(const boot_platform_t *platform, uint32_t addr,
                         size_t len, uint8_t *digest) {
  SHA256_CTX ctx;
  sha256_init(&ctx);

  uint8_t chunk[128] __attribute__((aligned(8)));
  size_t offset = 0;
  while (offset < len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    size_t step = (len - offset > sizeof(chunk)) ? sizeof(chunk) : len - offset;

    /* Direkter Bare-Metal Flash Read ohne OS-Abstraktion */
    if (platform->flash->read((uint32_t)(addr + offset), chunk, (uint32_t)step) == BOOT_OK) {
      sha256_update(&ctx, chunk, step);
    } else {
      /* Bei Hardware-Fehler Hash-Zustand vergiften */
      chunk[0] = 0xDE;
      chunk[1] = 0xAD;
      sha256_update(&ctx, chunk, 2);
    }
    offset += step;
  }

  sha256_final(&ctx, digest);

  boot_secure_zeroize(&ctx, sizeof(ctx));
  boot_secure_zeroize(chunk, sizeof(chunk));
}