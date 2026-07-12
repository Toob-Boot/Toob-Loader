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

#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"
#include "boot_merkle.h"

void stage0_hash_compute(const boot_platform_t *platform, uint32_t addr,
                         size_t len, uint8_t *digest) {
  if (!platform || !platform->crypto || !platform->crypto->hash_init ||
      !platform->crypto->hash_update || !platform->crypto->hash_finish ||
      !platform->crypto->get_hash_ctx_size || !digest) {
    return;
  }

  /* P10 Bounds Check */
  if (platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
    return;
  }

  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  if (platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx)) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return;
  }

  uint8_t chunk[128] __attribute__((aligned(8)));
  size_t offset = 0;
  while (offset < len) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    size_t step = (len - offset > sizeof(chunk)) ? sizeof(chunk) : len - offset;

    /* Direkter Bare-Metal Flash Read ohne OS-Abstraktion */
    if (platform->flash->read((uint32_t)(addr + offset), chunk, (uint32_t)step) == BOOT_OK) {
      platform->crypto->hash_update(hash_ctx, chunk, step);
    } else {
      /* Bei Hardware-Fehler Hash-Zustand vergiften. */
      chunk[0] = 0xDE;
      chunk[1] = 0xAD;
      platform->crypto->hash_update(hash_ctx, chunk, 2);
    }
    offset += step;
  }

  size_t digest_len = BOOT_MERKLE_HASH_LEN;
  platform->crypto->hash_finish(hash_ctx, digest, &digest_len);

  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(chunk, sizeof(chunk));
}