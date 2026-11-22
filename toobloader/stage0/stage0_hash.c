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

#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include "stage0_crypto.h"

boot_status_t stage0_hash_compute(const boot_platform_t *platform, uint32_t addr, size_t len,
                                  uint8_t *digest) {
  if (!platform || !platform->flash || !platform->flash->read || !platform->crypto ||
      !platform->crypto->hash_init || !platform->crypto->hash_update ||
      !platform->crypto->hash_finish || !platform->crypto->get_hash_ctx_size || !digest) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (len == 0U || len > (size_t)UINT32_MAX || (UINT32_MAX - addr) < (uint32_t)(len - 1U)) {
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_INVALID_ARG;
  }

  if (platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  uint8_t chunk[128] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(chunk, sizeof(chunk));

  if (platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx)) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_CRYPTO;
  }

  size_t offset = 0U;
  while (offset < len) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    size_t step = (len - offset > sizeof(chunk)) ? sizeof(chunk) : (len - offset);

    if (platform->flash->read(addr + (uint32_t)offset, chunk, step) != BOOT_OK) {
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(chunk, sizeof(chunk));
      boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
      return BOOT_ERR_FLASH_HW;
    }

    if (platform->crypto->hash_update(hash_ctx, chunk, step) != BOOT_OK) {
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(chunk, sizeof(chunk));
      boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
      return BOOT_ERR_CRYPTO;
    }
    offset += step;
  }

  size_t digest_len = BOOT_MERKLE_HASH_LEN;
  boot_status_t fin_st = platform->crypto->hash_finish(hash_ctx, digest, &digest_len);

  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(chunk, sizeof(chunk));

  if (fin_st != BOOT_OK || digest_len != BOOT_MERKLE_HASH_LEN) {
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_CRYPTO;
  }

  return BOOT_OK;
}
