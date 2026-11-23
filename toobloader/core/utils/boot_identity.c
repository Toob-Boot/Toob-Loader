#include "boot_identity.h"
#include "boot_ct_utils.h"
#include "boot_fih.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

#ifndef TOOB_MAX_OTP_SLOTS
#ifdef TOOB_OTP_MAX_SLOTS
#define TOOB_MAX_OTP_SLOTS TOOB_OTP_MAX_SLOTS
#else
#define TOOB_MAX_OTP_SLOTS 256U
#endif
#endif

_Static_assert((TOOB_MAX_OTP_SLOTS > 0U) && (TOOB_MAX_OTP_SLOTS <= 256U),
               "TOOB_MAX_OTP_SLOTS must be in [1, 256]");

/**
 * @brief Common KDF core: H([device_secret ||] chip_uid || root_pubkey || domain_separator).
 *
 * Writes a full 32-byte SHA-256 digest into out_digest.
 * Caller is responsible for truncation if fewer bytes are needed.
 */
static boot_status_t kdf_core(const boot_platform_t *platform, uint8_t key_index,
                              const uint8_t *device_secret, size_t secret_len,
                              const char *domain_sep, size_t sep_len, uint8_t out_digest[32]) {
  /* 1. Read Chip UID (variable length, max 32) */
  uint8_t uid[32];
  size_t uid_len = 0U;
  boot_secure_zeroize(uid, sizeof(uid));
  boot_status_t status = platform->keystore->read_chip_uid(uid, sizeof(uid), &uid_len);
  if (status != BOOT_OK || uid_len == 0U || uid_len > sizeof(uid)) {
    boot_secure_zeroize(uid, sizeof(uid));
    return (status != BOOT_OK) ? status : BOOT_ERR_INVALID_ARG;
  }

  /* 2. Read Root Public Key at caller-selected slot */
  uint8_t pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(pubkey, sizeof(pubkey));
  status = platform->keystore->read_pubkey(pubkey, sizeof(pubkey), key_index);
  if (status != BOOT_OK) {
    boot_secure_zeroize(uid, sizeof(uid));
    boot_secure_zeroize(pubkey, sizeof(pubkey));
    return status;
  }
  if (verify_not_all_zeros_glitch_safe(pubkey, sizeof(pubkey)) != BOOT_OK) {
    boot_secure_zeroize(uid, sizeof(uid));
    boot_secure_zeroize(pubkey, sizeof(pubkey));
    return BOOT_ERR_VERIFY;
  }

  /* 3. Iterative Hashing: H([secret ||] uid || pubkey || domain_separator) */
  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  status = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
  if (status != BOOT_OK) {
    boot_secure_zeroize(uid, sizeof(uid));
    boot_secure_zeroize(pubkey, sizeof(pubkey));
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    return status;
  }

  if (device_secret != NULL && secret_len > 0U) {
    status = platform->crypto->hash_update(hash_ctx, device_secret, secret_len);
  }
  if (status == BOOT_OK) {
    status = platform->crypto->hash_update(hash_ctx, uid, uid_len);
  }
  if (status == BOOT_OK) {
    status = platform->crypto->hash_update(hash_ctx, pubkey, sizeof(pubkey));
  }
  if (status == BOOT_OK) {
    status = platform->crypto->hash_update(hash_ctx, (const uint8_t *)domain_sep, sep_len);
  }
  size_t digest_len = 32U;
  if (status == BOOT_OK) {
    status = platform->crypto->hash_finish(hash_ctx, out_digest, &digest_len);
    if (status == BOOT_OK && digest_len != 32U) {
      status = BOOT_ERR_VERIFY;
      boot_secure_zeroize(out_digest, 32U);
    }
  } else {
    /* Finalize to clean up ctx even on error */
    uint8_t dummy[64];
    size_t dummy_len = sizeof(dummy);
    (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
    boot_secure_zeroize(dummy, sizeof(dummy));
    boot_secure_zeroize(out_digest, 32U);
  }

  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(uid, sizeof(uid));
  boot_secure_zeroize(pubkey, sizeof(pubkey));

  return status;
}

/**
 * @brief Validates crypto HAL prerequisites common to all KDF operations.
 */
static boot_status_t validate_kdf_prerequisites(const boot_platform_t *platform) {
  if (platform == NULL || platform->crypto == NULL || platform->keystore == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  if (platform->keystore->read_chip_uid == NULL || platform->keystore->read_pubkey == NULL ||
      platform->crypto->hash_init == NULL || platform->crypto->hash_update == NULL ||
      platform->crypto->hash_finish == NULL ||
      (platform->crypto->get_hash_ctx_size != NULL &&
       platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE)) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_OK;
}

boot_status_t boot_otp_get_active_key_index(const boot_platform_t *platform, uint8_t *out_idx) {
  if (platform == NULL || platform->keystore == NULL || platform->keystore->read_pubkey == NULL ||
      out_idx == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t k1[32] __attribute__((aligned(8)));
  uint8_t k2[32] __attribute__((aligned(8)));
  bool found_any = false;
  bool blank_seen = false;
  uint8_t last_valid = 0U;

  for (uint32_t idx = 0U; idx < (uint32_t)TOOB_MAX_OTP_SLOTS; idx++) {
    if ((idx & 0x1FU) == 0U && platform->wdt != NULL && platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }

    boot_secure_zeroize(k1, sizeof(k1));
    boot_secure_zeroize(k2, sizeof(k2));

    boot_status_t s1 = platform->keystore->read_pubkey(k1, sizeof(k1), (uint8_t)idx);
    BOOT_GLITCH_DELAY();
    boot_status_t s2 = platform->keystore->read_pubkey(k2, sizeof(k2), (uint8_t)idx);

    if (s1 != s2) {
      boot_secure_zeroize(k1, sizeof(k1));
      boot_secure_zeroize(k2, sizeof(k2));
      return BOOT_ERR_VERIFY;
    }

    if (blank_seen) {
      if (s1 != BOOT_ERR_NOT_FOUND) {
        boot_secure_zeroize(k1, sizeof(k1));
        boot_secure_zeroize(k2, sizeof(k2));
        return BOOT_ERR_VERIFY;
      }
      continue;
    }

    if (s1 == BOOT_OK) {
      if (verify_not_all_zeros_glitch_safe(k1, sizeof(k1)) != BOOT_OK ||
          verify_not_all_zeros_glitch_safe(k2, sizeof(k2)) != BOOT_OK ||
          constant_time_memcmp_glitch_safe(k1, k2, sizeof(k1)) != BOOT_OK) {
        boot_secure_zeroize(k1, sizeof(k1));
        boot_secure_zeroize(k2, sizeof(k2));
        return BOOT_ERR_VERIFY;
      }
      last_valid = (uint8_t)idx;
      found_any = true;
    } else if (s1 == BOOT_ERR_NOT_FOUND) {
      blank_seen = true;
    } else {
      boot_secure_zeroize(k1, sizeof(k1));
      boot_secure_zeroize(k2, sizeof(k2));
      return BOOT_ERR_VERIFY;
    }
  }

  boot_secure_zeroize(k1, sizeof(k1));
  boot_secure_zeroize(k2, sizeof(k2));

  BOOT_SECURE_REQUIRE(found_any, { return BOOT_ERR_VERIFY; });

  *out_idx = last_valid;
  return BOOT_OK;
}

boot_status_t boot_derive_device_id(const boot_platform_t *platform, uint8_t out_id[32]) {
  if (out_id == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  boot_status_t status = validate_kdf_prerequisites(platform);
  if (status != BOOT_OK) {
    return status;
  }

  boot_secure_zeroize(out_id, 32U);

  const char domain_separator[] = "toob-device-id-v1";
  return kdf_core(platform, 0U, NULL, 0U, domain_separator, sizeof(domain_separator) - 1U, out_id);
}

boot_status_t boot_derive_journal_key(const boot_platform_t *platform, uint8_t out_key[16]) {
  if (out_key == NULL) {
    return BOOT_ERR_INVALID_ARG;
  }
  boot_status_t status = validate_kdf_prerequisites(platform);
  if (status != BOOT_OK) {
    return status;
  }

  boot_secure_zeroize(out_key, 16U);

  uint8_t active_idx = 0U;
  status = boot_otp_get_active_key_index(platform, &active_idx);
  if (status != BOOT_OK) {
    return status;
  }

  uint8_t full_digest[32];
  boot_secure_zeroize(full_digest, sizeof(full_digest));

  if (platform->keystore->read_device_secret != NULL) {
    uint8_t device_secret[64];
    size_t secret_len = 0U;
    boot_secure_zeroize(device_secret, sizeof(device_secret));

    status =
        platform->keystore->read_device_secret(device_secret, sizeof(device_secret), &secret_len);
    if (status == BOOT_OK &&
        (secret_len < 16U || secret_len > sizeof(device_secret) ||
         verify_not_all_zeros_glitch_safe(device_secret, secret_len) != BOOT_OK)) {
      status = BOOT_ERR_VERIFY;
    }

    if (status == BOOT_OK) {
      const char domain_separator_v2[] = "toob-journal-key-v2";
      status = kdf_core(platform, active_idx, device_secret, secret_len, domain_separator_v2,
                        sizeof(domain_separator_v2) - 1U, full_digest);
    }

    boot_secure_zeroize(device_secret, sizeof(device_secret));
  } else {
#if (defined(TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION) &&                                         \
     TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION) ||                                                 \
    defined(TOOB_MOCK_TEST)
    const char domain_separator_v1[] = "toob-journal-key-v1";
    status = kdf_core(platform, active_idx, NULL, 0U, domain_separator_v1,
                      sizeof(domain_separator_v1) - 1U, full_digest);
#else
    status = BOOT_ERR_NOT_SUPPORTED;
#endif
  }

  if (status == BOOT_OK) {
    memcpy(out_key, full_digest, 16U);
  }

  boot_secure_zeroize(full_digest, sizeof(full_digest));
  return status;
}
