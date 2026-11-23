/**
 * @file boot_verify.c
 * @brief Implementierung des Envelope-First Checks (Mathematical Perfection
 * Revision)
 *
 * Architektur-Direktiven (concept_fusion.md):
 * - Anti-Truncation (Envelope-Wrap Proofs)
 * - Anti-Side-Channel (Constant-Time eFuse Read & OTFDEC Offline-Zwang)
 * - Glitching Defense (Control Flow Integrity & Double-Check Pattern)
 * - Pointer Provenance Defense (uintptr_t Casting gegen Compiler-Optimierungen)
 * - TOCTOU Defense (Isolierte O(1) Memory Clones)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Zero-Key Hardware Lock: Verhindert mathematisch "All-Zero Key Forgeries"
 * bei Ed25519 und PQC, falls ein EMFI-Glitch den SPI-Read oder eFuse-Read
 * unterbricht.
 * 2. Strict Internal CFI: Feingranulares Control Flow Integrity Tracking
 * beweist, dass Extrahierung, Downgrade-Check und Signatur lückenlos
 * durchlaufen wurden.
 * 3. Glitch-Gated Hardware Reads: Double-Check Pattern für kritische
 * HAL-Aufrufe.
 * 4. Branchless Math: Konstante Zeit-Berechnungen ohne Branches.
 */

#include "boot_verify.h"
#include "boot_ct_utils.h"
#include "boot_fih.h"
#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Mathematical glitch-resistance invariant required for double-check gating. */
_Static_assert(BOOT_OK == 0x55AA55AA, "BOOT_OK must remain a high-Hamming-weight sentinel!");

/* P10 CFI Token Slots (Randomized per call via TRNG) */
#define VERIFY_CFI_SLOT_1 1U
#define VERIFY_CFI_SLOT_2 2U
#define VERIFY_CFI_SLOT_3 3U
#define VERIFY_CFI_SLOT_4 4U
#define VERIFY_CFI_SLOT_5 5U
#define VERIFY_CFI_SLOT_5_SKIP 6U

/**
 * @brief Loads an OTP root key and proves its slot is non-revoked in constant time.
 */
static boot_status_t load_and_verify_root_pubkey(const boot_platform_t *platform, uint8_t key_index,
                                                 uint8_t root_pubkey[32]) {
  uint8_t dummy_pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));
  boot_secure_zeroize(root_pubkey, 32U);

  /* Always read an eFuse slot (even at index 255) to avoid index-branch timing leaks. */
  uint8_t next_idx = (uint8_t)(key_index + (key_index < 255U ? 1U : 0U));

  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }
  boot_status_t next_key_stat =
      platform->keystore->read_pubkey(dummy_pubkey, sizeof(dummy_pubkey), next_idx);
  boot_secure_zeroize(dummy_pubkey, sizeof(dummy_pubkey));
  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }

  if (next_key_stat != BOOT_OK && next_key_stat != BOOT_ERR_NOT_FOUND) {
    return next_key_stat;
  }

  bool is_max_key = (key_index == 255U);
  bool next_key_absent = (next_key_stat == BOOT_ERR_NOT_FOUND);

  BOOT_SECURE_REQUIRE(is_max_key || next_key_absent, { return BOOT_ERR_DOWNGRADE; });

  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }
  boot_status_t key_stat = platform->keystore->read_pubkey(root_pubkey, 32U, key_index);
  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }

  if (boot_secure_confirm(key_stat) != BOOT_OK) {
    boot_secure_zeroize(root_pubkey, 32U);
    return (key_stat != BOOT_OK) ? key_stat : BOOT_ERR_VERIFY;
  }

  if (verify_not_all_zeros_glitch_safe(root_pubkey, 32U) != BOOT_OK) {
    boot_secure_zeroize(root_pubkey, 32U);
    return BOOT_ERR_VERIFY;
  }

  return BOOT_OK;
}

/**
 * @brief Glitch-hardened Ed25519 signature verification with immediate key scrubbing.
 */
static boot_status_t verify_ed25519_hardened(const boot_platform_t *platform, const uint8_t *msg,
                                             size_t msg_len, const uint8_t *sig_ed25519,
                                             uint8_t root_pubkey[32]) {
  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }
  boot_status_t verify_stat =
      platform->crypto->verify_signature(msg, msg_len, sig_ed25519, root_pubkey);
  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }

#if TOOB_DOUBLE_VERIFY
  BOOT_GLITCH_DELAY();
  boot_status_t verify_stat_2 =
      platform->crypto->verify_signature(msg, msg_len, sig_ed25519, root_pubkey);
  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }

  boot_secure_zeroize(root_pubkey, 32U);

  BOOT_SECURE_REQUIRE(verify_stat == BOOT_OK && verify_stat_2 == BOOT_OK,
                      { return BOOT_ERR_VERIFY; });
#else
  boot_secure_zeroize(root_pubkey, 32U);
#endif

  BOOT_SECURE_REQUIRE(verify_stat == BOOT_OK, { return BOOT_ERR_VERIFY; });
  BOOT_GLITCH_DELAY();
  if (boot_secure_confirm(verify_stat) != BOOT_OK) {
    return BOOT_ERR_VERIFY;
  }

  return BOOT_OK;
}

#if TOOB_PQC_ENABLED
/**
 * @brief Verifies SHA-256 pinning of the envelope-embedded PQC public key.
 */
static boot_status_t verify_pqc_pubkey_pinning(const boot_platform_t *platform, uint8_t key_index,
                                               const uint8_t *pubkey_pqc, size_t pubkey_pqc_len) {
  uint8_t expected_hash[32] __attribute__((aligned(8)));
  uint8_t computed_hash[32] __attribute__((aligned(8)));
  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(expected_hash, sizeof(expected_hash));
  boot_secure_zeroize(computed_hash, sizeof(computed_hash));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  boot_status_t status = BOOT_ERR_VERIFY;

  if (platform->keystore->read_pqc_pubkey_hash != NULL) {
    status = platform->keystore->read_pqc_pubkey_hash(expected_hash, key_index);
    if (status != BOOT_OK) {
      goto pin_cleanup;
    }
  } else {
#ifdef TOOB_PINNED_PQC_PUBKEY_SHA256
    static const uint8_t pinned_hash[32] = TOOB_PINNED_PQC_PUBKEY_SHA256;
    _Static_assert(sizeof(pinned_hash) == 32U, "TOOB_PINNED_PQC_PUBKEY_SHA256 must be 32 bytes");
    memcpy(expected_hash, pinned_hash, sizeof(expected_hash));
#else
    status = BOOT_ERR_NOT_SUPPORTED;
    goto pin_cleanup;
#endif
  }

  if (verify_not_all_zeros_glitch_safe(expected_hash, sizeof(expected_hash)) != BOOT_OK) {
    status = BOOT_ERR_VERIFY;
    goto pin_cleanup;
  }

  if (platform->crypto->hash_init == NULL || platform->crypto->hash_update == NULL ||
      platform->crypto->hash_finish == NULL ||
      (platform->crypto->get_hash_ctx_size != NULL &&
       platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE)) {
    status = BOOT_ERR_NOT_SUPPORTED;
    goto pin_cleanup;
  }

  status = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
  if (status != BOOT_OK) {
    goto pin_cleanup;
  }

  status = platform->crypto->hash_update(hash_ctx, pubkey_pqc, pubkey_pqc_len);
  if (status == BOOT_OK) {
    size_t digest_len = sizeof(computed_hash);
    status = platform->crypto->hash_finish(hash_ctx, computed_hash, &digest_len);
    if (status == BOOT_OK && digest_len != 32U) {
      status = BOOT_ERR_VERIFY;
    }
  } else {
    uint8_t dummy[64];
    size_t dummy_len = sizeof(dummy);
    (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
    boot_secure_zeroize(dummy, sizeof(dummy));
  }

  if (status != BOOT_OK) {
    goto pin_cleanup;
  }

  BOOT_SECURE_REQUIRE(constant_time_memcmp_glitch_safe(computed_hash, expected_hash,
                                                       sizeof(expected_hash)) == BOOT_OK,
                      {
                        status = BOOT_ERR_VERIFY;
                        goto pin_cleanup;
                      });
  status = BOOT_OK;

pin_cleanup:
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(computed_hash, sizeof(computed_hash));
  boot_secure_zeroize(expected_hash, sizeof(expected_hash));
  return status;
}
#endif

boot_status_t boot_verify_manifest_envelope(const boot_platform_t *platform,
                                            const boot_verify_envelope_t *envelope,
                                            uint8_t *work_buffer, size_t work_buf_len) {

  /* ====================================================================
   * 1. P10 ALLOCATION & PESSIMISTIC INITIALIZATION
   * ==================================================================== */
  boot_status_t final_status = BOOT_ERR_VERIFY;

  uint8_t root_pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

  boot_verify_envelope_t local_env;
  boot_secure_zeroize(&local_env, sizeof(local_env));

  if (envelope != NULL) {
    memcpy(&local_env, envelope, sizeof(boot_verify_envelope_t));
  } else {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* ====================================================================
   * 2. P10 ARGUMENT & BOUNDS VALIDATION (Zero-Trust)
   * ==================================================================== */
  if (!platform || !platform->flash || !platform->wdt || !platform->crypto || !platform->keystore) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!local_env.signature_ed25519 || !work_buffer) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (!platform->keystore->read_pubkey || !platform->crypto->verify_signature) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }

  if (local_env.manifest_size == 0U || local_env.manifest_size > work_buf_len) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  uintptr_t base_ptr = (uintptr_t)work_buffer;
  if (UINTPTR_MAX - base_ptr < local_env.manifest_size) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  uint32_t verify_cfi_seed = 0U;
  boot_status_t rng_stat =
      boot_random_safe(platform, (uint8_t *)&verify_cfi_seed, sizeof(verify_cfi_seed));
  if (rng_stat != BOOT_OK) {
    final_status = (rng_stat == BOOT_ERR_NOT_SUPPORTED) ? BOOT_ERR_CRYPTO : rng_stat;
    goto cleanup;
  }

  boot_cfi_ctx_t verify_cfi_ctx;
  boot_cfi_init(verify_cfi_ctx, verify_cfi_seed);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_1);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_2);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_3);
  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_4);

  bool ed_sig_ok = is_buffer_within(local_env.signature_ed25519, 64U, work_buffer, work_buf_len);
  BOOT_SECURE_REQUIRE(ed_sig_ok, {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  });

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_1);

  /* ====================================================================
   * 3. CONSTANT-TIME OTP CHECK & ROOT KEY EXTRACTION
   * ==================================================================== */
  boot_status_t key_stat = load_and_verify_root_pubkey(platform, local_env.key_index, root_pubkey);
  if (key_stat != BOOT_OK) {
    final_status = key_stat;
    goto cleanup;
  }

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_2);
  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_3);

  /* ====================================================================
   * 5. ENVELOPE-FIRST ED25519 VERIFICATION (Glitch Hardened)
   * ==================================================================== */
  boot_status_t ed_stat = verify_ed25519_hardened(platform, work_buffer, local_env.manifest_size,
                                                  local_env.signature_ed25519, root_pubkey);
  if (ed_stat != BOOT_OK) {
    final_status = ed_stat;
    goto cleanup;
  }

  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_4);

  /* ====================================================================
   * 6. POST-QUANTUM HYBRID ENFORCEMENT & PUBKEY PINNING
   * ==================================================================== */
#if TOOB_PQC_ENABLED
  bool pqc_enforced = false;
  if (platform->crypto->is_pqc_enforced) {
    pqc_enforced = platform->crypto->is_pqc_enforced();
  }

  bool pqc_required_proven = false;
  if (pqc_enforced || local_env.pqc_hybrid_active) {
    BOOT_SECURE_REQUIRE(pqc_enforced || local_env.pqc_hybrid_active, {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    });
    pqc_required_proven = true;
  }

  if (pqc_required_proven) {
    if (!platform->crypto->verify_pqc) {
      final_status = BOOT_ERR_NOT_SUPPORTED;
      goto cleanup;
    }

    if (!local_env.signature_pqc || local_env.signature_pqc_len == 0U || !local_env.pubkey_pqc ||
        local_env.pubkey_pqc_len == 0U) {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    }

    bool pqc_pub_ok = is_buffer_within(local_env.pubkey_pqc, local_env.pubkey_pqc_len, work_buffer,
                                       local_env.manifest_size);
    bool pqc_sig_ok = is_buffer_within(local_env.signature_pqc, local_env.signature_pqc_len,
                                       work_buffer, local_env.manifest_size);

    BOOT_SECURE_REQUIRE(pqc_pub_ok && pqc_sig_ok, {
      final_status = BOOT_ERR_INVALID_ARG;
      goto cleanup;
    });

    if (verify_not_all_zeros_glitch_safe(local_env.pubkey_pqc, local_env.pubkey_pqc_len) !=
        BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    boot_status_t pin_stat = verify_pqc_pubkey_pinning(
        platform, local_env.key_index, local_env.pubkey_pqc, local_env.pubkey_pqc_len);
    if (pin_stat != BOOT_OK) {
      final_status = pin_stat;
      goto cleanup;
    }

    if (platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }
    boot_status_t pqc_stat = platform->crypto->verify_pqc(
        work_buffer, local_env.manifest_size, local_env.signature_pqc, local_env.signature_pqc_len,
        local_env.pubkey_pqc, local_env.pubkey_pqc_len);
    if (platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }

    BOOT_SECURE_REQUIRE(pqc_stat == BOOT_OK, {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    });
    BOOT_GLITCH_DELAY();
    if (boot_secure_confirm(pqc_stat) != BOOT_OK) {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    }

    boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5);
    boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5);
  } else {
    BOOT_SECURE_REQUIRE(!pqc_enforced && !local_env.pqc_hybrid_active, {
      final_status = BOOT_ERR_VERIFY;
      goto cleanup;
    });
    boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
    boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
  }
#else
  if (platform->crypto->is_pqc_enforced && platform->crypto->is_pqc_enforced()) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }

  boot_cfi_add_expected(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
  boot_cfi_step(verify_cfi_ctx, VERIFY_CFI_SLOT_5_SKIP);
#endif

  /* ====================================================================
   * 7. CONTROL FLOW INTEGRITY (CFI) RESOLUTION
   * ==================================================================== */
  boot_cfi_require(verify_cfi_ctx, {
    final_status = BOOT_ERR_VERIFY;
    goto cleanup;
  });
  final_status = BOOT_OK;

cleanup:
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(&local_env, sizeof(local_env));

  return final_status;
}

boot_status_t boot_verify_slot_image(const boot_platform_t *platform, uint32_t slot_addr,
                                     uint32_t slot_size, const toob_image_header_t *hdr,
                                     uint8_t *arena, size_t arena_len) {
#if defined(TOOB_ALLOW_UNSIGNED_APP_BOOT) && TOOB_ALLOW_UNSIGNED_APP_BOOT
#if defined(TOOB_PROFILE_PRODUCTION)
#error "TOOB_ALLOW_UNSIGNED_APP_BOOT forbidden in production!"
#endif
  (void)platform;
  (void)arena;
  (void)arena_len;
  if (hdr == NULL || slot_size < (uint32_t)sizeof(toob_image_header_t) ||
      (UINT32_MAX - slot_addr) < slot_size) {
    return BOOT_ERR_INVALID_ARG;
  }
  BOOT_SECURE_REQUIRE(hdr->magic == TOOB_MAGIC_HEADER, { return BOOT_ERR_NOT_FOUND; });
  if (hdr->image_size < (uint32_t)sizeof(toob_image_header_t) || hdr->image_size > slot_size ||
      (hdr->image_size & 3U) != 0U || (UINT32_MAX - slot_addr) < hdr->image_size) {
    return BOOT_ERR_INVALID_ARG;
  }
  return BOOT_OK;
#else
  boot_status_t final_status = BOOT_ERR_VERIFY;

  toob_image_header_t local_hdr;
  toob_img_sig_trailer_t trailer;
  uint8_t root_pubkey[32] __attribute__((aligned(8)));
  uint8_t digest[32] __attribute__((aligned(8)));
  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));

  boot_secure_zeroize(&local_hdr, sizeof(local_hdr));
  boot_secure_zeroize(&trailer, sizeof(trailer));
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  if (platform == NULL || platform->flash == NULL || platform->wdt == NULL ||
      platform->crypto == NULL || platform->keystore == NULL || hdr == NULL || arena == NULL ||
      arena_len < 256U) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto slot_cleanup;
  }

  if (platform->flash->read == NULL || platform->crypto->hash_init == NULL ||
      platform->crypto->hash_update == NULL || platform->crypto->hash_finish == NULL ||
      platform->crypto->verify_signature == NULL || platform->keystore->read_pubkey == NULL) {
    final_status = BOOT_ERR_NOT_SUPPORTED;
    goto slot_cleanup;
  }

  if (platform->crypto->get_hash_ctx_size != NULL &&
      platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto slot_cleanup;
  }

  memcpy(&local_hdr, hdr, sizeof(local_hdr));

  uint32_t cfi_seed = 0U;
  boot_status_t rng_stat = boot_random_safe(platform, (uint8_t *)&cfi_seed, sizeof(cfi_seed));
  if (rng_stat != BOOT_OK) {
    final_status = (rng_stat == BOOT_ERR_NOT_SUPPORTED) ? BOOT_ERR_CRYPTO : rng_stat;
    goto slot_cleanup;
  }

  boot_cfi_ctx_t slot_cfi;
  boot_cfi_init(slot_cfi, cfi_seed);
  boot_cfi_add_expected(slot_cfi, VERIFY_CFI_SLOT_1);
  boot_cfi_add_expected(slot_cfi, VERIFY_CFI_SLOT_2);
  boot_cfi_add_expected(slot_cfi, VERIFY_CFI_SLOT_3);
  boot_cfi_add_expected(slot_cfi, VERIFY_CFI_SLOT_4);

  BOOT_SECURE_REQUIRE(local_hdr.magic == TOOB_MAGIC_HEADER, {
    final_status = BOOT_ERR_NOT_FOUND;
    goto slot_cleanup;
  });

  uint32_t min_image_size =
      (uint32_t)(sizeof(toob_image_header_t) + sizeof(toob_img_sig_trailer_t));
  if (slot_size < min_image_size || local_hdr.image_size < min_image_size ||
      local_hdr.image_size > slot_size || (UINT32_MAX - slot_addr) < local_hdr.image_size) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto slot_cleanup;
  }

  boot_cfi_step(slot_cfi, VERIFY_CFI_SLOT_1);

  uint32_t signed_len = local_hdr.image_size - (uint32_t)sizeof(toob_img_sig_trailer_t);
  uint32_t trailer_addr = slot_addr + signed_len;

  if (platform->wdt->kick != NULL) {
    platform->wdt->kick();
  }
  boot_status_t read_stat =
      platform->flash->read(trailer_addr, (uint8_t *)&trailer, sizeof(trailer));
  if (read_stat != BOOT_OK) {
    final_status = read_stat;
    goto slot_cleanup;
  }

  BOOT_SECURE_REQUIRE(trailer.magic == TOOB_IMG_SIG_MAGIC, {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  });
  BOOT_SECURE_REQUIRE(trailer.flags == TOOB_IMG_SIG_FLAG_SHA256, {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  });
  BOOT_SECURE_REQUIRE(trailer.reserved == 0U, {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  });
  if (verify_not_all_zeros_glitch_safe(trailer.sig_ed25519, sizeof(trailer.sig_ed25519)) !=
      BOOT_OK) {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  }

  boot_cfi_step(slot_cfi, VERIFY_CFI_SLOT_2);

  boot_status_t key_stat = load_and_verify_root_pubkey(platform, trailer.key_index, root_pubkey);
  if (key_stat != BOOT_OK) {
    final_status = key_stat;
    goto slot_cleanup;
  }

  boot_status_t hash_stat = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
  if (hash_stat != BOOT_OK) {
    final_status = hash_stat;
    goto slot_cleanup;
  }

  uint32_t offset = 0U;
  while (offset < signed_len) {
    if (platform->wdt->kick != NULL) {
      platform->wdt->kick();
    }
    uint32_t remaining = signed_len - offset;
    uint32_t chunk = (remaining < (uint32_t)arena_len) ? remaining : (uint32_t)arena_len;
    read_stat = platform->flash->read(slot_addr + offset, arena, (size_t)chunk);
    if (read_stat != BOOT_OK) {
      uint8_t dummy[64];
      size_t dummy_len = sizeof(dummy);
      (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
      boot_secure_zeroize(dummy, sizeof(dummy));
      final_status = read_stat;
      goto slot_cleanup;
    }

    if (offset == 0U && constant_time_memcmp_glitch_safe(arena, (const uint8_t *)&local_hdr,
                                                         sizeof(local_hdr)) != BOOT_OK) {
      uint8_t dummy[64];
      size_t dummy_len = sizeof(dummy);
      (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
      boot_secure_zeroize(dummy, sizeof(dummy));
      final_status = BOOT_ERR_VERIFY;
      goto slot_cleanup;
    }

    hash_stat = platform->crypto->hash_update(hash_ctx, arena, (size_t)chunk);
    if (hash_stat != BOOT_OK) {
      uint8_t dummy[64];
      size_t dummy_len = sizeof(dummy);
      (void)platform->crypto->hash_finish(hash_ctx, dummy, &dummy_len);
      boot_secure_zeroize(dummy, sizeof(dummy));
      final_status = hash_stat;
      goto slot_cleanup;
    }
    offset += chunk;
  }

  size_t digest_len = sizeof(digest);
  hash_stat = platform->crypto->hash_finish(hash_ctx, digest, &digest_len);
  if (hash_stat != BOOT_OK) {
    final_status = hash_stat;
    goto slot_cleanup;
  }

  BOOT_SECURE_REQUIRE(digest_len == 32U, {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  });

  boot_cfi_step(slot_cfi, VERIFY_CFI_SLOT_3);

  boot_status_t ed_stat =
      verify_ed25519_hardened(platform, digest, sizeof(digest), trailer.sig_ed25519, root_pubkey);
  if (ed_stat != BOOT_OK) {
    final_status = ed_stat;
    goto slot_cleanup;
  }

  boot_cfi_step(slot_cfi, VERIFY_CFI_SLOT_4);

  boot_cfi_require(slot_cfi, {
    final_status = BOOT_ERR_VERIFY;
    goto slot_cleanup;
  });
  final_status = BOOT_OK;

slot_cleanup:
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
  boot_secure_zeroize(&trailer, sizeof(trailer));
  boot_secure_zeroize(&local_hdr, sizeof(local_hdr));
  if (arena != NULL && arena_len > 0U) {
    boot_secure_zeroize(arena, arena_len);
  }
  return final_status;
#endif
}