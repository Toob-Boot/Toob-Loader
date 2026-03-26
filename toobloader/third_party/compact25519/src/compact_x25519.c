
#ifndef COMPACT_DISABLE_X25519
#include "compact_x25519.h"
#include "c25519/c25519.h"
#include "c25519/sha512.h"
#include "compact_wipe.h"
#include "rp_assert.h"

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
void compact_x25519_keygen(uint8_t private_key[X25519_KEY_SIZE],
                           uint8_t public_key[X25519_KEY_SIZE],
                           uint8_t random_seed[X25519_KEY_SIZE]) {
  RP_ASSERT(private_key != NULL, "cx25519_k pk");
  RP_ASSERT(public_key != NULL, "cx25519_k puk");
  RP_ASSERT(random_seed != NULL, "cx25519_k rs");
  (void)memcpy(private_key, random_seed, X25519_KEY_SIZE);
  compact_wipe(random_seed, X25519_KEY_SIZE);
  c25519_prepare(private_key);
  c25519_smult(public_key, c25519_base_x, private_key);
}

void compact_x25519_shared(uint8_t shared_secret[X25519_SHARED_SIZE],
                           const uint8_t my_private_key[X25519_KEY_SIZE],
                           const uint8_t their_public_key[X25519_KEY_SIZE]) {
  RP_ASSERT(shared_secret != NULL, "cx25519_s ss");
  RP_ASSERT(my_private_key != NULL, "cx25519_s mpk");
  RP_ASSERT(their_public_key != NULL, "cx25519_s tpk");
  // Ensure that supplied private key is clamped (fix issue #1).
  // Calling `c25519_prepare` multiple times for the same private key
  // is OK because it won't modify already clamped key.
  uint8_t clamped_private_key[X25519_KEY_SIZE];
  (void)memcpy(clamped_private_key, my_private_key, X25519_KEY_SIZE);
  c25519_prepare(clamped_private_key);
  c25519_smult(shared_secret, their_public_key, clamped_private_key);
  compact_wipe(clamped_private_key, X25519_KEY_SIZE);
}

#ifndef COMPACT_DISABLE_X25519_DERIVE
#if (X25519_KEY_SIZE + (2 * X25519_KEY_SIZE)) > SHA512_BLOCK_SIZE
#error "Unexpected key sizes"
#endif

/**
 * @osv
 * component: Kernel.Security.Crypto
 * tag_status: auto
 */
KB_CORE()
static uint8_t *append(uint8_t *dst, const void *source, size_t length) {
  RP_ASSERT(dst != NULL, "app d");
  RP_ASSERT(source != NULL, "app s");
  (void)memcpy(dst, source, length);
  return dst + length;
}

void compact_x25519_derive_encryption_key(
    uint8_t *encryption_key, size_t key_size,
    const uint8_t shared_secret[X25519_SHARED_SIZE],
    const uint8_t public_key1[X25519_KEY_SIZE],
    const uint8_t public_key2[X25519_KEY_SIZE]) {
  RP_ASSERT(encryption_key != NULL, "cx25519_dek ek");
  RP_ASSERT(shared_secret != NULL, "cx25519_dek ss");
  RP_ASSERT(public_key1 != NULL, "cx25519_dek pk1");
  RP_ASSERT(public_key2 != NULL, "cx25519_dek pk2");
  if (key_size > SHA512_HASH_SIZE) {
    key_size = SHA512_HASH_SIZE;
  }
  uint8_t key_data[X25519_SHARED_SIZE + 2 * X25519_KEY_SIZE];
  uint8_t *p = key_data;
  p = append(p, shared_secret, X25519_SHARED_SIZE);
  p = append(p, public_key1, X25519_KEY_SIZE);
  (void)append(p, public_key2, X25519_KEY_SIZE);

  struct sha512_state hasher;
  (void)sha512_init(&hasher);
  (void)sha512_final(&hasher, key_data, sizeof(key_data));
  (void)sha512_get(&hasher, encryption_key, 0, key_size);

  (void)compact_wipe(key_data,
                     X25519_SHARED_SIZE); // clear the session key at least
}
#endif
#endif
