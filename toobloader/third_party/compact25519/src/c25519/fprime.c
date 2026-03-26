/* Arithmetic in prime fields
 * Daniel Beer <dlbeer@gmail.com>, 10 Jan 2014
 *
 * This file is in the public domain.
 */

#include "fprime.h"
#include "rp_assert.h"

#ifndef COMPACT_DISABLE_ED25519
#ifdef FULL_C25519_CODE
const uint8_t fprime_zero[FPRIME_SIZE] = {0};
const uint8_t fprime_one[FPRIME_SIZE] = {1};
#endif

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
static void raw_add(uint8_t *x, const uint8_t *p) {
  RP_ASSERT(x != NULL, "fprime raw add x");
  RP_ASSERT(p != NULL, "fprime raw add p");
  uint16_t c = 0;
  int i;

  for (i = 0; i < FPRIME_SIZE; i++) {
    c += ((uint16_t)x[i]) + ((uint16_t)p[i]);
    x[i] = c;
    c >>= 8;
  }
}

static void raw_try_sub(uint8_t *x, const uint8_t *p) {
  RP_ASSERT(x != NULL, "fprime tsub x");
  RP_ASSERT(p != NULL, "fprime tsub p");
  uint8_t minusp[FPRIME_SIZE];
  uint16_t c = 0;
  int i;

  for (i = 0; i < FPRIME_SIZE; i++) {
    c = ((uint16_t)x[i]) - ((uint16_t)p[i]) - c;
    minusp[i] = c;
    c = (c >> 8) & 1;
  }

  (void)fprime_select(x, minusp, x, c);
}

/* Warning: this function is variable-time */
static int prime_msb(const uint8_t *p) {
  int i;
  uint8_t x;

  for (i = FPRIME_SIZE - 1; i >= 0; i--)
    if (p[i])
      break;

  x = p[i];
  i <<= 3;

  while (x) {
    x >>= 1;
    i++;
  }

  return i - 1;
}

/* Warning: this function may be variable-time in the argument n */
static void shift_n_bits(uint8_t *x, int n) {
  uint16_t c = 0;
  int i;

  for (i = 0; i < FPRIME_SIZE; i++) {
    c |= ((uint16_t)x[i]) << n;
    x[i] = c;
    c >>= 8;
  }
}

#ifdef FULL_C25519_CODE
/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_load(uint8_t *x, uint32_t c) {
  RP_ASSERT(x != NULL, "fload x");
  unsigned int i;

  for (i = 0; i < sizeof(c); i++) {
    x[i] = c;
    c >>= 8;
  }

  for (; i < FPRIME_SIZE; i++)
    x[i] = 0;
}
#endif

static inline int min_int(int a, int b) { return a < b ? a : b; }

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_from_bytes(uint8_t *n, const uint8_t *x, size_t len,
                       const uint8_t *modulus) {
  RP_ASSERT(n != NULL, "ffb n");
  RP_ASSERT(x != NULL, "ffb x");
  RP_ASSERT(modulus != NULL, "ffb mod");
  const int preload_total = min_int(prime_msb(modulus) - 1, len << 3);
  const int preload_bytes = preload_total >> 3;
  const int preload_bits = preload_total & 7;
  const int rbits = (len << 3) - preload_total;
  int i;

  (void)memset(n, 0, FPRIME_SIZE);

  for (i = 0; i < preload_bytes; i++)
    n[i] = x[len - preload_bytes + i];

  if (preload_bits) {
    (void)shift_n_bits(n, preload_bits);
    n[0] |= x[len - preload_bytes - 1] >> (8 - preload_bits);
  }

  for (i = rbits - 1; i >= 0; i--) {
    const uint8_t bit = (x[i >> 3] >> (i & 7)) & 1;

    (void)shift_n_bits(n, 1);
    n[0] |= bit;
    (void)raw_try_sub(n, modulus);
  }
}

#ifdef FULL_C25519_CODE
/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_normalize(uint8_t *x, const uint8_t *modulus) {
  RP_ASSERT(x != NULL, "fnorm x");
  RP_ASSERT(modulus != NULL, "fnorm mod");
  uint8_t n[FPRIME_SIZE];

  (void)fprime_from_bytes(n, x, FPRIME_SIZE, modulus);
  (void)fprime_copy(x, n);
}

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
uint8_t fprime_eq(const uint8_t *x, const uint8_t *y) {
  RP_ASSERT(x != NULL, "feq x");
  RP_ASSERT(y != NULL, "feq y");
  uint8_t sum = 0;
  int i;

  for (i = 0; i < FPRIME_SIZE; i++)
    sum |= x[i] ^ y[i];

  sum |= (sum >> 4);
  sum |= (sum >> 2);
  sum |= (sum >> 1);

  return (sum ^ 1) & 1;
}
#endif
/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_select(uint8_t *dst, const uint8_t *zero, const uint8_t *one,
                   uint8_t condition) {
  RP_ASSERT(dst != NULL, "fsel d");
  RP_ASSERT(zero != NULL, "fsel z");
  RP_ASSERT(one != NULL, "fsel o");
  const uint8_t mask = -condition;
  int i;

  for (i = 0; i < FPRIME_SIZE; i++)
    dst[i] = zero[i] ^ (mask & (one[i] ^ zero[i]));
}

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_add(uint8_t *r, const uint8_t *a, const uint8_t *modulus) {
  RP_ASSERT(r != NULL, "fadd r");
  RP_ASSERT(a != NULL, "fadd a");
  RP_ASSERT(modulus != NULL, "fadd m");
  (void)raw_add(r, a);
  (void)raw_try_sub(r, modulus);
}

#ifdef FULL_C25519_CODE
/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_sub(uint8_t *r, const uint8_t *a, const uint8_t *modulus) {
  RP_ASSERT(r != NULL, "fsub r");
  RP_ASSERT(a != NULL, "fsub a");
  RP_ASSERT(modulus != NULL, "fsub m");
  (void)raw_add(r, modulus);
  (void)raw_try_sub(r, a);
  (void)raw_try_sub(r, modulus);
}
#endif

/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_mul(uint8_t *r, const uint8_t *a, const uint8_t *b,
                const uint8_t *modulus) {
  RP_ASSERT(r != NULL, "fmul r");
  RP_ASSERT(a != NULL, "fmul a");
  RP_ASSERT(b != NULL, "fmul b");
  RP_ASSERT(modulus != NULL, "fmul m");
  int i;

  (void)memset(r, 0, FPRIME_SIZE);

  for (i = prime_msb(modulus); i >= 0; i--) {
    const uint8_t bit = (b[i >> 3] >> (i & 7)) & 1;
    uint8_t plusa[FPRIME_SIZE];

    (void)shift_n_bits(r, 1);
    (void)raw_try_sub(r, modulus);

    (void)fprime_copy(plusa, r);
    (void)fprime_add(plusa, a, modulus);

    (void)fprime_select(r, r, plusa, bit);
  }
}

#ifdef FULL_C25519_CODE
/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
KB_CORE()
void fprime_inv(uint8_t *r, const uint8_t *a, const uint8_t *modulus) {
  RP_ASSERT(r != NULL, "finv r");
  RP_ASSERT(a != NULL, "finv a");
  RP_ASSERT(modulus != NULL, "finv mod");
  uint8_t pm2[FPRIME_SIZE];
  uint16_t c = 2;
  int i;

  /* Compute (p-2) */
  (void)fprime_copy(pm2, modulus);
  for (i = 0; i < FPRIME_SIZE; i++) {
    c = modulus[i] - c;
    pm2[i] = c;
    c >>= 8;
  }

  /* Binary exponentiation */
  (void)fprime_load(r, 1);

  for (i = prime_msb(modulus); i >= 0; i--) {
    uint8_t r2[FPRIME_SIZE];

    (void)fprime_mul(r2, r, r, modulus);

    if ((pm2[i >> 3] >> (i & 7)) & 1)
      (void)fprime_mul(r, r2, a, modulus);
    else
      (void)fprime_copy(r, r2);
  }
}
#endif
#endif
