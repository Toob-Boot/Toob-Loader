/*
 * ==============================================================================
 * Toob-Boot Core File: boot_merkle.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/merkle_spec.md (Chunk-wise Streaming, RAM Limit)
 * - docs/concept_fusion.md (WDT Kicks, Hash Alignment, Glitch-Defense)
 * - docs/testing_requirements.md (P10 Bound Checks, Constant Time Execution)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. O(1) ALU Stream-Pointer: Vermeidet Multiplikationen pro Iteration.
 * 2. Glitch-Resistant Tearing Defense: Forward/Backward Hash-Comparison
 * blockiert Single-Bit Voltage-Glitches in der Krypto-Evaluierung komplett.
 * 3. Array Overflow Traps (CVE-Prevention): Sichert (num_chunks * HASH_LEN) und
 *    Flash-Pointer auf 32-bit Architekturen absolut gegen Integer Wraparounds
 * ab.
 * 4. P10 Stack Zeroization: Nullifiziert Residuen zwingend nach Nutzung via
 * Single-Exit.
 */

#include "boot_merkle.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include <string.h>


/* Mathematisches Glitch-Resistenz-Gating. Darf sich statisch nicht auf
 * implizierte Enums verlassen! */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein, um "
               "das Double-Check Pattern zu garantieren!");

/**
 * @brief Führt einen speichersicheren, konstanten Zeit-Vergleich für SHA-256
 * Hashes aus. O(1) Laufzeit ohne SRAM-Bus-Stalls, doppelt gesichert gegen
 * physikalische Voltage-Glitches.
 */
static inline boot_status_t
constant_time_memcmp_32_glitch_safe(const uint8_t *a, const uint8_t *b) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  /* ALU Loop Unrolling durch den Compiler erlauben, aber Datenabhängigkeit
   * erzwingen. Vorwärts- und Rückwärts-Evaluierung macht Timing-Orakel und
   * Fault-Injection extrem schwer. Byte-Zugriffe gewährleisten Cortex-M0
   * (Unaligned-Access) Kompatibilität ohne HardFaults. */
  for (uint32_t i = 0; i < BOOT_MERKLE_HASH_LEN; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[BOOT_MERKLE_HASH_LEN - 1 - i] ^
                          b[BOOT_MERKLE_HASH_LEN - 1 - i]);
  }

  /* P10 Glitch-Defense Pattern via Hamming-Distance Mapping */
  volatile uint32_t flag1 = 0;
  volatile uint32_t flag2 = 0;

  if (acc_fwd == 0) {
    flag1 = BOOT_OK; /* 0x55AA55AA */
  }

  /* Branch Delay Injection gegen Voltage Faults (Instruction Skips) */
  BOOT_GLITCH_DELAY();

  if (flag1 == BOOT_OK && acc_rev == 0) {
    flag2 = BOOT_OK;
  }

  /* Dualer Check schließt asynchrone Manipulationen aus */
  if (flag1 != flag2 || flag2 != BOOT_OK) {
    return BOOT_ERR_VERIFY;
  }

  return BOOT_OK;
}

boot_status_t
boot_merkle_verify_stream(const boot_platform_t *platform,
                          uint32_t image_flash_addr, uint32_t image_size,
                          uint32_t chunk_size, const uint8_t *chunk_hashes,
                          uint32_t chunk_hashes_len, uint32_t num_chunks,
                          uint8_t *crypto_arena, size_t arena_size) {

  boot_status_t stat = BOOT_OK;

  /* ====================================================================
   * 1. P10 STACK ALLOCATION & ZEROIZATION
   * ==================================================================== */
  /* P10 Rule: Context Memory muss strikt 64-Bit / 8-Byte aligned sein */
  _Static_assert(BOOT_MERKLE_MAX_CTX_SIZE % sizeof(uint64_t) == 0,
                 "BOOT_MERKLE_MAX_CTX_SIZE must be exactly divisible by 8");

  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  uint8_t computed_hash[BOOT_MERKLE_HASH_LEN] __attribute__((aligned(8)));

  /* Zwingende Initialisierung aller Stack-Bereiche (Verhindert Leakage) */
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(computed_hash, sizeof(computed_hash));

  /* ====================================================================
   * 2. P10 POINTER & HAL VALIDATION (Zero-Trust)
   * ==================================================================== */
  if (!platform || !platform->wdt || !platform->crypto || !platform->flash) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* Strenges HAL-Capability Gating */
  if (!platform->crypto->hash_init || !platform->crypto->hash_update ||
      !platform->crypto->hash_finish || !platform->crypto->get_hash_ctx_size ||
      !platform->flash->read || !platform->wdt->kick) {
    stat = BOOT_ERR_NOT_SUPPORTED;
    goto cleanup;
  }

  if (!chunk_hashes || !crypto_arena) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  if (image_size == 0 || chunk_size == 0 || num_chunks == 0 ||
      arena_size == 0 || chunk_hashes_len == 0) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* P10 VLA Defense: Stack-Size Enforcement für Context Memory.
   * Verhindert Stack-Overflows, wenn Vendor-HAL PQC konfiguriert. */
  if (platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* ====================================================================
   * 3. MATHEMATICAL BOUNDS & CVE PREVENTION
   * ==================================================================== */

  /* 3.1 Wrap-Check: Verhindert (image_flash_addr + image_size) Overflow in der
   * Flash-Zone */
  if (UINT32_MAX - image_flash_addr < image_size) {
    stat = BOOT_ERR_FLASH_BOUNDS;
    goto cleanup;
  }

  /* 3.2 Wrap-Check: Verhindert Chunk-Multiplikation Overflows bei präparierten
   * Arrays */
  if (num_chunks > (UINT32_MAX / chunk_size)) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* 3.3 Array Overflow Trap: Sichert (num_chunks * HASH_LEN) auf 32-bit
   * Architekturen absolut ab */
  if (num_chunks > (UINT32_MAX / BOOT_MERKLE_HASH_LEN)) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }
  if ((num_chunks * BOOT_MERKLE_HASH_LEN) > chunk_hashes_len) {
    stat = BOOT_ERR_INVALID_ARG; /* Out-Of-Bounds Buffer Leak Versuch
                                    unwiderruflich blockiert */
    goto cleanup;
  }

  /* 3.4 Pointer-Space Wrap-Around Guard */
  if ((uintptr_t)chunk_hashes >
      (UINTPTR_MAX - (num_chunks * BOOT_MERKLE_HASH_LEN))) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* 3.5 GAP-F17 Chunk-Size Verifikation */
  if (chunk_size > platform->flash->max_sector_size) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }
  if (platform->flash->write_align > 0 &&
      (chunk_size % platform->flash->write_align) != 0) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* 3.6 SRAM Buffer Bounds-Check */
  if (arena_size < chunk_size) {
    stat = BOOT_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* 3.7 Malleability by Truncation Defense (Exakte Hash-Anzahl Evaluierung,
   * Wraparound-Safe) Verhindert Angriffe durch Abschneiden des Manifests. O(1)
   * Branchless Math. */
  uint32_t required_chunks =
      (image_size / chunk_size) + ((image_size % chunk_size) > 0 ? 1U : 0U);
  if (num_chunks != required_chunks) {
    stat = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  /* ====================================================================
   * 4. STREAMING HASH EXECUTION (O(1) ALU Overhead & P10 Safety)
   * ==================================================================== */

  /* O(1) Pointer-Tracker (Reduziert Rechenoverhead / MUL-Instruktionen in der
   * heißen Iteration) */
  uint32_t remaining_bytes = image_size;
  uint32_t current_flash_addr = image_flash_addr;
  const uint8_t *current_hash_ptr = chunk_hashes;

  for (uint32_t i = 0; i < num_chunks; i++) {
    /* Anti-Lockup (concept_fusion.md): Watchdog vor schweren IO-Operationen
     * füttern */
    platform->wdt->kick();

    uint32_t read_len =
        (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

    /* O(1) Chunk RAM-Transfer (Vermeidet OTFDEC Timings) */
    stat = platform->flash->read(current_flash_addr, crypto_arena, read_len);

    platform->wdt->kick();

    if (stat != BOOT_OK) {
      goto cleanup;
    }

    /* Stream-basiertes asymmetrisches Flat-Hashing */
    stat = platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
    if (stat != BOOT_OK)
      goto cleanup;

    stat = platform->crypto->hash_update(hash_ctx, crypto_arena, read_len);
    if (stat != BOOT_OK)
      goto cleanup;

    /* P10 Rule: Buffer sicher nullen, bevor er an externe HW-Register übergeben
     * wird */
    boot_secure_zeroize(computed_hash, sizeof(computed_hash));

    size_t digest_len = BOOT_MERKLE_HASH_LEN;
    stat = platform->crypto->hash_finish(hash_ctx, computed_hash, &digest_len);

    if (stat != BOOT_OK || digest_len != BOOT_MERKLE_HASH_LEN) {
      stat = (stat != BOOT_OK) ? stat : BOOT_ERR_VERIFY;
      goto cleanup;
    }

    /* Glitch-Resistant CONSTANT-TIME Verifikation (gibt sauber BOOT_ERR_VERIFY
     * bei Fail zurück) */
    stat = constant_time_memcmp_32_glitch_safe(computed_hash, current_hash_ptr);

    /* O(1) Säuberung transienter Secrets sofort nach der Nutzung (Verhindert
     * Leakage bei Interrupts) */
    boot_secure_zeroize(computed_hash, sizeof(computed_hash));

    if (stat != BOOT_OK) {
      goto cleanup;
    }

    /* O(1) Pointer-Arithmetik statt der alten "i * chunk_size" Multiplikation
     */
    remaining_bytes -= read_len;
    current_flash_addr += read_len;
    current_hash_ptr += BOOT_MERKLE_HASH_LEN;
  }

  /* Mathematischer Coverage-Beweis gegen Loop-Abortion Glitches (Voltage
   * Faults) Verhindert Angriffe, bei denen die For-Schleife nach wenigen
   * validen Chunks gewaltsam zum Abbruch gezwungen wird. */
  volatile uint32_t loop_guard_1 = 0;
  volatile uint32_t loop_guard_2 = 0;

  if (remaining_bytes == 0) {
    loop_guard_1 = BOOT_OK;
  }

  BOOT_GLITCH_DELAY(); /* Branch Skips Mitigation */

  if (loop_guard_1 == BOOT_OK && remaining_bytes == 0) {
    loop_guard_2 = BOOT_OK;
  }

  if (loop_guard_1 != loop_guard_2 || loop_guard_2 != BOOT_OK) {
    stat = BOOT_ERR_VERIFY;
    goto cleanup;
  }

  stat = BOOT_OK;

cleanup:
  /* ====================================================================
   * 5. P10 SINGLE EXIT: SECURE ZEROIZE FALLBACK
   * ====================================================================
   * Egal ob Erfolg oder Fail: Manipulierte Daten und Krypto-Residuen werden
   * radikal aus dem RAM gewischt, bevor die Funktion zurückkehrt. */
  if (crypto_arena != NULL && arena_size > 0) {
    boot_secure_zeroize(crypto_arena, arena_size);
  }

  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
  boot_secure_zeroize(computed_hash, sizeof(computed_hash));

  return stat;
}