/**
 * ==============================================================================
 * Toob-Boot OS Boundary: toob_wal_naive.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (WAL Append Boundary)
 * - docs/wal_internals.md (Sequence Wrapping, Torn-Write Defense)
 * - docs/concept_fusion.md (Phase-Bound Verification, Glitch Defense)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Wraparound Proof: RFC 1982 Serial Number Arithmetic verhindert
 *    End-of-Life Deadlocks bei Sequence-ID Überläufen (0xFFFFFFFF -> 0).
 * 2. Phase-Bound Verify: Sichert OS-Flash Writes unmittelbar per ECC-Read-Back.
 * 3. Torn-Write Protection: Valider Erase-State erfordert 100% Block-Coverage.
 * 4. P10 Leakage Prevention: Sämtliche Puffer werden via Zeroize am Ende des
 *    Scopes radiert, um Nonce-Leaking im Feature-OS zu blockieren.
 * 5. DMA Alignment: Structs sind nativ auf 8-Byte Boundaries fixiert.
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <stddef.h>
#include <string.h>

/* ==============================================================================
 * Cross-Compiler Glitch-Delay Injection für Fault-Injection (FI) Defense
 * ==============================================================================
 */
#if defined(__GNUC__) || defined(__clang__)
#define TOOB_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
#elif defined(__ICCARM__)
#include <intrinsics.h>
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __no_operation();                                                          \
    __no_operation();                                                          \
    __no_operation();                                                          \
  } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    __nop();                                                                   \
    __nop();                                                                   \
    __nop();                                                                   \
  } while (0)
#else
#define TOOB_GLITCH_DELAY()                                                    \
  do {                                                                         \
    volatile uint32_t _delay = 0;                                              \
    _delay = 1;                                                                \
    (void)_delay;                                                              \
  } while (0)
#endif

static const uint32_t wal_sector_addrs[CHIP_WAL_SECTORS] =
    TOOB_WAL_SECTOR_ADDRS;
static const uint32_t wal_sector_sizes[CHIP_WAL_SECTORS] =
    TOOB_WAL_SECTOR_SIZES;

/* ==============================================================================
 * INTERNAL MATHEMATICS & HELPERS
 * ==============================================================================
 */

/**
 * @brief OS-Safe Memory Zeroization (Prevents DCE).
 */
static inline void toob_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) {
    *p++ = 0;
  }
}

/**
 * @brief RFC 1982 Serial Number Arithmetic (100% Wrap-Around Safe).
 * Verhindert den finalen OS-Lockout, wenn der Journal Counter iteriert.
 */
static inline bool toob_is_newer_sequence(uint32_t new_seq, uint32_t old_seq) {
  if (new_seq == old_seq)
    return false;
  return ((new_seq > old_seq) && (new_seq - old_seq <= (1U << 31))) ||
         ((new_seq < old_seq) && (old_seq - new_seq > (1U << 31)));
}

/**
 * @brief Beweist mathematisch, ob ein Buffer komplett den Erased-Status
 * aufweist.
 */
static inline bool is_fully_erased(const uint8_t *buf, size_t len,
                                   uint8_t erased_val) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != erased_val)
      return false;
  }
  return true;
}

/**
 * @brief Führt einen speichersicheren, konstanten Zeit-Vergleich aus.
 */
static toob_status_t constant_time_memcmp_glitch_safe(const uint8_t *a,
                                                      const uint8_t *b,
                                                      size_t len) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  for (size_t i = 0; i < len; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[len - 1 - i] ^ b[len - 1 - i]);
  }

  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (acc_fwd == 0)
    shield_1 = TOOB_OK;
  TOOB_GLITCH_DELAY();
  if (shield_1 == TOOB_OK && acc_rev == 0)
    shield_2 = TOOB_OK;

  if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2)
    return TOOB_OK;
  return TOOB_ERR_VERIFY;
}

/* ==============================================================================
 * MAIN OS-API: NAIVE APPEND
 * ==============================================================================
 */

toob_status_t toob_wal_naive_append(const toob_wal_entry_payload_t *intent) {
  toob_status_t final_status = TOOB_OK;

  /* P10 Pointer Guarding */
  if (!intent) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* P10: Garantierte 8-Byte Alignments für sicheres OS-Hardware-DMA */
  toob_wal_entry_aligned_t aligned_buf __attribute__((aligned(8)));
  toob_wal_sector_header_aligned_t sector_header __attribute__((aligned(8)));
  toob_wal_entry_aligned_t flash_entry __attribute__((aligned(8)));

  /* Zeroization Initialisierung (Sicherheit gegen uninitialisierten Stack
   * Garbage) */
  toob_secure_zeroize(&aligned_buf, sizeof(aligned_buf));
  toob_secure_zeroize(&sector_header, sizeof(sector_header));
  toob_secure_zeroize(&flash_entry, sizeof(flash_entry));

  /* Prepare Payload (Padding mit Flash-Erased State füllen) */
  uint8_t erased_byte = (uint8_t)(CHIP_FLASH_ERASURE_MAPPING & 0xFF);
  memset(&aligned_buf, erased_byte, sizeof(aligned_buf));
  memcpy(&aligned_buf.data, intent, sizeof(toob_wal_entry_payload_t));

  /* Robustness: Force MAGIC incase the calling OS logic forgot it */
  aligned_buf.data.magic = TOOB_WAL_ENTRY_MAGIC;

  /* P10 Robustness: Calculate CRC32 via offsetof to eliminate ABI drift */
  size_t payload_len = offsetof(toob_wal_entry_payload_t, crc32_trailer);
  aligned_buf.data.crc32_trailer =
      toob_lib_crc32((const uint8_t *)&aligned_buf.data, payload_len);

  uint32_t active_sector_addr = 0;
  uint32_t active_sector_size = 0;
  uint32_t max_seq = 0;
  bool found_active = false;

  /* ====================================================================
   * Schritt 1: O(1) Discovery - Finde den aktiven Sektor
   * ==================================================================== */
  for (uint32_t i = 0; i < CHIP_WAL_SECTORS; i++) {
    uint32_t sector_addr = wal_sector_addrs[i];

    toob_secure_zeroize(&sector_header, sizeof(sector_header));

    if (toob_os_flash_read(sector_addr, (uint8_t *)&sector_header,
                           TOOB_WAL_HEADER_SIZE) != TOOB_OK) {
      continue;
    }

    /* CRC-32 und Magic-Header Evaluation (Glitch Protected) */
    size_t head_crc_len = offsetof(toob_wal_sector_header_t, header_crc32);
    uint32_t calc_head_crc =
        toob_lib_crc32((const uint8_t *)&sector_header.head, head_crc_len);

    volatile uint32_t shield_1 = 0, shield_2 = 0;
    bool magic_ok = (sector_header.head.sector_magic == TOOB_WAL_SECTOR_MAGIC);
    bool crc_ok = (calc_head_crc == sector_header.head.header_crc32);

    if (magic_ok && crc_ok)
      shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (shield_1 == TOOB_OK && magic_ok && crc_ok)
      shield_2 = TOOB_OK;

    if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2) {
      uint32_t seq_id = sector_header.head.sequence_id;

      /* Wraparound-Sichere O(1) Sliding-Window Bestimmung */
      if (!found_active || toob_is_newer_sequence(seq_id, max_seq)) {
        max_seq = seq_id;
        active_sector_addr = sector_addr;
        active_sector_size = wal_sector_sizes[i];
        found_active = true;
      }
    }
  }

  toob_secure_zeroize(&sector_header, sizeof(sector_header));

  if (!found_active) {
    final_status = TOOB_ERR_NOT_FOUND;
    goto cleanup;
  }

  /* Sanitycheck gegen Underflow bei extremen Sektorgroessen (P10) */
  if (active_sector_size <
      sizeof(toob_wal_entry_aligned_t) + TOOB_WAL_HEADER_SIZE) {
    final_status = TOOB_ERR_FLASH;
    goto cleanup;
  }

  uint32_t last_intent = TOOB_WAL_INTENT_NONE;
  final_status = TOOB_ERR_WAL_FULL;

  /* ====================================================================
   * Schritt 2: Aktiven Sektor scannen nach dem freien Slot (Erased State)
   * ==================================================================== */
  for (uint32_t offset = TOOB_WAL_HEADER_SIZE;
       offset <= active_sector_size - sizeof(toob_wal_entry_aligned_t);
       offset += sizeof(toob_wal_entry_aligned_t)) {

    toob_secure_zeroize(&flash_entry, sizeof(flash_entry));

    if (toob_os_flash_read(active_sector_addr + offset, (uint8_t *)&flash_entry,
                           sizeof(toob_wal_entry_aligned_t)) != TOOB_OK) {
      final_status = TOOB_ERR_FLASH;
      goto cleanup;
    }

    /* FULL-CHUNK ERASE PROOF:
     * Wir prüfen das gesamte 64-Byte Padding, nicht nur die Magic.
     * Das verhindert unwiderruflich, dass wir unsere Bytes in einen
     * durch Brownouts partiell korrumpierten Slot schreiben! */
    if (is_fully_erased((const uint8_t *)&flash_entry,
                        sizeof(toob_wal_entry_aligned_t), erased_byte)) {

      /* OS-API Schutzschaltung (GAP-API): Verhindere, dass das OS ein zweites
       * Update flusht, wenn der Journal-Ring bereits durch ein unfertiges
       * Update blockiert ist. */
      if (aligned_buf.data.intent == TOOB_WAL_INTENT_UPDATE_PENDING) {
        if (last_intent == TOOB_WAL_INTENT_UPDATE_PENDING ||
            last_intent == TOOB_WAL_INTENT_TXN_BEGIN) {
          final_status = TOOB_ERR_WAL_LOCKED;
          goto cleanup;
        }
      }

      /* Freier Slot gefunden! Naive-Append ausfuehren. */
      toob_status_t w_stat = toob_os_flash_write(
          active_sector_addr + offset, (const uint8_t *)&aligned_buf,
          sizeof(toob_wal_entry_aligned_t));

      /* P10 Phase-Bound Read-Back Verify: Garantiert, dass der WAL Eintrag
       * nicht durch SPI-Korruption oder defekte Vendor-Treiber des Feature-OS
       * zerbrochen ins Flash ging! */
      if (w_stat == TOOB_OK) {
        toob_wal_entry_aligned_t verify_buf __attribute__((aligned(8)));
        toob_secure_zeroize(&verify_buf, sizeof(verify_buf));

        if (toob_os_flash_read(active_sector_addr + offset,
                               (uint8_t *)&verify_buf,
                               sizeof(verify_buf)) == TOOB_OK) {
          if (constant_time_memcmp_glitch_safe((const uint8_t *)&aligned_buf,
                                               (const uint8_t *)&verify_buf,
                                               sizeof(verify_buf)) != TOOB_OK) {
            w_stat = TOOB_ERR_FLASH_HW; /* Bit-Rot / Tearing on write */
          }
        } else {
          w_stat = TOOB_ERR_FLASH_HW; /* SPI / Flash failure during Read-Back */
        }
        toob_secure_zeroize(&verify_buf, sizeof(verify_buf));
      }

      final_status = w_stat;
      goto cleanup;
    }

    /* ====================================================================
     * 4. GLITCH RESISTANT INTEGRITY CHECK (Frontier Evaluation)
     * ====================================================================
     * Nicht leer -> Prüfe auf logische Gültigkeit der historischen Entry.
     */
    uint32_t entry_crc =
        toob_lib_crc32((const uint8_t *)&flash_entry.data, payload_len);
    volatile uint32_t shield_1 = 0, shield_2 = 0;

    bool magic_ok = (flash_entry.data.magic == TOOB_WAL_ENTRY_MAGIC);
    bool crc_ok = (entry_crc == flash_entry.data.crc32_trailer);

    if (magic_ok && crc_ok)
      shield_1 = TOOB_OK;
    TOOB_GLITCH_DELAY();
    if (shield_1 == TOOB_OK && magic_ok && crc_ok)
      shield_2 = TOOB_OK;

    if (shield_1 == TOOB_OK && shield_2 == TOOB_OK && shield_1 == shield_2) {
      last_intent = flash_entry.data.intent;
    } else {
      /* P10 RACE-CONDITION DEFENSE: Magic/CRC is neither valid NOR erased.
       * This implies a partially written chunk or sector corruption where wir
       * zuvor gecrasht sind. Halt operation! Bootloader S1 muss dies
       * reparieren! */
      final_status = TOOB_ERR_REQUIRES_RESET;
      goto cleanup;
    }
  }

cleanup:
  /* ====================================================================
   * 5. P10 SINGLE EXIT ZEROIZATION (Leakage Defense)
   * ====================================================================
   * Verhindert Nonce-Leakage oder State-Leakage aus dem OS-SRAM/Stack
   * in nachfolgende C-Funktionen des Feature-OS.
   */
  toob_secure_zeroize(&aligned_buf, sizeof(aligned_buf));
  toob_secure_zeroize(&flash_entry, sizeof(flash_entry));

  return final_status;
}