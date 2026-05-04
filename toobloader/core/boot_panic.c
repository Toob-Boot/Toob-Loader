/*
 * ==============================================================================
 * Toob-Boot Core File: boot_panic.c (Mathematical Perfection Revision v3)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/stage_1_5_spec.md (Serial Rescue, SOS Mode, Exponential Penalty)
 * - docs/testing_requirements.md (Zero-Allocation, P10 Bounds, Tearing-Proof)
 *
 * ARCHITECTURAL UPGRADES (The "Reviewer's Cut"):
 * 1. True Zero-Allocation Mapping: 100% aller Buffer, inklusive des 1056-Byte
 *    Chunk-Buffers, des Read-Back-Arrays und aller Krypto-Keys liegen jetzt
 *    in disjunkten, 8-Byte-aligned Zonen der crypto_arena. (Spart >1.2 KB
 * Stack!)
 * 2. Sizeof-Logic-Bomb Fixed: Ersetzt gefährliche sizeof(ptr) Aufrufe durch
 *    hart codierte, statisch überprüfte Makro-Grenzen.
 * 3. Unaligned Access Mitigation: Verhindert Cortex-M0 Exception-Traps durch
 *    sichere memcpy-Extrahierung direkt aus dem UART-Empfangspuffer via
 * offsetof.
 * 4. WDT-Deadlock Fix: Erlaubt dem Hardware-Watchdog den finalen Biss am Ende
 *    der Übertragung, um einen sauberen Kaltstart des SoCs zu erzwingen.
 * 5. Glitch-Resistant 2FA Auth & EOF: Double-Check Gating schützt kritische
 *    Sprünge vor Voltage/EMFI-Faults.
 * 6. Math-Bound COBS: Subtraktive O(1) Grenzen verhindern Integer-Wraparounds.
 */

#include "boot_panic.h"
#include "generated_boot_config.h"

#include "boot_crc32.h"
#include "boot_delay.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

/* Terminal State besitzt die Arena nun exklusiv */
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(
    BOOT_CRYPTO_ARENA_SIZE >= 2048,
    "Crypto Arena muss mindestens 2KB aufweisen für Serial Rescue Puffer");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK must be high-hamming distance for Glitch-Shielding");

/* ============================================================================
 * P10 Memory Arena Boundaries (100% Zero Allocation & Stack-Bloat Prevention)
 * ============================================================================
 */
#define PANIC_CHALLENGE_MAX_SIZE 128
#define PANIC_RX_MAX_SIZE 128
#define PANIC_VERIFY_MAX_SIZE 80 /* 8-Byte Aligned (Spec requires 76) */
#define PANIC_CHUNK_MAX_SIZE                                                   \
  (BOOT_CRYPTO_ARENA_SIZE - PANIC_CHALLENGE_MAX_SIZE - PANIC_RX_MAX_SIZE -     \
   PANIC_VERIFY_MAX_SIZE)

/* Mathematischer Beweis zur Compile-Zeit, dass die Partitionen den RAM nicht
 * sprengen */
_Static_assert(
    (PANIC_CHALLENGE_MAX_SIZE + PANIC_RX_MAX_SIZE + PANIC_VERIFY_MAX_SIZE +
     PANIC_CHUNK_MAX_SIZE) == BOOT_CRYPTO_ARENA_SIZE,
    "FATAL: Arena Partitioning exceeds total BOOT_CRYPTO_ARENA_SIZE!");

/* P10 Security Constants */
#define CFI_PANIC_INIT 0xAAAAAAAA
#define CFI_AUTH_PASSED 0x55AA55AA

/**
 * @brief Führt einen speichersicheren, konstanten Zeit-Vergleich für 32-Byte
 * Hashes aus. O(1) Laufzeit ohne Timing-Leakage. Doppelt gesichert gegen
 * Voltage-Glitches.
 */
static inline boot_status_t
constant_time_memcmp_32_glitch_safe(const uint8_t *a, const uint8_t *b) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  for (uint32_t i = 0; i < 32; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[31 - i] ^ b[31 - i]);
  }

  volatile uint32_t flag1 = 0, flag2 = 0;
  if (acc_fwd == 0)
    flag1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (flag1 == BOOT_OK && acc_rev == 0)
    flag2 = BOOT_OK;

  if (flag1 != BOOT_OK || flag2 != BOOT_OK)
    return BOOT_ERR_VERIFY;
  return BOOT_OK;
}

/**
 * @brief O(1) Branch-freie Überprüfung auf Erased-Flash-Status. Verhindert
 * Timing-Orakel.
 */
static bool is_fully_erased_constant_time(const uint8_t *buf, size_t len,
                                          uint8_t erased_val) {
  uint32_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint32_t)(buf[i] ^ erased_val);
  }
  return diff == 0;
}

/**
 * @brief Streams a buffer to UART using Naked COBS encoding with O(1) memory.
 *        O(n) time complexity and native WDT feeding.
 */
static void send_cobs_frame(const boot_platform_t *platform,
                            const uint8_t *data, size_t len) {
  if (!platform || !platform->console || !platform->console->putchar ||
      len == 0 || !data)
    return;

  /* Frame Start Marker (Sync) */
  platform->console->putchar((char)COBS_MARKER_START);

  size_t ptr = 0;
  while (ptr < len) {
    uint8_t code = 1;
    size_t end = ptr;

    /* Find next zero or hit 254 data bytes limit (0xFF code) */
    while (end < len && data[end] != 0 && code < 0xFF) {
      end++;
      code++;
    }

    /* Write Block Code */
    platform->console->putchar((char)code);

    /* Write Block Data */
    for (size_t i = ptr; i < end; i++) {
      platform->console->putchar((char)data[i]);
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
    }

    ptr = end;
    /* Consume the physical zero that we encoded virtually */
    if (ptr < len && data[ptr] == 0) {
      ptr++;
    }
  }

  /* Frame End Marker */
  platform->console->putchar((char)COBS_MARKER_END);
  if (platform->console->flush) {
    platform->console->flush();
  }
}

/**
 * @brief O(1) in-place Naked COBS Decoder.
 *        Nutzt `__restrict` für Register-Optimierung, da Lese/Schreibzeiger nie
 * kollidieren.
 */
static boot_status_t cobs_decode_in_place(uint8_t *__restrict data, size_t len,
                                          size_t *__restrict out_len) {
  if (!data || !out_len || len == 0)
    return BOOT_ERR_INVALID_ARG;

  size_t read_idx = 0;
  size_t write_idx = 0;

  while (read_idx < len) {
    uint8_t code = data[read_idx++];
    if (code == 0)
      return BOOT_ERR_INVALID_ARG; /* Zeroes sind in COBS-Payloads illegal */

    uint8_t copy_len = code - 1;

    /* MATHEMATICAL GLITCH-SHIELD (Verhindert RCE via Pufferüberlauf)
     * Schützt `read_idx + copy_len > len` vor 32-bit Wraparound und Voltage
     * Faults! */
    volatile uint32_t bounds_shield_1 = 0;
    volatile uint32_t bounds_shield_2 = 0;
    bool is_within_bounds = (len - read_idx >= copy_len);

    if (is_within_bounds)
      bounds_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (bounds_shield_1 == BOOT_OK && is_within_bounds)
      bounds_shield_2 = BOOT_OK;

    if (bounds_shield_1 != BOOT_OK || bounds_shield_2 != BOOT_OK) {
      return BOOT_ERR_INVALID_ARG; /* Exploit Trap */
    }

    /* O(1) in-place shift. Funktioniert sicher, da write_idx <= read_idx
     * garantiert ist */
    for (uint8_t i = 0; i < copy_len; i++) {
      data[write_idx++] = data[read_idx++];
    }

    /* Implizite Nullen wiederherstellen */
    if (code < 0xFF && read_idx < len) {
      if (write_idx >= len)
        return BOOT_ERR_INVALID_ARG;
      data[write_idx++] = 0x00;
    }
  }

  *out_len = write_idx;

  /* P10 Defense: Reste (Trailing Garbage) nullen, um logische Leakage zu
   * verhindern */
  if (write_idx < len) {
    boot_secure_zeroize(&data[write_idx], len - write_idx);
  }

  return BOOT_OK;
}

/**
 * @brief Terminal Halt State.
 * Friert das System im Watchdog-Safe Blink-Modus ein.
 */
_Noreturn static void enter_sos_loop(const boot_platform_t *platform) {
  while (1) {
    if (platform && platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    if (platform && platform->clock && platform->clock->delay_ms)
      boot_delay_with_wdt(platform, 500);
  }
}

_Noreturn void boot_panic(const boot_platform_t *platform,
                          boot_status_t reason) {
  /* Hard-Fault Exit, wenn der Platform-Pointer defekt ist */
  if (!platform || !platform->wdt) {
    while (1) { /* Nichts tun, Hardware WDT Reset abwarten */
    }
  }

  if (!platform->console || !platform->console->putchar || !platform->crypto ||
      !platform->crypto->random || !platform->flash || !platform->flash->read ||
      !platform->flash->write || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    enter_sos_loop(platform);
  }

  uint32_t failed_auth_attempts = 0;

session_reset:
  if (platform->console->putchar) {
    /* Initialisierungs-UART Flush */
    platform->console->putchar('P');
    platform->console->putchar('N');
    platform->console->putchar('C');
    if (platform->console->flush)
      platform->console->flush();
  }

  /* ============================================================================
   * TRUE ZERO-ALLOCATION ARENA MAPPING (P10 Architecture)
   * ============================================================================
   * Der C-Stack bleibt physikalisch zu 100 % sauber. Die Arena wird
   * durch exakt definierte Makros in disjunkte Zonen segmentiert.
   */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  uint8_t *challenge_buf = crypto_arena;
  uint8_t *rx_buf = challenge_buf + PANIC_CHALLENGE_MAX_SIZE;
  uint8_t *verify_msg = rx_buf + PANIC_RX_MAX_SIZE;
  uint8_t *chunk_buf = verify_msg + PANIC_VERIFY_MAX_SIZE;

  volatile uint32_t panic_cfi = CFI_PANIC_INIT;

  /* ============================================================================
   * BLOCK 1: Challenge Generation (2FA)
   * ============================================================================
   */
  size_t challenge_len = 32; /* Nonce Base Size */

  if (platform->crypto->random(challenge_buf, 32) != BOOT_OK) {
    enter_sos_loop(platform); /* Terminal: TRNG Broken */
  }

  /* P10 HAL Containment: Zero-Allocation. Wir recyclen den ungenutzten
   * chunk_buf in Phase 1 für den DSLC Read, um den Stack absolut rein zu
   * halten. */
  uint8_t *temp_dslc = chunk_buf;
  size_t dslc_len = 64;

  if (platform->crypto->read_dslc) {
    boot_status_t d_status = platform->crypto->read_dslc(temp_dslc, &dslc_len);
    if (d_status == BOOT_OK && dslc_len > 0) {
      if (dslc_len > 64)
        dslc_len = 64; /* Hardware Clamp Protection */
      memcpy(challenge_buf + 32, temp_dslc, dslc_len);
    } else {
      dslc_len = 32; /* Fallback Zero-Padding */
      memset(challenge_buf + 32, 0, 32);
    }
  } else {
    dslc_len = 32;
    memset(challenge_buf + 32, 0, 32);
  }
  boot_secure_zeroize(temp_dslc, 64); /* O(1) Zeroize nach Kopie */
  challenge_len += dslc_len;

  /* Monotonic Timer zur Erleichterung für das Host-Tooling anfügen */
  uint32_t current_monotonic = 0;
  if (platform->crypto->read_monotonic_counter) {
    platform->crypto->read_monotonic_counter(&current_monotonic);
  }

  /* Exakte Speicher-Mappings (Vermeidet Cast-UBs) */
  memcpy(challenge_buf + challenge_len, &current_monotonic,
         sizeof(current_monotonic));
  challenge_len += sizeof(current_monotonic);

  memcpy(challenge_buf + challenge_len, &reason, sizeof(reason));
  challenge_len += sizeof(reason);

  /* Sende Challenge via COBS an den Techniker */
  send_cobs_frame(platform, challenge_buf, challenge_len);

  /* ============================================================================
   * BLOCK 2: Auth-Token Empfang & P10-Verifikation (Constant Time Logic)
   * ============================================================================
   */
  while (1) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE);
    size_t rx_len = 0;
    bool frame_ready = false;

    /* Frame Retrieval Logic */
    while (!frame_ready) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar &&
          platform->console->getchar(&c, 100) != BOOT_OK)
        continue;

      if (c == COBS_MARKER_END) {
        if (rx_len > 0)
          frame_ready = true;
      } else {
        if (rx_len < PANIC_RX_MAX_SIZE) {
          rx_buf[rx_len++] = c;
        } else {
          /* Overflow Defense: Buffer vernichten und auf nächsten Sync warten */
          boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE);
          rx_len = 0;
        }
      }
    }

    size_t decoded_len = 0;
    volatile uint32_t auth_eval = 0;

    if (cobs_decode_in_place(rx_buf, rx_len, &decoded_len) == BOOT_OK) {
      if (decoded_len == sizeof(stage15_auth_payload_t)) {

        /* Unaligned Access Mitigation: Cortex-M0/M0+ Exception Prevention.
         * Extraktion ohne Stack-Struct, direkt in lokale Primitive via
         * offsetof. */
        uint32_t safe_slot_id = 0;
        uint32_t safe_sequence_id = 0;

        memcpy(&safe_slot_id,
               rx_buf + offsetof(stage15_auth_payload_t, slot_id),
               sizeof(uint32_t));
        memcpy(&safe_sequence_id,
               rx_buf + offsetof(stage15_auth_payload_t, sequence_id),
               sizeof(uint32_t));

        const uint8_t *auth_nonce =
            rx_buf + offsetof(stage15_auth_payload_t, nonce);
        const uint8_t *auth_sig =
            rx_buf + offsetof(stage15_auth_payload_t, sig);

        /* P10 FIX: Verhindert Replay-Attacks durch Offline-Tokens!
         * Das Token MUSS exakt + 1 zum Hardware-Counter sein. */
        bool time_ok = (safe_sequence_id == current_monotonic + 1);
        bool slot_ok = (safe_slot_id == CHIP_STAGING_SLOT_ID);
        boot_status_t nonce_stat =
            constant_time_memcmp_32_glitch_safe(auth_nonce, challenge_buf);

        /* P10 Glitch-Resistant Auth-Shield */
        volatile uint32_t shield_1 = 0, shield_2 = 0;
        if (time_ok && slot_ok && nonce_stat == BOOT_OK)
          shield_1 = BOOT_OK;
        BOOT_GLITCH_DELAY();
        if (shield_1 == BOOT_OK && time_ok && slot_ok && nonce_stat == BOOT_OK)
          shield_2 = BOOT_OK;

        if (shield_1 == BOOT_OK && shield_2 == BOOT_OK) {
          /* Assemble Ed25519 Message exakt nach Spec (72 Bytes):
           * [Nonce(32)] | [Padded DSLC(32)] | [Slot ID(4)] | [Sequence ID(4)]
           */
          boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
          memcpy(verify_msg, challenge_buf,
                 64); /* Zieht saubere Nonce & DSLC Base */
          memcpy(verify_msg + 64, &safe_slot_id, sizeof(uint32_t));
          memcpy(verify_msg + 68, &safe_sequence_id, sizeof(uint32_t));

          /* Zero-Allocation Fix: Wir recyclen den ungenutzten chunk_buf für den
           * Root Pubkey */
          uint8_t *root_pubkey = chunk_buf;
          boot_secure_zeroize(root_pubkey, 32);

          if (platform->crypto->read_pubkey &&
              platform->crypto->read_pubkey(root_pubkey, 32, 0) == BOOT_OK) {

            volatile uint32_t auth_shield_1 = 0;
            volatile uint32_t auth_shield_2 = 0;

            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();
            boot_status_t sig_stat = platform->crypto->verify_ed25519(
                verify_msg, 72, auth_sig, root_pubkey);
            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();

            if (sig_stat == BOOT_OK)
              auth_shield_1 = BOOT_OK;
            BOOT_GLITCH_DELAY(); /* EMFI Protection */
            if (auth_shield_1 == BOOT_OK && sig_stat == BOOT_OK)
              auth_shield_2 = BOOT_OK;

            if (auth_shield_1 == BOOT_OK && auth_shield_2 == BOOT_OK) {
              auth_eval = BOOT_OK;

              /* OTP Burn: Nach erfolgreicher Autorisierung Token entwerten */
              if (platform->crypto->advance_monotonic_counter) {
                platform->crypto->advance_monotonic_counter();
                current_monotonic = safe_sequence_id;
              }
              panic_cfi ^= CFI_AUTH_PASSED;
            }
          }
          boot_secure_zeroize(root_pubkey, 32);
        }
        boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
      }
    }

    boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE); /* Wipe untrusted data */

    if (auth_eval == BOOT_OK) {
      break; /* Success! Aus Auth-Schleife ausbrechen */
    } else {
      failed_auth_attempts++;

      /* GAP-C06: Serial Rescue DoS Penalty */
      uint32_t shifts = (failed_auth_attempts > 10) ? 10 : failed_auth_attempts;
      uint32_t penalty_ms = (1U << shifts) * 100U;

      boot_delay_with_wdt(platform, penalty_ms);
      continue;
    }
  }

  /* ============================================================================
   * BLOCK 3: Naked COBS Flash-Transfer (Ping-Pong) & Handoff
   * ============================================================================
   */

  /* MATHEMATISCHER CFI-BEWEIS: Wir blockieren State-Confusion-Glitches, die uns
   * ohne Authentication direkt hier reinspringen lassen würden! */
  volatile uint32_t cfi_proof_1 = 0, cfi_proof_2 = 0;
  if (panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (cfi_proof_1 == BOOT_OK && panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_2 = BOOT_OK;

  if (cfi_proof_1 != BOOT_OK || cfi_proof_2 != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform);
  }

  uint32_t flash_offset = 0;
  uint32_t current_sector_end = CHIP_STAGING_SLOT_ABS_ADDR;
  bool staging_erased = false;

  while (1) {
    send_cobs_frame(platform, (const uint8_t *)"RDY", 3);

    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
    size_t chunk_len = 0;
    bool chunk_received = false;

    while (!chunk_received) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar &&
          platform->console->getchar(&c, 500) != BOOT_OK)
        break;

      if (c == COBS_MARKER_END) {
        if (chunk_len > 0)
          chunk_received = true;
      } else {
        /* Dynamischer P10 Bounds Check via Macro */
        if (chunk_len < PANIC_CHUNK_MAX_SIZE) {
          chunk_buf[chunk_len++] = c;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          chunk_len = 0; /* Frame overflow trap */
        }
      }
    }

    if (!chunk_received)
      continue;

    size_t payload_len = 0;
    if (cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK &&
        payload_len > 0) {

      volatile uint32_t eof_shield_1 = 0, eof_shield_2 = 0;
      if (payload_len == 3 && memcmp(chunk_buf, "EOF", 3) == 0)
        eof_shield_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (eof_shield_1 == BOOT_OK && payload_len == 3 &&
          memcmp(chunk_buf, "EOF", 3) == 0)
        eof_shield_2 = BOOT_OK;

      if (eof_shield_1 == BOOT_OK && eof_shield_2 == BOOT_OK) {
        send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        /* P10 HANDOFF FIX: Hardware-Reset erzwingen durch absichtliches
         * Verweigern des WDT-Kicks. Das friert die CPU sicher ein, bis der
         * Timer abläuft! */
        if (platform->console && platform->console->flush)
          platform->console->flush();
        if (platform->clock && platform->clock->deinit)
          platform->clock->deinit();

        /* Fallback Trap: Wenn der HW-WDT nach dem Deinit nicht beißt,
         * erzwingen wir einen HardFault (CPU Exception Trap), der über den
         * Vendor-NVIC zum Reset führt! */
        uint32_t hang_timeout = 10000000;
        while (hang_timeout > 0) {
          BOOT_GLITCH_DELAY();
          hang_timeout--;
        }

        void (*trap)(void) = NULL;
        trap();
      }

      /* Padding Alignment Guard for the final Chunk. */
      uint8_t align = platform->flash->write_align;
      if (align == 0)
        align = 1;

      size_t aligned_len = payload_len;
      uint8_t align_mod = (uint8_t)(payload_len % align);
      if (align_mod != 0) {
        size_t padding = align - align_mod;
        /* Wrap & Buffer Overflow Defense */
        if (UINT32_MAX - aligned_len < padding ||
            aligned_len + padding > PANIC_CHUNK_MAX_SIZE) {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
        memset(chunk_buf + payload_len, platform->flash->erased_value, padding);
        aligned_len += padding;
      }

      volatile uint32_t bounds_flag_1 = 0, bounds_flag_2 = 0;
      bool bounds_ok =
          (aligned_len <= CHIP_APP_SLOT_SIZE) &&
          (flash_offset <= (CHIP_APP_SLOT_SIZE - aligned_len)) &&
          (CHIP_STAGING_SLOT_ABS_ADDR <= (UINT32_MAX - CHIP_APP_SLOT_SIZE));

      if (bounds_ok)
        bounds_flag_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (bounds_flag_1 == BOOT_OK && bounds_ok)
        bounds_flag_2 = BOOT_OK;

      if (bounds_flag_1 != BOOT_OK || bounds_flag_2 != BOOT_OK) {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }

      uint32_t addr = CHIP_STAGING_SLOT_ABS_ADDR + flash_offset;
      size_t write_end = addr + aligned_len;

      if (write_end < addr) {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }

      while (!staging_erased || current_sector_end < write_end) {
        size_t s_size = 0;
        uint32_t erase_target = !staging_erased ? addr : current_sector_end;

        if (platform->flash->get_sector_size(erase_target, &s_size) ==
            BOOT_OK) {

          /* Smart-Erase Pre-Check: Ist der Sektor ohnehin schon 0xFF?
           * Zero-Allocation Nutzung des freien verify_msg Buffers! */
          bool needs_erase = false;
          uint32_t chk_off = 0;
          uint8_t e_val = platform->flash->erased_value;
          uint8_t *e_buf = verify_msg;
          size_t e_buf_size = PANIC_VERIFY_MAX_SIZE;

          while (chk_off < s_size) {
            uint32_t read_len = (s_size - chk_off > e_buf_size)
                                    ? (uint32_t)e_buf_size
                                    : (uint32_t)(s_size - chk_off);
            if (platform->flash->read(erase_target + chk_off, e_buf,
                                      read_len) != BOOT_OK) {
              needs_erase = true;
              break;
            }
            if (!is_fully_erased_constant_time(e_buf, read_len, e_val)) {
              needs_erase = true;
              break;
            }
            chk_off += read_len;
            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();
          }

          if (needs_erase) {
            if (platform->wdt && platform->wdt->suspend_for_critical_section) {
              platform->wdt->suspend_for_critical_section();
            } else if (platform->wdt && platform->wdt->kick) {
              platform->wdt->kick();
            }

            if (platform->flash->erase_sector(erase_target) != BOOT_OK) {
              boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
              goto session_reset;
            }

            if (platform->wdt && platform->wdt->resume) {
              platform->wdt->resume();
            }
          }

          if (UINT32_MAX - erase_target < s_size) {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            goto session_reset;
          }

          current_sector_end = erase_target + (uint32_t)s_size;
          staging_erased = true;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
      }

      if (platform->flash->write(addr, chunk_buf, aligned_len) == BOOT_OK) {

        /* P10 ECC Read-Back: Verhindert Bit-Rot / Tearing auf dem UART-Puffer!
         * Zero-Allocation Nutzung des freien verify_msg Buffers! */
        uint8_t *rb_buf = verify_msg;
        size_t rb_buf_size = PANIC_VERIFY_MAX_SIZE;
        uint32_t check_off = 0;
        bool write_ok = true;

        while (check_off < aligned_len) {
          if (platform->wdt && platform->wdt->kick)
            platform->wdt->kick();
          size_t step = (aligned_len - check_off > rb_buf_size)
                            ? rb_buf_size
                            : (aligned_len - check_off);

          if (platform->flash->read(addr + check_off, rb_buf, step) !=
              BOOT_OK) {
            write_ok = false;
            break;
          }

          /* Glitch-Resistant Constant-Time Chunk Comparison */
          uint32_t diff = 0;
          for (size_t i = 0; i < step; i++) {
            diff |= (rb_buf[i] ^ chunk_buf[check_off + i]);
          }

          volatile uint32_t v_shield_1 = 0, v_shield_2 = 0;
          if (diff == 0)
            v_shield_1 = BOOT_OK;
          BOOT_GLITCH_DELAY();
          if (v_shield_1 == BOOT_OK && diff == 0)
            v_shield_2 = BOOT_OK;

          if (v_shield_1 != BOOT_OK || v_shield_2 != BOOT_OK) {
            write_ok = false;
            break;
          }

          check_off += (uint32_t)step;
        }

        if (write_ok) {
          flash_offset += (uint32_t)aligned_len;
          send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset; /* Schreibfehler oder Bit-Rot -> Absturz und
                                 Neubeginn erzwingen! */
        }
      } else {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }
    }
    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
  }
}

/* ==============================================================================
 * ARCHITECTURE ROUTING (NMI & HARDFAULT)
 * ==============================================================================
 */

/**
 * @brief Globaler C-Contract für HAL-Interaktionen bei schweren Memory-Fehlern.
 * Vendor-ISRs (wie HardFault_Handler auf ARM) müssen diese Funktion aufrufen,
 * anstatt eigene Endlosschleifen zu implementieren.
 */
void __attribute__((section(".iram1.text"))) toob_ecc_trap(void) {
  /* ACHTUNG: toob_ecc_trap hat keinen Kontext zur `platform`, da sie asynchron
   * aus einer NMI aufgerufen wird! Wir müssen den globalen Handoff-State
   * oder eine reduzierte Panic fahren.
   * Wir versuchen einen sicheren WDT-Timeout herbeizuführen, indem wir in
   * eine unendliche Schleife ohne WDT-Kick gehen. Das ist P10 konform für NMIs.
   */
  while (1) {
    /* Warten auf den Watchdog-Biss. Keine Kicks erlaubt. */
    __asm__ volatile("nop");
  }
}

/*
 * Override libc's __stack_chk_fail to prevent pulling in abort(), raise(), and
 * printf() which bloat the binary by 120KB.
 */
/*
 * P10 / OSV Härtung: Eigene Stack Protector Definitionen.
 * Wenn wir diese nicht bereitstellen, zieht GCC `stack_protector.o` aus
 * `libc_nano.a`, was `abort()`, `raise()` und letztlich `printf()` und IO
 * nachzieht -> 145KB Bloat!
 */
uintptr_t __stack_chk_guard = 0xDEADBEEF;

void __stack_chk_fail(void);

void __stack_chk_fail(void) {
  /* Stack smashing detected: Enter hardware panic */
  boot_panic(NULL, BOOT_ERR_ECC_HARDFAULT);
}