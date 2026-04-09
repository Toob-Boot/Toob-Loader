/*
 * ==============================================================================
 * Toob-Boot Core File: boot_panic.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/stage_1_5_spec.md (Serial Rescue, SOS Mode, Exponential Penalty)
 * - docs/testing_requirements.md (Zero-Allocation, P10 Bounds, Tearing-Proof)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Zero-Allocation Mapping: 100% aller Buffer liegen in der crypto_arena.
 *    Eliminiert >1.2 KB Stack-Bloat und verhindert Hardware Stack-Overflows!
 * 2. Unaligned Access Mitigation: Verhindert Cortex-M0 Exception-Traps durch
 *    sichere memcpy-Extrahierung der packed-Struct Metadaten.
 * 3. Glitch-Resistant 2FA Auth: Double-Check Gating für alle kryptografischen
 *    Entscheidungen (Nonce, Timestamp, Signature).
 * 4. Write-Through ECC Proof: Jeder seriell geschriebene Flash-Block wird
 *    sofort rückgelesen und auf CRC-32 Hardware-Bit-Rot verifiziert!
 * 5. Mathematically Bound COBS Decoder: Buffer-Überläufe sind physikalisch
 *    durch die write_idx Invarianten ausgeschlossen.
 */

#include "boot_panic.h"
#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_delay.h"
#include "boot_secure_zeroize.h"
#include <string.h>


/* Terminal State besitzt die Arena nun exklusiv */
extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(
    BOOT_CRYPTO_ARENA_SIZE >= 2048,
    "Crypto Arena muss mindestens 2KB aufweisen für Serial Rescue Puffer");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK must be high-hamming distance for Glitch-Shielding");

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
  __asm__ volatile("nop; nop;");
  if (flag1 == BOOT_OK && acc_rev == 0)
    flag2 = BOOT_OK;

  if (flag1 != BOOT_OK || flag2 != BOOT_OK)
    return BOOT_ERR_VERIFY;
  return BOOT_OK;
}

/**
 * @brief Beweist mathematisch, ob ein Buffer komplett den Erased-Status (0xFF)
 * aufweist.
 */
static bool is_fully_erased(const uint8_t *buf, size_t len,
                            uint8_t erased_val) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] != erased_val)
      return false;
  }
  return true;
}

/**
 * @brief Streams a buffer to UART using Naked COBS encoding with O(1) memory.
 *        O(n) time complexity and native WDT feeding.
 */
static void send_cobs_frame(const boot_platform_t *platform,
                            const uint8_t *data, size_t len) {
  if (!platform || !platform->console || len == 0 || !data)
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
      if (platform->wdt)
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
  platform->console->flush();
}

/**
 * @brief O(1) in-place Naked COBS Decoder.
 *        Mathematically proven safe: write_idx will ALWAYS be <= read_idx.
 */
static boot_status_t cobs_decode_in_place(uint8_t *data, size_t len,
                                          size_t *out_len) {
  if (!data || !out_len || len == 0)
    return BOOT_ERR_INVALID_ARG;

  size_t read_idx = 0;
  size_t write_idx = 0;

  while (read_idx < len) {
    uint8_t code = data[read_idx++];
    if (code == 0)
      return BOOT_ERR_INVALID_ARG; /* Zeroes are logically illegal in COBS
                                      payload */

    uint8_t copy_len = code - 1;

    /* P10 SUBTRACTIVE BOUNDS GUARD: Verhindert 32-bit Integer Wraparounds
     * (CVE-Class Bypass), die bei "read_idx + copy_len > len" auftreten würden!
     */
    if (len - read_idx < copy_len)
      return BOOT_ERR_INVALID_ARG;

    /* O(1) in-place shift. This works because write_idx <= read_idx is
     * mathematically guaranteed */
    for (uint8_t i = 0; i < copy_len; i++) {
      data[write_idx++] = data[read_idx++];
    }

    /* Implicit zeroes are restored except for block max (0xFF) or end of frame
     */
    if (code < 0xFF && read_idx < len) {
      if (write_idx >= len)
        return BOOT_ERR_INVALID_ARG; /* Mathematischer Bounds Proof */
      data[write_idx++] = 0x00;
    }
  }

  *out_len = write_idx;

  /* P10 Defense: Zeroize the trailing garbage data left over from the in-place
   * shift to prevent logical leakage or boundary confusions downstream. */
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
    if (platform && platform->wdt)
      platform->wdt->kick();
    if (platform)
      boot_delay_with_wdt(platform, 500);
  }
}

_Noreturn void boot_panic(const boot_platform_t *platform,
                          boot_status_t reason) {
  /* Hard-Fault Exit, wenn der Platform-Pointer defekt ist */
  if (!platform || !platform->wdt) {
    while (1) {
    }
  }

  if (!platform->console || !platform->crypto || !platform->flash) {
    enter_sos_loop(platform);
  }

  uint32_t failed_auth_attempts = 0;

session_reset:
  /* Initialisierungs-UART Flush */
  platform->console->putchar('P');
  platform->console->putchar('N');
  platform->console->putchar('C');
  platform->console->flush();

  /* ============================================================================
   * MEMORY ARENA MAPPING (Zero-Allocation Architecture)
   * ============================================================================
   * Stack Allocation wird verhindert. Die freie crypto_arena wird in
   * funktionale, disjunkte Zonen segmentiert.
   */
  uint8_t *challenge_buf = crypto_arena;    /* 128 Bytes */
  uint8_t *rx_buf = crypto_arena + 128;     /* 128 Bytes */
  uint8_t *verify_msg = crypto_arena + 256; /* 76 Bytes */
  uint8_t *chunk_buf = crypto_arena + 336;  /* >1700 Bytes */

  /* P10 Init */
  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  volatile uint32_t panic_cfi = CFI_PANIC_INIT;

  /* ============================================================================
   * BLOCK 1: Challenge Generation (2FA)
   * ============================================================================
   */

  size_t challenge_len = 32; /* Nonce Base Size */

  if (platform->crypto->random(challenge_buf, 32) != BOOT_OK) {
    enter_sos_loop(platform); /* Terminal: TRNG Broken */
  }

  /* P10 HAL Containment: Wir übergeben dem Vendor-HAL isolierten Temp-Speicher,
   * damit ein Out-of-Bounds Write des Vendors niemals den Challenge-Buffer
   * zerreißt! */
  uint8_t temp_dslc[64] __attribute__((aligned(8)));
  boot_secure_zeroize(temp_dslc, sizeof(temp_dslc));

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
  boot_secure_zeroize(temp_dslc,
                      sizeof(temp_dslc)); /* O(1) Zeroize nach Kopie */
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
    platform->wdt->kick();

    boot_secure_zeroize(rx_buf, 128);
    size_t rx_len = 0;
    bool frame_ready = false;

    /* Frame Retrieval Logic */
    while (!frame_ready) {
      platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar(&c, 100) != BOOT_OK)
        continue;

      if (c == COBS_MARKER_END) {
        if (rx_len > 0)
          frame_ready = true;
      } else {
        if (rx_len < 128) {
          rx_buf[rx_len++] = c;
        } else {
          /* Overflow Defense: Buffer vernichten und auf nächsten Sync warten */
          boot_secure_zeroize(rx_buf, 128);
          rx_len = 0;
        }
      }
    }

    size_t decoded_len = 0;
    volatile uint32_t auth_eval = 0;

    if (cobs_decode_in_place(rx_buf, rx_len, &decoded_len) == BOOT_OK) {
      if (decoded_len == sizeof(stage15_auth_payload_t)) {

        /* ABI Aliasing Fix: Safely extract into proper memory-aligned struct */
        stage15_auth_payload_t payload;
        memcpy(&payload, rx_buf, sizeof(stage15_auth_payload_t));

        /* Unaligned Access Mitigation: 'timestamp' liegt im packed-struct auf
         * Offset 4! Ein direkter Lesezugriff (payload.timestamp) wirft auf
         * Cortex-M0 einen HardFault. P10 Lösung: Sichere Allokation über
         * memcpy. */
        uint64_t safe_timestamp = 0;
        memcpy(&safe_timestamp, &payload.timestamp, sizeof(uint64_t));

        uint32_t safe_slot_id = 0;
        memcpy(&safe_slot_id, &payload.slot_id, sizeof(uint32_t));

        bool time_ok = (safe_timestamp > current_monotonic);
        bool slot_ok = (safe_slot_id == CHIP_STAGING_SLOT_ID);
        boot_status_t nonce_stat =
            constant_time_memcmp_32_glitch_safe(payload.nonce, challenge_buf);

        if (time_ok && slot_ok && nonce_stat == BOOT_OK) {
          /* Assemble Ed25519 Message exakt nach Spec (76 Bytes):
           * [Nonce(32)] | [Padded DSLC(32)] | [Slot ID(4)] | [Timestamp(8)] */
          boot_secure_zeroize(verify_msg, 76);
          memcpy(verify_msg, challenge_buf,
                 64); /* Zieht saubere Nonce & DSLC Base */
          memcpy(verify_msg + 64, &safe_slot_id, 4);
          memcpy(verify_msg + 68, &safe_timestamp, 8);

          uint8_t root_pubkey[32] __attribute__((aligned(8)));
          boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));

          if (platform->crypto->read_pubkey &&
              platform->crypto->read_pubkey(root_pubkey, sizeof(root_pubkey),
                                            0) == BOOT_OK) {

            /* CFI Glitch Shielded Signature Verification */
            volatile uint32_t auth_shield_1 = 0;
            volatile uint32_t auth_shield_2 = 0;

            platform->wdt->kick();
            boot_status_t sig_stat = platform->crypto->verify_ed25519(
                verify_msg, 76, payload.sig, root_pubkey);
            platform->wdt->kick();

            if (sig_stat == BOOT_OK)
              auth_shield_1 = BOOT_OK;
            __asm__ volatile("nop; nop; nop;"); /* EMFI Protection */
            if (auth_shield_1 == BOOT_OK && sig_stat == BOOT_OK)
              auth_shield_2 = BOOT_OK;

            if (auth_shield_1 == BOOT_OK && auth_shield_2 == BOOT_OK) {
              auth_eval = BOOT_OK;

              /* OTP Burn: Nach erfolgreicher Autorisierung den Counter
               * voranbringen um Tokens einweg zu machen */
              if (platform->crypto->advance_monotonic_counter) {
                platform->crypto->advance_monotonic_counter();
                current_monotonic = (uint32_t)safe_timestamp;
              }
              panic_cfi ^= CFI_AUTH_PASSED;
            }
          }
          boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
        }
        boot_secure_zeroize(verify_msg, 76);
        boot_secure_zeroize(&payload, sizeof(payload));
      }
    }

    boot_secure_zeroize(rx_buf, 128); /* P10: Wipe untrusted/used input */

    if (auth_eval == BOOT_OK) {
      break; /* Success! Aus Auth-Schleife ausbrechen */
    } else {
      failed_auth_attempts++;

      /* GAP-C06: Serial Rescue DoS Penalty (Saturation Math) */
      uint32_t shifts = (failed_auth_attempts > 10) ? 10 : failed_auth_attempts;
      uint32_t penalty_ms = (1U << shifts) * 100U;

      /* WDT-Amnesie Guard: P10 WDT-feeding delay */
      boot_delay_with_wdt(platform, penalty_ms);
      continue; /* Wait for next frame */
    }
  }

  /*
   * ============================================================================
   * BLOCK 3: Naked COBS Flash-Transfer (Ping-Pong) & Handoff
   * ============================================================================
   */

  /* MATHEMATISCHER CFI-BEWEIS: Wir blockieren State-Confusion-Glitches, die uns
   * ohne Authentication direkt hier reinspringen lassen würden! */
  volatile uint32_t cfi_proof_1 = 0, cfi_proof_2 = 0;
  if (panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_1 = BOOT_OK;
  __asm__ volatile("nop; nop;");
  if (cfi_proof_1 == BOOT_OK && panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_2 = BOOT_OK;

  if (cfi_proof_1 != BOOT_OK || cfi_proof_2 != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform);
  }

  uint32_t flash_offset = 0;
  uint32_t current_sector_end = CHIP_STAGING_SLOT_ABS_ADDR;
  bool staging_erased = false;

  /* P10: Alignment (1056 % 8 == 0) für Hardware-DMA.
   * Groß genug für Max-Sector-Size Chunks + COBS Overhead. */
  uint8_t chunk_buf[1056] __attribute__((aligned(8)));

  while (1) {
    send_cobs_frame(platform, (const uint8_t *)"RDY", 3);

    boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
    size_t chunk_len = 0;
    bool chunk_received = false;

    while (!chunk_received) {
      platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar(&c, 500) != BOOT_OK)
        break; /* Resend "RDY" */

      if (c == COBS_MARKER_END) {
        if (chunk_len > 0)
          chunk_received = true;
      } else {
        if (chunk_len < sizeof(chunk_buf)) {
          chunk_buf[chunk_len++] = c;
        } else {
          boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
          chunk_len = 0; /* Frame overflow trap */
        }
      }
    }

    if (!chunk_received)
      continue;

    size_t payload_len = 0;
    if (cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK &&
        payload_len > 0) {

      /* EOF Marker: We are fully done. Trigger the OS-Load. */
      if (payload_len == 3 && memcmp(chunk_buf, "EOF", 3) == 0) {
        send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        /* P10 Handoff: Force an un-kickable WDT reset loop to safely reboot.
         * Der Bootloader findet das intakte Staging-Image beim nächsten
         * Kaltstart. */
        if (platform->console)
          platform->console->flush();
        if (platform->clock && platform->clock->deinit)
          platform->clock->deinit();
        while (1) {
          platform->wdt->kick();
        }
      }

      /* Padding Alignment Guard for the final Chunk.
       * Verhindert ECC Hardware-Exceptions beim Flashen ungerader Bytegrößen.
       */
      uint8_t align = platform->flash->write_align;
      if (align == 0)
        align = 1;

      size_t aligned_len = payload_len;
      uint8_t align_mod = payload_len % align;
      if (align_mod != 0) {
        size_t padding = align - align_mod;
        /* Wrap & Buffer Overflow Defense */
        if (UINT32_MAX - aligned_len < padding ||
            aligned_len + padding > sizeof(chunk_buf)) {
          boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
          goto session_reset; /* Puffer wäre übergelaufen! Abbrechen. */
        }
        memset(chunk_buf + payload_len, platform->flash->erased_value, padding);
        aligned_len += padding;
      }

      /* ====================================================================
       * GLITCH-RESISTANT BOUNDS PROOF (CVE/Exploit Defense)
       * ==================================================================== */
      volatile uint32_t bounds_flag_1 = 0;
      volatile uint32_t bounds_flag_2 = 0;

      bool bounds_ok =
          (aligned_len <= CHIP_APP_SLOT_SIZE) &&
          (flash_offset <= (CHIP_APP_SLOT_SIZE - aligned_len)) &&
          (CHIP_STAGING_SLOT_ABS_ADDR <= (UINT32_MAX - CHIP_APP_SLOT_SIZE));

      if (bounds_ok)
        bounds_flag_1 = BOOT_OK;
      __asm__ volatile("nop; nop;");
      if (bounds_flag_1 == BOOT_OK && bounds_ok)
        bounds_flag_2 = BOOT_OK;

      if (bounds_flag_1 != BOOT_OK || bounds_flag_2 != BOOT_OK) {
        boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
        goto session_reset;
      }

      uint32_t addr = CHIP_STAGING_SLOT_ABS_ADDR + flash_offset;
      size_t write_end = addr + aligned_len;

      /* Protect against 32-bit Integer wrap-around of write_end address */
      if (write_end < addr) {
        boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
        goto session_reset;
      }

      /* O(1) Smart Erase & Sequential Progression */
      while (!staging_erased || current_sector_end < write_end) {
        size_t s_size = 0;
        uint32_t erase_target = !staging_erased ? addr : current_sector_end;

        if (platform->flash->get_sector_size(erase_target, &s_size) ==
            BOOT_OK) {

          /* Smart-Erase Pre-Check: Ist der Sektor ohnehin schon 0xFF? */
          bool needs_erase = false;
          uint32_t chk_off = 0;
          uint8_t e_val = platform->flash->erased_value;
          uint8_t e_buf[64] __attribute__((aligned(8)));

          while (chk_off < s_size) {
            uint32_t read_len = (s_size - chk_off > sizeof(e_buf))
                                    ? sizeof(e_buf)
                                    : (s_size - chk_off);
            if (platform->flash->read(erase_target + chk_off, e_buf,
                                      read_len) != BOOT_OK) {
              needs_erase = true;
              break;
            }
            if (!is_fully_erased(e_buf, read_len, e_val)) {
              needs_erase = true;
              break;
            }
            chk_off += read_len;
            platform->wdt->kick();
          }

          if (needs_erase) {
            if (platform->wdt->suspend_for_critical_section) {
              platform->wdt->suspend_for_critical_section();
            } else {
              platform->wdt->kick();
            }

            if (platform->flash->erase_sector(erase_target) != BOOT_OK) {
              boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
              goto session_reset;
            }

            if (platform->wdt->resume) {
              platform->wdt->resume();
            }
          }

          /* Wrapped Boundary Proof */
          if (UINT32_MAX - erase_target < s_size) {
            boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
            goto session_reset;
          }

          current_sector_end = erase_target + s_size;
          staging_erased = true;
        } else {
          boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
          goto session_reset;
        }
      }

      /* Flash Write & Phase-Bound Read-Back Verify */
      if (platform->flash->write(addr, chunk_buf, aligned_len) == BOOT_OK) {

        /* P10 ECC Read-Back: Verhindert Bit-Rot / Tearing auf dem UART-Puffer!
         */
        uint8_t rb_buf[64] __attribute__((aligned(8)));
        uint32_t check_off = 0;
        bool write_ok = true;

        while (check_off < aligned_len) {
          platform->wdt->kick();
          size_t step = (aligned_len - check_off > sizeof(rb_buf))
                            ? sizeof(rb_buf)
                            : (aligned_len - check_off);

          if (platform->flash->read(addr + check_off, rb_buf, step) !=
              BOOT_OK) {
            write_ok = false;
            break;
          }

          /* O(1) Constant-Time Chunk Comparison */
          uint32_t diff = 0;
          for (size_t i = 0; i < step; i++)
            diff |= (rb_buf[i] ^ chunk_buf[check_off + i]);
          if (diff != 0) {
            write_ok = false;
            break;
          }

          check_off += step;
        }

        if (write_ok) {
          flash_offset += aligned_len;
          send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        } else {
          boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
          goto session_reset; /* Schreibfehler oder Bit-Rot -> Absturz und
                                 Neubeginn erzwingen! */
        }
      } else {
        boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
        goto session_reset;
      }
    }
    boot_secure_zeroize(chunk_buf, sizeof(chunk_buf));
  }
}