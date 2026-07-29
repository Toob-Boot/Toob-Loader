/**
 * @file stage0_main.c
 * @brief Immutable Core Entry
 *
 * Orchestrates Magic-Checks, Hashing, Ed25519-Verification and the Assembler-Jump.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "generated_boot_config.h"
#include "boot_hal.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include "stage0_crypto.h"
#include "boot_fih.h"
#include "boot_proof.h"

static uint32_t g_seal_key[4];

extern uint32_t stage0_get_active_slot(const boot_platform_t *platform);
extern uint32_t stage0_evaluate_tentative(const boot_platform_t *platform,
                                          uint32_t current_slot);
extern uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform);
extern uint32_t stage0_get_stage1_svn(const boot_platform_t *platform);

/* --- STAGE 0 STUBS (To satisfy linker without pulling in core/libtoob) --- */
#include "libtoob_types.h"
#include "boot_panic.h"
#include "boot_ct_utils.h"
TOOB_NOINIT toob_handoff_t toob_handoff_state;

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    (void)platform;
    (void)reason;
    while(1) { BOOT_GLITCH_DELAY(); } /* Hardware Trap */
}

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason, uint16_t site_id) {
    (void)site_id;
    boot_panic(platform, reason);
}

_Noreturn static void dead_halt(void) {
    while (1) {
        BOOT_GLITCH_DELAY(); /* Intentional starvation of WDT */
    }
}
/* -------------------------------------------------------------------------- */

#ifndef TOOB_ALLOW_DEV_BYPASS
  #ifdef NDEBUG
    #error "TOOB_ALLOW_DEV_BYPASS must be explicitly enabled for production builds"
  #endif
  #define TOOB_ALLOW_DEV_BYPASS 0
#endif

/* P10 Rule: O(1) Memory layout, Assembler Jump */
static void __attribute__((naked)) jump_to_payload(uint32_t vector_table_addr) {
  (void)vector_table_addr;
#if defined(__GNUC__) || defined(__clang__)
#if defined(__arm__) || defined(__aarch64__)
  __asm__ volatile(
      "ldr r1, [%0]\n"     /* Lade Stack Pointer (SP) aus Offset 0 */
      "msr msp, r1\n"      /* Setze Main Stack Pointer */
      "ldr r1, [%0, #4]\n" /* Lade Reset Handler (PC) aus Offset 4 */
      "bx r1\n"            /* Jump zum Payload */
      ::"r"(vector_table_addr)
      : "r1", "memory");
#elif defined(__riscv)
  __asm__ volatile("jr %0\n"        /* P10 FIX: Direkter Jump auf Binary Entry-Point für RISC-V */
                   ::"r"(vector_table_addr)
                   : "memory");
#endif
#endif
  while (1) {
    BOOT_GLITCH_DELAY();
  } /* Halt on unknown arch */
}

/**
 * @brief P7a: Per-Bank Boot Eligibility Check.
 *
 * Evaluates a single Stage-1 bank for:
 * 1. Valid magic header + bounds
 * 2. Valid Ed25519 signature (with DSLC dev-bypass support)
 * 3. SVN floor gate (efuse + WAL combined floor)
 *
 * @return true if the bank is eligible for boot, false otherwise.
 */
static bool stage0_try_boot_bank(const boot_platform_t *platform,
                                 uint32_t bank_addr, uint8_t confirmed_dslc,
                                 uint32_t svn_floor, boot_proof_t *out_proof) {
  (void)confirmed_dslc; /* Used only with TOOB_ALLOW_DEV_BYPASS */

  /* 1. Read and validate header */
  toob_image_header_t hdr __attribute__((aligned(8)));
  if (platform->flash->read(bank_addr, (uint8_t *)&hdr, sizeof(hdr)) !=
      BOOT_OK) {
    return false;
  }
  if (hdr.magic != TOOB_MAGIC_HEADER || hdr.image_size > CHIP_APP_SLOT_SIZE) {
    return false;
  }

  /* 2. Load hardware PubKey */
  uint8_t key_idx = stage0_get_active_otp_key_index(platform);
  uint8_t pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(pubkey, 32);

#if TOOB_ALLOW_DEV_BYPASS
  bool is_dev_bypass = false;
#endif
  if (platform->crypto->read_pubkey(pubkey, 32, key_idx) != BOOT_OK) {
#if TOOB_ALLOW_DEV_BYPASS
    if (confirmed_dslc == 0x00) {
      is_dev_bypass = true;
    } else {
      return false;
    }
#else
    return false;
#endif
  }

  /* 3. Hash computation */
  uint8_t digest[64] __attribute__((aligned(8)));
  boot_secure_zeroize(digest, 64);
  stage0_hash_compute(platform, bank_addr,
                      (uint32_t)sizeof(hdr) + hdr.image_size, digest);

  /* 4. Load signature */
  uint8_t sig[64] __attribute__((aligned(8)));
  if (platform->flash->read(bank_addr + (uint32_t)sizeof(hdr) + hdr.image_size,
                            sig, 64) != BOOT_OK) {
    boot_secure_zeroize(digest, 64);
    return false;
  }

  /* 5. Glitch-Resistant Ed25519 Verify */
  int sig_ok = -1;
#if TOOB_ALLOW_DEV_BYPASS
  if (is_dev_bypass) {
    sig_ok = 0;
  } else {
    sig_ok = stage0_verify_signature(platform, sig, pubkey, digest);
  }
#else
  sig_ok = stage0_verify_signature(platform, sig, pubkey, digest);
#endif

  boot_secure_zeroize(pubkey, 32);
  boot_secure_zeroize(digest, 64);
  boot_secure_zeroize(sig, 64);

  if (sig_ok != 0) {
    return false;
  }

  /* K1-T2: Populate and seal the proof handle */
  if (out_proof) {
    out_proof->image_addr = bank_addr;
    out_proof->image_size = hdr.image_size;
    out_proof->entry_point = hdr.entry_point;
    out_proof->svn = svn_floor;
    boot_proof_seal(out_proof, g_seal_key);
  }

  return true;
}

int main(void) {
  /* 1. Hardware Initialisierung */
  const boot_platform_t *platform = boot_platform_init();
  if (!platform || platform->flash->init() != BOOT_OK) {
    while (1)
      ; /* Terminal Hardware Failure */
  }
  if (platform->clock)
    platform->clock->init();
  if (platform->crypto)
    platform->crypto->init();
  if (platform->wdt)
    platform->wdt->init(BOOT_WDT_TIMEOUT_MS);

  /* P10 Rule: Secure Initialization of the Boot-Proof Seal Key using TRNG */
  if (boot_random_safe(platform, (uint8_t *)g_seal_key, sizeof(g_seal_key)) != BOOT_OK) {
    while (1) { BOOT_GLITCH_DELAY(); } /* TRNG Failure - Starve watchdog */
  }

  /* 1.5 DSLC Majority Vote Gate (Phase 2) */
  uint8_t dslc_reads[5];
  uint8_t confirmed_dslc = 0xFF;
  bool dslc_found = false;
  
  for (int round = 0; round < 5 && !dslc_found; round++) {
      /* Anti-Sustained-Glitch: Randomisierter Delay zwischen Reads */
      if (round > 0 && platform->crypto && platform->crypto->random) {
          uint8_t jitter = 0;
          platform->crypto->random(&jitter, 1);
          for (volatile uint32_t d = 0; d < (uint32_t)(jitter & 0x3F); d++) {
              BOOT_GLITCH_DELAY();
          }
      }
      uint8_t dslc_buf[64];
      size_t dslc_len = sizeof(dslc_buf);
      boot_secure_zeroize(dslc_buf, sizeof(dslc_buf)); /* P10 Defensive */
      
      if (platform->crypto->read_dslc(dslc_buf, &dslc_len) == BOOT_OK && dslc_len > 0) {
          dslc_reads[round] = dslc_buf[0];
      } else {
          dslc_reads[round] = 0xFF;
      }
      
      if (round >= 2) {
          /* Suche nach einem Wert, der mindestens 3x vorkommt */
          for (int i = 0; i <= round && !dslc_found; i++) {
              int matches = 0;
              for (int j = 0; j <= round; j++) {
                  if (dslc_reads[i] == dslc_reads[j]) matches++;
              }
              if (matches >= 3) {
                  confirmed_dslc = dslc_reads[i];
                  dslc_found = true;
              }
          }
      }
  }
  
  if (!dslc_found) {
      dead_halt(); /* Fail-Closed! eFuse unstable, erzwinge Hardware-Reset */
  }

  /* 2. Boot Pointer und Tentative Check */
  uint32_t active_slot = stage0_get_active_slot(platform);
  active_slot = stage0_evaluate_tentative(platform, active_slot);

  /* P7a: Read eFuse epoch and WAL-persisted stage1_svn for Anti-Rollback Gate */
  uint32_t efuse_epoch = 0;
  boot_read_monotonic_counter_safe(platform, &efuse_epoch);
  uint32_t wal_stage1_svn = stage0_get_stage1_svn(platform);

  /* P7a: Determine the effective Anti-Rollback floor.
   * eFuse is the hard floor (A2 defense), WAL is enforced (A1 defense, K4 chain-backed).
   * Use the higher of the two as the combined floor for defense-in-depth. */
  uint32_t svn_floor = (wal_stage1_svn > efuse_epoch) ? wal_stage1_svn : efuse_epoch;

  boot_proof_t proof;
  boot_secure_zeroize(&proof, sizeof(proof));

  /* 3-8. Per-Bank Verification (Signature + SVN)
   * Try preferred bank first. If ineligible, try the fallback bank.
   * If neither bank passes: Rescue-Pfad (boot_panic). */
  if (!stage0_try_boot_bank(platform, active_slot, confirmed_dslc, svn_floor, &proof)) {
    /* Preferred bank ineligible — try fallback */
    uint32_t fallback_slot = (active_slot == CHIP_STAGE1A_ABS_ADDR)
                                 ? CHIP_STAGE1B_ABS_ADDR
                                 : CHIP_STAGE1A_ABS_ADDR;
    if (!stage0_try_boot_bank(platform, fallback_slot, confirmed_dslc, svn_floor, &proof)) {
      /* No eligible bank → Rescue (erholbar, nicht permanent brick) */
      boot_panic(platform, BOOT_ERR_DOWNGRADE);
    }
    active_slot = fallback_slot;
  }

  /* Siegelprüfung direkt vor dem Jump */
  if (boot_proof_verify(&proof, g_seal_key) != BOOT_OK) {
    boot_secure_zeroize(g_seal_key, sizeof(g_seal_key));
    dead_halt();
  }
  boot_secure_zeroize(g_seal_key, sizeof(g_seal_key));

  /* Deinit Hardware (Schließt Flash/Crypto für S1-Isolation) */
  if (platform->crypto)
    platform->crypto->deinit();
  if (platform->wdt)
    platform->wdt->deinit();
  platform->flash->deinit();
  if (platform->clock)
    platform->clock->deinit();

  /* P10 FIX: XIP Flash-Cache Invalidierung erzwingen! Verhindert das Booten alten Codes. */
  if (platform->soc && platform->soc->invalidate_icache)
    platform->soc->invalidate_icache();

  /* P10 FIX: Jump Target muss weiterhin payload_addr + hdr.entry_point (also active_slot + hdr.entry_point) bleiben, 
   * da das Image relativ zum Slot-Start inkl. Header kompiliert wird. */
  __asm__ volatile("" ::: "memory");
  jump_to_payload(proof.image_addr + proof.entry_point);

  /* Fallback: jump_to_payload should never return */
  while (1) {
    if (platform->wdt)
      platform->wdt->kick();
    BOOT_GLITCH_DELAY();
  }
}