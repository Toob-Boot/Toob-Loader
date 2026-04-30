/**
 * @file stage0_main.c
 * @brief Immutable Core Entry
 *
 * Orchestrates Magic-Checks, Hashing, Ed25519-Verification and the Assembler-Jump.
 * 
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_config_mock.h"
#include "boot_hal.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include "stage0_crypto.h"

extern uint32_t stage0_get_active_slot(const boot_platform_t *platform);
extern uint32_t stage0_evaluate_tentative(const boot_platform_t *platform,
                                          uint32_t current_slot);
extern uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform);

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

  /* 2. Boot Pointer und Tentative Check */
  uint32_t active_slot = stage0_get_active_slot(platform);
  active_slot = stage0_evaluate_tentative(platform, active_slot);

  /* 3. Lese Stage 1 Header */
  toob_image_header_t hdr __attribute__((aligned(8)));
  if (platform->flash->read(active_slot, (uint8_t *)&hdr, sizeof(hdr)) !=
      BOOT_OK) {
    while (1) {
      if (platform->wdt)
        platform->wdt->kick();
      BOOT_GLITCH_DELAY();
    } /* Flash defekt */
  }

  /* 4. Magic Header Check */
  volatile uint32_t magic_shield_1 = 0, magic_shield_2 = 0;
  if (hdr.magic == TOOB_MAGIC_HEADER)
    magic_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (magic_shield_1 == BOOT_OK && hdr.magic == TOOB_MAGIC_HEADER)
    magic_shield_2 = BOOT_OK;

  if (magic_shield_1 != BOOT_OK || magic_shield_2 != BOOT_OK ||
      hdr.image_size > CHIP_APP_SLOT_SIZE) {
    while (1) {
      if (platform->wdt)
        platform->wdt->kick();
      BOOT_GLITCH_DELAY();
    } /* Brick Trap */
  }

  /* 5. Hardware PubKey Laden */
  uint8_t key_idx = stage0_get_active_otp_key_index(platform);
  uint8_t pubkey[32] __attribute__((aligned(8)));
  if (platform->crypto->read_pubkey(pubkey, 32, key_idx) != BOOT_OK) {
    while (1) {
      if (platform->wdt)
        platform->wdt->kick();
      BOOT_GLITCH_DELAY();
    }
  }

  /* 6. Zero-Allocation Hash Computation */
  uint8_t digest[32] __attribute__((aligned(8)));
  uint32_t payload_addr = active_slot + sizeof(hdr);
  stage0_hash_compute(platform, payload_addr, hdr.image_size, digest);

  /* 7. Lade die Signatur (Wir erwarten sie am Ende des Images) */
  uint8_t sig[64] __attribute__((aligned(8)));
  if (platform->flash->read(payload_addr + hdr.image_size, sig, 64) !=
      BOOT_OK) {
    while (1) {
      if (platform->wdt)
        platform->wdt->kick();
      BOOT_GLITCH_DELAY();
    }
  }

  /* 8. Glitch-Resistant Ed25519 Verify */
  int sig_ok = stage0_verify_signature(platform, sig, pubkey, digest);

  boot_secure_zeroize(pubkey, 32);
  boot_secure_zeroize(digest, 32);
  boot_secure_zeroize(sig, 64);

  volatile uint32_t sig_shield_1 = 0, sig_shield_2 = 0;
  if (sig_ok == 0)
    sig_shield_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (sig_shield_1 == BOOT_OK && sig_ok == 0)
    sig_shield_2 = BOOT_OK;

  if (sig_shield_1 == BOOT_OK && sig_shield_2 == BOOT_OK &&
      sig_shield_1 == sig_shield_2) {
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

    __asm__ volatile("" ::: "memory");
    jump_to_payload(payload_addr + hdr.entry_point);
  }

  /* Fallback: Signatur fehlerhaft! (Kein Booten!) */
  while (1) {
    if (platform->wdt)
      platform->wdt->kick();
    BOOT_GLITCH_DELAY();
  }
}