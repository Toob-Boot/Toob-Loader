#ifndef BOOT_PANIC_H
#define BOOT_PANIC_H

/*
 * Toob-Boot Core Header: boot_panic.h
 * Relevant Spec-Dateien:
 * - docs/stage_1_5_spec.md (Serial Rescue & SOS Mode)
 * - docs/testing_requirements.md
 */

#include "boot_hal.h"

/**
 * @brief The exact 104-byte Payload sent by the technician for Stage 1.5 Rescue.
 *        4 (Slot) + 4 (Sequence ID) + 32 (Nonce Echo) + 64 (Ed25519 Sig) = 104 Bytes.
 */
typedef struct __attribute__((packed)) {
    uint32_t slot_id;       /* Target Slot ID für das folgende Naked-COBS Image */
    uint32_t sequence_id;   /* 4-Byte Hardware Counter, Anti-Replay: Muss exakt current_monotonic + 1 sein */
    uint8_t  nonce[32];     /* Echo des 32-Byte kryptografischen Challenge Nonces */
    uint8_t  sig[64];       /* Ed25519(Nonce | DSLC(32) | Slot ID | Sequence ID) */
} stage15_auth_payload_t;

// P10: statically assert the 104 byte size explicitly
_Static_assert(sizeof(stage15_auth_payload_t) == 104, "Stage 1.5 Auth Payload must be exactly 104 bytes");

/**
 * @brief Atomically stops execution, attempts Serial Rescue (COBS)
 *        or enters SOS flashing loop if no console is present.
 *        Never returns.
 * 
 * @param platform Hardware HAL abstraction
 * @param reason   Reason for panic
 */
_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason);

/**
 * @brief Diagnostic forensic record structure stored in flash/RTC backup registers.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;             /* 0x464F524E ("FORN") */
    uint32_t reason;            /* boot_status_t */
    uint32_t site_id;           /* unique identifier where the freeze was triggered */
    uint32_t monotonic_counter; /* monotonic sequence ID */
    uint32_t crc32;             /* CRC-32 verification checksum of the record fields */
} boot_forensic_record_t;

_Static_assert(sizeof(boot_forensic_record_t) == 20, "Forensic record must be exactly 20 bytes");

typedef enum {
  SITE_DELAY_WARP = 1,
  SITE_DELAY_GLITCH,
  SITE_ROLLBACK_CONFUSION,
  SITE_PROVISIONING_GLITCH,
  SITE_CLOUD_CMD_GLITCH,
  SITE_MAIN_CFI_MISMATCH,
  SITE_MAIN_WIPE_FAIL,
  SITE_STATE_CFI_MISMATCH,
  SITE_STATE_LOCK_FAIL,
  SITE_ENERGY_CFI_MISMATCH,
  SITE_ENERGY_BROWNOUT,
  SITE_VERIFY_SHIELD_FAIL,
  SITE_SWAP_SHIELD_FAIL,
  SITE_JOURNAL_SHIELD_FAIL,
  SITE_DELTA_SHIELD_FAIL,
  SITE_COBS_SHIELD_FAIL,
  SITE_MULTIIMAGE_SHIELD_FAIL,
  SITE_CONFIRM_SHIELD_FAIL,
  SITE_TMR_FUTURE,
  SITE_RSTORE_SHIELD_FAIL
} boot_site_id_t;

/**
 * @brief Unified terminal halt function. Records forensic diagnostics and freezes.
 */
_Noreturn void boot_terminal_halt(const boot_platform_t *platform,
                                  boot_status_t reason, uint16_t site_id);

#endif /* BOOT_PANIC_H */
