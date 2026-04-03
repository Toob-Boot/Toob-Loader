#ifndef BOOT_PANIC_H
#define BOOT_PANIC_H

/*
 * Toob-Boot Core Header: boot_panic.h
 * Relevant Spec-Dateien:
 * - docs/stage_1_5_spec.md (Serial Rescue & SOS Mode)
 * - docs/testing_requirements.md
 */

#include "boot_hal.h"

#define COBS_MARKER_START 0x00
#define COBS_MARKER_END   0x00

/**
 * @brief The exact 108-byte Payload sent by the technician for Stage 1.5 Rescue.
 *        4 (Slot) + 8 (Timestamp) + 32 (Nonce Echo) + 64 (Ed25519 Sig) = 108 Bytes.
 */
typedef struct __attribute__((packed)) {
    uint32_t slot_id;       /* Target Slot ID für das folgende Naked-COBS Image */
    uint64_t timestamp;     /* 8-Byte UNIX Time, Anti-Replay: Muss current_monotonic + 1 sein */
    uint8_t  nonce[32];     /* Echo des 32-Byte kryptografischen Challenge Nonces */
    uint8_t  sig[64];       /* Ed25519(Nonce | DSLC(32) | Slot ID | Timestamp) */
} stage15_auth_payload_t;

// P10: statically assert the 108 byte size explicitly
_Static_assert(sizeof(stage15_auth_payload_t) == 108, "Stage 1.5 Auth Payload must be exactly 108 bytes");

/**
 * @brief Atomically stops execution, attempts Serial Rescue (COBS)
 *        or enters SOS flashing loop if no console is present.
 *        Never returns.
 * 
 * @param platform Hardware HAL abstraction
 * @param reason   Reason for panic
 */
_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason);

#endif /* BOOT_PANIC_H */
