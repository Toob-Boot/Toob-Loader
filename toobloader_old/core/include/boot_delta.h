/**
 * @file boot_delta.h
 * @brief Toob-Delta-Stream (TDS1) Virtual Machine Protocol
 *
 * Spezifikation:
 * - docs/merkle_spec.md (Delta-Patching, Streaming Virtual Machine)
 * - docs/concept_fusion.md (Brownout Recovery, Zero Allocation)
 *
 * Implementiert eine Turing-unvollständige, O(1)-RAM Bytecode-VM, die
 * binäre Diffs direkt im Flash assembliert und Tearing-proof
 * über das WAL-Journal absichert.
 */

#ifndef TOOB_BOOT_DELTA_H
#define TOOB_BOOT_DELTA_H

#include "boot_hal.h"
#include "boot_journal.h"
#include "boot_types.h"
#include <stdint.h>


#define TOOB_TDS_MAGIC 0x31534454 /* "TDS1" in Little Endian */

/* High-Hamming Distance Opcodes (Glitch/EMFI-Prävention) */
#define TOOB_TDS_OP_COPY_BASE                                                  \
  0xC0C0C0C0 /**< Kopiert N Bytes aus der alten Firmware */
#define TOOB_TDS_OP_INSERT_LIT                                                 \
  0x1A1A1A1A /**< Fügt N Bytes direkt aus dem Delta-Stream ein */
#define TOOB_TDS_OP_BZERO                                                      \
  0x5A5A5A5A /**< Füllt N Bytes mit 0x00 (Extrem effizient für BSS) */
#define TOOB_TDS_OP_EOF 0x0F0F0F0F /**< Legitimes Ende des Delta-Streams */

/**
 * @brief TDS Header (Strictly 32-Byte P10 Aligned)
 * Definiert die Base-Firmware und die Dimensionen des Patches.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t magic;                /**< Immer TOOB_TDS_MAGIC */
  uint32_t expected_target_size; /**< Exakte Größe der neuen Firmware (Bounds
                                    Proof) */
  uint8_t base_fingerprint[8];   /**< Die ersten 8 Bytes des SHA-256 der ALTEN
                                    Firmware */
  uint32_t base_size; /**< Erwartete physikalische Größe der alten Firmware */
  uint32_t literal_block_offset; /**< Offset im Stream, ab dem die INSERT_LIT
                                    Daten liegen */
  uint32_t instr_count;          /**< Anzahl der 16-Byte VM Instruktionen */
  uint32_t header_crc32;         /**< CRC-32 über die oberen 28 Bytes */
} toob_tds_header_t;

_Static_assert(sizeof(toob_tds_header_t) == 32, "TDS Header ABI Size Drift!");

/**
 * @brief TDS Virtual Machine Instruction (Strictly 16-Byte P10 Aligned)
 * Atomare Operation für den Flash-Controller.
 */
typedef struct __attribute__((aligned(8))) {
  uint32_t opcode; /**< TOOB_TDS_OP_* */
  uint32_t length; /**< Länge der Operation */
  uint32_t offset; /**< Source-Offset für COPY_BASE (sonst 0) */
  uint32_t crc32;  /**< Isolierte CRC-32 pro Instruktion gegen SPI-Rauschen */
} toob_tds_instr_t;

_Static_assert(sizeof(toob_tds_instr_t) == 16,
               "TDS Instruction ABI Size Drift!");

/**
 * @brief Führt den Delta-Patch als Streaming-VM aus und assembliert die
 * Firmware im Staging-Slot.
 *
 * @param platform Boot HAL Platform Pointer
 * @param delta_addr Startadresse des heruntergeladenen Delta-Packages
 * @param delta_max_size Maximale Grenzen des Delta-Speichers
 * @param dest_addr Zieladresse (Staging Slot) für das neue Image
 * @param dest_max_size Maximale Größe des Staging Slots
 * @param base_addr Startadresse der aktiven, alten Firmware (App Slot)
 * @param base_max_size Tatsächliche Größe der aktiven Firmware
 * @param open_txn Pointer auf die offene WAL-Transaktion für Checkpointing
 * @return BOOT_OK bei Erfolg, passender Fehlercode bei Manipulation oder
 * Hardware-Fehler.
 */
boot_status_t boot_delta_apply(const boot_platform_t *platform,
                               uint32_t delta_addr, size_t delta_max_size,
                               uint32_t dest_addr, size_t dest_max_size,
                               uint32_t base_addr, size_t base_max_size,
                               wal_entry_payload_t *open_txn);

#endif /* TOOB_BOOT_DELTA_H */