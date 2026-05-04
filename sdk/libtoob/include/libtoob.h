/**
 * ==============================================================================
 * Toob-Boot C-Interface (libtoob.h)
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * - docs/libtoob_api.md (API definitions, toob_status_t, .noinit references)
 * - docs/concept_fusion.md (Strict isolation policy, State Machine interactions)
 * - docs/structure_plan.md (Strict isolation from core/ headers)
 * - docs/testing_requirements.md (P10 compliance & Interface definition standards)
 *
 * This is the EXCLUSIVE OS-side API for Toob-Boot interaction.
 * Es spannt den C++ kompatiblen Schutzschirm (extern "C") für externe Feature-OS.
 */

#ifndef LIBTOOB_H
#define LIBTOOB_H

/* 
 * ARCHITEKTUR-GRUND: System-Header MÜSSEN vor dem `extern "C"` Block geladen 
 * werden, da eingebaute C++ Systembibliotheken bei geschachteltem `extern "C"` 
 * crashen können. 
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "libtoob_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==============================================================================
 * P10 Compliance & Symmetrie Validierungen
 * ============================================================================== */

/* GAP-39: Strict 8-Byte Formatierung für Boundaries */
_Static_assert(sizeof(toob_handoff_t) % 8 == 0, "GAP-39: toob_handoff_t size must align to 8 bytes.");
_Static_assert(sizeof(toob_boot_diag_t) % 8 == 0, "GAP-39: toob_boot_diag_t size must align to 8 bytes.");

/* Host-Compiler Symmetrie Check */
#ifndef TOOB_NOINIT
#error "FATAL: Host-Compiler lacks TOOB_NOINIT support. Must provide fallback for .noinit section mapping."
#endif

/* ==============================================================================
 * Handoff Verification Guard
 * ==============================================================================
 * Das `.noinit` RAM enthält illegitimate Garbage-Werte, wenn das OS durch den 
 * Watchdog abgewürgt wird, ohne dass Toob-Boot involviert war. Das Lesen der 
 * ungeschützten Boot-Variablen OHNE vorherige CRC-32 Validation riskiert Boot-Loop Crashes!
 */

/**
 * @brief Validiert die Integrität der .noinit Toob-Boot Boundary (GAP-Handoff).
 * @return TOOB_OK bei validem Magic/CRC-32, TOOB_ERR_VERIFY bei Fehler.
 */
toob_status_t toob_validate_handoff(void);

/**
 * @brief Liefert eine sichere, verifizierte "By-Value"-Kopie der Handoff-Daten.
 * @param out_handoff Pointer auf eine vom OS allozierte Ausgabestruktur.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_VERIFY wenn CRC ungültig, TOOB_ERR_INVALID_ARG bei NULL.
 */
toob_status_t toob_get_handoff(toob_handoff_t* out_handoff);

/**
 * @brief P10 Absicherungsmakro zur ausfallsicheren OS-Initialisierung.
 * @note  Kapselt die unabdingbare `toob_validate_handoff()` Routine.
 *        Wird vorab in das Feature OS `main()` verankert, um die Bootloader-Brücke 
 *        atomar abzusichern. Der While-Lock verhindert die Propagation korrupter Pointers.
 */
#define TOOB_OS_INIT_OR_PANIC() \
    do { \
        if (toob_validate_handoff() != TOOB_OK) { \
            /* PANIC: .noinit Korruption! Eskaliere Hardware-Trap für Systeme ohne WDT! */ \
            while (true) { TOOB_TRAP(); } \
        } \
    } while (false)

/* ==============================================================================
 * Primary Feature-OS API (IDE-UX & Doxygen Mappings)
 * ============================================================================== */

/**
 * @brief Bestätigt das asynchrone OTA-Update (Commit Flag).
 * 
 * @note  [GAP-07: Network Watchdog TTL]
 *        Das Feature-OS MUSS diese Funktion rufen, um ein laufendes Update 
 *        als erfolgreich zu flaggen. Nutzt das Update ein Cloud-Handshake 
 *        (z.B. DICE/CDI), MUSS das OS zwingend die Cloud-Bestätigung abwarten. 
 *        Dafür sammelt das OS "Network-TTL" Minuten via WAL. Bei Überschreiten 
 *        dieses TTLs führt das Ausbleiben des Aufrufs unwiderruflich zum Rollback.
 * 
 * @return TOOB_OK bei Erfolg, passender toob_status_t (z.B. TOOB_ERR_FLASH) bei Fehler.
 */
toob_status_t toob_confirm_boot(void);

/**
 * @brief Befreit das Recovery-OS aus dem Rettungsmodus (Anti Roach-Motel).
 * @note  Sobald das Recovery-OS die App repariert hat, MUSS es diese Funktion 
 *        aufrufen, um den RECOVERY_RESOLVED Intent ins WAL zu schreiben.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_FLASH bei Hardwarefehlern.
 */
toob_status_t toob_recovery_resolved(void);

/**
 * @brief Akkumuliert die aktive Cloud-Suchzeit (Anti-Lagerhaus Lockout).
 * @param active_search_ms Dauer der aktiven Netzwerk-Suche seit dem letzten Reset.
 * @return TOOB_OK bei Erfolg.
 */
toob_status_t toob_accumulate_net_search(uint32_t active_search_ms);

/**
 * @brief Extrahiert die rohen Hardware-Metriken aus dem .noinit RAM.
 * 
 * @note  [CRA Regulatorik & CBOR Extraktion]
 *        Liest die `toob_boot_diag_t` Struktur. Diese enthält u.A. den 
 *        kryptographischen SHA-256 Digest der SBOM, was direkt der Erfüllung
 *        des EU Cyber Resilience Acts 2027 (CRA) dient. Die weiterführende 
 *        Telemetrie zur Hardware-Lebensdauer ist optional via CBOR verpackt.
 *
 * @param diag Zeiger auf die vom OS bereitgestellte Struct-Instanz.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_VERIFY bei gebrochener Checksumme.
 */
toob_status_t toob_get_boot_diag(toob_boot_diag_t* diag);

/* ==============================================================================
 * Toob-Boot OTA Daemon (Network-Agnostic Stream Writer)
 * ============================================================================== */

/**
 * @brief Initializes the OTA Daemon for receiving a new update stream.
 * @param total_size Expected total size of the incoming image (Manifest + Payload).
 * @param image_type 0 for OS Update (App), 3 for Bootloader Update (Stage 1).
 * @return TOOB_OK on success, TOOB_ERR_INVALID_ARG if size exceeds staging slot.
 */
toob_status_t toob_ota_begin(uint32_t total_size, uint8_t image_type);

/**
 * @brief Initializes the OTA Daemon with streaming SHA-256 verification (Zero-Bloat).
 * @param total_size Expected total size.
 * @param image_type 0 for OS Update, 3 for Bootloader.
 * @param expected_sha256 32-byte hash to verify the stream against.
 * @return TOOB_OK on success.
 */
toob_status_t toob_ota_begin_verified(uint32_t total_size, uint8_t image_type, const uint8_t expected_sha256[32]);

/**
 * @brief Resumes a partially downloaded OTA update.
 * @param resume_offset Output pointer for the byte offset to resume from.
 * @return TOOB_OK if resumable, TOOB_ERR_NOT_FOUND if no partial download exists.
 */
toob_status_t toob_ota_resume(uint32_t* resume_offset);

/**
 * @brief Aborts an active OTA download and securely zeroizes buffers.
 * @return TOOB_OK.
 */
toob_status_t toob_ota_abort(void);

/**
 * @brief Processes a chunk of incoming bytes, writing them linearly to Staging.
 * @param chunk Pointer to the downloaded bytes.
 * @param len Length of the chunk.
 * @return TOOB_OK, or TOOB_ERR_FLASH on write error.
 */
toob_status_t toob_ota_process_chunk(const uint8_t* chunk, uint32_t len);

/**
 * @brief Finalizes the OTA process and registers the update intent in the WAL.
 * @return TOOB_OK on success. The system should be rebooted immediately after.
 */
toob_status_t toob_ota_finalize(void);

/**
 * @brief Registriert ein empfangenes SUIT-Manifest im Write-Ahead-Log (WAL).
 * 
 * @note  [GAP-37: P10 WAL-Atomarität]
 *        Toob-Loader stützt sich auf absolute P10-Resilienz. Ein Crash (Brownout) 
 *        während der Ausführung dieser Funktion hinterlässt niemals einen halben
 *        Zustand! Das System evaluiert CRC-gesicherte 64-Byte WAL-Sektoren beim
 *        nächsten Boot und schließt das Update ab, oder verwirft das Rausch-Fragment.
 *
 * @param manifest_flash_addr Absolute, hardware-bündige Flash-Adresse des Manifests im SPI.
 * @return TOOB_OK bei erfolgreichem WAL-Append.
 */
toob_status_t toob_set_next_update(uint32_t manifest_flash_addr);

/**
 * @brief Extrahiert die rohen Hardware-Metriken aus dem .noinit RAM.
 * 
 * @note  [CRA Regulatorik & CBOR Extraktion]
 *        Liest die `toob_boot_diag_t` Struktur. Diese enthält u.A. den 
 *        kryptographischen SHA-256 Digest der SBOM, was direkt der Erfüllung
 *        des EU Cyber Resilience Acts 2027 (CRA) dient. Die weiterführende 
 *        Telemetrie zur Hardware-Lebensdauer ist optional via CBOR verpackt.
 *
 * @param diag Zeiger auf die vom OS bereitgestellte Struct-Instanz.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_VERIFY bei gebrochener Checksumme.
 */
toob_status_t toob_get_boot_diag(toob_boot_diag_t* diag);

/**
 * @brief Extrahiert die Diagnosedaten kodiert im Cloud-tauglichen CBOR-Format.
 * @param out_buf Buffer für den CBOR-Stream
 * @param max_len Maximale Größe von out_buf
 * @param out_len Tatsächliche Größe des geschriebenen CBOR-Streams
 * @return TOOB_OK bei Erfolg
 */
toob_status_t toob_get_boot_diag_cbor(uint8_t* out_buf, size_t max_len, size_t* out_len);

/* ==============================================================================
 * Der Hard-Linker Contract "Zero-Bloat Shim"
 * ==============================================================================
 * Toob-Loader verweigert die Kopplung an ausufernde Vendor-SDK SPI Treiber. 
 * Um dem Bootloader dennoch persistente WAL-Transktionen (`toob_set_next_update`) 
 * zu ermöglichen, fordert die Library exakt diese beiden Symbole als harten Linker-Contract ein. 
 * Das Feature-OS (z.B. der Zephyr OS Storage API Stack) MUSS diese in seinem C/C++ Code 
 * zwingend physikalisch bereitstellen! Ein Fehlen führt absichtlich zu einem 
 * "Undefined Symbol" Kompilierungsabbruch (Fail-Fast).
 */

/**
 * @brief Zero-Bloat Hook: Physikalischer Flash-Lesezugriff.
 * @param addr Absolute Byte-Adresse im SPI Flash.
 * @param buf Datenpuffer im lokalen OS-SRAM.
 * @param len Länge der zu lesenden Daten.
 * @return TOOB_OK bei Erfolg. Bei Hardware-Fehler zwingend TOOB_ERR_FLASH!
 */
toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len);

/**
 * @brief Zero-Bloat Hook: Physikalischer Flash-Schreibzugriff.
 * @param addr Absolute Byte-Adresse im SPI Flash (Muss an Page-Boundary ausgerichtet sein).
 * @param buf Zu schreibender, konstanter Datenpuffer.
 * @param len Länge der zu schreibenden Daten.
 * @return TOOB_OK bei Erfolg. Bei Hardware-Fehler zwingend TOOB_ERR_FLASH!
 */
toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len);

/**
 * @brief Zero-Bloat Hook: Physikalischer Flash-Löschzugriff.
 * @param addr Absolute Byte-Adresse im SPI Flash (Muss Sektor-bündig sein).
 * @param len Länge der zu löschenden Daten (Muss Sektor-bündig sein).
 * @return TOOB_OK bei Erfolg. Bei Hardware-Fehler zwingend TOOB_ERR_FLASH!
 */
toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len);

/* ==============================================================================
 * Zero-Bloat Cryptography Hooks (Hardware Acceleration OS-Side)
 * ============================================================================== */

typedef struct {
    uint8_t opaque[128]; /* Context buffer for the OS hardware crypto driver */
} toob_os_sha256_ctx_t;

toob_status_t toob_os_sha256_init(toob_os_sha256_ctx_t* ctx);
toob_status_t toob_os_sha256_update(toob_os_sha256_ctx_t* ctx, const uint8_t* data, uint32_t len);
toob_status_t toob_os_sha256_finalize(toob_os_sha256_ctx_t* ctx, uint8_t out_hash[32]);

#ifdef __cplusplus
}
#endif

#endif /* LIBTOOB_H */
