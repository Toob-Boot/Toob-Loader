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
 *
 * ==============================================================================
 * ERROR HANDLING MATRIX & OS CONTRACTS (L1 / Mailbox Policy)
 * ==============================================================================
 * Die Funktionen toob_confirm_boot(), toob_recovery_resolved(), 
 * und toob_set_next_update() schreiben Mailbox-Anfragen in den Flash.
 * Diese Operationen können spezifische Fehlercodes zurückgeben:
 *
 * | Fehlercode                 | Ursache                              | Erwartete OS-Reaktion          |
 * |----------------------------|--------------------------------------|--------------------------------|
 * | TOOB_ERR_FLASH / FLASH_HW  | Hardwarefehler im Flash-Treiber.     | Fehler protokollieren.         |
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
#include "toob_swap_event_wire.h"

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
TOOB_MUST_CHECK toob_status_t toob_validate_handoff(void);

/**
 * @brief Liefert eine sichere, verifizierte "By-Value"-Kopie der Handoff-Daten.
 * 
 * @note  [Opaque validating accessor pattern]
 *        Dies ist der einzige legitime und unterstützte Zugriffspfad für das OS, 
 *        um an Boot-Handoff-Daten zu gelangen. Direkter Zugriff auf die uninitialisierte
 *        RAM-Variable (toob_handoff_state) ist gesperrt, um zu verhindern, dass das
 *        Betriebssystem korrupten RAM-Zustand liest. Die Funktion verifiziert Magic,
 *        ABI-Strukturversion und CRC32 vor dem Kopieren. Bei Validierungsfehler
 *        wird der Zielpuffer defensiv genullt und TOOB_ERR_VERIFY zurückgegeben.
 *
 * @param out_handoff Pointer auf eine vom OS allozierte Ausgabestruktur.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_VERIFY wenn die Validierung fehlschlägt, TOOB_ERR_INVALID_ARG bei NULL.
 */
TOOB_MUST_CHECK toob_status_t toob_get_handoff(toob_handoff_t* out_handoff);

/**
 * @brief P10 Absicherungsmakro zur ausfallsicheren OS-Initialisierung.
 *
 * Validates the .noinit handoff from Toob-Boot. On corruption, enters an
 * infinite TOOB_TRAP() loop — by design, this halts the system immediately
 * to prevent propagation of corrupted boot state into the OS.
 *
 * @warning Fail-Closed by Design. This macro NEVER RETURNS on failure.
 *          On systems with a Hardware Watchdog (WDT), the trap loop triggers
 *          a WDT reset within the configured timeout. On systems WITHOUT a
 *          WDT, the trap loop hangs PERMANENTLY — the device is bricked until
 *          a physical power cycle.
 *          Systems without WDT should use toob_os_init() instead and implement
 *          their own recovery strategy based on the returned status code.
 *
 * @note  Must be called as the very first statement in main()/app_main().
 */
#define TOOB_OS_INIT_OR_PANIC() \
    do { \
        if (toob_validate_handoff() != TOOB_OK) { \
            while (true) { TOOB_TRAP(); } \
        } \
    } while (false)

/**
 * @brief Non-panicking OS initialization — validates the .noinit handoff.
 *
 * Unlike TOOB_OS_INIT_OR_PANIC(), this function returns the validation
 * result instead of trapping. The caller decides the recovery strategy:
 * logging, rebooting, entering a safe mode, etc.
 *
 * @return TOOB_OK if the handoff is valid and the OS may proceed.
 *         TOOB_ERR_VERIFY if the .noinit region is corrupted — the OS
 *         MUST NOT call any other toob_* function in this case.
 */
static inline TOOB_MUST_CHECK toob_status_t toob_os_init(void) {
    return toob_validate_handoff();
}

/**
 * @brief Prüft, ob der Rückgabewert einer WAL-Operation einen System-Reboot erfordert.
 * @param status Rückgabewert einer libtoob-Funktion.
 * @return true wenn ein Reboot erforderlich ist, andernfalls false.
 */
#define TOOB_IS_REBOOT_REQUIRED(status) \
    (((status) == TOOB_ERR_REQUIRES_RESET) || ((status) == TOOB_ERR_WAL_FULL))

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
 * @return TOOB_OK bei Erfolg.
 * @return TOOB_OK bei Erfolg.
 *         Mögliche Fehler:
 *         - TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW: Flash-Hardwarefehler.
 */
TOOB_MUST_CHECK toob_status_t toob_confirm_boot(void);

/**
 * @brief Befreit das Recovery-OS aus dem Rettungsmodus (Anti Roach-Motel).
 * @note  Sobald das Recovery-OS die App repariert hat, MUSS es diese Funktion 
 *        aufrufen, um den RECOVERY_RESOLVED Intent in die Mailbox zu schreiben.
 * 
 * @return TOOB_OK bei Erfolg.
 *         Mögliche Fehler:
 *         - TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW: Flash-Hardwarefehler.
 */
TOOB_MUST_CHECK toob_status_t toob_recovery_resolved(void);


/* ==============================================================================
 * Zero-Bloat Platform & Cryptography Hooks (must precede OTA context definition)
 * ============================================================================== */
#include "toob_port.h"

/* ==============================================================================
 * Toob-Boot OTA Daemon (Network-Agnostic Stream Writer)
 * ============================================================================== */

/* OTA alignment buffer size — must match CHIP_FLASH_WRITE_ALIGNMENT multiples */
#define TOOB_OTA_BUF_SIZE 256U

/**
 * @brief OTA Session Context (caller-allocated, zero dynamic allocation).
 *
 * Encapsulates the complete state of a single OTA transfer session. The caller
 * allocates this struct (stack or static) and passes it to all toob_ota_*
 * functions. This enables re-entrant, testable OTA sessions without globals.
 *
 * Must be initialized with toob_ota_ctx_init() before first use.
 */
typedef struct __attribute__((aligned(8))) {
    uint8_t              state;              /* Internal state machine (opaque) */
    uint8_t              is_verified;        /* SHA-256 stream verification active */
    uint8_t              _reserved[2];       /* Alignment padding */
    uint32_t             write_cursor;       /* Absolute flash address of next write */
    uint32_t             total_size;         /* Declared image size from manifest */
    uint32_t             bytes_queued;       /* Bytes received so far */
    uint32_t             buf_len;            /* Bytes currently in alignment buffer */
    uint8_t              align_buf[TOOB_OTA_BUF_SIZE]; /* DMA-safe flash write buffer */
    uint8_t              expected_sha256[32];/* Expected hash for verified streams */
    toob_os_sha256_ctx_t sha_ctx;            /* Streaming SHA-256 context */
} toob_ota_ctx_t;

_Static_assert(sizeof(toob_ota_ctx_t) == 440, "toob_ota_ctx_t ABI size drift");

/**
 * @brief Registers a manufacturer-supplied notifier callback for update progress events.
 * @param cb Manufacturer callback function pointer (NULL to disable).
 */
void toob_set_swap_notifier(toob_swap_notify_fn cb);

/**
 * @brief Initializes a toob_ota_ctx_t to a clean idle state.
 *        Must be called once before first use. Securely zeroes all fields.
 * @param ctx Caller-allocated context.
 * @return TOOB_OK on success, TOOB_ERR_INVALID_ARG if ctx is NULL.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_ctx_init(toob_ota_ctx_t *ctx);

/**
 * @brief Initializes the OTA Daemon for receiving a new update stream.
 * @param ctx Caller-allocated OTA session context.
 * @param total_size Expected total size of the incoming image (Manifest + Payload).
 * @param expected_sha256 Optional 32-byte hash to verify the stream against (nullable).
 * @return TOOB_OK on success, TOOB_ERR_INVALID_ARG if size exceeds staging slot.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_begin(toob_ota_ctx_t *ctx, uint32_t total_size, const uint8_t expected_sha256[32]);

/**
 * @brief Resumes a partially downloaded OTA update.
 *
 * Restores the internal write cursor and byte counter from the handoff RAM
 * checkpoint. If expected_sha256 is non-NULL, reconstructs the SHA-256
 * streaming context by re-reading and re-hashing the already-staged flash prefix.
 *
 * @param ctx Caller-allocated OTA session context.
 * @param total_size   Expected total size of the image (from the manifest).
 * @param expected_sha256 Optional 32-byte hash to verify the stream against (nullable).
 * @param resume_offset Output pointer for the byte offset to resume from.
 * @return TOOB_OK if resumable, TOOB_ERR_NOT_FOUND if no partial download exists.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_resume(toob_ota_ctx_t *ctx, uint32_t total_size, const uint8_t expected_sha256[32], uint32_t* resume_offset);

/**
 * @brief Aborts an active OTA download and securely zeroizes buffers.
 * @param ctx OTA session context to abort.
 * @return TOOB_OK.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_abort(toob_ota_ctx_t *ctx);

/**
 * @brief Processes a chunk of incoming bytes, writing them linearly to Staging.
 * @param ctx OTA session context.
 * @param chunk Pointer to the downloaded bytes.
 * @param len Length of the chunk.
 * @return TOOB_OK, or TOOB_ERR_FLASH on write error.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_process_chunk(toob_ota_ctx_t *ctx, const uint8_t* chunk, uint32_t len);

/**
 * @brief Finalizes the OTA process and registers the update intent in the WAL.
 *
 * After all chunks have been received and the stream transitions to DONE,
 * this function flushes residual bytes, verifies the SHA-256 digest (if
 * verified mode), and atomically writes the update intent into the WAL.
 *
 * @param ctx OTA session context.
 * @return TOOB_OK on success. The system should be rebooted immediately after.
 *         TOOB_ERR_VERIFY      — SHA-256 mismatch (stream corrupted, re-download required).
 *         TOOB_ERR_FLASH       — Flash write failed during residual flush.
 *         TOOB_ERR_WAL_LOCKED  — A previous update is already pending in the WAL.
 *                                The OS must reboot to consume it before staging a new one.
 *         TOOB_ERR_WAL_FULL    — WAL sector exhausted. Reboot required.
 *         TOOB_ERR_INVALID_ARG — Context is NULL or not in DONE state.
 */
TOOB_MUST_CHECK toob_status_t toob_ota_finalize(toob_ota_ctx_t *ctx);

/**
 * @brief Registriert ein empfangenes Manifest in der Mailbox.
 * 
 * @note  [L1: Mailbox-Atomarität]
 *        Ein Crash (Brownout) während der Ausführung dieser Funktion hinterlässt
 *        niemals einen halben Zustand. Das System evaluiert CRC-gesicherte Mailbox-Einträge
 *        beim nächsten Boot und faltet sie in seine interne WAL ein.
 *
 * @param manifest_flash_addr Absolute, hardware-bündige Flash-Adresse des Manifests im SPI.
 * @return TOOB_OK bei Erfolg.
 *         Mögliche Fehler:
 *         - TOOB_ERR_FLASH / TOOB_ERR_FLASH_HW: Flash-Hardwarefehler.
 */
TOOB_MUST_CHECK toob_status_t toob_set_next_update(uint32_t manifest_flash_addr);

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
TOOB_MUST_CHECK toob_status_t toob_get_boot_diag(toob_boot_diag_t* diag);

/**
 * @brief Extrahiert die Diagnosedaten kodiert im Cloud-tauglichen CBOR-Format.
 * @param out_buf Buffer für den CBOR-Stream
 * @param max_len Maximale Größe von out_buf
 * @param out_len Tatsächliche Größe des geschriebenen CBOR-Streams
 * @return TOOB_OK bei Erfolg
 */
TOOB_MUST_CHECK toob_status_t toob_get_boot_diag_cbor(uint8_t* out_buf, size_t max_len, size_t* out_len);

/* ==============================================================================
 * Cloud-Command Submission API (Phase 7)
 * ==============================================================================
 * Das OS empfängt Cloud-Command Envelopes (CBOR, Ed25519-signiert) vom Server
 * und delegiert sie über dieses API an den Bootloader. Der Bootloader evaluiert
 * den Command beim nächsten Boot (Step 2.5 in boot_state.c).
 */

/**
 * @brief Schreibt ein Cloud-Command-Envelope in den CHIP_CLOUD_CMD_SLOT.
 *
 * Sequenz: Guard → Erase → Write → CRC Read-Back → Zeroize.
 * Der Bootloader evaluiert den Slot beim nächsten Boot autonom.
 *
 * @param envelope  Zeiger auf das rohe CBOR-Envelope (inkl. Signatur).
 * @param len       Länge des Envelopes in Bytes.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_INVALID_ARG bei NULL/Überlänge,
 *         TOOB_ERR_FLASH bei Erase/Write-Fehler,
 *         TOOB_ERR_FLASH_HW bei Read-Back-Mismatch.
 */
TOOB_MUST_CHECK toob_status_t toob_submit_cloud_command(const uint8_t *envelope, uint32_t len);

/**
 * @brief Extrahiert die 32-Byte DICE Device-ID aus dem Boot-Handoff.
 *
 * @note  [Validating Accessor Reference Pattern]
 *        Diese Funktion dient als Referenz-Muster für den sicheren, gekapselten
 *        Zugriff auf spezifische Handoff-Felder. Sie holt sich den Handoff-State
 *        validiert über toob_get_handoff(), liest die ID aus und löscht den temporären
 *        Stack-Buffer anschließend sicher mittels toob_secure_zeroize().
 *
 * @param out_id  Ziel-Buffer (mind. 32 Bytes).
 * @param id_len  Größe des Buffers. Muss >= 32 sein.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_INVALID_ARG bei NULL oder zu kleinem Buffer,
 *         TOOB_ERR_VERIFY bei korruptem Handoff.
 */
TOOB_MUST_CHECK toob_status_t toob_get_device_id(uint8_t *out_id, size_t id_len);

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
TOOB_MUST_CHECK toob_status_t toob_os_flash_read(uint32_t addr, uint8_t* buf, uint32_t len);

/**
 * @brief Zero-Bloat Hook: Physikalischer Flash-Schreibzugriff.
 * @param addr Absolute Byte-Adresse im SPI Flash (Muss an Page-Boundary ausgerichtet sein).
 * @param buf Zu schreibender, konstanter Datenpuffer.
 * @param len Länge der zu schreibenden Daten.
 * @return TOOB_OK bei Erfolg. Bei Hardware-Fehler zwingend TOOB_ERR_FLASH!
 */
TOOB_MUST_CHECK toob_status_t toob_os_flash_write(uint32_t addr, const uint8_t* buf, uint32_t len);

/**
 * @brief Zero-Bloat Hook: Physikalischer Flash-Löschzugriff.
 * @param addr Absolute Byte-Adresse im SPI Flash (Muss Sektor-bündig sein).
 * @param len Länge der zu löschenden Daten (Muss Sektor-bündig sein).
 * @return TOOB_OK bei Erfolg. Bei Hardware-Fehler zwingend TOOB_ERR_FLASH!
 */
TOOB_MUST_CHECK toob_status_t toob_os_flash_erase(uint32_t addr, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBTOOB_H */
