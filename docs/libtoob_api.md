# Toob-Boot C-Interface (libtoob) API
> Die offizielle OS-seitige Library zur Interaktion mit Toob-Boot.

Die `libtoob` ist eine winzige (Zero-Allocation) C-Bibliothek, die in das Feature-OS einkompiliert wird.
Sie abstrahiert die Interaktion mit dem Bootloader, um Status-Abfragen zu machen, das aktuelle Update zu bestätigen oder Over-the-Air Updates vorzubereiten.

## Architektur: Shared Memory & No-Init
Toob-Boot reicht den Boot-Zustand über eine designierte RAM-Adresse an das OS weiter. Diese Adresse MUSS im OS als `.noinit` Sektion deklariert sein, damit der Startup-Code des OS (crt0) die Variablen nicht vor dem Lesen nullt.

```c
/* GAP-39: Zwingendes 8-Byte Alignment für 64-bit Architektur-Kompatibilität (z.B. AArch64) */
typedef struct __attribute__((aligned(8))) {
    uint32_t magic;              /* Immer 0x55AA55AA */
    uint32_t struct_version;     /* GAP-11: ABI Versionierung (z.B. 0x01000000) für Abwärtskompatibilität */
    uint64_t boot_nonce;         /* Deterministische Anti-Replay Nonce */
    uint32_t active_slot;        /* 0 = Slot A, 1 = Slot B */
    uint32_t reset_reason;       /* Letzter Hardware-Reset-Grund */
    uint32_t boot_failure_count; /* Aktueller Stand des Edge-Recovery Counters */
    uint32_t _padding;           /* GAP-39: Explizites Padding auf 8-Byte Vielfache (32 Bytes Gesamtgröße) */
} toob_handoff_t;

extern __attribute__((section(".noinit"))) toob_handoff_t toob_handoff_state;
```

---

## 0. Error Codes & State Konstanten

```c
/* GAP-06: Spezifische libtoob Fehlercodes für sauberes OS-Handling */
typedef enum {
    TOOB_OK = 0x55AA55AA,
    TOOB_ERR_NOT_FOUND = -1,    /* Keine gültige Toob-Boot Signatur gefunden */
    TOOB_ERR_WAL_FULL = -2,     /* Journal Ring ist voll, Update abgewiesen */
    TOOB_ERR_WAL_LOCKED = -3,   /* WAL ist durch anstehendes Update blockiert */
    TOOB_ERR_FLASH = -4         /* Physikalischer Schreibfehler */
} toob_status_t;

/* GAP-12: Explizite Boot-State Konstanten für TENTATIVE/COMMITTED Logik */
#define TOOB_STATE_TENTATIVE  0xAAAA5555
#define TOOB_STATE_COMMITTED  0x55AA55AA
```

## API Referenz

### 1. `toob_confirm_boot()`
**Zweck:** Bestätigt dem Bootloader, dass das aktuell gebootete OS lauffähig ist. Setzt das Flag `COMMITTED`.
**Verhalten:** Muss vom OS aufgerufen werden, sobald alle kritischen Services (Network, Watchdog) hochgefahren sind. Geschieht dies vor dem nächsten Reset nicht, wird der Bootloader einen Rollback einleiten.

```c
/**
 * @brief Bestätigt das laufende Update.
 * @note  GAP-07: Diese Funktion verhält sich synchron und MUSS zwingend gerufen werden, bevor
 *        der an das OS durchgereichte Hardware-Watchdog auslöst! Es flusht das `COMMITTED` Flag 
 *        in die Hardware-eFuse oder den WAL-Sektor.
 * @return TOOB_OK bei Erfolg, toob_status_t Fehlercode sonst.
 */
toob_status_t toob_confirm_boot(void);
```

### 2. `toob_set_next_update(manifest_ptr)`
**Zweck:** Registriert ein neues heruntergeladenes OS-Manifest für den nächsten Boot.
**Verhalten:** Die Library hängt einen WAL-Eintrag in den Journal-Ring des Bootloaders an. Das OS muss den Payload zuvor in den inaktiven Slot geflasht haben.

```c
/**
 * @brief Signalisiert "Update Ready".
 * @note  GAP-37: Die Library garantiert hier WAL-Atomarität. Wenn das OS während des 
 *        Aufrufs crasht, ist das Update entweder vollständig im Journal registriert 
 *        oder gar nicht. Es gibt keinen "halben" Zustand.
 * @param manifest_flash_addr Absolute Adresse des SUIT Manifests im Flash.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_WAL_FULL oder TOOB_ERR_WAL_LOCKED sonst.
 */
toob_status_t toob_set_next_update(uint32_t manifest_flash_addr);
```

### 3. `toob_get_boot_diag()`
**Zweck:** Liest das Timing-IDS und die Crash-Historie aus der Bootloader Diagnostik-Sektion. Anstelle eines rohen String-Buffers (GAP-16) parst die Bibliothek exakt in eine strukturierte `toob_boot_diag_t` Repräsentation für maschinenlesbare Flotten-Auswertungen (CBOR-Extraction). **(GAP-F29 Harmonisierung)**

```c
typedef struct {
    uint32_t boot_duration_ms;
    uint32_t edge_recovery_events;
    uint32_t hardware_fault_record;
    /* ... weitere felder korrespondierend zu toob_telemetry.md */
} toob_boot_diag_t;

/**
 * @brief Extrahiert den strukturierten Boot-Log.
 * @param diag Zeiger auf die vom OS bereitgestellte Struct.
 * @return TOOB_OK bei Erfolg, TOOB_ERR_NOT_FOUND wenn keine Daten vorliegen.
 */
toob_status_t toob_get_boot_diag(toob_boot_diag_t* diag);
```
