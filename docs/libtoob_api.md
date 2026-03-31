# Toob-Boot C-Interface (libtoob) API
> Die offizielle OS-seitige Library zur Interaktion mit Toob-Boot.

Die `libtoob` ist eine winzige (Zero-Allocation) C-Bibliothek, die in das Feature-OS einkompiliert wird.
Sie abstrahiert die Interaktion mit dem Bootloader, um Status-Abfragen zu machen, das aktuelle Update zu bestätigen oder Over-the-Air Updates vorzubereiten.

## Architektur: Shared Memory & No-Init
Toob-Boot reicht den Boot-Zustand über eine designierte RAM-Adresse an das OS weiter. Diese Adresse MUSS im OS als `.noinit` Sektion deklariert sein, damit der Startup-Code des OS (crt0) die Variablen nicht vor dem Lesen nullt.

```c
typedef struct {
    uint32_t magic;              /* Immer 0x55AA55AA */
    uint32_t active_slot;        /* 0 = Slot A, 1 = Slot B */
    uint64_t boot_nonce;         /* Deterministische Anti-Replay Nonce */
    uint32_t reset_reason;       /* Letzter Hardware-Reset-Grund */
    uint32_t boot_failure_count; /* Aktueller Stand des Edge-Recovery Counters */
} toob_handoff_t;

extern __attribute__((section(".noinit"))) toob_handoff_t toob_handoff_state;
```

---

## API Referenz

### 1. `toob_confirm_boot()`
**Zweck:** Bestätigt dem Bootloader, dass das aktuell gebootete OS lauffähig ist. Setzt das Flag `COMMITTED`.
**Verhalten:** Muss vom OS aufgerufen werden, sobald alle kritischen Services (Network, Watchdog) hochgefahren sind. Geschieht dies vor dem nächsten Reset nicht, wird der Bootloader einen Rollback einleiten.

```c
/**
 * @brief Bestätigt das laufende Update.
 * @return 0x55AA55AA bei Erfolg, Fehlercode sonst.
 */
uint32_t toob_confirm_boot(void);
```

### 2. `toob_set_next_update(manifest_ptr)`
**Zweck:** Registriert ein neues heruntergeladenes OS-Manifest für den nächsten Boot.
**Verhalten:** Die Library hängt einen WAL-Eintrag in den Journal-Ring des Bootloaders an. Das OS muss den Payload zuvor in den inaktiven Slot geflasht haben.

```c
/**
 * @brief Signalisiert "Update Ready".
 * @param manifest_flash_addr Absolute Adresse des SUIT Manifests im Flash.
 * @return 0x55AA55AA bei Erfolg.
 */
uint32_t toob_set_next_update(uint32_t manifest_flash_addr);
```

### 3. `toob_get_boot_logs()`
**Zweck:** Liest das Timing-IDS und die Crash-Historie aus der Bootloader Diagnostik-Sektion.

```c
/**
 * @brief Extrahiert den letzten Boot-Log.
 * @param buffer Ziel Puffer.
 * @param max_len Puffer Länge.
 * @return Anzahl der geschriebenen Bytes.
 */
size_t toob_get_boot_logs(char* buffer, size_t max_len);
```
