# Toob-Boot HAL — Vollständige Funktionsliste

> Jede Funktion mit Signatur, Parametern, Rückgabewerten,
> Verhaltensregeln und wer sie im Core aufruft.

> [!NOTE]
> **Toobfuzzer Integration:** Diese HAL-Spezifikation (insbesondere die Flash-Metadaten) ist eng mit dem Toobfuzzer verknüpft. Das bedeutet: Diese Schnittstellen existieren, aber ihre dynamischen Limitierungen und Parameter (Alignment, Sektor-Größen) werden *ausdrücklich nicht hardcodiert*, sondern zur Build-Zeit via Manifest-Compiler aus den Fuzzer-Ergebnissen der physischen Hardware geladen.
> Lese dazu zunächst **`docs/toobfuzzer_integration.md`**.

---

## Gemeinsame Typen

```c
typedef enum {
    BOOT_OK = 0,
    BOOT_ERR_FLASH,          /* Flash-Operation fehlgeschlagen */
    BOOT_ERR_FLASH_ALIGN,    /* Adresse/Länge nicht aligned */
    BOOT_ERR_FLASH_BOUNDS,   /* Adresse außerhalb des Flash */
    BOOT_ERR_CRYPTO,         /* Kryptografische Operation fehlgeschlagen */
    BOOT_ERR_VERIFY,         /* Signatur/Hash ungültig */
    BOOT_ERR_TIMEOUT,        /* Operation hat Zeitlimit überschritten */
    BOOT_ERR_POWER,          /* Batteriespannung zu niedrig */
    BOOT_ERR_NOT_SUPPORTED,  /* Feature auf diesem Chip nicht verfügbar */
    BOOT_ERR_INVALID_ARG,    /* Ungültiger Parameter (NULL, 0-Länge, etc.) */
    BOOT_ERR_STATE,          /* Ungültiger Zustand (z.B. init nicht aufgerufen) */
} boot_status_t;

typedef enum {
    RESET_POWER_ON,
    RESET_PIN,
    RESET_WATCHDOG,
    RESET_SOFTWARE,
    RESET_BROWNOUT,
    RESET_UNKNOWN,
} reset_reason_t;
```

---

## 1. `flash_hal_t` — Flash-Speicher

```c
typedef struct {
    boot_status_t (*init)(void);
    boot_status_t (*read)(uint32_t addr, void *buf, size_t len);
    boot_status_t (*write)(uint32_t addr, const void *buf, size_t len);
    boot_status_t (*erase_sector)(uint32_t addr);
    size_t        (*get_sector_size)(uint32_t addr);

    uint32_t sector_size;      /* Größter Sektor (für Swap-Buffer-Dimensionierung) */
    uint32_t total_size;
    uint8_t  write_align;
    uint8_t  erased_value;
} flash_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt              | Detail                                                                                                                 |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**         | Flash-Controller initialisieren. SPI-Bus konfigurieren (ESP32), Flash-Clocks aktivieren (STM32), NVMC freigeben (nRF). |
| **Aufgerufen von**  | `boot_main.c`, einmal beim Start, als zweiter HAL nach Clock.                                                          |
| **Vorbedingung**    | Clock-HAL muss bereits initialisiert sein (Flash-Controller braucht Taktquelle).                                       |
| **Rückgabe**        | `BOOT_OK` bei Erfolg. `BOOT_ERR_FLASH` wenn der Controller nicht antwortet (SPI-Timeout, NVMC-Fehler).                 |
| **Darf blockieren** | Ja. SPI-Flash-Init kann ~10ms dauern (ESP32 Chip-Detect).                                                              |
| **Sandbox**         | Öffnet/erstellt die Flash-Simulationsdatei via `mmap()`. Füllt mit `erased_value` wenn neu.                            |

### `read(addr, buf, len)`

```c
boot_status_t (*read)(uint32_t addr, void *buf, size_t len);
```

| Aspekt               | Detail                                                                                                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**          | `len` Bytes ab Adresse `addr` in `buf` kopieren.                                                                                                                                   |
| **Aufgerufen von**   | Praktisch jedes Core-Modul. Häufigster HAL-Aufruf im System.                                                                                                                       |
| **Alignment**        | `addr` und `len` haben KEIN Alignment-Constraint für Read. Beliebige Byte-Zugriffe sind erlaubt.                                                                                   |
| **Flash-Encryption** | Bei aktiver HW-Encryption (ESP32, STM32 OTFDEC) MUSS `buf` den **Plaintext** enthalten. Die Entschlüsselung passiert transparent innerhalb der HAL. Der Core sieht nie Ciphertext. |
| **Bounds-Check**     | Wenn `addr + len > total_size` → `BOOT_ERR_FLASH_BOUNDS` zurückgeben.                                                                                                              |
| **Rückgabe**         | `BOOT_OK` oder `BOOT_ERR_FLASH` (Hardware-Fehler) oder `BOOT_ERR_FLASH_BOUNDS`.                                                                                                    |
| **Darf blockieren**  | Ja, kurz. SPI-Read dauert ~1µs/Byte bei 40 MHz. Bei nRF52 (kein RWW): Read blockiert wenn gerade ein Write läuft.                                                                  |
| **Sandbox**          | `memcpy` aus der mmap'd Datei.                                                                                                                                                     |

### `write(addr, buf, len)`

```c
boot_status_t (*write)(uint32_t addr, const void *buf, size_t len);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | `len` Bytes aus `buf` an Adresse `addr` im Flash schreiben.                                                                                                                                                                               |
| **Aufgerufen von**     | `boot_journal.c` (WAL-Entries), `boot_swap.c` (Sektor-Writes), `boot_rollback.c` (TMR-Flags).                                                                                                                                             |
| **Alignment-PFLICHT**  | `addr` MUSS ein Vielfaches von `write_align` sein. `len` MUSS ein Vielfaches von `write_align` sein. Bei Verletzung → `BOOT_ERR_FLASH_ALIGN`. Der Core garantiert Alignment — aber die HAL muss defensiv prüfen.                          |
| **Erase-Vorbedingung** | Der Zielbereich MUSS vorher gelöscht sein (alle Bytes == `erased_value`). NOR-Flash kann nur Bits 1→0 setzen. Schreiben auf nicht-gelöschten Bereich korrumpiert Daten still. Die HAL DARF optional prüfen (Debug-Mode), MUSS aber nicht. |
| **Flash-Encryption**   | Bei aktiver HW-Encryption: `buf` enthält Plaintext. Die HAL verschlüsselt transparent vor dem physischen Write.                                                                                                                           |
| **Atomizität**         | Nicht atomar! Ein Stromausfall mitten im Write hinterlässt einen halb-geschriebenen Bereich. Das WAL-Journal im Core handhabt das (Replay bei fehlgeschlagenem Commit).                                                                   |
| **Rückgabe**           | `BOOT_OK`, `BOOT_ERR_FLASH`, `BOOT_ERR_FLASH_ALIGN`, `BOOT_ERR_FLASH_BOUNDS`.                                                                                                                                                             |
| **STM32-Besonderheit** | STM32 Flash muss vor dem Write entsperrt werden (`HAL_FLASH_Unlock()`). Die HAL-Implementierung handhabt Lock/Unlock intern — der Core weiß nichts davon.                                                                                 |
| **ESP32-Besonderheit** | ESP32 SPI-Flash schreibt max 256 Bytes pro SPI-Transaktion. Die HAL splittet größere Writes intern.                                                                                                                                       |
| **Sandbox**            | `memcpy` in die mmap'd Datei + `msync()`. Optional: Fault-Injection bricht nach N Bytes ab.                                                                                                                                               |

### `erase_sector(addr)`

```c
boot_status_t (*erase_sector)(uint32_t addr);
```

| Aspekt                   | Detail                                                                                                                                                                                                                                                          |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**              | Den kompletten Flash-Sektor löschen der die Adresse `addr` enthält. Nach dem Erase sind alle Bytes im Sektor == `erased_value` (typisch `0xFF`).                                                                                                                |
| **Aufgerufen von**       | `boot_swap.c` (vor jedem Sektor-Write), `boot_journal.c` (WAL-Ring Pre-Erase), `boot_delta.c` (vor In-Place-Patch-Sektor).                                                                                                                                      |
| **Alignment**            | `addr` MUSS sektorausgerichtet sein (`addr % sector_size == 0`). Bei Verletzung → `BOOT_ERR_FLASH_ALIGN`.                                                                                                                                                       |
| **Dauer!**               | Das ist die LANGSAMSTE Flash-Operation. Typische Zeiten: ESP32 4KB Sektor: ~45ms. STM32L4 2KB Page: ~25ms. STM32H7 128KB Sektor: ~2000ms (!). nRF52 4KB Page: ~85ms. Die HAL blockiert für die gesamte Dauer. Der Core ruft `wdt_hal.kick()` VOR dem Erase auf. |
| **CPU-Blocking (nRF52)** | Auf nRF52 (kein RWW) ist die CPU während des Erase komplett blockiert — kein Interrupt, kein Code-Fetch. Der WDT-Timeout muss das tolerieren.                                                                                                                   |
| **Rückgabe**             | `BOOT_OK`, `BOOT_ERR_FLASH`, `BOOT_ERR_FLASH_ALIGN`, `BOOT_ERR_FLASH_BOUNDS`.                                                                                                                                                                                   |
| **Sandbox**              | `memset(addr, erased_value, sector_size)` auf der mmap'd Datei. Optional: Fault-Injection simuliert Stromausfall mitten im Erase.                                                                                                                               |

### `get_sector_size(addr)`

```c
size_t (*get_sector_size)(uint32_t addr);
```

| Aspekt                                        | Detail                                                                                                                                                                                                                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**                                   | Gibt die Sektorgröße an der gegebenen Adresse zurück. Für Chips mit uniformen Sektoren ist das immer `sector_size`. Für Chips mit variablen Sektoren (STM32F4: 16/64/128 KB gemischt) gibt diese Funktion die tatsächliche Größe des Sektors zurück der `addr` enthält. |
| **Aufgerufen von**                            | `boot_swap.c` (um zu wissen wie groß der aktuelle Swap-Schritt ist), `boot_journal.c` (Ring-Sektor-Größe).                                                                                                                                                              |
| **Warum nicht einfach `sector_size` nutzen?** | Weil STM32F4/F7 Sektoren von 16 KB bis 128 KB haben — gemischt im gleichen Flash. Ein Swap über den 16KB-Bereich darf nur 16KB auf einmal kopieren, auch wenn der Swap-Buffer 128KB groß ist.                                                                           |
| **Uniforme Chips**                            | Kann einfach `return sector_size;` sein.                                                                                                                                                                                                                                |
| **Rückgabe**                                  | Sektorgröße in Bytes. 0 wenn `addr` außerhalb des Flash liegt.                                                                                                                                                                                                          |

### Metadaten-Felder (Toobfuzzer Integration)

Die folgenden Felder werden **nicht** hardcodiert! Wie in `docs/toobfuzzer_integration.md` beschrieben, generiert der Manifest-Compiler diese Werte *automatisch* aus den Fuzzer-Scans (`aggregated_scan.json` und `blueprint.json`) und webt sie als `#define` Makros in die `chip_config.h` ein. Das erlaubt dem C-Code, mit variablen Hardware-Grenzen zu rechnen.

| Feld           | Typ        | Wer setzt es / Datenquelle                                                                                       | Wer liest es                                                                               |
| -------------- | ---------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `sector_size`  | `uint32_t` | Manifest-Compiler (aus `aggregated_scan.json` "size" Feld)                                                       | `boot_swap.c` (Swap-Buffer-Größe), `boot_journal.c` (Ring-Segment-Größe), Preflight-Checks |
| `total_size`   | `uint32_t` | Manifest-Compiler (Summe aller Sektoren aus Scan)                                                                | Bounds-Checks in Read/Write/Erase                                                          |
| `write_align`  | `uint8_t`  | Manifest-Compiler (aus `blueprint.json` → `flash_capabilities.write_alignment_bytes`)                            | Core padded alle Write-Operationen auf dieses Alignment                                    |
| `erased_value` | `uint8_t`  | Manifest-Compiler (aus Fuzzer "run_ping" Test)                                                                   | `boot_journal.c` (erkennt unbeschriebene WAL-Slots), `boot_swap.c` (Erase-Verifikation)    |

---

## 2. `confirm_hal_t` — Boot-Bestätigung

```c
typedef struct {
    boot_status_t (*init)(void);
    boot_status_t (*set_ok)(void);
    bool          (*check_ok)(void);
    boot_status_t (*clear)(void);
} confirm_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                  |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**        | Confirm-Subsystem initialisieren. Bei STM32: RTC-Domain-Clock aktivieren, Backup-Domain-Zugriff freischalten (`PWR->CR1 | = PWR_CR1_DBP`). Bei ESP32: RTC-FAST-MEM ist sofort nutzbar (kein Init nötig). Bei Flash-basiertem Confirm: dedizierten Sektor validieren. |
| **Aufgerufen von** | `boot_main.c`, nach Clock-Init (braucht Reset-Reason), vor State-Machine.                                               |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_STATE` wenn die RTC-Domain nicht aktiviert werden kann.                                            |

### `set_ok()`

```c
boot_status_t (*set_ok)(void);
```

| Aspekt                 | Detail                                                                                                                                                                                                     |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Das Confirm-Flag setzen. Signalisiert "der aktuelle Boot war erfolgreich, die Firmware darf permanent bleiben."                                                                                            |
| **ACHTUNG — Aufrufer** | Wird **NIE** vom Bootloader aufgerufen! Nur vom Feature-OS, über die `libtoob`-Bibliothek. Der Bootloader ruft nur `check_ok()` und `clear()`.                                                             |
| **Mechanismus**        | Schreibt ein Magic-Byte (`0x42`) an eine definierte Stelle. Bei RTC-RAM: direkte RAM-Adresse. Bei Backup-Register: `RTC->BKP0R = 0x42`. Bei Flash: Write in dedizierten Sektor (mit Wear-Leveling-Offset). |
| **Idempotenz**         | Mehrfaches Aufrufen ist sicher (überschreibt den gleichen Wert).                                                                                                                                           |
| **Rückgabe**           | `BOOT_OK`. `BOOT_ERR_FLASH` wenn Flash-basiert und der Sektor voll ist.                                                                                                                                    |

### `check_ok()`

```c
bool (*check_ok)(void);
```

| Aspekt                    | Detail                                                                                                                                                                                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**               | Prüfen ob das Confirm-Flag gesetzt ist.                                                                                                                                                                                                                                                                                              |
| **Aufgerufen von**        | `boot_confirm.c`, einmal pro Boot, NACH dem Reset-Reason-Check.                                                                                                                                                                                                                                                                      |
| **Kritische Interaktion** | Der Core prüft Reset-Reason BEVOR er `check_ok()` auswertet. Wenn `get_reset_reason() == WATCHDOG` oder `SOFTWARE_PANIC`, wird das Ergebnis von `check_ok()` ignoriert — auch wenn es `true` ist. Das verhindert die Todesspirale "OS setzt Flag → OS crasht 200ms später → WDT → Stage 1 sieht Flag → bootet crashendes OS erneut." |
| **Rückgabe**              | `true` wenn Magic-Byte vorhanden. `false` wenn nicht gesetzt, korrumpiert oder nach Kaltstart (RTC-RAM verloren).                                                                                                                                                                                                                    |

### `clear()`

```c
boot_status_t (*clear)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                           |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Das Confirm-Flag löschen.                                                                                                                                                                                        |
| **Aufgerufen von** | `boot_confirm.c` in zwei Situationen: (1) VOR dem Jump zum OS — damit das neue OS das Flag selbst setzen muss. (2) Nach einem Watchdog-Reset — um das (möglicherweise fälschlich gesetzte) Flag zu invalidieren. |
| **Mechanismus**    | Überschreibt das Magic-Byte mit `0x00` oder `erased_value`. Bei Flash-basiert: Erase des dedizierten Sektors.                                                                                                    |
| **Rückgabe**       | `BOOT_OK`.                                                                                                                                                                                                       |

---

## 3. `crypto_hal_t` — Kryptografie

```c
typedef struct {
    boot_status_t (*init)(void);
    boot_status_t (*hash_init)(void *ctx, size_t ctx_size);
    boot_status_t (*hash_update)(void *ctx, const void *data, size_t len);
    boot_status_t (*hash_finish)(void *ctx, uint8_t *digest, size_t *digest_len);
    boot_status_t (*verify_ed25519)(
        const uint8_t *message,  size_t msg_len,
        const uint8_t *sig,
        const uint8_t *pubkey
    );
    boot_status_t (*verify_pqc)(
        const uint8_t *message,  size_t msg_len,
        const uint8_t *sig,      size_t sig_len,
        const uint8_t *pubkey,   size_t pubkey_len
    );
    boot_status_t (*random)(uint8_t *buf, size_t len);

    bool has_hw_acceleration;
    bool supports_pqc;
} crypto_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Crypto-Engine starten. Bei nRF52: CC310 Power-On + Clock aktivieren. Bei ESP32: SHA/AES-Peripheral Clock. Bei Software-only (Monocypher): kein Init nötig (return `BOOT_OK`). |
| **Aufgerufen von** | `boot_main.c`, nach Flash-Init, vor Verify.                                                                                                                                   |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_CRYPTO` wenn HW-Engine nicht antwortet.                                                                                                                  |

### `hash_init(ctx, ctx_size)`

```c
boot_status_t (*hash_init)(void *ctx, size_t ctx_size);
```

| Aspekt             | Detail                                                                                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Einen neuen Hash-Context initialisieren. Der Context wird vom Aufrufer auf dem Stack allokiert und als opaker Buffer übergeben.                                       |
| **Parameter**      | `ctx`: Pointer auf Stack-Buffer. `ctx_size`: Größe des Buffers in Bytes.                                                                                              |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_INVALID_ARG` wenn `ctx_size` kleiner ist als der Backend-interne Context (z.B. Monocypher SHA-512 braucht 208 Bytes, SHA-256 braucht 108 Bytes). |
| **Context-Größe**  | Wird zur Compile-Zeit in `boot_config.h` als `BOOT_HASH_CTX_SIZE` gesetzt. Der Manifest-Compiler kennt das Backend und setzt den Wert korrekt.                        |
| **Aufgerufen von** | `boot_verify.c` (Image-Gesamt-Hash), `boot_merkle.c` (Chunk-Hash).                                                                                                    |

### `hash_update(ctx, data, len)`

```c
boot_status_t (*hash_update)(void *ctx, const void *data, size_t len);
```

| Aspekt             | Detail                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**        | Daten in den laufenden Hash einfließen lassen. Kann beliebig oft aufgerufen werden.                                                                          |
| **Parameter**      | `data`: Pointer auf Input-Daten. `len`: Anzahl Bytes. Kein Alignment-Constraint. `len = 0` ist erlaubt (No-Op).                                              |
| **Aufgerufen von** | `boot_merkle.c` in einer Schleife: Flash-Read 4KB → `hash_update(4KB)` → nächster Chunk.                                                                     |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_CRYPTO` bei HW-Engine-Fehler.                                                                                                           |
| **Performance**    | Bei HW-SHA (ESP32, STM32, nRF CC310) ist `hash_update` der Bottleneck für die Boot-Zeit. Typisch: Software SHA-256 ~30 Zyklen/Byte, Hardware ~3 Zyklen/Byte. |

### `hash_finish(ctx, digest, digest_len)`

```c
boot_status_t (*hash_finish)(void *ctx, uint8_t *digest, size_t *digest_len);
```

| Aspekt              | Detail                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**         | Den finalen Hash-Digest berechnen und in `digest` schreiben. Der Context ist danach verbraucht (nicht wiederverwendbar).                                     |
| **Parameter**       | `digest`: Output-Buffer, mindestens 32 Bytes (SHA-256) oder 64 Bytes (SHA-512). `digest_len`: In: Buffer-Größe. Out: tatsächliche Digest-Länge (32 oder 64). |
| **Aufgerufen von**  | `boot_verify.c` (nach allen Chunks), `boot_merkle.c` (nach einem Chunk).                                                                                     |
| **Rückgabe**        | `BOOT_OK`. `BOOT_ERR_INVALID_ARG` wenn `digest_len` zu klein für den gewählten Hash-Algorithmus.                                                             |
| **Nach dem Aufruf** | Der `ctx` ist ungültig. Für einen neuen Hash muss `hash_init()` erneut aufgerufen werden.                                                                    |

### `verify_ed25519(message, msg_len, sig, pubkey)`

```c
boot_status_t (*verify_ed25519)(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,      /* Immer 64 Bytes */
    const uint8_t *pubkey    /* Immer 32 Bytes */
);
```

| Aspekt             | Detail                                                                                                                                                                                                                                    |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Ed25519-Signatur über `message` verifizieren.                                                                                                                                                                                             |
| **Parameter**      | `message`/`msg_len`: Die signierten Daten (typisch: der SHA-256 Digest des SUIT-Manifests, also 32 Bytes). `sig`: 64-Byte Ed25519-Signatur. `pubkey`: 32-Byte Ed25519 Public Key (im Bootloader-Binary eingebrannt oder aus OTP geladen). |
| **Aufgerufen von** | `boot_verify.c` (SUIT-Manifest Envelope verifizieren), Serial Rescue (Auth-Token verifizieren).                                                                                                                                           |
| **Rückgabe**       | `BOOT_OK` wenn Signatur valide. `BOOT_ERR_VERIFY` wenn invalide. `BOOT_ERR_CRYPTO` bei HW-Fehler.                                                                                                                                         |
| **Timing**         | Software (Monocypher): ~720.000 Zyklen auf Cortex-M4 ≈ 9ms @ 80 MHz. HW (CC310): ~200.000 Zyklen ≈ 2.5ms. HW (STM32U5 PKA): ~150.000 Zyklen ≈ 1.9ms.                                                                                      |
| **Constant-Time**  | Die Implementierung MUSS constant-time sein (keine datenabhängigen Branches oder Speicherzugriffe). Monocypher garantiert das. HW-Engines sind inherent constant-time.                                                                    |
| **Envelope-First** | Der Core ruft `verify_ed25519` BEVOR er irgendein Manifest-Feld auswertet oder Daten schreibt. Kein einziges Byte aus dem Manifest wird interpretiert bevor die Signatur bestanden ist (Anti-Truncation).                                 |

### `verify_pqc(message, msg_len, sig, sig_len, pubkey, pubkey_len)`

```c
boot_status_t (*verify_pqc)(
    const uint8_t *message,  size_t msg_len,
    const uint8_t *sig,      size_t sig_len,
    const uint8_t *pubkey,   size_t pubkey_len
);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Post-Quantum-Signatur verifizieren (z.B. ML-DSA-65).                                                                                                                     |
| **Optional**         | Dieser Funktionspointer ist standardmäßig `NULL`. Wird nur gesetzt wenn das Crypto-Backend PQC unterstützt UND `pqc_hybrid = true` im TOML.                              |
| **Hybrid-Modus**     | Der Core ruft ERST `verify_ed25519`, DANN `verify_pqc`. Beide müssen bestehen. Ein Angreifer der nur den klassischen Algorithmus bricht, scheitert an PQC und umgekehrt. |
| **Parameter-Größen** | ML-DSA-65: `sig_len` = 3.309 Bytes, `pubkey_len` = 1.952 Bytes. Deutlich größer als Ed25519!                                                                             |
| **RAM-Impact**       | ML-DSA-65 Verify braucht ~10-30 KB Stack (je nach Implementierung). Der Manifest-Compiler prüft ob `bootloader_budget` das hergibt.                                      |
| **Rückgabe**         | `BOOT_OK`, `BOOT_ERR_VERIFY`, `BOOT_ERR_NOT_SUPPORTED` (wenn `NULL`).                                                                                                    |

### `random(buf, len)`

```c
boot_status_t (*random)(uint8_t *buf, size_t len);
```

| Aspekt                   | Detail                                                                                                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**              | Kryptografisch sichere Zufallszahlen generieren.                                                                                                                      |
| **Aufgerufen von**       | `boot_diag.c` (Nonce für Timing-IDS Report, Anti-Replay), `boot_main.c` (optional: zufällige Verzögerung gegen Timing-Side-Channels).                                 |
| **NICHT aufgerufen für** | Key-Generierung (passiert offline auf dem Host via `toob-keygen`). Signing (passiert auf dem Host via `toob-sign`). Nonce für Ed25519 (Ed25519 ist deterministisch).  |
| **Quellen**              | HW-TRNG (ESP32 `esp_random()`, STM32 `HAL_RNG_GenerateRandomNumber()`, nRF52 CC310 RNG). Software-Fallback: nicht akzeptabel für Produktion. Sandbox: `/dev/urandom`. |
| **Rückgabe**             | `BOOT_OK`. `BOOT_ERR_CRYPTO` wenn TRNG-Health-Check fehlschlägt.                                                                                                      |
| **Entropie**             | Mindestens 128 Bit Entropie pro Aufruf. Die HAL muss sicherstellen dass der TRNG eingeschwungen ist (ESP32: Mindestens 1 RF-Noise-Zyklus nach Power-On).              |

### Metadaten-Felder

| Feld                  | Typ    | Bedeutung                                                                                                                                                       |
| --------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `has_hw_acceleration` | `bool` | `true` wenn SHA-256 oder Ed25519 in Hardware laufen. Für Timing-IDS: HW-Verify ist ~5x schneller als SW, der Fleet-Baseline-Vergleich muss das berücksichtigen. |
| `supports_pqc`        | `bool` | `true` wenn `verify_pqc` nicht `NULL` ist.                                                                                                                      |

---

## 4. `clock_hal_t` — Zeit & Reset-Diagnostik

```c
typedef struct {
    boot_status_t   (*init)(void);
    uint32_t        (*get_tick_ms)(void);
    void            (*delay_ms)(uint32_t ms);
    reset_reason_t  (*get_reset_reason)(void);
} clock_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                                                                                  |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | System-Timer starten. Bei Cortex-M: SysTick konfigurieren (Reload-Wert basierend auf CPU-Frequenz). Bei RISC-V: `mtime`/`mtimecmp` konfigurieren. Bei Xtensa: CCOUNT nutzen (zählt automatisch).                                                                        |
| **Aufgerufen von** | `boot_main.c`, als ERSTER HAL-Aufruf überhaupt. Alles andere braucht eine Zeitbasis.                                                                                                                                                                                    |
| **CPU-Frequenz**   | Die Init-Funktion muss die CPU-Frequenz kennen (aus `chip_config.h` oder Hardware-Register). Bei ESP32 ist die Frequenz nach dem ROM-Bootloader bereits gesetzt. Bei STM32 muss der `startup.c` die Clocks konfiguriert haben BEVOR `clock_hal.init()` aufgerufen wird. |
| **Rückgabe**       | `BOOT_OK`. Praktisch kann diese Funktion nicht fehlschlagen (Timer-Hardware ist immer vorhanden).                                                                                                                                                                       |

### `get_tick_ms()`

```c
uint32_t (*get_tick_ms)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                                                                               |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Aktuelle Systemzeit in Millisekunden seit Boot zurückgeben.                                                                                                                                                                                                          |
| **Aufgerufen von** | `boot_journal.c` (Exponential-Backoff-Timer), `boot_diag.c` (Timing-IDS: Dauer jeder Boot-Phase messen), `boot_swap.c` (Timeout-Erkennung), `boot_main.c` (Boot-Timeout), Serial Rescue (UART-Timeout, Timestamp-Validierung).                                       |
| **Überlauf**       | Bei `uint32_t` und ms-Auflösung: Überlauf nach ~49 Tagen. Für einen Bootloader irrelevant (Boot dauert Sekunden, nicht Tage). Aber der Core berechnet Differenzen korrekt: `elapsed = now - start` funktioniert auch über den Überlauf hinweg (unsigned Arithmetik). |
| **Auflösung**      | 1 ms Mindestauflösung. Bei SysTick mit 1 kHz Interrupt ist das automatisch gegeben. CCOUNT (Xtensa) zählt in CPU-Zyklen — die HAL rechnet in ms um.                                                                                                                  |
| **Interrupt-frei** | Die Implementierung DARF einen Timer-Interrupt nutzen (SysTick), MUSS es aber nicht. Polling-basierte Implementierungen (CCOUNT-Register lesen) sind akzeptabel und vermeiden Interrupt-Komplexität im Bootloader.                                                   |
| **Sandbox**        | `gettimeofday()` mit Offset zum Prozessstart.                                                                                                                                                                                                                        |

### `delay_ms(ms)`

```c
void (*delay_ms)(uint32_t ms);
```

| Aspekt              | Detail                                                                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**         | Blockierend warten.                                                                                                                                                                                                 |
| **Aufgerufen von**  | `boot_main.c` (Boot-Timeout: Warte auf Recovery-Pin oder Serial-Eingabe), `boot_journal.c` (Exponential-Backoff: Warte N ms bevor erneuter Update-Versuch nach Brownout).                                           |
| **Implementierung** | Busy-Wait basierend auf `get_tick_ms()`: `while (get_tick_ms() - start < ms) {}`. KEIN Sleep/WFI — der Bootloader hat kein Interrupt-System das ihn aufwecken würde.                                                |
| **WDT-Interaktion** | Wenn `ms` größer als der WDT-Timeout ist, MUSS der Core den WDT zwischendurch kicken. Das ist NICHT die Aufgabe der HAL — der Core in `boot_main.c` wickelt den `delay_ms()`-Aufruf in eine Schleife mit WDT-Kicks. |
| **Sandbox**         | `usleep(ms * 1000)`.                                                                                                                                                                                                |

### `get_reset_reason()`

```c
reset_reason_t (*get_reset_reason)(void);
```

| Aspekt                              | Detail                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**                         | Den Grund des letzten Hardware-Resets zurückgeben.                                                                                                                                                                                                                                                                                                                                                                       |
| **Aufgerufen von**                  | `boot_confirm.c`, einmal pro Boot. DAS existenzkritische Feature für Auto-Rollback.                                                                                                                                                                                                                                                                                                                                      |
| **Seiteneffekt — Register löschen** | Bei STM32: Die Reset-Flags im `RCC_CSR` bleiben über Resets hinweg stehen. Die HAL MUSS die Flags nach dem ersten Lesen löschen (RMVF-Bit setzen). Sonst sieht der nächste normale Boot einen falschen Watchdog-Reset. Bei nRF52: `RESETREAS`-Register muss ebenfalls nach Lesen gelöscht werden (Bits auf 0 schreiben). Bei ESP32: `RTC_CNTL_RESET_CAUSE` wird automatisch aktualisiert (kein manuelles Löschen nötig). |
| **Priorität bei mehreren Flags**    | Es können mehrere Reset-Flags gleichzeitig gesetzt sein (z.B. WDT + Software auf STM32). Prioritätsreihenfolge: `WATCHDOG > BROWNOUT > SOFTWARE > PIN > POWER_ON`. Der schlimmste Grund gewinnt.                                                                                                                                                                                                                         |
| **Idempotenz**                      | DARF nur EINMAL pro Boot aufgerufen werden (weil die Funktion die Register löscht). Der Core ruft sie genau einmal auf und cached das Ergebnis.                                                                                                                                                                                                                                                                          |
| **Rückgabe**                        | Einer der `reset_reason_t` Enum-Werte. `RESET_UNKNOWN` wenn kein bekanntes Flag gesetzt ist.                                                                                                                                                                                                                                                                                                                             |

---

## 5. `wdt_hal_t` — Hardware-Watchdog

```c
typedef struct {
    boot_status_t (*init)(uint32_t timeout_ms);
    void          (*kick)(void);
    void          (*disable)(void);
} wdt_hal_t;
```

### `init(timeout_ms)`

```c
boot_status_t (*init)(uint32_t timeout_ms);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Hardware-Watchdog starten mit dem angegebenen Timeout.                                                                                                                                                                                   |
| **Parameter**          | `timeout_ms`: Wird vom Manifest-Compiler berechnet und in `boot_config.h` als `BOOT_WDT_TIMEOUT_MS` definiert. Typisch 5000ms, bei STM32H7 bis 8000ms.                                                                                   |
| **Aufgerufen von**     | `boot_main.c`, nach Flash-Init, so früh wie möglich.                                                                                                                                                                                     |
| **Hardware-Auswahl**   | ESP32: RWDT (RTC Watchdog) — überlebt Light-Sleep. STM32: IWDG (Independent WDT) — läuft auf eigenem 32 kHz LSI-Oszillator, unabhängig von System-Clocks. nRF52: WDT Peripheral — nicht stoppbar nach Start!                             |
| **nRF52-Besonderheit** | Der nRF52 WDT kann nach dem Start NICHT mehr deaktiviert werden (Hardware-Schutz). `disable()` ist auf nRF52 ein No-Op und gibt `BOOT_ERR_NOT_SUPPORTED` zurück. Das ist beabsichtigt — der WDT soll absichtlich nicht abschaltbar sein. |
| **Genauigkeit**        | WDT-Timer sind typisch ungenau (LSI ±10%). Ein 5000ms-Timeout kann real zwischen 4500ms und 5500ms auslösen. Die Timing-Berechnungen im Manifest-Compiler berücksichtigen 2× Safety-Margin.                                              |
| **Rückgabe**           | `BOOT_OK`. `BOOT_ERR_INVALID_ARG` wenn `timeout_ms` außerhalb des HW-Bereichs liegt.                                                                                                                                                     |

### `kick()`

```c
void (*kick)(void);
```

| Aspekt                | Detail                                                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**           | Den Watchdog-Timer zurücksetzen ("füttern"). Verhindert dass der WDT auslöst.                                                                                                                                      |
| **Aufgerufen von**    | `boot_swap.c` (3× pro Sektor-Swap: nach Swap-Write, nach App-Erase, nach App-Write), `boot_delta.c` (nach jedem Chunk), `boot_verify.c` (nach jedem Merkle-Chunk-Verify), `boot_main.c` (periodisch im Hauptloop). |
| **Frequenz**          | Muss mindestens alle `timeout_ms / 2` aufgerufen werden. Bei 5000ms Timeout: mindestens alle 2500ms. Der Core ruft `kick()` bei jeder Flash-Operation auf — das ist deutlich häufiger als nötig, aber sicher.      |
| **Kein Rückgabewert** | `kick()` kann nicht fehlschlagen. Es ist ein einziger Register-Write.                                                                                                                                              |
| **STM32 IWDG**        | `IWDG->KR = 0xAAAA;` — ein einziger Write.                                                                                                                                                                         |
| **ESP32 RWDT**        | `RTCCNTL.wdt_feed = 1;` — ein einziger Write.                                                                                                                                                                      |

### `disable()`

```c
void (*disable)(void);
```

| Aspekt             | Detail                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Watchdog deaktivieren.                                                                                                                                         |
| **Aufgerufen von** | `boot_main.c` NUR wenn Serial Rescue aktiviert wird (der Rescue-Flow hat keinen Timeout). Wird NICHT vor dem OS-Jump aufgerufen — der WDT läuft weiter ins OS! |
| **nRF52**          | Gibt `BOOT_ERR_NOT_SUPPORTED` zurück — der nRF52 WDT ist nach Start nicht deaktivierbar. Serial Rescue auf nRF52 muss periodisch `kick()` aufrufen.            |
| **Sandbox**        | Stoppt den Timer-Thread.                                                                                                                                       |

---

## 6. `console_hal_t` — Serielle Konsole (OPTIONAL)

```c
typedef struct {
    boot_status_t (*init)(uint32_t baudrate);
    void          (*putchar)(char c);
    int           (*getchar)(uint32_t timeout_ms);
    void          (*flush)(void);
} console_hal_t;
```

### `init(baudrate)`

```c
boot_status_t (*init)(uint32_t baudrate);
```

| Aspekt                | Detail                                                                                                                                             |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**           | UART initialisieren: Baudrate, 8N1, TX/RX-Pins konfigurieren.                                                                                      |
| **Parameter**         | `baudrate`: Aus `boot_config.h` (`BOOT_UART_BAUDRATE`), typisch 115200.                                                                            |
| **Aufgerufen von**    | `boot_main.c`, als letzter HAL-Init (nach allen Pflicht-HALs). Nur wenn `platform->console != NULL`.                                               |
| **Pin-Konfiguration** | Chip-spezifisch. ESP32: UART0 auf GPIO1/GPIO3 (Default). STM32: USART2 auf PA2/PA3 (Nucleo-Board-Standard). nRF52: UARTE0, Pins aus chip_config.h. |
| **Rückgabe**          | `BOOT_OK`. `BOOT_ERR_STATE` wenn UART-Peripheral nicht verfügbar.                                                                                  |

### `putchar(c)`

```c
void (*putchar)(char c);
```

| Aspekt                | Detail                                                                                                         |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**           | Ein einzelnes Zeichen senden. Blockiert bis das UART-TX-Register frei ist.                                     |
| **Aufgerufen von**    | `boot_diag.c` (JSON Boot-Log Zeichen für Zeichen ausgeben).                                                    |
| **Performance**       | Bei 115200 Baud: ~87µs pro Zeichen. Ein 200-Zeichen Boot-Log dauert ~17ms. Für die Boot-Zeit vernachlässigbar. |
| **Kein Rückgabewert** | Kann nicht fehlschlagen (blockiert bis fertig).                                                                |

### `getchar(timeout_ms)`

```c
int (*getchar)(uint32_t timeout_ms);
```

| Aspekt              | Detail                                                                                                                                                     |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**         | Ein Zeichen empfangen mit Timeout.                                                                                                                         |
| **Aufgerufen von**  | Serial Rescue (4a): Wartet auf Auth-Token vom Techniker (104 Bytes über UART).                                                                             |
| **Parameter**       | `timeout_ms`: Maximale Wartezeit. 0 = sofort zurückkehren wenn nichts da.                                                                                  |
| **Rückgabe**        | Empfangenes Byte (0-255) als `int`. `-1` wenn Timeout abgelaufen und kein Byte empfangen.                                                                  |
| **WDT-Interaktion** | Serial Rescue deaktiviert den WDT VOR dem `getchar()`-Loop (außer auf nRF52 wo `disable()` nicht geht — dort wird im Loop periodisch `kick()` aufgerufen). |

### `flush()`

```c
void (*flush)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**        | Warten bis alle gepufferten Zeichen gesendet wurden.                                                                                                                                                         |
| **Aufgerufen von** | `boot_diag.c` (nach dem letzten Log-Eintrag, vor dem OS-Jump), Serial Rescue (nach jeder Response an den Techniker).                                                                                         |
| **Warum nötig**    | Wenn `putchar()` in einen FIFO-Buffer schreibt (STM32 USART hat 8-Byte FIFO), muss `flush()` warten bis der FIFO leer ist. Sonst geht die letzte Log-Zeile verloren wenn `hal_deinit()` den UART abschaltet. |

---

## 7. `power_hal_t` — Batterie-Management (OPTIONAL)

```c
typedef struct {
    boot_status_t (*init)(void);
    uint32_t      (*battery_level_mv)(void);
    bool          (*can_sustain_update)(void);
    void          (*enter_low_power)(void);
} power_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | ADC initialisieren, Referenzspannung kalibrieren, Dummy-Load-Pin konfigurieren.                                                                                                                           |
| **Aufgerufen von** | `boot_main.c`, als letzter Init. Nur wenn `platform->power != NULL`.                                                                                                                                      |
| **Kalibrierung**   | ESP32 ADC hat ±6% Ungenauigkeit ohne Kalibrierung. Die HAL sollte den werksseitig kalibrierten eFuse-Wert laden (ESP32: `esp_adc_cal_characterize()`). STM32: VREFINT-Kalibrierung aus Factory-OTP laden. |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_NOT_SUPPORTED` wenn kein ADC vorhanden.                                                                                                                                              |

### `battery_level_mv()`

```c
uint32_t (*battery_level_mv)(void);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Batteriespannung in Millivolt messen, UNTER LAST.                                                                                                                                                                                         |
| **Aufgerufen von**     | `boot_energy.c` in drei Situationen: (1) VOR Update-Start (Entscheidung ob genug Energie). (2) WÄHREND Update (periodisch alle N Sektoren). (3) NACH Brownout-Recovery (prüfen ob Batterie sich erholt hat).                              |
| **Unter-Last-Messung** | Die HAL MUSS vor der Messung eine Last anlegen (GPIO-Pin auf High für eine LED, oder CPU-intensive Berechnung für ~50ms). Leerlaufmessungen an LiPo-Zellen sind nutzlos — die Spannung bricht erst unter Last ein.                        |
| **Spannungsteiler**    | Die meisten Boards messen die Batterie über einen resistiven Spannungsteiler (z.B. 2:1). Die HAL rechnet den Divider-Faktor ein (aus `chip_config.h`). Der zurückgegebene Wert ist die TATSÄCHLICHE Batteriespannung, nicht die geteilte. |
| **Rückgabe**           | Spannung in Millivolt. 0 wenn Messung fehlgeschlagen. Typische Werte: 4200 (voll), 3700 (50%), 3300 (kritisch), <3000 (Tiefentladung).                                                                                                    |
| **Sandbox**            | Liest Umgebungsvariable `TOOB_BATTERY_MV`. Default: 3700. Für Tests: `TOOB_BATTERY_MV=3100` simuliert niedrigen Akku.                                                                                                                     |

### `can_sustain_update()`

```c
bool (*can_sustain_update)(void);
```

| Aspekt             | Detail                                                                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Abschätzung ob die Batterie genug Energie für einen vollständigen Flash-Update-Zyklus hat.                                                                        |
| **Aufgerufen von** | `boot_energy.c`, einmal VOR dem Start eines Updates. Wenn `false` → Update wird abgelehnt, Gerät wartet auf Ladung.                                               |
| **Logik**          | `battery_level_mv() > (min_battery_mv + 200)`. Die 200mV Sicherheitsmarge kompensiert den Spannungsabfall während des Flash-Erase (200mA Spitzenstrom auf ESP32). |
| **Rückgabe**       | `true` wenn Update sicher durchführbar. `false` wenn Risiko eines Brownout besteht.                                                                               |

### `enter_low_power()`

```c
void (*enter_low_power)(void);
```

| Aspekt                | Detail                                                                                                                                                                                                                                                                              |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**           | Gerät in einen Low-Power-Zustand versetzen.                                                                                                                                                                                                                                         |
| **Aufgerufen von**    | `boot_energy.c` im Brownout-Backoff-Pfad: Wenn die Batterie während eines Updates unter den Schwellwert fällt, committet der Core den aktuellen WAL-Checkpoint und geht schlafen statt weiterzumachen. Der WDT weckt das Gerät nach dem Timeout, Stage 1 prüft die Batterie erneut. |
| **Implementierung**   | ESP32: `esp_light_sleep_start()` (GPIO oder Timer Wakeup). STM32: `HAL_PWR_EnterSTOPMode()`. nRF52: `__WFE()` (Wait-for-Event). Sandbox: `sleep(timeout_s)`.                                                                                                                        |
| **WDT**               | Der WDT bleibt aktiv im Low-Power-Mode! Er ist das Aufweck-Signal. Bei ESP32 RWDT und STM32 IWDG laufen die WDT-Timer auch im Sleep/Stop-Mode (eigene RC-Oszillatoren).                                                                                                             |
| **Kein Rückgabewert** | Die Funktion kehrt erst zurück wenn das Gerät aufwacht (WDT-Timeout oder externer Interrupt). Danach macht der Core normal mit `boot_main` weiter.                                                                                                                                  |

---

## Anhang: `boot_platform_t` und Initialisierungsreihenfolge

```c
typedef struct {
    flash_hal_t    *flash;     /* PFLICHT */
    confirm_hal_t  *confirm;   /* PFLICHT */
    crypto_hal_t   *crypto;    /* PFLICHT */
    clock_hal_t    *clock;     /* PFLICHT */
    wdt_hal_t      *wdt;       /* PFLICHT */
    console_hal_t  *console;   /* Optional, NULL erlaubt */
    power_hal_t    *power;     /* Optional, NULL erlaubt */
} boot_platform_t;

const boot_platform_t *boot_platform_init(void);
```

### Init-Reihenfolge und Begründung

```
boot_platform_init()          ← Chip-Startup (Clocks, JTAG-Lock)
    │
    ▼
① clock.init()                ← ZUERST: Alles andere braucht Zeitbasis
    │                           get_tick_ms() muss ab hier funktionieren
    ▼
② flash.init()                ← ZWEITENS: WAL + Partitionen lesen
    │                           Braucht Clock für SPI-Timing (ESP32)
    ▼
③ wdt.init(timeout_ms)        ← DRITTENS: So früh wie möglich
    │                           Ab hier: Crash → automatischer Reset
    │                           Braucht Clock für Timeout-Berechnung
    ▼
④ crypto.init()               ← VIERTENS: HW-Crypto-Engine starten
    │                           Braucht Clock für CC310-Clocks
    │                           Braucht Flash für Key-Laden (OTP)
    ▼
⑤ confirm.init()              ← FÜNFTENS: RTC-Domain/Backup-Reg init
    │                           Braucht Clock für get_reset_reason()
    │                           Wird direkt danach ausgewertet
    ▼
⑥ console.init() [optional]   ← SECHSTENS: Debug-Output
    │                           Braucht Clock für Baudrate
    ▼
⑦ power.init() [optional]     ← LETZTENS: ADC kalibrieren
    │                           Braucht Clock für ADC-Sampling
    │                           Nicht zeitkritisch
    ▼
boot_state_run()               ← State-Machine startet
```
