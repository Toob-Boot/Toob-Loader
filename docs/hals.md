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
    BOOT_OK = 0x55AA55AA,    /* AUTOSAR-kompatibel: Anti-Glitch Pattern statt 0x00 */
    BOOT_ERR_FLASH = 1,      /* Flash-Operation fehlgeschlagen */
    BOOT_ERR_FLASH_ALIGN,    /* Adresse/Länge nicht aligned */
    BOOT_ERR_FLASH_BOUNDS,   /* Adresse außerhalb des Flash */
    BOOT_ERR_CRYPTO,         /* Kryptografische Operation fehlgeschlagen */
    BOOT_ERR_VERIFY,         /* Signatur/Hash ungültig */
    BOOT_ERR_TIMEOUT,        /* Operation hat Zeitlimit überschritten */
    BOOT_ERR_POWER,          /* Batteriespannung zu niedrig */
    BOOT_ERR_NOT_SUPPORTED,  /* Feature auf diesem Chip nicht verfügbar */
    BOOT_ERR_INVALID_ARG,    /* Ungültiger Parameter (NULL, 0-Länge, etc.) */
    BOOT_ERR_STATE,          /* Ungültiger Zustand (z.B. init nicht aufgerufen) */
    BOOT_ERR_FLASH_NOT_ERASED, /* Zielsektor wurde vor Write nicht gelöscht */
    BOOT_ERR_COUNTER_EXHAUSTED /* OTP/eFuse Counter am Limit */
} boot_status_t;

#define BOOT_UART_NO_DATA (-1)

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

## 0. HardFault & ECC Guard

Bevor eine HAL initialisiert werden darf, verlangt die Toob-Boot Spezifikation die Definition eines asynchronen **`HardFault_Handler`** in `startup.c`. Moderne Flash-Speicher mit ECC (z.B. STM32G4/U5) werfen bei unkorrigierbaren Bit-Rot Lesefehlern direkt eine NMI/HardFault-Exception. Die C-HAL hat hierbei keine Chance auf Fehler-Rückgabe. Der Handler MUSS existieren, das `ECC_NMI` Flag abfangen und zwingend das System asynchron über das Watchdog-Reset-Register neustarten. Zuvor MUSS der Handler (falls RAM/Bus noch intakt) ein `BOOT_ERR_ECC_HARDFAULT` Status-Bit/Intent im Survival-RAM setzen, damit Stage 1 nach dem Power-Cycle explizit einen Boot-Recovery-Zyklus einleiten kann, um einen Dauer-Brick durch Exception-Deadlock abzuwenden.

---

## 1. `flash_hal_t` — Flash-Speicher

```c
typedef struct {
    uint32_t      abi_version;     /* Zwingende ABI-Version, z.B. 0x01000000 */
    boot_status_t (*init)(void);
    void          (*deinit)(void);
    boot_status_t (*read)(uint32_t addr, void *buf, size_t len);
    boot_status_t (*write)(uint32_t addr, const void *buf, size_t len);
    boot_status_t (*erase_sector)(uint32_t addr);
    boot_status_t (*get_sector_size)(uint32_t addr, size_t *size_out);
    boot_status_t (*set_otfdec_mode)(bool enable);
    uint32_t      (*get_last_vendor_error)(void);

    uint32_t max_sector_size;  /* Größter Sektor auf Target. Nur für Swap-Buffer-Dimensionierung. Für konkrete Adressen MUSS get_sector_size(addr) verwendet werden. */
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
| **Flash-Encryption** | Bei aktiver HW-Encryption (ESP32, STM32 OTFDEC) MUSS `buf` zwingend den rohen **Ciphertext** enthalten. OTFDEC (Hardware-Entschlüsselung) bleibt während Flash-Reads deaktiviert, um gravierende Timing-Sidechannels bei der Hash-Validierung zu verhindern. |
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
| **Erase-Vorbedingung** | Der Zielbereich MUSS vorher gelöscht sein (alle Bytes == `erased_value`). NOR-Flash kann nur Bits 1→0 setzen. Schreiben auf nicht-gelöschten Bereich korrumpiert Daten still. Die HAL MUSS vor dem Schreiben (als **32-Bit Aligned Word-Check** für O(1) Geschwindigkeit) prüfen ob das Target-Medium auf `erased_value` genullt ist. Auf Chips mit Hardware-ECC (STM32L4+) kann der Controller selbst einen Fehler melden → Blank-Check entfällt. Wenn nicht, bricht sie strikt mit `BOOT_ERR_FLASH_NOT_ERASED` ab, um Shadow-Bricking zu durchkreuzen. Um bei gigantischen Images (O(n) Komplexität) keine Boot-Zeit zu opfern, MUSS der Check via Build-Macro `TOOB_FLASH_DISABLE_BLANK_CHECK` exakt opt-in abschaltbar sein. |
| **Flash-Encryption**   | Bei aktiver HW-Encryption: Die HAL flasht den verschlüsselten oder rohen Payload exakt so, wie ihn die Architektur definiert. Keine transparenten Voodoo-Verschlüsselungen während des Writes durch die Bootloader-HAL!                                                                                                                                                                                                                                                                                       |
| **Atomizität**         | Nicht atomar! Ein Stromausfall mitten im Write hinterlässt einen halb-geschriebenen Bereich. Das WAL-Journal im Core handhabt das (Replay bei fehlgeschlagenem Commit).                                                                   |
| **Rückgabe**           | `BOOT_OK`, `BOOT_ERR_FLASH`, `BOOT_ERR_FLASH_ALIGN`, `BOOT_ERR_FLASH_BOUNDS`, `BOOT_ERR_FLASH_NOT_ERASED`.                                                                                                                                                             |
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
| **Dauer!**               | Das ist die LANGSAMSTE Flash-Operation. Typische Zeiten: ESP32 4KB Sektor: ~45ms. STM32H7 128KB Sektor: ~2000ms (!). Die HAL blockiert für die gesamte Dauer. Der Core ruft `wdt_hal.kick()` VOR dem Erase auf. **(GAP-C02 Mitigation): `boot_swap.c` und `boot_rollback.c` DÜRFEN NIEMALS Bereiche größer als `CHIP_FLASH_MAX_SECTOR_SIZE` am Stück löschen. Wenn die Vendor-ROM nur monolithische Löschfunktionen anbietet, deren Dauer den WDT überschreitet, MÜSSEN sie stattdessen eine Bounded Loop über Einzelsektoren ausführen und `wdt_hal->kick()` in der Schleife aufrufen.** |
| **CPU-Blocking (nRF52)** | Auf nRF52 (kein RWW) ist die CPU während des Erase komplett blockiert — kein Interrupt, kein Code-Fetch. Der WDT-Timeout muss das tolerieren.                                                                                                                   |
| **Rückgabe**             | `BOOT_OK`, `BOOT_ERR_FLASH`, `BOOT_ERR_FLASH_ALIGN`, `BOOT_ERR_FLASH_BOUNDS`.                                                                                                                                                                                   |
| **Sandbox**              | `memset(addr, erased_value, sector_size)` auf der mmap'd Datei. Optional: Fault-Injection simuliert Stromausfall mitten im Erase.                                                                                                                               |

### `get_sector_size(addr, size_out)`

```c
boot_status_t (*get_sector_size)(uint32_t addr, size_t *size_out);
```

| Aspekt                                        | Detail                                                                                                                                                                                                                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**                                   | Schreibt die Sektorgröße an der gegebenen Adresse in `size_out`. **(GAP-F09/F21)** Da der Toobfuzzer (via `aggregated_scan.json`) SoC-Segment-Limits aufdeckt (wie STM32F4 mit 16/64/128 KB gemischten Zonen), iteriert diese Funktion über die generierte Map aus `chip_config.h` und gibt die dynamisch korrekte Größe des Sektors zurück, in welchem `addr` liegt. Reguläres Bootloader-Iterieren erfolgt ausschließlich hierüber. |
| **Aufgerufen von**                            | `boot_swap.c` (um zu wissen wie groß der aktuelle Swap-Schritt ist), `boot_journal.c` (Ring-Sektor-Größe).                                                                                                                                                              |
| **Warum nicht einfach `sector_size` nutzen?** | Weil STM32F4/F7 Sektoren von 16 KB bis 128 KB haben — gemischt im gleichen Flash. Ein Swap über den 16KB-Bereich darf nur 16KB auf einmal kopieren, auch wenn der Swap-Buffer 128KB groß ist.                                                                           |
| **Rückgabe**                                  | `BOOT_OK` bei Erfolg. `BOOT_ERR_FLASH_BOUNDS` wenn `addr` außerhalb des Flashs liegt. |

### `set_otfdec_mode(enable)`

```c
boot_status_t (*set_otfdec_mode)(bool enable);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | On-The-Fly-Decryption (OTFDEC / XIP Encryption) für das Flash-Memory aktivieren oder deaktivieren.                                                                       |
| **Aufgerufen von**   | `boot_main.c`, bevor Images gehashed oder verifiziert werden, wenn `platform->flash->set_otfdec_mode` nicht NULL ist.                                                    |
| **Rückgabe**         | `BOOT_OK` bei Erfolg, `BOOT_ERR_NOT_SUPPORTED` wenn nicht verfügbar.                                                                                                     |

### `get_last_vendor_error()`

```c
uint32_t (*get_last_vendor_error)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Plattformspezifisches HW-Error-Register auslesen. **(GAP-F13)** Das Register liefert Hersteller-konforme Error-Codes (laut der `return_convention` in `blueprint.json`), welche von der HAL-Ebene zwingend als verständliche Error-States und P10-Metrik via CBOR oder `boot_status_t` umgeschlüsselt in die Telemetrie gemappt werden müssen. |
| **Cache & Clear Verhalten** | Das Vendor-Error Register MUSS beim Auslesen von der HAL gecached und in der Hardware via Reset-Bit gelöscht werden (Clear-on-Read), um nachfolgende Transaktionen nicht mit antiken Fehlern zu belegen.          |
| **Rückgabe**         | 32-Bit Vendor-Code. 0 = kein Fehler. |

### Metadaten-Felder & Hybride HAL-Architektur (Toobfuzzer Integration)

Die Bereitstellung der HAL-Parameter folgt der hybriden Zero-Bloat Architektur (siehe `docs/concept_fusion.md`).
Die folgenden Felder sowie kritische Registeradressen (Watchdog-Kick `REG_WDT_FEED`, Reset `REG_RESET_REASON`, BootROM-Pointer wie `ROM_PTR_FLASH_ERASE`) werden **nicht** hardcodiert! 

Wie in `docs/toobfuzzer_integration.md` beschrieben, generiert der Manifest-Compiler diese Werte *automatisch* aus den Fuzzer-Scans (z.B. `blueprint.json`) und webt sie als `#define` Makros in die `chip_config.h` ein. Das erlaubt dem C-Code, mit variablen Hardware-Grenzen und Raw-Pointern zu arbeiten, ohne Hersteller-SDKs wie ESP-IDF unnötig einbinden zu müssen.

| Feld           | Typ        | Wer setzt es / Datenquelle                                                                                       | Wer liest es                                                                               |
| -------------- | ---------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `max_sector_size`| `uint32_t` | **(F09/F21)** Manifest-Compiler (Maximum aller `size` Felder aus dem `aggregated_scan.json`) | Dient ausnahmslos als statisches Kompilier-Limit für die SRAM-Allokation (`uint8_t swap_buf[CHIP_FLASH_MAX_SECTOR_SIZE]`). |
| `total_size`   | `uint32_t` | Manifest-Compiler (Summe aller Sektoren aus Scan)                                                                | Bounds-Checks in Read/Write/Erase                                                          |
| `write_align`  | `uint8_t`  | Manifest-Compiler (aus `blueprint.json` → `flash_capabilities.write_alignment_bytes`)                            | Core padded alle Write-Operationen auf dieses Alignment                                    |
| `erased_value` | `uint8_t`  | Manifest-Compiler (aus Fuzzer "run_ping" Test)                                                                   | `boot_journal.c` (erkennt unbeschriebene WAL-Slots), `boot_swap.c` (Erase-Verifikation)    |

---

## 2. `confirm_hal_t` — Boot-Bestätigung

```c
typedef struct {
    uint32_t      abi_version;
    boot_status_t (*init)(void);
    void          (*deinit)(void);
    bool          (*check_ok)(uint64_t expected_nonce);
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


### `check_ok(expected_nonce)`

```c
bool (*check_ok)(uint64_t expected_nonce);
```

| Aspekt                    | Detail                                                                                                                                                                                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**               | Prüfen ob das Confirm-Flag gesetzt ist.                                                                                                                                                                                                                                                                                              |
| **Aufgerufen von**        | `boot_confirm.c`, einmal pro Boot, NACH dem Reset-Reason-Check.                                                                                                                                                                                                                                                                      |
| **Kritische Interaktion** | Der Core prüft Reset-Reason BEVOR er `check_ok()` auswertet. Wenn `get_reset_reason() == WATCHDOG` oder `SOFTWARE_PANIC`, wird das Ergebnis von `check_ok()` ignoriert — auch wenn es `true` ist. Das verhindert die Todesspirale "OS setzt Flag → OS crasht 200ms später → WDT → Stage 1 sieht Flag → bootet crashendes OS erneut." |
| **Persistenzpflicht**     | Der physische Speicherort (RTC-FAST-MEM, Wear-leveled Flash-Sektor, Backup-Register) ist ein HAL-Implementierungsdetail. Die HAL MUSS jedoch garantieren, dass der Wert einen vollständigen Power-Cycle überlebt. |
| **Rückgabe**              | `true` wenn der Speicherwert exakt mit der `expected_nonce` übereinstimmt. `false` wenn abweichend, korrumpiert oder nach ungültigem Kaltstart. |

### `clear()`

```c
boot_status_t (*clear)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                           |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Das Confirm-Flag löschen.                                                                                                                                                                                        |
| **Aufgerufen von** | `boot_confirm.c` in zwei Situationen: (1) VOR dem Jump zum OS — damit das neue OS das Flag selbst setzen muss. (2) Nach einem Watchdog-Reset — um das (möglicherweise fälschlich gesetzte) Flag zu invalidieren. |
| **Mechanismus**    | Löscht die hinterlegte Nonce (Überschreiben mit `0x00` oder `erased_value`). **(GAP-C08 Mitigation): Nach dem Überschreiben MUSS die HAL zwingend einen "Read-After-Write Verify" durchführen. Liefert das Zurücklesen nicht den komplett gelöschten Status (z.B. aufgrund stillen Bit-Rots), MUSS die HAL zwingend `BOOT_ERR_FLASH` zurückgeben, um einen sofortigen Panic-Reset auszulösen anstatt fehlerhaft ins OS zu springen.** |
| **Rückgabe**       | `BOOT_OK`.                                                                                                                                                                                                       |

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Hardware-Locks wiederherstellen. OTFDEC Re-Enable: Hat der Bootloader zuvor `set_otfdec_mode(false)` gerufen um Ciphertexts zu hashen, MUSS die `deinit` Funktion die Hardware-Decryption zwingend wieder aktivieren.                                                          |
| **Aufgerufen von**     | `boot_main.c`, in umgekehrter Init-Reihenfolge vor OS-Jump.                                                                                                                                                                              |

### Besonderheit: OS-seitiger Direct-Write (`libtoob` / F14 / F15)

Die Funktion `set_ok(nonce)` existiert absichtlich *nicht* im Bootloader-Interface. Der Bootloader liest den State nur noch. Das finale Bestätigen des Updates obliegt alleinig dem gebooteten Feature-OS. Dieses bindet die `libtoob` C-Library ein, die den Status `TENTATIVE` auf `COMMITTED` in den Speicher flippt. 

**(GAP-F14/F15 OS Boundary):** Damit `libtoob` exakt weiß, an welche physische hexadezimale Adresse es das Zwangssignal (`ADDR_CONFIRM_RTC_RAM` / `WAL_BASE_ADDR`) schreiben muss, generiert der Manifest-Compiler bei jedem Build einen dedizierten C-Header `libtoob_config.h` aus den `blueprint.json` / `aggregated_scan.json` Daten des Toobfuzzers. Das Feature-OS (Zephyr, FreeRTOS, Linux) inkludiert diesen Header zwingend, sodass Bootloader-Read und OS-Write auf garantiert identischen Fuzzer-validierten Adressen stattfinden, ohne dass sich die Repositories Code teilen müssen.
---

## 3. `crypto_hal_t` — Kryptografie

```c
typedef struct {
    uint32_t      abi_version;
    boot_status_t (*init)(void);
    void          (*deinit)(void);
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
    uint32_t      (*get_last_vendor_error)(void);
    
    /* Hardware OTP / Serial-Rescue Keys */
    boot_status_t (*read_pubkey)(uint8_t key[32], uint8_t key_index);
    boot_status_t (*read_dslc)(uint8_t *buffer, size_t *len);
    boot_status_t (*read_monotonic_counter)(uint32_t *ctr);
    boot_status_t (*advance_monotonic_counter)(void);

    bool has_hw_acceleration;
    /* supports_pqc wurde entfernt. Existenz wird alleinig durch (verify_pqc != NULL) geprueft. */
} crypto_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Crypto-Engine starten. Wenn ein HW-RNG existiert, MUSS `init()` zwingend einen TRNG Seed-Quality Health Check ausführen. Schlägt dieser fehl, blockiert die Init. |
| **Aufgerufen von** | `boot_main.c`, nach Flash-Init, vor Verify.                                                                                                                                   |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_CRYPTO` wenn HW-Engine nicht antwortet oder TRNG schwache Entropie liefert.                                                                                                                  |

### `hash_init(ctx, ctx_size)`

```c
boot_status_t (*hash_init)(void *ctx, size_t ctx_size);
```

| Aspekt             | Detail                                                                                                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Einen neuen Hash-Context initialisieren. Der Context-Pointer `ctx` wird vom Bootloader garantiert aus seiner statischen `crypto_arena` übergeben (keine unberechenbaren Stack-Allokationen!).                                       |
| **Parameter**      | `ctx`: Pointer auf die statische Arena. `ctx_size`: Größe des Buffers in Bytes.                                                                                              |
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
| **Timing**         | Software (Monocypher): ~720.000 Zyklen auf Cortex-M4 ≈ 9ms @ 80 MHz. RISC-V (RV32IMC): ~950.000 Zyklen ≈ 15ms @ 64 MHz. HW (CC310): ~200.000 Zyklen ≈ 2.5ms. HW (STM32U5 PKA): ~150.000 Zyklen ≈ 1.9ms. |
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
| **Option**           | Dieser Funktionspointer ist standardmäßig `NULL`. Wird nur gesetzt wenn das Crypto-Backend PQC unterstützt.                              |
| **Kritischer Guard** | Der Core prüft via `verify_pqc != NULL`, woraufhin `verify_pqc()` sicher verwendet wird. Ein extra State-Bool entfällt. |
| **Hybrid-Modus**     | Der Core ruft ERST `verify_ed25519`, DANN `verify_pqc`. Beide müssen bestehen. Ein Angreifer der nur den klassischen Algorithmus bricht, scheitert an PQC und umgekehrt. |
| **Parameter-Größen** | ML-DSA-65: `sig_len` = 3.309 Bytes, `pubkey_len` = 1.952 Bytes. Deutlich größer als Ed25519!                                                                             |
| **RAM-Impact**       | **(GAP-C04 Mitigation): Für ML-DSA Matrizen ist jegliche Stack-Allokation STRIKT VERBOTEN. Der C-Core MUSS zwingend einen Scratchpad-Pointer übergeben (angepasste abstrakte Signatur der HAL), welcher auf die vorkompilierte `.bss` `crypto_arena` zeigt, um Stack-Overflows sicher zu verhindern.** Der Manifest-Compiler prüft ob `bootloader_budget` das hergibt. |
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

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | HW-Crypto-Engine abschalten. **Kritisch:** Zeroize der `crypto_arena`, um Key-Material-Residuen aus dem SRAM zu tilgen bevor das OS bootet. Es darf niemals ein einfaches `memset(0)` verwendet werden (wird oft vom Compiler wegoptimiert)! Hier MUSS zwingend die O(1) Assembly-Funktion `boot_secure_zeroize()` genutzt werden. |
| **Aufgerufen von**   | `boot_main.c`, nach Verify-Phase in der Deinit-Kaskade vor dem Jump.                                                                                                     |
| **Sandbox**          | No-Op (Software-Krypto hat keinen persistenten Hardware-State, Arena wird dennoch generisch vom Core gelöscht).                                                          |

### Hardware OTP & Telemetrie

### `read_pubkey(key, key_index)`

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Public Key für Update-Verifikation aus Hardware-OTP (eFuse / Option Bytes) lesen. Ermöglicht hardwarebasierte Key-Rotation im Fall eines Leaks.                        |
| **Parameter**        | `key`: 32 Byte Output-Buffer. `key_index`: Welcher Slot gelesen wird (wird im Bootloader-Header des Manifests angefordert, z.B. 0 oder 1).                               |
| **Alternative**      | Wenn kein Hardware-OTP genutzt wird: Der Key liegt als Konstante in `chip_config.h` als `BOOT_ED25519_PUBKEY` und die Funktion kopiert diesen lediglich in den Buffer. |

### `read_dslc(buffer, len)`

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Device Specific Lock Code (DSLC) aus physisch unveränderlicher Quelle (eFuse, OTP, UID-Register) lesen. Dient als Factor-1 für Serial Rescue ("Besitz").               |
| **Format & Länge**   | Das Format ist plattformabhängig (meist Raw Bytes). Der Core behandelt es als opaken Blob. Länge variiert (z.B. ESP32 MAC: 6 Bytes, STM32 UID: 12 Bytes). Buffer ≥ 32B.  |
| **Rückgabe**         | `BOOT_OK`, `BOOT_ERR_NOT_SUPPORTED` wenn keine eindeutige HW-ID existiert.                                                                                               |

### `read_monotonic_counter(ctr)` & `advance_monotonic_counter()`

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Lese und erhöhe den Anti-Replay Timestamp des Devices um Replay-Angriffe auf das Recovery-OS abzuwehren. Darf *niemals* in zirkulärem WAL liegen (Amnesie-Gefahr!).      |
| **Exhaustion-Check** | Vor dem Advance MUSS die Funktion gegen die physikalische Puffer-Obergrenze (z.B. begrenzte Anzahl eFuses) prüfen. Wenn alle aufgebraucht: `BOOT_ERR_COUNTER_EXHAUSTED`. |
| **Atomizität**       | Das Brennen einer eFuse ist physikalisch inherent atomar (Partial Atomicity). Für einen auf dem Data-Flash emulierten OTP-Bereich MUSS der Increment-Schritt jedoch mittels XOR-Masking / TMR pseudo-atomar abgesichert sein. |

### `get_last_vendor_error()`

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Plattformspezifisches HW-Error-Register auslesen (z.B. CC310 Fault Status), um aussagekräftige IDS-Telemetrie bei `BOOT_ERR_CRYPTO` ans OS zu reporten.                  |
| **Rückgabe**         | 32-Bit Vendor-Code. 0 = kein Fehler. Die Funktion ist Read-only und modifiziert den Fehler-State nicht.                                                                  |

### Metadaten-Felder

| Feld                  | Typ    | Bedeutung                                                                                                                                                       |
| --------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `has_hw_acceleration` | `bool` | `true` wenn SHA-256 oder Ed25519 in Hardware laufen. Für Timing-IDS: HW-Verify ist ~5x schneller als SW, der Fleet-Baseline-Vergleich muss das berücksichtigen. |

---

## 4. `clock_hal_t` — Zeit & Reset-Diagnostik

```c
typedef struct {
    uint32_t        abi_version;
    boot_status_t   (*init)(void);
    void            (*deinit)(void);
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
| **Aufgerufen von** | `boot_main.c`, als ERSTER HAL-Aufruf überhaupt. Alles andere braucht eine Zeitbasis. `clock_hal.init` konfiguriert AUSSCHLIESSLICH den SysTick/Zähler. Die Kern-PLLs / High-Speed-Clocks werden strikt VOR dem call in der C-Laufzeitumgebung (`startup.c` / `SystemInit()`) hochgefahren. |
| **CPU-Frequenz**   | Die Init-Funktion muss die CPU-Frequenz kennen (aus `chip_config.h` oder Hardware-Register). Bei ESP32 ist die Frequenz nach dem ROM-Bootloader bereits gesetzt. |
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
| **Aufgerufen von**  | `boot_main.c` (Boot-Timeout: Warte auf Recovery-Pin oder Serial-Eingabe).                                           |
| **Verbot für Timeouts** | DARF NICHT für große Edge-Recovery Exponential Backoffs (1-24h) genutzt werden, da die Busy-Wait Schleife die Batterie leersaugt. Hierfür ist zwingend `soc_hal.enter_low_power` vorgesehen. |
| **WDT-Interaktion** | Wenn `ms` größer als der WDT-Timeout ist, MUSS der Core den WDT zwischendurch kicken. Das ist NICHT die Aufgabe der HAL — der Core in `boot_main.c` wickelt den `delay_ms()`-Aufruf in eine Schleife (die nun als standardisiertes `boot_delay_with_wdt` Hilfsfunktion in der Core API liegt) mit WDT-Kicks. |
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
| **Idempotenz (Caching Pflicht)**| Da das Auslesen Registern oft die Hardware-Clear-Bits triggert, MUSS die HAL-Implementierung den initial ausgelesenen Wert intern in einer statischen Variable cachen (`static reset_reason_t cached_reason;`). Jeder Folgeaufruf gibt nur noch den Cache zurück. Der Core darf beliebig oft pollen. |
| **Rückgabe**                        | Einer der `reset_reason_t` Enum-Werte. `RESET_UNKNOWN` wenn kein bekanntes Flag gesetzt ist.                                                                                                                                                                                                                                                                                                                             |

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | SysTick/Timer stoppen. Interrupt-Handler (falls SysTick IRQ genutzt wurde) deregistrieren. CPU-Frequenz wird NICHT geändert (OS erbt Startup-Clocks).                    |
| **Aufgerufen von**   | `boot_main.c`, als absolut letztes `deinit()` unmittelbar vor dem OS-Jump.                                                                                               |

---

## 5. `wdt_hal_t` — Hardware-Watchdog

```c
typedef struct {
    uint32_t      abi_version;
    boot_status_t (*init)(uint32_t timeout_ms);
    void          (*deinit)(void);
    void          (*kick)(void);
    void          (*suspend_for_critical_section)(void);
    void          (*resume)(void);
} wdt_hal_t;
```

### `init(timeout_ms)`

```c
boot_status_t (*init)(uint32_t timeout_ms);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Hardware-Watchdog starten mit dem angegebenen Timeout.                                                                                                                                                                                   |
| **Parameter**          | `timeout_ms`: Wird dynamisch aus `längste_Einzeloperation + 2x_Marge` berechnet. `init()` rundet diesen Wert implizit auf die *nächstmögliche physikalische Hardware-Treppenstufe* der MCU auf! Der tatsächlich konfigurierte Timeout kann (und darf) sicherheitsbedingt leicht höher sein, aber niemals niedriger. |
| **Aufgerufen von**     | `boot_main.c`, nach Flash-Init, so früh wie möglich.                                                                                                                                                                                     |
| **Hardware-Auswahl**   | ESP32: RWDT (RTC Watchdog) — überlebt Light-Sleep. STM32: IWDG (Independent WDT) — läuft auf eigenem 32 kHz LSI-Oszillator, unabhängig von System-Clocks. nRF52: WDT Peripheral — nicht stoppbar nach Start!                             |
| **nRF52-Besonderheit** | Der nRF52 WDT kann nach dem Start NICHT mehr deaktiviert werden (Hardware-Schutz). `deinit()` ist auf nRF52 ein No-Op. Das ist beabsichtigt — der WDT soll absichtlich nicht abschaltbar sein. |
| **Genauigkeit**        | WDT-Timer sind typisch ungenau (LSI ±10%). Ein 5000ms-Timeout kann real zwischen 4500ms und 5500ms auslösen. Die Timing-Berechnungen im Manifest-Compiler berücksichtigen 2× Safety-Margin.                                              |
| **Rückgabe**           | `BOOT_OK`. `BOOT_ERR_INVALID_ARG` wenn `timeout_ms` (nach Hardware-Limit-Check durch Compiler) trotz physikalischem Margin-Rounding fehlschlägt.                                                                                                                                                     |

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

### `suspend_for_critical_section()` & `resume()`

```c
void (*suspend_for_critical_section)(void);
void (*resume)(void);
```

| Aspekt             | Detail                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | Watchdog temporär deaktivieren oder den Prescaler signifikant hochskalieren. Erforderlich für Vendor-ROM Erase-Makros, die in C nicht iterativ pausierbar sind. |
| **WICHTIG (Keine völlige Deaktivierung)** | Auf produktionskritischen Systemen DARF die HAL den WDT hier nicht stumpf mit `0` (Disable) abschalten, sondern MUSS lediglich den dynamischen Hardware-Prescaler maximal hochskalieren (z.B. auf 26 Sekunden). |
| **Aufgerufen von** | `boot_swap.c` ODER `boot_delta.c` NUR unmittelbar vor monolithischen Flash-Operationen, die das WDT-Limit sprengen. Danach folgt strikt `resume`. |
| **Reentrancy**     | **NICHT REENTRANT!** Der Core garantiert, dass diese Methoden niemals iterativ verschachtelt aufgerufen werden. |

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Watchdog deaktivieren oder in Hardware-Default-State überführen, bevor das OS startet.                                                                                   |
| **Handoff (.noinit)**| Der aktive Watchdog-Status und Parameter MÜSSEN zwingend über die `.noinit` Sektion an das Feature-OS übergeben werden, damit dieses beim Boot lückenlos weiter füttern kann! |
| **Aufgerufen von**   | `boot_main.c`, in der Deinit-Kaskade.                                                                                                                                    |
| **Ausnahmen**        | Auf Hardware, die den Watchdog nicht stoppen kann (nRF52, STM32 IWDG), ist dies zwingend ein **No-Op**. Das OS erbt in diesem Fall einen laufenden Watchdog und muss diesen zeitnah kicken oder übernehmen! Bei konfigurierbarem ESP32 RWDT wird der Timer deaktiviert. |

---

## 6. `console_hal_t` — Serielle Konsole (OPTIONAL)

```c
typedef struct {
    uint32_t      abi_version;
    boot_status_t (*init)(uint32_t baudrate);
    void          (*deinit)(void);
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
| **WDT-Kicking Pflicht**| Da bei starkem Log-Aufkommen (z.B. >1 KB) das Blockieren über Dutzende Millisekunden kumuliert, verzichtet Toob-Boot als strikte Architekturregel auf das Kicken innerhalb von `console.putchar` (Architektur-Bloat) und zwingt stattdessen den aufrufenden diagnostischen Core, den WDT über non-blocking Batch-Ausgaben in der Aufrufschleife selbst zu füttern. |
| **Kein Rückgabewert** | Kann nicht fehlschlagen (blockiert bis fertig).                                                                |

### `getchar(timeout_ms)`

```c
int (*getchar)(uint32_t timeout_ms);
```

| Aspekt              | Detail                                                                                                                                                     |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**         | Ein Zeichen empfangen, als non-blocking Polling implementiert.                                                                                                                         |
| **Aufgerufen von**  | Serial Rescue (4a): Wartet auf Auth-Token vom Techniker (104 Bytes über UART).                                                                             |
| **Parameter**       | `timeout_ms`: Maximale Wartezeit. 0 = sofort zurückkehren wenn nichts da.                                                                                  |
| **Integer Cast Warnung** | Ein nativer `int` Rückgabewert ist zwingend, da ein impliziter Cast auf `uint8_t` den `-1` Fehlercode (0xFF) sofort als valides Payload-Byte tarnen würde! |
| **Rückgabe**        | Empfangenes Byte (0-255) als native `int`. `-1` (bzw. `BOOT_UART_NO_DATA`) wenn noch kein Byte im RX-Buffer liegt. |
| **WDT-Interaktion** | Da die Funktion sofort zurückkehrt, blockiert sie die CPU nicht. Die Recovery-Schleife ruft die Funktion beständig auf und kann im gleichen Zug sicher `wdt->kick()` antriggern! |

### `flush()`

```c
void (*flush)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**        | Warten bis alle gepufferten Zeichen gesendet wurden.                                                                                                                                                         |
| **Aufgerufen von** | `boot_diag.c` (nach dem letzten Log-Eintrag, vor dem OS-Jump), Serial Rescue (nach jeder Response an den Techniker).                                                                                         |
| **Warum nötig**    | Wenn `putchar()` in einen FIFO-Buffer schreibt (STM32 USART hat 8-Byte FIFO), muss `flush()` warten bis der FIFO leer ist. Sonst geht die letzte Log-Zeile verloren wenn `deinit()` den UART abschaltet. |

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | Serielle Peripherie deaktivieren. TX/RX GPIO Pins in den Default-Reset Zustand setzen (Analog/High-Z), IRQ Masks löschen und FIFOs verwerfen.                            |
| **Aufgerufen von**   | `boot_main.c`, in der Deinit-Kaskade vor OS-Jump. (Schützt vor Pin-Kollision im Ziel-OS).                                                                                |

---

## 7. `soc_hal_t` — System-on-Chip & Batterie-Management (OPTIONAL)

```c
typedef struct {
    uint32_t      abi_version;
    boot_status_t (*init)(void);
    void          (*deinit)(void);
    uint32_t      (*battery_level_mv)(void);
    bool          (*can_sustain_update)(void);
    void          (*enter_low_power)(uint32_t wakeup_s);
    void          (*assert_secondary_cores_reset)(void);
    void          (*flush_bus_matrix)(void);
    
    uint32_t min_battery_mv; /* Vom Manifest diktierter Schwellenwert (z.B. > 3100mV für SPI Erase Margin) */
} soc_hal_t;
```

### `init()`

```c
boot_status_t (*init)(void);
```

| Aspekt             | Detail                                                                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**        | ADC initialisieren, Referenzspannung kalibrieren, Dummy-Load-Pin konfigurieren.                                                                                                                           |
| **Aufgerufen von** | `boot_main.c` (letzter HAL-Init). Nur wenn `platform->soc != NULL`.                                                                                                                                       |
| **Kalibrierung**   | ESP32 ADC hat ±6% Ungenauigkeit ohne Kalibrierung. Die HAL sollte den werksseitig kalibrierten eFuse-Wert laden (ESP32: `esp_adc_cal_characterize()`). STM32: VREFINT-Kalibrierung aus Factory-OTP laden. |
| **Rückgabe**       | `BOOT_OK`. `BOOT_ERR_NOT_SUPPORTED` wenn kein ADC vorhanden.                                                                                                                                              |

### `battery_level_mv()`

```c
uint32_t (*battery_level_mv)(void);
```

| Aspekt                 | Detail                                                                                                                                                                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**            | Batteriespannung in Millivolt messen.                                                                                                                                                                                                     |
| **Dummy-Load Regel**   | Gibt die Peripherie es her, MUSS die Messung unter simulierter Last (Dummy-Load) stattfinden, damit der Voltage-Drop eines nahenden Flash-Writings das System nicht unvorhergesehen in den Brownout reißt. Das Schalten des Dummy-Loads verwaltet die HAL intern. |
| **Aufgerufen von**     | `boot_energy.c` in drei Situationen: (1) VOR Update-Start (Entscheidung ob genug Energie). (2) WÄHREND Update (Interleaved-Polling: dynamisch zwischen extrem stromfressenden Flash-Writes/Erases, um im Brownout-Ernstfall proaktiv schlafenzugehen). (3) NACH Brownout-Recovery (prüfen ob Batterie sich erholt hat).                              |
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
| **Aufgabe**        | Abschätzung ob die Batterie genug Energie für einen vollständigen Flash-Update-Zyklus hat. Evaluator der Metadaten-Grenze `min_battery_mv`.                       |
| **Dummy-Load Penalty** | Wenn die Hardware keinen steuerbaren Dummy-Load anlegen kann, MUSS die HAL das `min_battery_mv` Target als Penalty künstlich um z.B. 400mV erhöhen, um blinden Brownouts aus Leerlaufmessungen vorzubeugen. |
| **Aufgerufen von** | `boot_energy.c`, einmal VOR dem Start eines Updates. Wenn `false` → Update wird abgelehnt, Gerät wartet auf Ladung.                                               |
| **Rückgabe**       | `true` wenn Update sicher durchführbar. `false` wenn Risiko eines Brownout besteht.                                                                               |

### `enter_low_power(wakeup_s)`

```c
void (*enter_low_power)(uint32_t wakeup_s);
```

| Aspekt                | Detail                                                                                                                                                                                                                                                                              |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**           | Gerät in einen Low-Power-Zustand versetzen (Deep Sleep / Standby).                                                                                                                                                                                                                  |
| **Parameter**         | `wakeup_s`: Timeout in Sekunden, nach dem das System per RTC-Wakeup neu starten soll. Ein Wert von `0` bedeutet "Nur Wakeup durch externen Pin" (z.B. bei totalem Brownout).                                                                                                        |
| **Mechanismus (2x)**  | Es gibt 2 Backoff-Szenarien. (1) Edge-Recovery: Der Bootloader stürzt immer an derselben Flash-Stelle ab. Backoff wächst bis 24h. HAL setzt `wakeup_s` RTC Timer. (2) Brownout: Akku leer. HAL schläft bis externer Reset / Ladekabel triggert (`wakeup_s = 0`).                    |
| **Aufgerufen von**    | `boot_energy.c` im Edge-Recovery Pfad: Ist der `edge_unattended_mode` aktiv und crasht das System, nutzt S1 anstelle eines Hard-Locks einen stufenweisen Exponential Backoff-Sleep (1h, 4h, 12h, 24h). Die CPU taucht tiefgehend ab, um der Umgebung Marge für spontane Reparaturen (Netzwerk/Strom) zu gewähren. Fällt die Spannung primär *während* des Updates, wird nicht mehr endlos geschlafen, sondern extrem aggressiv für einen sofortigen Rollback das Journal versiegelt. |
| **Implementierung**   | ESP32: `esp_light_sleep_start()` (GPIO oder Timer Wakeup). STM32: `HAL_PWR_EnterSTOPMode()`. nRF52: `__WFE()` (Wait-for-Event). Sandbox: `sleep(timeout_s)`.                                                                                                                        |
| **WDT**               | Der WDT bleibt aktiv im Low-Power-Mode! Er ist das Aufweck-Signal. Bei ESP32 RWDT und STM32 IWDG laufen die WDT-Timer auch im Sleep/Stop-Mode (eigene RC-Oszillatoren).                                                                                                             |
| **Return-Sicherheit** | Bei Light-Sleep (RAM wird gehalten) kehrt die Funktion nach Wake-up linear zurück (Code läuft weiter). Bei regulärem Deep-Sleep löst das Aufwachen hingegen zwingend einen asynchronen Hard-Reset aus. Der Aufruf muss nach dem Deep-Sleep-Trigger folgend zwingend durch eine unendliche `while(1);` Trap im C-Code gesichert werden. |

### `assert_secondary_cores_reset()` & `flush_bus_matrix()`

```c
void (*assert_secondary_cores_reset)(void);
void (*flush_bus_matrix)(void);
```

| Aspekt                | Detail                                                                                                                                                                                                                                                                              |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Aufgabe**           | Physische Isolierung von Multi-Core/DMA-Nebenwirkungen vor dem OS-Einleseprozess oder Schreibvorgängen auf geteilten Speicher-Bussen.                                                                                                                                               |
| **Aufgerufen von**    | `boot_main.c`, VOR der restlichen HAL-Init Kaskade (sehr früh), um Bus-Traffic zu eliminieren. Zudem `flush_bus_matrix` direkt vor OS-Jump.                                                                                                                                         |
| **Bus-Timeout Limit** | Die `flush_bus_matrix` Funktion MUSS zwingend als Bounded-Loop (z.B. max 5.000 Zyklen) implementiert sein, da blockierte DMAs sonst einen endlosen Hänger auf dem Haupt-Bus-Matrix Reset verursachen. |
| **Mechanismus**       | `assert_secondary_cores_reset`: Hält Netzwerk/Radio-Cores (z.B. Cortex-M0+ auf STM32WB) permanent im Hardware-Reset-Hold fest, damit Bootloader-Speicher nicht von DMA-Attacken unterbrochen werden. `flush_bus_matrix`: Löscht AHB/APB Pipeline-Verzögerungen für den ungetrübten OS-Kaltstart (Sanitization).  |

### `deinit()`

```c
void (*deinit)(void);
```

| Aspekt               | Detail                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Aufgabe**          | SoC-spezifische Power-Domains (ADC) wieder abschalten, Dummy-Loads trennen, Taktung von Bus-Controllern auf Default zurücksetzen.                                        |
| **Aufgerufen von**   | `boot_main.c`, in der Deinit-Kaskade vor OS-Jump.                                                                                                                        |

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
    soc_hal_t      *soc;       /* Optional, NULL erlaubt */
} boot_platform_t;

const boot_platform_t *boot_platform_init(void);
```

### Init-Reihenfolge und Begründung

```c
/* Vollständige boot_platform_init() Routine inkl. Fallback SOS-Signalisierung */
const boot_platform_t *boot_platform_init(void) {
    /* Hardcoded Populate-Pattern. 
     * Wenn ein PFLICHT-HAL init() fehlschlaegt, muss der Bootloader atomar panicken.
     * Nutzt z.B. Fallback_SOS_LED Toggle, falls kein UART verfuegbar ist. */
}
```

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
⑦ soc.init() [optional]       ← LETZTENS: ADC kalibrieren & Handoff Isolierung
    │                           Braucht Clock für ADC-Sampling
    │                           Nicht zeitkritisch
    ▼
boot_state_run()               ← State-Machine startet
```
