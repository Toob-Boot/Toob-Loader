# Toob-Boot: Gap-Analyse `hals.md` v2 (Stand: 2026-03-31)

> Rigorose Analyse der **aktuellen** `hals.md` gegen `concept_fusion.md`.  
> Die vorherige `hals_gap_analysis.md` basierte auf einer älteren Version – viele dort aufgelisteten Gaps (deinit, WDT-Suspend, OTFDEC, DSLC, soc_hal_t, BOOT_ERR_FLASH_NOT_ERASED, get_last_vendor_error) wurden inzwischen eingearbeitet.  
> Dieses Dokument identifiziert alle **verbleibenden** Inkonsistenzen, Lücken und potentiellen Fehler.

---

## A. Strukturelle & API-Inkonsistenzen zwischen `hals.md` und `concept_fusion.md`

### Gap 1: `confirm_hal_t` — Fehlende `set_ok(nonce)` Spezifikation für `libtoob`

**Problem:** `concept_fusion.md` fordert explizit, dass das Feature-OS via `libtoob` die Boot-Nonce direkt im Flash-WAL von `TENTATIVE` auf `COMMITTED` flippt. Die alte Gap-Analyse empfahl, `set_ok` aus der Bootloader-HAL zu entfernen. Die aktuelle `hals.md` hat das auch getan — `confirm_hal_t` hat nur `init()`, `check_ok()`, `clear()`. 

**Aber:** Nirgendwo im Dokument-Ökosystem ist jetzt spezifiziert, **wie** `libtoob` die Nonce physisch schreibt. `hals.md` erwähnt kein `libtoob_hal.md`, kein separates Interface-Dokument. Das OS-seitige Pendant ist ein Phantom — der Schreib-Pfad ist undokumentiert.

**Mitigation:** Entweder ein expliziter Verweis in `hals.md` Anhang auf ein noch zu erstellendes `libtoob_hal.md`, oder ein minimaler Abschnitt, der die OS-seitige Schreib-Schnittstelle als „Out of Scope, siehe `libtoob`" deklariert und die physische Adresse/Methodik (Flash-WAL Direct-Write via `ADDR_CONFIRM_RTC_RAM` oder WAL-Sektor) klar benennt.

---

### Gap 2: `confirm_hal_t.check_ok()` — Nonce-Persistenz-Mechanismus unspezifiziert

**Problem:** `check_ok(expected_nonce)` prüft, ob das OS die korrekte Nonce gesetzt hat. `concept_fusion.md` beschreibt, dass das OS die Nonce „direkt im Flash-WAL" flippt. In `hals.md` wird `confirm_hal_t` aber als RTC-RAM/Backup-Register-Abstraktion beschrieben (ESP32: RTC-FAST-MEM, STM32: Backup-Domain). 

**Widerspruch:** Ist die Nonce im WAL (Flash) oder im RTC-RAM? Beides wird in verschiedenen Stellen behauptet. Wenn die Nonce im WAL liegt, ist `confirm_hal_t` nur ein dünner Proxy auf `flash_hal_t`-Sektoren. Wenn sie im RTC-RAM liegt, verliert ein Kaltstart (Knopfzelle leer) die Nonce — und `concept_fusion.md` erwähnt explizit „MCU-Kaltstarts ohne Knopfzelle" als Anwendungsfall, für den ein „wear-leveled Flash-Sector" als Alternative dient.

**Mitigation:** `hals.md` muss in `confirm_hal_t` **eindeutig klarstellen**, dass die Implementierung plattformabhängig ist (RTC-RAM ODER Flash-Sektor), aber die **Semantik** immer gleich ist: Survive Power-Cycle. Der Abschnitt `init()` erwähnt das am Rande, aber `check_ok()` und `clear()` müssen explizit sagen: „Der Speicherort (RTC-RAM, Flash, Backup-Reg) ist Implementierungsdetail. Die HAL MUSS garantieren, dass der Wert einen vollständigen Power-Cycle überlebt."

---

### Gap 3: `soc_hal_t` — Inkonsistenter Pointer-Name (`platform->power` vs. `platform->soc`)

**Problem:** `concept_fusion.md` Schicht 1 nennt das 7. Trait korrekt `soc_hal_t`. In `boot_platform_t` steht der Pointer-Name korrekt als `*soc`. **Aber** in der Init-Dokumentation von `soc_hal_t.init()` (Zeile 577) steht:

> `Aufgerufen von: boot_main.c, als letzter Init. Nur wenn platform->power != NULL.`

Das ist ein konkreter Bug: `platform->power` existiert nicht im Struct — dort heißt es `platform->soc`. Ein Implementierer sieht `platform->soc` im Struct und `platform->power` in der Tabelle und weiß nicht, was gilt.

**Mitigation:** Alle Referenzen auf `platform->power` in `hals.md` durch `platform->soc` ersetzen. Globales Suchen-und-Ersetzen.

---

### Gap 4: `soc_hal_t` — Fehlende `deinit()` Methode

**Problem:** `concept_fusion.md` fordert ein striktes `hal_deinit()` vor dem OS-Jump. `flash_hal_t`, `crypto_hal_t` und `clock_hal_t` haben alle `deinit()`. **`soc_hal_t` hat kein `deinit()`**. 

Konsequenz: Der ADC bleibt kalibriert und aktiv, der Dummy-Load-Pin steht möglicherweise auf HIGH (zieht permanenten Strom), die Bus-Matrix ist unklar. Das Feature-OS erbt einen schmutzigen SoC-State.

**Mitigation:** `soc_hal_t` MUSS `void (*deinit)(void)` erhalten. Aufgabe: ADC abschalten, Load-Pins deaktivieren, alle GPIO-Pins, die `init()` konfiguriert hat, in High-Z zurücksetzen. Wird in der Deinit-Kette aufgerufen (als erstes, da letztes Init).

---

### Gap 5: `confirm_hal_t` — Fehlende `deinit()` Methode

**Problem:** Gleiche Logik wie Gap 4. `confirm_hal_t` hat `init()`, aber kein `deinit()`. Bei STM32 wurde in `init()` die Backup-Domain entsperrt (`PWR->CR1 |= PWR_CR1_DBP`). Ohne `deinit()` bleibt die Backup-Domain offen — ein potenzielles Sicherheitsloch, da das Feature-OS (oder ein kompromittiertes Plugin) den RTC-Wert überschreiben könnte.

**Mitigation:** `confirm_hal_t` um `void (*deinit)(void)` erweitern. Sperrt auf STM32 die Backup-Domain wieder (`PWR->CR1 &= ~PWR_CR1_DBP`). Auf ESP32 ist es ein No-Op.

---

### Gap 6: `wdt_hal_t` — Fehlende `deinit()` Methode

**Problem:** `concept_fusion.md` besagt, `hal_deinit()` räumt die Peripherie auf. In `wdt_hal_t` existiert kein `deinit()`. Auf nRF52 ist der WDT ohnehin nicht stoppbar (beabsichtigt). Auf ESP32/STM32 jedoch könnte der Bootloader einen RWDT/IWDG konfiguriert haben, den das Feature-OS mit eigenen Timeout-Werten neu konfigurieren will.

**Besonderheit:** Bei STM32 IWDG und nRF52 WDT ist ein Stoppen physisch unmöglich. Hier ist `deinit` ein No-Op. Aber bei ESP32 RWDT ist ein Rekonfigurieren möglich.

**Mitigation:** `wdt_hal_t` um `void (*deinit)(void)` erweitern mit klarer Doku: „Auf Plattformen, die den WDT nicht stoppen können (nRF52, STM32 IWDG), ist dies ein No-Op. Auf Plattformen mit konfigurierbarem WDT wird der Timer in den Default-State zurückversetzt." Das Feature-OS muss seinen eigenen WDT konfigurieren.

---

### Gap 7: `console_hal_t` — Fehlende `deinit()` Methode

**Problem:** UART-Pins bleiben nach dem OS-Jump im Alternative-Function-Mode konfiguriert. Wenn das Feature-OS dieselben Pins für einen anderen Zweck (I2C, SPI, GPIO) nutzen möchte, kollidiert die Pin-Konfiguration.

**Mitigation:** `console_hal_t` um `void (*deinit)(void)` erweitern. Aufgabe: UART-Peripheral abschalten, TX/RX-Pins auf Analog/High-Z zurücksetzen, ausstehende FIFO-Daten verwerfen.

---

## B. Sicherheits-Lücken & Krypto-Spezifikation

### Gap 8: `crypto_hal_t.read_dslc()` — Keine Spezifikation für DSLC-Länge und -Format

**Problem:** `read_dslc(uint8_t *buffer, size_t *len)` existiert, aber `hals.md` spezifiziert nicht:
- Welches Format hat der DSLC? (Raw Bytes? ASCII Hex? MAC-Adresse?)
- Welche Länge hat er? (6 Bytes MAC? 16 Bytes UUID? Chipspezifisch?)
- Wo wird er physisch gelesen? (eFuse? OTP? Flash? MAC-Register?)

`concept_fusion.md` Kap. 3 erwähnt „Device-ID Conditions" und Abfrage via `boot_hal_get_dslc()`, gibt aber ebenfalls keine konkrete Byte-Spezifikation.

**Mitigation:** `hals.md` muss bei `read_dslc()` dokumentieren:
- Maximale Länge (z.B. 32 Bytes, Buffer muss mindestens so groß sein)
- Das Format ist plattformabhängig, aber der Core behandelt es als opaken Byte-Blob
- Typische Quellen pro Plattform (ESP32: MAC eFuse, STM32: UID96, nRF: FICR DEVICEID)

---

### Gap 9: `crypto_hal_t.advance_monotonic_counter()` — Fehler-Semantik unspezifiziert

**Problem:** Die Funktion existiert, aber es ist nicht dokumentiert:
- Was passiert, wenn alle eFuses gebrannt sind (Counter-Overflow)?
- Gibt sie einen Fehlercode zurück? (Aktuell: `boot_status_t`, aber welcher?)
- Ist die Operation atomar? (Ein Stromausfall zwischen zwei eFuse-Writes?)

`concept_fusion.md` fordert, dass der Counter in „verschleißfester Persistenzschicht" liegt. eFuses sind per Definition One-Time-Programmable — ein Overflow ist real.

**Mitigation:** Spezifikation ergänzen:
- `BOOT_ERR_FLASH` bei Hardware-Fehler, **neuer Code `BOOT_ERR_COUNTER_EXHAUSTED`** wenn keine eFuse-Bits mehr verfügbar (oder Mapping auf `BOOT_ERR_STATE`)
- Expliziter Hinweis: „Der Core muss den aktuellen Counter-Wert vor dem Advance lesen und gegen die maximale Kapazität prüfen. Ein erschöpfter Counter MUSS das Gerät in den Serial-Rescue-Only-Modus zwingen."
- Atomizität: eFuse-Burns sind inherent atomar (einmal gebrannt = permanent). Kein Stromausfall-Risiko. Das muss explizit gesagt werden.

---

### Gap 10: `crypto_hal_t` — Fehlender Public-Key-Access (OTP)

**Problem:** `concept_fusion.md` Kap. 3 beschreibt „Key-Index Rotation via OTP-eFuses" und dass der Public Key „im Bootloader-Binary eingebrannt oder aus OTP geladen" wird. `verify_ed25519` akzeptiert einen `pubkey`-Pointer, aber es gibt **keine HAL-Methode**, um den Key aus OTP/eFuse zu lesen. Der Core muss irgendwie die Adresse des eingebrannten Keys kennen.

**Mitigation:** Zwei Optionen:
1. Der Key ist als Build-Time-Konstante im Binary (→ `chip_config.h` Makro `BOOT_ED25519_PUBKEY`). Dann muss `hals.md` das explizit sagen.
2. Oder es braucht `boot_status_t (*read_pubkey)(uint8_t key[32], uint8_t key_index)` in `crypto_hal_t` für OTP-basierte Key-Rotation.

Aktuell ist beides nicht spezifiziert. Der Implementierer weiß nicht, woher der Key kommt.

---

### Gap 11: `crypto_hal_t.hash_init()` — `ctx_size` vs. `crypto_arena` Widerspruch im Text

**Problem:** `hals.md` beschreibt bei `hash_init`:  
> "Der Context-Pointer `ctx` wird vom Bootloader garantiert aus seiner statischen `crypto_arena` übergeben"

Gleichzeitig steht in der Parameterbeschreibung:
> "`ctx`: Pointer auf Stack-Buffer"

Das Wort „Stack-Buffer" ist ein Überbleibsel der alten Version und widerspricht direkt der `crypto_arena`-Regel. Ein Implementierer, der „Stack-Buffer" liest, wird den Context auf dem Stack allokieren — was bei PQC/SHA-512 den 14KB-Stack sprengt.

**Mitigation:** Text bereinigen: „Stack-Buffer" restlos durch „statische `crypto_arena`" oder „caller-provided arena buffer" ersetzen.

---

### Gap 12: `crypto_hal_t` — Nomenklatur `rng` vs. `random`

**Problem:** `concept_fusion.md` Schicht 1 listet die `crypto_hal_t` Methoden als `(hash · verify_ed25519 · rng)`. In `hals.md` heißt die Funktion `random()`, nicht `rng()`. Ein Reviewer, der in `hals.md` nach „rng" sucht, findet nichts.

**Mitigation:** Entweder `concept_fusion.md` auf `random` updaten oder `hals.md` auf `rng` umbenennen. Konsistenz ist wichtiger als der konkrete Name.

---

## C. Hardware-Edge-Cases & Verhaltens-Lücken

### Gap 13: `flash_hal_t.write()` — Erase-Vorabprüfung Performance-Spezifikation fehlt

**Problem:** Die aktuelle `hals.md` fordert korrekterweise einen Blank-Check vor jedem Write (`BOOT_ERR_FLASH_NOT_ERASED`). Aber es fehlt eine Performance-Abschätzung: Bei einem 4KB Write auf ESP32 SPI-Flash bedeutet das, vorher 4KB zu lesen und auf `0xFF` zu prüfen. Das verdoppelt die I/O-Last.

`concept_fusion.md` sagt explizit „als 32-Bit Alignment-Schritt" — das muss in `hals.md` exakt so stehen.

**Mitigation:** Die Spezifikation sollte klarstellen:
- Der Blank-Check ist ein **32-Bit-Aligned Word-Check** (nicht byte-weise), um die Prüfung 4x schneller zu machen
- Auf Chips mit Hardware-ECC (STM32L4+) kann der Controller selbst einen Fehler melden → Blank-Check entfällt
- Die 32-Bit Anforderung aus `concept_fusion.md` übernehmen

---

### Gap 14: `flash_hal_t.deinit()` — Verhalten undokumentiert

**Problem:** `flash_hal_t` hat `deinit()` als Funktionspointer, aber **keinerlei Dokumentation** (keinen eigenen Block mit Tabelle: Aufgabe, Aufgerufen von, Rückgabe, etc.).

**Mitigation:** Vollständiger Dokumentationsblock:
- **Aufgabe:** Flash-Controller herunterfahren. SPI-Bus deaktivieren (ESP32), Flash-Clocks abschalten (STM32), NVMC sperren (nRF).
- **Aufgerufen von:** `boot_main.c`, in umgekehrter Init-Reihenfolge vor OS-Jump.
- **Sicherheitsregel:** Alle ausstehenden Writes müssen abgeschlossen sein. `deinit()` während eines aktiven Erase ist undefiniert.
- **Sandbox:** `munmap()` + Datei schließen.

---

### Gap 15: `crypto_hal_t.deinit()` — Verhalten undokumentiert

**Problem:** `crypto_hal_t.deinit()` existiert im Struct, hat keinen Dokumentationsblock.

**Mitigation:** Dokumentationsblock:
- **Aufgabe:** HW-Crypto-Engine abschalten. **Kritisch:** Zeroize der `crypto_arena` (Memset zu 0), um Key-Material-Residuen aus dem SRAM zu tilgen bevor das OS bootet.
- **Aufgerufen von:** `boot_main.c`, nach Verify-Phase, vor OS-Jump.
- **Sandbox:** No-Op (Software-Crypto hat keinen persistenten Hardware-State).

---

### Gap 16: `clock_hal_t.deinit()` — Verhalten undokumentiert

**Problem:** `clock_hal_t` hat `deinit()` im Struct aber keine Doku.

**Mitigation:** Dokumentationsblock:
- **Aufgabe:** SysTick/Timer stoppen. Interrupt-Handler (falls SysTick IRQ genutzt) deregistrieren.
- **Aufgerufen von:** `boot_main.c`, als letztes `deinit()` (da Clock als erstes initialisiert wurde).
- **Besonderheit:** CPU-Frequenz wird NICHT geändert. Das Feature-OS erbt die vom `startup.c` gesetzte Clock-Konfiguration.

---

### Gap 17: `wdt_hal_t.suspend_for_critical_section()` — Keine Reentrancy-Regel

**Problem:** Was passiert bei verschachtelten Aufrufen? Core-Modul A ruft `suspend()`, dann ruft Modul B vor Modul-A's `resume()` ebenfalls `suspend()`. Beim ersten `resume()` wird der WDT reaktiviert, obwohl Modul A noch in seiner Critical Section ist.

**Mitigation:** Die Spezifikation muss explizit sagen: **Nicht reentrant.** Der Core garantiert, dass `suspend/resume` niemals verschachtelt aufgerufen wird. Die HAL muss kein Counting implementieren. Ein Verstoß ist ein Programmier-Fehler im Core.

---

### Gap 18: `wdt_hal_t.init()` — Hardware-Quantisierung des Timeouts fehlt

**Problem:** `concept_fusion.md` fordert explizit: „MUSS diesen T-Max-Wert strikt auf die **nächstmögliche physikalische Hardware-Treppenstufe** aufrunden". In `hals.md` steht nur, dass `timeout_ms` übergeben wird und `BOOT_ERR_INVALID_ARG` kommt wenn er „außerhalb des HW-Bereichs" liegt.

**Offen:** Wer rundet auf — der Manifest-Compiler oder die `wdt_hal_t.init()`? Wenn der Compiler aufrundet, warum kann `init()` noch fehlschlagen?

**Mitigation:** Explizit in `hals.md`: „`init()` rundet `timeout_ms` intern auf das nächsthöhere Hardware-kompatible Intervall auf. Der tatsächlich konfigurierte Timeout kann höher als der angeforderte sein, ist aber niemals niedriger. Der Manifest-Compiler liefert bereits einen auf die Zielarchitektur abgestimmten Vorschlag, die HAL validiert final."

---

### Gap 19: `soc_hal_t.enter_low_power()` — Wakeup-Quelle und Dauer unspezifiziert

**Problem:** `hals.md` beschreibt: „Die Funktion kehrt erst zurück wenn das Gerät aufwacht (WDT-Timeout oder externer Interrupt)." Aber welcher Interrupt? GPIO? Timer? RTC-Alarm? 

`concept_fusion.md` beschreibt den Exponential-Backoff-Timer (1h, 4h, 12h, 24h). Wer konfiguriert diesen Timer? Die HAL-Funktion akzeptiert keinen `duration`-Parameter.

**Mitigation:** Zwei Optionen:
1. `enter_low_power()` bekommt einen `uint32_t wakeup_s` Parameter, damit der Core den Backoff-Timer übergeben kann.
2. Die Funktion nutzt den WDT als Wakeup-Source (WDT-Timeout = Backoff-Dauer). Dann muss der Core vorher `wdt.init(backoff_duration_ms)` aufrufen.

Beides muss explizit dokumentiert werden.

---

### Gap 20: `soc_hal_t.can_sustain_update()` — Undefinierter Schwellwert `min_battery_mv`

**Problem:** Die Formel `battery_level_mv() > (min_battery_mv + 200)` steht im Text. Aber `min_battery_mv` ist nirgends definiert. Wo kommt dieser Wert her? Aus `chip_config.h`? Aus einem `soc_hal_t`-Metadatenfeld?

**Mitigation:** Zwei Optionen:
1. `soc_hal_t` bekommt ein `uint32_t min_battery_mv` Metadatenfeld (analog zu `flash_hal_t.sector_size`), das der Manifest-Compiler setzt.
2. Die Formel wird entfernt und die Funktion als opake HAL-Entscheidung spezifiziert — der Core fragt nur „Kann ich updaten?", nicht „Wie viel mV hast du?". Letzteres ist architektonisch sauberer.

---

### Gap 21: `soc_hal_t.battery_level_mv()` — Dummy-Load-Mechanismus unklar

**Problem:** „Unter-Last-Messung" mit GPIO-Pin HIGH oder CPU-Last für ~50ms. Aber:
- Welcher GPIO-Pin? Aus `chip_config.h`?
- Was wenn kein Dummy-Load-Pin existiert (Boards ohne LED)?
- Die 50ms Blockade — was passiert mit dem WDT?

**Mitigation:** Klare Spezifikation:
- Dummy-Load-Pin ist HAL-intern (aus `chip_config.h` oder Board-spezifisch).
- Ohne dedizierten Load-Pin: CPU-Last-Busy-Loop als Fallback.
- 50ms << WDT-Timeout (4-5s) → kein Kick erforderlich. Explizit dokumentieren.

---

## D. Spezifikations-Ambiguitäten & fehlende Definitionen

### Gap 22: `boot_status_t` — Fehlender Error-Code für Counter-Exhaustion

**Problem:** (Siehe Gap 9). Wenn der monotone eFuse-Counter erschöpft ist, gibt es keinen passenden Error-Code. `BOOT_ERR_STATE` ist semantisch falsch (kein Zustandsfehler). `BOOT_ERR_FLASH` passt nicht (kein Flash).

**Mitigation:** Neuen Code `BOOT_ERR_COUNTER_EXHAUSTED` oder dokumentieren, dass `BOOT_ERR_NOT_SUPPORTED` semantisch korrekt ist (Counter kann nicht mehr advanced werden = Operation nicht mehr unterstützt).

---

### Gap 23: `flash_hal_t.set_otfdec_mode()` — Keine Dokumentation

**Problem:** Die Methode existiert im Struct, hat keinen eigenen Dokumentationsblock.

**Mitigation:** Vollständiger Block:
- **Aufgabe:** OTFDEC/XIP-Crypto ein-/ausschalten.
- **Aufgerufen von:** `boot_verify.c` (disable vor Hash), `boot_main.c` (enable vor OS-Jump).
- **Parameter:** `false` → Ciphertext-Reads. `true` → Plaintext/XIP-Reads.
- **Rückgabe:** `BOOT_OK`. `BOOT_ERR_NOT_SUPPORTED` ohne OTFDEC-Hardware.

---

### Gap 24: `flash_hal_t.get_last_vendor_error()` — Keine Dokumentation

**Problem:** Funktionspointer existiert im Struct, kein eigener Block.

**Mitigation:** Dokumentationsblock:
- **Aufgabe:** Plattformspezifisches Error-Register auslesen.
- **Aufgerufen von:** `boot_diag.c` nach fehlendem Flash-Aufruf.
- **Rückgabe:** 32-Bit Vendor-Code. 0 = kein Fehler.
- **Seiteneffekt:** Read-only, keine Löschung des Registers.

---

### Gap 25: Init-Reihenfolge — `soc.assert_secondary_cores_reset()` Timing-Problem

**Problem:** Init-Reihenfolge: `soc.init()` ist Schritt ⑦ (letzter), aber `concept_fusion.md` fordert Secondary-Cores **VOR** Flash-Operationen im Reset. Flash-Init ist Schritt ②. Zwischen ② und ⑦ kann ein aktiver Secondary-Core den Shared-Bus stören.

**Mitigation:** `assert_secondary_cores_reset()` aus `soc.init()` herauslösen und als eigenständigen, extrem frühen Aufruf in `boot_platform_init()` platzieren (vor allen HAL-Inits). Bus-Sanitization gehört ins Chip-Startup, nicht in die HAL-Init-Kette. Init-Diagramm entsprechend anpassen.

---

### Gap 26: `console_hal_t.getchar()` — Rückgabetyp-Inkonsistenz

**Problem:** Signatur gibt `int` zurück. Doku sagt: `-1 (bzw. BOOT_ERR_AGAIN)`. Aber `BOOT_ERR_AGAIN` existiert weder im `boot_status_t` Enum, noch ist `getchar()` vom Typ `boot_status_t`.

**Mitigation:** Klarstellen: Werte 0-255 = empfangene Bytes. `-1` = kein Byte. `BOOT_ERR_AGAIN` als Verweis entfernen oder formal als `#define BOOT_UART_NO_DATA (-1)` definieren. Keine Vermischung mit `boot_status_t`.

---

### Gap 27: `boot_platform_t` — Fehlende Deinit-Orchestrierung

**Problem:** `concept_fusion.md` fordert `hal_deinit()` vor dem OS-Jump. Individuelle `deinit()`-Methoden existieren (teilweise), aber `boot_platform_t` hat keine Deinit-Funktion und kein Deinit-Diagramm.

**Mitigation:** Ein `void boot_platform_deinit(const boot_platform_t *platform)` Prototyp im Anhang mit Deinit-Reihenfolge:
```
⑦ soc.deinit()      ← Zuerst (letztes Init)
⑥ console.deinit()
⑤ confirm.deinit()
④ crypto.deinit()    ← Zeroize crypto_arena!
③ wdt.deinit()       ← No-Op auf nRF52
② flash.deinit()
① clock.deinit()     ← Zuletzt (erstes Init)
```

---

## E. Undokumentierte Funktionen

### Gap 28: `crypto_hal_t.read_dslc()` — Kein Dokumentationsblock

**Problem:** Funktionspointer existiert, keine Tabelle.

**Mitigation:** Block:
- **Aufgabe:** Device Specific Lock Code aus eFuse/OTP lesen.
- **Parameter:** `buffer` min. 32 Bytes, `len` In/Out.
- **Aufgerufen von:** Serial Rescue, SUIT-Parser (Device-ID Condition).
- **Rückgabe:** `BOOT_OK`, `BOOT_ERR_NOT_SUPPORTED`.

---

### Gap 29: `crypto_hal_t.read_monotonic_counter()` — Kein Dokumentationsblock

**Problem:** Funktionspointer existiert, keine Tabelle.

**Mitigation:** Block:
- **Aufgabe:** Aktuellen Anti-Replay-Counter aus OTP/eFuse lesen.
- **Aufgerufen von:** Serial Rescue (Timestamp-Validierung).
- **Rückgabe:** `BOOT_OK`, `BOOT_ERR_NOT_SUPPORTED`.

---

### Gap 30: `crypto_hal_t.advance_monotonic_counter()` — Kein Dokumentationsblock

**Problem:** Funktionspointer existiert, keine Tabelle.

**Mitigation:** Block:
- **Aufgabe:** Counter irreversibel inkrementieren (eFuse brennen).
- **Aufgerufen von:** Serial Rescue, nach erfolgreicher Token-Validierung.
- **Atomizität:** eFuse-Burns inherent atomar.
- **Rückgabe:** `BOOT_OK`, `BOOT_ERR_NOT_SUPPORTED`, Counter-Exhaustion (siehe Gap 22).

---

### Gap 31: `crypto_hal_t.get_last_vendor_error()` — Kein Dokumentationsblock

**Problem:** Analog zu `flash_hal_t.get_last_vendor_error()` — existiert im Struct, undokumentiert.

**Mitigation:** Identische Semantik wie Flash-Pendant: 32-Bit Vendor-Error-Code, 0 bei keinem Fehler.

---

## F. Konzeptionelle Unstimmigkeiten

### Gap 32: `boot_hal_get_dslc()` vs. `crypto_hal_t.read_dslc()`

**Problem:** `concept_fusion.md` Kap. 3 referenziert `boot_hal_get_dslc()` als freie Funktion. `hals.md` hat es als `platform->crypto->read_dslc()`. Ein Implementierer sucht nach `boot_hal_get_dslc` und findet nichts.

**Mitigation:** `concept_fusion.md` auf die korrekte API-Referenz updaten oder `hals.md` definiert einen Wrapper-Makro.

---

### Gap 33: Zwei verschiedene Exponential-Backoff-Mechanismen undifferenziert

**Problem:** Es gibt zwei Backoff-Typen:
1. **Brownout-Backoff** (ms-Delays zwischen WAL-Replays) → `clock.delay_ms()`
2. **Edge-Recovery-Backoff** (Stunden-Schlafphasen) → `soc.enter_low_power()`

Beide heißen im Text „Exponential Backoff" mit völlig unterschiedlichen Zeitskalen und HAL-Methoden.

**Mitigation:** In `soc_hal_t.enter_low_power()` explizit sagen: „Für Multi-Stunden Edge-Recovery-Backoff. **Nicht** zu verwechseln mit dem kurzzeitigen Brownout-Backoff (`clock.delay_ms()`)."

---

### Gap 34: `verify_pqc()` — NULL-Pointer-Guard unspezifiziert

**Problem:** `verify_pqc` „ist standardmäßig NULL". Rückgabe-Doku sagt `BOOT_ERR_NOT_SUPPORTED` wenn NULL. Aber **wer** fängt den NULL-Pointer ab? Ruft der Core blind `verify_pqc(...)` auf und crasht, oder prüft er vorher `supports_pqc`?

**Mitigation:** Explizit: „Der Core MUSS vor dem Aufruf `platform->crypto->supports_pqc` prüfen. Aufruf bei `supports_pqc == false` ist undefiniertes Verhalten. Das Metadatenfeld ist der Gate-Guard — nicht der Funktionspointer."

---

### Gap 35: `flash_hal_t` — `sector_size` Feld-Name verschleiert Semantik

**Problem:** Es gibt `uint32_t sector_size` (Metadatenfeld) UND `get_sector_size(uint32_t addr)` (Funktion). Das Feld heißt nicht `max_sector_size`, was die Semantik verschleiert. Auf uniformen Chips (ESP32 4KB) sind beide identisch — das maskiert das Problem. Auf STM32F4 (16-128KB gemischt) divergieren sie.

**Mitigation:** Feld in `max_sector_size` umbenennen. Kommentar: „Nur für Swap-Buffer-Dimensionierung. Für konkrete Adressen MUSS `get_sector_size(addr)` verwendet werden."

---

## Zusammenfassung

| Kategorie | Gaps | Schweregrad |
|---|---|---|
| Fehlende `deinit()` Hooks | 4, 5, 6, 7 | **Hoch** (Peripherie-Vergiftung) |
| Undokumentierte Funktionen | 14, 15, 16, 23, 24, 28-31 | **Mittel** (Implementierbarkeit) |
| Nomenklatur-Inkonsistenzen | 3, 12, 26, 32 | **Mittel** (Verwirrung) |
| Sicherheits-Lücken | 8, 9, 10, 34 | **Hoch** (Crypto/Key-Management) |
| Architektur-Timing | 19, 25 | **Hoch** (Bus-Deadlocks) |
| Spezifikations-Ambiguitäten | 1, 2, 11, 17, 18, 20, 21 | **Mittel** |
| Effizienz/Wartbarkeit | 13, 27, 33, 35 | **Niedrig-Mittel** |
| Konzeptionelle Widersprüche | 22, 34 | **Mittel** |

**Gesamt: 35 Gaps identifiziert.**
