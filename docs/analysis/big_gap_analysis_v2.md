# Toob-Boot Gap Analysis

> Systematische Analyse aller Architektur-Dokumente auf logische Lücken, Sicherheitsrisiken, Effizienzprobleme, Wartbarkeitsdefizite und DX-Schwächen. Jeder Gap enthält eine klare Problembeschreibung und die empfohlene Mitigation.

---

## Gap 1: Stage 0 → Stage 1 Jump hat keine Adress-Validierung

**Problem:** Stage 0 liest den `Boot_Pointer` (TMR-geschützt) und springt direkt zu Bank A oder B. Es wird nie geprüft, ob der Zielpointer tatsächlich in einen gültigen Flash-Adressbereich zeigt. Wenn alle drei TMR-Kopien durch einen gemeinsamen Fehler (z.B. ECC-Failure im gleichen Power-Rail) korrumpiert werden und der Majority-Vote ein konsistentes aber falsches Ergebnis liefert, springt Stage 0 in den Nirgendwo-Speicher. Da Stage 0 immutable ist, wäre das Gerät permanent gebrickt.

**Mitigation:** Stage 0 muss vor dem Jump eine Bounds-Validierung durchführen: Der Zielpointer muss innerhalb des bekannten Flash-Bereichs liegen (`S1A_BASE <= ptr <= S1B_END`). Zusätzlich sollte Stage 0 einen rudimentären Magic-Header-Check (z.B. 4 Byte Magic + CRC-16 über die ersten 64 Bytes von Stage 1) ausführen, bevor es den Jump wagt. Diese Adressen und Magics können zur Compile-Zeit als Konstanten in Stage 0 eingebrannt werden.

---

## Gap 2: Stage 0 Footprint-Budget für Ed25519 ist unrealistisch dokumentiert

**Problem:** Das Dokument gibt `ed25519-sw` mit ~8-12 KB C-Code an, aber Stage 0 soll in ~4-8 KB passen. Das heißt: Wählt ein Nutzer `stage0.verify_mode = ed25519-sw`, passt Stage 0 physisch nicht in den vorgesehenen Slot. Die Dokumentation lässt das als wählbare Option stehen, ohne die Implikation auf die Partition-Größe zu klären.

**Mitigation:** Der Manifest-Compiler muss bei `stage0.verify_mode = ed25519-sw` automatisch den S0-Slot auf mindestens 16 KB vergrößern und den Preflight-Report explizit warnen: _"Stage 0 slot enlarged to 16 KB due to SW-Ed25519. S1 slots shift accordingly."_ Die `device.toml` Dokumentation muss die realen Footprint-Kosten pro Verify-Mode tabellarisch darstellen.

---

## Gap 3: RTC-RAM Nonce hat keine Integrität bei Kaltstart ohne Batterie

**Problem:** Die 64-Bit Boot-Nonce wird im RTC-RAM gespeichert. Viele MCU-Boards (insbesondere kostengünstige IoT-Designs) haben keine RTC-Backup-Batterie (Knopfzelle). Bei einem vollständigen Power-Cycle verliert das RTC-RAM seinen Inhalt. Die Architektur erwähnt zwar `confirm_hal_t` als Abstraktion für verschiedene Storage-Backends, aber das `concept_fusion.md` referenziert an mehreren Stellen explizit "RTC-RAM" als primäres Medium für transiente Flags.

**Mitigation:** Die Dokumentation muss klarer kommunizieren, dass die `confirm_hal_t` Implementierung auf Plattformen ohne RTC-Backup-Batterie zwingend einen wear-leveled Flash-Sektor oder ein Backup-Register nutzen MUSS. Der Preflight-Report sollte warnen, wenn `device.toml` den `confirm_backend = rtc_ram` setzt, aber keine Backup-Batterie im Hardware-Profil deklariert ist. Idealerweise wird ein neues `device.toml` Feld `rtc_battery_backed = true|false` eingeführt.

---

## Gap 4: WAL-Sliding-Window Sektor-Rotation hat kein definiertes Discovery-Protokoll nach Factory-Reset

**Problem:** Das WAL nutzt ein Sliding Window über 4-8 rotierende Sektoren mit Sequence-Countern für O(1) Discovery. Aber: Was passiert beim allerersten Boot nach dem Factory-Flash? Alle WAL-Sektoren sind `0xFF` (erased). Kein Sequence-Counter existiert. Die Architektur definiert nicht, wie Stage 1 den initialen WAL-Sektor auswählt und den ersten Sequence-Counter schreibt. Ein naiver `for`-Loop über alle Sektoren auf der Suche nach dem höchsten Counter würde bei jungfräulichem Flash `0xFFFFFFFF` als höchsten Wert interpretieren.

**Mitigation:** Stage 1 muss den Sequence-Counter mit einem validierenden Magic-Prefix versehen (z.B. `0xBEEF` + `uint16_t seq`). Beim Boot scannt Stage 1 alle WAL-Sektoren: Findet es keinen validen Magic, initialisiert es deterministisch den physisch ersten WAL-Sektor mit `seq = 1`. Dieser Factory-Init-Pfad muss als expliziter State `WAL_STATE_VIRGIN` in der State-Machine existieren und in den SIL-Tests abgedeckt werden.

---

## Gap 5: Kein Schutz gegen "Replay of Old Valid Firmware"

**Problem:** Die hybride SVN (WAL-basierte Minor-Inkremente + eFuse-Epoch für kritische CVEs) schützt gegen Downgrades unterhalb der aktuellen Epoch. Aber innerhalb einer Epoch kann ein Angreifer theoretisch ein älteres, signiertes Image (z.B. v2.3.1 statt v2.5.0) replaying, solange dessen SVN ≥ aktuelle WAL-SVN ist. Das ist ein klassischer Replay-Angriff: Angreifer flasht eine alte verwundbare Version, die noch über dem Epoch-Minimum liegt, aber einen bekannten Exploit hat.

**Mitigation:** Die WAL-basierte SVN muss strikt monoton steigend sein — nicht nur ≥ Epoch-Minimum, sondern > letzte erfolgreich bestätigte SVN. Stage 1 muss den letzten bestätigten SVN-Wert in einem TMR-geschützten Persistent-Feld speichern und gegen den neuen Manifest-SVN prüfen: `manifest.svn > persisted_svn`. Der Manifest-Compiler muss SVN-Werte automatisch inkrementieren und Builds mit gleichem SVN verweigern.

---

## Gap 6: `libtoob` API hat keine Fehlerbehandlung für WAL-Write-Failures

**Problem:** `toob_set_next_update()` "hängt einen WAL-Eintrag an". Was passiert, wenn der WAL-Sektor voll ist, der Flash-Write fehlschlägt, oder der WAL-Ring gerade eine Rotation durchläuft? Die API gibt `0x55AA55AA` bei Erfolg zurück, aber es fehlt jede Dokumentation über Fehlercodes, Retry-Semantik und Thread-Safety (falls das OS multi-threaded ist).

**Mitigation:** Die `libtoob` API muss explizite Fehlercodes definieren:

- `TOOB_ERR_WAL_FULL` (WAL-Ring voll, braucht GC)
- `TOOB_ERR_FLASH_WRITE` (Hardware-Fehler)
- `TOOB_ERR_BUSY` (WAL-Rotation in Progress)
- `TOOB_ERR_INVALID_MANIFEST` (Manifest an gegebener Adresse hat keinen validen Header)

Die Dokumentation muss klarstellen, dass `toob_set_next_update()` **nicht** thread-safe ist und von einem einzigen OTA-Thread aufgerufen werden muss. Ein Mutex-Wrapper (`toob_lock()` / `toob_unlock()`) sollte als optionaler Adapter bereitgestellt werden.

---

## Gap 7: `toob_confirm_boot()` Timing-Window ist undefiniert

**Problem:** Das OS muss `toob_confirm_boot()` aufrufen, "sobald alle kritischen Services hochgefahren sind". Aber wann genau? Was ist der WDT-Timeout? Wenn der WDT-Timeout 5 Sekunden beträgt und das OS 8 Sekunden zum Booten braucht, kommt es nie zum Confirm und jedes Update wird gerollbackt. Die Architektur legt den WDT-Timeout im Manifest-Compiler fest (basierend auf Flash-Erase-Zeiten), nicht auf Basis der OS-Boot-Dauer.

**Mitigation:** Zwei Maßnahmen:

1. Das `device.toml` muss ein Feld `os_boot_timeout_s` haben, das den maximalen WDT-Timeout für die Post-Update-Phase separat definiert. Stage 1 muss den WDT-Timeout vor dem OS-Jump auf diesen höheren Wert umkonfigurieren (oder der OS-Startup-Code muss als erstes den WDT kicken/rekonfigurieren).
2. `libtoob` sollte eine Funktion `toob_heartbeat()` exportieren, die der OS-Startup-Code periodisch aufrufen kann, um den WDT während der Boot-Phase am Leben zu halten, bevor der finale Confirm kommt. Dies muss explizit in der `getting_started.md` dokumentiert werden.

---

## Gap 8: Merkle-Verifikation nutzt eine flache Hash-Liste, keinen echten Merkle-Tree

**Problem:** Das `merkle_spec.md` beschreibt ein Array von Chunk-Hashes (`chunk_hashes[i]`), nicht einen hierarchischen Merkle-Tree. Bei einem echten Merkle-Tree kann man O(log n) Hashes verifizieren, um einen einzelnen Chunk zu validieren. Mit einer flachen Liste muss das gesamte Hash-Array im Manifest signiert und ins RAM geladen werden. Bei einem 4 MB Image mit 4 KB Chunks sind das 1024 Hashes × 32 Bytes = 32 KB nur für die Hash-Liste — auf einer MCU mit 64 KB SRAM ist das die Hälfte des verfügbaren RAMs.

**Mitigation:** Zwei Optionen:

- **Option A (Pragmatisch):** Streame die Hash-Liste chunk-weise aus dem Flash (die Hash-Liste liegt im Manifest im Staging-Slot). Lade nur den jeweils benötigten Hash für den aktuellen Chunk. Das reduziert den RAM-Bedarf auf 32 Bytes + Chunk-Size. Die Integrität der Hash-Liste ist durch die Manifest-Envelope-Signatur transitiv geschützt.
- **Option B (Voller Merkle-Tree):** Implementiere einen echten Merkle-Tree, der nur den Root-Hash im Manifest speichert und die Intermediate-Hashes streaming berechnet. Dies erfordert `tree_depth × 32` Bytes RAM (typisch 320 Bytes für 1024 Chunks).

Die aktuelle Dokumentation suggeriert Option B durch den Namen "Merkle-Tree", implementiert aber de facto Option A (flache Liste). Die Benennung und SRAM-Berechnung (`tree_depth * 32` in der `concept_fusion.md`) müssen konsistent gemacht werden.

---

## Gap 9: Delta-Patching "Forward-Only" Constraint ist inkompatibel mit manchen Diff-Algorithmen

**Problem:** Die Architektur fordert strikt "Forward-Only und Non-Overlapping" für den Delta-Patcher. `detools` (das referenzierte Tool) verwendet intern bsdiff, das Copy-Befehle mit beliebigen Source-Offsets generieren kann — also auch rückwärts springende Reads. Das widerspricht dem Forward-Only Constraint direkt.

**Mitigation:** Entweder muss ein Custom-Delta-Format verwendet werden, das Forward-Only garantiert (z.B. ein vdiff/VCDIFF-Derivat mit monoton steigenden Source-Offsets), oder das `toob-sign` Host-Tool muss den generierten Diff post-validieren: Wenn ein Patch rückwärts springende Source-Reads enthält, wird er verworfen und stattdessen ein Full-Image bereitgestellt. Diese Validierung muss als Preflight-Check im Signing-Tool existieren, nicht erst auf der MCU.

---

## Gap 10: `getting_started.md` Beispielcode ist falsch und irreführend

**Problem:** Der Beispielcode in `getting_started.md` zeigt:

```c
download_os_to_flash(SLOT_B_ADDR);
toob_set_next_update(SLOT_B_ADDR);
reboot();
```

Das suggeriert, das OS schreibt direkt in "Slot B". Die Architektur hat aber keinen expliziten Slot B für das App-Image — es gibt App Slot A + Staging. Das OS soll das neue Image in den **Staging-Bereich** schreiben, nicht in einen "Slot B". Der Beispielcode kontradiziert die Flash-Layout-Architektur in `concept_fusion.md`.

**Mitigation:** Der Beispielcode muss korrigiert werden:

```c
download_os_to_staging(STAGING_ADDR);
toob_set_next_update(STAGING_MANIFEST_ADDR);
reboot();
```

Zusätzlich muss die `libtoob` API ein `toob_get_staging_addr()` exportieren, damit das OS die korrekte Staging-Adresse dynamisch abfragen kann, statt Magic-Konstanten zu verwenden.

---

## Gap 11: Keine Versionierung des `.noinit` Shared-RAM ABI

**Problem:** Die `toob_handoff_t` Struktur wird über `.noinit` RAM zwischen Bootloader und OS geteilt. Wenn sich das Struct-Layout in einer neuen Bootloader-Version ändert (z.B. neues Feld hinzugefügt), interpretiert ein älteres OS die neuen Felder als Garbage — oder schlimmer, das Magic `0x55AA55AA` liegt nun an einem falschen Offset, und das OS erkennt den Handoff nicht.

**Mitigation:** Die `toob_handoff_t` Struktur muss ein `uint16_t struct_version` Feld nach dem Magic enthalten. Die `libtoob` Bibliothek prüft die Version und degradiert graceful: Unbekannte Felder werden ignoriert, fehlende Felder erhalten Safe-Defaults. Die Struct-Version muss in `chip_config.h` als `TOOB_HANDOFF_ABI_VERSION` definiert und vom Manifest-Compiler generiert werden.

---

## Gap 12: Serial Rescue nutzt XMODEM + COBS, aber XMODEM hat eigenes Framing

**Problem:** Die `stage_1_5_spec.md` sagt: "XMODEM-CRC Protokoll, jedoch streng über COBS eingepackt." XMODEM hat aber sein eigenes Paket-Framing (SOH, 128-Byte Blocks, CRC-16). COBS über XMODEM ist eine doppelte Framing-Schicht, die Komplexität und Overhead erzeugt, ohne klaren Nutzen — XMODEM hat bereits eingebaute Fehlererkennung.

**Mitigation:** Entscheide dich für ein Protokoll:

- **Option A (Empfohlen):** COBS + eigenes Chunk-Protokoll (1 KB Chunks, CRC-32, ACK/NAK). XMODEM komplett streichen. Das ist einfacher, passt zum Ping-Pong Flow-Control, und vermeidet die Legacy-Quirks von XMODEM (128-Byte fixed blocks, NAK-basiertes Starten).
- **Option B:** XMODEM-1K direkt über UART ohne COBS. Nur für den Auth-Token-Transfer COBS verwenden (da der Token < 128 Bytes ist und nicht in XMODEMs Block-Schema passt).

Die aktuelle Spezifikation ist widersprüchlich und muss konsolidiert werden.

---

## Gap 13: Kein Timeout für den gesamten Update-Prozess

**Problem:** Die Architektur definiert granulare Timeouts (WDT für einzelne Operationen, Exponential Backoff für Crashes), aber keinen globalen Timeout für den gesamten Update-Transaktionsprozess. Wenn ein LoRa-Gerät über Wochen hinweg einzelne Chunks empfängt und dabei immer wieder Stromausfälle hat, bleibt die WAL-Transaktion ewig offen. Ein ewig offener `TXN_BEGIN` ohne `TXN_COMMIT` blockiert die State-Machine und verhindert eventuell neue Updates.

**Mitigation:** Das SUIT-Manifest muss ein `update_deadline` Feld enthalten (z.B. UNIX-Timestamp oder relative Dauer in Stunden). Stage 1 prüft bei jedem Boot, ob eine offene Transaktion abgelaufen ist. Wenn ja, wird die Transaktion automatisch via `TXN_ROLLBACK` verworfen und die Chunk-Bitmap gelöscht. Das OS kann dann ein frisches Update initiieren.

---

## Gap 14: `can_sustain_update()` ist ein einmaliger Check, aber Batterie ist dynamisch

**Problem:** `can_sustain_update()` wird einmal VOR dem Update geprüft. Aber bei batteriebetriebenen Geräten kann die Spannung während des Updates drastisch fallen (besonders bei großen Images mit vielen Flash-Erases). Der interleaved `battery_level_mv()` Poll ist zwar erwähnt, aber die Entscheidungslogik ("wann genau abbrechen?") ist nicht definiert. Was ist der Schwellwert während des Updates? Wie verhält sich das System, wenn die Batterie während eines Sector-Erase unter den Threshold fällt?

**Mitigation:** Definiere zwei Battery-Thresholds:

1. `min_battery_start_mv`: Minimum zum Starten eines Updates (höher, z.B. 3500 mV).
2. `min_battery_abort_mv`: Minimum während des Updates (niedriger, z.B. 3200 mV). Unter diesem Wert bricht Stage 1 sofort ab.

Die Abort-Logik muss im Core-Modul `boot_energy.c` als State-Machine definiert werden: `ENERGY_OK → ENERGY_WARNING → ENERGY_ABORT`. Bei `ENERGY_ABORT` wird kein neuer Sector-Erase gestartet, aber der aktuelle Write-Zyklus wird sauber beendet und das WAL-Journal korrekt geschlossen. Die Thresholds müssen im `device.toml` konfigurierbar sein.

---

## Gap 15: ECC-HardFault-Handler ist nur als Anforderung beschrieben, nicht spezifiziert

**Problem:** Das `hals.md` fordert einen `HardFault_Handler` in `startup.c` für ECC-NMI, aber definiert weder die Signatur, noch das Verhalten, noch wie er mit dem Rest der Architektur interagiert. Insbesondere: Wie unterscheidet der Handler einen ECC-Fehler von einem echten Code-Bug? Wie wird der ECC-Fehlerort (welcher Flash-Sektor?) an die Diagnostik weitergegeben?

**Mitigation:** Spezifiziere den Handler explizit:

```c
void HardFault_Handler(void) {
    if (is_ecc_nmi()) {
        uint32_t fault_addr = get_ecc_fault_address();
        persist_fault_info_to_noinit(fault_addr, FAULT_ECC);
        trigger_wdt_reset(); // Erzwinge sauberen Neustart
    }
    // Für andere Faults: Endlosschleife (WDT greift)
    while(1);
}
```

Die `fault_addr` muss über `.noinit` RAM an Stage 1 beim nächsten Boot übergeben werden, damit Diagnostik den betroffenen Sektor identifizieren kann. Dieses Verhalten muss als Pflicht-Bestandteil jeder HAL-Portierung dokumentiert werden, inklusive plattformspezifischer Register für ECC-Fault-Erkennung.

---

## Gap 16: `toob_get_boot_logs()` gibt einen rohen char-Buffer zurück — kein strukturiertes Format

**Problem:** Die `libtoob` API `toob_get_boot_logs(char* buffer, size_t max_len)` gibt einen rohen Text-Buffer zurück. Für ein OS, das Telemetrie an ein Cloud-Backend senden will, ist ein unstrukturierter String nutzlos — es müsste geparsed werden, was fragile Regex-Logik auf der MCU erfordern würde.

**Mitigation:** Definiere eine strukturierte `toob_boot_diag_t` Struktur:

```c
typedef struct {
    uint32_t boot_time_ms;
    uint32_t verify_time_ms;
    uint32_t last_error_code;
    uint32_t vendor_error;
    uint8_t  active_key_index;
    uint16_t svn;
    uint16_t failure_count;
    uint8_t  sbom_digest[32];
} toob_boot_diag_t;

boot_status_t toob_get_boot_diag(toob_boot_diag_t *out);
```

Der rohe char-basierte Logger kann als optionale Debug-Funktion bestehen bleiben, aber die primäre API für OTA-Agents muss strukturiert sein.

---

## Gap 17: Recovery-OS SVN-Isolation kann zu einer Abwärts-Spirale führen

**Problem:** Das Recovery-OS hat einen isolierten `SVN_recovery` Counter. Wenn das Recovery-OS selbst ein Update benötigt (z.B. Sicherheitspatch), aber das Feature-OS bereits gebrickt ist, gibt es keinen definierten Pfad, um das Recovery-OS über die Serial Rescue Schnittstelle zu aktualisieren. Die Serial Rescue (Schicht 4a) scheint nur für das Feature-OS gedacht zu sein, nicht für das Recovery-OS.

**Mitigation:** Die Serial Rescue Stage muss explizit einen `--target` Parameter im Auth-Token unterstützen, der bestimmt, welcher Flash-Slot beschrieben wird: `app`, `recovery`, oder `stage1b`. Das Auth-Token-Format muss um ein `target_slot` Byte erweitert werden, das vom HQ zusammen mit dem Timestamp signiert wird. Stage 1 validiert, dass der angeforderte Slot existiert und flasht entsprechend.

---

## Gap 18: Multi-Image Atomic Update hat kein Partial-Rollback Recovery

**Problem:** Bei Multi-Core SoCs (nRF5340) erzwingt die Architektur "Lock-Step": Wenn ein Sub-Image bricht, rollen ALLE zurück. Aber: Was passiert, wenn der Rollback selbst fehlschlägt? Beispiel: Radio-Core Image wird erfolgreich zurückgerollt, aber der Main-Core Rollback scheitert wegen eines Flash-Errors. Jetzt hat man ein inkonsistentes System mit alter Radio-FW und halb-gerollbackter Main-FW.

**Mitigation:** Der Rollback-Prozess muss selbst transaktional sein. Das WAL-Journal muss den Rollback als eigene Transaktion führen: `TXN_ROLLBACK_BEGIN → ROLLBACK_IMAGE_0 → ROLLBACK_IMAGE_1 → TXN_ROLLBACK_COMMIT`. Scheitert ein Rollback-Schritt, bleibt die Rollback-Transaktion offen und wird beim nächsten Boot replayed (identisch zum Forward-Update-Crash-Recovery). Erst wenn alle Images zurückgerollt sind, wird committed.

---

## Gap 19: `flash_hal_t.write()` Blank-Check ist auf großen Sektoren extrem langsam

**Problem:** Die HAL-Spezifikation fordert, dass `write()` vor dem Schreiben prüft, ob der Zielbereich auf `erased_value` steht (Blank-Check). Bei einem 128 KB Sektor (STM32H7) und einem Write von 4 KB muss die HAL 4096 Bytes lesen und wortweise vergleichen. Das ist O(n) und addiert bei jedem Write signifikant zur Latenz — besonders auf SPI-Flash, wo jeder Read-Byte ~1 µs kostet.

**Mitigation:** Zwei Ebenen:

1. **Opt-in Bypass:** Führe ein `FLASH_WRITE_FLAG_SKIP_BLANK_CHECK` Flag ein, das der Core setzen darf, wenn er selbst garantieren kann, dass er vorher einen `erase_sector()` ausgeführt hat (was der WAL-basierte Ablauf immer tut). Der defensive Blank-Check bleibt als Default für unbekannte Aufrufer.
2. **Hardware-ECC Delegation:** Auf Chips mit Hardware-ECC (STM32L4+, STM32U5) meldet der Flash-Controller selbst einen Fehler bei Write-auf-nicht-gelöscht. Die HAL-Implementierung auf diesen Chips kann den Software-Blank-Check komplett überspringen und sich auf den Hardware-Error verlassen.

---

## Gap 20: `console_hal_t.putchar()` mit WDT-Kicking erzeugt zirkuläre Abhängigkeit

**Problem:** Die Spezifikation fordert, dass `putchar()` intern `wdt->kick()` aufruft, um bei langem Logging den Watchdog am Leben zu halten. Aber die Console-HAL wird NACH der WDT-HAL initialisiert. Wenn `putchar()` den WDT kicken soll, muss die Console-HAL einen Pointer auf die WDT-HAL halten. Das erzeugt eine Cross-HAL-Abhängigkeit, die in der aktuellen Architektur (jede HAL ist ein isoliertes Struct) nicht vorgesehen ist.

**Mitigation:** Statt `putchar()` den WDT kicken zu lassen, sollte der **Core** (der beide HALs kennt) den WDT zwischen Log-Ausgaben kicken. Die `boot_diag.c` Logging-Funktion wickelt größere Outputs in eine Schleife:

```c
for (size_t i = 0; i < log_len; i++) {
    platform->console->putchar(log_buf[i]);
    if (i % 256 == 0) platform->wdt->kick();
}
```

Die `putchar()` WDT-Kick-Anforderung muss aus der HAL-Spezifikation entfernt werden.

---

## Gap 21: Keine Angriffsvektor-Analyse für `toob_handoff_t` in `.noinit` RAM

**Problem:** Die `.noinit` Shared-RAM Sektion überlebt Resets. Ein kompromittiertes OS könnte vor einem absichtlichen Crash die `toob_handoff_t` Struktur manipulieren (z.B. `boot_failure_count = 0` setzen), um Rollbacks zu unterdrücken. Der Magic + CRC-16 Schutz verhindert nur versehentliche Korruption, nicht gezielte Manipulation.

**Mitigation:** Die `.noinit` Daten, die Stage 1 **schreibt** und das OS **liest**, sind unkritisch (informativ). Aber die Richtung OS → Stage 1 (z.B. `toob_confirm_boot()` oder `toob_set_next_update()`) muss zwingend über den WAL-Flash-Pfad gehen (wie aktuell geplant), **nicht** über `.noinit` RAM. Die Architektur muss explizit klarstellen: `.noinit` ist ein **unidirektionaler** Kanal von Stage 1 → OS. Jede Rückkommunikation geht über das Flash-WAL (das vom Bootloader beim nächsten Boot validiert wird). Ein Satz in der Spezifikation reicht hier.

---

## Gap 22: `delay_ms()` ist eine Busy-Wait — kein WDT-Kicking intern

**Problem:** Die Spezifikation sagt, dass der Core den WDT während langer `delay_ms()`-Aufrufe kicken muss. Aber das ist eine implizite Verantwortung, die leicht vergessen wird. Wenn ein Entwickler in einem neuen Core-Modul `platform->clock->delay_ms(3000)` aufruft und den WDT nicht kickt, löst der Watchdog aus.

**Mitigation:** Erstelle eine Core-Helper-Funktion `boot_delay_with_wdt(uint32_t ms)`, die intern den Delay in kleinere Intervalle aufteilt und den WDT kickt:

```c
void boot_delay_with_wdt(const boot_platform_t *p, uint32_t ms) {
    uint32_t chunk = p->wdt ? (wdt_timeout_ms / 3) : ms;
    while (ms > 0) {
        uint32_t d = (ms < chunk) ? ms : chunk;
        p->clock->delay_ms(d);
        if (p->wdt) p->wdt->kick();
        ms -= d;
    }
}
```

Verbiete den direkten Aufruf von `clock->delay_ms()` im Core per Coding-Guideline und erzwinge es via Static-Analyse-Regel.

---

## Gap 23: Provisioning Guide definiert keinen Rollback-Pfad für fehlgeschlagenes eFuse-Burning

**Problem:** Wenn das eFuse-Burning (Public Key, DSLC, RDP) teilweise fehlschlägt (z.B. Key halb eingebrannt, RDP aber schon aktiv), ist der Chip in einem undefinierten Zustand: JTAG gesperrt, aber der Key unbrauchbar. Das Gerät ist vor Verlassen der Fabrik gebrickt.

**Mitigation:** Der Provisioning-Prozess muss eine strikte Reihenfolge mit Verifikation einhalten:

1. **Burn Key → Verify Key Readback → Burn DSLC → Verify DSLC Readback** (bei jedem Schritt: Abbruch bei Mismatch, Chip als Ausschuss markieren)
2. **RDP/JTAG-Lock als LETZTER Schritt** (erst wenn alle anderen eFuses verifiziert sind)
3. Die Factory-Line-Software muss für jeden Chip ein individuelles Provisioning-Log in die Fleet-Management-DB schreiben, bevor RDP gesetzt wird.

---

## Gap 24: Testing Requirements decken keine Multi-Image (nRF5340) Szenarien ab

**Problem:** Die `testing_requirements.md` definiert SIL/HIL Tests für Single-Image Szenarien (WAL-Rollback, Bit-Rot, Exponential Backoff). Multi-Core Atomic Updates (nRF5340 App + Network Core) werden nicht als Test-Szenario erwähnt. Gerade die Lock-Step Logik und der Stage-1.5 Boot-Agent sind extrem fehleranfällig und brauchen dedizierte Tests.

**Mitigation:** Ergänze folgende Pflicht-Szenarien:

- Multi-Image Update: Stromausfall nach Radio-Core Flash, vor Main-Core Flash → Verify, dass der vollständige Rollback auf BEIDE Cores erfolgt.
- Stage-1.5 IPC-Bridge: Simuliere einen hängenden Radio-Core, der die Versions-Vorgabe nicht bestätigt → Verify Timeout-Handling.
- Asymmetrische Busse: Teste den Fall, dass der Main-Core den Radio-Core-Bus physisch nicht erreichen kann → Verify Stage-1.5 Agent Delegation.

---

## Gap 25: `crypto_hal_t.deinit()` Zeroization hat keine Verifikation

**Problem:** Die Spezifikation fordert `memset(crypto_arena, 0, size)` zum Löschen von Key-Material. Aber Compiler optimieren `memset` auf null-gesetzten Speicher aggressiv weg, wenn der Buffer danach nicht mehr gelesen wird (Dead-Store Elimination). Ein Standard-`memset` ist keine sichere Zeroization.

**Mitigation:** Verwende explizit `memset_s()` (C11 Annex K) oder eine volatile-basierte sichere Löschfunktion:

```c
static void secure_zeroize(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}
```

Diese Funktion muss als `boot_secure_zeroize()` in den Core-Utilities bereitgestellt und in der HAL-Spezifikation als Pflicht-Implementation referenziert werden. Der CI-Pipeline muss ein Binary-Audit-Schritt hinzugefügt werden, der verifiziert, dass die Zeroization im kompilierten Binary tatsächlich existiert (z.B. via `objdump` Pattern-Match).

---

## Gap 26: Kein definiertes Verhalten bei `get_sector_size()` auf variablen Sektoren im Swap-Algorithmus

**Problem:** STM32F4 hat gemischte Sektoren (16 KB, 64 KB, 128 KB). Der Swap-Algorithmus muss Sektoren zwischen App Slot und Swap-Buffer kopieren. Wenn der App-Sektor 128 KB groß ist, aber der Swap-Buffer nur einen 128 KB Sektor hat, passt genau ein Sektor. Aber was passiert beim Swap eines 16 KB Sektors? Der 128 KB Swap-Buffer wird benutzt, aber es werden nur 16 KB beschrieben. Die restlichen 112 KB sind "verschwendet" (nicht relevant), aber beim nächsten Swap muss der gesamte 128 KB Swap-Buffer erst gelöscht werden — inklusive der ungenutzten 112 KB. Das verlangsamt den Swap-Prozess auf gemischten Sektoren erheblich.

**Mitigation:** Der Swap-Algorithmus muss sektorgrößen-bewusst arbeiten: Beim Swap eines 16 KB App-Sektors wird nur die Menge `min(app_sector_size, swap_buffer_size)` kopiert. Der Erase des Swap-Buffers kann nur einmal pro Nutzungszyklus stattfinden, da NOR-Flash nur ganze Sektoren löschen kann. Das bedeutet: Der Swap-Buffer wird am Anfang jeder Transaktion einmal gelöscht, nicht vor jedem Sektor-Swap. Das WAL muss den Swap-Buffer-Zustand tracken (`SWAP_BUFFER_CLEAN` vs. `SWAP_BUFFER_DIRTY`).

---

## Gap 27: Key-Index Rotation via OTP-eFuses hat kein Limit-Handling

**Problem:** Stage 0 nutzt Key-Index Rotation via OTP-eFuses, um Root-Key-Bricks zu vermeiden. eFuses sind physisch begrenzt (typisch 2-8 Key-Slots). Wenn alle Key-Slots aufgebraucht sind, kann kein weiterer Key rotiert werden. Die Architektur definiert nicht, was passiert, wenn der letzte Key-Slot erreicht ist.

**Mitigation:** Der Manifest-Compiler muss die Anzahl verfügbarer Key-Slots kennen (aus `device.toml` oder `aggregated_scan.json`). Wenn nur noch ein Key-Slot verfügbar ist, muss der Preflight-Report eine **dringende Warnung** ausgeben. Der Fleet-Manager muss informiert werden (via Diagnostik-Telemetrie), dass das Gerät seine Key-Rotation-Kapazität erschöpft. Wenn der letzte Slot aktiv ist, muss die Dokumentation klar kommunizieren: Eine weitere Key-Kompromittierung erfordert physischen Gerätewechsel.

---

## Gap 28: `stage_1_5_spec.md` definiert Recovery-Pin Debouncing, aber nicht Pull-up/Pull-down

**Problem:** Der Recovery-Pin muss 500 ms auf High/GND gehalten werden. Aber: Was ist der Default-Zustand des Pins? Wenn kein externer Pull-up/Pull-down beschaltet ist, floated der Pin und kann durch EMI-Noise fälschlicherweise die Serial Rescue triggern. Auf einem IoT-Gerät in industrieller Umgebung kann das regelmäßig passieren.

**Mitigation:** Die HAL-Spezifikation muss zwingend vorschreiben: Der Recovery-Pin MUSS mit einem internen Pull-Up (für Active-Low) oder Pull-Down (für Active-High) konfiguriert werden. Die Empfehlung: Active-Low mit internem Pull-Up ist der sichere Default (der Pin muss aktiv gegen GND gezogen werden, um Recovery zu triggern — Floating löst nie aus). Der `device.toml` Eintrag `recovery_pin_active = low` sollte als Default gesetzt werden, und der Preflight-Report warnt, wenn `active = high` ohne externen Pull-Down konfiguriert ist.

---

## Gap 29: WAL CRC-16 ist zu schwach für Datenintegrität in rauen Umgebungen

**Problem:** CRC-16 hat eine Hamming-Distanz von 4 für Daten bis ca. 4 KB. Für WAL-Entries, die kritische Zustände wie `Current_Primary_Slot` oder `Boot_Failure_Counter` schützen, ist CRC-16 bei industriellen EMI-Umgebungen potenziell unzureichend. Zwei gleichzeitige Bit-Flips in den richtigen Positionen können eine CRC-16-Kollision erzeugen.

**Mitigation:** Für die TMR-geschützten kritischen Felder (`Current_Primary_Slot`, `Boot_Failure_Counter`, WAL-Sector-Base-Pointer) ist CRC-16 plus TMR ausreichend, da TMR die Redundanz liefert und CRC-16 nur die Einzelkopie-Integrität prüft. Für reguläre WAL-Entries (die nicht TMR-geschützt sind) sollte zumindest ein CRC-32 in Betracht gezogen werden — der Overhead von 2 zusätzlichen Bytes pro Entry ist auf modernen MCUs vernachlässigbar und verdoppelt die Erkennungsfähigkeit.

---

## Gap 30: Kein definierter Mechanismus für "Feature-Flags" im Bootloader

**Problem:** Die Architektur beschreibt viele optionale Features (PQC, Multi-Core, Recovery-OS, Energy-Guard, Serial Rescue). Aber es gibt keinen zentralen Mechanismus, der zur Compile-Zeit festlegt, welche Features aktiv sind. Das führt zu unkontrollierbaren `#ifdef`-Ketten im C-Code — genau das, was die Architektur als "Architectural Slop" vermeiden will.

**Mitigation:** Der Manifest-Compiler muss eine `boot_features.h` generieren, die alle Feature-Toggles als saubere `#define`-Konstanten enthält:

```c
#define BOOT_FEATURE_PQC_HYBRID        0
#define BOOT_FEATURE_MULTI_IMAGE        1
#define BOOT_FEATURE_RECOVERY_OS        1
#define BOOT_FEATURE_ENERGY_GUARD       1
#define BOOT_FEATURE_SERIAL_RESCUE      0
#define BOOT_FEATURE_DELTA_PATCHING     1
```

Die Werte werden aus dem `device.toml` abgeleitet. Der C-Code nutzt diese Defines in klar abgegrenzten Modulen (nicht als verstreute `#ifdef`s im Core-Code, sondern als Compile-Unit-Selektion: Modul wird kompiliert oder nicht).

---

## Gap 31: `getting_started.md` erwähnt kein Signing-Workflow-Detail

**Problem:** Schritt 5 ("Deployment / Signing") sagt nur: "musst du es per `toob-sign` verpacken und im SUIT-Format signieren". Kein Beispiel-Kommando, keine Erklärung, wo der Private Key herkommt, kein Workflow für CI/CD-Integration. Für einen Entwickler, der gerade seinen ersten Toob-Boot Prototyp baut, ist das eine Sackgasse.

**Mitigation:** Ergänze ein minimales Signing-Beispiel:

```bash
# Erzeuge Schlüsselpaar (einmalig)
toob-keygen --output keys/

# Signiere das OS-Image
toob-sign --image build/feature_os.bin \
          --key keys/private.ed25519 \
          --svn 42 \
          --output build/feature_os.suit

# Optional: Delta-Patch erzeugen
toob-sign --delta --base build/feature_os_v41.bin \
          --image build/feature_os.bin \
          --key keys/private.ed25519 \
          --output build/feature_os_delta.suit
```

Zusätzlich: Dokumentiere den CI/CD-Pfad (Private Key in HSM/Vault, nicht im Repo).

---

## Gap 32: `SBOM Digest` Logging erfüllt CRA nur symbolisch

**Problem:** Die Architektur loggt den `sbom_digest` (SHA-256 der SBOM) in `boot_diag`. Aber der CRA fordert mehr als nur einen Hash: Er fordert die tatsächliche SBOM-Verfügbarkeit, Vulnerability-Disclosure-Prozesse und aktive Update-Pflichten. Das Logging eines Hashes im Bootloader ist ein nützliches Integrity-Feature, aber kein CRA-Compliance-Nachweis per se. Die Dokumentation übertreibt mit "CRA Compliance 2027 out-of-the-box."

**Mitigation:** Korrigiere die Formulierung: "Der `sbom_digest` im Manifest ermöglicht die **Verifikation der SBOM-Integrität** auf Gerätebene, was ein Baustein der CRA-Compliance ist. Vollständige CRA-Konformität erfordert zusätzlich: SBOM-Bereitstellung über das Fleet-Management-Backend, dokumentierte Vulnerability-Disclosure-Prozesse und nachweisliche Update-Fähigkeit."

---

## Gap 33: `clock_hal_t.init()` Reihenfolge vs. `startup.c` Clock-Setup

**Problem:** Die Spezifikation sagt: `clock_hal.init()` ist der ERSTE HAL-Aufruf. Aber gleichzeitig: "Bei STM32 muss der `startup.c` die Clocks konfiguriert haben BEVOR `clock_hal.init()` aufgerufen wird." Das heißt, die tatsächliche Clock-Konfiguration (PLL-Setup, HSE-Aktivierung) passiert VOR der HAL-Init — in `startup.c`. Die `clock_hal.init()` konfiguriert nur den SysTick-Timer. Dieser Unterschied ist verwirrend und führt zu Porting-Fehlern.

**Mitigation:** Benenne die Funktionen klarer: `clock_hal.init()` → dokumentiere explizit: "Konfiguriert den Tick-Timer. Setzt NICHT die System-Clocks auf — dies geschieht in der plattformspezifischen `startup.c` und ist abgeschlossen, bevor `boot_platform_init()` aufgerufen wird." Alternativ: Führe eine separate `clock_hal.configure_system_clocks()` ein, die in `startup.c` aufgerufen wird und den PLL/HSE-Setup übernimmt. Damit ist die Verantwortlichkeit klar getrennt.

---

## Gap 34: Keine Spezifikation für Maximum-Boot-Time Budget

**Problem:** Die Architektur optimiert einzelne Operationen (Merkle-Verify, Flash-Erase), aber definiert kein Gesamtbudget für die maximale Boot-Dauer. Für IoT-Geräte, die aus dem Deep-Sleep aufwachen und sofort einen Sensor-Wert senden müssen, ist die Boot-Zeit kritisch. Ein Bootloader, der 2 Sekunden für Verify braucht, kann für manche Use-Cases inakzeptabel sein.

**Mitigation:** Definiere im `device.toml` ein optionales `max_boot_time_ms` Feld. Der Preflight-Report berechnet die erwartete Boot-Zeit basierend auf: Image-Größe × Hash-Speed (SW vs. HW) + WAL-Recovery-Overhead + Flash-Read-Latenz. Wenn die berechnete Zeit das Budget überschreitet, warnt der Report und schlägt Optimierungen vor (z.B. HW-Crypto, größere Chunks, Verify-Caching für unveränderte Images).

---

## Gap 35: `boot_platform_init()` Fallback-SOS hat keine Spezifikation

**Problem:** Der Code-Kommentar sagt: "Wenn ein PFLICHT-HAL init() fehlschlägt, muss der Bootloader atomar panicken. Nutzt z.B. Fallback_SOS_LED Toggle." Aber es gibt keine Spezifikation, wie die SOS-LED angesteuert wird (welcher Pin? Welches Blink-Pattern? Welcher Fehlercode?). Ohne UART (Console ist optional und wird zuletzt initialisiert) hat der Entwickler keine Diagnose.

**Mitigation:** Definiere einen minimalen SOS-Mechanismus als Teil der `device.toml`:

```toml
[diagnostics.sos]
led_pin = "PA5"       # GPIO Pin für SOS-LED
active_high = true
```

Der Manifest-Compiler generiert daraus einen `boot_sos_blink(uint8_t error_code)` Stub, der über Direct-Register-Access (keine HAL-Abhängigkeit) die LED per Blink-Code den Fehler signalisiert. Blink-Patterns: 1 Blink = Clock-Fail, 2 = Flash-Fail, 3 = WDT-Fail, 4 = Crypto-Fail, 5 = Confirm-Fail.

---

## Gap 36: Anti-Rollback Epoch-Change wird nur im Manifest signalisiert — kein Out-of-Band Verification

**Problem:** Ein kritischer CVE-Epoch-Change wird im SUIT-Manifest via `Required_Key_Epoch` Feld kommuniziert. Wenn ein Angreifer ein Manifest mit einer niedrigeren Epoch signiert (mit dem alten, kompromittierten Key), würde Stage 1 es akzeptieren — solange die SVN ≥ current SVN ist. Der Epoch-Check greift erst, wenn das neue Manifest eine HÖHERE Epoch fordert. Ein Angreifer mit dem alten Key kann also weiterhin Updates innerhalb der alten Epoch einspielen.

**Mitigation:** Der Epoch-Wechsel muss **bidirektional** sein: Sobald eine eFuse für einen neuen Epoch gebrannt wurde, muss Stage 1 ALLE Manifeste mit der alten Epoch verweigern, unabhängig davon, ob das neue Manifest dies fordert. Das heißt: Die aktive Epoch wird in den eFuses gespeichert, nicht im Manifest gelesen. Das Manifest muss die Epoch **mindestens** matchen, nicht sie definieren. Stage 1 prüft: `manifest.epoch >= burned_epoch`. Ein Manifest mit `epoch < burned_epoch` wird sofort verworfen.

---

## Gap 37: `toob_set_next_update()` schreibt direkt ins Bootloader-WAL — potenzielle Korruptionsgefahr

**Problem:** Die `libtoob` Library, die im OS-Kontext läuft, schreibt direkt in das WAL-Journal des Bootloaders (Flash-basiert). Wenn das OS während dieses Writes abstürzt (oder ein anderer Task gleichzeitig Flash-Operationen durchführt), kann das WAL korrumpiert werden. Der Bootloader beim nächsten Boot findet ein inkonsistentes Journal.

**Mitigation:** Die `libtoob` muss das WAL-Write-Protokoll des Bootloaders exakt replizieren (inklusive CRC-16 Trailer und `ABI_VERSION_MAGIC`). Die Dokumentation muss die Invarianten explizit kommunizieren:

1. Flash-Writes im WAL-Bereich dürfen nur über `libtoob` erfolgen (keine direkten Flash-Writes durch das OS in den WAL-Bereich).
2. `toob_set_next_update()` muss als atomare Operation behandelt werden — der aufrufende Code muss sicherstellen, dass kein Interrupt oder Task-Switch den Write unterbricht.
3. Als zusätzlicher Schutz sollte Stage 1 beim Boot eine WAL-Integrity-Prüfung über alle Entries durchführen und korrupte Entries verwerfen (was es bereits tut via CRC-16, aber dies muss explizit als Defense gegen OS-seitige Korruption dokumentiert werden).

---

## Gap 38: Kein Health-Monitoring für den Staging-Slot Flash-Bereich

**Problem:** Die Architektur trackt Erase-Cycles für den WAL-Bereich (Sliding Window) und den Swap-Buffer (Counter + EOL Survival Mode). Aber der Staging-Slot, in den jedes OTA-Update geschrieben wird, hat kein Wear-Monitoring. Bei Geräten, die häufige Updates erhalten (z.B. tägliche Edge-AI-Modell-Updates), könnte der Staging-Bereich schneller verschleißen als erwartet.

**Mitigation:** Erweitere den `APP_SLOT_ERASE_COUNTER` Mechanismus um einen `STAGING_SLOT_ERASE_COUNTER` im WAL. Der Fleet-Manager erhält über die Diagnostik-Telemetrie (`boot_diag`) beide Counter-Werte und kann proaktiv warnen, wenn ein Bereich sein Lifecycle-Limit erreicht. Optional: Bei Chips mit ausreichend Flash, rotiere den Staging-Bereich zwischen zwei physischen Bereichen (ähnlich WAL-Rotation), um die Wear-Last zu verteilen.

---

## Gap 39: `libtoob_api.md` definiert `toob_handoff_t` ohne Padding/Alignment-Garantie

**Problem:** Die `toob_handoff_t` Struktur enthält gemischte Typen (`uint32_t`, `uint64_t`). Je nach Compiler und Plattform kann `uint64_t boot_nonce` unterschiedlich aligned werden. Wenn Bootloader und OS mit verschiedenen Compiler-Flags kompiliert werden (oder verschiedene Compiler verwenden), kann das Struct-Layout divergieren, und die Nonce wird an der falschen Adresse gelesen.

**Mitigation:** Das Struct muss `__attribute__((packed))` verwenden ODER explizite Padding-Felder definieren:

```c
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t struct_version;   // (siehe Gap 11)
    uint32_t active_slot;
    uint32_t _reserved_pad;    // Explizites Padding für 8-Byte Alignment
    uint64_t boot_nonce;
    uint32_t reset_reason;
    uint32_t boot_failure_count;
} toob_handoff_t;
_Static_assert(sizeof(toob_handoff_t) == 32, "ABI size check");
```

Der `_Static_assert` stellt sicher, dass das Layout über Compiler-Grenzen hinweg konsistent bleibt.

---

## Gap 40: Toobfuzzer-Ergebnisse sind zur Build-Zeit fixiert — Runtime-Varianz bleibt unberücksichtigt

**Problem:** Der Toobfuzzer ermittelt Flash-Timings (z.B. `max_erase_time_us`) auf einem spezifischen Eval-Board unter Laborbedingungen. In Produktion variieren Flash-Timings je nach Temperatur (bis zu 2x langsamer bei -40°C), Alterung (Erase-Zeiten steigen mit Wear) und Fertigungs-Varianz (Charge-to-Charge). Die statisch eingebrannten Werte in `chip_config.h` können in der Praxis zu kurz sein.

**Mitigation:** Der Manifest-Compiler muss einen konfigurierbaren `timing_safety_factor` auf alle Fuzzer-ermittelten Zeiten anwenden (Default: 2.0x). Zusätzlich sollte der WDT-Timeout nicht nur auf `max_erase_time + 2x_Marge` basieren, sondern auf `max_erase_time × timing_safety_factor + absolute_margin`. Die Dokumentation muss explizit warnen: "Toobfuzzer-Ergebnisse gelten für das getestete Eval-Board unter Raumbedingungen. Für Produktions-Deployments mit erweitertem Temperaturbereich muss der `timing_safety_factor` in `device.toml` erhöht werden."

---

## Gap 41: Keine Spezifikation für Bootloader-Telemetrie-Transportformat

**Problem:** Die Architektur beschreibt umfangreiche Diagnostik (Timing-IDS, CRA-Hashes, Failure-Counter, Erase-Counter). Aber das Format, in dem diese Daten vom OS an das Fleet-Management-Backend gesendet werden, ist undefiniert. Jeder Gerätehersteller müsste sein eigenes Telemetrie-Schema erfinden, was Interoperabilität zwischen Toob-Boot-basierten Flotten verhindert.

**Mitigation:** Definiere ein standardisiertes `toob_telemetry_t` CBOR-Schema (passend zur SUIT/CBOR-Philosophie), das die Diagnostik-Daten in einem kompakten, binären Format kodiert. Das Schema enthält: Boot-Timings, aktive SVN, Key-Epoch, Erase-Counter (WAL, Swap, App, Staging), Failure-Counter, letzter Error-Code, SBOM-Digest. Die `libtoob` exportiert eine `toob_serialize_telemetry(uint8_t *buf, size_t *len)` Funktion, die dieses Schema befüllt.

---

## Gap 42: Exponential Backoff bei Edge-Recovery hat keine Persistenz-Spezifikation

**Problem:** Der Exponential Backoff (1h, 4h, 12h, 24h) für den `edge_unattended_mode` muss über Deep-Sleep-Zyklen hinweg den aktuellen Backoff-Level persistieren. Die Architektur sagt, das Gerät "taucht ab" in Deep-Sleep, aber nicht, wo der aktuelle Backoff-Level gespeichert wird. Wenn er im RAM liegt, geht er beim Deep-Sleep-Wakeup verloren, und der Backoff startet bei 1h von vorne — eine endlose 1h-Schleife statt progressiver Erholung.

**Mitigation:** Der aktuelle Backoff-Level muss im WAL-Journal persistiert werden (z.B. als `BACKOFF_LEVEL` Entry: uint8_t, 0-3). Beim Boot liest Stage 1 den letzten Backoff-Level aus dem WAL, inkrementiert ihn (bis zum 24h-Cap) und schreibt den neuen Level zurück, bevor es in Deep-Sleep geht. Ein erfolgreicher Boot (Confirm-Flag gesetzt) resettet den Backoff-Level auf 0.

---

## Gap 43: `verify_ed25519` Timing-Angaben fehlen für RISC-V Targets

**Problem:** Die Timing-Tabelle in `hals.md` listet nur Cortex-M4 und Hardware-Engines (CC310, STM32U5 PKA). RISC-V MCUs (ESP32-C3/C6, GD32V) werden als Target in der Architektur unterstützt (der `chip_config.h` Beispielcode zeigt ESP32-S3), aber Timing-Referenzen für Ed25519-SW auf RISC-V fehlen komplett.

**Mitigation:** Ergänze Benchmark-Daten für RISC-V (RV32IMAC bei typischen 80-160 MHz). Monocypher Ed25519-Verify auf RISC-V RV32IM ist typischerweise ~1.5x langsamer als Cortex-M4 (wegen fehlender UMULL Instruction). Die Tabelle sollte lauten: "RISC-V RV32IM (Monocypher): ~1.100.000 Zyklen ≈ 14ms @ 80 MHz". Diese Daten sind für den Preflight-Report und die Boot-Time-Budgetierung essentiell.

---

## Gap 44: `soc_hal_t.enter_low_power()` kehrt zurück — aber der Caller erwartet möglicherweise keinen Return

**Problem:** Die Spezifikation sagt: "Die Funktion kehrt erst zurück wenn das Gerät aufwacht." Aber auf den meisten MCUs (STM32 Stop Mode, ESP32 Deep Sleep) führt ein Wakeup aus Deep Sleep zu einem **kompletten System-Reset** — die Funktion kehrt nie zurück, der Code startet von `main()` neu. Nur bei Light Sleep kehrt die Funktion tatsächlich zurück. Die Architektur behandelt beide Fälle identisch.

**Mitigation:** Dokumentiere explizit zwei Pfade:

1. **Light-Sleep / Stop-Mode:** Funktion kehrt zurück, Core macht weiter bei `boot_main`.
2. **Deep-Sleep:** Funktion kehrt nie zurück. Der nächste Boot durchläuft die komplette Init-Sequenz. Der Backoff-Level und der Crash-Kontext müssen VOR dem `enter_low_power()` Aufruf persistiert werden (WAL, nicht RAM).

Das `device.toml` muss ein Feld `low_power_mode = light_sleep | deep_sleep` haben, und der Core muss den Code-Pfad entsprechend anpassen. Bei `deep_sleep` wird vor dem Aufruf alles in den WAL geschrieben; bei `light_sleep` reicht RAM-Persistenz.

---

## Gap 45: Provisioning Guide erwähnt keinen RMA / Field-Return Prozess

**Problem:** Was passiert, wenn ein provisioniertes Gerät (JTAG gesperrt, RDP2 aktiv) zum Hersteller zurückgeschickt wird (RMA — Return Merchandise Authorization)? Der Hersteller kann das Gerät nicht mehr debuggen, weil JTAG permanent gesperrt ist. Die einzige Kommunikation ist die Serial Rescue Schnittstelle — aber wenn auch die Key-Rotation erschöpft ist oder das Auth-Token-System versagt, ist das Gerät für den Hersteller ein Black-Box-Brick.

**Mitigation:** Definiere einen RMA-Prozess:

1. Das Serial Rescue Auth-Token bekommt ein spezielles `RMA_MODE` Flag, das nach Autorisierung einen erweiterten Diagnostik-Dump über UART ausgibt (Boot-Log, WAL-Dump, Error-Counter, Flash-Health).
2. Für MCUs mit semi-reversibler Debug-Sperre (z.B. STM32 RDP1 statt RDP2): Empfehle RDP1 für Entwicklungsgeräte und RDP2 nur für finale Produktion. Dokumentiere den Trade-off explizit.
3. Der Fleet-Manager muss eine "RMA-authorized Device List" pflegen, gegen die das HQ das Auth-Token für den erweiterten Diagnostik-Modus signiert.

---

## Gap 46: `concept_fusion.md` referenziert mehrere Dateien, die nicht existieren

**Problem:** Das Dokument verlinkt auf `docs/getting_started.md`, `docs/provisioning_guide.md`, `docs/libtoob_api.md`, `docs/merkle_spec.md`, `docs/stage_1_5_spec.md`, `docs/testing_requirements.md`, `docs/hals.md`, `docs/toobfuzzer_integration.md`, `docs/blueprint.json`, `docs/aggregated_scan.json`. Von diesen existieren in den bereitgestellten Dokumenten nur Fragmente einiger. Insbesondere fehlen komplett: `toobfuzzer_integration.md`, `blueprint.json`, `aggregated_scan.json`. Das bedeutet, die Integration zwischen Toobfuzzer und Manifest-Compiler ist rein konzeptionell beschrieben, aber nicht spezifiziert.

**Mitigation:** Erstelle die fehlenden Spezifikationsdokumente, mindestens:

- `toobfuzzer_integration.md`: Schema-Definition für `blueprint.json` und `aggregated_scan.json`, Mapping-Regeln zu `chip_config.h` Makros, Versionierung des Scan-Formats.
- `blueprint.json` / `aggregated_scan.json`: JSON-Schema-Definitionen mit allen Pflichtfeldern, optionalen Feldern, Wertetypen und Validierungsregeln.

Ohne diese Dokumente kann kein Dritter den Manifest-Compiler implementieren oder einen neuen Toobfuzzer-Backend-Treiber schreiben.

---

## Gap 47: WAL `ABI_VERSION_MAGIC` Migrations-Logik ist undefiniert

**Problem:** Die Architektur sagt: "Weicht die C-Struct Größe ab (z.B. bei einem S1 v2 Update), migriert/verwirft der Bootloader die alten Payload-Daten sicher." Aber WIE? Migration von On-Flash Datenstrukturen auf einer MCU mit ≤64 KB RAM ist nicht trivial. Wenn das alte WAL-Format 8 Bytes pro Entry hatte und das neue 12 Bytes, kann Stage 1 nicht einfach alle Entries in-place konvertieren — die Sektorgrenzen verschieben sich.

**Mitigation:** Die pragmatische Lösung: Bei ABI-Mismatch werden alle offenen WAL-Transaktionen verworfen (Rollback auf bekannten guten Zustand) und das WAL wird mit dem neuen ABI-Format frisch initialisiert. Kritische Persistent-Daten (TMR-geschützte Slots, Erase-Counter, Backoff-Level) residieren NICHT im WAL-Entry-Format, sondern in fixen, format-unabhängigen Speicherpositionen. Die Dokumentation muss diese Trennung explizit machen: "WAL-Entries sind transient und dürfen bei ABI-Migration verloren gehen. Kritische Persistent-Daten liegen in format-stabilen TMR-Slots."

---

## Gap 48: Kein Cross-Compilation Dokumentation für den Sandbox-Modus

**Problem:** Der DX-Abschnitt erwähnt `$ boot-build --sandbox` für Host-natives Testing. Aber die Dokumentation enthält keine Anleitung, welche Toolchain, welche OS-Voraussetzungen (Linux/macOS/Windows), welche Dependencies (libc, libfuzzer, AFL++), oder welche Compiler-Flags benötigt werden. Ein neuer Entwickler kann den Sandbox-Modus nicht nutzen.

**Mitigation:** Erstelle eine `docs/sandbox_setup.md` mit:

- Unterstützte Host-Plattformen (Linux x86_64, macOS ARM64)
- Benötigte Pakete (`apt install gcc cmake libasan` / `brew install llvm`)
- Build-Kommando mit konkretem Beispiel
- Fuzz-Target Generierung (`toob build --sandbox --fuzz-targets`)
- Beispiel-Fuzzing-Session mit AFL++ oder libFuzzer
- CI-Integration (GitHub Actions / GitLab CI YAML-Snippet)

---

## Gap 49: Keine Forward-Compatibility Strategie für SUIT-Manifest-Versionen

**Problem:** Die Architektur nutzt SUIT-Manifeste (CBOR-basiert, RFC 9019). SUIT wird aktiv weiterentwickelt — neue Condition-Types, neue Directives. Wenn ein neues Manifest-Feature (z.B. ein neuer `suit-condition-*` Typ) verwendet wird, das der aktuelle Stage 1 Parser nicht kennt, ist das Verhalten undefiniert. Ignoriert er unbekannte Felder? Lehnt er das gesamte Manifest ab?

**Mitigation:** Definiere eine explizite Kompatibilitätspolitik:

- **Unbekannte Conditions:** Werden als `FAIL` evaluiert (sicherer Default — ein unbekanntes Condition könnte ein Sicherheitscheck sein).
- **Unbekannte Directives im Critical-Sequence:** Lehnen das Manifest ab.
- **Unbekannte Directives im Non-Critical-Sequence (z.B. `suit-text`):** Werden ignoriert.
- Das Manifest muss ein `min_parser_version` Feld enthalten. Stage 1 vergleicht dieses gegen seine eigene Version und verweigert Manifeste, die eine neuere Parser-Version erfordern. Dies muss im SUIT-Parser-Modul implementiert und im Testing abgedeckt werden.

---

## Gap 50: Anti-Glitch Pattern `0x55AA55AA` ist nicht robust gegen Single-Bit Glitches in der Vergleichsoperation

**Problem:** Der Rückgabewert `BOOT_OK = 0x55AA55AA` wird als "Anti-Glitch Pattern" beschrieben (AUTOSAR-kompatibel). Aber die eigentliche Schwachstelle liegt nicht im Wert, sondern in der **Branch-Instruction**, die den Wert prüft. Ein Voltage-Glitch auf die CPU kann eine `BNE` (Branch-if-Not-Equal) Instruction in eine `NOP` oder `BEQ` umwandeln, wodurch der Check unabhängig vom Returnwert bestanden wird. Das Pattern allein schützt nicht gegen Instruction-Skip Glitches.

**Mitigation:** Die Architektur erwähnt bereits ein "Core Double-Check-Pattern". Dieses muss konkret spezifiziert werden: Die Signaturprüfung muss zweimal unabhängig ausgeführt werden, und beide Ergebnisse müssen in separaten Variablen verglichen werden. Die beiden Vergleiche müssen an verschiedenen Code-Stellen stattfinden (nicht direkt hintereinander, da ein einzelner Glitch-Burst beide überspringen könnte). Zwischen den Checks sollte eine kurze, zufällige Delay-Schleife eingefügt werden (`boot_random_delay()`), um Time-of-Check Glitching zu erschweren.
