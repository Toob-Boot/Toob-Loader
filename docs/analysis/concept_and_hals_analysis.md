# Toob-Boot: Architektur Gap-Analyse

**Analysiert:** `concept_fusion.md` (Master-Konzept) & `hals.md` (HAL-Spezifikation)  
**Datum:** 2026-03-31  
**Scope:** Logik-Lücken, Sicherheits-Blindspots, Effizienz, Wartbarkeit, DX

---

## GAP-01: `crypto_arena` vs. PQC-RAM-Bedarf — Widerspruch

**Problem:** Schicht 2 verlangt ein striktes `uint8_t crypto_arena[1024]`-Budget und verbietet `malloc/free`. Gleichzeitig spezifiziert `crypto_hal_t::verify_pqc()` einen Stack-Bedarf von 10–30 KB für ML-DSA-65. Diese beiden Anforderungen sind physisch unvereinbar. Die 1024-Byte Arena reicht nicht ansatzweise für PQC-Verify, und der Stack-Verbrauch von 10–30 KB sprengt den gesamten SRAM-Footprint vieler Ziel-MCUs (z.B. nRF52 mit 64 KB RAM total).

**Mitigation:** Die `crypto_arena`-Größe muss vom Manifest-Compiler _dynamisch_ berechnet werden, basierend auf dem aktivierten Crypto-Backend. Wenn `pqc_hybrid = true` im TOML, muss die Arena auf den tatsächlichen PQC-Bedarf skaliert werden (z.B. `BOOT_CRYPTO_ARENA_SIZE = 16384`). Der Preflight-Report muss die SRAM-Gleichung dann mit diesem erhöhten Wert prüfen und den Build abbrechen, wenn der Gesamt-RAM (Merkle + WAL + Delta + Crypto-Arena) das Target übersteigt. Die `1024`-Angabe im Konzept-Dokument muss als _Minimalwert für Ed25519-only_ markiert werden, nicht als fester Wert.

---

## GAP-02: Boot-Nonce ist 32-Bit — Zu schwach

**Problem:** Die 32-Bit Boot-Nonce hat nur ~4 Milliarden mögliche Werte. Zwei Risiken: (a) Bei Geräten mit sehr häufigen Updates über 15+ Jahre Lebensdauer ist ein Wrap-Around denkbar. (b) Ein Angreifer, der das Confirm-Flag kontrolliert, kann mit ~2^31 Versuchen im Mittel eine gültige Nonce erraten (brute-force über den RTC-RAM Speicher). Da die Nonce per `crypto_hal_t::random()` erzeugt wird, ist die Entropie zwar gegeben, aber der Suchraum ist schlicht zu klein.

**Mitigation:** Nonce auf 64-Bit erweitern (`uint64_t`). Der Speicher-Overhead ist minimal (4 Bytes extra im WAL und RTC-RAM). Die `confirm_hal_t::check_ok()` Signatur ändert sich auf `bool (*check_ok)(uint64_t expected_nonce)`. 64-Bit Nonce macht Brute-Force physisch unmöglich und Wrap-Around irrelevant.

---

## GAP-03: `libtoob` WAL-Direktschreiber — Unspezifiziert & Gefährlich

**Problem:** Das Konzept beschreibt, dass das Feature-OS über `libtoob` _direkt_ im Flash-WAL von `TENTATIVE` auf `COMMITTED` flippt. Aber: (a) `libtoob` ist komplett "Out of Scope" und hat keine API-Spezifikation. (b) Wenn das OS während dieses WAL-Writes crasht, ist der WAL-Entry halb geschrieben. (c) Es gibt keine Spezifikation, wie `libtoob` den WAL-Sektor-Pointer findet (der WAL rotiert über 4–8 Sektoren mit Sliding Window). (d) Es fehlt ein ABI-Contract zwischen der `libtoob`-Version und der Stage-1-WAL-Version.

**Mitigation:**

1. `libtoob` braucht eine vollständige API-Spezifikation als separates Dokument (`docs/libtoob_api.md`).
2. Der WAL-Schreibvorgang muss atomar sein: `libtoob` schreibt eine neue WAL-Entry (Append-Only) mit Typ `CONFIRM_COMMIT`, nicht einen In-Place-Overwrite eines bestehenden Eintrags. Stage 1 interpretiert beim nächsten Boot die letzte gültige Entry.
3. Der WAL-Base-Pointer und die aktuelle ABI-Version müssen in einer fixen, bekannten Flash-Adresse (oder in der `.noinit`-Sektion) hinterlegt werden, damit `libtoob` den WAL-Ring findet.
4. Die `ABI_VERSION_MAGIC` muss _auch_ von `libtoob` geprüft werden, bevor sie schreibt.

---

## GAP-04: WAL Sliding-Window — Kein Cold-Boot-Discovery-Mechanismus

**Problem:** Der WAL rotiert über 4–8 Sektoren via Sliding Window. Nach einem Kaltstart muss Stage 1 den _aktuell aktiven_ WAL-Sektor finden. Es gibt keine Spezifikation dieses Discovery-Prozesses. Mögliche Fehler: Linearer Scan über alle Kandidaten-Sektoren ist O(n) und anfällig für Bit-Rot in den Magic-Headers.

**Mitigation:** Jeder WAL-Sektor bekommt einen monoton wachsenden 32-Bit Sequence-Counter im Header. Stage 1 scannt beim Boot alle WAL-Kandidaten-Sektoren (4–8 Reads, also O(1) de facto) und wählt den Sektor mit dem höchsten validen (CRC-geprüften) Sequence-Counter als aktiven Sektor. Der Counter wird bei jeder WAL-Rotation inkrementiert. Zusätzlich sollte ein TMR-geschützter Pointer auf den aktiven Sektor in der persistenten `Current_Primary_Slot`-Region liegen, als Fast-Path (Bypass des Scans bei korrektem CRC).

---

## GAP-05: TMR für Boot-Status — Aber nicht für WAL-Pointer und Failure-Counter

**Problem:** Das Konzept spezifiziert TMR (Triple Modular Redundancy) für den `Current_Primary_Slot` Boot-Status. Aber der `Boot_Failure_Counter` im WAL und der WAL-Sektor-Pointer selbst haben kein TMR. Ein Bit-Flip im Failure-Counter kann dazu führen, dass die Eskalation zum Recovery-OS nie triggert (Counter springt z.B. von 2 auf 66 oder von 2 auf 0). Ein Bit-Flip im WAL-Pointer verweist auf einen falschen Sektor.

**Mitigation:** Alle sicherheitskritischen, langlebigen Zustandswerte brauchen TMR oder mindestens CRC-32 Schutz:

- `Boot_Failure_Counter`: TMR (3× geschrieben, Majority-Vote beim Lesen).
- `Recovery_OS_Failure_Counter`: TMR.
- WAL Active-Sector-Pointer: TMR (falls als separater Pointer persistiert, alternativ Discovery via Sequence-Counter, siehe GAP-04).
- Alle TMR-Kopien müssen über mindestens 2 physisch getrennte Erase-Sektoren verteilt sein (wie bereits für den Boot-Status spezifiziert).

---

## GAP-06: CRC-16 für WAL-Entries und `.noinit` — Zu schwach

**Problem:** CRC-16 hat eine Kollisionswahrscheinlichkeit von 1/65536. Für Boot-Diagnostik in der `.noinit`-Sektion mag das akzeptabel sein, aber für WAL-Entries, die über Jahre in Flash liegen und unter Bit-Rot leiden, ist das Signal-to-Noise-Ratio zu niedrig. Ein einziger kosmischer Strahlen-Hit kann einen validen CRC-16 für korrumpierte Daten produzieren.

**Mitigation:** WAL-Entries auf CRC-32 upgraden (2 Bytes extra pro Entry). Der Overhead ist minimal (128-Byte WAL + 2 Bytes = vernachlässigbar). Die `.noinit`-Sektion kann bei CRC-16 bleiben, da sie flüchtig ist und nur eine Boot-Session überlebt. Im WAL-Kontext, wo Daten Monate/Jahre persistieren, ist CRC-32 der industrieübliche Mindeststandard (zlib-Polynom `0xEDB88320`). Alternativ: Das CRC-Polynom spezifizieren — aktuell steht nur "CRC-16" ohne Angabe des Polynoms (CRC-16-CCITT vs. CRC-16-IBM haben unterschiedliche Detektionseigenschaften).

---

## GAP-07: `get_sector_size(addr)` — Ambige Fehlerbehandlung

**Problem:** `get_sector_size(addr)` gibt `0` zurück wenn `addr` außerhalb des Flash liegt. Aber `0` ist ein _signalloser_ Wert — der Aufrufer kann `0` nicht von "fehlgeschlagen" vs. "Sektorgröße ist tatsächlich 0" unterscheiden (letzteres existiert in der Praxis nicht, aber der API-Vertrag ist trotzdem mehrdeutig). Der Core-Code, der `get_sector_size()` nutzt (z.B. `boot_swap.c`), muss jedes Mal manuell `if (size == 0)` prüfen, und ein vergessener Check führt zu Division-by-Zero oder Zero-Length-Erase.

**Mitigation:** Zwei Optionen:

- **Option A (Empfohlen):** Rückgabetyp auf `boot_status_t` ändern, Sektorgröße als Out-Parameter: `boot_status_t (*get_sector_size)(uint32_t addr, size_t *size_out)`. Gibt `BOOT_ERR_FLASH_BOUNDS` bei ungültiger Adresse zurück.
- **Option B:** Convention: Core-Code enthält ein `BOOT_ASSERT(sector_size > 0)` nach jedem Aufruf. Nachteil: Assertion-Handler muss im Bootloader existieren.

---

## GAP-08: `get_reset_reason()` Einmal-Aufruf-Semantik — Architektonisch nicht erzwungen

**Problem:** Die Spezifikation sagt: `get_reset_reason()` darf nur EINMAL pro Boot aufgerufen werden (weil STM32/nRF Register nach dem Lesen gelöscht werden). Der Core "cached das Ergebnis". Aber diese Einmal-Semantik wird architektonisch nicht erzwungen. Ein versehentlicher zweiter Aufruf (z.B. durch einen neuen Entwickler, der den Code erweitert) gibt auf STM32 `RESET_UNKNOWN` zurück und bricht die Auto-Rollback-Logik.

**Mitigation:** Die HAL-Implementierung selbst muss idempotent sein: Beim ersten Aufruf liest sie die Register, löscht sie, und cached das Ergebnis intern in einer `static`-Variable. Jeder weitere Aufruf gibt den gecachten Wert zurück. Der Core-Code kann dann `get_reset_reason()` beliebig oft aufrufen, ohne Seiteneffekte. Die `hals.md` Spezifikation sollte diese Idempotenz als **PFLICHT** für alle HAL-Implementierungen markieren.

---

## GAP-09: Ed25519-Verifikation — Kein Schutz gegen Fault-Injection auf Return-Wert

**Problem:** `verify_ed25519()` gibt `BOOT_OK` (numerischer Wert `0`) bei gültiger Signatur zurück. Ein einzelner Hardware-Glitch (Voltage Glitch, EM-Fault-Injection) auf den Return-Wert-Register kann `BOOT_ERR_VERIFY` auf `BOOT_OK` kippen — das ist ein Single-Point-of-Failure in der gesamten Sicherheitsarchitektur. Professionelle Angreifer nutzen diese Technik routinemäßig gegen Embedded-Bootloader.

**Mitigation:** Double-Check Pattern im Core:

```c
boot_status_t r1 = crypto->verify_ed25519(msg, len, sig, pk);
boot_status_t r2 = crypto->verify_ed25519(msg, len, sig, pk);
if (r1 != BOOT_OK || r2 != BOOT_OK || r1 != r2) {
    boot_panic("VERIFY_FAULT_DETECTED");
}
```

Zusätzlich: Der `BOOT_OK`-Enum-Wert sollte NICHT `0` sein. Setze `BOOT_OK = 0x55AA55AA` (ein alternierendes Bitmuster, das durch Single-Bit-Flips nicht aus einem Fehlerwert entstehen kann). Der Rückgabewert der Verifikation kann separat als dedizierter "verification token" implementiert werden (z.B. Rückgabe eines Hash des Inputs statt nur OK/FAIL), was Glitching exponentiell erschwert.

---

## GAP-10: `suspend_for_critical_section()` — Bricking-Risiko bei Crash

**Problem:** Wenn der Code zwischen `suspend_for_critical_section()` und `resume()` crasht (z.B. durch einen Hardware-Fehler im Flash-Controller), ist der Watchdog deaktiviert. Das Gerät hängt ewig und muss manuell resettet werden. Das widerspricht dem Kernprinzip "kein Brick ohne externen Eingriff".

**Mitigation:** `suspend_for_critical_section()` darf den WDT _niemals_ vollständig deaktivieren. Stattdessen wird der WDT-Prescaler auf den maximal möglichen Hardware-Timeout hochskaliert (z.B. von 5s auf 30s). So überlebt die HAL auch den längsten monolithischen Flash-Erase, aber ein echter Deadlock wird nach 30s trotzdem vom WDT beendet. Die `hals.md` Spezifikation sollte explizit verbieten, dass `suspend_for_critical_section()` den WDT auf 0 (= deaktiviert) setzt. Aktuell sagt sie "temporär deaktivieren _oder_ Prescaler hochskalieren" — das "deaktivieren" muss gestrichen werden.

---

## GAP-11: Flash-Write Blank-Check — O(1)-Behauptung ist falsch

**Problem:** `hals.md` spezifiziert für die Erase-Vorbedingungsprüfung einen "32-Bit Aligned Word-Check für O(1) Geschwindigkeit". Das ist algorithmisch falsch. Um zu prüfen, ob ein Speicherbereich auf `erased_value` steht, muss der gesamte Bereich gelesen werden — das ist O(n) bezüglich der Schreiblänge. "32-Bit aligned" beschleunigt den Check (4 Bytes pro Vergleich statt 1), aber ändert nicht die Komplexitätsklasse.

**Mitigation:** Korrektur der Dokumentation: "O(n/4) mit 32-Bit Word-Checks" statt "O(1)". Für Performance: Auf Chips mit Hardware-ECC (STM32L4+) kann der Blank-Check entfallen (der Flash-Controller meldet selbst Fehler). Auf Chips ohne ECC: Der Blank-Check ist obligatorisch, aber die HAL darf ihn als schnelle `memcmp` gegen einen `0xFFFFFFFF`-Vektor implementieren (SIMD-optimierbar auf Cortex-M33+).

---

## GAP-12: Delta-Patching — `heatshrink` ist kein Delta-Patcher

**Problem:** Das Konzept nennt "Micro-Dictionary Patcher wie `heatshrink`". Aber `heatshrink` ist eine reine _Kompressionsbibliothek_ (LZSS-basiert), kein Delta/Diff-Tool. Ein Delta-Patcher braucht einen Algorithmus, der Unterschiede zwischen zwei Binär-Images berechnet (z.B. `bsdiff`, `detools`, `JojoDiff`). Kompression und Delta-Patching sind fundamental verschiedene Operationen. Der Patcher muss ein Diff-Format decodieren (nicht nur dekomprimieren).

**Mitigation:** Die Architektur muss den Delta-Algorithmus explizit spezifizieren. Empfehlung: `detools` (unterstützt `heatshrink` als _Compression-Backend_ innerhalb des Delta-Formats, hat einen minimalen C-Decoder, ist Forward-Only, und ist für Embedded-Targets optimiert). Der Dokument-Text sollte korrigiert werden: "Delta-Decoder (z.B. `detools` mit `heatshrink`-Kompression)" statt "Micro-Dictionary Patcher wie `heatshrink`".

---

## GAP-13: Merkle-Tree — Keine Spezifikation der Baumstruktur

**Problem:** Der Merkle-Tree ist ein zentrales Sicherheitskonzept, aber es fehlen alle strukturellen Details: Branching-Faktor (binär? 4-ary?), Hash-Algorithmus für Zwischen-Knoten (gleicher wie Chunk-Hash?), Speicherort der Zwischen-Hashes (im Manifest? Im Staging-Slot?), Reihenfolge der Konkatenation (left‖right? Hash(chunk_index‖data)?), und maximale Baumtiefe. Ohne diese Spezifikation kann kein interoperabler Merkle-Verifier implementiert werden.

**Mitigation:** Dedizierte Spezifikation in `docs/merkle_spec.md`:

- Binärer Baum (Branching-Faktor 2).
- Chunk-Größe aus `device.toml` (Default 4096 Bytes).
- Hash: SHA-256.
- Zwischen-Knoten: `H(H_left ‖ H_right)`.
- Blätter: `H(chunk_index_u32_le ‖ chunk_data)` (Index als Domain-Separator gegen Second-Preimage-Angriffe).
- Zwischen-Hashes werden inline im SUIT-Manifest transportiert (in der `suit-payload-fetch` Sequenz).
- Maximale Tiefe: `ceil(log2(image_size / chunk_size))`.
- Die SRAM-Gleichung im Preflight muss `tree_depth * 32` Bytes für den Verifikationspfad berücksichtigen (bereits angedeutet, aber nicht formalisiert).

---

## GAP-14: Stage 0 Boot_Pointer — Single Point of Failure

**Problem:** Stage 0 wertet einen "ultimativen Hardware-`Boot_Pointer`" (OTP/Flash-Byte) aus, um Bank A oder B anzuspringen. Wenn dieses einzelne Byte durch Bit-Rot korrumpiert wird, springt Stage 0 in eine ungültige Adresse und das Gerät ist gebrickt. Kein TMR erwähnt.

**Mitigation:** Der Boot_Pointer muss TMR-geschützt sein (3 Kopien, Majority-Vote), genau wie der `Current_Primary_Slot`. Da Stage 0 in ROM/Write-Protected liegt, müssen die 3 Kopien des Pointers in einem separaten, lesbaren OTP/Flash-Bereich liegen. Alternativ: Wenn der Pointer ein OTP-eFuse ist, ist Bit-Rot weniger wahrscheinlich (eFuses sind physisch robuster als Flash-Zellen), aber ein TMR ist trotzdem Best Practice für 15+ Jahre Feldlebensdauer.

---

## GAP-15: Transfer-Bitmap — Speicherort und Persistenz unklar

**Problem:** Das WAL-Konzept erwähnt eine "Transfer-Bitmap", die den Download-Fortschritt trackt (z.B. "60% empfangen"). Es fehlt: Wo wird die Bitmap gespeichert? Im WAL selbst? In einem separaten Flash-Bereich? Wie groß ist sie? Bei 1.5 MB Image und 4 KB Chunks braucht die Bitmap 384 Bits = 48 Bytes. Ist sie Teil des WAL-Ring-Buffers oder separiert?

**Mitigation:** Die Bitmap sollte explizit als Teil des WAL-Headers spezifiziert werden. Format: Bit-Array mit 1 Bit pro Chunk (kompakt). Für 384 Chunks: 48 Bytes. Die Bitmap wird beim `TXN_BEGIN` initialisiert (alle Bits 0) und jedes Bit wird beim erfolgreichen `CHUNK_WRITE` gesetzt. Nach Power-Cycle liest Stage 1 die Bitmap und fordert nur fehlende Chunks an (Resume). Die Bitmap muss im WAL-Sektor liegen und dieselbe CRC-Prüfung durchlaufen.

---

## GAP-16: OTFDEC-Handling beim OS-Jump — Nicht spezifiziert

**Problem:** `flash_hal_t::set_otfdec_mode(false)` wird vor der Hash-Verifikation aufgerufen, damit der Bootloader den rohen Ciphertext liest. Aber das Feature-OS erwartet, dass OTFDEC _aktiv_ ist (XIP-Execution braucht transparente Entschlüsselung). Es gibt keine Spezifikation, ob und wann OTFDEC vor dem OS-Jump wieder aktiviert wird.

**Mitigation:** In der Deinit-Kaskade (`boot_main.c`) muss nach der Verify-Phase und vor dem OS-Jump explizit `set_otfdec_mode(true)` aufgerufen werden. Die `hals.md` Spezifikation muss dies als Schritt in der Deinit-Sequenz ergänzen:

```
⑤ flash.set_otfdec_mode(true)  ← Re-enable für OS XIP
⑥ flash.deinit()
```

---

## GAP-17: Keine HAL-Interface-Versionierung

**Problem:** Wenn Toob-Boot in v2 eine neue Funktion zu `flash_hal_t` hinzufügt (z.B. `get_write_latency()`), sind alle existierenden v1-HAL-Implementierungen inkompatibel. Es gibt keinen Mechanismus, um HAL-Versionen zu tracken oder Rückwärtskompatibilität zu erzwingen.

**Mitigation:** Jeder HAL-Struct bekommt ein `uint32_t version`-Feld an Position 0:

```c
typedef struct {
    uint32_t version;  /* BOOT_FLASH_HAL_V1 = 0x00010000 */
    boot_status_t (*init)(void);
    /* ... */
} flash_hal_t;
```

Der Core prüft `platform->flash->version >= BOOT_FLASH_HAL_V1` und nutzt neue Funktionen nur wenn `version >= V2`. Neue Felder werden _immer_ am Ende des Structs angefügt. Der Manifest-Compiler setzt `BOOT_HAL_VERSION` in `boot_config.h`, damit Compile-Time-Checks möglich sind.

---

## GAP-18: SVN-Hybrid (WAL + eFuse) — WAL-Rollback-Angriff

**Problem:** Zwischen zwei Epoch-Changes werden SVN-Inkremente nur im WAL gespeichert (keine eFuse gebrannt). Ein Angreifer, der physischen Zugriff hat und den WAL-Sektor löschen kann, resettet damit den virtuellen SVN auf den letzten Epoch-Wert. Er kann danach eine ältere (aber nach Epoch noch gültige) Firmware flashen — ein klassischer Downgrade-Angriff innerhalb der Epoche.

**Mitigation:** Zwei Ansätze:

1. **Härtung:** Der WAL-SVN-Counter wird nicht nur einmal, sondern redundant in 2+ physisch getrennten WAL-Sektoren geschrieben. Ein Angreifer müsste beide Sektoren synchron löschen.
2. **Risiko-Akzeptanz mit Dokumentation:** Physischer Zugriff auf das Flash ist ohnehin ein starker Angriff (Evil-Maid-Klasse). Der JTAG-Lockdown via eFuses schützt dagegen. Das verbleibende Restrisiko (SPI-Flash desoldieren und extern beschreiben) ist für die meisten IoT-Szenarien akzeptabel und muss dokumentiert werden, damit Integratoren eine informierte Entscheidung treffen.

---

## GAP-19: Recovery-OS-Update-Mechanismus — Komplett unspezifiziert

**Problem:** Das Recovery-OS liegt in einer separaten Flash-Partition und hat eine eigene `SVN_recovery`. Aber es gibt keine Spezifikation, _wie_ das Recovery-OS selbst aktualisiert wird. Kann es OTA-Updates empfangen? Durch wen? Durch das Feature-OS? Durch Stage 1? Durch Serial Rescue? Ohne Update-Mechanismus veraltet das Recovery-OS und wird selbst zum Sicherheitsrisiko.

**Mitigation:** Spezifizieren: Das Recovery-OS wird als separates Image im SUIT-Manifest transportiert (analog zu Multi-Core Sub-Images). Stage 1 flasht es in den Recovery-Slot mit derselben WAL-Transaktionssicherheit. Die `SVN_recovery` wird unabhängig inkrementiert. Das SUIT-Manifest enthält eine optionale `[images.recovery]`-Sektion. Kritische Einschränkung: Das Recovery-OS darf nie zeitgleich mit dem App-Image aktualisiert werden (ein gleichzeitiger Ausfall beider wäre ein Totalverlust). Der Manifest-Compiler muss diese Mutual-Exclusion erzwingen.

---

## GAP-20: `confirm_hal_t` — OS-seitiger Speicherort undeterministisch

**Problem:** Die HAL abstrahiert den Confirm-Speicher (RTC-RAM, Wear-Leveled Flash, Backup-Register). `libtoob` im OS muss denselben Speicherort beschreiben. Aber es gibt keinen spezifizierten Mechanismus, wie `libtoob` erfährt, _wo_ der Confirm-Wert liegt. Der Bootloader weiß es (über die HAL), aber das OS ist ein anderes Binary mit anderer Linkage.

**Mitigation:** Der Speicherort wird als `#define BOOT_CONFIRM_ADDR` in die `chip_config.h` geschrieben (vom Manifest-Compiler). `libtoob` wird gegen dieselbe `chip_config.h` kompiliert. Alternativ: Stage 1 schreibt die Confirm-Adresse als Teil des `.noinit`-Handoff-Structs in die Shared-RAM-Sektion, von wo `libtoob` sie zur Laufzeit liest.

---

## GAP-21: "Aktiv akkumulierte Netz-Suchzeit" — Persistenz über Power-Cycles

**Problem:** Das Anti-Lagerhaus-Lockout spezifiziert einen Timeout als "aktiv akkumulierte Netz-Suchzeit" (z.B. >10h reiner TCP-Retries). Aber wenn das Gerät während der Netzsuche den Strom verliert, geht der akkumulierte Zähler verloren (er liegt vermutlich im RAM). Bei Brownout-anfälligen IoT-Geräten könnte der Timer nie die 10h erreichen, weil er bei jedem Power-Cycle resettet wird.

**Mitigation:** Der akkumulierte Timer muss in Flash (z.B. im WAL) persistiert werden, in Intervallen von z.B. 15 Minuten. Der WAL-Entry hat den Typ `NET_SEARCH_ACCUM | minutes=45`. Nach jedem Power-Cycle liest Stage 1 den letzten akkumulierten Wert und addiert weiter. Achtung: Flash-Writes alle 15 Minuten über Monate hinweg erzeugen Wear — der Timer-Sektor muss Teil des WAL-Wear-Leveling-Pools sein.

---

## GAP-22: Multi-Image Atomic Rollback — Reihenfolge und Partielle Fehler

**Problem:** Bei Multi-Core Atomic Update Groups (z.B. nRF5340 App + Radio Core) spezifiziert das Konzept: "Wenn ein Sub-Image bricht, rollen ALLE assoziierten Images zurück." Aber: Was passiert, wenn Image A erfolgreich zurückgerollt wird, aber der Rollback von Image B aufgrund eines Flash-Hardware-Fehlers fehlschlägt? Das System wäre in einem inkonsistenten Zustand (alte App + neue Radio-Firmware), was genau die IPC/ABI-Crashes verursacht, die das Feature verhindern soll.

**Mitigation:** Die Rollback-Reihenfolge muss strikt definiert sein: Zuerst Sub-Images (Radio-Core), dann Main-Image (App). Die Swap-State-Machine muss für jedes Image einen separaten WAL-Zustand tracken. Wenn ein Teil-Rollback fehlschlägt (Flash-Fehler), eskaliert Stage 1 sofort zum Recovery-OS (statt ein inkonsistentes Image-Set zu booten). Der WAL muss den Zustand `ROLLBACK_PARTIAL | failed_image=netcore` loggen, damit das Recovery-OS gezielt reagieren kann.

---

## GAP-23: TRNG Seed-Qualität nach Kaltstart

**Problem:** `crypto_hal_t::random()` nutzt Hardware-TRNG. Aber viele TRNGs brauchen nach dem Kaltstart eine Einschwingzeit (ESP32: RF-Noise-Zyklus, STM32: Konditionierungs-Durchläufe). Der Boot-Nonce wird sehr früh generiert. Wenn der TRNG zu diesem Zeitpunkt noch nicht eingeschwungen ist, könnte die Nonce vorhersagbar sein.

**Mitigation:** Die `crypto_hal_t::init()` Funktion muss _garantieren_, dass der TRNG eingeschwungen ist, bevor sie `BOOT_OK` zurückgibt. Bei ESP32: Mindestens ein WiFi/BT-Radio-Noise-Zyklus (alternativ: ADC-Rauschen als Entropiequelle, was keinen Radio-Stack braucht). Die `hals.md`-Spezifikation für `init()` sollte explizit einen "TRNG health check" als Pflicht-Schritt aufnehmen (z.B. 256 Bytes generieren, auf Komprimierbarkeit prüfen → wenn komprimierbar, ist die Entropie zu gering → `BOOT_ERR_CRYPTO`).

---

## GAP-24: Secure Provisioning Flow — Nicht spezifiziert

**Problem:** Stage 0 nutzt im `hash-only`-Modus einen SHA-256 Hash von Stage 1, der in OTP liegt. Im `ed25519-sw/hw`-Modus liegt ein Public Key in OTP. Aber es gibt keine Spezifikation, wie diese Werte initial in die OTP-eFuses programmiert werden. Wer signiert den ersten Key? Wie wird der Hash berechnet und in der Fabrik eingebrannt? Ohne einen spezifizierten Provisioning-Flow ist die gesamte Root-of-Trust undefiniert.

**Mitigation:** Spezifizieren in `docs/provisioning_guide.md`:

1. `toob-keygen` generiert offline das Ed25519-Keypair.
2. Der Public Key (32 Bytes) wird in der Fabrik via JTAG/SWD in die OTP-eFuses gebrannt (vor dem JTAG-Lockdown!).
3. Der JTAG-Lockdown (RDP2 / eFuse) wird als _letzter_ Schritt in der Provisioning-Kette ausgeführt.
4. Der Provisioning-Flow ist _einmalig und irreversibel_. Die Key-Index-Rotation via eFuses dient als Failover nach dem Lockdown.

---

## GAP-25: Recovery-Pin Debouncing — EMI False-Positives

**Problem:** Der mechanische Recovery-Pin (`--rec-pin 0`) triggert sofortigen Recovery-Boot wenn er beim Start "high" ist. Aber: Auf PCBs mit schlechtem EMI-Layout kann der GPIO-Pin durch elektromagnetische Störung kurzzeitig auf High gezogen werden, was einen falschen Recovery-Boot auslöst.

**Mitigation:** Stage 1 muss den Pin _debounced_ lesen: Mindestens 3 Samples über 50ms, alle müssen "high" sein. Alternativ: Der Pin muss für eine Mindestdauer (z.B. 500ms) gehalten werden, bevor Recovery aktiviert wird. Diese Debounce-Zeit muss im `device.toml` konfigurierbar sein (`recovery_pin_hold_ms = 500`).

---

## GAP-26: SUIT-Manifest Transport — Unspezifiziert

**Problem:** Die Architektur beschreibt detailliert, wie das SUIT-Manifest geparst und verifiziert wird, aber nicht, wie es auf das Gerät gelangt. Die Schicht-Trennung (Bootloader hat keinen Netzwerk-Stack) bedeutet, dass das Feature-OS oder das Recovery-OS das Manifest empfängt und in den Staging-Slot schreibt. Aber die Schnittstelle zwischen OS-Empfang und Bootloader-Verarbeitung ist nicht definiert.

**Mitigation:** Spezifizieren: Das OS (oder Recovery-OS) empfängt das SUIT-Manifest + Payload über seinen eigenen Transport (WiFi, LoRa, BLE). Es schreibt das Manifest an den Anfang des Staging-Slots und die Payload-Chunks dahinter. Nach dem Schreiben setzt das OS ein `UPDATE_PENDING`-Flag im WAL (via `libtoob`). Beim nächsten Boot (oder sofortigem Reset) erkennt Stage 1 das Flag und beginnt die Validierung und das Flashen. Die genaue Flash-Offset-Konvention für Manifest vs. Payload im Staging-Slot muss in `docs/staging_layout.md` definiert werden.

---

## GAP-27: `get_last_vendor_error()` — Race-Condition

**Problem:** `get_last_vendor_error()` existiert in `flash_hal_t` und `crypto_hal_t`. Beide geben ein Hardware-Error-Register zurück. Aber wenn der Core nach einem Flash-Fehler weitere Flash-Operationen ausführt (z.B. WAL-Logging des Fehlers), überschreibt die zweite Operation das Error-Register. Der ursprüngliche Fehlercode geht verloren.

**Mitigation:** Die HAL muss den Vendor-Error intern cachen: Bei jedem `BOOT_ERR_*`-Return speichert die HAL den aktuellen HW-Status in einer `static uint32_t last_error`. `get_last_vendor_error()` gibt diesen gecachten Wert zurück. Der Cache wird nur durch einen _erfolgreichen_ Aufruf (der `BOOT_OK` zurückgibt) zurückgesetzt. So bleibt der erste Fehlercode erhalten, auch wenn Folgeoperationen stattfinden.

---

## GAP-28: eFuse-Kapazität für Key-Epochs — Endlich und unspezifiziert

**Problem:** Key-Revocation und Anti-Rollback-Epochs brennen eFuses. eFuses sind physisch endlich (typisch 256–1024 Bits pro Block bei ESP32, 32 Bytes bei STM32 OTP). Die Architektur spezifiziert nicht, wie viele Epochen maximal möglich sind und was passiert, wenn alle eFuses aufgebraucht sind.

**Mitigation:**

1. Der Manifest-Compiler muss die verfügbare eFuse-Kapazität des Ziel-Chips kennen (aus `blueprint.json`).
2. Der Preflight-Report muss berechnen: "Maximal N Epochen möglich" (basierend auf eFuse-Layout).
3. `crypto_hal_t::advance_monotonic_counter()` gibt `BOOT_ERR_COUNTER_EXHAUSTED` zurück — korrekt, bereits spezifiziert. Aber der Core muss dann eine sinnvolle Reaktion zeigen: Das Update wird angenommen (SVN-Check über WAL weiterhin möglich), aber kein neuer Epochenwechsel mehr gestattet. Dieser Zustand muss als `EPOCH_CAPACITY_DEPLETED` im Boot-Diag geloggt werden.
4. Fleet-Manager müssen diesen Zustand monitoren und betroffene Geräte proaktiv austauschen.

---

## GAP-29: `boot_platform_t` Struct — Initialisierung unspezifiziert

**Problem:** Die Init-Reihenfolge zeigt, wann welcher HAL initialisiert wird, aber nicht, wie der `boot_platform_t` Struct selbst bevölkert wird. Ist es ein globaler `static const`? Wird er zur Laufzeit in `boot_platform_init()` zusammengebaut? Wie werden plattformspezifische HAL-Implementierungen zur Link-Zeit ausgewählt?

**Mitigation:** Spezifizieren in `hals.md`:

```c
/* In platform/<chip>/boot_platform_<chip>.c */
static flash_hal_t   s_flash   = { .init = esp32_flash_init, ... };
static confirm_hal_t s_confirm = { .init = esp32_confirm_init, ... };
/* ... */

static const boot_platform_t s_platform = {
    .flash   = &s_flash,
    .confirm = &s_confirm,
    .crypto  = &s_crypto,
    .clock   = &s_clock,
    .wdt     = &s_wdt,
    .console = &s_console,  /* oder NULL */
    .soc     = &s_soc,      /* oder NULL */
};

const boot_platform_t *boot_platform_init(void) {
    return &s_platform;
}
```

Der Linker wählt das richtige `boot_platform_<chip>.c` über das CMake-Target. Diese Convention muss dokumentiert sein, damit HAL-Porter wissen, was sie implementieren müssen.

---

## GAP-30: SBOM-Digest — Passive Compliance statt aktive Verifikation

**Problem:** Das SUIT-Manifest enthält einen `sbom_digest` (SHA-256 der SBOM). Der Bootloader loggt diesen Hash in `boot_diag`. Aber er _verifiziert_ ihn nicht gegen die tatsächliche SBOM. Das ist passive Compliance — das Vorhandensein eines Hash-Werts beweist nicht, dass die SBOM korrekt oder vollständig ist. Ein Angreifer könnte einen beliebigen Hash injizieren.

**Mitigation:** Der `sbom_digest` ist durch die Ed25519-Signatur des SUIT-Manifests _mitgeschützt_ — wenn das Manifest signiert ist, ist auch der SBOM-Hash integritätsgesichert (der Angreifer kann ihn nicht ändern, ohne die Signatur zu brechen). Das ist tatsächlich ausreichend für CRA-Compliance, da der CRA verlangt, dass eine SBOM _existiert und dem Produkt zugeordnet_ ist, nicht dass der Bootloader sie zur Laufzeit validiert. Aber: Dies sollte im Dokument explizit klargestellt werden, damit Auditoren die Argumentationskette nachvollziehen können. Ergänzen: "Der `sbom_digest` wird transitiv durch die SUIT-Signatur geschützt. Eine Runtime-Verifikation der SBOM selbst ist für CRA nicht erforderlich."

---

## GAP-31: Exponential Backoff — Kein Maximum-Cap spezifiziert

**Problem:** Der Brownout-Backoff und der Edge-Recovery-Backoff nutzen Exponential-Backoff-Timer (1h, 4h, 12h, 24h). Aber es fehlt ein explizites Maximum. Was passiert nach der 24h-Stufe? Verdoppelt sich der Timer weiter auf 48h, 96h, 192h? Bei batteriebetriebenen IoT-Geräten könnte ein 192h-Sleep die Batterie durch RTC-Leakage vollständig entladen, bevor der nächste Boot-Versuch stattfindet.

**Mitigation:** Harter Cap bei 24h (oder konfigurierbarer `max_backoff_hours` im TOML). Nach Erreichen des Caps bleibt der Timer bei 24h und der Versuchszähler wird trotzdem inkrementiert. Nach z.B. 14 Tagen (14 Versuche bei 24h-Cap) kann Stage 1 optional in den Halt-State übergehen und nur noch auf Serial Rescue reagieren. Die maximale Backoff-Stufe muss vom Manifest-Compiler im Preflight als `MAX_BACKOFF_S` in die `boot_config.h` geschrieben werden.

---

## GAP-32: Partial eFuse Burn — Stromausfall während Epoch-Change

**Problem:** Ein Epoch-Change brennt irreversibel eine eFuse. Wenn der Strom exakt während des eFuse-Programmiervorgangs ausfällt, könnte die eFuse in einem undefinierten Zustand sein (weder vollständig 0 noch 1, sondern ein metastabiler Zwischenzustand). Auf manche Chips (ESP32) ist der eFuse-Burn per Hardware atomar, auf anderen (STM32 OTP über Flash-Emulation) nicht notwendig.

**Mitigation:** Die `hals.md` Spezifikation erwähnt korrekt: "Das Brennen einer eFuse oder OTP-Bits ist physikalisch inherent atomar." Das stimmt für echte eFuses (Single-Transistor-Blow), aber NICHT für OTP-emulierte Bereiche (z.B. STM32 Option Bytes, die über Flash-Writes emuliert werden). Die Spezifikation muss differenzieren:

- Echte eFuses: Atomar, kein WAL-Schutz nötig.
- OTP-via-Flash-Emulation: WAL-Intent MUSS vor dem Burn geschrieben werden. Beim Reboot prüft Stage 1 den Intent und wiederholt den Burn falls nötig.

---

## GAP-33: Console-HAL `putchar` Blocking — Boot-Zeit-Impact bei langem Log

**Problem:** `console_hal_t::putchar()` blockiert bis das UART-TX-Register frei ist. Bei 115200 Baud und einem 500-Zeichen Boot-Diag-JSON dauert die Ausgabe ~43ms. Bei niedrigeren Baudraten (9600 Baud, in Legacy-Systemen) steigt das auf ~520ms. In Kombination mit dem WDT kann ein langer Boot-Log den Timeout triggern, wenn der Core zwischen den UART-Writes nicht kickt.

**Mitigation:** Zwei Maßnahmen:

1. Der Core muss den WDT zwischen Log-Ausgaben kicken (z.B. `wdt->kick()` alle 100 Zeichen).
2. Die Boot-Diag-Ausgabe sollte auf maximal 256 Zeichen begrenzt werden (oder konfigurierbar via `BOOT_LOG_MAX_LEN`). Kritische Fehlermeldungen haben Priorität über informative Logs.

---

## GAP-34: `confirm_hal_t::clear()` — Keine Nonce-Diskrimination

**Problem:** `clear()` nimmt keine Parameter und löscht "das Confirm-Flag". Aber `check_ok()` prüft gegen eine spezifische `expected_nonce`. Wenn mehrere Update-Zyklen schnell aufeinander folgen (z.B. durch Test-Firmware), könnte es theoretisch zu einer Race-Condition kommen: OS A setzt Nonce 1, Stage 1 erwartet Nonce 2 (neues Update), `clear()` löscht Nonce 1, was korrekt ist — aber die Semantik ist fragil, weil `clear()` blind alles löscht.

**Mitigation:** Kein akutes Problem, da der Ablauf sequentiell ist (Stage 1 ruft `clear()` vor dem OS-Jump, danach ist der Bootloader inaktiv). Aber zur Robustheit: `clear()` sollte den Speicherort _vollständig_ auf `0x00000000` (oder `erased_value`) setzen, sodass kein Nonce-Fragment übrig bleibt. Die aktuelle Spezifikation sagt genau das. Klarstellung: Dieses Verhalten ist ausreichend, solange Stage 1 `clear()` _immer_ vor dem Jump aufruft. Diese Invariante als `ASSERT` im Core verankern.

---

## GAP-35: Manifest-Build-Pipeline — Kein E2E-Beispiel

**Problem:** Die Architektur referenziert viele generierte Artefakte (`chip_config.h`, `flash_layout.ld`, `boot_config.h`, Preflight-Report, Renode `.resc`), aber es gibt kein End-to-End-Beispiel, wie ein Entwickler von `device.toml` + `blueprint.json` zu einem fertigen, signierten, flashbaren Binary kommt. Für DX ist das der wichtigste Aspekt.

**Mitigation:** Ein `docs/getting_started.md` mit einem konkreten Durchlauf:

```bash
# 1. Hardware scannen (Toobfuzzer)
toobfuzz scan --target esp32s3 --output blueprint.json

# 2. Device-Konfiguration schreiben
vim device.toml

# 3. Manifest kompilieren (generiert alle Artefakte)
toob-manifest compile device.toml --blueprint blueprint.json

# 4. Preflight prüfen
cat build/preflight_report.txt

# 5. Cross-Compile
cmake -B build -DTARGET=esp32s3 && cmake --build build

# 6. Signieren
toob-sign build/stage1.bin --key private.pem --output stage1.signed.bin

# 7. Flashen (Initial Provisioning)
toob-flash --stage0 build/stage0.bin --stage1 stage1.signed.bin --provisioning
```

---

## GAP-36: Stage 1.5 für isolierte Sub-Cores — Null Spezifikation

**Problem:** Für Radio-Cores auf physisch isolierten Bussen (die Stage 1 nicht direkt flashen kann) wird ein "Stage 1.5 Boot-Agent" erwähnt. Dieser soll via IPC-Bridge Rollback-Befehle empfangen. Aber: Kein IPC-Protokoll spezifiziert. Keine Fehlersemantik. Kein WAL-Äquivalent für den Sub-Core. Keine Spezifikation, wo Stage 1.5 im Flash des Sub-Cores liegt. Kein eigener Confirm-Mechanismus.

**Mitigation:** Entweder:

1. Stage 1.5 vollständig spezifizieren als eigenes Mini-Dokument (`docs/stage_1_5_spec.md`): IPC-Protokoll (Shared-Memory Mailbox mit CRC-Schutz), minimales WAL (1 Sektor), eigener Confirm-Flow, Größen-Budget (<4 KB).
2. Oder: Stage 1.5 als "Out of Scope v1" markieren und in der v1-Version nur Chips unterstützen, auf denen Stage 1 alle Cores direkt flashen kann (z.B. nRF5340 über AHB).

---

## GAP-37: Sign-then-Hash vs. Hash-then-Sign — Unklar

**Problem:** `verify_ed25519()` Parameter sagen: `message` ist typisch "der SHA-256 Digest des SUIT-Manifests, also 32 Bytes". Das bedeutet Hash-then-Sign (das Manifest wird zuerst gehashed, dann wird der Hash signiert). Aber Ed25519 hasht intern nochmal (Ed25519 nutzt SHA-512 intern). Das Dokument spezifiziert nicht eindeutig, ob:

- (a) `sig = Ed25519_Sign(SHA256(manifest))` (Hash-then-Sign, der Core übergibt 32 Bytes)
- (b) `sig = Ed25519_Sign(manifest)` (Sign direkt, der Core übergibt das volle Manifest)

Variante (a) hat subtile Sicherheitsimplikationen (Collision Resistance hängt von SHA-256, nicht von Ed25519s internem SHA-512 ab).

**Mitigation:** Explizit spezifizieren: Für SUIT-Compliance wird das Manifest direkt signiert (Variante b), nicht ein Pre-Hash. SUIT definiert das Signing über den COSE_Sign1-Envelope, der den vollen Payload schützt. Wenn aus RAM-Gründen Pre-Hashing nötig ist (das volle Manifest passt nicht in den RAM), muss Ed25519ph (RFC 8032 Pre-Hash Mode) verwendet werden, nicht ein manueller SHA-256 vor Standard-Ed25519. Die `hals.md` sollte klarstellen, welcher Modus verwendet wird.

---

## GAP-38: Flash Wear-Monitoring für App-Slot — Fehlt

**Problem:** Erase-Cycle-Counter existieren für den Swap-Buffer und den WAL. Aber der App-Slot selbst wird bei jedem OTA-Update gelöscht und neu beschrieben. Bei Geräten mit täglichen Updates über 10 Jahre sind das 3650 Erase-Zyklen auf den App-Sektoren — weit unter dem Limit (typisch 10.000–100.000), aber ohne Monitoring ist das nicht nachweisbar.

**Mitigation:** Der WAL sollte einen `APP_SLOT_ERASE_COUNTER` pflegen, der bei jedem Update inkrementiert wird. Der Preflight-Report kann die erwartete Lebensdauer berechnen (`total_size / sector_size * max_updates_per_year * expected_lifetime_years`). Bei Überschreitung von 80% des Datenblatt-Limits wird eine Fleet-Warnung ausgelöst. Der Counter ist ein einzelner 32-Bit Wert im WAL (4 Bytes).

---

## GAP-39: Multi-Core Bus-Sanitization Timing

**Problem:** `soc_hal_t::flush_bus_matrix()` wird "direkt vor OS-Jump" aufgerufen. Aber auf manchen SoCs (STM32H7 mit AXI-Matrix) kann das Bus-Flush nicht-deterministisch lange dauern (abhängig von ausstehenden DMA-Transfers). Wenn der WDT aktiv ist und das Flush zu lange dauert, könnte der WDT während des Flush triggern.

**Mitigation:** `flush_bus_matrix()` muss eine maximale Wartezeit haben (Timeout). Wenn DMA-Transfers nach z.B. 10ms nicht abgeschlossen sind, bricht die Funktion den DMA hart ab (DMA-Channel-Disable) und loggt den Zustand. Der Core kickt den WDT vor dem Flush-Aufruf. Das Timeout muss in der `hals.md`-Spezifikation als Pflichtverhalten aufgenommen werden.

---

## GAP-40: `console_hal_t::getchar()` Return-Type Collision

**Problem:** `getchar()` gibt `int` zurück: 0–255 für gültige Bytes, `-1` für "keine Daten". Aber der Core könnte versehentlich den Return-Wert in ein `uint8_t` casten (was `-1` zu `255` macht und nicht von einem echten `0xFF`-Byte unterscheidbar ist). Die COBS-dekodierte Auth-Token-Übertragung enthält potenziell `0xFF`-Bytes im Payload.

**Mitigation:** Die Spezifikation ist korrekt (Return als `int`, `BOOT_UART_NO_DATA = -1`). Aber: Ergänze eine explizite Warnung in `hals.md`: "Der Core MUSS den Return-Wert als `int` verarbeiten und DARF ihn NICHT vor der -1-Prüfung auf `uint8_t` casten." Alternativ: Design-Change zu einem Out-Parameter-Modell: `boot_status_t (*getchar)(uint8_t *byte_out, uint32_t timeout_ms)`, das `BOOT_OK` oder `BOOT_ERR_TIMEOUT` zurückgibt. Dies eliminiert die Casting-Falle komplett.

---

## GAP-41: Timing-IDS Baseline — Keine Spezifikation

**Problem:** Das Timing-IDS misst die Boot-Dauer und meldet Abweichungen an Fleet-Manager. Aber: Wie wird die Baseline etabliert? Unterschiedliche MCU-Chargen haben Fertigungsvarianzen (±10% Clock-Genauigkeit bei LSI). Unterschiedliche Firmware-Größen erzeugen unterschiedliche Hash-Zeiten. Software-SHA vs. Hardware-SHA ändert die Baseline um Faktor 5. Ohne spezifizierte Baseline-Kalibrierung produziert das IDS massenweise False-Positives.

**Mitigation:** Die Baseline wird NICHT vom Bootloader berechnet, sondern vom Fleet-Manager. Stage 1 reportet folgende Rohdaten in `boot_diag`:

- `verify_duration_us`: Gesamt-Verifikationszeit.
- `image_size_bytes`: Image-Größe.
- `has_hw_acceleration`: Bool (aus `crypto_hal_t`).
- `cpu_freq_mhz`: CPU-Frequenz.
  Der Fleet-Manager berechnet daraus `us_per_byte` und bildet pro Gerätetyp + Crypto-Backend eine statistische Baseline (Mean ± 3σ). Ausreißer werden als Anomalien geflaggt. Die Spezifikation sollte klarstellen: "Stage 1 sammelt Rohdaten. Die Baseline-Berechnung und Anomalie-Erkennung ist Aufgabe des Fleet-Managements und außerhalb des Bootloader-Scopes."

---

## GAP-42: COBS-Framing ohne Flow-Control

**Problem:** Serial Rescue überträgt 104-Byte Auth-Tokens über UART mit COBS-Framing. Aber es gibt keine Spezifikation von Hardware- oder Software-Flow-Control (RTS/CTS oder XON/XOFF). Bei langsamen MCUs (z.B. 16 MHz AVR) und 115200 Baud könnte der RX-Buffer (oft nur 1–8 Bytes FIFO) überlaufen, wenn der Techniker den Token zu schnell sendet.

**Mitigation:** Zwei Optionen:

1. **Software-Pacing (Empfohlen):** Das Auth-Protokoll wird Ping-Pong: Techniker sendet DSLC-Request → Stage 1 antwortet mit DSLC + "READY" → Techniker sendet Auth-Token. Das "READY"-Signal fungiert als implizite Flow-Control.
2. **Hardware-RTS/CTS:** Als optional im `device.toml` konfigurierbar. Default: Kein HW-Flow-Control (die meisten Dev-Boards verdrahten RTS/CTS nicht).

---

## GAP-43: Kein spezifizierter Fehlerbehandlungs-Pfad für `boot_platform_init()` Fehler

**Problem:** `boot_platform_init()` gibt `const boot_platform_t *` zurück. Was passiert, wenn die Plattform-Initialisierung selbst fehlschlägt? Der Pointer kann nicht `NULL` sein (dann crasht der Core sofort). Die einzelnen HAL-`init()`-Funktionen geben `boot_status_t` zurück, aber der Gesamt-Initializer hat keinen Fehler-Reporting-Mechanismus.

**Mitigation:** Wenn ein Pflicht-HAL-Init fehlschlägt (z.B. Flash-Controller antwortet nicht), muss Stage 1 in einen Minimal-Modus fallen:

1. Wenn `console` verfügbar: Fehlermeldung über UART ausgeben.
2. LED blinken (wenn GPIO konfiguriert): SOS-Pattern.
3. WDT auslösen → Reset → Retry.
4. Nach N Retries: Halt.
   Die Init-Sequenz im `boot_main.c` muss jeden `init()`-Return prüfen und bei Fehler die Kaskade abbrechen. Dieses Verhalten muss spezifiziert werden.

---

## GAP-44: `soc_hal_t::battery_level_mv()` Dummy-Load — Board-spezifisch, nicht portable

**Problem:** Die Unter-Last-Messung verlangt, dass die HAL eine Last anlegt (GPIO-Pin für LED, CPU-intensive Berechnung). Aber nicht jedes Board hat einen schaltbaren Dummy-Load. Die HAL-Spezifikation sagt "Die HAL MUSS vor der Messung eine Last anlegen", was auf Boards ohne solche Hardware nicht umsetzbar ist.

**Mitigation:** Ändern zu "Die HAL SOLL eine Last anlegen, wenn die Hardware einen schaltbaren Dummy-Load bietet." Als Fallback: Der `min_battery_mv`-Schwellenwert im Manifest wird um einen konfigurierbaren Safety-Offset erhöht (z.B. +300mV statt +200mV), um den fehlenden Lasttest zu kompensieren. Der `device.toml` bekommt ein `has_dummy_load = false`-Flag, und der Preflight-Report warnt: "Kein Dummy-Load: Batteriemessungen könnten die Realkapazität überschätzen."

---

## GAP-45: Kein Test-Harness für WAL-Korruptionsszenarien spezifiziert

**Problem:** Die Fault-Injection über `hal_fault_inject.c` wird erwähnt, aber es fehlt eine Spezifikation des Test-Harness: Welche Szenarien müssen abgedeckt werden? Wie werden die Tests in CI automatisiert? Was ist die Mindest-Testabdeckung für die WAL-State-Machine?

**Mitigation:** Spezifiziere in `docs/testing_requirements.md` eine Matrix von Pflicht-Szenarien:

- Brownout nach WAL-Write, vor Flash-Write (Replay-Test)
- Brownout nach Flash-Write, vor WAL-Commit (Hash-Verify-Recovery)
- Brownout während Erase (Re-Erase-Test)
- Bit-Rot in TMR-Kopien (1/3, 2/3 korrumpiert)
- WAL-Sektor voll (Ring-Rotation)
- ABI-Version-Mismatch nach Stage-1-Update
- Gleichzeitiger Brownout und WDT-Timeout
- Delta-Patch mit falschem Base-Fingerprint
- Auth-Token Replay (Serial Rescue)
  Jedes Szenario muss als automatisierter Sandbox-Test (`--sandbox`) implementierbar sein. Die CI-Pipeline muss alle Szenarien pro Commit durchlaufen. Ziel: 100% Branch-Coverage in `boot_journal.c` und `boot_swap.c`.

---

## GAP-46: `verify_pqc()` Guard — Bool statt Pointer-Check ist fehleranfällig

**Problem:** Die Spezifikation sagt: "Der Core MUSS vor dem Aufruf zwingend den Metadaten-Bool `platform->crypto->supports_pqc` prüfen! [...] Das boolesche Feld ist der Gate-Guard, nicht der Pointer." Aber ein Entwickler könnte vergessen, den Bool zu prüfen und direkt den Pointer callen. Wenn `supports_pqc == false` aber `verify_pqc != NULL` (z.B. durch einen uninitialisierten Pointer), crasht das System. Die aktuelle Architektur hat zwei Wahrheitsquellen (Bool UND Pointer) die inkonsistent sein könnten.

**Mitigation:** Eliminiere die doppelte Wahrheitsquelle: `supports_pqc` wird zu einem berechneten Getter:

```c
static inline bool crypto_supports_pqc(const crypto_hal_t *c) {
    return c->verify_pqc != NULL;
}
```

Der Bool verschwindet aus dem Struct. Der Pointer ist die einzige Wahrheitsquelle. Der Core prüft nur noch `if (platform->crypto->verify_pqc != NULL)`. Konsistenz ist architektonisch garantiert.

---

## GAP-47: Kein explizites Verhalten bei Flash-ECC-Fehlern (Hard Faults)

**Problem:** Auf STM32L4+ mit Hardware-ECC kann ein Read auf eine nicht-gelöschte (aber korrumpierte) Flash-Zelle einen Hard Fault auslösen (nicht nur einen Return-Code). Die HAL-Spezifikation behandelt Flash-Errors als Return-Codes (`BOOT_ERR_FLASH`), aber ein Hard Fault umgeht den gesamten Return-Code-Mechanismus.

**Mitigation:** Stage 1 muss einen Hard-Fault-Handler registrieren, der:

1. Den Fault-Status-Register liest (CFSR auf Cortex-M).
2. Wenn der Fault von einem Flash-Read kommt: Den Fault als `BOOT_ERR_FLASH` in den `.noinit`-Bereich loggt.
3. Den WDT triggert (erzwingt Reset).
4. Beim nächsten Boot erkennt Stage 1 den geloggten Fault und eskaliert (z.B. Rollback oder Recovery).
   Die `hals.md` sollte spezifizieren, dass auf ECC-fähigen Chips ein `HardFault_Handler` als Teil der HAL-Implementierung Pflicht ist.

---

## GAP-48: `delay_ms()` als Busy-Wait — Energieverschwendung im Backoff

**Problem:** `delay_ms()` wird als Busy-Wait implementiert (`while(get_tick_ms() - start < ms) {}`). Für den Exponential-Backoff (1h, 4h, 12h, 24h) ist Busy-Wait energetisch katastrophal — der Prozessor läuft stundenlang bei voller CPU-Last, nur um zu warten. Das entleert jede Batterie.

**Mitigation:** Für kurze Delays (<1s) ist Busy-Wait OK. Für den Backoff-Mechanismus MUSS `soc_hal_t::enter_low_power(wakeup_s)` verwendet werden, NICHT `delay_ms()`. Die aktuelle Architektur tut das korrekt (das Konzept-Dokument nennt `enter_low_power` für Backoff), aber `hals.md` spezifiziert `delay_ms()` als Aufrufer für Backoff. Das ist inkonsistent. Klarstellen: `delay_ms()` ist NUR für kurze, nicht-energiekritische Wartezeiten (z.B. 100ms UART-Timeout). Für Backoff wird ausschließlich `enter_low_power()` genutzt.

---

## GAP-49: Kein Watchdog-Verhalten beim OS-Jump definiert

**Problem:** Auf nRF52 ist der WDT nach Start nicht mehr stoppbar. `wdt_hal_t::deinit()` ist ein No-Op. Das OS erbt einen laufenden Watchdog und muss ihn rechtzeitig kicken. Aber es gibt keine Spezifikation, wie das OS über den aktiven WDT und dessen Timeout-Wert informiert wird. Wenn das OS nicht weiß, dass ein WDT läuft, crasht es nach dem Timeout.

**Mitigation:** Der WDT-Status (aktiv/inaktiv, Timeout-Wert) wird als Teil des `.noinit`-Handoff-Structs übergeben:

```c
typedef struct {
    uint32_t magic;
    uint32_t boot_session_id;
    uint32_t wdt_timeout_ms;     /* 0 = kein WDT aktiv */
    uint32_t boot_diag_error_id;
    /* ... */
    uint16_t crc16;
} boot_handoff_t;
```

Das OS (bzw. `libtoob`) liest `wdt_timeout_ms` und konfiguriert seinen eigenen WDT-Kicker entsprechend.

---

## GAP-50: Stage 0 mit `ed25519-sw` (~8 KB) — Passt nicht in 4 KB Budget

**Problem:** Stage 0 wird als "~4-8 KB" spezifiziert. Die Crypto-Option `ed25519-sw` braucht "~8 KB C-Code". Zusammen mit dem restlichen Stage-0-Code (Boot_Pointer Auswertung, RTC-RAM Check, OTP-Read) liegt der Footprint bei 10+ KB. Das passt nicht in das 4-KB-Budget und ist hart an der 8-KB-Grenze.

**Mitigation:** Realistischere Budgets:

- `hash-only`: Stage 0 ≈ 2–4 KB (passt in erste Flash-Sektoren).
- `ed25519-sw`: Stage 0 ≈ 8–12 KB (braucht 2–3 Sektoren auf MCUs mit 4-KB-Sektoren).
- `ed25519-hw`: Stage 0 ≈ 4–6 KB (Hardware-Offload reduziert Code).
  Die `device.toml`-Konfiguration `stage0.verify_mode` muss diese unterschiedlichen Footprints reflektieren, und der Manifest-Compiler muss das Flash-Layout dynamisch anpassen. Die Angabe "~4 KB" im Konzept-Dokument muss zu "4–12 KB abhängig von `verify_mode`" korrigiert werden.

---
