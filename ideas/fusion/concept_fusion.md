# Toob-Boot: Architektur-Synthese & Master-Konzept

Dieses Dokument aggregiert die gesamten Recherchen (Bootloader Research PDF) sowie die visuellen und textuellen Architekturentwürfe (Input 1 & Input 2) zu einem umfassenden, zu 100% kohärenten Blueprint für "Toob-Boot".

---

## 1. Die fundamentale Architektur (Phasen & Schichten)

Die Struktur des Bootloaders löst das klassische Chaos (MCUBoot, WolfBoot) durch eine orthogonale Trennung von **zeitlichem Ablauf (Stages)** und **Software-Abstraktion (Schichten)**.

### A. Der zeitliche Boot-Ablauf (Zwei-Stufen-Architektur)

- **Stage 0 (Immutable Core):** Winzig (~4 KB), fest eingebrannt (ROM / Write-Protected). Führt nur SHA-256 Validierung, Public-Key Check und einen Jump-to-Stage-1 durch. Formell verifizierbar (wie DICE). **Löst das Crypto-Agility-Paradox:** Der Algorithmus in Stage 0 ist fix, aber alles andere inkl. PQC-Algorithmen kann über Stage 1 out-of-band aktualisiert werden. (Zwingend erfordert Stage 0 jedoch eine **Key-Index Rotation Strategy via Hardware-eFuses/OTP**: Statt einen kompromittierten Schlüssel fatal zu verbrennen, weicht der Bootloader bei Widerruf automatisch auf den 2. oder 3. vorprogrammierten Key-Slot aus).
- **Stage 1 (Updateable Engine):** Das dynamische Herz (Minimalversion ~14 KB, Full-Feature ~24-28 KB). Trägt alle Module: Update-Engine (WAL + Merkle), Crypto-HAL (Pluggable: Micro-Crypto wie `monocypher`, `chacha20`, `compact25519` oder direkte Hardware-Crypto-Wrapper statt des viel zu schweren mbedTLS!), SUIT-Parser, DICE-Identity (Achtung: Update von Stage 1 ändert die CDI-Identität! Dies bedingt einen **Two-Way Handshake**: 1. Vor dem Reboot emittiert Stage 1 ein `INTENT_TO_MIGRATE` (mit altem Token). 2. Nach dem Reboot bestätigt die *neue* Firmware `CURRENT_IDENTITY_CONFIRMED`. Erst dann entwertet die Cloud die alte ID. Das verhindert Lockouts bei Flash-Fails während des Bootens!), Delta-Patcher, Flash-HAL, Diagnostics, Energy-Guard.

*Das zu startende OS (Application / RTOS) bestätigt den erfolgreichen Start final via eines Confirm-Flags.* Damit das OS völlig vom Bootloader-Flash entkoppelt bleibt, schreibt das OS z.B. ein flüchtiges Magic-Byte ins `uninitialisierte RTC-RAM` und führt einen **Soft-Reset** aus. Der Bootloader (Stage 1) erwacht und liest als allererste Pflicht das **Hardware-Reset-Reason Register** (z.B. `RCC_CSR`). Lautet der Grund `WATCHDOG_RESET` oder `SOFTWARE_PANIC`, wird ein "erfolgreiches" RTC-RAM Flag gnadenlos ignoriert und gelöscht (Verhindert Todes-Schleifen, falls das OS kurz nach dem Flag-Setzen abstürzt!). Andernfalls sichert er den State in den Flash-WAL, löscht RAM und bootet endgültig.

### B. Das 5-Schichten Software-Modell

Ein revolutionärer, strikt entkoppelter Layer-Aufbau:

**Schicht 5: Build & Config Layer (Vendor-Plugins)**
Host-Ebene: Das `device.toml` beschreibt die Partitionsarchitektur abstrakt. Da Hersteller wie Espressif (ESP32) hochkomplexes Linken erfordern (z.B. Split auf `esp32c6.ld`, `peripherals.ld`, `rom.ld`), nutzt der Manifest-Compiler **herstellerspezifische Build-Plugins** (`vendors/esp/builder.py`). Diese abstrahieren die Vendor-spezifische Komplexität ohne KI/SVD-Analyse zur Laufzeit. Das Tool generiert `flash_layout.ld`, `boot_config.h` und einen weitreichenden **Predictive Preflight-Report** für CMake.
**Preflight-Automatisierung:** Der Compiler berechnet aus TOML-Werten (`merkle.chunk_size`) den **minimalen Watchdog-Timeout** (`flash_erase_time_per_sector * sectors`). Zudem prüft er die extrem kritische Gleichung: `Peak_SRAM_Needed = merkle.chunk_size + (tree_depth * 32) + WAL_Sector_Buffer_RAM`. Wenn (oft genutzte) 16 KB große Chunks den limitierten `14 KB` RAM-Footprint übersteigen, bricht der Build sofort ab (Hardware-Reality-Check!). `merkle.chunk_size` bleibt damit auf 2-4 KB zwingend gedrosselt.
**SUIT-Regulatorik (CRA):** Das Manifest enthält zwingend einen `sbom_digest` (Trägt den SHA-256 Hash der SPDX/CycloneDX SBOM-Datei). Der Bootloader loggt diesen beim Start in `boot_diag`. Flotten-Manager kennen so die SBOM-Integrität jeder Edge-Node, wodurch EU Cyber Resilience Act (CRA) Compliance 2027 out-of-the-box erfüllt wird.

**Schicht 4a: Serial Rescue (Fallback)**
Ein rein passiver Notfall-Zugang (UART / USB-DFU) direkt im Bootloader für das Labor/Werk, falls gar nichts mehr geht. (Die komplexe Netzwerkkommunikation ist ausgegliedert in ein Recovery-OS, siehe unten).
**Schicht 4b: Diagnostics**
Structured Log, Health, Telemetry.

**Schicht 3: Core Engine**
Reine Business-Logik: Update-State-Machine, Signatur-Verifikation, Journal, Merkle-Verify, SUIT-Manifest-Parser (Zwingend als **strikter Stream-Parser wie zcbor**, der zum Schutz vor Heap-Overflows nur bekannte C-Structs allokiert und variable Länge blockt) und **Anti-Rollback Protection**. Letztere nutzt eine Security Version Number - SVN (Monotonic Counter), die veraltete Firmware rigoros abweist (`Target_Manifest_SVN >= Hardware_SVN`). Bei ressourcenfressenden Delta-Patches wird diese SVN-Gültigkeit *zwingend vor dem Start* der Patch-Berechnung validiert.

**Schicht 2: OS Shim (Optional)**
Eine ultradünne Schicht, die standardmäßig `bare-metal` (malloc-frei) läuft und exakt vier primitive Dinge abstrahiert: `Mutex` (für Multi-Core), `Timer-Tick`, `malloc/free` (nur falls die Crypto-Lib es fordert) und `assert`. Für Zephyr, FreeRTOS oder NuttX existiert hierfür jeweils ein ~50-Zeilen-Adapter.

**Schicht 1: Platform HAL**
Statt monolithischer APIs werden exakt **6 C-Structs (Traits)** definiert. *(Zwingende Systemvorgabe: Bevor ein Jump zum OS stattfindet, fordert Toob-Boot als absolute Pflicht ein `hal_deinit()`, um alle genutzten Hardware-Register wie Clocks und UART in den Reset-Default zu zwingen und OS-Driver-Crashes alias "Peripherie-Vergiftung" abzuwehren):*

- [x] **`flash_hal_t`** (read · write · erase) -> PFLICHT
- [x] **`confirm_hal_t`** (set_ok · check_ok · clear) -> PFLICHT (Abstrahiert das Confirm-Flag hardwareunabhängig: Ob schnelles RTC-RAM für ESP32, ein wear-leveled Flash-Sector für MCU-Kaltstarts ohne Knopfzelle oder ein Always-On-Backup-Register für STM32, entscheidet die Plattform über diesen Trait!)
- [x] **`crypto_hal_t`** (hash · verify_ed25519 · rng) -> PFLICHT (Besitzt zudem den *optionalen PQC-Migrationspfad `verify_signature_pqc()`*. Erst wenn das Manifest `pqc_hybrid=true` signalisiert, lädt Stage 1 dynamisch z.B. ML-DSA Module – zukunftssicher ohne permanenten Footprint-Overhead).
- [x] **`clock_hal_t`** (init · get_tick · delay) -> PFLICHT
- [x] **`wdt_hal_t`** (kick · set_timeout) -> **PFLICHT für Auto-Rollback** (Ohne Hardware-Watchdog kann ein gebricktes OS nie resetten).
- [ ] **`console_hal_t`** (putchar · getchar) -> OPTIONAL (Serieller Log)
- [ ] **`power_hal_t`** (battery_level · sleep) -> OPTIONAL (Energy-Guard: Misst Batterie zwingend **unter Last (Dummy-Load)**, da Flachkurven an LiPos reines Verblenden sind).

---

## 2. Transaktionale Update-Engine (Der Kern-Mechanismus)

Das Ziel ist die absolute Minimierung des Footprints und gleichzeitige $2000-Truck-Roll-Vermeidung durch 100% Stromausfall-Resilienz.

### Das "Blockchain"-Konzept (Merkle-Tree RAM-Sparer)

Um ein 1,5 MB großes Image auf Signatur-Integrität zu prüfen, müsste man es klassisch komplett in den RAM laden (was auf einer MCU unmöglich ist) oder beim kleinsten externen Flash-Lesefehler von vorne anfangen. Die Lösung entleiht sich ein Konzept aus der Blockchain: **Den Merkle-Tree**.
Das SUIT-Manifest liefert asymmetrisch kryptografisch signiert nur den vertrauenswürdigen _Root-Hash_ des Trees. Der Bootloader kann damit jeden kleinen 4 KB-Chunk **einzeln und fliegend ("on-the-fly") verifizieren**, ohne jemals das Gesamtbild lesen zu können/müssen. Manipulierte oder über die Luft korrumpierte Chunks fliegen sofort auf, bevor sie geschrieben werden.

- **Ablaufkette:** `1. Empfang (Chunk-weise) -> 2. Chunk-Hash (Merkle-Pfad) -> 3. WAL-Eintrag (Intent -> Flash) -> 4. Write (Flash-Page)`
- **Das Write-Ahead Log (WAL):** Ein winziges (~128 Bytes) Journal auf dem Flash. Damit Flash-Speicher nicht durch ewigen Verschleiß getötet wird, operiert das WAL als **Append-Only Ring Buffer über mindestens 2 pre-erased Flash-Sektoren**. NOR-Flash hat jedoch eine empfindliche 10-Jahres Data-Retention. Gegen "stille" Bit-Rot Speicherfehler verlangt jeder WAL-Entry zwingend einen **CRC-16 Trailer (2 Bytes)**. **WICHTIG (Anti-Bit-Rot-Zeitbombe):** Sobald ein Update 100% OS-bestätigt ist, muss die Zustandsmaschine komplett finalisiert/entleert werden (z.B. stattdessen Nutzung eines redundanten 2-Byte "Current_Primary_Slot" Feld). Der Bootloader darf beim Start NIEMALS auf einen 6-Jahre alten `TXN_COMMIT` Log-Eintrag vertrauen – sonst triggern historische Bit-Rot CRC-Fehler völlig grundlose Rollbacks alter Firmware-Versionen in der Zukunft!
  - _Entry 0:_ `TXN_BEGIN | version=2.1.0 | chunks=64`
  - _Entry 1:_ `CHUNK_WRITE | page=3 | hash=0xa7f3...`
  - _Transfer-Bitmap:_ Eine effiziente Map (z.B. zeigt 60% empfangen an), perfekt für den _Transport (Layer 4a)_, falls das Gerät mitten im LoRa-Download die Verbindung verliert.
- **Vier-Stufige Stromausfall-Garantien (Brownout-Resilienz):**
  1. **Crash _vor_ WAL-Write:** Der Chunk wurde empfangen, aber der WAL-Intent fehlt. Beim Reboot gilt der Chunk laut WAL als unvollständig. Die Chunk-Bitmap signalisiert "verloren" -> Erneuter Download / Request. Nichts brickt.
  2. **Crash _nach_ WAL, vor Flash-Write (Kritisch):** Das System hat die Absicht ("Intent") notiert: _"Überschreibe Page 3 mit Hash 0xa7..."_. Der Strom fällt aus, Page 3 ist halb korrupt. Beim Reboot erkennt Stage 1 den fehlenden Commit im WAL, liest den Intent und führt den Schritt vollständig erneut aus (**Replay**). Das partielle Image wird geheilt. Nichts brickt.
  3. **Crash _nach_ Flash-Write, vor WAL-Commit:** Page 3 wurde physisch korrekt beschrieben, aber der Strom riss exakt davor ab, den WAL-Eintrag abzuhaken. Beim Reboot verifiziert Stage 1 den Hash von Page 3. Der Hash passt zum erwarteten Merkle-Root. Stage 1 vermerkt nachträglich den Commit und springt zum nächsten Chunk.
  4. **Post-Update Crash (Das Confirm-Flag):** Das gesamte Update (`TXN_COMMIT`) war erfolgreich. Das neue App-OS bootet, schlägt aber wegen eines Software-Bugs völlig fehl (Endlosschleife etc.). Das OS kann das erforderliche Boot-Confirm-Flag nicht in den RTC-RAM/Flash schreiben. Der Hardware-Watchdog (`wdt_hal_t`) greift ein und resettet den Chip. Die Bootloader Stage 1 fährt wieder hoch, erkennt das fehlende Confirm-Flag und führt über das Journal sauber einen kompletten **Rollback** auf die alte Firmware aus.
  5. **Brownout Death-Loop (Exponential Backoff):** Wenn exakt das hardwarenahe "Hardware-Flash-Erase" den Akku unterbrochen/gedrückt hat (Brownout-Spannungsabfall) und das System permanent resettet, würde sich der Akku in einer Replay/Erase-Todesschleife schnell hart-entladen. Das WAL registriert diese Crashs und implementiert automatisch eine Backpressure-Wartezeit (Exponential Backoff), bis sich die Spannungsquelle erholt hat.

---

## 3. Flash-Layout: In-Place Overwrite statt Resourcen-Abfall

MCUBoot nutzt Swapping und verlangt einen _Scratch-Bereich_, was den Gesamt-Overhead auf astronomische `~2.1x App-Größe` treibt.
Toob-Boot fährt eine radikale, viel effizientere Strategie:

1. **S0** (4 KB, Stage 0)
2. **S1** (24 KB, Stage 1)
3. **App Slot A** (Aktives Image)
4. **Staging** (Neues Image oder Delta-Patch)
5. **Swap-Buffer (Max_Sector_Size)** als atomarer In-Place Rettungsanker. (Hardware-Realität: Bei asymmetrischem MCU-Flash, z.B. bei STM32, wird die Puffer-Größe physikalisch durch den größten involvierten App-Sektor diktiert, was teils 128 KB am Ende des Flashs erfordert!).
6. **Journal** (WAL + Bitmap, ca 2-4 KB)

**Ergebnis:** Keine gigantische Scratch-Partition nötig! Das Schreiben erfolgt nahezu als In-Place-Overwrite. (Da ein In-Place Delta den Sektor zerstören würde, wenn der Strom ausfällt, wird der *Swap-Buffer* genutzt: `Diff im RAM -> Puffer Sektor -> WAL Commit -> Überschreibe App Slot A`).
_Sonderfaktor Delta-Updates:_ Da Staging winzig sein kann, ermöglicht der Delta-Patcher eine solide, **realistische 3- bis 5-fache Reduktion**. (Das oft beworbene "18x" reißt beim winzigen RAM Stack-Overflows, daher sind wir auf Micro-Dictionary Patcher wie `heatshrink` limitiert). Zwingende Architektur-Bedingung: Dieser Patcher muss **strictly Forward-Only und Non-Overlapping** abarbeiten. Zudem schützt ein obligatorischer **8-Byte Base-Fingerprint (Truncated SHA-256)** der Zielpartition im Patch-Header vor der Katastrophe, dass ein Delta (z.B. v2->v4) fälschlich an ein v3-Image genäht und das Zielgerät irreparabel gebrickt wird. Passt der Base-Fingerprint des Slot A nicht zum Base-Fingerprint des Patch-Headers, verweigert Stage 1 den Patch sofort.

---

## 4. ✅ AUFGELÖSTE ARCHITEKTUR-REIBUNGSPUNKTE (Refinement)

### ✅ Auflösung: Satelliten-Abbrüche & Das Recovery-OS (Layer-Trennung)

Ursprünglich schien es, als müsste der Bootloader selbst komplexe Stacks wie WLAN oder LoRa implementieren (was Footprint-Kosten von 100+ KB bedeutet). Die Architektur löst dies über zwei getrennte Wege:

- **Im Bootloader (Schicht 4a - Serial Rescue):** Nur nackte, billige Protokolle (UART, USB-DFU) für das Werk/Labor.
- **Das Recovery-OS Pattern (Zustandsmaschine):** Gerätehersteller, die "over-the-air" Fallbacks brauchen, flashen in einen separaten, kleinen Flash-Slot ein `Recovery-OS` (z.B. minimales Zephyr + WLAN-Stack). Toob-Boot verwaltet einen `Boot_Failure_Counter` im WAL:
  - 1 Crash: Rollback auf App Slot A.
  - Weitere Crashes (Max-Retries erreicht, Slot A auch gebrickt): Stage 1 bootet zwangsweise in die Recovery-Partition. **WICHTIG (Anti-Lockout):** Dieser Recovery-Boot muss hardwareseitig komplett aus der Anti-Rollback/SVN-Kette entkoppelt sein. Sonst würde die SVN-Prüfung das factory-alte Recovery-OS (v1) rigoros blockieren, falls die abgestürzte App bereits v5 war (= tödlicher Brick).
  - Erfolgreicher Start (Confirm-Flag): Der Boot_Failure_Counter wird strikt auf `0` zurückgesetzt, um zeitlich fernliegende Crashes nicht mit alten Ausfällen zu kumulieren!
  Dieses Recovery-OS bindet via C-Bibliothek den **Toob-Boot OTA-Agenten** ein, kommuniziert über denselben sicheren Kanal (Transfer-Bitmap, WAL) und repariert das Feature-OS.

### ✅ Auflösung: Vendor-Linker vs. Automatisierung (Schicht 5)

Wie generieren wir automatisierte Linker-Scripts für Chips wie den ESP32, die 3 komplett getrennte `.ld` Files (ROM, Peripherals, App) zur Assemblierung benötigen? Anstatt (wie in älteren Tools) SVD-Dateien zur Build-Zeit via teurer LLM-Analyse zu kompilieren, ist der Manifest-Compiler **Plugin-basiert**.
Für jede Chip-Familie existieren winzige "Vendor-Builder-Scripte" (z.B. `vendor_esp32_builder.py`). Diese Pipelines rüsten das herstellerspezifische Vorwissen intern aus. Der Nutzer deklariert nur stumpf im `device.toml` seine Flash-Partitionen, und das ESP-Plugin berechnet und assembliert alle 3 nötigen Linker-Scripte im Hintergrund 100% deterministisch vor dem Cross-Compile.

---

## 5. Developer Experience (DX) & Testing-Architektur

Features, die den Konkurrenzsystemen fehlen und die Entwicklerproduktivität maximieren:

- **Host-Nativer Sandbox-HAL & Fuzzing:** Der gesamte Bootloader kann auf dem PC (macOS/Linux) als natives Binary kompiliert werden (`$ boot-build --sandbox`). Da das System Host-nativ läuft, erzeugt die CI automatisch **Fuzz-Testing-Targets** (`cargo-fuzz` / `AFL++`) gegen den SUIT-Parser, den Delta-Decoder und Merkle-Verifier. So härten wir die sicherheitskritischen Angriffsflächen, die von außen erreichbar sind, massiv ab, ohne teure Hardware-HIL-Rigs aufzusetzen.
- **Auto-generierte Renode (Emulator) Configs:** Der Manifest-Compiler parst das `device.toml` und generiert daraus automatisch eine exakte `.resc` Datei für den Renode-Simulator. Hardware-Tests in der CI laufen immer deckungsgleich zur physikalischen Flash-Map, ohne manuelle Konfiguration.
- **Der Preflight-Report:** Statt kryptischer C-Fehler erhält der Entwickler _vor_ dem C-Compile einen Report: `Alignment check passed`, `Swap-Move kompatibel`, `Power Guard aktiv: min 3300mV`.
- **Deterministische Fault-Injection:** Über einen speziellen HAL-Mock (`hal_fault_inject.c`) lässt sich in der Sandbox sagen: _"Simuliere einen Brownout exakt nach dem 47. Sektor"_. Die WAL-Heilung kann so innerhalb von Sekunden 1000-fach in CI geprüft werden.
