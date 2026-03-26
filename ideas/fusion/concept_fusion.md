# Toob-Boot: Architektur-Synthese & Master-Konzept

Dieses Dokument aggregiert die gesamten Recherchen (Bootloader Research PDF) sowie die visuellen und textuellen Architekturentwürfe (Input 1 & Input 2) zu einem umfassenden, zu 100% kohärenten Blueprint für "Toob-Boot".

---

## 1. Die fundamentale Architektur (Phasen & Schichten)

Die Struktur des Bootloaders löst das klassische Chaos (MCUBoot, WolfBoot) durch eine orthogonale Trennung von **zeitlichem Ablauf (Stages)** und **Software-Abstraktion (Schichten)**.

### A. Der zeitliche Boot-Ablauf (Zwei-Stufen-Architektur)

- **Stage 0 (Immutable Core):** Fest eingebrannt (ROM / Write-Protected). Wertet beim Booten einen ultimativen Hardware-`Boot_Pointer` (OTP/Flash-Byte) aus, um gezielt Stage 1 Bank A oder B anzuspringen. Verifiziert Stage 1 via Hash-Check und springt dorthin. Da vollwertige Ed25519-Signaturprüfungen (inkl. Big-Int Math) schwer in 4 KB RAM/ROM passen, wird die Architektur hier hardware-realistisch wählbar (`stage0.verify_mode` via TOML): Entweder `hash-only` (nur SHA-256 Check gegen OTP-Wert, ~2 KB Footprint), `ed25519-sw` (~8 KB C-Code) oder `ed25519-hw` (~4 KB bei Hardware-Krypto-Cores wie CC310). Löst das Crypto-Agility-Paradox. Gegen Root-Key-Bricks nutzt Stage 0 eine **Key-Index Rotation via OTP-eFuses**.
- **Stage 1 (Updateable Engine):** Das dynamische Herz (Minimalversion ~14 KB, Full-Feature ~24-28 KB). Trägt alle Module: Update-Engine (WAL + Merkle), Crypto-HAL (Pluggable: Micro-Crypto wie `monocypher`, `chacha20`, `compact25519` oder direkte HW-Crypto), SUIT-Parser, DICE-Identity (Achtung: Update ändert CDI! Dies bedingt **Two-Way Handshake**: 1. `INTENT_TO_MIGRATE`. 2. Nach Reboot: `CURRENT_IDENTITY_CONFIRMED`. Das Backend muss ein TTL von max 72h auf Intent-Events setzen, um Hänge-Identitäten zu verhindern!), Delta-Patcher, Flash-HAL, Diagnostics, Energy-Guard.

*Das zu startende OS (Application / RTOS) bestätigt den erfolgreichen Start final via eines Confirm-Flags.* Damit das OS völlig vom Bootloader-Flash entkoppelt bleibt, schreibt das OS z.B. ein flüchtiges Magic-Byte ins `uninitialisierte RTC-RAM` und führt einen **Soft-Reset** aus. Der Bootloader (Stage 1) erwacht und liest als allererste Pflicht das **Hardware-Reset-Reason Register** (z.B. `RCC_CSR`). Lautet der Grund `WATCHDOG_RESET` oder `SOFTWARE_PANIC`, wird ein "erfolgreiches" RTC-RAM Flag gnadenlos ignoriert und gelöscht (Verhindert Todes-Schleifen, falls das OS kurz nach dem Flag-Setzen abstürzt!). Andernfalls sichert er den State in den Flash-WAL, löscht RAM und bootet endgültig.

### B. Das 5-Schichten Software-Modell

Ein revolutionärer, strikt entkoppelter Layer-Aufbau:

**Schicht 5: Build & Config Layer (Vendor-Plugins)**
Host-Ebene: Das `device.toml` beschreibt die Partitionsarchitektur abstrakt. Da Hersteller wie Espressif (ESP32) hochkomplexes Linken erfordern (z.B. Split auf `esp32c6.ld`, `peripherals.ld`, `rom.ld`), nutzt der Manifest-Compiler **herstellerspezifische Build-Plugins** (`vendors/esp/builder.py`). Diese abstrahieren die Vendor-spezifische Komplexität ohne KI/SVD-Analyse zur Laufzeit. Das Tool generiert `flash_layout.ld`, `boot_config.h` und einen weitreichenden **Predictive Preflight-Report** für CMake.
**Preflight-Automatisierung:** Der Compiler berechnet (`merkle.chunk_size`) den **Watchdog-Timeout** (`flash_erase_time * sectors`). Er prüft die SRAM-Gleichung: `Peak_SRAM = merkle.chunk_size + (tree_depth * 32) + WAL_Sector_Buffer_RAM`. Wenn oft genutzte 16 KB große Chunks den limitierten `14 KB` RAM-Footprint übersteigen, bricht der Build sofort ab.
**Multi-Core Atomic-Groups & Secondary Boot Delegation:** Das Device.toml abstrahiert nativ Arrays (`[images.app]`, `[images.netcore]`), da SoCs wie der nRF5340 eigenständige Firmware für Radio-Cores benötigen. Toob-Boot erzwingt hierbei absolute **Atomic Update Groups ("Lock-Step")**: Wenn ein Sub-Image bricht, rollen ALLE an dem Update beteiligten assoziierten Images zurück, um tödliche IPC/ABI C-Struct Crashes zwischen asynchronen Cores zu verhindern! **Architektur-Reinheit:** Obwohl Toob-Boot alle Cores synchron flasht und verifiziert, bootet es **immer nur den Main-Core (App)**. Das Aufwecken von Sub-Prozessoren (Secondary Boot Delegation) obliegt alleinig der C-Runtime des Feature-OS, sobald dieses die Shared-Memory-IPC-Puffer initialisiert hat. Zudem misst der Core die Mikrosekunden des Boot-Prozesses. Ein Hacker-Backdoor in Stage 1 reißt das Hardware-Timing sichtbar ein (**passives Timing Intrusion Detection System** für Flotten).
**SUIT-Regulatorik (CRA):** Das Manifest enthält zwingend einen `sbom_digest` (Trägt den SHA-256 Hash der SPDX/CycloneDX SBOM-Datei). Der Bootloader loggt diesen beim Start in `boot_diag`. Flotten-Manager kennen so die SBOM-Integrität jeder Edge-Node, wodurch EU Cyber Resilience Act (CRA) Compliance 2027 out-of-the-box erfüllt wird.

**Schicht 4a: Serial Rescue (Fallback)**
Ein rein passiver Notfall-Zugang (UART / USB-DFU) direkt im Bootloader für das Labor/Werk, falls lokal absolut nichts mehr geht. (Komplexe Flash-Logiken wie XMODEM sind strikt verboten und zwingend in das externe Recovery-OS ausgelagert, siehe unten).
**WICHTIG (Offline 2FA-Handshake & Anti-Replay):** Um "Evil-Maid"-Angriffe auf die offene serielle Konsole zu vereiteln, erzwingt Stage 1 einen 104-Byte kryptografischen Auth-Token-Transfer. **Faktor 1 (Besitz):** Der Techniker liest vor Ort einen plattformspezifischen DSLC ("Device Specific Lock Code") per UART aus. **Faktor 2 (Autorisation):** Das HQ (Internet) signiert diesen DSLC zusammen mit einem 8-Byte UNIX Timestamp mittels Ed25519 `Root-Key`. Um die Notwendigkeit einer batteriegestützten Echtzeituhr (RTC) zu umgehen, nutzt Stage 1 das **"Highest-Seen-Timestamp" Pattern**: Der lokal im WAL-NVRAM gespeicherte logische Timestamp muss strikt überboten werden (`New_Token > NVRAM_Highest`), wodurch der Timestamp als monotoner Hardware-Counter (Einmal-Passwort Eigenschaft) operiert! Nur bei validem Token öffnet Stage 1 die Recovery-OS Schnittstelle.
**Schicht 4b: Diagnostics (Das Handoff-Areal)**
Stage 1 sammelt passive Intrusion-Detection-System (IDS) Timings und CRA-Regulatorik Hashes (`boot_diag`). Da das obligatorische `hal_deinit()` vor dem Jump zum Feature-OS das RAM nullt (`__bss_start`), instruiert das Manifest-Build-System das Linker-Script, eine **exklusive `.noinit` Shared-RAM Sektion** auszusparen. Nur durch diesen deterministischen Data-Contract überleben die kryptografischen und zeitlichen Telemetrie-Daten den Bootloader-Brückenschlag zum OS, ohne durch ständiges Flash-Speichern das Wear-Leveling zu zerstören.

**Schicht 3: Core Engine**
Reine Business-Logik: Update-State-Machine, Signatur-Verifikation, Journal, Merkle-Verify, SUIT-Manifest-Parser (Zwingend als **strikter Stream-Parser wie zcbor**, der zum Schutz vor Heap-Overflows nur bekannte C-Structs allokiert und variable Länge blockt) und **Anti-Rollback Protection**. Letztere nutzt eine Security Version Number - SVN (Monotonic Counter), die veraltete Firmware rigoros abweist (`Target_Manifest_SVN >= Hardware_SVN`). Bei ressourcenfressenden Delta-Patches wird diese SVN-Gültigkeit *zwingend vor dem Start* der Patch-Berechnung validiert.
**Anti-Truncation (Envelope-Wrap):** Um "Malleability by Truncation" (das Abschneiden der Signatur am Dateiende) zu verhindern, fordert der SUIT-Parser zwingend die **"Signature-First" oder "Envelope-Wrap" Validierung**. Stage 1 wird niemals auch nur ein einziges manipulierbares Byte (z.B. Flash-Erase Befehle) aus dem Stream ausführen, bevor nicht die Ed25519-Signatur über das gesamte Manifest-Envelope mathematisch erfolgreich evaluiert wurde!
**Targeted Updates (Personalisiertes OTA-Pinning):** Der SUIT-Parser evaluiert nativ "Device-ID Conditions". Will ein Cloud-Backend ein A/B-Testing oder hochindividuelles Update an nur einen Kunden ausrollen, injiziert es den spezifischen Hardware-Code (z.B. DSLC/MAC) in das `suit-condition-device-identifier` Feld des Manifests. Stage 1 fragt über die Platform-HAL (`boot_hal_get_dslc()`) die eigene Identität ab und blockt das Update sofort, wenn sie nicht übereinstimmt. Perfekte Personalisierung bei voll erhaltener OTA-Skalierbarkeit!

**Schicht 2: OS Shim (Optional)**
Eine ultradünne Schicht, die standardmäßig `bare-metal` (malloc-frei) läuft und exakt vier primitive Dinge abstrahiert: `Mutex` (für Multi-Core), `Timer-Tick`, `malloc/free` (nur falls die Crypto-Lib es fordert) und `assert`. Für Zephyr, FreeRTOS oder NuttX existiert hierfür jeweils ein ~50-Zeilen-Adapter.

**Schicht 1: Platform HAL & Security Baseline**
Eine ultradünne Treiberschicht. Krypto erstickt, wenn physischer Speicher auslesbar bleibt. WICHTIGE Porting-Direktive: Eine Software-Sperre gegen Debug-Ports in `startup.c` gleicht einem Race-Condition-Spielzeug, das leichtem Hard-Reset-Glitching unterliegt. Toob-Boot verlangt daher zwingend den physischen **JTAG/SWD-Lockdown über Hardware-eFuses oder stählerne Option Bytes (z.B. STM32 RDP2)** durch die Hersteller! Die `startup.c` Software-Sperre fungiert ab sofort nur als Defense-in-Depth Netz. Zudem fordert der Core vor App-Start ein striktes `hal_deinit()`, um "Peripherie-Vergiftungen" für das OS auszumerzen. Es gibt exakt **6 C-Struct Traits**:

- [x] **`flash_hal_t`** (read · write · erase) -> PFLICHT (Achtung OTFDEC: Bei aktiver On-the-Fly Hardware-Verschlüsselung wie auf dem ESP32/STM32 ist diese HAL strikt dafür verantwortlich, Hash-Berechnungen transparent gegen den *Plaintext* laufen zu lassen. Hashes korrelieren niemals auf Ciphertext!).
- [x] **`confirm_hal_t`** (set_ok · check_ok · clear) -> PFLICHT (Abstrahiert das Confirm-Flag hardwareunabhängig: Ob schnelles RTC-RAM für ESP32, ein wear-leveled Flash-Sector für MCU-Kaltstarts ohne Knopfzelle oder ein Always-On-Backup-Register für STM32, entscheidet die Plattform über diesen Trait!)
- [x] **`crypto_hal_t`** (hash · verify_ed25519 · rng) -> PFLICHT (Besitzt zudem den *optionalen PQC-Migrationspfad `verify_signature_pqc()`*. Erst wenn das Manifest `pqc_hybrid=true` signalisiert, lädt Stage 1 dynamisch z.B. ML-DSA Module – zukunftssicher ohne permanenten Footprint-Overhead).
- [x] **`clock_hal_t`** (init · get_tick · delay · get_reset_reason) -> PFLICHT (Abstrahiert das plattform-spezifische Reset-Register wie `RCC_CSR` als generische Enum wie `RESET_WATCHDOG`. Essentiell für den Check, ob ein Confirm-Flag nur eine WDT-Illusion ist!).
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
- **Das Write-Ahead Log (WAL):** Ein winziges (~128 Bytes) Journal auf dem Flash. Damit Flash-Speicher nicht durch ewigen Verschleiß getötet wird, operiert das WAL als **Append-Only Ring Buffer über mindestens 2 pre-erased Flash-Sektoren**. NOR-Flash hat jedoch eine empfindliche 10-Jahres Data-Retention. Gegen "stille" Bit-Rot Speicherfehler verlangt jeder WAL-Entry zwingend einen **CRC-16 Trailer (2 Bytes)**. 
  - **WICHTIG (ABI Data-Contract):** Ein upgedatetes Stage 1 darf niemals blindlings alte WAL-Strukturen parsen. Das Journal nutzt zwingend einen `ABI_VERSION_MAGIC` Header. Weicht die C-Struct Größe ab (z.B. bei einem S1 v2 Update), migriert/verwirft der Bootloader die alten Payload-Daten sicher, statt an verschobenen Offsets zu sterben.
  - _Entry 0:_ `TXN_BEGIN | version=2.1.0 | chunks=64`
  - _Entry 1:_ `CHUNK_WRITE | page=3 | hash=0xa7f3...`
  - _Transfer-Bitmap:_ Eine effiziente Map (z.B. zeigt 60% empfangen an), perfekt für den _Transport (Layer 4a)_, falls das Gerät mitten im LoRa-Download die Verbindung verliert.
- **WICHTIG (Anti-Bit-Rot-Zeitbombe):** Sobald ein Update 100% OS-bestätigt ist, muss die Zustandsmaschine komplett finalisiert/geleert werden. Der Boot-Status residiert fortan im Feld `Current_Primary_Slot`. Ein Bootloader darf sich nicht auf 6 Jahre alte Logs verlassen, wo kosmische Strahlung einzelne CRC-Fehler zündet und grundlose Rollbacks startet!
  Da auch ein 2-Byte Pointer durch Strahlung (Bit-Rot) kippt, nutzen wir hier **Triple Modular Redundancy (TMR)** der Luft- und Raumfahrt: Das Flag wird 3x physikalisch auf den Flash geschrieben. Stage 1 liest via Majority-Vote (2 aus 3 gewinnen). 4 Bytes extra löschen den Single-Point-of-Failure der Architektur komplett aus.
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

1. **S0** (~4-8 KB, Stage 0 Immutable)
2. **S1a / S1b** (2x 24 KB, Stage 1 Dual-Bank) -> *Zwingend für Self-Updates:* Code kann sich im eXecute-In-Place (XIP) Flash physikalisch nicht während der exekution selbst überschreiben. Dieser Dual-Slot ist die zwingende Lösung für 100% stromausfallsichere S1-Updates ohne unkalkulierbare RAM-Copy Tricksereien!
3. **App Slot A** (Aktives Image) / *Ggf. plus Sub-Slots (Network-Core) bei Multi-Image SoCs.* 
4. **Staging** (Neues Image oder Delta-Patch)
5. **Swap-Buffer (Max_Sector_Size)** als atomarer In-Place Rettungsanker. (Hardware-Realität: Bei asymmetrischem MCU-Flash, z.B. bei STM32, wird die Puffer-Größe physikalisch durch den größten involvierten App-Sektor diktiert, was teils 128 KB am Ende des Flashs erfordert!).
6. **Journal** (WAL + Bitmap + 4-Byte Swap-Buffer Erase-Counter, ca ~4 KB). Der Counter mahnt Fleet-Manager, wenn In-Place-Puffer $>80.000$ von $100.000$ typischen Zyklen erreichen.

**Ergebnis:** Keine gigantische Scratch-Partition nötig! Das Schreiben erfolgt nahezu als In-Place-Overwrite. (Da ein In-Place Delta den Sektor zerstören würde, wenn der Strom ausfällt, wird der *Swap-Buffer* genutzt: `Diff im RAM -> Puffer Sektor -> WAL Commit -> Überschreibe App Slot A`).
_Sonderfaktor Delta-Updates:_ Da Staging winzig sein kann, ermöglicht der Delta-Patcher eine solide, **realistische 3- bis 5-fache Reduktion**. (Das oft beworbene "18x" reißt beim winzigen RAM Stack-Overflows, daher sind wir auf Micro-Dictionary Patcher wie `heatshrink` limitiert). Zwingende Architektur-Bedingung: Dieser Patcher muss **strictly Forward-Only und Non-Overlapping** abarbeiten. Zudem schützt ein obligatorischer **8-Byte Base-Fingerprint (Truncated SHA-256)** der Zielpartition im Patch-Header vor der Katastrophe, dass ein Delta (z.B. v2->v4) fälschlich an ein v3-Image genäht und das Zielgerät irreparabel gebrickt wird. Passt der Base-Fingerprint des Slot A nicht zum Base-Fingerprint des Patch-Headers, verweigert Stage 1 den Patch sofort.
**Stateful WAL-Checkpointing (Brownout-Sicherheit für In-Place Patches):** Ein Stromausfall beim In-Place Überschreiben löscht das RAM-Wörterbuch ("Sliding Window") des LZSS Decompressors unweigerlich aus. Der Delta-Patch wäre irreversibel gebrochen. Toob-Boot nutzt daher **Stateful WAL-Checkpointing**: Bei jedem Sektor-Commit flusht Stage 1 den aktuellen `compression_context` (das ~4 KB Wörterbuch) zusammen mit dem Hash in eine Backup-Page des WAL-Journals! Nach einem Crash lädt Stage 1 das Wörterbuch exakt aus dem Journal und setzt die In-Place Dekompression nahtlos fort. Nur so existiert echtes stromausfallsicheres In-Place Patching!

---

## 4. ✅ AUFGELÖSTE ARCHITEKTUR-REIBUNGSPUNKTE (Refinement)

### ✅ Auflösung: Satelliten-Abbrüche & Das Recovery-OS (Layer-Trennung)

Ursprünglich schien es, als müsste der Bootloader selbst komplexe Stacks wie WLAN oder LoRa implementieren (was Footprint-Kosten von 100+ KB bedeutet). Die Architektur löst dies über zwei getrennte Wege:

- **Im Bootloader (Schicht 4a - Serial Rescue):** Nur nackte, billige Protokolle (UART, USB-DFU) für das Werk/Labor.
- **Das Recovery-OS Pattern (Zustandsmaschine):** Gerätehersteller, die "over-the-air" Fallbacks brauchen, flashen in einen separaten, kleinen Flash-Slot ein `Recovery-OS` (z.B. minimales Zephyr + WLAN-Stack). Toob-Boot verwaltet einen `Boot_Failure_Counter` im WAL:
  - 1 Crash: Rollback auf App Slot A.
  - Weitere Crashes (Max-Retries erreicht, Slot A auch gebrickt): Stage 1 bootet zwangsweise in die Recovery-Partition. **WICHTIG (Anti-Lockout & Anti-Downgrade):** Der Recovery-Boot nutzt einen total isolierten `SVN_recovery` Counter. Flasht ein Angreifer manuell ein verwundbares, fabrikaltes v1-Recovery via lokalem SPI, fängt das Manifest es ab. Zugleich wehrt die abgetrennte App-SVN nicht mehr fälschlicherweise das rechtmäßige Recovery-OS ab.
  - Erfolgreicher App-Start (Confirm-Flag): Der Boot_Failure_Counter wird strikt auf `0` zurückgesetzt, um zeitlich fernliegende Crashes nicht mit alten Ausfällen zu kumulieren!
  - **Anti-Roach-Motel (Recovery Intent):** Wenn das Recovery-OS die App-Partition erfolgreich über die Luft repariert hat, MUSS es über die HAL ein `RECOVERY_RESOLVED` Intent ins WAL schreiben (bzw. den Fail-Counter resetten). Ohne diesen Schritt würde Stage 1 ewig im Recovery-OS gefangen bleiben!
  - **Mechanischer Anti-Softbrick-Override:** Um OS-Endlosschleifen zu entkommen, bei denen Slot A zwar kryptografisch legitim ist aber funktional crasht (Softbrick), unterstützt Toob-Boot einen hardwaregebundenen Recovery-Pin (`--rec-pin 0`). Ist dieser Pin beim Start der Stage 1 physikalisch "high" (gedrückt), überspringt Stage 1 jede Logik und weicht sofort atomar auf das Recovery-OS / Schicht 4a aus.
  Dieses Recovery-OS bindet via C-Bibliothek den **Toob-Boot OTA-Agenten** ein, kommuniziert über denselben sicheren Kanal (Transfer-Bitmap, WAL) und repariert das Feature-OS.

### ✅ Auflösung: Vendor-Linker vs. Automatisierung (Schicht 5)

Wie generieren wir automatisierte Linker-Scripts für Chips wie den ESP32, die 3 komplett getrennte `.ld` Files (ROM, Peripherals, App) zur Assemblierung benötigen? Anstatt (wie in älteren Tools) SVD-Dateien zur Build-Zeit via teurer LLM-Analyse zu kompilieren, ist der Manifest-Compiler **Plugin-basiert**.
Für jede Chip-Familie existieren winzige "Vendor-Builder-Scripte" (z.B. `vendor_esp32_builder.py`). Diese Pipelines rüsten das herstellerspezifische Vorwissen intern aus. Der Nutzer deklariert nur stumpf im `device.toml` seine Flash-Partitionen, und das ESP-Plugin berechnet und assembliert alle 3 nötigen Linker-Scripte im Hintergrund 100% deterministisch vor dem Cross-Compile.

---

## 5. Developer Experience (DX) & Testing-Architektur

Features, die den Konkurrenzsystemen fehlen und die Entwicklerproduktivität maximieren:

- **Link-Time Mocking (Zero Boilerplate):** Klassische Projekte zerstören ihren C-Code mit tausenden `#ifdef DEV_MODE` Blöcken, um für lokale Tests den eFuse/Krypto-Check auszuhebeln. Toob-Boot untersagt "Architectural Slop". Mocking wird stattdessen absolut unsichtbar über den **GNU Linker (`-Wl,--wrap=symbol`)** durchgeführt. Das produktive Stage-1 Binary wird zu 100% identisch kompiliert, aber der Linker lenkt Zugriffe auf Krypto-Hardware sicher in lokale RAM-Funktionen um, was blitzschnelle Mock-Tests ohne Code-Vergiftung erlaubt.
- **Host-Nativer Sandbox-HAL & Fuzzing:** Der gesamte Bootloader kann auf dem PC (macOS/Linux) als natives Binary kompiliert werden (`$ boot-build --sandbox`). Da das System Host-nativ läuft, erzeugt die CI automatisch **Fuzz-Testing-Targets** (`cargo-fuzz` / `AFL++`) gegen den SUIT-Parser, den Delta-Decoder und Merkle-Verifier. So härten wir die sicherheitskritischen Angriffsflächen, die von außen erreichbar sind, massiv ab, ohne teure Hardware-HIL-Rigs aufzusetzen.
- **Auto-generierte Renode (Emulator) Configs:** Der Manifest-Compiler parst das `device.toml` und generiert daraus automatisch eine exakte `.resc` Datei für den Renode-Simulator. Hardware-Tests in der CI laufen immer deckungsgleich zur physikalischen Flash-Map, ohne manuelle Konfiguration.
- **Der Preflight-Report:** Statt kryptischer C-Fehler erhält der Entwickler _vor_ dem C-Compile einen Report: `Alignment check passed`, `Swap-Move kompatibel`, `Power Guard aktiv: min 3300mV`.
- **Deterministische Fault-Injection:** Über einen speziellen HAL-Mock (`hal_fault_inject.c`) lässt sich in der Sandbox sagen: _"Simuliere einen Brownout exakt nach dem 47. Sektor"_. Die WAL-Heilung kann so innerhalb von Sekunden 1000-fach in CI geprüft werden.
