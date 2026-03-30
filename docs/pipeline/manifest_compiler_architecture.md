# Toob-Boot Manifest Compiler: Programmatische Architektur

Dieses Dokument beschreibt den sequenziellen, programmatischen Ablauf des Toob-Boot Manifest Compilers (`toob_manifest.py`). Es fasst die komplexen Anforderungen der Hardware-Abstraktionen (Fuzzer JSONs, Core-Registry), der Security-Regulatorik (EU-CRA SBOMs) und des Multi-Core Update-Modells in einem linearen System-Flow zusammen.

Dieses Dokument ersetzt die alte, diagramm-lastige Pipeline und dient als absolute Blaupause für die Codelogik des Compilers.

---

## 1. Phase ①: Input Ingestion & Registry Lookup

Der Compiler wird über die CLI gestartet und sammelt alle deklarativen Fakten des Users sowie die empirischen Fakten der Hardware.

### 1.1 CLI-Parsing & Laufzeit-Parameter
Der Compiler `toob_manifest.py` akzeptiert die TOML-Datei plus essentielle Steuer-Flags:
- `manifests/device.toml` (Pflicht)
- `--target-dslc <MAC/UUID>`: Device-Pinning. Bindet das Update exklusiv an dieses Gerät (SUIT `condition-device-identifier`).
- `--dry-run`: Führt Phase 1 bis 4 aus (Validation Report), generiert aber in Phase 5 weder C-Code noch Signaturdateien (Ideal für CI-Pipelines).
- `--output-dir <DIR>`: Überschreibt den Standard-Output (`build/generated/`).
- `--chip-override <CHIP>`: Ignoriert den `chip`-Wert in der TOML. (Genial für CI-Matrix Builds derselben Applikation auf STM32 vs. ESP32).
- `--verbose`: Gibt detaillierte Debug-Entscheidungen aus dem 3-Way Merge (Phase 2) in die Konsole aus.

### 1.2 TOML-Parsing & Syntax-Check
Einlesen der Datei `device.toml` und Validierung gegen das Pydantic-Basis-Schema (Prüfung auf Pflichtfelder wie `vendor`, `chip`, und korrekte Datentypen in den `size`-Strings).

### 1.3 Registry Lookup (Die Wahrheitsfindung)
Der Compiler durchsucht das System nach dem Hardware-Profil für den referenzierten `chip` in exakt dieser Priorität, um die Wahrheit zusammenzusetzen:
1. **Lokale Fuzzer-KI Registry:** `.toob/chips/<chip>_chip.json` (Erzeugt durch Toobfuzzer3 LLM-Extraction).
2. **Core Registry (Fallback):** `toob-manifest/core_chips/<chip>.json` (Die statische Hardcoded-Wahrheit für minimale Hardware-Alignments & Krypto-Cores).

---

## 2. Phase ②: Hydration & 3-Way Merge

Der Compiler fusioniert die gesammelten Wahrheiten zu einem einzigen multidimensionalen State (`hydrated_config`).

### 2.1 The Merge Rule
1. **Lowest Priority:** Core Registry (Statische Eigenschaften wie `flash.write_align=32` oder `crypto.hw_ed25519=True`).
2. **Medium Priority:** Fuzzer Registry (Dynamisch generierte Eigenschaften wie RAM-Boundaries und Boot-Vectors).
3. **Highest Priority:** `device.toml` (Der User überschreibt bewusst System-Defaults).

### 2.2 Auto-Resolution
Alle Felder, die im TOML-Vertrag explizit den Wert `"auto"` besitzen, werden nun durch die kombinierten Fakten intelligent aufgelöst:
- `entry_point = "auto"` → Wird durch den berechneten Slot-A Offset ersetzt.
- `confirm.watchdog_timeout_ms = "auto"` → Bleibt temporär vakant für die Timing-Engine.

---

## 3. Phase ③: Die Computation Engines (Das Herzstück)

### 3.1 Flash Layout Engine (Lock-Step & In-Place Overwrite)
Ermittelt deterministisch Laufzeit-Adressen im Flash ohne Zutun des Users. Toob-Boot untersagt Speicherverschwendung durch redundantes A/B-Swapping (wie bei MCUBoot) und erzwingt ressourceneffizientes In-Place-Mending via Delta-Patches.
1. **Basis-Offsets:** Sequenzielles Aufsummieren von `[partitions.stage0]` und `[partitions.stage1]`. Stage 1 erhält als Spezialfall zwei exakt große Slots (`s1a`, `s1b`), da aktiver XIP-Bootcode sich im Flash nicht über die Luft selbst überschreiben kann.
2. **Primary & Staging Dimensionierung (Multi-Core):** Für **jedes** definierte Image in `[partitions.images.*]` (z.B. `main_os`, `net_core`) erzeugt die Engine den produktiven `Primary Slot` in exakt der angegebenen `size` (z.B. 1536 KB). Anstelle eines identischen B-Slots berechnet die Engine ressourcenschonend isoliert einen zugehörigen `Staging Slot` in Höhe der winzigen deklarierten `staging_size` (für Delta-Patches).
3. **Swap-Puffer (Global):** Die Engine allokiert automatisch am Ende des Flash-Bereichs einen isolierten `Swap-Puffer`. Dessen Größe ist zwingend identisch mit der kapazitiv größten Sektor-Einheit der Hardware (z.B. 128KB beim STM32H7), um den In-Place Schreibvorgang ("Sektor aus RAM in Puffer, Patch anwenden, von Puffer in Primary-Sektor") atomar zu garantieren.
4. **Alignment-Fixes:** Jede ausgerechnete Adresse wird gegen `flash.sector_size` und `flash.app_align` (BootROM-Caching Restriktionen) geprüft und ggf. durch Padding-Bytes korrigiert. 
5. **Auto-Skip Holes:** Ist `auto_skip_holes = true`, ignoriert die Engine kaputte Bereiche aus der `aggregated_scan.json` und rückt die nächste Partition einfach ein paar Offset-Adressen weiter.

### 3.2 RAM Budget Engine
Sammelt den Peak-RAM-Bedarf der kryptografischen und logischen Operationen pro Update-Sequenz:
- `merkle_chunk_size` Hash-RAM + Sibling-Tree Tiefe.
- `delta.window_size` Delta-Dictionary Window (Heatshrink Dekompression).
- WAL (Write-Ahead-Log) Replay-Buffer (Maximalgröße eines Flash-Sektors).
- Crypto-Scratch-Memory (z.B. 2048 Bytes für die Ed25519 Verify Curve).
- **Hard Check:** Die Summe *muss* `>= peak_sram <= ram.bootloader_budget` sein.

### 3.3 Timing Engine
Berechnet die absolute Zeit, die ein Flash-Erase-Vorgang für den größten Slot dauern würde.
- **Formel:** `max(slot_sizes) / flash.sector_size * erase_time_per_sector`.
- **Zweck:** Konfiguriert den Hardware-Watchdog (WDT) dynamisch so, dass er während eines massiven OTA-Swaps in Stage 1 niemals verfrüht das System zurücksetzt.

---

## 4. Phase ④: Preflight Validator Engine (Die "Safety Gates")

Das `hydrated_config` durchläuft nun dutzende knallharte Validierungsregeln. Jede Verletzung führt zum sofortigen **BUILD ABBRUCH** und einem menschlich lesbaren `preflight.txt` Report.

### 4.1 Flash & Memory Alignment
- **`FLASH_001`**: Ist jedes mathematisch generierte Offset ein sauberes Vielfaches von `flash.sector_size`?
- **`FLASH_003`**: Überschreiten alle Partitionen summiert die physische Flash-Grenze (`sum(all_partitions) <= flash.total_size`)?
- **`WRITE_001`**: Ist die WAL-Entry-Size an das physikalische `flash.write_align` des Chips (z.B. 8 Byte bei STM32L4, 32 Byte bei STM32H7) gebunden?

### 4.2 Security & Regulatorik (EU-CRA)
- **`SEC_001`**: Warnung, falls `security.debug.jtag_lock == 'none'` im Production Build.
- **`SEC_003` (CRA-SBOM Constraint)**: Wenn in der TOML `manifest.sbom_path` deklariert ist, prüft der Compiler physisch via `exists_on_disk()`, ob die CycloneDX-JSON Datei erreichbar ist. Fehlt sie, abort.
- **`HW_001`**: Die TOML verlangt `verify_mode="ed25519-hw"`, aber die Core-Registry verneint `crypto.hw_ed25519=false`? Abort.

### 4.3 Multi-Core Integrity
- **`LAYOUT_004` (Lock-Step Staging Space)**: Hat jedes deklarierte Coprozessor-Image under `[partitions.images.*]` auch eine dezidierte `staging_size` eingetragen, die groß genug ist, um atomare Delta-Updates sicher auszuführen?

---

## 5. Phase ⑤: Code-Generation & SUIT-Packaging

Der finale Output des Compilers bereitet das System für das Build-System vor.

### 5.1 Vendor-Plugin Interface (`AbstractVendorPlugin`)
Das System instanziiert das hardware-spezifische Python-Plugin (z.B. `vendors/stm32.py`), welches von `AbstractVendorPlugin` erben muss. 
Jedes Plugin **muss** folgende Methoden implementieren:
1. `validate_config(self, hydrated_config)`: Erlaubt dem Chip, eigene Preflight-Regeln (wie RDP-Level Konsistenz bei STM32) in die Engine zu injizieren.
2. `generate_linker_sections(self, config, layout)`: Übersetzt die abstrakten Layout-Offsets in architektur-verbundene Linker-Sections.
3. `generate_startup_hints(self, config)`: Generiert optionale Header-Dateien oder CSVs (`partition-table.csv` beim ESP32).

### 5.2 Jinja2 Render Engine
Der Compiler rendert alle generischen Code-Fragmente in Form nackter `C`- und `Linker`-Dateien:
1. `build/generated/flash_layout.ld`: Das Memory-Script für den GNU LD Linker.
2. `build/generated/boot_config.h`: Stark getypte Konstanten für den KPL (Kernel Porting Layer).
3. `build/generated/stage0_config.h`: Bootrom-Parameter.
4. `build/generated/platform.resc`: Komplettes Antmicro Renode-Simulations-Setup für CI/CD.

### 5.3 SUIT-Manifest Compilation & Envelope
Der essenzielle kryptologische Security-Wrap des Payloads.
1. Einlesen von `vendor_id` und `class_id` aus der TOML zur Festbindung der Produktlinie.
2. **SBOM-Hashing:** (Sofern in TOML aktiv). Liest die Metadaten-Datei aus `manifest.sbom_path`, hasht sie via SHA-256 und fügt diesen kryptografischen Stempel nativ in das Telemetrie-Feld des SUIT-Manifests ein. Physisches Abstreiten der SBOM nach dem Release ist damit physikalisch unmöglich (CRA Proof).
3. **Target Pinning:** Enthielt die Laufzeit-CLI den Parameter `--target-dslc`, wird die Device-MAC hart als `condition-device-identifier` in das Manifest gebacken.
4. **Signatur:** Das gesamte Manifest (Header, Bedingungen, Hashes) wird über den Private-Key (`ed25519`) blockweise signiert und in die standardisierte `.suit` Datei verschweißt. Bootvorgang ab hier unmanipulierbar.

---

## 6. Fehlerbehandlung & Exit Codes (Der Decision Tree)

Jeder Build-Lauf verlässt den Compiler determiniert. Dies ist die absolute Prioritätskette der Fehler:

### Exit Code 1 (Fatal Errors)
1. **File Not Found:** Wenn die übergebene `device.toml` nicht existiert.
2. **Parse Error:** Wenn die TOML Syntax-Fehler hat (String nicht geschlossen) oder Pflichtfelder (`chip`) fehlen.
3. **Registry Miss:** Wenn der deklarierte Chip weder in den Fuzzer-Blueprints (`.toob/chips/`) noch in der Core-Registry existiert, und `--chip-override` nicht gesetzt ist. *Lösung:* Dokumentation zu Custom-Ports konsultieren.
4. **Validation Error (Phase 4):** Finden die Preflight-Checks auch nur *eine einzige* Inkompatibilität (z.B. `RAM_001` - RAM Budget überschritten), bricht der Compiler vor Phase 5 ab.

### Warning-Handling (Build läuft weiter, Exit Code 0)
- **Unknown Fields:** Gibt es Felder in der TOML, die das Pydantic-Schema nicht kennt, spuckt der Compiler ein Warning aus (`"Did you mean X?"`), baut aber weiter.
- **Validation Warnings:** Regelverletzungen mit "warning"-Schwere (z.B. `SEC_002` offener Rescue-Port) werden rot formatiert, triggern aber keinen Abbruch.

> [!IMPORTANT]
> Fehlerhafte Runs generieren immer einen aufklärenden Ausgabe-Dump im Format:  
> `ERROR [RULE_ID]: [Explanation] \n Fix: [Suggestion]`  
> Dadurch repariert der User Layout-Fehler in Sekunden, anstatt stundenlang Hex-Offsets manuell zu verifizieren.
