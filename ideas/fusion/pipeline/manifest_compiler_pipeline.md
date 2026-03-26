# Toob-Boot Manifest Compiler — Pipeline-Spezifikation

> Dieses Dokument beschreibt die vollständige Verarbeitungspipeline des
> `toob-manifest compile` Befehls. Voraussetzung: Kenntnis der
> `device.toml` Spec und `chip_database.py`.

---

## 1. Gesamtübersicht (High-Level Flow)

```mermaid
flowchart TD
    subgraph INPUT["① Eingabe"]
        TOML["device.toml\n(User-Deklaration)"]
        CHIPDB["chip_database.py\n(Hardware-Wahrheiten)"]
        TEMPLATES["templates/\n(Jinja2)"]
        CDDL["toob_suit.cddl\n(SUIT-Schema)"]
    end

    subgraph PHASE1["② Laden & Fusionieren"]
        PARSE["TOML Parser\n(tomllib)"]
        LOOKUP["Chip-Lookup\nchip → arch/vendor/toolchain"]
        MERGE["Default-Merge\nTOML-Werte überschreiben\nChip-Defaults"]
    end

    subgraph PHASE2["③ Berechnung"]
        LAYOUT["Flash-Layout-Rechner\nOffsets, Alignment,\nSwap/Journal auto-sizing"]
        RAMCALC["RAM-Budget-Rechner\nPeak-SRAM = Stack +\nMerkle + WAL + Crypto + Delta"]
        TIMING["Timing-Rechner\nWDT-Timeout,\nErase-Zeiten, Boot-Timeout"]
        MERKLE["Merkle-Rechner\nBaumtiefe, Sibling-RAM,\nManifest-Overhead"]
    end

    subgraph PHASE3["④ Validierung"]
        VALIDATE["validator.py\n18 Preflight-Regeln"]
        PASS{Bestanden?}
        ERROR["BUILD ABBRUCH\nmit Erklärung +\nLösungsvorschlag"]
    end

    subgraph PHASE4["⑤ Code-Generierung"]
        VENDOR["Vendor-Plugin\n(esp32.py / stm32.py / nrf.py)"]
        RENDER["Jinja2 Renderer"]
    end

    subgraph OUTPUT["⑥ Ausgabe"]
        LD["flash_layout.ld\n(Linker-Script)"]
        CONFIG_H["boot_config.h\n(C-Header)"]
        S0_H["stage0_config.h\n(Stage-0 Config)"]
        RESC["platform.resc\n(Renode-Config)"]
        REPORT["preflight.txt\n(Human-Readable Report)"]
        CMAKE_VARS["cmake_vars.txt\n(TOOB_ARCH, TOOB_VENDOR,\nTOOB_CHIP, TOOB_TOOLCHAIN)"]
    end

    TOML --> PARSE
    PARSE --> LOOKUP
    CHIPDB --> LOOKUP
    LOOKUP --> MERGE
    MERGE --> LAYOUT
    MERGE --> RAMCALC
    MERGE --> TIMING
    MERGE --> MERKLE
    LAYOUT --> VALIDATE
    RAMCALC --> VALIDATE
    TIMING --> VALIDATE
    MERKLE --> VALIDATE
    VALIDATE --> PASS
    PASS -- "Ja" --> VENDOR
    PASS -- "Nein" --> ERROR
    VENDOR --> RENDER
    TEMPLATES --> RENDER
    RENDER --> LD
    RENDER --> CONFIG_H
    RENDER --> S0_H
    RENDER --> RESC
    RENDER --> CMAKE_VARS
    VALIDATE --> REPORT
    CDDL -.-> CONFIG_H
```

---

## 2. Phase ② Detail: Laden & Fusionieren

```mermaid
flowchart TD
    TOML_RAW["device.toml\n(Rohdaten)"]

    TOML_RAW --> SCHEMA_CHECK["Schema-Validierung\n• Pflichtfelder vorhanden?\n• Typen korrekt?\n• Unbekannte Felder?"]

    SCHEMA_CHECK -- "chip = 'esp32s3'" --> DB_LOOKUP["chip_database.py\nLookup"]

    DB_LOOKUP --> CHIP_RECORD["Chip-Record\n─────────────────\narch: xtensa\nvendor: esp\ntoolchain: esp-idf\nflash.sector_size: 4096\nflash.write_align: 4\nflash.app_align: 65536\nram.total: 524288\ncrypto.hw_sha256: true\nconfirm.default: rtc_ram\n..."]

    CHIP_RECORD --> THREE_WAY["Drei-Wege-Merge\n─────────────────\n① Chip-Default\n② TOML-Override\n③ Computed Value"]

    THREE_WAY --> MERGED["Fusioniertes Config-Objekt\n(Vollständig aufgelöst,\nkeine 'auto'-Werte mehr)"]

    subgraph MERGE_RULES["Merge-Regeln (Priorität)"]
        direction LR
        R1["TOML explizit gesetzt\n→ TOML gewinnt immer"]
        R2["TOML = 'auto' oder leer\n→ Chip-Default greift"]
        R3["Computed Values\n(Offsets, WDT-Timeout)\n→ werden berechnet,\nnicht aus DB/TOML"]
    end

    THREE_WAY -.-> MERGE_RULES
```

### Merge-Beispiel (ESP32-S3)

```mermaid
flowchart LR
    subgraph TOML_IN["device.toml sagt:"]
        T1["flash.sector_size = ∅\n(nicht gesetzt)"]
        T2["flash.total_size = '8MB'"]
        T3["confirm.mechanism = 'auto'"]
        T4["ram.bootloader_budget = '32KB'"]
    end

    subgraph DB_IN["chip_database sagt:"]
        D1["flash.sector_size = 4096"]
        D2["flash.total_size = ∅\n(weiß nur max)"]
        D3["confirm.default = 'rtc_ram'"]
        D4["ram.default_budget = 32768"]
    end

    subgraph RESULT["Fusioniertes Ergebnis:"]
        M1["flash.sector_size = 4096\n← Chip-Default"]
        M2["flash.total_size = 8388608\n← TOML (8MB parsed)"]
        M3["confirm.mechanism = 'rtc_ram'\n← 'auto' aufgelöst"]
        M4["ram.bootloader_budget = 32768\n← TOML explizit = Chip-Default"]
    end

    T1 --> M1
    D1 --> M1
    T2 --> M2
    T3 --> M3
    D3 --> M3
    T4 --> M4
```

---

## 3. Phase ② Detail: Flash-Layout-Berechnung

```mermaid
flowchart TD
    START["Fusioniertes Config-Objekt"]

    START --> COLLECT["Partitions-Liste sammeln\n(Reihenfolge aus TOML)"]

    COLLECT --> FIXED["Feste Partitionen einfügen:\n• stage0 (User-Size)\n• stage1a (User-Size)\n• stage1b (= stage1a.size, auto)"]

    FIXED --> APP_ALIGN["App-Partition ausrichten:\noffset = next_multiple_of(\n  current_offset,\n  chip.flash.app_align\n)"]

    APP_ALIGN --> USER_PARTS["User-Partitionen platzieren:\n• app (aligned)\n• staging\n• recovery (wenn enabled)\n• nvs (wenn enabled)"]

    USER_PARTS --> AUTO_PARTS["Auto-Partitionen berechnen:\n• journal_size = 2 × sector_size\n  + bitmap_size(app.size, merkle.chunk_size)\n  + 512  (TMR + Erase-Counter)\n• swap_buffer = max(sector_sizes)"]

    AUTO_PARTS --> PLACE["Alle Offsets sequenziell setzen:\noffset[n] = offset[n-1] + size[n-1]\nAusgerichtet auf sector_size"]

    PLACE --> TOTAL_CHECK{"Gesamt ≤\nflash.total_size?"}

    TOTAL_CHECK -- "Ja" --> BANK_CHECK{"Dual-Bank?\nPartitionen innerhalb\nBank-Grenzen?"}
    TOTAL_CHECK -- "Nein" --> FAIL_FLASH["ERROR FLASH_003:\nPartitions exceed flash\ncapacity"]

    BANK_CHECK -- "Ja / N/A" --> LAYOUT_DONE["Flash-Layout fertig\n(Offset-Tabelle)"]
    BANK_CHECK -- "Nein" --> FAIL_BANK["ERROR HW_003:\nPartition crosses\nbank boundary"]

    subgraph BITMAP_CALC["Bitmap-Größenberechnung"]
        BC1["total_chunks = app.size / merkle.chunk_size"]
        BC2["bitmap_bytes = ceil(total_chunks / 8)"]
        BC3["bitmap_size = max(bitmap_bytes, sector_size)\n(muss mindestens 1 Sektor sein)"]
    end

    AUTO_PARTS -.-> BITMAP_CALC
```

### Flash-Layout-Ergebnis (Datenstruktur)

```mermaid
classDiagram
    class FlashLayout {
        +List~Partition~ partitions
        +int total_used
        +int total_free
        +float usage_percent
        +validate() bool
        +to_linker_script() str
        +to_c_header() str
        +to_renode_config() str
    }

    class Partition {
        +str name
        +int offset
        +int size
        +int alignment
        +bool auto_calculated
        +str purpose
    }

    FlashLayout "1" --> "*" Partition

    note for FlashLayout "Immutable nach Berechnung.\nWird an Renderer + Validator übergeben."

    note for Partition "offset wird NIE vom User gesetzt.\nImmer berechnet aus Vorgänger + Alignment."
```

---

## 4. Phase ③ Detail: RAM-Budget-Berechnung

```mermaid
flowchart TD
    CONFIG["Fusioniertes Config"]

    CONFIG --> STACK["stack_size\n(aus TOML oder Default 4096)"]
    CONFIG --> MERKLE_RAM["Merkle-Chunk RAM:\nmerkle.chunk_size\n(1 Chunk muss komplett ins RAM)"]
    CONFIG --> SIBLING["Merkle-Sibling RAM:\ntree_depth = ceil(log2(\n  app.size / merkle.chunk_size\n))\nsibling_ram = tree_depth × 32"]
    CONFIG --> WAL_BUF["WAL-Buffer RAM:\nmax(flash.sector_size, 4096)\n(1 Sektor für Replay-Writes)"]
    CONFIG --> CRYPTO["Crypto-Scratch RAM:\n~2048 B (Ed25519 Verify)\n+512 B (SHA-256 Context)"]
    CONFIG --> DELTA["Delta-Dictionary RAM:\n2^window_size + 2^lookahead\n(heatshrink Parameter)"]
    CONFIG --> CHECKPOINT["Checkpoint-Buffer RAM:\n(Wenn delta.checkpoint = 'sector')\n= heatshrink context (~window_size B)"]

    STACK --> SUM["Σ Peak-SRAM"]
    MERKLE_RAM --> SUM
    SIBLING --> SUM
    WAL_BUF --> SUM
    CRYPTO --> SUM
    DELTA --> SUM
    CHECKPOINT --> SUM

    SUM --> COMPARE{"peak_sram ≤\nbootloader_budget?"}

    COMPARE -- "Ja" --> OK["✓ RAM Budget OK\nUsage: {peak} / {budget}\n({percent}%)"]
    COMPARE -- "Nein" --> SUGGEST["✗ ERROR RAM_001\n\nVorschläge:\n• merkle.chunk_size: 4KB → 2KB\n• delta.window_size: 8 → 7\n• bootloader_budget erhöhen\n  (wenn Chip es hergibt)"]
```

---

## 5. Phase ④ Detail: Validierung (validator.py)

```mermaid
flowchart TD
    INPUT["Flash-Layout +\nRAM-Budget +\nTiming-Werte +\nConfig-Objekt"]

    INPUT --> CAT1

    subgraph CAT1["Flash-Alignment-Checks"]
        F001["FLASH_001\nJede Partition\nsector-aligned?"]
        F002["FLASH_002\nApp-Partition\napp_align-aligned?"]
        F003["FLASH_003\nGesamt ≤ Flash?"]
        F004["FLASH_004\nMerkle chunk ≤\nsector_size?"]
    end

    subgraph CAT2["Write-Alignment-Checks"]
        W001["WRITE_001\nWAL-Entry-Size\n% write_align == 0?"]
    end

    subgraph CAT3["RAM-Checks"]
        R001["RAM_001\nPeak SRAM ≤\nbudget?"]
        R002["RAM_002\nnoinit + budget ≤\ntotal RAM?"]
    end

    subgraph CAT4["Stage-0-Checks"]
        S001["S0_001\nStage0 size ≥\nmin für verify_mode?"]
    end

    subgraph CAT5["Security-Checks"]
        SEC1["SEC_001\nJTAG locked?"]
        SEC2["SEC_002\nRescue auth\nenabled?"]
    end

    subgraph CAT6["Hardware-Kompatibilität"]
        HW1["HW_001\ned25519-hw:\nChip hat HW-Crypto?"]
        HW2["HW_002\nbackup_register:\nVBAT vorhanden?"]
        HW3["HW_003\nDual-Bank:\nBank-Grenzen OK?"]
    end

    subgraph CAT7["Chip-spezifisch"]
        H7["H7_001\nSTM32H7:\nWDT ≥ 8000ms?"]
        MC["MC_001\nMulti-Core:\nAtomic Groups\nvollständig?"]
    end

    CAT1 --> COLLECT
    CAT2 --> COLLECT
    CAT3 --> COLLECT
    CAT4 --> COLLECT
    CAT5 --> COLLECT
    CAT6 --> COLLECT
    CAT7 --> COLLECT

    COLLECT["Ergebnisse sammeln"]

    COLLECT --> HAS_ERROR{"Errors\nvorhanden?"}
    COLLECT --> HAS_WARN{"Nur\nWarnings?"}

    HAS_ERROR -- "Ja" --> ABORT["BUILD ABBRUCH\n─────────────\nAlle Errors + Warnings\nausgeben mit:\n• Rule-ID\n• Erklärung\n• Lösungsvorschlag\n• Betroffener TOML-Pfad"]

    HAS_WARN -- "Ja" --> WARN_OUT["Warnings ausgeben\n(Build läuft weiter)"]
    HAS_ERROR -- "Nein" --> PASS_CHECK
    HAS_WARN -- "Nein" --> PASS_CHECK

    WARN_OUT --> PASS_CHECK["✓ Validierung bestanden"]
```

---

## 6. Phase ⑤ Detail: Vendor-Plugin & Code-Generierung

```mermaid
flowchart TD
    VALIDATED["Validiertes Config +\nFlash-Layout +\nRAM-Budget"]

    VALIDATED --> SELECT{"vendor_family?"}

    SELECT -- "esp" --> ESP["vendors/esp32.py"]
    SELECT -- "stm32" --> STM["vendors/stm32.py"]
    SELECT -- "nrf" --> NRF["vendors/nrf.py"]
    SELECT -- "sandbox" --> GEN["vendors/generic.py"]

    subgraph ESP_WORK["ESP32-Plugin"]
        ESP --> ESP1["Boot-Header generieren\n(Flashmode, Freq, Size)"]
        ESP1 --> ESP2["3 Linker-Scripts assemblieren:\n• memory_regions.ld\n  (IRAM, DRAM, Flash-Map)\n• sections.ld\n  (.text, .rodata, .data, .bss)\n• toob_partitions.ld\n  (Toob-Boot Slot-Offsets)"]
        ESP2 --> ESP3["Partition-Table CSV\ngenerieren\n(ESP-IDF kompatibel)"]
    end

    subgraph STM_WORK["STM32-Plugin"]
        STM --> STM1["Bank-Konfiguration\nberechnen\n(Single vs Dual-Bank)"]
        STM1 --> STM2["Linker-Script:\n• FLASH origin + length\n  (pro Bank wenn dual)\n• RAM origin + length\n• .noinit Section\n• Vektor-Tabelle Offset"]
        STM2 --> STM3["Option-Bytes Validierung:\n• RDP Level Check\n• DUALBANK Bit\n• nSWAP_BANK"]
    end

    subgraph NRF_WORK["nRF-Plugin"]
        NRF --> NRF1["Multi-Core Check:\nnRF5340 → Net-Core\nFlash separat addressieren"]
        NRF1 --> NRF2["Linker-Script:\n• App-Core Flash-Map\n• Net-Core Flash-Map\n  (separates Binary!)\n• UICR/FICR Adressen"]
        NRF2 --> NRF3["APPROTECT Config\ngenerieren"]
    end

    ESP_WORK --> JINJA
    STM_WORK --> JINJA
    NRF_WORK --> JINJA
    GEN --> JINJA

    JINJA["Jinja2 Template-Engine"]

    subgraph JINJA_TEMPLATES["Templates"]
        JT1["flash_layout.ld.j2\n─────────────────\nMEMORY {\n  STAGE0 : ORIGIN = {{s0.offset}},\n           LENGTH = {{s0.size}}\n  STAGE1 : ORIGIN = {{s1a.offset}},\n           LENGTH = {{s1.size}}\n  APP    : ORIGIN = {{app.offset}},\n           LENGTH = {{app.size}}\n  ...\n}"]
        JT2["boot_config.h.j2\n─────────────────\n#define BOOT_FLASH_SECTOR_SIZE {{sector_size}}\n#define BOOT_FLASH_WRITE_ALIGN {{write_align}}\n#define BOOT_APP_OFFSET        {{app.offset}}\n#define BOOT_MERKLE_CHUNK_SIZE {{merkle.chunk}}\n#define BOOT_MERKLE_DEPTH      {{merkle.depth}}\n#define BOOT_WDT_TIMEOUT_MS    {{wdt_timeout}}\n..."]
        JT3["platform.resc.j2\n─────────────────\nmachine LoadPlatformDescription\n  @platforms/{{chip}}.repl\nsysbus LoadBinary\n  @stage0.bin {{s0.offset}}\nsysbus LoadBinary\n  @stage1.bin {{s1a.offset}}\n..."]
    end

    JINJA --> JT1
    JINJA --> JT2
    JINJA --> JT3

    JT1 --> OUT_LD["build/generated/\nflash_layout.ld"]
    JT2 --> OUT_H["build/generated/\nboot_config.h +\nstage0_config.h"]
    JT3 --> OUT_RESC["build/generated/\nplatform.resc"]

    VALIDATED --> PREFLIGHT["Preflight-Report\ngenerieren\n(Human-Readable)"]
    PREFLIGHT --> OUT_REPORT["build/generated/\npreflight.txt"]

    VALIDATED --> CMAKE_OUT["CMake-Variablen\nexportieren"]
    CMAKE_OUT --> OUT_CMAKE["build/generated/\ntoob_config.cmake\n─────────────────\nset(TOOB_ARCH xtensa)\nset(TOOB_VENDOR esp)\nset(TOOB_CHIP esp32s3)\nset(TOOB_TOOLCHAIN_FILE\n  cmake/toolchain-xtensa-esp.cmake)"]
```

---

## 7. Gesamter CLI-Aufruf (Sequenzdiagramm)

```mermaid
sequenceDiagram
    actor Dev as Entwickler
    participant CLI as toob-manifest compile
    participant Parser as TOML Parser
    participant DB as chip_database
    participant Merger as Config Merger
    participant Layout as Layout-Rechner
    participant RAM as RAM-Rechner
    participant Timing as Timing-Rechner
    participant Val as Validator
    participant Plugin as Vendor-Plugin
    participant Jinja as Jinja2 Renderer
    participant FS as Dateisystem

    Dev->>CLI: $ toob-manifest compile\nmanifests/dabox_iot_powerbank.toml

    CLI->>Parser: parse(device.toml)
    Parser-->>CLI: raw_config{}

    CLI->>DB: lookup(chip="esp32s3")
    DB-->>CLI: chip_record{}

    CLI->>Merger: merge(raw_config, chip_record)
    Note over Merger: TOML überschreibt Defaults\n"auto" wird aufgelöst\nGrössen-Strings → Bytes
    Merger-->>CLI: merged_config{}

    CLI->>Layout: calculate(merged_config)
    Note over Layout: Offsets berechnen\nAlignment prüfen\nSwap/Journal auto-sizing
    Layout-->>CLI: flash_layout{}

    CLI->>RAM: calculate(merged_config, flash_layout)
    Note over RAM: Peak-SRAM summieren\nMerkle + WAL + Crypto + Delta
    RAM-->>CLI: ram_budget{}

    CLI->>Timing: calculate(merged_config, flash_layout)
    Note over Timing: WDT-Timeout aus\nErase-Zeiten berechnen
    Timing-->>CLI: timing{}

    CLI->>Val: validate_all(merged_config,\nflash_layout, ram_budget, timing)

    alt Errors gefunden
        Val-->>CLI: errors[]
        CLI-->>Dev: ✗ BUILD ABBRUCH\n  FLASH_002: App not 64KB-aligned\n  RAM_001: Peak 38KB > budget 32KB
    else Nur Warnings oder OK
        Val-->>CLI: warnings[], pass=true

        CLI->>Plugin: select(vendor="esp")
        CLI->>Plugin: generate(merged_config, flash_layout)
        Note over Plugin: ESP32-spezifische\nLinker-Sections,\nPartition-Table CSV
        Plugin-->>CLI: vendor_artifacts{}

        CLI->>Jinja: render_all(templates/, merged_config,\nflash_layout, vendor_artifacts)
        Jinja-->>CLI: rendered_files{}

        CLI->>FS: write(build/generated/flash_layout.ld)
        CLI->>FS: write(build/generated/boot_config.h)
        CLI->>FS: write(build/generated/stage0_config.h)
        CLI->>FS: write(build/generated/platform.resc)
        CLI->>FS: write(build/generated/toob_config.cmake)
        CLI->>FS: write(build/generated/preflight.txt)

        CLI-->>Dev: ✓ Preflight Report\n  (alle Checks + Layout-Tabelle)\n\n BUILD READY.
    end
```

---

## 8. Vendor-Plugin Interface (Klassendiagramm)

```mermaid
classDiagram
    class VendorPlugin {
        <<abstract>>
        +name: str
        +supported_chips: List~str~
        +validate_config(config) List~Warning~
        +generate_linker_sections(config, layout) str
        +generate_startup_hints(config) dict
        +get_toolchain_file() str
        +get_flash_tool_command(binary, port) str
    }

    class Esp32Plugin {
        +name = "esp"
        +supported_chips = [esp32, esp32s2, esp32s3,\nesp32c3, esp32c6, esp32h2]
        +generate_linker_sections()
        +generate_partition_csv()
        +get_flash_tool_command()
    }

    class Stm32Plugin {
        +name = "stm32"
        +supported_chips = [stm32l4, stm32h7,\nstm32u5, stm32f4, stm32g4, ...]
        +generate_linker_sections()
        +validate_option_bytes()
        +check_dual_bank_layout()
    }

    class NrfPlugin {
        +name = "nrf"
        +supported_chips = [nrf52832, nrf52840,\nnrf5340]
        +generate_linker_sections()
        +generate_netcore_layout()
        +validate_approtect()
    }

    class GenericPlugin {
        +name = "generic"
        +supported_chips = [sandbox, custom]
        +generate_linker_sections()
    }

    VendorPlugin <|-- Esp32Plugin
    VendorPlugin <|-- Stm32Plugin
    VendorPlugin <|-- NrfPlugin
    VendorPlugin <|-- GenericPlugin

    note for VendorPlugin "Neue Vendors: Erbe VendorPlugin,\nimplementiere 4 Methoden,\nregistriere in plugin_registry."

    note for Esp32Plugin "Generiert zusätzlich:\n• ESP-IDF partition CSV\n• Boot-Header mit\n  flashmode/freq/size"

    note for Stm32Plugin "Prüft zusätzlich:\n• RDP-Level Konsistenz\n• Bank-Boundary Crossing\n• OTFDEC Kompatibilität"
```

---

## 9. Datenfluss: Was kommt rein, was geht raus

```mermaid
flowchart LR
    subgraph IN["Eingabedateien"]
        direction TB
        I1["device.toml"]
        I2["chip_database.py"]
        I3["templates/*.j2"]
        I4["vendors/*.py"]
    end

    subgraph COMPILER["toob-manifest compile"]
        direction TB
        C1["Parse"]
        C2["Merge"]
        C3["Calculate"]
        C4["Validate"]
        C5["Generate"]
    end

    subgraph OUT_BUILD["build/generated/"]
        direction TB
        O1["flash_layout.ld\n→ CMake include"]
        O2["boot_config.h\n→ #include in core/"]
        O3["stage0_config.h\n→ #include in stage0/"]
        O4["toob_config.cmake\n→ CMake include\n(TOOB_ARCH, TOOB_VENDOR,\nTOOB_CHIP, Toolchain-File)"]
    end

    subgraph OUT_TEST["build/generated/ (Test)"]
        direction TB
        O5["platform.resc\n→ Renode Simulation"]
        O6["preflight.txt\n→ CI Log / Review"]
    end

    subgraph OUT_ESP["build/generated/ (ESP only)"]
        direction TB
        O7["partitions.csv\n→ ESP-IDF kompatibel"]
    end

    IN --> COMPILER
    COMPILER --> OUT_BUILD
    COMPILER --> OUT_TEST
    COMPILER --> OUT_ESP
```

---

## 10. Fehlerbehandlung: Entscheidungsbaum

```mermaid
flowchart TD
    START["toob-manifest compile device.toml"]

    START --> F1{"device.toml\nexistiert?"}
    F1 -- "Nein" --> E1["ERROR: File not found.\nUsage: toob-manifest compile <path>"]

    F1 -- "Ja" --> F2{"TOML\nsyntaktisch korrekt?"}
    F2 -- "Nein" --> E2["ERROR: TOML parse error at line N.\nDetails: {toml_error_message}"]

    F2 -- "Ja" --> F3{"device.chip\ngesetzt?"}
    F3 -- "Nein" --> E3["ERROR: Missing required field 'device.chip'.\nAvailable chips: esp32s3, stm32l4, nrf52840, ..."]

    F3 -- "Ja" --> F4{"chip in\nchip_database?"}
    F4 -- "Nein" --> E4["ERROR: Unknown chip '{chip}'.\nKnown chips: {list}.\nFor custom chips, set architecture/vendor/toolchain\nmanually. See docs/PORTING.md"]

    F4 -- "Ja" --> F5{"Unbekannte\nTOML-Felder?"}
    F5 -- "Ja" --> W1["WARNING: Unknown field '{field}'.\nDid you mean '{suggestion}'?\n(Build continues)"]

    F5 -- "Nein" --> F6["Merge + Calculate + Validate"]
    W1 --> F6

    F6 --> F7{"Validation\nErrors?"}
    F7 -- "Ja" --> E5["ERROR(s) ausgeben:\n─────────────────────\nFLASH_002: App partition at 0x00E100\nnot aligned to 65536 (required for esp32s3).\nFix: Remove explicit offset or set to 0x010000.\n─────────────────────\nRAM_001: Peak SRAM 38912 B exceeds budget\n32768 B. Reduce merkle.chunk_size to 2KB.\n─────────────────────\nExit code: 1"]

    F7 -- "Nein" --> F8{"Validation\nWarnings?"}
    F8 -- "Ja" --> W2["WARNING(s) ausgeben\n(Build läuft weiter)"]
    F8 -- "Nein" --> OK
    W2 --> OK

    OK["✓ Generate + Write Files\nExit code: 0"]
```

---

## Anhang: CLI-Interface

```
USAGE:
  toob-manifest compile <manifest.toml> [OPTIONS]

OPTIONS:
  --output-dir <DIR>     Output-Verzeichnis (Default: build/generated/)
  --dry-run              Nur validieren, nichts schreiben
  --verbose              Alle Merge-Entscheide anzeigen (Debug)
  --format <FMT>         Preflight-Output: text | json | github-actions
  --chip-override <CHIP> Chip überschreiben (für CI-Matrix-Builds)

EXAMPLES:
  # Standard-Build
  toob-manifest compile manifests/dabox_iot_powerbank.toml

  # Nur validieren (CI-Check)
  toob-manifest compile manifests/generic_stm32h7.toml --dry-run

  # CI-Matrix: gleiche TOML, verschiedene Chips
  toob-manifest compile manifests/generic.toml --chip-override esp32c3
  toob-manifest compile manifests/generic.toml --chip-override nrf52840

  # GitHub Actions Annotations
  toob-manifest compile device.toml --format github-actions
  # Gibt ::error:: und ::warning:: Annotations aus

EXIT CODES:
  0  Erfolg (ggf. mit Warnings)
  1  Validierungsfehler (Errors)
  2  Datei nicht gefunden / Parse-Fehler
```
