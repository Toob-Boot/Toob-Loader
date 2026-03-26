# Toob-Boot — Projekt-Struktur & Repository-Blueprint

> Jede Datei hat einen Grund. Nichts ist Platzhalter.

---

## Verzeichnisbaum

```
toob-boot/
│
├── .github/                              # CI/CD + Community-Templates
│   ├── workflows/
│   │   ├── ci.yml                        # Matrix: [sandbox, esp32s3, stm32l4, nrf52840]
│   │   ├── nightly-fuzz.yml              # 8h AFL++ gegen Parser-Targets
│   │   └── release.yml                   # Signierte Releases + PyPI publish
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── feature_request.yml
│   │   └── new_chip_port.yml             # Checklist für Community-Ports
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── CODEOWNERS
│   └── SECURITY.md
│
├── docs/
│   ├── ARCHITECTURE.md                   # Die Spec (Abschnitte 1-5)
│   ├── PORTING.md                        # 10-Schritt-Checklist
│   ├── MANIFEST_REFERENCE.md             # Alle device.toml Felder
│   ├── SECURITY_MODEL.md                 # Threat Model + Trust Boundaries
│   ├── HAL_LAYERING.md                   # Arch vs Vendor vs Chip erklärt
│   ├── BOOT_FLOW.md                      # Sequenzdiagramm
│   ├── WAL_INTERNALS.md                  # Ring-Buffer, CRC, TMR, ABI
│   └── diagrams/
│       ├── boot_flow.mermaid
│       ├── flash_layout.svg
│       └── hal_layers.svg
│
│ # ════════════════════════════════════════════════════════
│ # CORE — Null Hardware-Abhängigkeit, null Boilerplate
│ # ════════════════════════════════════════════════════════
│
├── core/
│   ├── include/
│   │   ├── boot_hal.h                    # 6 HAL-Trait-Structs + boot_platform_t
│   │   ├── boot_types.h                  # Enums, Error-Codes, Image-Header
│   │   ├── boot_config.h                 # ← GENERIERT
│   │   ├── boot_journal.h
│   │   ├── boot_merkle.h
│   │   ├── boot_suit.h                   # ← GENERIERT (zcbor)
│   │   ├── boot_delta.h
│   │   └── boot_diag.h
│   │
│   ├── boot_main.c                       # Entry → State-Machine → Jump
│   ├── boot_state.c                      # IDLE/STAGING/TESTING/CONFIRMED
│   ├── boot_journal.c                    # WAL, CRC-16, TMR, ABI-Migration
│   ├── boot_verify.c                     # Hash + Signatur (→ crypto_hal)
│   ├── boot_merkle.c                     # Chunk-weise Verifikation
│   ├── boot_swap.c                       # In-Place-Overwrite via Swap-Buffer
│   ├── boot_delta.c                      # Forward-Only Patch-Applier
│   ├── boot_suit.c                       # ← GENERIERT (zcbor aus CDDL)
│   ├── boot_rollback.c                   # SVN, Failure-Counter, Recovery
│   ├── boot_confirm.c                    # Reset-Reason + confirm_hal
│   ├── boot_diag.c                       # JSON Boot-Log + Timing-IDS
│   ├── boot_energy.c                     # Battery-Guard (optional)
│   └── boot_multiimage.c                 # Atomic Update Groups
│
│ # ════════════════════════════════════════════════════════
│ # STAGE 0 — Eigenes Binary, eigener Linker-Script
│ # ════════════════════════════════════════════════════════
│
├── stage0/
│   ├── stage0_main.c                     # Reset → Hash/Verify → Jump S1a|S1b
│   ├── stage0_hash.c                     # SHA-256 Software (~1.5 KB)
│   ├── stage0_verify.c                   # Optional Ed25519 (verify_mode)
│   ├── stage0_otp.c                      # OTP/eFuse Key-Lesen
│   ├── stage0_boot_pointer.c             # S1a oder S1b?
│   └── include/
│       └── stage0_config.h               # ← GENERIERT
│
│ # ════════════════════════════════════════════════════════
│ # HAL — Drei Ebenen: Architektur → Vendor → Chip
│ # ════════════════════════════════════════════════════════
│
├── hal/
│   │
│   ├── include/                          # ── HAL-interne Shared Header ──
│   │   ├── hal_internal.h                # Gemeinsame Macros/Helpers
│   │   └── hal_deinit.h                  # Deinit-Checkliste
│   │
│   ├── arch/                             # ── EBENE 1: CPU-Architektur ──
│   │   │                                 # Was die ISA vorgibt, unabhängig
│   │   │                                 # vom Hersteller.
│   │   │
│   │   ├── arm_cortex_m/                 # Für: STM32, nRF52, nRF5340, NXP
│   │   │   ├── arch_systick.c            # SysTick Timer (clock_hal partial)
│   │   │   ├── arch_nvic.c               # Interrupt-Disable, Priority
│   │   │   ├── arch_scb.c                # VTOR, System-Reset
│   │   │   ├── arch_deinit.c             # Generischer Peripheral-Cleanup
│   │   │   └── include/
│   │   │       └── arch_cortex_m.h       # CMSIS Core Definitionen
│   │   │
│   │   ├── riscv32/                      # Für: ESP32-C3, ESP32-C6, GD32V
│   │   │   ├── arch_timer.c              # mtime/mtimecmp
│   │   │   ├── arch_trap.c               # Trap-Handler, mcause
│   │   │   └── include/
│   │   │       └── arch_riscv.h
│   │   │
│   │   └── xtensa/                       # Für: ESP32, ESP32-S2, ESP32-S3
│   │       ├── arch_timer.c              # CCOUNT Register
│   │       ├── arch_interrupt.c          # Interrupt-Matrix
│   │       └── include/
│   │           └── arch_xtensa.h
│   │
│   ├── vendor/                           # ── EBENE 2: Hersteller-Familie ──
│   │   │                                 # Identisch über Chip-Varianten
│   │   │                                 # desselben Herstellers.
│   │   │
│   │   ├── stm32/                        # Geteilt: L4, H7, U5, F4, ...
│   │   │   ├── vendor_flash.c            # Unlock/Lock, Page-Erase, DWORD-Write
│   │   │   ├── vendor_iwdg.c             # Independent Watchdog
│   │   │   ├── vendor_backup_reg.c       # Backup-Register (confirm_hal)
│   │   │   ├── vendor_rcc_reset.c        # RCC_CSR → Reset-Reason-Enum
│   │   │   ├── vendor_console.c          # USART (konfigurierbar per Pin/Instanz)
│   │   │   └── include/
│   │   │       ├── stm32_flash_cfg.h     # Config-Struct für Flash-Parametrisierung
│   │   │       └── stm32_common.h        # LL-Includes + gemeinsame Defines
│   │   │
│   │   ├── nrf/                          # Geteilt: nRF52832, nRF52840, nRF5340
│   │   │   ├── vendor_nvmc.c             # Flash-Controller
│   │   │   ├── vendor_cc3xx.c            # CC310/CC312 Ed25519+SHA (runtime detect)
│   │   │   ├── vendor_uarte.c            # UART Console
│   │   │   ├── vendor_retained_ram.c     # Confirm via Retained-RAM
│   │   │   ├── vendor_resetreas.c        # RESETREAS → Reset-Reason-Enum
│   │   │   └── include/
│   │   │       └── nrf_common.h
│   │   │
│   │   └── esp/                          # Geteilt: ESP32, S2, S3, C3, C6
│   │       ├── vendor_spi_flash.c        # esp_flash API Wrapper
│   │       ├── vendor_rtc_mem.c          # RTC-Fast-Memory (confirm_hal)
│   │       ├── vendor_sha_hw.c           # Hardware-SHA-256
│   │       ├── vendor_rwdt.c             # RTC Watchdog
│   │       ├── vendor_reset_reason.c     # RTC_CNTL → Reset-Reason-Enum
│   │       ├── vendor_console.c          # UART0
│   │       └── include/
│   │           └── esp_common.h
│   │
│   └── chips/                            # ── EBENE 3: Chip-Adapter ──
│       │                                 # Nur Konfiguration + Wiring.
│       │                                 # Typisch: ~90 LOC total pro Chip.
│       │
│       ├── esp32s3/                       # Xtensa + esp vendor
│       │   ├── chip_config.h             # Flash-Map, Pin-Belegung, RAM-Größen
│       │   ├── chip_platform.c           # Wiring: arch/xtensa + vendor/esp → Traits
│       │   └── startup.c                 # Cache, Clocks, JTAG-SW-Sperre
│       │
│       ├── esp32c3/                       # RISC-V + esp vendor (!)
│       │   ├── chip_config.h
│       │   ├── chip_platform.c           # Wiring: arch/riscv32 + vendor/esp → Traits
│       │   └── startup.c
│       │
│       ├── esp32c6/
│       │   ├── chip_config.h
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── stm32l4/                       # Cortex-M + stm32 vendor
│       │   ├── chip_config.h             # 2KB Sektoren, Dual-Bank
│       │   ├── chip_platform.c           # Wiring: arch/arm_cortex_m + vendor/stm32
│       │   └── startup.c
│       │
│       ├── stm32h7/
│       │   ├── chip_config.h             # 128KB Sektoren, OTFDEC
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── nrf52840/                      # Cortex-M + nrf vendor
│       │   ├── chip_config.h             # CC310, 4KB Pages
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── nrf5340/                       # Multi-Core
│       │   ├── chip_config.h
│       │   ├── chip_platform.c
│       │   ├── chip_ipc.c               # Inter-Processor-Comm
│       │   └── startup.c
│       │
│       └── sandbox/                       # Host-Native (kein arch/vendor)
│           ├── chip_config.h
│           ├── chip_platform.c           # Direkt POSIX → Traits
│           ├── chip_fault_inject.c
│           ├── main.c
│           └── startup.c
│
│ # ════════════════════════════════════════════════════════
│ # CRYPTO — Pluggable Backends
│ # ════════════════════════════════════════════════════════
│
├── crypto/
│   ├── monocypher/                       # DEFAULT
│   │   ├── monocypher.c                  # Upstream, unmodifiziert
│   │   ├── monocypher.h
│   │   ├── monocypher-ed25519.c
│   │   ├── monocypher-ed25519.h
│   │   └── crypto_monocypher.c           # → crypto_hal_t Wrapper
│   │
│   ├── pqc/                              # OPTIONAL (pqc_hybrid=true)
│   │   ├── ml_dsa_65.c
│   │   ├── ml_dsa_65.h
│   │   └── crypto_pqc.c
│   │
│   └── README.md
│
│ # ════════════════════════════════════════════════════════
│ # VENDORED THIRD-PARTY LIBS
│ # ════════════════════════════════════════════════════════
│
├── lib/
│   ├── heatshrink/                       # ISC License, statisch allokiert
│   │   ├── heatshrink_decoder.c
│   │   ├── heatshrink_decoder.h
│   │   ├── heatshrink_common.h
│   │   ├── heatshrink_config.h           # DYNAMIC_ALLOC=0
│   │   ├── LICENSE
│   │   └── VERSION
│   │
│   ├── zcbor/                            # Apache-2.0
│   │   ├── src/
│   │   ├── include/
│   │   ├── LICENSE
│   │   └── VERSION
│   │
│   └── unity/                            # MIT, nur Host-Build
│       ├── unity.c
│       ├── unity.h
│       └── LICENSE
│
│ # ════════════════════════════════════════════════════════
│ # SUIT MANIFEST SCHEMA + CODE-GEN
│ # ════════════════════════════════════════════════════════
│
├── suit/
│   ├── toob_suit.cddl                    # CDDL-Schema → zcbor generiert C
│   ├── generate.sh                       # → core/boot_suit.c
│   └── examples/
│       ├── minimal.suit
│       ├── delta_update.suit
│       └── multi_image.suit
│
│ # ════════════════════════════════════════════════════════
│ # HOST-TOOLS (Python)
│ # ════════════════════════════════════════════════════════
│
├── tools/
│   ├── manifest_compiler/
│   │   ├── __init__.py
│   │   ├── cli.py                        # $ toob-manifest compile device.toml
│   │   ├── compiler.py                   # TOML → Artefakte
│   │   ├── validator.py                  # Preflight-Checks
│   │   ├── generator.py                  # Jinja2 Rendering
│   │   ├── chip_database.py              # Chip → arch/vendor/toolchain Lookup
│   │   └── vendors/                      # Vendor-spezifische Linker-Plugins
│   │       ├── base.py
│   │       ├── esp32.py
│   │       ├── stm32.py
│   │       ├── nrf.py
│   │       └── generic.py
│   │
│   ├── sign_tool/
│   │   ├── cli.py                        # $ toob-sign --key ... firmware.bin
│   │   ├── signer.py                     # Ed25519 via PyNaCl
│   │   ├── manifest_builder.py           # SUIT-Manifest + Merkle-Tree
│   │   ├── delta_builder.py              # detools Wrapper
│   │   └── keygen.py                     # $ toob-keygen
│   │
│   ├── partition_inspector/
│   │   ├── cli.py                        # $ toob-inspect flash.bin
│   │   ├── parser.py
│   │   └── renderer.py                   # Rich Terminal-Output
│   │
│   ├── templates/                        # Jinja2
│   │   ├── flash_layout.ld.j2
│   │   ├── boot_config.h.j2
│   │   ├── stage0_config.h.j2
│   │   └── platform.resc.j2
│   │
│   └── pyproject.toml                    # pip install -e tools/
│
│ # ════════════════════════════════════════════════════════
│ # MANIFESTS + KEYS + EXAMPLES
│ # ════════════════════════════════════════════════════════
│
├── manifests/
│   ├── dabox_iot_powerbank.toml
│   ├── generic_esp32s3.toml
│   ├── generic_esp32c3.toml
│   ├── generic_stm32l4.toml
│   ├── generic_nrf52840.toml
│   ├── generic_nrf5340.toml
│   └── sandbox.toml
│
├── keys/
│   ├── .gitignore                        # Alles außer README+example ignoriert
│   ├── README.md
│   └── dev_ed25519.pem.example
│
├── examples/
│   ├── blinky_esp32s3/
│   ├── blinky_nrf52840/
│   └── ota_demo/
│
│ # ════════════════════════════════════════════════════════
│ # TESTS — Dreistufige Pyramide
│ # ════════════════════════════════════════════════════════
│
├── test/
│   ├── unit/                             # Unity, <5s, Host-native
│   │   ├── test_journal.c
│   │   ├── test_swap.c
│   │   ├── test_merkle.c
│   │   ├── test_verify.c
│   │   ├── test_rollback.c
│   │   ├── test_confirm.c
│   │   ├── test_delta.c
│   │   ├── test_suit.c
│   │   ├── test_multiimage.c
│   │   └── test_runner.c
│   │
│   ├── fuzz/                             # AFL++/libFuzzer
│   │   ├── fuzz_suit_parser.c
│   │   ├── fuzz_delta_decoder.c
│   │   ├── fuzz_merkle_verify.c
│   │   ├── fuzz_wal_recovery.c
│   │   ├── corpus/
│   │   └── Makefile
│   │
│   ├── integration/                      # pytest, Sandbox-Binary
│   │   ├── test_full_update.py
│   │   ├── test_power_loss.py
│   │   ├── test_rollback_chain.py
│   │   ├── test_delta_update.py
│   │   ├── test_stage1_update.py
│   │   ├── test_multi_image.py
│   │   └── conftest.py
│   │
│   └── renode/
│       ├── run_tests.sh
│       ├── common.robot
│       ├── test_nrf52840_boot.robot
│       └── platforms/                    # ← GENERIERT
│
│ # ════════════════════════════════════════════════════════
│ # BUILD INFRASTRUCTURE
│ # ════════════════════════════════════════════════════════
│
├── cmake/
│   ├── toolchain-arm-none-eabi.cmake
│   ├── toolchain-riscv32.cmake
│   ├── toolchain-xtensa-esp.cmake
│   ├── toolchain-host.cmake
│   ├── toob_hal.cmake                    # Drei-Ebenen HAL Assembly
│   ├── toob_core.cmake
│   └── toob_stage0.cmake
│
├── scripts/
│   ├── bootstrap.sh                      # Einmal: venv + pip + Toolchain-Check
│   ├── build.sh                          # manifest → cmake → make
│   ├── flash.sh
│   ├── test.sh
│   └── new_port.sh                       # Scaffolding für neuen Chip
│
├── CMakeLists.txt
├── LICENSE                               # Apache-2.0
├── NOTICE                                # Third-Party-Lizenzen
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── README.md
├── .clang-format
├── .clang-tidy
├── .editorconfig
├── .gitignore
├── .gitattributes
└── Dockerfile
```

---

## Do's & Don'ts für das Repository

### Dependency-Management

**DO:** Third-Party-Code direkt in `lib/` vendorn (kopieren). Jede Lib hat eine
`VERSION`-Datei und die unmodifizierte Upstream-`LICENSE`. Bootloader-Projekte
dürfen keine Runtime-Dependencies auf Package-Manager haben — der Build
muss offline funktionieren, auch in 10 Jahren.

**DON'T:** Git-Submodules für `lib/` verwenden. Submodules brechen wenn
Upstream-Repos gelöscht/umbenannt werden. Für einen Bootloader der Jahrzehnte
im Feld läuft ist das inakzeptabel. Vendoring mit klarer VERSION-Datei ist
der einzig verlässliche Weg.

**Ausnahme:** Die Python-Tools in `tools/` dürfen `pyproject.toml` Dependencies
haben (toml, Jinja2, PyNaCl, rich, detools) — die laufen nur auf dem
Entwickler-Host, nie auf dem Target.

### Generierter Code

**DO:** Generierte Dateien klar kennzeichnen. `boot_config.h` beginnt mit:

```c
/* ╔═══════════════════════════════════════════════════╗
 * ║  AUTO-GENERATED by toob-manifest — DO NOT EDIT   ║
 * ║  Source: manifests/dabox_iot_powerbank.toml       ║
 * ╚═══════════════════════════════════════════════════╝ */
```

**DO:** Generierte Dateien in `.gitignore` aufnehmen. Sie werden bei jedem
Build neu erzeugt. In CI wird `toob-manifest compile` explizit aufgerufen.

**DON'T:** Generierte Dateien committen. Das führt zu Merge-Konflikten und
Drift zwischen TOML und Header.

### Code-Qualität

**DO:** Compiler-Flags als Minimum:

```cmake
-std=c11 -Wall -Wextra -Werror -Wconversion -Wshadow
-Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
-fstack-protector-strong  # (außer Stage 0)
-ffunction-sections -fdata-sections  # Dead-Code-Elimination
```

**DO:** `.clang-format` mit diesen Einstellungen:

```yaml
BasedOnStyle: LLVM
IndentWidth: 4
ColumnLimit: 100
BreakBeforeBraces: Linux
AllowShortFunctionsOnASingleLine: None
```

**DO:** `_Static_assert` großzügig einsetzen:

```c
_Static_assert(sizeof(wal_entry_t) == 16,
    "WAL entry size changed — update ABI_VERSION_MAGIC!");
_Static_assert(BOOT_FLASH_SECTOR_SIZE >= 4096,
    "Sector size too small for Merkle chunk");
```

**DON'T:** `#pragma once` verwenden. Es ist nicht im C-Standard. Klassische
Include-Guards sind portabler:

```c
#ifndef BOOT_HAL_H
#define BOOT_HAL_H
/* ... */
#endif
```

### Sicherheit

**DO:** `keys/` komplett gitignoren. Die `.gitignore` enthält:

```
keys/*
!keys/README.md
!keys/.gitignore
!keys/dev_ed25519.pem.example
```

**DO:** Ein `SECURITY.md` mit Responsible-Disclosure-Policy. Mindestinhalt:
Kontakt-E-Mail, PGP-Key, erwartete Antwortzeit (48h), Scope.

**DON'T:** Dev-Keys als Default nutzen ohne Warnung. Das `sign_tool` gibt
bei Erkennung des Example-Keys aus:

```
⚠ WARNING: Using example development key!
   NEVER ship devices with this key.
   Run 'toob-keygen' to create production keys.
```

### Versionierung & Releases

**DO:** Semantic Versioning: `MAJOR.MINOR.PATCH`.

- MAJOR: Breaking HAL-Trait-Änderung oder WAL-ABI-Inkompatibilität
- MINOR: Neues Feature (neuer Chip-Port, neue TOML-Option)
- PATCH: Bugfix, Security-Patch

**DO:** Git-Tags mit `v` Prefix: `v0.1.0`, `v1.0.0-rc1`.

**DO:** `CHANGELOG.md` im Keep-a-Changelog Format pflegen. Jeder Eintrag hat
eine Kategorie: Added, Changed, Fixed, Security, Breaking.

### CI-Pipeline

**DO:** Die CI baut immer diese Matrix:

```yaml
matrix:
  target: [sandbox, esp32s3, stm32l4, nrf52840]
  build_type: [Release, Debug]
```

Sandbox-Build läuft auf jedem Push. Hardware-Targets laufen auf jedem PR
und nightly.

**DO:** Fuzz-Testing als eigener Nightly-Job (8h). Der Corpus wird als
CI-Artifact archiviert und beim nächsten Lauf wiederverwendet.

### Dokumentation

**DO:** Jede Datei in `hal/*/` beginnt mit einem 3-Zeilen-Kommentar:

```c
/*
 * Toob-Boot HAL — ESP32-S3 Flash Driver
 * Implements: flash_hal_t (read, write, erase_sector)
 * Depends on: ESP-IDF SPI Flash API (esp_flash.h)
 */
```

**DO:** `docs/PORTING.md` enthält eine Schritt-für-Schritt-Checklist:

```
□ 1. hal/<chip>/ Verzeichnis anlegen ($ ./scripts/new_port.sh mychip)
□ 2. hal_flash.c implementieren (read/write/erase)
□ 3. hal_crypto.c implementieren (hash/verify/rng)
□ 4. hal_clock.c implementieren (init/get_tick/delay/get_reset_reason)
□ 5. hal_confirm.c implementieren (set_ok/check_ok/clear)
□ 6. hal_wdt.c implementieren (kick/set_timeout)
□ 7. hal_platform.c: boot_platform_init() registriert Traits
□ 8. startup.c: Minimal-Init + JTAG-Lock
□ 9. manifests/generic_mychip.toml erstellen
□ 10. Unit-Tests gegen Sandbox laufen lassen
□ 11. PR erstellen mit Preflight-Report als Attachment
```

**DON'T:** API-Docs in separaten Dateien pflegen die out-of-sync geraten.
Die Header-Dateien in `core/include/` SIND die API-Dokumentation. Jede
öffentliche Funktion hat einen Doxygen-Kommentar:

```c
/**
 * @brief Verify a single Merkle chunk against the tree root.
 * @param chunk     Pointer to chunk data (must be chunk_size bytes)
 * @param siblings  Array of sibling hashes along the path
 * @param depth     Number of tree levels (siblings array length)
 * @param root      Expected Merkle root hash (32 bytes)
 * @return BOOT_OK if chunk is valid, BOOT_ERR_VERIFY otherwise
 */
boot_status_t boot_merkle_verify_chunk(...);
```

This file is generally an updated version of an older one.

Here's what changed:

# Toob-Boot HAL — Dreischichtige Wiederverwendung

## Das Problem mit der flachen Struktur

Die alte Struktur (`hal/esp32s3/`, `hal/stm32l4/`, `hal/nrf52840/`) führt dazu,
dass beim Hinzufügen eines STM32H7 etwa 80% des STM32L4-Codes kopiert wird.
Der Flash-Unlock/Lock-Tanz, der IWDG-Setup, das Backup-Register-Handling —
alles identisch, nur die Sektorgrößen und Adressen ändern sich.

Gleiches gilt auf Architektur-Ebene: SysTick-Timer, NVIC-Init und
Vektor-Tabellen-Relokation sind auf jedem Cortex-M identisch — egal ob
STM32, nRF52 oder NXP. Das sind hunderte Zeilen die aktuell in jedem
Port einzeln leben würden.

## Die neue Struktur

```
hal/
│
├── include/                         # ══ GEMEINSAME HAL-INTERNE HEADER ══
│   ├── hal_internal.h               # Shared Macros, Inline-Helpers
│   ├── hal_flash_common.h           # Flash-Traits mit Default-Implementierungen
│   └── hal_deinit.h                 # Peripheral-Cleanup-Checkliste
│
├── arch/                            # ══ EBENE 1: CPU-ARCHITEKTUR ══
│   │                                # Alles was von der ISA abhängt,
│   │                                # aber herstellerunabhängig ist.
│   │
│   ├── arm_cortex_m/
│   │   ├── arch_systick.c           # SysTick als Tick-Source (clock_hal teilweise)
│   │   ├── arch_nvic.c              # Interrupt-Disable vor Jump, Vektor-Relokation
│   │   ├── arch_scb.c               # System-Reset, VTOR setzen
│   │   ├── arch_mpu.c               # MPU-Setup für Stack-Guard (optional)
│   │   ├── arch_deinit.c            # Generic Cortex-M Peripheral-Cleanup
│   │   └── include/
│   │       ├── arch_cortex_m.h      # CMSIS-kompatible Definitionen
│   │       └── arch_systick.h
│   │
│   ├── riscv32/
│   │   ├── arch_timer.c             # mtime/mtimecmp als Tick-Source
│   │   ├── arch_trap.c              # Trap-Handler, mcause lesen
│   │   ├── arch_csr.c               # CSR-Zugriffe (mstatus, mtvec)
│   │   └── include/
│   │       └── arch_riscv.h
│   │
│   └── xtensa/
│       ├── arch_timer.c             # CCOUNT als Tick-Source
│       ├── arch_interrupt.c         # Interrupt-Matrix Setup
│       ├── arch_window.c            # Register-Window-Setup
│       └── include/
│           └── arch_xtensa.h
│
├── vendor/                          # ══ EBENE 2: HERSTELLER-FAMILIE ══
│   │                                # Alles was innerhalb eines Herstellers
│   │                                # über Chip-Varianten gleich bleibt.
│   │
│   ├── stm32/
│   │   ├── vendor_flash.c           # Flash Unlock/Lock, Page-Erase, DWORD-Write
│   │   │                            # Parametrisiert über stm32_flash_config_t
│   │   ├── vendor_iwdg.c            # Independent Watchdog (identisch für alle STM32)
│   │   ├── vendor_backup_reg.c      # Backup-Register als Confirm-HAL
│   │   ├── vendor_rcc_reset.c       # RCC_CSR Reset-Reason (WDT/SW/POR)
│   │   ├── vendor_ll_includes.h     # LL-Driver Header Aggregation
│   │   └── include/
│   │       ├── stm32_flash_config.h # Config-Struct: Sektorgröße, Bank-Modus, etc.
│   │       └── stm32_common.h       # Shared Defines für alle STM32 Chips
│   │
│   ├── nrf/
│   │   ├── vendor_nvmc.c            # NVMC Read/Write/Erase (identisch nRF52/53)
│   │   ├── vendor_cc310.c           # CryptoCell-310 SHA/Ed25519 Wrapper
│   │   ├── vendor_cc312.c           # CryptoCell-312 (nRF5340 hat 312 statt 310)
│   │   ├── vendor_uarte.c           # UARTE Console (identisch alle nRF)
│   │   ├── vendor_retained_ram.c    # Retained-RAM als Confirm-HAL
│   │   ├── vendor_resetreas.c       # RESETREAS Register parsen
│   │   └── include/
│   │       └── nrf_common.h
│   │
│   └── esp/
│       ├── vendor_spi_flash.c       # SPI-Flash Read/Write/Erase via esp_flash API
│       ├── vendor_rtc_mem.c          # RTC-Fast-Memory als Confirm-HAL
│       ├── vendor_sha.c             # Hardware-SHA-256 Accelerator
│       ├── vendor_wdt.c             # RTC Watchdog (RWDT)
│       ├── vendor_reset_reason.c     # RTC_CNTL Reset-Cause parsen
│       └── include/
│           └── esp_common.h
│
├── chips/                           # ══ EBENE 3: CHIP-SPEZIFISCHE ADAPTER ══
│   │                                # Pro Chip existiert EIN Verzeichnis.
│   │                                # Enthält fast nur Konfiguration + Wiring.
│   │                                # Typisch: 1 C-Datei + 1 Header + startup.
│   │
│   ├── esp32s3/
│   │   ├── chip_config.h            # Flash-Geometrie, RTC-RAM-Adresse, UART-Pins
│   │   ├── chip_platform.c          # Verdrahtet vendor/esp/* → boot_platform_t
│   │   └── startup.c                # Minimal: Cache on, Clocks, JTAG-Lock
│   │
│   ├── esp32c3/                     # RISC-V statt Xtensa — andere arch/ aber gleiche vendor/
│   │   ├── chip_config.h
│   │   ├── chip_platform.c          # Nutzt arch/riscv32 + vendor/esp
│   │   └── startup.c
│   │
│   ├── esp32c6/
│   │   ├── chip_config.h
│   │   ├── chip_platform.c
│   │   └── startup.c
│   │
│   ├── stm32l4/
│   │   ├── chip_config.h            # 2KB Sektoren, Dual-Bank, 256KB/1MB Flash
│   │   ├── chip_platform.c          # Verdrahtet arch/arm_cortex_m + vendor/stm32
│   │   └── startup.c
│   │
│   ├── stm32h7/
│   │   ├── chip_config.h            # 128KB Sektoren (!), Dual-Bank, OTFDEC
│   │   ├── chip_platform.c          # Gleiche vendor/stm32 Funktionen, andere Config
│   │   └── startup.c
│   │
│   ├── stm32u5/                     # TrustZone-M Variante
│   │   ├── chip_config.h
│   │   ├── chip_platform.c
│   │   └── startup.c
│   │
│   ├── nrf52840/
│   │   ├── chip_config.h            # 4KB Sektoren, CC310, 1MB Flash
│   │   ├── chip_platform.c          # Verdrahtet arch/arm_cortex_m + vendor/nrf
│   │   └── startup.c
│   │
│   ├── nrf5340/                     # Multi-Core: App-Core + Net-Core
│   │   ├── chip_config.h            # CC312, IPC-Config, Net-Core Flash-Adresse
│   │   ├── chip_platform.c
│   │   ├── chip_ipc.c               # Inter-Processor-Comm (nRF5340-spezifisch)
│   │   └── startup.c
│   │
│   └── sandbox/                     # Host-Native (kein arch/, kein vendor/)
│       ├── chip_config.h
│       ├── chip_platform.c
│       ├── chip_fault_inject.c      # Power-Loss Simulation
│       ├── main.c                   # POSIX main()
│       └── startup.c                # No-op
│
└── README.md                        # Erklärt die 3 Ebenen + "So portierst du"
```

## Konkret: Was spart das?

### Beispiel 1: Neuen STM32H7-Port hinzufügen

OHNE Layering (alte Struktur):
→ hal/stm32h7/hal_flash.c kopieren von stm32l4, Sektorgrößen ändern
→ hal/stm32h7/hal_clock.c kopieren, SysTick-Code identisch
→ hal/stm32h7/hal_confirm.c kopieren, Backup-Register identisch
→ hal/stm32h7/hal_wdt.c kopieren, IWDG identisch
→ 5-6 Dateien, ~600 Zeilen, 80% Copy-Paste

MIT Layering (neue Struktur):
→ chips/stm32h7/chip_config.h (30 Zeilen: Sektorgrößen, Bank-Config)
→ chips/stm32h7/chip_platform.c (40 Zeilen: Wiring)
→ chips/stm32h7/startup.c (20 Zeilen: Clock-Init, JTAG-Lock)
→ Fertig. 3 Dateien, ~90 Zeilen. Alles andere kommt aus vendor/stm32/.

### Beispiel 2: ESP32-C3 hinzufügen (RISC-V statt Xtensa)

OHNE Layering:
→ hal/esp32c3/ komplett neu, weil arch_timer.c anders ist als bei ESP32-S3
→ Aber vendor_spi_flash.c, vendor_rtc_mem.c, vendor_wdt.c sind identisch!
→ Ergebnis: Flash/WDT/Console aus esp32s3 kopieren, nur Timer-Code ändern.

MIT Layering:
→ chips/esp32c3/chip_platform.c nutzt arch/riscv32 (statt arch/xtensa)
PLUS vendor/esp (identisch!).
→ chip_config.h definiert Flash-Größe und UART-Pins.
→ Null Copy-Paste der Flash/WDT/RTC-Code.

### Beispiel 3: Ganz neuen Hersteller (z.B. GigaDevice GD32)

GD32 ist Cortex-M basiert und hat sehr ähnliche Peripherals wie STM32
(historisch ein Klon). Aber die Register-Adressen und Bit-Positionen
weichen leicht ab.

→ arch/arm_cortex_m/ wird 1:1 wiederverwendet.
→ vendor/gd32/ wird neu geschrieben (Flash-Unlock anders, WDT anders).
→ chips/gd32vf103/ hat nur chip_config.h + chip_platform.c.

## Die chip_platform.c — das zentrale Wiring

Diese Datei ist der einzige Ort wo arch + vendor + chip zusammenkommen.
Sie implementiert boot_platform_init() und registriert alle Traits:

```c
/* chips/stm32l4/chip_platform.c */

#include "boot_hal.h"
#include "arch_cortex_m.h"
#include "stm32_common.h"
#include "chip_config.h"

/* Chip-spezifische Flash-Konfiguration */
static const stm32_flash_config_t flash_cfg = {
    .bank_mode    = STM32_FLASH_DUAL_BANK,
    .page_size    = 2048,
    .total_pages  = 256,
    .base_address = 0x08000000,
};

/* Vendor-Funktionen mit Chip-Config parametrisieren */
static boot_status_t flash_write(uint32_t addr, const void *buf, size_t len) {
    return stm32_flash_write(&flash_cfg, addr, buf, len);
}

static boot_status_t flash_erase(uint32_t addr) {
    return stm32_flash_erase_page(&flash_cfg, addr);
}

static flash_hal_t chip_flash = {
    .init         = stm32_flash_init,        /* aus vendor/stm32/ */
    .read         = stm32_flash_read,        /* aus vendor/stm32/ */
    .write        = flash_write,             /* lokaler Wrapper mit Config */
    .erase_sector = flash_erase,
    .sector_size  = 2048,                    /* aus chip_config.h */
    .total_size   = 512 * 1024,
    .write_align  = 8,                       /* STM32L4: Doppelwort */
    .erased_value = 0xFF,
};

static clock_hal_t chip_clock = {
    .init             = arch_systick_init,        /* aus arch/arm_cortex_m/ */
    .get_tick_ms      = arch_systick_get_ms,      /* aus arch/arm_cortex_m/ */
    .delay_ms         = arch_systick_delay,       /* aus arch/arm_cortex_m/ */
    .get_reset_reason = stm32_get_reset_reason,   /* aus vendor/stm32/ */
};

static confirm_hal_t chip_confirm = {
    .set_ok  = stm32_backup_reg_set,    /* aus vendor/stm32/ */
    .check_ok = stm32_backup_reg_check, /* aus vendor/stm32/ */
    .clear   = stm32_backup_reg_clear,
};

static crypto_hal_t chip_crypto = {
    .init   = crypto_monocypher_init,    /* aus crypto/monocypher/ */
    .hash_init   = crypto_monocypher_hash_init,
    .hash_update = crypto_monocypher_hash_update,
    .hash_finish = crypto_monocypher_hash_finish,
    .verify_ed25519 = crypto_monocypher_verify,
    .has_hw_acceleration = false,
};

static wdt_hal_t chip_wdt = {
    .init    = stm32_iwdg_init,     /* aus vendor/stm32/ */
    .kick    = stm32_iwdg_kick,
    .disable = stm32_iwdg_disable,
};

static boot_platform_t platform = {
    .flash   = &chip_flash,
    .confirm = &chip_confirm,
    .crypto  = &chip_crypto,
    .clock   = &chip_clock,
    .wdt     = &chip_wdt,
};

const boot_platform_t *boot_platform_init(void) {
    arch_cortex_m_early_init();          /* NVIC, VTOR */
    stm32_clock_init_hsi16();            /* vendor/stm32: HSI16 als Taktquelle */
    return &platform;
}
```

## Build-System Integration (CMake)

Die dreischichtige Struktur mappt sauber auf CMake-Targets:

```cmake
# cmake/toob_hal.cmake — wird vom Top-Level CMakeLists.txt inkludiert

# Aus device.toml extrahiert der Manifest-Compiler:
#   TOOB_ARCH = "arm_cortex_m"
#   TOOB_VENDOR = "stm32"
#   TOOB_CHIP = "stm32l4"

# Ebene 1: Architektur (statische Lib)
add_library(toob_arch STATIC
    hal/arch/${TOOB_ARCH}/arch_systick.c
    hal/arch/${TOOB_ARCH}/arch_nvic.c
    hal/arch/${TOOB_ARCH}/arch_scb.c
    hal/arch/${TOOB_ARCH}/arch_deinit.c
)
target_include_directories(toob_arch PUBLIC
    hal/arch/${TOOB_ARCH}/include
)

# Ebene 2: Vendor (statische Lib)
file(GLOB VENDOR_SOURCES "hal/vendor/${TOOB_VENDOR}/*.c")
add_library(toob_vendor STATIC ${VENDOR_SOURCES})
target_include_directories(toob_vendor PUBLIC
    hal/vendor/${TOOB_VENDOR}/include
)
target_link_libraries(toob_vendor PUBLIC toob_arch)

# Ebene 3: Chip (statische Lib)
file(GLOB CHIP_SOURCES "hal/chips/${TOOB_CHIP}/*.c")
add_library(toob_chip STATIC ${CHIP_SOURCES})
target_include_directories(toob_chip PUBLIC
    hal/chips/${TOOB_CHIP}
)
target_link_libraries(toob_chip PUBLIC toob_vendor)

# Final: Stage 1 linkt gegen toob_chip (zieht arch+vendor transitiv rein)
target_link_libraries(toob_stage1 PRIVATE toob_core toob_chip toob_crypto)
```

## device.toml: Drei neue Felder

```toml
[device]
name          = "iot-powerbank-v2"
chip          = "esp32s3"
# ↓ NEU: Automatisch aus Chip ableitbar, aber überschreibbar
architecture  = "xtensa"       # arm_cortex_m | riscv32 | xtensa
vendor        = "esp"          # stm32 | nrf | esp | gd32 | sandbox

[build]
toolchain     = "esp-idf"     # gcc-arm | gcc-riscv | esp-idf | iar | host
```

Der Manifest-Compiler hat eine Lookup-Tabelle:

```python
CHIP_DATABASE = {
    "esp32s3":  {"arch": "xtensa",      "vendor": "esp",   "toolchain": "esp-idf"},
    "esp32c3":  {"arch": "riscv32",     "vendor": "esp",   "toolchain": "esp-idf"},
    "esp32c6":  {"arch": "riscv32",     "vendor": "esp",   "toolchain": "esp-idf"},
    "stm32l4":  {"arch": "arm_cortex_m","vendor": "stm32", "toolchain": "gcc-arm"},
    "stm32h7":  {"arch": "arm_cortex_m","vendor": "stm32", "toolchain": "gcc-arm"},
    "stm32u5":  {"arch": "arm_cortex_m","vendor": "stm32", "toolchain": "gcc-arm"},
    "nrf52840": {"arch": "arm_cortex_m","vendor": "nrf",   "toolchain": "gcc-arm"},
    "nrf5340":  {"arch": "arm_cortex_m","vendor": "nrf",   "toolchain": "gcc-arm"},
    "sandbox":  {"arch": "host",        "vendor": "sandbox","toolchain": "host"},
}
```

Der User schreibt nur `chip = "esp32c3"` und arch/vendor/toolchain werden
automatisch gesetzt. Wer einen unbekannten Chip nutzt, kann alles manuell
überschreiben.

## Die Abwägung: Abstraction vs. Coupling

Die ehrliche Antwort auf deine Frage:

### Wo Abstraktion sich lohnt (DO):

- **arch/arm_cortex_m/**: SysTick, NVIC, SCB, Vektor-Relokation —
  das ist bei jedem Cortex-M physikalisch identisch, definiert durch
  die ARM-Spezifikation, nicht durch den Chip-Hersteller. Hier spart
  Abstraktion ~200 LOC pro neuen Cortex-M-Port.

- **vendor/stm32/**: Flash-Unlock/Lock-Sequenz, IWDG-Register,
  Backup-Register-Zugriff — identisch von STM32F1 bis STM32U5.
  Nur die Sektorgrößen und Adressen ändern sich (→ stm32_flash_config_t).

- **vendor/nrf/**: NVMC-Zugriff, CC310-API, UARTE, Retained-RAM —
  identisch zwischen nRF52832, nRF52840, nRF5340 (App-Core).

### Wo Abstraktion schadet (DON'T):

- **Across vendors**: STM32-Flash und nRF-NVMC sehen oberflächlich
  gleich aus (read/write/erase), aber die Implementierung ist komplett
  verschieden (STM32 braucht Unlock/Lock, nRF hat Write-Enable-Bit,
  ESP nutzt SPI-Protokoll). Ein "generic_flash_driver.c" der das
  alles hinter Abstraktionen versteckt wäre schwerer zu debuggen
  als die drei vendor-spezifischen Dateien.

- **Startup-Code**: Der Reset-Handler ist immer chip-spezifisch
  (Clock-Tree, Flash-Wait-States, JTAG-Lock-Mechanismus). Hier lohnt
  sich keine Abstraktion — jeder Chip hat seinen eigenen startup.c
  mit 15-30 Zeilen die nicht wiederverwendbar sind.

- **Crypto-Backend-Wahl**: Ob ein Chip CC310, Hardware-SHA oder
  nur Software-Crypto hat, ist eine Chip-Entscheidung, keine die sich
  in einer Vendor-Abstraktion sinnvoll kapseln lässt. Der
  chip_platform.c wählt das passende Backend direkt.

### Die Faustregel:

Wenn du den Code kopierst und nur Konstanten änderst → Abstraktion.
Wenn du den Code kopierst und die Logik änderst → Separate Datei.

```

```
