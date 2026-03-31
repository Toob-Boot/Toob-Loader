# Toob-Boot — Projekt-Struktur & Repository-Blueprint (V2)

> Jede Datei hat einen Grund. Nichts ist Platzhalter.
>
> **Änderungen gegenüber V1:** Synchronisiert mit `concept_fusion.md` V4, `hals.md` V4, `libtoob_api.md`, `toobfuzzer_integration.md` V4 und allen Subdocs. Alle API-Signaturen, HAL-Trait-Counts und Verzeichnisse spiegeln den aktuellen Architektur-Stand wider.

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
│   ├── concept_fusion.md                 # Die Master-Spec (Abschnitte 1-6)
│   ├── hals.md                           # Vollständige HAL-Funktionsliste (7 Traits)
│   ├── libtoob_api.md                    # OS-seitige C-Library API
│   ├── toobfuzzer_integration.md         # Fuzzer → chip_config.h Pipeline
│   ├── getting_started.md                # Quickstart für Entwickler
│   ├── provisioning_guide.md             # Factory-Line eFuse/OTP Prozesse
│   ├── merkle_spec.md                    # Chunk-basierte Streaming-Verifikation
│   ├── stage_1_5_spec.md                 # Serial Rescue & COBS Protokoll
│   ├── testing_requirements.md           # SIL/HIL Matrix & P10 Standards
│   ├── toob_telemetry.md                 # CBOR Telemetrie-Spezifikation
│   ├── porting_guide.md                  # 10-Schritt-Checklist für neue Chips
│   ├── manifest_reference.md             # Alle device.toml Felder
│   ├── security_model.md                 # Threat Model + Trust Boundaries
│   ├── hal_layering.md                   # Arch vs Vendor vs Chip erklärt
│   ├── boot_flow.md                      # Sequenzdiagramm (Textform)
│   ├── wal_internals.md                  # Ring-Buffer, CRC, TMR, ABI
│   └── diagrams/
│       ├── boot_flow.mermaid
│       ├── flash_layout.svg
│       ├── hal_layers.svg
│       └── update_state_machine.mermaid
│
│ # ════════════════════════════════════════════════════════
│ # CORE — Null Hardware-Abhängigkeit, null Boilerplate
│ # ════════════════════════════════════════════════════════
│
├── core/
│   ├── include/
│   │   ├── boot_hal.h                    # 7 HAL-Trait-Structs + boot_platform_t
│   │   │                                 #   PFLICHT: flash_hal_t, confirm_hal_t,
│   │   │                                 #            crypto_hal_t, clock_hal_t, wdt_hal_t
│   │   │                                 #   OPTIONAL: console_hal_t, soc_hal_t
│   │   ├── boot_types.h                  # boot_status_t, reset_reason_t, Image-Header
│   │   ├── boot_config.h                 # ← GENERIERT (Manifest-Compiler: Feature-Flags, Arena-Sizes)
│   │   ├── boot_journal.h
│   │   ├── boot_merkle.h
│   │   ├── boot_suit.h                   # ← GENERIERT (zcbor aus toob_suit.cddl)
│   │   ├── boot_delta.h
│   │   ├── boot_diag.h
│   │   ├── boot_energy.h
│   │   ├── boot_confirm.h
│   │   ├── boot_rollback.h
│   │   └── boot_secure_zeroize.h         # O(1) Assembly: Compiler-sichere RAM-Löschung
│   │
│   ├── boot_main.c                       # Entry → Init-Kaskade → State-Machine → Jump
│   ├── boot_state.c                      # IDLE/STAGING/TESTING/CONFIRMED
│   ├── boot_journal.c                    # WAL, CRC-32 Entries, Sliding Window, ABI-Migration
│   ├── boot_verify.c                     # Hash + Signatur (→ crypto_hal), Envelope-First
│   ├── boot_merkle.c                     # Chunk-weise Streaming-Verifikation
│   ├── boot_swap.c                       # In-Place-Overwrite via Swap-Buffer
│   ├── boot_delta.c                      # Forward-Only Patcher + 16KB Chunk WAL-Checkpointing
│   ├── boot_suit.c                       # ← GENERIERT (zcbor Stream-Parser, Anti-Truncation)
│   ├── boot_rollback.c                   # SVN (hybrid eFuse/WAL), Fail-Counter, RECOVERY_RESOLVED
│   ├── boot_panic.c                      # Schicht 4a: Serial Rescue (COBS + 2FA Auth)
│   ├── boot_confirm.c                    # Reset-Reason Auswertung + confirm_hal Orchestrierung
│   ├── boot_diag.c                       # CBOR Telemetrie + Timing-IDS (.noinit Shared-RAM)
│   ├── boot_energy.c                     # Battery-Guard + Brownout-Backoff (→ soc_hal)
│   ├── boot_multiimage.c                 # Atomic Groups + Secondary Boot Delegation
│   ├── boot_delay.c                      # boot_delay_with_wdt() Helper (WDT-sichere Wartezeit)
│   └── boot_secure_zeroize.S             # Assembly: volatile memset für crypto_arena Cleanup
│
│ # ════════════════════════════════════════════════════════
│ # STAGE 0 — Eigenes Binary, eigener Linker-Script
│ # ════════════════════════════════════════════════════════
│
├── stage0/
│   ├── stage0_main.c                     # Reset → TMR Boot_Pointer → Hash/Verify → Jump S1a|S1b
│   ├── stage0_hash.c                     # SHA-256 Software (~1.5 KB)
│   ├── stage0_verify.c                   # Optional Ed25519 (stage0.verify_mode: hash-only|ed25519-sw|ed25519-hw)
│   ├── stage0_otp.c                      # OTP/eFuse Key-Lesen + Key-Index Rotation
│   ├── stage0_boot_pointer.c             # TMR Majority-Vote + Bounds-Validation + Magic-Header
│   ├── stage0_tentative.c                # RTC-RAM TENTATIVE Flag + RESET_REASON Auswertung
│   └── include/
│       └── stage0_config.h               # ← GENERIERT (Slot-Adressen, Verify-Mode, Key-Index-Limit)
│
│ # ════════════════════════════════════════════════════════
│ # HAL — Drei Ebenen: Architektur → Vendor → Chip
│ # ════════════════════════════════════════════════════════
│
├── hal/
│   │
│   ├── include/                          # ── HAL-interne Shared Header ──
│   │   ├── hal_internal.h                # Gemeinsame Macros/Helpers
│   │   └── hal_deinit.h                  # Deinit-Checkliste (inkl. OTFDEC Re-Enable)
│   │
│   ├── arch/                             # ── EBENE 1: CPU-Architektur ──
│   │   │                                 # Was die ISA vorgibt, unabhängig
│   │   │                                 # vom Hersteller.
│   │   │
│   │   ├── arm_cortex_m/                 # Für: STM32, nRF52, nRF5340, NXP
│   │   │   ├── arch_systick.c            # SysTick Timer (clock_hal partial)
│   │   │   ├── arch_nvic.c              # Interrupt-Disable, Priority
│   │   │   ├── arch_scb.c               # VTOR, System-Reset
│   │   │   ├── arch_deinit.c            # Generischer Peripheral-Cleanup
│   │   │   └── include/
│   │   │       └── arch_cortex_m.h       # CMSIS Core Definitionen
│   │   │
│   │   ├── riscv32/                      # Für: ESP32-C3, ESP32-C6, GD32V
│   │   │   ├── arch_timer.c             # mtime/mtimecmp
│   │   │   ├── arch_trap.c             # Trap-Handler, mcause
│   │   │   └── include/
│   │   │       └── arch_riscv.h
│   │   │
│   │   └── xtensa/                       # Für: ESP32, ESP32-S2, ESP32-S3
│   │       ├── arch_timer.c             # CCOUNT Register
│   │       ├── arch_interrupt.c         # Interrupt-Matrix
│   │       └── include/
│   │           └── arch_xtensa.h
│   │
│   ├── vendor/                           # ── EBENE 2: Hersteller-Familie ──
│   │   │                                 # Identisch über Chip-Varianten
│   │   │                                 # desselben Herstellers.
│   │   │
│   │   ├── stm32/                        # Geteilt: L4, H7, U5, F4, ...
│   │   │   ├── vendor_flash.c           # Unlock/Lock, Page-Erase, DWORD-Write
│   │   │   ├── vendor_iwdg.c           # Independent Watchdog (init/kick/suspend/resume)
│   │   │   ├── vendor_backup_reg.c     # Backup-Register (confirm_hal: check_ok/clear)
│   │   │   ├── vendor_rcc_reset.c      # RCC_CSR → reset_reason_t (mit Caching + Clear)
│   │   │   ├── vendor_console.c        # USART (konfigurierbar per Pin/Instanz)
│   │   │   └── include/
│   │   │       ├── stm32_flash_cfg.h   # Config-Struct für Flash-Parametrisierung
│   │   │       └── stm32_common.h       # LL-Includes + gemeinsame Defines
│   │   │
│   │   ├── nrf/                          # Geteilt: nRF52832, nRF52840, nRF5340
│   │   │   ├── vendor_nvmc.c            # Flash-Controller
│   │   │   ├── vendor_cc3xx.c           # CC310/CC312 Ed25519+SHA (runtime detect)
│   │   │   ├── vendor_uarte.c          # UART Console
│   │   │   ├── vendor_retained_ram.c   # Confirm via Retained-RAM (check_ok/clear)
│   │   │   ├── vendor_resetreas.c      # RESETREAS → reset_reason_t (mit Caching + Clear)
│   │   │   └── include/
│   │   │       └── nrf_common.h
│   │   │
│   │   └── esp/                          # Geteilt: ESP32, S2, S3, C3, C6
│   │       ├── vendor_spi_flash.c       # ROM-Pointer basiert (SPIEraseSector/SPIWrite)
│   │       ├── vendor_rtc_mem.c         # RTC-Fast-Memory (confirm_hal: check_ok/clear)
│   │       ├── vendor_sha_hw.c          # Hardware-SHA-256 (ROM init/update/finish)
│   │       ├── vendor_rwdt.c            # RTC Watchdog (init/kick/suspend/resume)
│   │       ├── vendor_reset_reason.c    # RTC_CNTL → reset_reason_t (auto-update, kein Clear)
│   │       ├── vendor_console.c         # UART0
│   │       └── include/
│   │           └── esp_common.h
│   │
│   └── chips/                            # ── EBENE 3: Chip-Adapter ──
│       │                                 # Nur Konfiguration + Wiring.
│       │                                 # Typisch: ~90 LOC total pro Chip.
│       │
│       ├── esp32s3/                       # Xtensa + esp vendor
│       │   ├── chip_config.h             # ← GENERIERT (Toobfuzzer → Manifest-Compiler)
│       │   ├── chip_platform.c           # Wiring: arch/xtensa + vendor/esp → 7 Traits
│       │   └── startup.c                 # Cache, Clocks, JTAG-SW-Sperre
│       │
│       ├── esp32c3/                       # RISC-V + esp vendor (!)
│       │   ├── chip_config.h             # ← GENERIERT
│       │   ├── chip_platform.c           # Wiring: arch/riscv32 + vendor/esp → 7 Traits
│       │   └── startup.c
│       │
│       ├── esp32c6/
│       │   ├── chip_config.h             # ← GENERIERT
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── stm32l4/                       # Cortex-M + stm32 vendor
│       │   ├── chip_config.h             # ← GENERIERT (2KB Sektoren, Dual-Bank)
│       │   ├── chip_platform.c           # Wiring: arch/arm_cortex_m + vendor/stm32
│       │   └── startup.c
│       │
│       ├── stm32h7/
│       │   ├── chip_config.h             # ← GENERIERT (128KB Sektoren, OTFDEC)
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── stm32u5/                       # TrustZone-M Variante
│       │   ├── chip_config.h             # ← GENERIERT
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── nrf52840/                      # Cortex-M + nrf vendor
│       │   ├── chip_config.h             # ← GENERIERT (CC310, 4KB Pages)
│       │   ├── chip_platform.c
│       │   └── startup.c
│       │
│       ├── nrf5340/                       # Multi-Core
│       │   ├── chip_config.h             # ← GENERIERT (CC312, IPC-Config)
│       │   ├── chip_platform.c
│       │   ├── chip_ipc.c               # Inter-Processor-Comm (nRF5340-spezifisch)
│       │   └── startup.c
│       │
│       └── sandbox/                       # Host-Native (kein arch/vendor)
│           ├── chip_config.h             # Statische Sandbox-Defaults (GAP-F19)
│           ├── chip_platform.c           # Direkt POSIX → 7 Traits
│           ├── chip_fault_inject.c       # Deterministischer Brownout nach Sektor N
│           ├── main.c                    # POSIX main()
│           └── startup.c                # No-op
│
│ # ════════════════════════════════════════════════════════
│ # CRYPTO — Pluggable Backends
│ # ════════════════════════════════════════════════════════
│
├── crypto/
│   ├── monocypher/                       # DEFAULT: Software Ed25519 + SHA-512
│   │   ├── monocypher.c                  # Upstream, unmodifiziert
│   │   ├── monocypher.h
│   │   ├── monocypher-ed25519.c
│   │   ├── monocypher-ed25519.h
│   │   └── crypto_monocypher.c           # → crypto_hal_t Wrapper (constant-time garantiert)
│   │
│   ├── pqc/                              # OPTIONAL (Manifest: pqc_hybrid=true)
│   │   ├── ml_dsa_65.c                   # ML-DSA-65 Verify (~10-30 KB Stack!)
│   │   ├── ml_dsa_65.h
│   │   └── crypto_pqc.c                 # → crypto_hal_t.verify_pqc Wrapper
│   │
│   └── README.md
│
│ # ════════════════════════════════════════════════════════
│ # LIBTOOB — OS-seitige C-Library (Feature-OS bindet ein)
│ # ════════════════════════════════════════════════════════
│
├── libtoob/
│   ├── include/
│   │   ├── libtoob.h                     # Öffentliche API: toob_confirm_boot(),
│   │   │                                 #   toob_set_next_update(), toob_get_boot_diag()
│   │   ├── libtoob_types.h               # toob_status_t, toob_handoff_t, toob_boot_diag_t,
│   │   │                                 #   TOOB_STATE_TENTATIVE/COMMITTED Konstanten
│   │   └── libtoob_config.h              # ← GENERIERT (ADDR_CONFIRM_RTC_RAM, WAL_BASE_ADDR)
│   │                                     #   Aus blueprint.json/aggregated_scan.json
│   │
│   ├── toob_confirm.c                    # CONFIRM_COMMIT Append ins WAL (atomares Flash-Write)
│   ├── toob_update.c                     # WAL-Eintrag für nächstes Update registrieren
│   ├── toob_diag.c                       # .noinit Shared-RAM → toob_boot_diag_t Parsing
│   ├── toob_handoff.c                    # toob_handoff_t Validierung (Magic + CRC-16)
│   └── README.md                         # Integrations-Anleitung für Zephyr/FreeRTOS/Linux
│
│ # ════════════════════════════════════════════════════════
│ # VENDORED THIRD-PARTY LIBS
│ # ════════════════════════════════════════════════════════
│
├── lib/
│   ├── heatshrink/                       # ISC License, statisch allokiert (DYNAMIC_ALLOC=0)
│   │   ├── heatshrink_decoder.c
│   │   ├── heatshrink_decoder.h
│   │   ├── heatshrink_common.h
│   │   ├── heatshrink_config.h
│   │   ├── LICENSE
│   │   └── VERSION
│   │
│   ├── zcbor/                            # Apache-2.0 (SUIT-Parser + Telemetrie CBOR)
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
│   ├── toob_telemetry.cddl               # CDDL für CBOR Telemetrie-Pakete
│   ├── generate.sh                       # → core/boot_suit.c + core/include/boot_suit.h
│   └── examples/
│       ├── minimal.suit
│       ├── delta_update.suit
│       ├── multi_image.suit
│       └── pqc_hybrid.suit
│
│ # ════════════════════════════════════════════════════════
│ # HOST-TOOLS (Python)
│ # ════════════════════════════════════════════════════════
│
├── tools/
│   ├── manifest_compiler/
│   │   ├── __init__.py
│   │   ├── cli.py                        # $ toob-manifest compile device.toml
│   │   ├── compiler.py                   # TOML + Fuzzer-JSON → Artefakte
│   │   ├── validator.py                  # Preflight-Checks (RAM-Budget, Alignment, WDT)
│   │   ├── generator.py                  # Jinja2 Rendering → chip_config.h, libtoob_config.h,
│   │   │                                 #   boot_config.h, boot_features.h, flash_layout.ld,
│   │   │                                 #   stage0_config.h, platform.resc
│   │   ├── chip_database.py              # Chip → arch/vendor/toolchain Lookup
│   │   ├── crypto_arena.py               # Pipeline: blueprint.json → Arena-Size → RAM-Check
│   │   └── vendors/                      # Vendor-spezifische Linker-Plugins
│   │       ├── base.py
│   │       ├── esp32.py                  # Assembliert 3 separate .ld Files
│   │       ├── stm32.py
│   │       ├── nrf.py
│   │       └── generic.py
│   │   └── toolchains/                   # Zero-Touch Compiler Auto-Discovery
│   │       ├── espressif.py              # Sucht nativ nach IDF_PATH / esp-idf
│   │       └── generic.py                # Sucht nativ nach arm-none-eabi-gcc
│   │
│   ├── sign_tool/
│   │   ├── cli.py                        # $ toob-sign --in fw.bin --key key.pem --out fw.suit
│   │   ├── signer.py                     # Ed25519 via PyNaCl (Sign-then-Hash / COSE_Sign1)
│   │   ├── manifest_builder.py           # SUIT-Manifest + Merkle-Tree Chunk-Hashes
│   │   ├── delta_builder.py              # detools Wrapper (16KB Chunk Dictionary-Resets)
│   │   └── keygen.py                     # $ toob-keygen --out-priv key.pem --out-pub pub.bin
│   │
│   ├── partition_inspector/
│   │   ├── cli.py                        # $ toob-inspect flash.bin
│   │   ├── parser.py                     # WAL, TMR, Slot-Header lesen
│   │   └── renderer.py                   # Rich Terminal-Output
│   │
│   ├── templates/                        # Jinja2
│   │   ├── flash_layout.ld.j2            # inkl. .noinit Handoff-Areal + crypto_arena
│   │   ├── boot_config.h.j2              # Feature-Flags, Arena-Sizes, Hash-Ctx-Size
│   │   ├── boot_features.h.j2            # Bereinigte Build-Feature-Flags
│   │   ├── chip_config.h.j2              # ROM-Pointer, Register-Adressen, Sector-Map
│   │   ├── libtoob_config.h.j2           # OS-Boundary: Confirm-Addr, WAL-Base
│   │   ├── stage0_config.h.j2            # Slot-Adressen, Verify-Mode, S0-Größe
│   │   └── platform.resc.j2             # Renode-Simulator Config
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
│   ├── generic_esp32c6.toml
│   ├── generic_stm32l4.toml
│   ├── generic_stm32h7.toml
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
│   └── ota_demo/                         # Vollständiges Beispiel: libtoob + WiFi OTA
│
│ # ════════════════════════════════════════════════════════
│ # TESTS — Dreistufige Pyramide
│ # ════════════════════════════════════════════════════════
│
├── test/
│   ├── unit/                             # Unity, <5s, Host-native
│   │   ├── test_journal.c                # WAL Ring, CRC-32, ABI-Migration, Sliding Window
│   │   ├── test_swap.c                   # In-Place-Overwrite, asymmetrische Sektoren
│   │   ├── test_merkle.c                 # Chunk-Verifikation, Bit-Rot Injection
│   │   ├── test_verify.c                 # Envelope-First, Anti-Truncation
│   │   ├── test_rollback.c               # SVN hybrid, Epoch-Change, Fail-Counter
│   │   ├── test_confirm.c                # Reset-Reason + Nonce Matching
│   │   ├── test_delta.c                  # Forward-Only, Base-Fingerprint Mismatch
│   │   ├── test_suit.c                   # SUIT Stream-Parser, unbekannte Conditions
│   │   ├── test_multiimage.c             # Atomic Groups, TXN_ROLLBACK_BEGIN
│   │   ├── test_energy.c                 # Battery-Guard Thresholds, Backoff
│   │   ├── test_tmr.c                    # Triple Modular Redundancy Majority-Vote
│   │   └── test_runner.c
│   │
│   ├── mocks/                            # Link-Time Mocking (--wrap)
│   │   ├── mock_flash.c                  # mmap-basierte Flash-Simulation
│   │   ├── mock_efuses.c                 # Dummy Root-Keys im RAM
│   │   ├── mock_crypto_policy.c          # DEV_MODE Signature Bypass
│   │   ├── mock_rtc_ram.c                # Confirm-Flag Simulation
│   │   └── mock_wdt.c                    # Watchdog Timeout-Tracking
│   │
│   ├── fuzz/                             # AFL++/libFuzzer
│   │   ├── fuzz_suit_parser.c            # Envelope-Wrap Malleability
│   │   ├── fuzz_delta_decoder.c          # Base-Fingerprint + Corrupt Patches
│   │   ├── fuzz_merkle_verify.c          # Manipulierte Chunk-Hashes
│   │   ├── fuzz_wal_recovery.c           # Stateful Context-Recovery nach Brownout
│   │   ├── fuzz_cobs_framing.c           # Serial Rescue COBS Parser
│   │   ├── corpus/                       # Seed-Inputs (archiviert als CI-Artifact)
│   │   └── Makefile
│   │
│   ├── integration/                      # pytest, Sandbox-Binary
│   │   ├── test_full_update.py           # Kompletter OTA Lifecycle
│   │   ├── test_power_loss.py            # Brownout bei 0%/50%/99%
│   │   ├── test_rollback_chain.py        # App → Recovery → Rescue-Only Lock
│   │   ├── test_delta_update.py          # Delta-Patch + WAL-Checkpointing
│   │   ├── test_stage1_update.py         # S1 Self-Update (Bank A↔B)
│   │   ├── test_multi_image.py           # Atomic Group Rollback
│   │   ├── test_serial_rescue.py         # COBS + 2FA Auth Token
│   │   ├── test_eol_survival.py          # Flash EOL → STATE_READ_ONLY
│   │   ├── test_manifest_compiler.py     # GAP-F20: Defekte chip_config.h → #error
│   │   └── conftest.py
│   │
│   └── renode/
│       ├── run_tests.sh
│       ├── common.robot
│       ├── test_nrf52840_boot.robot
│       └── platforms/                    # ← GENERIERT (aus device.toml → platform.resc)
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
│   ├── toob_hal.cmake                    # Drei-Ebenen HAL Assembly (arch+vendor+chip)
│   ├── toob_core.cmake
│   ├── toob_stage0.cmake
│   ├── toob_libtoob.cmake               # Separate Build-Config für OS-seitige Library
│   └── toob_crypto.cmake                # Pluggable Backend-Selection
│
├── scripts/
│   ├── bootstrap.sh                      # Einmal: venv + pip + Toolchain-Check
│   ├── build.sh                          # manifest → cmake → make
│   ├── flash.sh
│   ├── test.sh
│   └── new_port.sh                       # Scaffolding für neuen Chip (3 Dateien + TOML)
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

**DO:** Third-Party-Code direkt in `lib/` vendorn (kopieren). Jede Lib hat eine `VERSION`-Datei und die unmodifizierte Upstream-`LICENSE`. Bootloader-Projekte dürfen keine Runtime-Dependencies auf Package-Manager haben — der Build muss offline funktionieren, auch in 10 Jahren.

**DON'T:** Git-Submodules für `lib/` verwenden. Submodules brechen wenn Upstream-Repos gelöscht/umbenannt werden. Für einen Bootloader der Jahrzehnte im Feld läuft ist das inakzeptabel. Vendoring mit klarer VERSION-Datei ist der einzig verlässliche Weg.

**Ausnahme:** Die Python-Tools in `tools/` dürfen `pyproject.toml` Dependencies haben (toml, Jinja2, PyNaCl, rich, detools) — die laufen nur auf dem Entwickler-Host, nie auf dem Target.

### Generierter Code

**DO:** Generierte Dateien klar kennzeichnen:

```c
/* ╔═══════════════════════════════════════════════════╗
 * ║  AUTO-GENERATED by toob-manifest — DO NOT EDIT    ║
 * ║  Source: manifests/yourproject.toml               ║
 * ╚═══════════════════════════════════════════════════╝ */
```

Betrifft: `chip_config.h`, `libtoob_config.h`, `boot_config.h`, `boot_features.h`, `stage0_config.h`, `flash_layout.ld`, `boot_suit.c`, `boot_suit.h`, `platform.resc`.

**DO:** Generierte Dateien in `.gitignore` aufnehmen. Sie werden bei jedem Build neu erzeugt. In CI wird `toob-manifest compile` explizit aufgerufen.

**DON'T:** Generierte Dateien committen. Das führt zu Merge-Konflikten und Drift zwischen TOML/JSON und Header.

### Code-Qualität

**DO:** Compiler-Flags als Minimum:

```cmake
-std=c17 -Wall -Wextra -Werror -Wconversion -Wshadow
-Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
-fstack-protector-strong  # (außer Stage 0 — zu groß)
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
_Static_assert(CHIP_FLASH_MAX_SECTOR_SIZE >= 4096,
    "Sector size too small for Merkle chunk");
_Static_assert(sizeof(toob_handoff_t) % 8 == 0,
    "Handoff struct must be 8-byte aligned (GAP-39)");
```

**(GAP-C03 Mitigation) DO: WAL Struct Padding:** Strukturen, die direkt in den Flash geschrieben werden (wie `wal_entry_t`), MÜSSEN zwingend eine `union` nutzen, die mit einem Padding-Array auf Basis von `CHIP_FLASH_WRITE_ALIGN` aufgefüllt wird. Ein `_Static_assert` muss zusätzlich modulo 0 Division für das Schreib-Alignment erzwingen, um Hardfaults bei C-Packing-Optimierungen auf 8/16-Byte aligned Hardware zu zerschmettern:

```c
union wal_entry_aligned {
    wal_entry_t data;
    uint8_t padding[ (sizeof(wal_entry_t) + CHIP_FLASH_WRITE_ALIGN - 1) & ~(CHIP_FLASH_WRITE_ALIGN - 1) ];
};
_Static_assert(sizeof(union wal_entry_aligned) % CHIP_FLASH_WRITE_ALIGN == 0, 
    "WAL padding violates hardware alignment!");
```

**DON'T:** `#pragma once` verwenden. Es ist nicht im C-Standard. Klassische Include-Guards:

```c
#ifndef BOOT_HAL_H
#define BOOT_HAL_H
/* ... */
#endif
```

**DO:** Absolutes `malloc`/`free` Verbot durchsetzen:

```cmake
# In CMakeLists.txt für core/ und stage0/
add_compile_definitions(malloc=MALLOC_FORBIDDEN free=FREE_FORBIDDEN)
```

### Sicherheit

**DO:** `keys/` komplett gitignoren:

```
keys/*
!keys/README.md
!keys/.gitignore
!keys/dev_ed25519.pem.example
```

**DO:** Ein `SECURITY.md` mit Responsible-Disclosure-Policy. Mindestinhalt: Kontakt-E-Mail, PGP-Key, erwartete Antwortzeit (48h), Scope.

**DON'T:** Dev-Keys als Default nutzen ohne Warnung. Das `sign_tool` gibt bei Erkennung des Example-Keys aus:

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

**DO:** `CHANGELOG.md` im Keep-a-Changelog Format pflegen. Jeder Eintrag hat eine Kategorie: Added, Changed, Fixed, Security, Breaking.

### CI-Pipeline

**DO:** Die CI baut immer diese Matrix:

```yaml
matrix:
  target: [sandbox, esp32s3, esp32c3, stm32l4, nrf52840]
  build_type: [Release, Debug]
```

Sandbox-Build läuft auf jedem Push. Hardware-Targets laufen auf jedem PR und nightly.

**DO:** Fuzz-Testing als eigener Nightly-Job (8h). Der Corpus wird als CI-Artifact archiviert und beim nächsten Lauf wiederverwendet.

---

## Toob-Boot HAL — Dreischichtige Wiederverwendung

### Das Problem mit der flachen Struktur

Die alte Struktur (`hal/esp32s3/`, `hal/stm32l4/`, `hal/nrf52840/`) führt dazu, dass beim Hinzufügen eines STM32H7 etwa 80% des STM32L4-Codes kopiert wird. Der Flash-Unlock/Lock-Tanz, der IWDG-Setup, das Backup-Register-Handling — alles identisch, nur die Sektorgrößen und Adressen ändern sich.

Gleiches gilt auf Architektur-Ebene: SysTick-Timer, NVIC-Init und Vektor-Tabellen-Relokation sind auf jedem Cortex-M identisch — egal ob STM32, nRF52 oder NXP.

### Konkret: Was spart das?

**Beispiel 1: Neuen STM32H7-Port hinzufügen**

OHNE Layering: 5-6 Dateien, ~600 Zeilen, 80% Copy-Paste.
MIT Layering: 3 Dateien (`chip_config.h`, `chip_platform.c`, `startup.c`), ~90 Zeilen. Alles andere kommt aus `vendor/stm32/`.

**Beispiel 2: ESP32-C3 hinzufügen (RISC-V statt Xtensa)**

`chip_platform.c` nutzt `arch/riscv32` (statt `arch/xtensa`) PLUS `vendor/esp` (identisch!). Null Copy-Paste der Flash/WDT/RTC-Code.

**Beispiel 3: Ganz neuer Hersteller (z.B. GigaDevice GD32)**

`arch/arm_cortex_m/` wird 1:1 wiederverwendet. `vendor/gd32/` wird neu geschrieben. `chips/gd32vf103/` hat nur `chip_config.h` + `chip_platform.c`.

### Die Faustregel

Wenn du den Code kopierst und nur Konstanten änderst → Abstraktion (vendor/).
Wenn du den Code kopierst und die Logik änderst → Separate Datei (chips/).

---

## Die chip_platform.c — das zentrale Wiring

Diese Datei ist der einzige Ort wo arch + vendor + chip zusammenkommen. Sie implementiert `boot_platform_init()` und registriert alle 7 Traits:

```c
/* chips/stm32l4/chip_platform.c
 *
 * Toob-Boot HAL — STM32L4 Platform Wiring
 * Implements: boot_platform_init() → 7 HAL-Traits
 * Depends on: arch/arm_cortex_m, vendor/stm32, chip_config.h (GENERIERT)
 */

#include "boot_hal.h"
#include "arch_cortex_m.h"
#include "stm32_common.h"
#include "chip_config.h"        /* ← GENERIERT: CHIP_FLASH_MAX_SECTOR_SIZE, ROM-Pointer, etc. */

/* ── Flash ── */

static const stm32_flash_config_t flash_cfg = {
    .bank_mode    = STM32_FLASH_DUAL_BANK,
    .page_size    = CHIP_FLASH_PAGE_SIZE,             /* aus chip_config.h */
    .total_pages  = CHIP_FLASH_TOTAL_PAGES,
    .base_address = CHIP_FLASH_BASE_ADDRESS,
};

static boot_status_t flash_write(uint32_t addr, const void *buf, size_t len) {
    return stm32_flash_write(&flash_cfg, addr, buf, len);
}

static boot_status_t flash_erase(uint32_t addr) {
    return stm32_flash_erase_page(&flash_cfg, addr);
}

static boot_status_t flash_get_sector_size(uint32_t addr, size_t *size_out) {
    return stm32_flash_get_sector_size(&flash_cfg, addr, size_out);
}

static flash_hal_t chip_flash = {
    .version          = 0x01000000,
    .init             = stm32_flash_init,             /* aus vendor/stm32/ */
    .deinit           = stm32_flash_deinit,
    .read             = stm32_flash_read,
    .write            = flash_write,
    .erase_sector     = flash_erase,
    .get_sector_size  = flash_get_sector_size,
    .set_otfdec_mode  = NULL,                         /* STM32L4 hat kein OTFDEC */
    .get_last_vendor_error = stm32_flash_get_vendor_error,
    .max_sector_size  = CHIP_FLASH_MAX_SECTOR_SIZE,
    .total_size       = CHIP_FLASH_TOTAL_SIZE,
    .write_align      = CHIP_FLASH_WRITE_ALIGN,       /* STM32L4: 8 (Doppelwort) */
    .erased_value     = 0xFF,
};

/* ── Clock ── */

static clock_hal_t chip_clock = {
    .version          = 0x01000000,
    .init             = arch_systick_init,             /* aus arch/arm_cortex_m/ */
    .deinit           = arch_systick_deinit,
    .get_tick_ms      = arch_systick_get_ms,
    .delay_ms         = arch_systick_delay,
    .get_reset_reason = stm32_get_reset_reason,        /* aus vendor/stm32/ (cached!) */
};

/* ── Confirm (Bootloader liest nur noch; OS schreibt via libtoob) ── */

static confirm_hal_t chip_confirm = {
    .version  = 0x01000000,
    .init     = stm32_backup_reg_init,
    .deinit   = stm32_backup_reg_deinit,
    .check_ok = stm32_backup_reg_check,                /* bool (*)(uint64_t expected_nonce) */
    .clear    = stm32_backup_reg_clear,
};

/* ── Crypto (Software, kein CC310 auf STM32L4) ── */

static crypto_hal_t chip_crypto = {
    .version            = 0x01000000,
    .init               = crypto_monocypher_init,      /* aus crypto/monocypher/ */
    .deinit             = crypto_monocypher_deinit,
    .hash_init          = crypto_monocypher_hash_init,
    .hash_update        = crypto_monocypher_hash_update,
    .hash_finish        = crypto_monocypher_hash_finish,
    .verify_ed25519     = crypto_monocypher_verify,
    .verify_pqc         = NULL,                        /* Kein PQC auf diesem Target */
    .random             = stm32_rng_random,            /* aus vendor/stm32/, nutzt TRNG */
    .get_last_vendor_error = NULL,
    .read_pubkey        = stm32_otp_read_pubkey,
    .read_dslc          = stm32_uid_read_dslc,         /* 96-Bit UID als DSLC */
    .read_monotonic_counter   = stm32_otp_read_counter,
    .advance_monotonic_counter = stm32_otp_advance_counter,
    .has_hw_acceleration = false,
};

/* ── Watchdog ── */

static wdt_hal_t chip_wdt = {
    .version                      = 0x01000000,
    .init                         = stm32_iwdg_init,   /* aus vendor/stm32/ */
    .deinit                       = stm32_iwdg_deinit, /* No-Op: IWDG nicht stoppbar */
    .kick                         = stm32_iwdg_kick,
    .suspend_for_critical_section = stm32_iwdg_suspend,/* Prescaler hochskalieren */
    .resume                       = stm32_iwdg_resume, /* Prescaler wiederherstellen */
};

/* ── Console (Optional) ── */

static console_hal_t chip_console = {
    .version  = 0x01000000,
    .init     = stm32_usart_init,
    .deinit   = stm32_usart_deinit,
    .putchar  = stm32_usart_putchar,
    .getchar  = stm32_usart_getchar,
    .flush    = stm32_usart_flush,
};

/* ── Platform Assembly ── */

static boot_platform_t platform = {
    .flash   = &chip_flash,
    .confirm = &chip_confirm,
    .crypto  = &chip_crypto,
    .clock   = &chip_clock,
    .wdt     = &chip_wdt,
    .console = &chip_console,        /* Optional: NULL wenn kein UART gewünscht */
    .soc     = NULL,                 /* STM32L4 Nucleo: kein Batterie-Management */
};

const boot_platform_t *boot_platform_init(void) {
    arch_cortex_m_early_init();                /* NVIC, VTOR */
    stm32_clock_init_hsi16();                  /* vendor/stm32: HSI16 als Taktquelle */
    return &platform;
}
```

### Init-Reihenfolge (vom Core orchestriert)

```
boot_platform_init()          ← Chip-Startup (Clocks, JTAG-Lock via startup.c)
    │
    ▼
① clock.init()                ← ZUERST: Alles andere braucht Zeitbasis
    │                           get_tick_ms() + get_reset_reason() ab hier verfügbar
    ▼
② flash.init()                ← ZWEITENS: WAL + Partitionen lesen
    │                           Braucht Clock für SPI-Timing (ESP32)
    ▼
③ wdt.init(BOOT_WDT_TIMEOUT_MS) ← DRITTENS: So früh wie möglich
    │                           Ab hier: Crash → automatischer Reset
    ▼
④ crypto.init()               ← VIERTENS: HW-Crypto-Engine + TRNG Health Check
    │                           Braucht Flash für OTP Key-Laden
    ▼
⑤ confirm.init()              ← FÜNFTENS: RTC-Domain/Backup-Reg init
    │                           Wird direkt danach via check_ok(nonce) ausgewertet
    ▼
⑥ console.init() [optional]   ← SECHSTENS: Debug-Output
    │                           Nur wenn platform->console != NULL
    ▼
⑦ soc.init() [optional]       ← LETZTENS: ADC + Multi-Core Isolation
    │                           Nur wenn platform->soc != NULL
    ▼
boot_state_run()               ← State-Machine startet
```

---

## Build-System Integration (CMake)

Die dreischichtige Struktur mappt sauber auf CMake-Targets:

```cmake
# cmake/toob_hal.cmake — wird vom Top-Level CMakeLists.txt inkludiert

# Aus device.toml extrahiert der Manifest-Compiler:
#   TOOB_ARCH   = "arm_cortex_m"
#   TOOB_VENDOR = "stm32"
#   TOOB_CHIP   = "stm32l4"

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

---

## device.toml: Chip-Database Mapping

```toml
[device]
name          = "iot-powerbank-v2"
chip          = "esp32s3"
# ↓ Automatisch aus Chip ableitbar, aber überschreibbar
architecture  = "xtensa"       # arm_cortex_m | riscv32 | xtensa
vendor        = "esp"          # stm32 | nrf | esp | gd32 | sandbox

[build]
toolchain     = "esp-idf"      # gcc-arm | gcc-riscv | esp-idf | host
```

Der Manifest-Compiler hat eine Lookup-Tabelle:

```python
CHIP_DATABASE = {
    "esp32s3":  {"arch": "xtensa",       "vendor": "esp",     "toolchain": "esp-idf"},
    "esp32c3":  {"arch": "riscv32",      "vendor": "esp",     "toolchain": "esp-idf"},
    "esp32c6":  {"arch": "riscv32",      "vendor": "esp",     "toolchain": "esp-idf"},
    "stm32l4":  {"arch": "arm_cortex_m", "vendor": "stm32",   "toolchain": "gcc-arm"},
    "stm32h7":  {"arch": "arm_cortex_m", "vendor": "stm32",   "toolchain": "gcc-arm"},
    "stm32u5":  {"arch": "arm_cortex_m", "vendor": "stm32",   "toolchain": "gcc-arm"},
    "nrf52840": {"arch": "arm_cortex_m", "vendor": "nrf",     "toolchain": "gcc-arm"},
    "nrf5340":  {"arch": "arm_cortex_m", "vendor": "nrf",     "toolchain": "gcc-arm"},
    "sandbox":  {"arch": "host",         "vendor": "sandbox", "toolchain": "host"},
}
```

Der User schreibt nur `chip = "esp32c3"` und arch/vendor/toolchain werden automatisch gesetzt. Wer einen unbekannten Chip nutzt, kann alles manuell überschreiben.

---

## Porting-Checklist (Kurzfassung)

```
□  1. $ ./scripts/new_port.sh mychip (scaffoldet hal/chips/mychip/)
□  2. Toobfuzzer-Lauf auf Zielhardware → aggregated_scan.json + blueprint.json
□  3. manifests/generic_mychip.toml erstellen
□  4. toob-manifest compile → chip_config.h + libtoob_config.h generiert
□  5. startup.c: Minimal-Init + JTAG-Lock (eFuse/Option Bytes!)
□  6. chip_platform.c: arch/* + vendor/* → boot_platform_t verdrahten
□  7. Falls neuer Vendor: vendor/mychip/ Dateien implementieren
       (flash, wdt, confirm, reset_reason — je ~50-100 LOC)
□  8. Sandbox Unit-Tests laufen lassen ($ toob build --target sandbox && ctest)
□  9. Preflight-Report als PR-Attachment anhängen
□ 10. Hardware-HIL Smoke-Test (Flash + Boot + Rollback)
```

---

## Dokumentation

**DO:** Jede Datei in `hal/*/` beginnt mit einem 3-Zeilen-Kommentar:

```c
/*
 * Toob-Boot HAL — ESP32-S3 Flash Driver
 * Implements: flash_hal_t (read, write, erase_sector, get_sector_size)
 * Depends on: ESP BootROM SPI Flash API (ROM-Pointer aus chip_config.h)
 */
```

**DON'T:** API-Docs in separaten Dateien pflegen die out-of-sync geraten. Die Header-Dateien in `core/include/` und `libtoob/include/` SIND die API-Dokumentation. Jede öffentliche Funktion hat einen Doxygen-Kommentar:

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

---

## V2 Änderungsprotokoll (gegenüber V1)

| Bereich                    | Änderung                                                                               | Begründung                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `boot_hal.h`               | "7 HAL-Trait-Structs" statt "6"                                                        | `soc_hal_t` war bereits spezifiziert aber im Kommentar vergessen                 |
| `confirm_hal_t`            | `set_ok()` entfernt                                                                    | OS schreibt via `libtoob` direkt ins WAL/RTC-RAM (GAP-F14/F15)                   |
| `confirm_hal_t`            | `check_ok(uint64_t expected_nonce)`                                                    | Nonce-basierte Verifikation statt Bool-Flag                                      |
| `wdt_hal_t`                | `disable` → `suspend_for_critical_section()` / `resume()`                              | WDT darf nie komplett deaktiviert werden, nur Prescaler hochskaliert             |
| `flash_hal_t`              | `+get_sector_size()`, `+set_otfdec_mode()`, `+get_last_vendor_error()`                 | Asymmetrische Sektoren (STM32F4/F7), OTFDEC Anti-Side-Channel, Vendor-Telemetrie |
| `crypto_hal_t`             | `+verify_pqc()`, `+read_pubkey()`, `+read_dslc()`, `+read/advance_monotonic_counter()` | PQC-Migration, OTP Key-Rotation, Serial Rescue DSLC, Anti-Replay                 |
| `crypto_hal_t`             | `supports_pqc` Bool entfernt                                                           | Existenz-Check via `verify_pqc != NULL`                                          |
| Alle HAL-Structs           | `+version` Feld (uint32_t)                                                             | ABI-Versionierung für Forward-Kompatibilität                                     |
| Alle HAL-Structs           | `+deinit()` explizit                                                                   | Sauberer Peripheral-Cleanup vor OS-Jump (OTFDEC Re-Enable, Zeroize)              |
| `libtoob/`                 | Neues Top-Level-Verzeichnis                                                            | OS-seitige Library war nur als Konzept beschrieben, jetzt eigene Dateien         |
| `docs/`                    | Synchronisiert mit 10 referenzierten Subdocs                                           | Alte Docs (ARCHITECTURE.md etc.) ersetzt durch tatsächliche Dateinamen           |
| `suit/`                    | `+toob_telemetry.cddl`                                                                 | CBOR Telemetrie-Schema als CDDL formalisiert                                     |
| `test/fuzz/`               | `+fuzz_cobs_framing.c`                                                                 | Serial Rescue COBS Parser ist externe Angriffsfläche                             |
| `test/integration/`        | `+test_serial_rescue.py`, `+test_eol_survival.py`, `+test_manifest_compiler.py`        | Neue Architektur-Features brauchen Integration-Coverage                          |
| `cmake/`                   | `+toob_libtoob.cmake`, `+toob_crypto.cmake`                                            | Separate Build-Targets für OS-Library und pluggable Crypto                       |
| `chip_platform.c` Beispiel | Komplett aktualisiert                                                                  | Alle 7 Traits, korrekte Signaturen, `version` Felder, Kommentare                 |
| `manifests/`               | `+generic_esp32c6.toml`, `+generic_stm32h7.toml`                                       | Fehlende Manifeste für bereits unterstützte Chips                                |
