# Toob-Boot Implementation Backlog (Chronologisch)

Dieser Plan spiegelt die strikte Reihenfolge wider, in der die C-Dateien implementiert und getestet werden müssen, damit das Projekt jederzeit kompilierbar und in der Sandbox überprüfbar bleibt (basierend auf `dev_plan.md` und `concept_fusion.md`).

## Phase 1: WAL & Crypto Foundation (Aktueller Fokus)
Das Write-Ahead-Log muss zwingend zuerst existieren, da alle künftigen State-Machines (Swap, Rollback, Confirm) ihre persistenten Zustände darin ablegen.      
- `[x]` `core/include/boot_journal.h` (WAL Structs, CRC, Padding-Alignment, TMR Sector-Headers)
- `[x]` `core/boot_journal.c`:
  - `[x]` Implementiere statische Zustandsvariablen für Active WAL Index, Current Sequence und Cached Sector Addresses.
  - `[x]` Implementierung: `boot_journal_init()` (O(1) Sliding-Window Scanning via Sector Sequence IDs, Factory Reset Logic bei fehlendem Magic, GAP-C01 Majority Vote TMR für Status-Restoring).
  - `[x]` Implementierung: `boot_journal_update_tmr()` (GAP-C01 Strided Writes über drei Sektoren, Brownout-sicherer Window-Slide).
  - `[x]` Implementierung: `boot_journal_reconstruct_txn()` (Schrittweise Validierung über 64-Byte Payload-Blöcke, Absturz bei inkorrektem CRC32 oder leerem Magic).
  - `[x]` Implementierung: `boot_journal_append()` (Search nach Erased Boundary, Sliding-Window Überlauf handling, Flash-physikalischer Brownout-Overrite Schutz).
  - `[x]` Refactoring: Boot Journal Mathematical Hardening v2 (TMR-Exclude Bugfix, O(1) Cached Append Offset, Asymmetrisches Wear-Leveling).
- `[x]` `crypto/monocypher/` (Software-Krypto Wrapper integriert)

## Phase 2: Verifikation & Confirm-Logik
Das System muss empfangene OTA-Pakete verifizieren können (Signatur + Merkle) und das OS muss über die Nonce beim Kaltstart validiert werden.
- `[x]` `core/include/boot_verify.h` & `core/boot_verify.c` (Envelope-First Validierung, Constant-Time Ed25519)
  - `[x]` Sub-Step 1: Argument-Checks, Bounds-Validation & OTFDEC Offline-Toggling.
  - `[x]` Sub-Step 2: Watchdog-Kicked Flash-Read des Envelopes.
  - `[x]` Sub-Step 3: Public-Key Load aus eFuse / HW-Root.
  - `[x]` Sub-Step 4: Ed25519 Verify mit Double-Check Delay-Glitching Protection.
  - `[x]` Sub-Step 5: Post-Quantum Migration Hook.   
- `[x]` `core/include/boot_merkle.h` & `core/boot_merkle.c` (O(1) Streaming Chunk Hashing während Flash-Reads)
- `[x]` `core/include/boot_confirm.h` & `core/boot_confirm.c` (Auswertung der Boot-Nonce und Reset-Reasons)
- `[x]` `suit/` (CDDL-Spezifikation für den zcbor Parser via generate.sh integrieren)
  - `[x]` `suit/toob_telemetry.cddl` (CDDL strikt auf Phase 5 `toob_boot_diag_t` C-Struct kalibrieren)    
  - `[x]` `suit/toob_suit.cddl` (SUIT-Envelope, PQC-Hybride, Merkle-Limits und SBOM-Digest definieren)    
  - `[x]` `suit/generate.sh` (Intelligenten Fallback/Mock Generator für CMake CI ohne Python anlegen)     
    - `[x]` Python `zcbor` Modul Check integrieren.
    - `[x]` Fallback-Zweig (Mock): Dummy C-Funktionen & `chip_config.h` Header erzeugen.
    - `[x]` CMake Anpassung in `toob_core.cmake` (Ersatz der `touch` Befehle durch Bash-Aufruf).      
    - `[x]` Windows-Linker Fix: Host-Sandboxing freundliches `stage0_layout.ld` generieren (Vermeidung von `relocation truncated to fit` bei 0-Byte Skripten).

## Phase 3: State Machine, Swap & Rollback
Orchestrierung aller Phase-1 und Phase-2 Bausteine. Hier erwacht der Lifecycle zum Leben!

### 3.1. Core State & Helpers
- `[/]` `core/include/boot_state.h` & `core/boot_state.c` (IDLE, STAGING, TESTING, CONFIRMED Loops)       
- `[x]` `core/include/boot_delay.h` & `core/boot_delay.c` (WDT-sichere Wartezeit `boot_delay_with_wdt`)   
- `[x]` `core/boot_main.c` (Update: `hal_init()` Kaskade, `hal_deinit()`, OS Jump & Boot-Delay Integration)
  - `[x]` Block 1: P10 Guarding
  - `[x]` Block 2: Init Cascade (Strikt nach Spec)
  - `[x]` Block 2.5: HW Recovery Pin Debouncing (Serial Rescue Trap)
  - `[x]` Block 3: Execution (State Machine)
  - `[x]` Block 4: Diagnostics, Panic Fallback & Bounds Validation
  - `[x]` Block 5: Handoff (.noinit Mapping & CRC-16 Sealing)
  - `[x]` Block 6: Deinit Cascade (Hardware Sicherung vor Handoff)

### 3.2. Swap & Rollback Logic
- `[x]` `core/include/boot_swap.h` & `core/boot_swap.c` (In-Place Overwrite Logik mit dynamischer Sektorabfrage und `wdt.suspend_for_critical_section()`)      
- `[x]` `core/include/boot_rollback.h` & `core/boot_rollback.c` (Hybrid SVN Check, Fail-Counter, Recovery-OS Fallback & `RECOVERY_RESOLVED` Intent)

### 3.3. OS Boundary C-API (libtoob)
- `[x]` `libtoob/include/libtoob_types.h` (`toob_status_t`, `toob_handoff_t` mit Padding)
  - `[x]` Define `toob_status_t` Error Enum (`TOOB_OK = 0x55AA55AA`, `TOOB_ERR_NOT_FOUND`, etc.)
  - `[x]` Define OS Boot States (`TOOB_STATE_TENTATIVE = 0xAAAA5555`, `TOOB_STATE_COMMITTED = 0x55AA55AA`)
  - `[x]` Implement `toob_handoff_t` with explicit `__attribute__((aligned(8)))` and 40 bytes exact definition (`magic`, `struct_version`, `boot_nonce` (64-bit), `active_slot`, `reset_reason`, `boot_failure_count`, `net_search_accum_ms`, `_reserved_pad`, `crc32_trailer`).
  - `[x]` Implement `toob_ext_health_t` struct (Wear Counters: WAL, App, Staging, Swap).
  - `[x]` Implement `toob_boot_diag_t` for CBOR representation (`boot_duration_ms`, `edge_recovery_events`, `hardware_fault_record`, `verify_time_ms`, etc.).
- `[x]` `libtoob/include/libtoob.h` (APIs inkl. RECOVERY_RESOLVED und NET_SEARCH_ACCUM)
- `[x]` `libtoob/include/libtoob_config_sandbox.h` (Temporärer Mock-Header für Addressen in Phase 3)      
- `[x]` `libtoob/toob_confirm.c` (Append `CONFIRM_COMMIT` atomar ins WAL)
- `[x]` `libtoob/toob_update.c` (Registriert Manifest Array ins WAL)
- `[x]` `libtoob/toob_handoff.c` (Validierung von Magic + CRC-16 über `.noinit`)
- `[x]` `libtoob/toob_diag.c` (Erster Stub für `toob_get_boot_diag`, Parse `.noinit`)
- `[x]` `libtoob/toob_wal_naive.c` (Zero Dependency Append Logik + Pessimistic Locking)

## Phase 4: Delta Patching & Energy Guard
Zusatz-Komponenten für Bandbreiten-/Verschleißreduktion und Batterie-Schutz.
- `[ ]` `core/include/boot_delta.h` & `core/boot_delta.c` (Heatshrink Vorwärts-Patcher, 16-KB Resume-Checkpointing)
- `[ ]` `core/include/boot_energy.h` & `core/boot_energy.c` (Spannungs-Abfragen über `soc_hal`, Rollback bei low_battery_mv)

## Phase 5: Diagnostics, Serial Rescue & Telemetrie  
Sichtbarkeit des Systems (Metriken sammeln und dem OS via CBOR in `.noinit` überreichen) und Offline-Notrettung.
- `[ ]` `core/include/boot_diag.h` & `core/boot_diag.c` (Telemetrie sammeln: WDT Kicks, Boot-Time, Erase-Cycles S0..S4)
- `[x]` `core/include/boot_panic.h` & `core/boot_panic.c` (Strikter UART COBS Ping-Pong, 2FA Ed25519 Auth-Token Handshake)
  - `[x]` Block 1: O(1) Naked-Cobs Decoder / Encoder
  - `[x]` Block 2: 2FA Auth Token Verifikation (Ed25519 Root Key, UNIX Timestamp, Staging Slot Target)
  - `[x]` Block 3: Ping-Pong Flash Orchestration (Bounds Validation, Padding, Reboot Handoff)
- `[ ]` `libtoob/libtoob.c` (Teil 2: `toob_get_boot_diag()` zum Parsen der `.noinit` Sektion einbauen)    

## Phase 6: Stage 0 (Immutable Core) & Hardware Ports
Ganz am Schluss entsteht der eXecute-In-Place-Mini-Bootloader, der vor dem Toob-Boot Core anläuft. Ebenso die echten STM32/ESP32 Ports.
- `[ ]` `stage0/include/stage0_config.h` & `stage0_types.h`
- `[ ]` `stage0/stage0_tentative.c` (Lesen des WDT + Tentative-Flags aus RTC-RAM zur Verhinderung von Loop-Crashes)
- `[ ]` `stage0/stage0_hash.c` (Der O(1) Check, ob Bank A oder Bank B geladen wird)
- `[ ]` `stage0/stage0_boot_pointer.c` (Majority Vote Scan für die TMR Boot-Pointer)
- `[ ]` `stage0/stage0_main.c` (Immutable Boot-Entry des Microcontrollers)

## Phase 7: Multi-Core / Fortgeschritten (Optional)  
- `[ ]` `core/boot_multiimage.c` (Sub-Core Resets halten, IPC Matrices bereinigen vor App-Boot)
