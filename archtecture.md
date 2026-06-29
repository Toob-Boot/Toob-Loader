# Toob-Boot — Funktionale Architektur des Bootloader-Core

Stand: abgeleitet aus dem Quellstand `toobloader/core` + `toobloader/stage0` (Phase-5/6-Codebasis inkl. Cloud-Command, DSLC, KDM, Provisioning). Die mitgelieferte Datei `registry_production_architecture.md` beschreibt die Registry-Cloud-Infrastruktur und ist **nicht** Teil der Bootloader-Laufzeitarchitektur; sie wird hier nicht behandelt.

---

## 1. Einordnung und Boot-Kette

Toob-Boot ist als mehrstufige, transaktionale Boot-Kette für MCU-Klasse-Geräte organisiert. Jede Stufe hat ein klar abgegrenztes Vertrauensmodell und eigene Speicherdisziplin:

```
ROM/Reset
   │
   ▼
Stage 0 (immutabel)            stage0_main.c, stage0_*.c
   │  DSLC-Gate, Bank-Auswahl A/B, Ed25519-Verify von Stage 1
   ▼
Stage 1 (updatebar, A/B)       boot_main.c → boot_state.c
   │  WAL/TMR, Confirm, Cloud-Commands, Update-Pipeline, Rollback
   │
   ├──► Stage 1.5 Serial Rescue   boot_panic.c   (Fehler-/Lock-Pfad, _Noreturn)
   ├──► Factory Provisioning      boot_provisioning.c (nur DSLC == 0x00)
   ▼
Feature-OS / Recovery-OS       Handoff via .noinit (toob_handoff_t, toob_boot_diag_t)
```

Stage 0 ist bewusst minimal: kein WAL-Parser, kein Update-Code, nur Pointer-Resolution, Tentative-Auswertung und Signaturprüfung der aktiven Stage-1-Bank. Stage 1 trägt die vollständige Lifecycle-Logik (Journal, Verifikation, Swap, Rollback, Cloud-Control-Plane). Stage 1.5 ist kein eigenes Image, sondern der terminale Rescue-Zustand innerhalb von Stage 1 (`boot_panic`). Der OS-Übergang erfolgt nie per Funktionsaufruf, sondern über einen versiegelten `.noinit`-Handoff plus Assembler-Jump im Vendor-Startup.

---

## 2. Querschnittsprinzipien

Diese Muster ziehen sich durch praktisch jedes Modul und sind die eigentliche Architektur-Signatur des Cores.

### 2.1 Zero-Allocation über die `crypto_arena`

Es gibt genau einen großen RAM-Block: `uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE]` (definiert in `boot_main.c`, 8-Byte aligned). Kein `malloc`, keine VLAs, kein nennenswertes BSS pro Modul. Die Arena wird **phasenexklusiv** übernommen: Wer sie nutzt (Delta-VM, Swap, Panic, Provisioning, Merkle, Cloud-Cmd), partitioniert sie intern über Makros oder Offsets, beweist die Partitionierung per `_Static_assert` und zeroized sie am Single-Exit vollständig. Beispiele für Partitionierungsschemata: `boot_panic.c` (Challenge/RX/Verify/Chunk mit Compile-Time-Summenbeweis), `boot_delta.c` (heatshrink-Decoder + zwei DMA-alignte Hälften als Write-Combiner/Read-Buffer), `boot_cloud_cmd.c` (Envelope-Zone + Work-Zone mit explizitem Aliasing-Verbot).

### 2.2 Glitch-Defense-Patterns

Vier wiederkehrende Mechanismen gegen Fault-Injection (Voltage/EMFI/Laser):

**Double-Check-Shields.** Jede sicherheitsentscheidende Bedingung wird zweimal evaluiert, getrennt durch `BOOT_GLITCH_DELAY()`, in zwei `volatile uint32_t`-Flags. Beide Flags müssen exakt `BOOT_OK` ergeben. `BOOT_OK == 0x55AA55AA` ist per `_Static_assert` als High-Hamming-Weight-Pattern erzwungen, damit ein einzelner Bit-Flip nie aus „Fehler“ ein „OK“ machen kann.

**CFI-Akkumulatoren mit TRNG-Randomisierung.** Jede größere Funktion führt einen `volatile`-XOR-Akkumulator über Tokens, die pro Boot via `cfi_derive(seed, slot)` (Fibonacci-Hashing, Bit 0 erzwungen ≠ 0) aus einem TRNG-Seed abgeleitet werden. Am Funktionsende muss der Akkumulator dem erwarteten XOR aller Pfad-Tokens entsprechen — ein PC-Glitch, der Blöcke überspringt, fällt damit auf. Negative Pfade (z. B. „PQC legitim übersprungen“ in `boot_verify.c`, „kein Update pending“ in `boot_state.c`) bekommen eigene Skip-Tokens, damit die Kaskade auch ohne Aktivität geschlossen wird. In `boot_multiimage.c` ist der erwartete Wert zusätzlich dynamisch aus den Component-IDs berechnet, damit sich das Überspringen zweier Komponenten nicht per XOR aufheben kann.

**WDT-Starvation als Fail-Secure-Halt.** Erkennt ein Modul einen aktiven Angriff oder einen Zustand, aus dem es keinen sicheren Software-Pfad gibt (ALU-Glitch in `boot_delay`, RAM-Wipe-Glitch in `boot_main`, CFI-Bruch in `boot_energy`), wird die CPU absichtlich in eine Endlosschleife ohne WDT-Kick gehängt — vorher Clock-Deinit und `disable_interrupts()`, damit auch RTOS-/ROM-Hintergrund-Interrupts den Watchdog nicht versehentlich füttern. Der Hardware-Watchdog erzwingt den Kaltstart.

**Constant-Time-Primitiven.** Zentralisiert in `boot_ct_utils.h`: `constant_time_memcmp_glitch_safe` (dualer Vorwärts-/Rückwärts-Akkumulator, `len == 0` ist explizit ein Fehler), `is_fully_erased_constant_time` (Timing-Orakel-freie Smart-Erase-Checks), `boot_read_monotonic_counter_safe` (Doppel-Read mit Shield), `boot_random_safe` (TRNG-Health-Check gegen All-0x00/All-0xFF).

### 2.3 P10-Disziplin (NASA Power of Ten)

Konsequent umgesetzt: Loop-Guards mit harten Obergrenzen (Delta-VM, Erase-Schleifen, Rollback), subtraktive Bounds-Checks gegen 32-Bit-Wraparounds vor jeder Adressarithmetik, Pointer-Provenance-Beweise (`is_buffer_within` mit `uintptr_t`-Wrap-Proofs), 8-Byte-Alignment-Erzwingung für DMA/Cortex-M0, Single-Exit-Cleanup mit `boot_secure_zeroize` (eigene Assembler-Implementierung gegen Dead-Code-Elimination, Host-Mock für die Sandbox), Pre-Declaration aller Buffer am Scope-Anfang.

### 2.4 Persistenz-Philosophie

Aller persistente Zustand lebt in genau zwei Strukturen des WAL-Subsystems: dem **TMR-Payload** (langlebige Werte, per 3-Sektor-Majority-Vote geschützt: SVNs, Failure-Counter, Erase-Counter, aktive Nonce, KDM-State, Stage-1-Bank) und den **Append-Entries** (transaktionale Intents mit CRC-Trailer). Module schreiben nie direkt rohe Statusbytes in den Flash; jede Zustandsänderung läuft über `boot_journal_append`/`boot_journal_update_tmr`, jeder Resume nach Brownout über `boot_journal_reconstruct_txn`.

---

## 3. Stage 0 — Immutable Root of Trust

| Datei | Funktion |
|---|---|
| `stage0_main.c` | Entry, DSLC-Gate, Header-Check, Hash+Verify, Jump |
| `stage0_boot_pointer.c` | O(1)-Majority-Vote über WAL-Header → aktive Stage-1-Bank (A/B) |
| `stage0_tentative.c` | Trial-Boot-Auswertung, Bank-Rollback bei Crash |
| `stage0_hash.c` | Zero-Allocation SHA-256 über Flash mit Poisoning bei Read-Fehler |
| `stage0_verify.c` | Glitch-resistenter Ed25519(ph)-Check (HW/SW/Hash-only per Build-Mode) |
| `stage0_otp.c` | Key-Index-Rotation aus dem Monotonic-Counter (eFuse-Epoch) |

Ablauf in `main()`:

1. **Minimal-Init** der HAL (Flash zwingend, Clock/Crypto/WDT optional).
2. **DSLC-Majority-Vote-Gate**: bis zu 5 eFuse-Reads mit TRNG-randomisiertem Jitter zwischen den Reads (Anti-Sustained-Glitch); ein Wert gilt erst ab 3 übereinstimmenden Lesungen. Kein stabiler Wert → `dead_halt()` (fail-closed).
3. **Bank-Resolution**: `stage0_get_active_slot` liest alle WAL-Sektor-Header, validiert Magic+CRC glitch-geschirmt und wählt über die höchste `sequence_id` die Stage-1-Bank aus `tmr_data.active_stage1_bank` — explizit die Bootloader-Bank, nicht das Feature-OS.
4. **Tentative-Auswertung**: War der letzte Stage-1-Boot `TOOB_STATE_TENTATIVE` (Self-Update-Trial) und die Reset-Ursache ein Crash (WDT/HardFault/Brownout), wird das `.noinit`-Magic atomar genullt und auf die andere Bank zurückgefallen (Anti-Death-Loop für Bootloader-Self-Updates).
5. **Header + Signatur**: Image-Header lesen, Magic doppelt prüfen, Größe gegen `CHIP_APP_SLOT_SIZE` begrenzen. Key-Index = eFuse-Epoch (Monotonic-Counter, gekappt auf 255). Hash läuft über **Header + Payload** (Entry-Point-Fälschung = ACE wird damit signiert abgedeckt); der SHA-256-Digest liegt in einem genullten 64-Byte-Buffer, weil Monocyphers Ed25519ph 64 Bytes erwartet (OOB-Read-Prävention). Die Signatur liegt hinter dem Payload.
6. **Dev-Bypass** existiert nur, wenn `TOOB_ALLOW_DEV_BYPASS` explizit gesetzt ist **und** DSLC == 0x00; Produktions-Builds erzwingen per `#error`, dass das Flag bewusst gesetzt wurde.
7. **Jump**: bei doppelt geschirmtem Verify-OK Deinit-Kaskade, ICache-Invalidierung (XIP-Stale-Code-Prävention), dann naked `jump_to_payload(active_slot + hdr.entry_point)` (ARM: MSP+Reset-Handler aus Vector-Table; RISC-V: direkter `jr`).

Stage 0 enthält Stubs für `boot_panic`/Handoff, um den Linker nicht in den Core zu ziehen — Fehlerpfade enden ausnahmslos in Halt-Loops.

---

## 4. Stage 1 — Orchestrierung (`boot_main.c`)

`boot_main()` ist der Lifecycle-Rahmen um die State-Machine. Sechs Blöcke, durch einen 6-Token-CFI-Akkumulator verkettet:

**Block 1 — Zero-Trust-Plattformvalidierung.** Alle HAL-Pointer (clock, flash, wdt, crypto, confirm; console/soc optional) werden auf NULL geprüft, jede HAL muss `TOOB_HAL_ABI_V2` melden, Pflicht-Funktionspointer werden einzeln verifiziert, `max_erase_cycles == 0` ist verboten.

**Block 2 — Init-Kaskade mit Bitmasken-Rollback.** Reihenfolge: Bus-Matrix-Flush + Secondary-Core-Reset (hängende DMAs), Clock → Flash → OTFDEC-Off → WDT → Crypto → Confirm → Console → SoC. Jeder Schritt setzt ein Bit in `init_mask`; bei Fehlern wird in exakt umgekehrter Reihenfolge nur das Initialisierte deinitalisiert und hart an Stage 0 zurückgegeben (Panic wäre hier noch unsicher). Erst **nach** `crypto->init()` werden die CFI-Tokens aus dem TRNG gezogen.

**Block 2.5 — Recovery-Pin.** Pin-High → 500 ms Debounce (`boot_delay_with_wdt`) → doppelt geschirmter Re-Check → atomarer Sprung in `boot_panic(BOOT_RECOVERY_REQUESTED)`.

**Block 2.6 — Provisioning-Gate.** DSLC == 0x00 (unprovisioniert) und Provisioning-HAL vorhanden → `boot_provisioning_run()` (kein Return). Fabriksicherheit basiert auf physischem Zugang, kein Recovery-Pin nötig.

**Block 3 — State-Machine.** `boot_state_run()` (Abschnitt 5), umrahmt von Wrap-around-sicherer Boot-Zeitmessung; das Resultat wird glitch-geschirmt evaluiert.

**Block 4 — XIP-Bounds.** `active_entry_point` muss in `[CHIP_FLASH_BASE_ADDR, +CHIP_FLASH_TOTAL_SIZE)` liegen (subtraktiv, wrap-frei), `active_image_size` > 0 und innerhalb der Restgröße, Vector-Table 4-Byte-aligned.

**Block 5 — Handoff-Versiegelung (TOCTOU-frei).** Diag-State wird befüllt (Boot-Zeit, Recovery-Events und Wear-Counter aus dem TMR) und via `boot_diag_seal()` CRC-versiegelt. Der `toob_handoff_t` (Magic TENTATIVE/COMMITTED, Struct-Version, Boot-Nonce, Reset-Reason, Partition, Net-Search-Accum, Resume-Offset, DICE-Device-ID, `wipe_requested`) wird **lokal im Stack** assembliert, CRC-32-versiegelt, dann atomar per `memcpy` in den `.noinit`-Bereich kopiert und sofort per Read-Back-CRC + Doppel-Shield verifiziert.

**Block 6 — Deinit + Wipe-Beweis.** OTFDEC wieder an, Flash-Deinit, Arena-Zeroize, danach ein stichprobenartiger O(1)-Beweis (erste 32 Bytes ODER-akkumuliert == 0, doppelt geschirmt) — schlägt der Wipe fehl (geglitcht), friert das System ein. Crypto/Confirm/Console/SoC-Deinit, Bus-Matrix-Flush, Clock-Deinit. Finales CFI-Gate über alle 6 Tokens; hier ist `boot_panic` nicht mehr erlaubt (Hardware bereits down), Fehler enden in WDT-Starvation. Der **WDT wird als allerletztes** deinitalisiert, unmittelbar vor dem Return an den Vendor-Jump.

Der `panic_fallthrough`-Pfad füllt einen minimalen Diag-Record (Error-Code, Boot-Dauer, CRC-Trailer) ins `.noinit` und ruft `boot_panic`.

---

## 5. State-Machine (`boot_state.c`) — Lebenszyklus

`boot_state_run()` ist der CFI-Orchestrator mit 8 Token-Slots. Sequenz:

**Step 1 — Rekonstruktion.** `boot_journal_init` (Sliding-Window + TMR-Quorum), `boot_journal_get_tmr`, `boot_journal_reconstruct_txn` liefert dreierlei getrennt: den offenen Haupt-Intent, den Netz-Such-Akkumulator (`NET_SEARCH_ACCUM`) und den Download-Resume-Offset (`DOWNLOAD_CHECKPOINT`). Leerer WAL wird auf `WAL_INTENT_NONE` normalisiert.

**Step 2 — Confirmation.** Die 64-Bit-Trial-Nonce liegt im TMR (hi/lo, hardware-quorum-geschützt — bewusst nicht in den Append-Entries). Drei Autorisierungswege: `confirm->check_ok(nonce)` (RTC-basiertes OS-Confirm), `WAL_INTENT_CONFIRM_COMMIT` mit XOR-exaktem Nonce-Match, oder `RECOVERY_RESOLVED` plus harmloser Reset-Reason (PIN/POWER_ON). Alles doppelt geschirmt; jede Inkonsistenz wird stumm als `NONE` verworfen. Bei Erfolg: Failure-Counter → 0 (TMR-Update), Intent → NONE persistieren, danach **Datenhygiene**: Fire-and-Forget-Erase des kompletten Staging-Slots (Firmware-Leak-Prävention; Fehler hier dürfen den committeten Boot nicht mehr gefährden). **Sticky Lock**: `DEVICE_LOCKED` überspringt den gesamten Confirm-Block — ein gelocktes Gerät kann sich nicht durch normale OS-Confirmation entsperren.

**Step 2.5 — Cloud-Command-Evaluation** (`_handle_cloud_cmd`, Details Abschnitt 9). Läuft bewusst **vor** dem Lock-Gate, damit `TOOB_CMD_UNLOCK` greifen kann. Leerer/invalider Slot ist der Normalfall und ein Skip-Pfad mit eigenem CFI-Token. Nach erfolgreichem Dispatch wird der Command-Slot gelöscht (Fire-and-Forget).

**Step 2.7 — Lock-Gate.** `DEVICE_LOCKED` aktiv → doppelt geschirmt → `boot_panic(BOOT_ERR_DEVICE_LOCKED)`; dort wartet Block 3A des Rescue auf ein UART-Unlock-Envelope. Der Nicht-Lock-Pfad XORt sein eigenes Token.

**Step 3 — Crash-Kaskade.** App-Crash = Reset-Reason ∈ {WDT, HardFault, Brownout} **und** Intent ∉ {UPDATE_PENDING, TXN_BEGIN} (damit Crashes während der Intent-Verarbeitung selbst nicht doppelt zählen). Counter++ im TMR. `_handle_rollback_flow`: Crash unmittelbar nach `TXN_COMMIT` (oder offenes `ROLLBACK_PENDING`) → `boot_rollback_trigger_revert` (physischer Restore Staging→App), danach vollständige Heilung (Counter 0, Intent NONE, kein Recovery-OS — die alte Firmware ist wieder Baseline). Sonst → `boot_rollback_evaluate_os` (Kaskade App/Recovery-OS/Terminal, Abschnitt 8.1).

**Step 4 — Update-Pipeline** (`_handle_update_flow`), nur bei `UPDATE_PENDING`:

1. Manifest aus `open_txn->offset` komplett in die Arena lesen, **zcbor-Parse** des SUIT-Manifests.
2. **Pointer-Sandboxing**: Ed25519-Signatur (exakt 64 B), PQC-Signatur/-Key und Conditions-Bytestrings müssen via `is_buffer_within` nachweislich in der Arena liegen; die Ed25519-Signatur wird auf den Stack kopiert (Anti-Aliasing — sie muss das spätere Überschreiben des Buffers überleben).
3. **Envelope-first** `boot_verify_manifest_envelope` (Abschnitt 7.1), erst danach SVN-Anti-Rollback (`boot_rollback_verify_svn`), dann **Device-Binding**: ist Conditions-Feld 201 gesetzt, muss es 32 Bytes lang sein und constant-time mit dem DSLC matchen (Anti-Clone). SBOM-Digest (Payload-Feld 301, 32 B) und SVN/Key-Index gehen in die Diag-Telemetrie (EU-CRA).
4. **Image-Routing** über `images[0]`: *Raw* → `boot_merkle_verify_stream` direkt auf dem Staging-Slot (Scratch-Bereich der Arena hinter dem Manifest, 8-Byte-aligned). *Delta* → erst werden die Chunk-Hashes in einen Stack-Buffer gerettet (**Use-After-Overwrite-Defense**: die SDVM zerstört die Arena, in der die Hashes liegen; `_Static_assert` beweist, dass der 2-KB-Buffer für die maximale Chunk-Anzahl reicht), dann `boot_delta_apply` mit Ziel `CHIP_SCRATCH_SLOT` (**Anti-Brick**: nie in-place in den App-Slot patchen, die Base wird noch gebraucht), anschließend zwingender Merkle-Verify des SDVM-Outputs gegen die geretteten signierten Hashes (ACE-Prävention bei korrumpierter VM-Ausgabe). Swap-Quelle wird entsprechend Scratch oder Staging.
5. **Swap** via `boot_swap_apply` in den App-Slot; danach optional **Multi-Image** für `images[1..3]` (NetCore/Recovery-OS/inaktive Stage-1-Bank, Whitelist-gebunden, Abschnitt 7.5), mit lückenlos fortgeschriebenem Staging-Offset.
6. **Commit**: `TXN_COMMIT` atomar appen; erst dann wird die extrahierte SVN an den TMR übergeben (`extracted_svn` → `app_svn` nur bei echter Installation).
7. **Smart Error Topology**: Verifikationsklasse-Fehler (VERIFY/DOWNGRADE/INVALID_ARG/BOUNDS/STATE/NOT_FOUND) verwerfen das Update kontrolliert (Intent → NONE persistieren, kein Bootloop), nur Hardware-Fehler propagieren in die Panic.

**Step 5 — Handoff-Vorbereitung.** Header des Ziel-Slots (App oder Recovery) lesen, Magic doppelt prüfen, Entry-Point/Size exportieren. `is_tentative_boot` = (Intent == TXN_COMMIT, doppelt geschirmt). Bei Tentative: 64-Bit-Nonce via `boot_random_safe` generieren, in den TMR persistieren, offenen Intent re-appen (Stateful-Slide-Abandonment-Fix gegen Verlust durch TMR-Rotation). Net-Accum und Resume-Offset werden ans OS durchgereicht.

**Finales CFI-Gate** nur, wenn `core_status == BOOT_OK` (Hardware-Fehler dürfen nicht in `INVALID_STATE` umgeschrieben werden). Bei jedem Fehler wird `target_out` genullt; TMR/WAL-Stack-Residuen werden immer zeroized.

---

## 6. Persistenz: WAL & TMR (`boot_journal.c`)

**Layout.** 4–8 physische Sektoren (`TOOB_WAL_SECTORS`, Adressen/Größen aus dem generierten Manifest, Sanity-Check Header+1 Entry pro Sektor). Jeder Sektor beginnt mit einem 64-Byte-Header (`wal_sector_header_aligned_t`): Magic, `sequence_id`, `erase_count`, eingebetteter **TMR-Payload (48 B)**, CRC-32. Dahinter Append-Entries in 64-Byte-Slots (`wal_entry_aligned_t`): Magic, Intent, 64-Bit-Nonce (8-Byte-aligned ohne Padding), Deadline, 256-Bit-Transfer-Bitmap, `delta_chunk_id`, generisches Offset, CRC-Trailer. ABI-Drift zwischen Bootloader- und libtoob-Typen ist über eine Batterie von `_Static_assert`s versiegelt.

**Sequenzlogik.** RFC-1982-Serial-Number-Arithmetik (`is_newer_sequence`) macht das Sliding Window wrap-sicher über die volle 32-Bit-Lebensdauer.

**Init.** Scan aller Header (CRC glitch-geschirmt) → höchste Sequenz = aktiver Sektor. Fabrikneu: Sektor 0 initialisieren. Sonst: **TMR-Majority-Vote** als striktes Whole-Struct-Voting (kein „Frankenstein“-Byte-Mixing) über die Sequenzen N, N-1, N-2 mit Constant-Time-Vergleichen; bei totaler Korruption gewinnt die höchste kryptografisch valide Sequenz. Danach **linearer Frontier-Scan**: vorwärts bis zum ersten vollständig gelöschten Slot oder Torn-Write (CRC/Magic-Fail stoppt die Front) — ECC-trap-frei, UB-frei.

**Append.** Vor jedem Write ein Full-Width-Pre-Check der Zielposition: ist sie nicht vollständig erased (Brownout-Fragment), wird sofort rotiert statt drübergeschrieben (HardFault-Prävention auf ECC-Flash). Rotation wählt per Wear-Leveling den am wenigsten abgenutzten Sektor, **schützt aber die letzten 4 Sequenzen** (N…N-3): die 3-Sektor-TMR-Rotation darf nie einen offenen Intent in Sektor N-3 überrollen (Cross-Sector-Fix). Erase-Budget wird gegen `max_erase_cycles` geprüft (`COUNTER_EXHAUSTED`). Nach dem Write: Read-Back + Constant-Time-Vergleich; bei Mismatch wird der Sektor logisch als voll markiert, damit der nächste Append rotiert.

**TMR-Update.** Zero-Wear-Skip bei bit-identischem Payload (constant-time). Sonst Quorum-Write über **3 frische Sektoren** (Sequenzen n+1, n+2, n+3): Stromausfall nach Sektor 1 → die alten zwei Kopien gewinnen den Vote; nach Sektor 2 → die neuen zwei gewinnen. Mathematisch tearing-sicher ohne Doppel-Writes in denselben Sektor.

**Rekonstruktion.** Rückwärts-Scan ab der Frontier, **über Sektorgrenzen hinweg** (absteigende Sequenzen, Underflow-Guards für Fabrikgeräte). Intent-Isolation: der erste intakte Kernel-Intent ist die aktive Transaktion; `NET_SEARCH_ACCUM` und `DOWNLOAD_CHECKPOINT` werden unabhängig davon eingesammelt; Side-Band-Intents (SLEEP_BACKOFF, DEPRECATED_NONCE, ROLLBACK_PENDING) beeinflussen den Hauptzustand nicht. Early-Exit, sobald alle gesuchten Komponenten gefunden sind.

**Intent-Übersicht (Auszug):**

| Intent | Bedeutung |
|---|---|
| `NONE` | Stabiler Idle-Zustand |
| `UPDATE_PENDING` | Manifest im Staging, Pipeline beim nächsten Boot ausführen |
| `TXN_COMMIT` | Update geswappt, Trial-Boot steht aus |
| `CONFIRM_COMMIT` / `RECOVERY_RESOLVED` | OS-/Rescue-seitige Bestätigung |
| `TXN_ROLLBACK_PENDING` / `TXN_ROLLBACK` | Physischer Revert läuft / abgeschlossen |
| `NET_SEARCH_ACCUM`, `DOWNLOAD_CHECKPOINT`, `SLEEP_BACKOFF` | OS-/Edge-Checkpoints |
| `CLOUD_CMD`, `DEVICE_LOCKED` | Cloud-Control-Plane (Soft-Lock = sticky) |

---

## 7. Update-Pipeline

### 7.1 Manifest-Verifikation (`boot_verify.c`)

Envelope-first nach COSE_Sign1-Philosophie: nichts aus dem Manifest wird interpretiert, bevor die Hülle bewiesen ist. Ablauf (7-Token-CFI):

1. **TOCTOU-Shield**: die komplette `boot_verify_envelope_t` wird auf den Stack geklont, bevor irgendein Feld geprüft wird (DMA-Manipulation zwischen Check und Use ausgeschlossen).
2. **Bounds**: Manifest-Größe gegen den Work-Buffer, Adressraum-Wrap-Proofs.
3. **Constant-Time-Downgrade-Check**: es wird *immer* der eFuse-Slot `key_index + 1` gelesen (branchless Index, kein Timing-Leak). Existiert der nächste Key, ist der angefragte revoziert → `BOOT_ERR_DOWNGRADE`. Hardware-Fehler beim Read schalten kein Downgrade frei.
4. **Root-Key-Extraktion** glitch-gegated, plus **Zero-Key-Forgery-Defense** (All-0x00/All-0xFF-Keys aus geglitchten Reads oder leeren eFuses werden abgewiesen — der bekannte Ed25519-Trivial-Forge-Vektor).
5. **Ed25519-Verify** über den SRAM-geladenen Manifest-Buffer; optional `TOOB_DOUBLE_VERIFY` (zweite vollständige Ausführung gegen algorithmus-interne Faults, dokumentierter DPA-Trade-off). Der Root-Key wird unmittelbar danach geschreddert.
6. **PQC-Hybrid-Enforcement**: erzwungen, wenn die Hardware (`is_pqc_enforced`) **oder** das Manifest es verlangt; der Skip-Pfad ist per Negativ-CFI bewiesen (ein Glitch kann PQC nicht stillschweigend überspringen). PQC-Key und -Signatur müssen per Pointer-Beweis **innerhalb des Ed25519-signierten Buffers** liegen (Anchored-Payload-Defense) und den Zero-Key-Check bestehen.
7. CFI-Resolution, Single-Exit-Zeroize (Keys, Envelope-Klon).

### 7.2 Image-Integrität (`boot_merkle.c`)

Funktional eine **Flat-Hash-List** (nicht binärer Baum): chunk-weises Streaming-SHA-256 mit O(1) RAM. Vorab eine vollständige Bounds-Algebra: Wrap-Checks für `addr+size`, `num_chunks*chunk_size`, `num_chunks*32`, Pointer-Wrap des Hash-Arrays, Chunk-Size gegen Sektor-Maximum und Write-Align, Arena ≥ Chunk-Size, und die **Truncation-Defense**: `num_chunks` muss exakt `ceil(image_size/chunk_size)` sein — abgeschnittene Manifeste fallen mathematisch durch. Pro Chunk: Flash→Arena, Hash, Constant-Time-32-Byte-Vergleich (dualer Fwd/Rev-Akkumulator). Abschließender Coverage-Beweis (`remaining_bytes == 0`, doppelt geschirmt) gegen erzwungene Loop-Abbrüche.

### 7.3 Delta-Updates (`boot_delta.c`) — TDS1-SDVM

Eine Turing-unvollständige Streaming-Bytecode-VM, die Patches mit O(1) RAM direkt Flash→Flash assembliert:

- **Format**: 32-Byte-Header (Magic `TDS1`, Ziel-/Base-Größe, 8-Byte-Base-Fingerprint, Literal-Offset, Instruktionszahl, CRC) + 16-Byte-Instruktionen mit **isolierter CRC pro Instruktion** (SPI-Bit-Rot) + Literal-Block. Der Literal-Offset wird hart gegen `header + instr_count*16` erzwungen — kein angreifergewählter Offset, kein Arbitrary-Flash-Read.
- **Opcodes** mit High-Hamming-Encodings: `COPY_BASE`, `INSERT_LIT` (heatshrink-LZSS-dekomprimiert), `BZERO`, `EOF`.
- **Ghost-Base-Verifikation**: vor dem ersten Patch-Byte wird die alte Firmware komplett gestream-hasht und die ersten 8 Digest-Bytes gegen den Header-Fingerprint geprüft (Anti-Brick: Patch auf falsche Base unmöglich). Beim Brownout-Resume entfällt das, weil die Base bereits im vorigen Lauf verifiziert und im WAL geloggt wurde.
- **Arena-Layout**: heatshrink-Decoder-State (alignment-gepaddet) + zwei 8-Byte-alignte Hälften (Write-Combiner / Read-Buffer). Wichtig: der Decoder-State wird bei Checkpoints **nicht** resettet (das würde den LZSS-Stream zerstören).
- **Zip-Bomb-Guards** an zwei Stellen: statisch für Raw-Opcodes, dynamisch im `poll()`-Loop für `INSERT_LIT` und explizit auch im EOF-Drain (dort lag historisch die Lücke).
- **Checkpointing/Resume**: `flush_target_buffer` schreibt mit Smart-Erase-Pre-Emption (isolierte Stack-Buffer, damit die Arena nicht zerstört wird), Read-Back-Verify pro 64-Byte-Step, und setzt WAL-Checkpoints (`delta_chunk_id`) exakt an `CHIP_FLASH_MAX_SECTOR_SIZE`-Grenzen. Nach Brownout: Fast-Forward per **Dry-Run** — die VM läuft logisch erneut, schreibt aber bis zum Checkpoint nichts; Checkpoint-Sektoralignment wird nachgerechnet.
- **Abschluss**: finaler Flush mit Write-Align-Padding, Anti-Truncation-Beweis (`eof_reached && target == expected_size`), CFI-Resolution, Arena-Zeroize.

### 7.4 A/B-Swap (`boot_swap.c`)

In-Place-Swap über den Scratch-Slot mit **kryptografischer Zustandsdeduktion** statt Metadaten in den Zielsektoren:

- **Blockgrößen-Solver**: pro Iteration das Maximum der Sektorgrößen von Src/Dest/Scratch (Anti-Write-Amplification auf asymmetrischen Flashes), letzte Iteration mit Align-Padding.
- **Zero-Wear-Identity-Check**: CRC-Gleichheit + Constant-Time-Byte-Vergleich → Block überspringen (spart Erases und WAL-Writes massiv, z. B. bei Re-Flashes).
- **WAL-Anker**: vor jeder destruktiven Phase werden `crc_src`, `crc_dest` und der Marker `0xAA55AA55` in die `transfer_bitmap` der offenen Transaktion geschrieben.
- **Tearing-Deduktion**: nach Brownout werden die physischen CRCs von Src/Dest/Scratch gegen die geankerten CRCs gematcht; daraus wird eindeutig abgeleitet, welche der drei Phasen (A: Dest→Scratch-Backup, B: Src→Dest, C: Scratch→Src) noch laufen müssen. Inkonsistente Kombinationen sind FATAL (`FLASH_HW` / `INVALID_STATE`) — niemals raten.
- **EOL-Schutz**: erreicht der App-Slot-Erase-Counter `max_erase_cycles`, geht der Swapper in einen persistenten Read-Only-Zustand (`COUNTER_EXHAUSTED`).
- **Telemetrie**: physische Erases pro Slot landen am Ende kumuliert im TMR (Wear-Leveling-Reporting fürs OS).

### 7.5 Multi-Image (`boot_multiimage.c`)

Deployment von bis zu 256 Sub-Images (NetCore, Modems, Recovery-OS, inaktive Stage-1-Bank) aus dem Staging-Archiv:

- **Software-MPU**: bevor ein Byte angefasst wird, müssen *alle* Komponenten beweisen, dass `[target, target+size)` vollständig in einer Whitelist-Region liegt (subtraktive Wrap-Proofs) — Arbitrary-Write in Bootloader/WAL/App-Slot ist mathematisch ausgeschlossen.
- **O(1)-Brownout-Resume** über die 256-Bit-`transfer_bitmap`: bereits verankerte Komponenten werden übersprungen (mit CFI-Verrechnung).
- **Phantom-Read-Back-Defense**: gehasht wird ausschließlich der **zurückgelesene** Buffer, nicht der geschriebene — der Vendor-Treiber kann keinen RAM-Cache validieren lassen; vor dem Read-Back wird der Buffer genullt (TOCTOU-Beweis der physischen SPI-Transaktion). Finaler SHA-256 gegen den signierten `expected_hash`.
- Pro Komponente ein atomarer WAL-Checkpoint (Bitmap-Bit + Append); dynamischer Erwartungs-CFI aus `~component_id` (siehe 2.2).

---

## 8. Recovery & Resilienz

### 8.1 Rollback-Kaskade (`boot_rollback.c`)

**SVN-Hybrid-Check** (`verify_svn`): Manifest-SVN muss ≥ persistierter WAL-SVN (App oder Recovery getrennt) **und** ≥ eFuse-Epoch (Monotonic-Counter) sein — identische Versionen (Reparatur-Re-Flash) sind zulässig, Downgrades nicht. Blank-Device-Toleranz (kein TMR → Baseline 0), eFuse `NOT_SUPPORTED` ist erlaubt, alles glitch-geschirmt + CFI.

**Crash-Kaskade** (`evaluate_os`): dreistufige, doppelt evaluierte CFI-Pfad-Flags (0x111…, 0x222…, 0x444…):
Counter ≤ `MAX_RETRIES` → App; ≤ `MAX_RETRIES + MAX_RECOVERY_RETRIES` → Recovery-OS; darüber Terminal:
im Unattended-Edge-Mode wird der Backoff-Level (`SLEEP_BACKOFF`-Intent mit Wakeup-Zeit) **vor** dem Schlafen ins WAL geschrieben, dann `enter_low_power` mit eskalierender Penalty (4 h → 12 h → 24 h Cap, saturierende Arithmetik); kehrt die HAL fälschlich zurück, folgt WDT-Starvation. Attended-Mode → direkt `boot_panic(BOOT_RECOVERY_REQUESTED)`. Pfad-Konfusion (State-Confusion-Attack) → Panic.

**Physischer Revert** (`trigger_revert`): Staging-Header lesen (DMA-aligned 32-B-Buffer), Magic/Size glitch-geschirmt prüfen, Bounds-Proofs. Resume über `ROLLBACK_PENDING.delta_chunk_id` oder neuen Intent ankern. Dann sektorweise Staging→App: Zero-Wear-Identity-Fast-Forward, sonst WAL-Checkpoint **vor** dem Erase, Erase via `boot_swap_erase_safe`, chunk-weiser Copy mit Phase-Bound-CRC-Verify inkl. **Ghost-Match-Prevention** (Arena vor dem Read-Back nullen — beweist, dass wirklich der SPI-Flash und nicht ein Treiber-Cache antwortet). Abschluss: Wear-Counter ins TMR, `TXN_ROLLBACK`-Intent, CFI-Resolution, Single-Exit-Zeroize.

### 8.2 Boot-Confirmation (`boot_confirm.c`)

`boot_confirm_evaluate`: Nonce-Check via Confirm-HAL (WDT-gerahmt), kombiniert mit einer **Reset-Reason-Whitelist** — nur POWER_ON, PIN_RESET und **BROWNOUT** gelten als unschädlich. Der Brownout steht bewusst auf der Whitelist: ein Monate nach dem Update leerlaufender Akku ist kein OS-Crash; passierte der Brownout während des Handoffs, liefert `check_ok()` ohnehin false. Glitch-Doppel-Check; jeder Fail → Flag clearen → Rollback-Signal (`BOOT_ERR_VERIFY`), Hardware-Fehler werden durchgeschleift.

### 8.3 Energie-Gate (`boot_energy.c`)

Vor jeder Flash-destruktiven Update-Aktion: **Fail-Open für Netzgeräte** (keine SoC-HAL → bedingungslos OK, aber CFI-bewiesen). Sonst zwei unabhängige Kriterien: PMIC-Veto (`can_sustain_update`) und Roh-ADC mit **branchless 3-Sample-Median** (SPA-resistent, kompiliert zu CSEL) inkl. ADC-Failure-Traps (0 mV / 0xFFFFFFFF) und **Brownout-Hysterese** (+12,5 % auf `min_battery_mv`, weil Ruhespannung nach Brownout trügerisch hoch ist; overflow-gesichert). Fällt das Gate: im Unattended-Mode 1-h-Deep-Sleep-Penalty zum Laden (**bevor** das WAL angefasst wird — Brownout-Death-Loop-Prevention), sonst `boot_panic(BOOT_ERR_POWER)`. CFI-Bruch → Starvation-Freeze.

### 8.4 Stage 1.5 — Serial Rescue (`boot_panic.c`, `_Noreturn`)

Terminalzustand für Hardware-Fehler, Lock-State und Recovery-Pin. Architektur:

- **Arena-Mapping**: vier disjunkte Zonen (Challenge 128 / RX 128 / Verify 80 / Chunk = Rest), Summenbeweis per `_Static_assert`; Stack bleibt sauber (>1,2 KB gespart), freie Zonen werden phasenweise recycelt (DSLC-Read, Root-Key, Read-Back).
- **2FA-Challenge**: `[TRNG-Nonce(32) | DSLC(≤64, gepaddet) | Monotonic-Counter(4) | Reason(4)]`, COBS-geframt an den Techniker.
- **Auth**: exakt 104-Byte-Payload (`slot_id`, `sequence_id`, Nonce-Echo, Ed25519-Signatur über die 72-Byte-Message `[Nonce|DSLC|Slot|Seq]` mit dem Root-Key). **Anti-Replay**: `sequence_id` muss exakt `counter + 1` sein; nach Erfolg wird der Counter gebrannt (Token-OTP-Entwertung). Unaligned-Access-sicher via `memcpy`+`offsetof` direkt aus dem RX-Buffer.
- **Anti-Brute-Force über Power-Cycles**: der Fehlversuchszähler wird in RTC-Backup-Registern persistiert; ohne RTC ersatzweise 5 s deterministischer Boot-Delay. Exponentielle Penalty `2^min(n,10) · 100 ms`.
- **CFI-Beweis** zwischen Auth und Transfer: State-Confusion-Glitches, die direkt in den Flash-Pfad springen, landen im SOS-Loop.
- **Block 3A (Device-Locked)**: sendet `LCK`, wartet auf ein vollwertiges Cloud-Command-Envelope; nur `TOOB_CMD_UNLOCK` (kryptografisch via `boot_cloud_cmd_evaluate_buffer`) entsperrt → `ULK` → erzwungener Kaltstart.
- **Block 3B (Firmware-Stream)**: `RDY`/`ACK`/`EOF`-Protokoll, Naked-COBS-Chunks in den Staging-Slot mit Align-Padding, glitch-geschirmten Bounds, Smart-Erase und Read-Back-Verify pro Chunk; jeder Fehler erzwingt `session_reset` (neue Challenge). Nach `EOF`: Arena-Wipe und **bewusster WDT-Timeout** als Handoff-Reset, mit NULL-Pointer-Trap als HardFault-Fallback.
- **Randständiges**: `enter_sos_loop` (Blink-Halt mit WDT-Kicks) wenn keine Console/Crypto-HAL existiert; `toob_ecc_trap` als kontextfreier NMI/HardFault-Endpunkt (WDT-Biss abwarten); eigener `__stack_chk_fail`/`__stack_chk_guard`, um 120–145 KB libc-Bloat (abort/raise/printf) aus dem Binary zu halten.

---

## 9. Cloud-Control-Plane (`boot_cloud_cmd.c`)

Der Bootloader kann ohne OS-Beteiligung kryptografisch signierte Cloud-Befehle ausführen, die das OS zuvor in den `CHIP_CLOUD_CMD_SLOT` gelegt hat.

**Key-Hierarchie (KDM).** Der Cloud-Key ist nicht der Root-Key, sondern über ein **Key Delegation Manifest** delegiert: 128-Byte-Struktur (Sequenz, neuer Cloud-Pubkey, Root-Signatur über die ersten 36 Bytes, Flash-Align-Padding, per `_Static_assert` fixiert) in zwei A/B-Slots. `load_active_cloud_key`: beide Slots lesen, Root-Key laden (mit Zero-Key-Glitch-Defense — ein All-Zero-Read würde sonst beliebige KDM-Fakes akzeptieren), beide Signaturen glitch-geschirmt prüfen, bei zwei gültigen Slots gewinnt die höhere Sequenz. **KDM-Healing** (Reparatur des defekten Slots) ist per Architekturentscheid Aufgabe des OS-Background-Tasks — der Bootloader schreibt im Lesepfad nicht (O(1)- und Watchdog-Garantie). Der Fallback auf eFuse-Slot 1 ist **ausschließlich** im Provisioning-Zustand (DSLC == 0x00) erlaubt; ein provisioniertes Gerät mit zerstörten KDM-Slots verweigert (Downgrade-by-Destruction-Defense).

**Envelope-Pipeline** (`evaluate_buffer`, 5-Token-CFI): CBOR-Decode (zcbor-CDDL) → **Device-ID-Match** constant-time gegen die DICE-abgeleitete ID (`boot_derive_device_id`) → **Anti-Replay** (`counter_min > Monotonic-Counter`, doppelt geschirmt, sonst `DOWNGRADE`) → Ed25519 über das Envelope abzüglich der 64-Byte-Signatur mit dem aktiven Cloud-Key (Key wird sofort danach gewiped) → **Exhaustion-Defense**: der Counter wird **erst nach** erfolgreicher Signaturprüfung exakt um die Differenz gebrannt (ein Angreifer kann eFuses nicht per ungültigen Envelopes verbrauchen); jeder einzelne Burn ist glitch-geschirmt, ein fehlgeschlagener Burn bricht den Dispatch ab (Replay-Fenster geschlossen). `evaluate_flash` kapselt das mit Single-Read-TOCTOU-Defense (Slot einmal komplett in die Arena) und Aliasing-Verbot zwischen Envelope- und Work-Zone.

**Dispatch** (in `boot_state.c`): `KILLSWITCH` → `DEVICE_LOCKED`-Intent (Soft-Lock, sticky); `UNLOCK` → Intent NONE; `FORCE_UPDATE` → `UPDATE_PENDING`; `WIPE` → `wipe_requested` im Handoff (Factory-Reset führt das OS aus); `REVOKE` → DSLC wird auf 0xFF gebrannt und das Gerät geht in den permanenten Dead-Halt (Hard-Lock, irreversibel). `ROTATE_KEY`/`NOP` sind im Boot-Dispatch No-Ops (Rotation läuft über die KDM-Slots).

*Hinweis aus dem Code:* die Slot-Adressen (`CHIP_CLOUD_CMD_SLOT_ABS_ADDR`, KDM A/B) sind aktuell noch als temporäre Fallback-Makros definiert, solange das Device-Manifest sie nicht liefert.

---

## 10. Factory Provisioning (`boot_provisioning.c`)

`_Noreturn`-UART-Loop, ausschließlich erreichbar bei DSLC == 0x00 (Gate in `boot_main`). Arena-partitioniert (RX 256 / TX 16 / Key 128, Summen-Assert). Wire-Protokoll: COBS-Frames `[CMD(1)][Payload][CRC-32(4)]`, CRC glitch-geschirmt geprüft, jede Antwort ein 4-Byte-LE-Status. Kommandos: `BURN_KEY` (Index + Key, über Key-Buffer mit Zeroize davor/danach), `SET_DSLC`, `SET_PROTECTION` (32-Bit-Maske), `ENABLE_SB`, `ENABLE_FE`, `READ_ID` (Status-Frame + UID-Frame), `REBOOT` (Arena-Wipe, dann bewusste WDT-Starvation als Hardware-Reset). Kein Rückpfad in den normalen Bootflow — die Trennung Provisioning↔Boot ist strukturell, nicht nur logisch.

---

## 11. Hilfsmodule

**`boot_cobs.c/.h`** — gemeinsame COBS-Transportschicht für Panic und Provisioning (aus `boot_panic.c` extrahiert, DRY). Sende-Pfad mit WDT-Feeding; **In-Place-Decode** mit der Invariante `write_idx ≤ read_idx`, glitch-geschirmtem Bounds-Check pro Block (Anti-RCE/Wraparound) und Zeroize des Trailing-Garbage (Anti-Leakage); blockierender Frame-Empfang mit Overflow-Defense (Buffer vernichten, auf nächsten Sync warten).

**`boot_crc32.c`** — bitweises IEEE-802.3-CRC-32 (0xEDB88320), tabellenfrei (Flash-Größe vor Geschwindigkeit). Wird überall für WAL-Header/-Entries, Handoff/Diag-Sealing, TDS-Instruktionen und Swap-Zustandsdeduktion verwendet.

**`boot_ct_utils.h`** — siehe 2.2; zusätzlich `cfi_derive` als Token-Fabrik.

**`boot_secure_zeroize.S` / `_host.c`** — byte-weises Zeroize in nacktem ARM-Thumb-/RISC-V-Assembler, damit kein Compiler den Wipe als Dead Code eliminiert; Host-Variante mit volatile + Memory-Clobber für die Sandbox.

**`boot_delay.c`** — glitch-resistentes Warten: Dual-Track-Akkumulation (Hardware-Ticks + Software-Zähler mit invertiertem Zwilling für Bit-Flip-Detektion), **Time-Warp-Kappung** (Delta > 1000 ms → 0; bestraft Timer-Manipulation und fängt 16-Bit-HAL-Wraps), algebraisch bewiesene Obergrenze gegen `max_sw_limit`-Overflow, 50-ms-Steps (WDT-sicher). Exit nur, wenn HW **und** SW das Ziel erreichen; eingefrorener Timer oder übersprungene `delay_ms` (Software-Zähler explodiert) sowie ALU-Divergenz enden in WDT-Starvation — im Penalty-Sleep ist ein Fail-Open-Return streng verboten.

**`boot_identity.c`** — DICE-artige Device-ID: `SHA-256(Chip-UID ‖ Root-PubKey ‖ "toob-device-id-v1")`, O(1) iterativ, vollständige Capability-Gates und Residuen-Zeroize (inkl. Dummy-Finalize bei Update-Fehlern).

**`boot_diag.c`** — Telemetrie-Akkumulator im `.noinit`: Verify-/Boot-Zeiten, letzter Fehler + Vendor-Code, SVN/Key-Index/SBOM-Digest (EU-CRA-Evidenz), Recovery-Events, Wear-Daten; `boot_diag_seal()` nullt explizit das Struct-Padding (kein Stack-Leak über Alignment-Löcher) und setzt den CRC-Trailer.

---

## 12. Handoff-Verträge an das OS

Zwei CRC-versiegelte `.noinit`-Strukturen (8-Byte-aligned, Section-Attribut compilerabhängig):

**`toob_handoff_state`** — Magic (`TENTATIVE`/`COMMITTED`; Stage 0 wertet TENTATIVE für den Bank-Rollback aus), Struct-Version, 64-Bit-Boot-Nonce (das OS muss sie bei `confirm` echoen), übersetzter Reset-Reason (1:1-Mapping per Static-Assert garantiert), gebootete Partition (App/Recovery), Netz-Such-Akkumulator, Download-Resume-Offset, 32-Byte-Device-ID (bei Derivation-Fehler im Dev-Mode genullt), `wipe_requested`.

**`toob_diag_state`** — siehe `boot_diag.c`; das OS extrahiert daraus das CBOR-Telemetriepaket für das Fleet-Management.

Der Vertrag mit dem OS: ein Tentative-Boot **muss** vor dem nächsten Reset über die Confirm-HAL mit der exakten Nonce bestätigt werden, sonst greift beim nächsten Boot die Crash-/Rollback-Kaskade. Die Nonce selbst liegt redundant im TMR — ein Angreifer kann sie nicht durch WAL-Append-Manipulation ersetzen.

---

## 13. Modulmatrix

| Modul | Verantwortung | Schreibt Flash? | Nutzt Arena exklusiv? |
|---|---|---|---|
| `stage0_*` | Root of Trust, Bank-Auswahl, S1-Verify | nein | nein (eigene Stack-Buffer) |
| `boot_main` | Init/Deinit-Kaskade, Gates, Handoff-Sealing | nein | definiert sie |
| `boot_state` | Lifecycle-Orchestrierung, SUIT-Parsing, Routing | via Journal | ja (Manifest/Scratch) |
| `boot_journal` | WAL, TMR-Quorum, Wear-Leveling, Rekonstruktion | ja (WAL-Sektoren) | nein (Stack-Structs) |
| `boot_verify` | Envelope-first Ed25519 + PQC-Hybrid | nein | nutzt Work-Buffer (Arena) |
| `boot_merkle` | Flat-Hash-Streaming-Verify | nein | ja (Chunk-Buffer) |
| `boot_delta` | TDS1-SDVM, heatshrink, Checkpoints | ja (Scratch-Slot) | ja |
| `boot_swap` | A/B-Swap, Tearing-Deduktion, EOL | ja (App/Staging/Scratch) | ja |
| `boot_multiimage` | Peripherie-Deployment, Software-MPU | ja (Whitelist-Regionen) | ja |
| `boot_rollback` | SVN, Crash-Kaskade, Revert | ja (App-Slot, WAL) | ja |
| `boot_confirm` | Nonce-/Reset-Reason-Bewertung | via Confirm-HAL | nein |
| `boot_energy` | Update-Energie-Gate | nein | nein |
| `boot_cloud_cmd` | KDM, Envelope-Verify, Counter-Burn | eFuse-Counter, Cmd-Slot-Erase | ja |
| `boot_panic` | Stage 1.5 Rescue, Lock-Pfad | ja (Staging-Slot) | ja |
| `boot_provisioning` | Factory-Loop (DSLC 0) | via Provisioning-HAL | ja |
| `boot_cobs`/`crc32`/`ct_utils`/`zeroize`/`delay`/`identity`/`diag` | Querschnitts-Primitiven | nein | nein |

---

## 14. Hinweise aus dem Codestand

Drei Punkte, die der Code selbst als offen markiert und die für die Architektur-Lesart relevant sind:

1. **Cloud-Cmd/KDM-Slot-Adressen** sind temporäre Fallback-Makros, bis das Device-Manifest (`generated_boot_config.h`) sie liefert — bis dahin ist die Slot-Platzierung pro Chip nicht garantiert kollisionsfrei mit User-Daten.
2. **Signatur-Längenermittlung im Cloud-Envelope** (`envelope_len − 64` statt eines vom zcbor-Generator gelieferten Payload-Offsets) ist als pragmatische Übergangslösung im Kommentar dokumentiert; sie setzt voraus, dass die 64-Byte-Signatur das physisch letzte Feld des Envelopes ist.
3. **KDM-Healing** ist bewusst aus dem Bootloader herausgehalten (OS-Background-Task) — der Recovery-Pfad bei dauerhaft einseitig defektem KDM-Slot hängt damit an der OS-Verfügbarkeit.

Diese Punkte ändern nichts am Sicherheitsmodell der dokumentierten Pfade, gehören aber in jede ARCHITECTURE.md-Pflege und ins Pre-Go-Live-Tracking.