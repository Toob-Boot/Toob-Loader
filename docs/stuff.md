# Toob-Boot: Killswitch & Device Lifecycle — Integrationsarchitektur

---

## 1. Bestandsaufnahme: Was existiert, was fehlt

Die Architektur-Beschreibung definiert ein 3-Schichten Trust-Modell (Cloud → Bootloader → OS), vier DSLC-Zustände, signierte Cloud-Befehle und einen zweistufigen Killswitch. Gegen den bestehenden Code geprüft ergibt sich folgendes Delta:

**Vollständig vorhanden und direkt nutzbar:**

Die `crypto_hal_t` liefert bereits `read_pubkey(key, len, index)` mit Key-Index-Routing, `read_dslc()`, `read_monotonic_counter()` / `advance_monotonic_counter()`, `verify_ed25519()`, `random()` und `hash_*()`. Das WAL-System (`boot_journal.c`) unterstützt atomare Appends, TMR Majority-Vote und Cross-Sector Reconstruction. Die 2FA-Recovery in `boot_panic.c` implementiert bereits Challenge-Response mit Nonce, DSLC, Counter und Ed25519-Signatur. Die SUIT-Manifest-Pipeline über zcbor ist operativ, inklusive COSE-Sign1-Envelope-Verifikation in `boot_verify.c`.

**Teilweise vorhanden, erweiterungsbedürftig:**

Stage 0 (`stage0_main.c`) liest bereits den DSLC, nutzt ihn aber nicht als Boot-Gate. Der `boot_state.c`-Orchestrator kennt keine Lock-State-Evaluierung. Die `boot_types.h` enthält noch keine Cloud-Command-Enums. Das Handoff-Struct (`toob_handoff_t`) transportiert keine Device-ID ans OS.

**Vollständig neu zu implementieren:**

Cloud-Command Envelope Parsing (neues CBOR-Schema), DEVICE_LOCKED WAL-Intent und zugehörige Boot-Logik, Device-ID DICE-Derivation (basierend auf Chip-UID), Key Delegation Manifest (KDM) mit A/B-Slots, TMR-Erweiterung für KDM-Sequenzen, REVOKE-Pfad (eFuse DSLC → 0xFF), dedizierter `CHIP_CLOUD_CMD_SLOT`, die Provisioning/Lock-Pipeline in Stage 1 und die Cloud-seitige HSM/Inventory-API.

---

## 2. Architektonische Leitprinzipien

### 2.1 Separationsprinzip: Zwei Key-Domänen

Die strikte Trennung von Root Key (Slot 0, Firmware-Signing) und Cloud Command Key (Killswitch/Unlock) ist die sicherheitskritischste Design-Entscheidung. Der Root-Key liegt unveränderlich in eFuse Slot 0. Der Cloud-Key wird in einem Key Delegation Manifest (KDM) im Flash gespeichert, welches mit dem Root-Key signiert ist. Um Korruption und Downgrades zu verhindern, nutzt das KDM ein A/B-Slot-System (2 × 4 KB) und verankert seine Sequenznummer im hochsicheren TMR-WAL.

### 2.2 OS bleibt untrusted

Cloud-Befehle erreichen den Bootloader **ausschließlich** über den Flash. Das OS empfängt signierte Envelopes via TLS, schreibt sie unverändert in den dedizierten `CHIP_CLOUD_CMD_SLOT` und rebootet. Die Verifikation erfolgt erst in Stage 1. Kein OS-Code darf Signaturen evaluieren, Counter manipulieren oder DSLC-Bits setzen.

### 2.3 Additiver, nicht-invasiver Einbau

Die Killswitch-Logik darf die existierende Update-Pipeline nicht brechen. Sie wird als zusätzliche Evaluierungsstufe **vor** dem Update-Check in `boot_state_run()` eingefügt, analog zur bestehenden Crash-Cascade in Step 3.

---

## 3. Stage 0: DSLC-Gate

### 3.1 Eingriffspunkt

In `stage0_main.c` nach der Hardware-Initialisierung (Punkt 1) und vor dem Boot-Pointer-Lookup (Punkt 2). Der DSLC wird über `crypto_hal->read_dslc()` gelesen.

### 3.2 Entscheidungslogik

```
DSLC = 0x00 (DEVELOPMENT):
  → Signature-Check wird OPTIONAL (Fallback: Boot ohne Verify)
  → Aktiviert den Provisioning-Entry-Point in Stage 1 (UART lauscht)

DSLC = 0x01 (PROVISIONED) oder 0x03 (PRODUCTION):
  → Signature-Check MANDATORY (aktuelles Verhalten bei vorhandenem Key)
  → Cloud Commands werden evaluiert (Stage 1 Aufgabe)

DSLC = 0xFF (REVOKED):
  → Sofort dead_halt(platform), kein Boot, kein Recovery, kein UART
  → Stage 1 wird NICHT geladen
```

### 3.3 Implementierungsdetail (Majority-Vote & Fail-Closed)

Um transiente Hardware-Glitches bei extremen Temperaturen abzufangen, nutzt Stage 0 einen Majority-Vote (3 aus 5) für den DSLC-Read. Der Check folgt danach einem Fail-Closed Double-Shield-Pattern. Er muss **vor** jeglicher Console-Initialisierung stehen.

```c
uint8_t dslc_reads[5];
uint8_t majority = 0xFF; // Default: REVOKED (Fail-Closed)
bool found = false;

for (int round = 0; round < 5 && !found; round++) {
        uint8_t dslc_buf[64];
        size_t dslc_len = sizeof(dslc_buf);
        platform->crypto->read_dslc(dslc_buf, &dslc_len);
        dslc_reads[round] = (dslc_len > 0) ? dslc_buf[0] : 0xFF;
    if (round >= 2) {
        // Prüfe ob irgendein Wert mindestens 2x vorkommt
        for (int i = 0; i <= round && !found; i++) {
            int count = 0;
            for (int j = 0; j <= round; j++) {
                if (dslc_reads[i] == dslc_reads[j]) count++;
            }
            if (count >= 2) { majority = dslc_reads[i]; found = true; }
        }
    }
}

// Fail-Closed Shield Check
volatile uint32_t allow_boot_1 = 0, allow_boot_2 = 0;
bool valid_dslc = (majority == 0x00 || majority == 0x01 || majority == 0x03);

if (valid_dslc) allow_boot_1 = BOOT_OK;
BOOT_GLITCH_DELAY();
if (allow_boot_1 == BOOT_OK && valid_dslc) allow_boot_2 = BOOT_OK;

if (allow_boot_1 != BOOT_OK || allow_boot_2 != BOOT_OK || allow_boot_1 != allow_boot_2) {
    dead_halt(platform); // DEFAULT: Halt.
}
```

```c
_Noreturn static void dead_halt(const boot_platform_t *platform) {
    // Kein UART, kein Flash, kein Crypto — alles bleibt uninitialisiert
    if (platform->clock && platform->clock->deinit) platform->clock->deinit();
    if (platform->soc && platform->soc->disable_interrupts) platform->soc->disable_interrupts();

    // WDT-Starvation-Loop (By Design: Zuverlässigster Halt)
    // Optional: Latch-Mode via soc->enter_low_power(), falls hardwareseitig unterstützt.
    while (1) { BOOT_GLITCH_DELAY(); }
}
```

### 3.4 Development-Mode Bypass

Wenn `DSLC = 0x00` und `read_pubkey(key, 32, 0)` fehlschlägt (keine Keys gebrannt), überspringt Stage 0 die Signaturprüfung. Ein `DSLC = 0x00` mit gebrannten Keys ist ein valider Zustand, in dem die Signaturprüfung normal läuft.

---

## 4. Stage 1: Cloud-Command Pipeline

### 4.1 Dedizierter Slot und WAL-Intent

Cloud-Commands und OTA-Firmware dürfen nicht kollidieren. Im Memory-Map wird ein `CHIP_CLOUD_CMD_SLOT` (4 KB) definiert. Der Slot wird für jeden neuen Befehl gelöscht (Wear-Leveling-Overhead ist bei < 10 Befehlen pro Jahr unnötig).

Ergänzung in `boot_journal.h`:

```c
WAL_INTENT_CLOUD_CMD = 12
```

### 4.2 CDDL-Schema für Cloud-Command Envelope

```cddl
toob_cloud_cmd = {
    1: bstr .size 32,    ; device_id (SHA-256 Hash)
    2: uint .size 1,     ; command (toob_cloud_cmd_t enum)
    3: uint .size 4,     ; counter_min (Anti-Replay)
    4: uint .size 4,     ; issued_at (Unix Timestamp)
    ? 5: bstr,           ; params (optional, command-specific)
}
```

Die Command-Typen beginnen ab `0x01` (`NOP` ist verboten, da jeder Command den Replay-Counter inkrementieren muss). Das Schema wird durch zcbor in einen C-Parser (`boot_cloud_cmd.c`) transformiert.

### 4.3 Cloud-Command Evaluierung: Striktes Sequencing

Die Evaluierung in `boot_cloud_cmd.c` verhindert TOCTOU-Angriffe und DoS-Counter-Exhaustion durch eine strikte Verifikationsreihenfolge:

```
1. Flash-Read des Envelopes in einen lokalen SRAM-Buffer (Kein Double-Read!)
2. CBOR Parse auf dem SRAM-Buffer (kein Counter-Touch)
3. Device-ID Match (kein Counter-Touch)
4. Counter-Wert aus Envelope >= current+1 ? (kein Counter-Touch)
5. Ed25519 Verify gegen Cloud-Key aus KDM (kein Counter-Touch)
6. ← ERST HIER: advance_monotonic_counter()
7. Command Dispatch
```

Bei Fehlschlag in Schritt 2-5 wird ein exponentieller Penalty-Delay (`boot_delay_with_wdt`) erzwungen, um Brute-Force/CPU-DoS zu unterbinden. Dies folgt dem GAP-C06 Pattern: `(1U << shifts) * 100ms` mit einem Maximum bei 10 Shifts (~100 Sekunden).

### 4.4 Command-Dispatch

| Command               | Aktion                                               | WAL-Effekt                                                 |
| --------------------- | ---------------------------------------------------- | ---------------------------------------------------------- |
| `FORCE_UPDATE (0x01)` | Triggert `_handle_update_flow()` nach Bounds-Check   | Append `WAL_INTENT_UPDATE_PENDING` mit Offset aus `params` |
| `KILLSWITCH (0x02)`   | Schreibt `DEVICE_LOCKED` Flag in den WAL             | Append `WAL_INTENT_DEVICE_LOCKED`                          |
| `UNLOCK (0x03)`       | Entfernt `DEVICE_LOCKED` aus dem WAL                 | Append `WAL_INTENT_NONE`                                   |
| `ROTATE_KEY (0x04)`   | Schreibt inaktiven A/B-Slot, swappt Index im WAL     | Erfordert `params` mit dem neuen KDM                       |
| `WIPE (0x05)`         | Löscht Bootloader-Slots, setzt Flag für OS           | Append `WAL_INTENT_TXN_ROLLBACK`                           |
| `REVOKE (0x06)`       | Brennt `DSLC = 0xFF` in die eFuse. **Irreversibel.** | Kein WAL nötig — der nächste Boot in Stage 0 erkennt 0xFF  |

**Detail zu FORCE_UPDATE:** Es wird lediglich ein physischer Bounds-Check auf den Parameter durchgeführt, bevor der Intent geschrieben wird:

```c
if (cmd.params_offset > CHIP_FLASH_TOTAL_SIZE - MIN_MANIFEST_SIZE) return BOOT_ERR_FLASH_BOUNDS;
```

Das eigentliche Manifest-Parsing passiert regulär in der Update-Pipeline.

**Detail zu WIPE:** Der Bootloader löscht nur die App-/Staging-/KDM-Slots und setzt das System zurück. Das OS erhält im Handoff ein `wipe_requested`-Flag, um seine eigenen User-Data-Partitionen (NVS/FAT) zu löschen.

### 4.5 Soft-Lock und Eingeschränktes Rescue

Der `DEVICE_LOCKED`-Zustand (`WAL_INTENT_DEVICE_LOCKED = 13`) wird in `boot_state_run()` (Step 2.5) evaluiert:

```
1. Rekonstruiere WAL → prüfe auf WAL_INTENT_DEVICE_LOCKED
2. Wenn LOCKED:
   a. Lese den CHIP_CLOUD_CMD_SLOT aus.
   b. UNLOCK Envelope gefunden und verifiziert? → Counter advance, Lock entfernen, normal weiter
   c. Sonst → boot_panic(platform, BOOT_ERR_DEVICE_LOCKED)
```

In `boot_panic.c` prüft das Rescue-System den `reason`. Ist das Gerät `DEVICE_LOCKED`, wird der Firmware-Flash-Pfad übersprungen! Stattdessen wird über UART nach erfolgreicher 2FA ein signiertes UNLOCK-Envelope erwartet.

### 4.6 Hard-Lock: REVOKE-Pfad

`TOOB_CMD_REVOKE` ist der einzige Cloud-Command, der direkt eine eFuse-Operation auslöst (`provisioning_hal->write_dslc(0xFF)`). Jeder andere Parameterwert als `0xFF` wird von der HAL abgelehnt. Der REVOKE-Pfad greift auf denselben HAL-Pointer zu wie das Provisioning, umgeht aber die Phase-Lock-Regel (`DSLC == 0x00`), da es sich um den ultimativen `0xFF`-Übergang handelt.

**Kritischer Sicherheitsaspekt:** Der REVOKE-Befehl muss vier unabhängige Bestätigungen durchlaufen:

1. Standard-Envelope-Verifikation (Ed25519 + Counter).
2. Device-ID-Verifikation im `params`-Feld (doppelte Sicherheit gegen Flotten-Wipe).
3. Dedizierter CFI-Token `CFI_REVOKE_CONFIRMED = 0xDEADDEAD` als Hardware-Glitch-Schutz vor dem eFuse-Burn.
4. **Hardware-Read-Back:** Nach dem Burn-Vorgang wird `read_dslc()` aufgerufen und verifiziert, dass die eFuse tatsächlich `0xFF` enthält. Bei Inkonsistenz friert das System ein.

---

## 5. Device Identity: DICE-Derivation

### 5.1 Berechnung

Die Device-ID ist kryptografisch an den physischen Chip gebunden. Die variable UID-Länge (z.B. ESP32 6-Byte MAC vs STM32 12-Byte UID) wird direkt verhasht:

```
Device-ID = SHA-256(Chip_Unique_ID || eFuse_Root_PubKey || "toob-device-id-v1")
```

Die `crypto_hal_t` muss eine **mandatory** Funktion bereitstellen:

```c
boot_status_t (*read_chip_uid)(uint8_t *buf, size_t max_len, size_t *out_len);
```

Die Hash-Funktion zieht exakt `out_len` Bytes ein, generiert aber konsistent 32-Byte Digests.

### 5.2 Handoff-Erweiterung

Das `toob_handoff_t` wächst um das 32-Byte `device_id`-Feld und ein boolsches `wipe_requested`-Flag. Die ABI-Version `TOOB_HANDOFF_STRUCT_VERSION` wird auf `0x02000000` inkrementiert.

---

## 6. Provisioning-Pipeline: Stage 1 Phase-Locked Mode

### 6.1 Kommando-Hierarchie (`toob-cli`)

```
toob provision [--development | --production]   # Keys brennen, DSLC setzen
toob lock --confirm-production                  # PROVISIONED → PRODUCTION
toob rescue                                     # Cloud-HSM-Bridge für 2FA
toob identity                                   # Device-ID auslesen (Debug)
```

### 6.2 DSLC-Gated Provisioning in Stage 1

Um einen Doppel-Flash in der Fabrik zu vermeiden, wird der Provisioning-Entry-Point in `boot_main.c` nur aktiviert, wenn `DSLC == 0x00`. Dieser lauscht über UART auf Befehle vom `toob-cli`.

Das UART-Protokoll nutzt COBS, Frame-Marker, CRC-32 und erfordert das Halten eines Recovery-Pins, was Line-Noise-Injections ausschließt. Optional kann ein temporäres "Factory Secret" (PSK im RAM) als Defense-in-Depth verlangt werden.

**Definition:** Der `provisioning_hal_t` existiert separat zur `crypto_hal_t` und wird vom Vendor-Port bereitgestellt:

```c
typedef struct {
    boot_status_t (*burn_pubkey)(const uint8_t *key, size_t len, uint8_t index);
    boot_status_t (*write_dslc)(uint8_t value);
    boot_status_t (*set_protection_bits)(uint32_t bitmask);
    boot_status_t (*enable_secure_boot)(void);
    boot_status_t (*enable_flash_encryption)(void);
} provisioning_hal_t;
```

**Provisioning-Ablauf (DEVELOPMENT → PROVISIONED):**

1. Brenne Root Public Key → eFuse Slot 0 via `provisioning_hal->burn_pubkey(..., 0)`.
2. Schreibe initiales KDM (Cloud-Key) in KDM-Slot A.
3. Setze `WR_DIS` für Key-Blöcke (Keys eingefroren) via `provisioning_hal->set_protection_bits()`.
4. Setze `DSLC = 0x01` (PROVISIONED) via `provisioning_hal->write_dslc(0x01)`.
5. Reboot. Der Provisioning-Entry-Point ist nun durch den DSLC unwiderruflich deaktiviert.

**Production-Lock-Ablauf (PROVISIONED → PRODUCTION):**
Wenn `toob lock --confirm-production` aufgerufen wird, durchläuft das Gerät die finale Härtung:

1. Setze `RD_DIS` (Software kann Keys nicht mehr lesen).
2. Setze `JTAG_DIS` und `DL_DIS` (Debug-Port und UART-Download deaktiviert).
3. Setze `SECURE_BOOT_EN` via `provisioning_hal->enable_secure_boot()`.
4. Optional: Aktiviere Flash-Encryption.
5. Setze `DSLC = 0x03` (PRODUCTION).

---

## 7. KDM-Infrastruktur und Anti-Downgrade

### 7.1 KDM A/B Slots

Das KDM wird in `CHIP_KDM_SLOT` (2 × 4 KB) gespeichert. Um Brownout-Korruption zu verhindern, schreibt `ROTATE_KEY` in den inaktiven Slot, verifiziert, und schreibt dann einen WAL-Append, um den Index zu flippen. Bei Boot liest Stage 1 den aktiven Slot, bei Korruption den inaktiven (Selbstheilung).

### 7.2 Anti-Downgrade (TMR-Payload)

Um Replay-Angriffe mit alten KDMs zu verhindern, wächst die `wal_tmr_payload_t` um 4 Bytes:

```c
typedef struct {
    // ... bestehende Felder ...
    uint32_t kdm_sequence;   // Höchste verifizierte KDM-Sequenznummer
} wal_tmr_payload_t;
```

Beim Boot verifiziert `boot_cloud_cmd.c` das geladene KDM gegen `tmr.kdm_sequence`. Ist die KDM-Sequenz kleiner, wird das KDM abgelehnt, selbst wenn die Signatur gültig ist.

---

## 8. CMake-Integration

```cmake
option(TOOB_FEATURE_CLOUD_COMMANDS "Enable Cloud Command Pipeline" ON)
target_sources(toob_core PRIVATE ${TOOB_CORE_DIR}/boot_cloud_cmd.c)
```

Wenn `OFF`, wird `boot_cloud_cmd.c` nicht kompiliert, um MCU-Ressourcen zu sparen.
Das CBOR-Schema wird via zcbor generiert.

---

## 9. Neue `boot_types.h` Ergänzungen

```c
/* Cloud Command Types */
typedef enum {
    TOOB_CMD_FORCE_UPDATE  = 0x01,
    TOOB_CMD_KILLSWITCH    = 0x02,
    TOOB_CMD_UNLOCK        = 0x03,
    TOOB_CMD_ROTATE_KEY    = 0x04,
    TOOB_CMD_WIPE          = 0x05,
    TOOB_CMD_REVOKE        = 0x06,
} toob_cloud_cmd_t;

BOOT_ERR_DEVICE_LOCKED       = 0xF9A9A9A9,
BOOT_ERR_CMD_REPLAY          = 0xFABABABA,
BOOT_ERR_CMD_DEVICE_MISMATCH = 0xFBCBCBCB,

WAL_INTENT_CLOUD_CMD         = 12,
WAL_INTENT_DEVICE_LOCKED     = 13,
```

---

## 9. libtoob OS-API Erweiterungen

### 9.1 Cloud-Command Flash-Writer

```c
toob_status_t toob_submit_cloud_command(const uint8_t *envelope, uint32_t envelope_len);
```

Schreibt den Envelope-Blob in den dedizierten `CHIP_CLOUD_CMD_SLOT`, validiert den Flash-Schreibvorgang via CRC-Read-Back, erstellt einen `WAL_INTENT_CLOUD_CMD`-Append und gibt `TOOB_OK` zurück. Die Verifikation erfolgt beim nächsten Boot.

### 9.2 Device-ID Accessor

```c
toob_status_t toob_get_device_id(uint8_t device_id_out[32]);
```

Liest die Device-ID aus dem validierten Handoff-Struct.

### 9.3 Lock-Status Query

```c
bool toob_is_device_locked(void);
```

Gibt Auskunft über den Locked-State für OS-Metadaten. Hat keine Sicherheitsrelevanz.

---

## 10. Sicherheitskritische Überlegungen

### 10.1 Timing des Cloud-Command-Checks

```
Step 1: WAL Reconstruction
Step 2: Confirmation Check
Step 2.5: Cloud-Command Evaluierung (Liest aus CHIP_CLOUD_CMD_SLOT)
Step 2.7: Lock-State Prüfung
Step 3: Crash Cascade
Step 4: Update Pipeline (Liest aus CHIP_STAGING_SLOT)
Step 5: Handoff + Device-ID
```

### 10.2 Counter-Exhaustion & Anti-Replay

eFuse-basierte Monotonic Counter haben eine begrenzte Kapazität (z.B. 256). **Jeder** Cloud-Command verbraucht einen Counter-Schritt, was unbegrenzte Replay-Attacken ausschließt. Für 10+ Jahre Lifecycle reichen 256 kritische Operationen völlig aus. NOP-Befehle (ohne Counter-Advance) sind ein DoS-Risiko und daher verboten.

### 10.3 Key-Rotation via Key Delegation Manifest (KDM)

`TOOB_CMD_ROTATE_KEY` brennt keine eFuses mehr. Stattdessen wird ein KDM (signiert mit dem Root Key) in den Flash geschrieben. Stage 1 verifiziert das KDM bei jedem Boot gegen den Root-Key aus eFuse Slot 0 und extrahiert den aktuellen Cloud-Key. Unbegrenzte Rotationen sind somit hardware-schonend möglich.

### 10.4 Offline-Geräte und Replay-Fenster

Das `issued_at`-Feld im Command dient der Flotten-Auditierung. Der physische Monotonic-Counter verhindert Replays.

### 10.5 Glitch-Resistenz der REVOKE-Operation

`write_dslc(0xFF)` benötigt 3 Stufen: Envelope-Verifizierung, Device-ID-Bindung und Hardware-Read-Back nach dem Burn-Vorgang.

---

## 11. Testbarkeit und Sandbox

### 11.1 Mock-Strategie

Die Sandbox (`TOOB_ARCH=host`) mockt die neuen HAL-Funktionen: `write_dslc()`, `read_chip_uid()`.

### 11.2 Fuzz-Targets

**`fuzz_cloud_cmd_parser`:** Prüft zcbor-Codegen auf Memory-Corruption.
**`fuzz_cloud_cmd_verify`:** Validiert State-Transitions und Fehlerbehandlung bei manipulierten Envelopes.

---

## 12. Zusammenfassung: Implementierungsreihenfolge

| Phase | Modul                                            | Aufwand |
| ----- | ------------------------------------------------ | ------- |
| **A** | `boot_types.h` + `wal_tmr_payload_t` Updates     | Gering  |
| **B** | Stage 0 DSLC-Gate (Majority-Vote + Fail-Closed)  | Gering  |
| **C** | CDDL-Schema + zcbor-Codegen für Cloud-Commands   | Mittel  |
| **D** | `boot_cloud_cmd.c` (Parse + SRAM-Verify + KDM)   | Hoch    |
| **E** | Device-ID Derivation (`read_chip_uid`)           | Mittel  |
| **F** | `boot_state.c` Integration + `boot_panic.c` Lock | Mittel  |
| **G** | Handoff-Erweiterung (ABI V2, `wipe_requested`)   | Mittel  |
| **H** | `toob-cli` Provisioning-Modus (Phase-Locked S1)  | Hoch    |
| **I** | Sandbox-Mocks + Fuzz-Targets                     | Mittel  |
