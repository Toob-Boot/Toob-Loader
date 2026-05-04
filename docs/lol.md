Basierend auf der von dir bereitgestellten (beeindruckend gehärteten und streng P10-konformen) Architektur lässt sich der Update-Zyklus extrem robust, tearing-sicher und als echter "Zero-Allocation" Workflow abbilden.

Da dein System strikt in **Stage 0 (Immutable Root-of-Trust)**, **Stage 1 (Bootloader Core)** und das **Feature-OS (RTOS via `libtoob`)** getrennt ist, ergeben sich für die beiden Cases (OS-Update vs. Bootloader-Update) zwei unterschiedliche, aber optimal ineinandergreifende Hardware-Zyklen.

Hier ist der optimale Ablauf für beide Cases, inklusive der Identifikation von **4 architektonischen Lücken** in deinem aktuellen Code, die für das Case 2 Bootloader-Update noch geschlossen werden müssen.

---

### Case 1: Der optimale Zyklus für das OS (Delta-Update)

Da du Delta-Updates über eine SDVM (Streaming Delta Virtual Machine) einsetzt, darf das laufende OS **niemals** in-place gepatcht werden, da ein Brownout das System unwiederbringlich bricken würde. Dein Code ist hierfür bereits mit einem dedizierten **A/B Safe Buffer (`CHIP_SCRATCH_SLOT_ABS_ADDR`)** gerüstet.

**Der Zyklus:**

1. **Download & Intent (RTOS-Seite):**
   Das OS (Zephyr/ESP-IDF) lädt das SUIT-Manifest und den komprimierten TDS1 Delta-Stream über seine Cloud-Verbindung herunter und speichert diese "blind" im `CHIP_STAGING_SLOT`. Es ruft lediglich `toob_set_next_update(manifest_addr)` aus der `libtoob` auf. Das schreibt den `WAL_INTENT_UPDATE_PENDING` atomar (P10) in den WAL-Sektor. Das RTOS rebootet.
2. **Pre-Flight Check (Stage 1):**
   Stage 1 startet, liest das WAL, erkennt den Update-Wunsch und lädt das SUIT-Manifest. Noch bevor irgendetwas geflasht wird, prüft `boot_verify_manifest_envelope()` die Ed25519-Signatur glitch-resistent ab. Danach wird der `base_fingerprint` gegen das aktuelle OS evaluiert (Anti-Brick).
3. **Delta Assemblierung (Stage 1 SDVM):**
   `boot_delta_apply()` führt den Patch-Vorgang aus. Die Zero-Allocation Streaming VM liest Block für Block aus dem aktiven `APP_SLOT` (alte Firmware), appliziert den Delta-Patch und schreibt das **vollständige, neue Image** in den `CHIP_SCRATCH_SLOT`. Der alte App-Slot bleibt währenddessen zu 100 % unangetastet.
4. **Merkle-Verifikation & Swap (Stage 1):**
   `boot_merkle_verify_stream()` prüft das neue Image im Scratch-Slot gegen die Chunk-Hashes aus dem Manifest. Erst bei 100%igem Erfolg triggert Stage 1 `boot_swap_apply()`. Der Scratch-Slot wird nun sicher in den `APP_SLOT` gespiegelt (Tearing-Proof durch WAL Checkpointing).
5. **Tentative Boot (Stage 1):**
   Stage 1 setzt den Intent auf `WAL_INTENT_TXN_COMMIT`. Die `.noinit` RAM Boundary (`toob_handoff_t`) wird mit `TOOB_STATE_TENTATIVE` und der generierten deterministischen `boot_nonce` befüllt. S1 springt ins neue OS.
6. **Confirmation / Rollback (RTOS-Seite):**
   Das neue OS bootet (`TOOB_OS_INIT_OR_PANIC`), prüft die Cloud-Konnektivität und ruft bei Erfolg `toob_confirm_boot()` auf. Das Update wandelt sich von _TENTATIVE_ zu _COMMITTED_.
   _(Crasht das RTOS hingegen in einer WDT-Schleife, erkennt Stage 1 beim nächsten Start den fehlenden Confirm und rollt mit `boot_rollback_trigger_revert()` sicher auf die alte OS-Version aus dem Scratch-Slot zurück)._

---

### Case 2: Der optimale Zyklus für das Bootloader-Update (Stage 1 / Core)

Ein laufender Bootloader kann sich nicht aus sich selbst heraus sicher überschreiben (XIP Limitierung). Dein Code in `boot_config.h` ist dafür bereits brillant als **Dual-Bank-Architektur** ausgelegt (`CHIP_STAGE1A_ABS_ADDR` und `CHIP_STAGE1B_ABS_ADDR`).

Da Stage 0 _immutable_ (unveränderlich in Mask-ROM/Write-Protect) ist, obliegt es S0 zu entscheiden, ob Bank A oder Bank B gebootet wird.

**Der Zyklus:**

1. **Download (RTOS-Seite):**
   Das RTOS lädt das neue Stage-1-Binary (Raw, da unkomprimiert meist nur ~28KB) in den Staging-Slot, ruft `toob_set_next_update()` auf und führt einen Reset aus.
2. **Multi-Image Routing (Alte Stage 1):**
   Das aktive Stage 1 erkennt im SUIT-Manifest, dass es sich um ein Bootloader-Update handelt (z.B. `image_type = 3`). Es leitet das Update in `boot_state.c` an den `boot_multiimage_apply()` Orchestrator weiter.
3. **Cross-Bank Flashing (Alte Stage 1):**
   `boot_multiimage_apply()` schreibt das neue Binary zwingend in die **inaktive Bank** (Bsp: S1 läuft aus Bank A und flasht in Bank B). Die aktive Bank überschreibt sich niemals selbst!
4. **Pointer Flip im WAL:**
   Nach erfolgreicher Signaturprüfung der inaktiven Bank modifiziert S1 das TMR-Payload des WAL (`boot_journal_update_tmr`) und flaggt den Zeiger auf die neue Bank um (z.B. `active_stage1_bank = 1`). Ein Reboot wird ausgelöst.
5. **Verifikation & Handoff (Stage 0):**
   Nach dem Reset startet **Stage 0**. S0 liest das WAL aus, sieht `active_stage1_bank = 1`, verifiziert erneut die Ed25519-Signatur von Bank B (!) und springt per Assembler-Jump hinein.
6. **Self-Healing Fallback (Stage 0):**
   Ist das neue Stage 1 in Bank B defekt (Hardware-Crash, Bug), fängt der Watchdog das System ab. `stage0_evaluate_tentative()` registriert den unbeendeten Boot in S0, rotiert den Pointer zurück auf Bank A und rettet das System vor dem Brick.

---

### ⚠️ Notwendige Code-Korrekturen für Case 2 (Bootloader Update)

Um diesen Case 2 Update-Zyklus lückenlos durch deine P10-Logik zu schleusen, gibt es in der vorliegenden Codebasis noch **4 kleine Architektur-Lücken**, die geschlossen werden müssen:

#### Fix 1: Logikfehler in `stage0_boot_pointer.c` beheben

Aktuell liefert deine Stage 0 für `primary_slot_id == 0/1` den `APP_SLOT` und `STAGING_SLOT` zurück. Das ist für einen Multi-Stage Loader falsch: Stage 0 muss den Bootloader (Stage 1) aufrufen, nicht direkt das RTOS!

```c
// Korrektur in stage0_boot_pointer.c
if (shield_1 == BOOT_OK && shield_2 == BOOT_OK) {
  if (hdr.data.sequence_id > highest_seq) {
    highest_seq = hdr.data.sequence_id;
    /* FIX: Stage 0 wählt die Bootloader-Bank, NICHT das Feature-OS! */
    active_slot = (hdr.data.tmr_data.active_stage1_bank == 0)
                      ? CHIP_STAGE1A_ABS_ADDR
                      : CHIP_STAGE1B_ABS_ADDR;
  }
}
```

#### Fix 2: TMR Payload (`boot_journal.h`) um `active_stage1_bank` erweitern

Das WAL muss sich merken, welche Bootloader-Bank aktiv ist.

```c
typedef struct {
  uint32_t primary_slot_id;          /* OS Bank: 0 = App, 1 = Staging */
  uint32_t active_stage1_bank;       /* NEU: 0 = Stage1A, 1 = Stage1B */
  uint32_t app_svn;
  /* ... restliche Variablen ... */
} wal_tmr_payload_t;
```

_(Da `wal_tmr_payload_t` hierdurch von 36 auf 40 Bytes anwächst, muss das `_padding[12]` im `wal_sector_header_t` auf `_padding[8]` reduziert werden, um die statische 64-Byte WAL-Geometrie aufrechtzuerhalten)._

#### Fix 3: SUIT CDDL Manifest freischalten

In der `suit/toob_suit.cddl` muss Stage 1 als Typ definiert werden, damit das Cloud-Backend Updates korrekt routen kann:

```cddl
401: uint .size 1,  ; image_type (0=App, 1=NetCore, 2=Recovery, 3=Stage1)
```

#### Fix 4: MPU-Whitelist & Routing (`boot_state.c`) erweitern

In `boot_state.c` (Z. 420+) muss das P10-Routing für `image_type == 3` hinzugefügt werden. Zudem muss die MPU-Whitelist das Schreiben in die Bänke explizit erlauben:

```c
} else if (sub_img->toob_image_raw.image_type == 3) {
    /* Identifiziere inaktive Bank und setze sie als Ziel */
    uint32_t active_s1_bank = current_tmr.active_stage1_bank;
    components[comp_count].target_addr = (active_s1_bank == 0)
                                         ? CHIP_STAGE1B_ABS_ADDR
                                         : CHIP_STAGE1A_ABS_ADDR;
}
// ...
// Whitelist in boot_state.c erweitern, um P10 Arbitrary-Write Defense nicht zu triggern!
boot_allowed_region_t whitelist[4] = {
    {CHIP_NETCORE_SLOT_ABS_ADDR, 0x00200000},
    {CHIP_RECOVERY_OS_ABS_ADDR, 0x00050000},
    {CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE}, /* NEU */
    {CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE}  /* NEU */
};
```

_(Analog muss in `stage0_tentative.c` beim Rollback von S1 ebenfalls zwischen `CHIP_STAGE1A_ABS_ADDR` und `CHIP_STAGE1B_ABS_ADDR` statt `APP` / `STAGING` getoggelt werden)._
