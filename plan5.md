# Technische Architektur: Slot-Transport-Schicht (Backlog-Grundlage)

**Zweck:** Die im Masterplan beschriebene Zwei-Schichten-Architektur (chip-agnostischer
Transactional Slot Manager + austauschbare Slot Transport Provider) auf Datei-, Interface- und
Integrationsebene so konkret machen, dass sie direkt in einen großen Backlog zerlegt werden kann.

**Leitprinzip:** *Der Core trägt die Algorithmen, der Registry-Treiber deklariert nur Fähigkeiten.*
Ein generischer Chip braucht keinen Treiber-Code — nur eine `slot_caps_t`. Spezialhardware
(Bank-Swap, MMU-Remap) liefert je eine winzige Primitive. Provider-Auswahl ist **Compile-Time**
(Codegen wählt einen, `--gc-sections` strippt den Rest).

---

## 1. Design-Iterationen (verworfene erste Entwürfe → finale Entscheidung)

Damit der Backlog auf der *gereiften* Architektur steht, hier die Punkte, an denen der naive
Erstentwurf beißt und wie er aufgelöst wurde:

**I1 — Runtime- vs. Compile-Time-Provider.** *Erst:* Provider-Registry mit Runtime-Negotiation
(`select(caps)`). *Verworfen,* weil MCU-Firmware ein festes Target hat → Caps sind beim Build bekannt
→ Runtime-Auswahl kostet Flash für ungenutzte Provider. *Final:* Codegen setzt
`#define TOOB_TRANSPORT_PROVIDER …` aus den Caps; nur ein Provider wird gelinkt. Das Interface bleibt
sauber, die Selektion ist statisch.

**I2 — Eigener Boot-Pointer-Bereich vs. TMR-Feld.** *Erst:* separate A/B-Pointer-Region (Mailbox-
Klon). *Verworfen,* weil die TMR bereits ein quorum-rotierender, brownout-sicherer A/B-Speicher ist —
ein zweiter wäre redundant und ein weiterer Wear-/Korrektheits-Angriffspunkt. *Final:* aktiver
App-Slot = TMR-Feld `active_app_slot`; Commit = `boot_journal_update_tmr` mit geflipptem Slot. Für
HW-Tiers ist der „Pointer" das Hardware-Register; der Provider abstrahiert den Commit.

**I3 — Delta-Output-Ziel.** *Erst:* Delta schreibt in Scratch, Swap nutzt Scratch als Temp (= der
bestätigte Bug). *Final:* Der Provider besitzt die Ziel-Topologie. Dual-Slot: Delta-Output direkt in
den inaktiven Slot → Flip. Single-Slot: dedizierter Output-Bereich → Two-Phase-One-Way. Die geteilte
Adresse existiert nicht mehr.

**I4 — Wie dünn ist der Treiber wirklich?** *Ziel geprüft:* generischer fixe-Adresse-Single-Slot-
Chip → Treiber = **reine Daten** (`slot_caps_t`, kein Code). STM32-Dual-Bank → Caps + `bank_flip()`
(~30 Zeilen). ESP32-C6 → Caps + `xip_remap_commit()`. Der Core carriert 100 % der Algorithmen.

**I5 — Verifikation vs. Commit-Reihenfolge.** *Invariante, universell:* Das Ziel-Image wird
verifiziert, *bevor* der Commit (Flip) es aktiv macht. Für Null-Kopie-Tiers: Secondary in-place
verifizieren, dann flippen. Für Kopie-Tiers: Read-Back-CRC pro Effekt + Merkle-Verify des
zusammengesetzten Images, dann committen. Der `EFF_FLIP` ist auf Verify-Erfolg gegated.

---

## 2. Die Kern-Abstraktionen (neue Header)

### `common/include/boot_slot_caps.h` (geteilt: Core + Treiber)

```c
typedef enum {
  SLOT_EXEC_FIXED = 0,       /* muss von fixer physischer Adresse laufen */
  SLOT_EXEC_RELOCATABLE,     /* Image läuft aus jedem Slot (dual-linked/PIC) */
  SLOT_EXEC_XIP_REMAP,       /* Ausführungsadresse per MMU remappbar */
  SLOT_EXEC_BANK_SWAP        /* HW-Dual-Bank-Flip */
} slot_exec_model_t;

typedef struct {
  slot_exec_model_t exec_model;
  uint8_t  slot_count;           /* 1 = in-place swap nötig; 2 = dual-slot */
  bool     has_scratch;
  uint32_t scratch_size;
  uint32_t max_erase_cycles;     /* Endurance, für wear-aware Auswahl (Phase 5) */

  /* Chip-Primitiven — NULL wenn nicht unterstützt. Nur diese liefert der Treiber. */
  boot_status_t (*bank_flip)(uint32_t target_bank);
  boot_status_t (*xip_remap_commit)(uint32_t slot_phys_addr);
  boot_status_t (*exec_addr_select)(uint32_t slot_phys_addr); /* VTOR/Reset-Vector, Tier 1 */
  boot_status_t (*get_active_slot)(uint32_t *out_slot);        /* HW-Tiers: Register lesen */
} slot_caps_t;

/* Vom generierten Treiber-Glue bereitgestellt (Registry-Package). */
const slot_caps_t *boot_get_slot_caps(void);
```

### `common/include/boot_slot_transport.h` (Provider-Interface)

```c
typedef struct {
  uint32_t src_addr;         /* neues Image (Staging raw / Scratch delta) */
  uint32_t dest_addr;        /* Ausführungs-Slot */
  uint32_t backup_addr;      /* wohin die alte App gesichert wird (0 = nicht nötig) */
  uint32_t length;
  bool     src_is_delta_output;
  boot_dest_slot_t dest_slot;
  uint8_t  transport_id;     /* welcher Provider diese Txn fährt (Resume-Dispatch) */
} slot_txn_t;

typedef struct {
  const char *name;
  uint8_t     tier;
  uint8_t     id;            /* stabile ID, landet im WAL für Resume-Dispatch */
  boot_status_t (*apply)(const boot_platform_t *pf, const slot_caps_t *caps,
                         slot_txn_t *txn, wal_entry_payload_t *open_txn,
                         uint8_t *arena, size_t arena_len);
  boot_status_t (*rollback)(const boot_platform_t *pf, const slot_caps_t *caps,
                            slot_txn_t *txn, uint8_t *arena, size_t arena_len);
} slot_transport_t;

/* Compile-Time gewählt; gibt den einen einkompilierten Provider zurück. */
const slot_transport_t *boot_transport_active(void);
```

---

## 3. Die Provider (Core-seitig, je Tier — Algorithmen sind chip-agnostisch)

| Datei | Provider | Tier | Wear | Nutzt Caps-Primitive |
|-------|----------|------|------|----------------------|
| `boot_transport_pointer.c` | Bank-Flip / XIP-Remap / Dual-Slot-Pointer | 0–1 | 1 E + 1 W / neuem Sektor | `bank_flip` / `xip_remap_commit` / `exec_addr_select` |
| `boot_transport_swapmove.c` | Swap-Move (in-place, kein Hotspot) | 2 | ~2 ops / Sektor | — |
| `boot_transport_oneway.c` | Two-Phase One-Way (raw + delta) | 3 | 2 ops / Sektor | — |
| `boot_transport_swapscratch.c` | Swap-Scratch (Fallback, aus altem `boot_swap.c`) | 4 | 3 ops / Sektor | — |

Alle planen `flash_effect_t[]` und rufen den **gemeinsamen** `boot_effect_execute`. `boot_multiimage.c`
ist bereits das One-Way-Muster → wird unter `boot_transport_oneway.c` subsumiert (oder bleibt als
dessen Multi-Target-Variante). Resume: jeder Provider nutzt `open_txn->delta_chunk_id` +
`transfer_bitmap` als Checkpoint; der `transport_id` im WAL sichert, dass Resume denselben Provider
dispatcht.

---

## 4. Effect-Engine-Erweiterung

`boot_effect.c/.h`: neuer Effekt-Typ **`EFF_FLIP`** (der universelle Commit). Ausführung je Realisierung:
- Tier 0 Bank: `caps->bank_flip(target)`.
- Tier 0 MMU: `caps->xip_remap_commit(slot_phys)`.
- Tier 1 Pointer: `boot_journal_update_tmr` mit `active_app_slot = neu` (+ ggf. `exec_addr_select`).

`EFF_FLIP` ist der einzige Effekt mit „Commit-Semantik" — davor ist alles reversibel, danach ist das
neue Image aktiv. `boot_effect_execute` gated `EFF_FLIP` auf vorausgegangenen Verify-Erfolg.

---

## 5. Integrationspunkte im bestehenden Core (die kritischen Nähte)

**N1 — `boot_state.c` / `stage_swap`.** Baut ein `slot_txn_t` (statt direkt `boot_swap_apply`) und
ruft `boot_transport_active()->apply(...)`. Das Delta-Ziel wird hier aus den Caps aufgelöst (I3). Die
Multi-Image-Sub-Images (Netcore/Recovery/Stage1) laufen weiter über den One-Way-Provider.

**N2 — `boot_state.c` / STEP 5 Handoff.** Die Ausführungsadresse kommt jetzt aus dem aktiven Slot
(`caps->get_active_slot` bei HW-Tiers, `tmr.active_app_slot` bei Tier 1) statt fix
`CHIP_APP_SLOT_ABS_ADDR`. Für Tier 0/1 mit zwei Slots wählt der Handoff den aktiven physischen Slot.

**N3 — `boot_state.c` / `_handle_rollback_flow`.** Ruft `boot_transport_active()->rollback(...)`
statt `boot_rollback_trigger_revert` direkt. Für Tier 0/1 ist Rollback ein Re-Flip (0 Wear); für
Kopie-Tiers die (bestehende) Reverse-Copy; Reverse-Delta (Phase 5) ist eine Provider-Rollback-Variante.

**N4 — `boot_journal.h` / `wal_tmr_payload_t`.** Neues Feld `active_app_slot` (Tier-1-Pointer) aus dem
`reserved`-Tail; `struct_version` bump; `WAL_TMR_POPULATED_SIZE` als eine Quelle der Wahrheit
(dieselbe Disziplin wie beim Mailbox-Watermark). Optional `active_transport_id` für Resume-Robustheit.

**N5 — `wal_entry_payload_t`.** `transport_id` im offenen Txn, damit ein Brownout-Resume den richtigen
Provider dispatcht (kein Provider-Wechsel mitten in einer Txn).

**N6 — `boot_delta.c`.** Das Delta-Output-Ziel ist jetzt ein Parameter vom TSM (dedizierter
Secondary-Bereich), nicht mehr implizit der Swap-Scratch. Nur der Aufrufer (`stage_apply_delta`)
ändert sich; die VM selbst bleibt.

**N7 — `boot_hal.h`.** `const slot_caps_t *slot_caps;` in `boot_platform_t` (oder via
`boot_get_slot_caps()`), plus die optionalen Primitiven-Signaturen.

---

## 6. Registry-Anbindung (Compile-Time-Treiber-Installation)

**Fluss:** `device.toml` deklariert `chip = "stm32h743"` → Toob-Registry löst das Slot-Treiber-Package
auf → Build linkt `drivers/stm32h743/slot_caps.c` → der Manifest-Compiler generiert
`generated_slot_caps.h`/`.c` mit `boot_get_slot_caps()` **und** dem `#define TOOB_TRANSPORT_PROVIDER`
(Provider-Selektion aus den Caps). Nur der gewählte Provider wird kompiliert.

**Treiber-Package-Inhalt (das dünne Delta):**
- `drivers/<chip>/slot_caps.c` — die `slot_caps_t`-Instanz + Primitiven-Impls, wo Hardware es verlangt.
  - Generischer Cortex-M0 (1 Slot, fix): **reine Daten**, kein Code.
  - STM32-Dual-Bank: Caps + `bank_flip()` (FLASH_OPTR BFB2).
  - ESP32-C6: Caps + `xip_remap_commit()` (MMU-Table).
  - Cortex-M dual-slot relocatable: Caps + `exec_addr_select()` (VTOR).
- Optional `drivers/<chip>/README` + Conformance-Testvektoren.

**Codegen (Manifest-Compiler):**
- `generated_slot_caps.c` — `boot_get_slot_caps()` gibt die Chip-Caps zurück.
- `generated_boot_config.h` — Slot-Geometrie, Secondary-/Backup-Adressen, Boot-Pointer-Semantik,
  Scratch nur noch wo der gewählte Provider ihn braucht.

---

## 7. Build-Co-Design (hebt fixe-Adresse-Chips nach Tier 1)

- **Linker:** Dual-Linked-Images (Slot-A- + Slot-B-Adresse), beide Fixup-Sätze im Image; oder
  kompakte Boot-Time-Relocation-Tabelle.
- **Image-Format (TBM1):** ein `slot_variant`-Feld / zweiter Vektor-Satz; der Bootloader wählt beim
  Handoff den Satz des aktiven Slots (VTOR).
- **`toob`-CLI / Pipeline:** emittiert dual-slot-fähige Images; verifiziert, dass beide Varianten
  denselben Merkle-Root ergeben (identischer Code, nur Fixups).

---

## 8. Datei-Übersicht (Backlog-Rohmaterial)

**Neu (Core):**
`common/include/boot_slot_caps.h`, `common/include/boot_slot_transport.h`,
`toobloader/core/boot_transport.c/.h` (Selektions-Glue), `boot_transport_pointer.c`,
`boot_transport_swapmove.c`, `boot_transport_oneway.c`, `boot_transport_swapscratch.c`.

**Geändert (Core):**
`boot_state.c` (N1/N2/N3), `boot_journal.h/.c` (N4), `boot_effect.c/.h` (EFF_FLIP),
`boot_delta.c`-Aufrufer (N6), `boot_hal.h` (N7), `wal_wire.h` (N5), `generated_boot_config.h`.

**Retiring / migriert:**
`boot_swap.c` → `boot_transport_swapscratch.c`; `boot_multiimage.c` → One-Way-Provider;
`boot_rollback.c` → Rollback-Pfad des jeweiligen Providers (Policy `boot_rollback_evaluate_os` bleibt).

**Neu (Treiber/Registry):**
`drivers/<chip>/slot_caps.c` je Chip; generiert `generated_slot_caps.c/.h`.

**Neu (Build/Toolchain):**
Dual-Slot-Linker-Skripte, TBM1-`slot_variant`, CLI-Dual-Image-Emission.

**Neu (Test):**
Provider-Resume+Rollback-Modelle (je Provider), TSM-Invarianten-Modellcheck
(Atomarität / kein Halb-Boot / Rollback-immer-verfügbar), Roach-Motel-artige HW-Integrationstests.

---

## 9. Epic-Struktur für den Backlog

- **E0 — Sofortfix + Fundament.** Delta-Bug (Two-Phase-One-Way als erster Provider), vier
  Swap-Sofortgewinne. Entkoppelt sofort, liefert Provider #1.
- **E1 — Abstraktionen.** `boot_slot_caps.h`, `boot_slot_transport.h`, Effect-`EFF_FLIP`,
  TMR-`active_app_slot` (N4), WAL-`transport_id` (N5).
- **E2 — TSM-Refactor.** `boot_state.c` N1/N2/N3 auf die Transport-Schicht umstellen; `boot_swap.c`/
  `boot_multiimage.c`/`boot_rollback.c` als Provider migrieren.
- **E3 — Provider-Suite.** Swap-Scratch (Fallback), Swap-Move, One-Way (raw+delta), Pointer/Bank/MMU.
  Jeder mit Resume- + Rollback-Modell.
- **E4 — Capability-Codegen + Registry.** `slot_caps_t`-Treiber-Packages, Manifest-Compiler-Glue,
  Compile-Time-Provider-Selektion, `--gc-sections`-Nachweis.
- **E5 — Boot-Pointer-Commit.** Tier-0/1-Commit (TMR-Feld + HW-Primitiven), verify-before-flip-Gate,
  Handoff-Slot-Auswahl.
- **E6 — Build-Co-Design.** Dual-Linked-Images, TBM1-`slot_variant`, CLI-Emission, VTOR-Auswahl.
- **E7 — Advanced Wear.** Reverse-Delta-Rollback, wear-aware Provider-Auswahl (TMR-Counter steuernd),
  wear-gelevelter Scratch-Pool.
- **E8 — Formale Verifikation.** TSM-Invarianten-Modellcheck, per-Provider-Sims, HW-Brownout-Matrix.

**Reihenfolge:** E0 → E1 → E2/E3 (parallel) → E4/E5 → E6 → E7 → E8. E0 liefert sofort Nutzen und den
ersten Provider; E1–E3 sind das Rückgrat; E4/E5 machen es chip-übergreifend; E6 hebt die breite
Chip-Masse nach Tier 1; E7/E8 sind Perfektion + Absicherung.

---

## 10. Die nicht verhandelbare Grenze

Provider dürfen nur die **Kosten** variieren (Erases, Writes, Dauer), nie die **Sicherheit**. Der TSM
erzwingt auf jedem Chip: Es bootet immer entweder das alte oder das neue *verifizierte* Image, nie ein
Halbzustand, und bis zum Confirm ist der Rückweg garantiert. Jeder neue Provider muss diese
Invarianten gegen ein Modell beweisen, bevor er in die Registry darf.