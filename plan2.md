# Backlog: Slot-Transport-Schicht (Core-Seite)

Umsetzung der Architektur aus `slot_transport_architecture.md`, beschränkt auf den **Core** (kein
Registry-Package-Inhalt, keine Toolchain/Dual-Link-Arbeit — die haben eigene Backlogs; ihre
Core-Haken sind hier aber enthalten).

**Ticket-Schema:** ID · Ziel · Berührt · Skizze · Fertig-wenn · Aufwand · Risiko · Hängt-an.
**Aufwand:** S ≤0,5 T · M 1–2 T · L 3–5 T. **Risiko:** 🟢 mechanisch · 🟡 kritischer Pfad · 🔴 sicherheitskritischer Boot-Pfad / Design.

## Übergreifende Abnahmekriterien (gelten für JEDES Ticket)

1. **Invarianten unantastbar.** Nach jeder Änderung gilt weiterhin: Es bootet immer entweder das alte
   oder das neue *verifizierte* Image, nie ein Halbzustand; bis zum Confirm ist der Rückweg garantiert.
2. **Modell vor Merge.** Jedes Ticket, das Offsets/Flush/Checkpoint/Resume/Commit anfasst, wird gegen
   ein Referenzmodell bewiesen (frisch + Resume von jedem Checkpoint + Brownout nach jeder
   Flash-Operation → identisches Ergebnis), bevor es gemergt wird. Methodik wie bei `boot_delta`.
3. **Compile + HW.** Jedes Ticket, das Flash schreibt, braucht `-Werror`-Compile gegen echte Header +
   einen On-Hardware-Durchlauf inkl. eines echten Brownout-Resume-Tests.
4. **Verhaltenserhaltend heißt bit-identisch.** Migrations-Tickets („kein Verhaltenswechsel") werden
   gegen den Ist-Zustand bit-identisch verifiziert (gleiche Effektliste, gleiche Erase-/Write-Zahlen).
5. **C17, keine Sicherheitssemantik-Drift.** CFI, Glitch-Shields, Bounds, Single-Exit-Zeroize,
   Phase-Bound-Read-Back bleiben in jedem migrierten/neuen Provider erhalten.

---

# E0 — Sofortfix & Stabilisierung (unabhängig, sofort)

### ST-001 — Delta-Bug: Two-Phase-One-Way (chirurgisch)                         [M · 🔴]
Ziel        Den bestätigten Delta-Korruptions-/Brick-Bug beheben: Delta-Output (Scratch) kollidiert
            mit dem Swap-Temp (Scratch). Delta umgeht `boot_swap_apply` und nutzt eine zweistufige
            One-Way-Kopie über disjunkte Partitionen.
Berührt     `boot_state.c` (`stage_apply_delta`/`stage_swap`), evtl. kleiner Helper in `boot_swap.c`.
Skizze      Phase 1: App(alt) → Staging (Backup). Phase 2: Scratch(neu) → App. Kein Adresskonflikt;
            Rollback findet die alte App in Staging (wie `boot_rollback` erwartet); 2 statt 3 ops/Sek.
Fertig wenn Delta-Update bootet neues Image; Rollback nach Delta stellt altes Image her (Modell +
            HW); kein Write auf eine mit einer Quelle geteilte Adresse.
Hängt an    —  (chirurgischer Stopgap; wird später von ST-031 absorbiert)

### ST-002 — Swap-Sofortgewinne (vier sichere Optimierungen)                   [M · 🟡]
Ziel        Ohne Format-Änderung: (a) Tearing-Deduktion nur beim Resume laufen lassen (fresh →
            run_all, −60 % Pre-Phase-Reads); (b) Early-Exit-Erased-Check; (c) Identity-CRCs als
            Deduktions-CRCs wiederverwenden; (d) Whitelist-Scratch-Größe `65536` → `CHIP_SCRATCH_SLOT_SIZE`.
Berührt     `boot_swap.c` (`boot_swap_apply`, `_boot_swap_erase_tracked`).
Fertig wenn Fresh-Pfad ohne 3 Deduktions-Reads (Map-/Trace-Nachweis); Erase-Scan bricht beim ersten
            Nicht-Erased-Byte ab; Ergebnis-Image bit-identisch zum Ist.
Hängt an    —

---

# E1 — Abstraktionen & persistenter Zustand

### ST-010 — Header `boot_slot_caps.h`                                          [S · 🟢]
Ziel        `slot_exec_model_t`, `slot_caps_t` (exec_model, slot_count, has_scratch, scratch_size,
            max_erase_cycles + optionale Primitiven bank_flip/xip_remap_commit/exec_addr_select/
            get_active_slot), `boot_get_slot_caps()`-Deklaration. Nur stdint/bool, geteilt Core+Treiber.
Berührt     neu `common/include/boot_slot_caps.h`.
Fertig wenn Header steht, `_Static_assert` für ABI-Größe/Alignment; von Core und einem Dummy-Treiber
            inkludierbar ohne Zirkularität.
Hängt an    —

### ST-011 — Header `boot_slot_transport.h`                                     [S · 🟢]
Ziel        `slot_txn_t` (src/dest/backup/length/src_is_delta_output/dest_slot/transport_id),
            `slot_transport_t` (name/tier/id/apply/rollback), `boot_transport_active()`-Deklaration.
Berührt     neu `common/include/boot_slot_transport.h`.
Fertig wenn Header steht; `apply`/`rollback`-Signaturen nehmen `boot_platform_t*`, `slot_caps_t*`,
            `slot_txn_t*`, `wal_entry_payload_t*`, arena.
Hängt an    ST-010

### ST-012 — Effect `EFF_FLIP` + Verify-vor-Commit-Gate                         [M · 🟡]
Ziel        Neuer Effekt-Typ `EFF_FLIP` als *einziger* Commit-Effekt. `boot_effect_execute` führt ihn
            nur nach vorausgegangenem Verify-Erfolg aus (Gate). Realisierung je Tier delegiert
            (Caps-Primitive oder TMR-Feld).
Berührt     `boot_effect.c/.h` (`flash_effect_t`-Enum, Executor).
Skizze      `EFF_FLIP{ target_slot }`; Executor ruft `caps->bank_flip`/`xip_remap_commit` oder
            TMR-Update; davor ein `verified`-Flag im Effekt-Kontext, das nur gesetzt ist, wenn die
            vorherigen Verify-Effekte grün waren.
Fertig wenn `EFF_FLIP` ohne Verify-Vorlauf gibt `BOOT_ERR_VERIFY` (Test); mit Vorlauf committet er;
            glitch-doppelt abgesichert.
Hängt an    ST-010

### ST-013 — TMR-Feld `active_app_slot` (+ `active_transport_id`)               [M · 🟡]
Ziel        Software-Boot-Pointer als TMR-Feld (Tier 1). Aus `reserved`-Tail; `struct_version` bump;
            `WAL_TMR_POPULATED_SIZE` als *eine* Quelle der Wahrheit (dieselbe Disziplin wie beim
            Mailbox-Watermark).
Berührt     `boot_journal.h` (`wal_tmr_payload_t`, Static-Asserts), `boot_journal.c` (populated_size).
Fertig wenn Feld liest/schreibt persistent über Quorum-Rotation; `struct_version`-Migration lässt
            Alt-TMR sauber lesen; Offset-Static-Asserts grün.
Hängt an    —

### ST-014 — WAL-Feld `transport_id` im offenen Txn                            [S · 🟢]
Ziel        `transport_id` in `wal_entry_payload_t`, damit ein Brownout-Resume den richtigen Provider
            dispatcht und kein Provider-Wechsel mitten in einer Txn passiert.
Berührt     `common/include/toob_wal_wire.h`, ggf. `boot_journal.c` (CRC-Länge).
Fertig wenn Feld im WAL persistiert; Resume liest es; ABI-Static-Asserts grün.
Hängt an    —

### ST-015 — `boot_hal.h`: Caps + Primitiven-Signaturen                        [S · 🟢]
Ziel        `const slot_caps_t *slot_caps;` in `boot_platform_t` (oder Accessor), plus die optionalen
            Primitiven-Signaturen dokumentiert.
Berührt     `boot_hal.h`.
Fertig wenn Core kommt an die Caps; NULL-tolerant (fehlende Primitive = Tier nicht verfügbar).
Hängt an    ST-010

### ST-016 — Core-Config: Secondary-/Backup-/Pointer-Regionen                  [M · 🟡]
Ziel        `generated_boot_config.h` bekommt getrennte Adressen für Delta-Output-Secondary,
            Rollback-Backup und (Tier 1) den logischen zweiten Slot — statt Scratch für alles.
Berührt     `generated_boot_config.h` (Core-Sicht; Codegen-Seite ist eigener Backlog).
Fertig wenn Delta-Output-Ziel ≠ Swap-Temp per Config erzwungen; Geometrie-Static-Asserts grün.
Hängt an    —  (Codegen liefert die echten Werte; Core definiert die Felder/Verträge)

---

# E2 — TSM-Refactor (verhaltenserhaltend)

### ST-030 — Provider `swapscratch` (Migration, bit-identisch)                 [L · 🔴]
Ziel        Die aktuelle `boot_swap.c`-Logik als Fallback-Provider (Tier 4) hinter `slot_transport_t`
            ziehen — **ohne Verhaltenswechsel** —, damit E2 gegen etwas Funktionierendes umbaut.
            Die ST-002-Gewinne sind eingefaltet.
Berührt     neu `boot_transport_swapscratch.c`; `boot_swap.c` (retiring), `boot_swap_erase_safe`
            als Util behalten/umziehen.
Fertig wenn Über den Provider gefahren erzeugt dieselbe Effektliste/Erase-Zahlen wie das Ist
            (bit-identisch, Modell); Sicherheitssemantik erhalten.
Hängt an    ST-011, ST-002

### ST-020 — Selektions-Glue `boot_transport.c/.h`                             [M · 🟡]
Ziel        `boot_transport_active()` gibt den *einen* per `TOOB_TRANSPORT_PROVIDER` (Codegen)
            gebundenen Provider zurück; `--gc-sections` strippt die übrigen. Bootstrap gegen
            `swapscratch`.
Berührt     neu `boot_transport.c/.h`.
Fertig wenn Default-Build bindet `swapscratch`; ungenutzte Provider nicht im Map-File; Umschalten per
            `#define` ohne Code-Änderung.
Hängt an    ST-011, ST-030

### ST-021 — `stage_swap` → `slot_txn_t` + `transport->apply` (N1)             [L · 🔴]
Ziel        `boot_state.c` baut eine `slot_txn_t` (Delta-Ziel aus Caps aufgelöst) und ruft
            `boot_transport_active()->apply` statt direkt `boot_swap_apply`. Multi-Image bleibt.
Berührt     `boot_state.c` (`stage_swap`, `update_ctx_t`).
Fertig wenn Update-Pfad läuft über die Transport-Schicht mit `swapscratch` → Ergebnis bit-identisch
            zum Ist (Regression); `transport_id` in den WAL geschrieben.
Hängt an    ST-020, ST-024, ST-014

### ST-022 — Handoff: aktiver Slot statt fixer Adresse (N2)                    [M · 🔴]
Ziel        STEP 5 bezieht die Ausführungsadresse aus dem aktiven Slot (`caps->get_active_slot` HW /
            `tmr.active_app_slot` SW) statt fix `CHIP_APP_SLOT_ABS_ADDR`.
Berührt     `boot_state.c` (STEP 5, `boot_proof_seal`-Eingaben).
Fertig wenn Single-Slot-Chip unverändert (aktiver Slot == App-Slot); der Pfad ist für Tier 0/1
            vorbereitet (zwei Slots wählbar).
Hängt an    ST-013

### ST-023 — Rollback-Flow → `provider->rollback` (N3)                         [M · 🔴]
Ziel        `_handle_rollback_flow` ruft `boot_transport_active()->rollback` statt direkt
            `boot_rollback_trigger_revert`. Policy (`boot_rollback_evaluate_os`) bleibt unberührt.
Berührt     `boot_state.c` (`_handle_rollback_flow`), `boot_rollback.c` (als swapscratch/oneway-
            Rollback-Pfad).
Fertig wenn Rollback über den Provider erzeugt dasselbe Ergebnis wie das Ist (Modell + HW).
Hängt an    ST-020

### ST-024 — Delta-Output vom Swap-Temp entkoppeln (N6)                        [M · 🔴]
Ziel        `stage_apply_delta` schreibt in einen dedizierten Secondary-Bereich (aus ST-016), den der
            TSM an `boot_delta_apply` übergibt — nie mehr implizit den Swap-Scratch.
Berührt     `boot_state.c` (`stage_apply_delta`), `boot_delta.c`-Aufrufparameter.
Fertig wenn Delta-Output-Adresse ≠ jede Swap-Temp-Adresse (statisch geprüft); ST-001 wird obsolet
            (der Konflikt existiert strukturell nicht mehr).
Hängt an    ST-016

---

# E3 — Provider-Suite (neue Algorithmen)

### ST-031 — Provider `oneway` (Two-Phase, raw + delta)                        [L · 🔴]
Ziel        Der saubere Two-Phase-One-Way-Provider (Tier 3), der ST-001 absorbiert und auch den
            Raw-Pfad kann. 2 ops/Sektor, alte App landet in Staging.
Berührt     neu `boot_transport_oneway.c`.
Fertig wenn Modell-verifiziert (fresh/resume/brownout); raw + delta beide korrekt; Rollback aus
            Staging; HW-getestet.
Hängt an    ST-011, ST-016

### ST-032 — Provider `swapmove` (kein Scratch-Hotspot)                        [L · 🔴]
Ziel        Swap-Move (Tier 2): in-place-Austausch mit einem Reserve-Sektor, ~2 ops/Sektor,
            Verschleiß über den Slot verteilt statt auf einen Scratch-Sektor.
Berührt     neu `boot_transport_swapmove.c`.
Fertig wenn Modell-verifiziert; Wear-Bench zeigt keinen Einzel-Sektor-Hotspot; Resume von jedem
            Move-/Swap-Schritt identisch; HW-getestet.
Hängt an    ST-011
Notiz       Komplexeste Resume-Logik der Suite — Move-Phase und Swap-Phase getrennt checkpointen.

### ST-033 — Provider `pointer` (Bank-Flip / XIP-Remap / Dual-Slot)           [L · 🔴]
Ziel        Null-Kopie-Commit (Tier 0/1): Secondary vorbereiten + verifizieren, dann `EFF_FLIP`.
            Nutzt `caps->bank_flip`/`xip_remap_commit`/`exec_addr_select`. Rollback = Re-Flip.
Berührt     neu `boot_transport_pointer.c`.
Fertig wenn Auf einem Chip mit HW-Bank *oder* MMU: 1 E + 1 W pro neuem Sektor, Commit atomar,
            Rollback = Flip (0 Wear); Brownout vor/nach Flip beide sicher (Modell + HW).
Hängt an    ST-011, ST-012, ST-013, ST-015

### ST-034 — `boot_multiimage` als One-Way-Multi-Target migrieren             [M · 🟡]
Ziel        Das bereits effiziente Multi-Image-One-Way unter den `oneway`-Provider (Multi-Target-
            Variante) fassen oder als registrierten Provider führen — eine Kopier-Semantik im System.
Berührt     `boot_multiimage.c`, `boot_transport_oneway.c`.
Fertig wenn Netcore/Recovery/Stage1-Deployment läuft über denselben One-Way-Pfad; bit-identisch zum Ist.
Hängt an    ST-031

---

# E4 — Commit, Resume & Rollback-Korrektheit (querschnittlich)

### ST-040 — Atomarer Commit + Resume-über-den-Flip (Modell)                   [L · 🔴]
Ziel        Beweisen, dass der Commit ein einziger atomarer Punkt ist: Brownout *vor* dem Flip →
            altes Image bootet; *nach* dem Flip → neues Image bootet; *während* → A/B-Redundanz
            (TMR-Quorum bzw. HW-Register) lässt genau einen gültigen Zustand überleben.
Berührt     Modell-Harness; ggf. `boot_effect.c` (Flip-Atomarität), `boot_journal.c`.
Fertig wenn Modell zeigt für jeden Provider: kein Brownout-Zeitpunkt führt zu einem Halb-Boot.
Hängt an    ST-012, ST-013, ST-033

### ST-041 — Resume-Dispatch über `transport_id`                               [M · 🟡]
Ziel        Ein Resume dispatcht den Provider aus dem WAL (`transport_id`), niemals einen anderen als
            den, der die Txn begann. Fehlender/unbekannter Provider → sicher abbrechen, nicht raten.
Berührt     `boot_state.c` (Resume-Pfad), `boot_transport.c`.
Fertig wenn Resume mit fremdem `transport_id` wird abgelehnt (Test); passender Provider setzt fort.
Hängt an    ST-014, ST-020

### ST-042 — Rollback pro Provider                                             [L · 🔴]
Ziel        Jeder Provider implementiert `rollback` passend: Re-Flip (Tier 0/1, 0 Wear),
            Reverse-Copy aus Staging (oneway/swapscratch), Reverse-Swap (swapmove).
Berührt     alle `boot_transport_*.c`, `boot_rollback.c` (als Copy-Rollback-Pfad).
Fertig wenn Für jeden Provider stellt Rollback nachweislich das letzte gute Image her (Modell + HW);
            Rollback ist selbst brownout-resumbar.
Hängt an    ST-031, ST-032, ST-033

### ST-043 — Wear-Telemetrie pro Provider in die TMR                           [S · 🟢]
Ziel        Jeder Provider meldet seine physischen Erases sauber in die TMR-Counter
            (`app/staging/swap_buffer_erase_counter`), damit ST-052 und spätere wear-aware Logik echte
            Zahlen haben.
Berührt     alle `boot_transport_*.c`, `boot_journal` (Counter).
Fertig wenn Counter stimmen mit der Wear-Bench (ST-052) überein (±0).
Hängt an    ST-030, ST-031, ST-032, ST-033

---

# E5 — Verifikation, Absicherung & Wear-Regression

### ST-050 — Per-Provider Resume+Rollback-Modell-Harness                       [M · 🟡]
Ziel        Ein wiederverwendbares Python-Referenzmodell + Flash-Sim (wie bei `boot_delta`), das jeden
            Provider gegen frisch/Resume/Brownout prüft und „kein Write in nicht-erased Sektor" hart
            asserted.
Berührt     Test-Harness (`/tools/models/`).
Fertig wenn Alle vier Provider laufen grün durchs Harness; Teil der CI.
Hängt an    ST-031, ST-032, ST-033

### ST-051 — TSM-Invarianten-Modellcheck                                        [L · 🔴]
Ziel        Den transaktionalen Layer strategie-unabhängig modell-checken: Atomarität, kein
            Halb-Boot, Rollback-immer-verfügbar-bis-Confirm, Anti-Rollback bleibt.
Berührt     Modell (TLA+/Alloy oder erschöpfender Python-Zustandsraum).
Fertig wenn Der Check erschöpft die Brownout-×-Provider-×-State-Matrix ohne Invarianten-Verletzung.
Hängt an    ST-040
Notiz       Das ist die „Perfektion"-Absicherung — sollte ein Merge-Gate für neue Provider werden.

### ST-052 — Wear-Regressions-Bench                                            [M · 🟢]
Ziel        Reproduzierbarer Bench: Erase-/Write-Zahlen je Provider für definierte Update-Profile
            (voll / 30 % / 5 % geändert), gegen die Baseline (swap-scratch) und untereinander.
Berührt     Test-Harness.
Fertig wenn Zahlen bestätigen die Tier-Erwartung (pointer 1 E/Sek, oneway 2, swapmove ~2 ohne
            Hotspot, swapscratch 3); als CI-Regression verankert.
Hängt an    ST-043

### ST-053 — HW-Brownout-Matrix                                                [L · 🔴]
Ziel        Auf echter Hardware jeden Provider an jeder Phasengrenze (Erase/Write/Verify/Flip)
            unterbrechen und Resume → korrektes bootbares Image nachweisen.
Berührt     HW-Testrig.
Fertig wenn Für jeden Provider: Cut an jeder Grenze → Gerät bootet altes oder neues verifiziertes
            Image, nie brick.
Hängt an    ST-031, ST-032, ST-033

---

# E6 — Core-Haken für Advanced Wear (vorbereitend, optional)

### ST-060 — Reverse-Delta-Rollback (Provider-Rollback-Variante)               [L · 🔴]
Ziel        Für Delta-Updates Δ⁻¹ (Reverse-Patch, winzig) statt der ganzen alten App als
            Rollback-Datum. Rollback = Δ⁻¹ auf die neue App anwenden.
Berührt     `boot_transport_oneway.c` (rollback), `boot_delta.c` (rückwärts anwendbar), TBM1
            (Δ⁻¹-Region), Delta-Generator (Build, eigener Backlog).
Fertig wenn Rollback-Storage = `size(Δ⁻¹)`; Rollback stellt bit-genau die alte App her (Modell + HW).
Hängt an    ST-042
Notiz       Braucht Build-Seite (Δ⁻¹-Erzeugung) — hier nur der Core-Anwendungspfad.

### ST-061 — Wear-gelevelter Scratch-Pool (swapscratch-Verbesserung)          [M · 🟡]
Ziel        Im Fallback-Provider den Scratch über einen Pool von Spare-Sektoren rotieren
            (Round-Robin via TMR-Zähler) statt fix — verteilt den Hotspot ohne volle Swap-Move-
            Komplexität.
Berührt     `boot_transport_swapscratch.c`, `boot_journal` (Rotations-Zähler).
Fertig wenn Wear-Bench zeigt gleichmäßige Scratch-Pool-Verteilung; Resume kennt den aktiven
            Pool-Sektor.
Hängt an    ST-030, ST-043

---

## Reihenfolge & kritischer Pfad

```
E0 (ST-001, ST-002)                      ── sofort, unabhängig
   │
E1 (ST-010,011,012,013,014,015,016)      ── Abstraktionen + Zustand (parallelisierbar)
   │
ST-030 swapscratch-Migration (Brücke)    ── verhaltenserhaltend, ermöglicht E2
   │
ST-020 Glue → ST-024 Delta-Entkopplung → ST-021 stage_swap → ST-022/023  (E2-Refactor)
   │
E3 (ST-031 oneway, ST-032 swapmove, ST-033 pointer, ST-034 multiimage)   ── neue Provider
   │
E4 (ST-040 commit-atomar, ST-041 resume-dispatch, ST-042 rollback, ST-043 telemetry)
   │
E5 (ST-050 harness, ST-051 invariant-check, ST-052 wear-bench, ST-053 hw-matrix)
   │
E6 (ST-060 reverse-delta, ST-061 scratch-pool)   ── optional/vorbereitend
```

**Merge-Gate ab E3:** Kein neuer Provider geht in die Registry, bevor er ST-050 (Resume/Rollback-
Modell) und — sobald vorhanden — ST-051 (Invarianten-Check) grün durchläuft. Das ist die Grenze
zwischen „schnell/sparsam" und „korrekt", und sie ist nicht verhandelbar.

## Bewusst NICHT in diesem Backlog (eigene Backlogs, nur Core-Haken hier)

- Registry-Package-Inhalt (`drivers/<chip>/slot_caps.c`) + Manifest-Compiler-Codegen (Provider-
  Selektion, `generated_slot_caps.c`). Core-Haken: ST-016, ST-020 (`TOOB_TRANSPORT_PROVIDER`).
- Build-Co-Design (Dual-Linked-Images, TBM1-`slot_variant`, VTOR, CLI-Emission). Core-Haken: ST-022.
- Δ⁻¹-Erzeugung im Delta-Generator. Core-Haken: ST-060.