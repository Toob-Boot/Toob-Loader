# Recovery-OS — Backlog (v2)

Ziel: Den Core-seitigen Recovery-*Vertrag* dichtmachen und danach den `recovery/`-Source-Tree als
dumme OTA-only-App bauen. Grundprinzip aus der Analyse: **Recovery bleibt dumm** — kein eigenes
Krypto, keine zweite Root-of-Trust. Es streamt Bytes ins Staging, schreibt einen Mailbox-Request,
rebootet; **Stage 1 verifiziert.** Auflösung läuft über `RECOVERY_RESOLVED`, das der Core idempotent
faltet.

**Voraussetzung:** Der Patch `PATCH_boot_state_heal_then_crash.md` (Lücke 1, Heal-then-Crash) ist
eingearbeitet. Dieser Backlog deckt die verbleibenden drei Vertragslücken (E1–E3) und den
Source-Tree (E4) ab.

**Ticket-Schema** — ID · Ziel · Berührt · Skizze · Fertig-wenn · Aufwand · Risiko · Hängt-an.
**Aufwand** S ≤0,5 T · M 1–2 T · L 3–5 T. **Risiko** 🟢 mechanisch · 🟡 kritischer Pfad/RoT · 🔴 Design-Entscheidung.

---

## D0 — Scope-Entscheidungen (zuerst treffen, sie steuern den Aufwand aller Tickets)

Diese drei Fragen sind keine Tickets, sondern Weichen. Jede ist im zugehörigen Epic als Entscheidung
verankert; hier gebündelt, weil sie sich gegenseitig beeinflussen.

- **D0-A — Recovery-Kanal.** Lokal (USB-DFU/seriell/BLE) vs. netzfähig (WiFi+TLS). *Empfehlung:
  lokal zuerst.* Netzfähiges Recovery ist fast app-groß, erbt jeden Netz-Fehlermodus und verbrennt
  bei Netzfehlern still das Recovery-Fenster (siehe E1). Netz nur, wenn „unbeaufsichtigte Heilung
  ohne physischen Zugriff" hartes Requirement ist. → steuert E4-T2.
- **D0-B — Recovery updatebar?** Immutable (factory-locked) vs. zweistufig (winziges immutables
  Minimal-Recovery reflasht größeres) vs. eigenes A/B. *Empfehlung: immutable + klein für den
  Start.* → steuert E3.
- **D0-C — Was heißt „resolved"?** „Neues App-Image gestaged" (Standard, vom Code so gelebt) vs.
  „gibt auf, App nochmal versuchen". *Empfehlung: „gestaged", und der Folge-App-Boot ist tentative*
  (E2). → steuert E2 + E4-T4.

---

# E1 — Recovery-Erschöpfung entkoppeln (Vertragslücke 2)

Problem: `boot_rollback_evaluate_os` nutzt einen einzigen `boot_failure_counter` für App *und*
Recovery. Ein Recovery-OS, das selbst wiederholt crasht (kaputtes Image, Netzfehler in Schleife),
zählt denselben Counter hoch, überschreitet `limit_rec` und fällt in den **Unattended-Backoff oder
Panic** — ohne dass je eine lokale Rescue-Schnittstelle drankam. Das grobe Sicherheitsnetz kann die
Rettung selbst aussperren.

### E1-T1 — App- und Recovery-Fehlversuche trennen                             [M · 🔴]
Ziel        Ein separater `recovery_failure_counter` in der TMR, damit Recovery-Crashes nicht das
            App-Fenster verbrennen und umgekehrt.
Berührt     `boot_journal.h` (`wal_tmr_payload_t`, neues Feld aus `reserved`-Tail; `struct_version`
            bump; `WAL_TMR_POPULATED_SIZE`), `boot_rollback.c`, `boot_state.c`.
Skizze      Beim Recovery-Boot (`booted_partition == RECOVERY`) inkrementiert ein Crash den
            `recovery_failure_counter`, nicht den App-Counter. `boot_rollback_evaluate_os` liest
            beide.
Fertig wenn Recovery-Crashes lassen den App-Counter unberührt (Test); ein reparierter App-Boot
            heilt den App-Counter, nicht den Recovery-Counter.
Hängt an    D0-B (Zählerlogik hängt an updatebar/immutable)

### E1-T2 — Recovery eskaliert nie terminal, sondern in lokale Rescue          [M · 🟡]
Ziel        Aus dem Recovery-Kontext heraus wird **nie** in den Unattended-Backoff-Sleep oder Panic
            eskaliert. Erschöpftes Recovery → definierte lokale Rescue (UART/DFU-Warteschleife),
            damit ein Mensch/Tool immer eine Chance hat.
Berührt     `boot_rollback.c` (`boot_rollback_evaluate_os`, Terminal-Zweig).
Skizze      Wenn `recovery_failure_counter` erschöpft: statt `enter_low_power`/`boot_panic` gezielt
            `boot_panic(BOOT_RECOVERY_REQUESTED)` (Serial-Rescue) — nie der stille Akku-Backoff.
Fertig wenn Ein dauerhaft crashendes Recovery landet in der Rescue-Schleife, nicht im
            136-Jahre-Backoff; App-seitiger Backoff bleibt unverändert.
Hängt an    E1-T1

---

# E2 — Reparierter Boot wird tentative (Vertragslücke 3)

Problem: In Step 5 wird `requires_confirmation`/`is_tentative_boot` nur bei
`open_txn.intent == WAL_INTENT_TXN_COMMIT` gesetzt. Nach einer Recovery-Reparatur heilt der Core den
Counter und bootet die App — aber **ohne Tentative-Nonce**, also ohne Confirm-Zwang. Eine schlechte
Reparatur wird erst über die normale Crash-Kaskade wieder gefangen; der schnelle Sicherheitsgurt
fehlt genau nach der Reparatur.

### E2-T1 — Recovery-reparierten App-Boot als tentative markieren              [M · 🟡]
Ziel        Ein App-Boot, der aus `RECOVERY_RESOLVED`-Heilung hervorgeht, bekommt eine
            Tentative-Nonce und muss confirmen — sonst schneller Rückfall statt stiller
            Crash-Kaskade.
Berührt     `boot_state.c` (Step 2 Heilungszweig setzt Marker; Step 5
            `requires_confirmation`-Bedingung erweitern).
Skizze      Neben `TXN_COMMIT` auch „geheilt aus Recovery in diesem Boot" als
            `requires_confirmation`-Auslöser; nutzt denselben `healed_this_boot`-Kontext wie der
            Heal-then-Crash-Patch.
Fertig wenn Nach Recovery-Reparatur ist `is_tentative_boot == true`, Nonce registriert; bleibt der
            Confirm der reparierten App aus, folgt zügiger Rückfall (Test).
Hängt an    D0-C, Patch (Heal-then-Crash, für `healed_this_boot`)

---

# E3 — Recovery-Update brownout-sicher (Vertragslücke 4, gefährlichste)

Problem: Der Recovery-Slot wird via Multi-Image **in-place** aktualisiert
(`TBM1_SLOT_RECOVERY` → `CHIP_RECOVERY_OS_ABS_ADDR`). Ein Stromausfall mitten im Recovery-Update
hinterlässt ein halb-geschriebenes Recovery — **die Rückfallebene selbst ist beim eigenen Update
angreifbar.** Wenn Recovery kaputt ist, ist das letzte Sicherheitsnetz weg.

Die Umsetzung hängt an **D0-B**:

### E3-T1a — Variante immutable: Recovery-Update abweisen                      [S · 🔴]
Ziel        Wenn D0-B = immutable: `TBM1_SLOT_RECOVERY` wird aus der Multi-Image-Whitelist entfernt;
            ein Manifest mit Recovery-Sub-Image wird sauber abgelehnt (kein in-place-Risiko).
Berührt     `boot_state.c` (`stage_swap` Whitelist + Slot-Mapping), Manifest-Compiler (Slot
            verbieten).
Fertig wenn Ein Recovery-Sub-Image führt zu definiertem Reject, nie zu einem in-place-Write;
            Recovery bleibt factory-locked.
Hängt an    D0-B

### E3-T1b — Variante zweistufig/A-B: brownout-sicheres Recovery-Update        [L · 🔴]
Ziel        Wenn D0-B = updatebar: Recovery-Update erhält dieselbe WAL-journaled, resume-fähige
            Semantik wie der App-Swap — entweder eigenes A/B oder ein winziges immutables
            Minimal-Recovery, das das größere reflasht und dabei einen halben Schreibvorgang beim
            nächsten Boot fortsetzt.
Berührt     `boot_state.c`, `boot_swap.c`/`boot_multiimage.c`, Flash-Map (zweiter Recovery-Slot bzw.
            Minimal-Recovery-Region), `boot_rollback.c` (`ROLLBACK_TARGET_RECOVERY`-SVN-Persistenz).
Fertig wenn Power-Cut mitten im Recovery-Update → beim nächsten Boot existiert immer ein bootbares
            Recovery (das alte oder das fertige neue), nie ein halbes.
Hängt an    D0-B

---

# E4 — `recovery/` Source-Tree (die dumme OTA-only-App)

Erst bauen, wenn E1–E3 den Vertrag dichtgemacht haben — sonst baut Recovery auf einer Heilung/einem
Update-Pfad, der nicht hält.

### E4-T1 — Recovery-Grundgerüst: Handoff lesen, Modus erkennen                [M · 🟢]
Ziel        Minimal-App, die via `toob_get_handoff()` prüft `booted_partition == RECOVERY`,
            `TOOB_OS_INIT_OR_PANIC()` läuft, sonst nichts tut. Kein Krypto, kein Netz.
Berührt     neu `recovery/main.c`, bindet libtoob + `toob_port.h`.
Fertig wenn Recovery bootet, erkennt seinen Modus, ist ein eigenständiges, verifizierbares Image
            (eigenes TBM1-Header, `TBM1_SLOT_RECOVERY`).
Hängt an    —

### E4-T2 — Reparatur-Kanal (gemäß D0-A)                                       [L · 🔴]
Ziel        Recovery bezieht ein funktionierendes App-Image und streamt es via
            `toob_ota_begin/process_chunk/finalize` ins Staging — Kanal je nach D0-A.
Berührt     `recovery/`; bei lokal: DFU/seriell-Empfang; bei Netz: `os_client`-Wiederverwendung.
Skizze      Kein Verify im Recovery — `finalize` schreibt `MBX_CMD_UPDATE_PENDING`; Stage 1
            verifiziert beim nächsten Boot. Recovery bleibt damit ohne Root-of-Trust.
Fertig wenn Recovery lädt ein App-Image in Staging und registriert es; ein absichtlich korruptes
            Image wird von Stage 1 (nicht von Recovery) abgelehnt.
Hängt an    D0-A, E4-T1

### E4-T3 — Auflösung: `toob_recovery_resolved()` sauber aufrufen              [S · 🟡]
Ziel        Nach erfolgreichem Staging ruft Recovery `toob_recovery_resolved()` (Mailbox
            `RECOVERY_RESOLVED`) und rebootet. Der Core heilt (mit dem Patch: korrekt auf 0) und
            bootet die reparierte App.
Berührt     `recovery/main.c`.
Fertig wenn End-to-End: Crash-Kaskade → Recovery-Boot → Reparatur → resolved → App bootet,
            App-Counter = 0 (Patch), reparierte App ist tentative (E2-T1).
Hängt an    E4-T2, E2-T1, Patch

### E4-T4 — Status-/Anzeige-Integration (SWEV-T9)                              [S · 🟢]
Ziel        Recovery bindet denselben `toob_swap_notify_fn`-Herstellertreiber wie die App ein und
            zeichnet `phase = TOOB_SWAP_PHASE_RECOVERY` — reiche Anzeige trivial, weil volles OS.
Berührt     `recovery/main.c`; Wiederverwendung der Swap-Event-Naht.
Fertig wenn Recovery zeigt „Firmware wird neu geladen" über denselben Treibercode wie die App
            (Ebene C aus dem Swap-Display-Backlog).
Hängt an    E4-T1

### E4-T5 — Roach-Motel-Test: Recovery kann sich nicht selbst einsperren       [M · 🟡]
Ziel        Der Integrationstest, der beweist, dass Recovery immer einen Ausweg hat — die zentrale
            Garantie des ganzen Epics.
Berührt     Test-Harness.
Skizze      Szenarien: (a) Recovery repariert erfolgreich → App bootet, Counter 0; (b) Recovery
            crasht wiederholt → landet in lokaler Rescue (E1-T2), nie im stillen Backoff;
            (c) Power-Cut während Recovery-Update → bootbares Recovery bleibt (E3).
Fertig wenn Alle drei Szenarien grün; kein Pfad führt in einen Zustand ohne
            Mensch-/Tool-Eingriffsmöglichkeit.
Hängt an    E1-T2, E3, E4-T3

---

## Reihenfolge

1. **D0-A/B/C** entscheiden — sie bestimmen E2/E3/E4-Aufwand.
2. **E1** (Erschöpfung entkoppeln) + **E2** (tentative Reparatur) — die zwei restlichen
   Vertragslücken im Boot-Pfad; unabhängig voneinander, beide bauen auf dem Heal-then-Crash-Patch.
3. **E3** (brownout-sicheres Recovery-Update) — Variante nach D0-B; die gefährlichste Lücke, aber
   erst relevant, wenn Recovery überhaupt updatebar sein soll.
4. **E4** (Source-Tree) — zuletzt, gegen den dann dichten Vertrag.
5. **E4-T5** als Abschluss-Gate.

## Kern-Garantie, die am Ende grün sein muss

**Kein Pfad sperrt die Rettung aus.** Nach erfolgreichem Recovery ist der App-Counter sauber 0
(Patch), die reparierte App ist tentative (E2), ein crashendes Recovery landet in lokaler Rescue
statt im stillen Backoff (E1), und ein Power-Cut im Recovery-Update lässt immer ein bootbares
Recovery zurück (E3). Recovery ist dumm (kein eigenes Krypto), Stage 1 verifiziert (E4).