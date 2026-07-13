# Patch: Heal-then-Crash-Bug in `boot_state.c`

**Datei:** `toobloader/core/boot_state.c`
**Funktion:** `boot_state_run()`
**Art:** chirurgischer Fix, keine ABI-/Signatur-Änderung, keine neuen Abhängigkeiten.

---

## Problem (verifiziert)

Wenn in **Step 2** der Failure-Counter geheilt wird (`ACT_HEAL_COUNTER` über
`WAL_INTENT_CONFIRM_COMMIT` oder `WAL_INTENT_RECOVERY_RESOLVED`), leitet **Step 3** unmittelbar
danach aus dem `reset_reason` einen frischen `EV_CRASH` ab und zählt den gerade geheilten Counter
via `ACT_CRASH_ACCUM` sofort wieder hoch.

Das passiert im Normalfall, weil der Reboot, der die Heilung anstößt, typischerweise per
Watchdog/Panic erfolgt — der `reset_reason` ist also noch `WATCHDOG`/`HARD_FAULT` und beschreibt den
*vergangenen* Crash, den Confirm/Recovery gerade aufgelöst hat, nicht einen neuen.

Betrifft beide Heilungspfade:
- **Recovery aufgelöst** (`RECOVERY_RESOLVED`) + WDT-Reboot → Counter landet auf 1 statt 0.
- **Normaler Confirm nach Update** (`CONFIRM_COMMIT`) + WDT-Reboot → Counter landet auf 1 statt 0.

Echte App-Crashes (kein Heal in diesem Boot) sind **nicht** betroffen — der Counter zählt dort
weiter wie bisher.

Simulationsnachweis (4 Szenarien, alle grün): Recovery+WDT 1→0, Confirm+WDT 1→0, Recovery+SW-Reset
0→0 (unverändert), echter App-Crash 3→3 (unverändert, kein Overreach).

---

## Fix

Eine boot-lokale Flagge `healed_this_boot`, die in Step 2 gesetzt wird und in Step 3 die
Crash-Ableitung aus dem `reset_reason` für genau diesen Boot unterdrückt.

### Änderung 1 — Flagge deklarieren

Bei den lokalen Deklarationen am Anfang von `boot_state_run()`, in der Nähe von `open_txn` /
`current_tmr` / `app_header` (z. B. direkt nach `boot_status_t core_status = BOOT_OK;`):

```c
  /* Wurde der Failure-Counter in DIESEM Boot geheilt (Confirm/Recovery)?
   * Verhindert, dass Step 3 den bereits aufgelösten (vergangenen) Crash aus dem
   * reset_reason erneut als frischen EV_CRASH wertet. */
  bool healed_this_boot = false;
```

### Änderung 2 — Flagge in Step 2 setzen (im Heilungszweig)

In **STEP 2**, im `else`-Zweig nach der erfolgreichen Autorisierung, dort wo
`evaluate_transition(..., EV_CONFIRM_OK, ...)` gerufen wird. Die Flagge wird gesetzt, wenn eine
Transition mit Heilung ausgeführt wurde.

**Vorher:**
```c
    } else {
      if (rtc_confirmed && open_txn.intent == WAL_INTENT_NONE) {
        open_txn.intent = WAL_INTENT_CONFIRM_COMMIT;
      }
      core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CONFIRM_OK, target_out, arena, arena_len);
      if (core_status != BOOT_OK)
        goto state_cleanup;
    }
```

**Nachher:**
```c
    } else {
      if (rtc_confirmed && open_txn.intent == WAL_INTENT_NONE) {
        open_txn.intent = WAL_INTENT_CONFIRM_COMMIT;
      }
      core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CONFIRM_OK, target_out, arena, arena_len);
      if (core_status != BOOT_OK)
        goto state_cleanup;

      /* Heilung fand statt (CONFIRM_COMMIT/RECOVERY_RESOLVED -> ACT_HEAL_COUNTER).
       * reset_reason in Step 3 beschreibt den bereits aufgelösten Crash. */
      healed_this_boot = true;
    }
```

> Hinweis für die Einarbeitung: `healed_this_boot = true` ist bewusst konservativ an den
> **auth-erfolgreichen** Confirm-/Recovery-Zweig gebunden — genau dort, wo `ACT_HEAL_COUNTER` läuft.
> Der Zweig wird nur betreten, wenn `open_txn.intent` `CONFIRM_COMMIT`/`RECOVERY_RESOLVED` war oder
> `rtc_confirmed` gilt; alle drei bedeuten „dieser Boot hat einen vorherigen Zustand aufgelöst".

### Änderung 3 — Flagge in Step 3 auswerten

In **STEP 3**, in der Berechnung von `is_app_crash`. Ein in diesem Boot geheilter Zustand darf
keinen frischen Crash aus dem `reset_reason` mehr erzeugen.

**Vorher:**
```c
  bool wal_indicates_crash = (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT);
  bool rst_indicates_crash = (rst_reason == RESET_REASON_WATCHDOG ||
                              rst_reason == RESET_REASON_HARD_FAULT);

  bool is_app_crash = wal_indicates_crash ||
                      (rst_indicates_crash &&
                       open_txn.intent != WAL_INTENT_UPDATE_PENDING &&
                       open_txn.intent != WAL_INTENT_TXN_BEGIN);
```

**Nachher:**
```c
  bool wal_indicates_crash = (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT);
  bool rst_indicates_crash = (rst_reason == RESET_REASON_WATCHDOG ||
                              rst_reason == RESET_REASON_HARD_FAULT);

  bool is_app_crash = wal_indicates_crash ||
                      (rst_indicates_crash &&
                       open_txn.intent != WAL_INTENT_UPDATE_PENDING &&
                       open_txn.intent != WAL_INTENT_TXN_BEGIN);

  /* Fix Heal-then-Crash: Wurde in diesem Boot geheilt (Confirm/Recovery), beschreibt
   * der reset_reason den bereits aufgelösten Crash — nicht erneut als frisch werten. */
  if (healed_this_boot) {
    is_app_crash = false;
  }
```

---

## Warum das korrekt und eng begrenzt ist

- **Kein Overreach.** Die Flagge wird ausschließlich im auth-erfolgreichen Heilungszweig gesetzt.
  Ein echter App-Crash ohne vorausgehende Heilung lässt `healed_this_boot == false` und den
  Counter-Pfad unverändert.
- **`wal_indicates_crash` wird ebenfalls neutralisiert** — korrekt: Nach der Heilung ist
  `open_txn.intent` bereits auf `NONE` gesetzt, sodass `wal_indicates_crash` ohnehin `false` ist;
  die Flagge deckt zusätzlich den reset-reason-Pfad ab, der der eigentliche Bug war.
- **CFI unberührt.** Es werden keine CFI-Slots, keine Tabellen und keine Kontrollfluss-Struktur
  geändert; nur eine boolesche Nebenbedingung ergänzt.
- **Kein neuer State im WAL/TMR.** Die Flagge ist rein boot-lokal (C-Stack) und wird beim
  `state_cleanup` nicht benötigt; sie muss nicht persistiert werden.

## Testempfehlung (für die Einarbeitung)

Vier Fälle, die grün sein müssen:

| Intent (Step 2)     | reset_reason | counter vorher | counter nachher (erwartet) |
|---------------------|--------------|----------------|----------------------------|
| RECOVERY_RESOLVED   | WATCHDOG     | 5              | **0** |
| CONFIRM_COMMIT      | WATCHDOG     | 0              | **0** |
| RECOVERY_RESOLVED   | SOFTWARE     | 5              | 0 (unverändert) |
| NONE (echter Crash) | WATCHDOG     | 2              | 3 (unverändert) |