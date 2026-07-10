# Toob-Boot Core — Umsetzungs-Backlog K1–K7

Dieser Backlog macht die sieben Architektur-Konzepte vollständig planbar. Jedes Konzept ist ein
Epic; jedes Epic zerfällt in Tickets mit konkreten Datei-/Funktions-Berührungspunkten,
Code-Skizzen auf euren echten Typen, Akzeptanzkriterien, Aufwand und Risiko.

Die Code-Skizzen folgen den Hausregeln des Cores: `BOOT_OK == 0x55AA55AA`, Single-Exit mit
`boot_secure_zeroize`, CFI-Akkumulatoren mit TRNG-Seed, und — als Konsequenz aus der Review —
`BOOT_SECURE_REQUIRE` wird nur auf *neu auswertbaren* Bedingungen benutzt, nie auf einem bereits
berechneten lokalen `bool`.

---

## Wie dieser Backlog zu lesen ist

**Ticket-Schema**

```
### <ID> — <Titel>                                        [Aufwand · Risiko]
Ziel        Was am Ende gilt.
Berührt     Dateien/Funktionen.
Skizze      Code oder Struktur.
Fertig wenn Akzeptanzkriterien (prüfbar).
Hängt an    Vorbedingungen.
```

**Aufwand** S = ≤0,5 Tag · M = 1–2 Tage · L = 3–5 Tage · XL = >1 Woche.
**Risiko** 🟢 mechanisch · 🟡 berührt Sicherheitspfad · 🔴 ABI-/Format-/Schlüssel-Entscheidung.

---

## Abhängigkeitsgraph & Wellenplan

```
E0  Foundations ───────────────┬──────────────┬─────────────┬───────────┐
                               │              │             │           │
Welle 1   E-K5 Record/Replay + Enumerator (Sicherheitsnetz — zuerst)     │
                               │                                          │
Welle 2   E-K6 Tabellen-Pipeline (verkleinert Fläche für K3)             │
                               │                                          │
Welle 3   E-K3 Effekt-Executor ──────────► E-K7 Energie-Zulassung (Anhängsel)
                                                                          │
Welle 4   E-K1 Beweis-Handles (parallel, berührt nur Schnittstellen) ────┘
Welle 5   E-K4 Journal-Kette (zusammen mit DICE/KDM-Schlüsselarbeit)
Welle 6   E-K2 Festformat-Manifest (größte Koordination — zuletzt)
```

Regel für jeden Merge: Nach dem Umbau muss ein Auditor **weniger** Code lesen, um **mehr**
Garantien zu verstehen. Wird ein Ticket dieser Regel nicht gerecht, ist es falsch geschnitten.

---

# E0 — Foundations

Querschnittsarbeit, die mehrere Epics voraussetzen. Klein, aber blockierend.

### E0-T1 — Shared-Header-Hausputz aus der Review nachziehen                 [S · 🟢]
Ziel        `is_buffer_within`, Streaming-Flash-CRC und die v1→v2-TMR-Migration existieren je
            genau einmal. Diese Dedup ist Voraussetzung, damit K2/K3 nicht auf Kopien aufsetzen.
Berührt     `boot_ct_utils.h` (neu: `is_buffer_within`), `boot_crc32.[ch]` (neu:
            `boot_crc32_flash_stream`), `boot_journal.c` (neu: `migrate_v1_tmr`), Entfernen der
            Kopien in `boot_state.c`, `boot_verify.c`, `boot_swap.c`, `boot_rollback.c`.
Skizze
```c
/* boot_crc32.h */
boot_status_t boot_crc32_flash_stream(const boot_platform_t *p,
                                      uint32_t addr, size_t len,
                                      uint8_t *arena, size_t arena_len,
                                      uint32_t *out_crc);
```
Fertig wenn `grep -rc "0xEDB88320 & (-(crc & 1))" toobloader/` == 1; Build grün; HIL-Regression
            unverändert.
Hängt an    —

### E0-T2 — HAL-Fassade für Test-Einspeisung (Record/Replay-Naht)           [M · 🟡]
Ziel        Der Core spricht Hardware ausschließlich über einen Funktionszeiger-Satz an (ist
            bereits so) — E0-T2 fixiert das als *Vertrag* und ergänzt einen dünnen Shim-Punkt,
            an dem K5 später Record/Replay einklinkt, ohne Core-Code zu ändern.
Berührt     `boot_platform_t` (Doku-Kommentar „einziger Hardwarezugang"), neuer Host-Build-Target
            `sandbox-replay`.
Skizze      Kein Core-Code ändert sich; nur ein `_Static_assert`-Audit, dass keine
            `.c`-Datei im `core/` direkt auf Register/`volatile`-Adressen zugreift.
```bash
# CI-Gate: verbietet direkten MMIO-Zugriff im Core
! grep -rnE '\(\s*volatile\s+uint32_t\s*\*\s*\)\s*0x' toobloader/core/
```
Fertig wenn CI-Gate grün; dokumentierter „HAL ist die einzige Außenwelt"-Vertrag in
            `security_model.md`.
Hängt an    —

### E0-T3 — Zentrale Fehlerklassen-Taxonomie                                 [S · 🟢]
Ziel        Die in `_handle_update_result` verstreute Reject-vs-Propagate-Liste wird eine
            benannte Menge — Voraussetzung für die K6-Fehlertabelle.
Berührt     `boot_types.h` (neu: `boot_error_is_rejectable(boot_status_t)`).
Skizze
```c
static inline bool boot_error_is_rejectable(boot_status_t s) {
  switch (s) {
    case BOOT_ERR_VERIFY: case BOOT_ERR_DOWNGRADE:
    case BOOT_ERR_INVALID_ARG: case BOOT_ERR_FLASH_BOUNDS:
    case BOOT_ERR_INVALID_STATE: case BOOT_ERR_NOT_FOUND:
      return true;
    default: return false; /* Hardware → propagate/panic */
  }
}
```
Fertig wenn `_handle_update_result` nutzt die Funktion; Verhalten identisch.
Hängt an    —

---

# E-K5 — Boot als reine Funktion (Record/Replay + Unterbrechungs-Enumerator)

**Warum zuerst.** Jede folgende Änderung wird gegen aufgezeichnete Referenzläufe und den
Enumerator verifiziert statt gegen Hoffnung. Ohne dieses Netz sind K3 und K6 riskante Blindflüge.

**Definition of Done (Epic).** Ein Host-Build spielt einen aufgezeichneten Boot bit-exakt ab
(inkl. TRNG); der Enumerator prüft Konsistenz nach Abbruch an *jeder* Flash-Schreibgrenze; ein
CBMC-Harness prüft den Journal-Reducer erschöpfend im gebundenen Raum.

### K5-T1 — Host-Flash-Modell als Datei                                      [M · 🟢]
Ziel        Ein `flash_hal_t`-kompatibles Modell, das den Flash-Zustand als Datei hält und
            NOR-Semantik (nur 1→0 per write, Sektor-Erase setzt auf `erased_value`) korrekt
            nachbildet.
Berührt     `test/host/flash_model.c` (neu).
Skizze
```c
typedef struct {
  uint8_t  *cells;         /* mmap'd Datei */
  size_t    size;
  uint32_t  sector_size;
  uint8_t   erased_value;  /* i.d.R. 0xFF */
  /* Fehler-/Torn-Write-Injektion (siehe K5-T3) */
  uint32_t  fail_at_op;    /* 0 = nie; sonst: brich beim n-ten write/erase ab */
  uint32_t  torn_prefix;   /* Bytes, die vom abgebrochenen write noch landen */
  uint32_t  op_counter;
} flash_model_t;

static boot_status_t model_write(uint32_t a, const void *b, size_t n) {
  flash_model_t *m = /* ctx */;
  m->op_counter++;
  size_t eff = n;
  if (m->fail_at_op && m->op_counter == m->fail_at_op) eff = m->torn_prefix;
  for (size_t i = 0; i < eff; i++)
    m->cells[a+i] &= ((const uint8_t*)b)[i];   /* NOR: nur Bits löschen */
  return (m->fail_at_op && m->op_counter == m->fail_at_op)
           ? BOOT_ERR_FLASH_HW : BOOT_OK;
}
```
Fertig wenn Modell besteht eine NOR-Semantik-Testsuite (write kann kein Bit setzen; erase
            setzt Sektor auf `erased_value`; Lesen nach Erase liefert `erased_value`).
Hängt an    E0-T2

### K5-T2 — Record/Replay-Shim um die HAL                                    [M · 🟡]
Ziel        Im Record-Modus wird jeder HAL-Call + Rückgabe (inkl. `crypto->random`-Bytes) auf
            ein Band geschrieben; im Replay-Modus bit-exakt zurückgespielt. Damit werden
            CFI-Seeds und Nonces reproduzierbar.
Berührt     `test/host/hal_tape.c` (neu), Wrapper um `crypto->random`, `flash->read/write/erase`,
            `crypto->read_monotonic_counter`, `clock->get_reset_reason`.
Skizze
```c
/* Bandformat: [op_id u8][args...][ret u32][payload_len u16][payload...] */
static boot_status_t tape_random(uint8_t *buf, size_t len) {
  if (mode == RECORD) { real_random(buf, len); tape_put(OP_RND, buf, len); }
  else                { tape_get(OP_RND, buf, len); }
  return BOOT_OK;
}
```
Fertig wenn Ein Record-Lauf, danach Replay desselben Bands, ergibt identischen End-Flash-Zustand
            und identischen `target_out`/Handoff (byte-diff == 0).
Hängt an    K5-T1

### K5-T3 — Unterbrechungs-Enumerator                                        [L · 🟡]
Ziel        Für einen nominellen Update-Boot mit W destruktiven Flash-Ops: für jedes
            i ∈ 1…W und jede Torn-Prefix-Variante das Band bei i kappen, resultierendes
            Flash-Abbild einfrieren, frischen Boot fahren, Invarianten prüfen.
Berührt     `test/host/enumerate_crash.c` (neu).
Skizze
```c
for (uint32_t i = 1; i <= W; i++) {
  for (uint32_t tp = 0; tp <= max_prefix(i); tp += write_align) {
    flash_model_t snap = clone(baseline);
    snap.fail_at_op = i; snap.torn_prefix = tp;
    run_boot(&snap);                 /* Abbruch bei Op i */
    flash_model_t after = clone(snap);
    after.fail_at_op = 0;
    boot_result_t r = run_boot(&after); /* frischer Reboot */
    assert_invariants(&r, &after);   /* siehe K5-T4 */
  }
}
```
Fertig wenn Enumerator läuft grün über Swap-, Revert- und Multi-Image-Pfad; ein absichtlich
            eingebauter Off-by-one im Revert-Checkpoint wird gefangen (Mutation-Test).
Hängt an    K5-T2

### K5-T4 — Invarianten-Prädikate                                            [M · 🟡]
Ziel        Formale, testbare Nachbedingungen, die nach *jedem* Reboot gelten müssen.
Berührt     `test/host/invariants.c` (neu).
Skizze
```
INV-1  Das Gerät bootet ein Image (kein Dead-Halt) ODER ist legitim gelockt/revoked.
INV-2  Der TMR-Zustand ist genau EINER (alt XOR neu) — nie feldweise gemischt.
INV-3  Kein zuvor persistierter Kern-Intent ging verloren (LOCKED bleibt LOCKED).
INV-4  app_svn / stage1_svn sind monoton nicht-fallend über die Bootfolge.
INV-5  Nach erfolgreichem Swap ist App-Slot-CRC == manifest-erwartete CRC.
```
Fertig wenn Alle fünf als Code; K5-T3 nutzt sie.
Hängt an    K5-T3

### K5-T5 — CBMC-Harness für den Journal-Reducer                             [L · 🟡]
Ziel        Der Rückwärts-Rekonstruktions-/TMR-Vote-Kern wird im gebundenen Raum erschöpfend
            geprüft (Totalität, kein Underflow, kein OOB-Read).
Berührt     `verification/cbmc/journal_harness.c` (neu), CI-Job.
Skizze
```c
void harness(void) {
  wal_tmr_payload_t c[3]; __CPROVER_havoc_object(c);
  int n = nondet_int(); __CPROVER_assume(n >= 1 && n <= 3);
  wal_tmr_payload_t out = tmr_majority_vote(c, n);   /* extrahierte reine Fn */
  /* Property: Ergebnis ist immer einer der Kandidaten, nie Frankenstein */
  __CPROVER_assert(is_one_of(&out, c, n), "vote_returns_candidate");
}
```
Fertig wenn CBMC terminiert ohne Verletzung; Job im CI. Voraussetzung: TMR-Vote als reine
            Funktion extrahiert (kleiner Vorab-Refactor in `boot_journal.c`).
Hängt an    E0-T1

---

# E-K6 — Zustandslogik als Daten (Intent-Algebra + Tabellen-Pipeline)

**Warum als Zweites.** Verkleinert `boot_state_run` drastisch und schafft die Struktur, auf der
K3 sauber aufsetzt. Alle Änderungen sofort gegen das K5-Netz verifizierbar.

**Definition of Done (Epic).** Intent-Übergänge und die Update-Pipeline werden aus statischen
Tabellen interpretiert; die CFI-Sollmenge wird aus der Pipeline-Tabelle generiert; ein
Totalitätstest deckt alle `{intent, ereignis}`-Paare ab; `boot_state_run` ist wesentlich kürzer.

### K6-T1 — Fehlertopologie als Tabelle                                      [M · 🟡]
Ziel        Der Reject-vs-Propagate-`switch` in `_handle_update_result` wird eine Datentabelle.
Berührt     `boot_state.c`.
Skizze
```c
typedef struct { boot_status_t in; boot_status_t out; wal_intent_t reject_to; } err_row_t;
static const err_row_t ERR_TABLE[] = {
  { BOOT_ERR_VERIFY,        BOOT_OK, WAL_INTENT_NONE }, /* reject: verwerfen */
  { BOOT_ERR_DOWNGRADE,     BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_FLASH_BOUNDS,  BOOT_OK, WAL_INTENT_NONE },
  /* Hardware-Fehler stehen NICHT hier → default: propagate */
};
```
Fertig wenn Verhalten von `_handle_update_result` bitidentisch (Replay-Diff == 0);
            neue Fehlerklasse = eine Tabellenzeile.
Hängt an    E0-T3, K5-T2

### K6-T2 — Intent-Übergangstabelle + Reducer                               [L · 🔴]
Ziel        Die verstreute Intent-Logik (Step-2-Normalisierung, `reconstruct_txn`-Sonderfälle,
            Sticky-Lock) wird eine Tabelle `{intent, event} → {next_intent, action}`; ein
            Reducer interpretiert sie.
Berührt     `boot_state.c`, `boot_journal.c` (Intent-Klassifikation).
Skizze
```c
typedef enum { EV_CONFIRM_OK, EV_CRASH, EV_CLOUD_UNLOCK, EV_UPDATE_PENDING, EV_NONE } boot_event_t;
typedef struct {
  wal_intent_t  cur;
  boot_event_t  ev;
  wal_intent_t  next;
  uint8_t       action;   /* ACT_NONE | ACT_HEAL_COUNTER | ACT_APPEND | ACT_PANIC_LOCKED */
} intent_row_t;

static const intent_row_t INTENT_TABLE[] = {
  { WAL_INTENT_DEVICE_LOCKED, EV_CLOUD_UNLOCK,  WAL_INTENT_NONE,    ACT_APPEND       },
  { WAL_INTENT_DEVICE_LOCKED, EV_CONFIRM_OK,    WAL_INTENT_DEVICE_LOCKED, ACT_PANIC_LOCKED }, /* sticky */
  { WAL_INTENT_CONFIRM_COMMIT,EV_CONFIRM_OK,    WAL_INTENT_NONE,    ACT_HEAL_COUNTER },
  { WAL_INTENT_CONFIRM_COMMIT,EV_CRASH,         WAL_INTENT_CONFIRM_COMMIT, ACT_NONE },
  /* … vollständige Matrix … */
};
```
Fertig wenn Reducer ersetzt Step-2/Step-3-Sonderfälle; K6-T4-Totalitätstest grün;
            Replay-Diff == 0 gegen Referenzbänder.
Hängt an    K6-T1

### K6-T3 — Pipeline-Tabelle + Treiber + generierte CFI-Sollmenge           [L · 🟡]
Ziel        Die P6-Stages (`stage_parse` … `stage_commit`) werden eine Tabelle
            `{fn, cfi_slot, fehlerpolitik}`; der Treiber baut die CFI-Sollmenge **aus dieser
            Tabelle** statt aus handgepflegten `boot_cfi_add_expected`-Listen. Beseitigt die
            fragile „PQC-Slot nachträglich addieren"-Kopplung.
Berührt     `boot_state.c`, `boot_verify.c` (PQC-Slot-Logik).
Skizze
```c
typedef boot_status_t (*stage_fn_t)(update_ctx_t*);
typedef struct { stage_fn_t fn; uint8_t cfi_slot; bool skippable; } stage_row_t;

static const stage_row_t PIPELINE[] = {
  { stage_parse,          STATE_CFI_SLOT_P1, false },
  { stage_verify_envelope,STATE_CFI_SLOT_P2, false },
  { stage_check_svn,      STATE_CFI_SLOT_P3, false },
  { stage_check_binding,  STATE_CFI_SLOT_P4, true  },
  { stage_route,          STATE_CFI_SLOT_P5, false },
  { stage_apply,          STATE_CFI_SLOT_P6, false }, /* delta|raw intern */
  { stage_swap,           STATE_CFI_SLOT_P7, false },
  { stage_commit,         STATE_CFI_SLOT_P8, false },
};

static boot_status_t run_pipeline(update_ctx_t *ctx, boot_cfi_ctx_t *cfi) {
  for (size_t i = 0; i < ARRAY_LEN(PIPELINE); i++)
    boot_cfi_add_expected(*cfi, PIPELINE[i].cfi_slot);   /* Sollmenge aus Tabelle */
  for (size_t i = 0; i < ARRAY_LEN(PIPELINE); i++) {
    boot_status_t s = PIPELINE[i].fn(ctx);
    if (s != BOOT_OK) return s;
    boot_cfi_step(*cfi, PIPELINE[i].cfi_slot);
  }
  return BOOT_OK;
}
```
Fertig wenn `_handle_update_flow` nutzt `run_pipeline`; die separate PQC-Sollmengen-Sonderlogik
            ist entfernt; Replay-Diff == 0; Fault-Injection-Test (Skip einer Stage) wird von
            der finalen `boot_cfi_require` gefangen.
Hängt an    K6-T2

### K6-T4 — Totalitätstest + Diagramm-Generator                             [M · 🟢]
Ziel        Host-Test iteriert *alle* `{intent, event}`-Paare und beweist: kein undefinierter
            Übergang. Build-Schritt erzeugt aus derselben Tabelle das Zustandsdiagramm für die Doku.
Berührt     `test/host/intent_total.c`, `tools/gen_state_diagram.py`.
Skizze
```c
for (int i = 0; i < N_INTENTS; i++)
  for (int e = 0; e < N_EVENTS; e++)
    assert(lookup(INTENT_TABLE, i, e) != NULL); /* kein Loch */
```
Fertig wenn Test grün; generiertes `.mermaid`/`.svg` im Doku-Ordner; CI bricht bei
            Tabellenloch.
Hängt an    K6-T2

---

# E-K3 — Idempotente Effekt-Transaktionen (ein Executor für alle Schreibpfade)

**Warum als Drittes.** Setzt auf K6-Struktur (`stage_swap`/`stage_apply` sind schon isoliert) und
das K5-Netz auf. Bringt K7 fast geschenkt mit (Planner liefert die Kostenbasis).

**Definition of Done (Epic).** Swap, Revert und Multi-Image sind Effekt-Listen für einen einzigen
Executor; Recovery nach Abbruch ist „Liste nochmal ausführen"; die drei alten Resume-Buchhaltungen
sind entfernt; der Enumerator (K5-T3) läuft grün über den neuen Executor.

### K3-T1 — Effekt-Typ + Planner-Schnittstelle                              [M · 🔴]
Ziel        Ein Datentyp, der jede destruktive Flash-Operation idempotent beschreibt, plus die
            Planner-Signatur (reine Funktion, schreibt nicht).
Berührt     `boot_effect.h` (neu).
Skizze
```c
typedef enum { EFF_ERASE = 1, EFF_COPY = 2 } effect_op_t;
typedef struct {
  effect_op_t op;
  uint32_t    src;       /* nur COPY */
  uint32_t    dst;
  uint32_t    len;
  uint32_t    post_crc;  /* Soll-CRC von [dst, dst+len) NACH dem Effekt */
} flash_effect_t;

/* Planner: schreibt NICHTS, füllt nur die Liste. */
typedef boot_status_t (*planner_fn_t)(const boot_platform_t*, const update_ctx_t*,
                                      flash_effect_t *out, size_t cap, size_t *n_out);
```
Fertig wenn Header + `_Static_assert(sizeof(flash_effect_t) % 4 == 0)`; drei leere Planner-Stubs
            (swap/revert/multi) linken.
Hängt an    E0-T1

### K3-T2 — Der Executor (einziger Schreibpfad im Core)                     [L · 🔴]
Ziel        Genau eine Funktion ruft `erase`/`write`. Regel pro Effekt: Post-CRC stimmt schon →
            überspringen (Zero-Wear + Idempotenz); sonst ausführen und per Read-Back gegen
            `post_crc` verifizieren. WAL-Checkpoint nur den *Index* des laufenden Effekts.
Berührt     `boot_effect.c` (neu), ersetzt Kernschleifen in `boot_swap.c`/`boot_rollback.c`/
            `boot_multiimage.c`.
Skizze
```c
boot_status_t boot_effect_execute(const boot_platform_t *p,
                                  const flash_effect_t *fx, size_t n,
                                  wal_entry_payload_t *txn,
                                  uint8_t *arena, size_t arena_len) {
  for (size_t i = 0; i < n; i++) {
    if (p->wdt) p->wdt->kick();

    /* Idempotenz-Gate: schon im Sollzustand? → skip (Resume + Zero-Wear in einem) */
    uint32_t cur = 0;
    if (boot_crc32_flash_stream(p, fx[i].dst, fx[i].len, arena, arena_len, &cur) == BOOT_OK
        && cur == fx[i].post_crc)
      continue;

    /* Checkpoint VOR Destruktion (nur der Index — die Liste ist reproduzierbar) */
    txn->delta_chunk_id = (uint32_t)i;
    boot_status_t cp = boot_journal_append(p, txn);
    if (cp != BOOT_OK) return cp;

    boot_status_t s = (fx[i].op == EFF_ERASE)
        ? boot_swap_erase_safe(p, fx[i].dst, fx[i].len, arena, arena_len)
        : stream_flash_copy(p, fx[i].src, fx[i].dst, fx[i].len, arena, arena_len);
    if (s != BOOT_OK) return s;

    /* Phase-Bound Read-Back gegen post_crc (kein lokaler bool ins SECURE_REQUIRE!) */
    uint32_t back = 0;
    boot_status_t rb = boot_crc32_flash_stream(p, fx[i].dst, fx[i].len, arena, arena_len, &back);
    if (rb != BOOT_OK) return rb;
    BOOT_SECURE_REQUIRE(back == fx[i].post_crc, { return BOOT_ERR_FLASH_HW; });
  }
  return BOOT_OK;
}
```
Fertig wenn Executor besteht K5-Enumerator über einen synthetischen 3-Effekt-Plan an *jeder*
            Abbruchstelle; Idempotenz-Test: doppelte Ausführung derselben Liste ändert Flash
            nach dem ersten Durchlauf nicht mehr.
Hängt an    K3-T1, K5-T3

### K3-T3 — Revert-Planner (erster echter Nutzer)                           [M · 🟡]
Ziel        `boot_rollback_trigger_revert` wird: Header lesen + validieren → Planner baut
            Effekt-Liste (Staging→App, sektorweise) → Executor. Die manuelle
            `delta_chunk_id`-Fortschreibung entfällt.
Berührt     `boot_rollback.c`.
Fertig wenn Äquivalenztest gegen die alte Revert-Implementierung über 50 Zufalls-Images
            (gleicher End-Flash); Enumerator grün; `rollback_compute_flash_crc32` entfernt
            (durch E0-T1 ersetzt).
Hängt an    K3-T2

### K3-T4 — Swap-Planner                                                    [M · 🟡]
Ziel        `boot_swap_apply` → Planner + Executor. Der Zero-Amplification-Block-Solver
            (Sektor-Max aus src/dst/scratch) zieht in den Planner.
Berührt     `boot_swap.c`.
Fertig wenn Äquivalenztest + Enumerator grün; alte Swap-Schleife entfernt.
Hängt an    K3-T3

### K3-T5 — Multi-Image-Planner mit doppelter Whitelist-Prüfung            [M · 🟡]
Ziel        `boot_multiimage_apply` → Planner + Executor. Die Region-Whitelist wird **zweimal**
            geprüft — im Planner (Ziel-Adressen) und im Executor (jeder `dst` gegen Whitelist) —
            womit die §5.1-Unabhängigkeit zweier Linien aus der Architektur fällt.
Berührt     `boot_multiimage.c`, `boot_effect.c` (Whitelist-Parameter am Executor).
Skizze
```c
boot_status_t boot_effect_execute_bounded(/* … */,
    const boot_allowed_region_t *wl, size_t wl_n /* Executor prüft erneut */);
```
Fertig wenn Ein Test mit manipuliertem Planner-Output (dst außerhalb Whitelist) wird vom
            Executor gefangen; Enumerator grün.
Hängt an    K3-T4

### K3-T6 — Alte Resume-Buchhaltung entfernen                               [S · 🟡]
Ziel        Die drei bespoke `WAL_INTENT_TXN_ROLLBACK_PENDING`-Fortschritts-Logiken sind weg;
            Recovery ist überall „Effekt-Liste neu ausführen".
Berührt     `boot_rollback.c`, `boot_swap.c`, `boot_multiimage.c`, `boot_state.c`
            (`_handle_rollback_flow`).
Fertig wenn `grep -rc "delta_chunk_id" toobloader/core/` ist deutlich gesunken; Enumerator grün;
            Netto-Zeilendiff des Epics negativ.
Hängt an    K3-T5

---

# E-K7 — Energie-bewusste Zulassung

**Warum als Anhängsel an K3.** Der Planner liefert die vollständige Effekt-Liste — ihre
Worst-Case-Kosten sind damit *vor* dem ersten destruktiven Schreibzugriff bekannt.

**Definition of Done (Epic).** Vor einem Swap prüft eine Zulassung, ob Erase-Budget (und wo
verfügbar: Spannung) reichen; sonst wird per `WAL_INTENT_SLEEP_BACKOFF` vertagt und das alte
Image gebootet.

### K7-T1 — HAL-Kostenmetadaten                                             [S · 🔴]
Ziel        `flash_hal_t` erhält optionale Kostenfelder; ABI-V2 bleibt kompatibel (append-only am
            Struct-Ende, Null bedeutet „unbekannt").
Berührt     `boot_hal.h`.
Skizze
```c
/* Append-only am Ende von flash_hal_t: */
  uint32_t erase_time_us_max;   /* Worst-Case Erase eines max_sector_size-Sektors, 0=unbekannt */
  uint32_t write_time_us_page;  /* pro write_align-Page, 0=unbekannt */
  /* optionaler Versorgungs-Readout (kann NULL sein): */
  boot_status_t (*get_supply_mv)(uint32_t *mv_out);
```
Fertig wenn `_Static_assert(offsetof(...))` sichert Feld-Reihenfolge; ein Vendor-Port füllt die
            Werte, alle anderen lassen sie 0 (Zulassung degradiert zu No-Op — fail-open bei
            Unwissen, dokumentiert).
Hängt an    E0-T2

### K7-T2 — Zulassungsprüfung vor dem Swap                                  [M · 🟡]
Ziel        Aus der K3-Effekt-Liste Worst-Case-Kosten summieren, gegen Budget prüfen, sonst
            vertagen.
Berührt     `boot_state.c` (vor `stage_swap`), `boot_effect.c` (Kosten-Summierer).
Skizze
```c
static boot_status_t admit_or_defer(const boot_platform_t *p,
                                    const flash_effect_t *fx, size_t n) {
  uint64_t worst_us = effect_cost_us(p, fx, n);  /* Σ erase/write Worst-Case */
  uint32_t mv = 0;
  bool have_mv = p->flash->get_supply_mv && p->flash->get_supply_mv(&mv) == BOOT_OK;

  /* Erase-Budget aus Wear-Countern (Daten sind schon in der TMR): */
  if (wear_exceeds_limit(p)) return BOOT_ERR_COUNTER_EXHAUSTED;

  if (have_mv && !supply_sufficient(mv, worst_us, BOOT_SUPPLY_MARGIN_MV))
    return BOOT_ERR_DEFER;   /* neu: nicht fatal */
  return BOOT_OK;
}
```
Fertig wenn Bei `BOOT_ERR_DEFER` wird `WAL_INTENT_SLEEP_BACKOFF` angehängt und das alte Image
            gebootet (Test); bei fehlenden Kostendaten ist der Pfad ein No-Op (kein
            Verhaltensbruch).
Hängt an    K7-T1, K3-T4

---

# E-K1 — Beweis-tragende Boot-Handles

**Warum parallel möglich.** Berührt nur Schnittstellen (Verify → Jump), keine Algorithmen —
kann neben K5/K6/K3 laufen. Löst nebenbei den ungeprüften Header-Re-Read in `stage0_main.c`.

**Definition of Done (Epic).** `jump_to_payload` (Stage 0) und `boot_main`s finaler Übergang
akzeptieren nur ein versiegeltes `boot_proof_t`; Sprungziel und Verifikationsergebnis sind ein
Datum; der rohe Header-Re-Read ist entfernt.

### K1-T1 — `boot_proof_t` + Siegel-Primitive                               [M · 🔴]
Ziel        Ein Handle-Typ + Siegel/Prüf-Funktionen; der Siegel-Schlüssel ist ein pro Boot
            einmalig gezogener TRNG-Wert, sichtbar nur innerhalb der Verify-Übersetzungseinheit.
Berührt     `boot_proof.h`/`.c` (neu, Core); `stage0_proof.h`/`.c` (neu, Stage 0 — eigene
            Instanz, da Stage 0 nicht gegen Core linkt).
Skizze
```c
typedef struct {
  uint32_t image_addr, image_size, entry_point, svn;
  uint32_t seal[2];   /* keyed checksum über die vier Felder */
} boot_proof_t;

/* seal_key: static, per Boot aus boot_random_safe() befüllt, nie exportiert. */
void boot_proof_seal(boot_proof_t *pr, const uint32_t seal_key[4]);
boot_status_t boot_proof_verify(const boot_proof_t *pr, const uint32_t seal_key[4]);
```
            Siegel = zwei unabhängige geschlüsselte Prüfsummen über dieselben Felder (Doppel-Akku
            gegen Einzel-Bit-Fault), analog zu `constant_time_memcmp_glitch_safe`.
Fertig wenn Unit-Test: manipuliertes Feld ODER falscher Key ⇒ `boot_proof_verify != BOOT_OK`;
            Seal-Key wird über `boot_random_safe` gezogen (schließt die in der Review notierte
            TRNG-Health-Lücke gleich mit).
Hängt an    E0-T1

### K1-T2 — Stage-0-Verify gibt ein Handle zurück                          [M · 🟡]
Ziel        `stage0_try_boot_bank` befüllt `boot_proof_t` im Moment der Hash-Berechnung
            (Entry-Point kommt aus dem *gehashten* Header) und versiegelt es bei Erfolg.
Berührt     `stage0_main.c` (`stage0_try_boot_bank`, `main`), `stage0_verify.c`.
Skizze
```c
static bool stage0_try_boot_bank(/* … */, boot_proof_t *out_proof) {
  /* … Header lesen, hashen, Signatur prüfen … */
  out_proof->image_addr  = bank_addr;
  out_proof->image_size  = hdr.image_size;
  out_proof->entry_point = hdr.entry_point;   /* aus dem SIGNIERTEN Header */
  out_proof->svn         = /* … */;
  boot_proof_seal(out_proof, g_seal_key);
  return true;
}
```
Fertig wenn Der zweite, rohe `flash->read(active_slot, &hdr, …)` in `main()` ist entfernt —
            der Entry-Point stammt jetzt aus dem versiegelten Handle.
Hängt an    K1-T1

### K1-T3 — `jump_to_payload` verlangt ein gültiges Handle                  [M · 🔴]
Ziel        Die Sprung-Primitive akzeptiert kein rohes `vector_table_addr` mehr, sondern ein
            `boot_proof_t*`; sie prüft das Siegel unmittelbar vor dem Sprung.
Berührt     `stage0_main.c` (`jump_to_payload`).
Skizze
```c
static void __attribute__((naked)) jump_to_payload_sealed(const boot_proof_t *pr);
/* Nicht-naked Wrapper prüft Siegel, berechnet Ziel, ruft dann den naked-Jump: */
static void jump_gate(const boot_proof_t *pr) {
  if (boot_proof_verify(pr, g_seal_key) != BOOT_OK) dead_halt();
  uint32_t target = pr->image_addr + pr->entry_point;
  /* Bounds-Recheck aus dem Handle, dann Assembler-Jump */
  jump_to_payload_raw(target);
}
```
Fertig wenn Fault-Injection-Test: ein Skip der Verifikation (per `should_inject_fault`) führt zu
            fehlendem/ungültigem Siegel ⇒ `dead_halt` statt Sprung; Happy-Path unverändert.
Hängt an    K1-T2

### K1-T4 — Handle-Form auch für Stage-1→OS-Übergang                        [M · 🟡]
Ziel        `boot_main`s finaler Übergang nutzt dieselbe Form: `target_out->active_entry_point`
            wird durch ein versiegeltes Handle ersetzt, das `boot_state_run` befüllt.
Berührt     `boot_main.c`, `boot_state.c` (Handoff-Block), `boot_types.h` (Handle im
            `boot_target_config_t`).
Fertig wenn Der Bounds-Block in `boot_main.c` prüft das Handle statt roher Felder; CFI-Akkus
            bleiben als zweite Schicht (§5.1); Replay-Diff == 0.
Hängt an    K1-T3

---

# E-K4 — Das Journal beweist seine eigene Geschichte

**Warum spät.** Setzt ein gerätegebundenes Geheimnis voraus (aus DICE/KDM-Material); gehört in
denselben Planungsblock wie die Identitätsarbeit. Härtet den heute „advisory" genannten
WAL-Floor zu einer echten zweiten Linie.

**Definition of Done (Epic).** Die drei sicherheitstragenden Intents (LOCKED, SVN-relevante
TMR-Updates, CONFIRM) sind gerätegebunden verkettet; ein manipulierter oder voll-zurückgespielter
Journal-Zustand fällt auf, sobald die eFuse-Epoche je fortgeschritten ist. Grenzen sind in
`security_model.md` benannt.

### K4-T1 — Gerätegebundenen Journal-Schlüssel ableiten                     [M · 🔴]
Ziel        Ein Schlüssel `k_dev` aus vorhandenem Identitätsmaterial (Chip-UID +
            Fuse-Geheimnis via KDF); Fallback-Verhalten auf Chips ohne geschützten Speicher
            explizit definiert und dokumentiert.
Berührt     `boot_identity.c` (neben `boot_derive_device_id`), `security_model.md`.
Fertig wenn `k_dev` deterministisch pro Gerät; auf Chips ohne Fuse-Geheimnis degradiert die
            Kette zu „Erkennung gegen Akteure ohne Codeausführung" (dokumentiert, nicht
            verschwiegen).
Hängt an    —

### K4-T2 — Verkettungs-Tag am WAL-Eintrag                                  [L · 🔴]
Ziel        Sicherheitstragende Einträge tragen `tag_n = H(k_dev, entry_n ‖ tag_{n-1})`; der
            Sektor-Header verankert den Kettenkopf.
Berührt     `boot_journal.h` (Feld im `wal_entry_payload_t` — nutzt `reserved`-Raum; ABI-Bump),
            `boot_journal.c` (`append`/`reconstruct_txn`).
Skizze
```c
/* Nur für sicherheitstragende Intents befüllt; sonst 0. Verankert im reserved-tail: */
uint8_t chain_tag[16];   /* verkürztes H(k_dev, entry ‖ prev_tag) */
```
Fertig wenn Ein nachträglich CRC-konform manipulierter LOCKED-Eintrag wird von der
            Ketten-Prüfung erkannt (Test); nicht-sicherheitstragende Einträge bleiben CRC-only
            (Hash-Kosten pro Boot begrenzt).
Hängt an    K4-T1

### K4-T3 — Epochen-Anker gegen Voll-Replay                                 [M · 🟡]
Ziel        Bei jeder TMR-Rotation wird die aktuelle eFuse-Epoche in die Kette eingebunden; ein
            voll-zurückgespieltes altes WAL-Abbild fällt auf, sobald die Epoche fortgeschritten ist.
Berührt     `boot_journal.c` (`update_tmr`).
Fertig wenn Test: komplettes altes (in sich konsistentes) WAL-Abbild + fortgeschrittene Epoche
            ⇒ Ketten-/Epochen-Mismatch erkannt; innerhalb derselben Epoche bleibt Replay
            unentdeckt (als Grenze dokumentiert).
Hängt an    K4-T2

### K4-T4 — WAL-Floor von „advisory" zu „enforced" hochstufen              [S · 🟡]
Ziel        Da die Kette den WAL-Zustand jetzt trägt, wird die SVN-Untergrenze aus dem WAL zur
            belastbaren zweiten Linie neben der eFuse-Epoche.
Berührt     `stage0_svn.c`-Kommentare, `boot_rollback.c` (`boot_rollback_verify_svn`),
            `security_model.md` (§5.1-Unabhängigkeit).
Fertig wenn Der Kommentar „advisory (A1)" ist durch eine belastbare Aussage ersetzt; die
            Zwei-Linien-Unabhängigkeit ist im Modell dokumentiert.
Hängt an    K4-T3

---

# E-K2 — Der Core parst keine Grammatik (Festformat-Manifest)

**Warum zuletzt.** Höchster Koordinationsaufwand (Registry, Manifest-Compiler,
Migrationsfenster), größter Einzelgewinn an Core-Minimalität. Braucht das K5-Netz, die
K6-Struktur und einen sauberen K3-Executor als Fundament.

**Definition of Done (Epic).** Der Boot-Pfad liest ein kanonisches Festformat („TBM1") über
konstante Offsets; kein zcbor mehr im Trusted Core; CBOR/SUIT bleibt Transport-/Cloud-Hülle,
abgestreift von libtoob (das ein volles OS unter sich hat). Migrationsfenster mit Doppel-Support.

### K2-T1 — TBM1-Spezifikation                                              [M · 🔴]
Ziel        Ein-Seiten-Spec: versionierter Header, feste Feld-Offsets, definite Längen, keine
            optionalen Umsortierungen. Deckt alles ab, was der *Boot-Pfad* aus dem Manifest liest
            (Signatur, Key-Index, SVN, Device-Binding, Chunk-Hashes, Image-Deskriptoren, PQC).
Berührt     `docs/tbm1_format.md` (neu), `boot_tbm1.h` (neu, Struct-Layout + `_Static_assert`s).
Skizze
```c
/* Alles little-endian, feste Offsets, keine Pointer — der "Parser" sind Feld-Reads. */
typedef struct __attribute__((packed)) {
  uint32_t magic;            /* 'TBM1' */
  uint16_t version;
  uint16_t header_len;
  uint32_t svn;
  uint8_t  key_index;
  uint8_t  pqc_active;
  uint16_t image_count;
  uint32_t chunk_size;
  uint32_t num_chunks;
  uint32_t chunk_hash_off;   /* Offset in Bytes ab TBM1-Start */
  uint32_t device_bind_off;  /* 0 = nicht vorhanden */
  /* … definierte, feste Reihenfolge … */
  uint8_t  sig_ed25519[64];  /* deckt [0 .. sig_off) ab */
} tbm1_header_t;
_Static_assert(offsetof(tbm1_header_t, sig_ed25519) == /* fix */, "TBM1 layout drift");
```
Fertig wenn Spec reviewt; alle heute aus dem SUIT-Objekt gelesenen Boot-Felder sind abgedeckt;
            Layout per `_Static_assert` fixiert.
Hängt an    —

### K2-T2 — TBM1-Encoder im Manifest-Compiler / in der Registry            [L · 🔴]
Ziel        Die Registry erzeugt TBM1 direkt aus dem Build; die Signatur deckt die TBM1-Bytes ab.
Berührt     Registry/Manifest-Compiler (außerhalb dieses Repos), Testvektoren.
Fertig wenn Ein Referenz-Update liegt als TBM1 + gültiger Signatur vor; Testvektoren im
            Repo für K2-T3.
Hängt an    K2-T1

### K2-T3 — TBM1-Reader im Core (ersetzt zcbor im Boot-Pfad)               [L · 🟡]
Ziel        `stage_parse` wird ~100 Zeilen bounds-geprüfte Feld-Reads über konstante Offsets;
            das gesamte Pointer-Sandboxing (`is_buffer_within`-Aufrufe gegen die Arena) entfällt,
            weil es keine parser-generierten Pointer mehr gibt.
Berührt     `boot_state.c` (`stage_parse`, `stage_route`, PQC-Feldzugriffe), Entfernen der
            zcbor-Abhängigkeit im Core-Build.
Skizze
```c
static boot_status_t stage_parse_tbm1(update_ctx_t *ctx) {
  ctx->platform->flash->read(ctx->open_txn->offset, ctx->arena, sizeof(tbm1_header_t));
  const tbm1_header_t *h = (const tbm1_header_t*)ctx->arena;
  if (h->magic != TBM1_MAGIC) return BOOT_ERR_INVALID_ARG;
  if (h->header_len > ctx->arena_len) return BOOT_ERR_INVALID_ARG;
  /* Chunk-Hash-Region als Offset+Länge — Bounds gegen header_len, KEIN Pointer-Sandbox nötig */
  if (h->chunk_hash_off + h->num_chunks*32u > h->header_len) return BOOT_ERR_INVALID_ARG;
  /* … Felder direkt übernehmen … */
  return BOOT_OK;
}
```
Fertig wenn `TOOB_MANIFEST_TBM1`-Build besteht denselben Verify-/Swap-Testvektorsatz wie der
            zcbor-Pfad; die 53 zcbor-Voll-Ketten-Zugriffe in `boot_state.c` sind eliminiert;
            Enumerator grün.
Hängt an    K2-T2, K3-T4

### K2-T4 — libtoob streift die Transport-Hülle ab                          [M · 🟡]
Ziel        CBOR/SUIT bleibt auf Transport-/Cloud-Ebene; libtoob (mit OS darunter) extrahiert
            TBM1 aus der Hülle und legt es ins Staging. Der Core sieht nur noch TBM1.
Berührt     `sdk/libtoob/toob_ota.c`, `toob_update.c`.
Fertig wenn Ein CBOR/SUIT-Update wird von libtoob korrekt in ein TBM1-Staging überführt;
            End-to-End-Test (Cloud-Hülle → Boot) grün.
Hängt an    K2-T3

### K2-T5 — Migrationsfenster + zcbor-Ausbau                                [M · 🔴]
Ziel        Doppel-Support (zcbor **und** TBM1) für ein definiertes Fenster; danach zcbor aus dem
            Core-Build entfernt.
Berührt     Core-Build, `boot_state.c`, `common/lib/zcbor/*` (Entfernung aus Core-Link).
Fertig wenn Feldgeräte-Flotte migriert (Betriebsentscheidung); `grep -rl zcbor toobloader/core`
            leer; Trusted-Core-Zeilenzahl messbar gesunken.
Hängt an    K2-T4

---

## Sprint-Vorschlag (Reihenfolge, nicht Kalender)

| Sprint | Inhalt | Ergebnis |
|---|---|---|
| S1 | E0 komplett + K5-T1/T2 | Dedup erledigt; Replay läuft |
| S2 | K5-T3/T4/T5 | Enumerator + CBMC grün — **das Netz steht** |
| S3 | K6-T1/T2 | Intent- & Fehlerlogik als Tabellen |
| S4 | K6-T3/T4 | Pipeline-Tabelle + generierte CFI-Sollmenge |
| S5 | K3-T1/T2 | Effekt-Executor, gegen Enumerator gehärtet |
| S6 | K3-T3/T4/T5/T6 | Alle Schreibpfade auf einem Executor; Resume-Buchhaltung weg |
| S7 | K7-T1/T2 (+ K1-T1/T2 parallel) | Energie-Zulassung; Handles beginnen |
| S8 | K1-T3/T4 | Sprung nur mit Siegel; roher Header-Re-Read weg |
| S9 | K4-T1..T4 (mit DICE/KDM-Block) | Journal-Kette; WAL-Floor „enforced" |
| S10+ | K2-T1..T5 | Festformat; zcbor aus dem Core |

## Messgrößen fürs Epic-Review

- **Trusted-Core-Zeilen** (LoC in `toobloader/core` + `stage0`, ohne Fremdcode) — soll sinken.
- **Zyklomatik** von `boot_state_run`, `stage_parse`, `boot_rollback_trigger_revert` — soll sinken.
- **Anzahl Schreibpfade** (Funktionen, die `flash->write/erase` rufen) — Zielwert nach K3: **1**.
- **Enumerator-Abdeckung** — Anteil der Flash-Schreibgrenzen mit geprüfter Nachbedingung: **100 %**.
- **Fremdcode im Core-Link** — nach K2: zcbor entfernt.