# boot_journal.c — Größen- & Code-Optimierung

Ziel: Quelltext **und** finale Bytes (Flash `.text` + RAM `.bss`/Peak-Stack) verkleinern, ohne
Funktionalität zu verlieren. Alle Vorschläge sind verhaltensneutral; die eine gefundene
Verhaltensänderung ist ein **Bugfix**, kein Feature-Verlust.

Eure Vorüberlegungen sind zu ~90 % korrekt und übernommen. Ergänzt: eine RAM-Einsparung, die noch
nicht drinstand, eine mathematisch verifizierte Vereinfachung, und eine latente Inkonsistenz, die
eher ein Bug als eine Größenfrage ist.

## Einsparungs-Überblick (grobe Schätzung)

| # | Maßnahme | `.text` | RAM | Risiko |
|---|---|---:|---:|---|
| R1 | Sektor-Adress-/Größen-Arrays → `const` (rodata) | ~40 B | **−64 B .bss** | 🟢 |
| R2 | Transiente Header-Stack-Puffer → 1 geteilter Scratch | ~120 B | **−200 B Peak-Stack** (+96 .bss) | 🟡 |
| C1 | `rotate_to_sector()` — 3–4 Kopien → 1 | **~200 B** | −Stack | 🟢 |
| C2 | `hash_chain_compute()` — 2 Hash-Skelette → 1 | **~200 B** | — | 🟢 |
| C3 | `read_header()` + `find_sector_by_seq()` | ~120 B | — | 🟢 |
| C4 | `classify_entry()` — geteilte Entry-Validierung | ~60 B | — | 🟢 |
| C5 | Nicht-inline CRC-Helfer (2×) | ~40 B | — | 🟢 |
| M1 | Modulare Wear-Protection (verifiziert) | ~50 B | — | 🟡 |
| X1 | `populated_size` als `#define` (**+ Bugfix**) | ~10 B | — | 🔴 |
| X2 | Majority-Vote gibt Index statt Struct | ~40 B | −152 B Stack | 🟢 |
| X3 | Redundantes Pre-Read-`zeroize` entfernen | ~60 B | — | 🟡 |

Summe grob: **~800–900 B `.text`**, **~260 B RAM/Peak-Stack** — bei unveränderter Funktion.
Die Zahlen sind Richtwerte (`-Os`, Cortex-M0); der strukturelle Gewinn an Lesbarkeit ist der
eigentliche Wert.

---

## 1. RAM-Einsparungen

### R1 — Sektor-Arrays gehören in `.rodata`, nicht `.bss` (neu)

```c
static uint32_t wal_sector_addrs[MAX_WAL_SECTORS];
static size_t   wal_sector_sizes[MAX_WAL_SECTORS];
```

Diese werden in `boot_journal_init` aus `TOOB_WAL_SECTOR_ADDRS`/`_SIZES` **kopiert** — also aus
compile-time-Konstanten. Nach der Init werden sie ausschließlich **gelesen** (jeder Zugriff ist ein
Read). Damit sind die veränderlichen Arrays plus die Kopierschleife reine Verschwendung: Sie
duplizieren rodata in RAM.

Fix: als file-scope `static const` deklarieren und direkt indizieren.

```c
static const uint32_t wal_sector_addrs[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_ADDRS;
static const size_t   wal_sector_sizes[TOOB_WAL_SECTORS] = TOOB_WAL_SECTOR_SIZES;
```

Spart ~64 B `.bss` (bei 8 Sektoren × 2×4 B) **und** die Init-Kopierschleife. Voraussetzung
verifiziert: nirgends wird in die Arrays geschrieben. Der `sizeof()`-Sanity-Check in der Init bleibt,
liest nur jetzt die Konstante.

### R2 — Transiente Header-Puffer zu einem Scratch zusammenführen

Über das Modul verteilt liegen ~8 Instanzen von
`wal_sector_header_aligned_t hdr __attribute__((aligned(8)))` auf dem Stack (je ~96 B), teils
mehrere pro Funktion, plus verschachtelt über Aufrufe (`update_tmr` → `get_best_wear_leveling_sector`
hat beide gleichzeitig live). Der **Peak-Stack** ist die Summe entlang der Aufrufkette — für einen
M0 mit knappem RAM die kritische Größe.

Da das Modul single-threaded und nicht-reentrant ist, kann **ein** modul-statischer Lese-Scratch
alle transienten Read-and-Inspect-Stellen bedienen:

```c
static wal_sector_header_aligned_t g_hdr_scratch __attribute__((aligned(8)));
```

**Wichtige Aliasing-Analyse (sonst Bug):** Ein geteilter Scratch ist nur sicher, wenn keine Funktion
Daten darin über einen Aufruf hält, der ihn ebenfalls beschreibt. Ich habe die Aufrufkette geprüft:
`append` und `update_tmr` lesen ihren `tg_hdr` **nach** dem `get_best_wear_leveling_sector`-Aufruf
(Reihenfolge: erst `new_idx` holen, dann Header lesen) — kein Overlap. Deshalb ist der geteilte
Scratch hier korrekt. Weil das aber fragil gegen künftige Edits ist, ist die **sichere Variante**,
den Scratch als Parameter an die Leaf-Helfer (`read_header`, `get_best_wear_leveling_sector`)
durchzureichen, sodass der Eigentümer sichtbar ist und der Compiler das Sharing sieht. Der
Write-Puffer (`write_hdr`, muss während des Schreibens leben) bleibt getrennt — davon gibt es nur
wenige und sie überlappen nicht, ein zweiter Static reicht.

Trade: +~96–192 B `.bss`, −~200–300 B Peak-Stack. Netto meist ein klarer Gewinn, weil die
Verschachtelung den Peak-Stack größer macht als den Static-Bedarf. Als bewusste Design-Entscheidung
dokumentieren.

---

## 2. Code-Deduplizierung (der Hauptteil der `.text`-Ersparnis)

### C1 — `rotate_to_sector()` (größter Einzelgewinn)

Das Muster „prev_erase lesen → smart-erase → Header bauen (seq/erase/tmr) → schreiben" steht
**vier Mal**: einmal in `append` (Rotation), dreimal in der `update_tmr`-Quorum-Schleife, plus eine
Variante im Factory-Blank-Pfad der Init.

```c
static boot_status_t rotate_to_sector(const boot_platform_t *p, uint32_t idx,
                                      uint32_t seq, const wal_tmr_payload_t *tmr,
                                      uint32_t *out_erase) {
  uint32_t prev = 0;
  if (read_header(p, idx) && verify_header_crc_glitch_safe(&g_hdr_scratch))
    prev = g_hdr_scratch.data.erase_count;

  boot_status_t s = smart_erase_sector(p, idx);
  if (s != BOOT_OK) return s;

  wal_sector_header_aligned_t wh __attribute__((aligned(8)));
  memset(&wh, p->flash->erased_value, sizeof(wh));
  wh.data.sector_magic = WAL_ABI_VERSION_MAGIC;
  wh.data.sequence_id  = seq;
  wh.data.erase_count  = prev + 1;
  wh.data.tmr_data     = *tmr;
  wh.data.header_crc32 = sector_hdr_crc(&wh.data);

  if (p->wdt && p->wdt->kick) p->wdt->kick();
  s = p->flash->write(wal_sector_addrs[idx], (const uint8_t *)&wh, sizeof(wh));
  boot_secure_zeroize(&wh, sizeof(wh));
  if (s == BOOT_OK && out_erase) *out_erase = prev + 1;
  return s;
}
```

`append` ruft es einmal, `update_tmr` in der Schleife dreimal. Der Rumpf verschwindet aus beiden.
Geschätzt ~200 B `.text` plus deutlich weniger Stack (nur noch ein `wh` pro Aufruf statt pro
Kopie).

### C2 — `hash_chain_compute()` als Segment-Liste

`compute_chain_tag` hasht `(key ‖ entry_bytes ‖ prev_tag)`; `update_tmr` codiert offen
`(key ‖ tmr_bytes ‖ epoch ‖ prev_tag)` — unterschiedliche Eingaben, **identisches Skelett**
(init → update× → finish → truncate, plus Fehlerpfad mit Dummy-Finish und `zeroize`). Ein
generischer Helfer über eine Segment-Liste vereint beide:

```c
typedef struct { const uint8_t *p; size_t n; } hash_seg_t;

static boot_status_t hash_chain_compute(const boot_platform_t *pf,
                                        const hash_seg_t *seg, size_t nseg,
                                        uint8_t out[WAL_CHAIN_TAG_BYTES]) {
  uint8_t ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(ctx, sizeof(ctx));
  boot_secure_zeroize(out, WAL_CHAIN_TAG_BYTES);

  boot_status_t s = pf->crypto->hash_init(ctx, sizeof(ctx));
  for (size_t i = 0; s == BOOT_OK && i < nseg; i++)
    s = pf->crypto->hash_update(ctx, seg[i].p, seg[i].n);

  uint8_t digest[32]; size_t dl = 32;
  if (s == BOOT_OK) {
    s = pf->crypto->hash_finish(ctx, digest, &dl);
    if (s == BOOT_OK) memcpy(out, digest, WAL_CHAIN_TAG_BYTES);
  } else {
    (void)pf->crypto->hash_finish(ctx, digest, &dl); /* Kontext sauber schließen */
  }
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(ctx, sizeof(ctx));
  return s;
}
```

Aufrufseiten:

```c
/* compute_chain_tag: */
hash_seg_t seg[] = {{key,WAL_CHAIN_TAG_BYTES},
                    {(const uint8_t*)entry, offsetof(wal_entry_payload_t,crc32_trailer)},
                    {prev_tag,WAL_CHAIN_TAG_BYTES}};
return hash_chain_compute(platform, seg, 3, out_tag);

/* update_tmr Epoch-Anker (prev_tag steckt implizit in den tmr-Bytes — Reihenfolge bewahrt!): */
hash_seg_t seg[] = {{journal_key,WAL_CHAIN_TAG_BYTES},
                    {(const uint8_t*)&tmr_to_write, sizeof(wal_tmr_payload_t)},
                    {(const uint8_t*)&efuse_epoch, sizeof(efuse_epoch)}};
hash_chain_compute(platform, seg, 3, tmr_to_write.chain_tag);
```

Die subtile Ordnung bleibt erhalten: Im Epoch-Anker enthalten die `tmr_to_write`-Bytes noch den
**alten** `chain_tag`; er wird erst danach vom Digest überschrieben. Geschätzt ~200 B.

### C3 — `read_header()` + `find_sector_by_seq()`

Das „read + zeroize"-Muster für Sektor-Header steht ~8×; die „Sektor mit passender sequence_id
finden"-Schleife 2× (`reconstruct_txn`, Init-Quorum).

```c
static bool read_header(const boot_platform_t *p, uint32_t idx) {
  return p->flash->read(wal_sector_addrs[idx], (uint8_t *)&g_hdr_scratch,
                        sizeof(g_hdr_scratch)) == BOOT_OK;
}
static int32_t find_sector_by_seq(const boot_platform_t *p, uint32_t seq) {
  for (uint32_t i = 0; i < TOOB_WAL_SECTORS; i++)
    if (read_header(p, i) && verify_header_crc_glitch_safe(&g_hdr_scratch) &&
        g_hdr_scratch.data.sequence_id == seq)
      return (int32_t)i;
  return -1;
}
```

Beide Suchschleifen kollabieren auf einen Aufruf. ~120 B plus weniger Stack.

### C4 — `classify_entry()`

Read + CRC + Magic + `BOOT_SECURE_REQUIRE` steht in `scan_for_frontier_linear` **und**
`reconstruct_txn`. Ein Klassifikator vereinheitlicht die Prüfung (der Frontier-Scan braucht die
Unterscheidung ERASED vs. CORRUPT, die Rekonstruktion nur VALID vs. nicht):

```c
typedef enum { WAL_E_ERASED, WAL_E_VALID, WAL_E_CORRUPT } wal_entry_state_t;

static wal_entry_state_t classify_entry(const wal_entry_aligned_t *e, uint8_t ev) {
  if (is_fully_erased_constant_time((const uint8_t*)e, sizeof(*e), ev)) return WAL_E_ERASED;
  bool ok = (e->data.magic == WAL_ENTRY_MAGIC) &&
            (entry_crc(&e->data) == e->data.crc32_trailer);
  return ok ? WAL_E_VALID : WAL_E_CORRUPT;
}
```

~60 B, und die doppelte CRC-Berechnungslogik verschwindet.

### C5 — Nicht-inline CRC-Helfer

`compute_boot_crc32(&X, offsetof(wal_sector_header_t, header_crc32))` steht 5×, das Entry-Pendant
4×. Als **nicht-inline** `static`-Funktionen (bewusst nicht `inline` — für Größe zählt eine Kopie
statt fünf):

```c
static uint32_t sector_hdr_crc(const wal_sector_header_t *h) {
  return compute_boot_crc32((const uint8_t *)h, offsetof(wal_sector_header_t, header_crc32));
}
static uint32_t entry_crc(const wal_entry_payload_t *e) {
  return compute_boot_crc32((const uint8_t *)e, offsetof(wal_entry_payload_t, crc32_trailer));
}
```

Kostet je einen Call, spart die wiederholten Immediate-Ladungen und die Textkopien.

---

## 3. Mathematische Vereinfachung

### M1 — Modulare Wear-Protection (verifiziert)

`get_best_wear_leveling_sector` schützt die letzten 4 Sequenzen mit einem verschachtelten
Konstrukt aus `is_newer_sequence()`, einer zusammengesetzten Bedingung und einer
Spezialfall-Wrap-Heuristik (`seq > 0xFFFFFFF0 && highest < 10`). Das gesamte Konstrukt ist durch
**eine** modulare Subtraktion ersetzbar:

```c
/* highest_seq - seq wrappt mod 2^32; Fenster = 4 */
if ((uint32_t)(highest_seq - hdr.data.sequence_id) < WAL_PROTECT_WINDOW)
  continue;   /* schütze diesen Sektor */
```

Ich habe die Äquivalenz über alle Rand- und Wrap-Fälle numerisch geprüft (Innen-/Außenrand des
Fensters, „seq neuer als highest" = Korruption, und vier Wrap-Konstellationen um 0 herum). Die
modulare Version ist nicht nur äquivalent, sie behandelt den Sequenz-Wrap **sauberer** — genau den
Fall, den die alte Heuristik nur halb abdeckte. Ergebnis:

```
seq==highest        -> schützt     highest-4           -> frei
highest-3 (Rand)    -> schützt     seq neuer (Korrupt) -> frei (huge diff)
wrap highest=2,     seq=2^32-1     -> schützt (== highest-3)
wrap highest=0,     seq=2^32-3     -> schützt (== highest-3)
```

Entfernt ~10 Zeilen, den `is_newer_sequence`-Aufruf an dieser Stelle und die Wrap-Sonderlogik.
🟡, weil es den Schutzpfad berührt — deshalb der Enumerator/Test aus dem K5-Netz darüber.

---

## 4. Latente Inkonsistenz (Bugfix, kein reiner Cleanup)

### X1 — `populated_size` widerspricht sich (52 vs. 76)

`migrate_v1_tmr` setzt `populated_size = 76` mit expliziter Herleitung
(4 + 48 + 4 stage1_svn + 16 chain_tag + 4 chain_entry_count). Der Factory-Blank-Pfad in
`boot_journal_init` setzt aber:

```c
current_active_header.tmr_data.populated_size = 52;
```

76 − 52 = 24 = genau `stage1_svn (4) + chain_tag (16) + chain_entry_count (4)`. Ein **migriertes**
Gerät deklariert also, diese Felder seien populated; ein **fabrikneues** Gerät deklariert das
Gegenteil — für dieselbe `struct_version`. Wenn `populated_size` je von einem Forward-Compat-Reader
als memcpy-/Gültigkeitsgrenze benutzt wird, unterschätzt ein fabrikneues Gerät seine populated
Region und die Chain-Felder gelten fälschlich als „nicht vorhanden".

Fix an einer Stelle, der zugleich die Magic-Zahlen beseitigt:

```c
/* boot_journal.h — eine Quelle der Wahrheit, offsetof-verankert */
#define WAL_TMR_POPULATED_SIZE  offsetof(wal_tmr_payload_t, _reserved_after_populated)
/* bzw. ein #define, das genau die belegten Felder abdeckt */
```

Beide Setzstellen nutzen `WAL_TMR_POPULATED_SIZE`. Damit können sie nicht mehr auseinanderlaufen,
und der `struct_version`/`populated_size`-Vertrag ist konsistent. Das ist die einzige Änderung mit
Verhaltenswirkung — und sie behebt einen Bug, statt Funktionalität zu entfernen.

---

## 5. Mikro-Optimierungen

### X2 — Majority-Vote gibt Index statt Struct-Wert

`tmr_majority_vote` gibt `wal_tmr_payload_t` **by value** zurück (≥76 B). Der große Struct-Return
läuft über einen versteckten Pointer (memcpy), und der Aufrufer kopiert nochmal in
`current_active_header.tmr_data` — zwei Kopien. Ein Index-Rückgabewert lässt genau eine Kopie übrig:

```c
static int tmr_majority_vote_idx(const wal_tmr_payload_t *c, int n); /* 0..2 */
/* Aufrufer: */
current_active_header.tmr_data = tmr_candidates[tmr_majority_vote_idx(cands, n)];
```

Die drei `constant_time_memcmp`-Vergleiche bleiben (sie sind das mathematische Minimum für einen
3-fach-Mehrheitsentscheid, C(3,2)=3 — nicht weiter reduzierbar). Nur der Rückgabeweg wird billiger:
~40 B `.text`, −152 B Stack (zwei 76-B-Kopien gespart).

### X3 — Redundantes Pre-Read-`zeroize` entfernen

Viele Stellen tun `boot_secure_zeroize(&hdr, …)` **vor** einem `flash->read`, das den Puffer
vollständig überschreibt. Ist der Read-Rückgabewert geprüft (ist er überall), ist das Pre-Zeroize
totes Werk — der Read füllt alles. Die *Leakage*-Sorge (Nonce-Bytes im Puffer nach Gebrauch)
adressiert nur ein **Post**-Use-`zeroize`, das an einigen Stellen fehlt. Also: Pre-Read-Zeroize
streichen, Post-Use-Zeroize für nonce-tragende Puffer beibehalten/ergänzen. Sicherheitsneutral bis
leicht besser, ~60 B über alle Stellen. 🟡 nur, weil es Zeroize berührt — die Regel ist klar:
*einmal nach Gebrauch, nie vor einem vollständigen Read.*

### X4 — Init: Doppel-Read des Highest-Headers vermeiden

`boot_journal_init` scannt alle Sektoren für `highest_idx` und liest danach denselben Sektor
erneut. Cacht man den Gewinner-Header während des Scans (Kopie beim Finden eines neuen Maximums),
entfällt der zweite Flash-Read plus etwas Code. Klein, aber sauber.

---

## 6. Bewusst NICHT anfassen

- **Whole-Struct-Vergleich im TMR-Vote**: vergleicht bereits nur `wal_tmr_payload_t` (die TMR,
  nicht den ganzen Header). Kein Gewinn durch „nur TMR-Bytes".
- **`memset(&wh, erased_value, …)` vor `memcpy`**: setzt Padding auf 0xFF, damit ungeschriebene
  Bits 1 bleiben (flash-konform). Bleibt — wandert in `rotate_to_sector`.
- **CRC vs. Chain-Tag zusammenlegen**: unterschiedliche Domänen (Fehlererkennung vs.
  geräte­gebundene Kette). Nicht mergen.
- **Intent-Klassifikation → Tabelle** (`reconstruct_txn`): die Handler schreiben in verschiedene
  Out-Parameter; eine Tabelle + `switch` spart im Binary kaum etwas gegenüber der if-Kette und kann
  die Lesbarkeit senken. Niedrige Priorität — nur mitnehmen, wenn K6 die Intent-Algebra ohnehin
  tabellarisiert.

---

## 7. Reihenfolge

1. **X1** zuerst — es ist der Bugfix; alles andere baut auf konsistentem `populated_size` auf.
2. **R1** (const-Arrays) und **C5** (CRC-Helfer) — rein mechanisch, sofort grün.
3. **C3** (`read_header`/`find_sector_by_seq`) legt den geteilten Scratch an → Voraussetzung für R2.
4. **C1** (`rotate_to_sector`) und **C2** (`hash_chain_compute`) — die zwei großen Text-Gewinne.
5. **R2** (Scratch-Zusammenführung) mit der dokumentierten Aliasing-Begründung.
6. **M1** (modulare Wear-Protection) und **X2/X3/X4** — verifiziert bzw. mikro.

Jeder Schritt einzeln committen und gegen den K5-Enumerator (Stromausfall an jeder
Schreibgrenze) fahren — besonders C1, R2 und M1, weil sie Rotations- und Schutzpfade berühren.
Das Netz beweist, dass die Verkleinerung die Crash-Konsistenz nicht antastet.