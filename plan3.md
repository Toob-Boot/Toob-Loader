# TBM1 v2 — Reader- & Härtungs-Backlog

Fokus: den TBM1-v2-Reader (`boot_tbm1.c`) bauen und die Findings aus der Header-Review schließen.
Verfeinert die Eltern-Tickets **K2-T1** (Header/Spec) und **K2-T3** (Reader). Alle Findings der
Review sind hier in umsetzbare Tickets übersetzt.

Leitsatz aus der Review: *Der Header ist nur so stark wie sein Reader.* Fast alle offenen Punkte
sind Reader-Vertrag, nicht Layout. Dieser Backlog macht den Vertrag explizit und testbar.

**Ticket-Schema** — ID · Ziel · Berührt · Skizze · Fertig-wenn · Hängt-an.
**Aufwand** S ≤0,5 T · M 1–2 T · L 3–5 T. **Risiko** 🟢 mechanisch · 🟡 Sicherheitspfad · 🔴 Spec-/ABI-Entscheidung.

---

## Reihenfolge

```
H-Block (Header-Textfixes, klein) ──► R-Block (Reader) ──► V-Block (Vektoren/Fuzz)
       TBM1-H1..H4                        TBM1-R1..R6           TBM1-V1..V3
```

H zuerst, weil R gegen die geklärte Spec baut. V begleitet R ab R2 (Golden Vectors entstehen mit
jeder Prüfung mit).

---

# H — Header- & Spec-Klärungen (aus der Review)

### TBM1-H1 — Reserved-Semantik trennen (Encoder-Pflicht vs. Reader-Toleranz)   [S · 🔴]
Ziel        Der Widerspruch „`_reserved_tail` must be zero" ⇄ „future minor-version fields" ist
            aufgelöst. Additives Wachstum funktioniert ab Tag eins.
Berührt     `boot_tbm1.h` (Kommentare an `_reserved_tail`, `_rsvd`, `_rsvd0`), `docs/tbm1_format.md`.
Skizze      Zwei getrennte Regeln:
```
Encoder MUSS ungenutzte Reserved-/Padding-Bytes auf 0 setzen.
Reader DARF NICHT wegen Nicht-Null in Reserved-/Padding-Bytes ablehnen (Toleranz).
Begründung: Reserved liegt im signierten Bereich → nur der legitime Signierer füllt es;
unbekannte Bytes werden semantisch ignoriert. Zero-Check würde Minor-Upgrades brechen.
```
Fertig wenn Kommentare + Spec spiegeln die Trennung; keine Reader-Prüfung erzwingt Null auf dem
            Schwanz (siehe TBM1-R1).
Hängt an    —

### TBM1-H2 — `TBM1_SIGNED_LEN` als bounds-prüfende Funktion                   [S · 🟡]
Ziel        Kein Makro-Doppelauswertungs-Footgun; kein `size_t`-Unterlauf bei `total_len < 64`.
Berührt     `boot_tbm1.h`.
Skizze
```c
/* Ersetzt das Makro. Gibt 0 zurück, wenn total_len unplausibel — Aufrufer prüft. */
static inline size_t tbm1_signed_len(const tbm1_header_t *hdr) {
  if (hdr->total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) return 0;
  return (size_t)hdr->total_len - TBM1_SIG_LEN;
}
```
Fertig wenn Makro entfernt; alle Aufrufer nutzen die Funktion und behandeln 0 als Reject.
Hängt an    —

### TBM1-H3 — `tbm1_find_region`-Guard + Dedup-Kontrakt                         [S · 🟢]
Ziel        `find_region(hdr, 0)` matcht nicht mehr versehentlich leere Slots; Duplikat-Verhalten
            dokumentiert (Validierung lehnt Duplikate ab, siehe TBM1-R3).
Berührt     `boot_tbm1.h`.
Skizze
```c
static inline const tbm1_region_t *
tbm1_find_region(const tbm1_header_t *hdr, uint16_t id) {
  if (id == TBM1_REGION_NONE) return NULL;              /* Guard */
  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++)
    if (hdr->regions[i].region_id == id) return &hdr->regions[i];
  return NULL;
}
```
Fertig wenn Guard drin; Doxygen sagt „nur nach bestandener Validierung aufrufen (Duplikate dort
            abgelehnt)".
Hängt an    —

### TBM1-H4 — Doku: harte Maxima + Familienname                                [S · 🟢]
Ziel        Zwei Onboarding-Stolpersteine aus der Review sind dokumentiert.
Berührt     `boot_tbm1.h`, `docs/tbm1_format.md`.
Skizze      Zwei Doku-Sätze:
```
TBM1_MAX_IMAGES (4) und TBM1_MAX_REGIONS (8) sind die HARTEN Decken des Formats.
Feste Arrays an festen Offsets → Überschreiten ist ein Major-Version-Ereignis.
"TBM1" ist der FormatFAMILIEN-Name, nicht die Versionsnummer (die steht in version_major).
```
Fertig wenn Beide Sätze im Header-Doxygen und in der Spec.
Hängt an    —

---

# R — Reader-Implementierung (`boot_tbm1.c`)

Der Kern. Eine zusammenhängende, überlaufsichere Validierung, die den gesamten Reader-Vertrag an
*einer* Stelle festnagelt. Alles hier ist Voraussetzung, bevor irgendein Feld des Manifests im
Boot-Pfad benutzt wird.

### TBM1-R1 — Fehler-Taxonomie                                                  [S · 🟢]
Ziel        Distinkte Reject-Codes, damit Feld-Telemetrie Fehlermodi unterscheidet (statt alles
            auf `BOOT_ERR_INVALID_ARG` zu kollabieren).
Berührt     `boot_tbm1.h` (neu: `tbm1_reject_t`).
Skizze
```c
typedef enum {
  TBM1_OK = 0,
  TBM1_BAD_MAGIC,        TBM1_BAD_FIXED_LEN,   TBM1_BAD_VERSION,
  TBM1_BAD_TOTAL_LEN,    TBM1_BAD_CRC,         TBM1_BAD_IMAGE_COUNT,
  TBM1_BAD_CHUNK_MATH,   TBM1_BAD_KEY_INDEX,   TBM1_BAD_CRIT_FLAG,
  TBM1_BAD_REGION_BOUNDS,TBM1_BAD_REGION_ORDER,TBM1_BAD_REGION_DUP,
  TBM1_BAD_CHUNKHASH_LEN,TBM1_BAD_HW_COMPAT,
} tbm1_reject_t;
```
Fertig wenn Enum vorhanden; Mapping `tbm1_reject_t → boot_status_t` für den Boot-Pfad definiert;
            jeder Code wird von genau einem Golden Vector ausgelöst (TBM1-V1).
Hängt an    —

### TBM1-R2 — Struktur-Pre-Checks (vor jedem Feldzugriff)                       [M · 🟡]
Ziel        Die billigen, angreiferkontroll-kritischen Prüfungen, die *vor* allem anderen laufen —
            insbesondere die Grenze, die den späteren Hash-Loop steuert.
Berührt     `boot_tbm1.c`.
Skizze
```c
tbm1_reject_t tbm1_precheck(const uint8_t *buf, size_t staging_cap) {
  if (staging_cap < TBM1_FIXED_LEN) return TBM1_BAD_TOTAL_LEN;
  const tbm1_header_t *h = (const tbm1_header_t *)buf;

  if (h->magic != TBM1_MAGIC)            return TBM1_BAD_MAGIC;
  if (h->fixed_len != TBM1_FIXED_LEN)    return TBM1_BAD_FIXED_LEN;
  if (h->version_major != TBM1_VERSION_MAJOR) return TBM1_BAD_VERSION;

  /* total_len steuert den Hash-Loop → ZUERST gegen physische Kapazität klemmen */
  if (h->total_len < (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) return TBM1_BAD_TOTAL_LEN;
  if (h->total_len > staging_cap)                               return TBM1_BAD_TOTAL_LEN;

  /* Kompatibilitäts-Gates */
  if ((h->flags_critical & ~TBM1_CRIT_KNOWN_MASK) != 0)         return TBM1_BAD_CRIT_FLAG;
  /* min_reader_* gegen die eigene Reader-Version (durchgereicht) */

  /* Schneller CRC-Vorabcheck — trennt "Staging korrupt" von "Signatur ungültig" */
  uint32_t crc = boot_crc32(buf, TBM1_CRC_LEN);
  if (crc != h->fixed_crc32)             return TBM1_BAD_CRC;

  return TBM1_OK;
}
```
Fertig wenn Ein absichtlich zu großes `total_len` wird gefangen, *bevor* gehasht wird
            (kein OOB-Read im Fuzzer, TBM1-V3); CRC-Mismatch liefert `TBM1_BAD_CRC`, nicht
            `BAD_SIG`.
Hängt an    TBM1-R1, TBM1-H2, E0-T1 (`boot_crc32_flash_stream`/`boot_crc32`)

### TBM1-R3 — Region-Directory-Validierung (überlaufsicher, kanonisch)          [M · 🟡]
Ziel        Alle belegten Regionen in einer Schleife: überlaufsichere Bounds, aufsteigend
            sortiert, nicht überlappend, keine Duplikate.
Berührt     `boot_tbm1.c`.
Skizze
```c
tbm1_reject_t tbm1_validate_regions(const tbm1_header_t *h) {
  uint32_t prev_end = TBM1_FIXED_LEN;   /* Regionen liegen hinter dem festen Header */
  uint16_t seen = 0;                    /* Bitset gesehener IDs (klein, IDs < 16) */
  size_t sig_start = tbm1_signed_len(h);           /* = total_len - 64 */
  if (sig_start == 0) return TBM1_BAD_TOTAL_LEN;

  for (unsigned i = 0; i < TBM1_MAX_REGIONS; i++) {
    const tbm1_region_t *r = &h->regions[i];
    if (r->region_id == TBM1_REGION_NONE) continue;

    if (r->region_id < 16) {                        /* Duplikat-Erkennung */
      if (seen & (1u << r->region_id)) return TBM1_BAD_REGION_DUP;
      seen |= (1u << r->region_id);
    }
    /* Überlaufsicher: NIE off + len */
    if (r->off > sig_start)              return TBM1_BAD_REGION_BOUNDS;
    if (r->len > (uint32_t)sig_start - r->off) return TBM1_BAD_REGION_BOUNDS;
    /* Kanonisch: aufsteigend, nicht überlappend */
    if (r->off < prev_end)               return TBM1_BAD_REGION_ORDER;
    prev_end = r->off + r->len;
  }
  return TBM1_OK;
}
```
Fertig wenn Je ein Golden Vector für BOUNDS/ORDER/DUP wird gefangen; Regionen dürfen die Signatur
            nicht überlappen (`sig_start` als Obergrenze).
Hängt an    TBM1-R2

### TBM1-R4 — Image-Descriptor-Konsistenz                                       [M · 🟡]
Ziel        `image_count`, Chunk-Mathematik, Slot-/Enum-Plausibilität, HW-Kompatibilität.
Berührt     `boot_tbm1.c`.
Skizze
```c
tbm1_reject_t tbm1_validate_images(const tbm1_header_t *h,
                                   uint16_t dev_product, uint16_t dev_hw_rev,
                                   uint8_t provisioned_keys) {
  if (h->image_count < 1 || h->image_count > TBM1_MAX_IMAGES) return TBM1_BAD_IMAGE_COUNT;
  if (h->key_index >= provisioned_keys)                       return TBM1_BAD_KEY_INDEX;

  /* HW-Gate: signiert, also vertrauenswürdig sobald Signatur ok — hier nur Plausibilität */
  if (h->product_id != dev_product)                           return TBM1_BAD_HW_COMPAT;
  if (dev_hw_rev < h->hw_rev_min || dev_hw_rev > h->hw_rev_max)return TBM1_BAD_HW_COMPAT;

  for (unsigned i = 0; i < h->image_count; i++) {
    const tbm1_image_desc_t *d = &h->images[i];
    if (d->chunk_size == 0)                                   return TBM1_BAD_CHUNK_MATH;
    uint32_t expect = (d->installed_size + d->chunk_size - 1) / d->chunk_size;
    if (d->num_chunks != expect)                             return TBM1_BAD_CHUNK_MATH;
    if (d->target_slot > TBM1_SLOT_STAGE1)                    return TBM1_BAD_CHUNK_MATH; /* o. eigener Code */
  }
  return TBM1_OK;
}
```
Fertig wenn `chunk_size==0`, falsches `num_chunks`, `image_count` außerhalb `[1..4]`, falsches
            Produkt und HW-Rev außerhalb `[min..max]` werden je gefangen (Golden Vectors).
Hängt an    TBM1-R2

### TBM1-R5 — Chunk-Hash-Partitionierung (die Interop-Landmine)                 [M · 🔴]
Ziel        Die bisher nur konventionelle „Hashes in Descriptor-Reihenfolge konkateniert"-Regel
            wird explizit und per Länge gegengeprüft. Reader liefert Per-Image-Hash-Offsets.
Berührt     `boot_tbm1.c`, `docs/tbm1_format.md` (Regel festschreiben).
Skizze
```c
/* Spec-Regel: REGION_CHUNK_HASHES enthält je num_chunks_i × 32 Bytes,
 * in image-descriptor-Reihenfolge konkateniert. */
tbm1_reject_t tbm1_chunkhash_slices(const tbm1_header_t *h,
                                    uint32_t *out_off /*[image_count]*/) {
  const tbm1_region_t *r = tbm1_find_region(h, TBM1_REGION_CHUNK_HASHES);
  if (!r) return TBM1_BAD_CHUNKHASH_LEN;
  uint64_t sum = 0;
  for (unsigned i = 0; i < h->image_count; i++) {
    out_off[i] = r->off + (uint32_t)(sum);           /* Präfix-Summe */
    sum += (uint64_t)h->images[i].num_chunks * 32u;  /* u64 gegen Überlauf */
  }
  if (sum != r->len) return TBM1_BAD_CHUNKHASH_LEN;   /* exakte Längen-Kreuzprüfung */
  return TBM1_OK;
}
```
Fertig wenn `region.len != Σ(num_chunks_i)×32` wird gefangen; die Partitionierungsregel steht
            wörtlich in der Spec; ein 2-Image-Golden-Vector prüft korrekte Slice-Offsets.
Hängt an    TBM1-R4

### TBM1-R6 — Top-Level-Validierung + Signatur-Reihenfolge                      [M · 🟡]
Ziel        Eine `tbm1_validate()`-Fassade, die R2→R3→R4→R5 in der richtigen Reihenfolge fährt
            und danach den signierten Bereich `[0..tbm1_signed_len)` an die Ed25519-Prüfung
            übergibt. Reihenfolge: erst struktur-/CRC-billig ablehnen, dann teuer signieren.
Berührt     `boot_tbm1.c`, Aufrufstelle in `stage_parse` (K2-T3).
Skizze
```c
tbm1_reject_t tbm1_validate(const uint8_t *buf, size_t staging_cap,
                            const boot_device_ctx_t *dev) {
  tbm1_reject_t rc;
  if ((rc = tbm1_precheck(buf, staging_cap)))               return rc;
  const tbm1_header_t *h = (const tbm1_header_t *)buf;
  if ((rc = tbm1_validate_regions(h)))                      return rc;
  if ((rc = tbm1_validate_images(h, dev->product_id,
                                 dev->hw_rev, dev->keys)))  return rc;
  uint32_t offs[TBM1_MAX_IMAGES];
  if ((rc = tbm1_chunkhash_slices(h, offs)))                return rc;
  return TBM1_OK;   /* Signatur prüft der Aufrufer über tbm1_signed_len(h) */
}
```
Fertig wenn Vollständiger Happy-Path-Vector besteht; jede Prüfung läuft *vor* der Signatur;
            `stage_parse` ruft nur noch `tbm1_validate` + Ed25519 über `tbm1_signed_len`.
            Struct-Cast setzt `_Alignas(4)`-Arena voraus (dokumentiert).
Hängt an    TBM1-R5

---

# V — Golden Vectors, geteilte Tests, Fuzzing

### TBM1-V1 — Golden-Vector-Satz                                                [M · 🟢]
Ziel        Ein kanonischer Happy-Path-Vektor plus je ein Vektor pro `tbm1_reject_t`-Code.
Berührt     `test/vectors/tbm1/*.bin` + `*.json` (erwartetes Ergebnis).
Fertig wenn Jeder Reject-Code aus TBM1-R1 wird von genau einem Vektor ausgelöst; der Happy-Path
            besteht `tbm1_validate` + Signatur.
Hängt an    TBM1-R1

### TBM1-V2 — Geteilter Vektor-Test über Reader UND Encoder                     [M · 🟢]
Ziel        Reader (`boot_tbm1.c`) und Registry-Encoder testen gegen *dieselben* Vektoren →
            kein Drift zwischen Erzeuger und Leser.
Berührt     `test/host/tbm1_vectors.c`, Encoder-Testsuite (Registry-Repo).
Fertig wenn Beide Seiten grün gegen `test/vectors/tbm1/`; ein absichtlicher Encoder-Off-by-one in
            der Chunk-Hash-Länge wird von der Reader-Seite gefangen.
Hängt an    TBM1-V1, TBM1-R6

### TBM1-V3 — Fuzz-Harness für `tbm1_validate`                                  [M · 🟡]
Ziel        `tbm1_validate` gegen zufällige/mutierte Buffer — kein OOB-Read, kein Crash, immer
            ein definierter `tbm1_reject_t`.
Berührt     `test/fuzz/tbm1_fuzz.c` (libFuzzer/AFL), CI-Job.
Skizze
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < TBM1_FIXED_LEN) return 0;
  boot_device_ctx_t dev = { .product_id=1, .hw_rev=1, .keys=4 };
  (void)tbm1_validate(data, size, &dev);   /* darf nie abstürzen/OOB-lesen */
  return 0;
}
```
Fertig wenn ASAN-sauberer Fuzz-Lauf (≥1 h) ohne Findings; besonders die `total_len`-getriebene
            Grenze aus TBM1-R2 hält jedem Mutationsdruck stand.
Hängt an    TBM1-R6

---

## Abhängigkeit zum Eltern-Backlog

Dieser Block ersetzt den Platzhalter **K2-T3** durch R1–R6+V1–V3 und ergänzt **K2-T1** um H1–H4.
`tbm1_precheck` braucht `boot_crc32` aus **E0-T1**. Der Fuzz-/Vektor-Block (V) läuft im Host-Build,
der bereits durch **E-K5** (Record/Replay-Naht) etabliert ist — die Vektoren können denselben
Host-Harness nutzen.

## Definition of Done (Epic)

- `stage_parse` benutzt kein Manifest-Feld, bevor `tbm1_validate` bestanden **und** die Ed25519-
  Signatur über `tbm1_signed_len` verifiziert ist.
- Jeder `tbm1_reject_t`-Code hat einen Golden Vector; Reader und Encoder testen gegen denselben Satz.
- Fuzzer läuft ASAN-sauber; die angreiferkontrollierte `total_len`-Grenze ist bewiesen dicht.
- Header-Spec ist widerspruchsfrei (Reserved-Toleranz, bounds-prüfendes `tbm1_signed_len`,
  dokumentierte harte Maxima).