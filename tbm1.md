# TBM1 v2 — Praktisches Format-Redesign

Fokus: Benutzbarkeit, Erweiterbarkeit, Werkzeuge, Flash-Freundlichkeit, Diagnose, Betrieb.
Sicherheit ist hier bewusst **nicht** Thema — die Signatur-Umfang-Frage aus der Format-Review ist
separat und orthogonal zu allem hier. Dieser Entwurf feedet Ticket **K2-T1** (TBM1-Spezifikation).

Leitprinzip: **Jetzt ist das einzige Fenster für brechende Änderungen.** Bevor Geräte im Feld TBM1
lesen, kostet ein Layout-Umbau nichts. Danach ist jede Nicht-additive Änderung ein
Flotten-Migrationsprojekt. Also: alle brechenden Verbesserungen *einmalig* bündeln, danach nur noch
additiv wachsen. Dieser Entwurf ist dieses eine Bündel.

---

## 1. Die zwei strukturellen Weichenstellungen

### 1.1 Region-Directory statt verstreuter Offset/Längen-Paare

Heute sind sieben Offset/Längen-Bezüge über den Header verteilt, und sie sind uneinheitlich:
`chunk_hash` hat Offset **und** Länge, `device_bind` nur Offset mit impliziten 32 Bytes, PQC-Sig
und PQC-Key je ein eigenes Paar. Jeder Bezug braucht seine eigene Bounds-Prüfung im Reader — sieben
Sonderfälle.

Ein **Directory** aus gleichförmigen Einträgen ersetzt das durch *eine* Validierungsschleife:

```c
typedef struct __attribute__((packed)) {
  uint16_t region_id;   /* REGION_CHUNK_HASHES, REGION_PQC_PUBKEY, … 0 = leerer Slot */
  uint16_t _rsvd;       /* muss 0 sein */
  uint32_t off;         /* relativ zu TBM1-Start, 0 = nicht vorhanden */
  uint32_t len;         /* Byte-Länge */
} tbm1_region_t;        /* 12 Bytes */

enum {
  REGION_NONE          = 0,
  REGION_CHUNK_HASHES  = 1,
  REGION_PQC_SIGNATURE = 2,
  REGION_PQC_PUBKEY    = 3,
  REGION_DEVICE_BIND   = 4,
  REGION_DELTA_SCRIPT  = 5,  /* Platz für spätere Delta-Metadaten */
  /* 6..127 reserviert, 128..255 vendor */
};
```

Gewinn:
- **Ein Validierungs-Loop** prüft alle Regionen: `off <= total_len && len <= total_len - off`
  (überlaufsicher, siehe §3), plus kanonische Regel „aufsteigend sortiert, nicht überlappend".
- **Neue Regionstypen ohne Layout-Bruch** — einfach neue `region_id`, kein Struct-Umbau.
- Der Reader wird kleiner und die Bounds-Logik existiert genau einmal.

Trade-off: minimal weniger selbstdokumentierend als benannte Felder (`pqc_pubkey_off`). Das fängt
das Codegen (§6) mit generierten Accessoren wieder auf: `tbm1_region(hdr, REGION_PQC_PUBKEY)`.

### 1.2 Signatur ans Ende, relativ zur Gesamtlänge

Statt die Signatur auf einen harten Offset *im* Header zu nageln, verankere sie als die **letzten
64 Bytes des Gesamtblocks**. Das entkoppelt die Signatur-Position von der Header-Größe und macht
den „signiere alles außer der Signatur"-Umfang trivial ausdrückbar: `[0 .. total_len - 64)`. Der
feste Header bleibt kompakt, und spätere Header-Wachstumsschübe verschieben die Signatur nicht
relativ zum Signatur-Umfang.

---

## 2. Wachstumsregeln (damit v2 die letzte brechende Version ist)

- **`version_major` / `version_minor` getrennt** (je `uint8`): Major-Bump = inkompatibel (alter
  Reader lehnt ab), Minor-Bump = rein additiv (alter Reader liest weiter, ignoriert Neues).
- **Zwei Flag-Wörter mit Kritikalität**: `flags_critical` (u16) und `flags_info` (u16). Ein Reader,
  der ein gesetztes Bit in `flags_critical` **nicht** kennt, muss ablehnen; unbekannte Bits in
  `flags_info` ignoriert er gefahrlos. Das ist der saubere „must-understand vs. may-ignore"-Split,
  den CBOR/COSE über Critical-Header-Parameter löst — hier als zwei Bitmasken.
- **Fester Header exakt 512 Bytes** mit großzügigem `_reserved_tail` (148 Bytes). Neue Skalarfelder
  wachsen in den Schwanz hinein, ohne irgendeinen Offset zu verschieben — additive Minor-Version.
- **`min_reader_major/minor`** (signiert, aber hier als Kompatibilitäts-Gate relevant): erzwingt,
  dass ein zu alter Bootloader ein zu neues Manifest ablehnt statt es falsch zu interpretieren.

---

## 3. Flash- & Reader-Praktikabilität

- **512 Bytes fester Header** = genau eine (oder zwei) Flash-Page(s) auf typischen MCUs, ein
  einziger `flash->read`, triviale Kopfrechnung. Der 252-Byte-Header von v1 war krumm (nicht
  8-aligned, passt in keine Page-Grenze).
- **`fixed_crc32` als letzte 4 Bytes des festen Headers** (kein Sicherheits-, ein
  *Praktikabilitäts*-Feature): Vor der teuren Ed25519-Prüfung — und bevor überhaupt die
  variablen Regionen gelesen werden — ein schneller CRC über `[0 .. 508)`. Fängt kaputte
  Staging-Writes sofort ab und liefert dem Bootloader eine saubere Fehlerklasse
  („Staging korrupt", nicht „Signatur ungültig"). Kostet ~µs, spart Diagnosezeit im Feld.
- **Überlaufsichere Bounds** als kanonische Reader-Regel: nie `off + len <= total_len` (u32-Wrap),
  immer `off <= total_len && len <= total_len - off`; Chunk-Rechnung in `size_t` mit Guard.
- **`total_len` als u32** statt `header_len` als u16 — hebt die 64-KB-Decke (v1 sprengte bei ~8-MB-
  Images allein an der rohen Hash-Liste). Und **umbenannt**: „header_len" beschrieb fälschlich den
  *gesamten* Block inklusive Trailing-Daten; `total_len` ist ehrlich.
- **Struct-Cast-Portabilität**: fester Header ist 512 Bytes, jeder Mehrbyte-Feld-Offset ist durch
  ein generiertes `_Static_assert` fixiert; Arena mit `_Alignas(4)`. Für strikt portablen Code auf
  M0/M0+ liefert das Codegen wahlweise `memcpy`-basierte Accessoren statt roher Dereferenzierung.

---

## 4. Inhaltliche Lücken schließen

### 4.1 Hardware- & Produktkompatibilität (die größte praktische Lücke)

v1 hat nichts, was verhindert, dass das Image der falschen Produktfamilie auf das falsche Gerät
geflasht wird. Das ist genau das, was MCUboot/SUIT über Vendor/Class-IDs lösen. Neu im festen
Header:

```c
  uint16_t vendor_id;     /* herstellergebunden */
  uint16_t product_id;    /* Produktfamilie */
  uint16_t hw_rev_min;    /* dieses Image läuft auf Revisionen [min..max] */
  uint16_t hw_rev_max;
```

Der Bootloader gated das Flashen: passt `product_id` nicht zur eFuse/Config-Identität oder liegt die
HW-Revision außerhalb `[min..max]` → sauberes Reject mit eigener Fehlerklasse, kein Brick durch
Fehlbespielung.

### 4.2 Explizites Daten-Layout im Staging (`data_off` pro Image)

v1 beschreibt die Images, sagt aber nicht, *wo* im Staging ihre Bytes liegen — der Bootloader muss
sequentielles Layout annehmen. Ein explizites `data_off` pro Descriptor entkoppelt das und erlaubt,
Image-Starts auf **Sektorgrenzen** zu legen — was der K3-Planner für erase-effizientes Kopieren
direkt ausnutzt.

### 4.3 `stored_size` vs. `installed_size`

Bei komprimierten und/oder Delta-Images sind zwei Größen nötig, die v1 vermischt: die im Staging
abgelegte Byte-Zahl (`stored_size`) und die nach Dekompression/Patch installierte
(`installed_size`). Der Bootloader braucht beide — die erste fürs Streamen aus dem Staging, die
zweite fürs Bounds-Checking des Zielslots.

### 4.4 Kompression/Delta als Enum statt `bool`

`is_compressed`/`is_delta` als Bool ist zu starr und nicht versionierbar. Enums halten es
erweiterbar:

```c
enum { COMP_NONE = 0, COMP_HEATSHRINK = 1, COMP_LZ4 = 2 /* … */ };
enum { DELTA_NONE = 0, DELTA_BSDIFF = 1, DELTA_DETOOLS = 2 /* … */ };
```

### 4.5 Delta-Basis: nicht nur Fingerprint, auch Version

v1 hat `base_fingerprint[8]` (welches Basis-Image der Patch erwartet). Praktisch fehlt die
**Basis-SVN** (`base_svn`): Der Bootloader kann so *vor* dem teuren Patch-Versuch prüfen, ob die
installierte Basis überhaupt die richtige Version ist, statt erst am Fingerprint-Mismatch zu
scheitern.

### 4.6 Semantische Version + Build-Nummer (Telemetrie/Registry)

Für gerätе­seitiges Reporting gegen die Registry-Version-Oracle: `fw_ver_major/minor/patch`
(3× u16) plus `build_number` (u32). Das schließt die Diagnose-Lücke aus dem `toob_diag`-Backlog
(dort standen mehrere `TODO(TELEMETRY-SPEC)` genau zu solchen Feldern) und macht „welche Version
läuft auf welchem Gerät" ohne Umweg beantwortbar.

### 4.7 `manifest_id` als berechneter Selbst-Identifikator

Nicht speichern — **berechnen**: die ersten 8–16 Bytes von SHA-256 über den gesamten
TBM1-Block. Dient als stabile ID in Logs, Telemetrie und Registry-Korrelation und als natürlicher
Dedup-Schlüssel. Der Reader kann ihn on-the-fly aus dem ohnehin gehashten Block ableiten.

### 4.8 Klare Benennungen & Wertebereiche

- `max_resume` → **`boot_retry_limit`** mit dokumentierter Semantik (was genau zählt es).
- `image_type`: Bereiche reservieren — `0..127` Standard, `128..255` Vendor.
- `target_slot` pro Image explizit (statt allein aus Chip-Config abzuleiten) für Multi-Image.
- Alle `_reserved`/`_pad`: dokumentiert „muss 0 sein, vom Reader geprüft".

### 4.9 Magic ehrlich machen

v1 nennt das Format „TBM1", aber die Magic-Bytes buchstabieren „TOOB". Ein `hexdump` oder
`file`-Kommando erkennt das Format dann nicht wieder. Magic so wählen, dass sie „TBM1" (oder eine
klar zugeordnete Konstante) buchstabiert, und eine `magic(5)`-Signatur registrieren — Kleinkram,
aber genau die Art Reibung, die Werkzeug-Ergonomie ausmacht.

---

## 5. Konkreter v2-Layout-Vorschlag (verifiziert: 512 Bytes, alle Felder aligned)

> Als **Vorschlag** zu lesen, nicht als Gesetz — die Feldauswahl ist begründet, die exakten Offsets
> sind eine von mehreren gültigen Anordnungen. Layout ist gegengeprüft: fester Block = exakt 512 B,
> jedes Mehrbyte-Feld natürlich ausgerichtet, 148 B reservierter Schwanz.

```c
typedef struct __attribute__((packed)) {         /* 44 Bytes, wiederholt 4× */
  uint8_t  image_type;        /* 0..127 std, 128..255 vendor */
  uint8_t  target_slot;       /* Zielregion im Multi-Image-Layout */
  uint8_t  compression_alg;   /* COMP_* */
  uint8_t  delta_alg;         /* DELTA_* */
  uint32_t data_off;          /* Offset der Image-Bytes im Staging (§4.2) */
  uint32_t stored_size;       /* Bytes im Staging (§4.3) */
  uint32_t installed_size;    /* Bytes nach Dekomp/Patch */
  uint32_t chunk_size;
  uint32_t num_chunks;
  uint32_t base_svn;          /* Delta: erwartete Basis-Version (§4.5) */
  uint16_t ver_major, ver_minor, ver_patch, _rsvd;
  uint8_t  base_fingerprint[8];
} tbm1_image_desc_v2_t;

typedef struct __attribute__((packed)) {         /* fester Block = 512 Bytes */
  uint32_t magic;                 /* buchstabiert die Format-ID (§4.9) */
  uint8_t  version_major;         /* brechend */
  uint8_t  version_minor;         /* additiv */
  uint16_t fixed_len;             /* == 512 */
  uint32_t total_len;             /* fest + variabel + Signatur (§3) */
  uint16_t flags_critical;        /* unbekanntes Bit → reject */
  uint16_t flags_info;            /* unbekanntes Bit → ignorieren */

  uint16_t vendor_id, product_id; /* §4.1 */
  uint16_t hw_rev_min, hw_rev_max;

  uint8_t  key_index;
  uint8_t  image_count;           /* 1..4, vom Reader erzwungen */
  uint16_t boot_retry_limit;      /* ex-max_resume (§4.8) */
  uint16_t min_reader_major, min_reader_minor;

  uint32_t svn, stage1_svn, key_epoch, build_number;
  uint16_t fw_ver_major, fw_ver_minor, fw_ver_patch, _rsvd0;
  uint8_t  sbom_digest[32];       /* CRA-SBOM */

  tbm1_region_t        regions[8];   /* Directory (§1.1), je 12 B → 96 B */
  tbm1_image_desc_v2_t images[4];    /* je 44 B → 176 B */

  uint8_t  _reserved_tail[148];   /* additives Wachstum, muss 0 sein */
  uint32_t fixed_crc32;           /* schneller Pre-Check über [0..508) (§3) */
} tbm1_fixed_v2_t;

_Static_assert(sizeof(tbm1_image_desc_v2_t) == 44, "desc drift");
_Static_assert(sizeof(tbm1_region_t)        == 12, "region drift");
_Static_assert(sizeof(tbm1_fixed_v2_t)      == 512, "fixed header must be one page");
_Static_assert(offsetof(tbm1_fixed_v2_t, regions) == 88,  "region dir offset drift");
_Static_assert(offsetof(tbm1_fixed_v2_t, images)  == 184, "image desc offset drift");
_Static_assert(offsetof(tbm1_fixed_v2_t, fixed_crc32) == 508, "crc must be last word");
/* … je Feld ein offsetof-Assert (vom Codegen erzeugt) … */
```

Die Ed25519-Signatur bleibt die letzten 64 Bytes des Gesamtblocks (§1.2); Layout im Staging:
`[fester Header 512][variable Regionen…][Signatur 64]`, Image-Bytes bei `data_off`
(sektorausgerichtet).

---

## 6. Werkzeuge & Reproduzierbarkeit (der eigentliche „für die Allgemeinheit nutzbar"-Teil)

Ein Format ist nur so gut wie seine Werkzeugkette. Das Muster, das Drift verhindert:

- **Schema einmal, maschinenlesbar.** Das Layout in *einer* Quelle definieren (z. B. eine kleine
  Schema-Datei), aus der generiert wird: der C-Header mit allen `_Static_assert`s, der Rust- und
  Go-Encoder für die Registry, das Python-Tooling, der Fuzz-Harness. So können Manifest-Compiler und
  Core-Reader nicht auseinanderlaufen. (Eure Codegen-Kultur ist ohnehin stark — das ist die
  natürliche Erweiterung.)
- **`tbm1 dump`-CLI.** Ein Kommando, das einen Block menschenlesbar ausgibt (Felder, Directory,
  Descriptors, berechnete `manifest_id`). In CI genutzt, um Images zu diffen und
  Layout-Regressionen sichtbar zu machen.
- **Golden Vectors im Repo.** Kanonische Beispiele plus je ein Vektor pro Fehlerklasse
  (BAD_MAGIC, BAD_VERSION, BAD_BOUNDS, BAD_CONSISTENCY, BAD_CRC). Alle Implementierungen
  (Reader, Encoder, Tooling) testen gegen dieselben Vektoren.
- **Explizite Fehler-Taxonomie.** Statt alles auf `BOOT_ERR_INVALID_ARG` zu kollabieren, distinkte
  Reject-Codes — dann kann Feld-Telemetrie „Staging korrupt" von „falsches Produkt" von „zu alter
  Bootloader" unterscheiden, ohne dass jemand ein Gerät einschickt.

---

## 7. Bewusst *nicht* geändert (Begründung)

- **Feste 4 Image-Slots** (3 leer im Single-Image-Fall = 132 B „verschwendet"): Der feste Offset
  ist mehr wert als die paar Bytes. Bleibt.
- **`image_size`/`num_chunks`/`chunk_size` teils redundant**: bewusst *behalten* — der Reader
  erzwingt Konsistenz (`num_chunks == ceil(installed_size/chunk_size)`) als billige Kreuzprüfung
  gegen kaputte Encoder. Dokumentieren, welches Feld autoritativ ist.
- **Little-Endian fest**: korrekt für ARM; alle Cortex-M sind LE. Das Codegen kapselt Byte-Swaps,
  falls je ein BE-Ziel dazukommt.
- **`image_size` als u32** (4-GB-Decke): für MCU-Images auf absehbare Zeit irrelevant. Kein u64.

---

## Migrations-Notiz

Weil v2 brechend ist, gehört es *vor* den ersten Feldeinsatz von TBM1 — idealerweise fällt es mit
K2-T2 (Encoder) und K2-T3 (Reader) zusammen, sodass nie ein v1-Reader ausgeliefert wird. Ab v2 ist
Wachstum ausschließlich additiv: neue Skalare in den `_reserved_tail`, neue variable Daten als neue
`region_id`, neue Fähigkeiten über `flags_info` (unkritisch) bzw. `flags_critical` (mit
`min_reader_*`-Gate). Damit ist v2 die letzte Version, die je einen Flotten-Umstieg erzwingt.