# libtoob — Refactor-Backlog

Ziel: die in der Architektur-Review gefundenen Probleme beheben und libtoob **kleiner und
einfacher handhabbar** machen — ohne Funktionsverlust. Sprache bleibt C (Begründung im Decision
Record unten).

Kernbewegung: libtoob hört auf, die WAL mitzubesitzen. Der OS↔Bootloader-Kontrakt wird eine
**Single-Record-Mailbox** statt eines geteilten Append-Logs. Geteilte Primitiven wandern in *eine*
Definition. Die API verliert ihre Redundanzvarianten.

**Ticket-Schema** — ID · Ziel · Berührt · Skizze · Fertig-wenn · Hängt-an.
**Aufwand** S ≤0,5 T · M 1–2 T · L 3–5 T. **Risiko** 🟢 mechanisch · 🟡 Sicherheits-/ABI-Pfad · 🔴 Kontrakt-/Migrations-Entscheidung.

---

## Decision Record: warum C, nicht Rust

Geprüft und verworfen für die **MCU-seitige** libtoob:

- **Async trägt nicht.** libtoob besitzt das Networking nicht (Stream-Writer, bekommt Chunks
  gereicht), die Flash-Seite ist synchron, und als eingebundene Bibliothek ist libtoob Gast in der
  Runtime der App — Async-Executoren (tokio/embassy) wollen die Event-Loop besitzen.
- **Memory-Safety real, aber gedämpft.** Die eigentliche Verifikation macht der C-Core; ein
  libtoob-Buffer-Bug ist DoS, kein Integritäts-Bypass.
- **Entscheidend:** Das zu lösende Problem *ist* ABI-Duplikation an der OS↔Bootloader-Naht. Eine
  zweite Sprache an dieser Naht verschärft ABI-Drift (Structs in C *und* Rust) oder erzwingt
  bindgen-Codegen. Der Core ist und bleibt C.
- **Opportunitätskosten:** C-Refactor ~1–2 Wochen (begrenzt) vs. Rust-Rewrite ~Monate (Toolchain,
  Dual-ABI, no_std, Re-Verifikation).

**Wann Rust wieder auf den Tisch kommt:** eine *host-seitige* Komponente (Linux-Fleet-Agent /
Referenz-Update-Client). Dort greifen std, echtes Async und Safety-auf-Untrusted-Input, ohne
geteilte MCU-ABI und ohne Runtime-Gast-Problem. Dann sofort empfehlenswert — nicht hier.

---

# L0 — Geteilte Wire/ABI-Fundamente

Zuerst, weil die Mailbox und alles Weitere darauf aufsetzen. Rein mechanisch, risikoarm.

### L0-T1 — `toob_wal_wire.h`: eine Definition der WAL-Entry-ABI              [M · 🟡]
Ziel        Der Handspiegel `toob_wal_entry_payload_t` (libtoob) und `wal_entry_payload_t` (Core)
            werden *eine* Definition, die beide einbinden. Der fragile
            `_Static_assert(...==64)`-Mirror entfällt — er fängt Größen-, aber nicht
            Feld-Layout-Drift.
Berührt     neu `common/include/toob_wal_wire.h`; `libtoob_types.h`, `boot_journal.h` binden ihn ein.
Skizze
```c
/* toob_wal_wire.h — geteilt von Core und libtoob. Die EINE Wahrheit der Entry-ABI. */
typedef struct __attribute__((packed)) {
  uint32_t magic;          /* TOOB_WAL_ENTRY_MAGIC */
  uint16_t intent;
  uint16_t _rsvd;
  uint32_t offset;         /* z. B. TBM1-Flash-Adresse bei UPDATE_PENDING */
  /* … exakt die Felder, die der Core heute definiert … */
  uint32_t crc32_trailer;
} wal_entry_payload_t;
_Static_assert(sizeof(wal_entry_payload_t) == 64, "WAL entry ABI drift");
```
Fertig wenn Beide Seiten kompilieren gegen denselben Header; libtoobs Kopie ist gelöscht; ein
            Feld-Umsortieren in der einen Quelle bricht sofort beide Builds.
Hängt an    —

### L0-T2 — Geteiltes CRC-32                                                  [S · 🟢]
Ziel        `toob_crc32.c` und `boot_crc32.c` (gleiches Polynom) werden eine Implementierung.
Berührt     neu `common/crc32.[ch]`; beide Seiten linken sie; `toob_crc32.c` gelöscht.
Fertig wenn `grep -rl 0xEDB88320 sdk/ toobloader/` zeigt genau eine Quelle.
Hängt an    —

### L0-T3 — Geteiltes `secure_zeroize`                                        [S · 🟢]
Ziel        Eine `secure_zeroize`-Definition statt je einer pro Welt.
Berührt     `common/secure_zeroize.[ch]`; libtoob + Core linken sie.
Fertig wenn Eine Quelle; Verhalten unverändert (Compiler-Barrier bleibt).
Hängt an    —

### L0-T4 — Encoding & Kommentar-Hygiene                                      [S · 🟢]
Ziel        Quelldateien sauber UTF-8 (aktuell Mojibake: `Ã¼`, `ÃœberlÃ¤ufen`); die
            „Mathematical Perfection Revision"-Bannerkommentare auf sachliche Modul-Header kürzen.
Berührt     alle `sdk/libtoob/*.c`.
Fertig wenn `file sdk/libtoob/*.c` meldet UTF-8; Banner sind einzeilige Zweckbeschreibungen.
Hängt an    —

---

# L1 — Mailbox-Kontrakt (die architektonische Kernänderung)

libtoob besitzt die WAL nicht mehr. Ein einzelner Record-Slot ersetzt den geteilten Append-Log.

**Warum die Mailbox simpel sein darf:** Die OS-Seite ist *retry-fähig*. Verliert ein Crash die
halb geschriebene Mailbox (Bad-CRC → ignoriert), ruft die App `toob_set_next_update` einfach
erneut. Der Bootloader dagegen kann nicht retryen — deshalb braucht *seine* WAL Torn-Write-Schutz,
TMR und Ketten, die Mailbox aber nicht. Genau diese Asymmetrie rechtfertigt die Vereinfachung.

### L1-T1 — Mailbox-Record-Format                                            [M · 🔴]
Ziel        Ein festes Single-Record-Format in einer dedizierten Flash-Region.
Berührt     neu `common/include/toob_mailbox.h`; Chip-Konstante `CHIP_MAILBOX_ADDR`/`_SIZE`.
Skizze
```c
typedef enum {
  TOOB_REQ_NONE = 0,
  TOOB_REQ_UPDATE_PENDING,   /* -> tbm1_addr */
  TOOB_REQ_CONFIRM,
  TOOB_REQ_RECOVERY_RESOLVED,
} toob_req_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;        /* 'TMBX' */
  uint16_t version;      /* 1 */
  uint16_t request;      /* toob_req_t */
  uint32_t seq;          /* monoton; Core merkt sich zuletzt konsumierte seq */
  uint32_t tbm1_addr;    /* nur UPDATE_PENDING */
  uint8_t  reserved[10];
  uint32_t crc32;        /* über [0 .. offsetof(crc32)) */
} toob_mailbox_t;        /* 32 Bytes */
```
            `seq` erlaubt dem Core, eine frische Anfrage von einer bereits konsumierten zu
            unterscheiden. Torn-Write-sicher per **Double-Slot**: zwei Records, in den inaktiven
            schreiben, höhere `seq` gewinnt (2-fach-Max statt Frontier-Scan).
Fertig wenn Format spezifiziert; `docs/mailbox_format.md`; Golden-Record-Testvektoren.
Hängt an    L0-T2

### L1-T2 — libtoob-Mailbox-Writer (ersetzt `toob_wal_naive.c`)              [M · 🟡]
Ziel        `toob_set_next_update`, `toob_confirm_boot`, `toob_recovery_resolved` schreiben einen
            Mailbox-Record statt einen WAL-Eintrag. Sequenzarithmetik, Frontier-Scan,
            Torn-Write-Logik verschwinden aus libtoob.
Berührt     neu `sdk/libtoob/toob_mailbox.c`; `toob_update.c`, `toob_confirm.c`; **löscht**
            `toob_wal_naive.c` (~279 Zeilen).
Skizze
```c
static toob_status_t mailbox_put(toob_req_t req, uint32_t tbm1_addr) {
  toob_mailbox_t cur; uint32_t next_seq = read_active_seq() + 1;
  uint32_t slot = inactive_slot();          /* Double-Slot */
  toob_mailbox_t m = {0};
  m.magic = TOOB_MAILBOX_MAGIC; m.version = 1;
  m.request = (uint16_t)req; m.seq = next_seq; m.tbm1_addr = tbm1_addr;
  m.crc32 = toob_crc32((const uint8_t*)&m, offsetof(toob_mailbox_t, crc32));
  return flash_write_verify(CHIP_MAILBOX_ADDR + slot*sizeof(m), &m, sizeof(m));
}
```
Fertig wenn libtoob enthält keinen Frontier-Scan / keine RFC-1982-Arithmetik mehr; `toob_wal_naive.c`
            ist gelöscht; Netto-Zeilendiff stark negativ.
Hängt an    L1-T1, L0-T3

### L1-T3 — Core-seitiges Fold-in                                            [L · 🔴]
Ziel        Der Bootloader liest beim Boot die Mailbox, validiert (Magic/CRC/seq > zuletzt
            konsumiert) und faltet eine gültige Anfrage in seine **eigene reiche WAL** (mit
            TMR/Kette nach Bedarf), dann merkt er sich die konsumierte `seq`.
Berührt     `boot_state.c` (früher Boot-Schritt), `boot_journal.c` (Intent-Append).
Skizze
```c
/* Vor der Update-Pipeline: OS-Anfragen einsammeln. */
toob_mailbox_t mb;
if (mailbox_read_valid(platform, &mb) && mb.seq > last_consumed_seq(&current_tmr)) {
  switch (mb.request) {
    case TOOB_REQ_UPDATE_PENDING:
      boot_journal_append_update_pending(platform, mb.tbm1_addr); break;
    case TOOB_REQ_CONFIRM:
      /* Core schreibt den (ggf. ketten-getaggten) CONFIRM-Eintrag SELBST */
      boot_journal_append_confirm(platform); break;
    /* … */
  }
  record_consumed_seq(&current_tmr, mb.seq);
}
```
            Löst das K4-Problem strukturell: der geräte­gebunden **ketten-getaggte** CONFIRM wird
            vom Core geschrieben, der den Schlüssel hat — nicht mehr von libtoob.
Fertig wenn Ein via Mailbox gesetztes UPDATE_PENDING/CONFIRM landet korrekt in der Core-WAL; der
            K5-Enumerator (Stromausfall an jeder Schreibgrenze) läuft grün über den Fold-in-Pfad.
Hängt an    L1-T2

### L1-T4 — Migration / Koexistenz                                          [M · 🔴]
Ziel        In-Flight-Geräte, die noch libtoob-WAL-Einträge geschrieben haben, dürfen beim Update
            auf den Mailbox-Build nicht bricken.
Berührt     `boot_state.c`.
Skizze      Für ein Release liest der Core **beides** — alte libtoob-WAL-Einträge *und* die neue
            Mailbox — und bevorzugt die Mailbox. Nach der Flotten-Migration fällt der Alt-Lesepfad
            weg (eigenes späteres Ticket).
Fertig wenn Ein Gerät mit altem WAL-Eintrag bootet unter dem neuen Core korrekt; Dual-Read
            dokumentiert mit klarem Sunset-Kriterium.
Hängt an    L1-T3

---

# L2 — API-Oberfläche verschlanken

### L2-T1 — verified/unverified-Varianten zusammenlegen                     [S · 🟢]
Ziel        `ota_begin` + `ota_begin_verified` → eine Funktion mit optionalem
            `expected_sha256` (NULL = unverified). Analog `ota_resume`. Vier Symbole → zwei.
Berührt     `libtoob.h`, `toob_ota.c`.
Skizze
```c
toob_status_t toob_ota_begin(toob_ota_ctx_t *ctx, uint32_t total_size,
                             const uint8_t expected_sha256[32] /* nullable */);
```
Fertig wenn Alte Symbole als dünne Deprecation-Wrapper oder entfernt; Doku aktualisiert.
Hängt an    —

### L2-T2 — Port-HAL abtrennen                                              [S · 🟢]
Ziel        `toob_os_flash_read/write/erase` (die Portierungsschicht) wandern in `toob_port.h`,
            getrennt von der aufrufbaren API.
Berührt     neu `sdk/libtoob/include/toob_port.h`; `libtoob.h`.
Fertig wenn Ein Integrator sieht die 3–4 zu implementierenden Hooks getrennt von den ~15
            Aufruf-Funktionen.
Hängt an    —

### L2-T3 — `_flush_buffer` Read-Back-Gap schließen                         [M · 🟡]
Ziel        Der Stream-Writer verifiziert Flash nach dem Schreiben (Read-Back), statt blind zu
            schreiben — die eine Stelle, an der ein stiller Flash-Fehler durchrutscht.
Berührt     `toob_ota.c` (`_flush_buffer`).
Fertig wenn Nach jedem `_flush_buffer` wird der geschriebene Bereich zurückgelesen und verglichen;
            ein injizierter Flash-Fehler wird gefangen (Host-Test).
Hängt an    —

---

# L3 — Diagnose vervollständigen

### L3-T1 — `diag_t` mit dem Telemetrie-CDDL abgleichen                     [M · 🟡]
Ziel        Die vier `TODO(TELEMETRY-SPEC)` in `toob_diag.c` schließen: `hardware_fault_record`
            und A/B-Bank-Tracking, die im CDDL-Schema existieren, aber nicht im C-`diag_t`.
Berührt     `toob_diag.c`, `libtoob_types.h`, `toob_telemetry.cddl`.
Fertig wenn C-Struct und CDDL sind deckungsgleich; keine TODO(TELEMETRY-SPEC) mehr offen.
Hängt an    —

### L3-T2 — Telemetrie-Codec-Round-Trip                                     [S · 🟢]
Ziel        Nach L3-T1 die zcbor-Decoder/Encoder regenerieren und Round-Trip prüfen
            (C-Struct → CBOR → C-Struct identisch).
Berührt     Codegen (`generator.go`), Host-Test.
Fertig wenn Round-Trip-Test grün.
Hängt an    L3-T1

---

## Reihenfolge

1. **L0** komplett — geteilte Header/Primitiven, Encoding. Mechanisch, macht den Rest sauber.
2. **L1-T1** (Mailbox-Format) — die eine 🔴-Design-Entscheidung; alles Weitere hängt daran.
3. **L1-T2** (libtoob-Writer) + **L1-T3** (Core-Fold-in) — das Herzstück; gegen den K5-Enumerator.
4. **L1-T4** (Migration) — bevor der Mailbox-Build eine Flotte erreicht.
5. **L2** parallel jederzeit — reine API-Kosmetik, außer L2-T3 (Read-Back, 🟡).
6. **L3** unabhängig — Diagnose-Vervollständigung.

## Ergebnis nach dem Refactor

libtoob ist im Kern: ein **Stream-Writer** (Staging), ein **Mailbox-Writer** (~40 Zeilen statt
~279), ein **Handoff-Reader**, plus Cloud-Submit und Diagnose. Einseitig gekoppelt, kein geteilter
Log, keine duplizierten Primitiven, keine ABI-Handspiegel. Der Core bleibt alleiniger Herr der WAL.
Messgröße: `sdk/libtoob`-Zeilenzahl deutlich gesunken, und `grep -rc "sequence\|frontier\|torn"
sdk/libtoob/` geht gegen null.