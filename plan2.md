# Backlog — `libtoob` Härtung, Resync & DX

**Scope:** Diese Liste deckt ausschließlich `sdk/libtoob/` ab, plus eine klar markierte angrenzende Epic für `sdk/os_client/`. Der Bootloader-Core (`toobloader/`) wird **nicht** umgebaut — er ist hier die *Source of Truth*. Jeder Ticket-Auftrag bringt `libtoob` an den bereits refaktorierten Core heran, härtet die OS-Boundary und verbessert die Developer Experience für integrierende Feature-OS-Teams.

**Leitprinzip:** `libtoob` trägt fast keine fault-injection-kritische Logik — es macht CRC-gated Byte-Kopien, WAL-Appends und Flash-Streaming. Die Härtung sitzt im Core. Deshalb zielen diese Tickets auf **Korrektheit an der Grenze**, **ABI-Integrität** und **Missbrauchssicherheit der API**, nicht auf neue Glitch-Shields.

---

## Legende & Konventionen

**Priorität**
- **P0** — Korrektheits-Regression aus dem Core-Refactoring oder sicherheitsrelevant. Zuerst.
- **P1** — Wichtig: latenter Bug, ABI-Risiko oder DX-Falle mit realer Crash-/Bypass-Konsequenz.
- **P2** — Robustheit / DX-Verbesserung mit mittelbarem Nutzen.
- **P3** — Code-Hygiene, Doku, Portabilität.

**Typ:** `bug` · `refactor` · `dx` · `abi` · `security` · `cleanup` · `spike`

**Aufwand (T-Shirt):** S (≤ ½ Tag) · M (1–2 Tage) · L (> 2 Tage / koordiniert)

**Definition of Done (global, gilt für jedes Ticket):**
1. Code-Änderung + alle bestehenden `_Static_assert`s kompilieren grün.
2. Sandbox-/Host-Build (`host` Arch) und mindestens ein RTOS-Target-Build (Zephyr **oder** ESP-IDF) brechen nicht.
3. Bei Verhaltensänderung: ein gezielter Test (Host-Mock oder Fuzzer-Vektor) deckt das alte Fehlverhalten ab.
4. Betroffene Doxygen-Kommentare in `libtoob.h` / `libtoob_types.h` aktualisiert.
5. Cross-Referenz im Core dokumentiert, falls ein Core-Folgeticket nötig ist (Core wird **nicht** in diesem Backlog umgesetzt).

---

## Ticket-Übersicht

| ID | Titel | Prio | Typ | Aufwand |
|---|---|---|---|---|
| LIBTOOB-001 | `CLOUD_CMD`-WAL-Append entfernen (vestigial + Fehlattribution) | P0 | bug/security | S |
| LIBTOOB-002 | RTC/WAL Confirm-Backend-Kohärenz (P7b) auflösen | P2 | bug/abi | M |
| LIBTOOB-003 | `REQUIRES_RESET` / `WAL_FULL` / `WAL_LOCKED` als dokumentierte Kontrakte | P1 | dx | S |
| LIBTOOB-010 | Single-Source `toob_handoff_t` / `toob_boot_diag_t` + Cross-Assert | P1 | abi | M |
| LIBTOOB-011 | CRC32-Äquivalenz Core↔libtoob per CI-Test absichern | P1 | abi/security | S |
| LIBTOOB-012 | Handoff hinter validierenden Accessor / opaken Handle | P2 | dx | M |
| LIBTOOB-020 | Verified-Resume-Bug: SHA-Kontext beim Resume korrekt behandeln | P1 | bug/security | M |
| LIBTOOB-021 | OTA-State aus File-Globals in übergebenen `toob_ota_ctx_t` | P2 | refactor/dx | L |
| LIBTOOB-022 | `WAL_LOCKED` beim Finalize sauber surface-n (Doppel-Update-Schutz) | P2 | dx | S |
| LIBTOOB-023 | Read-Back pro Flush im OTA-Schreibpfad (SRAM→Flash-Lücke) | P2 | bug/security | S |
| LIBTOOB-030 | `warn_unused_result` auf alle `toob_status_t`-Funktionen | P1 | dx/security | S |
| LIBTOOB-031 | Phantom-Parameter `image_type` klären/entfernen | P2 | dx | S |
| LIBTOOB-032 | `TOOB_OS_INIT_OR_PANIC()` Hänge-Semantik dokumentieren/absichern | P2 | dx | S |
| LIBTOOB-033 | Status-Logging-Format portabel machen | P3 | cleanup | S |
| LIBTOOB-040 | Dedup: `toob_ota_secure_zeroize` / `TOOB_OTA_GLITCH_DELAY` | P3 | cleanup | S |
| LIBTOOB-041 | Doppelte `toob_get_boot_diag`-Deklaration in `libtoob.h` bereinigen | P3 | cleanup | S |
| LIBTOOB-042 | CBOR-Telemetrie-Mapping-Hacks dokumentieren/auflösen | P3 | cleanup | S |
| LIBTOOB-050 | `os_client` CBOR-Manifest-Parser auditieren/härten (Rust-Kandidat) | P2 | security/spike | M |
| LIBTOOB-051 | Optionale Rust-Wrapper-Crate über C-`libtoob` (DX-Layer) | P3 | spike | L |

---

# EPIC A — Core-Resync

> Diese Tickets schließen die Lücken, die entstanden sind, weil der Core refaktoriert wurde, `libtoob` aber nicht nachgezogen hat.

---

### LIBTOOB-001 — `CLOUD_CMD`-WAL-Append entfernen
**Prio:** P0 · **Typ:** bug/security · **Aufwand:** S
**Datei:** `sdk/libtoob/toob_cloud_submit.c`

**Problem**
`toob_submit_cloud_command()` schreibt nach dem erfolgreichen Envelope-Write einen `TOOB_WAL_INTENT_CLOUD_CMD` (Wert 12) ins WAL, um „den Bootloader zu benachrichtigen". Der refaktorierte Core liest den Cloud-Slot aber **bei jedem Boot bedingungslos** (`boot_state.c`, Step 2.5, `_handle_cloud_cmd` ist *slot-getrieben*, nicht *intent-getrieben*). Das Signal wird also nie konsumiert.

**Root Cause**
Step 2.5 wurde im Core auf „slot-driven" umgestellt; das Intent-Signal in `libtoob` blieb stehen. Schlimmer als nur tot: In `boot_journal_reconstruct_txn` fällt Intent 12 in **keinen** der Side-Band-Zweige (`NET_SEARCH_ACCUM`, `DOWNLOAD_CHECKPOINT`, `SLEEP_BACKOFF`, `DEPRECATED_NONCE`, `TXN_ROLLBACK_PENDING`) und landet im `else` → wird als **Haupt-Intent** (`open_txn`) selektiert. Bleibt dieser Intent nach einem `NOP`- oder `ROTATE_KEY`-Cloud-Command liegen (beide appenden im Core keinen Folge-Intent) und folgt ein WDT-/HardFault-Reset, wird in `boot_state.c` Step 3 `is_app_crash == true` (Intent ≠ `UPDATE_PENDING`, ≠ `TXN_BEGIN`) → `boot_failure_counter++`. Konsequenz: spurious Failure-Counting, das Richtung Recovery-OS-Boot oder (auf Edge-Geräten) 1-Stunden-Penalty-Sleep schiebt.

**Lösung**
1. Den kompletten „Step 4: WAL Signal"-Block aus `toob_submit_cloud_command()` entfernen (Erase → Write → CRC-Read-Back bleiben; das WAL-Signal entfällt ersatzlos).
2. Den Enum-Wert `TOOB_WAL_INTENT_CLOUD_CMD` in `libtoob_types.h` **behalten** (ABI-Konstante, der `_Static_assert` in `boot_journal.h` referenziert ihn) — nur die *Emission* entfällt.
3. Funktions-Doxygen anpassen: Sequenz ist jetzt „Guard → Erase → Write → CRC-Read-Back → Zeroize".

**Cross-Referenz (Core, separates Ticket, hier nur dokumentiert):** Defensiv sollte der Core `WAL_INTENT_CLOUD_CMD` zusätzlich in die Side-Band-Liste von `boot_journal_reconstruct_txn` aufnehmen — als Belt-and-Suspenders gegen Alt-Geräte, deren Flash noch einen 12er-Intent aus früheren `libtoob`-Versionen trägt.

**Akzeptanzkriterien**
- [ ] `toob_submit_cloud_command()` schreibt keinen WAL-Intent mehr.
- [ ] Host-Test: nach `submit_cloud_command` + simuliertem WDT-Reset bleibt `boot_failure_counter` unverändert (vorher: +1).
- [ ] Enum-Wert 12 bleibt definiert; `boot_journal.h`-Cross-Assert kompiliert.

---

### LIBTOOB-002 — RTC/WAL Confirm-Backend-Kohärenz (P7b)
**Prio:** P2 · **Typ:** bug/abi · **Aufwand:** M
**Datei:** `sdk/libtoob/toob_confirm.c`

**Problem**
Der Core hat die Crash-Detection auf „WAL-primary" umgestellt (Kommentar P7b: „WAL-Intent ist die Autorisierung, nicht der Reset-Reason"; ein un-aufgelöster `CONFIRM_COMMIT` ist das stärkste Crash-Signal, Brownout zählt nicht mehr als Crash). Im **RTC-Backend** (`#ifdef ADDR_CONFIRM_RTC_RAM`) schreibt `toob_confirm_boot()` jedoch **keinen** `CONFIRM_COMMIT`-Intent — nur die Nonce ins RTC-RAM. Die beiden Backends erzeugen damit unterschiedliche WAL-Historien.

**Root Cause**
Die P7b-Logik im Core ist um den WAL-Pfad herum geschrieben. Beim RTC-Pfad hängt die Bestätigung allein an `platform->confirm->check_ok(nonce)` (Step 2), während der WAL-Pfad zusätzlich am `CONFIRM_COMMIT`-Intent hängt. Happy Path funktioniert in beiden Fällen, aber ein OS-Integrator, der das Backend wechselt, ändert *implizit* das Crash-Detection-Verhalten des Bootloaders. Das ist eine versteckte Kopplung, kein eindeutiger Bug — aber ein Fußangel für Integratoren.

**Lösung (Variante A bevorzugt)**
- **A (Vereinheitlichung):** RTC-Pfad zusätzlich einen `CONFIRM_COMMIT`-Intent ins WAL appenden (idempotent, Fire-and-Forget), sodass beide Backends dieselbe WAL-Signatur erzeugen. Damit ist die Core-Crash-Detection backend-unabhängig.
- **B (Dokumentation, falls A zu invasiv):** Den Verhaltensunterschied explizit in `libtoob.h` über `toob_confirm_boot()` dokumentieren: „Bei RTC-Backend hängt die Bestätigung an der Confirm-HAL; bei WAL-Backend am `CONFIRM_COMMIT`-Intent. Beide sind äquivalent für den Standard-Lifecycle, divergieren aber im Crash-Attribution-Detail."

**Akzeptanzkriterien**
- [ ] Variante A: Host-Test zeigt, dass RTC- und WAL-Backend nach einem bestätigten Boot dieselbe WAL-Intent-Sequenz hinterlassen.
- [ ] Oder Variante B: Doku-PR mit explizitem Hinweis + Verweis auf P7b im Core.

---

### LIBTOOB-003 — `REQUIRES_RESET` / `WAL_FULL` / `WAL_LOCKED` als dokumentierte Kontrakte
**Prio:** P1 · **Typ:** dx · **Aufwand:** S
**Dateien:** `sdk/libtoob/include/libtoob.h`, `sdk/libtoob/toob_wal_naive.c`

**Problem**
`toob_wal_naive_append()` kann `TOOB_ERR_REQUIRES_RESET` (torn write entdeckt), `TOOB_ERR_WAL_FULL` (aktiver Sektor voll, keine Rotation OS-seitig) und `TOOB_ERR_WAL_LOCKED` (zweites `UPDATE_PENDING` blockiert) zurückgeben. Diese propagieren bis in `toob_confirm_boot()`, `toob_recovery_resolved()`, `toob_set_next_update()` etc. — Funktionen, deren Doxygen nur `TOOB_OK` / `TOOB_ERR_FLASH` als Rückgabe nennt. Ein OS-Entwickler behandelt diese Pfade fast garantiert nicht und gerät in stillen Lockout.

**Root Cause**
Bewusste Asymmetrie (OS darf nicht rotieren/heilen → muss rebooten, damit Stage 1 repariert), aber der „du musst rebooten"-Kontrakt ist nirgends an der API sichtbar.

**Lösung**
1. Doxygen jeder `toob_status_t`-Funktion, die `toob_wal_naive_append` aufruft, um die vollständige Liste möglicher Rückgaben + empfohlenes OS-Handling ergänzen: „`TOOB_ERR_REQUIRES_RESET` / `TOOB_ERR_WAL_FULL` ⇒ Reboot anstoßen, Stage 1 heilt/rotiert beim nächsten Boot."
2. Eine kompakte „Error-Handling-Matrix" als Abschnitt in `libtoob.h` (welcher Fehler ⇒ welche OS-Reaktion: retry / reboot / abort).
3. Optional: Convenience-Makro/-Helper `TOOB_IS_REBOOT_REQUIRED(status)`.

**Akzeptanzkriterien**
- [ ] Jede betroffene Funktion listet ihre realen Rückgabewerte im Doxygen.
- [ ] Error-Handling-Matrix im Header vorhanden.

---

# EPIC B — ABI-Integrität

> Die Grenze lebt von bit-exakten Typ-Layouts und CRC-Gleichheit zwischen zwei unabhängig kompilierten Binaries. Diese Tickets machen die stillschweigenden Annahmen compiler- bzw. CI-prüfbar.

---

### LIBTOOB-010 — Single-Source `toob_handoff_t` / `toob_boot_diag_t` + Cross-Assert
**Prio:** P1 · **Typ:** abi · **Aufwand:** M
**Dateien:** `sdk/libtoob/include/libtoob_types.h`, Core `boot_types.h` (Koordination), ggf. neues Test-TU

**Problem**
Für die WAL-Typen existieren in `boot_journal.h` Cross-Asserts (`_Static_assert(sizeof(wal_entry_payload_t) == sizeof(toob_wal_entry_payload_t), ...)` u.v.m.). Für `toob_handoff_t` und `toob_boot_diag_t` ist **kein** analoger Cross-Check sichtbar. `stage0` inkludiert `libtoob_types.h` direkt (gleiche Definition), aber Stage 1 (`boot_main.c`) schreibt den Handoff über die Core-eigene Definition. Driften beide (z.B. Feld eingefügt, Padding verschoben), bricht jede Handoff-Validierung **stillschweigend** — das Gefährlichste, was an dieser Grenze passieren kann.

**Root Cause**
Beide Binaries kompilieren nie zusammen, also kann ein klassischer `_Static_assert` die Definitionen nicht gegeneinander prüfen.

**Lösung (Variante 1 bevorzugt)**
- **1 (Single-Source):** Der Core inkludiert für den Handoff- und Diag-Typ `libtoob_types.h` als kanonische Quelle — exakt so, wie `boot_journal.h` es für die WAL-Typen bereits tut. Damit gibt es nur **eine** Definition; Drift wird strukturell unmöglich.
- **2 (Golden-Layout-Test, falls 1 nicht gewollt):** Dedizierte Test-TU, die beide Header über Namespacing/Makro-Renaming einbindet und `offsetof`/`sizeof` aller Felder vergleicht. Läuft in CI.

**Akzeptanzkriterien**
- [ ] Es existiert ein Mechanismus, der `sizeof` und alle relevanten `offsetof` von `toob_handoff_t` (80 B, `crc32_trailer`@76) und `toob_boot_diag_t` (88 B) Core↔libtoob garantiert.
- [ ] Ein absichtlich eingefügtes Test-Feld lässt den Build/CI rot werden.

---

### LIBTOOB-011 — CRC32-Äquivalenz Core↔libtoob per CI-Test
**Prio:** P1 · **Typ:** abi/security · **Aufwand:** S
**Dateien:** `sdk/libtoob/toob_crc32.c`, `toobloader/core/boot_crc32.c`, neuer CI-Test

**Problem**
Core nutzt eine table-less CRC32 (`compute_boot_crc32`), `libtoob` eine table-based (`toob_lib_crc32`). Beide **müssen** bit-identisch sein, sonst scheitert jede Handoff-/Diag-/WAL-Validierung über die Grenze. Garantiert wird das aktuell nur durch einen Testvektor im Kommentar (`"IEEE_802.3" -> 0xE0DFD6DA`), nicht durch einen ausgeführten Cross-Check.

**Root Cause**
„Zero-Dependency"-Philosophie verbietet das Teilen der Implementierung — aber die mathematische Äquivalenz wird nie maschinell verifiziert.

**Lösung**
1. CI-Test (Host-Build), der über eine Reihe von Vektoren (leer, 1 Byte, `"IEEE_802.3"`, ein voller `toob_handoff_t`-Dump, Zufalls-Buffer) `compute_boot_crc32` **und** `toob_lib_crc32` aufruft und auf Gleichheit prüft.
2. Den bestehenden Kommentar-Testvektor als ersten Test-Case übernehmen.

**Akzeptanzkriterien**
- [ ] CI-Test grün; ein absichtlich verfälschtes Tabellen-Wort lässt ihn rot werden.
- [ ] Mindestens 5 Vektoren inkl. eines echten Struct-Layouts.

---

### LIBTOOB-012 — Handoff hinter validierenden Accessor / opaken Handle
**Prio:** P2 · **Typ:** dx · **Aufwand:** M
**Dateien:** `sdk/libtoob/include/libtoob.h`, `sdk/libtoob/toob_handoff.c`

**Problem**
Aktuell ist `toob_handoff_state` als `extern` exponiert, die Validierung muss der OS-Entwickler aktiv via `toob_validate_handoff()` / `TOOB_OS_INIT_OR_PANIC()` anstoßen. Das defensive Pre-Zeroing in `toob_get_handoff()` existiert nur, *weil* das OS den rohen State direkt lesen oder den Return-Code ignorieren könnte. Die API lädt zum „erst lesen, hoffentlich vorher validieren" ein.

**Lösung**
- `toob_handoff_state` aus dem Header so weit wie möglich zurückziehen (intern bleibt es `extern` für die `.noinit`-Linkage, aber die öffentliche API führt nur noch über `toob_get_handoff()`).
- Optional: opakes Handle-Pattern — `toob_get_handoff()` als einziger legitimer Zugriffspfad, dokumentiert als „die einzige unterstützte Art, an Handoff-Daten zu kommen".
- `device_id`-Zugriff (`toob_get_device_id`) bereits korrekt über Handoff geroutet — als Referenz-Pattern dokumentieren.

**Akzeptanzkriterien**
- [ ] Öffentliche Header-Oberfläche bietet keinen empfohlenen Direktzugriff auf den rohen `.noinit`-State mehr.
- [ ] Doku nennt `toob_get_handoff()` explizit als einzigen unterstützten Pfad.

> **Abhängigkeit:** sinnvoll *nach* LIBTOOB-010 (Single-Source-Typ), damit der Handle denselben kanonischen Typ kapselt.

---

# EPIC C — OTA-Engine Robustheit

> Die fehleranfälligste Stelle der gesamten SDK. File-scoped State + fragiler Resume.

---

### LIBTOOB-020 — Verified-Resume-Bug: SHA-Kontext beim Resume korrekt behandeln
**Prio:** P1 · **Typ:** bug/security · **Aufwand:** M
**Dateien:** `sdk/libtoob/toob_ota.c`, `sdk/os_client/src/toob_network_client.c`

**Problem**
Ein **verifizierter, fortgesetzter** Download ist gebrochen. Zwei sich überlagernde Defekte:
1. In `toob_network_trigger_ota()`: bei erfolgreichem `toob_ota_resume()` wird `toob_ota_begin_verified()` **nicht** aufgerufen → `s_is_verified_stream` bleibt `false`, `s_expected_sha256` wird nie gesetzt → die End-to-End-SHA-Prüfung in `toob_ota_finalize()` wird **stillschweigend übersprungen**.
2. In `toob_ota_resume()`: selbst wenn man `s_is_verified_stream` setzen würde, wird der `s_sha_ctx` nicht rekonstruiert. Der bereits ins Staging geschriebene Präfix ist nicht im Hash-Zustand → Hash-Mismatch beim Finalize.

**Sicherheits-Einordnung:** Defense-in-Depth, **kein** Totalbypass — der Bootloader verifiziert post-Reboot Merkle + Ed25519 über das volle Image. Aber die `libtoob`-Ebene gibt ihre Stream-Verifikations-Garantie *still* auf. Ein Angreifer, der einen Download unterbricht und auf Resume korrupte Bytes einspeist, umgeht die libtoob-SHA. Das ist eine stille Garantie-Verletzung und gehört gefixt.

**Lösung (bevorzugt: Re-Hash des Präfix)**
1. `toob_ota_resume()` so erweitern, dass bei einem verifizierten Stream der bereits gestagte Präfix (`[CHIP_STAGING_SLOT_ABS_ADDR .. resume_offset]`) erneut durch `toob_os_sha256_update` gehasht wird, um `s_sha_ctx` zu rekonstruieren. `s_is_verified_stream` und `s_expected_sha256` dabei korrekt wiederherstellen (Hash muss aus dem Manifest/Handoff verfügbar sein — siehe unten).
2. In `toob_network_trigger_ota()`: auch im Resume-Zweig sicherstellen, dass der erwartete SHA gesetzt ist (aus dem frisch geparsten Manifest `info.sha256`), bevor `rtos_http_get` startet.
3. **Falls Re-Hash zu teuer/unmöglich** (z.B. Hash nach Reboot nicht mehr verfügbar): Resume + Verified-Stream ehrlich als „Verifikation für diesen Lauf deaktiviert, Bootloader verifiziert das volle Image post-Reboot" dokumentieren **und** einen expliziten Status (`TOOB_ERR_NOT_SUPPORTED` o.ä.) zurückgeben, statt still durchzulaufen.

**Akzeptanzkriterien**
- [ ] Host-Test: Download abbrechen bei 50 %, resumen, korrekt zu Ende laden ⇒ `toob_ota_finalize()` verifiziert den vollen SHA und liefert `TOOB_OK`.
- [ ] Host-Test: korrupte Bytes auf Resume ⇒ `toob_ota_finalize()` liefert `TOOB_ERR_VERIFY` (statt stillem `TOOB_OK`).
- [ ] Kein Pfad mehr, der eine angeforderte Stream-Verifikation still überspringt.

> **Hinweis:** Eng verzahnt mit LIBTOOB-021 — falls der State-Refactor parallel läuft, dieses Ticket auf der refaktorierten Context-Variante umsetzen.

---

### LIBTOOB-021 — OTA-State aus File-Globals in übergebenen `toob_ota_ctx_t`
**Prio:** P2 · **Typ:** refactor/dx · **Aufwand:** L
**Datei:** `sdk/libtoob/toob_ota.c`, `sdk/libtoob/include/libtoob.h`

**Problem**
Die komplette OTA-Session liegt in `static`-File-Globals (`s_state`, `s_write_cursor`, `s_total_size`, `s_bytes_queued`, `s_align_buf`, `s_sha_ctx`, `s_expected_sha256`, `s_is_verified_stream`). Folgen: keine nebenläufigen Sessions, State-Leakage zwischen Durchläufen, schwer testbar, und `toob_ota_resume` rekonstruiert den Byte-Cursor fragil aus `toob_handoff_state.resume_offset`.

**Lösung**
- Einen `toob_ota_ctx_t` einführen (opak, vom Aufrufer alloziert), der den gesamten Session-State kapselt. Alle `toob_ota_*`-Funktionen nehmen `toob_ota_ctx_t* ctx` als ersten Parameter.
- `_reset_state()` → `toob_ota_ctx_init(ctx)`.
- Zero-Allocation bleibt gewahrt: der Context ist eine vom OS bereitgestellte Struktur (Stack oder statisch beim OS), `libtoob` alloziert nichts dynamisch.
- Rückwärtskompatibilität: optional einen dünnen Shim mit dem alten globalen Context behalten, deprecaten.

**Akzeptanzkriterien**
- [ ] Alle `toob_ota_*`-Funktionen sind re-entrant über getrennte Contexts.
- [ ] Host-Test fährt zwei unabhängige OTA-Sessions parallel ohne Cross-Contamination.
- [ ] `_Static_assert` auf `sizeof(toob_ota_ctx_t)`-Stabilität (ABI).

> **Größtes Refactor im Backlog.** Sequenzieren *vor* LIBTOOB-020, wenn beide in einem Sprint landen.

---

### LIBTOOB-022 — `WAL_LOCKED` beim Finalize sauber surface-n
**Prio:** P2 · **Typ:** dx · **Aufwand:** S
**Dateien:** `sdk/libtoob/toob_ota.c`, `sdk/libtoob/toob_update.c`

**Problem**
`toob_ota_finalize()` ruft `toob_set_next_update()` → `toob_wal_naive_append()`. Liegt bereits ein nicht-konsumiertes `UPDATE_PENDING` vor, liefert der Append `TOOB_ERR_WAL_LOCKED`. Der OTA-Flow gibt das zwar weiter, aber ohne klare Semantik für den Aufrufer („was jetzt?").

**Lösung**
- `toob_ota_finalize()`-Doxygen explizit um `TOOB_ERR_WAL_LOCKED` ergänzen mit Handlungsempfehlung („vorheriges Update zuerst durch Reboot konsumieren").
- Optional: im `os_client`-Daemon (`toob_network_trigger_ota`) `WAL_LOCKED` gesondert loggen statt generisch „Finalize failed".

**Akzeptanzkriterien**
- [ ] `WAL_LOCKED` im Finalize-Doxygen dokumentiert.
- [ ] Daemon unterscheidet `WAL_LOCKED` von echten Flash-Fehlern im Log.

---

### LIBTOOB-023 — Read-Back pro Flush im OTA-Schreibpfad
**Prio:** P2 · **Typ:** bug/security · **Aufwand:** S
**Datei:** `sdk/libtoob/toob_ota.c`

**Problem**
`_flush_buffer()` schreibt den Alignment-Puffer via `toob_os_flash_write()` ins Staging-Flash und prüft per Glitch-Shield ausschließlich den **Rückgabe-Status** des Writes — den Flash-**Inhalt** liest es nie zurück. Ein Flash-Write, der still ein Byte korrumpiert, aber `TOOB_OK` liefert, wird damit **nicht** beim Schreiben gefangen. Der OTA-rollende SHA-256 hilft hier nicht: er hasht den empfangenen Chunk in `toob_ota_process_chunk` **vor** dem Write, validiert also Netz→SRAM, nicht SRAM→Flash. Konsequenz: Speicher-Korruption wird erst beim nächsten Boot durch `boot_merkle_verify_stream` entdeckt — einen ganzen Boot-Zyklus später, mit anschließendem Verwerfen des Updates und Re-Download.

**Root Cause**
Der OTA-Hot-Path vertraut dem Status des Vendor-Flash-Treibers. Die WAL-Append-Logik (`toob_wal_naive_append`) **und** die Cloud-Command-Submission (`toob_submit_cloud_command`) führen demgegenüber bereits einen chunked Phase-Bound Read-Back-Verify durch. Der OTA-Schreibpfad ist die **einzige** Stelle in `libtoob`, die ins Flash schreibt, ohne zurückzulesen — eine Inkonsistenz im Integritätsmodell der SDK.

**Lösung**
1. Nach jedem erfolgreichen `toob_os_flash_write()` in `_flush_buffer()` den gerade geschriebenen Bereich chunked aus dem Flash zurücklesen und gegen den Quellpuffer (`s_align_buf`) vergleichen — exakt das Muster aus `toob_submit_cloud_command()`:
   - kleiner Stack-Puffer (≤ 64 B, 8-Byte-aligned), Schleife über `write_len`;
   - Vergleich via `toob_ct_memcmp_glitch_safe()` (bereits in `toob_internal.h` verfügbar) oder XOR-Akkumulator-Diff gegen `s_align_buf + check_off`.
2. **Ghost-Match-Proof:** Read-Back-Puffer **vor** jedem Read nullen (zwingt den Treiber, tatsächlich aus dem Flash zu lesen statt einen RAM-Cache zu bestätigen) und am Ende zeroizen.
3. Bei Mismatch `TOOB_ERR_FLASH_HW` zurückgeben (nicht `TOOB_OK`). `toob_ota_process_chunk` geht damit in `TOOB_OTA_STATE_ERROR`, der Download wird verworfen/retried.
4. **Bewusst nicht-kryptografisch:** Dies ist ein Storage-Integritäts-Check (Bit-Rot / Tearing / stiller Write-Fail), **keine** Authentizitäts-Prüfung. Ed25519 + Per-Chunk-Merkle beim Boot bleiben die kryptografischen Gates — dieses Ticket schließt nur die Lücke früher (beim Schreiben statt beim Boot). Defense-in-Depth, kein neuer Vertrauensanker.
5. **Zero-Allocation wahren:** keine zweite 256-Byte-Stack-Allokation; ausschließlich chunked vergleichen wie in `toob_submit_cloud_command`.

**Akzeptanzkriterien**
- [ ] `_flush_buffer()` liest nach jedem Write den geschriebenen Bereich zurück und vergleicht ihn gegen `s_align_buf`.
- [ ] Host-Test mit Mock-Flash, der beim Write still ein Byte kippt, aber `TOOB_OK` liefert ⇒ `toob_ota_process_chunk` liefert `TOOB_ERR_FLASH_HW` (vorher: `TOOB_OK`, Fehler erst beim Boot-Merkle).
- [ ] Read-Back-Puffer wird vor jedem Read genullt und am Ende zeroized.
- [ ] Keine zweite 256-Byte-Stack-Allokation; Vergleich chunked (≤ 64 B Stack), konsistent mit `toob_submit_cloud_command`.
- [ ] Glitch-Shield-Muster (`TOOB_GLITCH_DELAY` / Double-Check) wird beim Mismatch-Verdict beibehalten.

**Abhängigkeit / Hinweis**
Ergänzt **LIBTOOB-020** (Verified-Resume) um die SRAM→Flash-Abdeckung — zusammen schließen beide die beiden offenen Stellen der OTA-Integritätskette. Läuft **LIBTOOB-021** (OTA-Context-Refactor) parallel, dieses Ticket auf der refaktorierten `toob_ota_ctx_t`-Variante umsetzen (Read-Back-Logik im Context-basierten `_flush_buffer`).

---

# EPIC D — API-DX-Härtung

> Die größten DX-Gewinne ohne ABI- oder Integrationskosten. Genau hier zahlt sich „API schärfen statt neu schreiben" aus.

---

### LIBTOOB-030 — `warn_unused_result` auf alle `toob_status_t`-Funktionen
**Prio:** P1 · **Typ:** dx/security · **Aufwand:** S
**Dateien:** `sdk/libtoob/include/libtoob.h`, `sdk/libtoob/include/libtoob_types.h`

**Problem**
Ein erheblicher Teil des defensiven Pre-Zeroing in `libtoob` (`toob_get_handoff`, `toob_get_boot_diag`) existiert **nur**, weil das OS den Return-Code ignorieren könnte und dann auf Garbage zugreift. Das Ignorieren ist heute völlig still.

**Lösung**
1. Ein Cross-Compiler-Makro definieren, z.B.
   ```c
   #if defined(__GNUC__) || defined(__clang__)
   #  define TOOB_MUST_CHECK __attribute__((warn_unused_result))
   #else
   #  define TOOB_MUST_CHECK
   #endif
   ```
   (für ICCARM/Keil ggf. passendes Pendant ergänzen).
2. Jede `toob_status_t`-zurückgebende öffentliche Funktion in `libtoob.h` mit `TOOB_MUST_CHECK` annotieren.

**Akzeptanzkriterien**
- [ ] Ein bewusst ignoriertes `toob_get_handoff()` erzeugt eine Compiler-Warnung im Host-Build.
- [ ] Bestehende SDK-Aufrufe in `os_client` lösen keine neuen Warnungen aus (sie prüfen bereits).

---

### LIBTOOB-031 — Phantom-Parameter `image_type` klären/entfernen
**Prio:** P2 · **Typ:** dx · **Aufwand:** S
**Dateien:** `sdk/libtoob/toob_ota.c`, `sdk/libtoob/include/libtoob.h`

**Problem**
`toob_ota_begin(total_size, image_type)` verwirft `image_type` mit `(void)image_type`. Das tatsächliche Routing (App / Recovery / Stage-1-Bank) entscheidet der SUIT-Parser im Bootloader über `component_id`. Die Signatur suggeriert Kontrolle, die der Aufrufer nicht hat — besonders irreführend bei `image_type == 3` (vermeintliches Bootloader-Update).

**Lösung (Variante A bevorzugt)**
- **A:** `image_type` aus der Signatur entfernen (`toob_ota_begin(total_size)`), alten Prototyp als deprecated-Shim behalten.
- **B (falls API-Bruch unerwünscht):** Parameter behalten, aber Doxygen klarstellen: „informativ/zukünftig; das tatsächliche Image-Routing erfolgt ausschließlich über das SUIT-Manifest (`component_id`) im Bootloader."

**Akzeptanzkriterien**
- [ ] Entweder Parameter entfernt + Shim, oder Doxygen stellt die Wirkungslosigkeit unmissverständlich klar.

---

### LIBTOOB-032 — `TOOB_OS_INIT_OR_PANIC()` Hänge-Semantik dokumentieren/absichern
**Prio:** P2 · **Typ:** dx · **Aufwand:** S
**Datei:** `sdk/libtoob/include/libtoob.h`

**Problem**
Das Makro endet bei Handoff-Korruption in `while(true){ TOOB_TRAP(); }` — eine unendliche Trap-Schleife. Auf Systemen ohne Hardware-WDT hängt damit die OS-Init **für immer**. Das ist als Fail-Closed gewollt, aber ein Makro, das deine OS-Init endlos hängen lassen kann, gehört prominent dokumentiert.

**Lösung**
- Doxygen-Warnblock am Makro: „Fail-Closed by Design. Ohne Hardware-WDT führt eine `.noinit`-Korruption zum permanenten Hang. Systeme ohne WDT sollten stattdessen `toob_validate_handoff()` direkt aufrufen und eine eigene Recovery-Strategie implementieren."
- Optional: eine nicht-hängende Variante `toob_os_init()` anbieten, die `toob_status_t` zurückgibt (Aufrufer entscheidet über die Reaktion).

**Akzeptanzkriterien**
- [ ] Warnblock vorhanden, der das WDT-lose Hang-Risiko explizit nennt.
- [ ] Optional: nicht-hängende Init-Variante verfügbar.

---

### LIBTOOB-033 — Status-Logging-Format portabel machen
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S
**Dateien:** `sdk/os_client/src/*.c`, `sdk/os_client/include/toob_network_client.h`

**Problem**
Logs nutzen `"0x%08X"` für `toob_status_t`-Werte (Enum). Die Enum-Konstanten (z.B. `0xE6601CAE`) überschreiten `INT_MAX`; der Underlying-Type des Enums ist implementierungsdefiniert. Mit `%X` (erwartet `unsigned int`) ist das formal UB-anfällig auf manchen Toolchains.

**Lösung**
- Beim Logging konsistent nach `(unsigned)status` casten und `%08X` verwenden, oder eine kleine `toob_status_to_str()`-Hilfsfunktion einführen (lesbarer als Hex).

**Akzeptanzkriterien**
- [ ] Keine Format-Spezifizierer-Warnung mehr unter `-Wformat` auf 32- und 64-bit Host-Builds.

---

# EPIC E — Code-Hygiene (innerhalb `libtoob`)

> Reine Aufräumarbeiten. Kein Verhaltensrisiko, verbessert Wartbarkeit.

---

### LIBTOOB-040 — Dedup: `toob_ota_secure_zeroize` / `TOOB_OTA_GLITCH_DELAY`
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S
**Dateien:** `sdk/libtoob/toob_ota.c`, `sdk/libtoob/toob_internal.h`

**Problem**
`toob_ota.c` definiert eine **eigene** `toob_ota_secure_zeroize()` und ein **eigenes** `TOOB_OTA_GLITCH_DELAY()`, obwohl es bereits `toob_internal.h` inkludiert, das `toob_secure_zeroize()` und `TOOB_GLITCH_DELAY()` bereitstellt. Zwei Implementierungen derselben Sache in derselben Library.

**Lösung**
- `toob_ota_secure_zeroize` → `toob_secure_zeroize` (aus `toob_internal.h`) ersetzen, lokale Definition löschen.
- `TOOB_OTA_GLITCH_DELAY` → `TOOB_GLITCH_DELAY` ersetzen, lokales Makro löschen.

**Akzeptanzkriterien**
- [ ] Keine duplizierten Zeroize-/Glitch-Delay-Definitionen mehr in `toob_ota.c`.
- [ ] Build grün, Verhalten unverändert.

---

### LIBTOOB-041 — Doppelte `toob_get_boot_diag`-Deklaration bereinigen
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S
**Datei:** `sdk/libtoob/include/libtoob.h`

**Problem**
`toob_get_boot_diag()` ist in `libtoob.h` **zweimal** deklariert (einmal im Abschnitt „Primary Feature-OS API", einmal im OTA-Daemon-Abschnitt) mit identischem Doxygen. Legal, aber sloppy und verwirrend.

**Lösung**
- Eine der beiden Deklarationen entfernen, die verbleibende im logisch passenderen Abschnitt belassen.

**Akzeptanzkriterien**
- [ ] Genau eine Deklaration von `toob_get_boot_diag()` im Header.

---

### LIBTOOB-042 — CBOR-Telemetrie-Mapping-Hacks dokumentieren/auflösen
**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S
**Datei:** `sdk/libtoob/toob_diag.c`

**Problem**
`toob_get_boot_diag_cbor()` belegt `vendor_error` in **zwei** CDDL-Feldern (`uint3` und `uint4`, Kommentar: „belege vendor_error in beiden Feldern") und setzt mehrere Felder hart auf 0 (`uint5`, `uint8bool`, `uint11`), weil das C-Struct sie nicht trägt. Das ist ein stiller Schema-Workaround.

**Lösung**
- Entweder das CDDL-Schema an das tatsächliche `toob_boot_diag_t` angleichen (Felder entfernen, die nie befüllt werden), oder die fehlenden Felder ins Diag-Struct aufnehmen.
- Mindestens: jeden Hack mit einem präzisen Kommentar versehen, warum das Feld dupliziert/genullt ist, plus TODO mit Referenz auf das Telemetrie-Spec.

**Akzeptanzkriterien**
- [ ] Kein undokumentierter Schema-Workaround mehr; entweder Schema bereinigt oder Mapping vollständig kommentiert.

---

# EPIC F — `os_client` (angrenzend, **nicht** `libtoob`)

> **Scope-Hinweis:** `os_client` sitzt *hinter* dem C-API von `libtoob` (`toob_ota_process_chunk`, `toob_get_boot_diag`) und redet **nicht** über die `.noinit`-ABI. Es ist der stärkste Rust-Kandidat der SDK, weil es untrusted Netzwerk-Input parst. Hier gelistet, weil es Teil der SDK-Auslieferung ist — aber bewusst von den `libtoob`-Tickets getrennt.

---

### LIBTOOB-050 — `os_client` CBOR-Manifest-Parser auditieren/härten (Rust-Kandidat)
**Prio:** P2 · **Typ:** security/spike · **Aufwand:** M
**Datei:** `sdk/os_client/src/toob_network_client.c`

**Problem**
`_parse_cbor_manifest()` und der HTTP-Stream verarbeiten **untrusted** Server-Input. Das ist die genuin angriffsexponierte Stelle der SDK. Aktuell C + zcbor.

**Lösung (Spike + Entscheidung)**
1. Audit des bestehenden C-Parsers: Bounds, Pflichtfeld-Erzwingung (`has_size`/`has_sha256`/`has_svn`), Integer-Overflow im Chunk-Callback (`_manifest_chunk_cb`), URL-Parsing in `rtos_http_zephyr.c`.
2. Spike: Re-Implementierung des Parsers als Rust-`#![no_std]`-Crate, eingebunden als staticlib hinter dem bestehenden C-API. **Wichtig:** berührt **keinen** `_Static_assert` der `libtoob`-ABI, da `os_client` nicht über `.noinit` redet.
3. Entscheidungsvorlage: Rust-Parser vs. gehärteter C-Parser, inkl. Integrationskosten in Zephyr-CMake / ESP-IDF-Component.

**Akzeptanzkriterien**
- [ ] Audit-Findings dokumentiert (mind. Bounds, Overflow, Pflichtfelder, URL-Parsing).
- [ ] Spike-Ergebnis + Entscheidungsvorlage (Rust vs. C-Härtung) liegt vor.

---

### LIBTOOB-051 — Optionale Rust-Wrapper-Crate über C-`libtoob` (DX-Layer)
**Prio:** P3 · **Typ:** spike · **Aufwand:** L

**Problem / Chance**
Das stärkste Pro-Rust-Argument ist nicht Memory-Safety, sondern **Typestate**. Eine `OtaSession<Receiving> → OtaSession<Done>`-Maschine würde die Missbrauchsanfälligkeit von LIBTOOB-021 *strukturell* beseitigen (kein `process_chunk` vor `begin`, kein Re-Entry). Trait-basierte Flash-Ops (`impl FlashOps for MyFlash`) sind discoverbarer als ein „undefined symbol"-Linker-Contract.

**Lösung (Spike)**
- Dünne, **optionale** Rust-Crate über dem C-`libtoob`: idiomatische Wrapper, Typestate für die OTA-Session, Trait für die Zero-Bloat-Flash-/Crypto-Hooks.
- Ausdrücklich **kein** Ersatz von `libtoob` — C bleibt die ABI-tragende Schicht (behält Cross-Asserts + niedrige Integrationshürde für die Rust-fremde Hälfte der Zielgruppe). Die Rust-Crate ist DX-Zuckerguss für Rust-affine Integratoren.

**Akzeptanzkriterien**
- [ ] Spike-Crate kapselt mindestens die OTA-Session als Typestate-Maschine über dem C-API.
- [ ] Bewertung: DX-Gewinn vs. Wartungslast einer zweiten API-Oberfläche.

---

## Empfohlene Reihenfolge (abhängigkeitsbewusst)

**Sprint 1 — „Stop the bleeding" (Korrektheit + billige DX):**
`LIBTOOB-001` (P0, trivial) → `LIBTOOB-011` (CRC-CI) → `LIBTOOB-030` (`warn_unused_result`) → `LIBTOOB-003` (Error-Kontrakte) → Hygiene `LIBTOOB-040/041`.

**Sprint 2 — ABI & OTA-Robustheit:**
`LIBTOOB-010` (Single-Source-Typ) → `LIBTOOB-021` (OTA-Context-Refactor) → darauf aufbauend `LIBTOOB-020` (Verified-Resume-Fix) → `LIBTOOB-023` (Read-Back pro Flush) → `LIBTOOB-022`.

**Sprint 3 — DX-Politur & Kohärenz:**
`LIBTOOB-012` (opaker Handoff) → `LIBTOOB-002` (Confirm-Backend-Kohärenz) → `LIBTOOB-031/032/033` → `LIBTOOB-042`.

**Parallel/separat (eigenes Team, eigene Entscheidung):**
`LIBTOOB-050` (os_client-Audit + Rust-Spike) → `LIBTOOB-051` (optionale Rust-Wrapper-Crate).

---

## Architektur-Merksatz für neue Mitarbeiter

`libtoob` ist die **OS-Seite einer Zwei-Binary-Grenze**. Es trägt keine Glitch-kritische Logik — die sitzt im Core. Drei Kanäle: `.noinit`-Handoff (CRC-versiegelt), Flash-Slots (OS schreibt, Bootloader evaluiert/mutiert — niemals umgekehrt), und der Zero-Bloat-Linker-Contract (OS liefert Flash-/SHA-Hooks). Die Grenze lebt von **bit-exakten Typ-Layouts** und **CRC-Gleichheit**. Jede Änderung an `libtoob` muss diese drei Annahmen wahren — die Tickets in EPIC B existieren, um genau das compiler-/CI-prüfbar zu machen, statt es zu hoffen.