# Backlog — Toob Update Service

**Grundlage:** `ARCHITEKTUR-update-service-v2.md` (plan7.md). Jedes Ticket referenziert den Abschnitt (§)
bzw. den Befund (B), den es umsetzt. Doku und Code dürfen nicht driften — ändert ein Ticket
eine Entscheidung, wird die Architektur im selben PR angepasst.

**Scope:** Der ausführende Update-Dienst plus die Core-/SDK-Vorbedingungen, ohne die er nicht
betreibbar ist. Flotten, Rollouts und Plugin-Markets sind **nicht** enthalten — sie hängen an
EPIC G und erzeugen keine Tickets hier.

**Leitprinzip:** Der Dienst wählt und liefert, er entscheidet nicht über Vertrauen. Jedes
Ticket, das eine Sicherheitsaussage in den Server verlagern würde, ist falsch geschnitten.

---

## Legende & Konventionen

**Priorität**
- **P0** — Blockierend oder sicherheitsrelevant. Ohne diese läuft kein sinnvoller Betrieb.
- **P1** — Für das Gate der jeweiligen Phase erforderlich.
- **P2** — Robustheit, Performance, Beobachtbarkeit.
- **P3** — Hygiene, Doku.

**Typ:** `bug` · `security` · `feature` · `refactor` · `infra` · `abi` · `perf` · `dx`

**Aufwand:** S (≤ ½ Tag) · M (1–2 Tage) · L (> 2 Tage / koordiniert)

**Komponente:** `core` (toobloader) · `sdk` (libtoob / os_client) · `cli` (toob) ·
`svc` (Update Service) · `sign` (Signing Service) · `infra`

**Definition of Done (global):**
1. Bei Core-/SDK-Änderungen: Sandbox-Build **und** ESP32-C6-Target-Build grün, alle
   `_Static_assert` kompilieren.
2. Bei Verhaltensänderung: gezielter Test, der das alte Verhalten nachweist (Host-Mock,
   Integrationstest oder HIL).
3. Fail-Fast eingehalten: kein stiller Default, kein Fallback, der einen Fehlerzustand
   maskiert. Fehlende Konfiguration bricht den Start ab, nicht den Request.
4. Kein neuer Codepfad liefert Bytes aus, die das Gerät garantiert ablehnen würde (§P4).
5. Betroffene Abschnitte der Architektur bestätigt oder per PR angepasst.

---

## Ticket-Übersicht

| ID | Titel | Prio | Typ | Komp. | Aufw. |
|---|---|---|---|---|---|
| **EPIC A — Core-/SDK-Vorbedingungen** ||||||
| UPD-001 | Diag auf jedem Boot befüllen (Kaltstart liefert Müll) | P0 | bug/security | core | S |
| UPD-002 | HTTP-Hook generalisieren (Methode, Header, Status, Retry-After) | P0 | feature | sdk | M |
| UPD-003 | Device-Credential-Speicher im OS-NVS | P1 | feature | sdk | M |
| UPD-004 | Check-in-Client auf POST + Diag-Body umbauen | P1 | refactor | sdk | M |
| UPD-005 | Blob-Download über gebundenen Pfad-Suffix | P1 | feature | sdk | M |
| UPD-006 | `counter_min`-Deckel + `issued_at`-Freshness | P0 | security | core | S |
| UPD-007 | Diag v3 — ABI-Bump (Sammelticket) | P2 | abi | sdk/core | L |
| UPD-008 | Resume-State im OS-eigenen `.noinit`-Slot | P2 | feature | sdk | M |
| UPD-009 | `wdt_kicks` echt zählen oder als reserviert kennzeichnen | P3 | cleanup | core | S |
| **EPIC B — Datenmodell, Ingest, Artefakt-Store** ||||||
| UPD-010 | Schema-Migration v1 | P1 | infra | svc | M |
| UPD-011 | Admission-Gate: host-kompilierter C-Reader im Ingest | P0 | security | svc | M |
| UPD-012 | SVN-Geländer pro Target-Slot als DB-Invariante | P0 | security | svc | M |
| UPD-013 | Artefakt-Store: WORM, Digest-Verifikation nach Upload | P1 | infra | svc | M |
| UPD-014 | Ingest-API + Release-Pointer | P1 | feature | svc | M |
| UPD-015 | Signing-Service-Policy (Produkt-, Key-, SVN-Bindung) | P1 | security | sign | M |
| UPD-016 | Reproduzierbarkeits-Invariante für `build_number` | P2 | infra | svc | S |
| **EPIC C — Device Gateway (Hot Path)** ||||||
| UPD-020 | Check-in-Endpunkt | P1 | feature | svc | M |
| UPD-021 | Resolver: Pin → Channel → Kompatibilität → Fortschritt | P1 | feature | svc | M |
| UPD-022 | Lazy Materialisierung + Ein-offene-Zuweisung-Invariante | P1 | feature | svc | M |
| UPD-023 | Blob-Auslieferung: Range, 416, identity, kein Redirect | P0 | bug/infra | svc | M |
| UPD-024 | `Retry-After` in jeder Antwort inkl. 204 und 5xx | P1 | feature | svc | S |
| UPD-025 | Assignment-Zustandsautomat mit Monotonie-Guard | P1 | feature | svc | M |
| UPD-026 | Confirm-Inferenz aus dem Folge-Check-in | P1 | feature | svc | M |
| UPD-027 | Events-Endpunkt (best effort) | P2 | feature | svc | S |
| UPD-028 | Idempotenz über `X-Toob-Seq` | P1 | feature | svc | S |
| **EPIC D — Identität & Schlüssel** ||||||
| UPD-030 | Enrollment in `toob provision` | P1 | feature | cli/svc | L |
| UPD-031 | Token-Verifikation via HMAC (nicht Argon2id) | P1 | security/perf | svc | S |
| UPD-032 | Server-initiierte Token-Rotation (Key 7) | P2 | security | svc/sdk | M |
| UPD-033 | Key-Custody-Trennung als Deployment-Grenze | P1 | security | infra | M |
| UPD-034 | Auth-Pflicht ohne Bypass-Schalter | P0 | security | svc | S |
| **EPIC E — Verschleiß & Fehlerpolitik** ||||||
| UPD-040 | Attempt-Cap als Hardware-Schutz | P1 | feature | svc | S |
| UPD-041 | `deferred_power` erhöht `attempts` nicht | P1 | bug | svc | S |
| UPD-042 | Verschleiß-bewusste Auslieferung via `ext_health` | P2 | feature | svc | M |
| UPD-043 | Fehlertaxonomie + Artefakt-Quarantäne | P2 | feature | svc | M |
| UPD-044 | `device.health`-Aussteuerung | P2 | feature | svc | S |
| **EPIC F — Performance** ||||||
| UPD-050 | Kohorten-Cache für den 204-Pfad | P2 | perf | svc | M |
| UPD-051 | Zero-Write-Hot-Path (Append + Rollup) | P2 | perf | svc | M |
| UPD-052 | Edge-Konfiguration (Cache-Policies, Origin Cache Lock) | P2 | infra | infra | S |
| UPD-053 | Lastprofil-Test: Flotten-Rückkehr nach Regionalausfall | P2 | infra | svc | M |
| **EPIC G — Naht zum Management-Layer** ||||||
| UPD-060 | Internal-API für Desired State | P2 | feature | svc | M |
| UPD-061 | Transactional Outbox + Poller | P2 | feature | svc | M |
| UPD-062 | Pinning (`assignment_source = 'pin'`) | P2 | feature | svc | S |
| UPD-063 | `ramp_bps` / `cohort_seed` als Resolver-Eingabe | P2 | feature | svc | S |
| **EPIC H — Delta (Vorbereitung)** ||||||
| UPD-070 | Delta-Auswahl im Resolver | P3 | feature | svc | S |
| UPD-071 | Delta-Admission: exakter `base_build`-Match | P3 | security | svc | S |

---

# EPIC A — Core-/SDK-Vorbedingungen

> Ohne UPD-001 und UPD-002 ist der Dienst nicht sinnvoll betreibbar. Diese Epic ist Phase 0.

---

### UPD-001 — Diag auf jedem Boot befüllen

**Prio:** P0 · **Typ:** bug/security · **Komp.:** core · **Aufwand:** S · **Ref:** B1, §12.1
**Dateien:** `toobloader/core/boot_main.c`, `toobloader/core/utils/boot_diag.c`,
`toobloader/core/utils/include/boot_diag.h`

**Problem**
`boot_diag_set_security_meta()` wird ausschließlich aus `stage_check_binding()` gerufen — also
nur auf einem Boot, der tatsächlich ein Update durch die Pipeline schiebt. `boot_diag_init()`
(das zeroisiert und `struct_version` setzt) läuft in `boot_main.c` nur im Forensik-Zweig
(`if (forensic_valid)`). `toob_diag_state` liegt in `.noinit`.

Nach einem **Kaltstart** enthält die Diag-Struktur damit undefiniertes RAM, und
`boot_diag_seal()` versieht diesen Zufall am Ende jedes Boots mit einer *gültigen* CRC.
`toob_get_boot_diag()` liefert `TOOB_OK` mit Müll.

**Root Cause**
Die Diag-Befüllung ist an den Update-Pfad gekoppelt statt an den Boot-Pfad. Die Werte, die das
OS braucht (`current_svn`, `build_number`, `fw_ver_*`), liegen aber auf jedem Boot vor: im TMR
(`tmr.app_svn`, `tmr.stage1_svn`) und im `toob_image_header_t` des gebooteten Slots.

**Auswirkung**
`toob_network_client.c` setzt `current_svn = diag.current_svn` und schickt das an den Server.
Meldet ein Gerät nach einem Netzausfall zufällig einen hohen Wert, filtert der Resolver alles
weg — das Gerät fällt **dauerhaft und still** aus der Update-Versorgung. Meldet es 0, lädt es
Updates herunter, die es bereits hat, und verbrennt Staging-Erase-Zyklen. Der `sbom_digest` in
der CRA-Evidenz ist Zufallsrauschen.

**Lösung**
1. `boot_diag_init()` unbedingt und früh in `boot_main.c` rufen, nicht nur im Forensik-Zweig.
   Der Forensik-Pfad überschreibt danach wie bisher via `boot_diag_set_error()`.
2. Neuer Setter in `boot_diag.c`:
   ```c
   void boot_diag_set_installed_state(uint32_t app_svn, uint32_t stage1_svn,
                                      uint32_t build_number);
   ```
3. In `boot_main.c` BLOCK 5 aufrufen, wo `tmr` bereits gelesen und `app_header` bereits
   verfügbar ist. Kein zusätzlicher Flash-Read.
4. Kommentar an beiden Stellen, der die Kopplung erklärt — sonst wird der Aufruf beim nächsten
   Refactoring wieder entfernt.

**Akzeptanzkriterien**
- [ ] Host-Test: `.noinit` vor dem Boot mit `0xA5`-Muster gefüllt ⇒ `toob_get_boot_diag()`
      liefert die echten TMR-Werte, nicht das Muster.
- [ ] Host-Test: Boot **ohne** Update ⇒ `diag.current_svn == tmr.app_svn` (vorher: 0 oder Müll).
- [ ] HIL: Kaltstart (Netztrennung ≥ 10 s) ⇒ das Gerät meldet dieselbe SVN wie vor dem Trennen.
- [ ] `struct_version` ist nach jedem Boot gesetzt, auch ohne Forensik-Record.

**Abhängigkeit:** Keine. **Blockiert:** UPD-021, UPD-026, UPD-042 und damit faktisch Phase 1.

---

### UPD-002 — HTTP-Hook generalisieren

**Prio:** P0 · **Typ:** feature · **Komp.:** sdk · **Aufwand:** M · **Ref:** B5, §12.2
**Dateien:** `sdk/os_client/include/toob_network_client.h`, `rtos_http_zephyr.c`,
`rtos_http_esp.c`, `sdk/os_client/src/toob_network_client.c`

**Problem**
`rtos_http_get(url, resume_offset, cb, ctx)` ist der einzige RTOS-Hook. Damit sind unmöglich:
`Authorization`-Header, CBOR-Request-Body, `Retry-After`-Auswertung und die Unterscheidung von
`204` gegenüber „200 mit leerem Body" — beides ergibt heute `mbuf.len == 0`.

**Root Cause**
Der Hook wurde für genau einen Anwendungsfall (Blob-Download) entworfen und trägt keine
HTTP-Semantik nach außen.

**Lösung**
Ein Hook, nicht zwei — die Zero-Bloat-Philosophie soll nicht durch Hook-Vermehrung erodieren:

```c
typedef enum { TOOB_HTTP_GET = 0, TOOB_HTTP_POST = 1 } toob_http_method_t;

TOOB_MUST_CHECK toob_status_t rtos_http_request(
    toob_http_method_t method,
    const char *url,
    const char *const *headers, uint32_t header_count,
    const uint8_t *body, uint32_t body_len,
    uint32_t range_offset,
    toob_http_chunk_cb_t callback, void *ctx,
    uint16_t *out_status,
    uint32_t *out_retry_after_s);
```

- `out_status` ist Pflicht: ohne echten Statuscode ist die Fehlertabelle aus §4.5 nicht
  implementierbar.
- `out_retry_after_s` ist Pflicht: `204` hat keinen Body, der Header ist der einzige Kanal für
  serverseitiges Poll-Steering.
- Beide Ausgaben werden **vor** dem ersten Callback gesetzt, damit der Aufrufer bei `204`
  gar nicht erst puffert.
- `headers` ist ein Array von `"Name: Value"`-Strings; der Aufrufer besitzt den Speicher.
  Kein dynamischer Aufbau im Hook.

**Akzeptanzkriterien**
- [ ] Zephyr- und ESP-IDF-Implementierung liefern `204` und `200`-mit-leerem-Body
      unterscheidbar zurück.
- [ ] `Retry-After` wird auf beiden Plattformen aus dem Response-Header extrahiert;
      fehlender Header ⇒ `*out_retry_after_s = 0` (Aufrufer entscheidet, kein Default im Hook).
- [ ] POST mit CBOR-Body funktioniert gegen einen Host-Mock-Server.
- [ ] Der alte `rtos_http_get` existiert nicht mehr — kein Deprecation-Shim, ein Aufrufer.

**Abhängigkeit:** Keine. **Blockiert:** UPD-003 bis UPD-005, UPD-020, UPD-024.

---

### UPD-003 — Device-Credential-Speicher im OS-NVS

**Prio:** P1 · **Typ:** feature · **Komp.:** sdk · **Aufwand:** M · **Ref:** §12.3, §6

**Problem**
Der Check-in braucht ein Bearer-Token (§7.1) und einen Idempotenz-Sequenzzähler (§6, B2).
Beides ist **nicht** aus Chip-UID oder Root-Key ableitbar — beide sind öffentlich.

**Lösung**
Ein OS-eigener NVS-Bereich (Zephyr Settings / ESP-IDF NVS), nicht in `toob_handoff_t`
(80 Byte, static-asserted, bootloader-versiegelt):

```c
typedef struct {
    uint8_t  device_token[32];
    uint64_t checkin_seq;
} toob_device_cred_t;
```

`checkin_seq` wird **pro Check-in** inkrementiert und geschrieben, nicht pro Boot. Bei einem
Poll-Intervall von Stunden ist der Verschleiß vernachlässigbar.

Zugriff über zwei Funktionen, kein direkter NVS-Zugriff aus dem Update-Flow:
`toob_cred_load()`, `toob_cred_bump_seq()`. Fehlt das Credential ⇒ `TOOB_ERR_NOT_FOUND`, und
der Daemon bricht den Check-in ab — kein anonymer Request.

**Akzeptanzkriterien**
- [ ] Token überlebt Reboot und Firmware-Update.
- [ ] `checkin_seq` ist über Reboots hinweg strikt monoton.
- [ ] Fehlendes Credential ⇒ Check-in wird gar nicht erst gesendet, Log-Eintrag, Backoff.

**Abhängigkeit:** UPD-002.

---

### UPD-004 — Check-in-Client auf POST + Diag-Body umbauen

**Prio:** P1 · **Typ:** refactor · **Komp.:** sdk · **Aufwand:** M · **Ref:** §4.2
**Datei:** `sdk/os_client/src/toob_network_client.c`

**Problem**
`toob_network_trigger_ota()` baut heute `"%s/check?svn=%u"` und schickt einen GET ohne
Identität. Die Architektur verlangt einen POST mit dem Diag-CBOR als Body, Token im Header und
Sequenz im `X-Toob-Seq`-Header.

**Lösung**
1. Request bauen: `POST {base}/v1/devices/{hex(device_id)}/checkin`,
   Header `Authorization: Bearer …` und `X-Toob-Seq: …`,
   Body = unveränderte Ausgabe von `toob_get_boot_diag_cbor()`.
2. `device_id` über `toob_get_device_id()` beziehen, hex-kodieren (feste Länge 64, kein
   dynamischer String).
3. Antwortauswertung anhand `out_status`:
   `200` → Manifest parsen; `204` → kein Update; `401/403/404` → Backoff + Log;
   `429/5xx` → Backoff mit `Retry-After`.
4. Der bestehende `_parse_cbor_manifest()` bleibt unverändert nutzbar (Keys 1–4); neue Keys
   fallen durch `zcbor_any_skip()`.

**Akzeptanzkriterien**
- [ ] Host-Test gegen Mock: `204` führt zu keinem Download-Versuch und keinem Fehlerlog.
- [ ] Host-Test: `401` führt zu Backoff, nicht zu einem Retry-Sturm.
- [ ] Der Body ist byte-identisch mit `toob_get_boot_diag_cbor()` — kein Re-Encoding.
- [ ] URL-Länge bleibt unter der `check_url[256]`-Grenze (Trunkierungsprüfung bleibt bestehen).

**Abhängigkeit:** UPD-002, UPD-003.

---

### UPD-005 — Blob-Download über gebundenen Pfad-Suffix

**Prio:** P1 · **Typ:** feature · **Komp.:** sdk · **Aufwand:** M · **Ref:** §4.4

**Problem**
Der Client baut heute `"%s/download"` — ein fest verdrahteter Pfad, der keine
Objektschlüssel-Migration und keine Region-Steuerung erlaubt. Eine freie absolute URL aus der
Antwort ist aber nicht tragfähig: `cbor_manifest_buf_t.buf[256]` fasst die **gesamte**
CBOR-Antwort, und eine Pre-Signed-URL ist allein 400–700 Zeichen lang.

**Lösung**
1. `cbor_manifest_buf_t.buf` auf 512 Byte (OS-seitiges RAM, nicht Bootloader).
2. Key 5 als `tstr` mit harter Längenprüfung ≤ 128 Byte parsen. Überlänge ⇒
   `TOOB_ERR_INVALID_ARG`, kein Abschneiden.
3. **Ablehnen**, wenn der Wert `":"` oder `"//"` enthält — Key 5 trägt ausschließlich Pfad und
   Query, niemals Schema oder Host. Der Host bleibt einkompiliert und ist vom Netz nicht
   veränderbar.
4. Download-URL: `snprintf(url, sizeof(url), "%s%s", CONFIG_TOOB_SERVER_URL, blob_path)`,
   mit Trunkierungsprüfung.

**Akzeptanzkriterien**
- [ ] Ein Key-5-Wert mit `http://` oder `//` wird abgelehnt, kein Request abgesetzt.
- [ ] Ein 129-Byte-Wert wird abgelehnt.
- [ ] Fehlt Key 5 ⇒ `TOOB_ERR_INVALID_ARG` (kein Rückfall auf einen Default-Pfad).
- [ ] Der Manifest-Puffer wird nach dem Parsen zeroisiert.

**Abhängigkeit:** UPD-002. **Hinweis:** MISRA/CERT-relevant — netzkontrollierter String im
URL-Aufbau. Die Host-Bindung ist die Kernabsicherung und darf nicht wegkonfiguriert werden.

---

### UPD-006 — `counter_min`-Deckel + `issued_at`-Freshness

**Prio:** P0 · **Typ:** security · **Komp.:** core · **Aufwand:** S · **Ref:** B4, §12.5
**Datei:** `toobloader/core/boot_cloud_cmd.c`

**Problem**
`boot_cloud_cmd_evaluate_buffer()` berechnet `burns_needed = decoded.counter_min - current_counter`
und brennt so oft, **ohne Obergrenze**. Ein fehlerhaft berechneter oder manipulierter Wert
verbrennt irreversibel OTP-Bits bis zur Erschöpfung des Zählers.

Zusätzlich wird `decoded.issued_at` dekodiert, aber nie geprüft: ein abgefangenes, nie
zugestelltes Kommando bleibt unbegrenzt gültig.

**Lösung**
```c
/* Ein einzelner Command darf den OTP-Zähler nie um mehr als
 * TOOB_CMD_MAX_BURN_STEPS vorrücken. Ein zu hoher counter_min ist ein Fehler
 * des Ausstellers oder ein Angriff — kein Grund, OTP-Bits zu verbrennen. */
uint32_t burns_needed = decoded.counter_min - current_counter;
if (burns_needed > TOOB_CMD_MAX_BURN_STEPS) {
    final_status = BOOT_ERR_INVALID_ARG;
    goto cleanup;
}
```

`TOOB_CMD_MAX_BURN_STEPS` als generierte Konstante (Vorschlag: 4). Dazu ein Freshness-Fenster
gegen `issued_at`, dessen Breite aus dem Geräte-TOML kommt.

> **TODO:** Das Gerät hat keine vertrauenswürdige Wanduhr. Das Freshness-Fenster kann daher
> nur gegen einen monoton wachsenden Referenzwert geprüft werden (z. B. `issued_at` des zuletzt
> akzeptierten Commands). Die genaue Semantik ist vor der Umsetzung festzulegen — ein
> Zeitfenster ohne Zeitquelle wäre ein Scheingate.

**Akzeptanzkriterien**
- [ ] Host-Test: `counter_min = current + 5` bei `MAX_BURN_STEPS = 4` ⇒ `BOOT_ERR_INVALID_ARG`,
      **kein** `advance_monotonic_counter()`-Aufruf.
- [ ] Host-Test: `counter_min = current + 1` ⇒ genau ein Burn.
- [ ] `issued_at` kleiner als der zuletzt akzeptierte Wert ⇒ Ablehnung.

**Abhängigkeit:** Keine. Unabhängig vom Rest des Backlogs umsetzbar.

---

### UPD-007 — Diag v3 (ABI-Bump, Sammelticket)

**Prio:** P2 · **Typ:** abi · **Komp.:** sdk/core · **Aufwand:** L · **Ref:** §12.6
**Dateien:** `sdk/libtoob/include/libtoob_types.h`, `toobloader/core/utils/boot_diag.c`,
`cli/cbor/toob_telemetry.cddl`, generierte zcbor-Encoder

**Problem**
Mehrere Felder, die der Server für Resolver, Confirm-Inferenz und sichere Cloud-Commands
braucht, existieren in `toob_boot_diag_t` nicht. `_reserved_diag[1]` reicht nicht.

**Lösung — als *ein* Bump, nicht als drei**

| Feld | Zweck |
|---|---|
| `installed_app_svn`, `installed_stage1_svn` | Resolver-Fortschrittsfilter (§6, UPD-001) |
| `reader_major`, `reader_minor` | `min_reader_*`-Gate serverseitig prüfbar (§7.4) |
| `monotonic_counter` | Sichere `counter_min`-Berechnung (§4.3) |
| `last_update_outcome` | enum: none / applied / rejected / reverted / deferred |
| `last_update_reject` | `tbm1_reject_t` — heute verliert `_handle_update_result()` die feingranulare Ursache über die `ERR_TABLE`, obwohl `boot_tbm1.c` selbst anmerkt, dass genau sie in die Telemetrie gehört |

Koordiniert mitzuziehen: die vollständige `_Static_assert`-Offsetkette,
`TOOB_DIAG_STRUCT_VERSION` → `0x03000000`, das CDDL-Schema (additiv, neue Keys ≥ 12) und der
generierte Encoder.

**Akzeptanzkriterien**
- [ ] Alle Offset-Asserts aktualisiert; ein absichtlich eingefügtes Testfeld lässt den Build rot werden.
- [ ] `last_update_reject` trägt nach einem abgelehnten Update den echten `tbm1_reject_t`.
- [ ] Der Server kann aus der Telemetrie „abgelehnt" von „nie versucht" unterscheiden.
- [ ] CDDL und C-Struct sind konsistent (Round-Trip-Test Encode → Decode).

**Abhängigkeit:** UPD-001 (sonst sind auch die neuen Felder auf einem Normalboot leer).

---

### UPD-008 — Resume-State im OS-eigenen `.noinit`-Slot

**Prio:** P2 · **Typ:** feature · **Komp.:** sdk · **Aufwand:** M · **Ref:** B3, §12.4

**Problem**
`toob_ota_resume()` liest `toob_handoff_state.resume_offset`. Der Core füllt das Feld aus
`WAL_INTENT_DOWNLOAD_CHECKPOINT`; seit der Mailbox-Umstellung schreibt aber nichts mehr diesen
Intent, und `toob_mailbox_wire.h` kennt keinen Checkpoint-Request. Der Wert ist konstant 0,
`toob_ota_resume()` liefert immer `TOOB_ERR_NOT_FOUND`.

**Lösung — ohne Core-Änderung**
Der tote WAL-Pfad wird nicht wiederbelebt. Stattdessen ein OS-eigener `.noinit`-Slot, getrennt
vom bootloader-versiegelten `toob_handoff_state` (dessen CRC das OS nicht neu berechnen darf):

```c
typedef struct __attribute__((aligned(8))) {
    uint32_t magic;
    uint32_t bytes_staged;
    uint8_t  artifact_sha256[32];
    uint8_t  assignment_id[16];
    uint32_t crc32_trailer;
} toob_ota_resume_state_t;
```

Resume nur, wenn Magic und CRC stimmen **und** `artifact_sha256` mit dem Wert aus dem frischen
Check-in übereinstimmt. Sonst Neustart — ein Spleiß zweier verschiedener Images würde sonst
erst am Finalize-SHA auffallen, nach vollem Download.

Kein flash-persistenter Checkpoint: bei einem 1-MB-Image kostete das dutzende Sektor-Erases pro
Download und griffe genau die Lebensdauer an, die EPIC E schützt. Resume überlebt WDT-Reset,
HardFault und Soft-Reboot; ein Stromausfall führt bewusst zum Neustart.

**Akzeptanzkriterien**
- [ ] HIL: WDT-Reset bei 50 % Download ⇒ Resume ab exakt `bytes_staged`, Finalize-SHA grün.
- [ ] Wechselt der Server die Zuweisung, wird der Resume verworfen und neu begonnen —
      nachweisbar über ein `download_started`-Event mit `bytes_done == 0`.
- [ ] Kaltstart ⇒ kein Resume, kein Fehler.
- [ ] Die Region ist als `reserved_ram_regions`-Eintrag im Chip-Package deklariert
      (`ARCHITEKTUR-registry-chips.md` §3.1 R5) und wird vom ELF-Audit gegen `.noinit`
      geprüft.

**Abhängigkeit:** UPD-004, UPD-005; Chip-Package-Ticket REG-002/REG-041 für die Region.

---

### UPD-009 — `wdt_kicks` echt zählen oder als reserviert kennzeichnen

**Prio:** P3 · **Typ:** cleanup · **Komp.:** core · **Aufwand:** S · **Ref:** §12.7

**Problem**
`boot_main.c` ruft `boot_diag_set_system_status(0, …)` — `wdt_kicks` ist hart auf 0 verdrahtet.
Ein konstant nullwertiges Telemetriefeld ist schlimmer als kein Feld: es täuscht eine Auswertung
vor, die es nicht gibt.

**Lösung**
Entweder einen echten Zähler im WDT-HAL-Wrapper führen, oder das Feld im CDDL und im Header
explizit als `reserved` dokumentieren und serverseitig nicht auswerten. Keine dritte Variante.

**Akzeptanzkriterien**
- [ ] Feld liefert entweder echte Werte oder ist als reserviert dokumentiert und wird vom
      Ingest ignoriert.

---

# EPIC B — Datenmodell, Ingest, Artefakt-Store

---

### UPD-010 — Schema-Migration v1

**Prio:** P1 · **Typ:** infra · **Komp.:** svc · **Aufwand:** M · **Ref:** §3.1

**Lösung**
Tabellen `products`, `product_svn_floor`, `artifacts`, `releases`, `devices`, `assignments`,
`device_events` gemäß Architektur. Kritische Invarianten als DB-Constraints, nicht als
Anwendungscode:

- `releases_one_active` — partieller Unique-Index auf `(product, channel) WHERE active`.
- `assignments_one_open` — partieller Unique-Index auf `device_id` für offene Zustände.
- `artifacts_build_unique` auf `(product, build_number, kind, COALESCE(base_build, -1))`.
- `CHECK ((kind = 'delta') = (base_build IS NOT NULL))`.
- `CHECK (octet_length(digest) = 32)` und analog für `device_id`, `sbom_digest`.

**Akzeptanzkriterien**
- [ ] Jede Invariante hat einen Negativtest, der den Constraint auslöst.
- [ ] Migration ist vorwärts *und* rückwärts lauffähig.
- [ ] `device_events` ist append-only: kein `UPDATE`/`DELETE`-Grant für die Anwendungsrolle.

---

### UPD-011 — Admission-Gate: host-kompilierter C-Reader im Ingest

**Prio:** P0 · **Typ:** security · **Komp.:** svc · **Aufwand:** M · **Ref:** §7.4

**Problem**
`validateBlock()` in `tools/tbm1/tbm1_encoder.go` ist ein *Spiegel* des C-Readers. Spiegel
driften. Golden Vectors decken das stichprobenartig ab, nicht vollständig.

**Lösung**
Der echte C-Reader (`tbm1_precheck` → `tbm1_validate_regions` → `tbm1_validate_images` aus
`boot_tbm1.c`) ist host-kompilierbar und läuft in der Publish-Pipeline über den **fertigen
Blob**, mit der echten `staging_cap`, `product_id` und `hw_rev` des Zielprofils.

Zusätzlich die vier Regeln, die kein Vorgänger hatte:

1. **Kein Image mit `target_slot == TBM1_SLOT_RECOVERY`.** `stage_swap()` gibt dafür
   unbedingt `BOOT_ERR_NOT_SUPPORTED` zurück — Recovery ist factory-locked. Ein solches
   Artefakt ist garantiert unbrauchbar.
2. **Bei `TBM1_SLOT_STAGE1`: `stage1_svn != 0`**, sonst `BOOT_ERR_INVALID_ARG` im Core.
3. **`min_reader_major/minor` ≤ Reader-Version** aller Geräte im Zielkanal.
4. **`size_bytes` ≤ kleinste `staging_capacity`** im Zielkanal — sonst lehnt
   `toob_ota_begin()` nach dem Download ab.

Ein Artefakt, das hier durchfällt, wird **nicht** gespeichert und nicht assignbar. Kein
Warn-und-trotzdem-publizieren.

**Akzeptanzkriterien**
- [ ] Ein Artefakt mit Recovery-Image wird abgewiesen, mit nennbarem Grund.
- [ ] Ein Artefakt größer als `staging_capacity` des Zielkanals wird abgewiesen.
- [ ] Der C-Reader läuft im CI gegen jedes Testartefakt; ein absichtlich verfälschtes CRC32
      führt zu `TBM1_BAD_CRC` und nicht zu einer Go-seitigen Fehlermeldung.
- [ ] Reject-Grund wird als `tbm1_reject_t` protokolliert, nicht als generischer Fehler.

**Abhängigkeit:** UPD-010.

---

### UPD-012 — SVN-Geländer pro Target-Slot als DB-Invariante

**Prio:** P0 · **Typ:** security · **Komp.:** svc · **Aufwand:** M · **Ref:** §7.3

**Problem**
Ein Artefakt mit zu niedriger SVN zu veröffentlichen, nachdem eine höhere im Feld ist, macht
Geräte dauerhaft unerreichbar für diese Linie: `boot_rollback_verify_svn()` verweigert alles
unterhalb des TMR-Floors, und die eFuse-Epoche ist irreversibel.

Ein **gemeinsamer** Zähler pro Produkt ist zu grob: der Core führt getrennte Floors für
`ROLLBACK_TARGET_APP` (`tmr.app_svn`), `_RECOVERY` (`tmr.svn_recovery_counter`) und
`_STAGE1` (`tmr.stage1_svn`).

**Lösung**
```sql
SELECT max_published_svn FROM product_svn_floor
  WHERE product = $1 AND target_slot = $2 FOR UPDATE;
-- Abbruch wenn new_svn < max_published_svn
UPDATE product_svn_floor SET max_published_svn = GREATEST(max_published_svn, $3)
  WHERE product = $1 AND target_slot = $2;
```

In derselben Transaktion wie das Einfügen des Artefakts. Ein `force`-Pfad existiert, erfordert
aber einen Audit-Eintrag mit Begründung und ist nicht über die normale API erreichbar.

**Akzeptanzkriterien**
- [ ] Publish mit `svn < max_published_svn` schlägt fehl, Artefakt wird nicht gespeichert.
- [ ] App- und Stage-1-Linie beeinflussen sich nicht.
- [ ] Nebenläufiger Publish zweier Artefakte: der Floor ist danach das Maximum, kein Lost Update.
- [ ] `force` ohne Audit-Eintrag ist nicht möglich.

**Abhängigkeit:** UPD-010.

---

### UPD-013 — Artefakt-Store: WORM, Digest-Verifikation nach Upload

**Prio:** P1 · **Typ:** infra · **Komp.:** svc · **Aufwand:** M · **Ref:** §7.4, §13

**Lösung**
- Hetzner Object Storage mit Object Lock (WORM), Schlüssel = `hex(sha256(blob))`.
- **Nach** dem Upload zurücklesen und den Digest verifizieren. Mismatch ⇒ Objekt verwerfen,
  Alarm, kein Katalogeintrag. Derselbe Read-Back-Gedanke wie im Flash-Pfad des Geräts.
- Beim Ausliefern (UPD-023) verifiziert der Store den Digest nicht erneut — das wäre auf dem
  Hot Path zu teuer; die WORM-Garantie trägt.

**Akzeptanzkriterien**
- [ ] Ein manipuliertes Objekt kann nach dem Publish nicht ersetzt werden (Object-Lock-Test).
- [ ] Digest-Mismatch beim Upload ⇒ kein `artifacts`-Eintrag.

---

### UPD-014 — Ingest-API + Release-Pointer

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §5, §7.4

**Lösung**
```
POST /v1/internal/artifacts     # signierter Blob + Metadaten → Admission → Store
POST /v1/internal/releases      # setzt (product, channel) → artifact, atomar
```

Metadaten werden **aus dem signierten TBM1-Header gelesen**, nicht aus der Operator-Eingabe:
`svn`, `product_id`, `hw_rev_min/max`, `key_index`, `build_number`, `fw_ver_*`, `sbom_digest`,
`target_slot`. Das Artefakt ist die Wahrheit über sich selbst; Operator-Eingaben sind
höchstens Plausibilisierung.

`releases_one_active` sorgt dafür, dass ein Channel nie zwei aktive Releases hat.

**Akzeptanzkriterien**
- [ ] Widerspricht eine Operator-Angabe dem Header, wird abgewiesen — nicht die Angabe
      übernommen und nicht der Header überschrieben.
- [ ] Release-Wechsel ist atomar; ein paralleler Check-in sieht entweder das alte oder das
      neue Release, nie keines.

**Abhängigkeit:** UPD-011, UPD-012, UPD-013.

---

### UPD-015 — Signing-Service-Policy

**Prio:** P1 · **Typ:** security · **Komp.:** sign · **Aufwand:** M · **Ref:** §7.2

**Problem**
`SignBlock()` validiert bereits die Struktur und ist damit kein generisches Ed25519-Orakel.
Es fehlt die Policy-Ebene: *welcher Schlüssel darf für welches Produkt signieren.*

**Lösung**
Vor dem Signieren prüfen: erlaubte `product_id`-Menge pro Schlüssel, Konsistenz von
`key_index`/`key_epoch`, und die SVN-Monotonie aus UPD-012 (zweite Verteidigungslinie —
der Signer ist der letzte Punkt, an dem ein Fehler noch billig ist). Jede Signatur wird mit
Antragsteller, Digest und Policy-Entscheidung auditiert.

**Akzeptanzkriterien**
- [ ] Ein Block mit fremder `product_id` wird nicht signiert.
- [ ] Audit-Log enthält für jede Signatur Digest und Entscheidungsgrundlage.
- [ ] Der Update Service hat keinen Netzpfad zum Signer-Schlüssel (Netzwerk-Test).

---

### UPD-016 — Reproduzierbarkeits-Invariante für `build_number`

**Prio:** P2 · **Typ:** infra · **Komp.:** svc · **Aufwand:** S · **Ref:** §8

**Problem**
Deltas werden über `base_build` (= `build_number` der Basis) verschlüsselt, nicht über den
8-Byte `base_fingerprint`. Das ist die schlankere Wahl, setzt aber voraus, dass
`build_number` **1:1 auf Image-Bytes** abbildet. Sonst schlägt der Ghost-Base-Check im SDVM
fehl — nach vollem Download.

**Lösung**
`artifacts_build_unique` erzwingt Eindeutigkeit im Katalog. Zusätzlich beim Ingest: existiert
bereits ein Artefakt mit derselben `(product, build_number, kind='full')` aber anderem Digest,
ist das ein harter Fehler und ein Hinweis auf eine nicht-reproduzierbare Build-Pipeline.

**Akzeptanzkriterien**
- [ ] Zweiter Upload mit gleicher `build_number` und abweichendem Digest wird abgewiesen.
- [ ] Die Anforderung ist in der Build-Doku als Vertrag festgehalten.

---

# EPIC C — Device Gateway (Hot Path)

---

### UPD-020 — Check-in-Endpunkt

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §4.2

**Lösung**
`POST /v1/devices/{device_id_hex}/checkin`, CBOR rein (Diag), CBOR raus (Meta-Map).
Antwort-Keys 1–4 exakt wie vom heutigen `_parse_cbor_manifest()` erwartet; 5–7 und 20 additiv.

Harte Grenzen:
- Request-Body ≤ 1 KiB, sonst `413`.
- Antwort ≤ 512 Byte (Puffergrenze des Clients nach UPD-005). Ein Test erzwingt das.
- Kein Trailing-Byte nach der CBOR-Map — das Gerät prüft `consumed == len`.
- `Cache-Control: no-store`.

**Akzeptanzkriterien**
- [ ] Antwort überschreitet nie 512 Byte, auch mit Key 7 und Key 20 gleichzeitig.
- [ ] Ein Gerät mit Altprotokoll (nur Keys 1–4 verstanden) funktioniert weiter.
- [ ] `204` hat einen leeren Body und trägt trotzdem `Retry-After`.

**Abhängigkeit:** UPD-010, UPD-021, UPD-022, UPD-031.

---

### UPD-021 — Resolver

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §6

**Lösung**
Reine Funktion, nur lesende I/O:

```go
func Resolve(dev Device, obs ObservedState) (*Artifact, Reason, error)
```

Reihenfolge:
1. **Pin** — `assignments.source = 'pin'`. Gewinnt immer.
2. **Channel** — aktives Release für `(dev.product, dev.channel)`.
3. **Kompatibilität** — `dev.hw_rev BETWEEN hw_rev_min AND hw_rev_max`,
   `size_bytes <= dev.staging_capacity`, `min_reader_* <= dev.reader_*`.
4. **Fortschritt** — `artifact.svn >= obs.reported_svn` **und**
   `artifact.build_number != obs.reported_build`.
5. **Delta** (UPD-070), sonst `kind='full'`.

Kein Treffer ⇒ `204`. Kein stiller Fallback auf „irgendein neueres Artefakt".

Der Resolver muss **deterministisch in `device_id`** sein — kein Zufallszug pro Request, sonst
wird die Materialisierung aus UPD-022 zur Lotterie.

**Akzeptanzkriterien**
- [ ] Zwei aufeinanderfolgende Aufrufe mit identischem Input liefern identischen Output.
- [ ] Ein Downgrade wird verworfen, nicht dem Gerät zugemutet.
- [ ] Ein Artefakt größer als die Staging-Kapazität des Geräts wird nie angeboten.
- [ ] Property-Test: für zufällige Geräte/Artefakt-Kombinationen gilt — was der Resolver
      anbietet, besteht `admissible()`.

**Abhängigkeit:** UPD-001 (ohne echte `reported_svn` ist Schritt 4 wirkungslos).

---

### UPD-022 — Lazy Materialisierung + Ein-offene-Zuweisung-Invariante

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §5.2, §5.3

**Problem**
Eine Zuweisung muss stabil sein, sobald sie einem Gerät gezeigt wurde — ein Download über drei
Boots muss dreimal dieselbe Antwort bekommen. Bulk-Materialisierung über eine Million Geräte
pro Rampenschritt ist dafür aber unnötig teuer.

**Lösung**
```
a := open_assignment(device)
if a != null:  return a                 # stabil, keine Neuberechnung, kein Write
art := Resolve(device, obs)             # rein lesend, deterministisch
if art == null: return 204              # Normalfall, kein Write
a := INSERT assignments(...)            # Materialisierung genau hier
```

Die Zuweisung entsteht in dem Moment, in dem sie erstmals gezeigt wird, und ist ab dann
autoritativ. Der Partial-Unique-Index `assignments_one_open` erzwingt genau eine offene
Zuweisung pro Gerät; ein Konflikt ist ein harter Fehler, kein Merge.

**Akzeptanzkriterien**
- [ ] Wechselt der Channel während eines laufenden Downloads, bekommt das Gerät weiterhin die
      alte Zuweisung, bis sie abgeschlossen oder explizit `superseded` ist.
- [ ] Der 204-Pfad erzeugt keinen `assignments`-Eintrag.
- [ ] Nebenläufige Check-ins desselben Geräts erzeugen genau eine Zuweisung
      (Constraint-Test unter Last).

**Abhängigkeit:** UPD-010, UPD-021.

---

### UPD-023 — Blob-Auslieferung

**Prio:** P0 · **Typ:** bug/infra · **Komp.:** svc · **Aufwand:** M · **Ref:** §3.3

**Problem**
Zwei Fehlerklassen korrumpieren das Staging **still**:
- Ein `200` auf einen Range-Request schreibt Byte 0 des Blobs an `resume_offset`.
- Ein CDN, das transparent gzip't, verschiebt Bytegrenzen und zerstört jeden Resume.

Beides fällt erst beim Finalize-SHA auf, nach vollem Download plus Staging-Erase.

**Lösung**
`GET /v1/artifacts/{sha256hex}`:
- `Accept-Ranges: bytes`, `Range: bytes=N-` → `206` mit `Content-Range`.
- **Unerfüllbarer Range ⇒ `416`**, niemals `200` mit Vollinhalt.
- **`identity`-Encoding erzwingen**, kein `Content-Encoding` auf dieser Route.
- **Keine Redirects** — Zephyr `http_client` folgt ihnen nicht zuverlässig; ein `302` wäre ein
  stiller Fehlerpfad quer durch die Flotte.
- `ETag: "<digest>"`, `Cache-Control: public, max-age=31536000, immutable`.
- Unbekannter Digest ⇒ `404`, kein „ähnliches Artefakt".

**Akzeptanzkriterien**
- [ ] `Range: bytes=999999999-` ⇒ `416`, nicht `200`.
- [ ] `Accept-Encoding: gzip` ⇒ Antwort ist trotzdem `identity` (Edge-Konfiguration
      mitgetestet, nicht nur Origin).
- [ ] Kein Response auf dieser Route hat jemals Status `3xx`.
- [ ] Integrationstest: Download in zwei Teilen über `Range` ergibt bitgleich denselben Blob.

**Abhängigkeit:** UPD-013.

---

### UPD-024 — `Retry-After` in jeder Antwort

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §4.2

**Problem**
Geräteseitiger Backoff (`_calculate_backoff_sec`) kann eine Flotte nicht entzerren. Nach einem
regionalen Strom- oder Netzausfall kommen alle Geräte gleichzeitig zurück.

**Lösung**
`Retry-After: <s>` in **jeder** Antwort, inklusive `204` und `5xx`, mit Jitter aus einem
deterministischen Anteil (`H(device_id) mod jitter_window`) plus Basisintervall. Da `204`
keinen Body hat, ist der Header die einzige Quelle — **kein CBOR-Duplikat**, sonst gibt es
zwei Wahrheiten.

**Akzeptanzkriterien**
- [ ] Alle Antwortpfade tragen den Header (Test über die vollständige Statuscode-Matrix).
- [ ] Bei 10 000 simulierten Geräten ist die Poll-Verteilung über das Fenster gleichmäßig.
- [ ] Der Client bevorzugt `Retry-After` gegenüber seinem eigenen Backoff (UPD-004).

**Abhängigkeit:** UPD-002 (Client kann den Header sonst nicht lesen).

---

### UPD-025 — Assignment-Zustandsautomat mit Monotonie-Guard

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §5.1

**Lösung**
Zustände: `assigned → downloading → staged → installing → {confirmed | rolled_back | failed}`,
plus `superseded` aus jedem offenen Zustand.

**`assignment.state` darf nie zurückspringen.** Jeder Zustand bekommt eine Ordinalzahl; ein
verspätet eintreffender `downloading`-Event nach `confirmed` wird verworfen, nicht angewendet.
Übergänge laufen über eine einzige Funktion mit expliziter Erlaubnis-Matrix — kein verstreutes
`state = …`.

**Akzeptanzkriterien**
- [ ] Ein Event, der einen Rückwärtsübergang verlangt, wird verworfen und protokolliert.
- [ ] Jeder Übergang erzeugt genau einen `device_events`-Eintrag.
- [ ] Property-Test: keine Eventreihenfolge führt zu einem ungültigen Zustand.

---

### UPD-026 — Confirm-Inferenz

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §6

**Problem**
Übergänge nach `staged` sind nicht meldbar — das Gerät rebootet. Ein gebricktes Gerät kann
keinen Fehler melden. Der einzige fälschungssichere Erfolgsbeweis ist ein *nachfolgender
Check-in mit dem neuen Build*.

**Lösung**
```
if diag.build_number == want.build_number and diag.booted_partition == APP:
    state = 'confirmed'
elif diag.booted_partition == RECOVERY:
    state = 'rolled_back';  device.health = 'degraded'
elif state == 'installing' and diag.build_number == device.reported_build:
    attempts += 1
    state = (attempts >= MAX_ATTEMPTS) ? 'failed' : 'assigned'
```

Zwei Korrekturen gegenüber dem ursprünglichen Entwurf:
1. Idempotenz über `X-Toob-Seq` (UPD-028), **nicht** über `diag.boot_session_id` — dieser ist
   `tmr.chain_entry_count` und steigt nur bei security-bearing Intents, also nicht auf jedem
   Boot (B2).
2. `attempts` steigt nur, wenn das Gerät **nachweislich mit dem alten Build** zurückkehrt.
   Ohne diese Bedingung zählt jeder Check-in im Zustand `installing` hoch, auch wenn das Gerät
   den Download nur fortsetzt.

**Akzeptanzkriterien**
- [ ] Ein Gerät, das den Download über drei Check-ins fortsetzt, hat danach `attempts == 0`.
- [ ] Boot in Recovery ⇒ `rolled_back` **und** `device.health = 'degraded'`.
- [ ] Erfolgreiches Update ⇒ genau ein `confirmed`-Übergang, auch bei doppeltem Check-in.

**Abhängigkeit:** UPD-001 (kritisch — ohne echten `build_number` läuft die Inferenz blind),
UPD-025, UPD-028.

---

### UPD-027 — Events-Endpunkt

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §4.5

**Lösung**
`POST /v1/devices/{id}/events` → `202`.
`kind ∈ { download_started, download_failed, staged, deferred_power, verify_failed }`.

Events sind **best effort** und nie entscheidungsrelevant: ein Ausfall der Event-Ingestion darf
den Update-Pfad nicht blockieren. Sie sind untrusted Input und beeinflussen in v1 keine
Zuweisung automatisch.

**Akzeptanzkriterien**
- [ ] Event-Endpunkt ausgefallen ⇒ Check-in und Download funktionieren unverändert.
- [ ] Unbekannter `kind` wird verworfen, nicht gespeichert.

---

### UPD-028 — Idempotenz über `X-Toob-Seq`

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §6, B2

**Problem**
Ohne Idempotenzschlüssel führt ein wiederholt zugestellter Check-in (Netz-Retry) zu doppelten
Zustandsübergängen und falschen `attempts`-Werten. `diag.boot_session_id` ist dafür ungeeignet
(B2).

**Lösung**
Header `X-Toob-Seq: <uint64>` aus dem OS-NVS (UPD-003). `seq <= device.last_seq` ⇒
gecachte Antwort zurückgeben, **kein** Zustandsübergang. `last_seq` wird nur bei
tatsächlicher Verarbeitung fortgeschrieben.

**Akzeptanzkriterien**
- [ ] Derselbe Check-in dreimal gesendet ⇒ ein Zustandsübergang, drei identische Antworten.
- [ ] Fehlender Header ⇒ `400`, kein Verarbeiten ohne Idempotenzschlüssel.

**Abhängigkeit:** UPD-003.

---

# EPIC D — Identität & Schlüssel

---

### UPD-030 — Enrollment in `toob provision`

**Prio:** P1 · **Typ:** feature · **Komp.:** cli/svc · **Aufwand:** L · **Ref:** §4.1

**Problem**
Ohne Enrollment kennt der Server weder Produkt, Hardware-Revision, Staging-Kapazität noch
Reader-Version — und der Check-in müsste all das mitschicken, mit entsprechender Angriffsfläche.

**Lösung**
`toob provision` liest bereits per `PROV_CMD_READ_ID` die Chip-UID und brennt den Root-Key. Es
kann `device_id = SHA-256(chip_uid ‖ root_pubkey ‖ "toob-device-id-v1")` deterministisch
berechnen und in einem Zug registrieren:

```
POST /v1/internal/devices
{ device_id, vendor_id, product_id, hw_rev, key_index,
  staging_capacity, reader_major, reader_minor, channel }
→ 201 { device_token }
```

Das Token wird anschließend in den NVS-Bereich des Geräts geschrieben (UPD-003). Bricht der
Vorgang zwischen Registrierung und Token-Write ab, ist das Gerät registriert, aber ohne
Credential — die CLI muss diesen Zustand erkennen und die Registrierung wiederholbar machen
(idempotent über `device_id`).

**Akzeptanzkriterien**
- [ ] Die von der CLI berechnete `device_id` stimmt bitgleich mit `toob_get_device_id()` überein.
- [ ] Wiederholtes Provisioning desselben Chips erzeugt keinen zweiten Datensatz.
- [ ] Abbruch nach Registrierung, vor Token-Write ⇒ erneuter Lauf stellt einen konsistenten
      Zustand her.
- [ ] Ein nicht-enrolltes Gerät bekommt beim Check-in `404` und niemals Firmware.

**Abhängigkeit:** UPD-003, UPD-010.

---

### UPD-031 — Token-Verifikation via HMAC

**Prio:** P1 · **Typ:** security/perf · **Komp.:** svc · **Aufwand:** S · **Ref:** §7.1, §10.3

**Problem**
Argon2id ist für menschliche Passwörter gebaut — niedrige Entropie, niedrige Rate, absichtlich
teuer. Ein Device-Token ist ein 256-Bit-Zufallswert mit voller Entropie; Brute-Force ist
unabhängig von der KDF aussichtslos. Argon2id auf dem Hot Path macht den Check-in dagegen zum
DoS-Verstärker: eine Flotte im Retry-Sturm erzeugt Hunderte Verifikationen pro Sekunde
à ~50 ms CPU.

**Lösung**
Token = `token_id ‖ secret`. Gespeichert wird `HMAC-SHA256(server_key, secret)`; der Vergleich
läuft constant-time über den `token_id`-Index. ~1 µs statt ~50 ms. Kein Salt nötig (volle
Entropie), und `server_key` ist rotierbar, ohne alle Tokens neu auszustellen.

**Akzeptanzkriterien**
- [ ] Benchmark: ≥ 50 000 Verifikationen/s auf einem CX22-Kern.
- [ ] Vergleich ist constant-time (kein `bytes.Equal` auf dem Secret).
- [ ] `server_key`-Rotation invalidiert keine ausgestellten Tokens.

---

### UPD-032 — Server-initiierte Token-Rotation

**Prio:** P2 · **Typ:** security · **Komp.:** svc/sdk · **Aufwand:** M · **Ref:** §7.1

**Lösung**
Key 7 im Check-in-Response trägt ein neues Token. Das Gerät schreibt es in NVS und bestätigt
implizit durch dessen Verwendung beim nächsten Check-in. Der alte Token bleibt für ein Fenster
gültig, damit ein Absturz zwischen Empfang und NVS-Write nicht aussperrt.

**Akzeptanzkriterien**
- [ ] Absturz zwischen Empfang und NVS-Write ⇒ Gerät bleibt erreichbar (Test mit
      simuliertem Reset).
- [ ] Nach erfolgreicher Rotation wird der alte Token nach Ablauf des Fensters abgelehnt.

**Abhängigkeit:** UPD-003, UPD-031.

---

### UPD-033 — Key-Custody-Trennung als Deployment-Grenze

**Prio:** P1 · **Typ:** security · **Komp.:** infra · **Aufwand:** M · **Ref:** §7.2

**Lösung**
Build Service (schlüssellos) → Signing Service (KMS/HSM) → Artifact Store → Update Service
(liest nur). Der Update Service hat **keinen Netzpfad** zum Signer.

**Akzeptanzkriterien**
- [ ] Netzwerk-Test: vom Update-Service-Host ist der Signer nicht erreichbar.
- [ ] Der Update Service hat keine Credentials, mit denen sich ein Artefakt erzeugen ließe.
- [ ] Dokumentierte Blast-Radius-Aussage: kompromittierter Gateway ⇒ Verfügbarkeit,
      nicht Integrität.

---

### UPD-034 — Auth-Pflicht ohne Bypass-Schalter

**Prio:** P0 · **Typ:** security · **Komp.:** svc · **Aufwand:** S · **Ref:** §7.1, P5

**Problem**
Ein `auth_optional`-Schalter für die Entwicklung überlebt erfahrungsgemäß bis in die Produktion.

**Lösung**
Kein Schalter. Ein Request ohne gültigen Token ist `401`. Fehlt die Token-Konfiguration beim
Start, bricht der Dienst ab — er startet nicht im ungesicherten Modus. Für lokale Entwicklung
wird ein echtes Test-Token erzeugt, kein Bypass.

**Akzeptanzkriterien**
- [ ] Es existiert kein Codepfad, der ohne gültigen Token ausliefert (Test über alle Endpunkte).
- [ ] Start ohne Auth-Konfiguration ⇒ Prozessabbruch mit klarer Meldung.

---

# EPIC E — Verschleiß & Fehlerpolitik

---

### UPD-040 — Attempt-Cap als Hardware-Schutz

**Prio:** P1 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §9.2

**Problem**
Jeder Versuch beginnt mit `toob_ota_begin()` → Erase des Staging-Slots über
`ceil(total_size / sector)` Sektoren. Der geräteseitige Backoff deckelt bei
`TOOB_BACKOFF_MAX_SEC = 1800`, also **48 Versuche pro Tag** im Dauerfehlerfall. Bei
`max_erase_cycles = 100 000` ist der Staging-Slot nach ~5,7 Jahren verbraucht — innerhalb der
Auslegungslebensdauer, durch ein einziges dauerhaft fehlschlagendes Artefakt.

**Lösung**
`MAX_ATTEMPTS = 3` pro Assignment. Danach `state = 'failed'`, Artefakt-Flag, kein Re-Serve ohne
Operator-Eingriff. Der Cap gehört serverseitig, weil das Gerät die Historie über Reboots hinweg
nicht kennt.

**Akzeptanzkriterien**
- [ ] Nach dem dritten Fehlversuch liefert der Check-in `204`, nicht dasselbe Artefakt.
- [ ] Ein Operator kann die Zuweisung explizit zurücksetzen.
- [ ] Der Cap gilt pro `(device, artifact)`, nicht global pro Gerät.

---

### UPD-041 — `deferred_power` erhöht `attempts` nicht

**Prio:** P1 · **Typ:** bug · **Komp.:** svc · **Aufwand:** S · **Ref:** §4.5, §9.1

**Problem**
`BOOT_ERR_DEFER` aus `boot_effect_admit_or_defer()` bedeutet Unterspannung oder erschöpftes
Erase-Budget — **kein Fehler**. Zählt der Server das als Versuch, quarantänisiert er Geräte mit
leerem Akku.

**Lösung**
Eigener Event-Typ `deferred_power`, kein `attempts++`, stattdessen längeres `Retry-After`.

**Akzeptanzkriterien**
- [ ] Zehn `deferred_power`-Events hintereinander ⇒ `attempts == 0`, Zuweisung bleibt offen.
- [ ] `Retry-After` ist nach `deferred_power` deutlich länger als im Normalfall.

---

### UPD-042 — Verschleiß-bewusste Auslieferung via `ext_health`

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §9.3

**Problem**
`toob_boot_diag_t` enthält bereits `ext_health` mit `app_slot_erase_count`,
`staging_slot_erase_count` und `swap_buffer_erase_count`, aus dem TMR befüllt und im
CBOR-Telemetrieschema als optionaler Key 20 vorhanden. Niemand wertet das aus.

**Lösung**
Drei Anwendungen, alle ohne Geräteänderung und ohne zusätzlichen Traffic:

1. **Delta-Priorisierung nach Verschleiß** — Geräte mit hohem `staging_slot_erase_count`
   bekommen bevorzugt Deltas (kleinerer Blob, weniger Erase-Sektoren pro Versuch).
2. **Aussteuerung vor der Erschöpfung** — nähert sich ein Zähler `max_erase_cycles`, stellt der
   Resolver die Auslieferung ein und setzt `device.health = 'degraded'`, **bevor**
   `boot_effect_admit_or_defer()` gerätelokal mit `BOOT_ERR_COUNTER_EXHAUSTED` dichtmacht.
   Der Unterschied: der Server weiß es vorher und kann den Betreiber warnen.
3. **Flottenweite Verschleiß-Prognose** als Betriebs- und CRA-Evidenz.

**Akzeptanzkriterien**
- [ ] Ein Gerät oberhalb der Warnschwelle bekommt kein Full-Artefakt mehr angeboten, wenn ein
      Delta existiert.
- [ ] Oberhalb der Sperrschwelle wird gar nichts mehr angeboten und der Betreiber alarmiert.
- [ ] Fehlt `ext_health` (optional im CDDL), gilt das Gerät als unbekannt — nicht als
      verschleißfrei. Fail-Fast statt optimistischer Annahme.

**Abhängigkeit:** UPD-001, UPD-020.

---

### UPD-043 — Fehlertaxonomie + Artefakt-Quarantäne

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §9.1

**Lösung**
Klassifikation gemäß Architektur-Tabelle: transient / deferred / permanent-Artefakt /
permanent-Gerät. Häufen sich permanente Artefakt-Fehler über mehrere Geräte hinweg, wird das
Artefakt automatisch quarantänisiert (nicht mehr assignbar) und der Betreiber alarmiert — ein
defektes Release darf nicht die halbe Flotte durchlaufen.

**Akzeptanzkriterien**
- [ ] Schwellwert-Test: N Geräte melden `verify_failed` für dasselbe Artefakt ⇒ Quarantäne.
- [ ] Quarantäne blockiert neue Zuweisungen, bricht laufende Downloads aber nicht ab.

---

### UPD-044 — `device.health`-Aussteuerung

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §5.1, §9.3

**Lösung**
`healthy | degraded | quarantined`. `degraded` nach Rollback oder nahender
Erase-Erschöpfung — kein Auto-Retry, aber weiterhin Check-ins. `quarantined` wird nur manuell
gesetzt und blockiert jede Auslieferung.

**Akzeptanzkriterien**
- [ ] `degraded` verhindert automatische Neuzuweisung desselben Artefakts.
- [ ] `quarantined` liefert unter allen Umständen `204`.

---

# EPIC F — Performance

---

### UPD-050 — Kohorten-Cache für den 204-Pfad

**Prio:** P2 · **Typ:** perf · **Komp.:** svc · **Aufwand:** M · **Ref:** §10.1

**Problem**
Über die Lebensdauer einer Flotte ist die überwältigende Mehrheit aller Check-ins ein
`204 — kein Update`. Diese Antwort hängt ausschließlich von
`(product, channel, reported_build, hw_rev)` ab, nicht vom einzelnen Gerät.

**Lösung**
In-Process-Cache mit diesem Schlüssel, TTL ~30 s, invalidiert beim Publish eines Release
(UPD-014) und beim Setzen eines Pins. Eine Million täglicher Check-ins kollabiert damit auf
einige Dutzend DB-Abfragen.

Der Cache darf **nur** den 204-Fall und den Assignment-*Kandidaten* halten, nie eine bereits
materialisierte Zuweisung — die ist gerätespezifisch.

**Akzeptanzkriterien**
- [ ] Nach einem Release-Publish liefert kein Gerät mehr eine veraltete 204-Antwort
      (Invalidierungstest).
- [ ] Ein gepinntes Gerät umgeht den Cache.
- [ ] Cache-Hit-Rate > 95 % im Lastprofil aus UPD-053.

---

### UPD-051 — Zero-Write-Hot-Path

**Prio:** P2 · **Typ:** perf · **Komp.:** svc · **Aufwand:** M · **Ref:** §10.1

**Problem**
`UPDATE devices SET last_seen = now()` pro Check-in erzeugt eine Hot-Row-Schreiblast, die genau
dann eskaliert, wenn die Flotte nach einem Ausfall gleichzeitig zurückkommt.

**Lösung**
Telemetrie und `last_seen` gehen in eine Append-Only-Ingest-Tabelle bzw. den Event-Strom und
werden periodisch in `devices` zusammengefasst (Rollup-Job).

**Ziel-Invariante:** Der 204-Pfad ist ein Cache-Lookup plus ein Append. Kein Row-Update, kein
Join, keine Transaktion.

**Akzeptanzkriterien**
- [ ] Ein 204-Check-in erzeugt nachweislich kein `UPDATE` (Query-Log-Assertion im Test).
- [ ] Rollup-Verzögerung ist konfiguriert und dokumentiert; `last_seen` ist explizit als
      „bis zu N Minuten alt" spezifiziert, nicht als exakt.

---

### UPD-052 — Edge-Konfiguration

**Prio:** P2 · **Typ:** infra · **Komp.:** infra · **Aufwand:** S · **Ref:** §10.2, §13

**Lösung**
- Blob-Route: `immutable`, langes TTL, **Origin Cache Lock** (Request-Coalescing) gegen den
  Cache-Miss-Sturm beim ersten Zugriff nach einem Publish.
- Check-in-Route: `no-store`, kein Caching.
- **Keine Komprimierung auf der Blob-Route** (Gegenstück zu UPD-023, hier am Edge erzwungen).

**Akzeptanzkriterien**
- [ ] 10 000 gleichzeitige Erstzugriffe erzeugen genau einen Origin-Request.
- [ ] Edge liefert auf der Blob-Route nie `Content-Encoding: gzip`.

---

### UPD-053 — Lastprofil-Test: Flotten-Rückkehr

**Prio:** P2 · **Typ:** infra · **Komp.:** svc · **Aufwand:** M · **Ref:** §10

**Lösung**
Simulation: 100 000 Geräte kommen innerhalb von 60 s zurück (Regionalausfall). Gemessen wird
Origin-QPS, DB-Verbindungen, p99-Latenz und die Verteilung über das `Retry-After`-Fenster.

**Akzeptanzkriterien**
- [ ] Zwei API-Knoten halten das Profil ohne Fehlerantworten.
- [ ] Die Poll-Verteilung ist nach einem Zyklus gleichmäßig, nicht synchronisiert.
- [ ] Kein DB-Verbindungspool läuft voll.

---

# EPIC G — Naht zum Management-Layer

---

### UPD-060 — Internal-API für Desired State

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §11

**Lösung**
```
PUT    /v1/internal/assignments          # idempotent, bulk
DELETE /v1/internal/assignments/{device_id}
GET    /v1/internal/devices?filter=…     # Observed State als Policy-Input
```

Getrennte Authentifizierung (OIDC/Token), nie über den Geräte-Kanal erreichbar.

**Akzeptanzkriterien**
- [ ] `PUT` ist idempotent: zweimal dieselbe Zuweisung ⇒ ein Datensatz, kein Fehler.
- [ ] Die Internal-API ist vom Geräte-Listener netzwerkseitig getrennt.

---

### UPD-061 — Transactional Outbox + Poller

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** M · **Ref:** §11

**Lösung**
Zustandsübergänge schreiben in derselben Transaktion einen Outbox-Eintrag; ein Poller stellt
sie nach NATS/Webhook zu. Das ist der Punkt, an dem ein Rollout-Layer „Fehlerrate > X % →
Kampagne anhalten" implementiert, ohne die Executor-Datenbank zu pollen.

**Akzeptanzkriterien**
- [ ] Kein Übergang ohne Outbox-Eintrag (Transaktionstest mit induziertem Abbruch).
- [ ] At-least-once-Zustellung mit Dedup-Schlüssel beim Konsumenten.

---

### UPD-062 — Pinning

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §6

**Lösung**
`assignment_source = 'pin'` gewinnt im Resolver immer. Ein Pin überschreibt eine offene
Channel-Zuweisung durch `superseded` — ein gezielter Write, kein flächiger.

**Akzeptanzkriterien**
- [ ] Ein Pin auf ein älteres Artefakt wird trotzdem vom Fortschrittsfilter geprüft und, falls
      es ein Downgrade wäre, abgelehnt — mit klarer Fehlermeldung an den Operator statt stiller
      Wirkungslosigkeit.

---

### UPD-063 — `ramp_bps` / `cohort_seed` als Resolver-Eingabe

**Prio:** P2 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §5.2, §11

**Lösung**
Zwei Felder am Release. Der Resolver wertet
`H(device_id ‖ cohort_seed) mod 10000 < ramp_bps` aus. Deterministisch in `device_id` —
ein Zufallszug pro Request würde die Materialisierung zur Lotterie machen.

Damit ist der gesamte Rollout-Mechanismus vorbereitet, ohne dass der Executor das Wort
„Rollout" kennt: ein Management-Layer setzt zwei Zahlen.

**Akzeptanzkriterien**
- [ ] Dasselbe Gerät bekommt bei unverändertem `ramp_bps` immer dieselbe Antwort.
- [ ] Rampenerhöhung nimmt nie Geräte aus der Kohorte heraus (Monotonie-Test).

---

# EPIC H — Delta (Vorbereitung)

---

### UPD-070 — Delta-Auswahl im Resolver

**Prio:** P3 · **Typ:** feature · **Komp.:** svc · **Aufwand:** S · **Ref:** §8

**Lösung**
```
if exists artifact{kind:delta, product, build_number:target, base_build:obs.reported_build}:
    serve delta
else:
    serve full
```

v1 baut die Spalten und diesen einen `if`, aber **keine Delta-Erzeugungs-Pipeline** — die hängt
am Build Service.

**Akzeptanzkriterien**
- [ ] Existiert kein passendes Delta, wird das Full-Artefakt geliefert (kein Fehler — Delta ist
      eine Optimierung, kein Zustand, der fehlschlagen kann).

---

### UPD-071 — Delta-Admission: exakter `base_build`-Match

**Prio:** P3 · **Typ:** security · **Komp.:** svc · **Aufwand:** S · **Ref:** §8

**Problem**
Ein Delta an ein Gerät mit abweichender Basis wird vom Ghost-Base-Check im SDVM
(`verify_ghost_base`) abgefangen — aber erst nach vollem Download plus Staging-Erase.

**Lösung**
Nur exakter `base_build`-Match. Kein „nächstbester" Treffer, keine Heuristik.

**Akzeptanzkriterien**
- [ ] Ein Gerät mit unbekanntem Build bekommt nie ein Delta.
- [ ] Ein gemeldeter Build, zu dem kein Artefakt im Katalog passt, erzeugt ein
      `unknown_build`-Event (Hinweis auf nicht-autorisierte Firmware im Feld).

---

## Empfohlene Reihenfolge

**Phase 0 — Core-Vorbedingungen (blockierend):**
`UPD-001` → `UPD-002` → `UPD-003`. Parallel und unabhängig: `UPD-006`.
*Gate:* Ein Gerät meldet nach einem Kaltstart reproduzierbar seine echte SVN und Build-Nummer.

**Phase 1 — Labor:**
`UPD-010` → `UPD-011` → `UPD-012` → `UPD-013` → `UPD-014` → `UPD-021` → `UPD-022` →
`UPD-020` → `UPD-023` → `UPD-025` → `UPD-026` → `UPD-028` → `UPD-004` → `UPD-005`.
*Gate:* Ein Gerät durchläuft `assigned → confirmed` reproduzierbar.

**Phase 2 — Auth & Enrollment:**
`UPD-031` → `UPD-034` → `UPD-030` → `UPD-024` → `UPD-040` → `UPD-041` → `UPD-015` → `UPD-033`.
*Gate:* Nicht-enrolltes Gerät bekommt `404`. Kein Codepfad liefert ohne gültigen Token aus.

**Phase 3 — Beobachtbarkeit & Härtung:**
`UPD-007` → `UPD-027` → `UPD-008` → `UPD-042` → `UPD-043` → `UPD-044` → `UPD-032` →
`UPD-016` → `UPD-009`.
*Gate:* Ein Feldfehler ist ohne Geräterücksendung klassifizierbar; Resume überlebt harten Reset.

**Phase 4 — Naht & Performance:**
`UPD-050` → `UPD-051` → `UPD-052` → `UPD-053` → `UPD-060` → `UPD-061` → `UPD-062` → `UPD-063`.
*Gate:* Ein externer Prozess kann Desired State schreiben und Übergänge konsumieren.

**Phase 5 — Delta:**
`UPD-070` → `UPD-071`, nach der Delta-Erzeugung im Build Service.

---

## Architektur-Merksatz für neue Mitarbeiter

Der Update Service ist ein **Reconciliation-Loop** über zwei Zustände: Desired State
(`assignments`, vom Backend) und Observed State (Check-in-Telemetrie, vom Gerät). Er wählt und
liefert — er entscheidet nicht über Vertrauen. Jede Sicherheitsaussage wird gerätelokal
durchgesetzt und hielte auch dann, wenn dieser Dienst in fremder Hand wäre.

Zwei Dinge sind teuer und deshalb nicht verhandelbar: **jeder ausgelieferte Byte, den das Gerät
verwirft**, und **jeder Erase-Zyklus, den es nicht überlebt**. Wer ein Ticket schneidet, das
eines von beidem billigend in Kauf nimmt, hat es falsch geschnitten.