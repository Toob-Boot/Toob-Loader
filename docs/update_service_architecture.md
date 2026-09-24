# Toob Update Service — Architektur v2 (konsolidiert)

**Status:** Verbindlich. Löst `ARCHITEKTUR-update-service.md`, `ARCHITEKTUR-ota-service.md` und
den externen Entwurf ab. Die drei Vorgänger sollten gelöscht oder als `superseded` markiert
werden — mehrere normative Quellen für dieselbe Grenze sind ein Fehler, kein Archiv.

**Rolle:** Der ausführende Dienst zwischen Backend und Gerät. Er entscheidet nicht, *warum* ein
Gerät ein Update bekommt, sondern sorgt dafür, dass ein gefälltes Urteil deterministisch,
brownout-fest, verschleißschonend und auditierbar ankommt.

**Nicht Teil dieses Dokuments:** Flotten, gradual/canary Rollouts, Cohorts, Plugin-Markets.
Diese hängen sich über *eine* Naht an (§11) und sind Schreiber von Desired State, keine
Sonderfälle im Hot Path.

---

## 0. Was gegenüber den Vorgängern geändert wurde

| Entscheidung | Herkunft | Begründung |
|---|---|---|
| Desired/Observed-State als Kernmodell | extern | Beste Rahmung der drei; macht den Executor klein |
| Enrollment bei der Provisionierung | extern | `toob provision` kennt Chip-UID und Root-Key → kann `device_id` berechnen. Der Check-in-Wire wird dadurch minimal |
| Check-in = Diag-CBOR hoch, Meta-Map runter, ein Round-Trip | extern | Nutzt beide bestehenden CBOR-Formate unverändert |
| SVN-Monotonie als DB-Invariante | extern | Der einzige irreversible Fehler gehört nicht in eine Review-Checkliste |
| Attempt-Cap als Hardware-Schutz | extern | Quantifiziert in §9.2 |
| `identity`-Encoding + `416` auf unerfüllbaren Range | extern / v1 | Beide Fehler korrumpieren Staging still |
| Materialisierung **lazy statt bulk** | Synthese | §5.2 — behebt die Schreibverstärkung des externen Entwurfs |
| Blob-Locator: **gebundener Pfad-Suffix**, nicht freie URL | Synthese | §4.4 — eine Pre-Signed-URL passt nicht in den 256-Byte-Puffer |
| Token-Verifikation HMAC statt Argon2id | neu | §7.1 — Argon2id auf dem Hot Path ist ein DoS-Verstärker |
| 204-Antwort als Kohorten-Cache | neu | §10.1 — der Normalfall wird ein reiner Cache-Hit |
| Verschleiß-bewusste Auslieferung via `ext_health` | neu | §9.3 — die Telemetrie liegt bereits vor und wird nirgends genutzt |
| Admission-Gate gegen `TBM1_SLOT_RECOVERY` | neu | §7.4 — der Core lehnt Recovery-Updates *immer* ab |
| SVN-Geländer **pro Target-Slot** | neu | §7.3 — App und Stage-1 haben getrennte SVN-Linien |

---

## 1. Kernprinzip: Desired State vs. Observed State

Zwei Zustände pro Gerät, ein Reconciliation-Loop:

| | Quelle | Autorität |
|---|---|---|
| **Desired State** | `assignments` | Backend (später: Management-Layer) |
| **Observed State** | Check-in-Telemetrie | Gerät |

Zwei Ableitungen tragen den Rest des Designs:

1. **Eine Zuweisung ist stabil, sobald sie einem Gerät gezeigt wurde.** Ein Download über drei
   Boots hinweg muss dreimal dieselbe Antwort bekommen, auch wenn zwischenzeitlich der Channel
   umgestellt wurde. Berechnung-on-read macht Resume rennanfällig und jeden späteren
   Rollout-Layer racy.
2. **Erfolg wird beobachtet, nicht gemeldet.** Ein gebricktes Gerät kann keinen Fehler melden.
   Der einzige fälschungssichere Erfolgsbeweis ist ein *nachfolgender Check-in mit dem neuen
   Build*. Fortschrittsmeldungen sind Operator-Komfort, nie Entscheidungsgrundlage.

---

## 2. Blockierende Befunde am bestehenden Code

Diese stehen vor dem Design, weil das Design auf ihnen aufbaut. Alle drei Vorgänger-Entwürfe
setzen Eigenschaften voraus, die der Code nicht hat.

### B1 — Diag-Telemetrie ist nach einem Kaltstart undefiniert *(kritisch)*

`boot_diag_set_security_meta()` wird **ausschließlich** aus `stage_check_binding()` gerufen —
also nur auf einem Boot, der tatsächlich ein Update durch die Pipeline schiebt. Auf einem
normalen Boot bleiben `current_svn`, `build_number`, `fw_ver_*`, `sbom_digest` und
`active_key_index` unberührt.

`boot_diag_init()` (das zeroisiert) wird in `boot_main.c` nur im Forensik-Zweig gerufen,
also `if (forensic_valid)`. `toob_diag_state` liegt in `.noinit`.

Konsequenz: Nach einem **Kaltstart** enthält die Diag-Struktur undefiniertes RAM, und
`boot_diag_seal()` versieht diesen Zufall am Ende jedes Boots mit einer *gültigen* CRC.
`toob_get_boot_diag()` liefert dann `TOOB_OK` mit Müll.

Das ist kein kosmetisches Problem:

- `toob_network_client.c` setzt `current_svn = diag.current_svn` und schickt das an den Server.
- Ein Gerät kann nach jedem Netzausfall eine zufällige SVN melden. Meldet es einen sehr hohen
  Wert, filtert der Resolver alles weg — das Gerät bekommt **nie wieder** ein Update, still.
- Meldet es 0, lädt es Updates herunter, die es bereits hat.
- Der `sbom_digest` in der CRA-Evidenz ist Zufallsrauschen.

**Fix, ~3 Zeilen** (§12.1). Ohne diesen Fix sind Resolver-Fortschrittsfilter und
Confirm-Inferenz beider Vorgänger-Entwürfe funktionslos.

### B2 — `boot_session_id` ist kein Boot-Zähler

`boot_main.c`: `session_id = tmr.chain_entry_count`. Dieser Zähler wird in
`boot_journal_append()` nur erhöht, wenn `journal_key_valid && wal_intent_is_security_bearing(intent)`
— also nur bei `DEVICE_LOCKED`, `CONFIRM_COMMIT` und `TXN_COMMIT`. Ein eingeschwungener Boot
ohne Update und ohne Confirm hängt keinen Eintrag an.

Der Wert ist damit über beliebig viele Boots hinweg konstant. Eine Idempotenz-Logik der Form
`if diag.boot_session_id <= device.last_session: return cached` verwirft echte neue Check-ins
und friert den Zustandsautomaten ein.

**Konsequenz für das Design:** Der Check-in wird *inhaltlich* idempotent gemacht (§6), und der
Sequenzzähler kommt aus dem OS-NVS, nicht aus der Diag. Kein Core-Change nötig.

### B3 — Resume ist end-to-end nicht verdrahtet

`toob_ota_resume()` liest `toob_handoff_state.resume_offset`. Der Core füllt dieses Feld aus
`WAL_INTENT_DOWNLOAD_CHECKPOINT` (`boot_journal_reconstruct_txn`). Seit der Mailbox-Umstellung
schreibt libtoob keine WAL-Einträge mehr, und `toob_mailbox_wire.h` kennt keinen
Checkpoint-Request. Nichts im gelieferten Code hängt diesen Intent an.

`resume_offset` ist damit konstant 0, `toob_ota_resume()` liefert immer `TOOB_ERR_NOT_FOUND`.
Das Phase-0-Gate des externen Entwurfs („inkl. Resume nach hartem Reset mitten im Download")
ist heute nicht erfüllbar. Lösung in §12.4 — ohne Core-Änderung.

### B4 — `counter_min` erlaubt unbegrenztes eFuse-Brennen

`boot_cloud_cmd_evaluate_buffer()` berechnet `burns_needed = decoded.counter_min - current_counter`
und brennt so oft, ohne Obergrenze. Ein fehlerhaft berechneter Wert verbrennt irreversibel
OTP-Bits. Kein Vorgänger-Entwurf erwähnt das. Für dieses Dokument relevant, weil der
Check-in-Response der natürliche Transportweg für Cloud-Commands ist (§4.3, Key 20).

### B5 — Der Gerätekanal kann weder Header noch POST noch Statuscodes

`rtos_http_get(url, resume_offset, cb, ctx)` ist der einzige Hook. Damit ist unmöglich:
`Authorization`-Header, CBOR-Request-Body, `Retry-After`-Auswertung, und die Unterscheidung
von `204` gegenüber „200 mit leerem Body" (beides ergibt `mbuf.len == 0`).
Ein Entwurf, der Identität in die Query-URL legt, um das zu umgehen, macht das Credential
in jeder Proxy- und CDN-Logzeile sichtbar. Hook-Generalisierung in §12.2.

---

## 3. Gerätevertrag (unveränderlich, der Server richtet sich danach)

### 3.1 Paketformat

```
[ Fixed Header 512 ][ Regions … ][ Ed25519-Sig 64 ][ Image-Payloads @ data_off … ]
                    \______ signiert: [0 .. total_len-64) ______/
```

Die Signatur deckt Header und Regions, **nicht** die Payloads. Payload-Integrität kommt aus den
signierten Chunk-Hashes. Der Server darf Payloads deshalb nie umordnen: `data_off` steht im
signierten Header.

### 3.2 Zwei getrennte Integritätsebenen

| Ebene | Mechanismus | Prüfort |
|---|---|---|
| Transport | SHA-256 über den gesamten gestreamten Blob | `toob_ota_finalize()` |
| Authentizität | Ed25519 + Merkle-Chunk-Hashes aus Flash | Bootloader-Pipeline |

Der Server verantwortet Ebene 1 (er muss den Digest *exakt der ausgelieferten Bytes* kennen)
und transportiert das Ergebnis von Ebene 2. Er ist zu keinem Zeitpunkt Vertrauensinstanz
für die Firmware.

### 3.3 Auslieferungs-Anforderungen

- Artefakte content-adressiert (`sha256(blob)` = Objektschlüssel), immutable.
- `Accept-Ranges: bytes`; `Range: bytes=N-` → `206` mit `Content-Range`.
- **`416` auf unerfüllbaren Range, niemals `200` mit Vollinhalt.** Ein `200` auf einen
  Range-Request schreibt Byte 0 des Blobs an `resume_offset` und korrumpiert das Staging
  still — gefangen erst beim Finalize-SHA, nach vollem Download.
- **Kein `Content-Encoding` auf der Blob-Route.** Ein CDN, das transparent gzip't, verschiebt
  Bytegrenzen und zerstört jeden Resume.
- **Keine Redirects.** Zephyr `http_client` folgt ihnen nicht zuverlässig; ein `302` wäre ein
  stiller Fehlerpfad quer durch die Flotte.
- Starkes `ETag` = Digest, `Cache-Control: public, max-age=31536000, immutable`.

### 3.4 Identität

`device_id = SHA-256(chip_uid ‖ root_pubkey ‖ "toob-device-id-v1")`, 32 Byte, über
`toob_get_device_id()`. Stabil und gerätegebunden, aber **kein Geheimnis** — beide Eingaben
sind öffentlich. Als Credential unbrauchbar.

### 3.5 Anti-Rollback

`boot_rollback_verify_svn()` verweigert jedes Manifest mit
`svn < max(TMR-Floor, eFuse-Epoch)`, getrennt pro Target (`ROLLBACK_TARGET_APP`,
`_RECOVERY`, `_STAGE1`). Der TMR-Floor steigt bei jedem übernommenen Update
(`if (extracted_svn > current_tmr.app_svn)`); die eFuse-Epoche steigt nur über
Cloud-Commands und Rescue-Auth, ist dafür aber irreversibel.

---

## 4. Protokoll

### 4.1 Enrollment findet bei der Provisionierung statt

Die wichtigste Vereinfachung des gesamten Designs. `toob provision` liest per
`PROV_CMD_READ_ID` die Chip-UID und brennt den Root-Key — es kann `device_id` deterministisch
berechnen und in einem Zug den Geräte-Datensatz anlegen:

```
POST /v1/internal/devices
{ device_id, vendor_id, product_id, hw_rev, key_index,
  staging_capacity, reader_major, reader_minor, channel }
→ 201 { device_token }        # einmalig, wird zurück aufs Gerät geschrieben
```

Konsequenzen:

- Der Check-in schickt **keine** Produkt-/HW-Identität — der Server kennt sie.
- Ein nicht-enrolltes Gerät bekommt `404` und niemals Firmware.
- `TBM1_BAD_HW_COMPAT` nach vollständigem Download ist strukturell unmöglich: der Resolver
  filtert `hw_rev BETWEEN hw_rev_min AND hw_rev_max` vor der Zuweisung.
- `staging_capacity` verhindert, dass ein Artefakt angeboten wird, das `toob_ota_begin()`
  mit `TOOB_ERR_INVALID_ARG` ablehnt (`total_size > CHIP_STAGING_SLOT_SIZE`).
- `reader_major/minor` erlaubt die Prüfung des TBM1-`min_reader_*`-Gates serverseitig.

### 4.2 Check-in (der einzige Hot Path)

```
POST /v1/devices/{device_id_hex}/checkin
Authorization: Bearer <device_token>
Content-Type: application/cbor
X-Toob-Seq: <uint64>                  # OS-NVS-Sequenz, Idempotenzschlüssel (B2)

Body: unverändert die Ausgabe von toob_get_boot_diag_cbor()
```

Ein Round-Trip trägt Telemetrie hoch und Desired State runter.

**Antwort 200, CBOR:**

```cddl
toob_checkin_resp = {
    1: uint .size 4,      ; svn
    2: uint .size 4,      ; total_size == artifacts.size_bytes
    3: bstr .size 32,     ; sha256 des Blobs == artifacts.digest
  ? 4: uint .size 1,      ; image_type (TBM1 target_slot des Primär-Images)
    5: tstr .size 1..128, ; blob_path — Pfad+Query, KEIN Host (§4.4)
    6: bstr .size 16,     ; assignment_id
  ? 7: bstr .size 32,     ; rotated_device_token (Server-initiierte Rotation)
  ? 20: bstr              ; Cloud-Command-Envelope (Phase 3, siehe B4)
}
```

Keys 1–4 sind exakt das, was `_parse_cbor_manifest()` heute parst; 5–7 und 20 fallen bei
Altclients durch `zcbor_any_skip()`. Das Protokoll ist konstruktionsbedingt vorwärts- und
rückwärtskompatibel.

**Antwort 204:** leerer Body — der Client behandelt das bereits korrekt als `TOOB_ERR_NOT_FOUND`.

**`Retry-After: <s>` in jeder Antwort**, inklusive `204` und `5xx`. Serverseitig gesteuertes
Polling mit Jitter ist der einzige praktikable Schutz gegen den Thundering Herd nach einem
regionalen Strom- oder Netzausfall; geräteseitiger Backoff allein kann eine Flotte nicht
entzerren. Da `204` keinen Body hat, ist der Header die einzige Quelle — kein CBOR-Duplikat.

### 4.3 Cloud-Commands als optionale Beigabe

Key 20 transportiert ein fertig signiertes Envelope (Ed25519, `counter_min`-Anti-Replay). Der
Update Service **erzeugt** es nie und hält den Schlüssel nicht — er reicht Bytes durch. Der
Server muss dafür den aktuellen eFuse-Zählerstand des Geräts kennen und `counter_min = reported + 1`
setzen; ohne den Deckel aus §12.5 ist das ein Brennrisiko (B4). Deshalb Phase 3, nicht Phase 1.

### 4.4 Download — gebundener Pfad statt freier URL

```
GET  <compiled_in_base><blob_path>
Range: bytes=<resume_offset>-      (optional)
```

Der externe Entwurf schlug eine absolute `blob_url` vor, um Speicherort, Region und
Pre-Signed-URLs serverseitig austauschbar zu halten. Das Argument ist operativ richtig, das
Mittel aber nicht tragfähig:

- `cbor_manifest_buf_t.buf[256]` fasst die **gesamte** CBOR-Antwort. Eine typische
  Pre-Signed-S3-URL ist allein 400–700 Zeichen lang — die Hauptbegründung für das freie
  URL-Feld scheitert genau an dem Fall, für den es gedacht war.
- Ein unbegrenzter, netzkontrollierter String, der den Ziel-**Host** bestimmt, ist auf einem
  MCU die falsche Vertrauensrichtung.

Synthese: Key 5 trägt **Pfad und Query, nie Schema oder Host**, gebunden auf 128 Byte. Der
Host ist einkompiliert und kann vom Netz nicht verändert werden. Regionen, Objektschlüssel-
Migration und kurzlebige Query-Token bleiben damit serverseitig frei; Host-Injection ist
unmöglich. Der Manifest-Puffer wächst auf 512 Byte (OS-seitiges RAM, nicht Bootloader).

> **TODO:** Wenn Firmware-Vertraulichkeit als Produktanforderung dazukommt, ist ein
> Query-Token in Key 5 der vorgesehene Ort. Bis dahin gilt: der Digest ist die einzige
> Zugangsbeschränkung, und Firmware-Geheimhaltung ist **keine** Sicherheitszusage dieses
> Systems.

### 4.5 Events (best effort, nie entscheidungsrelevant)

```
POST /v1/devices/{device_id_hex}/events   → 202
{ assignment_id, kind, bytes_done?, boot_status?, reject_code? }
```

`kind ∈ { download_started, download_failed, staged, deferred_power, verify_failed }`.

`deferred_power` bildet `BOOT_ERR_DEFER` aus `boot_effect_admit_or_defer()` ab (Unterspannung
oder erschöpftes Erase-Budget). Das ist **kein Fehler** und darf `attempts` nicht erhöhen —
sonst quarantänisiert man Geräte mit leerem Akku.

---

## 5. Assignment-Lebenszyklus

### 5.1 Zustände

```
            ┌──────────────► superseded  (durch neue Zuweisung ersetzt)
            │
assigned ─► downloading ─► staged ─► installing ─┬─► confirmed
    │            │            │                  └─► rolled_back ─► device: degraded
    └────────────┴────────────┴─────────────────────► failed
```

`assignment.state` darf **nie zurückspringen**. Jeder Zustand bekommt eine Ordinalzahl; ein
verspätet eintreffender `downloading`-Event nach `confirmed` wird verworfen.

### 5.2 Lazy Materialisierung — die Korrektur am externen Entwurf

Der externe Entwurf materialisiert Zuweisungen und begründet das mit Resume-Stabilität. Das
Argument ist richtig, die Umsetzung „Control Plane schreibt Desired State für alle Geräte"
skaliert aber schlecht: ein Rollout-Schritt über eine Million Geräte ist ein
Millionen-Zeilen-Write, jede Rampenänderung erneut.

Der deterministische Resolver (mein Vorgänger-Entwurf) vermeidet die Schreiblast, ist aber
allein nicht stabil genug: ändert sich die Rampe zwischen zwei Polls, wechselt die Antwort
mitten im Download.

**Synthese — beides, in dieser Reihenfolge:**

```
on checkin(device, obs):
    a := open_assignment(device)
    if a != null:
        return a                          # stabil, keine Neuberechnung, kein Write
    art := Resolve(device, obs)            # rein lesend, deterministisch
    if art == null: return 204             # Normalfall, kein Write (§10.1)
    a := INSERT assignments(...)           # Materialisierung genau hier
    return a
```

Eine Zuweisung entsteht **in dem Moment, in dem sie einem Gerät erstmals gezeigt wird**, und
ist ab dann autoritativ. Kein Bulk-Write, keine Rampenmaterialisierung, aber die volle
Stabilitätsgarantie für Resume und für spätere Rollout-Logik. Ein Rollout-Layer ändert nur die
Eingaben des Resolvers (`ramp_bps`) und, wenn er eine laufende Kampagne stoppen will,
`state = 'superseded'` auf offenen Zuweisungen — ein gezielter Write, kein flächiger.

`Resolve` muss dafür **deterministisch in `device_id`** sein:
`H(device_id ‖ release_id) mod 10000 < ramp_bps`. Ein Zufallszug pro Request würde die
Materialisierung zur Lotterie machen.

### 5.3 Der Partial-Unique-Index ist die Invariante

```sql
CREATE UNIQUE INDEX assignments_one_open ON assignments (device_id)
    WHERE state NOT IN ('confirmed','failed','rolled_back','superseded');
```

Genau eine offene Zuweisung pro Gerät. Ein Konflikt ist ein harter Fehler, kein Merge. Das ist
dieselbe Invariante, die auch für Cloud-Commands gilt: da der eFuse-Zähler bei jedem
verifizierten Command vorrückt, ist eine Warteschlange semantisch sinnlos.

---

## 6. Confirm-Inferenz (korrigiert)

```
on checkin(device, diag, seq):
    if seq <= device.last_seq: return cached_response      # Idempotenz über OS-NVS (B2)
    a := open_assignment(device)
    if a == null: return resolve_and_maybe_assign(device, diag)

    want := artifact(a)
    if diag.build_number == want.build_number and diag.booted_partition == APP:
        a.state = 'confirmed'
    elif diag.booted_partition == RECOVERY:
        a.state = 'rolled_back';  device.health = 'degraded'
    elif a.state == 'installing' and diag.build_number == device.reported_build:
        # Reboot fand statt, altes Build zurück → verworfen oder revertiert
        a.attempts += 1
        a.state = (a.attempts >= MAX_ATTEMPTS) ? 'failed' : 'assigned'
    # sonst: noch nicht angewendet, Zuweisung bleibt offen
```

Zwei Korrekturen gegenüber dem externen Entwurf:

1. Der Idempotenzschlüssel ist `X-Toob-Seq` aus dem OS-NVS, **nicht** `diag.boot_session_id`
   (B2). Das OS schreibt den Zähler ohnehin in denselben NVS-Bereich wie das Device-Token —
   ein Write pro Check-in, also einmal pro Poll-Intervall. Vernachlässigbarer Verschleiß.
2. Der Attempt-Zähler steigt nur, wenn das Gerät **nachweislich mit dem alten Build**
   zurückkehrt. Ohne die zusätzliche Bedingung würde jeder Check-in im Zustand `installing`
   hochzählen, auch wenn das Gerät den Download nur fortsetzt.

**Die gesamte Inferenz hängt an B1.** Vor dem Diag-Fix ist `diag.build_number` auf einem
normalen Boot undefiniert und die Zustandsmaschine läuft blind. Das ist der Grund, warum
§12.1 vor Phase 1 stehen muss und nicht in Phase 2.

---

## 7. Sicherheit

### 7.1 Geräte-Authentifizierung — Token, aber HMAC statt Argon2id

`crypto_hal_t` bietet `verify_signature`, aber **kein `sign`**. Das Gerät kann seine Identität
kryptografisch nicht beweisen; `device_id` ist aus öffentlichen Werten abgeleitet.

| Option | Aufwand | Bewertung |
|---|---|---|
| A: nur TLS, keine App-Auth | 0 | Firmware-Authentizität bleibt intakt, aber Telemetrie ist fälschbar → jede Rollout-Halt-Logik manipulierbar; Flotten-Enumeration möglich |
| **B: Per-Device-Token, bei Provisionierung erzeugt** | gering | Gewählt |
| C: mTLS-Client-Zertifikat | hoch | Key-Storage + CA-Betrieb auf MCU; für die Basis überdimensioniert |
| D: Challenge-Response mit Geräte-Keypair | hoch | Braucht `crypto_hal->sign` + Keygen im Provisioning. Das saubere Endziel |

**B jetzt, D als Roadmap.** Auth nachträglich in eine ausgelieferte Flotte zu retrofitten ist
praktisch unmöglich — der Token muss ab dem ersten produzierten Gerät im Provisioning-Flow
stecken. Kein „auth optional"-Schalter: ein Request ohne gültigen Token ist `401`.

**Korrektur am externen Entwurf: kein Argon2id.** Argon2id ist für menschliche Passwörter
gebaut — niedrige Entropie, niedrige Rate, absichtlich teuer. Ein Device-Token ist ein
256-Bit-Zufallswert mit voller Entropie; ein Brute-Force ist unabhängig von der KDF
aussichtslos. Argon2id auf dem Hot Path macht den Check-in dagegen zum DoS-Verstärker: eine
Flotte im Retry-Sturm erzeugt Hunderte Verifikationen pro Sekunde à ~50 ms CPU.

Gewählt: `token_id ‖ secret`, gespeichert wird `HMAC-SHA256(server_key, secret)`,
Vergleich constant-time über den `token_id`-Index. Konstante Zeit, ~1 µs, kein Salt nötig
(volle Entropie), und der Server-Key ist rotierbar, ohne alle Tokens neu auszustellen.

**Rotation:** Key 7 im Check-in-Response. Der Server initiiert, das Gerät schreibt den neuen
Token in NVS und bestätigt implizit durch dessen Verwendung beim nächsten Check-in. Der alte
Token bleibt für ein Fenster gültig, damit ein Absturz zwischen Empfang und NVS-Write nicht
aussperrt. Kein Cloud-Command nötig — der externe Entwurf verweist hier auf einen Kanal, den
er selbst als out-of-scope erklärt.

### 7.2 Key-Custody

```
Build Service (schlüssellos)  ──unsigned_block──►  Signing Service (KMS/HSM)
        │                                                  │
        └──────────────► Update Service ◄──signed_block─────┘
                          (hält NIE einen Schlüssel)
```

`SignBlock()` validiert vor dem Signieren — der Dienst ist kein generisches Ed25519-Orakel.
Er setzt zusätzlich Policy durch: erlaubte `product_id` pro Schlüssel,
`key_index`/`key_epoch`-Konsistenz, SVN-Monotonie (§7.3). Er ist der letzte Punkt, an dem ein
Fehler noch billig ist.

**Blast Radius:** Ein vollständig kompromittierter Update Service kann Updates zurückhalten,
alte (gültig signierte) Artefakte anbieten und die Flottendatenbank verfälschen. Er kann keine
Firmware fälschen, keinen Downgrade erzwingen (SVN-Floor gerätelokal) und keine fremde
Hardware bespielen (`hw_rev`-Gate im TBM1-Header). Verfügbarkeit, nicht Integrität.

### 7.3 SVN-Geländer — pro Target-Slot

```sql
-- Im Ingest, in einer Transaktion:
SELECT max_published_svn FROM product_svn_floor
  WHERE product = $1 AND target_slot = $2 FOR UPDATE;
-- Abbruch wenn new_svn < max_published_svn (außer explizites force + Audit-Eintrag)
UPDATE product_svn_floor SET max_published_svn = GREATEST(max_published_svn, $3)
  WHERE product = $1 AND target_slot = $2;
```

Der externe Entwurf führt `max_published_svn` als **eine** Spalte auf `products`. Das ist zu
grob: `boot_rollback_verify_svn()` hält getrennte Floors für `ROLLBACK_TARGET_APP`,
`_RECOVERY` und `_STAGE1` (`tmr.app_svn`, `tmr.svn_recovery_counter`, `tmr.stage1_svn`), und
ein Stage-1-Update trägt seine eigene `stage1_svn` im TBM1-Header. Ein gemeinsamer Zähler
würde entweder App-Releases künstlich hochtreiben oder den Stage-1-Floor unterlaufen.

Warum überhaupt eine DB-Invariante: Ein Artefakt mit zu niedriger SVN zu veröffentlichen,
nachdem eine höhere im Feld ist, macht Geräte dauerhaft unerreichbar für diese Linie. Der
TMR-Floor ist theoretisch reparierbar, der eFuse-Floor nicht. Das ist der teuerste denkbare
Fehler des Systems und gehört deshalb in eine Datenbank-Invariante, nicht in eine
Review-Checkliste.

### 7.4 Admission-Gate beim Ingest

Ein Artefakt wird erst assignbar, wenn es alle diese Prüfungen besteht — jede spiegelt ein
Gate, das der Bootloader ohnehin durchsetzt. Der Unterschied ist, wo der Fehler auffällt:
hier kostenlos, dort nach vollem Download plus Staging-Erase.

1. **Host-kompilierter C-Reader** über den fertigen Blob: `tbm1_precheck` →
   `tbm1_validate_regions` → `tbm1_validate_images`, mit der echten `staging_cap`,
   `product_id` und `hw_rev` des Zielprofils. Das schließt die Writer/Reader-Drift, die
   Golden Vectors nur stichprobenartig abdecken.
2. **`sha256(blob)` == angekündigter Digest**, verifiziert *nach* dem Upload in den Store.
3. **SVN-Monotonie** (§7.3).
4. **Kein Image mit `target_slot == TBM1_SLOT_RECOVERY`.** `stage_swap()` gibt für Recovery
   unbedingt `BOOT_ERR_NOT_SUPPORTED` zurück — Recovery ist factory-locked. Ein solches
   Artefakt ist garantiert unbrauchbar und darf nie in den Katalog.
5. **Bei `target_slot == TBM1_SLOT_STAGE1`: `stage1_svn != 0`.** Der Core lehnt sonst mit
   `BOOT_ERR_INVALID_ARG` ab.
6. **`min_reader_major/minor` ≤ Reader-Version** aller Geräte im Zielkanal.
7. **`size_bytes` ≤ kleinste `staging_capacity`** im Zielkanal.

---

## 8. Delta-Pfad

Serverseitig ist ein Delta ein normales, eigenständig signiertes Artefakt mit `kind='delta'`
und `base_build`. Die Auswahl ist ein zusätzlicher Resolver-Schritt:

```
if exists artifact{kind:delta, product, build_number:target, base_build:obs.reported_build}:
    serve delta
else:
    serve full
```

Ein Delta darf **niemals** an ein Gerät gehen, dessen gemeldeter Build nicht exakt `base_build`
entspricht. Kein „nächstbester" Match — der Ghost-Base-Check im SDVM (`verify_ghost_base`)
fängt es zwar ab, aber erst nach vollem Download plus Staging-Erase.

Der externe Entwurf schlüsselt Deltas über `build_number` statt über den 8-Byte
`base_fingerprint`. Das ist die bessere Wahl (kein zusätzliches Feld im Check-in), setzt aber
eine Invariante voraus, die explizit gehalten werden muss: **`build_number` muss 1:1 auf
Image-Bytes abbilden.** Der Unique-Index `artifacts_build_unique` erzwingt das innerhalb des
Katalogs; die Build-Pipeline muss es davor garantieren (reproduzierbare Builds oder
zwangsweise Inkrementierung).

v1 baut die Spalten und den einen `if`, aber **keine Delta-Erzeugungs-Pipeline**. Diese hängt
am Build Service.

---

## 9. Fehlerpolitik & Flash-Verschleiß

### 9.1 Klassifikation

| Klasse | Beispiel | Reaktion |
|---|---|---|
| Transient | Netzabbruch, 5xx, DNS | Zuweisung bleibt offen, `Retry-After` mit Jitter, kein `attempts++` |
| Deferred | `BOOT_ERR_DEFER` (Unterspannung, Erase-Budget) | Eigener Event-Typ, kein Fehler, längeres `Retry-After` |
| Permanent-Artefakt | SHA-Mismatch nach Vollstream, `tbm1_reject_t`, Signaturfehler | `attempts++`; ab `MAX_ATTEMPTS` (3) → `failed`, Artefakt-Flag, kein Re-Serve ohne Operator |
| Permanent-Gerät | Rollback, Boot in Recovery | `rolled_back`, `device.health = degraded`, kein Auto-Retry |

### 9.2 Der Attempt-Cap ist Hardware-Schutz, nicht Bandbreiten-Optimierung

Jeder Versuch beginnt mit `toob_ota_begin()` → Erase des Staging-Slots über
`ceil(total_size / sector)` Sektoren. Der geräteseitige Backoff (`_calculate_backoff_sec`)
deckelt bei `TOOB_BACKOFF_MAX_SEC = 1800`, also **48 Versuche pro Tag** im Dauerfehlerfall.

Bei `max_erase_cycles = 100 000` (ESP32-C6-Manifest) ist der Staging-Slot nach
`100 000 / 48 ≈ 2 083 Tagen ≈ 5,7 Jahren` verbraucht — innerhalb der Auslegungslebensdauer
industrieller Geräte, und das durch ein einziges dauerhaft fehlschlagendes Artefakt.
Ein Server, der stur weiter ausliefert, zerstört Hardware. Der Cap gehört serverseitig, weil
das Gerät die Historie über Reboots hinweg nicht kennt.

### 9.3 Verschleiß-bewusste Auslieferung *(neu, nutzt vorhandene Telemetrie)*

`toob_boot_diag_t` enthält bereits `ext_health` mit `app_slot_erase_count`,
`staging_slot_erase_count` und `swap_buffer_erase_count`, aus dem TMR befüllt
(`boot_main.c` BLOCK 5) und im CBOR-Telemetrieschema als optionaler Key 20 vorhanden.
Kein Vorgänger-Entwurf verwendet diese Daten.

Drei Anwendungen, alle ohne zusätzliche Geräteänderung:

1. **Delta-Priorisierung nach Verschleiß.** Geräte mit hohem `staging_slot_erase_count`
   bekommen bevorzugt Deltas — kleinerer Blob, weniger Erase-Sektoren pro Versuch.
2. **Aussteuerung vor der Erschöpfung.** Nähert sich ein Zähler `max_erase_cycles`, stellt der
   Resolver die Auslieferung ein und markiert `device.health = 'degraded'`, bevor
   `boot_effect_admit_or_defer()` gerätelokal mit `BOOT_ERR_COUNTER_EXHAUSTED` dichtmacht.
   Der Unterschied: der Server weiß es *vorher* und kann den Betreiber warnen.
3. **Flottenweite Verschleiß-Prognose** als Betriebs- und CRA-Evidenz (Produktlebensdauer).

Das ist die günstigste substanzielle Verbesserung im ganzen Dokument: null Geräteänderung,
null zusätzlicher Traffic, und sie adressiert genau die Ressource, die Toob-Boot sonst
überall schützt.

---

## 10. Performance

### 10.1 Der Normalfall ist ein Cache-Hit ohne Write

Über die Lebensdauer einer Flotte ist die überwältigende Mehrheit aller Check-ins ein
`204 — kein Update`. Diese Antwort hängt ausschließlich von
`(product, channel, reported_build, hw_rev)` ab, nicht vom einzelnen Gerät. Also:

- **Kohorten-Cache** im Prozess: Schlüssel `(product, channel, reported_build, hw_rev)`,
  Wert `204 | assignment_candidate`, TTL ~30 s, invalidiert beim Publish eines Release.
  Eine Million täglicher Check-ins kollabiert damit auf einige Dutzend DB-Abfragen.
- **Kein Write auf dem 204-Pfad.** `devices.last_seen` und die Telemetrie gehen in eine
  Append-Only-Ingest-Tabelle bzw. den Event-Strom und werden periodisch in `devices`
  zusammengefasst. Ein `UPDATE devices SET last_seen = now()` pro Check-in erzeugt sonst
  eine Hot-Row-Schreiblast, die genau dann eskaliert, wenn die Flotte nach einem Ausfall
  gleichzeitig zurückkommt.

Ziel-Invariante: **Der 204-Pfad ist ein Cache-Lookup plus ein Append. Kein Row-Update, kein
Join, keine Transaktion.**

### 10.2 Blob-Auslieferung

Der Blob ist vollständig cachebar, der Check-in per Definition `no-store`. Bei einer
gleichzeitig updatenden Flotte laufen ~99,99 % des Volumens über den Edge-Cache und nur das
Zuweisungs-Bit über den Origin — das ist die eigentliche Skalierungsaussage des Designs.

Der erste Zugriff nach einem Publish ist allerdings ein Cache-Miss-Sturm. Zwei Maßnahmen:
**Request-Coalescing** am Edge (Cloudflare: „Origin Cache Lock") und ein per `Retry-After`
gestreutes Poll-Fenster, das die Flotte über die Rampe verteilt statt sie zu synchronisieren.

### 10.3 Token-Verifikation

Siehe §7.1: HMAC statt Argon2id. ~1 µs statt ~50 ms pro Request. Bei 48 Retries/Tag über eine
Million Geräte ist das der Unterschied zwischen zwei API-Knoten und einer Farm.

---

## 11. Naht zum Management-Layer

Der Update Service kennt das Wort „Rollout" nicht. Er exponiert nach innen genau vier Dinge —
das ist der gesamte Vertrag:

```
PUT    /v1/internal/assignments          # idempotent, bulk: setze Desired State (Pins)
DELETE /v1/internal/assignments/{device_id}
GET    /v1/internal/devices?filter=…     # Observed State als Policy-Input
       → Event-Stream (Transactional Outbox)   # Zustandsübergänge als Trigger
```

Die Outbox-Tabelle plus Poller (NATS/Webhook) ist der Punkt, an dem ein Rollout-Layer
„Fehlerrate > X % → Kampagne anhalten" implementiert, ohne die Executor-Datenbank zu pollen.

Zusätzlich, für die lazy Materialisierung (§5.2): der Resolver liest `ramp_bps` und
`cohort_seed` pro Release. Ein Rollout-Layer setzt diese beiden Werte — mehr braucht er nicht.

**Was durch diese Naht nicht durchgereicht wird:** Prozentsätze im Hot Path, Zeitfenster,
Cohort-Definitionen, Abhängigkeitsauflösung. Der Executor sieht immer nur „Gerät → Artefakt".

---

## 12. Erforderliche Core-/SDK-Änderungen

Nach Priorität. Ohne (12.1) ist der gesamte Zustandsautomat blind.

### 12.1 Diag auf jedem Boot befüllen *(kritisch, ~3 Zeilen — behebt B1)*

In `boot_main.c`:

```c
/* Unbedingt, nicht nur im Forensik-Zweig: .noinit ist nach einem Kaltstart
 * undefiniert, und boot_diag_seal() versieht diesen Zufall mit gültiger CRC. */
boot_diag_init();
```

und in BLOCK 5, wo `tmr` ohnehin bereits gelesen ist:

```c
if (boot_journal_get_tmr(platform, &tmr) == BOOT_OK) {
    ...
    /* Auf einem Boot ohne Update läuft stage_check_binding() nie — ohne diese
     * Zeile meldet das Gerät undefinierte SVN/Build-Werte an die Cloud. */
    boot_diag_set_installed_state(tmr.app_svn, tmr.stage1_svn, app_header.build_number);
}
```

Dazu ein neuer Setter in `boot_diag.c`. Der Aufwand ist trivial, die Wirkung nicht: ohne ihn
kann ein Gerät nach einem Netzausfall dauerhaft aus der Update-Versorgung fallen, ohne dass
irgendwo ein Fehler sichtbar wird.

### 12.2 HTTP-Hook generalisieren *(blockierend — behebt B5)*

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

`out_status` ist notwendig, weil der Client heute `204` nicht von „200 mit leerem Body"
unterscheiden kann. `out_retry_after_s` ist notwendig, weil `204` keinen Body hat und der
Header damit der einzige Kanal für serverseitiges Poll-Steering ist.

### 12.3 Device-Credential-Speicher

Ein OS-eigener NVS-Bereich für `device_token` **und** `checkin_seq` (§6). **Nicht** ableitbar
aus Chip-UID oder Root-Key — beide sind öffentlich. Ein NVS-Write pro Check-in, also einmal
pro Poll-Intervall.

### 12.4 Resume ohne Core-Änderung *(behebt B3)*

Der tote WAL-Pfad wird nicht wiederbelebt. Stattdessen ein OS-eigener `.noinit`-Slot, getrennt
vom bootloader-versiegelten `toob_handoff_state` (dessen CRC das OS nicht neu berechnen darf):

```c
typedef struct __attribute__((aligned(8))) {
    uint32_t magic;
    uint32_t bytes_staged;
    uint8_t  artifact_sha256[32];   /* Identität des laufenden Downloads */
    uint8_t  assignment_id[16];
    uint32_t crc32_trailer;
} toob_ota_resume_state_t;
```

Resume nur, wenn Magic und CRC stimmen **und** `artifact_sha256` mit dem Wert aus dem frischen
Check-in übereinstimmt. Sonst Neustart.

Eigenschaften: null Flash-Verschleiß, überlebt WDT-Reset, HardFault und Soft-Reboot — die
häufigsten Abbruchgründe — und überlebt bewusst keinen Stromausfall. Ein flash-persistenter
Checkpoint würde bei einem 1-MB-Image dutzende Sektor-Erases pro Download kosten und damit
genau die Lebensdauer angreifen, die §9 schützt. Die Region gehört als `reserved_ram_regions`-
Eintrag ins Chip-Package (siehe `ARCHITEKTUR-registry-chips.md` §3.1 R5).

### 12.5 `counter_min`-Deckel im Core *(Sicherheit — behebt B4)*

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

Zusätzlich: `decoded.issued_at` wird dekodiert, aber nie geprüft. Ein Freshness-Fenster
schließt die Lücke, dass ein abgefangenes, nie zugestelltes Kommando unbegrenzt gültig bleibt.

### 12.6 Diag v3 — ABI-Bump

Sammelticket, damit die `_Static_assert`-Kette in `libtoob_types.h` genau einmal angefasst
wird. Neue Felder:

| Feld | Zweck |
|---|---|
| `installed_app_svn`, `installed_stage1_svn` | §12.1, Resolver-Fortschrittsfilter |
| `reader_major`, `reader_minor` | `min_reader_*`-Gate serverseitig prüfbar (§7.4) |
| `monotonic_counter` | Sichere `counter_min`-Berechnung (§4.3) |
| `last_update_outcome` | enum: none / applied / rejected / reverted / deferred |
| `last_update_reject` | `tbm1_reject_t` — heute verliert `_handle_update_result()` die feingranulare Ursache, obwohl `boot_tbm1.c` selbst anmerkt, dass genau sie in die Telemetrie gehört |

`_reserved_diag[1]` reicht nicht; `TOOB_DIAG_STRUCT_VERSION` geht auf `0x03000000`, und das
CDDL-Schema wird additiv erweitert.

### 12.7 Kleinbefund

`boot_diag_set_system_status(0, ...)` — `wdt_kicks` ist hart auf 0 verdrahtet. Entweder echt
zählen oder das Feld als reserviert dokumentieren; ein konstant nullwertiges Telemetriefeld
ist schlimmer als keines, weil es Auswertungen vortäuscht.

---

## 13. Infrastruktur

Bewusst identisch zum bestehenden Registry-Stack — kein zweiter Betriebs-Stack:

| Komponente | Wahl | Anmerkung |
|---|---|---|
| API | Go, 2× CX22 (Falkenstein + Helsinki) | zustandslos, hinter Cloudflare |
| DB | Managed PostgreSQL | **eigene Datenbank**, nicht das Registry-Schema |
| Blobs | Hetzner Object Storage, WORM Object Lock | content-adressiert, immutable |
| Edge | Cloudflare | Blob-Route `immutable` + Origin Cache Lock, Check-in `no-store` |
| Signing | isoliert, KMS/HSM | kein Netzpfad vom Update Service zum Schlüssel |

Getrennte Datenbank von der Registry, trotz geteilter Infrastruktur: Registry hält
Paket-Metadaten (selten geschrieben, build-getrieben), Update Service hält Flottenzustand
(pro Gerät pro Boot geschrieben). Unterschiedliche Schreibprofile, unterschiedlicher
Blast Radius.

---

## 14. Phasenplan

| Phase | Inhalt | Gate |
|---|---|---|
| **0 — Core-Vorbedingungen** | §12.1 (Diag-Fix), §12.2 (HTTP-Hook), §12.3 (NVS) | Ein Gerät meldet nach Kaltstart reproduzierbar seine echte SVN und Build-Nummer |
| **1 — Labor** | Schema, Ingest + Admission-Gate (§7.4), Resolver (Channel), Check-in, Blob mit Range/416/identity, Confirm-Inferenz, lazy Materialisierung | Ein Gerät durchläuft `assigned → confirmed` reproduzierbar |
| **2 — Auth & Enrollment** | Provisioning schreibt Device-Record + Token, Token-Pflicht, `Retry-After`, Attempt-Cap, SVN-Geländer | Nicht-enrolltes Gerät bekommt 404. Kein Codepfad liefert ohne gültigen Token |
| **3 — Beobachtbarkeit & Härtung** | Diag v3 (§12.6), Event-Endpunkt, Resume (§12.4), verschleiß-bewusste Auslieferung (§9.3), `counter_min`-Deckel (§12.5) | Ein Feldfehler ist ohne Geräterücksendung klassifizierbar; Resume überlebt harten Reset |
| **4 — Naht** | Internal-API + Transactional Outbox, Pinning, Kohorten-Cache (§10.1) | Ein externer Prozess kann Desired State schreiben und Übergänge konsumieren |
| **5+** | Deltas, Flotten, gradual Rollouts, Plugin-Markets, Cloud-Commands über Key 20 | Bauen ausschließlich auf §11 auf. Kein Umbau am Executor |

---

## 15. Tragende Entscheidungen

1. **Desired vs. Observed State** — der Executor ist ein Reconciliation-Loop, alles andere ist
   Politik, die Desired State schreibt.
2. **Enrollment bei der Provisionierung** — der Server kennt Produkt, HW-Revision,
   Staging-Kapazität und Reader-Version; Inkompatibilität wird vor dem Download ausgefiltert.
3. **Lazy Materialisierung** — Zuweisung entsteht beim ersten Zeigen und ist ab dann
   autoritativ. Stabil wie eine Tabelle, billig wie ein Resolver.
4. **Erfolg wird beobachtet, nicht gemeldet** — der nächste Check-in mit dem neuen Build ist
   der einzige Beweis, den ein gebricktes Gerät nicht fälschen kann.
5. **SVN-Monotonie als DB-Invariante, pro Target-Slot** — der einzige irreversible Fehler
   gehört nicht in eine Review-Checkliste.
6. **Attempt-Cap und Verschleiß-Aussteuerung als Hardware-Schutz** — 5,7 Jahre bis zur
   Zerstörung des Staging-Slots durch ein einziges dauerhaft fehlschlagendes Artefakt.
7. **Der 204-Pfad ist ein Cache-Lookup plus ein Append** — der Normalfall darf die Datenbank
   nicht anfassen.
8. **Host einkompiliert, Pfad vom Server** — operative Freiheit ohne Host-Injection und ohne
   Puffer-Überlauf.
9. **Der Executor kennt keine Rollouts** — eine Naht, vier Endpunkte, kein Sonderfall im
   Hot Path.

---

## Merksatz

> Der Update Service **wählt** und **liefert**. Er entscheidet nicht über Vertrauen.
> Jede Sicherheitsaussage — Echtheit, Anti-Rollback, Hardware-Passung, Integrität — wird
> gerätelokal durchgesetzt und hielte auch dann, wenn dieser Dienst vollständig in fremder
> Hand wäre. Was er zusätzlich leistet, ist Sparsamkeit: er liefert keine Bytes aus, die das
> Gerät ohnehin verwerfen müsste, und keinen Erase-Zyklus, den es nicht überleben würde.