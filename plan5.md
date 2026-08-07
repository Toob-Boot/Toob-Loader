# Toob Identity — Review des Umsetzungsstands

**Prüfgrundlage:** Repository-Export vom 2026-08-07 (498 Dateien, ohne `registry/`)
**Gemessen gegen:** Zielarchitektur v1.0 und Umbau-Backlog v1.0
**Prüftiefe:** `identity/**` vollständig (Dateiinhalte im Export enthalten). `platform/**` teilweise. `policy/**`, `shared/**`, `scripts/**`, `update/**` nur über den Dateibaum und über ihre Verwendung im Identity-Code.

---

## 0. Methodik und Grenzen der Prüfung

Der Export bricht inhaltlich bei `platform/deploy/ansible/roles/ubicloud-db/` ab. Alles, was danach im Dateibaum steht, liegt **nur als Pfadangabe** vor. Betroffen: `policy/*.yaml`, die `.fga`-Modelle, `shared/policy/*.go`, `shared/errors/*`, `shared/metrics/*`, `shared/boundaries_test.go`, die restlichen Ansible-Rollen, Terraform, `scripts/`.

Befunde sind entsprechend markiert:

| Marker | Bedeutung |
|---|---|
| **[belegt]** | Aus dem vorliegenden Quelltext direkt nachweisbar |
| **[abgeleitet]** | Folgt zwingend aus vorliegendem Code + Dateibaum, aber der Gegenpart ist nicht im Export |
| **[prüfen]** | Starker Verdacht, Verifikation am Repo nötig |

Schweregrade: **S1** = nachweislich defekt / blockiert · **S2** = Sicherheitsverlust oder stille Fehlfunktion · **S3** = strukturelle Schuld · **S4** = Hygiene.

**Vorweg die direkte Antwort auf die Ausgangsfrage:** Ja, es gibt erhebliche Doppelungen — TrustLevel, AMR-Menge, Audit-Hashkette, Org-Namensregeln, Enforcement-Kette, Revocation, Problem-Details und HTTP-Middleware existieren jeweils zwei- bis viermal, teilweise mit **abweichender Semantik**. Das ist aber nicht das größte Problem. Das größte Problem ist, dass ein erheblicher Teil des Codes wie eine Implementierung aussieht, aber keine ist, und dass die zugehörigen Tests so gebaut sind, dass sie das nicht auffallen lassen.

---

## 1. Gesamtbild: Umsetzungsgrad gegen den Backlog

| Ticket | Status | Kernbefund |
|---|---|---|
| FND-01 `principal` | 🟡 | Existiert und ist sauber. Aber `token` definiert einen **zweiten** `TrustLevel`. |
| FND-02 Boundary-Test | 🟡 | Datei vorhanden [prüfen]; `.golangci.yml` enthält **keine** Regel für `identity/`. |
| FND-03 Clock | 🟡 | `shared/x/clock` vorhanden und breit genutzt — aber `time.Since()` steht direkt neben `clk.Now()`. |
| FND-04 Fehler-Taxonomie | 🟡 | `ProblemDetails` existiert, wird aber über **drei** Pfade geschrieben, einer davon ohne `Code`. |
| FND-05 Dev-Umgebung | 🟡 | Compose + `just dev-identity` da. Der Seed **druckt nur** und signiert mit einem prozesslokalen Ephemeral-Key. |
| FND-06 Idempotency-Keys | 🔴 | Nicht vorhanden. Keine Middleware, keine Tabelle. |
| FND-07 Layer-Layout | 🟢 | Umgesetzt. |
| STATE-01 Session-Store | 🟡 | Postgres-Store gut gebaut. `BFF` nutzt ihn nicht, hält Sessions in einer Map. |
| STATE-02 Rate-Limit | 🟡 | Valkey-Backend da, aber **nirgends verdrahtet**; Login-Pfad ruft es nie auf; Delay-Kurve still geändert. |
| STATE-03 Kill-Switch | 🟡 | Cache + Postgres-Store da; **kein echter Valkey-Client**, nur `MemoryPubSub`. |
| STATE-04 DPoP-Replay | 🟡 | Vorhanden, aber fail-open bei Redis-Fehler und bei `client == nil`. |
| STATE-05 Event-Dedup | 🟡 | Tabelle `processed_events` existiert — **kein Go-Code liest oder schreibt sie**. |
| STATE-06 Impersonation | 🟡 | Store + `act`-Claim da; parallel dazu ein zweiter Impersonationspfad in `token/exchange.go`. |
| STATE-07 Freigabezustand | 🔴 | Nur die Migration. **Kein Go-Code berührt `release_approvals`.** |
| POL-01…03 Policy-Pipeline | 🟡 | `policygen` erzeugt genau 2 Go-Dateien + 1 Markdown. `endpoints_gen.go`, `gates_gen.go`, `audit_gen.go`, `ratelimit_gen.go` stehen im Baum, werden aber **nicht generiert**. |
| POL-04 Regel-Generierung | 🟡 | Generiert — aber `target/rules.go` ruft die generierten Validatoren **nicht** auf, sondern hat eigene. |
| POL-05 Buildzeit-Vollständigkeit | 🔴 | Nicht vorhanden. Endpunkte werden per Hand registriert. |
| POL-06 Linter | ❓ | `shared/policy/linter.go` existiert [prüfen]. |
| POL-07 Berechtigungsmatrix | 🟡 | Generator schreibt nach `docs/permissions.md` — **`docs/` existiert im Baum nicht**. |
| AUTHZ-01 Betrieb | 🟡 | Nomad-Job + Ansible-Rolle da, mit zwei konkreten Deployment-Fehlern (§ 2.3, § 2.4). |
| AUTHZ-02…05 Modelle | ❓ | `.fga`-Dateien nicht im Export. |
| AUTHZ-06 Store-Provisionierung | 🟢 | Sauber, inkl. SAGA-Kompensation und Fehlerinjektionstests. **Bestes Stück im Repo.** |
| AUTHZ-07 Modell-Rollout | 🔴 | Kein Rollout-Code, keine `authorization_model_id`-Verwaltung. |
| AUTHZ-08 Client | 🟡 | Da, aber ohne Konsistenzparameter, ohne Timeout, ohne Circuit Breaker. |
| AUTHZ-09 Decision-Cache | 🔴 | Nicht vorhanden (`authz/audit.go` ist etwas anderes). |
| AUTHZ-10 Shadow-Mode | 🟢 | Gut gebaut, asynchron, mit Latenztest. |
| AUTHZ-11 Explain | 🟡 | Da, mit Tenant-Guard. Bewertet das Ziel-Subjekt aber mit **erfundenem** TrustLevel. |
| AUTHZ-12 Rebuild | 🟡 | Logik gut. Das CLI ruft sie **nicht** auf (`_ = fga.RebuildDiff{}`). |
| AUTHZ-13 Break-Glass | 🟡 | Dual-Control korrekt. Der Grant wird **nie nach FGA geschrieben** — er verleiht keine Rechte. |
| ZIT-02 Provisioner | 🟡 | Idempotent + Drift-Check, gut. Rollenkatalog aber **in Go hartkodiert** statt aus `policy/`. |
| ZIT-03 Targets | 🟡 | Fail-closed/fail-open korrekt getrennt. Signaturprüfung bei leerem Secret **fail-open**. |
| ZIT-04 JS→Go | 🟡 | JS-Dateien entfernt, 14 Go-Regeln da — aber hartkodiert, mit **abweichenden Grenzwerten**. |
| ZIT-05 Claims/Budget | 🟡 | Größenbudget gut. `mfa` zählt weiterhin als phishing-resistent (Backlog sagte: darf nicht). |
| ZIT-06 Token Exchange | 🟢 | Sauber: Pflicht-`actor_token`, Justification, 4h-Deckel, `act`-Claim. |
| ZIT-07 Device Flow | 🔴 | `PollForToken(ctx, code, isApproved bool)` — **die Sicherheitsentscheidung ist ein Parameter**. |
| ZIT-08 SCIM | 🟡 | Handler da, **ohne jede Authentifizierung**, mit defektem Revocation-URN. |
| ZIT-09 Contract-Tests | 🟡 | Da — laufen aber gegen In-Process-Mocks, nicht gegen eine echte Zitadel-Instanz. |
| ZIT-10 Rotation | 🟢 | KeyRing + Re-Encryption sauber. |
| ZIT-11 Backup-Verifikation | 🟡 | Go-Verifier da; nichts ruft `RecordResult` auf. |
| ENF-01 token neu | 🟡 | Auf `principal` umgestellt. `extractRoles` ist **toter Code** ⇒ Rollen-Bridge fehlt. |
| ENF-02 JWKS `crv` | 🔴 | **Nicht behoben.** `parsePublicKey` verwirft `crv` weiterhin. |
| ENF-03 DPoP | 🟢 | Signaturprüfung, kanonischer Thumbprint, `jti` — vollständig und korrekt. **Aber nirgends verdrahtet.** |
| ENF-04 Stage-1-Gates | 🟡 | Zwei konkurrierende Ketten (`Stage1Chain` + `Pipeline`), kein DPoP-Gate. |
| ENF-05 Generierte Interceptors | 🔴 | Handgeschrieben; `RouteSecurityPolicy` wieder von Hand registriert. |
| ENF-06 RFC 9470 | 🟢 | Header + Body konsistent, mit Contract-Test. |
| ENF-07 BFF | 🟡 | Struktur richtig; Sessions in-memory; CSRF-Token nie an den Client ausgeliefert. |
| ENF-08 Listen-Endpunkte | 🔴 | `ListObjects() []string { return nil }`. `BatchCheck` ist eine `for`-Schleife über Einzelchecks. |
| ENF-09 Latenzbudget | 🟡 | Instrumentierung da; misst unter FakeClock falsch (§ 9.4). |
| SYNC-01…05 | 🟡 | Design gut, aber **nur Memory-Implementierungen**; ein Retry-Bug (§ 2.5). |
| SYNC-06/07/08 | 🟡 | Vorhanden; Deprovisionierung zielt auf einen falschen URN (§ 2.6). |
| CELL-01…10 | 🟡 | Modell sauber. Directory hat **keinen Store**; `SET LOCAL $1` ist ungültiges SQL (§ 2.2). |
| REL-01…06 Release-Governance | 🔴 | **Vollständig abwesend.** Das alte `approval`-Paket wurde gelöscht, der Ersatz nie gebaut. |
| DEV-01…07 PKI | 🟢 | Substanziell und durchdacht. Zwei X.509-Detailfehler (§ 9.6). |
| AUD-01…06 | 🟡 | Ledger + Checkpoints gut. **Zwei inkompatible Hashketten**, Retention hängt an der schwachen. |
| OPS-01…05 | 🟡 | Metriken da. Ausfallmatrix-Tests sind tautologisch (§ 5.2). |
| QA-01…06 | 🔴 | Ein erheblicher Teil der Tests kann konstruktionsbedingt nicht fehlschlagen. |
| CLEAN-01…08 | 🟡 | `roles`, `mirror`, `approval` entfernt ✅. `middleware` **gewachsen statt abgebaut**. Migrationen nicht konsolidiert. |

**Grobbild:** Etwa ein Drittel ist solide gebaut, ein Drittel ist strukturell da, aber nicht angeschlossen, ein Drittel ist Fassade oder fehlt. Der kritische Pfad (Enforcement → AuthZ → DB) ist **nicht durchgängig verdrahtet**: Es gibt keinen einzigen Codepfad, auf dem ein Request von HTTP über Stage-1, FGA, RLS bis zum Audit-Eintrag läuft. Das Gate B aus dem Backlog („Walking Skeleton") wurde nie erreicht — stattdessen wurde in die Breite gebaut.

---

## 2. S1 — Nachweislich defekt

### 2.1 Migration 008 kann nicht laufen · `identity/migrations/008_rls_hardening.up.sql` **[belegt]**

Die Migration referenziert Tabellen und Spalten, die keine Migration anlegt:

| Referenz in 008 | Realität |
|---|---|
| `ALTER TABLE tenant_members …` | Tabelle wird **nirgends** erzeugt |
| `ALTER TABLE outbox_events …` | Tabelle wird **nirgends** erzeugt |
| `revocation_entries.tenant_id` | Spalte fehlt (004 hat sie nicht) |
| `release_approvals.tenant_id` | Spalte fehlt (006 hat sie nicht) |
| `impersonation_sessions.tenant_id` | Spalte fehlt (007 hat `target_org_id`) |
| `CREATE INDEX … release_approvals(tenant_id, id)` | Es gibt keine Spalte `id`; PK ist `release_id` |

Die Migration schlägt beim ersten `ALTER TABLE` fehl. Damit existiert **keine einzige RLS-Policy** im System — die vierte Isolationsschicht der Zielarchitektur ist nicht vorhanden.

Warum das durchgerutscht ist: `celldir/rls_test.go` prüft die Migration per `strings.Contains` gegen `migrations.All[7]`. Der Test liest SQL als Text und führt es nie aus. Er ist grün, während die Migration nicht lauffähig ist.

Zusätzlich: `009` vergibt Rechte an die Rolle `identity_app`, die von keiner Migration erzeugt wird.

▸ *Nebenbefund:* `migrations.All` ist ein `[]string` ohne Version, Name oder Down-Migration, und die Tests indizieren positionsbasiert (`All[7]`, `All[len-1]`). Eine neue Migration bricht zwei Tests, ohne dass ein inhaltlicher Fehler vorliegt.

### 2.2 `SET LOCAL app.tenant_id = $1` ist ungültiges SQL · `identity/celldir/pool.go` **[belegt]**

```go
_, err := tx.ExecContext(ctx, "SET LOCAL app.tenant_id = $1", tenantID)
```

PostgreSQL akzeptiert in `SET` keine Bind-Parameter. Der Aufruf scheitert beim Parsen. Die korrekte Form steht 200 Zeilen entfernt im selben Repo:

```go
// identity/tenant/tenant.go — funktioniert
exec.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", orgID)
```

Es gibt also zwei Implementierungen desselben Mechanismus, und die nicht funktionierende hat die Tests — die allerdings nichts ausführen (§ 5.2).

### 2.3 Portkonflikt: OpenFGA gegen Zitadel/API · `identity/deploy/nomad/jobs/openfga.nomad.hcl` **[belegt]**

```hcl
constraint { attribute = "${meta.pool}"; value = "api" }
network { mode = "host"; port "http" { static = 8080 } }
```

Auf dem `api`-Pool binden bereits Zitadel (`Port: 8080` im Config-Template) und die Registry-API (`reverse_proxy localhost:8080` im Caddyfile) auf 8080. Mit `network_mode = "host"` und statischem Port kann OpenFGA dort nicht starten. Zusätzlich ist `count = 2` ohne `distinct_hosts`-Constraint gesetzt — zwei Allocations auf demselben Host kollidieren miteinander.

Port 8082 („playground") wird exponiert, obwohl `OPENFGA_PLAYGROUND_ENABLED=false`.

### 2.4 Falsches CA-Zertifikat für die OpenFGA-Datenbank · dieselbe Datei **[belegt]**

```
OPENFGA_DATASTORE_URI=postgres://…?sslmode=verify-full&sslrootcert=/etc/ssl/certs/vault-ca.pem
```

Der Job mountet und referenziert die **Vault**-CA. Die Ubicloud-Datenbank wird von der Ubicloud-CA signiert (`common`-Rolle verteilt `/etc/ssl/certs/ubicloud-ca.pem`). `verify-full` schlägt fehl.

### 2.5 Webhook-Retries senden einen leeren Body · `identity/sync/outbound.go` **[belegt]**

```go
req, _ := http.NewRequestWithContext(ctx, POST, recipient.URL, bytes.NewBuffer(event.Payload))
for attempt := 0; attempt <= maxRetries; attempt++ {
    resp, lastErr = d.httpClient.Do(req)   // ← derselbe req, Body nach dem 1. Do konsumiert
```

Der zweite und dritte Versuch POSTen einen leeren Body — mit einer Signatur über den *vollen* Payload. Der Empfänger lehnt sie zwangsläufig ab. Effekt: Jeder Empfänger, der einmal einen transienten Fehler hat, landet garantiert in der DLQ. Der Request muss pro Versuch neu gebaut werden.

### 2.6 SCIM-Deprovisionierung widerruft einen URN, den es nicht gibt · `identity/scim/provider.go` **[belegt]**

```go
principalURN := fmt.Sprintf("toob:human:shared:org_scim:%s", updated.ID)
p.revocation.RevokePrincipal(ctx, principalURN)
```

`org_scim` ist eine erfundene Organisation. Der reale Principal heißt `toob:human:<cell>:<echteOrg>:<id>`. Der Kill-Switch-Eintrag trifft nie. **Die SCIM-Deprovisionierung entzieht faktisch keinen Zugang.**

Im selben Paket baut `scim/deprovision.go` den URN anders (`toob:human:shared:%s:%s` mit echtem Tenant) — also zwei URN-Konstruktionen in einem Paket, eine davon kaputt. Beide umgehen `principal.FormatHumanURN`.

Der Test `TestSCIM_Deprovisioning_RevokesSessionsImmediately` prüft gegen denselben falschen URN und ist deshalb grün.

### 2.7 Ansible-Rolle `zitadel` referenziert gelöschte Dateien · **[prüfen]**

Im Dateibaum sind die 14 JS-Actions unter `platform/deploy/ansible/roles/zitadel/files/` **entfernt** (korrekt nach CLEAN-06). Die Vorgängerversion von `tasks/main.yml` enthielt jedoch elf `copy:`-Tasks auf genau diese Dateien, und `provision-instance-policies.sh` (weiterhin vorhanden) lädt sie hoch. Wurden Task und Skript nicht mitbereinigt, bricht die Rolle beim ersten Lauf.

Der Inhalt von `tasks/main.yml` liegt im Export nicht mehr vor — bitte gezielt prüfen.

---

## 3. S2 — Fail-open: Fehlkonfiguration wird zu erlaubtem Zugriff

Der wichtigste Block. In allen folgenden Fällen führt ein *Verdrahtungsfehler* nicht zu einem Ausfall, sondern zu erlaubtem Zugriff — genau das Gegenteil des Prinzips „fail-fast, keine Default-Fallbacks".

### 3.1 Nil-Chain lässt Requests durch · `identity/middleware/interceptor.go` **[belegt]**

```go
if s.chain == nil {
    slog.Warn("interceptor: Stage1Chain nil, proceeding with default principal extraction")
    next.ServeHTTP(w, r)
    return
}
```

Ein `SecurityInterceptor` ohne Chain lässt **jeden Request unauthentifiziert** an den Handler. Das ist die schwerste Einzelstelle im Repo. Ein vergessener Konstruktor-Parameter öffnet die API.

### 3.2 Unregistrierter Endpunkt ist nicht mehr fail-closed · dieselbe Datei **[belegt]**

```go
policy, hasPolicy := s.registry.Get(endpointID)
…
if hasPolicy { /* Trust-Level und Step-Up setzen */ }
// kein else → weiter mit TrustLevelL1, ohne Step-Up
```

Der Ist-Stand lieferte hier HTTP 500 („CRITICAL SECURITY CONFIGURATION ERROR"). Das ist ersatzlos entfallen. Ein Endpunkt ohne Policy läuft jetzt mit den schwächsten Anforderungen. **Regression gegenüber dem Altsystem.**

Ebenso entfallen: `FleetPolicyRegistry.Register` gibt jetzt immer `nil` zurück — die Duplikat-Erkennung (AUTH-041) existiert nicht mehr. Und `RouteSecurityPolicy.RequiredRole` / `RequiredProductRole` werden gesetzt, aber **nirgends ausgewertet** — die Governance-Rollenprüfung des Altsystems ist verschwunden.

### 3.3 Leeres Webhook-Secret deaktiviert die Signaturprüfung · `identity/target/target.go` **[belegt]**

```go
func (v *SignatureVerifier) VerifySignature(payload []byte, signature string) error {
    if len(v.secretKey) == 0 {
        return nil // No secret configured (dev mode)
    }
```

Eine fehlende Umgebungsvariable macht aus einem authentifizierten Zitadel-Hook einen offenen Endpunkt, über den jeder Login-Entscheidungen beeinflussen kann. „Dev mode" ist keine Eigenschaft, die man aus dem Fehlen eines Wertes ableiten darf — sie gehört in eine explizite Konfiguration.

### 3.4 Fabrizierte Zitadel-Org-IDs · `identity/internal/orgs/orgs.go` **[belegt]**

```go
if m.saClient != nil {
    id, err := m.saClient.CreateOrganization(...)
    zitadelOrgID = id
} else {
    zitadelOrgID = "zitadel-" + normName   // ← erfundene ID
}
```

Zweimal im selben File (Create + ProvisionPersonal). Ein nicht verdrahteter Zitadel-Client führt nicht zum Abbruch, sondern zu einer Organisation mit einer ID, die im IdP nicht existiert. Die anschließende SAGA-Kompensation kann sie folglich auch nicht löschen.

Direkt daneben:
```go
if err := ValidateName(orgName); err != nil { orgName = "user-" + user.ID }
```
Ein ungültiger Username wird still ersetzt statt abgelehnt.

### 3.5 Revocation-Fehler wird als „nicht widerrufen" behandelt · `identity/authz/check.go` **[belegt]**

```go
revoked, err := c.revChecker.IsRevoked(ctx, req.Principal.URN)
if err != nil {
    slog.Warn("…assuming unrevoked with fail-fast audit", …)   // und macht weiter
}
```

Das Log sagt „fail-fast", der Code macht fail-open. Ein Ausfall des Revocation-Stores hebt den Kill-Switch auf.

Verschärfend: `enforce.RevocationChecker` ist als `IsRevoked(urn, orgID string) bool` typisiert — **ohne `error`**. Ein Speicherfehler ist per Signatur nicht von „nicht widerrufen" unterscheidbar. Das ist Fail-open im Interface-Design, nicht nur in der Implementierung.

### 3.6 `storeID = "global"` als Rückfallwert · `identity/authz/check.go`, `explain.go` **[belegt]**

```go
storeID := "global"
if c.resolver != nil && tenantID != "" { … }
```

Ohne Resolver landen **alle Tenants im selben FGA-Store**. Die in ADR-4 begründete Store-per-Tenant-Isolation ist damit von einem Nil-Check abhängig.

### 3.7 DPoP-Replay fällt bei Redis-Fehler offen · `identity/dpop/replay.go` **[belegt]**

```go
set, err := v.client.SetNX(...)
if err != nil { …"failing open"…; return nil }
if v.client == nil { …; return nil }
```

Rate-Limiting darf fail-open (steht so in der Ausfallmatrix). Replay-Schutz nicht — er ist die halbe Wirkung von DPoP.

### 3.8 Kill-Switch startet ohne Store · `identity/revocation/cache.go` **[belegt]**

```go
func (c *RevocationCache) Init(ctx) error {
    if c.store == nil { slog.Info("…skipping DB initial sync"); return nil }
```

Der Test `TestRevocationCache_FailClosedStartup` beweist Fail-closed bei DB-**Fehler**. Bei DB-**Abwesenheit** startet der Prozess mit leerem Cache und meldet Erfolg.

### 3.9 Weitere Fälle **[belegt]**

| Ort | Muster |
|---|---|
| `sync/writer.go` `SaveEvent` | Type-Assertion auf `*MemoryTx`; jede andere `Tx` ⇒ Event **still verworfen**, `return nil` |
| `sync/writer.go` `WriteEvent` | Sequenznummer nur für `*MemoryOutboxStore`; sonst konstant `1` ⇒ Ordering-Garantie still weg |
| `audit/dispatcher.go` | Nicht-kritischer Schreibfehler ⇒ Log „BUFFERED / DEFERRED" — es wird **nichts** gepuffert |
| `audit/ledger.go` `RecordEventAsync` | Ohne Writer/Tx passiert nichts, geloggt wird „AUDIT EVENT RECORDED" |
| `session/session.go` `IsFamilyRevoked` | Unbekannte Familie ⇒ `false` (Altsystem: `true`). Semantik invertiert |
| `celldir/resolver.go` | Ungültiger Fetch-Eintrag wird kommentarlos verworfen, kein Log, kein Fehler |
| `target/rules.go` | `failed_attempts` fehlt ⇒ `0` ⇒ **erlaubt**; `authenticator_count` fehlt ⇒ `0` ⇒ **verboten**. Inkonsistente Default-Semantik bei fehlenden Payload-Keys |
| ~15 Konstruktoren | `if clk == nil { clk = NewSystemClock() }`, `if store == nil { … }`, `if verifier == nil { … }` — jede vergessene Abhängigkeit wird zu stiller Degradation statt zu einem Startfehler |

▸ **Querschnittliche Empfehlung:** Pflichtabhängigkeiten gehören in den Konstruktor **ohne** Nil-Toleranz. Wenn ein `nil` ein Programmierfehler ist, ist `panic` beim Wiring korrekter als eine Ersatzimplementierung zur Laufzeit. Optionalität nur dort, wo sie fachlich begründet ist (z. B. Shadow-Evaluator).

---

## 4. S3 — Duplikate und Divergenzen

Das ist der Teil, den du vermutet hast. Er ist umfangreicher als erwartet, und in vier Fällen weichen die Kopien **inhaltlich** voneinander ab.

### 4.1 TrustLevel — zwei Typen, zwei Skalen **[belegt]**

| Ort | Typ | Werte |
|---|---|---|
| `identity/principal/trustlevel.go` | `type TrustLevel int` | `None=0, L1=1, L2=2, L3=3`, mit `Rank()`, `AtLeast()`, `ParseTrustLevel()` |
| `identity/token/verifier.go` | `type TrustLevel string` | `"L1"`, `"L2"`, `"L3"`, mit eigenem `Rank()`, `AtLeast()`, `IsL3()` |

`middleware/interceptor.go` deklariert `RequiredTrustLevel identityToken.TrustLevel` und konvertiert dann zur Laufzeit:

```go
pTrust, parseErr := principal.ParseTrustLevel(string(policy.RequiredTrustLevel))
if parseErr == nil { req.RequiredTrustLevel = pTrust }
// bei Parse-Fehler: bleibt bei L1 — stille Abschwächung
```

Das ist exakt der Befund F-1 der Ist-Analyse („zwei Ordnungsrelationen"), in neuer Form wieder eingebaut — und jetzt mit einem Konvertierungspfad, der bei Fehlern still das schwächste Level nimmt.

### 4.2 Phishing-resistente AMR-Menge — zwei Listen mit unterschiedlichem Inhalt **[belegt]**

| `identity/token/amr.go` | `identity/federation/customer_idp.go` |
|---|---|
| `webauthn`, `fido2`, `passkey`, `user_presence`, `user_verification` | `phr`, `fido2`, `hwk`, `webauthn`, `pop` |

Drei Werte nur links, drei nur rechts. Ein Kunden-IdP, das `phr` (RFC 8176) liefert, gilt in `federation` als phishing-resistent und im TrustLevel-Pfad als nicht-resistent. Backlog-Ticket ENF-01 forderte wörtlich: „Die Menge phishing-resistenter `amr`-Werte existiert genau einmal im Repo."

Zusätzlich: `token/verifier.go` zählt weiterhin `mfa` mit:
```go
if IsPhishingResistantAMR(str) || strings.EqualFold(str, "mfa") { … }
```
Damit ergibt `["webauthn","mfa"]` weiterhin L3, obwohl das nur *ein* Hardware-Faktor ist. Der Contract-Test `TestContract_TokenFormatAndClaims` **schreibt dieses Verhalten fest** — der Defekt ist jetzt testgeschützt.

### 4.3 Audit-Hashkette — zwei Formate, drei Verifikationen, zwei identische Kopien **[belegt]**

| Ort | Hash-Eingabe |
|---|---|
| `audit/ledger.go` `ComputeCanonicalHash` | kanonisches JSON über `{action, actor, prev_hash, seq, target, tenant, timestamp}` |
| `audit/retention.go` `ComputeAuditLogHash` | `fmt.Sprintf("%s:%s:%s:%s:%s", id, actor, target, action, prevHash)` — **ohne Tenant, Sequenz, Zeitstempel** |
| `sync/deletion.go` `ComputeAuditLogHash` | **byteweise identisch** zu `retention.go` |

`AuditLogRecord` und `PseudonymizePII` sind ebenfalls in `audit/retention.go` und `sync/deletion.go` doppelt vorhanden — identischer Code in zwei Paketen.

Konsequenz für AUD-06: Die Pseudonymisierung baut die **schwache** Kette neu auf. Der Test „Kette bleibt nach Pseudonymisierung intakt" prüft also die schwache Kette, nicht das Ledger. Die eigentliche Anforderung — Pseudonymisierung ohne Bruch der `audit_ledger`-Kette — ist unbewiesen und mit dem aktuellen Format auch nicht erfüllbar, weil `ComputeCanonicalHash` den Zeitstempel einschließt und die Retention-Logik ihn gar nicht kennt.

Kettenverifikation existiert dreimal: `ledger.VerifyTenantChain`, `verifier_cli.VerifyChainWithCheckpoints`, `sync.verifyAuditChainLocked`.

### 4.4 Org-Namensregeln — drei Implementierungen, drei Längenlimits **[belegt]**

| Ort | Länge | Doppelbindestrich | Reserved Names |
|---|---|---|---|
| `internal/orgs/orgs.go` | Regex ⇒ 3–32 (Fehlertext sagt „3-32") | erlaubt | keine |
| `target/rules.go` | 3–63 | verboten | 8 Wörter, hartkodiert |
| `shared/policy/rules_gen.go` (generiert) | aus `policy/rules/org_names.yaml` | konfigurierbar | aus YAML |

`target/rules.go` ist der Zitadel-Hook — also genau der Pfad, den POL-04 auf den generierten Validator umstellen sollte. Er ruft ihn nicht auf. Die Divergenz Go↔IdP aus der Ist-Analyse (F-10) ist damit nicht behoben, sondern **verdreifacht**.

Zusätzlich existieren zwei Regeldateien: `policy/rules/org_names.yaml` (vom Generator gelesen) und `policy/rules/org_naming.yaml` (**tot**).

### 4.5 Enforcement — zwei Ketten, drei HTTP-Middlewares **[belegt]**

| Konstrukt | Interface | Request-Typ | Verwendet von |
|---|---|---|---|
| `enforce.Stage1Chain` | `Gate` | `enforce.Request` | `middleware.SecurityInterceptor`, `enforce.HTTPMiddleware` |
| `enforce.Pipeline` | `PipelineStage` (genau 7) | `enforce.PipelineRequest` | **nur eigene Tests** |

`Request` und `PipelineRequest` sind nahezu feldgleich. Es existiert **keine einzige echte `PipelineStage`-Implementierung** im Repo — die 7-Stufen-Pipeline ist ein reines Testkonstrukt mit Produktions-API.

HTTP-Middlewares: `enforce.HTTPMiddleware(chain)`, `Pipeline.HTTPMiddleware`, `SecurityInterceptor.HTTPInterceptor`/`AutomaticHTTPInterceptor`, `MTLSTerminationMiddleware.HTTPMiddleware`, `BFFHandler.HTTPProxyMiddleware`. Fünf Einstiegspunkte, keine dokumentierte Reihenfolge.

### 4.6 Revocation — vier Konzepte, zwei Stores **[belegt]**

| Ort | Signatur / Zweck |
|---|---|
| `enforce.RevocationChecker` | `IsRevoked(urn, orgID) bool` — kein ctx, kein error |
| `authz.RevocationChecker` | `IsRevoked(ctx, urn) (bool, error)` |
| `scim.RevocationNotifier` | `RevokePrincipal(ctx, urn) error` |
| `pki.DeviceKillSwitchRegistry` | eigener In-Memory-Store für Geräte |

Geräte-Widerrufe laufen über `pki.InMemoryDeviceKillSwitchRegistry` und erreichen den Plattform-Kill-Switch (`identity/revocation`) **nie**. Ein gesperrtes Gerät ist nur auf dem Knoten gesperrt, der den Sperrbefehl entgegengenommen hat.

### 4.7 Impersonation — vier Grenzwerte **[belegt]**

| Ort | Max. Dauer | Min. Begründung |
|---|---|---|
| `impersonation.MaxImpersonationDuration` | 4 h | Pflicht (Länge egal) |
| `token.MaxTokenExchangeLifetime` | 4 h | Pflicht (Länge egal) |
| `target/rules.go` `EvaluateImpersonationAuditRules` | **1 h** | **10 Zeichen** |
| `authz/breakglass.go` | 4 h (240 min) | **15 Zeichen** |
| `shared/policy` `ValidateImpersonationRequest` | aus YAML | aus YAML |

Fünf Definitionen derselben Regel, mindestens zwei nachweislich widersprüchlich.

### 4.8 Weitere Doppelungen **[belegt]**

| Doppelt | Orte |
|---|---|
| `ProblemDetails` schreiben | `serrors.WriteProblemDetails`, `middleware.WriteProblemDetails`, `enforce/interceptor_http.go` (inline, **ohne `Code`**) |
| Tenant-Boundary | `tenant.EnforceTenantBoundary`, `enforce.TenantGate` |
| Tenant-Mismatch-Fehler | `principal.ErrTenantMismatch`, `tenant.ErrCrossTenantAccessForbidden`, `serrors.ErrTenantMismatch`, `authz.ErrTenantStoreNotFound` |
| Zitadel-API-Client | `serviceaccount.Client`, `cmd/zitadel-provision/httpZitadelClient`, `internal/zitadel/client.go` (leerer Stub) |
| `TokenClaims`-Struct | `token/verifier.go` (**tot**), `test/tokens/issuer.go` |
| Audit-Subsysteme | `identity/audit`, `authz/audit.go`, `shared/audit` |
| Prometheus-Regeln | `platform/telemetry/rules/`, `platform/deploy/monitoring/prometheus/rules/` |
| Postgres-Treiber | `lib/pq` (identity) und `pgx` (registry) im selben Modul |

---

## 5. S3 — Scheinimplementierungen

Code, der die Form einer Implementierung hat, aber die Funktion nicht erfüllt. Das ist gefährlicher als fehlender Code, weil es im Review als „erledigt" liest.

### 5.1 Stubs mit Produktions-API **[belegt]**

| Datei | Inhalt |
|---|---|
| `authz/listobjects.go` | `func (c *FGAClient) ListObjects() []string { return nil }` — ohne ctx, ohne Parameter |
| `audit/chain.go` | `type HashChain struct{}` |
| `audit/writer.go` | `type AuditWriter struct{}` |
| `internal/sync/outbox.go` | `type Outbox struct{}` |
| `internal/sync/consumer.go` | `type Consumer struct{}` |
| `internal/scim/mapping.go` | `type SCIMMapping struct{}` |
| `internal/zitadel/client.go` | `type Client struct{}` |
| `cmd/celldir/main.go` | `fmt.Println("Tenant Directory Service")` |
| `deploy/nomad/jobs/celldir.nomad.hcl` | `job "celldir" { type = "service" }` — ohne group/task, von Nomad nicht deploybar |
| `deploy/nomad/jobs/identity-sync.nomad.hcl` | dito |

`internal/sync/*` und `internal/scim/*` sind Platzhalter aus der geplanten Struktur, während die echten Implementierungen in `identity/sync` und `identity/scim` liegen. Sie gehören gelöscht.

`authz.BatchCheckPermissions` ist formal vorhanden, ruft aber `CheckPermission` in einer Schleife — N Netzwerk-Roundtrips statt einem, und bricht beim ersten Fehler ab. Der Zweck von BatchCheck (ENF-08) ist damit nicht erfüllt.

### 5.2 Tests, die konstruktionsbedingt nicht fehlschlagen können **[belegt]**

Das ist der schwerwiegendste Qualitätsbefund, weil er die Aussagekraft der gesamten Suite untergräbt.

**`identity/test/failure/failure_matrix_test.go`** — sechs der neun Szenarien definieren eine Closure im Test und prüfen deren hartkodiertes Verhalten:

```go
// Szenario 3
checkAuthz := func(cacheKey string, isWrite bool) (bool, error) {
    if isWrite { return false, errors.New("openfga: service unreachable (fail-closed)") }
    …
}
allowedWrite, errWrite := checkAuthz("tenant-1:package:write", true)
if errWrite == nil || allowedWrite { t.Errorf(...) }
```

Der Test prüft die Zeile darüber. Kein Produktionscode ist beteiligt. Szenario 4, 6, 7, 8, 9 folgen demselben Muster.

Szenario 6 enthält zusätzlich toten Logikcode:
```go
if err == nil || !errors.Is(err, err) {   // errors.Is(x, x) ist immer true
```

**`identity/celldir/pool_test.go`** — alle drei Tests:
```go
var poolTenantID string = ""       // Konstante deklarieren
if poolTenantID != "" { t.Errorf(...) }   // und prüfen, dass sie leer ist
```
Der eigentliche `ExecInTenantTx` (der ungültiges SQL absetzt, § 2.2) wird nie aufgerufen.

**`identity/test/isolation/isolation_suite_test.go`** — die drei „Isolationsschichten" sind Closures im Test; die Negativtests („Fehlschlag-Nachweis") prüfen, dass eine Funktion ohne Schutz keinen Schutz bietet. Das ist tautologisch.

**`identity/enforce/order_test.go`** — die Spy-Gates heißen `"DPoPGate"`, `"PrincipalGate"`, `"EndpointSecurityGate"`. Diese Typen **existieren nicht**. Der Test prüft die Reihenfolge, in der er selbst seine Spies übergeben hat. Eine Vertauschung der echten Kette kann er nicht erkennen.

**`identity/celldir/rls_test.go`** — `strings.Contains` auf SQL-Text; deckt die Defekte aus § 2.1 nicht auf.

**`identity/celldir/saga_test.go`** — „Crash Recovery" wird simuliert, indem `saga.CompletedSteps` von Hand gesetzt wird. Kein Prozess wird neu gestartet, kein Zustand persistiert (die Engine hält Sagas in einer Map).

▸ **Konsequenz:** Die grüne Suite sagt nichts über Migration 008, über `SET LOCAL`, über die Ausfallmatrix, über die Gate-Reihenfolge und über Crash-Recovery. Diese Tests sollten **entfernt** werden — ein fehlender Test ist ehrlicher als ein Test, der Sicherheit vortäuscht.

### 5.3 CLIs, die nichts tun **[belegt]**

| CLI | Verhalten |
|---|---|
| `cmd/fga-admin` | Druckt Statusmeldungen; `_ = fga.RebuildDiff{}` als einziger Bezug zur Logik. Der `TupleRebuilder` wird nie instanziiert. |
| `cmd/cell-admin` | `switch-tenant` druckt „completed successfully", ohne etwas zu tun |
| `cmd/identity-sync` | Druckt „Daemon starting" und kehrt zurück — kein Loop, kein Server |
| `cmd/celldir` | siehe oben |
| `cmd/identity-seed` | Druckt Tenants, die es nicht anlegt; erzeugt Tokens mit einem **prozesslokalen Ephemeral-RSA-Key** (`getDevKeys()` mit `sync.Once`), die kein laufender Dienst verifizieren kann |

### 5.4 Break-Glass verleiht keine Rechte · `authz/breakglass.go` **[belegt]**

Der Grant wird in einer Map gehalten und enthält `ConditionName`/`ConditionParams` — er wird aber **nie nach OpenFGA geschrieben**. `IsGrantActive(grant, evalTime)` wird von keinem Enforcement-Pfad aufgerufen. Zusätzlich friert `ConditionParams["current_time"]` den Aktivierungszeitpunkt ein, was als Zeitbedingung bedeutungslos ist.

Und: `AuditDispatcherInterface.DispatchCriticalAudit(ctx, tenantID, actor, action, target)` passt **nicht** auf `audit.AuditDispatcher.DispatchAudit(ctx, tx, entry, class)`. Die beiden Komponenten können ohne Adapter nicht verbunden werden — die kritische Audit-Pflicht bei Break-Glass ist unverdrahtet.

### 5.5 Device Flow mit der Entscheidung als Parameter · `device/flow.go` **[belegt]**

```go
func (m *DeviceFlowManager) PollForToken(ctx, deviceCode string, isApproved bool) (*TokenResponse, error) {
    if !isApproved { return nil, ErrAuthorizationPending }
    return &TokenResponse{AccessToken: "toob_at_device_cli_approved_token", …}, nil
}
```

Der Aufrufer teilt mit, ob der Nutzer zugestimmt hat, und bekommt einen konstanten String zurück. `ErrDeviceCodeExpired`, `ErrAccessDenied`, `ErrSlowDown` sind deklariert und ungenutzt. Es gibt keine Zitadel-Anbindung.

---

## 6. Nicht umgesetzte Kernentscheidungen

Diese Punkte sind keine Bugs, sondern fehlende Architekturteile, die die Zielarchitektur tragend gemacht hatte.

### 6.1 Release-Governance existiert nicht mehr **[belegt]**

Das alte `identity/approval`-Paket (Dual-Control, 30-Minuten-Soak, HMAC-Proof, Cancel) wurde gelöscht. Der Ersatz aus REL-01…06 (Signatur-Workflow, 2-of-N, Uptane-Kopplung) wurde **nicht gebaut**. Übrig ist die Migration `006_release_approvals.up.sql`, die keine Zeile Go-Code berührt.

Netto: Die Plattform hat aktuell **keine Release-Freigabelogik**. Gemessen am Ist-Stand ist das ein Funktionsverlust, nicht ein Fortschritt.

### 6.2 Zitadel-Rollen erreichen FGA nicht **[belegt]**

`token/verifier.go` enthält `extractRoles()` — die Funktion wird von `Verify` **nicht mehr aufgerufen** (toter Code, kompiliert, weil Package-Level-Funktionen nicht als unused gelten). `principal.Principal` hat kein Rollenfeld. `authz.CheckRequest.ContextualTuples` muss vom Aufrufer befüllt werden, und niemand tut es.

Damit ist ADR-6 („Zitadel-Rollen als Contextual Tuples") nicht implementiert, und es gibt auch keinen Sync-Pfad, der Rollen als persistierte Tupel schreibt. **Zwischen Zitadel-Rollen und FGA besteht keine Verbindung.**

### 6.3 Konsistenz, Decision-Cache, Timeouts fehlen · `authz/` **[belegt]**

- Kein `consistency.go`. `CheckRequest` hat keinen Konsistenzparameter — ADR/Backlog forderten einen Pflichtparameter.
- Kein Decision-Cache (AUTHZ-09).
- Kein Timeout, kein Circuit Breaker im Client.
- `CheckRequest.Sensitivity` (String) und `IsWriteAction` (bool) werden gesetzt und **nie gelesen** — außer für Logausgaben. Das ist derselbe Defekt wie F-3 der Ist-Analyse (deklarierte, nicht ausgewertete Policy-Felder), nur an neuer Stelle.

### 6.4 Der Permission-Katalog wird generiert, aber nicht konsumiert **[belegt/abgeleitet]**

`policygen` erzeugt eine `PermissionCatalog`-Map mit `MinTrustLevel`, `StepUp`, `Sensitivity`, `Audit`, `Cost`, `ImpersonationAllowed`, `RequiresSignature`. Im Identity-Code findet sich **kein einziger Zugriff** auf `policy.PermissionCatalog` oder `policy.GetPermission`.

Stattdessen:
- Trust-Level und Step-Up kommen aus handregistrierten `RouteSecurityPolicy`-Literalen.
- `Cost` kommt vom Aufrufer (`RateLimitRequest.Cost`).
- `Sensitivity` kommt vom Aufrufer (`CheckRequest.Sensitivity`).
- Die Audit-Klasse kommt als String-Literal (`DispatchAudit(ctx, tx, entry, "critical")`).
- `ImpersonationAllowed` wird von niemandem gelesen — die differenzierte Impersonationsregel aus § 8.4 der Zielarchitektur existiert nicht.

Die Single-Source-of-Truth-Kette ist also gebaut, aber an keinem Ende angeschlossen. Ebenso: `policy/actors.yaml`, `policy/sensitivity.yaml`, `policy/rules/factor_policy.yaml`, `policy/rules/invite.yaml` werden von `policygen` gar nicht gelesen — vier inerte Quelldateien.

### 6.5 DPoP ist implementiert, aber nicht verdrahtet **[belegt]**

`identity/dpop` ist die qualitativ beste Einzelkomponente: RFC-9449-Signaturprüfung, RFC-7638-kanonischer Thumbprint, `jti`-Replay, strikter `htu`-Vergleich. Aber:

- Es gibt kein DPoP-Gate in `enforce/`.
- `enforce.Request.DPoPProof` wird von der Middleware befüllt und von **keinem Gate gelesen**.
- `VerifyTokenBinding` wird außerhalb von Tests nicht aufgerufen.

Der `jkt`-Claim wird auch nirgends aus dem Token extrahiert (`principal.Principal` hat kein `JKT`-Feld). Sender-Constraining ist damit nicht wirksam.

### 6.6 Postgres-Implementierungen fehlen für die tragenden Stores **[belegt]**

| Store | Postgres | Memory |
|---|---|---|
| `session` | ✅ | ✅ |
| `impersonation` | ✅ | ✅ |
| `revocation` | ✅ | (Cache) |
| `sync.OutboxStore` | ❌ | ✅ |
| `scim.UserStore` | ❌ | ✅ |
| `celldir` Tenant Directory | ❌ | Cache only |
| `celldir` Saga-Persistenz | ❌ | Map |
| `authz` Break-Glass-Grants | ❌ | Map |
| `pki` Bootstrap-Invalidierung | ❌ | Map |
| `bff` Sessions | ❌ | Map |

Für die untere Hälfte ist die Memory-Variante die faktische Produktionsimplementierung. Damit ist STATE-01 („kein sicherheitsrelevanter Zustand im Prozessspeicher") in der Sache nicht erreicht — er wurde nur aus einigen Paketen in andere verschoben.

Besonders relevant: `celldir` hat **keinen Store**. `migration.SwitchDirectory` schreibt in den **Cache**:
```go
cache.Evict(tenantID); cache.Set(entry)
```
Nach TTL-Ablauf liefert der Fetcher wieder die alten Koordinaten. Ein Zellumzug hält höchstens eine Cache-Lebensdauer lang. Der Test ist grün, weil er innerhalb der TTL prüft.

### 6.7 Fehlende Querschnittsteile **[belegt]**

- **Kein Idempotency-Key-Mechanismus** (FND-06), obwohl Org-Erstellung und Einladungen ihn brauchen.
- **Keine Buildzeit-Vollständigkeitsprüfung** (POL-05).
- **Kein Modell-Rollout** über Stores (AUTHZ-07).
- **Kein `docs/`-Verzeichnis** im Dateibaum — weder ADRs noch die 24 Runbooks aus dem Altstand. [prüfen: gelöscht oder nur nicht exportiert?] Falls gelöscht: Jeder neue Alarm (FGA-Ausfall, DLQ, Break-Glass, Zell-Bootstrap) ist ohne Runbook.
- **Kein `.github/workflows/`** im Baum. [prüfen]

---

## 7. Regressionen gegenüber dem Ist-System

Punkte, an denen der Umbau hinter den analysierten Altstand zurückfällt.

| # | Altstand | Jetzt |
|---|---|---|
| R1 | Unregistrierter Fleet-Endpunkt ⇒ HTTP 500, fail-closed | Läuft mit L1 ohne Step-Up durch (§ 3.2) |
| R2 | `Register()` verhindert Doppelregistrierung | Gibt immer `nil` zurück |
| R3 | Governance-Rollenhierarchie wird geprüft (`isGovernanceRoleAtLeast`) | `RequiredRole` wird nie ausgewertet |
| R4 | `identity/approval`: Dual-Control + Soak + HMAC-Proof | Ersatzlos entfernt (§ 6.1) |
| R5 | `mirror.Reconciler` erkennt **Rollenänderungen** (Ist≠Soll bei gleichem Key) | `sync.ReconcilerV2` vergleicht nur Key-Präsenz — `ReconcileItem.Value` wird nie verglichen |
| R6 | Progressives Delay 200 ms / 1 s / 5 s / 10 s, mit Test | Kurve auf `500ms · 2^(n-3)` geändert, **ohne Test** auf die Werte |
| R7 | `IsFamilyRevoked` für unbekannte Familie ⇒ `true` | ⇒ `false` (§ 3.9) |
| R8 | JWKS-Offline-Fallback ohne Fremdabhängigkeit | `jwks` importiert jetzt `shared/metrics` und ruft den globalen Monitor **unter gehaltenem Write-Lock** auf (§ 9.5) |
| R9 | 24 Runbooks unter `docs/runbooks/` | Nicht im Baum [prüfen] |

R5 und R6 sind stille Regressionen: Der Code sieht moderner aus, kann aber weniger.

---

## 8. Paketstruktur und Abhängigkeiten

### 8.1 Der Graph ist nicht mehr azyklisch geschichtet **[belegt]**

Die Zielarchitektur legte fest: `principal` unten, alles andere darüber, keine Kanten zum HTTP-Transport. Tatsächlich:

```
audit        ──► sync         (für sync.Tx)
sync         ──► authz        (für authz.TupleKey)
scim         ──► authz
celldir      ──► authz
internal/orgs ──► celldir
middleware   ──► enforce, token, pki, principal
enforce      ──► principal, shared/errors, shared/metrics
jwks         ──► shared/metrics   (globaler Singleton)
```

Damit hängt das Audit-Subsystem transitiv an der Autorisierungs-Engine. Das ist die falsche Richtung: Audit ist eine Querschnittsfunktion und darf von keiner Fachkomponente abhängen. Ursache ist jeweils ein **Typ-Import** (`sync.Tx`, `authz.TupleKey`) — beide gehören in ein neutrales unteres Paket (`identity/principal` bzw. ein neues `identity/dbtx`, `identity/tuple`).

### 8.2 Die Schichtung wird nicht erzwungen **[belegt]**

`.golangci.yml` enthält depguard-Regeln für `shared/`, `platform/`, `update/` — **keine für `identity/`**. Es gibt also weder eine Regel „`identity` darf `registry` nicht importieren" noch „nichts darf `identity/middleware` importieren" noch „`principal` importiert nichts". `shared/boundaries_test.go` existiert [prüfen], deckt laut Namensgebung aber die Layer-Grenzen ab, nicht die Feinschichtung innerhalb von `identity`.

FND-02 verlangte ein deklaratives Regelwerk mit Meta-Test. Ohne das wächst der Graph weiter zu.

### 8.3 Namensgebung erzeugt vermeidbare Verwechslungen **[belegt]**

| Paket | Problem |
|---|---|
| `identity/sync` | Verdeckt das stdlib-Paket. In `sync/jit_test.go` steht bereits `import stdSync "sync"`. Vorschlag: `identity/replication` oder `identity/eventsync`. |
| `identity/device` | Bedeutet „OAuth Device Authorization Grant" (CLI-Login). `identity/pki` bedeutet „physisches Gerät". Zwei Bedeutungen von „Device" nebeneinander. Vorschlag: `identity/deviceflow` oder `identity/clilogin`. |
| `identity/target` | Sagt nicht, worum es geht (Zitadel Actions v2 Hooks). Vorschlag: `identity/zitadelhooks`. |
| `authz/audit.go` vs `identity/audit` vs `shared/audit` | Drei „Audit"-Begriffe: FGA-Entscheidungslog, manipulationsevidentes Ledger, Loki-Alerting. |

### 8.4 Test-Doubles in Produktionspaketen **[belegt]**

`session.MemoryStore`, `scim.MemoryUserStore`, `sync.MemoryOutboxStore`, `sync.MemoryLeaderElector`, `revocation.MemoryPubSub`, `pki.InMemory*`, `ratelimit.MemoryBackend`, `dpop.MemoryReplayStore`, `impersonation.MemoryStore` liegen alle im jeweiligen Produktionspaket. Das ist für Interface-Tests bequem, wird aber gefährlich, wenn — wie hier — für die Hälfte davon **keine** Produktionsvariante existiert (§ 6.6). Es ist dann nicht mehr erkennbar, ob eine Memory-Variante Absicht oder Provisorium ist.

Vorschlag: Memory-Implementierungen nach `…/memstore` oder in `_test`-Dateien verschieben, und für jedes Interface mit Produktionsanspruch eine bewusst leere Datei mit `// TODO(STATE-xx): Postgres implementation` — oder besser: den Konstruktor der Memory-Variante `NewMemoryStoreForTesting` nennen, sodass ein Produktionsaufruf im Review auffällt.

### 8.5 `MemoryLeaderElector` erfüllt sein eigenes Interface nicht **[belegt]**

```go
type LeaderElector interface { AcquireLeader(ctx) (bool, error); … }
func (m *MemoryLeaderElector) AcquireLeader(ctx, instanceID string) (bool, error)  // andere Signatur
```

Das Interface ist unimplementiert und unbenutzt. Zusätzlich nutzt die Memory-Variante **paketglobale Variablen** (`globalLeaderLock`, `globalLeaderHolder`) — alle Instanzen im Prozess teilen sich einen Leader-Zustand, und Tests im selben Paket beeinflussen sich gegenseitig.

---

## 9. Code-Qualität im Detail

### 9.1 Sicherheitsrelevante Entscheidungen als Boolean-Parameter **[belegt]**

```go
impersonation.CanExecuteOperation(ctx, sessionID, isPrivileged bool)
device.PollForToken(ctx, deviceCode, isApproved bool)
federation.ValidateCustomerIdPAuth(amrValues, isPrivileged bool)
pki.ValidateInternalServiceAuth(cert, rawStaticSecret string, …)
```

In allen vier Fällen liefert der Aufrufer das Merkmal, gegen das geprüft werden soll. Das ist keine Prüfung, sondern eine Höflichkeitsfrage. Bei `ValidateInternalServiceAuth` ist es besonders deutlich: Der „Static-Secret-Verbot"-Guard feuert nur, wenn der Aufrufer freiwillig ein Secret übergibt.

Richtig wäre, das Merkmal aus dem Permission-Katalog abzuleiten (`policy.GetPermission(id).Sensitivity`) und nicht aus dem Aufruf.

### 9.2 Secret-Fragment im Log · `pki/workload.go` **[belegt]**

```go
slog.Error("SECURITY ALARM: STATIC SECRET S2S AUTH ATTEMPTED & REJECTED!",
    slog.String("raw_secret_snippet", rawStaticSecret[:min(len(rawStaticSecret), 4)]+"***"))
```

Auch vier Zeichen eines Secrets gehören nicht in ein Log, das nach Loki fließt. Ein Hash-Präfix (`sha256[:8]`) leistet dasselbe für die Korrelation, ohne Material preiszugeben.

### 9.3 Redundante stdlib-Nachbauten **[belegt]**

| Ort | Nachbau |
|---|---|
| `pki/workload.go` | `func min(a, b int) int` — schattet den Builtin seit Go 1.21 (go.mod: 1.26.3) |
| `authz/shadow.go` | `splitColon()` mit `cur += string(val[i])` in einer Schleife — statt `strings.Cut` |
| `sync/writer.go` | `generateUUID()` gefolgt von `hex.EncodeToString([]byte(generateUUID()[:8]))` — nimmt die ersten 8 ASCII-Zeichen der UUID-Darstellung und hext sie erneut. Effektive Entropie: 32 Bit für eine Event-ID. |

### 9.4 Clock-Injektion ist halb durchgeführt **[belegt]**

```go
// authz/check.go
start := c.clk.Now()          // FakeClock
…
duration := time.Since(start) // echte Uhr
```

Unter `FakeClock` ist `duration` die Distanz zwischen fiktiver und realer Zeit — also unbrauchbar, potenziell negativ. Dasselbe Muster in `authz/audit.go`. FND-03 verlangte, dass **keine** Zeitlogik an `time` hängt; die Regel ist nicht durch einen Lint erzwungen und wird verletzt.

### 9.5 Fremdaufruf unter gehaltenem Lock · `jwks/jwks.go` **[belegt]**

```go
func (c *Client) recordFetchError(err error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    …
    metrics.GetLatencyBudgetMonitor().RecordJWKSOutageDuration(c.jwksURL, outageDuration)
```

Ein globaler Singleton wird unter dem Write-Lock des JWKS-Caches aufgerufen. Wenn der Monitor selbst sperrt (Prometheus-Collector tun das), entsteht eine Lock-Ordnung, die niemand dokumentiert hat. Metrik-Aufrufe gehören hinter das `Unlock`.

Ebenso: `celldir/upgrade.go` liest `resolver.Cache().clock` **ohne** den Cache-Mutex (`Cache.clock` ist mutex-geschützt und hat einen `SetClock`-Setter). Data Race.

### 9.6 X.509-Details · `pki/hierarchy.go`, `pki/zero_touch.go` **[belegt]**

1. **Fehlende Pfadlängenbeschränkung.** Die Tenant-Issuing-CA setzt `MaxPathLen: 0` **ohne** `MaxPathLenZero: true`. Go interpretiert das als „Feld nicht vorhanden" — die Tenant-CA darf also Sub-CAs ausstellen. Korrekt: `MaxPathLen: 0, MaxPathLenZero: true`.
2. **Isolation ist eine String-Prüfung.** Die Tenant-Kompromittierungs-Isolation beruht ausschließlich auf `tenantCA.Subject.OrganizationalUnit[0] == expectedTenantID` in Applikationscode. Zertifikatsseitig gibt es keine Name Constraints. Die Garantie ist damit so stark wie der Aufrufer, der `expectedTenantID` übergibt. Für eine als „Compromise Isolation" dokumentierte Eigenschaft ist das zu wenig — `PermittedURIDomains`/Name-Constraints oder Trust-Anchor-per-Tenant wären die kryptografische Form.
3. **RSA-2048 für eine 10-Jahres-Root-CA**, während der Rest des Systems ECDSA nutzt (DPoP, Test-Zertifikate). Uneinheitlich und für die Laufzeit knapp bemessen.
4. **Reihenfolge im Zero-Touch-Tausch.** `ExchangeBootstrapForOperationalCert` stellt erst das operative Zertifikat aus und markiert *danach* das Bootstrap-Zertifikat als verbrannt. Schlägt das Markieren fehl, existiert ein operatives Zertifikat und ein weiterhin gültiges Bootstrap-Zertifikat. Reservieren/Brennen muss vor der Ausstellung atomar passieren.

### 9.7 Trust-Level-Modellfehler bei mTLS · `principal/certificate.go` **[belegt]**

```go
p := &principal.Principal{ …, TrustLevel: TrustLevelL3, … }
```

Jedes gültige Client-Zertifikat erhält L3 — das höchste Vertrauensniveau, das laut Modell „zwei registrierte phishing-resistente Authenticator" bedeutet. Ein Gerät erfüllt damit jedes L3-Gate, das für menschliche Schreiboperationen gedacht war. Zwei unvergleichbare Skalen werden auf eine abgebildet.

Richtiger: Gerätevertrauen ist eine eigene Dimension. Entweder ein separates Feld (`AuthenticatorAssurance` vs. `ChannelBinding`) oder Gates, die zusätzlich auf `ActorType` prüfen.

### 9.8 Weitere Punkte **[belegt]**

| Ort | Befund |
|---|---|
| `token/verifier.go` | Wenn `sub` nicht mit `toob:` beginnt, wird ein URN **fabriziert**: `toob:human:shared:<org>:<sub>` — Zelle hartkodiert „shared", ActorType hartkodiert „human". Service-Accounts und Workloads werden als Menschen geführt. |
| `token/verifier.go` | `TokenClaims`, `extractRoles` — toter Code |
| `token/rotation.go` | `KeyRing.clk` gesetzt, nie benutzt; `ReencryptPayload(ctx, …)` — ctx ungenutzt |
| `enforce/pipeline.go` | HTTP-Status wird per `strings.Contains(err.Error(), "AuthZ")` bestimmt — String-Matching auf Fehlermeldungen neben einer existierenden Typ-Taxonomie |
| `enforce/interceptor_http.go` | `ProblemDetails` ohne `Code` — bricht den FND-04-Contract auf diesem Pfad |
| `principal/context.go` | `MustFromContext` **panict**. In einem HTTP-Pfad ist das ein DoS-Vektor; `mtls_termination_test.go` nutzt es bereits |
| `bff/bff.go` | `ValidateSessionAndCSRF` nutzt `Lock()` mit vier verstreuten `Unlock()`-Aufrufen statt `defer`; CSRF-Token wird nie an den Client ausgeliefert (kein Cookie, kein Endpunkt) — der Flow ist unvollständig |
| `scim/handler.go` | **Keine Authentifizierung**, kein Tenant-Pfadsegment (`/scim/v2/{orgId}` aus der Planung fehlt) |
| `scim/provider.go` | Idempotenz per Lookup-dann-Create ohne Unique-Constraint (racy); Treffer auf **E-Mail** liefert den bestehenden Account auch bei abweichender `externalId` → Account-Übernahme durch ein fremdes IdP |
| `sync/consumer.go` | `time.Sleep(backoff)` ignoriert `ctx`; Retries blockieren den ganzen Batch; DLQ-Events werden zusätzlich als `processed` markiert ⇒ bei Neustart **Datenverlust** |
| `sync/outbound.go` | `RotateRecipientSecret` ersetzt das Secret ohne Überlappungsfenster — in-flight-Zustellungen schlagen fehl (dieselbe Anforderung wird in `token/rotation.go` korrekt gelöst) |
| `authz/audit.go` | `DenialSpikeDetector`-Map wächst pro eindeutigem Subjekt unbegrenzt; nur prozesslokal, erkennt verteilte Angriffe nicht |
| `ratelimit/limiter.go` | `Backend` mischt Quota (`Allow`) und Login-Zähler (`RecordLoginFailure/Success`) — Interface-Segregation verletzt; `MultiLimiter` nutzt nur `Allow`, die Login-Methoden ruft **niemand** auf |
| `audit/checkpoint.go` | Feld heißt `PublicKeyPEM`, enthält aber base64-kodiertes Rohmaterial. Mit einem echten Vault-Transit-Key (der PEM liefert) bricht die Verifikation |
| `identity/migrations/002,003` | `CREATE TABLE audit_chain (id UUID PRIMARY KEY)` und `tenant_directory (id UUID PRIMARY KEY)` — Platzhalter, die niemand nutzt; die echten Tabellen heißen anders |
| `coverage` (Repo-Root) | Committetes Coverage-Artefakt, das auf `shared/identity/token/verifier.go` verweist — einen Pfad, den es nicht mehr gibt. Nicht in `.gitignore` |

---

## 10. DevOps und Infrastruktur

### 10.1 Secrets im Klartext · `.env.dev`, `.env.staging` **[belegt]**

Beide Dateien enthalten produktionsnahe Zugangsdaten: Hetzner-Token, Ubicloud-PAT, Cloudflare-Token, DockerHub-PAT, S3-Keys, GitHub-App-Key-Pfad, Grafana-Passwort. `.gitignore` deckt `.env.*` ab — die Dateien liegen also vermutlich nur lokal, sind aber in einem Export gelandet und damit faktisch verteilt. **Alle darin enthaltenen Credentials sind als kompromittiert zu behandeln und zu rotieren.**

Zwei konkrete Fehler in den Dateien selbst:

```
SEED_GH_CLIENT_ID=4411e74466e6794fa80ccf69fdfcdc8e5735ef8c
SEED_GH_CLIENT_SECRET=4411e74466e6794fa80ccf69fdfcdc8e5735ef8c   ← identisch
```
Die GitHub-OAuth-Integration kann so nicht funktionieren.

```
.env.dev:      …hwUYlhw3GQyue6JU0hpD
.env.staging:  …hwUYlhw3GQvue6JU0hpD     ← ein Zeichen Unterschied
```
Vermutlich ein Tippfehler beim Kopieren; eine der beiden Umgebungen hat ein ungültiges Hetzner-Token.

### 10.2 `justfile` zeigt auf nicht mehr existierende Pfade **[belegt]**

| Target | Referenz | Realität |
|---|---|---|
| `plan-tf` / `apply-tf` | `deploy/terraform/{{dir}}` | Terraform liegt unter `platform/deploy/terraform/` |
| `plan-app` | `deploy/nomad/*.nomad.hcl` | Jobs liegen unter `registry/deploy/nomad/jobs/` und `identity/deploy/nomad/jobs/` |
| `deploy` | `deploy/api/deploy.sh` | Existiert nicht |
| `test-integration` | `./test/integration/...` | Pfad existiert nicht (jetzt `registry/test/integration`) |
| `destroy` | `./cmd/toob-ops` | Liegt unter `platform/cmd/toob-ops` |
| `test-restore-raft` / `-db` | `scripts/…` ✅ | korrekt |
| `validate-policy` | `./shared/policy/...` ✅ | korrekt |
| `dev-identity` | `platform/deploy/dev/docker-compose.identity.yml` ✅ | korrekt |

Über die Hälfte der operativen Kommandos ist nach der Layer-Umstellung nicht mitgezogen worden. Ein `just plan-infra` schlägt sofort fehl.

### 10.3 Ansible-Rolle `openfga` **[belegt, Teilinhalt]**

- `openfga_db_password` hat **keine Quelle** — kein Vault-Lookup, keine Generierung. Undefinierte Variable ⇒ Playbook-Fehler oder leeres Passwort.
- Die Rolle nutzt `vault_root_token`, während alle anderen Rollen (`nomad`) auf AppRole umgestellt sind. Root-Token in Ansible widerspricht dem eigenen Muster.
- `postgresql_user`/`postgresql_db` setzen einen lokal erreichbaren Postgres voraus; die Ubicloud-Instanz ist über TLS und Firewall angebunden. [prüfen]
- Kein `handlers/`, keine Idempotenz-Marker; `changed_when: false` überall ⇒ die Rolle meldet nie eine Änderung.

### 10.4 Fehlende Deployment-Verdrahtung **[belegt]**

- `platform/deploy/ansible/roles/valkey/` existiert als Verzeichnis; **kein Identity-Code kennt eine Valkey-Adresse**. `ratelimit.ValkeyBackend`, `dpop.ValkeyReplayStore` und `revocation.Broadcaster` haben keine Konstruktionsstelle außerhalb von Tests.
- Es gibt **keinen Nomad-Job für die Identity-API/BFF** — nur für OpenFGA (real) sowie celldir/identity-sync (Platzhalter).
- `backup/verifier.go` erwartet, dass jemand `RecordResult` aufruft; `scripts/test-restore-fga-db.sh` schreibt vermutlich selbst eine `.prom`-Datei [prüfen] ⇒ zwei parallele Metrikpfade für dieselbe Aussage.

---

## 11. Was gut gelungen ist

Der Vollständigkeit halber, weil der Rest des Dokuments hart ist:

- **`identity/dpop`** — vollständige, korrekte RFC-9449/7638-Implementierung inklusive kanonischem Thumbprint und Replay-Store. Der Test „manipulierte Signatur wird abgelehnt" ist genau der Beweis, den der Backlog verlangt hat. Fehlt nur die Verdrahtung.
- **`identity/internal/fga/store.go`** — SAGA-Kompensation mit Fehlerinjektion an beiden Fehlerstellen und Tests, die auf *ausgebliebene* Nebenwirkungen prüfen. Vorbildlich.
- **`identity/internal/fga/rebuild.go`** — saubere Soll/Ist-Differenz mit Kategorisierung, Dry-Run als Default, deterministische Sortierung.
- **`identity/authz/shadow.go`** — asynchron, mit Latenztest, der beweist, dass ein 500-ms-Shadow den Hauptpfad nicht blockiert. Genau die richtige Testform.
- **`identity/token/exchange.go`** — RFC 8693 mit Pflicht-`actor_token`, Pflicht-Justification und hartem Lebenszeitdeckel; drei Negativtests.
- **`identity/pki`** — substanziell, mit Rotations-Überlappungsfenster, Offline-Gnadenfrist und Backlog-Metrik. Die zwei X.509-Details aus § 9.6 sind reparabel.
- **`identity/sync/reconciler.go`** — die strikte Trennung von DB-Fehler und Drift ist genau der Punkt aus F-6 der Ist-Analyse und sauber umgesetzt.
- **`identity/principal`** — URN-Schema, `Rank()`, Validierung; die Grundlage stimmt.
- **`shared/x/clock`** — richtig geschnitten und breit adoptiert.

---

## 12. Priorisierte Sofortmaßnahmen

Reihenfolge nach „was blockiert am meisten" bzw. „was ist am billigsten zu reparieren und verhindert die meisten Folgefehler".

**Sofort — Blocker beseitigen**

1. **Migrationen 001–009 neu schneiden** (§ 2.1). Grüne Wiese nutzen: ein konsistentes Initial-Set mit `tenant_id` überall, allen referenzierten Tabellen, `identity_app`-Rolle, Down-Migrationen und einem Runner mit Versionstabelle. `migrations.All` durch eine benannte Struktur ersetzen, damit Tests nicht mehr per Index zugreifen.
2. **`celldir/pool.go` löschen**, `tenant.SetTenantContext` als einzigen RLS-Pfad behalten (§ 2.2).
3. **OpenFGA-Job korrigieren**: dynamischer Port oder eigener Node-Pool, `distinct_hosts`, Ubicloud-CA für die DB, Playground-Port entfernen (§ 2.3/2.4).
4. **Webhook-Retry** reparieren: Request pro Versuch neu bauen (§ 2.5).
5. **SCIM-URN** auf `principal.FormatHumanURN` mit echtem Tenant umstellen und den Test anpassen (§ 2.6).
6. **Zitadel-Ansible-Rolle** auf entfernte JS-Dateien prüfen (§ 2.7).

**Diese Woche — Fail-open schließen**

7. **Alle Nil-Toleranzen in Sicherheitskomponenten entfernen.** `SecurityInterceptor` ohne Chain, `SignatureVerifier` ohne Secret, `orgs.Manager` ohne SA-Client, `RevocationCache` ohne Store: jeweils Konstruktor-Fehler statt Laufzeit-Degradation (§ 3.1, 3.3, 3.4, 3.8).
8. **Fail-closed bei unregistriertem Endpunkt wiederherstellen** und `Register()` die Duplikatprüfung zurückgeben (§ 3.2, R1/R2).
9. **`enforce.RevocationChecker` auf `(bool, error)` umstellen** und den Fehlerfall fail-closed behandeln (§ 3.5).
10. **`storeID = "global"`-Fallback entfernen** — fehlender Resolver ist ein Startfehler (§ 3.6).

**Nächste zwei Wochen — Duplikate auflösen**

11. **TrustLevel vereinheitlichen**: `token.TrustLevel` löschen, `RouteSecurityPolicy` auf `principal.TrustLevel` umstellen, Lint gegen String-Vergleiche (§ 4.1).
12. **AMR-Menge zusammenlegen** und `mfa` entfernen; den Contract-Test entsprechend korrigieren (§ 4.2).
13. **Audit-Kette auf ein Format**: `ComputeAuditLogHash` und `AuditLogRecord` aus `retention.go` und `sync/deletion.go` entfernen, alles auf `ComputeCanonicalHash` ziehen, Pseudonymisierung so gestalten, dass sie die *echte* Kette erhält (§ 4.3).
14. **`target/rules.go` auf die generierten Validatoren umstellen**, `policy/rules/org_naming.yaml` löschen, `internal/orgs.ValidateName` durch `policy.ValidateOrgName` ersetzen (§ 4.4).
15. **Eine Enforcement-Kette wählen.** Empfehlung: `Pipeline` löschen, `Stage1Chain` behalten, DPoP-Gate ergänzen, `enforce.HTTPMiddleware` als einzigen Einstiegspunkt behalten und `middleware/interceptor.go` darauf reduzieren (§ 4.5, 6.5).

**Danach — Substanz nachziehen**

16. **Scheintests entfernen** (§ 5.2). Ein leeres Testfile mit `// TODO` ist ehrlicher. Danach die Ausfallmatrix gegen echte Komponenten neu bauen.
17. **Stubs entfernen**: `internal/sync`, `internal/scim`, `internal/zitadel/client.go`, `audit/chain.go`, `audit/writer.go`, `authz/listobjects.go` (§ 5.1).
18. **Permission-Katalog anschließen** — Trust-Level, Step-Up, Audit-Klasse, Kosten, Impersonationsregel aus `policy.PermissionCatalog` beziehen statt aus Aufrufparametern (§ 6.4). Das ist der Punkt, der die gesamte Policy-Pipeline erst wirksam macht.
19. **Postgres-Implementierungen** für Outbox, Tenant-Directory, Saga-Persistenz, BFF-Sessions, Break-Glass-Grants (§ 6.6).
20. **Release-Governance neu bauen** (§ 6.1) — aktuell ist die Plattform hier funktional schlechter als vor dem Umbau.
21. **depguard-Regeln für `identity/`** ergänzen, `audit → sync` und `sync → authz` durch neutrale Typpakete auflösen (§ 8.1/8.2).
22. **`justfile` an die neue Struktur anpassen** (§ 10.2) und Credentials aus `.env.*` rotieren (§ 10.1).

---

## 13. Offene Prüfpunkte

Punkte, die ich am Export nicht abschließend beurteilen kann und die du am Repo verifizieren solltest:

| # | Frage |
|---|---|
| P1 | Kompiliert `shared/policy` überhaupt? `generated.go` (vom Generator) und `permissions_gen.go` (im Baum, **nicht** vom Generator erzeugt) könnten `PermissionCatalog`/`PermissionDefinition` doppelt deklarieren. Gleiches für `gates_gen.go`, `endpoints_gen.go`, `audit_gen.go`, `ratelimit_gen.go`. |
| P2 | Welche dieser `*_gen.go` sind handgeschrieben? Generierte und handgeschriebene Dateien im selben Paket ohne Trennung machen `go generate` gefährlich. Empfehlung: generierte Dateien in ein Unterpaket `shared/policy/gen`. |
| P3 | Existiert `docs/` (ADRs, 24 Runbooks) noch, oder ist es dem Export zum Opfer gefallen? Falls gelöscht: Regression, jeder neue Alarm ist ohne Runbook. |
| P4 | Existiert `.github/workflows/` noch? Im Baum nicht vorhanden. |
| P5 | Prüft `shared/boundaries_test.go` die Feinschichtung innerhalb von `identity/`, oder nur die Layer-Grenzen? |
| P6 | Werden `policy/tests/*.fga.yaml` und `policy/tests/matrix/expectations.yaml` von irgendetwas ausgeführt? `just validate-policy` startet nur `go test ./shared/policy/...`. |
| P7 | Enthält `policy/permissions.yaml` tatsächlich alle Registry-/Fleet-Endpunkte (POL-02), oder nur die im Generator-Beispiel sichtbaren Domänen? |
| P8 | Ist die `zitadel`-Ansible-Rolle auf Actions v2 umgestellt, oder lädt `provision-instance-policies.sh` weiterhin die entfernten JS-Dateien hoch? |
| P9 | Wird `platform/deploy/ansible/site.yml` um die Rollen `openfga` und `valkey` erweitert? |
| P10 | Schreibt `scripts/test-restore-fga-db.sh` eigene Prometheus-Metriken parallel zu `identity/backup/verifier.go`? |

---

## 14. Fazit in drei Sätzen

Die Zielarchitektur ist in ihren Grundzügen erkennbar umgesetzt — Principal-Schicht, FGA-Client, Zellmodell, PKI, DPoP und Token-Exchange sind an mehreren Stellen sogar besser gebaut als geplant. Der Umbau ist jedoch **in die Breite statt in die Tiefe** gelaufen: Es gibt keinen einzigen durchgehend verdrahteten Request-Pfad, tragende Verbindungen (Permission-Katalog → Enforcement, Zitadel-Rollen → FGA, DPoP → Gate, Break-Glass → FGA, Audit → Ledger) fehlen, und die zentralen Sicherheitsentscheidungen sind an mehreren Stellen von Nil-Checks abhängig, die im Fehlerfall öffnen statt zu schließen. Der dringendste Schritt ist deshalb nicht mehr Code, sondern das Nachholen von Gate B aus dem Backlog: **eine einzige Permission vollständig durch alle Schichten ziehen** — Katalogeintrag, Generierung, Stage-1-Gate mit DPoP, FGA-Check mit Store-Auflösung, RLS-Query auf einer Migration, die tatsächlich läuft, und ein Audit-Eintrag in der echten Kette — und erst danach die Breite darauf umstellen.