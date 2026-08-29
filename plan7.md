# Toob Identity — Schwerpunktanalyse & Refactoring-Plan

**Prüfgrundlage:** Repository-Export vom 2026-08-07, 04:33 (510 Dateien, inkl. OpenFGA-Modelle)
**Methodik:** Bewertet wird **ausschließlich der ausgeführte Code**. Kommentare, Log-Texte und Requirement-IDs im Quelltext sind als Behauptung behandelt, nicht als Beleg. Wo Kommentar und Code auseinanderfallen, ist das selbst ein Befund.
**Schweregrade:** **S1** nachweislich defekt/blockierend · **S2** Sicherheits- oder Semantikverlust · **S3** strukturelle Schuld · **S4** Hygiene.

---

## 0. Zusammenfassung vorweg

Gegenüber dem letzten Stand ist substanziell nachgebessert worden: DPoP verifiziert jetzt Signaturen mit kanonischem RFC-7638-Thumbprint, `jwks` parst `crv`, `celldir/pool.go` nutzt `set_config`, `internal/orgs` und `target.SignatureVerifier` schließen bei fehlender Konfiguration, der Reconciler trennt Fehler von Drift, der Webhook-Retry baut den Request neu, Idempotency-Middleware und Approval-Engine existieren. Die Bausteinqualität ist stellenweise hoch — `pki`, `dpop`, `internal/fga`, `token/exchange` sind sauber gebaut.

Das Problem liegt eine Ebene darüber. **Die Bausteine sind überwiegend nicht miteinander verdrahtet, und dort wo sie verdrahtet sind, ist die Verdrahtung nichtdeterministisch oder umgehbar.** Es gibt keinen HTTP-Server, kein `cmd/identity-api`, keinen lauffähigen Nomad-Job für die API. Der einzige generische Enforcement-Einstiegspunkt (`AutomaticHTTPInterceptor`) kann konstruktionsbedingt keinen einzigen Request durchlassen. Die Policy-Registry wird aus einer Go-Map befüllt und ist damit pro Prozessstart unterschiedlich. DPoP ist durch Weglassen eines Headers vollständig umgehbar. Der Circuit Breaker rastet permanent ein. Zwei der zehn Migrationen können nicht ausgeführt werden.

---

## 1. Der Schwerpunkt

### 1.1 Empfehlung

> **Schwerpunkt: Verdrahtung und Determinismus des Enforcement-Pfads.**
> Konkret: `shared/policy` → `middleware` → `enforce` → `authz` zu **einem** deterministischen, tatsächlich montierten Pfad zusammenführen und alle Parallelimplementierungen löschen.

Das ist weder ein DevOps- noch ein Feature-Schwerpunkt, und bewusst nicht „Sicherheitsfeatures ergänzen". Es ist der Bereich, in dem pro Arbeitstag die meiste Risikoreduktion entsteht.

### 1.2 Warum dieser und kein anderer

| Kandidat | Gewicht | Warum nicht zuerst |
|---|---|---|
| **Enforcement-Pfad** | ⭐ | Enthält die zwei schärfsten Sicherheitsdefekte (§ 3.1, § 3.2), den schwersten Verfügbarkeitsdefekt (§ 2.2), das größte Duplikationscluster (§ 5.1) — und blockiert jede Ende-zu-Ende-Verifikation aller übrigen Bereiche. |
| Persistenz & Migrationen | hoch | Zwei Migrationen sind nicht lauffähig (§ 2.1), dreizehn Stores sind In-Memory. Aber: ohne durchgängigen Request-Pfad lässt sich nicht prüfen, ob die Persistenz das Richtige speichert. Direkt danach. |
| DevOps / Infrastruktur | mittel | Enthält harte Blocker (Portkonflikt, falsche CA, Stub-Jobs, kaputtes `justfile`), aber sie werden erst wirksam, wenn es überhaupt ein Artefakt zu deployen gibt. Es gibt kein Identity-Binary. |
| Audit & Compliance | mittel | `audit_ledger` hat Schema und Verifizierer, aber **keinen Schreiber**. Die Kette lässt sich zudem nach einem Postgres-Roundtrip nicht mehr verifizieren (§ 4.2). Wichtig, aber nachgelagert. |
| Neue Features | niedrig | Es fehlt kein Feature. Es fehlt die Verbindung zwischen den vorhandenen. |

### 1.3 Was der Schwerpunkt konkret umfasst

1. **Einen** Enforcement-Mechanismus: `Stage1Chain` behalten, `Pipeline` löschen (§ 5.1).
2. **Einen** HTTP-Einstiegspunkt mit **einem** Fehlerschreiber (§ 5.2).
3. Policy-Registry deterministisch aus dem generierten Katalog, gekeyt auf die **Permission-ID**, nicht auf `Resource` (§ 3.1).
4. DPoP als Gate **in** der Kette, mit `jkt` im Principal (§ 3.2).
5. Circuit Breaker atomar und mit Half-Open (§ 2.2).
6. Buildzeit-Konformitätstest Katalog ↔ Registry ↔ Handler.

Ergebnis: ein vertikaler Durchstich, gegen den sich alles Übrige testen lässt.

---

## 2. S1 — Nachweislich defekt

### 2.1 Migration 008 und 009 sind nicht ausführbar

**008** legt `tenant_members` und `outbox_events` jetzt korrekt an und ergänzt `tenant_id` per `ADD COLUMN IF NOT EXISTS`. Zwei Indexe scheitern trotzdem:

```sql
CREATE INDEX ... ON release_approvals(tenant_id, id);        -- 006 hat keine Spalte "id" (PK ist release_id)
CREATE INDEX ... ON impersonation_sessions(tenant_id, id);   -- 007 hat keine Spalte "id" (PK ist session_id)
```

**009** vergibt Rechte an eine Rolle, die keine Migration erzeugt:

```sql
REVOKE UPDATE, DELETE ON audit_ledger FROM PUBLIC, identity_app;
GRANT INSERT, SELECT ON audit_ledger TO identity_app;
```
`identity_app` existiert nicht → `role "identity_app" does not exist`.

Damit existiert weiterhin **keine einzige RLS-Policy** und **kein Append-Only-Schutz** in einer real migrierten Datenbank.

Warum es nicht auffällt: `celldir/rls_test.go` und `audit/ledger_test.go` prüfen ausschließlich per `strings.Contains` gegen `migrations.All[7]` bzw. gegen den Treffer einer Substring-Suche. Es wird nie SQL ausgeführt, und der Zugriff ist positionsbasiert — eine neue Migration verschiebt den Index und bricht den Test ohne inhaltlichen Grund.

Ergänzend: `migrations.All` ist ein `[]string` ohne Version, Name, Down-Migration und ohne Runner. Es gibt im gesamten Repo keinen Code, der Migrationen anwendet.

### 2.2 Der Circuit Breaker rastet permanent ein · `authz/check.go`, `authz/client.go`

```go
if c.circuitOpen {
    return CheckResult{Allowed: false, Degraded: true, Reason: "circuit_breaker_open", ...}, ErrFGAUnavailable
}
…
allowed, err := c.fgaChecker.Check(evalCtx, …)
if err != nil { c.failureCount++; if c.failureCount >= 5 { c.circuitOpen = true }; … }
c.failureCount = 0
c.circuitOpen = false
```

Der Reset steht **hinter** dem Aufruf, der Kurzschluss **davor**. Sobald `circuitOpen == true` gesetzt ist, wird `Check` nie wieder erreicht — also wird `circuitOpen` nie wieder `false`. Es gibt weder einen Half-Open-Zustand noch einen Timer.

**Konsequenz:** Fünf aufeinanderfolgende FGA-Fehler (ein Netzwerk-Blip, ein FGA-Neustart, ein Deploy) setzen den Prozess dauerhaft auf „alles verweigert". Nur ein Neustart der Anwendung stellt Autorisierung wieder her.

Zusätzlich sind `circuitOpen` und `failureCount` **nicht synchronisiert**, während `BatchCheckPermissions` explizit N Goroutinen auf demselben Client startet. Das ist ein Data Race unter `-race` und führt zu Lost Updates am Zähler.

### 2.3 Die Policy-Registry ist nichtdeterministisch · `middleware/interceptor.go`

```go
for _, perm := range spolicy.PermissionCatalog {   // Map-Iteration
    endpoint := perm.Resource                      // z. B. "device_group"
    if endpoint == "" { endpoint = perm.ID }
    reg.Register(RouteSecurityPolicy{EndpointID: endpoint, RequiredTrustLevel: minTL, RequireStepUp: perm.StepUp})
}
```

Zwei Defekte in vier Zeilen:

1. **Gekeyt auf `Resource`, nicht auf die Permission.** Mehrere Permissions teilen sich denselben Resource-Typ (`device_group` trägt mindestens `read_aggregate`, `read_granular`, `deploy`). `Register` überschreibt. Welche Policy gewinnt, hängt an der **Go-Map-Iterationsreihenfolge** — und die ist per Sprachdefinition randomisiert. Derselbe Binary erzwingt bei jedem Prozessstart ein anderes Trust-Level für denselben Endpunkt.
2. **`AutomaticHTTPInterceptor` sucht mit `r.URL.Path`.** Registry-Keys sind Resource-Typen (`tenant`, `device_group`), Lookup-Keys sind URL-Pfade (`/api/v1/deployments`). Die Namensräume schneiden sich nie → `!hasPolicy` → HTTP 500 für **jeden** Request. Der generische Interceptor ist nicht benutzbar; nur der explizite `HTTPInterceptor("/pfad")` funktioniert, und auch nur für händisch registrierte Pfade.

`Register` gibt zudem keinen Fehler mehr zurück — Doppelregistrierung ist still.

### 2.4 `device.PollForToken` hat eine Hintertür · `device/flow.go`

```go
func (m *DeviceFlowManager) PollForToken(ctx context.Context, deviceCode string, legacyIsApproved ...bool) (*TokenResponse, error) {
	sess, err := m.store.GetSessionByDeviceCode(ctx, deviceCode)
	if err != nil {
		if len(legacyIsApproved) > 0 && legacyIsApproved[0] {
			return &TokenResponse{AccessToken: "toob_at_device_cli_approved_token", …}, nil
		}
	…
	if len(legacyIsApproved) > 0 {
		if legacyIsApproved[0] { sess.State = StateApproved }
	}
```

Ein **vom Aufrufer gelieferter Boolean überschreibt den gespeicherten Autorisierungszustand** — und liefert bei unbekanntem Device-Code sogar ein Token für eine Session, die es nie gab. Der Parameter existiert nur, um eine alte Testsignatur am Leben zu halten (`flow_test.go` ruft `PollForToken(ctx, code, true)`).

Unabhängig davon ist der zurückgegebene Access Token die Konstante `"toob_at_device_cli_approved_token"` — kein Zitadel-Austausch, keine Signatur. Der Device-Flow stellt keine verwertbaren Credentials aus.

#### 2.4-T Offene Tickets aus der Umsetzung von 2.4

Beim Beheben von § 2.4 aufgefallen, bewusst nicht mitgemacht, damit die Änderung klein bleibt:

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-2.4.1** | **`TokenIssuer` produktiv implementieren.** `device.PollForToken` reicht die Ausstellung an ein injiziertes `device.TokenIssuer` durch; im Repo existiert nur die Schnittstelle. Ein echter Issuer signiert wie `token/exchange.go` (RS256 + `kid`) — und braucht dafür eine Antwort darauf, wie der Schlüssel in die vom `token.Verifier` gelesene JWKS gelangt. Ohne diese Antwort entstünde ein zweiter Pfad, der Tokens ausstellt, die niemand verifizieren kann. | Gehört zu `cmd/identity-api` (Sprint 3, § 10) zusammen mit der Schlüsselverwaltung. | § 2.4 |
| **T-2.4.2** | **RFC 8628 § 3.5 Polling-Intervall durchsetzen.** `ErrSlowDown` war deklariert und wurde nie zurückgegeben; das Sentinel ist beim Fix gelöscht worden. Die Durchsetzung braucht `LastPolledAt` in `DeviceSession` plus eine Store-Methode und ist erst mit einem HTTP-Endpunkt überhaupt wirksam. | Ohne Server kein Angriffsvektor; vorher wäre es unbenutzter Code. | § 2.4, § 5.8 |
| **T-2.4.3** | **`MemoryDeviceFlowStore` begrenzen.** Abgelaufene Sessions werden nie entfernt, beide Maps wachsen unbegrenzt. Ein `PurgeExpired` ohne Aufrufer wäre wieder toter Code — die Bereinigung gehört an den Session-Janitor des Servers, gemeinsam mit den übrigen zwölf Strukturen. | Sammelposten § 6.4. | § 6.4 |
| **T-2.4.4** ✅ | **Paket `identity/device` → `identity/deviceflow` umbenennen.** „Device" bedeutet hier OAuth Device Authorization Grant, in `identity/pki` dagegen physisches Gerät. Aktuell kostet die Umbenennung zwei Importzeilen und einen Verzeichnis-Move; mit jedem weiteren Konsumenten mehr. | **Erledigt.** Dabei kam heraus, dass `identity/device` zwei unverwandte Dinge enthielt: den Grant (`flow.go`) und `SecureDPoPKeyStore`, einen clientseitigen DPoP-Schlüsseldateispeicher ohne jeden Produktivaufrufer. Letzterer liegt jetzt als `dpop.SecureKeyStore` in `identity/dpop`, wo eine künftige CLI ihn sucht. Die Typen sind entstottert (`Manager`, `Session`, `Store`, `MemoryStore`, `AuthorizationRequest/-Response`), die 16 Fehlerpräfixe lauten `deviceflow:`. | § 8.3 |

*Kein Befund, geprüft:* die ignorierten Fehler von `rand.Read` in `generateUserCode`/`generateDeviceCode` — seit Go 1.24 ist `crypto/rand.Read` spezifiziert, den Puffer immer vollständig zu füllen und nie einen Fehler zurückzugeben (`go.mod`: 1.26.5).

### 2.5 Break-Glass-Grants sind unbefristet und treffen nie · `authz/breakglass.go`

```go
tuple := TupleKey{
    User:     fmt.Sprintf("user:%s", strings.TrimPrefix(req.TargetUserURN, "urn:")),
    Relation: "break_glass_operator",
    Object:   fmt.Sprintf("organization:%s", req.TenantID),
}
b.tupleWriter.WriteTuple(ctx, "global", tuple)
```

Vier Fehler in einem Tupel:

- `TrimPrefix(…, "urn:")` ist ein No-Op — Toob-URNs beginnen mit `toob:`. Das Subjekt wird `user:toob:human:cell:org:usr_1`, während `PrincipalToFGASubject` `user:usr_1` erzeugt. **Das Tupel kann nie matchen.**
- Objekttyp `organization` existiert im Modell nicht (dort heißt es `tenant`).
- Store `"global"` ignoriert die Store-per-Tenant-Isolation.
- `ConditionName` und `ConditionParams` werden berechnet und **nicht übergeben** — `WriteTuple` nimmt keine Condition. Das Tupel wird **unbefristet** geschrieben; es gibt keinen Löschpfad, keinen Sweeper, keine Ablaufprüfung im Check-Pfad. `IsGrantActive` wird von keinem Enforcement aufgerufen.

Der Code tut damit das Gegenteil der behaupteten Eigenschaft: statt eines automatisch ablaufenden Grants schreibt er einen permanenten, der zufällig wirkungslos ist. Wäre das Subjekt-Format korrekt, wäre es ein permanenter Notfallzugang.

Zusätzlich passt `AuditDispatcherInterface.DispatchCriticalAudit(ctx, tenantID, actor, action, target)` weiterhin nicht auf `audit.AuditDispatcher.DispatchAudit(ctx, tx, entry, class)`. Ohne Adapter ist die kritische Audit-Pflicht unverdrahtet.

#### 2.5-T Offene Tickets aus der Umsetzung von 2.5

Der Grant wird nicht mehr geschrieben, sondern pro abgelehntem Check als **contextual Tuple** beigesteuert (ADR 0005). Damit entfallen Subjektformat-, Objekttyp- und Store-Fehler ersatzlos, und es kann konstruktionsbedingt kein stehendes Notfallrecht existieren. Offen bleibt:

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-2.5.1** ✅ | **Audit-Adapter `audit → authz.CriticalAuditDispatcher`.** Der Signaturbruch bleibt bestehen; der Adapter müsste ein `audit.AuditEntry` mit `SequenceNumber`, `PrevHash` und `EntryHash` erzeugen. Es gibt aber keine Komponente, die Sequenznummern vergibt oder die Kette fortschreibt — `audit.AuditWriter` ist `type AuditWriter struct{}`. Ein Adapter jetzt würde ungekettete Einträge produzieren und § 4.2 verdoppeln. Die Engine erzwingt den Dispatcher inzwischen (kein `nil` mehr) und lehnt die Aktivierung ab, wenn das kritische Audit fehlschlägt. | Gehört an den Ledger-Schreiber (Sprint 2, Punkt 18). | § 2.5, § 4.2 |
| **T-2.5.2** | **`GrantStore` in Postgres.** `MemoryGrantStore` verliert alle Grants beim Neustart — im Ernstfall genau dann, wenn deployt wird. Abgelaufene Grants werden beim nächsten `Save` verworfen, die Struktur bleibt also begrenzt, aber prozesslokal. Schema: `break_glass_grants(grant_id PK, tenant_id, target_subject, target_urn, requester_urn, approver_urn, activated_at, expires_at, justification)` mit RLS wie in Migration 008. | Sammelposten Sprint 3, Punkt 24. | § 2.5, § 6.4 |
| **T-2.5.3** | **Typ `rollout` fehlt im FGA-Modell.** Der Katalog deklariert `fleet.rollout.start` und `fleet.rollout.cancel` auf `resource: rollout`, `policy/model/fleet.fga` kennt nur `channel`, `release` und `device_group`. Break-Glass erreicht das Abbrechen eines Rollouts derzeit nur über `channel.can_deploy`. Beim Anlegen des Typs muss `operator` analog `[user] or admin from parent or break_glass_operator from parent` lauten, sonst fällt der Notfallzugriff für genau die Operation aus, für die er gedacht ist. | Modellarbeit, gehört zu plan6 § 4.6. | § 2.5, plan6 § 4.6 |
| **T-2.5.4** | **`fga model test` ausführen** (`just validate-policy`). Die Fixtures unter `policy/tests/` laufen nirgends. Beim Aktivieren fällt auf, dass das Format der Dateien (`check: [{user, relation, object, result}]`) nicht dem offiziellen `assertions`-Schema entspricht und dass `fleet_test.fga.yaml` bereits eine falsche Erwartung enthält: `user:bob` hat dort nur `operator` auf `channel:prod_channel`, wird aber für `can_deploy` auf `device_group:prod_fleet` als `true` erwartet. | § 10 / Prüfpunkt P7. | § 10 |

*Prüfpunkt P2 ist damit beantwortet:* Das Modell kannte weder `break_glass_operator` noch eine Condition `is_active_breakglass` noch einen Typ `organization`. Die Relation ist jetzt in `core.fga` definiert und über `channel`/`device_group` verdrahtet; Conditions werden nicht verwendet, weil `OpenFGAChecker.Check` keinen Context-Parameter führt und der contextual-Tuple-Ansatz die Ablaufgarantie ohne sie erfüllt.

### 2.6 OpenFGA-Job kann nicht starten · `identity/deploy/nomad/jobs/openfga.nomad.hcl`

- `constraint meta.pool == "api"` + `network_mode = "host"` + `port "http" { static = 8080 }`. Auf dem API-Pool belegen Zitadel (`Port: 8080` im Config-Template) und die Registry-API (Caddy → `localhost:8080`) diesen Port bereits.
- `count = 2` mit `spread`, aber ohne `distinct_hosts` → zwei Allocations können auf einem Host landen und kollidieren miteinander.
- `sslrootcert=/etc/ssl/certs/vault-ca.pem` für die **Ubicloud**-Datenbank; die `common`-Rolle verteilt dafür `ubicloud-ca.pem`. Mit `sslmode=verify-full` schlägt der Verbindungsaufbau fehl.
- `OPENFGA_HTTP_ADDR=0.0.0.0:${NOMAD_PORT_http}` steht in einem Heredoc-`template`. Nomads `${…}`-Interpolation greift dort nicht; korrekt wäre `{{ env "NOMAD_PORT_http" }}`. [prüfen]

`celldir.nomad.hcl` und `identity-sync.nomad.hcl` sind einzeilige Stubs (`job "celldir" { type = "service" }`) ohne `group`/`task` — von Nomad abgelehnt.

#### 2.6-T Offene Tickets aus der Umsetzung von 2.6

Der Portkonflikt war schärfer als hier notiert: `registry-api` belegt `static = 8080` auf demselben Pool mit `network_mode = host`, die Allocation wäre also dauerhaft `pending` statt gelegentlich kollidiert. OpenFGA liegt jetzt auf 8180/8181, Metriken auf 2112, `count` steht auf 1 mit `distinct_hosts` (die Inventory hat genau einen API-Host). Die DSN wird nur noch von der Ansible-Rolle zusammengesetzt und aus `secret/data/openfga/postgres` gelesen; Zugriff auf die Engine erfordert einen Preshared Key. Offen bleibt:

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-2.6.1** | **Nomad-Jobs für `celldir` und `identity-sync` schreiben.** Beide Dateien sind als `TODO: PLACEHOLDER, NOT DEPLOYABLE` markiert und von Nomad weiterhin ablehnbar. Es gibt keine Artefakte: beide `cmd/`-Programme drucken und kehren zurück, es existiert kein Image und kein Release-Eintrag. `identity-sync` ist wegen der Leader-Election ein Single-Allocation-Service, kein Spread-Cluster. | Job-Spec entsteht mit dem Binary (Sprint 3, Punkt 25). | § 2.6, § 10 |
| **T-2.6.2** | **`openfga`-Rolle auf Vault AppRole umstellen.** Sie nutzt weiterhin `vault_root_token`, während die `nomad`-Rolle bereits auf AppRole umgestellt ist. Das ist kein Rollenproblem, sondern ein rollenübergreifender Schnitt (`vault-primary` schreibt ebenfalls mit Root-Token). | Eigener Schritt über alle Rollen. | § 10 |

*Beim Umsetzen gefunden und behoben:* `prometheus.yml.j2` erzeugte an drei Stellen `regex: "10\.1\.1\.10:(.*)"`. In einem doppelt gequoteten YAML-Skalar ist `\.` keine gültige Escape-Sequenz — die gerenderte `prometheus.yml` war **nicht parsebar**, Prometheus hätte die Konfiguration abgelehnt. Der Jinja-Filter erzeugt jetzt `\\.`. Verifiziert durch Rendern der Vorlage mit Beispiel-Inventory und anschließendem YAML-Parse.

### 2.7 `shared/policy` kompiliert vermutlich nicht [prüfen]

`policygen` schreibt genau vier Dateien: `generated.go`, `audit_gen.go`, `ratelimit_gen.go`, `rules_gen.go`. Im Baum liegen zusätzlich `permissions_gen.go`, `endpoints_gen.go`, `gates_gen.go`. Trägt `permissions_gen.go` — wie der Name nahelegt — ebenfalls `PermissionCatalog`/`PermissionDefinition`, ist das eine doppelte Deklaration im selben Package.

Unabhängig davon: `policygen` liest die Regel-YAMLs mit verworfenen Fehlern.

```go
orgBytes, _ := os.ReadFile(orgYAMLPath)
var orgRule OrgNamesRuleYAML
_ = yaml.Unmarshal(orgBytes, &orgRule)
```

Fehlt `org_names.yaml` oder ist es fehlerhaft, ist `orgRule` der Nullwert → generiert wird `regexp.MustCompile("")` (matcht alles) und `if len(name) < 0` / `> 0` → **jeder Name wird abgelehnt**. Eine fehlende Datei kippt die Policy still ins Gegenteil. Hier muss `log.Fatalf` stehen wie bei `permissions.yaml`.

Ferner liest der Generator `actors.yaml`, `sensitivity.yaml`, `rules/factor_policy.yaml` und `rules/invite.yaml` **gar nicht** — vier inerte Quelldateien. Und `policy/rules/` enthält weiterhin sowohl `org_names.yaml` (gelesen) als auch `org_naming.yaml` (tot).

#### 2.7-T Ergebnis und offene Tickets aus der Umsetzung von 2.7

**Prüfpunkt P1 ist beantwortet: `shared/policy` kompiliert.** `permissions_gen.go` deklarierte nicht `PermissionCatalog`, sondern drei Konstanten, deren Werte FGA-*Relationen* sind (`PermissionManageMembers = "can_manage_members"`); `endpoints_gen.go` und `gates_gen.go` waren leere Maps. Keines der Symbole wurde irgendwo verwendet, keine der drei Dateien stammte aus einem Generator — alle drei sind gelöscht. Was `_gen` heißt, kommt jetzt auch aus `policygen`.

Zwei Befunde über den Bericht hinaus: Auch `audit_gen.go` und `ratelimit_gen.go` entstanden fehlerverschluckend (`if err == nil { _ = os.WriteFile(…) }`), und der Frische-Test verglich nur `generated.go` — die übrigen vier Ausgaben durften beliebig veralten. Präzisierung zur Fail-open-Frage: Bei fehlender `elevation.yaml` wird `require_owner` zu `false` und die generierte `ValidateRoleElevation` **überspringt die Owner-Prüfung**; `org_names.yaml` und `impersonation.yaml` kippen bei Nullwerten dagegen in Fail-closed. Boolesche Regelfelder sind deshalb jetzt `*bool`: ein fehlender Schlüssel ist von einem expliziten `false` unterscheidbar und bricht die Generierung ab.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-2.7.1** | **`factor_policy.yaml` und `invite.yaml` verdrahten.** Beide bleiben Quelldateien ohne Generator-Anschluss; ihre Werte sind in `target.EvaluateWebAuthnOnlyPrivileged`, `EvaluateSecureFactorRegistration` und `EvaluateInviteRules` hartkodiert. Das Durchreichen von `ttl_seconds` und `initial_role` verlangt Payload-Felder, die der Zitadel-Hook nicht führt. Sie stehen als `deferredInputs` mit Begründung in `shared/policy/policygen_test.go` und werden vom Inventartest überwacht — eine dritte unverdrahtete Datei fällt sofort auf. | § 3.5 (Sprint 1) baut genau diese Evaluatoren um. | § 2.7, § 3.5 |
| **T-2.7.2** ✅ | **`identity/migrations/runner.go:106` ruft `time.Now()` direkt auf.** `TestNoDirectTimeNowInIdentity` (FND-03) ist dadurch rot und maskiert künftige Verstöße derselben Regel. Gehört zum Migrations-Runner aus § 2.1, nicht zur Policy-Toolchain. | **Erledigt — ohne Clock.** Die Spalte ist bereits `NOT NULL DEFAULT CURRENT_TIMESTAMP` und wird von keinem Go-Code gelesen; das INSERT überschrieb den Default mit der Uhr der Maschine, die gerade migriert. Wann eine Migration lief, ist eine Eigenschaft der Datenbanktransaktion — `applied_at` fällt jetzt aus der Spaltenliste, der `time`-Import entfällt. FND-03 ist grün. | § 2.1, FND-03 |

---

## 3. S2 — Sicherheit

### 3.1 DPoP ist durch Weglassen eines Headers vollständig umgehbar

`identity/dpop` ist korrekt implementiert: Signaturprüfung gegen das eingebettete JWK, RFC-7638-kanonischer Thumbprint, `htm`/`htu`, `iat`-Fenster, `jti`-Replay. Die Verdrahtung hebt das auf:

```go
// middleware/dpop_middleware.go
if dpopHeader != "" || strings.HasPrefix(authHeader, "DPoP ") || strings.HasPrefix(authHeader, "dpop ") {
    proof, err := dpop.ParseAndVerifyDPoPHeaderWithOpts(…)
    …
}
next.ServeHTTP(w, r)
```

Ein Angreifer mit einem gestohlenen, DPoP-gebundenen Access Token sendet `Authorization: Bearer <token>` **ohne** DPoP-Header. Die Bedingung ist falsch, die Prüfung wird übersprungen, der Request geht durch.

Verschärfend: `VerifyTokenBinding` wird außerhalb von Tests nirgends aufgerufen, und `principal.Principal` hat **kein `JKT`-Feld**. Die Bindung Token ↔ Schlüssel könnte also selbst dann nicht geprüft werden, wenn der Proof validiert würde.

Es gibt zudem kein DPoP-Gate in `enforce`; `enforce.Request.DPoPProof` wird von der Middleware befüllt und von keinem Gate gelesen.

**Der einzig korrekte Ansatz:** Bindung ist eine Eigenschaft des Tokens, nicht des Requests. Enthält das Token ein `cnf.jkt`, **muss** ein gültiger Proof vorliegen — sonst 401. Die Entscheidung darf nicht davon abhängen, was der Client mitschickt.

#### 3.1-T Ergebnis und offene Tickets aus der Umsetzung von 3.1

Umgesetzt wie beschrieben: `token.Verifier` liest `cnf.jkt` in ein neues `principal.Principal.JKT`, `enforce.DPoPGate` steht direkt hinter dem `TokenGate` und verlangt einen gültigen Proof, sobald das Token gebunden ist. `middleware/dpop_middleware.go` ist gelöscht — eine zweite, umgehbare Prüfung daneben wäre das Muster aus § 5.1.

Zwei Dinge über den Bericht hinaus:

- **Die umgekehrte Lücke war ebenfalls offen:** Ein Token *ohne* `cnf.jkt`, präsentiert mit `Authorization: DPoP <token>`, wurde akzeptiert. RFC 9449 § 7.1 erlaubt das Schema nur für sender-constrained Tokens; das Gate lehnt den Widerspruch jetzt ab.
- **`htu` wurde bisher wahlweise gegen die volle URL *oder* nur gegen den Pfad geprüft.** Ein Proof für `/api/v1/x` war damit auf jedem Host gültig. Die Prüfung ist jetzt strikt gegen eine konfigurierte Origin (`publicBaseURL` am Interceptor) — bewusst **nicht** gegen `Host`/`X-Forwarded-Host`, weil die hinter Caddy und Cloudflare angreiferkontrolliert sind.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.1.1** | **BFF-Sessions sind nicht gebunden.** `identity/bff` verwaltet Tokens serverseitig und kennt weder DPoP noch `cnf`; ADR 0007 („BFF und DPoP") ist ein Titel ohne Inhalt. Ein gestohlenes `__Host-`Session-Cookie ist damit so wertvoll wie das Token dahinter. Die Bindung des Browser-Pfads braucht eine eigene Entscheidung (DPoP im Browser vs. Cookie-Binding über mTLS/Token-Binding). | Eigener Entwurf, eigener Angriffspfad. | § 3.1, ADR 0007 |
| **T-3.1.2** | **`require_dpop` im Permission-Katalog.** Heute passiert ein Token *ohne* `cnf.jkt` das Gate; eine Permission kann Bindung nicht verlangen. Sinnvoll für `fleet.device.delete`, `release.approval.grant` und `admin.*`. Gehört zu O5 („Katalog lastfähig machen") und braucht eine Katalogänderung plus Generator-Feld. | Katalogschnitt, gemeinsam mit den übrigen O5-Feldern. | § 3.1, O5 |
| **T-3.1.3** ✅ | **`enforce/order_test.go` ist weiterhin eine Tautologie.** Der Test übergibt Spy-Gates und prüft die Reihenfolge, in der er sie selbst übergeben hat. Immerhin: `DPoPGate` ist jetzt ein realer Typ, und die dort dokumentierte Sollreihenfolge (`TokenGate → DPoPGate → …`) entspricht der implementierten. Der Test kann gegen die echte Kette gezogen werden, sobald `Pipeline` weg ist. | Sprint 2, Punkt 23 (Scheintests). | § 9 |
| **T-3.1.4** ✅ | **`enforce/interceptor_http.go` und `enforce/pipeline.go` setzen `HTTPURL` und `UsesDPoPScheme` nicht.** Ein gebundenes Token fällt dort fail-closed durch — für nicht sanktionierte Einstiegspunkte das richtige Verhalten, aber es zementiert, dass sie verschwinden müssen. | Sprint 2, Punkt 16 (§ 5.1). | § 5.1 |

### 3.2 L3 lässt sich mit einem einzigen Passkey erreichen · `token/verifier.go`

```go
for _, v := range amrSlice {
    if str, ok := v.(string); ok {
        if IsPhishingResistantAMR(str) {
            if hasWebAuthn { hasSecondFactor = true }
            hasWebAuthn = true
        }
    }
}
```

mit

```go
var PhishingResistantAMRValues = map[string]bool{
    "webauthn": true, "fido2": true, "passkey": true,
    "user_presence": true, "user_verification": true,
}
```

Formal soll gelten: `L3 ⟺ |{registrierte, phishing-resistente Authenticator}| ≥ 2`. Implementiert ist: `L3 ⟺ |{i : amr_i ∈ P}| ≥ 2`.

`user_presence` und `user_verification` sind **Eigenschaften einer einzelnen WebAuthn-Zeremonie**, keine getrennten Faktoren. Ein IdP, der für einen Passkey `["webauthn","user_presence","user_verification"]` emittiert — das ist die übliche Form — erzeugt L3. Ebenso `["webauthn","fido2"]`, was denselben Authenticator zweimal benennt; genau dieser Fall steht als *erwartetes* Verhalten im Contract-Test.

Es wird auch nicht dedupliziert: `["webauthn","webauthn"]` ergibt L3.

**Das ist eine Privilegien-Eskalation L2 → L3 mit einem einzigen Credential**, und L3 ist im Modell die Schreibberechtigung.

Korrekt wäre: L3 ausschließlich aus einem expliziten `acr`-Wert oder aus einem Zähler registrierter Authenticator, den der IdP liefert — niemals aus der Kardinalität von `amr`.

#### 3.2-T Ergebnis und offene Tickets aus der Umsetzung von 3.2

Die Ableitung lautet jetzt: deklarierter `acr`-Wert (exakter Vergleich gegen eine Allowlist, kein Suffix-Match mehr) → L3/L2; sonst `authenticator_count ≥ 2` **und** eine phishing-resistente Methode → L3; sonst eine phishing-resistente Methode → L2; sonst L1. Die Kardinalität von `amr` fließt nirgends mehr ein. `user_presence` und `user_verification` sind aus der Methodenmenge entfernt.

Der Defekt war in **fünf** Tests als Sollverhalten festgeschrieben, nicht in einem: `zitadel_contract_test.go`, `verifier_test.go`, `claims_test.go`, `issuer.go` und `issuer_test.go`. Alle korrigiert.

Zwei Funde über den Bericht hinaus:

- **`acr` akzeptierte jeden Aussteller.** `strings.HasSuffix(acr, ":l3")` erreichte L3 auch für `urn:evil:mfa:l3`.
- **Kein einziges Token aus `test/tokens.GenerateTestToken` war verifizierbar.** Der Aussteller setzte die Organisation als `org_id`-Claim, `token.Verifier` liest sie aus `scope` (`urn:zitadel:iam:org:id:<org>`) und lehnte jedes Token mit `ErrMissingOrgClaim` ab. § 9 beschreibt den Widerspruch zwischen Aussteller und Verifizierer als Trust-Level-Problem — er war vollständig. Gefunden durch den neuen Test, der ein ausgestelltes Token tatsächlich verifiziert, statt nur seine Claims zu lesen.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.2.1** | **Zitadel muss den L3-Claim ausstellen — Deployment-Voraussetzung.** Weder `acr` noch `authenticator_count` wird heute von Zitadel gesetzt (keine Spur in `roles/zitadel/`). Bis eine Action v2 einen der beiden emittiert, erreicht **kein** produktives Token L3, und die neun L3-Permissions sind verwehrt. Das ist die richtige Richtung (fail-closed statt Eskalation), aber es muss vor dem ersten L3-Endpunkt erledigt sein. Ort: `platform/deploy/ansible/roles/zitadel/files/` plus eine Action-Definition; der Claim-Name ist `authenticator_count`, identisch mit dem Hook-Payload-Feld in `target/rules.go`. | Zitadel-Konfiguration, kein Go-Code; wirkt erst mit `cmd/identity-api`. | § 3.2, § 10 |
| **T-3.2.2** | **`acr`-Werte und AMR-Menge gehören in die Policy-Quelle.** Beide stehen als Konstanten in `token/amr.go`. Sie sind ein Vertrag mit dem IdP, genau wie die Permissions — der natürliche Ort ist `policy/` mit Generator-Anschluss (der Inventartest aus § 2.7 erzwingt die Verdrahtung). Sinnvoll erst **nach** § 3.3, sonst entstehen drei Quellen statt zwei. | Reihenfolge: erst § 3.3 vereinheitlichen, dann generieren. | § 3.2, § 3.3, O5 |

### 3.3 Zwei divergierende AMR-Mengen


| `token/amr.go` (kommentiert als „single source of truth") | `federation/customer_idp.go` |
|---|---|
| `webauthn`, `fido2`, `passkey`, `user_presence`, `user_verification` | `phr`, `fido2`, `hwk`, `webauthn`, `pop` |

Nicht-monoton: ein Kunden-IdP, das `phr` (RFC 8176) liefert, gilt in `federation` als phishing-resistent, im Trust-Level-Pfad nicht (→ L1). Umgekehrt erreicht `passkey` L2/L3, wird aber von `federation` für privilegierte Operationen abgelehnt. Dieselbe Anmeldung besteht das eine Gate und fällt am anderen durch.

#### 3.3-T Ergebnis und offene Tickets aus der Umsetzung von 3.3

Die Menge ist jetzt in `policy/authn.yaml` deklariert, wird von `policygen` nach `shared/policy/authn_gen.go` erzeugt und von `identity/token` **und** `identity/federation` gelesen — eine Implementierung (`spolicy.IsPhishingResistantAMR`), nicht zwei gleichnamige Funktionen in zwei Paketen. Mitgewandert sind die `acr`→Trust-Level-Abbildung und `min_authenticators_for_l3`; **T-3.2.2 ist damit erledigt**, weil ein Zwischenschritt über ein temporäres Go-Paket entfallen ist.

**Die Vereinigung war keine Vereinigung.** `federation` führte zusätzlich die RFC-8176-Werte `hwk` („Proof-of-Possession eines hardwaregesicherten Schlüssels") und `pop` („Proof-of-Possession eines Schlüssels"). Keiner der beiden sagt etwas über Origin-Bindung — genau die Eigenschaft, die Phishing-Resistenz ausmacht; ein hardwaregestützter Schlüssel lässt sich durch einen AitM-Proxy hindurch ebenso verwenden wie ein Passwort. Ein Kunden-IdP, der `pop` emittiert — was PoP- und DPoP-nahe Flows tun —, schaltete damit privilegierte Operationen frei. Beide Werte sind entfernt; eine naive Vereinigung hätte sie stattdessen in den Trust-Level-Pfad getragen und L2 für einen bloßen Besitznachweis vergeben.

Aufgenommen wurde `phr`, das im Trust-Level-Pfad fehlte, und `passkey` gilt nun auch für `federation` — das sind die beiden Richtungen der oben beschriebenen Nicht-Monotonie.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.3.1** | **IDP-052 ist nicht verdrahtet.** `federation.ValidateCustomerIdPAuth` hat keinen Aufrufer — wie zuvor die DPoP-Middleware. Ein sinnvoller Anschluss setzt voraus, dass der Enforcement-Pfad erkennt, ob ein Principal aus einem Kunden-IdP stammt; dafür fehlt ein `idp`-Claim und dessen Auswertung im Verifier. Teilweise gedeckt ist die Absicht seit § 3.2: eine Anmeldung ohne phishing-resistente Methode erreicht kein L2 und L3 gar nicht. | Eigener Entwurf (Claim, Gate, Katalogflag für „privilegiert"). | § 3.3, § 5.8 |

### 3.4 mTLS-Zertifikate erhalten pauschal L3 · `principal/certificate.go`

```go
p := &Principal{ …, TrustLevel: TrustLevelL3, … }
```

Jedes gültige Client-Zertifikat — Gerät, interner Service, CI-Workload — erhält das höchste Vertrauensniveau. `enforce.TrustGate` prüft nur `p.TrustLevel.AtLeast(req.RequiredTrustLevel)`. Ein Geräte-Zertifikat erfüllt damit jedes L3-Gate, auch eines, das für menschliche Dual-Passkey-Freigaben gedacht ist.

Zwei unvergleichbare Skalen (Kanalbindung vs. Authenticator-Assurance) sind auf eine kollabiert. Zusätzlich setzt `ExtractPrincipalFromCertificate` `AuthTime: cert.NotBefore` — bei einem 90-Tage-Zertifikat ist `AuthTime` bis zu 90 Tage alt, sodass jedes `StepUpGate` fehlschlägt. Geräte bestehen also den Trust-Check und scheitern am Step-Up: die Semantik ist in beide Richtungen falsch.

#### 3.4-T Ergebnis und offene Tickets aus der Umsetzung von 3.4

`principal.ActorType.HasAuthenticatorAssurance()` trennt die beiden Skalen: L1–L3 beschreiben eine **menschliche** Authentisierungszeremonie, die `human` und `operator` durchlaufen können und `service_account`, `workload`, `device` nicht. Zertifikate erhalten L1 statt L3, `AuthTime` ist der Zeitpunkt der Vorlage statt `NotBefore`. `TrustGate` lehnt ab L2 jeden Aktor ohne Assurance ab, `StepUpGate` verweigert Maschinen die Step-up-Anforderung mit klarem Fehler statt einer RFC-9470-Challenge, die sie nie erfüllen könnten.

Entscheidend ist, **wo** die Prüfung sitzt: im Gate, nicht im Extractor. Der Test konstruiert Geräte-Principals mit von Hand gesetztem `TrustLevelL3` — dem Wert, den der Extractor früher vergab — und weist nach, dass das Gate sie trotzdem ablehnt. Sonst hinge die Zusage daran, dass jede künftige Credential-Quelle sich korrekt verhält.

**Der Defekt war beidseitig, und die andere Seite bleibt offen:** Ein CI-Workload über den *Token*-Pfad hat kein `amr` und landet seit § 3.2 auf L1; über den *Zertifikats*-Pfad bekam derselbe Workload L3. Welche Rechte eine Maschine hatte, hing also am Credential-Typ. Jetzt sind es einheitlich L1-Permissionen — richtig gegen die Eskalation, aber es fehlt weiterhin jede Möglichkeit, einer Maschine legitim mehr zu geben.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.4.1** | **`allowed_actors` je Permission im Katalog.** Maschinenrechte müssen positiv ausgedrückt werden („diese Operation dürfen `workload` und `human`") statt als Nebenwirkung eines menschlichen Assurance-Levels. Betrifft `policy/permissions.yaml` (22 Einträge), `policygen`, die Registry und ein Gate. Ohne das kann ein CI-Workload `registry.package.publish` (L2) nicht ausüben — heute nur deshalb, weil sein Zertifikat sich als L3 ausgab. | Eigener Katalogschnitt, gemeinsam mit den übrigen O5-Feldern. | § 3.4, O5 |
| **T-3.4.2** ✅ | **§ 3.8: Geräte-Leafs tragen `ExtKeyUsageServerAuth`**, die Tenant-CA hat keine Pfadlängenbeschränkung, und die Tenant-Isolation ist ein OU-Stringvergleich statt X.509 Name Constraints. Zertifikats*inhalte*, nicht Trust-Level-Ableitung. | Eigener Befund (§ 3.8, O12). | § 3.8 |

### 3.5 Fünf von vierzehn Zitadel-Regeln fallen bei fehlendem Feld offen · `target/rules.go`

Alle Regeln lesen mit ignoriertem `ok`:

```go
role, _ := req.Payload["user_role"].(string)
failedAttempts, _ := req.Payload["failed_attempts"].(float64)
```

| Regel | Fehlendes Feld ⇒ | |
|---|---|---|
| `dual_authenticator_requirement` | `0 < 2` ⇒ **deny** | ✅ |
| `secure_factor_registration` | `"" ∉ {L2,L3}` ⇒ **deny** | ✅ |
| `webauthn_only_privileged` | `""` ⇒ nicht privilegiert ⇒ **allow** | ❌ |
| `no_self_service_reset` | `false` ⇒ **allow** | ❌ |
| `lockout_policy` | `0 < 5` ⇒ **allow** | ❌ |
| `mfa_init_skip_disallowed` | `false` ⇒ **allow** | ❌ |
| `invite_rules` | `""` ⇒ **deny** | ✅ |

Die Payload kommt über HTTP von Zitadel. Eine Feldumbenennung in einer Zitadel-Version deaktiviert vier Regeln lautlos. Es gibt keine Schemavalidierung von `TargetRequest.Payload`.

Verschärfend der Dispatcher:

```go
default:
    return &TargetResponse{Allow: true}, nil
```

Ein unbekannter Regelname — inklusive des Fallbacks `ruleName = string(req.HookType)` für jeden nicht gelisteten Hook-Typ — wird erlaubt. Fail-open als Default in einem Policy-Dispatcher.

Und `EvaluateGitHubUpstreamPolicy` hartkodiert `"toob-boot"` als einzig zulässige GitHub-Organisation — in einem Produkt, dessen Kernversprechen B2B2C-Föderation ist. Jede Kunden-GitHub-Anbindung wird abgelehnt.

#### 3.5-T Ergebnis und offene Tickets aus der Umsetzung von 3.5

**Es waren nicht fünf von vierzehn Regeln, sondern der Zugriffsstil aller vierzehn.** Jede las mit verworfenem `ok`; auf welcher Seite ein fehlendes Feld landete, war ein Zufall der nachfolgenden Vergleichsrichtung. Über die im Bericht genannten hinaus fielen auch `permanent_l3_no_downgrade`, `role_elevation_owner_approval`, `user_login_must_be_domain` und `github_upstream_policy` offen — und `break_glass_audit` protokollierte bei fehlender Rolle schlicht nichts.

Ein `payload`-Decoder (`identity/target/payload.go`) sammelt jetzt fehlende und typfalsche Felder und benennt sie in der Ablehnung. Der Default-Zweig lehnt ab; Hook-Typen, die dieser Dienst bewusst nicht prüft (`pre_token_creation`, `post_authentication`), sind explizit als solche deklariert — sonst wäre „deny by default" nicht von „wir haben keine Regel dafür" unterscheidbar. `factor_policy.yaml` ist verdrahtet, die AMR-Prüfung nutzt das kanonische Vokabular aus § 3.3 statt `strings.Contains`.

Zwei Funde über den Bericht hinaus:

- **Die Kritikalität kam vom Aufrufer.** `handler.go` entschied Fail-open/Fail-closed anhand von `req.IsCritical` — einem Feld aus dem Payload. Ein Timeout bei `webauthn_only_privileged` wurde durchgewinkt, wenn Zitadel das Feld nicht setzte. Kritikalität wird jetzt lokal aus der Regel bestimmt; das Payload-Flag darf sie nur noch erhöhen.
- **`io.ReadAll` ohne Grenze vor der Signaturprüfung** (O13) — jetzt `http.MaxBytesReader` mit 64 KiB.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.5.1** | **Replay-Fenster auf dem Zitadel-Webhook** (zweite Hälfte von O13). Eine gültige Signatur ist unbegrenzt wiederverwendbar; nötig sind ein `t=`-Timestamp im Signaturheader analog `sync/outbound.go` und ein Replay-Store. | Braucht Header-Format und Store, eigener Schnitt. | O13 |
| **T-3.5.2** | **`GitHubOrgPolicy` braucht eine dauerhafte Quelle.** Es gibt nur `MemoryGitHubOrgPolicy`; die zulässigen Organisationen eines Tenants müssen aus der Tenant-Konfiguration kommen — dieselbe Familie wie der Break-Glass-`GrantStore` (T-2.5.2). | Sammelposten Persistenz, Sprint 3. | § 3.5, § 6.4 |
| **T-3.5.3** | **Feldnamen gegen das reale Zitadel verifizieren.** Fail-closed hat eine Kehrseite: Benennt eine Zitadel-Version ein Payload-Feld um, **blockiert** der Hook den Login, statt die Regel stillzulegen. Die erwarteten Namen stehen jetzt an einer Stelle und erscheinen namentlich in Log und Antwort — ein Contract-Test gegen eine echte Zitadel-Instanz (oder die Action-Definitionen im Provisioning) fehlt trotzdem. | Braucht eine laufende Zitadel-Instanz; gehört zu den Actions-Definitionen aus T-3.2.1. | § 3.5, § 10 |

### 3.6 SCIM: Authentifizierung optional, Deprovisionierung wirkungslos

```go
func NewSCIMHandler(provider *ServiceProvider) *SCIMHandler { return &SCIMHandler{provider: provider} }
…
if h.authToken != "" { /* Bearer prüfen */ }
```

Ein ohne `WithAuthToken` konstruierter Handler ist **unauthentifiziert** — und genau so wird er im Contract-Test und im Handler-Test gebaut. Der Vergleich ist zudem nicht laufzeitkonstant.

Der Deprovisionierungspfad trifft weiterhin ins Leere:

```go
// scim/provider.go
principalURN, _ := principal.FormatHumanURN("shared", "org_scim", updated.ID)
p.revocation.RevokePrincipal(ctx, principalURN)
```

`org_scim` ist eine erfundene Organisation, `shared` eine hartkodierte Zelle. Der reale Principal heißt `toob:human:<cell>:<echteOrg>:<id>`. Der Kill-Switch-Eintrag matcht nie. Im selben Paket baut `deprovision.go` den URN anders (`toob:human:shared:%s:%s` mit echtem Tenant) — zwei Konstruktionen, beide an `principal.FormatHumanURN`s Zellparameter vorbei.

Weiter: kein Tenant-Pfadsegment (`/scim/v2/{orgId}`), `MemoryUserStore.byEmail` ist global → **zwei Tenants können keine Nutzer mit gleicher E-Mail haben**, und der Account-Takeover-Guard vergleicht `externalId` über Tenantgrenzen hinweg. Die Idempotenzprüfung ist ein Lookup-dann-Create außerhalb jedes Locks (TOCTOU) ohne Unique-Constraint.

#### 3.6-T Ergebnis und offene Tickets aus der Umsetzung von 3.6

Alle vier Teilbefunde hatten dieselbe Ursache: **SCIM kannte keinen Mandanten.** Der Pfad ist jetzt `/scim/v2/{tenantID}/Users[/{id}]`, der `TokenVerifier` ist Konstruktor-Pflicht und prüft je Mandant über SHA-256-Digest mit `subtle.ConstantTimeCompare`, jede `UserStore`-Methode führt den Mandanten, und die Idempotenz liegt als `CreateUserIfAbsent` unter dem Lock des Stores. Die Principal-URN entsteht an **einer** Stelle (`ServiceProvider.PrincipalURN`) aus echter Zelle und echtem Mandanten; der Fallback in `deprovision.go` ist ersatzlos entfallen.

Zwei Verschärfungen über den Bericht hinaus:

- **Eine fehlgeschlagene Deprovisionierung wurde als Erfolg gemeldet.** `UpdateUser` protokollierte den Revocation-Fehler und gab den Nutzer zurück; der IdP sah HTTP 200. Fehler werden jetzt durchgereicht, und `DeleteUser` widerruft **vor** dem Löschen — ein gelöschtes Konto mit weiterhin gültiger Session ist schlimmer als ein Datensatz, den man erneut löschen kann.
- **Der Test hielt die nie matchende URN als Sollwert fest** (`toob:human:shared:org_scim:<id>`), wie schon in § 3.2 und § 3.4.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.6.1** | **Postgres-`UserStore` mit Unique-Constraints.** `CreateUserIfAbsent` ist so geschnitten, dass die Implementierung `UNIQUE (tenant_id, external_id)` und `UNIQUE (tenant_id, primary_email)` plus `ON CONFLICT` wird, statt die Invariante erneut in der Anwendung zu bauen. | Sammelposten Persistenz, Sprint 3, Punkt 24. | § 3.6, § 6.4 |
| **T-3.6.2** | **`CellResolver` an `celldir` anschließen.** Es gibt nur `MemoryCellResolver`; die Zelle steht autoritativ in `celldir.CellCoordinates.CellID`. Der Adapter gehört an die Stelle, an der SCIM montiert wird — also an `cmd/identity-api`. | Braucht den Server (Sprint 3, Punkt 25). | § 3.6 |
| **T-3.6.3** ✅ | **PATCH ist kein PUT.** `handleUpdateUser` behandelt beide gleich und ersetzt die Ressource. RFC 7644 § 3.5.2 verlangt für PATCH `Operations`-Semantik; ein IdP, der nur `active: false` patcht, löscht damit heute alle übrigen Felder. | **Erledigt.** `scim/patch.go` ist ein reiner Operationsparser (`ApplyPatchOperations`), `ServiceProvider.PatchUser` lädt, patcht eine entkoppelte Kopie und reicht sie an `UpdateUser` — damit widerruft `active:false` per PATCH die Sitzungen genauso wie per PUT. Deny-by-default: unbekannte `op`, unbekannter Pfad, Wertfilter, fehlendes `PatchOp`-Schema und das Entfernen von Pflichtattributen sind 400 mit `scimType`, kein stilles Ignorieren. Der pfadlose Objekt-Merge (Okta/Zitadel) wird unterstützt. | § 3.6 |
| **T-3.6.4** ✅ | **`internal/scim/mapping.go` schreibt Tupel auf `group:<id>`** — einen Typ, den das FGA-Modell nicht kennt (§ 5.6). | **Erledigt, in zwei Schritten und ohne O1.** Der Schreiber ist weg — `mapping.go` ist heute ein leerer Typ —, und die Klasse ist geschlossen: `authz.TupleKey.Validate()` ruft `spolicy.ValidateTuple`, jeder Erzeuger ruft es vor dem Schreiben, und ein unbekannter Objekttyp fällt damit vor dem Netzwerkaufruf durch. Die Generierung aus O1 würde denselben Fehler noch früher fangen, ist aber nicht mehr die Bedingung dafür. | § 5.6 |
| **T-3.6.5** | **PATCH ist ein Read-Modify-Write ohne Sperre.** `PatchUser` liest, patcht und schreibt; zwei gleichzeitige PATCHes desselben Benutzers verlieren einen. Die Antwort steht in RFC 7644 § 3.14 — `meta.version` als ETag plus `If-Match` —, und `SCIMMeta.Version` existiert bereits ungenutzt. | Braucht optimistische Nebenläufigkeit im `UserStore`, dieselbe Familie wie T-3.6.1. | § 3.6, § 7 |

### 3.7 Weitere Fail-open-Stellen

| Ort | Muster |
|---|---|
| `audit/dispatcher.go` | `if d.writer != nil { writeErr = … }` — ohne Writer bleibt `writeErr` nil ⇒ **kritischer Audit „gelingt"**. `NewAuditDispatcher(nil)` ist konstruierbar. |
| `audit/dispatcher.go` | Nicht-kritischer Schreibfehler ⇒ Log „BUFFERED / DEFERRED", Rückgabe nil. Es wird nichts gepuffert; das Event ist weg. |
| `audit/ledger.go` | `RecordEventAsync`: ohne Writer/Tx passiert nichts, geloggt wird „AUDIT EVENT RECORDED". |
| `sync/writer.go` | `SaveEvent`: Type-Assertion auf `*MemoryTx`; jede andere `Tx` ⇒ `return nil` ohne Speichern. |
| `sync/writer.go` | Sequenznummer nur für `*MemoryOutboxStore`; sonst konstant `1` ⇒ Ordering-Garantie still weg. |
| `celldir/resolver.go` | Fetch liefert ungültigen Eintrag ⇒ `Validate()`-Fehler wird kommentarlos verschluckt, Fallthrough auf Stale-Cache oder `ErrTenantNotFound`. |
| `dpop/replay.go` | Valkey-Fehler oder `client == nil` ⇒ Fallback auf **prozesslokalen** Memory-Store. Replay-Schutz degradiert damit exakt im Mehrinstanzfall auf wirkungslos. |
| `token/exchange.go` | Rate-Limit wird mit leerem `TokenHash` und leerem `TenantID` aufgerufen ⇒ `MultiLimiter` überspringt alle Dimensionen ⇒ **No-Op**. |
| `token/exchange.go` | `RequestedLifetime <= 0` ⇒ Default ist das **Maximum** (4 h) statt eines kurzen Werts. |
| `cmd/zitadel-provision` | `CreateProject`/`CreateRole` prüfen den HTTP-Status **nicht**; ein 403 liefert leere ID und `nil` ⇒ der Provisioner meldet Erfolg. |

#### 3.7-T Ergebnis und offene Tickets aus der Umsetzung von 3.7

Alle zehn Stellen sind geschlossen, nach einem Prinzip: **eine Sicherheitskomponente hat ihre Abhängigkeit oder lässt sich nicht konstruieren.** `NewAuditDispatcher`, `NewAuditLedgerService` und `NewValkeyReplayStore` paniken bei nil; `RecordEventAsync` verlangt eine Transaktion und loggt erst **nach** dem Schreiben; `SaveEvent` lehnt eine fremde `Tx` ab; die Outbox-Sequenz ist Teil der `OutboxStore`-Schnittstelle statt einer Type-Assertion mit Konstante 1; der Resolver meldet ungültige Verzeichniseinträge, statt auf veraltete Koordinaten zurückzufallen; der Valkey-Replay-Store lehnt bei Ausfall ab, statt prozesslokal weiterzulaufen; das Rate-Limit des Token-Exchange ist zweistufig verdrahtet (Token-Dimension vor, Tenant-Dimension nach der Verifikation) und `RequestedLifetime` ist Pflicht; der Zitadel-Client prüft den HTTP-Status.

**Ein Entwurfsfehler kam beim Umbau ans Licht:** `CheckpointEngine.VerifyCheckpointStandalone` konstruierte `NewAuditLedgerService(nil)`, nur um `VerifyTenantChain` zu erreichen. Kettenprüfung ist eine reine Funktion der Einträge — sie hängt weder an einem Writer noch an einer Transaktion. `VerifyTenantChain` ist jetzt zusätzlich als Paketfunktion verfügbar; die Methode delegiert. Genau so wird ein nil-toleranter Konstruktor tragend: weil eine reine Operation nur über ein Objekt erreichbar ist, das sie nicht braucht.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.7.1** | **Echter Puffer für nicht-kritische Audits.** Der Dispatcher protokolliert jetzt ehrlich „DROPPED (NOT BUFFERED)", statt eine Pufferung zu behaupten, die es nie gab. Ein tatsächlicher Puffer braucht einen Speicher und gehört zum Outbox-/DLQ-Komplex. | Braucht Persistenz (Sprint 3). | § 3.7, § 6.4 |
| **T-3.7.2** ✅ | **`audit.AuditWriter` ist `type AuditWriter struct{}`.** Der Ledger hat weiterhin keinen Schreiber (§ 4.2). Diese Änderung macht das Fehlen nur sichtbar, statt Erfolg zu melden — der Schreiber selbst fehlt. | Gehört zum Ledger-Umbau (Sprint 2, Punkt 18). | § 4.2 |
| **T-3.7.3** | **Valkey ist nirgends verdrahtet.** `ValkeyReplayStore` verlangt jetzt einen Client, hat aber außerhalb von Tests keine Konstruktionsstelle (§ 10). Bis dahin läuft DPoP-Replay-Schutz nur mit dem explizit gewählten Memory-Store, also einzelinstanzfähig. | Braucht Konfiguration und den Server. | § 10 |

### 3.8 Kryptografie und Geheimnisse

- **Hartkodierte Pseudonymisierungs-Secrets.** `audit.NewRetentionEngine(nil)` → `[]byte("default_audit_retention_secret")`, `sync.NewPurgeEngine(nil)` → `[]byte("default_gdpr_pseudonymization_secret")`. Ein HMAC mit im Quelltext stehendem Schlüssel ist keine Pseudonymisierung — jeder mit Repo-Zugriff kann die Abbildung `usr_x → anon_usr_…` vollständig rekonstruieren.
- **Nicht-konstanter Vergleich** bei CSRF (`csrfReq != sess.CSRFToken`, `bff/bff.go`) und beim SCIM-Bearer-Token.
- **Secret-Präfix im Log**: `pki/workload.go` loggt `rawStaticSecret[:min(len,4)]+"***"`.
- **Geräte-Leafs mit `ExtKeyUsageServerAuth`** (`pki/hierarchy.go`): ein kompromittiertes Gerät kann sich in mTLS als *Server* ausgeben. Geräte brauchen ausschließlich `ClientAuth`.
- **Tenant-CA ohne Pfadlängenbeschränkung**: `MaxPathLen: 0` ohne `MaxPathLenZero: true` kodiert in Go „keine Beschränkung" — die Tenant-CA darf Sub-CAs ausstellen.
- **Tenant-Isolation ist eine String-Prüfung.** `VerifyCertificateChain` vergleicht `OrganizationalUnit[0]`; es gibt keine X.509 Name Constraints. Die Garantie hält nur, weil der Verifizierer die erwartete Tenant-CA übergeben bekommt. `MTLSTerminationMiddleware.HTTPMiddleware(expectedTenantID)` nimmt den Tenant als **statischen Parameter** — ein Endpunkt bedient damit genau einen Tenant. Ein realer mandantenfähiger Edge muss den Tenant aus dem Zertifikat ableiten, und genau dann fällt die Prüfung in sich zusammen.
- **Bootstrap-Invalidierung im Prozessspeicher** (`pki.InMemoryBootstrapInvalidationStore`): nach jedem Deploy ist jedes werksseitige Bootstrap-Zertifikat (Laufzeit 1 Jahr) wieder einlösbar. Zudem wird das operative Zertifikat **vor** dem Verbrennen ausgestellt — schlägt das Markieren fehl, existieren beide.
- **`.env.dev` / `.env.staging`** enthalten produktionsnahe Zugangsdaten (Hetzner, Ubicloud, Cloudflare, DockerHub, S3) sowie `Klopfer1025!` als Webhook-Secret und Grafana-Passwort. Zusätzlich: `SEED_GH_CLIENT_ID == SEED_GH_CLIENT_SECRET` (identischer Wert ⇒ GitHub-OAuth funktioniert nicht), und die beiden Hetzner-Token unterscheiden sich um genau ein Zeichen (`GQyue` / `GQvue`) — eines der beiden ist ein Vertipper. **Alle Werte als kompromittiert behandeln und rotieren.**

#### 3.8-T Ergebnis und offene Tickets aus der Umsetzung von 3.8

Sieben der acht Punkte waren offen; der nicht-konstante SCIM-Bearer-Vergleich war bereits mit § 3.6 erledigt (`subtle.ConstantTimeCompare` auf SHA-256-Digests). Zwei Angaben im Befund waren zu korrigieren: `SEED_GH_CLIENT_ID == SEED_GH_CLIENT_SECRET` ist bestätigt (40 Zeichen, identisch), die „um ein Zeichen abweichenden Hetzner-Token" sind in `.env.dev` dagegen zeichengleich.

**Der Leitgedanke war, Zusicherungen aus Zeichenketten in Kryptografie zu überführen.** Geräte-Leafs tragen nur noch `ClientAuth` — ein kompromittiertes Gerät kann sich nicht mehr als Toob-Dienst ausgeben; zellinterne Workloads behalten beide EKUs, weil ein Dienst tatsächlich Server *und* Client ist, und der Unterschied steht als Kommentar im Code. Die Tenant-CA bekam `MaxPathLenZero: true`, ohne das Go `MaxPathLen: 0` als „unbeschränkt" kodiert; alle Leafs stellen jetzt ein explizites kritisches `CA:FALSE`. Die Pseudonymisierungsschlüssel sind Pflichtparameter mit Mindestlänge 32 Byte — `NewRetentionEngine` und `NewPurgeEngine` paniken sonst, statt einen im Quelltext stehenden HMAC-Schlüssel zu verwenden, mit dem jeder Repo-Leser die Abbildung `usr_x → anon_usr_…` rekonstruieren kann. Der CSRF-Vergleich läuft konstant-zeitig, und die Methodenprüfung ist Deny-by-Default: befreit sind `GET`, `HEAD`, `OPTIONS`, `TRACE`, alles andere braucht den Token — die vorherige Aufzählung der unsicheren Methoden ließ ein kleingeschriebenes `post` durch, das Go unverändert weiterreicht.

**O12 ist nicht so umsetzbar, wie es dasteht.** Gos Verifizierer unterstützt X.509 Name Constraints nur für DNS, IP, E-Mail und URIs *mit Host*. Unsere Identität steht in einem `OrganizationalUnit` (= `directoryName`) und in einer hostlosen `toob:`-URI; eine `directoryName`-Constraint landete in `UnhandledCriticalExtensions` und ließe danach **jede** Verifikation scheitern. Die gemeinte Garantie ist stattdessen über einen **Trust-Anchor pro Tenant** umgesetzt (`pki.TenantTrustStore`): der Edge liest den Tenant aus dem vorgelegten Zertifikat — ein ungeprüfter Anspruch, ausschließlich als Nachschlageschlüssel — und verifiziert gegen die Anker genau dieses Tenants. Ein gefälschter Anspruch wählt damit eine Ankermenge, zu der die Kette sich gar nicht bilden lässt. `HTTPMiddleware` verliert seinen `expectedTenantID`-Parameter; ein Endpunkt bedient jetzt alle registrierten Tenants. Damit ist auch **T-3.4.2 erledigt** (Geräte-EKU, Pfadlänge, OU-Stringvergleich).

**Die Bootstrap-Einlösung war ein TOCTOU.** `IsBootstrapInvalidated` und `MarkBootstrapInvalidated` waren zwei Aufrufe — zwei gleichzeitige Einlösungen desselben Werkszertifikats bestanden beide die Prüfung. Das Interface hat jetzt eine einzige Operation `BurnBootstrap`, die beim zweiten Mal `ErrBootstrapAlreadyInvalidated` liefert, und sie läuft **vor** der Ausstellung, nachdem alle Prüfungen bestanden sind. Der Preis ist bewusst gewählt: schlägt die Ausstellung danach fehl, ist das Werkszertifikat verbraucht und das Gerät muss neu provisioniert werden. Die umgekehrte Reihenfolge ist die gefährliche — sie lässt aus einem extrahierten Werksschlüssel eine zweite operative Identität entstehen, still und ohne Spur.

**Fünf angrenzende Fail-open-Stellen im selben Code wurden mitgeschlossen:** der Kill-Switch verwarf den Registry-Fehler (`revoked, rec, _ :=`) und ließ damit jede Anfrage durch, sobald die Sperrliste unerreichbar war — eine unerreichbare Registry heißt jetzt „unbekannt" und wird abgelehnt; er war zudem optional (`killSwitch != nil`) und ist jetzt Pflichtabhängigkeit des Konstruktors, ebenso Trust-Store und SAN-Verifizierer. Der Spoofing-Alarm loggte den angreiferkontrollierten Headerwert, die Static-Secret-Sperre vier Zeichen des vorgelegten Geheimnisses — beides entfällt. Dazu: totes Feld `pkiEngine` in `WorkloadIdentityEngine` entfernt (der Konstruktor verliert den Parameter), lokales `min` gelöscht, das seit Go 1.21 das Builtin verdeckte, vier `rand.Int`-Kopien mit verworfenem Fehler durch `newSerialNumber()` ersetzt, `url.Parse`-Fehler behandelt, und die SAN-URN-Extraktion aus `ExtractPrincipalFromCertificate` als `principal.SANURNFromCertificate` herausgezogen, statt sie im Edge ein drittes Mal zu schreiben.

`.env.dev` und `coverage` waren **getrackt** — `.gitignore` greift bei bereits getrackten Dateien nicht. Beide sind jetzt aus dem Index entfernt (Dateien bleiben auf der Platte), `coverage` steht in `.gitignore`. Die Werte selbst liegen weiterhin in der Historie (seit `e26f47d`); Rotation und ein möglicher Historien-Rewrite sind T-3.8.1.

Neue Tests, jeder vorher rot: `TestPKI_DeviceLeafIsClientAuthOnly`, `TestPKI_TenantCACannotIssueSubCA` (Sub-CA unter der Tenant-CA verifiziert nicht), `TestMTLSTermination_ServesEveryRegisteredTenant`, `TestMTLSTermination_ForgedTenantClaimCannotChain` (Leaf mit OU `org_globex`, signiert von `org_acme`), `TestMTLSTermination_UnregisteredTenantIsRejected`, `TestMTLSTermination_KillSwitchErrorDeniesAccess`, `TestMTLSTermination_RevokedDeviceIsRejected`, `TestMTLSTermination_RequiresKillSwitch`, `TestZeroTouch_ConcurrentExchangeYieldsOneIdentity` (acht parallele Einlösungen, genau eine gewinnt), `TestZeroTouch_BootstrapIsSpentEvenIfIssuanceFails`, `TestZeroTouch_RequiresInvalidationStore`, `TestRetention_RejectsWeakPseudonymizationKey`, `TestDeletion_RejectsWeakPseudonymizationKey` sowie sechs CSRF-Fälle für `post`, `PROPFIND`, `CONNECT` und die drei sicheren Methoden. Drei bestehende Tests kodierten den Defekt und wurden korrigiert: zwei übergaben Schlüssel mit 12 bzw. 15 Byte, einer `nil`.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-3.8.1** | **Secrets rotieren, dann über die Historie entscheiden.** Alle Werte aus `.env.dev`/`.env.staging` bei Hetzner, Ubicloud, Cloudflare, DockerHub, S3, GitHub und Grafana erneuern und `SEED_GH_CLIENT_ID == SEED_GH_CLIENT_SECRET` korrigieren. `git rm --cached` entfernt die Datei nur aus dem Index — die Werte stehen seit `e26f47d` in der Historie. Ein `git filter-repo` plus Force-Push ist irreversibel und ohne vorherige Rotation wirkungslos. | Nur der Betreiber kann rotieren; der Rewrite braucht eine ausdrückliche Entscheidung. | § 3.8 |
| **T-3.8.2** | **Persistenter `BootstrapInvalidationStore`.** Die In-Memory-Variante ist jetzt korrekt atomar, aber prozesslokal — nach jedem Deploy ist jedes werksseitige Zertifikat (Laufzeit 1 Jahr) wieder einlösbar. | Braucht Postgres (Sprint 3). | § 3.8, § 10 |
| **T-3.8.3** | **Echte Name Constraints (O12).** Erst wenn SAN-URIs ein hostführendes Schema tragen (z. B. `spiffe://<tenant>.<cell>.toob.internal/...`), greift `PermittedURIDomains` und die Isolation steht im Zertifikat statt in der Nachschlagelogik. | Berührt `principal.ParseURN` und das gesamte URN-Vokabular. | § 3.8, § 5.5, § 5.6 |
| **T-3.8.4** | **Kein Edge-Pfad für Operator- und zellweite Workload-Zertifikate.** `IssueWorkloadCertificate` signiert mit der Zell-CA und trägt `OU=cell:<id>`; solche Leafs können die Tenant-CA-Prüfung konstruktionsbedingt nicht bestehen. Bisher scheiterten sie am statischen OU-Vergleich, jetzt an der fehlenden Tenant-Ableitung — in beiden Fällen gibt es keinen Weg durch den Edge. | Eigener Schnitt: braucht eine zweite Ankerklasse für zellweite Identitäten. | § 3.8 |
| **T-3.8.5** ✅ | **Doppelte Audit-Hash-Definition.** `AuditLogRecord`, `ComputeAuditLogHash` und `PseudonymizePII` existieren in `identity/audit` **und** `identity/sync` — mit verschiedenen Hashfunktionen (kanonisch vs. `fmt.Fprintf`). Derselbe Datensatz hasht in beiden Paketen unterschiedlich. | Zusammenlegen erst gemeinsam mit § 4.1, sonst migriert man auf einen Hash, den § 4.1 wieder ändert. | § 3.8, § 4.1, § 5 |
| **T-3.8.6** | **Herkunft des Pseudonymisierungsschlüssels.** Die Engines verlangen ihn jetzt; die Verdrahtung aus Vault (`shared/vault`) fehlt, weil es außerhalb der Tests keine Konstruktionsstelle gibt. | Braucht den Server (Sprint 3, Punkt 25). | § 3.8 |
| **T-3.8.7** ✅ | **`ComputeAuditLogHash` fällt bei Fehler auf eine andere Hashfunktion zurück** (`audit/retention.go`): schlägt `ComputeCanonicalHash` fehl, wird still ein SHA-256 über eine `fmt.Sprintf`-Zeile zurückgegeben. Stiller Algorithmuswechsel mitten in der Kette. | Gehört zum Hash-Umbau in § 4.1. | § 3.8, § 4.1 |

---

## 4. Mathematisch-logische Defekte

### 4.1 Der Audit-Hash bindet den Datensatz nicht

```go
// audit/retention.go
func ComputeAuditLogHash(id, actor, target, action, prevHash string) string {
	hash, _, err := ComputeCanonicalHash(prevHash, "shared", 1, actor, action, target, time.Time{})
	…
}
```

Der Parameter `id` wird **nicht verwendet**; `tenantID` ist konstant `"shared"`, `seq` konstant `1`, `timestamp` der Nullwert. Die Kette committet damit nur auf die Projektion `(actor, action, target, prevHash)`.

Sei `π(r) = (actor, action, target)`. Dann gilt für zwei Einträge mit `π(r_i) = π(r_j)`: `h_i` und `h_j` sind bei gleichem Vorgänger identisch. Folge: **Einträge mit gleicher Projektion sind austauschbar, duplizierbar und löschbar, ohne die Kette zu brechen.** Ein Ledger mit `(rec_01, alice, doc_100, read)` und `(rec_09, alice, doc_100, read)` erlaubt, einen der beiden zu entfernen und den anderen zu duplizieren — die Verifikation bleibt grün. Weder Sequenz noch Zeitstempel noch ID sind gebunden.

Parallel existiert in `sync/deletion.go` eine **gleichnamige Funktion mit anderem Algorithmus**:

```go
fmt.Fprintf(h, "%s:%s:%s:%s:%s", id, actor, target, action, prevHash)
```

Zwei Funktionen `ComputeAuditLogHash` in zwei Paketen, unterschiedliche Werte, beide beanspruchen Ketten-Integrität. Ebenso ist `PseudonymizePII` wortgleich dupliziert.

#### 4.1-T Ergebnis und offene Tickets aus der Umsetzung von 4.1

Es waren nicht zwei Implementierungen, sondern **vier**: zwei Hashfunktionen (`audit.ComputeAuditLogHash` als kanonischer Aufruf mit Konstanten, `sync.ComputeAuditLogHash` als `fmt.Fprintf`) und **drei** Verifikationsschleifen (`VerifyTenantChain`, `AuditChainVerifier.VerifyChainWithCheckpoints`, `PurgeEngine.verifyAuditChainLocked`). Die drei Schleifen waren bereits auseinandergelaufen: nur die CLI-Variante prüfte, dass alle Einträge zum selben Mandanten gehören — `VerifyTenantChain` tat das trotz seines Namens **nicht**, und da jeder Eintrag seine eigene `tenant_id` hasht, verifizierte dort eine Kette, die zwischen Mandanten springt.

**Die Ursache war das Datenmodell, nicht der Hash.** `AuditLogRecord` hatte fünf Felder — id, actor, target, action, zwei Hashes. Kein Mandant, keine Sequenz, kein Zeitstempel. Eine Kette über diesen Typ *kann* nichts weiter binden; `ComputeAuditLogHash` war der Adapter, der das arme Modell in die reiche Funktion presste, indem er `tenantID = "shared"`, `seq = 1` und `timestamp = time.Time{}` erfand. Der Fix besteht deshalb im Löschen des zweiten Modells, nicht im Nachbessern des Hashes: Pseudonymisierung arbeitet jetzt auf `AuditEntry`, das Mandant, Sequenz, Zeitstempel und `canonical_json` ohnehin führt.

`ComputeCanonicalHash` mit seinen sieben Positionsparametern — vier davon benachbarte Strings — ist durch die Methode `AuditEntry.Canonicalize()` ersetzt, dazu `Seal(prevHash)` für den Schreibpfad. Genau diese Signatur hatte den Defekt erst ermöglicht: `action` und `target` zu vertauschen oder Konstanten für Mandant und Sequenz einzusetzen kompilierte lautlos. Die kanonische Struktur bindet jetzt zusätzlich `id`, und der Zeitstempel wird vor dem Formatieren auf **Mikrosekunden** getruncatet — `audit_ledger.created_at` ist `TIMESTAMP WITH TIME ZONE`, ohne die Truncation wäre jeder Hash nach dem ersten Postgres-Roundtrip falsch (erste Hälfte von § 4.2).

`sync` gibt die Audit-Kette ab. `identity/audit` importiert `identity/sync` (§ 8.1), `sync` kann also nicht zurückimportieren — genau daher stammte die Duplikation. Was `sync` dort hatte, gehörte ihm aber ohnehin nicht: `MemoryPurgeStore.AuditLedger` war ein Slice, den ausschließlich sein eigener Test befüllte. `PurgeEngine` deklariert die Abhängigkeit jetzt als Port `AuditRedactor` (Pflicht, Panic bei nil, Fehler bricht die Löschung ab), statt AUD-06 ein zweites Mal zu implementieren. Nebeneffekt: die Purge braucht keinen Pseudonymisierungsschlüssel mehr, der GDPR-Schlüssel lebt nur noch in `audit.RetentionEngine`.

Dazu aufgeräumt: `chain.go` enthielt `type HashChain struct{}` — toter Stub (§ 5.8) — und trägt jetzt die Kette selbst (`Canonicalize`, `Seal`, `ChainDivergence`, `VerifyChain`), während `ledger.go` den Dienst behält.

**Ein glücklicher Umstand machte das billig:** `audit/writer.go` ist `type AuditWriter struct{}`, niemand vergibt Sequenznummern, niemand schreibt `audit_ledger`. Es gab **keine gespeicherten Hashes**. Nach dem ersten produktiven Eintrag wäre dieselbe Änderung eine Migration über eine Tabelle, der `UPDATE` und `DELETE` per `REVOKE` entzogen sind.

Neue Tests: `TestAuditChain_HashBindsEveryField` (tabellengetrieben über alle acht Felder — der direkte Beweis), `TestAuditChain_SwappedTwinsAreDetected` (das Szenario aus dem Befund: zwei Einträge mit gleicher Projektion tauschen ID und Zeitstempel, alle gespeicherten Hashes bleiben gültig), `TestAuditChain_MixedTenantsAreRejected`, `TestAuditChain_HashSurvivesTheStorageRoundtrip`, `TestAuditChain_DivergenceNamesTheEntry`, `TestDeletion_RequiresAuditRedactor`, `TestDeletion_FailedRedactionFailsTheErasure`. **Zwei bestehende Tests kodierten den Defekt**: `TestRetention_PseudonymizationLeavesChainIntact` und `TestDeletion_AuditChainVerifiesAfterPseudonymization` prüften die Kette mit derselben kaputten Funktion, die sie erzeugt hatte, und konnten konstruktionsbedingt nicht fehlschlagen.

Damit sind **T-3.8.5** und **T-3.8.7** erledigt.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.1.1** | **`AuditRedactor` hat keine Implementierung.** `audit.RetentionEngine.PseudonymizeUserPII` ist die richtige, aber rein: sie nimmt eine Kette und gibt eine zurück. Ein Adapter, der den Port erfüllt, braucht einen Ledger-Speicher, den es nicht gibt (T-3.7.2). Bis dahin gibt es außerhalb der Tests keine Konstruktionsstelle für `PurgeEngine` — der Panic macht das sichtbar, statt eine Löschung zu melden, die den Audit-Ledger nicht anfasst. | Braucht den Ledger-Schreiber und Postgres (Sprint 3). | § 4.1, § 4.2 |
| **T-4.1.2** | **Pseudonymisierung ist von Manipulation nicht unterscheidbar.** Die Redaktion siegelt die Kette ab dem betroffenen Eintrag neu; jeder vorher gezogene Checkpoint passt danach nicht mehr. Ohne einen Anker, der „hier wurde rechtmäßig redigiert" signiert festhält, sieht eine DSGVO-Löschung aus wie ein Angriff. | Gehört zum Anker-Konzept aus § 4.2. | § 4.1, § 4.2 |
| **T-4.1.3** ✅ | **`ConstructCheckpointPayload` nutzt `time.RFC3339`** — Sekundenauflösung, während der Eintragshash Mikrosekunden bindet. Zwei Präzisionen im selben Beweisgebäude; zwei Checkpoints innerhalb derselben Sekunde signieren dieselbe Payload. | Eigener Schnitt am Checkpoint-Format. | § 4.1, § 4.2 |
| **T-4.1.4** ✅ | **`audit → sync` bleibt bestehen.** Für § 8.1 ein Fund, der dort Zeit spart: die naive Interface-Extraktion geht nicht auf, weil `OutboxWriter.WriteEvent` `(*sync.OutboxEvent, error)` zurückgibt — ein `audit`-seitiges Interface müsste den `sync`-Typ nennen. Es braucht `identity/dbtx` für `Tx` **plus** einen schmaleren Writer oder einen Adapter am Kompositionspunkt. | **Erledigt — beides, aber ohne Adapter.** `identity/dbtx` hält jetzt `Tx` und `ErrTxRequired` und sonst nichts; `sync.Tx` ist ein Alias darauf, also bleibt jeder vorhandene Aufrufer gültig. Der schmalere Writer ist `StageEvent`, das nur einen Fehler liefert — genau das, was `audit` von `WriteEvent` benutzt hat. Damit ist `audit.OutboxStager` ein Interface über eine Methode, `*sync.OutboxWriter` erfüllt es strukturell, und keine der acht Konstruktionsstellen braucht einen Adapter. `identity/audit` importiert `identity/sync` nicht mehr und erreicht `identity/authz` nicht mehr transitiv. | § 8.1 |

### 4.2 Die Ledger-Kette ist nach einem Postgres-Roundtrip nicht mehr verifizierbar

`ComputeCanonicalHash` serialisiert `TimestampRFC: timestamp.UTC().Format(time.RFC3339Nano)` — Nanosekunden. `audit_ledger.created_at` ist `TIMESTAMP WITH TIME ZONE`, in Postgres **Mikrosekunden**. Beim Schreiben werden die letzten drei Stellen abgeschnitten; beim Lesen liefert `entry.CreatedAt` einen anderen Wert; `VerifyTenantChain` rechnet neu und erhält einen anderen Hash → `ErrAuditTamperingDetected` für **jeden** Eintrag.

Die Spalte `canonical_json` speichert exakt die Bytes, über die gehasht wurde — und `VerifyTenantChain` liest sie nie. Der Fix ist naheliegend: über die gespeicherte kanonische Form verifizieren, nicht neu serialisieren; und Zeitstempel vor dem Hashen auf Mikrosekunden truncaten.

**Zweiter Bruch:** `VerifyTenantChain` verlangt `expectedSeq` beginnend bei 1 und lückenlos. `RetentionEngine.ArchiveAndPruneSegments` verschiebt alte Einträge in `archived` → das aktive Segment beginnt bei `seq > 1` → Verifikation schlägt strukturell fehl. Archivierung und Verifikation schließen einander aus. Es fehlt ein Anker-Konzept („verifiziere ab Checkpoint X").

Ergänzend: `audit_ledger` hat `UNIQUE (tenant_id, sequence_number)`, aber **kein Code vergibt Sequenznummern** und `audit/writer.go` ist `type AuditWriter struct{}`. Das Ledger hat Schema und Verifizierer, aber keinen Schreiber.

#### 4.2-T Ergebnis und offene Tickets aus der Umsetzung von 4.2

Der erste Bruch (Nanosekunden gegen Mikrosekunden) war bereits mit § 4.1 erledigt. Beim zweiten stellte sich heraus, dass er **tiefer liegt als beschrieben**: der Befund nimmt an, das aktive Segment beginne nach dem Archivieren bei `seq > 1` und ein Anker löse das. `ArchiveAndPruneSegments` archivierte aber gar kein Segment — es filterte **pro Eintrag** nach Klasse und Alter. Ein `critical`-Eintrag von vor 500 Tagen blieb aktiv, ein `read`-Eintrag von vor 100 Tagen wanderte weg; das Ergebnis war `{1, 5}` mit Loch. **Kein Ankerkonzept repariert Löcher** — in einer Hash-Kette lässt sich kein mittlerer Eintrag entfernen. Archivierung ist notwendigerweise ein Präfixschnitt. `SplitAtRetentionBoundary` schneidet jetzt beim ersten Eintrag, der bleiben muss, prüft die Kontiguität seiner Eingabe und liefert den Anker mit, unter dem das aktive Segment weiter verifizierbar ist.

Der Preis steht im Code: **ein permanent aufbewahrter Eintrag an früher Position blockiert jede Archivierung dahinter.** Das ist eine Eigenschaft der Kette, keine der Implementierung. Getrennte Ketten pro Klasse wären der Ausweg — anderer Entwurf, siehe T-4.2.3.

**Verifikation liest jetzt `canonical_json`, statt neu zu serialisieren** — mit beiden Hälften, die dafür nötig sind: `SHA256(canonical_json) == entry_hash` verankert den Eintrag in der Kette, und ein Feldvergleich bindet die gespeicherte Form an die Zeile. Ohne die zweite Prüfung bewiese die Kette nur, dass ein JSON-Blob unverändert ist, während die Spalten — aus denen jede Abfrage liest — frei überschreibbar wären. Ein fehlendes `canonical_json` ist ein Fehler, kein Durchwinken; unbekannte Felder werden abgewiesen.

**Der Anker ist die gefährlichste Stelle des Entwurfs** und ist entsprechend gebaut: `ChainAnchor` weist inkohärente Werte ab (Sequenz ohne Hash und umgekehrt), denn „Sequenz 42, kein Hash" hieße, 42 Einträge ohne Nachweis zu überspringen. Der sichere Weg ist `CheckpointEngine.VerifySegment`, das **zuerst die Signatur prüft** und erst dann das Segment gegen den attestierten Anker — ein selbstgebauter Anker bewiese nichts, weil ein Angreifer schlicht hinter den manipulierten Teil ankert.

**Der Schreiber existierte bereits als Port** — beinahe hätte ich einen zweiten gebaut. `AuditWriterInterface.WriteAuditRecord` *ist* der Ledger-Append, ist seit § 3.7 Pflichtabhängigkeit und hat Tests; es fehlte nur die Implementierung, während `writer.go` mit `type AuditWriter struct{}` den guten Namen blockierte. Der Stub ist gelöscht, das Interface heißt `LedgerWriter` und dokumentiert den Vertrag: Sequenzvergabe, Verkettung und Speichern sind **eine** atomare Operation in der Transaktion des Aufrufers — getrennt würden zwei nebenläufige Appends auf denselben Vorgänger siegeln, und nur der `UNIQUE`-Constraint fiele darüber, nachdem einer der beiden schon als „recorded" zurückgemeldet wurde. `MemoryLedgerWriter` hält den Vertrag fest, `AuditLedgerService.Record` schreibt autoritativ ins Ledger und stellt danach die Replikation in die Outbox. Vorher stellte `RecordEventAsync` ein ungesiegeltes Objekt ohne Sequenznummer in die Outbox und loggte `sequence=0`.

Dazu **T-4.1.3** erledigt: `ConstructCheckpointPayload` band den Zeitstempel mit `time.RFC3339` auf Sekunden, während der Eintragshash Mikrosekunden bindet — zwei Checkpoints innerhalb derselben Sekunde signierten byteidentische Payloads, also zwei verschiedene Ketten-Spitzen mit einer Signatur. Format auf Mikrosekunden angeglichen, Marker von `v1` auf `v2` gehoben.

**Ein Blocker, der eine Entscheidung braucht:** Migration 009 führt `REVOKE UPDATE, DELETE ON audit_ledger FROM PUBLIC, identity_app`. `PseudonymizeUserPII` schreibt Einträge um. Gegen das reale Schema mit der Anwendungsrolle ist dieser Schreibvorgang **nicht möglich**. T-4.1.1 ist damit kein Verdrahtungsproblem, sondern eine offene Grundsatzfrage — siehe T-4.2.2.

Neue Tests: `TestAuditChain_DetectsColumnDrift` (fünf Spalten hinter intaktem Blob), `TestAuditChain_DetectsCanonicalFormReplacement`, `TestAuditChain_RejectsEntryWithoutCanonicalForm`, `TestAuditChain_RejectsCanonicalFormWithUnknownFields`, `TestAuditChain_SegmentVerifiesFromAnchor`, `TestAuditChain_AnchorCannotSkipAPrefix` (vier inkohärente Anker), `TestAuditChain_AnchorRejectsAForeignTip`, `TestCheckpoint_VerifySegmentChecksTheSignatureFirst`, `TestCheckpoint_PayloadDistinguishesCheckpointsWithinASecond`, `TestRetention_ArchivesOnlyAContiguousPrefix`, `TestRetention_SplitYieldsAVerifiableActiveSegment`, `TestRetention_RejectsNonContiguousInput`, `TestRetention_RejectsUnclassifiedAction`, `TestLedgerWriter_AllocatesSequencesAtomically` (32 nebenläufige Appends), `TestAuditLedgerService_RecordSealsBeforeStaging`. **Ein bestehender Test zementierte den Defekt**: `TestRetention_ConfiguredRetentionSchedulesAndArchiving` verlangte `expected 2 active records` — also genau das Ergebnis mit Loch.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.2.1** | **Postgres-`LedgerWriter`.** `MemoryLedgerWriter` hält den Vertrag fest, ist aber prozesslokal. Die SQL-Variante vergibt die Sequenz in derselben Anweisung, die einfügt (`INSERT … SELECT COALESCE(MAX(sequence_number),0)+1 … FOR UPDATE` oder eine Sequenztabelle pro Mandant), sonst greift nur der `UNIQUE`-Constraint — und der meldet den Konflikt erst, nachdem einer der beiden Aufrufer bereits Erfolg gesehen hat. | Braucht Postgres (Sprint 3, Punkt 24). | § 4.2, § 10 |
| **T-4.2.2** | **DSGVO-Löschung gegen ein Append-only-Ledger.** Migration 009 entzieht `UPDATE` und `DELETE`; die Pseudonymisierung schreibt Einträge um. Entweder eine getrennte, selbst auditierte Redaktionsrolle mit `UPDATE`-Recht — womit die Unveränderlichkeit aus AUD-01 eine Ausnahme bekommt — oder **Crypto-Shredding**: PII pro Nutzer verschlüsselt ablegen und zum Löschen den Schlüssel vernichten, wodurch Kette und Hashes vollständig intakt bleiben. Diese Entscheidung bestimmt, ob T-4.1.1 überhaupt einen Adapter haben kann. | Grundsatzentscheidung, kein Verdrahtungsschritt. | § 4.2, § 3.8 |
| **T-4.2.3** | **Eine Kette pro Aufbewahrungsklasse.** Solange alle Klassen in einer Kette liegen, blockiert ein permanent aufbewahrter Eintrag an früher Position jede Archivierung dahinter. Getrennte Sequenzräume je Klasse lösen das, kosten aber einen Anker je Kette. | Eigener Entwurf am Ledger-Schema. | § 4.2, § 6.4 |
| **T-4.2.4** ✅ | **`AuditDispatcher` und `AuditLedgerService` halten beide einen `LedgerWriter`.** Sauber wäre `Dispatcher → Service → Store`: der Dispatcher ist die Fehlermatrix (AUD-04) über einem Schreibvorgang, der Service ist der Schreibvorgang. Heute sind es zwei Konsumenten desselben Ports. | Architekturfrage, gehört zur Konsolidierung der Ketten (§ 5.1). | § 4.2, § 5.1 |

### 4.3 Event-IDs kollidieren mit hoher Wahrscheinlichkeit

```go
// sync/writer.go
ID: "evt-" + hex.EncodeToString([]byte(generateUUID()[:8]))
```

`generateUUID()` liefert `xxxxxxxx-xxxx-…`; `[:8]` sind die ersten acht ASCII-Zeichen — das ist die Hex-Darstellung der Bytes 0–3, also **32 Bit Entropie**, anschließend erneut hex-kodiert (16 Zeichen, die Länge täuscht).

Kollisionswahrscheinlichkeit nach dem Geburtstagsproblem mit `N = 2³²`:

```
P(n) ≈ 1 − exp(−n² / 2N)
n = 10 000  → P ≈ 1,2 %
n = 50 000  → P ≈ 25 %
n = 100 000 → P ≈ 69 %
```

Nach 100 000 Events ist eine Kollision **wahrscheinlicher als keine**. Da die Event-ID zugleich Dedup-Schlüssel ist (`EventDeduplicatorStore.IsProcessed(eventID)`), bedeutet eine Kollision ein **stillschweigend verworfenes Event**. Die vorhandene UUID hat 128 Bit — sie wird erzeugt und weggeworfen.

#### 4.3-T Ergebnis und offene Tickets aus der Umsetzung von 4.3

Der Befund nennt eine Stelle; es sind **sieben**, und die schwerste steht nicht darin.

| Ort | Entropie vorher | Folge einer Kollision |
|---|---|---|
| `authz/breakglass.go` `bg_<tenant>_<UnixNano>` | **0 Bit** | **Grant überschreibt Grant** |
| `sync/writer.go` `evt-` | 32 Bit | Event still verworfen |
| `authz/audit.go` `evt-`/`corr-` | 64 Bit | Audit-Korrelation vermischt |
| `scim/provider.go` `usr-` | 64 Bit | Benutzer überschreibt Benutzer |
| `shared/audit/alerts.go` `alt-` | 64 Bit | Alarm überschreibt Alarm |
| `impersonation` `imp-`, `deviceflow` `dev-` | 128 Bit | — |

**Die Break-Glass-Grant-ID war der eigentliche Fund.** Sie bestand aus Mandant plus `UnixNano()` — keinerlei Entropie — und ist zugleich der Schlüssel, unter dem der Grant im Store abgelegt wird. Zwei Aktivierungen desselben Mandanten im selben Augenblick ergaben denselben Schlüssel, und der zweite Grant **ersetzte den ersten lautlos**. Mit einer `FakeClock` passiert das deterministisch, und unter Windows ist die Auflösung von `time.Now()` grob genug, dass es auch im Betrieb realistisch bleibt. Break-Glass-Grants sind die höchstprivilegierten Objekte des Systems.

Statt sechs lokaler Generatoren gibt es jetzt `shared/x/idgen`: `idgen.New(prefix)` liefert `<prefix>-<26 Base32-Zeichen>`, also 130 Bit, über `crypto/rand.Text()`. Der Ort ist `shared/x/`, weil `shared/audit/alerts.go` einer der Aufrufer ist und `shared` nicht aus `identity` importieren darf. Netto weniger Code als vorher.

**Eine Präzisierung zum Befund:** `_, _ = rand.Read(b)` war kein Fail-open. Seit Go 1.24 gibt `crypto/rand.Read` nie einen Fehler zurück und paniked, wenn die Systemquelle versagt — für ein Sicherheitsprimitiv das richtige Verhalten. Die Stellen waren trotzdem falsch, weil sie wie verschluckte Fehler aussehen und `errcheck` (O9) sie alle angestrichen hätte. `rand.Text()` hat das Problem nicht mehr.

**Bewusst unverändert:** `generateUserCode()` bleibt bei 32 Bit. Das ist ein Code, den ein Mensch von einem Bildschirm abliest und in einen anderen tippt; RFC 8628 § 5.2 verlangt dort ausdrücklich keine hohe Entropie, sondern ≥ 20 Bit **plus Rate-Limiting**. Ebenfalls unverändert die Request-ID in `registry/internal/server/middleware/logging.go` — 64 Bit, reine Log-Korrelation, kein Store-Key, andere Schicht.

**Angrenzend mitgenommen, weil es dieselbe Zusicherung trägt:** `consumer.go` verwarf den Fehler von `IsProcessed`. Bei unerreichbarem Dedup-Store war `processed` damit false und der Handler lief **erneut** — eine Kollision verliert ein Event, ein verworfener Fehler dupliziert eines. Die richtige Antwort ist weder verarbeiten noch überspringen, sondern die Charge scheitern lassen: das Event bleibt pending, die Outbox ist genau dafür da. Ebenso die vier verworfenen `MarkProcessed`-Fehler, die ein Event endlos pending hielten — beim Zweig „kein Handler registriert" sogar in einer Schleife ohne Fortschritt. Sie werden mit `errors.Join` gesammelt und zurückgegeben, ohne den korrekt gezählten Fortschritt zu verwerfen. Der Dedup-Vermerk **nach** erfolgreichem Handler bleibt nicht-fatal — die Nebenwirkung ist bereits eingetreten —, wird aber protokolliert statt verschluckt.

Neue Tests: `TestIDGen_CarriesAtLeast128Bits` (deterministische Schranke), `TestIDGen_NoCollisionsAtScale` (200 000 IDs; mit den alten 32 Bit schlägt das zu ~99 % fehl), `TestBreakGlass_GrantsAtTheSameInstantGetDistinctIDs` (**heute deterministisch rot**, weil der zweite Grant den ersten überschreibt), `TestOutbox_EventIDsAreUnique`, `TestConsumer_DedupOutageDoesNotReprocess` (inklusive Nachweis, dass das Event nach der Erholung genau einmal verarbeitet wird), `TestConsumer_MarkProcessedFailureIsReported`.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.3.1** | **Kein Rate-Limit auf der Suche per Device-Benutzercode.** Die 32 Bit des Benutzercodes sind nach RFC 8628 § 5.2 nur zusammen mit Rate-Limiting ausreichend; `GetSessionByUserCode` ist ungebremst. | Braucht den Server und den vorhandenen `MultiLimiter`. | § 4.3, § 2.4 |
| **T-4.3.2** | **`MemoryEventDeduplicator` ist prozesslokal**, während `OutboxConsumer` Leader-Election für Mehrinstanzbetrieb mitbringt — dedupliziert wird also nur innerhalb einer Instanz. Dieselbe Familie wie T-3.7.3 (Valkey). | Braucht Valkey-Verdrahtung (Sprint 3, Punkt 26). | § 4.3, § 10 |

### 4.4 Der progressive Login-Delay bricht bei hohen Fehlerzahlen zusammen

```go
func calculateDelay(failures int) time.Duration {
	if failures < 3 { return 0 }
	delay := 500 * time.Millisecond * time.Duration(1<<(failures-3))
	if delay > MaxDelay { return MaxDelay }
	return delay
}
```

`500 ms = 5·10⁸ ns`. Überlauf von `int64` bei `5·10⁸ · 2^k > 9,22·10¹⁸`, also `k > 34,1` ⇒ ab `failures ≥ 38` ist das Produkt negativ. Der Vergleich `delay > MaxDelay` ist dann falsch, und es wird eine **negative Duration** zurückgegeben. Ab `failures ≥ 67` ist der Shift ≥ 64 und das Ergebnis exakt `0`.

Der Delay verschwindet also genau dort, wo er wirken soll: beim anhaltenden Brute-Force. Korrekt ist, den Exponenten zu deckeln: `k := min(failures-3, 5)`.

Nebenbefund: `calculateDelay` wird ausschließlich von `RecordLoginFailure` verwendet, und **`RecordLoginFailure` wird von keinem Code im Repository aufgerufen**. Der gesamte Mechanismus ist derzeit toter Code.

#### 4.4-T Ergebnis und offene Tickets aus der Umsetzung von 4.4

Die Überlaufrechnung stimmt, eine Zahl nicht. Nachgemessen:

| `failures` | Verhalten |
|---|---|
| 3 – 7 | korrekt: 500 ms, 1 s, 2 s, 4 s, 8 s |
| 8 – 37 | korrekt: `MaxDelay` |
| **38 – 58** | **13 von 21 Werten negativ** — `time.Sleep` kehrt sofort zurück; die übrigen 8 landen zufällig auf 10 s |
| **≥ 59** | **exakt 0, dauerhaft** |

Der Befund nennt für den Totalausfall `failures ≥ 67`; korrekt ist **59**. Der Grund ist feiner als „Shift ≥ 64": `500 ms = 5·10⁸ ns = 2⁸ · 1953125`, und 1953125 ist ungerade. Damit ist `5·10⁸ · 2^k ≡ 0 (mod 2⁶⁴)` bereits ab `k ≥ 56`. Der Schutz fällt acht Fehlversuche früher aus als angenommen. Der Bereich 38–58 ist der unangenehmste: dort **wechselt** das Verhalten zwischen „keine Verzögerung" und „korrekte 10 s", ein Stichprobentest sieht also mit knapp 40 % das richtige Ergebnis. `calculateDelay` hatte keinen einzigen Test.

Der Exponent wird jetzt **vor** dem Shift gedeckelt. Statt des vorgeschlagenen `min(failures-3, 5)` trennt die Umsetzung zwei Grenzen: `maxProgressiveShift = 34` schützt die Darstellbarkeit (`500 ms << 34` ≈ 8,6·10¹⁸ ns, eine Verdopplung unter `math.MaxInt64`), `MaxDelay` ist die Richtlinie. `min(…, 5)` wäre heute äquivalent, koppelt aber stillschweigend an die zehn Sekunden — wer den Deckel später auf eine Minute hebt, bekäme ohne Vorwarnung weiterhin nur 16 s.

`RecordLoginFailure` bleibt trotz fehlender Aufrufer erhalten: der progressive Login-Delay ist eine benannte Sicherheitskontrolle, sie fehlt nur, weil es keinen Login-Pfad gibt. Gleiche Lage wie beim Ledger-Schreiber und bei Valkey. Wird T-4.4.1.

**Drei angrenzende Befunde derselben Kontrolle, die der Abschnitt nicht nennt:**

`ValkeyBackend.RecordLoginFailure` antwortete auf einen Ausfall mit `(0, 0, false, nil)` — „null Fehlversuche, keine Verzögerung, alles in Ordnung". Das ist vom allerersten Fehlversuch **nicht unterscheidbar**: wer Valkey degradiert, schaltet die Brute-Force-Verzögerung ab, und nichts im System merkt es. Der Fehler wird jetzt zurückgegeben. Die Abgrenzung zu `Allow` steht im Code: dort ist Fail-open eine dokumentierte Verfügbarkeitsentscheidung (Outage-Matrix § 14) und bleibt — ein Durchsatzlimit soll den Dienst vor Last schützen, nicht ihn während eines Cache-Ausfalls selbst abschalten. Fehlversuche zu zählen ist dagegen der Detektor selbst.

`NewMultiLimiter(nil, …)` ersetzte ein fehlendes Backend stillschweigend durch `MemoryBackend` — und `token/exchange.go` übergab **absichtlich** nil. Bei N Instanzen war das effektive Exchange-Limit damit N-mal das konfigurierte. Backend und Client sind jetzt Pflicht; `NewTokenExchangeEngine` nimmt den Limiter als Parameter, `WithLimiter` entfällt (ein Builder, der nil verwirft, ist dieselbe Krankheit in klein).

`AccountCounter.LastFailure` wurde geschrieben und **nie gelesen**: `MemoryBackend` vergaß Fehlversuche nie, während `ValkeyBackend` seinen Zähler nach 24 h ablaufen ließ. Zwei Implementierungen einer Schnittstelle mit unterschiedlicher Verfallssemantik. Ein gemeinsames `failureWindow` gleicht sie an und gibt dem Feld seinen Zweck.

Neue Tests: `TestMemoryBackend_ProgressiveDelayRamp`, `TestMemoryBackend_DelayNeverVanishesUnderSustainedBruteForce` (500 Fehlversuche, **heute rot ab 38**), `TestMemoryBackend_FailuresDecayAfterTheWindow`, `TestValkeyBackend_LoginFailureOutageIsReported`, `TestValkeyBackend_LoginSuccessOutageIsReported`, `TestRateLimiters_RequireTheirBackends`. `TestValkeyBackend_FailOpenResilience` bleibt unverändert — das Durchsatzlimit fällt weiterhin bewusst offen.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.4.1** | **Der progressive Login-Delay hat keinen Aufrufer.** `RecordLoginFailure` und `RecordLoginSuccess` sind vollständig und getestet, aber niemand ruft sie — es gibt keinen Login-Pfad. | Braucht `cmd/identity-api` (Sprint 3, Punkt 25). | § 4.4 |
| **T-4.4.2** | **`MemoryBackend.failures` und `buckets` wachsen unbegrenzt.** Das Zeitfenster setzt den Zähler zurück, entfernt den Eintrag aber nicht. | Sammelposten § 6.4. | § 4.4, § 6.4 |
| **T-4.4.3** | **Kein Valkey-Backend ist irgendwo verdrahtet**, also läuft jedes Limit prozesslokal. Der Konstruktor verlangt jetzt ein Backend, aber die einzige verfügbare Implementierung außerhalb von Valkey ist `MemoryBackend`. | Braucht Valkey-Verdrahtung (Sprint 3, Punkt 26); dieselbe Familie wie T-3.7.3 und T-4.3.2. | § 4.4, § 10 |

### 4.5 Revocation kann bis zu 30 Sekunden verloren gehen

`RevocationCache.StartBackgroundSync` ersetzt beim periodischen Resync die gesamte Map:

```go
entries, maxGen, err := c.store.FetchAllActive(ctx, c.clk.Now())
if err == nil {
    c.mu.Lock()
    c.entries = make(map[string]RevocationEntry)   // vollständiger Ersatz
    …
}
```

Ablauf: Resync liest die DB zum Zeitpunkt `t−ε` (Widerruf noch nicht committet) → Pub/Sub liefert den Widerruf zu `t` → `Put` schreibt ihn in die Map → Resync schreibt zu `t+δ` seinen alten Snapshot zurück. Der Widerruf ist gelöscht, bis zum nächsten Intervall (Default 30 s).

`lastGeneration` wird geführt, aber **nie zur Konfliktauflösung verwendet**. Damit ist die Zusage „< 5 s Wirksamkeit" nicht haltbar. Korrekt: Snapshot nur übernehmen, wenn `maxGen >= c.lastGeneration`, sonst mergen.

#### 4.5-T Ergebnis und offene Tickets aus der Umsetzung von 4.5

Der beschriebene Ablauf stimmt. **Der vorgeschlagene Fix trägt nicht.**

`generation` zählt **pro Schlüssel**, nicht global: das Upsert macht `generation = revocation_entries.generation + 1` *auf der Zeile*. `maxGen` ist damit das Maximum über lauter unabhängiger Zähler und keine Tabellenversion. Konkret: Schlüssel A wurde fünfmal widerrufen (`lastGeneration = 5`), jetzt wird Schlüssel C **neu** widerrufen — dessen Generation ist 1, `Put` lässt `lastGeneration` bei 5. Ein Snapshot von vor C liefert `maxGen = 5`, besteht `maxGen >= lastGeneration` und löscht C. Genau das Szenario aus dem Befund überlebt den vorgeschlagenen Fix.

**Der Weg über eine Sync-Runde als Barriere war ebenfalls zu schwach** — das hat erst der Test gezeigt, nicht die Planung. Eine Barriere, die vor dem Lesen gesetzt wird, schützt nur Einträge, die *während* der Abfrage ankommen. Ein Widerruf, der *zwischen* zwei Runden eintrifft und dessen Zeile eine hinterherhinkende Read-Replica noch nicht kennt, wird in der Folgerunde verworfen: derselbe Fehler, eine Runde später.

Tragfähig ist ein einziges Bit pro Eintrag: **hat der Store diesen Schlüssel jemals gemeldet?**

| Fall | Regel |
|---|---|
| Schlüssel in beiden, Cache hat höhere `Generation` | Cache gewinnt — veralteter Replica-Read darf nichts zurückdrehen |
| Schlüssel im Snapshot | Snapshot, Eintrag gilt als bestätigt |
| Schlüssel nur im Cache, **unbestätigt** | **behalten** — der Snapshot kann vor dem Commit gelesen worden sein oder von einer Replica stammen |
| Schlüssel nur im Cache, bestätigt | verwerfen — der Store hat ihn gemeldet und meldet ihn nicht mehr |

Das ist zugleich einfacher (kein Rundenzähler, keine Arithmetik) und stärker: es deckt beide Rennen ab. Die Fehlerrichtung ist bewusst — ein aufgehobener Widerruf bleibt eine Runde länger stehen, was für einen Kill-Switch die richtige Seite ist.

`lastGeneration` entfällt, und `FetchAllActive` gibt kein `maxGen` mehr zurück: ein Rückgabewert, der wie eine Tabellenversion aussieht und keine ist, hat schon einmal zum falschen Fix geführt.

**Drei weitere stille Ausfälle im selben Pfad:** Der Resync-Fehler wurde ohne `else` verworfen — ein Cache, der seit Stunden nicht synchronisiert hat, sah aus wie ein gesunder; er wird jetzt mit laufendem Fehlerzähler und Driftdauer protokolliert. Das `_ = c.pubsub.Subscribe(…)` verschluckte den Abonnementfehler, womit die Zusage „< 5 s" lautlos auf das Resync-Intervall zusammenfiel; `StartBackgroundSync` gibt ihn jetzt zurück und startet den Selbstheilungs-Ticker trotzdem, damit ein Aufrufer, der weitermacht, keinen eingefrorenen Cache behält. Und eine unlesbare Pub/Sub-Nachricht fiel durch ein `err == nil &&` ohne Gegenzweig — ein Kanal, der Müll liefert, war von einem stillen nicht zu unterscheiden.

Store und Pub/Sub sind Pflichtparameter. `TestFailure_05_ValkeyDown` übergab für „Valkey ist unten" **beide** als nil — Valkey ist aber das Pub/Sub, Postgres der Store; das modellierte „nichts ist konfiguriert". Das Szenario ist korrigiert: Store gesund, Pub/Sub-Client liefert Fehler, und es prüft zusätzlich, dass der Ausfall gemeldet wird.

Dazu ein Daten-Race außerhalb des Befunds: `MemoryPubSub.Subscribe` hängt an `handlers` an, während `Publish` darüber iteriert — ohne Sperre, in Produktivcode. Jetzt gesperrt, mit Kopie vor dem Aufruf, damit ein Handler, der selbst abonniert, nicht in die eigene Sperre läuft. Mit `-race` verifiziert.

Neue Tests: `ResyncKeepsRevocationsThatArrivedDuringTheQuery` (der Store-Stub ruft **in** `FetchAllActive` selbst `Put` auf — das Rennen exakt und ohne Timing), `ResyncDropsEntriesThatAreGone`, `StaleSnapshotCannotLowerAGeneration`, `SubscribeFailureIsReported`, `SelfHealingContinuesWithoutPubSub`, `RequiresStoreAndPubSub`, `UnreadablePubSubMessageIsRejected`. **Der bestehende Test konnte den Fehler nicht sehen**: `TestRevocationCache_RealtimePubSubAndSelfHealing` prüfte unmittelbar nach dem Broadcast, also bevor der Ticker feuerte — er wartet jetzt über zwei Resyncs hinaus.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.5.1** | **`StartBackgroundSync` hat keinen Aufrufer** außerhalb der Tests; der Cache ist wie der Rest unverdrahtet. | Braucht `cmd/identity-api` (Sprint 3, Punkt 25). | § 4.5 |
| **T-4.5.2** | **Unbestätigte Einträge ohne `ExpiresAt` bleiben unbegrenzt.** Bestätigt der Store einen per Pub/Sub gelernten Widerruf nie — etwa weil der DB-Schreibvorgang des Widerrufenden scheiterte —, bleibt er dauerhaft im Speicher. Die Richtung ist sicher, die Menge unbegrenzt. | Sammelposten § 6.4. | § 4.5, § 6.4 |
| **T-4.5.3** | **`FetchAllActive` darf nicht von einer Read-Replica lesen.** Die Bestätigungsregel fängt Replikationsverzug ab, aber ein Kill-Switch-Cache, der eine nachhinkende Replica als Autorität nimmt, ist unabhängig davon unsauber. Gehört in die Verdrahtung des `*sql.DB`. | Deployment-Frage, kein Code in diesem Paket. | § 4.5, § 10 |

### 4.6 `DecisionCache.InvalidateSubject` löscht alles

```go
func cacheKeyMatches(key, urn string) bool {
	return len(key) > len(urn) && (key == urn || containsURN(key, urn))
}
func containsURN(key, urn string) bool { return len(key) >= len(urn) }
```

`containsURN` prüft keine Enthaltensein-Beziehung, sondern Längen. `cacheKeyMatches` reduziert sich auf `len(key) > len(urn)` — für jeden Cache-Key wahr. `InvalidateSubject("beliebig")` leert praktisch den gesamten Cache.

Da der Cache ohnehin nirgends verdrahtet ist (`check.go` ruft weder `Get` noch `Put`), ist der Defekt derzeit folgenlos — er würde aber beim Anschließen die Trefferrate vernichten und Korrektheitsfehler maskieren.

#### 4.6-T Ergebnis und offene Tickets aus der Umsetzung von 4.6

Der Befund stimmt vollständig. Ergänzend: der `key == urn`-Zweig ist ebenfalls tot — innerhalb von `len(key) > len(urn)` können die beiden nie gleich sein. Und `DecisionCache` hatte **keine einzige Testdatei**, während `identity/authz/` sechs davon hat: eine Funktion, die für jeden Schlüssel `true` liefert, ist nie geprüft worden.

**Repariert wurde nicht der Vergleich, sondern der Schlüssel.** `decisionKey` ist jetzt eine vergleichbare Struktur statt eines mit `fmt.Sprintf` plattgedrückten Strings; damit ist `InvalidateSubject` ein Gleichheitsvergleich auf einem Feld und der Fehler unausdrückbar. Das ist hier keine Stilfrage: eine Principal-URN enthält selbst Doppelpunkte (`toob:human:shared:org_acme:usr_alice`), ein Aufteilen des Schlüssels an `:` gewinnt die Felder also gar nicht zurück, und `strings.Contains` fände `usr_alice` in `usr_alice2`. Jede stringbasierte Variante bleibt fragil. Nebeneffekt: `fmt.Sprintf` verschwindet aus `Get` und `Put` — auf einem Pfad, dessen einziger Daseinsgrund ist, schneller zu sein als eine OpenFGA-Abfrage.

**Ein zweiter Fund im selben Code:** `cacheKey` setzte bei fehlendem `Principal` eine leere URN ein. Ein so abgelegter Eintrag ist von `InvalidateSubject` **nie erreichbar** — eine Entscheidung, die den Widerruf ihres Subjekts überlebt. `Get` und `Put` lehnen Anfragen ohne Principal jetzt ab; ein Cache-Miss ist immer eine gültige Antwort, eine unlöschbare Entscheidung nicht. Damit trägt kein Eintrag mehr eine leere URN und die Sonderfallprüfung im Schleifenrumpf entfällt ersatzlos.

Dazu zwei kleinere Korrekturen: `Get` hängte `"_cached"` an den `Reason`, womit eine zwischengespeicherte Entscheidung **nicht gleich** der Entscheidung war, die sie zwischenspeichert — der zweite Rückgabewert sagt ohnehin schon, dass es ein Treffer war. Und `NewDecisionCache` ersetzte ein `ttl <= 0` still durch fünf Sekunden; die TTL ist das Staleness-Fenster einer Autorisierungsentscheidung, also wie lange ein entzogenes Recht weiter gilt, und damit eine Richtlinie und keine Bequemlichkeit. `InvalidateSubject` gibt jetzt die Anzahl gelöschter Einträge zurück — Invalidierung läuft im Widerrufspfad, und dass sie lautlos nichts tun kann, war Teil des Problems.

Neue Tests (erste Testdatei für dieses Paket): `InvalidateSubjectOnlyRemovesThatSubject` (**heute rot** — zwei Principals, Bobs Einträge überleben Alices Invalidierung), `UnknownSubjectRemovesNothing`, `DecisionsAreScopedByEveryKeyField` (tabellengetrieben über Mandant, Objekttyp, Objekt-ID, Permission, Principal — das Gegenstück zu §4.1s „bindet jedes Feld"), `HitReturnsTheDecisionItCached`, `ExpiredEntryIsAMiss`, `RefusesToCacheWithoutAPrincipal`, `RequiresATTL`.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-4.6.1** | **`DecisionCache` hat keinen Aufrufer.** `check.go` ruft weder `Get` noch `Put`. Das Anschließen braucht zusätzlich Invalidierungs-Hooks aus dem Widerrufspfad, damit ein Widerruf die zwischengespeicherten Entscheidungen tatsächlich erreicht. | Braucht den Server und die Verdrahtung von `revocation` (Sprint 3, Punkt 25). | § 4.6 |
| **T-4.6.2** | **Abgelaufene Einträge bleiben liegen.** `Get` erkennt sie und gibt einen Miss zurück, entfernt sie aber nicht; nichts sonst räumt auf, und der Schlüsselraum ist über Objekt-IDs unbegrenzt. | `authz.DecisionCache.cache` steht namentlich im Sammelposten § 6.4. | § 4.6, § 6.4 |

---

## 5. Duplikation und Divergenz

### 5.1 Zwei Enforcement-Ketten, fünf HTTP-Einstiegspunkte

| Konstrukt | Interface | Request-Typ | Reale Implementierungen |
|---|---|---|---|
| `enforce.Stage1Chain` | `Gate` | `enforce.Request` | 6 (`TokenGate` … `KillSwitchGate`) |
| `enforce.Pipeline` | `PipelineStage` (genau 7) | `enforce.PipelineRequest` | **0** |

`PipelineRequest` und `Request` sind nahezu feldgleich. Es existiert keine einzige echte `PipelineStage` — `pipeline_test.go` verwendet ausschließlich `spyStage`. Die 7-Stufen-Pipeline ist ein Testkonstrukt mit Produktions-API, inklusive `strings.Contains(err.Error(), "AuthZ")` zur HTTP-Status-Bestimmung neben einer vorhandenen Typ-Taxonomie.

HTTP-Einstiegspunkte: `enforce.HTTPMiddleware`, `Pipeline.HTTPMiddleware`, `SecurityInterceptor.HTTPInterceptor`, `SecurityInterceptor.AutomaticHTTPInterceptor`, `MTLSTerminationMiddleware.HTTPMiddleware`, `BFFHandler.HTTPProxyMiddleware`, `DPoPMiddleware.Handler`, `IdempotencyMiddleware`. Acht Middlewares, keine dokumentierte Reihenfolge, kein Router, der sie montiert.

#### 5.1-T Ergebnis und offene Tickets aus der Umsetzung von 5.1

Die Pipeline war restlos tot: `NewPipeline` hatte nur Aufrufer in `pipeline_test.go`, es existierte keine einzige echte `PipelineStage`. Auch `enforce.HTTPMiddleware` hatte **null Aufrufer**, nicht einmal in Tests. Beide sind gelöscht.

`enforce.HTTPMiddleware` war inhaltlich die schwächere Kopie von `HTTPInterceptor`: keine Policy, also `RequiredTrustLevel` und `MaxStepUpAge` immer null; `HTTPURL` und `UsesDPoPScheme` ungesetzt, womit sender-gebundene Token dort fail-closed durchfielen (**T-3.1.4**, damit erledigt); immer 401, nie 403, nie Step-up-Challenge; und ein eigener, handgeschriebener Problem-Details-Block ohne `Code`. Von den drei Schreibern aus §5.2 bleibt damit genau einer übrig — `serrors.WriteProblemDetails`. Die vier Tenant-Fehler bleiben für §5.2 offen.

Von den acht Middlewares waren zwei schon vorher entfallen (`DPoPMiddleware.Handler` mit §3.1, `AutomaticHTTPInterceptor`). Übrig bleiben **drei mit je eigener Aufgabe**: mTLS-Terminierung am Rand, Idempotenz, und `SecurityInterceptor.HTTPInterceptor` als *der* Enforcement-Eingang. (`BFFHandler.HTTPProxyMiddleware` ist der vierte, auf dem Browser-Pfad.)

**Der schwerste Befund steht nicht im Abschnitt: es gab nirgends eine kanonische Gate-Reihenfolge.** `NewStage1Chain(gates ...Gate)` nahm, was der Aufrufer übergab — und jeder Aufrufer war ein Test mit einer anderen Auswahl (`interceptor_test.go`: Token/Tenant/Trust/StepUp; `dpop_contract_test.go`: nur Tenant; `order_test.go`: sechs Spione mit zwei Namen, die es gar nicht gibt). Die Reihenfolge ist aber eine Sicherheitseigenschaft. `NewStandardStage1Chain(Stage1Config)` legt sie erstmals fest:

`TokenGate → DPoPGate → ImpersonationGate → KillSwitchGate → TenantGate → TrustGate → StepUpGate`

Begründung im Code: Token erzeugt als einziges Gate einen Principal, alle anderen verlangen einen. DPoP beweist den Besitz, bevor irgendeine Entscheidung über die Identität fällt. Impersonation prüft den `act`-Anspruch, damit die effektive Identität darunter eine ist, die der Operator annehmen durfte. **Kill-Switch vor den Richtlinien-Gates**, und **Step-up ganz zuletzt** — es ist das einzige Gate, dessen Fehlschlag eine *Challenge* (RFC 9470) statt einer Ablehnung ist, und darf nicht für eine Anfrage feuern, die ohnehin scheitert. Zusammen heißt das: ein widerrufener Principal bekommt „widerrufen" und keine Aufforderung, sich erneut zu authentifizieren.

`order_test.go` war eine Tautologie — es übergab eine Reihenfolge und prüfte, dass sie eingehalten wurde, also dass `for range` iteriert. Es prüft jetzt die zusammengebaute Standardkette gegen die deklarierte Ordnung und deren beide tragende Eigenschaften verhaltensbasiert. Damit ist **T-3.1.3** erledigt.

Dazu ein Fail-open im selben Paket: `KillSwitchGate` übersprang die Prüfung bei `revocationStore == nil` — eine vollständig aussehende Kette ohne jede Widerrufsprüfung, dasselbe Muster, das ich in §3.8 am mTLS-Rand geschlossen habe. Register ist jetzt Pflicht.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.1.1** | **ENF-09 hat keine Implementierung mehr.** `Pipeline.Evaluate` war der einzige Aufrufer von `RecordAuthzDuration` und `RecordRequestLatency` (15-%-AuthZ-Latenzbudget). Gelaufen ist das nie — die Pipeline hatte keine Stufen und keinen Mount —, aber der Anschein ist mit ihr verschwunden. Der richtige Ort ist der zusammengesetzte Request-Pfad, weil nur dort Gesamt- und AuthZ-Latenz beide sichtbar sind; `Stage1Chain` macht keine OpenFGA-Prüfung. | Braucht `cmd/identity-api` (Sprint 3, Punkt 25). | § 5.1, ENF-09 |
| **T-5.1.2** | **Kein Router montiert die verbliebenen Middlewares.** Ihre Reihenfolge (mTLS-Terminierung → BFF → Interceptor → Idempotenz) ist weiterhin nirgends ausführbar festgehalten — anders als die Gate-Reihenfolge innerhalb von Stage 1. | Braucht den Server. | § 5.1 |

#### Zwischenstand: T-4.2.4 und T-2.5.1 nachgezogen

Beide Tickets standen ausdrücklich auf etwas, das inzwischen fertig war — T-4.2.4 auf §5.1, T-2.5.1 auf „keine Komponente vergibt Sequenznummern" (§4.2). Zusammen mit vier Tickets, die durch spätere Abschnitte erledigt und nur nicht abgehakt worden waren (T-3.1.3, T-3.1.4 durch §5.1; T-3.4.2 durch §3.8; T-3.7.2 durch §4.2), sind damit sechs Zeilen geschlossen.

**T-4.2.4 war keine Schichtungsfrage.** `AuditDispatcher` hielt einen `LedgerWriter` direkt, die Outbox-Staging steckt aber ausschließlich in `AuditLedgerService.Record`. Damit wurde **jedes über die AUD-04-Fehlermatrix laufende Audit gespeichert und nie repliziert** — auch die kritischen. Der Dispatcher sitzt jetzt auf einem `AuditRecorder`, und die drei Verantwortlichkeiten stehen getrennt: Dispatcher = Richtlinie (was bei Schreibfehlern passiert), Service = Schreibvorgang (Ledger **und** Outbox), `LedgerWriter` = Speicher.

**T-2.5.1** ist `audit.CriticalAuditAdapter`. Die Transaktion kann nicht vom Aufrufer kommen: `identity/sync` importiert `identity/authz`, also kann `authz` niemals `sync.Tx` benennen — dafür bräuchte es das neutrale `identity/dbtx` aus §8.1 (T-4.1.4). Der Adapter öffnet deshalb seine eigene Transaktion und committet sie **vor** der Wirkung, was genau das ist, was `ActivateBreakGlass` ohnehin verlangt („no emergency access exists until it is on the record"). Die verbleibende Fehlerrichtung — ein Audit-Eintrag für eine Aktivierung, deren Grant danach nicht gespeichert wurde — ist die wahrheitsgemäße; die verbotene, ein Grant ohne Audit, kann nicht eintreten. Der Adapter importiert `authz` **nicht**: Go-Interfaces sind strukturell, und die Zusicherung steht im Vertragstest, wo beide Pakete ohnehin im Bild sind.

Dabei fiel eine Lücke aus §4.2 auf: `WriteAuditRecord` prüfte `entry.TenantID`, aber nicht `entry.ID` — ein Eintrag ohne ID wurde mit `id: ""` gesiegelt, und da §4.1 die `id` in den kanonischen Hash aufgenommen hat, band jeder solche Eintrag dasselbe leere Feld. Der Schreiber vergibt jetzt neben der Sequenznummer auch die Zeilenidentität; eine vom Aufrufer gesetzte bleibt erhalten.

Neue Tests: `TestAuditDispatcher_CriticalAuditIsAlsoReplicated` (**heute rot** — die Lücke), `TestLedgerWriter_AssignsRowIdentity`, vier Adapter-Tests, sowie `TestContract_BreakGlassAuditReachesTheLedger` und `TestContract_BreakGlassRefusesWithoutADurableAudit` — der zusammengesetzte Stapel von `MemoryOutboxStore` bis `BreakGlassEngine`, plus die Compile-Zeit-Zusicherung auf den Port.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-2.5.5** | **Break-Glass-Aktivierung ist keine Arbeitseinheit.** Audit und `GrantStore.Save` committen getrennt. Zusammenzuführen setzt einen Postgres-`GrantStore` (T-2.5.2) **und** `identity/dbtx` voraus, damit `authz` überhaupt eine Transaktion benennen kann. | Zwei Vorbedingungen, beide Sprint 3 bzw. § 8.1. | § 2.5, § 4.2, § 8.1 |
| **T-2.5.6** | **Das `action`-Feld quetscht Requester, Approver und Justification per `:` in einen String** — der zudem mit den Doppelpunkten der URNs kollidiert. Er wird mitgehasht, ist also manipulationsevident, aber nicht abfragbar. Eigene Felder ändern den kanonischen Datensatz. | Gehört zum Hash-Umbau (§ 4.1). | § 2.5, § 4.1 |

### 5.2 Drei Problem-Details-Schreiber, vier Tenant-Fehler

`serrors.WriteProblemDetails` · `middleware.WriteProblemDetails` (eigene Signatur, mappt Status→Code und überschreibt den Code mit dem *Titel*, verwirft den übergebenen `typeURI`) · `enforce/interceptor_http.go` (inline, **ohne** `Code`).

Tenant-Mismatch: `tenant.ErrCrossTenantAccessForbidden` · `principal.ErrTenantMismatch` · `serrors.ErrTenantMismatch` · `authz.ErrTenantStoreNotFound`. Ein Client kann auf den Fall nicht schalten.

#### 5.2-T Ergebnis und offene Tickets aus der Umsetzung von 5.2

Der Abschnitt zählt vier Fehler. Es waren **fünf Prüfstellen mit vier verschiedenen Ausnahmeregeln** — und die Ausnahmen wichen weiter voneinander ab als die Fehlerwerte:

| Prüfstelle | Ausnahmen | gemeldet als |
|---|---|---|
| `enforce.TenantGate` (der Live-Pfad) | Operator, Workload ohne Org, leere Anfrage | `serrors.ErrForbidden` — **gar kein Tenant-Fehler** |
| `principal.ExtractPrincipalFromCertificate` | Operator, Workload ohne Org | `principal.ErrTenantMismatch` |
| `pki.SANCertificateVerifier` (Schritt 3) | Operator | `principal.ErrTenantMismatch` |
| `authz.ExplainPermission` | keine | `authz.ErrTenantStoreNotFound` |
| `tenant.EnforceTenantBoundary` | keine | `tenant.ErrCrossTenantAccessForbidden` |

Der praktisch wichtigste Punkt steht in der ersten Zeile: **das einzige Gate, das im laufenden Betrieb je feuert, meldete `403 forbidden` ohne jeden Hinweis auf den Tenant.** Der Fall, auf den ein Client schalten soll, erreichte die Leitung überhaupt nicht — und `SecurityInterceptor` mappte ihn davor auf `401 unauthorized`, also ununterscheidbar von einem kaputten Token.

Zwei Werte trugen dabei je zwei Bedeutungen. `authz.ErrTenantStoreNotFound` behauptete einen fehlenden Store für das, was die Zeile darüber als Sicherheitsverletzung *loggte* — dieselbe Konstante stand gleichzeitig für „Directory nicht erreichbar". Und `tenant.EnforceTenantBoundary` hatte **keinen Produktionsaufrufer**; die Regel darin kannte weder Operatoren noch Plattform-Workloads, hätte also beide ausgesperrt, wäre sie je montiert worden. Sie ist samt `isolation_test.go` gelöscht.

Die Grenze steht jetzt einmal, als `principal.MayActIn(requestedOrgID)`. Der Ort ist erzwungen: `identity/principal` darf laut `boundaries_test.go` **nichts** aus dem Modul importieren, es ist damit das einzige Paket, das alle fünf Prüfstellen erreichen. Die vereinheitlichte Regel ist die Vereinigung der bisherigen Ausnahmen — Operator überall, Workload ohne Org überall, leere Anfrage offen —, weil jede engere Variante einen heute funktionierenden Pfad gebrochen hätte.

Auf der Ausgabeseite kam `serrors.Classify(err) → (status, code)` dazu: die einzige Stelle, an der eine solche Zuordnung liegen *kann*, weil `shared` nicht nach `identity` importieren darf. Jede Schicht wickelt deshalb ein Sentinel ein, statt für dieselbe Bedingung einen eigenen Fehler zu erfinden — `identity/bff` tut das jetzt für seine fünf Sitzungsfehler, die vorher allesamt in den 500er-Default gefallen wären. Die Reihenfolge ist spezifisch-zuerst; `ErrTenantMismatch` **vor** `ErrForbidden`, sonst verschwindet der Fall wieder hinter dem generischen.

Zwei Fail-opens sind dabei mitgegangen. `NewProblemDetails` machte aus einem leeren Code `CodeInternalError` — der einzige Schreiber der Plattform durfte damit eine `403` ausliefern, die sich selbst als internen Fehler bezeichnet; jetzt Panik (O10). Und `authz.CheckPermission` setzte ohne Resolver die Store-ID aus der Tenant-ID zusammen: eine geratene Store-ID im Autorisierungspfad ist entweder nicht vorhanden (jede Prüfung fällt in den degradierten Zweig) oder vorhanden und nicht die, die das Directory genannt hätte. Beides ist schlechter, als es zu sagen.

Neu: `TestPrincipal_MayActIn` (8 Fälle, die einzige Definition der Grenze), `shared/errors/classify_test.go`, sowie `TestContract_EveryCrossTenantRejectionUnwrapsToOneSentinel` — Enforcement-Kette, Zertifikatsprüfung und Explain-Pfad liefern alle `errors.Is(err, serrors.ErrTenantMismatch)` — und `TestContract_TenantMismatchReachesTheWireAsSuch`, das `"code":"tenant_mismatch"` mit `403` auf der Leitung festnagelt.

Wieder war der Defekt in Tests als erwartetes Verhalten festgeschrieben: `TestExplain_CrossTenantAccessDenied` prüfte, dass ein Cross-Tenant-Angriff als „Tenant-Store nicht gefunden" gemeldet wird.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.2.1** | **`ProblemDetails.Instance` wird nirgends gesetzt.** Das Feld existiert, ist `omitempty` und bleibt in jeder Antwort leer — eine Fehlermeldung ohne Bezug zum Vorfall. Der Wert wäre die Korrelations-ID, und die liegt im Request-Kontext, den `shared/errors` nicht kennen darf. Braucht entweder einen Kontext-Parameter an `WriteError` oder einen neutralen Trägertyp. | Entscheidung gehört zum Request-Kontext-Umbau, der ohne `cmd/identity-api` keinen Prüfstein hat. | § 5.2, FND-04 |
| **T-5.2.2** | **`Title` wiederholt den Maschinencode.** RFC 9457 will in `title` eine für Menschen lesbare, über alle Vorkommen *gleiche* Kurzfassung; `Title: code` liefert stattdessen `"tenant_mismatch"` doppelt. Eine Zuordnung Code→Titel gehört neben die Taxonomie in `codes_gen.go`. | Kosmetisch gegenüber dem Rest von § 5.2, und `codes_gen.go` heißt `_gen`, hat aber keinen Generator — das will zuerst geklärt sein. | § 5.2, FND-04 |
| **T-5.2.3** ✅ | **`mtls_termination.go` wählt an sieben Stellen Status und Code von Hand**, sechsmal `401/unauthorized` — darunter für `ErrUnresolvableTenant`, was keine Authentifizierungsfrage ist. Der Rand ist der letzte Ort, der am Taxonomie-Sentinel vorbei direkt auf den Low-Level-Schreiber geht. | **Erledigt.** Die Sentinels des mTLS-Randes umschließen jetzt die Taxonomie (`ErrUnresolvableTenant` umschließt `serrors.ErrForbidden`), alle sieben Stellen schreiben über `serrors.WriteError`. Der Statuswechsel ist inhaltlich: wer ein gültiges Zertifikat vorlegt, dessen Tenant sich nicht auflösen lässt, ist authentifiziert und nicht berechtigt — 403, nicht 401. Die Testerwartung wurde entsprechend korrigiert, nicht umgekehrt. | § 5.2, § 3.8 |

### 5.3 Vier Org-Namensregeln

| Ort | Regel |
|---|---|
| `shared/policy.ValidateOrgName` (generiert) | aus `policy/rules/org_names.yaml` |
| `internal/orgs.ValidateName` | Regex `^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$` (3–32, `--` erlaubt, keine Reserved Names) |
| `celldir.ValidateQuotaAndOrgName` | `len(trimmed) >= 2` |
| `target/rules.go` | delegiert an `shared/policy` ✅ |

Nur einer der vier Aufrufer nutzt die generierte Quelle.

#### 5.3-T Ergebnis und offene Tickets aus der Umsetzung von 5.3

Es waren **sechs Regeln**, und die beiden, die die Tabelle nicht nennt, sind die mit den echten Aufrufern:

| Ort | Regel | Aufrufer |
|---|---|---|
| `shared/policy.ValidateOrgName` (generiert) | 3–63, 6 reservierte Wörter | die Quelle |
| `identity/internal/orgs.ValidateName` | 3–32, `--` **erlaubt**, **keine** reservierten Wörter | `CreateOrganization`, `ProvisionPersonalOrganization` |
| `celldir.ValidateQuotaAndOrgName` | `len >= 2` | nur Test |
| `identity/target/rules.go` | delegiert ✅ | POL-04-Hook |
| **`registry/internal/validate.ValidateOrgName`** | 3–30, 22 reservierte Wörter | **keiner** |
| **`registry/.../handler.validateOrgName`** | 3–32, 4 reservierte Wörter | **`POST /api/v1/orgs`** |

**Der Weg hinein war die persönliche Organisation.** `ProvisionPersonalOrganization` leitet den Org-Namen aus dem Benutzernamen ab und prüfte mit der Regel ohne Reserved-Check — ein Benutzer namens `admin`, `root`, `registry` oder `fleet` bekam bei der Registrierung eine Organisation dieses Namens im **globalen** Namensraum (`GetOrgByName` ist global eindeutig). Über den HTTP-Endpunkt gingen zusätzlich `root`, `registry` und `fleet` durch, weil dessen Liste vier Wörter kannte.

**Und eine Kollision, die in keiner der sechs Listen stand.** Ein Org-Name ist ein Pfadsegment: `GET /api/v1/orgs/{name}` steht neben `GET /api/v1/orgs/mine`, und Gos `ServeMux` gibt dem Literal den Vorrang. Eine Organisation namens `mine` wäre über GET und DELETE nie erreichbar gewesen — anlegbar, aber unadressierbar.

Die reservierte Liste ist jetzt die **Vereinigung aller drei Listen plus `mine`** (6 → 25 Wörter). Streng nach dem §5.2-Prinzip wäre nur die Vereinigung der *lebenden* Regeln nötig gewesen (7 Wörter); die 22 aus `registry/internal/validate` hatten keinen Aufrufer. Sie sind trotzdem übernommen, weil diese Datei der einzige Ort war, an dem die Absicht überhaupt aufgeschrieben stand, und weil die Kosten asymmetrisch sind: Übervorsorge kostet einen abgelehnten Namen bei der Registrierung, Untervorsorge einen Namen, der eine Route oder eine Plattform-Identität verdeckt.

`min_length: 3` und `max_length: 63` bleiben unverändert — 63 ist der einzige Wert mit nennbarem Grund (DNS-Label) und wurde über `target/rules.go` ohnehin schon live erzwungen. Konsequenz: Namen mit 33–63 Zeichen sind über die beiden anderen Pfade neu annehmbar; die DB-Spalte ist `TEXT`, dahinter liegt keine Längenannahme.

**Der Validator trimmt nicht mehr.** `ValidateOrgName` prüfte den getrimmten Namen, der Aufrufer speicherte seinen eigenen — `target/rules.go` reicht die Payload ungetrimmt durch und gab `" acme "` ein `allow`. Normalisierung gehört vor die Prüfung, nicht hinein; die drei anderen Aufrufer normalisieren bereits, `ProvisionPersonalOrganization` bekam das fehlende `TrimSpace`.

Zwei Fail-opens nebenbei: `validateRules` erzwang `prohibit_double_hyphen` explizit, prüfte `reserved_words` aber nicht — eine gelöschte Liste hätte lautlos einen Validator ohne jede Reserved-Prüfung erzeugt. Und `ValidateQuotaAndOrgName` las `maxAllowedTenants == 0` als „unbegrenzt", womit eine unkonfigurierte Quote genau die Prüfung abschaltete, die vor jedem externen Aufruf laufen soll.

`registry/internal/validate/rules.go` ist gelöscht: `Rule`, `Compose`, `MinLength`, `MaxLength`, `AlphanumericDashes`, `NoConsecutiveDashes`, `NoLeadingOrTrailingDash`, `NotReserved` und `ValidateOrgName` hatten zusammen null Nutzer außerhalb der eigenen Datei — das dritte tote Konstrukt in Folge nach `enforce.Pipeline` (§5.1) und `tenant.EnforceTenantBoundary` (§5.2).

Wieder stand der Defekt als Erwartung in einem Test: `saga_test.go` prüfte mit `"Acme Corp"` — Großbuchstaben und Leerzeichen — und schrieb damit fest, dass diese Zeichenkette die Namensprüfung besteht.

Ein einziger schichtübergreifender Vertragstest ist hier **nicht baubar**: `identity` darf nicht nach `registry` importieren, und `identity/internal/orgs` ist für `registry` durch Gos `internal`-Regel gesperrt. Nach der Vereinheitlichung ist die Übereinstimmung ohnehin strukturell — die Fälle liegen erschöpfend in `shared/policy/rules_gen_test.go` (inklusive aller 25 reservierten Wörter über `ReservedOrgNames` und der Whitespace-Fixture), je ein dünner Test bei `orgs`, `celldir` und dem Registry-Handler weist die Benutzung nach. Dazu `TestOrgRouteLiteralsAreReservedNames`, der `routes_org.go` parst und jedes literale Segment hinter `/api/v1/orgs/` gegen `ReservedOrgNames` prüft — sonst wiederholt sich der `mine`-Fall bei der nächsten Route.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.3.1** | **Persönliche Org scheitert bei reserviertem Benutzernamen.** `ProvisionPersonalOrganization` bricht für einen Benutzer namens `support` oder `api` jetzt hart ab — richtig, aber die Registrierung schlägt damit fehl. Die Ableitung Benutzername → Org-Name braucht eine Strategie (Suffix, Vorschlag, oder Entkopplung beider Namensräume). | Produktentscheidung, keine Sicherheitsfrage. | § 5.3 |
| **T-5.3.2** | **`shared/errors` hat kein Validierungs-Sentinel.** Seit §5.2 ergeben sich Status und Code aus `Classify`; ein Namensfehler unterwandert nichts, fällt aber mangels Sentinel in den 500er-Default. Heute folgenlos — kein Aufrufer mappt ihn über `Classify` —, beim ersten `cmd/identity-api` sofort falsch. | Ein Taxonomie-Code ohne Konsument ist Spekulation. | § 5.2, § 5.3 |
| **T-5.3.3** | **`ValidateQuotaAndOrgName` prüft zwei Dinge.** Auftrennen, wenn der Onboarding-Pfad gebaut wird — wie der Rest des Saga-Pfads hat die Funktion bis heute nur Tests als Aufrufer. | Braucht den Pfad. | § 5.3, CELL-07 |

### 5.4 Vier Impersonations-Grenzwerte

| Ort | Max. Dauer | Min. Begründung |
|---|---|---|
| `impersonation.MaxImpersonationDuration` | 4 h | Pflicht, Länge egal |
| `token.MaxTokenExchangeLifetime` | 4 h | Pflicht, Länge egal |
| `shared/policy.ValidateImpersonationRequest` | aus YAML | aus YAML |
| `authz` Break-Glass | 240 min | 15 Zeichen |

Der Pfad, der das Impersonations-Token tatsächlich ausstellt (`token/exchange.go`), wendet die **schwächste** Regel an.

#### 5.4-T Ergebnis und offene Tickets aus der Umsetzung von 5.4

**Die Maximaldauer divergierte gar nicht** — alle vier sagten 4 h, viermal aufgeschrieben. Was divergierte, war die Begründungslänge: **1 / 1 / 10 / 15 Zeichen**, ein Faktor fünfzehn.

| Ort | Max. Dauer | Min. Dauer | Min. Begründung | Quelle | Aufrufer |
|---|---|---|---|---|---|
| `impersonation.ValidateImpersonationConstraints` | 4 h | **keine** (≤0 erlaubt) | **1 Zeichen** | Konstante | **nur Tests** |
| `token.ExchangeToken` | 4 h | > 0 | **1 Zeichen** | Konstante | *der* Ausstellungspfad |
| `shared/policy.ValidateImpersonationRequest` | 14400 s | > 0 | 10 Zeichen | YAML ✅ | `target/rules.go` |
| `authz` Break-Glass | 240 min | 1 min | 15 Zeichen | Konstanten | `ActivateBreakGlass` |

Der Satz des Abschnitts stimmt und war noch zu freundlich: `ExchangeToken` verlangt eine „mandatory audit justification" und akzeptierte dafür **ein Zeichen** — auf dem einzigen Pfad im System, der ein Impersonations-Token tatsächlich prägt.

**Konstanten statt einer gemeinsamen Validierungsfunktion.** Die drei durchsetzenden Pakete haben je eine eigene, sinnvolle Fehlertaxonomie — „Begründung zu kurz" und „Dauer außerhalb des Fensters" sind für einen Client verschiedene Reparaturen. Ein gemeinsamer Validator mit einem undurchsichtigen Fehler hätte genau die Unterscheidung eingeebnet, die §5.2 gerade hergestellt hat. Divergiert ist die **Zahl**, also wird die Zahl einquellig: `spolicy.MaxImpersonationDuration`, `MinImpersonationJustificationLen`, `MaxBreakGlassDuration`, `MinBreakGlassDuration`, `MinBreakGlassJustificationLen`. Break-Glass bekam eine eigene `policy/rules/break_glass.yaml`, weil es ein anderer Mechanismus ist (AUTHZ-13, Dual-Control, Grant-Store, Ledger) und die 4 h nur zufällig teilt — zwei deklarierte Zahlen können absichtlich auseinandergehen, eine Konstante in zwei Paketen geht versehentlich auseinander. **Keine deklarierte Zahl wurde geändert, nur ihr Ort.**

`ValidateImpersonationRequest` nimmt jetzt `time.Duration` statt ganzer Sekunden. Die Umrechnung schnitt ab: vier Stunden und eine halbe Sekunde kamen als exakt 14400 an und wurden angenommen. Der Vertragstest hält genau diesen Fall fest.

Zwei Fail-opens nebenbei: `ValidateImpersonationConstraints` ließ `duration <= 0` durch — die Sitzung wurde gespeichert, den Org-Eigentümern gemeldet und war vor ihrem Beginn abgelaufen. Und die Fehlermeldungen buchstabierten die Grenze aus (`"maximum duration is 4 hours"`, `"minimum 15 characters"`, `"between 1 and 240 minutes"`); sie hätten gelogen, sobald die YAML sich ändert. Die Zahl nennt jetzt die Umhüllung am Prüfort, nicht der Sentinel-Text.

**Der Härtungsschritt am Ausstellungspfad:** `ExchangeToken` verifizierte `actor_token`, prüfte aber nicht, dass der Akteur ein **Operator** ist. `enforce.ImpersonationGate` lehnt einen anderen `act`-Anspruch bei der Durchsetzung ab — das Token wurde trotzdem geprägt, als Impersonation protokolliert und lebte seine volle Lebensdauer. Die Regel gehört an die Ausstellung, wo sie eine Ablehnung ist, nicht nur ans Kettenende, wo sie eine Überraschung ist.

**Der strukturelle Befund, der bleibt:** das gesamte Paket `identity/impersonation` hat **keinen Importeur außerhalb der eigenen Tests**. Sitzung, Eigentümer-Benachrichtigung, strikte `viewer`-Rolle, Ablaufprüfung, `CanExecuteOperation`, `EnforceNoStandingGrants` — IDP-060 ist implementiert und an nichts angeschlossen, während `token.ExchangeToken` das Token ohne jede Sitzung ausstellt. Das vierte tote Konstrukt in Folge nach `enforce.Pipeline`, `tenant.EnforceTenantBoundary` und `registry/internal/validate/rules.go`. Als T-5.4.1 vertagt, weil die Verbindung eine Entwurfsänderung ist.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.4.1** | **`identity/impersonation` ist an nichts angeschlossen.** `token.ExchangeToken` stellt das Impersonations-Token aus, ohne eine Sitzung anzulegen oder zu prüfen: keine Eigentümer-Benachrichtigung (AUTH-053), keine `viewer`-Beschränkung, kein Store-Eintrag, keine Ablaufprüfung. IDP-060 gilt damit heute für nichts. Die Verbindung — der Exchange verlangt eine aktive Sitzung — ist eine Entwurfsänderung. | Braucht den HTTP-Pfad (`cmd/identity-api`, Sprint 3). | § 5.4, IDP-060 |
| **T-5.4.2** | **Die 4 h stehen an zwei fachlich verschiedenen Stellen zufällig gleich.** Impersonations-Token-Lebensdauer und Break-Glass-Fenster sind beide 14400 s. Jetzt sind es zwei deklarierte Zahlen, die getrennt geändert werden können — ob sie das *sollen*, hat niemand entschieden. | Produktfrage. | § 5.4 |

### 5.5 Sechs URN-Konstruktionsstellen

`principal.Format*URN` existiert und wird an genau zwei Stellen genutzt. Daneben bauen `fmt.Sprintf`-Aufrufe URNs in `scim/provider.go`, `scim/deprovision.go`, `pki/workload.go`, `pki/zero_touch.go`, `test/tokens/issuer.go`, `authz/breakglass.go`. Zwei davon erzeugen Formate, die `principal.ParseURN` ablehnt (`toob:service_account:…` statt `toob:sa:…`).

#### 5.5-T Ergebnis und offene Tickets aus der Umsetzung von 5.5

Drei der sechs genannten Stellen waren bereits geschlossen: `scim/provider.go` nutzt seit §3.x `FormatHumanURN` und ist dort als „the single construction site" dokumentiert, `scim/deprovision.go` verlangt die URN vom Aufrufer, `authz/breakglass.go` parst statt zu bauen. Offen waren vier — `pki/zero_touch.go` zählt doppelt.

**Der Defekt ist nicht die Doppelung, sondern was die Doppelung wegoperiert.** Jeder `Format*URN` prüft auf leere Felder; das ist sein einziger Zweck über das `Sprintf` hinaus. Die handgebauten Stellen übersprangen ihn, `url.Parse("toob:workload:svc::")` ist gültig, und weder `IssueWorkloadCertificate` noch `GenerateFactoryBootstrapCert` validierten ihre Eingaben. **Ein Zertifikat wurde also mit einer Identität ausgestellt, die `ParseURN` später ablehnt** — der Fehler landete am anderen Ende der Kette, auf einem Credential, das schon im Feld war.

**Der Test-Issuer erzeugte für drei von fünf Aktortypen unparsbare URNs, nicht für zwei.** `fmt.Sprintf("toob:%s:shared:%s:test_usr_123", actorType, orgID)` liefert mit `ActorServiceAccount` `toob:service_account:…` (der Parser erwartet `sa`), mit `ActorWorkload` eine unbekannte Workload-Art `shared`, mit `ActorOperator` fünf Segmente statt drei. Nur `human` und `device` gingen durch. Heute ruft nur `identity-seed` mit `ActorHuman` auf, der Rest war latent — aber es ist ein Test-Helfer: jeder Test, der ihn mit einem anderen Aktortyp benutzt hätte, wäre gegen ein Credential gelaufen, das die Produktion ablehnt. Ein Aktortyp ohne URN-Form ist jetzt ein Fehler statt einer Zeichenkette.

**`toob:bootstrap:device:…` kannte `ParseURN` überhaupt nicht.** Das war *zufällig richtig* — ein Werks-Bootstrap-Credential darf niemals zu einem Principal werden —, stand aber nirgends und fiel in denselben Zweig wie ein Tippfehler. Jetzt ein benannter Ablehnungsgrund, `ErrNotAPrincipalURN`, plus `FormatDeviceBootstrapURN`/`ParseDeviceBootstrapURN` mit eigenem Rückgabetyp `DeviceBootstrap`: die Aussage „das ist kein Principal" steht damit im Typsystem, nicht nur im Kommentar.

**Und ein Format ohne Erzeuger:** `ParseURN` akzeptierte `toob:workload:tenant:<cell>:<orgId>:<workloadID>`, aber kein `Format*` produzierte es — es existierte nur als Literal in `san_verifier_test.go`. `FormatTenantWorkloadURN` schließt die Asymmetrie und ist zugleich die Form, die der Test-Issuer für `ActorWorkload` braucht.

**Eine Reihenfolge, die dabei auffiel.** In `ExchangeBootstrapForOperationalCert` steht über dem Verbrennen des Bootstrap-Zertifikats: „Everything that can reject this request has already run." Der Bau der operativen URN stand *danach*. Ein leeres Feld dort hätte das Gerät sein Werks-Credential gekostet, ohne ein operatives zu bekommen. Der URN-Bau ist jetzt vor dem Burn, und die Zusicherung im Kommentar stimmt wieder. Die Handzerlegung der Bootstrap-URN in derselben Funktion ist durch `ParseDeviceBootstrapURN` ersetzt.

Neu: `TestFormatParseRoundtrip` über alle sieben Principal-Formatierer — die verletzte Eigenschaft, genau einmal geprüft, dort wo die Grammatik wohnt —, `TestFormatURNs_RejectEmptyFields`, `TestBootstrapURN_IsNotAPrincipal`, je ein Ausstellungs-Test bei Workload und Zero-Touch, und `TestGenerateTestToken_EveryActorProducesAParsableURN` über alle fünf Aktortypen. Dazu **`TestContract_URNsAreFormattedNeverPrinted`**, der `identity/**` mit `go/ast` durchgeht und jeden `fmt`-Formatstring meldet, der mit `toob:` beginnt. Die Regel braucht keine Ausnahmeliste: Lesen benutzt `ParseURN`, Auswählen benutzt `strings.HasPrefix`, keins von beiden einen Formatstring. Der Test ist an den Formatierern in `principal` verankert, damit er nicht leer bestehen kann.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.5.1** ✅ | **Präfixvergleiche sind der zweite Grammatik-Besitzer.** `rotation.go`, `workload.go` und `zero_touch.go` wählen die SAN-URI per `strings.HasPrefix(uri.String(), "toob:device:")` aus mehreren SANs aus. Richtig wäre `ParseURN` plus eine Prüfung des Aktortyps — das ändert die Auswahlsemantik bei mehreren SANs. | **Erledigt.** `principal.URNFromCertificate` ist die eine Auswahl: SAN-URI vor CommonName, danach `ParseURN`. Die Prüfung des Aktortyps steht an der Aufrufstelle, weil nur sie weiß, welchen Aktor sie erwartet. `rotation.go` verliert damit auch seinen zweiten Grammatik-Besitzer — den handgeschriebenen Split 40 Zeilen später, aus dem der Tenant kam. `zero_touch.go` benutzt `ParseDeviceBootstrapURN` als Typprüfung und tut es jetzt **vor** der Kettenprüfung. | § 5.5, § 3.8 |
| **T-5.5.2** | **`toob:workload:tenant:…` hat jetzt einen Erzeuger, aber keinen Produktionsaufrufer** — nur den Test-Issuer und ein Literal in `san_verifier_test.go`. Entweder benutzt ein echter Pfad die Form, oder Parser und Formatierer beschreiben eine Identität, die es nicht gibt. | Braucht die Entscheidung, ob Tenant-Workloads existieren. | § 5.5 |

### 5.6 Vokabular-Bruch Go ↔ FGA-Modell

| Go schreibt | Modell kennt |
|---|---|
| `organization:<id>` (`sync/jit.go`, `authz/breakglass.go`, `sync/deletion.go`) | `tenant` |
| `group:<id>` (`scim/mapping.go`) | — |
| `device:<id>` als **Subjekt** (`PrincipalToFGASubject`) | keine Relation akzeptiert `[device]` |

Jeder Tupel-Write aus Sync, SCIM und Break-Glass wird von OpenFGA abgelehnt. Die zugehörigen Tests laufen gegen Mock-Writer und prüfen nur, *dass* geschrieben wurde.

#### 5.6-T Ergebnis und offene Tickets aus der Umsetzung von 5.6

Break-Glass war bereits korrigiert (`breakglass.go:286` schreibt `tenant:%s`), `sync/deletion.go` baut gar keine Objekte mehr. Offen waren drei Stellen — und zwei Ebenen, die der Abschnitt nicht nennt.

**Der Grund, warum das niemandem auffiel: kein Go-Code las jemals `policy/model/*.fga`.** Das Modell war Dokumentation, die Vokabeln standen viermal von Hand daneben — in `sync/jit.go`, in `scim/mapping.go`, in `PrincipalToFGASubject` und als Literal `activeRelations` in `linter_test.go`. `policygen` liest jetzt `fga.mod` und die darin genannten Dateien und erzeugt `FGATypes`/`FGARelations`; `shared/policy.ValidateTuple` prüft die drei Ebenen, an denen es brach: Objekttyp existiert, Relation existiert auf ihm, Relation nimmt den Subjekttyp **direkt** an. Berechnete Relationen (`or`, `from`) nehmen nichts an — man kann sie auswerten, aber nicht beschreiben, und OpenFGA lehnt den Write ab.

`authz.TupleKey.Validate()` ist der eine Aufhänger; jeder Erzeuger ruft ihn vor dem Schreiben.

**Die vierte Stelle, die der Abschnitt nicht nennt:** der `default`-Zweig von `PrincipalToFGASubject` machte aus einem unbekannten Aktortyp lautlos `user:<urn>` — ein nicht erkannter Akteur wurde als **Mensch** autorisiert. Jetzt ein Fehler, wie `ActorDevice` auch.

**Die fünfte, und die schwerste: der Berechtigungskatalog spricht das Modell selbst nicht.** `policy/permissions.yaml` und `policy/model/*.fga` liegen beide unter `policy/`, und nichts hat sie je verglichen — **8 von 22 Berechtigungen** nennen einen Typ oder eine Relation, die es nicht gibt. Das ist T-5.6.1; der Generator liefert ab jetzt die Daten, um es zu entscheiden.

**`GroupTupleMapper` ist gelöscht.** Er hatte keinen Produktionsaufrufer, und anders als `identity/impersonation` (§5.4, korrekt aber unverdrahtet) ist er **nicht korrigierbar**, ohne dass das Modell einen `group`-Typ bekommt — eine ADR-Entscheidung. Sein Test war genau der aus dem Abschnitt: er prüfte Subjekt und Anzahl der Writes und nie, ob der Objekttyp existiert. Ein Indiz, dass die Abbildung nie fertig wurde: `ReconcileGroupMembership` nahm einen `tenantID`-Parameter entgegen und benutzte ihn nirgends. Der naheliegende Kurzschluss — alle Gruppen auf `tenant#member` — wäre eine Ausweitung: eine IdP-Gruppe „externe-dienstleister" verliehe damit Tenant-Mitgliedschaft. Fünftes totes Konstrukt in Folge.

Dabei fielen zwei Fail-opens in `jit.go` auf. Der Writer war optional (`if fgaWriter != nil`) — ohne ihn meldete die JIT-Provisionierung Erfolg für einen Nutzer, von dem die Autorisierung nie erfahren hat. Und der Erstlogin-Claim in `seenFederatedUsers` wurde **vor** der Arbeit gesetzt und bei Fehlschlag nicht zurückgegeben: ein einziger Fehlversuch markierte den Nutzer dauerhaft als provisioniert, jeder Retry nahm den idempotenten Skip. Der Claim vor der Arbeit ist richtig (zwei gleichzeitige Erstlogins dürfen nicht beide provisionieren), er muss nur bei Fehlschlag zurück.

Zwölf Testliterale in vier Dateien schrieben `organization:` als erwartete Daten fest; sie sind mitgezogen.

Neu: `TestValidateTuple` (alle drei Bruchebenen plus Positivfälle je Modelltyp), `TestFGAModel_MatchesTheAuthorizationModel` (liest `policy/model/*.fga` unabhängig vom Generator und vergleicht — sonst driftet die Tabelle still vom Modell weg, derselbe Fehler eine Ebene höher), drei JIT-Tests und `TestPrincipalToFGASubject_ProducesSubjectsTheModelAccepts`. Der Generator lehnt jetzt eine `.fga`-Datei ab, die `fga.mod` nicht nennt.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.6.1** | **8 von 22 Berechtigungen nennen Typen oder Relationen, die das Modell nicht hat:** `fleet.device.list`, `fleet.device.read_granular` (`device` hat kein `viewer`), `fleet.device.register` (kein `operator`), `fleet.channel.create` (`channel` hat kein `admin`), `fleet.rollout.start`, `fleet.rollout.cancel`, `release.approval.grant`, `release.approval.cancel` (Typ `rollout` existiert nicht). Entweder wächst das Modell, oder der Katalog zeigt auf `device_group`/`release`. Dazu gehört das Literal `activeRelations` in `linter_test.go`: die Linter-Regeln 3 und 4 sind nach blankem Relationsnamen geschlüsselt und werten fehlende Typ-Constraints als Verstoß, passen also nicht auf `FGARelations` (`typ#relation`, berechnete Relationen ohne Constraints), solange der Katalog nicht stimmt. | Ändert, was autorisiert wird — ADR. | § 5.6, POL-06 |
| **T-5.6.2** | **SCIM-Gruppen haben kein Modell.** SYNC-06 verlangt Gruppen→Tupel-Sync; es gibt keinen `group`-Typ. Entweder `group` mit `parent: [tenant]`, oder eine explizite Abbildung Gruppenname→Tenant-Relation. Der Mapper wird gegen den dann existierenden Typ neu geschrieben. | ADR. | § 5.6, SYNC-06 |
| **T-5.6.3** | **Geräte sind im Modell Objekte, keine Subjekte.** `ActorDevice` existiert, Geräte authentifizieren sich per mTLS, aber keine Relation nimmt `[device]` an. Entweder handeln Geräte nie selbst gegenüber der AuthZ, oder das Modell braucht sie. | ADR. | § 5.6, DEV-03 |
| **T-5.6.4** | **`CheckPermission` übergibt die Berechtigungs-ID als FGA-Relation.** `Check(..., req.Permission, ...)` — kein Typ definiert eine Relation `fleet.device.list`. Die Abbildung existiert als `PermissionDefinition.Relation` und wird von `zitadel/provisioner.go` benutzt, von der Prüfung aber nicht. Heute folgenlos, weil `CheckPermission` außerhalb von `authz` keinen Aufrufer hat; mit dem ersten schlägt jede Prüfung fehl. | Hängt an T-5.6.1: die Zielrelationen müssen erst stimmen. | § 5.6 |

### 5.7 Zwei Zitadel-Rollenkataloge

`zitadel.DefaultPermissionCatalog()` (8 Rollen, hartkodiert) und `zitadel.DynamicPermissionCatalog()` (aus `spolicy.PermissionCatalog`, erzeugt Rollen aus FGA-**Relationen**). `NewProvisioner(client, nil)` fällt immer auf den hartkodierten zurück; der dynamische wird nirgends aufgerufen. `ErrUnreferencedRoleFound` ist deklariert und ungenutzt.

#### 5.7-T Ergebnis und offene Tickets aus der Umsetzung von 5.7

`DynamicPermissionCatalog` hatte nicht nur keinen Aufrufer — es **konnte** keinen sinnvollen haben. Es dedupliziert nach FGA-Relation allein, also fallen `viewer` auf `channel`, auf `package` und auf `device` zu **einer** Zitadel-Rolle zusammen, deren `DisplayName` die Beschreibung der zuerst einsortierten Berechtigung wird (`fleet.device.list` → „List registered devices within the tenant organization boundaries") und deren `Group` deren Ressource ist (`device`). Aus „Fleet Telemetry Viewer" wäre eine Rolle mit dem Anzeigenamen eines Geräte-Listings geworden, die auch für Pakete gilt. Gelöscht — sechstes totes Konstrukt in Folge.

`NewProvisioner` verliert den Katalog-Parameter. Alle drei Aufrufer übergaben `nil`, worauf der Konstruktor still den Standard einsetzte: ein Injektionspunkt, den niemand benutzt, der einen Fallback bewacht, den niemand will. Welches Rollenmodell in den Identitätsanbieter geschrieben wird, ist keine Aufruferentscheidung. `ErrUnreferencedRoleFound` ist ebenfalls weg — `DriftReport.UnreferencedRoles` trägt die Information als Daten, und `--check-drift` beendet sich darauf mit Code 2; ein zweiter Weg, dasselbe zu sagen, war nie nötig.

**Der Befund, der nicht im Abschnitt steht: die Rollen werden ausgestellt und weggeworfen.**

```go
govRole, _ := extractRoles(mapClaims)   // verifier.go:189 — die Produktrollen fallen hier weg
Role: govRole,                          // verifier.go:195 — Principal.Role liest niemand
```

Acht Rollen werden in Zitadel angelegt, erscheinen im Token, und beim Verifizieren nimmt der Aufrufer die eine Hälfte gar nicht entgegen, während die andere in einem Feld landet, das §5.8 als „gesetzt, nie gelesen" führt. Autorisiert wird über OpenFGA-Relationen. Das ist T-5.7.1.

**Und ein viertes Rollenvokabular, das den anderen widerspricht:** `zitadel.PermissionCatalog`, `policy/model/core.fga` (`tenant`) und `token.extractRoles` sagen alle owner/**admin**/member — `orgs.OrgRole` sagt owner/**maintainer**/member. Der lokale Spiegel vergibt eine Rolle, die weder der IdP noch das Autorisierungsmodell kennt. Das ist T-5.7.2.

Der neue Test ist **verhaltensbasiert, nicht vergleichend**: er stellt für jede der acht Katalogrollen ein Token aus, schickt es durch den echten `token.Verifier` und verlangt, dass genau die Rollen des `governance`-Projekts als `Principal.Role` überleben. Ein Vergleich des Katalogs gegen eine Literalliste hätte nur eine dritte Stelle geschaffen, die mitgepflegt werden muss. Er liegt neben dem Katalog und nicht in `identity/test/contract`, weil `boundaries_test.go` `identity/internal` kapselt — strenger als Gos eigene `internal`-Regel, und mein Plan lag da falsch.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.7.1** | **Das Zitadel-Rollenmodell hat keinen Konsumenten.** Acht Rollen werden angelegt, erscheinen im Token und werden beim Verifizieren verworfen: `govRole, _ :=` lässt die Produktrollen fallen, `Principal.Role` liest niemand. Entweder gaten die Rollen etwas — dann fehlt der Auswertungspunkt im Enforcement-Pfad —, oder sie sind IdP-Zierde und der Katalog kann schrumpfen. | Braucht `cmd/identity-api` und die Entscheidung, ob IdP-Rollen neben FGA-Relationen überhaupt eine Rolle spielen. `Principal.Role` und `TokenClaims` gehören zu § 5.8. | § 5.7, ZIT-02 |
| **T-5.7.2** | **`orgs.OrgRole` kennt `maintainer`, Zitadel und das FGA-Modell kennen `admin`.** Vier Vokabulare, drei einig, eines nicht. Der Spiegel schreibt `maintainer` in die DB; sobald etwas Spiegelrollen auf FGA-Relationen abbildet, hat sie kein Ziel. | Die Werte stehen in der Postgres-Spiegeltabelle; das Umbenennen ist eine Migration. | § 5.7, § 5.6 |
| **T-5.7.3** | **Nicht referenzierte *Projekte* erkennt die Drift-Prüfung nicht.** `UnreferencedRoles` meldet Rollen außerhalb des Katalogs; ein ganzes Projekt außerhalb des Katalogs bleibt unsichtbar, obwohl seine Rollen zuweisbar sind. Dieselbe Klasse, eine Ebene höher. | Zitadel legt eigene Projekte an; die Prüfung braucht eine deklarierte Ausnahmemenge, und die ist eine Deployment-Tatsache, die im Repo nicht steht. | § 5.7 |
| **T-5.7.4** | **Rollennamen stehen an fünf Stellen im Go-Code:** `target/rules.go:147` („privilegiert" = owner/admin/release-manager), `:196` (owner/admin brauchen L3-Faktoren), die elevation-Regel in `policygen` (owner/admin), `token.extractRoles` und der Katalog selbst. Eine `policy/roles.yaml` mit Projekt, Gruppe, Anzeigename und den Prädikaten „privilegiert"/„braucht L3" hätte damit **echte** Konsumenten — anders als das Rollenmodell heute. | Gehört in den O5-Katalogschnitt zusammen mit T-3.1.2, T-3.4.1, T-2.7.1 und T-5.6.1. | § 5.7, O5 |

### 5.8 Toter Code

`token.TokenClaims` (Verify liefert `*principal.Principal`) · `middleware/auth.go` komplett (`GetClaimsFromContext` liest einen Context-Key, den niemand setzt; nimmt zudem ein anonymes Interface statt `context.Context`) · `authz.ConsistencyMode`/`WithConsistencyMode` (`c.consistency` wird gesetzt und nie an `Check` übergeben — die Signatur hat keinen Konsistenzparameter) · `authz.CheckRequest.IsWriteAction` (gesetzt, nie gelesen) · `RouteSecurityPolicy.RequiredRole`/`RequiredProductRole` (gesetzt, nie ausgewertet) · `Principal.Role` (gesetzt, nie gelesen) · `pki.min()` (schattet den Builtin seit Go 1.21; go.mod sagt 1.26.3) · `sync.LeaderElector` (Interface wird von `MemoryLeaderElector` **nicht** implementiert — abweichende Signatur) · `RateLimitRequest.Permission` · `WorkloadClaims.Issuer`/`Audience` · `test/failure` `var _ = big.NewInt(0)` zur Unterdrückung eines ungenutzten Imports.

#### 5.8-T Ergebnis und offene Tickets aus der Umsetzung von 5.8

Zwei Einträge waren erledigt, einer war falsch klassifiziert, einer war überhaupt kein toter Code.

| Eintrag | Befund | Ergebnis |
|---|---|---|
| `token.TokenClaims` | **lebt** — `registry/.../middleware/auth.go:121` baut sie im CI-Token-Pfad und legt sie in den Kontext. Das ist der einzige produktiv greifende Authentifizierungspfad, denn `am.jwtVerifier` wird nie gesetzt. | bleibt |
| `middleware/auth.go` | tot: eigener Kontextschlüssel, eigener Getter, kein Setzer, kein Aufrufer | gelöscht |
| `authz.ConsistencyMode`/`WithConsistencyMode` | tot: `c.consistency` gesetzt, nie gelesen | gelöscht, **T-5.8.2** |
| `authz.CheckRequest.IsWriteAction` | tot: nur in drei Tests gesetzt | gelöscht |
| `RouteSecurityPolicy.RequiredRole`/`RequiredProductRole` | bereits entfernt | — |
| `Principal.Role` | tot — und mit ihm `token.extractRoles` als einziger Konsument sowie `TokenClaims.GovernanceRole`/`ProductRoles` | gelöscht |
| `pki.min()` | bereits mit § 3.8 entfernt | — |
| `sync.LeaderElector` | tot **und irreführend**: `MemoryLeaderElector.AcquireLeader(ctx, instanceID)` hat eine andere Signatur, erfüllt das Interface also nicht — wer es implementiert, baut die falsche Form | gelöscht, **T-5.8.1** |
| `RateLimitRequest.Permission` | tot: einmal gesetzt, vom Limiter nie gelesen — `Cost` dagegen schon | gelöscht, **T-5.8.3** |
| `WorkloadClaims.Issuer`/`Audience` | **kein toter Code, sondern eine fehlende Prüfung** | siehe unten |
| `test/failure` `var _ = big.NewInt(0)` | Import-Unterdrücker | gelöscht samt Import |

**Der falsch überschriebene Eintrag.** `ValidateWorkloadClaims` prüfte Repository, Ref und Workflow — aber weder `iss` noch `aud`. Für ein GitHub-Actions-OIDC-Token heißt das: **jeder Aussteller genügt**, solange die Repository-Claims passen; die drei geprüften Felder sind selbstbehauptete Zeichenketten, und nichts stellte fest, wer sie behauptet. Die Felder zu löschen hätte den Beleg entfernt, nicht den Mangel.

Dazu war jede Prüfung `if expected != "" && …`, also war `ValidateWorkloadClaims(claims, "", "", "", "dev")` ein Freibrief für jedes Token außer der Produktionskanal-Regel. Die fünf Zeichenketten sind jetzt eine `WorkloadExpectation` mit **fünf Pflichtfeldern** — eine unvollständige Erwartung ist ein Konfigurationsfehler, kein Verzicht.

Der kürzeste Beweis, dass die Audience nie geprüft wurde: der Test-Fixture setzte sie gar nicht. `Issuer` stand drin, `Audience` fehlte, und keine Zusicherung brauchte sie.

**Eine Folge für § 5.7.** Der dortige Vertragstest band den Rollenkatalog verhaltensbasiert an `token.extractRoles` — genau die Funktion, die hier entfällt. Damit gibt es nichts mehr zu binden: eine Zitadel-Rolle berührt nach dieser Umsetzung keine Zeile Entscheidungslogik mehr. Der Test hält jetzt nur noch die Struktur des Katalogs fest und sagt im Kommentar, warum. Wiederhergestellt wird der Konsument mit T-5.7.1.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-5.8.1** | **Die Leader-Wahl ist prozesslokal.** `MemoryLeaderElector` hält den Inhaber in einer Paketvariablen; zwei Prozesse halten sich beide für den Leader, und `identity-sync` soll mehrinstanzlich laufen — doppelte Outbox-Verarbeitung. `OutboxConsumer` hängt zudem am konkreten Typ statt an einem Port. SYNC-02 ist damit nicht erfüllt. | Braucht Postgres-Advisory-Locks oder Valkey (Sprint 3). Das Interface wird gegen die echte Implementierung geschrieben, nicht vorher. | § 5.8, SYNC-02 |
| **T-5.8.2** ✅ | **Die Konsistenzstufe der FGA-Prüfung ist nicht wählbar.** `WithConsistencyMode` versprach `HIGHER_CONSISTENCY` und lieferte immer `MINIMAL_LATENCY`. Für Widerrufe ist das die Frage aus § 4.5: eine Prüfung mit minimaler Latenz darf veraltete Tupel sehen. `OpenFGAChecker.Check` braucht den Parameter. | **Erledigt mit dem Portschnitt (§ 6.2) und geschlossen mit dem Adapter (§ 6.1.1).** `FGACheckRequest.Consistency` ist ein Feld des Ports, die Break-Glass-Nachprüfung verlangt ausdrücklich `HIGHER_CONSISTENCY`, und der OpenFGA-Client reicht es als echtes API-Feld durch — am laufenden Server v1.18.3 nachgemessen. | § 5.8, § 4.5 |
| **T-5.8.3** | **Die Ratenbegrenzung ist nicht permissionsbezogen.** `RateLimitRequest.Permission` war die einzige Spur davon; `Cost` aus dem Katalog wird ausgewertet, die Permission selbst nicht, also teilen sich alle Operationen eines Tokens einen Eimer. | Gehört zur Verdrahtung des `MultiLimiter` mit dem Server (T-4.3.1). | § 5.8, STATE-02 |
| **T-5.8.4** ✅ | **`registry/.../middleware.ClaimsContextKeyVal` ist eine nackte Zeichenkette als Kontextschlüssel.** `identity/middleware` hatte dafür einen eigenen Typ — und genau diese Datei ist hier gelöscht, sodass die saubere Variante verschwindet und die kollisionsanfällige bleibt. | **Erledigt.** `type claimsContextKey struct{}` mit `ClaimsContextKeyVal` als einzigem Wert: ein nicht exportierter, leerer Strukturtyp kann von keinem anderen Paket erzeugt werden, also kann kein Fremdschlüssel denselben Kontexteintrag treffen oder überschreiben. Der Name bleibt, damit die Lesestellen unverändert bleiben. | § 5.8 |
| **T-5.8.5** | **`ValidateWorkloadClaims` hat keinen Produktionsaufrufer** — wie `ValidateCustomerIdPAuth` (T-3.3.1). Nach dieser Umsetzung prüft sie das Richtige, aber niemand ruft sie. | Braucht den Token-Exchange-Endpunkt (`cmd/identity-api`). | § 5.8, IDP-053 |

---

## 6. Effizienz und Performance

### 6.1 `ListObjects` ist N Netzwerkaufrufe

```go
// authz/listobjects.go
for _, id := range candidateIDs { reqs = append(reqs, CheckRequest{…}) }
batchRes, err := c.BatchCheckPermissions(ctx, reqs)
```

`BatchCheckPermissions` startet **eine Goroutine pro Request**, ohne Semaphor, jede mit eigenem `context.WithTimeout`. Eine Seite mit 10 000 Kandidaten erzeugt 10 000 Goroutinen und 10 000 parallele FGA-Aufrufe gegen denselben Client — dessen `failureCount` unsynchronisiert ist (§ 2.2).

Zwei Optimierungen liegen unmittelbar bereit:
- OpenFGA bietet eine native `ListObjects`-API: **ein** Roundtrip statt n.
- Der Nomad-Job setzt bereits `OPENFGA_MAX_CHECKS_PER_BATCH=100` — die Server-Batch-API ist konfiguriert, der Client nutzt sie nicht.

Zudem verwirft ein einzelner Fehler die gesamte Charge (`return nil, firstErr`), inklusive der n−1 gültigen Ergebnisse.

#### 6.1-T Ergebnis und offene Tickets aus der Umsetzung von 6.1

Zwei Angaben des Abschnitts ließen sich nicht bestätigen. **`OPENFGA_MAX_CHECKS_PER_BATCH=100` steht nicht im Baum** — es gibt überhaupt keine Nomad-Jobdateien mehr (T-2.6.1: „Job-Spec entsteht mit dem Binary"). Der Ankerwert für eine Grenze war also nicht verfügbar. Und **die native `ListObjects`-API ist nicht nutzbar**: `OpenFGAChecker` hat keine Produktionsimplementierung, nur das Interface und Test-Mocks. Einen Port für einen Client zu bauen, den es nicht gibt, wäre das siebte tote Konstrukt dieses Reviews gewesen.

Was blieb, ist der Fächer selbst — und der war schlimmer als beschrieben. Der Rot-Nachweis vor der Reparatur: **bei 500 Kandidaten liefen 386 Prüfungen gleichzeitig.** Jede davon startet über den Shadow-Evaluator (§6.2) potenziell eine weitere Goroutine. Ein einziger Listenaufruf konnte damit den Autorisierungsdienst einer ganzen Zelle belegen.

`DefaultBatchConcurrency = 32`, einstellbar über `WithBatchConcurrency`. Die Zahl ist nicht der Punkt — der Punkt ist, dass die Kosten einer Anfrage **konstant** statt linear in ihrer Eingabe sind. Dazu bricht das Verteilen ab, sobald der Kontext fertig ist; erst das macht die Grenze nützlich, weil sonst die Deadline des Aufrufers nichts stoppen kann.

**Ein einzelner Fehler verwirft nichts mehr.** `return nil, firstErr` warf die n−1 entschiedenen Ergebnisse weg — darunter die **degradierten**, die `CheckPermission` bereits sauber liefert und die genau die Information tragen, welche Prüfung unentschieden blieb. Jetzt ist `results` immer vollständig, und beide Rückgaben können gesetzt sein: wer den Fehler ignoriert, bekommt eine Liste, in der jede unentschiedene Prüfung `Allowed: false` ist — sicher; wer ihn prüft, weiß, dass sie unvollständig ist — laut.

**`ListObjects` heißt jetzt `FilterAuthorizedObjects`.** Der Name versprach die FGA-Semantik „welche Objekte darf dieser Nutzer sehen?", während die Funktion verlangt, dass der Aufrufer alle Kandidaten schon kennt — sie filtert eine übergebene Liste. Der Name ist frei für den einen Roundtrip, sobald es einen Client gibt.

**Zwei Lehren aus dem Nachweis selbst**, beide Tests betreffend, beide dieselbe Klasse wie §9:

- Der Abbruch-Test bestand zunächst **aus dem falschen Grund**: nicht die Abbruchprüfung begrenzte die Aufrufe, sondern der Circuit Breaker, der nach fünf Fehlern öffnet. Die Zusicherung hängt jetzt an der Fehleridentität (`context.DeadlineExceeded`), die nur der Verteil-Abbruch erzeugt — eine fehlgeschlagene Prüfung meldet `ErrFGAUnavailable`.
- Der Grenz-Test verglich den Spitzenwert gegen **dieselbe Konstante**, die der Code benutzt: das Anheben der Konstante hob die Messlatte mit. Er setzt die Grenze jetzt explizit über `WithBatchConcurrency(4)`; ein zweiter Test nagelt den Standardwert fest, damit dessen Änderung eine sichtbare Entscheidung ist.

Vier Mutationen, vier rote Tests: Semaphor entfernt, Abbruchzweig ohne Kontextfehler, Fehlermeldung der unentschiedenen Prüfungen entfernt, degradierte Kandidaten als erlaubt gewertet.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-6.1.1** ✅ | **Ein Roundtrip statt n.** | **Erledigt — aber mit BatchCheck, nicht ListObjects.** Siehe 6.1.1-T. | § 6.1, ENF-08 |
| **T-6.1.2** | **`FilterAuthorizedObjects` und `BatchCheckPermissions` haben keinen Produktionsaufrufer.** ENF-08 verlangt die Fähigkeit, kein Endpunkt nutzt sie. | Braucht `cmd/identity-api` (Sprint 3, Punkt 25). | § 6.1 |
| **T-6.1.3** ✅ | **Die Latenz bleibt linear in der Kandidatenzahl.** Die Grenze macht die Ressourcen konstant, nicht die Dauer: 10 000 Kandidaten bei 32 parallel und 500 ms Timeout laufen im schlechtesten Fall in jede Deadline. | **Erledigt — die Obergrenze gehört an die Funktion, nicht an den Endpunkt.** Meine ursprüngliche Begründung war zu weit gefasst: eine Funktion, deren Kosten in ihrer Eingabe unbeschränkt sind, kann übergroße Eingaben selbst ablehnen — dieselbe Fail-fast-Regel wie „eine Quote von null heißt unkonfiguriert, nicht unbegrenzt“. `MaxFilterCandidates = 256`, hergeleitet aus den beiden vorhandenen Zahlen: `ceil(N/32)` Wellen à 500 ms sind bei 256 Kandidaten vier Sekunden im schlechtesten Fall, und ENF-09 gibt der Autorisierung 15 % einer Anfrage. Eine übergroße Liste wird an der Tür abgelehnt statt halb versucht — ein Aufruf, der in die Deadline läuft, kostet dieselbe Arbeit und beantwortet nichts. Paginierung bleibt Sache des Endpunkts. | § 6.1 |

### 6.2 Shadow-Evaluation ist ein Lastverdoppler ohne Bremse

```go
go func() {
    ctx := context.Background()      // kein Timeout, keine Cancellation
    shadowAllowed, err := s.checker.Check(ctx, …)
    …
    s.discrepancyReport = append(s.discrepancyReport, event)   // wächst unbegrenzt
}()
```

Eine Goroutine und ein zusätzlicher FGA-Aufruf **pro Check**, ohne Nebenläufigkeitsgrenze. Bei 1 000 rps und 500 ms Shadow-Latenz (der Testwert) stehen dauerhaft ~500 Goroutinen offen. `discrepancyReport` wird nie beschnitten.

`extractType` nutzt eine handgeschriebene Zerlegung mit `cur += string(val[i])` — O(n²) Allokationen, wo `strings.Cut` eine Zeile wäre.

#### 6.2-T Ergebnis und offene Tickets aus der Umsetzung von 6.2

**Erst der Portschnitt, dann §6.2** — ein Hinweis von außen hat die Reihenfolge korrigiert, und er hatte recht. `OpenFGAChecker.Check(ctx, storeID, user, relation, object, tuples)` konnte drei Dinge nicht ausdrücken, und **jedes davon war ein eigenes Ticket mit derselben Ursache**: welches Modell ausgewertet wird (T-6.2.2), wie frisch gelesen werden muss (T-5.8.2), und den Kontext, den eine Condition liest. Der Port ist jetzt ein `FGACheckRequest` mit `AuthorizationModelID`, `Consistency` und `Context`; `ConsistencyMode` kehrt damit zurück, nachdem §5.8 es löschen musste, weil es keinen Platz hatte. Die Break-Glass-Nachprüfung verlangt seither ausdrücklich `HIGHER_CONSISTENCY`: der Grant wurde Sekunden zuvor geschrieben, und eine Entscheidung von einer nachhängenden Replik verweigert Zugang genau während des Vorfalls, für den er existiert.

Drei Aufrufstellen, sieben Test-Implementierungen — der Schnitt war so klein, wie der Hinweis sagte.

**Damit ist §6.2 überhaupt erst sinnvoll.** `ShadowModelID` wurde viermal gelesen — Freigabebedingung, zwei Logzeilen, Ereignisstempel — und **nie an eine Auswertung gereicht**. Der Schatten wiederholte die Primärprüfung gegen dasselbe Modell; jede gemeldete „Divergenz" war ein Rennen zwischen zwei Lesevorgängen. Ein begrenzter, befristeter, gedeckelter Sampler, der ein Modell mit sich selbst vergleicht, wäre gut gebautes Nichts gewesen.

Die Maschinerie-Defekte, die unabhängig davon real waren:

- **`context.Background()` ist schlimmer als „keine Bremse".** Der Primärpfad hat 500 ms, der Schatten hatte **gar keine Frist** — ein hängendes Backend leakte die Goroutine für die Lebensdauer des Prozesses. Nicht „500 offene bei 1000 rps", sondern monotones Wachstum. Jetzt eine **eigene** Frist, ausdrücklich nicht der Kontext des Aufrufers: die Anfrage ist normalerweise vor dem Schatten fertig, ihn zu erben hieße, nie eine Probe zu bekommen.
- **Die Grenze aus §6.1 wurde auf dem Schattenpfad zurückgegeben.** 32 primäre Prüfungen durften 32 Sampler starten. Jetzt 8 Slots, **nicht blockierend**: ist alles belegt, wird verworfen. Verwerfen ist hier richtig — eine Stichprobe zum Vergleich darf verloren gehen, Latenz auf dem Entscheidungspfad nicht.
- **Das Verwerfen wird gezählt** (`DroppedEvaluations()` und `status="dropped"`). Ein Sampler, der still aufhört zu sampeln, meldet „keine Abweichungen" für ein Modell, das er nicht mehr ansieht.
- **`discrepancyReport` hat einen Deckel** (256, neueste gewinnen). Die wahre Gesamtzahl bleibt in `GetDiscrepancyCount()` — der Deckel kostet Beispiele, nie Zählungen.
- **`extractType` gab den Rohwert als Prometheus-Label zurück**, wenn kein Doppelpunkt vorkam: der eigene `"unknown"`-Zweig war unerreichbar, weil `splitColon` für jede nicht-leere Eingabe mindestens ein Element lieferte. Ein missgebildetes Subjekt eröffnete damit eine neue Zeitreihe. Jetzt `strings.Cut` in einer Zeile, und ohne Typ heißt es `"unknown"`.

**Sieben Mutationen, sieben rote Tests.** Eine überlebte zunächst: blockierend statt verwerfend ändert den Spitzenwert nicht — es ändert, ob der *Entscheidungspfad wartet*. Der vorhandene `AsyncZeroLatency`-Test kann das nicht sehen, weil er eine einzelne Prüfung in leere Slots feuert. Der fehlende Test ist ergänzt; danach war auch diese Mutation rot.

`prometheus/testutil` ist jetzt nutzbar — `go mod tidy` hat `godebug` als indirekte Testabhängigkeit ergänzt und die von den Aikido-Aktualisierungen überholten Alteinträge aus `go.sum` geräumt. Alle acht angehobenen Versionen (pgx 5.10.0, x/crypto 0.54.0, x/mod 0.37.0, x/net 0.56.0, x/sync 0.22.0, x/sys 0.47.0, x/term 0.45.0, x/text 0.40.0) stehen unverändert.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-6.2.1** | **Die Schattenauswertung hat keinen Aufrufer im zusammengesetzten Dienst.** `SetShadowEvaluator` wird nur in Tests gerufen. Der Port trägt jetzt alles, was AUTHZ-10 braucht; es fehlt die Verdrahtung. | Braucht `cmd/identity-api` (Sprint 3, Punkt 25) — der Engpass, an dem rund 28 Tickets hängen. | § 6.2, AUTHZ-10 |
| **T-6.2.3** | **Prometheus-Labelkardinalität aus aufrufergesteuerten Werten.** `permission` kommt ungeprüft aus `CheckRequest`; jede erfundene Berechtigung eröffnet eine Zeitreihe. `extractType` ist abgesichert, die Berechtigung nicht. | Gehört zu T-5.6.4, wo die Berechtigungs-ID ohnehin auf eine Modellrelation abgebildet werden muss. | § 6.2, § 5.6 |
| **T-6.2.4** ✅ | **Kein Adapter liest die neuen Portfelder.** `AuthorizationModelID`, `Consistency` und `Context` werden von den Aufrufstellen mit echten Werten gefüllt und in Tests gelesen — eine echte OpenFGA-Implementierung, die sie an die API weitergibt, gibt es aber nicht. | **Erledigt mit T-6.1.1.** `identity/authz/openfga` schreibt alle drei Felder in den Request-Body — `authorization_model_id`, `consistency`, `contextual_tuples` und `context` —, und der Vertragstest prüft das gegen den laufenden Server, nicht gegen ein Double. Offen bleibt allein die Verdrahtung (T-6.1.5). | § 6.2, T-5.8.2 |

#### 6.1.1-T Ergebnis: der Adapter, und was die Sondierung ergab

**Das Ticket benannte die falsche API.** Es stehen zwei Fragen dahinter: „filtere diese Seite" (50 Pakete aus einer SQL-Abfrage mit Suche, Sortierung, Paginierung) und „welche Objekte darf der Nutzer sehen". `FilterAuthorizedObjects` beantwortet die erste, `ListObjects` die zweite. Sie sind nicht austauschbar: `ListObjects` hat eine serverseitige Ergebnisobergrenze und eine Deadline, kennt keinen Cursor und lässt sich nicht mit SQL-Filtern kombinieren. Was die n Roundtrips für **unseren** Fall beseitigt, ist **BatchCheck**.

Beleg dafür stand im Abschnitt selbst: das zitierte `OPENFGA_MAX_CHECKS_PER_BATCH=100` ist BatchChecks serverseitiges Limit. Der ursprüngliche Autor hatte BatchCheck konfiguriert und die falsche API in den Befund geschrieben.

**Gemessen statt vermutet.** Ich habe einen einzelnen OpenFGA-Container gestartet und die API befragt:

| | |
|---|---|
| aktuelle Version | **v1.18.3** — Compose und Nomad-Job pinnten **v1.5.3**, 13 Minor zurück |
| BatchCheck auf v1.5.3 | **HTTP 404** |
| BatchCheck auf v1.18.3 | ✅ Antwort ist eine **Map** über `correlation_id`, keine Liste |
| Serverlimit | **50** je Batch; 60 werden mit `validation_error` abgelehnt, nicht gekürzt |
| `authorization_model_id`, `contextual_tuples`, `consistency` | **alle drei sind echte API-Felder** — der Portschnitt aus §6.2 trifft die API exakt |
| unser modulares Modell | `is_valid:true`, lädt **auch** auf v1.5.3 — das Modell war nie der Blocker |

**Der Adapter** (`identity/authz/openfga`) ist handgeschrieben, ohne SDK, im Muster von `celldir/client.go`. Das Argument für das SDK war, die Wire-Formate nicht zu kennen — und die kenne ich jetzt gemessen. Er reicht die drei Portfelder durch, chunkt bei 50, bildet Fehler auf die vorhandenen Sentinels ab und verlangt die Authentifizierungsart als **ausdrückliche Wahl**: ein leeres Token darf nicht „braucht keine Authentifizierung" heißen, denn genau so steht eine Autorisierungs-Engine ungeschützt im Netz.

**Der Umbau, der den Batch erst möglich macht.** `CheckPermission` machte acht Schritte, von denen der FGA-Aufruf einer ist. Batchen ohne Umbau hätte eine zweite Stelle geschaffen, an der „ist dieser Principal widerrufen" entschieden wird. Stattdessen sind es jetzt zwei Phasen — `prepare` und `finish` —, die Einzelprüfung und Batch **gemeinsam** benutzen und sich nur darin unterscheiden, wie sie OpenFGA erreichen. Eine Regel, zwei Abläufe.

Für eine Seite mit 256 Kandidaten: **6 Roundtrips statt 256.**

**Drei Befunde nebenbei:**

- **Der Nomad-Job setzte eine Variable, die der Server nicht liest.** `OPENFGA_MAX_CHECKS_PER_BATCH=100` heißt in Wahrheit `..._BATCH_CHECK`; empirisch geprüft: mit dem falschen Namen bleibt das Limit bei 50, mit dem richtigen greift die 100. Der Eintrag ist entfernt statt korrigiert — der Client chunkt beim Server-**Standard**, und ein Client, der ein angehobenes Limit annimmt, verliert gegen einen Standardserver jeden Check einer Charge. Eine Zahl, an einer Stelle.
- **Ein abgebrochener Resolver meldete „Store nicht gefunden"** und verlor die Ursache (`%v` statt `%w`). Ein abgebrochener Request muss als solcher erkennbar bleiben.
- **Ich lag mit „es gibt keine Nomad-Jobs mehr im Baum" falsch** — ich hatte nur `platform/` durchsucht. Die Jobs liegen in `identity/deploy/nomad/` und `registry/deploy/nomad/`, und Nomad ist der Orchestrator dieser Plattform: Ansible-Rolle, Terraform-Worker-Modul, Vault-PKI-Policies, acht Job-Spezifikationen, ein Autoscaler an seiner API. Es wird gebraucht und bleibt.

**Der Vertragstest ist der erste in diesem Review, der gegen das echte Fremdsystem prüft** statt gegen ein Double, das ich aus derselben Annahme geschrieben habe, die es belegen soll. `just test-openfga-contract` startet nur OpenFGA, nichts sonst. Fünf Mutationen, fünf rote Tests — die Chunking-Grenze fällt **nur** dort auf, nicht in den Unit-Tests.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-6.1.4** | **`ListObjects` ist ungebaut.** Der Server kann es (gemessen: liefert `{"objects":["tenant:acme"]}`, also **voll qualifiziert**, nicht die nackte ID). Es beantwortet aber die andere Frage, und kein Aufrufer stellt sie. | Erst mit einem Endpunkt, der „alle Objekte dieses Typs" braucht — sonst eine Methode, die niemand ruft. | § 6.1 |
| **T-6.1.5** | **Der Adapter ist nirgends verdrahtet.** Er ist gegen den echten Server geprüft, aber `NewFGAClient` bekommt ihn von keinem Kompositionspunkt gereicht. | Der Kompositionspunkt ist `cmd/identity-api` (Sprint 3, Punkt 25). | § 6.1 |
| **T-6.1.6** | **Die Versionsanhebung ist erst in dev und im Job-Default vollzogen.** Ein laufendes Staging oder Produktion auf v1.5.3 beantwortet `batch-check` mit 404, und der Client fällt dann in den degradierten Zweig — laut, aber vollständig. | Ausrollen ist ein Betriebsschritt. | § 6.1, § 10 |

### 6.3 Weitere Hotspots

| Ort | Problem |
|---|---|
| `session.IsFamilyRevoked` | Implementiert eine **Lesefrage als Schreibtransaktion**: `RotateToken(fam, "dummy-non-matching-token")` mit `BEGIN` + `SELECT … FOR UPDATE`. Liefert zudem `false` für unbekannte Familien (unbekannt ≠ nicht widerrufen). |
| `session.Manager` | Alle Store-Aufrufe mit `context.Background()` — Deadline, Cancellation und Tracing des Aufrufers gehen verloren. |
| `jwks.recordFetchError` | Ruft den globalen `metrics.GetLatencyBudgetMonitor()` **unter gehaltenem Write-Lock** des Key-Caches auf. Lock-Ordering-Risiko gegen die Prometheus-Registry. |
| `sync.OutboxConsumer` | Retries sind seriell **innerhalb** von `ProcessBatch` mit blockierendem `time.Sleep`, das `ctx` ignoriert. Bei 50 fehlschlagenden Events und Default-Backoff blockiert der Leader ~35 s. |
| `zitadel.Provisioner.Provision` | Ruft `DetectDrift` (listet alle Projekte + Rollen) und listet danach alles erneut — doppelte API-Last. |
| `authz/audit.go` | `slog.Info` bei **jeder** erlaubten Entscheidung. Bei 1 000 rps sind das 1 000 strukturierte Zeilen/s pro Instanz nach Loki. Allow-Entscheidungen gehören in einen Counter, nicht ins Log. |

### 6.4 Dreizehn unbegrenzte In-Memory-Strukturen auf Request-Pfaden

`sync.EventIngestor.seenEvents` · `sync.MemoryEventDeduplicator.events` (abgelaufene Einträge werden erkannt, aber nie gelöscht) · `sync.OutboundWebhookDispatcher.dlqs` · `sync.OutboxConsumer.dlqEvents` · `authz.DenialSpikeDetector.denials` · `authz.DecisionCache.cache` · `authz.ShadowEvaluator.discrepancyReport` · `celldir.Cache.items` · `celldir.OnboardingSagaEngine.persistedMap` · `celldir.CellMigrationEngine.importedStores` · `bff.sessions` · `device.MemoryDeviceFlowStore` (beide Maps) · `pki.InMemoryDeviceKillSwitchRegistry.records` · `approval.MemoryApprovalStore.approvals` · `sync.JITProvisioner.seenFederatedUsers`.

Keine davon hat Eviction oder Größenbegrenzung. Mehrere sind gleichzeitig die **einzige** Implementierung ihres Interfaces.

#### 6.4-T Ergebnis: Wachstumsgrenzen, und sieben Tickets aus vier Abschnitten

Vorab eine Korrektur an der Überschrift: die Liste zählt **fünfzehn** Strukturen, nicht dreizehn.

**Es sind zwei Arten von unbegrenzter Map, und sie brauchen entgegengesetzte Antworten.** Die erste läuft ab: jeder Eintrag hat eine Gültigkeit, der Code erkennt sie beim Lesen sogar — und lässt den Eintrag dann liegen. Die zweite läuft nicht ab: ein DLQ-Eintrag, ein Saga-Zustand, ein Kill-Switch, eine Widerrufsnotiz. Für die erste ist Verfall die Antwort; für die zweite wäre er Datenverlust, und im Sicherheitsfall ein Fail-Open. Die Liste in § 6.4 nennt beide in einem Atemzug, und genau das macht „alle fünfzehn begrenzen" zur falschen Aufgabe.

**Die Verfallspolitik steht jetzt einmal und gilt an vier Stellen gleich.** Ein Schreibzugriff kehrt aus, sobald die Map eine Schwelle erreicht hat; danach ist die Schwelle das Doppelte der Überlebenden, mindestens 64. Über die Schreibzugriffe, die das Wachstum verursacht haben, kostet das konstant Zeit pro Schreibzugriff, und die Map bleibt bei etwa dem Doppelten ihrer lebenden Menge statt beim Schlüsselraum — und der ist hier jeder Token-Hash, jede Tenant-ID, jedes Device-Code, das die Flotte je gezeigt hat. Lesezugriffe räumen zusätzlich lazy auf, sodass ein wieder angefasster Schlüssel nie liegen bleibt.

Kein Hintergrund-Goroutine mit Ticker: das wäre ein Lebenszyklus, den jemand starten und beenden muss, für Speicher, der ohnehin nur der Platzhalter des persistenten ist. Eine amortisierte Kehrung braucht niemanden, der sie abschaltet.

Begrenzt sind damit `authz.DecisionCache.cache`, `ratelimit.MemoryBackend` (beide Maps — nicht in der Liste, aber dieselbe Klasse), `deviceflow.MemoryStore` (beide Maps) und, schon aus § 6.2, `authz.ShadowEvaluator.discrepancyReport`. **Drei der fünfzehn**, plus zwei, die die Liste nicht kennt.

**Der Widerruf-Cache ist die Ausnahme, und die Ausnahme ist der eigentliche Fund.** `revocation.RevocationCache` wächst über genau die Einträge, die es über Pub/Sub gelernt und nie in einem Store-Snapshot wiedergesehen hat. Sie verfallen zu lassen wäre naheliegend und falsch: einen Widerruf zu vergessen heißt, Zugang zurückzugeben. Die Menge wird deshalb nicht getrimmt, sondern **eskaliert** — mit Anzahl und Alter, ab fünf Minuten als `SECURITY ALARM`. Ein Widerruf, den der Store nie bestätigt, bedeutet, dass Publisher und Store sich uneinig sind, typischerweise weil der Schreiber nach dem Publizieren nicht committen konnte. Das ist ein Vorfall und keine Speicherfrage. Die Sicherheitseigenschaft selbst — der unbestätigte Eintrag überlebt den Resync — steht seit § 4.5 in `TestRevocationCache_ResyncKeepsRevocationsThatArrivedDuringTheQuery`; neu ist nur, dass man ihn jetzt sieht.

**Drei Tickets waren bereits erledigt** und sind nur nachgetragen: T-6.2.4 und T-5.8.2 mit dem Adapter aus § 6.1.1, T-3.6.4 mit dem Wegfall von `scim/mapping.go` und `TupleKey.Validate()`.

**Vier weitere aus vier Abschnitten**, alle in dieselbe Richtung: T-4.1.4 (`identity/dbtx`), T-5.5.1 (SAN-Auswahl), T-5.2.3 (mTLS-Rand an der Taxonomie), T-5.8.4 (Kontextschlüssel als Typ). Bei T-4.1.4 löst sich die im Ticket beschriebene Schwierigkeit auf, sobald man die Methode nach dem Bedarf des Aufrufers schneidet statt nach dem Bestand des Anbieters: `audit` benutzte vom Rückgabewert `(*sync.OutboxEvent, error)` nur den Fehler. `StageEvent` liefert genau das, `*sync.OutboxWriter` erfüllt das Ein-Methoden-Interface strukturell, und keiner der acht Konstruktionspunkte braucht einen Adapter.

**Ein Fund, der nicht im Ticket stand.** Die alte SAN-Auswahl suchte, bis sie fand, was sie wollte: erst unter den SAN-URIs nach `toob:device:`, und wenn dort nichts stand, im CommonName. Ein Zertifikat, dessen SAN-URI eine Workload nennt und dessen CommonName ein Gerät behauptet, wurde deshalb **als Gerät rotiert** — die Mutation protokolliert es wörtlich: `OPERATIONAL DEVICE CERTIFICATE ROTATED SUCCESSFULLY … san_uri=toob:workload:tenant:cell-01:org_acme:wl_7`. Welches Feld den Träger benennt, ist jetzt entschieden: die SAN-URI, der CommonName nur, wenn keine da ist.

**Der Nachweis.** Jede neue Grenze wurde einmal in beide Richtungen gebrochen — zu wenig kehren und zu viel kehren sind beide Defekte:

| Test | Mutation | |
|---|---|---|
| `DecisionCache` / Miss | `Get` löscht den abgelaufenen Eintrag nicht mehr | rot |
| `DecisionCache` / lebende Einträge | `sweepExpired` löscht bedingungslos | rot |
| `MemoryBackend` / Fenster | `Allow` kehrt nicht mehr aus | rot |
| `MemoryBackend` / Login-Zähler | `sweepFailures` löscht bedingungslos | rot |
| `MemoryStore` / Device Flow | die Kehrung vergisst `byUserCode` | rot |
| Rotation / SAN | die Prüfung des Aktortyps entfällt | rot |

Die Tests der Grenzen liegen bewusst **im Paket**: die geprüfte Eigenschaft ist die Größe einer nicht exportierten Map, und ein Accessor dafür existierte nur für den Test — und lüde einen Aufrufer ein, sich auf eine Zahl zu verlassen, die absichtlich amortisiert ist.

Nebenbei hat der Vertragstest aus § 5.5 **meinen eigenen neuen Test** gefangen: er baute seine tausend Principal-URNs mit `fmt.Sprintf`, was `TestContract_URNsAreFormattedNeverPrinted` genau verbietet — die Regel gilt für Testcode mit, weil sonst die Formatierer im Test umgangen und im Produktivcode verlangt würden. Der Test benutzt jetzt `FormatDeviceURN`. Umgekehrt war die Begründung des Vertragstests veraltet: sie nannte `strings.HasPrefix` als die richtige Art, eine SAN auszuwählen. Das war sie bis T-5.5.1.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-6.4.1** ✅ | **Zwei weitere Strukturen der ersten Art sind noch offen:** `celldir.Cache.items` und `authz.DenialSpikeDetector.denials`. Beide haben eine Gültigkeit bzw. ein Zeitfenster und nehmen dieselbe Kehrung. | **Erledigt — und „derselbe Handgriff" war für `celldir` falsch.** Siehe den Nachtrag unten: dort ist die TTL die Frischegrenze des schnellen Pfads und nicht die Lebensdauer, und begrenzt werden musste die Veraltung, nicht die Größe. Beim Detektor waren es zwei Lecks statt einem. | § 6.4 |
| **T-6.4.2** | **Zehn Strukturen der zweiten Art bleiben unbegrenzt** (`sync.EventIngestor.seenEvents`, `MemoryEventDeduplicator.events`, `JITProvisioner.seenFederatedUsers`, beide DLQs, `celldir.OnboardingSagaEngine.persistedMap`, `CellMigrationEngine.importedStores`, `bff.sessions`, `pki.InMemoryDeviceKillSwitchRegistry.records`, `approval.MemoryApprovalStore.approvals`). Bei ihnen ist Vergessen eine Verhaltensänderung: ein vergessener Dedup-Schlüssel verarbeitet ein Ereignis doppelt, ein vergessener Kill-Switch gibt ein Gerät frei. | Die Antwort ist nicht Eviction, sondern der persistente Store — genau die Sprint-3-Arbeit, für die diese Maps Platzhalter sind. Eine Grenze einzuziehen, bevor es einen Speicher gibt, würde den Verlust nur früher eintreten lassen. | § 6.4, Sprint 3 |

#### Nachtrag zu 6.4: T-6.4.1, und die Politik bekommt einen Ort

**Das Ticket hat die beiden Strukturen in einen Topf geworfen, und für `celldir` war das falsch.** „Beide haben eine Gültigkeit und nehmen dieselbe Kehrung" — die erste Hälfte stimmt, die zweite nicht:

- Die TTL des Zell-Caches ist die **Frischegrenze des schnellen Pfads** (`resolver.go` liest zuerst `Get(key, false)`), nicht die Lebensdauer des Eintrags. Danach hat dieselbe Kopie eine zweite, gewollte Aufgabe: sie ist der Fallback, den der Resolver nach einem gescheiterten Fetch liest (`Get(key, true)`). Nach TTL zu kehren hätte genau den Fallback gelöscht — dieselbe Form wie beim Widerruf-Cache, wo die naheliegende Antwort die falsche ist.
- **Die Größe war ohnehin nie das Risiko.** `Set` schreibt nur nach einem erfolgreichen *und validierten* Fetch; es gibt kein Negative-Caching. Der Schlüsselraum ist damit „reale Tenants × 2" und nicht angreifergesteuert. Unbegrenzt ist nicht die Map, sondern die **Veraltung**.

**Was dort wirklich zu begrenzen war: die Zellmigration.** `CellMigrationEngine` räumt den umgezogenen Tenant aus dem Cache — im Prozess, der migriert hat. Jede andere Instanz behält die alten Koordinaten; innerhalb der TTL ist das eine Aktualisierung entfernt, während eines Directory-Ausfalls dauert es so lange wie der Ausfall. Der Tenant würde weiter in die Zelle geroutet, die er verlassen hat. `CacheConfig.MaxStaleAge` (24 h) ist die Antwort: lange genug, dass ein gewöhnlicher Ausfall die Flotte nicht lahmlegt, kurz genug, dass eine Migration nicht still von einem Ausfall rückgängig gemacht wird.

Die beiden Zeiten sind **eine** Einstellung, weil keine ohne die andere etwas bedeutet — `CacheConfig` mit `Validate()`, das `MaxStaleAge > TTL` erzwingt. Ein ungültiger Wert paniert beim Konstruieren; die vorherige stille Ersetzung einer fehlenden TTL durch fünfzehn Minuten hat eine Richtlinie im Konstruktor versteckt (O10). Entfernt wird ein Eintrag an zwei Stellen: beim Lesen jenseits `MaxStaleAge` und amortisiert beim Schreiben. Nur beim Schreiben zu kehren würde die Antwort davon abhängig machen, wie voll die Map gerade ist.

**Beim Detektor waren es zwei Lecks, nicht eines.** Die Schlüssel verschwanden nie — und wer abgelehnt wird, entscheidet der Absender der Anfragen, nicht die Größe der Kundenbasis. Das zweite stand in derselben Funktion: die Slice hinter *einem* Schlüssel hielt **jede** Ablehnung im Fenster, also reichte ein einziges Subjekt unter Dauerbeschuss. Sie ist jetzt auf `threshold` Einträge gekappt, und die Kappung ändert **keine** Antwort: der Alarm feuert, wenn mindestens `threshold` Ablehnungen im Fenster liegen, und wenn mehr darin liegen, dann auch die neuesten `threshold`. Genau das prüft `TestDenialSpikeDetector_TheCapKeepsTheNewestDenials` — der einzige Test, der die beiden Kappungsrichtungen überhaupt unterscheiden kann.

**Die Politik hat jetzt einen Ort.** `shared/x/sweep` hält die Schwellenarithmetik (`Due`/`Reset`, `MinSize = 64`) — vorher stand dieselbe Rechnung mit vier verschieden formulierten Kommentaren in vier Paketen, und ein Leser musste raten, ob die vier 64er dieselbe 64 sind. Der Nullwert ist benutzbar, also verlieren drei Konstruktoren ihre Initialisierungszeile. Bewusst **nicht** mit umgezogen ist die Schleife: was „abgelaufen" heißt, ist je Map wirklich verschieden (zurückgesetztes Fenster, absolutes Ablaufdatum, Alter seit dem letzten Fehlversuch, Alter seit der letzten Bestätigung), und eine Map löscht in einem Durchgang aus zwei Indizes. Ein generischer Sweep-Lauf hätte vier von fünf Aufrufern bedient und den fünften seine eigene Schleife schreiben lassen — der Zustand, den das Paket beendet.

Nebenbei sind zwei `sync.RWMutex` zu `sync.Mutex` geworden: in beiden Caches schreibt inzwischen jeder Pfad, weil das Lesen den überalterten Eintrag entfernt. Ein RWMutex, der nur je schreibend genommen wird, behauptet ein Zugriffsmuster, das es nicht gibt.

**Gesucht, aber nicht gehoben:** 49 Konstruktoren enthalten `if clk == nil { clk = clock.NewSystemClock() }`. Das ist die größte verbliebene Wiederholung im Baum — und genau deshalb wäre ein `clock.OrSystem()`-Helfer falsch: er würde die Toleranz zementieren, die O10 abschaffen will. Der richtige Griff ist, sie zu entfernen, nicht sie bequemer zu machen.

| Test | Mutation | |
|---|---|---|
| Detektor / vergessene Subjekte | `Record` kehrt nicht mehr aus | rot |
| Detektor / aktives Subjekt | die Kehrung löscht bedingungslos | rot |
| Detektor / Kappungsrichtung | die Kappung behält die ältesten statt der neuesten | rot |
| Zell-Cache / Lesen | `Get` entfernt den überalterten Eintrag nicht | rot |
| Zell-Cache / Schreiben | `Set` kehrt nicht mehr aus | rot |
| Zell-Cache / Fallback | die Kehrung nimmt die TTL statt `MaxStaleAge` | rot |

---

## 7. Nebenläufigkeit

| Ort | Race |
|---|---|
| `authz.FGAClient.circuitOpen` / `failureCount` | Unsynchronisiert, während `BatchCheckPermissions` N Goroutinen startet. |
| `celldir/upgrade.go` | `resolver.Cache().clock.Now()` — direkter Lesezugriff auf ein per `Cache.mu` geschütztes Feld (`SetClock` schreibt es unter Lock). |
| `celldir.OnboardingSagaEngine.Compensate` | Iteriert `saga.CompletedSteps` **ohne** gehaltenen Lock, während `ExecuteOrResume` dieselbe Slice unter Lock anhängt. `GetSaga` gibt denselben Pointer heraus. |
| `sync.OutboundWebhookDispatcher` | `DispatchToRecipient` liest `recipient.Secret` außerhalb des Locks; `RotateRecipientSecret` schreibt dasselbe Feld unter Lock. |
| `revocation.MemoryPubSub` | `handlers` wird in `Subscribe` ohne Mutex angehängt und in `Publish` ohne Mutex gelesen. |
| `session.Manager.SetClock` | Schreibt `m.clk` und `mem.clk` ohne Mutex; `MemoryStore` liest `clk` unter seinem eigenen Lock. |
| `test/tokens.getDevKeys` | `err` wird außerhalb von `initOnce.Do` deklariert. Beim **zweiten** Aufruf ist `err` nil, auch wenn die Generierung beim ersten fehlschlug ⇒ nil-Key wird zurückgegeben ⇒ nil-Dereferenz in `SignedString`. |
| `sync.MemoryLeaderElector` | Paketglobale `globalLeaderLock` / `globalLeaderHolder`: alle Instanzen im Prozess teilen einen Leader-Zustand, der nie automatisch freigegeben wird. Tests beeinflussen sich gegenseitig. |

#### 7-T Ergebnis und offene Tickets aus der Umsetzung von 7

Zwei Einträge waren erledigt: `authz.FGAClient.circuitOpen`/`failureCount` gibt es nicht mehr (heute `CircuitBreaker` mit eigenem Mutex), und `revocation.MemoryPubSub` kopiert die Handler unter Lock.

**Das Vorgehen: erst der rote Test.** Der Race-Detector hatte über `identity/...` nichts gemeldet — er sieht nur ausgeführte Pfade, und kein Test ließ die beiden Seiten dieser Races gleichzeitig laufen. Für jeden Befund wurde deshalb zuerst ein nebenläufiger Test geschrieben und **nachgewiesen, dass er gegen den damaligen Code fehlschlägt**: `WARNING: DATA RACE` beim Webhook, `DATA RACE` an `saga.go:148` und `:155`, und beide Leader-Tests rot. Erst danach die Reparatur.

**Drei der fünf offenen Befunde waren derselbe Fehler: der Mutex schützt den Behälter, nicht den Wert.**

```go
d.mu.RLock()
recipient, exists := d.recipients[recipientID]   // ein Zeiger
d.mu.RUnlock()
sigHeader := ComputeSignature(event.Payload, recipient.Secret, nowSec)   // ungeschützt
```

Der Lock wird gehalten, während der *Zeiger* geholt wird, und losgelassen, bevor das *Ziel* gelesen wird. Dieselbe Konstruktion in `OnboardingSagaEngine`: `GetSaga` gab den Zeiger aus `persistedMap` heraus, während `ExecuteOrResume` unter demselben Mutex an `CompletedSteps` anhängte und `Status` zuwies. Und `upgrade.go:68` las `resolver.Cache().clock` direkt — ein Feld, das `SetClock` unter `c.mu` schrieb. Alle drei sind jetzt Kopien bzw. gar keine Mutation mehr: `Cache` bekommt die Uhr im Konstruktor (FND-03), `SetClock` entfällt.

**Ein Nebenbefund, den der neue Test sofort fing:** `NewCache(ttl, clk)` ignorierte den frisch hinzugefügten Parameter und setzte weiter `clock.NewSystemClock()`. Genau dafür war der Test geschrieben — ein Konstruktor-Parameter, der nicht benutzt wird, ist Dekoration.

**`getDevKeys` war kein Race, sondern eine falsch verwendete `sync.Once`.** Das `err` stand außerhalb von `Do`, also sah nur der erste Aufrufer es. Ein zweiter fand ein frisches nil, übersprang die Prüfung und bekam `(nil, nil, nil)` — `SignedString` dereferenzierte dann einen Nil-Zeiger. Ein einziger Fehlschlag beim ersten Aufruf hätte jeden folgenden in einen Absturz verwandelt. Der Ausgang des einen Versuchs lebt jetzt neben den Schlüsseln.

**`session.Manager.SetClock`** war zugleich tot und falsch: kein Aufrufer, und es schrieb `MemoryStore.clk`, ohne dessen Lock zu halten, während `MemoryStore` dasselbe Feld unter seinem Lock liest. Gelöscht.

**`MemoryLeaderElector`** hält den Inhaber jetzt in der Instanz. Geteilt wird durch Übergabe desselben Electors — was der Consumer-Test und `cmd/identity-sync` ohnehin tun. `IsLeader()` und `ReleaseLeader()` sind entfallen: beide hatten keinen Aufrufer, beide waren Reste des in §5.8 gelöschten Interfaces, und `IsLeader()` war bei geteiltem Elector bedeutungslos, weil der zweite `AcquireLeader` die Sicht des ersten überschrieb.

**T-7.2 ist entschieden statt vertagt: überlappende Geheimnisse.** Die Frage war, welches Geheimnis gilt, wenn während einer Zustellung rotiert wird. Weder „altes bis zum Ende" noch „Abbruch und Neuversand" ist die richtige Antwort — ein harter Schnitt bricht drei Dinge in dem Moment, in dem ein Empfänger es sich am wenigsten leisten kann: die laufenden Requests, den Retry-Rückstau, und jede Zustellung, bis der Empfänger das neue Geheimnis ausgerollt hat. Ein `WebhookRecipient` trägt deshalb `PreviousSecret` mit Ablauf (`SecretRotationOverlap`, 24 h), eine Zustellung signiert unter **jedem** noch gültigen Geheimnis, und der Empfänger akzeptiert eine beliebige der mitgelieferten Signaturen. Das ist das Verfahren von Stripe und GitHub — und der Grund, warum das Headerformat `t=…,v1=…,v1=…` mehr als einen Eintrag zulässt.

Dabei fiel auf, dass die Verifikation zwei Fehler hatte: sie behielt nur den **letzten** `v1`-Eintrag, und sie verglich den **gesamten Header** gegen einen selbst gebauten statt die Signatur gegen die Signatur. Beides hätte die Überlappung unmöglich gemacht. Der Vergleich läuft jetzt je Signatur und weiter konstantzeitig. Dazu lehnt die Rotation ein leeres Geheimnis ab — sie hätte sonst jede Zustellung mit einem leeren Schlüssel signiert, was `VerifySignature` ablehnt: ein stilles Ende der Webhook-Zustellung.

**Verifikation:** `-race` mit `-count=4` über `identity/...`, keine Meldung.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-7.1** | **Ein geteilter `MemoryLeaderElector` gibt die Führung nie zurück.** `AcquireLeader` setzt den Inhaber, und nichts löscht ihn — ein Leader, der stirbt, blockiert die Rolle dauerhaft. Prozesslokal folgenlos, für eine echte Wahl ist Ablauf/Heartbeat konstituierend. | Gehört zur echten Implementierung: Postgres-Advisory-Locks oder Valkey (T-5.8.1). | § 7, SYNC-02 |
| **T-7.3** | **Die Überlappungsdauer ist eine Konstante, kein Vertrag.** 24 Stunden sind der Branchenwert, aber ein Empfänger erfährt weder, dass eine Rotation läuft, noch wann das alte Geheimnis abläuft. Ein `X-Toob-Signature-Rotation`-Hinweis oder ein Feld in der Empfängerverwaltung würde die Migration beobachtbar machen. | Braucht die Empfänger-API, die es noch nicht gibt. | § 7, SYNC-05 |

---

## 8. Struktur, Abhängigkeiten, Namensgebung

### 8.1 Der Abhängigkeitsgraph zeigt in die falsche Richtung

```
audit    ──► sync    (für sync.Tx, sync.OutboxWriter)
sync     ──► authz   (für authz.TupleKey)
scim     ──► authz
celldir  ──► authz
token    ──► ratelimit          (exchange.go)
middleware ──► pki, enforce, token
internal/orgs ──► celldir
jwks     ──► shared/metrics     (globaler Singleton)
```

`audit → sync → authz` bedeutet: das manipulationsevidente Ledger hängt transitiv an der Autorisierungs-Engine. Ursache sind jeweils **Typ-Imports** (`sync.Tx`, `authz.TupleKey`), die in ein neutrales unteres Paket gehören (`identity/dbtx`, `identity/tuple`).

`.golangci.yml` hat inzwischen eine `identity_boundary`-Regel gegen `registry`/`update` — gut. Es fehlt jede Regel **innerhalb** von `identity`, und es fehlt die Absicherung, dass `identity/<public>` nicht `identity/internal/...` importiert (Gos Internal-Regel greift innerhalb desselben Modul-Teilbaums nicht).

Aktiviert ist ausschließlich `depguard`. Kein `gofmt`, `govet`, `errcheck`, `ineffassign`, `unused`, `staticcheck`, `bodyclose`, `noctx`, `gosec`. Allein `unused` + `errcheck` + `gofmt` würden einen erheblichen Teil der Befunde aus § 5.8 und § 3.5 mechanisch aufdecken.

### 8.2 Formatierung

Nicht gofmt-konform (Feld-Alignment, Leerzeilen): `authz/cache.go`, `authz/client.go`, `authz/breakglass.go`, `celldir/cache.go`, `celldir/bootstrap.go`, `dpop/replay.go`, `sync/writer.go`, `sync/ingest.go`, `scim/scim.go`, `scim/provider_test.go`, `internal/orgs/orgs_test.go`, `internal/zitadel/provisioner.go`, `audit/ledger.go` (drei Leerzeilen), `pki/rotation.go`, `ratelimit` (mehrere). Ein `gofmt -l`-Gate in CI kostet nichts.

### 8.3 Benennung

| Problem | |
|---|---|
| `identity/sync` verdeckt das stdlib-Paket | `jit_test.go` muss bereits `import stdSync "sync"` schreiben |
| `identity/device` = OAuth Device Flow, `identity/pki` = physische Geräte | Zwei Bedeutungen von „Device" nebeneinander |
| `identity/target` | Sagt nicht, dass es Zitadel-Actions-v2-Hooks sind |
| `audit` (Ledger) · `authz/audit.go` (FGA-Entscheidungslog) · `shared/audit` (Loki-Alerting) | Drei „Audit"-Begriffe |
| `RouteSecurityPolicy.EndpointID` | Registry ist auf `Resource` gekeyt — der Feldname lügt |
| Fehlerpräfixe | `authz:`, `sync:`, `pki:` … aber `token` nutzt `identity:` |
| `AuditCheckpoint.PublicKeyPEM` | Enthält rohes Base64, kein PEM. Mit einem echten Vault-Transit-Key (PEM) schlägt jede Verifikation fehl. |
| Log-Stil | ALL-CAPS mit eingebetteten Requirement-IDs (`"... [DEV-06]"`), gemischt mit drei Attribut-Stilen (`slog.String("error",…)`, `slog.Any("error",…)`, `"error", err`) |
| Sprache | Deutsche Kommentare (`fliegende rotation`), deutsches justfile, englische Fehlertexte |

---

## 9. Tests, die konstruktionsbedingt nicht fehlschlagen können

Verbessert: `test/failure` Szenarien 1, 2, 5 nutzen jetzt echte Komponenten. Bestehen bleiben:

- **`test/failure` Szenarien 6, 7, 8, 9** — Closures im Test. Szenario 6 enthält zusätzlich `if err == nil || !errors.Is(err, err)`; `errors.Is(x, x)` ist für nicht-nil immer wahr, die Bedingung reduziert sich auf `err == nil`. Vier von neun normativen Ausfallszenarien sind unbelegt.
- **`test/failure` Szenarien 3, 4** — konstruieren `NewFGAClient(nil, nil, nil, …)` und prüfen den Nil-Checker-Pfad, nicht einen Ausfall. Szenario 3 behauptet Decision-Cache-Verhalten; der Cache ist nicht verdrahtet.
- **`test/isolation`** — alle drei Schichten sind Closures. Die „Fehlschlag-Nachweise" prüfen, dass eine Funktion, die `nil` zurückgibt, `nil` zurückgibt (`bypassedCheck`), bzw. dass ein Resolver, der eine Konstante liefert, eine Konstante liefert (`unprotectedResolver`).
- **`enforce/order_test.go`** — Spy-Gates heißen `"DPoPGate"`, `"PrincipalGate"`, `"EndpointSecurityGate"`; diese Typen existieren nicht. Der Test prüft die Reihenfolge, in der er selbst die Spies übergeben hat. `TestStage1Chain_OrderMismatchFails` prüft, dass eine umgekehrte Liste ungleich der korrekten ist — eine Tautologie über `reflect.DeepEqual`.
- **`celldir/pool_test.go`** — `var poolTenantID string = ""`, danach die Prüfung, dass er leer ist. Der reale `ExecInTenantTx` wird nie aufgerufen.
- **`celldir/saga_test.go`** — „Crash Recovery" setzt `saga.CompletedSteps` von Hand; kein Prozess startet neu, nichts wird persistiert.
- **`celldir/rls_test.go`, `audit/ledger_test.go`** — `strings.Contains` auf SQL-Text, positionsbasierter Zugriff (`migrations.All[7]`).

Ein weiterer Fall, der bereits sichtbaren Schaden anrichtet: `test/tokens/issuer.go` setzt für L3 `amr = ["webauthn","mfa"]`. Da `mfa` **nicht** in `PhishingResistantAMRValues` steht, verifiziert dieses Token als **L2**. `GenerateTestToken(..., TrustLevelL3)` erzeugt kein L3-Token — Aussteller und Verifizierer widersprechen sich, und der Seed liefert falsch etikettierte Credentials.

#### 9-T Ergebnis und offene Tickets aus der Umsetzung von 9

Drei Punkte waren bereits erledigt: `enforce/order_test.go` (§5.1), der positionsbasierte `migrations.All[7]`-Zugriff (jetzt `GetByVersion`), und der L3/`amr`-Fehler im Test-Issuer (§3.2 — L3 kommt über `acr`, mit Begründung im Code).

**Das Prinzip des Umbaus: differentiell statt simuliert.** Ein „Fehlschlag-Nachweis" per Closure beweist nichts, weil er den Produktionscode nicht befragt. Jeder ersetzte Test fährt jetzt **dieselbe Produktionsfunktion zweimal** — einmal mit einer Eingabe, die die Grenze zulässt, einmal mit einer, die sie verletzen will. Ohne die erlaubte Hälfte kann ein Test nicht unterscheiden, ob die Grenze hielt oder ob dort ohnehin nie etwas durchkommt.

**Schritt 1 — die Ausfallmatrix.** Vier von neun Szenarien (6, 7, 8, 9) berührten keine Zeile Produktionscode: jedes definierte eine Funktion, die einen Fehler liefert, und prüfte, dass sie einen liefert. Szenario 6 enthielt zusätzlich `!errors.Is(err, err)` — für jedes Nicht-nil falsch, die Bedingung war also `err == nil`. Die Szenarien 3 und 4 konstruierten `NewFGAClient(nil, nil, nil, …)`, was „nichts konfiguriert" modelliert und nicht „Ausfall": der nil-Checker wird abgelehnt, bevor irgendeine Auswertung stattfindet, also blieben der degradierte Pfad, der Reason-Code und der Circuit Breaker unausgeführt.

Alle sechs laufen jetzt gegen die echte Komponente: `FGAClient` mit einem Checker, der einen Netzwerkfehler liefert (inklusive öffnendem Breaker), Resolver-Ausfall plus `ValidateTuple` aus §5.6, `session.Manager` mit einem ausgefallenen Store, `audit.CheckpointEngine` mit einem toten Signer, `celldir.Resolver` mit warmem Cache, `audit.AuditDispatcher` mit der AUD-04-Matrix.

**Zwei normative Regeln stimmen nicht mit dem Code überein** — und die Attrappen prüften sie wie geschrieben und waren grün. Genau so blieben die Lücken unsichtbar:

- Szenario 3 verspricht „Reads within decision cache (≤ 30 s) succeed". `authz.DecisionCache` existiert, `CheckPermission` konsultiert ihn nie. → **T-9.1**
- Szenario 9 verspricht „standard writes buffer in outbox". `AuditDispatcher` verwirft sie und begründet das im eigenen Kommentar, weil ein behaupteter Puffer eine Wiederherstellung behaupten würde, die nicht stattfindet (T-3.7.1).

**Schritt 2 — Isolation, Pool, Saga.**

`celldir/pool_test.go` hatte drei Tests, von denen keiner fehlschlagen konnte: `strings.Contains(q+" -> "+id, q)`, `var poolTenantID string = ""` gefolgt von der Prüfung auf `""`, und die Feststellung, dass ein Literal seinen eigenen Teilstring enthält. Der reale `ExecInTenantTx` wurde nie aufgerufen. Ersetzt durch einen `database/sql/driver`, der mitschreibt, was auszuführen verlangt wird — damit ist die CELL-06-Eigenschaft **beobachtbar**: `set_config('app.tenant_id', $1, true)`, und der dritte Parameter `true` ist die Transaktionslokalität. Mit `false` wandert die Bindung mit der Verbindung zurück in den Pool, und der nächste Entleiher erbt die Zeilensicht eines fremden Tenants. Der Treiber kommt über `sql.OpenDB(connector)` statt `sql.Register`, sonst paniken Wiederholungsläufe am prozessglobalen Treibernamen.

`test/isolation` endete auf allen drei Schichten in einem „Fehlschlag-Nachweis", der eine Closure definierte, die `nil` liefert, und dann protokollierte, dass sie `nil` liefert. Schicht 1 war vollständig Attrappe. Jetzt: Schicht 1 gegen `ExecInTenantTx` mit dem Treiber, Schicht 2 gegen `ExplainPermission` mit eigenem **und** fremdem Tenant, Schicht 3 gegen `celldir.Resolver` mit gemapptem **und** ungemapptem Tenant.

`celldir/saga_test.go` setzte `saga.CompletedSteps` von Hand und prüfte dann, dass die Engine genau diese Schritte überspringt — also dass ein `continue` in einer Schleife über eine Slice, die der Test selbst gefüllt hat, die Einträge überspringt, die der Test hineingeschrieben hat. Kein Schritt lief je vor dem „Absturz", nichts wurde je gecheckpointet. Jetzt führt der erste Lauf wirklich drei Schritte aus und bleibt am vierten stehen, weil er keinen Executor hat — ein Pfad, der vor jeder Kompensation zurückkehrt. Der wiederaufgenommene Vorgang wird mit `GetSaga` aus der Engine gelesen, der Zustand stammt also von ihr und nicht vom Test.

**Der Nachweis.** Jeder neu gebaute Test wurde einmal rot gemacht, indem die geschützte Zeile im Produktionscode entfernt wurde; danach war der Code unverändert gegen HEAD (per `git diff` geprüft):

| Test | Mutation | |
|---|---|---|
| Szenario 3 | `Allowed: false` → `true` im degradierten Zweig | rot |
| Szenario 4 | Resolver-Fehler fällt auf `storeID = "global"` durch | rot |
| Szenario 6 | `CreateFamily` schluckt den Store-Fehler | rot |
| Szenario 7 | `CreateCheckpoint` ignoriert den Signer-Fehler | rot |
| Szenario 8 | Resolver liefert eine Fallback-Zelle statt `ErrTenantNotFound` | rot |
| Szenario 9 | kritischer Audit-Zweig liefert `nil` | rot |
| Pool / Isolation 1 | `set_config(..., true)` → `false` | rot |
| Pool | Leerfeld-Guard setzt `tenantID = "public"` | rot |
| Isolation 2 | `MayActIn`-Prüfung entfernt | rot |
| Isolation 3 | Fallback-Zelle statt Fehler | rot |
| Saga | Wiederaufnahme überspringt nichts mehr | rot |

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-9.1** | **`authz.DecisionCache` ist nicht verdrahtet.** Die Ausfallmatrix verspricht für einen OpenFGA-Ausfall „Reads within decision cache (≤ 30 s) succeed"; `CheckPermission` konsultiert keinen Cache, also fällt jeder Read fail-closed. Entweder wird der Cache verdrahtet oder die normative Regel gestrichen. | Beides ist eine Entscheidung über die Ausfallmatrix, keine Reparatur. | § 9, § 6.4 |
| **T-9.2** ✅ | **RLS-Policies werden als Text geprüft, nicht ausgeführt.** `rls_test.go` und `ledger_test.go` prüfen Migrations-SQL per `strings.Contains`. Das fängt eine gelöschte Zeile, aber keine vorhandene und falsche Policy — und eine semantisch gleiche Umformulierung macht es grundlos rot. | **Erledigt.** `identity/test/integration` fährt die Migrationen gegen ein echtes PostgreSQL 18 und prüft, was der Server daraus macht. Die Textprüfungen sind entfallen. Details im Block unten — darunter eine Mutation, die überlebt hat. | § 9, CELL-05 |
| **T-9.3** | **`identity/celldir` ist einmal sporadisch fehlgeschlagen** — in einem von vier `-race`-Gesamtläufen, in zehn weiteren Durchgängen nicht reproduzierbar. Ein sporadisch roter Test untergräbt jedes „alles grün". | Nicht reproduzierbar; braucht einen gezielten Lauf unter Last. | § 9, § 7 |
| **T-9.4** | **Saga-Wiederaufnahme über einen Prozessneustart ist nicht geprüft.** `persistedMap` ist prozesslokal, also endet der Nachweis bei „dieselbe Engine nimmt wieder auf". Ein echter Neustart braucht den persistenten Saga-Store. | Braucht Postgres (T-3.6.1). | § 9, CELL-07 |

#### 9.2-T Ergebnis: das Schema wird jetzt ausgeführt, nicht gelesen

**Was das ist, und was nicht.** Der Prüfling ist das SQL in `identity/migrations` — ein Artefakt mit Logik darin. Der Harness startet ein leeres Wegwerf-PostgreSQL, spielt genau dieses Artefakt ein und fragt den Server, ob er tut, was wir behaupten. „Rot" heißt damit: **meine Policy ist falsch**, nicht: eine Umgebung ist kaputt. Ein Deployment-Test — „läuft Umgebung X korrekt" — ist etwas anderes, hängt am fehlenden `cmd/identity-api` und bleibt § 10. Dass es kein Unit-Test mit Double sein kann, ist derselbe Grund wie beim OpenFGA-Vertragstest: RLS wertet **Postgres** aus, und ein Go-Double dafür schriebe ich aus derselben Annahme, die der Test belegen soll.

**Zwei Rollen, sonst prüft sich der Test selbst nicht.** Superuser und `BYPASSRLS` umgehen RLS immer; `FORCE ROW LEVEL SECURITY` wirkt nur auf den **Eigentümer**. Wer als `postgres` migriert, macht „der Eigentümer kann seine eigene Policy nicht umgehen" per Konstruktion unprüfbar. Der Harness legt deshalb `identity_migrator` an (NOSUPERUSER, NOBYPASSRLS), migriert als diese Rolle — womit sie Eigentümerin ist — und wechselt für die App-Sicht mit `SET LOCAL ROLE` nach `identity_app`. Beide Bindungen sind transaktionslokal, wie `set_config('app.tenant_id', …, true)`; nichts läuft in die gepoolte Verbindung zurück.

**Drei Dinge, die der Harness beim Bauen selbst gefunden hat:**

- **Seit PostgreSQL 16 bekommt der Erzeuger einer Rolle `ADMIN`, aber nicht `SET`.** `identity_migrator` erzeugt `identity_app` (die Migration läuft ja als Migrator) und konnte trotzdem nicht hineinwechseln; ein nachgeschobenes `GRANT` half nicht, weil die Mitgliedschaft bereits bestand und ihre Optionen nur geändert werden, wenn man sie benennt. Es braucht `WITH SET TRUE` — und `INHERIT` bleibt bewusst falsch, damit `SET ROLE` genau die Rechte der App-Rolle liefert und nicht die der Eigentümerin.
- **Die Fixtures leiten sich aus den Testnamen ab und sind damit über Läufe hinweg stabil** — der zweite Lauf gegen denselben Container kollidierte auf dem Primärschlüssel, und der Fehler sah aus wie ein Schemadefekt. Der Lauf setzt das Schema deshalb zurück, statt Zeilen zu löschen: aus einem Append-Only-Ledger Platz für den nächsten Lauf zu räumen würde genau die Eigenschaft untergraben, die nebenan geprüft wird. Der Reset weigert sich bei einer Datenbank, deren Name ihn nicht als Wegwerf ausweist — `POSTGRES_TEST_URL` ist eine Umgebungsvariable, und die exportiert irgendwann jemand in der falschen Shell.
- **Ein von Hand angelegtes `public` hat kein `USAGE` für PUBLIC**, anders als das von initdb. Folge: die App-Rolle sah *keine* Relation — gemeldet als „does not exist", nicht als Rechtefehler. Wiederhergestellt, damit „diese Rolle kommt an die Tabelle nicht heran" eine Aussage über Tabellenrechte bleibt (T-9.5) und kein Artefakt des Resets.

**Die interessanteste Mutation hat überlebt.** `WITH CHECK` aus der Policy zu entfernen macht **keinen** Test rot — und das ist richtig so: fehlt `WITH CHECK`, benutzt PostgreSQL den `USING`-Ausdruck auch für Schreibzugriffe, und der ist hier identisch. Die Klausel hat also keine eigenständige Wirkung; der alte Textest hat die Anwesenheit von etwas geprüft, das nichts entscheidet. Sie bleibt trotzdem stehen — sie macht die Absicht explizit und trägt, sobald `USING` je gelockert wird. Der Test bekommt seinen Nachweis stattdessen aus `WITH CHECK (true)`: dann fällt er, wie er soll.

| Mutation im SQL | |
|---|---|
| `FORCE ROW LEVEL SECURITY` entfernt | **vier** Tests rot — der Eigentümer liest *und schreibt* fremde Tenants |
| `WITH CHECK` entfernt | **grün** — siehe oben, `USING` springt ein |
| `WITH CHECK (true)` | rot |
| Index auf `(id, tenant_id)` gedreht | rot |
| `REVOKE UPDATE, DELETE` entfernt | **nicht verifiziert** — der Testlauf wurde in dieser Sitzung von der Werkzeugfreigabe blockiert, während die Rechteänderung im Baum lag. Der Test prüft positiv (INSERT erlaubt, UPDATE/DELETE mit SQLSTATE 42501 abgewiesen) und ist beim Fehlen der Rechte nachweislich rot geworden; der gezielte Gegenbeweis fehlt |

**Postgres-Version vereinheitlicht.** Ubicloud bietet 16/17/18 und hat 18 als `DEFAULT_VERSION`/`LATEST_VERSION`; unser Terraform-Modul bestellte bereits 18. Abweichend war allein die Dev-Compose mit 16 — jetzt 18, wie der Testcontainer, mit einer `validation`-Regel am Terraform-Variablenwert. Eine Policy, die auf einer anderen Hauptversion bewiesen wurde, ist für die laufende nicht bewiesen.

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-9.5** | **`identity_app` hat Rechte auf genau einer von zehn Tabellen.** Migration 009 legt die Rolle an und erteilt `INSERT, SELECT` auf `audit_ledger`; für `tenant_members`, `outbox_events`, `revocation_entries` und die übrigen gibt es keinen einzigen `GRANT` — weder in einer Migration noch in Ansible oder Terraform. Ein Dienst, der sich als diese Rolle verbindet, bekäme dort „permission denied". Niemand merkt es, weil sich nichts als sie verbindet. Sichtbar geworden ist es daran, dass die RLS-Prüfung als App-Rolle nur auf `audit_ledger` möglich ist. | Das sind Produktionsrechte, keine Testentscheidung: welche Tabelle die Anwendung schreiben darf, gehört zusammen mit dem Kompositionspunkt entschieden. | § 9, § 4.1, AUD-01 |
| **T-9.6** ✅ | **Es gibt keinen `dbtx.Tx` über einem echten Treiber.** `sync.MemoryTx` ist die einzige Implementierung, also kann keine transaktionale Komponente — Ledger, Outbox, Break-Glass — gegen Postgres laufen. Der Harness kann das Schema prüfen, aber keinen Schreiber, der es benutzt. | **Erledigt.** `audit.PostgresLedgerWriter` ist der erste echte Schreiber; das Interface musste dafür erst lesefähig werden. Treiber: `pgx/v5/stdlib`. Siehe den Block unten. | § 9, § 4.1, T-4.1.4 |

#### 9.6-T Ergebnis: das Interface konnte nicht, was es versprach

**`dbtx.Tx` hatte keine Lesemethode** — und `WriteAuditRecord` muss laut eigenem Vertrag die Spitze der Kette lesen, die nächste Sequenznummer vergeben und einfügen, „atomically, inside the caller's transaction". Die einzige Implementierung umging das, indem sie die Transaktion auf `nil` prüfte und dann an ihr vorbei in eine eigene Map schrieb. Der Parameter war Dekoration; der Vertrag stand im Kommentar und nirgends sonst.

Das Interface hat jetzt `QueryRow` und dazu `Row` und `ErrNoRows`. `Row` ist ein Interface mit einer Methode und nicht `*sql.Row`: dieser Typ lässt sich außerhalb von `database/sql` nicht konstruieren, ein Double könnte `Tx` also nie erfüllen — und Doubles sind bis heute fast alles, was diese Schnittstelle benutzt. `ErrNoRows` gehört aus demselben Grund dazu: „nichts gefunden" von „fehlgeschlagen" zu unterscheiden, ohne `database/sql` zu importieren, ist genau der Zweck des Pakets.

**Der Schreiber nennt keinen Treiber und importiert kein `database/sql`.** Alles, was er braucht, steht auf `dbtx.Tx`; die einzige PostgreSQL-Tatsache, die er kennt — SQLSTATE `23505` —, liest er über `interface{ SQLState() string }` vom Fehler ab, was pgx und lib/pq gleichermaßen bedienen. Der Treiber taucht erst im Adapter `identity/dbtx/sqltx` und im Kompositionspunkt auf. Gewählt ist **`pgx/v5/stdlib`**: gepflegt, bereits direkte Abhängigkeit des Monorepos, und der Harness-Helfer bleibt unverändert, weil beide `SQLState()` anbieten.

**Der Sequenzkonflikt ist eine Betriebseigenschaft, keine Fußnote.** Zwei gleichzeitige Anhänge desselben Tenants lesen dieselbe Spitze; `UNIQUE (tenant_id, sequence_number)` weist einen ab. Innen wiederholen geht nicht — nach dem Fehler ist die Transaktion abgebrochen —, und nur den Insert zu wiederholen wäre falsch, weil er dann auf einen Vorgänger zeigt, der nicht mehr der letzte ist. Der Schreiber liefert deshalb `ErrSequenceConflict`, und der Aufrufer wiederholt die **ganze** Arbeitseinheit.

**Die beiden Transaktionsidiome treffen sich jetzt.** `celldir.ExecInTenantTx` nahm `*sql.Tx` und ist die einzige Stelle, die `app.tenant_id` setzt — für einen Schreiber, der die neutrale Transaktion bekommt, war sie damit unerreichbar. Sie nimmt jetzt `dbtx.Tx`. Der Ledger-Schreiber setzt den Scope weiterhin **nicht** selbst: wer die Transaktion öffnet, kennt den Tenant (CELL-06), und dass er ohne Scope fail-closed ist, prüft ein eigener Test — RLS weist den Insert mit `42501` ab.

**Eine Mutation hat überlebt, und die Erklärung ist ein Fund.** Die Kürzung von `created_at` auf Mikrosekunden zu entfernen macht keinen Test rot: `canonicalRecord()` kürzt bereits auf `ledgerTimeResolution`, der Hash ist also ohnehin sicher. Die **Spalte** ist es nicht. Ein Treiber, der den Zeitstempel als Text zum Parsen an den Server gibt, überlässt PostgreSQL das Runden — und Postgres rundet zur nächsten Mikrosekunde, während der Hash abschneidet. Eine halbe Mikrosekunde Unterschied, und die gespeicherte Zeile passt nicht mehr zu den kanonischen Bytes daneben. pgx schneidet beim Kodieren ab, also stimmen die beiden heute **durch Glück des Treibers** überein. Die Kürzung bleibt deshalb stehen, benutzt aber jetzt dieselbe Konstante wie die Kanonisierung, statt `time.Microsecond` ein zweites Mal hinzuschreiben.

| Mutation | |
|---|---|
| Spitze mit `ORDER BY … ASC` gelesen | rot — der dritte Anhang kollidiert |
| `created_at` nicht gekürzt | **grün** — siehe oben, die Kanonisierung kürzt schon; mit einem rundenden Treiber wäre es rot |
| vor dem Setzen der Sequenznummer gesiegelt | rot |
| Konflikt als generischer Fehler geliefert | rot |
| `set_config`-Drittargument auf `false` | rot (drei Tests, zwei Pakete) |

| # | Ticket | Warum vertagt | Auslöser |
|---|---|---|---|
| **T-9.7** ✅ | **Die Outbox-Tabelle und das Outbox-Modell beschreiben verschiedene Dinge.** `outbox_events` (nur in Migration 008 angelegt) hat `id, tenant_id, event_type, payload, created_at`. `sync.OutboxEvent` hat zusätzlich `AggregateType`, `AggregateID`, `SequenceNumber`, `Status`, `RetryCount` — und **kein** `TenantID`, obwohl die Spalte `NOT NULL` ist und die RLS-Policy darauf steht. Die Ordnungsgarantie aus § 5.8, für die `NextSequence` gehärtet wurde, hat in der Datenbank keinen Platz; der Schreiber kann die RLS-Diskriminante nicht einmal füllen. | **Erledigt** mit Migration 011, `identity/outbox` und `sync.PostgresOutboxStore`. Es waren drei Kollisionen, nicht eine — siehe den Block unten. | § 9, § 5.8, SYNC-01 |

#### 9.7-T Ergebnis: drei Kollisionen, und eine Ausnahme mit Namen

**Die dritte war die schwerste, und sie stand in keinem Ticket.** `OutboxConsumer.ProcessBatch` ruft `GetPendingEvents` — tenant-übergreifend, ohne Transaktion und ohne Scope. Auf einer Tabelle mit `FORCE ROW LEVEL SECURITY` und `USING (tenant_id = current_setting('app.tenant_id', true))` liefert das **null Zeilen, immer**: ohne gesetzten Scope ist `current_setting` NULL, und NULL gleicht keiner Tenant-ID. Der Dispatcher hätte gegen diese Tabelle nie gearbeitet, egal wie gut der Store ist. Auffallen konnte das erst, als Schema und Konsument gleichzeitig angefasst wurden.

**Die Ausnahme wird benannt, nicht das Verfahren abgeschaltet.** Migration 011 legt `identity_outbox_worker` an und gibt ihr zwei Policies — `FOR SELECT` und `FOR UPDATE`, beide `USING (true)` — statt `BYPASSRLS`. Der Unterschied ist nicht kosmetisch: `BYPASSRLS` ist eine **Rolleneigenschaft** und schaltet Row Level Security für diese Rolle auf **jeder** Tabelle der Datenbank ab; eine Policy steht im Katalog neben der Regel, die sie ausnimmt, und gilt für genau eine Tabelle. PostgreSQL verknüpft permissive Policies mit **oder**, also bleibt der Anwendungspfad unverändert tenant-gebunden. `INSERT` bekommt die Rolle nicht: eine Warteschlange zu leeren verlangt nicht, sie zu füllen.

**Die zweite Kollision:** ein Produzent hat gar keinen Tenant. `ZitadelEvent` trägt Event-ID, Typ, Aggregat und Payload — sonst nichts. `IngestZitadelEvent` nimmt ihn deshalb als Pflichtparameter. Es gibt heute keinen Produktivaufrufer, also verschiebt das die Frage an die Stelle, die sie beantworten kann: den Hook-Handler, der weiß, wessen Zitadel ihn ruft. Ein Default auf einen Pseudo-Tenant hätte die Frage zugemauert.

**`identity/outbox` ist das zweite `identity/dbtx`.** Der Erste Entwurf gab `audit.OutboxStager` eine `sync.StageRequest` — und hätte damit `audit → sync → authz` wieder eingeführt, genau die Abhängigkeit, die T-4.1.4 entfernt hat. Der Typ hat dasselbe Problem wie `Tx` und bekommt dieselbe Lösung: ein Paket, das nichts importiert, plus ein Alias in `sync`, damit kein Aufrufer bricht. `go list -deps ./identity/audit` erreicht weder `sync` noch `authz`.

**Zwei Funde am Rande:**

- **`migrations.All` war eine zweite, von Hand gepflegte Registratur** derselben Migrationen — und sie driftete in dem Moment, in dem 011 dazukam: `List` hatte elf Einträge, `All` zehn, und `registry/cmd/server` liest `All`. Jetzt wird `All` aus `List` abgeleitet. Der Test, der es fing, ersetzt außerdem eine fest verdrahtete Zahl („erwarte 10 Migrationen") durch die Invariante, die sie nur nachahmte: **jede `.up.sql` im Verzeichnis ist registriert**. Die Zahl musste bei jeder Migration von Hand nachgezogen werden und hat den Fehler, nach dem sie aussah, nie fangen können.
- **Das `INSERT`-Verbot für den Dispatcher hängt nicht am `GRANT`.** Die Rolle das Recht zu erteilen, macht den Test nicht rot — es gibt keine `FOR INSERT`-Policy, und ohne Policy weist RLS ab. Zwei unabhängige Barrieren, was gut ist; die Mutation, die wirklich trifft, ist die realistische Fehlerform „die Ausnahme zu breit geschrieben" (`FOR ALL` statt `FOR SELECT`).

| Mutation | |
|---|---|
| Worker-Lesepolicy tenant-gebunden wie die App-Policy | rot — der Dispatcher sieht 0 von 2 Tenants |
| Ausnahme als `FOR ALL` plus `INSERT`-Recht | rot |
| `uq_outbox_aggregate_sequence` entfernt | rot |
| `NextSequence` nicht nach Aggregat getrennt | rot |
| `MarkProcessed` meldet ein Update ohne Treffer als Erfolg | rot |

**Zur Verifikation selbst:** auf diesem Rechner blockiert Windows Smart App Control frisch gebaute, unsignierte Testbinaries — zufällig verteilt über Pakete, mehrfach pro Lauf. Die Suite wurde deshalb über mehrere Läufe aggregiert: **null echte Testfehler, jedes Paket mit Tests mindestens einmal grün**, 26 Integrationstests gegen echtes PostgreSQL 18. Ein blockierter Lauf sieht in der Ausgabe einem grünen ähnlich, wenn man nur nach `--- FAIL` greppt — zwei Mutationsprüfungen liefen mir deshalb zunächst durch und wurden mit Blockade-Erkennung wiederholt.

**`just test-docker` beantwortet das dauerhaft** — und hat sofort etwas gefunden. Im Linux-Container greift die Windows-Codeintegrität nicht; die Suite läuft in **einem** Durchgang durch statt in dreien. Dabei kam heraus, dass `registry/cmd/vmrunner` **linux-only** ist (`build constraints exclude all Go files` auf Windows): sein Test war auf dieser Maschine nie ausgeführt worden, und er konnte nicht bestehen — die Fehlermeldung formatiert den Compilernamen mit `%q`, die Prüfung suchte die Zeichenkette ohne Anführungszeichen. Ein Test, der auf keiner Plattform des Entwicklers je lief, ist der Grenzfall des Scheintests aus § 9: er behauptet Abdeckung, die niemand je eingelöst hat.

Das Image folgt der Toolchain aus `go.mod`; eine andere Nebenversion prüfte etwas anderes als das, was gebaut wird. `registry/test/integration` ist ausgenommen, weil es eine eigene Datenbank braucht — die Ausnahme wird bei jedem Lauf ausgegeben, nicht verschwiegen.

---

## 10. DevOps und Betrieb

| Befund | |
|---|---|
| **Kein Identity-Binary** ✅ | Es gibt kein `cmd/identity-api`, keinen Router, keinen Server. Sämtliche Middleware ist nirgends montiert. **Erledigt als Durchstich:** `cmd/identity-api` bedient eine Route — `GET /api/v1/tenants/{id}/members` — über die vollständige Kette. Siehe § 10.1-T. Der Rest von Welle 1 hängt sich daran, ohne dass noch etwas Strukturelles entsteht. |
| **CLIs melden Erfolg ohne Wirkung** | `cmd/fga-admin`: `rebuilder := fga.NewTupleRebuilder(nil,nil,nil); _ = rebuilder` → Ausgabe „REBUILD APPLIED SUCCESSFULLY". `cmd/cell-admin switch-tenant` → „completed successfully". `cmd/identity-sync` → druckt und kehrt zurück, DLQ-Replay arbeitet auf einem frischen Memory-Store. `cmd/celldir` → `fmt.Println`. `cmd/identity-seed` → druckt Tenants, die es nicht anlegt. |
| **`justfile` zeigt großflächig ins Leere** | `plan-infra` ruft `plan-tf "s3"/"cloudflare"/"database"/"control-plane"/"worker"` — vorhanden sind `identity`, `ops`, `staging`, `update`. `deploy` ruft `deploy/api/deploy.sh` (existiert nicht). `plan-app` liest `deploy/api/.last_tag`. `validate-policy` startet **nur** `go test ./shared/policy/...` und ruft nie `fga model test` — `policy/tests/*.fga.yaml` und `policy/tests/matrix/expectations.yaml` werden von nichts ausgeführt. |
| **Valkey ohne Anbindung** | Die Ansible-Rolle existiert; `ratelimit.ValkeyBackend`, `dpop.ValkeyReplayStore`, `revocation.ValkeyPubSubClient` haben außerhalb von Tests **keine Konstruktionsstelle**. Die verteilten Stores sind produktiv unerreichbar. |
| **Ansible-Rolle `openfga`** | `openfga_db_password` hat keine Quelle (kein Vault-Lookup, keine `vars`). Nutzt `vault_root_token`, während `nomad` auf AppRole umgestellt ist. `postgresql_user`/`postgresql_db` setzen ein lokal erreichbares Postgres voraus; die DB ist verwaltetes Ubicloud über TLS. `changed_when: false` überall ⇒ die Rolle meldet nie eine Änderung. |
| **`backup/verifier.go` erfindet Metriken** | `res.RowsRestored = fi.Size() / 100 // Estimate rows`, `res.DurationMs = 50`. Es wird nichts wiederhergestellt — nur `os.Stat`. Die Gauge `toob_db_restore_verification_success` meldet 1 für einen korrupten, aber nicht leeren Dump. Eine Metrik, der man vertraut, obwohl sie nichts misst, ist schlechter als keine. |
| **`coverage` im Repo-Root** | Verweist auf `shared/identity/token/verifier.go` — ein Pfad, den es nicht mehr gibt. Nicht in `.gitignore`. |
| **Kein `docs/`** | Weder ADRs noch Runbooks. `policygen` schreibt nach `docs/permissions.md` in ein Verzeichnis, das nicht existiert. |

#### 10.1-T Ergebnis: der Durchstich, und was er beim Zusammenstecken zeigte

Eine Route — `GET /api/v1/tenants/{id}/members` — vom signierten Token über die sechs Stage-1-Tore und den Tenant-Scope bis zu einer RLS-Abfrage gegen echtes PostgreSQL. Jedes Teil davon gab es vorher, und **keine zwei davon hatten sich je getroffen.** Genau darin lag der Wert: das Zusammenstecken hat drei Dinge aufgedeckt, die einzeln unsichtbar waren.

**Der Tenant hatte drei Quellen, und keine war die richtige.** Der Interceptor las `X-Tenant-ID` aus dem Header, `celldir.ExecInTenantTx` nahm ihn als Parameter, `tenant.SetTenantContext` ausschließlich aus dem Principal. Für eine pfad-gebundene Route ist keine davon korrekt — und der Header war die gefährlichste: `MayActIn("")` liefert **true**, ohne Header prüfte die `TenantGate` also nichts, während der Handler anschließend nach dem Pfadsegment scopen wollte, das kein Tor gesehen hatte.

Jetzt deklariert jede Route ihre Quelle (`TenantFromPath`, `TenantFromHeader`, `TenantNone`), und „diese Route hat keinen Tenant" ist etwas, das sie **sagt**, statt etwas, das sie vergisst. Beides erzeugt denselben leeren String, und nur eines davon ist eine Entscheidung.

**Eine Mutation hat überlebt und den Entwurf korrigiert.** Als ich testweise die Quelle von Pfad auf Header umstellte, blieb alles grün — weil mein Handler den Tenant *noch einmal* selbst prüfte. Zwei Besitzer derselben Regel, und der zweite verdeckte, ob der erste überhaupt lief. Der Handler liest jetzt den **geprüften** Wert über `middleware.VerifiedTenant` aus dem Kontext und den Request gar nicht mehr an. Danach war dieselbe Mutation in drei Tests rot.

**Die Abfrage trägt bewusst kein `WHERE tenant_id`.** Row Level Security ist, was sie einschränkt — also sind die zurückgegebenen Zeilen der Beweis, dass der Scope gesetzt war. Mit einer `WHERE`-Klausel lieferte sie dieselben Zeilen, ob die Policy wirkt oder nicht, und der Test könnte beides nicht mehr unterscheiden. Die Mutation bestätigt es: ohne `ExecInTenantTx` kommen **null** Zeilen zurück.

**Die erste echte DB-Rolle entsteht mit ihrem Prozess.** `identity_api` (Migration 012) darf `tenant_members` lesen und ins Ledger anhängen — sonst nichts. Das ist die Antwort auf T-9.5, aber ohne die Sammelmigration: die Rechte entstehen dort, wo der Bedarf entsteht. Sechs Rollen anzulegen, unter denen sich kein Prozess verbindet, wäre wieder ein Konstrukt ohne Aufrufer gewesen.

**Zwei Zusagen sind jetzt eingelöst statt gebaut:** `spolicy.VerifyEndpointPolicyCompleteness` (POL-05 / T-6.6) bekommt seine erste Routentabelle und läuft beim **Start**, nicht pro Request — ein Prozess, der nicht durchsetzen kann, was er ausliefert, darf nicht starten. Und `enforce.StandardGateOrder()` wird beim Hochfahren protokolliert, statt nur in einem Test zu existieren.

Gebunden werden **zwei** Listener, nicht vier: L1 mit der Route, L4 mit `/healthz` und `/readyz`. Flotte und Partner bleiben unverdrahtet, bis sie Routen haben — ein Port, der nur 404 antwortet, ist Angriffsfläche ohne Gegenwert. `/readyz` prüft dabei auch `schema_migrations` gegen die einkompilierte Erwartung: eine Instanz mit veralteter Migration nimmt keinen Verkehr an.

| Mutation | |
|---|---|
| Tenantquelle von Pfad auf Header | zuerst **grün** — der Handler prüfte doppelt; nach der Korrektur rot in drei Tests |
| Abfrage ohne `ExecInTenantTx` | rot, 0 statt 2 Zeilen |
| `identity_api` bekommt `INSERT` auf `tenant_members` | rot |
| Route mit unbekannter Permission | rot, schon beim Zusammenbau |

**Offen und bewusst nicht angefasst:** die Widerrufe verbreiten sich zwischen Instanzen heute nur über das Resync-Intervall, weil der prozesslokale Pub/Sub nur diesen Prozess erreicht — Valkey hat weiterhin keine Konstruktionsstelle. Und `tenant.SetTenantContext` ist als zweiter Besitzer des Scopes stehen geblieben; es gehört zusammengelegt, sobald ein zweiter Handler schreibt.

#### 10.2-T Ergebnis: Idempotenz, die im Cluster hält

Der Durchstich ist ein GET, für den das folgenlos war — **Welle 1 besteht überwiegend aus Mutationen**, und für die verdrahtete `cmd/identity-api` einen prozesslokalen Speicher, weil es keinen anderen gab. Ich hatte die Middleware bei `nil` gerade zum Panic gebracht, damit niemand versehentlich genau das bekommt.

**Vier Funde, und der Speicher war nur der kleinste davon.**

- **`idempotency_keys` stand als einzige tenant-gebundene Tabelle ohne RLS.** Was darin liegt, ist der Antwortkörper einer Mutation, also Geschäftsdaten; ohne Policy hätte ein Tenant die Antwort eines anderen lesen können.
- **Der Tabelle fehlte eine Spalte, die das Modell hat.** `CachedResponse` trägt die Header, die Middleware spielt sie zurück, die Tabelle konnte sie nicht speichern. Eine wiedergegebene `201` hätte ihren `Location`-Header verloren — und „dieselbe Antwort" ist die einzige Zusage, die ein idempotenter Endpunkt macht.
- **Die Tabelle hatte eine Spalte, die das Interface nicht kannte.** `request_path` existiert seit Migration 010; `Get(ctx, tenantID, key)` konnte sie nicht füllen. Damit war ein wiederverwendeter Schlüssel kein Konflikt, sondern die Antwort einer **anderen** Operation.
- **`ErrIdempotencyConflict` wurde deklariert und nie zurückgegeben** — es gab keine Reservierung. Zwei gleichzeitige Anfragen verfehlten beide den Cache und führten beide aus. Genau dieser Fall ist der Grund, warum es den Header gibt.

**Das Interface konnte nicht ausdrücken, was die Semantik verlangt** — dieselbe Form wie bei `dbtx.Tx` (konnte nicht lesen) und der Outbox (Tabelle ⇄ Modell). Drei Zustände statt zwei: abwesend, beansprucht, beantwortet. In Postgres ist der Anspruch **ein** Statement, `INSERT … ON CONFLICT DO NOTHING`, und damit entscheidet die Datenbank, wer den Schlüssel hält, nicht die Anwendung.

**Zwei Horizonte in einer Spalte.** Die Reservierung läuft nach 60 Sekunden ab, die Antwort nach 24 Stunden. Ein Prozess, der zwischen Anspruch und Antwort stirbt, gibt den Schlüssel damit von selbst frei, statt ihn bis morgen zu blockieren — und `Complete` meldet es, wenn die Reservierung während der Ausführung abgelaufen war, statt still Erfolg zu behaupten.

**Der Speicher scopet seine eigenen Transaktionen.** Die Middleware läuft außerhalb der Handler-Transaktion, und seit 013 steht die Tabelle unter RLS — ohne eigenen Scope sähe sie schlicht nichts. Das ist der Punkt, den man beim Portieren übersieht.

Der Memory-Speicher hat dieselben drei Zustände bekommen. Zwei Implementierungen eines Interfaces, die sich unterschiedlich verhalten, machen jeden Test gegen die schnellere wertlos.

| Mutation | |
|---|---|
| `ON CONFLICT DO NOTHING` → `DO UPDATE` | rot — **8 von 8** gleichzeitigen Anfragen beanspruchen den Schlüssel, die Operation liefe achtmal |
| Pfadbindung entfernt | rot |
| `FORCE ROW LEVEL SECURITY` weggelassen | rot |
| `Release` weggelassen | rot — der Schlüssel einer fehlgeschlagenen Operation bleibt gesperrt |

#### 10.3-T Ergebnis: W1.1, und warum Welle 1 im Katalog beginnt

**Das Nadelöhr waren nicht die Handler.** Von den Permissions, die plan6 für Welle 1 nennt, fehlten **zehn** im Katalog — POL-05 weist jede Route ab, die eine unbekannte nennt, und zwar beim Start. Welle 1 beginnt damit bei Policy-Entscheidungen: der Katalog legt Trust-Level, Step-up, Audit-Klasse und Kosten fest, die Route nennt nur die ID. Handler zuerst hieße, diese Werte im Handler zu entscheiden — genau das, wogegen POL-05 und O5 existieren. Drei Einträge sind dazugekommen (`admin.tenant.create/read/update`), erzeugt über `policygen`, nicht von Hand.

Nebenbei: plan6 §4.3 nennt `admin.role.assign`; der Katalog kennt `admin.role.update`, mit `L3`, `step_up: true`, `audit: critical` und `requires_signature: true`. Der Katalog ist die Autorität.

**Zwei verschiedene Tenant-Modelle, und beide werden gebraucht.** Ich wollte `identity/tenant` löschen, weil es keine Aufrufer hat — mit demselben Argument, das ich sonst ausdrücklich nicht gelten lasse, solange der Kompositionspunkt jung ist. Der Einwand von außen war berechtigt. `tenant_directory` beantwortet „welche Zelle", ist PII-frei und ausdrücklich **nicht** tenant-gebunden; `tenants` beantwortet „welche Organisation existiert und wie heißt sie", trägt den Kundennamen und ist gescopet wie jede andere Tabelle. Das Paket zeigte auf etwas Reales — ihm fehlte die Migration, nicht ein Grund zu existieren. Migration 014 baut sie.

**Die eine Ausnahme im Schema, und warum sie eine bleibt.** `POST /api/v1/tenants` erzeugt den Scope, es gibt also während des Aufrufs nichts, wogegen `current_setting` prüfen könnte. Die Policy trennt deshalb: `SELECT` und `UPDATE` bleiben an `id = current_setting(...)` gebunden, `INSERT` bekommt eine eigene Policy. Für `DELETE` gibt es **keine** — ohne Policy weist RLS den Befehl ab, die Abwesenheit ist die Regel.

**Mitgliedschaft geht über die Outbox, nicht direkt an OpenFGA.** Ein FGA-Schreibzugriff innerhalb einer Datenbanktransaktion ist ein verteilter Schreibvorgang ohne Atomarität: entweder steht die Zeile ohne Tupel oder das Tupel ohne Zeile, je nachdem, wo es scheiterte. Zeile und Ereignis werden zusammen geschrieben, das Tupel schreibt der Sync-Worker. Genau dafür gibt es die Outbox, und seit T-9.7 kann sie das Ereignis halten.

**Zwei Funde beim Bauen der Tests:**

- **Die URN-Grammatik macht „Principal ohne Organisation" unrepräsentierbar.** `toob:human:<cell>:<orgId>:<userId>` verlangt eine Organisation. Wer eine anlegt, gehört also schon zu einer — die neue ist eine andere. Das ist keine Einschränkung, sondern die Antwort auf die Frage, wer diese Route ruft, und plan6 §4.3 („erzeugt den Scope, existiert also noch nicht") war darin ungenau.
- **Der Organisationsname ist ein Slug, kein Anzeigename.** `policy/rules/org_names.yaml` verlangt Kleinbuchstaben mit einfachen Bindestrichen. Ein zweites Feld für einen Anzeigenamen wäre erfunden, solange niemand es liest.

**Zur Plan-Frage, die dabei aufkam:** es gibt bereits drei Achsen. `shared/plan` mit `free/pro/enterprise` und Limits wie `MaxOrgs`, `celldir.ProfileType` als technische Isolationsstufe, und `identity/internal/orgs` prüft die Quote **planbasiert**. `celldir.OnboardingSagaEngine.ValidateQuotaAndOrgName` nimmt `maxAllowedTenants` dagegen als Parameter ohne Quelle — zwei Quotenprüfungen, eine mit Herkunft und eine ohne. Die Route erzwingt heute nur die Namensregel; die Quote braucht eine Planquelle für den Aufrufer, und identity hat keine. Eine erfundene Zahl wäre schlechter als die benannte Lücke. → **T-10.1**

| Mutation | |
|---|---|
| Mitgliedschaftsänderung staged kein Ereignis | rot |
| Audit-Fehler bei der Rollenänderung geschluckt | rot |

#### 10.3-U Ergebnis: W1.2 — die Outbox bekommt einen Konsumenten, und ein Schweigen wird laut

**Der Befund, der alles andere überschattet: jede Outbox-Nutzlast war Base64.** `outbox.StageRequest.Payload` war `any`, und jeder Produzent im Baum — Mitgliedschaft, Audit-Replikation, JIT-Provisionierung — kodierte selbst und übergab `[]byte`. `json.Marshal` eines `[]byte` ist eine Base64-Zeichenkette. Die Ereignisse landeten also als undurchsichtige Blobs in der JSONB-Spalte, die kein Konsument dekodieren kann. **Niemandem ist es aufgefallen, weil bis heute nichts die Outbox gelesen hat.** Der Typ ist jetzt `json.RawMessage`: derselbe Aufrufcode, aber ein Struct statt Bytes übersetzt nicht mehr. Ein `any`, das sowohl den Wert als auch dessen Kodierung annimmt und mit einem von beidem still das Falsche tut, ist keine Flexibilität, sondern eine Falle mit Verzögerungszündung.

**Redelivery ist der Normalfall, nicht die Ausnahme.** Ein Prozess, der zwischen Tupelschreiben und Als-verarbeitet-Markieren stirbt, sieht das Ereignis wieder. OpenFGA weist das doppelte Schreiben ab — würde der Projektor das als Fehler lesen, landete jede Wiederzustellung in der Dead-Letter-Queue, die sich mit bereits erledigter Arbeit füllte. Welche Antwort „schon angewendet" heißt, habe ich **gemessen statt geraten**: OpenFGA v1.18.3 antwortet auf ein doppeltes Schreiben *und* auf das Löschen eines fehlenden Tupels mit `write_failed_due_to_invalid_input`, auf einen wirklich ungültigen Typ oder eine unbekannte Relation dagegen mit `validation_error`. Die beiden sind unterscheidbar — nur deshalb ist es sicher, das eine zu akzeptieren und das andere nicht. `authz.ErrTupleAlreadyApplied` trägt diese Messung.

**Ein Ereignis, das der Empfänger nicht ausführen kann, ist kein Ereignis.** Eine Mitgliedschaft in OpenFGA zu entfernen heißt, *eine benannte* Relation zu löschen. Der Entfernungspfad staged aber nur die Benutzerkennung — der Konsument hätte raten müssen, und „alle Relationen löschen" wäre eine Vermutung, die Zugriff nimmt, den niemand nehmen wollte. `DELETE … RETURNING role` holt die Rolle aus derselben Anweisung heraus; der Rollenwechsel tut dasselbe für die Vorrolle.

**Anfragekörper und Ereignisnutzlast sind zwei Verträge, nicht einer.** Sie hatten denselben Typ, also konnte ein Aufrufer `previous_role` mitschicken — und damit dem Konsumenten sagen, welches Tupel zu löschen ist. Das ist die Antwort der Datenbank, nicht die des Aufrufers. `memberRequest` und `MemberEventPayload` sind jetzt getrennt, und der Angriff ist nicht mehr *ausdrückbar*: das Feld existiert im Anfragetyp nicht. Ein Vertragstest hält die Namen und Feldschlüssel beider Seiten in Deckung — sie importieren einander bewusst nicht, sonst zöge die HTTP-Fläche in den Sync-Dienst.

**Führerwahl über Advisory-Lock, und warum die Sitzung die Wahl ist.** Zwei Eigenschaften des Locks tragen den ganzen Entwurf: er gehört zur *Sitzung*, nicht zur Transaktion — deshalb hält der Wähler eine eigene, festgepinnte Verbindung statt eine aus dem Pool; und er wird beim Ende der Sitzung freigegeben, aus welchem Grund auch immer. Ein abgestürzter Anführer gibt die Rolle frei, ohne dass jemand seinen Tod bemerken muss. Genau das muss ein Lease mit Zeitüberschreitung über Heartbeats und Uhrenannahmen nachbauen. Damit ist auch die Lebendigkeitsprüfung trivial: der Lock lebt exakt so lange wie die Verbindung, also *ist* „lebt die Verbindung" dieselbe Frage wie „halte ich die Rolle". Kein zweiter Zustand, der widersprechen könnte. `pg_try_advisory_lock`, nicht die blockierende Form: ein Wartender hielte Verbindung und Goroutine so lange, wie der Anführer lebt, und übernähme zu einem Zeitpunkt, den niemand gewählt hat.

**Eine unentscheidbare Wahl ist kein „nein".** `ProcessBatch` verwarf den Fehler der Führerwahl und meldete „kein Anführer" — mit dem prozesslokalen Wähler konnte das nie eintreten, mit dem Datenbank-Wähler jederzeit. Der Daemon hätte weiter fröhlich leere Stapel gemeldet, während die Warteschlange nie geleert wird: dasselbe Bild, das eine ruhige Warteschlange malt. Jetzt erreicht der Fehler den Aufrufer.

**Zwei Befunde am Widerrufs-Store, beide von der Migration aufgedeckt.** Erstens schrieb er auf einem Pool-Handle ohne Mandantenbereich — seit Migration 015 weist die `WITH CHECK`-Klausel die Zeile schlicht ab. `celldir.ExecInTenantTx` ist der eine Eigentümer dieses Bereichs, hier wie überall. Zweitens las `List` **alle** Mandanten und filterte danach in Go. Der Filter war korrekt, aber die Daten der anderen Organisationen waren zu diesem Zeitpunkt bereits im Prozess. RLS kann sie nur draußen halten, wenn die Abfrage den Bereich trägt — `ListActive` ist deshalb eine eigene, gescopete Abfrage und kein Filter über `FetchAllActive`. Der zellweite Lesezugriff bleibt, wofür er da ist: den Durchsetzungspfad.

**Reihenfolge beim Widerrufen: schreiben, protokollieren, dann den Cache füllen.** Der Cache kommt zuletzt, weil er der einzige Schritt ohne Rücknahme ist. Ein im Speicher gesperrter Principal ohne Datenbankzeile wird beim nächsten Resync wieder freigegeben; einer in der Datenbank, aber noch nicht im Speicher, ist einen Moment länger erlaubt — das ist die Richtung, die sicher scheitert. Beim Aufheben wird der Cache **nicht** korrigiert: er wird aus dem Store aufgefrischt, und Zugriff vor der dauerhaften Aufzeichnung der Entscheidung zurückzugeben, wäre die falsche Richtung.

| Mutation | |
|---|---|
| Wiederzustellung gilt nicht mehr als Erfolg | rot |
| jeder Fehler gilt als „schon angewendet" | rot |
| Store kommt aus dem Ereignis statt aus dem Verzeichnis | rot |
| Rollenwechsel löscht die alte Beziehung nicht | rot |
| unentscheidbare Führerwahl bleibt still | rot |
| `pg_try_advisory_lock` durch `true` ersetzt | rot — beide Instanzen führten |
| ein Lock-Schlüssel für alle Rollen | rot — unabhängige Warteschlangen blockierten sich |
| Widerruf ohne Mandantenbereich geschrieben | rot |
| Widerruf erreicht den Durchsetzungspfad nicht | rot |
| Aufheben eines nie erteilten Widerrufs meldet Erfolg | rot |
| Entfernung staged keine Rolle | rot |
| Ereignisnamen der beiden Seiten driften auseinander | rot |
| Nutzlast doppelt kodiert | rot |

**Was der Aufrufer nicht mehr fälschen kann, prüft kein Test:** dass ein Aufrufer `previous_role` diktiert, ist nach der Typtrennung nicht mehr ausdrückbar — die Mutation übersetzt nicht. Ein Typ, der den Fehler unmöglich macht, ist stärker als ein Test, der ihn fängt.

#### 10.3-V Ergebnis: W1.4 — der Login-Pfad, und ein Test, der sich mit sich selbst einig war

**Der Signaturprüfer hätte jede echte Anmeldung blockiert.** Zitadels eigenes `pkg/actions/signing.go` sendet `ZITADEL-Signature: t=<unix>,v1=<hex>` und rechnet HMAC-SHA256 über `<timestamp>.<body>`, mit 300 s Toleranz. Unser Prüfer las `X-Zitadel-Signature`, rechnete über den Body **allein** und akzeptierte ein `sha256=`-Präfix — das ist GitHubs Webhook-Konvention. Da die Hooks fail-closed sind, heißt „jeder echte Aufruf wird abgewiesen" schlicht: **niemand kann sich anmelden.**

**Und warum das niemandem auffiel, ist der eigentliche Befund.** Der Test erzeugte die Signatur mit derselben falschen Rezeptur, die der Prüfer erwartete. Er war grün, weil er sich mit sich selbst einig war und mit sonst niemandem. Beim Durchmutieren ist mir derselbe Fehler in meiner *eigenen* Neufassung passiert: `ComputeSignatureHeader` teilt sich die Implementierung mit dem Prüfer, also überlebte „Zeitstempel nicht mitsignieren" — beide Seiten änderten sich gleich. Erst ein außerhalb des Pakets gerechneter fester Vektor (`3b290a89…` für `1700000000.{"hook":"x"}`) bindet das Verfahren an Zitadel statt an sich selbst. Ein Vertragstest, der beide Seiten des Vertrags aus derselben Funktion holt, prüft keinen Vertrag.

**Kein Replay-Schutz.** Der Zeitstempel wird genau deshalb mitsigniert; wir werteten ihn nicht aus. Ein mitgeschnittener Body war so lange gültig wie der Signierschlüssel. Das Fenster gilt jetzt in beide Richtungen — ein Zeitstempel weit in der Zukunft ist ebenso unmöglich wie einer weit in der Vergangenheit, und ihn abzuweisen kostet nichts, was dieselbe Toleranz nicht ohnehin für Uhrendrift erlaubt.

**Drei Fail-Open-Pfade durch Auslassung.** Ein `nil`-Prüfer hieß „keine Signaturprüfung nötig"; ein `nil`-Evaluator wurde zu einem Auswertungsfehler, der auf einer nicht-kritischen Route Durchlass bedeutet; und ein Evaluator, der `(nil, nil)` lieferte, wurde als „erlaubt" gelesen. Alle drei sind jetzt unmöglich statt unwahrscheinlich: der Konstruktor paniert, und „keine Entscheidung" ist ein Fehler.

**D5 zu Ende gebracht — die Route besitzt Hook-Typ und Kritikalität.** `RuleNameOf` fiel auf `req.HookType` zurück, also aus dem Body: wer `post_authentication` behauptete, bekam Fail-Open auf einem Pre-Auth-Gate. Vier Routen, je eine pro Hook-Typ, Kritikalität als Konstante der Route. Ein Body, der einer anderen Route widerspricht, wird abgewiesen und als Fehlkonfiguration protokolliert — die beiden stillen Auflösungen wären beide falsch. Die `nonCriticalRules`-Tabelle ist gelöscht: **zwei Eigentümer derselben Regel, einer davon vom Absender beschreibbar.** Dabei fiel ein direkter Widerspruch zwischen Code und Spezifikation auf: `pre_token_creation` stand als fail-open, plan6 §D5 verlangt fail-closed. Ein Token ist genau das, was man nicht zurücknehmen kann.

**Das 500-ms-Budget war ein Angebot, keine Grenze.** `context.WithTimeout` begrenzt nur Arbeit, die den Kontext liest — und bis auf die GitHub-Regel sind alle Regeln reine Funktionen, die ihn nie ansehen. Die Auswertung läuft jetzt in einer eigenen Goroutine, und die Überschreitung ist ein Auswertungsfehler, der durch dieselbe Kritikalitätsweiche läuft.

**Zwei Regeln waren mit ihrer Verdrahtung unbrauchbar.** `github_upstream_policy` las eine In-Memory-Karte, die kein Produktionspfad je füllte — sie wies also jede GitHub-Föderation ab, ohne dass jemand eine hätte freischalten können. Migration 016 legt die Allowlist auf die Organisation, und `PATCH /api/v1/tenants/{id}` macht sie bedienbar: keine neue Route, keine neue Permission. **Die Richtung ist dabei der Punkt** — die Organisation ist unsere, die GitHub-Organisation ist nur ein akzeptierter Nachweis, ihr beizutreten. Umgekehrt läge unsere Mandantengrenze in einem Namensraum, in dem Namen freigegeben und neu vergeben werden, in dem ein Mensch vielen Organisationen angehört und in dem ein Okta-Kunde gar keinen Mandanten hätte.

**Und ein Loch, das erst beim Bauen der Allowlist sichtbar wurde:** ein `github_org`, das vorhanden aber leer ist, gilt dem Nutzlastleser nicht als fehlend — und hätte einen leeren Eintrag in der Allowlist getroffen. Zwei Wächter, weil jeder allein eine Anmeldung durchließe, die keine Organisation nennt, autorisiert von einer Liste, die auch keine nennt.

**`break_glass_audit` schrieb kein Audit.** Die Regel meldete ihren „SECURITY ALARM" nach stderr — das ist kein Datensatz, sondern die Hoffnung, dass jemand stdout einsammelte. Jetzt geht der Eintrag ins Ledger, **vor** der Freigabe, und ein fehlgeschlagener Schreibvorgang verweigert die Anmeldung. Der Einwand liegt nahe: Break-Glass ist der Notfallpfad, darf der von der Datenbank abhängen? Er hängt ohnehin von ihr ab — ein Break-Glass-Login administriert genau diese Datenbank, und ist sie unerreichbar, verwaltet die Anmeldung nichts. Verweigern kostet also nichts, was sonst möglich gewesen wäre; Erlauben kostet den einzigen Beweis, dass es geschah. Ein Break-Glass-Konto ist in Zitadel instanzweit und trägt womöglich keine Organisation; der Eintrag läuft dann auf den zellweiten `shared`-Mandanten, den Migration 008 bereits kennt — die Anmeldung deswegen zu verweigern, würde den Instanz-Eigentümer aus dem Notfallpfad aussperren.

| Mutation | |
|---|---|
| Zeitstempel nicht in die HMAC-Eingabe | rot |
| Trennzeichen aus der HMAC-Eingabe | rot |
| Replay-Fenster entfernt | rot |
| nur die Vergangenheit geprüft | rot |
| `hmac.Equal` durch einen Längenvergleich | rot |
| fehlende Signatur durchgelassen | rot |
| Kritikalität der Route ignoriert | rot |
| Body darf den Hook-Typ bestimmen | rot |
| Route überschreibt den Hook-Typ nicht | rot |
| Budget nur angeboten, nicht durchgesetzt | rot |
| „keine Entscheidung" heißt erlauben | rot |
| `pre_token_creation` wieder fail-open | rot |
| ein Hook-Typ ohne Route bleibt unbemerkt | rot |
| Break-Glass ohne Aufzeichnung erlaubt | rot |
| Break-Glass-Eintrag erreicht das Ledger nicht | rot |
| leere GitHub-Organisation akzeptiert | rot |
| leerer Allowlist-Eintrag akzeptiert | rot |
| PATCH überschreibt ungenannte Felder | rot |

**Offen und benannt:** welche Regel auf welchem Hook ankommt, weiß heute niemand — eine Allowlist erlaubter Regeln pro Hook-Typ wäre der nächste Schritt von D5, aber ich müsste sie erfinden, und Raten ist genau das, was dieser Abschnitt vermeiden sollte. Sie gehört geschlossen, sobald eine echte Zitadel-Action konfiguriert ist und man beobachten kann, was tatsächlich ankommt. → **T-10.3**

Ebenfalls benannt: `inTenantTx` existiert jetzt in `identity/api` und `identity/revocation` in zwei gleichen Fassungen. Ich habe keine dritte hinzugefügt — die Adapter des Login-Pfads liegen deshalb in `identity/api` —, aber der eine Eigentümer dieses Musters wäre `celldir`. → **T-10.4**

#### 10.3-W Ergebnis: die Naht — was zwei Hälften mit Tests und keinem Test dazwischen verbergen

**Die Rollenprüfung existierte und stand auf der falschen Seite.** `POST /members` prüfte nur, dass `role` nicht leer ist. Das Modell lässt auf `type tenant` genau `owner`, `admin` und `member` direkt zu; `operator`, `manager`, `self_user` und `support` sind berechnet, und `break_glass_operator` darf laut core.fga nie in den Store geschrieben werden. Ein `{"role":"operator"}` bekam also 201, die Zeile wurde committet, das Ereignis gestaged — und erst der Projektor lehnte ab, drei Wiederholungen später, in einem anderen Prozess. Das Mitglied hatte eine Zeile und keine Autorisierung, und auf dem Anfragepfad hatte nichts widersprochen. `spolicy.ValidateTuple` war die ganze Zeit in dieselbe Binärdatei kompiliert.

Behoben mit `ValidateMembershipRole` auf denselben erzeugten Daten — und die Mitgliedsrollen werden *abgeleitet*, nicht aufgezählt: eine Liste im Code wäre eine zweite Quelle neben dem Modell, und genau die driftet. Sichtbar war die Drift schon: `target/rules.go` führt `release-manager` als privilegierte Rolle, und das ist eine Relation auf `channel`.

**`tenant:` wurde in zwei Paketen buchstabiert.** Der Projektor baute `"tenant:" + id`, die API hätte `"tenant"` nennen müssen. Beide lesen die Konstante jetzt aus `shared/policy` — kein Vertragstest nötig, weil es nur noch eine Schreibweise gibt.

**Die Naht lief zum ersten Mal — und schlug fehl.** Der neue Test in `identity/test/seam` führt HTTP → Outbox → Konsument → echtes OpenFGA aus, mit dem **echten** Modell: `openfga/cli model transform --file fga.mod` übersetzt die vier `.fga`-Dateien, die Rezeptur lädt das Ergebnis frisch hoch. Kein eingechecktes JSON, das driften könnte, und kein von Hand nachgebautes Minimalmodell — die bisherigen Vertragstests prüften gegen ein solches und damit gegen ihre eigene Annahme.

Beim ersten Lauf kamen null Tupel an, **ohne Fehler**. Der Grund ist der, vor dem der Store in seinem eigenen Kommentar warnt: `GetPendingEvents` liest mandantenübergreifend, und nur `identity_outbox_worker` hält die Policy dafür. Unter jeder anderen Rolle *filtert* row level security, statt abzulehnen — die Abfrage liefert null Zeilen und keinen Fehler. Ein Daemon auf der falschen Rolle meldet also für immer gesunde leere Stapel, während jede Mitgliedschaftsänderung unangewandt liegen bleibt. Genau das Bild, das eine geleerte Warteschlange malt.

Daraus wurde `sync.VerifyDrainRole`: der Daemon prüft beim Start `current_user` gegen `identity_outbox_worker` und startet sonst nicht. Der Namensvergleich ist nicht spröde — Migration 011 vergibt die Policy an diesen Namen, der Name *ist* die Regel.

**Die Dead-Letter-Queue lag im Arbeitsspeicher.** Ein erschöpftes Ereignis wanderte in eine Prozess-Map, und die Zeile wurde `processed` markiert. Beide Hälften falsch in dieselbe Richtung: die Zeile behauptete, das Ereignis sei erledigt, und der einzige Beleg für das Gegenteil starb mit dem Prozess — kein Poll brachte es zurück. `GetDLQCount` las die Länge dieser Map und meldete deshalb auf jeder Instanz `0`, die nicht selbst etwas verworfen hatte; das ist die Zahl, die ein Alarm als gesund liest. Migration 017 gibt dem Status `dlq` eine Zeile mit `failed_at` und `last_error`, `ReplayDLQ` liest aus dem Store statt aus dem Prozess, und `DLQDepth` ist eine Abfrage, die scheitern kann.

Nebenbei: der Index für den heißen Pfad ist jetzt partiell über `status = 'pending'`. Tote Briefe sammeln sich sonst im selben Index und werden bei jedem Scan übersprungen.

**identity-sync bekommt `/healthz` und `/readyz`.** Von außen sieht ein Standby, der korrekt nichts tut, genauso aus wie ein Anführer, der aufgehört hat zu leeren. `/readyz` misst den letzten Poll, der *sauber* zurückkam — nicht den letzten Versuch: ein einzelner Fehlschlag ist normal und dürfte keine gesunde Instanz aus dem Dienst nehmen, eine anhaltende Ursache lässt das Fenster verstreichen. Und der Nomad-Job ist geschrieben: seine Begründung („druckt und kehrt zurück") war überholt, und sein Rat „single-allocation" in der Gegenrichtung falsch — mit dem Advisory-Lock ist `count = 2` mit `distinct_hosts` richtig, und `IDENTITY_INSTANCE_ID` kommt aus `NOMAD_ALLOC_ID`, dem einzigen Wert, der pro Allocation wirklich verschieden ist.

| Mutation | |
|---|---|
| API prüft die Rolle nicht | rot |
| berechnete Relationen gelten als zuweisbar | rot |
| `break_glass_operator` wird Mitgliedsrolle | rot |
| Objekttyp weicht zwischen den Hälften ab | rot |
| DLQ wieder als `processed` markiert | rot |
| Ursache wird nicht aufgezeichnet | rot |
| DLQ-Lesen trifft die falsche Menge | rot |
| Replay schließt das Ereignis nicht | rot |
| Drain-Rolle wird nicht geprüft | rot |

#### 10.3-Z Ergebnis: W2.2 — Ratenlimits bekommen Zahlen, einen Ort und eine Quelle

**Es gab keine Ratenbegrenzung. Nirgends.** Der Limiter existierte, war getestet und lief an keiner Stelle: die einzigen Zahlen waren zwei Konstanten in `token/exchange.go`, und dieses Paket ist auf keiner Route montiert. `RateLimitCostCatalog` wurde seit jeher erzeugt und **von niemandem gelesen**.

**Die stille Lücke im Typ.** `RateLimitRequest` trug die Limits als Zahlen vom Aufrufer, und `if req.TokenLimit > 0` übersprang jede Dimension ohne Zahl. „Limit vergessen" und „kein Limit gewollt" waren damit dasselbe Ergebnis, und nur eines davon war beabsichtigt. Ersetzt durch `Subject` — ein Struct der deklarierten Dimensionen — plus aufgelöste Klassen aus dem Katalog: eine Dimension ohne Zahl ist jetzt ein Generierungsfehler, und eine Anfrage, die ihre Klasse nicht attribuieren kann, ist ein Verdrahtungsfehler statt eines Freifahrtscheins.

**Zwei Limitierungspunkte, nicht einer.** `RL-pre` pro Quelladresse **vor** der Tokenprüfung, weil eine unauthentifizierte Flut sonst pro Anfrage einen JWKS-Lookup und eine Signaturprüfung kostet, bevor sie abgewiesen wird. `RL-post` pro Token und Mandant **nach** der Kette, weil es dort erst einen Principal gibt, dem man etwas zurechnen kann.

**Und die Korrektur, die der Integrationstest erzwungen hat:** ich hatte den Vorfilter zunächst mit der Klasse `authn` gebaut. Die ist eng — sechzig pro Minute —, weil jeder Anmeldeversuch teuer ist. Vor *jede* Anfrage gesetzt erdrosselt sie ein Konsolen-Frontend, das eine Seite aus dreißig Lesezugriffen rendert: der Vorfilter band, bevor irgendein Leselimit überhaupt greifen konnte. Die beiden schützen verschiedene Dinge und können sich keine Zahl teilen. Daraus wurde die Klasse `edge` (1 200/min pro Adresse), und `authn` bleibt, wofür plan6 sie vorsah — die Anmeldeendpunkte selbst.

**`hook` ist eine Nebenläufigkeitsgrenze, keine Rate**, und das ist der Grund für die eigene Klasse. Die L4-Hooks liegen auf dem Anmeldepfad mit 500-ms-Budget; was sie umbringt, ist nicht die Anzahl pro Minute, sondern wie viele gleichzeitig auf eine langsame Abhängigkeit warten. Ein Eimer pro Minute merkt das erst, wenn das Budget längst gerissen ist. Die Grenze ist prozesslokal, und auch das ist eine Entscheidung: eine flottenweite Semaphore ließe die freie Kapazität einer Instanz Arbeit auf einer anderen zulassen, die keine hat. Voll heißt hier abweisen statt anstellen — Warten verbraucht genau das Budget, das der Endpunkt schützen soll, und Zitadel hat dann längst aufgegeben.

**Der Brute-Force-Zähler ist gelöscht.** `RecordLoginFailure`, die progressive Verzögerung, der Alarmschwellwert — und ein sorgfältig begründeter Overflow-Fix („bei 38 Fehlversuchen negativ, ab 59 dauerhaft null") für Code, den **niemand aufrief**. Anmeldungen finden bei Zitadel statt, und die `lockout_policy`-Regel liest dessen Zähler; unserer war ein zweiter, den niemand hochzählte. Gelöscht statt aufgehoben: ein ungetesteter zweiter Zähler ist genau das, was in Eile verdrahtet wird und dann dem ersten widerspricht.

**Und das Limit im Token-Exchange fiel mit.** Beim Umstellen zeigte sich, dass die Engine an dieser Stelle oft gar keine Organisation kennt — die `write`-Klasse konnte sie nicht zählen. Zwei Limitierungspunkte für dieselbe Operation, von denen einer sich nicht attribuieren kann, sind die Duplikation, die dieser Bericht sonst entfernt. Der Endpunkt wird begrenzt, wenn er montiert wird, an der Schicht, die Adresse und `client_id` hat.

| Mutation | |
|---|---|
| unattribuierbare Anfrage wird durchgelassen | rot |
| Kosten aus dem Katalog werden ignoriert | rot |
| Dimension fällt aus dem Schlüssel | rot |
| Nebenläufigkeit ohne Grenze | rot |
| Ratenklasse als Semaphore akzeptiert | rot |
| Vorfilter lässt alles durch | rot |
| Nach-Auth-Limit greift nicht | rot |
| `Retry-After` fehlt | rot |
| Klassenbudget nicht über Instanzen geteilt | rot |
| Nebenläufigkeitsgrenze um eins zu groß | rot |
| fehlende Klasse wird durchgelassen | **überlebt** — unerreichbar, siehe unten |

**Ein Wächter, der überlebt, und warum er bleibt.** Die Klassenprüfung in `rateLimitAfterAuth` läuft *nach* der Registry-Prüfung, die einen unbekannten Permission-Namen bereits fail-closed abweist — und policygen verlangt für jede Permission eine Klasse. Der Zustand „in der Registry, aber ohne Klasse" ist damit nicht herstellbar; die Mutation überlebt, weil kein Test ihn erzeugen kann. Das steht hier, statt die Zeile stillschweigend zu löschen: eine zweite Verteidigungslinie zu entfernen, weil die erste sie unerreichbar macht, ist genau der Schritt, nach dem man sich später fragt, warum niemand etwas gemerkt hat.

Bei der Nebenläufigkeitsgrenze war es zunächst dasselbe — die Formprüfung überlebte, weil jede Ratenklasse ohnehin ein Concurrency-Limit von null hat und der *zweite* Wächter („lässt niemanden herein") sie fing. Dort ließ sich der erste erreichbar machen: eine Klasse, die Nebenläufigkeit *und* eine Ratendimension zählt, kann aus der Policy nicht kommen, aber der exportierte Konstruktor nimmt entgegen, was man ihm gibt. Mit diesem Test ist die Formprüfung gedeckt.

**Zwei Testfehler, die dabei auffielen** — beide von der Art, die grün bleibt und nichts misst. Der Lesebudget-Test erzeugte pro Anfrage ein *neues* Token, also je einen eigenen Eimer: das Budget wäre nie ausgeschöpft worden, und der Test hätte gemeldet, dass ein Limit wirkt, während er nichts maß. Und der Vorfilter-Test lief zunächst gegen die falsche Klasse, was die `edge`-Korrektur oben überhaupt erst sichtbar machte.

---

#### 10.3-Y Ergebnis: W2.1 — geteilter Zustand, und was dabei nicht trug

**Der DPoP-Replay-Speicher war prozesslokal, und das ist keine Performancefrage.** `cmd/identity-api` baute `dpop.NewMemoryReplayStore`. Ein abgefangener Beweis ist damit einmal *pro Instanz* verwendbar: bei zwei Instanzen wird aus „genau einmal" „zweimal", und genau das ist die Eigenschaft, für die der Beweis existiert. Das ist der Teil von W2.1, der jetzt trägt — gemessen über zwei Speicher an einem echten Valkey.

**Vier Ports, kein Adapter, keine Bibliothek.** `ratelimit.RedisClient`, `dpop.RedisSetNXClient`, `revocation.RedisPubSubRaw` waren sauber geschnitten und alle drei unimplementierbar; `go.mod` kannte keinen Redis-Client. `identity/valkey` ist jetzt die eine Stelle, die die Bibliothek kennt, mit Übersetzungszusicherungen gegen jeden Port — ein Adapter, der von seinem Port abdriftet, scheitert am Bau statt am Kompositionspunkt.

**Die Ansible-Rolle druckte „Valkey role initialization"** und stand nicht in `site.yml`. Sie ist jetzt echt: Bind ans WireGuard-Interface, `requirepass` aus Vault, `maxmemory-policy noeviction` — nicht `allkeys-lru`, denn ein verworfener `jti` heißt, derselbe Beweis ist wieder verwendbar. Keine Persistenz, und das ist eine begründete Entscheidung statt einer Auslassung: der `jti` lebt 70 Sekunden (`MaxProofAgeSeconds + 10`), der Beweis ist 60 Sekunden frisch, ein Neustart öffnet also höchstens ein 70-Sekunden-Fenster für Beweise, die ohnehin fast abgelaufen sind.

**Was zunächst nicht trug — und warum es doch trägt.** Der Nahttest kappte die Abonnentenverbindung serverseitig, und die Zustellung kam nicht zurück: nicht nach 5, nicht nach 45 Sekunden. Auf dieser Grundlage habe ich die Widerrufs-Propagation bewusst *nicht* montiert und den Befund als T-11.1 notiert.

Die Diagnose, die ich damals schuldig blieb, löst ihn auf, und die Antwort ist keine Fehlerbehebung: **Pub/Sub ist at-most-once.** Der Test veröffentlichte unmittelbar nach dem Kill, also in das Wiederverbindungsfenster hinein — und eine Nachricht an einen Kanal ohne Abonnenten ist nicht verzögert, sondern weg. Danach konnte kein Warten der Welt sie noch liefern. Isoliert gegen den Treiber und dann gegen diesen Baum zeigte sich beide Male: die Wiederverbindung greift, die Zustellung läuft weiter.

**Die Folge ist größer als der Test.** Die Propagation über Pub/Sub ist ein *Beschleuniger*, keine Zusicherung. Der 30-Sekunden-Resync ist die Zusicherung, und er fängt genau den Widerruf, der in ein Wiederverbindungsfenster gesendet wurde. Den Resync als Rückfallebene für einen kaputten Kanal zu lesen, hatte es andersherum.

Der Kanal ist damit montiert. Und der Beinahe-Schaden gehört genannt: ein Test, der ein *internes* Merkmal um eine Race herum beobachtete, hätte fast eine bewusste Verlangsamung des Kill-Switches gekauft. Der Test misst jetzt die Zustellung — die Eigenschaft — statt der Fahne.

Der Reihe nach ist dabei viermal etwas kaputtgegangen, was ich vorher geglaubt hatte: dass die Abo-Schleife nur eine Wiederverbindung braucht; dass `Healthy()` Echtzeit-Propagation melden könne (der Treiber repariert darunter, die Fahne kann es nicht sehen); dass 5 Sekunden zu knapp seien (45 ändern nichts); und schließlich, dass überhaupt ein Defekt vorlag. Jede Korrektur kam aus einer Messung, keine aus dem Nachdenken — die letzte erst, nachdem ich die Diagnose zu Ende geführt hatte, statt bei „45 Sekunden, nichts" stehenzubleiben.

**Nebenbei erledigt: T-10.4.** `inTenantTx` stand in drei Fassungen — `api`, `revocation`, `scim` — und W1.3 hätte fast eine vierte gebracht. `celldir.InTenantTx` ist jetzt der eine Eigentümer, was richtig ist, weil eine Kopie, die den Bereich vergisst, nicht scheitert: sie liest eine leere Tabelle.

| Mutation | |
|---|---|
| `SetNX` meldet immer Erfolg | rot |
| Zähler wird nicht geteilt | rot |
| Nachricht wird nicht zugestellt | rot |
| widersprechende Konfiguration akzeptiert | rot |
| unbekannter Modus fällt auf Speicher zurück | rot |
| Wiederverbindung nach Verbindungsabbruch | rot |

Die drei Mutationen im Wiederverbindungspfad, die in der ersten Runde überlebten, sind mit dem korrigierten Test gedeckt.

**Die ausdrückliche Wahl** `IDENTITY_SHARED_STATE=valkey|memory` statt „eine Adresse ist gesetzt, also wird sie benutzt": eine fehlende Umgebungsvariable ist keine Entscheidung. `memory` protokolliert bei jedem Start auf WARN, was es kostet, und eine Konfiguration, die sich selbst widerspricht — Adresse gesetzt, Modus `memory` — wird beim Start abgewiesen.

---

#### 10.3-X Ergebnis: W1.3 — der Katalog lernt, wer fragt

**Der Katalog beschrieb bisher nur Principals, und tat so, als sei das alle.** `min_trust_level`, `step_up`, `impersonation_allowed` und `requires_signature` sind Eigenschaften eines verifizierten Principals. Der Aufrufer der SCIM-Oberfläche ist keiner: er ist der Provisionierungs-Konnektor eines Kunden mit einem Bearer-Token, das wir *ihm* ausgestellt haben. Ihn als „L1-Mensch" einzutragen wäre eine Beschreibung gewesen, die schlicht falsch ist — und eine Katalogzeile, die wie eine Kontrolle aussieht, ohne eine zu sein.

`policy/actors.yaml` sagt jetzt pro Akteurstyp, ob er einen Principal mitbringt, und `actor_type` an der Permission entscheidet, ob die vier Felder überhaupt etwas bedeuten. Die Wirkung ist erzwungen, nicht dokumentiert: **policygen weist eine Partner-Permission zurück, die einen Trust-Level nennt**, und drei Prüfstellen sind entsprechend nachgezogen — die Fleet-Registry überspringt sie, der Linter prüft Relation und Trust-Level nur für Principal-Akteure, und `api.VerifyRoutes` weist eine Route ab, die eine Partner-Permission auf die Principal-Fläche holt. Umgekehrt weist `scim.VerifyOperations` eine SCIM-Operation ab, die eine Principal-Permission nennt.

Der Weg dahin hat drei eigene Fehler gezeigt, alle von Tests gefangen: der Generator gab `ActorType` zunächst gar nicht aus, also war jeder Wert leer, also übersprang die Registry *alles* — 500 auf jeder Route. Der Vertragstest für Akteure verlangte zu jedem Typ ein `principal.ActorType`; für einen Partner darf es das gerade nicht geben, sonst könnte die Kette einen Trust-Level für ihn benennen. Und `shared/boundaries_test.go` fing einen Vergleich auf `MinTrustLevel` im Generator, wo das Feld nur YAML-Text ist.

**Der Verzeichnisspeicher lag im Arbeitsspeicher, und das ist keine Haltbarkeitsfrage.** `CreateUserIfAbsent` trägt den Account-Takeover-Wächter: eine eingehende Person, deren E-Mail zu einem Datensatz passt, deren `externalId` aber auf jemand anderen zeigt, wird abgewiesen. Prozesslokal gehalten ist dieser Schutz **umgehbar, indem man die andere Instanz trifft** — sie kennt den ersten Datensatz nicht, legt ein zweites Konto für dieselbe E-Mail an und meldet Erfolg. Migration 018 verlegt beide Eindeutigkeitsregeln in die Datenbank, mandantengebunden, damit zwei Kunden denselben Auftragnehmer haben können.

**Ein Kunde konnte gar kein Token bekommen.** `SetToken` hatte keinen Produktionsaufrufer — die Oberfläche wäre auch montiert unbenutzbar gewesen. Die Ausgabe läuft jetzt über eine L1-Route mit L3, Step-up und Signatur, und dabei ist ein Fund aufgetaucht, den ich beim Planen nicht erwartet hatte: **die Idempotenz-Schicht schreibt den Antwortkörper jeder erfolgreichen Mutation 24 Stunden lang in `idempotency_keys`.** Das Klartext-Token hätte dort gelegen, lesbar über jede Verbindung, die die API-Fläche hält. `Route.SecretResponse` unterdrückt das Aufzeichnen; ein Replay bekommt 409 statt eines leeren Körpers, der wie eine zweite erfolgreiche Ausstellung aussähe. Ein zweites Token wird nicht stillschweigend geprägt: erst widerrufen, dann neu ausstellen — zwei gültige Tokens ließen niemanden sagen, welches der Konnektor gerade präsentiert.

**Die Discovery-Endpunkte beschreiben, was der Server tut.** Ein Konnektor liest sie zuerst und handelt danach, ohne nachzufragen; `bulk` oder `sort` anzukündigen, weil es vollständig aussieht, hieße Okta Anfragen schicken zu lassen, die dieser Server mit 404 beantwortet.

| Mutation | |
|---|---|
| Geheimnis wird doch zwischengespeichert | rot |
| zweites Token wird stillschweigend ausgestellt | rot |
| Token wird im Klartext statt als Digest gespeichert | rot |
| Übernahme-Wächter abgeschaltet | rot |
| Discovery verspricht Bulk | rot |
| Partner-Permission auf der Principal-Fläche erlaubt | rot |
| SCIM-Operation nennt eine Principal-Permission | rot |
| Mutation ohne Ledger-Eintrag | rot |

**Vier davon überlebten zuerst, und alle vier waren Testlücken.** Die schlimmste: mein Geheimnis-Test durchsuchte `idempotency_keys` — aber der Test-Server benutzte den In-Memory-Speicher, schrieb also nie in diese Tabelle und wäre grün geblieben, egal was die Middleware tut. Ein Test, der Abwesenheit dort prüft, wo nie etwas hinkommt. Ebenso prüfte die Digest-Zusicherung nur, dass der Klartext *nicht* dasteht; sie sagt jetzt positiv, dass der gespeicherte Wert der SHA-256-Digest des ausgegebenen Tokens **ist**.

**Nicht in W1.3, benannt:** Gruppen (plan6 selbst Welle 2 — und eine Gruppe wäre das, was einen Verzeichniseintrag auf eine Rolle abbildet; halb ausgeliefert wäre sie der kürzeste Weg von „der Kunde hat einen Nutzer angelegt" zu „der Kunde hat Autorisierung vergeben"). Outbox-Staging für SCIM, dessen Begründung eben diese Gruppenänderungen sind. Und das Ratenlimit: `identity/ratelimit.MultiLimiter` existiert und ist **nirgends im System montiert** — es nur auf einer Oberfläche anzubringen ließe das System aussehen, als hätte es eines. → **T-10.5**

**Ein bereitgestellter Nutzer trägt keine Autorisierung**, und `identity_scim` bekommt bewusst keinerlei Zugriff auf `tenant_members`: dass Provisionierung keine Rechte vergeben kann, ist damit nicht eine Sache, die wir unterlassen, sondern eine, die nicht geht.

---

**Ein Befund über das Prüfen selbst, zum zweiten Mal:** vier Mutationen meldeten zunächst „überlebt", und drei davon lagen an einem `-run`-Muster, das keinen Test traf — `go test` druckt dann `ok`. Dieselbe Form wie die von Windows blockierten Testbinaries, die `FAIL` ohne `--- FAIL` druckten. Die Prüfschleife erkennt jetzt zusätzlich „kein Test gelaufen". Ein Werkzeug, das Abwesenheit als Erfolg meldet, ist genau das, wonach dieser ganze Bericht sucht.

---

#### 10.3-AA Ergebnis: W2.3 — die Stelle, an der ein Verzeichniseintrag zu einer Rolle wird

**Die Lücke aus W1.3 war Absicht, und sie schließt hier — mit einer Abbildung, die uns gehört.** Der Kunde liefert den Nachweis, wir entscheiden, was er bedeutet: sein Verzeichnis sagt, wer in einer Gruppe ist; ein Operator sagt einmal, welche Rolle diese Gruppe impliziert. Eine nicht abgebildete Gruppe vergibt nichts. Ohne diese Trennung verschafft sich ein Kunde die Rolle, die er möchte, indem er eine Gruppe „owner" nennt — dieselbe Richtung wie bei der GitHub-Allowlist.

Die Trennung ist nicht in Go verzweigt, sondern vergeben: `identity_scim` schreibt `scim_groups` und `scim_group_members`, liest `scim_group_roles` **nur**, und hat auf `tenant_members` weiterhin gar keinen Zugriff. Die Mitgliedschaft schreibt der Sync-Daemon unter seiner eigenen Rolle, gegen eine Abbildung, die ein Mensch mit L3 angelegt hat. Eine Regel, die nur im Code steht, ist eine, um die ein hinzugefügter Codepfad herumläuft — und der Codepfad, der Rollen vergibt, ist der, den ein Angreifer sucht.

**Der Projektor rechnet neu, statt Deltas anzuwenden**, und das ist der Unterschied zwischen richtig und beinahe. Wer aus der Gruppe fliegt, die ihn zum Admin machte, muss auf das zurückfallen, was seine übrigen Gruppen implizieren — nicht die Rolle behalten und nicht die Mitgliedschaft verlieren. Ein Delta kann das nicht ausdrücken, ohne alle anderen Gruppen zu kennen, wäre also genau im interessanten Fall falsch. Nebenbei kostet Redelivery dadurch nichts: dasselbe Ereignis zweimal angewandt erreicht denselben Zustand. Bei mehreren abgebildeten Gruppen gewinnt die höhere Rolle, und `membershipRoleRank` ist der eine Ort, an dem diese Ordnung steht — ein Vergleich über Strings sortierte „admin" über „owner".

**Zwei Schreiber, disjunkte Zeilen.** `tenant_members.source` unterscheidet `admin` von `scim`, und beide Richtungen werden **beantwortet statt stillschweigend überschrieben**: das Verzeichnis überschreibt keine von Hand angelegte Mitgliedschaft, und ein Administrator ändert keine, die aus einer Gruppe folgt (409, mit Hinweis, wo die Änderung hingehört). Die Alternative ist der schlimmste Fehlertyp in diesem System: Ein Operator entfernt jemanden, der nächste Sync setzt ihn zurück, und nirgends steht, warum.

**Doppelmitgliedschaften — die Frage aus der Planung, beantwortet.** Ein Nutzer hält jetzt **eine** Rolle pro Organisation (`uq_tenant_members_tenant_user`); vorher konnte er zwei halten, und niemand hätte sagen können, welche gilt — der Projektor schriebe zwei Tupel, eine Entfernung löschte eins und ließe das andere stehen. **Derselbe Nutzer in mehreren Organisationen bleibt ausdrücklich erlaubt**, das sind Zeilen mit verschiedener `tenant_id`. Die Migration verdichtet vorhandene Duplikate nicht, sie **bricht ab**: eine Migration, die im Zweifel zwei Rollen zu einer zusammenfaltet, entscheidet stillschweigend über Rechte.

**Beide Schreibweisen der Mitglieder-Entfernung werden verstanden** — Oktas `{"op":"remove","path":"members","value":[…]}` und die Filterform aus RFC 7644 § 3.5.2, die Entra und AWS schicken. Ein Server, der nur eine kennt, beantwortet jede Entfernung der anderen Klientel mit 400, und eine Entfernung, die nicht ankommt, ist ein ausgeschiedener Mitarbeiter mit weiterhin gültigem Zugang. Was der Parser nicht ausdrücken kann, weist er zurück, statt es zu nähern.

| Mutation | |
|---|---|
| höhere Rolle wählt die niedrigere | rot |
| nicht abgebildete Gruppe vergibt doch eine Rolle | rot |
| Verzeichnis überschreibt eine Administrator-Mitgliedschaft | rot |
| Administrator ändert eine Verzeichnis-Mitgliedschaft | rot |
| PUT vergisst, wer aus der Gruppe gefallen ist | rot |
| Gruppenlöschung staged niemanden | rot |
| Gruppenänderung wird protokolliert, aber nie gestaged | rot |
| unlesbarer Filter wird genähert | rot |
| Konnektor darf die Abbildung schreiben | rot |
| ein Nutzer hält zwei Rollen in einer Organisation | rot |

**Der Nahttest fand einen echten Defekt, den keine der beiden Hälften finden konnte.** `AddMembers` benutzte `$3` zweimal — einmal als eingefügten Wert, einmal im Vergleich — und PostgreSQL weist eine bloße Select-Liste ohne ableitbaren Typ mit 42P08 zurück. Die Unit-Tests laufen gegen den Speicher-Doppelgänger, die Integrationstests fügen direkt ein; nur der Weg über die echte Oberfläche in die echte Datenbank führt durch diese Zeile. Genau der Befund, für den die Naht existiert.

**Und eine Mutation überlebte zuerst, aus dem Grund, den dieser Bericht am häufigsten findet.** Ein fehlgeschlagener Projektionsversuch landet nach den Wiederholungen in der Dead-Letter-Queue, und `ProcessBatch` meldet Erfolg. Ohne Prüfung der Queue-Tiefe sind „die Gruppe hat nichts vergeben" und „die Projektion ist abgestürzt" dieselbe Beobachtung — jede Zusicherung, die *kein* Tupel erwartet, wäre aus dem falschen Grund grün gewesen. Die Gruppentests drainieren jetzt über eine Hilfsfunktion, die eine nicht leere DLQ als Fehlschlag wertet.

**Nicht in W2.3, benannt:** Ein Gruppenwechsel ändert die Rolle eines *bereits angemeldeten* Nutzers erst, wenn sein Token erneuert wird — die Autorisierungsentscheidung liest zwar frisch aus OpenFGA, ein bereits ausgestelltes Token trägt aber seine Organisation. Für eine sofortige Herabstufung ist der Widerruf der richtige Hebel, nicht die Gruppensynchronisierung. → **T-10.6**

---

#### 10.3-AB Ergebnis: W2.4 — das Ledger bekommt einen Leser, und die erste Prüfung überhaupt

**Sechs Oberflächen schrieben seit W1.1 in ein Protokoll, das niemand lesen konnte.** Jeder Anhang prüfte seinen eigenen Vorgänger; **niemand hatte je das Ganze geprüft**. Migration 012 hatte `identity_api` ausdrücklich alles entzogen und nur `INSERT` zurückgegeben, mit der Begründung, die dort steht: „until those exist the rights they need do not". Migration 020 ist der Moment, in dem das Recht dazukommt — nicht früher.

**Ein gefiltertes Fenster ist kein Kettensegment, und deshalb gibt es zwei Routen.** `VerifyChainFrom` braucht einen lückenlosen Abschnitt *und* den Eintrag davor; chain.go sagt es selbst: „An attacker who may choose the anchor can validate any suffix he likes by anchoring past the part he altered." Die naheliegende Alternative — eine Route mit einem `verifiable`-Schalter — wäre schlechter: eine Zusage, die ein Klient prüfen *muss*, wird genau einmal übersehen.

| | `GET …/audit` | `GET …/audit/segment` |
|---|---|---|
| Frage | „was ist passiert?" | „ist es unversehrt?" |
| Reihenfolge | neueste zuerst, filterbar | aufsteigend, lückenlos, ungefiltert |
| Felder | Projektion **ohne** `prev_hash`/`canonical_json` | vollständig gesiegelt + Anker |

Die Weglassung ist die eigentliche Kontrolle: aus der Operatorenansicht lässt sich **kein einziger Hash berechnen**. Eine Antwort, die man nicht prüfen kann, darf nicht so aussehen, als könnte man es — und hier kann man es nicht bloß nicht, man kann es nicht einmal versuchen.

**Der Anker kommt aus der Zeile, nie aus der Anfrage.** Beim Bauen fiel auf, dass sich die naheliegende Mutation („Anker aus dem Query-Parameter") gar nicht schreiben lässt: `anchorAt` sieht die Anfrage nicht. Das ist kein Zufall, sondern die Signatur, die die Regel trägt. Und `after_sequence=0` behauptet nicht Genesis, sondern prüft es — sobald irgendwann archiviert wird, wäre ein Genesis-Anker eine Zusage über ein Präfix, das niemand mehr nachrechnen kann.

**Bei gebrochener Kette wird gemeldet, nicht verweigert.** Die Antwort trägt `intact: false` samt Divergenzposition und Alarm im Log — und die Einträge weiterhin. Ein 500 hieße: wer eine Zeile korrumpiert, blendet den Operator vollständig, mit derselben Handlung, die das Lesen dringend gemacht hat. **Das Urteil des Servers ist nicht der Beweis.** Es ist ein Rauchmelder; der Beweis ist, dass der Klient mit Anker und `canonical_json` selbst nachrechnet, und der Test tut genau das statt dem Server zu glauben.

| Mutation | |
|---|---|
| Anker aus der falschen Zeile gelesen | rot |
| archiviertes Kettenstück als Genesis ausgegeben | rot |
| Segment wird nie geprüft | rot |
| Divergenz als „unversehrt" gemeldet | rot |
| gebrochene Kette verbirgt das Protokoll | rot |
| Segment absteigend ausgeliefert | rot |
| Operatorenansicht liefert die Prüffelder mit | rot |
| Filter werden ignoriert | rot |
| Cursor auf einer kurzen Seite angeboten | rot |
| unlesbarer Cursor als Anfang gelesen | rot |
| API-Rolle darf das Ledger umschreiben | rot |
| kritische Route protokolliert nichts | rot |

**Eine überlebte zuerst, und der Grund war eine ungeprüfte Zusage.** Der Paging-Test lief mit `limit=1`, wo jede Seite voll ist — die Aussage „kein Cursor heißt: du hast alles" prüfte niemand. Sie ist auf dieser Route nicht kosmetisch: wer an einer Seitengrenze aufhört und glaubt, die Geschichte ende dort, rekonstruiert den falschen Vorfall. Jetzt wird beides zugesichert, in beide Richtungen und auf beiden Routen.

**Und der Leser macht eine Prüfung möglich, die es vorher nicht geben konnte.** Der Katalog sagt mit `audit: critical`, welche Handlungen ins manipulationsevidente Protokoll gehören. Die Entsprechung hielt bisher von Hand — jede kritische Route protokolliert, jede `audit: write`-Route nicht — und **nichts verglich die Erklärung mit dem Verhalten**, weil der einzige Weg, es zu bemerken, das Zurücklesen des Ledgers ist. Der neue Test läuft die montierte Routentabelle ab und verlangt zu jeder kritischen Route eine Sonde; er hat beim ersten Lauf sofort eine Route gefunden, die ich vergessen hatte.

**Nebenbei korrigiert:** `AuditCheckpoint.PublicKeyPEM` enthielt kein PEM — der Verifizierer dekodierte das Feld als Base64. Wer echtes PEM übergeben hätte, bekäme eine **fehlgeschlagene Signaturprüfung**, und die liest sich auf diesem Pfad als Manipulation. Der Name hätte den falschen Vorfall ausgelöst; das Feld heißt jetzt `PublicKeyBase64`.

**Nicht in W2.4, benannt:** Checkpoints (**T-10.7**). Sie brauchen eine Tabelle, einen Signer-Adapter — `VaultSignerInterface` hat bis heute *keinen* Implementierer, und `shared/signing.Signer` passt nicht (hex statt base64) — sowie eine Vault-Konfiguration im API-Prozess, die es dort nicht gibt. Für die Prüfbarkeit sind sie heute nicht nötig: jede Kette beginnt bei Sequenz 1 und ist vollständig. Tragend werden sie in dem Moment, in dem `retention.go` archiviert — und dieser Archivierer ist selbst unmontiert. Eine Route, die dauerhaft eine leere Liste zurückgibt, wäre schlechter als keine. Ebenso weiterhin ohne Aufrufer: `PseudonymizePII` (gehört an den Export-, nicht an den Lesepfad) und der `audit.recorded`-Outbox-Konsument.

---

**Ein Befund über das Prüfen selbst, zum dritten Mal:** die Mutationsschleife lief als Skript und wurde mitten in einer Mutation abgebrochen — die Wiederherstellung kam nicht mehr dazu, und die Änderung blieb in der Datei stehen. Aufgefallen ist es nur, weil ein Test, der vorher grün war, danach rot war; ohne diesen Vergleich wäre eine abgeschwächte Prüfung in den Commit gewandert. Ein Werkzeug, das den Baum verändert, muss seine Wiederherstellung überleben können, oder es darf ihn nicht verändern.

---

#### 10.3-AC Ergebnis: W2.5 — Notfallzugang und Support-Zugriff werden erreichbar, und dabei echt

Zwei Mechanismen, beide fertig geschrieben, **beide ohne einen einzigen Produktionsaufrufer**. Das ist sicher wie eine ausgesteckte Maschine und ebenso nützlich: im Vorfall ist die Alternative zu einem montierten Break-Glass-Pfad jemand mit einer Datenbankkonsole. Drei Schritte, drei Commits.

**Schritt 1: `impersonation_allowed` stand seit POL-01 auf jeder Permission und niemand las es.** policygen erzeugte das Feld nach Go und in die Berechtigungsmatrix; `RouteSecurityPolicy` projizierte Trust-Level, Step-Up und Step-Up-Alter und ließ es fallen. Der `ImpersonationGate` prüfte, *wer* impersoniert — URN-Format, Akteurstyp —, nie *ob die Operation es zulässt*. Ein Support-Operator in einer Sitzung konnte Rollen ändern, Mitglieder entfernen, Widerrufe schreiben, SCIM-Token ausstellen und Gruppen abbilden. Der Nullwert des neuen Feldes lehnt ab: wer eine Request baut, ohne von Impersonation zu wissen, weist impersonierte Principals zurück.

Dazu zwei Funktionen ersatzlos entfernt, die beide **das Gefahrenurteil vom Aufrufer nahmen**: `CanExecuteOperation(…, isPrivileged bool)` und `EnforceNoStandingGrants(…, isCustomerOrg bool)`. Die zweite las nichts, entschied nichts und hatte keine Aufrufer — sie formatierte einen Fehler, den der Aufrufer bereits beschlossen hatte. IDP-061 steht jetzt dort, wo eine stehende Mitgliedschaft entsteht.

**Schritt 2: Vier-Augen, die eine Person allein durchführen konnte.** `ActivateBreakGlass` nahm Antragsteller *und* Genehmigenden aus demselben Aufruf; geprüft wurde nur, dass die URNs verschieden sind. Wer den Namen einer Kollegin tippt, hatte die Zusage erfüllt. Jetzt zwei Handlungen von zwei verifizierten Principals, `ApproverURN` existiert im Body nicht mehr, und `CHECK (requester_urn <> approver_urn)` plus der Fremdschlüssel tragen die Regel in der Datenbank.

**Schritt 3: Die Support-Sitzung verlieh nichts.** Sie wurde eröffnet, gespeichert, angekündigt und mit `Role: "viewer"` versehen — als String auf einer Struktur, die keine Autorisierungsentscheidung je las. `impersonation_viewer` steht jetzt im Modell, ausschließlich in `can_view`, und wird wie Break-Glass pro Anfrage beigesteuert statt geschrieben. „Nur lesend" ist damit eine Eigenschaft des Autorisierungsmodells statt eines Kommentars.

**Drei Defekte, die nur der echte Pfad zeigen konnte** — alle drei dieselbe Form, alle drei von einem Speicher-Doppelgänger verdeckt:

| Fund | Warum unsichtbar |
|---|---|
| Der Critical-Audit-Adapter öffnete seine Transaktion **ohne Mandantenscope**; `audit_ledger` trägt FORCE RLS, die Policy verglich gegen NULL, **jeder INSERT wurde abgewiesen** | Der einzige Ledger auf diesem Pfad lag im Speicher |
| `impersonation_sessions` trug **zwei Spalten für einen Begriff** — 007 legte `target_org_id` an, 008 fügte `tenant_id` hinzu; der Code schrieb die erste, die Policy prüfte die zweite. Der `PostgresStore` konnte **keine Zeile** schreiben | Die Tests fuhren `MemoryStore`, der Store hatte keinen Aufrufer — die Tabelle war beweisbar leer |
| `audit_ledger.action` ist `VARCHAR(128)` und die Aktion enthielt die vollständige Begründung | Der Vertragstest benutzt `MemoryLedgerWriter` ohne Spaltenbreiten |

**Und der W2.4-Wächter hat zweimal meine eigene Auslassung gefunden**: dass `RevokeGrant` nichts protokollierte, obwohl der Katalog die Route als `audit: critical` führt — das Protokoll hielt den Beginn jedes Notfalls fest und das Ende keines —, und danach die beiden Impersonationsrouten. Genau so soll er wirken.

| Mutation | |
|---|---|
| eine Person genehmigt ihre eigene Anfrage | rot |
| dieselbe Anfrage wird zweimal beantwortet | rot |
| widerrufener oder abgelaufener Grant zählt weiter | rot |
| die Sitzung verleiht `admin` statt `impersonation_viewer` | rot |
| beendete oder abgelaufene Sitzung verleiht weiter | rot |
| jeder darf eine Support-Sitzung eröffnen | rot |

**Drei davon überlebten zuerst, und jede benannte eine echte Lücke.** Die Nebenläufigkeitssicherung beim Genehmigen war durch zwei weitere Schichten gedeckt und zählte nur im Rennen — das prüft jetzt ein Test mit zwei gleichzeitigen Genehmigern. `ActiveFor`, die Funktion, die über Notfallzugang *entscheidet*, wurde von **keinem** Test gegen PostgreSQL gefahren; sie hat jetzt einen Nahttest. Und dass nur Personal eine Sitzung eröffnen darf, prüfte nichts — ohne das könnte sich ein Kundenadministrator eine „Support-Sitzung" über die eigene Organisation eröffnen, die die Sichtbarkeitsroute den Kolleginnen dann als Toob-Support anzeigt.

**Abweichung von plan6, bewusst:** §273 legt die Routen auf `/api/v1/admin/…` ohne Mandanten. Dann käme der Mandant aus dem Body und wäre ein zweiter Leser eines Wertes, den das Gate nie gesehen hat, während Ledger-Eintrag, RLS-Transaktion und Idempotenzschlüssel ihn jeweils woanders herholen. Unter `/api/v1/tenants/{id}/…` lesen alle vier denselben.

**Nicht in W2.5, benannt:** `requires_signature` steht bei jeder Permission im Katalog und hat **ebenfalls keinen Konsumenten** — dieselbe Form wie `impersonation_allowed` vor diesem Schritt. Die Durchsetzung braucht ein Signaturverfahren für API-Klienten und gehört zur Arbeit an deren Anmeldedaten. → **T-10.8**. Ebenso offen: `identity/celldir` trägt zwei Aufgaben — den Mandanten-Transaktionsbesitz und die Zellmigration — und importiert deswegen `identity/authz`, was zweimal in dieser Welle erzwungen hat, einen Speicher in `identity/api` statt neben seinem Aggregat abzulegen. → **T-10.9**

---

#### 10.3-AD Ergebnis: W2.6 Schritt 1 — Freigaben, und die erste durchgesetzte Signatur

**`requires_signature` stand seit POL-01 auf jeder Permission und wurde von nichts gelesen** — dieselbe Form wie `impersonation_allowed` vor W2.5, und plan6 §4.6 sagt, was das auf dieser Route kostet: „Ohne diese Eigenschaft ist die Freigabe ein DB-Flag und kein kryptografisches Artefakt."

**Die Entscheidung: der Freigebende signiert mit dem Schlüssel, an den sein Token schon gebunden ist.** RFC 9449 `cnf.jkt`, dessen Besitz das DPoP-Gate ohnehin auf jeder Anfrage prüft. Nichts zu registrieren, kein geteiltes Geheimnis, kein zweiter Schlüssellebenszyklus — und im Klienten unsichtbar, weil er denselben Schlüssel schon für den Proof benutzt. Nichtabstreitbarkeit hängt damit an einem Sitzungsschlüssel einer Person statt an einem Bearer-Token, das jeder weiterreichen kann.

**Signiert wird eine Aussage, nicht der Body.** Der Server leitet `(Zweck, Mandant, Release, Artefakt, Kanal)` selbst ab und vergleicht — wer signiert, kann nicht das eine unterschreiben und das andere beantragen. Bei der Zweitfreigabe kommt die Aussage aus der **gespeicherten Zeile**, sodass der zweite Freigebende dem Artefakt zustimmt, das der erste gebunden hat. Die Felder sind längenpräfigiert, damit `"ab"+"c"` und `"a"+"bc"` nicht dieselben Bytes ergeben.

**Ein Endpunkt statt zwei**, wie plan6 §4.6 verlangt — und bewusst anders als Break-Glass. Dort sind es zwei *verschiedene* Handlungen (bitten, zustimmen), hier zweimal *dieselbe* von zwei Personen. Zwei Endpunkte ließen hier beide glauben, sie seien die erste.

| Befund | |
|---|---|
| `NewApprovalManager` ersetzte einen fehlenden Store durch einen im Speicher | Freigaben, die beim Neustart verschwinden, ohne dass es jemand erfährt |
| Weder `ReleaseApproval` noch `ApprovalStore` kannten einen Mandanten, während die Tabelle `tenant_id` mit FORCE RLS trug | Genau die Konstellation, die bei `impersonation_sessions` jeden INSERT scheitern ließ — hier gab es nie einen Postgres-Store, also kostete die Reparatur nichts |
| Primärschlüssel war `release_id` allein | Zwei Organisationen konnten dieselbe Kennung nicht benutzen, und der Versuch scheiterte mit einem Unique-Verstoß: ein **Existenz-Orakel über die Mandantengrenze** |
| Die Soak-Dauer brachte der Freigebende mit, einschließlich null | Wer freigibt, wählte auch, wie lange jemand widersprechen kann |
| `CreateReleaseApproval` überschrieb ohne Existenzprüfung | Eine zweite „erste Freigabe" setzte eine abgeschlossene Zeremonie zurück |
| `CancelRelease` prüfte keinen Zustand | Meldete auf alles Erfolg, auch auf eine bereits ausgelieferte Freigabe |
| `EvaluateReleaseForDeployment` duplizierte die Freigabelogik | Vier Regeln an zwei Orten, die auseinandergehen können, ohne dass eine Kopie falsch aussieht |

| Mutation | |
|---|---|
| jeder Schlüssel darf signieren | rot |
| die signierte Aussage wird nicht verglichen | rot |
| Vier-Augen in Engine, Store **und** CHECK entfernt | rot |
| die Soak-Dauer kommt wieder aus der Anfrage | rot |
| die Auslieferungsprüfung ignoriert den Artefakt-Digest | rot |

**Eine Mutation überlebte, und das ist diesmal die richtige Antwort.** Die Vier-Augen-Prüfung *nur* in der Engine zu entfernen ändert nichts: der Store prüft sie unter der Sperre erneut, das SQL-Prädikat `first_approver_id <> $1` entscheidet das Rennen, und `ck_release_approvals_dual_control` hält als Letztes. Erst alle drei zusammen entfernt wird der Test rot — und der Fehlschlag kommt dann aus der Datenbank. Das ist Tiefenstaffelung, die tatsächlich staffelt, und keine Testlücke.

**Nicht in Schritt 1: der Konsument, und was die Untersuchung dazu ergeben hat.**

`POST /api/v1/admin/releases/{id}/publish` ist in der **Registry** montiert, hinter `domain.PermAdminRelease` — einem registry-lokalen Berechtigungssystem, das den Identity-Katalog nicht kennt. Die Registry verifiziert Identity-*Token* (`middleware/auth.go` importiert `identity/token`), aber ihre Autorisierung, ihre Rollen und ihr Mandantenbegriff sind vollständig eigen. Bis das verbunden ist, gatet die Freigabe nichts.

Beim Nachsehen ist dabei ein Fund aufgetaucht, der die Reihenfolge ändert: **der Veröffentlichungspfad kann nicht sagen, was er veröffentlicht.** `PublishDraftRelease` bekommt ein Repo und eine numerische GitHub-Release-ID; `domain.ReleaseJob` trägt einen `CommitSHA`, aber keinen Digest des gebauten Artefakts. Die Digests, die es im System gibt (`RootfsSHA256`, `TarballSHA`, `job.SHA256`), liegen in anderen Strukturen und erreichen diesen Handler nicht.

Eine Freigabe bindet ein Artefakt — das ist der Teil von „kryptografisches Artefakt", der auch ohne Signatur trägt. Ein Gate, das stattdessen auf den Commit bindet, ist schwächer: zwei Builds desselben Commits können sich unterscheiden, und genau das soll die Bindung ausschließen. Es ist aber nicht nichts.

Damit zerfällt der Konsument in zwei Tickets:

- **T-10.10 — Der Release-Job hält fest, was er gebaut hat.** Ohne das kann kein Gate auf ein Artefakt binden, und die Freigabe-Zusage bleibt schwächer als ihre Datenstruktur. Das ist Arbeit im Build-Pfad der Registry.
- **T-10.11 — Das Gate selbst.** Port in der Registry, Klient gegen die Identity, fail-closed und ausdrücklich konfiguriert statt „nil heißt aus" — das wäre genau die Form, die diese Welle sechsmal entfernt hat. Sinnvoll erst nach T-10.10, sonst wird die Bindung nachträglich verschärft statt richtig angelegt.

---

#### 10.3-AE Zwischenbefund: die Autorisierungs-Engine hat keinen Kompositionspunkt

Beim Abgleich der montierten Routentabelle gegen plan6 §4 ist der größte verbleibende Fund aufgetaucht, und er betrifft nicht eine fehlende Route, sondern das Zentrum: **`authz.NewFGAClient` hat keinen einzigen Produktionsaufrufer.** Nur Tests konstruieren ihn.

Das ist zunächst kein Widerspruch zur Architektur — plan6 D2 legt fest, dass Autorisierung eine **Bibliothek** ist und kein Dienst, weil ein zentraler Entscheidungspunkt pro Anfrage einen Netzwerksprung kostet und das 15 %-Latenzbudget aus ENF-09 reißt. `POST /api/v1/authz/check` steht deshalb ausdrücklich auf der Liste dessen, was **nicht** gebaut wird.

Der Fund ist, dass die Bibliothek **nirgends eingebettet ist**:

- `identity/api` montiert Stufe 1 — Gates, Mandantenschnitt, Trust-Level, Step-Up. Eine Stufe-2-Entscheidung trifft sie nie.
- Die Registry bringt mit `registry/internal/server/authz` ein vollständig eigenes, rollenbasiertes System mit, das `identity/authz` nicht kennt und OpenFGA nicht anfasst.

Damit erreichen die Mechanismen aus W2.5 in Produktion keine Entscheidung: der kontextuelle Break-Glass-Tupel und der `impersonation_viewer`-Tupel werden von einem Klienten beigesteuert, den kein Binary baut. Die Nahttests beweisen, dass es funktioniert; kein Prozess führt es aus.

**`POST /api/v1/authz/explain` ist der Hebel.** Es ist der letzte substanzielle Welle-2-Posten der Identity-API, es ist der menschenzugewandte Debug-Pfad („warum wurde das abgelehnt?") für genau die Mechanismen, die gerade gebaut wurden — und es zwingt zum ersten Mal einen `FGAClient` in einen Produktionsprozess, mit beiden Providern daran. Der Endpunkt ist der Anlass, nicht der Zweck.

Der Blocker, den plan6 §263 nennt, ist unverändert und schärfer als dort notiert: `explain.go:89` setzt hartkodiert `Permission: "can_manage"` für die Selbstautorisierung des Aufrufers, und diese Relation existiert **ausschließlich in `marketplace.fga`** — nicht auf `tenant`, `channel`, `device_group`, `package` oder `device`. Der Endpunkt schlüge also für praktisch jeden Objekttyp fehl, den jemand erklärt haben möchte. → **W2.7**

Dass die Bibliothek darüber hinaus dort eingebettet wird, wo Entscheidungen tatsächlich fallen, ist eine eigene, größere Frage: sie berührt die Registry und die Flottendienste und ist keine Route. → **T-10.12**

---

#### 10.3-AF Ergebnis: W2.7 — die Engine bekommt ihren ersten Kompositionspunkt

`POST /api/v1/tenants/{id}/authz/explain` ist montiert, und damit ist der Befund aus 10.3-AE geschlossen: `identity-api` baut jetzt einen `authz.NewFGAClient` mit beiden Providern daran. `IDENTITY_OPENFGA_URL` und `IDENTITY_OPENFGA_STORE_ID` sind Pflichtvariablen — ein Prozess, der ohne sie startet, würde Stufe-2-Entscheidungen stillschweigend nicht treffen, und das ist genau die Klasse „fail-open durch Auslassung", die dieser Plan sonst überall notiert.

Die drei Reparaturen, ohne die die Route eine Attrappe geblieben wäre:

**Die Selbstautorisierung war gegen eine Relation gebaut, die es fast nirgends gibt.** `Permission: "can_manage"` existiert ausschließlich auf `marketplace`. An seine Stelle tritt `managementRelations` — eine Tabelle Typ → Verwaltungsrelation (`tenant`→`admin`, `channel`/`device_group`/`release`→`operator`, `package`→`owner`, `platform`→`security_admin`, …) plus `ManagementRelationForType`. Ein Typ, der nicht in der Tabelle steht, wird **abgelehnt** (`ErrNoManagementRelation`), nicht auf einen Standard gezogen: eine Erklärung, die niemand administrieren darf, ist eine Auskunft über fremde Berechtigungen.

`type release` hatte tatsächlich keine Verwaltungsrelation — `policy/model/fleet.fga` bekam `define operator: operator from channel`, damit die Tabelle nicht auf etwas zeigt, das das Modell nicht hergibt.

**Der Store-Fallback und die Sperrprüfung waren beide fail-open.** Der Fallback auf einen Store namens `"global"` hätte gegen einen leeren Store geprüft und alles erlaubt; die Sperrprüfung ließ durch, wenn der Cache nicht antwortete. Beide lehnen jetzt ab. `revocation.AuthzChecker` reicht den geteilten Flotten-Cache als `authz.RevocationChecker` durch — statt eines zweiten Sperrbegriffs neben dem bestehenden.

**Ein Test, der mit sich selbst übereinstimmte.** `explain_test.go` prüfte gegen den Typ `"document"` und die Relation `"can_manage"` — beides existiert im Modell nicht. Der Test bestätigte ein System, das es nicht gibt; er läuft jetzt gegen `tenant`/`can_view`. Der Nahttest dazu setzt seine Voraussetzungen mit `grantTuple`/`revokeTuple` **her**, statt sie anzunehmen: OpenFGA-Stores überleben den Testlauf, und ein Test, der „Tupel existiert noch nicht" voraussetzt, ist beim zweiten Durchlauf rot.

Ergänzend: `Expand` löst genau **eine** Ebene auf. Die Nahtprüfung behauptet deshalb nicht, aufgelöste Nutzer zu sehen, sondern dass der Baum die vier errechneten Usersets benennt — was die API tatsächlich zusagt.

---

#### 10.3-AG Ergebnis: der Berechtigungskatalog wird zum Artefakt, die Version zur Laufzeitauskunft

plan6 §4.4 sah `GET /api/v1/permissions` vor, damit die Konsole ihre Menüs rendern kann, ohne die Permissions ein zweites Mal im Frontend zu pflegen — mit dem ausdrücklichen Zusatz: „Wenn das Frontend stattdessen zur Buildzeit generiert wird, entfällt der Endpunkt." Die Entscheidung ist gefallen, und zwar aus einem Betriebsgrund: **Konsole und Identity-API sollen getrennte Deployment-Zyklen haben.** Ein Endpunkt, den das Frontend beim Start abrufen *muss*, koppelt genau das wieder zusammen — fällt die API aus, rendert die Konsole nicht einmal mehr die Seite, auf der stünde, dass die API ausgefallen ist.

Der Katalog wandert deshalb als **Artefakt**, nicht als Antwort:

- `policygen` schreibt `docs/permissions.json` neben das bestehende `docs/permissions.md` — dieselben Daten, einmal für Menschen, einmal für Maschinen, aus einem Generator, damit sie nicht auseinanderlaufen können. Die Konsole baut die JSON in ihr Bundle ein.
- `policygen` schreibt zusätzlich `shared/policy/catalog_version_gen.go` mit `CatalogVersion`.
- `middleware.CatalogVersion` setzt den Header `Toob-Catalog-Version` auf **jede** Antwort der öffentlichen API.

Vier Entscheidungen, die den Unterschied machen:

**Die Version ist ein Hash des Katalogs, keine gepflegte Nummer und kein Build-Zeitstempel.** Eine Nummer, die jemand von Hand erhöht, driftet von dem weg, was sie benennt — genau das Muster, das dieser Plan an mehreren Stellen als Befund führt. Ein Zeitstempel ändert sich bei jedem Deploy: jede Konsole der Flotte würde nach einem Release neu laden, das nichts anfasst, was sie liest. Ein Hash über den Inhalt kann per Konstruktion nichts anderes benennen als sich selbst.

**Gehasht wird die kompakte Kodierung, ausgeliefert wird die eingerückte.** Whitespace ist, wie die Datei sich liest, nicht was sie sagt. Eine Version über die eingerückte Form würde sich ändern, wenn die Datei je anders formatiert wird. Kompaktes JSON ist außerdem die einzige Form, die ein Konsument ohne Kenntnis dieses Generators reproduzieren kann — was die Version unabhängig nachprüfbar macht. `TestCatalogVersion_NamesTheArtifact` rechnet sie genau so nach und ist damit zugleich die ausführbare Spezifikation dieser Prüfung.

**Die Liste ist nach ID sortiert.** Sonst würde ein reines Umsortieren von `permissions.yaml` die Version ändern — die Flotte lädt neu, weil zwei Zeilen getauscht wurden. Sortiert beantwortet die Version „haben sich die Regeln geändert" statt „hat sich die Datei geändert".

**Die Version trägt keine Ordnung.** Ein Hash sagt „gleich" oder „verschieden", nie „neuer". Das ist Absicht, denn es erzwingt beim Konsumenten die einzige Regel, die terminiert: **höchstens einmal pro Browser-Sitzung neu laden, danach einen Hinweis anzeigen.** Während eines rollierenden Deploys antworten zwei Instanzen legitim unterschiedlich; eine Regel der Form „neu laden, bis sie übereinstimmen" hört nie auf, und „neu laden, wenn der Server neuer ist" läuft gegen ein Rollback endlos.

**Der Stempel sitzt außerhalb des Mux — und außerhalb des Pre-Auth-Limits.** Eine Konsole erfährt von ihrem veralteten Katalog durch den Aufruf, den sie als Nächstes macht, und das sind überproportional die *fehlschlagenden*: die Aktion, die sie angeboten hat und die das Gate ablehnt; die Route, die sie noch kennt und die es nicht mehr gibt; das Limit, in das sie läuft. Ein Header nur auf dem Erfolgsfall fehlte genau dort, wo er die Nachricht trägt. Gesetzt wird er **vor** dem Handler, weil `WriteHeader` die Map einfriert.

Der Mutationstest hat hier einen echten Testfehler gefunden, keinen Codefehler: die erste Fassung prüfte `rec.Header()` und überlebte die Mutation „Header nach dem Handler setzen" — die lebende Map des Recorders nimmt Schreibzugriffe an, lange nachdem eine echte Verbindung die Statuszeile gesendet hätte. Die Prüfung läuft jetzt gegen `rec.Result().Header`, den Snapshot, den `WriteHeader` festhält. Ein Test, der den Fehlerfall nicht sehen kann, ist genau das Muster aus § 5.1 — nur eine Ebene höher.

Als Drift-Wächter vergleicht `TestCatalogArtifact_MatchesTheEnforcedCatalog` das Artefakt Feld für Feld gegen `PermissionCatalog`. Er deklariert die Empfängerstruktur **selbst**, statt die des Generators zu importieren: ein Test, der den Typ des Produzenten benutzt, beweist nur, dass der Produzent mit sich einig ist.

`GET /api/v1/permissions` ist damit in plan6 §4.4 gestrichen — nicht „für später" stehengelassen, wie es dort ausdrücklich verlangt wird.

---

#### 10.3-AH Ergebnis: die Mutationsklammer — plan5 Säule 4

Sieben Commits (`f7420f4`, `8890d0a`, `8807533`, `f233a8b`, `01adba1`, `82062db`, `40b2996`). Der Anlass steht in plan5 N1: dieselbe Klammer — Mandantentransaktion, Geschäftsdatum, Ledger-Eintrag, Replikationsereignis — war überall von Hand geschrieben und in **drei Formen** auseinandergelaufen, von denen keine für ihren Fall entschieden worden war.

**Der Befund war schärfer als die Wiederholung.** Zehn Stellen schrieben einen Audit-Eintrag, auf zwei verschiedenen Wegen: sieben riefen `AuditLedgerService.Record` direkt und fragten die AUD-04-Matrix **nie**, drei verdrahteten `"critical"` als String. Der generierte Katalog wurde von keiner gelesen. Dass alle zehn richtig lagen, war Zufall der Abdeckung — alle hingen an `critical`-Permissions. Die nächste Kopie auf einer `write`-Route hätte fail-closed geerbt, was AUD-04 ausdrücklich verbietet.

**`identity/mutation` nimmt dem Aufrufer drei Dinge ab:**

- Die Klasse kommt aus `PermissionCatalog[id].Audit`. Eine Permission, die der Build nicht kennt, lässt `Mutate` sofort scheitern — beide Defaults wären falsch, „critical" tarnt einen Tippfehler als Strenge, „write" stuft still herab.
- Mandant und Akteur kommen aus der Klammer. Sie waren Felder am Eintrag, also konnte jede Stelle eine andere Organisation nennen als die, in deren Scope ihre Transaktion lief.
- **Eine Permission, deren Klasse nicht `read` ist, committet nicht ohne Ledger-Eintrag.** Das ist der Teil, der am weitesten trägt: das Vergessen ist keine Ausliefermöglichkeit mehr. Der Mutationstest zeigt es — `s.Audit` aus `Invite` entfernt gibt keinen still unauditierten Endpunkt, sondern einen 500 an der Klammer.

`Scope.Tx()` liefert `*sql.Tx` und nicht `dbtx.Tx`, weil `dbtx.Exec` keine Zeilenzahl meldet und die Prädikate dieser Stores nur etwas bedeuten, wenn der Aufrufer prüft, dass genau eine Zeile sich änderte — `dbtx` sagt das selbst. `Scope` ist eine Schnittstelle, damit Komponenten, deren Regeln nichts mit Transaktionen zu tun haben, Unit-Tests behalten: die vierzehn Break-Glass-Tests prüfen Gültigkeitsfenster, Vier-Augen und URN-Parsing.

**Vier ausformulierte Sicherheitszusagen wurden dabei ersetzt.** Das ist der Teil, der hier stehen muss, weil er sonst nur im Git-Verlauf existiert:

| Stelle | Alte Zusage | Warum sie fällt |
|---|---|---|
| `ApproveBreakGlass` | *„CRITICAL AUDIT BEFORE EFFECT"* — Audit committen, dann die Gewährung | Garantierte eine Richtung. Ein Absturz dazwischen hinterließ `break_glass.approved` für eine Gewährung, die es nie gab — und ein Prüfer liest das als erteilten Zugang. Atomar stimmen Aufzeichnung und Wirklichkeit. |
| `RevokeGrant` | *„eine Sperrung darf nicht daran scheitern, dass ihr Audit nicht geschrieben werden konnte"* | Der Katalog sagt `critical`, und `critical` heißt genau, dass ein fehlgeschlagener Nachweis die Operation kostet. Der Code widersprach seiner eigenen Deklaration. Nebeneffekt: der Wiederholversuch funktioniert jetzt — vorher stand die Sperrung schon und der zweite Versuch meldete „gibt es nicht". |
| `RevocationsHandler` | *„revoke, then record — eine Sperrung, die niemand zuordnen kann, ist die sichere Richtung"* | Dasselbe Argument, dieselbe Auflösung. |
| `StartImpersonation` | *„Zugang zurückzunehmen, den jemand schon hält, ließe Mitarbeiter ohne Nachweis arbeiten"* | Während die Transaktion offen ist, hält niemand etwas. Es gibt keinen Zugang zurückzunehmen. Die Zusage schützte einen Zustand, den es nicht mehr gibt. |

Alle vier Argumente waren in sich schlüssig. **Wer den Kompromiss anders will, stellt die Permission auf `audit: write` um** — an einer Stelle, sichtbar, statt als handgeschriebene Ausnahme in einer Funktion, die nichts mit dem Katalog vergleicht.

**Drei Funde, die unterwegs auffielen:**

1. **`AuditSensitivityCatalog` ist eine Falle.** Sie liegt in `audit_gen.go`, ist als „required audit sensitivity level" dokumentiert und hält das Feld `sensitivity`. Die Vokabulare — `read`/`write`/`critical` gegen `low`/`standard`/`high`/`critical` — überschneiden sich in genau einem Wert, und `admin.impersonation.stop` sowie `release.approval.cancel` sind `audit: critical` bei `sensitivity: high`. Wer die Karte für die Klasse hält, bekommt dort `"high"`, und jeder Vergleich gegen `"critical"` sagt nein: ein Pflicht-Audit wird still zur Nebensache. Kein Produktionsleser, aber der Umschlag wollte gerade zugreifen. Der generierte Kommentar sagt es jetzt und zeigt auf `PermissionCatalog[id].Audit`.
2. **Eine Fehllesung von AUD-04 stand als Begründung im Testfixture:** *„only audit: critical reaches the manipulation-evident ledger."* Der Dispatcher ruft `Record` in **beiden** Zweigen; die Klasse entscheidet nur, was ein Fehlschlag kostet.
3. **Vier montierte Routen deklarierten eine Audit-Klasse und schrieben nichts** — `admin.tenant.create`, `admin.tenant.update`, `admin.member.invite`, `admin.member.remove`. `tenants.go` hatte überhaupt keine Audit-Abhängigkeit. Der Drift-Wächter sah es nicht, weil er per Konstruktion nur `critical` ablief — mit derselben Fehllesung als Begründung. Er heißt jetzt `TestAudit_EveryRecordedRouteReachesTheLedger` und läuft jede Route ab, deren Permission eine Klasse deklariert.

**Was dabei weggefallen ist:** `audit.CriticalAuditAdapter` und `api.TenantTxSource` (existierten nur wegen eines Importzyklus, den `go list` als aufgelöst auswies), der Body von `api.OutboxOwnerNotifier` (Staging ist, was `Scope.Outbox` tut), und `impersonation.NotificationFailed` — ein Zustand, den kein Pfad mehr erreichen kann.

**Zur Testarbeit, weil zwei Stellen erst im zweiten Anlauf trugen:**

Der erste Orphan-Test für Break-Glass konnte nicht fehlschlagen: die zweite Freigabe wird an `pending.State` abgewiesen, bevor die Klammer aufgeht. Das Store-Prädikat greift nur bei echter Nebenläufigkeit, also sitzt die Prüfung jetzt in `TestBreakGlass_ConcurrentApprovalsElectOneWinner` — das Ledger verzeichnet genau eine Freigabe für ein Rennen, das genau einer gewonnen hat.

Bei Revocations und Freigaben ist der Mutant „Audit-Fehler schlucken" **äquivalent**, und das ist die Klammer und kein schwacher Test: `scope.audited` wird erst nach erfolgreichem Dispatcher gesetzt, also verweigert `Mutate` den Commit ohnehin. Aussagekräftig ist stattdessen „der Store öffnet seine eigene Transaktion" — bei intaktem Ledger nicht von der Klammer zu unterscheiden, weshalb `TestRevocations_AnUnrecordableRevocationDoesNotStand` und `TestApproval_AnUnrecordableApprovalIsRefused` die montierte Route gegen ein Ledger fahren, das nicht schreiben kann.

#### 10.3-AI Ergebnis: der SCIM-Listener bekommt die Klasse, nicht die Klammer

Beim Schneiden hat sich die Einschätzung gedreht, und das gehört hierher, weil ich den Posten vorher als „kleinen, abgeschlossenen Schnitt" angekündigt hatte.

**Die volle Klammer wäre groß und der Nutzen ist hier kleiner.** Sie hieße: zwei Store-Schnittstellen, rund zehn Schreibmethoden, sechs Provider-Methoden und deren Doubles — ungefähr so viel wie die drei Handler zusammen. Und der Grund, aus dem die Spaltung auf der Admin-Oberfläche unhaltbar war, gilt hier nicht: **SCIM-Operationen sind per Konstruktion idempotent** (`CreateUserIfAbsent`, PUT als Ersetzung, DELETE). Der Klient wiederholt. Eine Mutation, die geschah, deren Eintrag scheiterte und die als Fehler beantwortet wurde, wird wiederholt — und die Wiederholung kostet einen No-op und schließt die Lücke. Der Kommentar in `scim/handler.go` sagte das schon vorher, und er hat recht. Die Admin-Routen hatten diesen Vertrag nicht; deshalb mussten sie atomar werden und diese muss es nicht.

**Was tatsächlich falsch war, ist etwas anderes.** `AuditClassOf(op)` liest den Katalog seit jeher korrekt — es ist die einzige Stelle im System, die das von Anfang an tat. Benutzt wurde die Klasse aber nur, um Lesezugriffe zu überspringen; bei allem anderen scheiterte die Anfrage, gleich welcher Klasse. `identity.scim.provision` ist `audit: write`, und damit **stoppte ein Ledger-Ausfall die Bereitstellung** — genau der Fall, den AUD-04 ausdrücklich ausnimmt. Ein interner Ausfall wurde zum Ausfall des Kunden.

`api.SCIMAuditRecorder` hält jetzt einen `audit.AuditDispatcher` statt des Ledgers, und die Klasse reist als Parameter über die Portgrenze — `identity/scim` kennt die Operation, `identity/api` kennt das Ledger, und die Klasse ist das Einzige, was zwischen beiden wandern muss. Zusätzlich lehnt `record` jetzt ab, wenn die Routentabelle eine Permission nennt, die der Build nicht kennt: dann entscheidet nichts, was ein fehlgeschlagener Eintrag kostet, und Erfolg zu melden hieße, eine Verzeichnisänderung unter gar keiner Policy aufzuzeichnen.

`TestSCIM_TheAuditClassDecidesWhatALedgerOutageCosts` fährt beide Richtungen gegen ein Ledger, das nicht schreiben kann: Bereitstellung (`write`) läuft durch, Deprovisionierung (`critical`) wird abgelehnt. Der Mutant — Klasse ignorieren und wieder hart `"critical"` einsetzen — stirbt daran.

**Damit ist die Aussage präziser als „jede Mutation geht durch die Klammer":** jede Mutation, deren Aufzeichnung ihr Ausbleiben nicht anders schließen kann, geht durch die Klammer. Der SCIM-Listener schließt sie über die Wiederholung, und was ihn mit dem Rest verbindet, ist nicht die Transaktion, sondern dass der Katalog entscheidet.

---

#### 10.3-AJ Ergebnis: die Verbindung wird beim Start geprüft — plan5 Säule 3

Drei Commits (`6c812a1`, `2935853`, `8caa610`). Der Befund beim Aufmessen war größer als der geplante Posten, und er trifft die Grundlage von allem darunter.

**Jede Aussage dieses Systems über Isolation ist eine Aussage über eine Verbindung** — die Policies, das Append-only-Ledger, die engen Grants pro Rolle. Geprüft hat das kein laufender Prozess. Die Tests konnten es nicht: sie wechseln mit `SET LOCAL ROLE` in die Rolle, die sie prüfen wollen, und beweisen damit, dass der Schnitt stimmt. Ob ihn ein Binary benutzt, ist eine andere Frage. **Eine DSN auf einen Superuser besteht jeden Test in diesem Repository und setzt nichts davon durch** — ein Superuser umgeht RLS vollständig.

Zwei Funde machten es schlimmer als „ungeprüft":

1. **Alle vier Anwendungsrollen waren `NOLOGIN`.** Kein Prozess *konnte* sich als eine davon verbinden. Was `identity-api` in Produktion benutzt, ist keine davon — mit ziemlicher Sicherheit etwas Mächtigeres. Die Trennung war nicht ungenutzt, sie war unerreichbar.
2. **Admin-API und Partner-SCIM teilten sich ein Handle.** Jede Einschränkung von `identity_scim` — kein `tenant_members`, `scim_group_roles` nur lesend, also die Form, in der W1.3 sagt „Provisionierung kann keine Rechte vergeben" — galt in den Tests und nirgends sonst. Der Provisionierungs-Connector eines Kunden erreichte die Datenbank mit dem, was die Admin-Rolle konnte.

**`identity/dbguard` prüft jetzt beim Start, pro Verbindung, und bricht ab.** Die Prüfungen sind bewusst alle *negativ* — darf nicht Superuser sein, darf `BYPASSRLS` nicht halten, darf die bedienten Tabellen nicht besitzen, darf `audit_ledger` nicht ändern —, weil ein Negativ kein Inventar dessen braucht, was der Prozess vorhat. Der positive Check („kann sie lesen, was ihre Routen anfassen?") hätte den W2.4-Fund gefangen, bräuchte aber eine Tabellenliste pro Binary neben dem Routentisch, die davon abdriftet; er gehört später aus dem Routentisch abgeleitet.

**Die fünfte Prüfung ist das RLS-Inventar gegen eine Ausnahmeliste, und die Liste ist der eigentliche Wert.** Sie trennt **entschieden** (mandantenübergreifend by design: das Zellverzeichnis, die Deduplizierung des Outbox-Workers, Replay-Hashes) von **unentschieden**. Der Unterschied ist wichtig: nur der zweite Typ ist eine Schuld, und eine Liste, die beides gleich behandelt, wird zu einer Freigabeliste.

`token_families` ist der einzige unentschiedene Eintrag, und die Untersuchung ist der Grund: `session.NewPostgresStore` hat **keinen einzigen Aufrufer**, `identity/bff` wird von nichts außerhalb seiner eigenen Tests importiert. Die fehlende Mandantenspalte ist also keine Entscheidung — sie jetzt zu treffen wäre Schemaarbeit an einer Tabelle ohne Schreiber und ohne Leser. Ein Test hält die Zahl vom Wachsen ab. → **eigener Backlog-Posten:** `identity/bff` und `identity/session` sind zusammen über 300 Zeilen Sitzungsverwaltung mit Token-Rotation und Reuse-Erkennung, die kein Prozess baut.

**Migration 024 vergibt ausschließlich `LOGIN` und bewusst kein Passwort.** Zugangsdaten gehören nicht ins Schema und nicht in dieses Repository; bis ein Deployment sie setzt, kann sich niemand verbinden — die sichere Richtung. Die `NO*`-Attribute werden nicht wiederholt, weil eine `CREATEROLE`-Rolle seit PostgreSQL 16 nur Attribute setzen darf, die sie selbst besitzt, und der Migrator absichtlich keines davon hat. Dass sie gelten, fragt der Guard die Verbindung selbst — die stärkere Aussage.

**Beide gefährlichen Fähigkeiten sind einzeln bewiesen.** Die Admin-Rolle trägt `rolsuper` und `rolbypassrls` gemeinsam, also zeigt ihre Ablehnung nur, dass *eine* der beiden Prüfungen trägt. Der Test legt je eine Rolle mit genau einer Fähigkeit an. `CREATE ROLE ... SUPERUSER` ist das gefährlichste Statement der Suite und trägt deshalb seine eigene Datenbankprüfung neben sich, statt sie aus `ResetSchema` in einer anderen Funktion zu erben.

**Die Typsperre wurde bewusst nicht ausgerollt.** `tenantdb.DB` gibt es, ohne Notausgang — ein Rückgabeweg auf das rohe Handle machte die Sperre unverbindlich, und es braucht keinen: die Komponenten, die mandantenübergreifend lesen, behalten das einfache Handle. Migriert sind die vier Halter, deren Handle für nichts anderes als eine gescopte Transaktion benutzt wird.

Die übrigen nicht, und die Messung ist der Grund: **der Fehler, den der Typ verhindert, kommt nirgends vor.** Die einzigen zwei direkten Handle-Zugriffe in den mandantengebundenen Paketen öffnen eine Transaktion und setzen den Scope innen — korrekt, nur anders geschrieben. Vierzig Typen umzustellen gegen einen Fehler, den niemand gemacht hat, auf einer Grenze, die dbguard jetzt beim Start verifiziert, ist Umbau ohne Ertrag. Nach dbguard ist der Typ ohnehin Tiefenstaffelung und nicht mehr die Grenze: ein ungescopter Lesezugriff liefert *nichts* statt fremder Zeilen.

Was den nächsten stillen Fehler verhindert, ist `TestNoUndeclaredRawDatabaseHandles`: er parst den Baum, findet jedes `*sql.DB`-Strukturfeld und verlangt pro Paket eine Begründung — und schlägt ebenso fehl, wenn ein Eintrag auf nichts mehr zeigt, damit eine veraltete Zeile keine stehende Erlaubnis wird. Er hat die Liste beim ersten Lauf korrigiert: er zählt Strukturfelder statt Vorkommen, also halten `dbguard` und die beiden Kommandos gar keins, und `dbtx/sqltx.Beginner` eines, das ich übersehen hatte.

**Offen für das Deployment:** die vier Rollen brauchen Passwörter, und `IDENTITY_SCIM_DATABASE_URL` ist ab jetzt Pflicht. Ohne beides startet `identity-api` nicht — was der Zweck ist.

---

#### 10.3-AK Befund: der Anmeldepfad hat keinen Kompositionspunkt — Zitadel ruft nichts

Der größte verbleibende Fund, und der direkte Nachfolger von §10.3-AE: dort war es die Autorisierungs-Engine, hier ist es **der gesamte Anmeldepfad**.

**Was real ist.** Zitadel läuft — systemd-Unit, Konfiguration über Vault-Agent gerendert, `0400`. Die Instanz-Policies für Login, Passwort, Lockout und OIDC werden über `admin/v1` tatsächlich gesetzt. Das Projekt- und Rollenmodell (ZIT-02) ist als Code beschrieben.

**Was nicht existiert:**

**1. Kein Actions-v2-Target, nirgends.** `identity/target` bedient vier Endpunkte — `pre-authentication`, `pre-token-creation`, `pre-user-creation`, `post-authentication` — drei davon als `Critical`, dahinter vierzehn Regeln mit Unit-Tests: WebAuthn-Pflicht für Privilegierte, Trust-Level, Lockout, kein Self-Service-Reset, Organisationsnamen, Rollen-Elevation. Eine Suche über das gesamte Repository nach `targets`, `executions`, `actions/v2` findet **nichts**. Zitadel wird an keiner Stelle gesagt, dass es diese Endpunkte rufen soll.

**2. Die zehn Actions v1 werden still übersprungen.** `provision-instance-policies.sh` registriert zehn JavaScript-Actions, jede in dieser Form:

```bash
if [ -f "$ACTION_SCRIPT_FILE" ]; then
    curl -f -X POST ".../admin/v1/actions" -d "{\"name\": \"enforceWebAuthnOnlyForPrivileged\", ...}"
fi
```

Die `.js`-Dateien existieren im Repository nicht, und keine Ansible-Task kopiert sie nach `/usr/local/bin/`. Kein `else`, keine Meldung. Zehnmal übersprungen, Skript endet mit 0, Ansible meldet Erfolg.

**3. `IDENTITY_ZITADEL_SIGNING_KEY` erzeugt niemand.** Pflichtvariable — ohne sie startet `identity-api` nicht — und in keinem Vault-Template, Nomad-Job oder Skript vorhanden. Sie *könnte* auch nicht: der Signaturschlüssel entsteht als Antwort auf das Anlegen eines Actions-v2-Targets, und das passiert nie.

**4. Drei Dinge verdecken es.** Beide Provisionierungs-Tasks tragen `failed_when: false`. `/usr/local/bin/zitadel-provision` wird ausgeführt, aber nirgends dorthin kopiert oder gebaut. Und daneben liegt `provision-projects-and-roles.sh`, eine zweite Implementierung derselben Sache, die nichts aufruft — plus `identity/internal/zitadel/client.go`, ein `type Client struct{}` ohne Methoden, während der echte HTTP-Client in `cmd/` lebt.

**Der Code ist bereits für Actions v2 gebaut.** `identity/target/signature.go` erwartet den Header `ZITADEL-Signature` im Format `t=<unix>,v1=<hex>`, HMAC-SHA256 über Zeitstempel und Rumpf, mit Toleranz gegen Replay und Mehrfach-`v1=` für die Schlüsselrotation. Das *ist* das v2-Signaturschema. Die Bauteile passen; es fehlt ausschließlich die Registrierung.

**Aber die Routennamen sind v1-Begriffe.** `pre-authentication`, `pre-token-creation`, `pre-user-creation`, `post-authentication` sind Flow-Typen aus Actions v1. Actions v2 kennt diese Triggermenge nicht: es hat vier Bedingungsarten — Request, Response, Function, Event —, und der Migrationsleitfaden bildet die alten Flows darauf ab. „Complement Token" wird zur Function `preaccesstoken` bzw. `preuserinfo`; Pre/Post-Authentication und Pre/Post-User-Creation werden zu Request- und Response-Bedingungen auf konkreten API-Methoden. **Der Routentisch kodiert also ein v1-Modell mit einem v2-Signaturschema** — beides für sich stimmig, zusammen nicht.

Die `Critical`-Markierung hat in v2 eine genaue Entsprechung, die heute nirgends steht: der Zieltyp. `restWebhook` prüft nur den Statuscode, `restCall` wertet auch den Rumpf aus und bricht bei Nicht-2xx ab, wenn `interrupt_on_error` gesetzt ist, `restAsync` wartet gar nicht. Was der Routentisch `Critical: true` nennt, ist ein `restCall` mit `interrupt_on_error`.

**Und das Henne-Ei-Problem bleibt davon unberührt:** selbst mit vollständiger Verdrahtung fehlt der Weg von „Zitadel-Konto existiert" zu „diese Person darf `POST /api/v1/tenants`". Die erste Organisation entsteht nirgends. `identity-seed` umgeht das mit Entwicklungstoken aus `identity/test/tokens` — eine lokale Krücke, kein Produktionspfad.

→ eigener Arbeitsposten, größer als alles in Welle 2. Reihenfolge: erst die Registrierung (Target anlegen, Signaturschlüssel nach Vault, Executions binden), dann die Routennamen auf v2-Bedingungen umstellen, dann der Bootstrap.

---

#### 10.3-AL Verifiziert an einer laufenden Zitadel v4.16.2

Alles hier ist gegen eine echte Instanz gefahren, nicht aus der Dokumentation abgeschrieben. Das war die richtige Reihenfolge: **drei der Feststellungen widersprechen dem, was ich vorher geplant hätte.**

**Die API-Version ist geklärt.** `POST /v2/actions/targets` **und** `/v2beta/…` werden beide bedient; `/v2` ist der richtige Pfad. Die Antwort:

```json
{"id":"386305254460751875","creationDate":"…","signingKey":"DlHUAeUZufWu4g8ggeZDcpnavpgxEWpEq06z"}
```

Der `signingKey` kommt genau einmal, beim Anlegen. `PUT /v2/actions/executions` mit `{"condition":…,"targets":[id]}` nimmt sowohl `{"request":{"method":"/zitadel.user.v2.UserService/AddHumanUser"}}` als auch `{"function":{"name":"preuserinfo"}}` an.

**Die Nutzlast ist eine ganz andere als unsere.** Was tatsächlich ankommt:

```json
{"fullMethod":"/zitadel.user.v2.UserService/AddHumanUser",
 "instanceID":"…","orgID":"…","userID":"…",
 "request":{ …die echte API-Anfrage… },
 "headers":{ "Content-Type":["application/grpc"], "X-Forwarded-For":["…"], … }}
```

`TargetRequest` erwartet `{hook_type, request_id, user_id, org_id, payload{rule, user_role, amr, …}}`. Keine Überschneidung außer der Bedeutung. Und `userID` ist der **aufrufende** Principal, nicht das Subjekt der Anfrage — für `user_login_must_be_domain` ist das der Unterschied zwischen der richtigen und einer plausibel falschen Prüfung.

**Der Signaturheader stimmt exakt.** `Zitadel-Signature: t=1786751920,v1=<hex>` — genau das Schema, das `identity/target/signature.go` erwartet, inklusive Toleranzfenster und Mehrfach-`v1=`. Dieser Teil ist fertig und richtig.

**Der Antwortvertrag ist falsch herum, und das ist der schwerste Fund.** Bei `restCall` auf einer Request-Bedingung ist der **Antwortrumpf die neue Anfrage**. Vier Modi gemessen:

| Antwort des Ziels | Wirkung auf den abgefangenen Aufruf |
|---|---|
| `200`, leerer Rumpf | geht unverändert durch |
| `200`, Rumpf = die ursprüngliche `request` | geht unverändert durch |
| `200`, Rumpf = `{}` | **Anfrage wird durch `{}` ersetzt** → `invalid AddHumanUserRequest.Profile` |
| nicht-2xx bei `interruptOnError` | Anfrage abgebrochen, `Execution failed (EXEC-…)` |

`handler.go:125` schreibt heute `200` **und** `{"allow":true,"reason":""}`. Verdrahtet man das, wird jede abgefangene API-Anfrage durch `{"allow":true}` ersetzt. **Der Hook würde nicht nur nichts durchsetzen — er bräche jeden Aufruf, an den er gebunden ist.** Der richtige Vertrag ist: erlauben = `200` ohne Rumpf, ablehnen = nicht-2xx. `TargetResponse{Allow, Reason}` gehört gelöscht, nicht angepasst.

**Zwei Deployment-Tatsachen, die sonst erst beim Ausrollen aufgefallen wären:**

1. **Zitadel ≥ 4.15 sperrt alle privaten Netze für Action-Ziele.** Voreinstellung von `ZITADEL_HTTPCLIENT_DENYLIST` (kommasepariert) sind `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, Loopback, Link-local, ULA. Unser Hook-Listener ist der **interne**, also privat. Es gibt [keine Allowlist und keine Ausnahme pro Ziel](https://github.com/zitadel/zitadel/issues/12326), und geprüft wird vor dem Verbindungsaufbau anhand der aufgelösten IP — ein Hostname hilft nicht. Verifiziert: mit verengter Denylist wird dasselbe Ziel angenommen, das vorher abgelehnt wurde. **Das ist eine echte SSRF-Abwägung und gehört bewusst entschieden**, nicht nebenbei in einem Ansible-Template.
2. **Der Zielhostname muss beim Anlegen auflösen**, nicht erst beim Aufruf. Ein nicht auflösbarer Name wird mit demselben `Errors.Target.DeniedURL` abgelehnt. Die Reihenfolge beim Ausrollen ist damit festgelegt: Hook-Host erreichbar → Target anlegen → Schlüssel nach Vault → `identity-api` starten.

**Was das am Plan ändert:** Schritt 2 („den Umschlag ersetzen") ist größer als gedacht und Schritt 4 („Routentisch") kleiner — die Kritikalität ist schon richtig modelliert, nur der Antworttyp nicht. Und der Antwortvertrag muss **vor** jeder Verdrahtung stimmen, sonst ist die erste gebundene Execution ein Ausfall.

**Die Function-Nutzlast ist eine dritte Form.** Über einen Client-Credentials-Fluss ausgelöst und mitgeschnitten:

```json
{"function":"function/preuserinfo",
 "userinfo":{"sub":"…"},
 "user":{"id","username","preferred_login_name","state","resource_owner","machine":{…}},
 "org":{"id","name","primary_domain"},
 "application":{"client_id":"…"}}
```

Damit gibt es **drei** Umschläge: unseren erfundenen, den der Request-Bedingung (`fullMethod`/`request`/`headers`) und den der Function-Bedingung (`user`/`org`/`application`). Ein Adapter muss alle drei kennen.

**Und zwei Regeln haben keinen Angriffspunkt.** Weder die Request- noch die Function-Nutzlast enthält `amr` oder `authenticator_count`:

- `webauthn_only_privileged` prüft `amr` gegen die phishing-resistenten Methoden.
- `dual_authenticator_requirement` prüft die Zahl registrierter Authenticatoren.

Beide müssten diese Fakten innerhalb von 500 ms aus Zitadels API nachladen — auf dem Anmeldepfad, fail-closed. Das ist kein Adapterdetail, sondern die Frage, ob die Regel dort überhaupt hingehört: Zitadels eigene Login-Policy setzt bereits `forceMFA: true` und `passwordlessType: PASSKEY_TYPE_ALLOWED` mit `preventOrgOverride`. **Der Verdacht ist, dass auch diese beiden nativ abgedeckt sind** und damit zu den sieben zu löschenden gehören — das ist vor dem Bau des Adapters zu klären, nicht danach.

> **Nachtrag aus §10.3-AM: der letzte Satz war falsch, und zwar in jedem Bestandteil.** Die Instanz setzte `forceMFA` nicht, `passwordlessType` nicht, und `preventOrgOverride` ist überhaupt kein Feld dieser API. Der Verdacht ist damit widerlegt: von den vierzehn Regeln ist genau **eine** ein sauberes Duplikat. Der Absatz bleibt stehen, weil er zeigt, wie plausibel die Annahme war — sie stammte aus der Konfigurationsdatei, nicht aus der Instanz. Genau das war der Fehler.

`preaccesstoken` hat bei einem Client-Credentials-Fluss **nicht** ausgelöst; nur `preuserinfo`. Welche Flüsse welche Function auslösen, ist noch zu messen.

---

#### 10.3-AM Befund: die Härtung war nie eingeschaltet — und das Skript dafür schaltete sie ab

Der Anlass war die Regel-Triage aus §10.3-AL: sieben, vielleicht neun der vierzehn Go-Regeln sollten als Duplikate nativer Zitadel-Kontrollen gelöscht werden. Der Nachweis sollte lauten „Zitadel erzwingt das schon". Gemessen an v4.16.2 lautet er: **die nativen Kontrollen waren nicht konfiguriert.** Die Prämisse ist gekippt, und die Triage hat kein einziges Löschen ergeben.

**Die gemeinsame Ursache.** Beide Konfigurationswege verwerfen falsche Namen still und melden Erfolg: viper ignoriert unbekannte YAML-Schlüssel, grpc-gateway ignoriert unbekannte JSON-Felder. `{"forceMfa":true,"totalerUnsinn":true}` antwortet 200. Deshalb war „die Namen korrigieren" nicht die Lösung — das repariert die heutigen Tippfehler und lässt den nächsten genauso lautlos.

**F1 — `provision-instance-policies.sh` härtete die Instanz nicht, es entschärfte sie.** Ich habe die Login-Policy korrekt gesetzt und dann exakt das Payload des Skripts darübergeschickt:

| Feld | vorher | nach dem Skript |
|---|---|---|
| `forceMfa` | `true` | fehlt → **false** |
| `passwordlessType` | `ALLOWED` | fehlt → **NOT_ALLOWED** |
| `allowUsernamePassword` | `true` | fehlt → **false** |
| `allowExternalIdp` | `true` | fehlt → **false** |
| `hidePasswordReset` | `true` | fehlt → **false** |

HTTP 200, keine Warnung, Sequenz erhöht. Das Feld heißt `forceMfa`, nicht `forceMFA`; `hidePasswordReset`, nicht `disallowPasswordReset`. `preventOrgOverride`, `hidePasswordIfUserNotFound`, `mfaInitSkipPossible`, `passwordlessAllowed` und `hidePasswordScreen` sind auf diesem Endpunkt gar keine Felder. Und der Endpunkt ist ein **Voll-Ersatz**: jedes reale Feld ohne erkannten Wert wird auf `false` gesetzt. Nach jedem Lauf war formal kein einziges Anmeldeverfahren mehr aktiviert.

**F2 — zehn Action-Uploads gegen einen 404.** `POST /admin/v1/actions` existiert in v4 nicht. Zusätzlich hingen alle zehn an `if [ -f /usr/local/bin/*.js ]`; diese Dateien existieren nirgends im Repo und keine Task kopiert sie. Selbst bei Erfolg hätte der Aufruf die Action nur angelegt, nie an einen Trigger gebunden. Der Fehlerzweig lautete `NOTICE: … already exists or registered.`

**F3 — jeder Aufruf war fail-open.** `set -euo pipefail` in Zeile 9, aufgehoben durch `|| echo WARNING` an jedem `curl`. `PUT /admin/v1/policies/lockout` antwortet **405** (für PUT, POST und PATCH gemessen), `PUT /admin/v1/policies/oidc` **404** — beide gemeldet als Erfolg. Die Access-Tokens liefen deshalb nicht 15 Minuten, sondern auf Zitadels Default von **12 Stunden**.

**F4 — drei Schlüssel im Config-Template werden verschluckt.** Gemessen, indem eine Instanz mit genau unserem Template gebootet und die Projektion gelesen wurde:

| Template sagt | Projektion | richtiger Schlüssel |
|---|---|---|
| `DisallowPasswordReset: true` | `hide_password_reset = false` | `HidePasswordReset` |
| `MFAInitSkipPossible: false` | `mfa_init_skip_lifetime = 30 Tage` | `MFAInitSkipLifetime: 0s` |
| `PasswordPolicy.MinLength: 16` | `min_length = 8` | `PasswordComplexityPolicy` |
| `PasswordPolicy.MaxAgeDays: 90` | `max_age_days = 0` | `PasswordAgePolicy` |

Self-Service-Reset war also für alle offen, MFA-Einrichtung einen Monat überspringbar, das 16-Zeichen-Minimum in Wahrheit 8. Wirksam waren `AllowRegister`, `ForceMFA`, `PasswordlessType`, `IgnoreUnknownUsernames`, `AllowDomainDiscovery`, `LockoutPolicy` und `DomainPolicy`.

**Die Regeln 5 und 13 sind das Gegenteil eines Duplikats.** `no_self_service_reset` und `mfa_init_skip_disallowed` sind das Einzige, was die beiden kaputten Schlüssel aufgefangen hätte. Nach Aktenlage statt nach Messung hätte die Triage genau die zwei Regeln gelöscht, die den Defekt decken.

##### Was gebaut wurde

Ein Eigentümer, der sich selbst prüft. Die Instanz-Policies sind aus der Shell nach `identity/cmd/zitadel-provision` gezogen, dorthin, wo Projekte und Rollen schon mit `--check-drift` / `--apply` liegen.

- **`identity/internal/zitadel/policies.go`** — `InstancePolicySpec` als einzige Absichtserklärung. Jede Struktur wird in **beide Richtungen** benutzt: sie erzeugt die Anfrage und nimmt die Rückantwort auf. Ein falscher json-Tag heißt damit nicht mehr „still ignoriert", sondern „Rückvergleich stimmt nicht" — und der Lauf scheitert unter Nennung des Feldes.
- **Der Vergleich läuft über Reflexion**, nicht über eine handgeschriebene Liste. Eine Liste kann ein Feld vergessen, und ein vergessenes Feld ist ungeprüft — dieselbe Fehlerklasse. Ein neues Feld in der Spec ist ab dem Moment seiner Deklaration geprüft.
- **Vor dem Schreiben wird gelesen.** Zitadel lehnt einen Schreibvorgang, der nichts ändert, mit 400 ab — und formuliert das je Policy anders (`Default Password Age Policy has not been changed` gegenüber dem untranslierten `Errors.Instance.LockoutPolicy.NotChanged`). Erfolg an einem Fehlertext zu erkennen hielte, bis Zitadel eine Zeichenkette ändert oder in einer anderen Sprache antwortet. Vergleichen braucht kein solches Einvernehmen.
- **Zweitfaktoren** sind über die Login-Policy nicht setzbar — ein PUT nur mit U2F kam mit OTP zurück. Sie haben eigene Endpunkte, und OTP wird zurückgezogen: `forceMfa` verlangt *irgendeinen* zweiten Faktor, mit OTP daneben ist das keine Phishing-Resistenz.
- **Org-Overrides werden gemeldet und lassen den Lauf scheitern.** Gemessen: jede Org kann eine eigene Login-Policy anlegen und darin `forceMfa` abschalten; die Instanz-Policy gilt für ihre Mitglieder dann nicht mehr. Ein Feld dagegen gibt es nicht.
- **`policy/rules/lockout.yaml`** ist neu, weil die Sperrschwelle sonst zweimal dagestanden hätte — hier gesetzt, in `identity/target` geprüft. Der Generator erzeugt `MaxFailedPasswordAttempts`/`MaxFailedOTPAttempts`.
- Gelöscht: `provision-instance-policies.sh` und die zwei Ansible-Tasks. F1, F2 und F3 gehen mit der Datei.

##### Die korrigierte Endpunkttabelle (v4.16.2, gemessen)

| Zweck | Schreiben | Lesen |
|---|---|---|
| Login-Policy | `PUT /admin/v1/policies/login` (Voll-Ersatz) | derselbe Pfad |
| Lockout | `PUT /admin/v1/policies/password/lockout` | `GET /admin/v1/policies/lockout` |
| Passwort-Komplexität | `PUT /admin/v1/policies/password/complexity` | derselbe Pfad |
| Passwort-Alter | `PUT /admin/v1/policies/password/age` | derselbe Pfad |
| Token-Laufzeiten | `PUT /admin/v1/settings/oidc` (alle vier Felder) | derselbe Pfad |
| Zweitfaktoren | `POST`/`DELETE /admin/v1/policies/login/second_factors[/{typ}]` | im Login-Policy-GET |
| Orgs auflisten | `POST /admin/v1/orgs/_search` | — |

`/management/v1/orgs/_search` ist ein 404; die Management-API antwortet für je eine Org.

##### Was der Nahttest gefunden hat, den Unit-Tests nicht finden konnten

`identity/cmd/zitadel-provision/policies_seam_test.go` (Tag `zitadelseam`, `just test-zitadel-policies`) fand beim ersten Lauf zwei echte Defekte: den 404 auf `/management/v1/orgs/_search` und die 400-Ablehnung unveränderter Schreibvorgänge, an der **jeder zweite Deploy** abgebrochen wäre.

Wichtiger war der dritte Fund, und er betraf den Test selbst. Als Mutant habe ich den Originalfehler zurückgebaut — den Tag `forceMFA` — und **er überlebte**. Grund: `encoding/json` ordnet eingehende Schlüssel *ohne Rücksicht auf Groß- und Kleinschreibung* zu, während es beim Schreiben die falsche Schreibweise ausgibt. Die Instanz trug den richtigen Wert bereits aus dem vorigen Lauf, es gab keine Abweichung, also wurde gar nicht geschrieben. **Ein Test, der einen bereits richtigen Wert liest, beweist nichts darüber, ob dieser Code ihn hätte schreiben können.** Jeder dieser Tests schwächt die Instanz jetzt zuerst gezielt ab (`weakenInstance`); danach stirbt der Mutant mit genau dem Satz, der ein Jahr lang gefehlt hat:

```
login.forceMFA: declared true, instance holds false
```

##### Vorbehalt: Sitzungsabbrüche durch die Token-Laufzeiten

Die Access-Tokens gehen von faktisch **12 Stunden auf 15 Minuten**, die Refresh-Tokens von 90 Tagen auf 8 Stunden mit 30 Minuten Leerlauf. Das ist die dokumentierte Absicht — und die einzige Änderung dieses Blocks, die laufende Clients spürbar trifft.

Konkret: jeder Client, der ein Access-Token länger als 15 Minuten hält, **ohne den Refresh-Fluss korrekt zu implementieren**, bekommt ab dem Ausrollen 401 mitten in der Sitzung statt nach Stunden. Das trifft nicht die Anmeldung, sondern alles, was danach kommt: langlaufende Uploads, Geräte-Registrierungen und jeden Hintergrundprozess, der sich einmal ein Token holt und es weiterverwendet. Ein Refresh-Idle von 30 Minuten heißt zusätzlich, dass eine Sitzung, die eine halbe Stunde nichts tut, neu angemeldet werden muss.

Heute ist das folgenlos, weil kein Produktivsystem läuft und keine Clients angebunden sind. Es bleibt es nicht. **Vor dem ersten echten Ausrollen ist zu prüfen, ob jeder Client den Refresh beherrscht** — insbesondere der Geräte-Fluss und die CLI. Andernfalls ist der Wert bewusst zu erhöhen, statt ihn stillschweigend geerbt zu bekommen: die Zahl steht in `InstancePolicy()` an einer Stelle und wird beim nächsten Lauf verifiziert, also ist sie leicht zu ändern und schwer zu vergessen.

##### Stand der Triage

| Regel | Zweiter Eigentümer | Ergebnis |
|---|---|---|
| `lockout_policy` | nativ, 5/5 wirkt jetzt | **löschbar** |
| `org_name_rules` | `ValidateOrgName` an drei Stellen im API-Pfad, `AllowRegister: false` | löschbar, zu bestätigen |
| `no_self_service_reset`, `mfa_init_skip_disallowed` | jetzt nativ gesetzt und verifiziert | zu prüfen, **nachdem** der Umbau ausgerollt ist |
| `webauthn_only_privileged` | teilweise: `forceMfa` + nur U2F | bleibt, solange Rollenabhängigkeit fehlt |
| die übrigen neun | keiner | bleiben |

Damit ist der Weg frei, den §10.3-AL suchte — aber in umgekehrter Reihenfolge: **erst muss die native Kontrolle nachweislich greifen, dann darf die Regel weichen.** Genau das ist, was der Rückvergleich jetzt liefert.

**Offen geblieben:** wo `preventOrgOverride` in v4 tatsächlich hingehört (Org-Overrides bleiben möglich, werden nur gemeldet), und ob `AddSecondFactor` gegen eine Instanz funktioniert, auf der der Faktor fehlt — der Nahttest deckt bisher nur die Rücknahme, weil U2F voreingestellt ist.

---

#### 10.3-AN Befund: die Auslieferungskette hatte kein einziges vollständiges Glied

Anlass war eine kleine Frage — wer legt eigentlich `zitadel-provision` auf den Host? Antwort: niemand. Beim Nachziehen der Kette fehlte **jedes** Glied, und das war nicht sichtbar, weil kein Schritt scheitern konnte.

| # | Was passieren muss | Vorher |
|---|---|---|
| 1 | `site.yml` lässt sich überhaupt parsen | **neun ungültige `when:` auf Play-Ebene** |
| 2 | Der IdP steht im Inventar | Generator kannte `[idp]` nicht |
| 3 | `/usr/local/bin/zitadel` liegt auf dem Host | nichts lieferte es |
| 4 | Die erste Instanz wird nach unseren Vorgaben angelegt | `DefaultInstance.Org`/`Admin` — beides verschluckt |
| 5 | Ein Admin-Token existiert | nichts erzeugte es |
| 6 | `/usr/local/bin/zitadel-provision` liegt auf dem Host | nichts lieferte es |
| 7 | Die Provisionierung darf scheitern | `os.Exit(0)` bei fehlendem Token |

**`when:` ist kein gültiges Attribut für ein Play.** ansible-core verweigert daraufhin das gesamte Playbook — nicht das eine Play, das ganze. Alle neun sagten dasselbe („nur ausführen, wenn die Gruppe nicht leer ist"), und genau das tut Ansible ohnehin: ein Play ohne passende Hosts wird übersprungen. Sie waren also redundant *und* tödlich.

**Der Ansible-Stage erzeugt `inventory.ini` und überschreibt die Datei im Repo.** Er schrieb nur `[unseal_vault]`, `[api]` und `[workers]`. `groups['idp']` war damit nie definiert, Phase 6 wurde bei jedem Deploy übersprungen — und die `[idp:vars]`, aus denen die ausgehende Denylist berechnet wird, verschwanden gleich mit. Die sorgfältig kommentierte statische Inventardatei aus §10.3-AL hat nie ein Playbook gesehen.

**`FirstInstance` ist keine Sektion der Config.** Zitadel liest sie ausschließlich aus der Datei hinter `--steps`. Unser Template legte `Org` und `Admin` unter `DefaultInstance` ab; viper verwirft beides wortlos. Gemessen, indem je eine Instanz mit beiden Schreibweisen gebootet und die Projektion gelesen wurde:

| Konfiguriert als | Ergebnis |
|---|---|
| `DefaultInstance.Org.Name: Toob Alliance` | Org heißt `ZITADEL`, Admin `zitadel-admin@zitadel.localhost` |
| `FirstInstance` in der Steps-Datei | Instanz „Toob Identity", Org „Toob Alliance", `provision-sa`, PAT geschrieben |

Die Policies unter `DefaultInstance` wirken dagegen — das ist geprüft und bleibt, wo es ist. Es ist der fünfte Fund derselben Klasse in dieser Datei.

**Der stille Erfolg im Provisioner.** `zitadel-provision` beendete sich mit 0, wenn die Token-Datei fehlte, und protokollierte „skipping provisioning until token rendering". Das ist derselbe Defekt wie das `failed_when: false` aus §10.3-AM, eine Ebene tiefer — und er hat dessen Entfernung überlebt, weil das Kommando von sich aus 0 zurückgab. Es verweigert jetzt, auch bei leerer Datei.

**Zwei Templatesprachen in einer Datei.** `zitadel-config.yaml.tpl` mischt Vaults `{{ … }}` mit Ansibles `{% … %}` und wurde mit `copy:` unverändert abgelegt — der in §10.3-AL ergänzte Denylist-Block wäre also als wörtliches Jinja in der YAML gelandet. Jetzt `template:`, mit der Vault-Hälfte in einem Rohblock. Der erklärende Kommentar steht in einem *Jinja*-Kommentar davor, und das ist kein Stil: als YAML-Kommentar im Block geschrieben enthielt die Prosa den Terminator des Blocks und beendete ihn auf der Zeile, die ihn beschreibt. Ein `#jinja2:`-Kopf zum Umstellen der Trennzeichen war der erste Versuch; ansible-core 2.21 beachtet ihn nicht.

##### Was gebaut wurde

`zitadel-provision` wird von der **Artifacts-Stufe des Assistenten** gebaut, neben worker, autoscaler und vm-runner — nicht als Release-Artefakt ausgeliefert. Der Grund ist zwingend: das Binary trägt die deklarierte Instanz-Policy einkompiliert und prüft die Instanz **gegen die eigene Kopie davon**. Ein veralteter Stand meldete „applied and verified" und setzte die Policy vom letzten Monat durch.

Das Zitadel-Binary kommt über die Rolle, mit **im Commit festgeschriebenem Digest** statt aus der `checksums.txt` neben dem Archiv: Zitadel signiert seine Releases nicht — kein cosign, kein GPG, anders als Nomad und Vault. Eine unsignierte Prüfsumme neben dem Artefakt beweist nur, dass derselbe Server beides ausgeliefert hat. Version und Digest stehen zusammen, damit ein Versionssprung nicht mit der alten Prüfsumme landet.

Das Admin-Token durchbricht seinen eigenen Zirkel über die Steps-Datei: Zitadel schreibt das PAT des Maschinennutzers genau einmal bei der Einrichtung, Ansible legt es in Vault, löscht die lokale Kopie und der Vault-Agent rendert es danach wie jedes andere Geheimnis. Vault wird **zuerst** gefragt — die lokale Datei existiert nur beim allerersten Lauf, und unbedingt darauf zu warten würde jeden weiteren Deploy in den Timeout laufen lassen.

`--check-drift` hat endlich einen Aufrufer: ein täglicher systemd-Timer, dessen `OnFailure` in denselben notify-failure-Handler läuft wie die Zitadel-Unit selbst.

##### Was gemessen wurde

Die Installationssequenz ist in einem Container durchgespielt worden, genau wie die Rolle sie fährt: Digest geprüft, `--strip-components=1 --wildcards '*/zitadel'` entpackt das Binary allein, `zitadel --version` meldet v4.16.2. Beide Vorlagen wurden mit dem echten Filter-Plugin gerendert — 29 Denylist-Einträge, der Hook-Host korrekt ausgeschnitten, kein Jinja-Rest, beide Ergebnisse gültiges YAML.

##### Die Kette endet weiterhin im Leeren — zwei Gründe

**Die Knoten-Adressen verlassen Terraform nicht.** ~~Es gibt keinen IdP-Knoten.~~ **Diese Aussage war falsch und ist korrigiert:** `modules/cell` reicht an `modules/project-baseline` durch, und das legt sehr wohl zwei Server an — `node-fsn1` auf 10.20.1.10 und `node-hel1` auf 10.20.1.11, in zwei Rechenzentren. Mein Grep hatte nur `modules/cell/*.tf` nach `hcloud_server` durchsucht und die Delegation übersehen.

Was tatsächlich fehlt, ist schmaler: **keines der Module gibt die Adressen als Output heraus.** `project-baseline` exportiert Netz, Subnetz und Firewall-ID, aber keine Knoten-IPs; `cell` und `projects/identity` können sie deshalb nicht durchreichen, und `stages/terraform.go` — das `api_private_ips` in den Pipeline-State schreibt — hat nichts aufzuzeichnen. `[idp]` wird darum leer erzeugt und das Play übersprungen, jetzt mit einer Zeile im Protokoll statt lautlos. Vier kleine Ergänzungen, eine je Ebene; siehe `docs/devops_architecture.md` §5.

**`site.yml` parst noch immer nicht.** Nach der `when:`-Korrektur bleibt ein zweiter Fehler derselben Art: `roles/ubicloud-db/tasks/main.yml:44` hängt ein `loop:` an einen `block:`, was Ansible nie unterstützt hat. Das ist die Datenbank-Firewall, nicht diese Kette; es sauber zu übersetzen heißt, fremde Logik auf `include_tasks` umzubauen, und das ungeprüft zu tun wäre schlechter, als es zu benennen.

Beides zusammen heißt: die Auslieferung ist gebaut und geprüft, so weit sie ohne Hetzner prüfbar ist, aber ein Deploy kann sie noch nicht ausführen. Der nächste Schritt ist die Server-Ressource für die Identity-Zelle — und das ist eine Infrastrukturentscheidung (Größe, Standort, Anzahl, Firewall), keine Fleißarbeit.

---

#### 10.3-AO Abgleich: was von §10.3-AK bis AN zu ist, und zwei neue Funde

Anlass war eine Zwangspause. Ubicloud bekommt eine Zellen-Datenbank seit zwölf Stunden nicht fertig, und die Identity-Zelle stand beim letzten Deploy **eine Migration** vor dem Laufen. Also der Rückvergleich des Backlogs gegen den Code statt gegen die Erinnerung.

##### Geschlossen

**Das Actions-v2-Target existiert.** §10.3-AK Punkt 1 und 3 sind zusammen erledigt: der Deploy legt es an und protokolliert `target_id=388351848840429834`, der Signaturschlüssel liegt unter `secret/data/identity/zitadel-hooks`. `IDENTITY_ZITADEL_SIGNING_KEY` hat damit endlich eine Quelle. Dieselbe Meldung sagt, was noch fehlt: *„no executions bound — the target is registered and inert until conditions are attached"*.

**Die zehn Actions v1 sind weg.** `provision-instance-policies.sh` existiert nicht mehr, ebenso wenig `provision-projects-and-roles.sh` — die zweite Implementierung derselben Sache — und `identity/internal/zitadel/client.go`, der `type Client struct{}` ohne Methoden. §10.3-AK Punkt 2 und 4 sind gegenstandslos, und in der Zitadel-Rolle steht kein `failed_when: false` mehr (§10.3-AM).

**Der Antwortvertrag stimmt.** Der schwerste Fund aus §10.3-AL — `200` zusammen mit `{"allow":true}` hätte jede abgefangene Anfrage *ersetzt* — ist in `identity/target/handler.go` behoben: `writeDecision` schreibt beim Erlauben einen leeren `200`, beim Ablehnen einen Statuscode, und der Kommentar hält die vier gemessenen Modi fest. Das war die Bedingung dafür, überhaupt eine Execution binden zu dürfen.

**Und zuletzt scheiterte die Zelle nur noch an einem GRANT.** `schema_migrations` ist die einzige Tabelle, die keine Migration anlegt — der Runner erzeugt sie selbst —, also fiel sie durch jedes tabellenweise `GRANT` der Migrationen 009 bis 023. `identity-api` prüft beim Start die Schemaversion und starb achtmal an `permission denied for table schema_migrations (SQLSTATE 42501)`, während `identity-migrate` Erfolg meldete. Migration 025 vergibt `SELECT` an alle vier Serving-Rollen. Die Integrationssuite hatte es nicht gesehen, weil jeder Test dort auf der Migrator-Verbindung liest, der die Tabelle gehört; der neue fragt als die Rollen, die bedienen.

##### Weiterhin offen

1. **Der Umschlag-Adapter.** `handler.go` liest den Rumpf unverändert in `TargetRequest` — die Form, die Zitadel nachweislich nicht sendet. Solange das so ist, darf keine Execution gebunden werden: der Handler lehnte jeden Aufruf auf dem Anmeldepfad ab.
2. **Der Routentisch trägt v1-Namen** — `pre-authentication`, `pre-token-creation`, `pre-user-creation`, `post-authentication`. Die Kritikalität ist richtig modelliert, die Bedingungsarten fehlen.
3. **Zwei Regeln ohne Angriffspunkt** (`webauthn_only_privileged`, `dual_authenticator_requirement`). §10.3-AM hat den Verdacht widerlegt, sie seien nativ abgedeckt; sie bleiben und brauchen `amr` bzw. den Authenticator-Zähler aus Zitadels API, auf dem Anmeldepfad, fail-closed.
4. **Der Bootstrap.** Von „Zitadel-Konto existiert" zu „darf `POST /api/v1/tenants`" führt weiterhin kein Weg.

##### Neu: wir stehen zwei Minor-Versionen hinter der Sicherheit

`versions.json` pinnt Zitadel auf **4.16.2**. Aktuell ist **4.17.1** (14. August 2026), und die Änderungen liegen genau auf unserem Gebiet: Login-V2-Auth für deaktivierte Organisationen wird blockiert, das Ausstellen von Passkey-Enrollment-Codes prüft Berechtigungen, OTP-Codes gehen nicht mehr über `returnCode` an den Browser, und vor der 2FA-Registrierung steht ein MFA-Prompt.

Das ist mehr als ein Versionssprung: mehrere dieser Kontrollen sind Kandidaten für die Triage aus §10.3-AL, könnten also Go-Regeln nativ ablösen. Aber die teuer erkaufte Lehre aus §10.3-AM gilt weiter — **erst muss die native Kontrolle an der laufenden Instanz nachweislich greifen, dann darf die Regel weichen.** Nicht aus einem Changelog schließen. Und der Sprung gehört hinter den ersten grünen Deploy, nicht davor: eine ungetestete Version einzuziehen, während die Zelle noch nie vollständig lief, macht aus zwei Unbekannten eine.

**Eine Warnung fürs Binden:** [zitadel/zitadel#12225](https://github.com/zitadel/zitadel/issues/12225) beschreibt eine Regression, bei der eine Execution auf einer **Event**-Bedingung — besonders auf allen Events — die Instanz instanzweit lahmlegt, mit `interrupt_on_error` vollständig. Unser Plan bindet Request- und Function-Bedingungen; Event bleibt draußen, und jetzt aus einem benannten Grund.

##### Neu: der Antwortvertrag ist nicht für jede Bedingungsart derselbe

§10.3-AL hat vier Modi an einer **Request**-Bedingung gemessen: leerer `200` reicht durch, ein anderer Rumpf *ersetzt* die Anfrage. Zitadels Dokumentation beschreibt Function-Ziele dagegen so, dass sie „modified claims or metadata objects" zurückgeben — dort ist der Rumpf bedeutungstragend, und ein leerer `200` könnte Claims löschen statt durchzureichen.

Gemessen ist das nicht, und `writeDecision` schreibt heute für jede Route dasselbe. **Vor dem Binden einer Function-Bedingung ist deren Modus eigens zu messen** — aus demselben Grund wie damals bei den Request-Bedingungen: dort war die Annahme schon einmal genau falsch herum, und sie hätte jeden gebundenen Aufruf gebrochen.

---

#### 10.3-AP Ergebnis: der Adapter steht — und zeigt, dass nicht er der Engpass war

§10.3-AO Punkt 1 ist erledigt. `ParseEnvelope` bildet alle drei Umschläge auf die Form ab, die die Regeln lesen; `TargetRequest` hat seine JSON-Tags verloren und ist kein Drahttyp mehr. Ein Rumpf, der zu keinem der drei passt, wird abgelehnt statt in eine leere Struktur gelesen, die ablehnt und dabei wie eine Entscheidung aussieht.

`UserID` heißt jetzt `CallerUserID`. Zitadel nennt es `userID` und meint den Principal, der den abgefangenen Aufruf gemacht hat — nicht dessen Subjekt. Der alte Name lud genau die Verwechslung ein, vor der §10.3-AL warnt.

##### Der Befund: von achtzehn Eingaben beantwortet ein echter Umschlag drei

Die vierzehn Regeln lesen achtzehn verschiedene Payload-Felder. Gegen die gemessenen Umschläge gehalten:

| beantwortet | `invitee_email`, `org_name`, `domain` |
|---|---|
| **methodenabhängig** | `is_self_service_reset`, `target_role`, `justification`, `duration_seconds` — steckt in `request`, sobald die Execution an die passende Methode gebunden ist |
| **gar nicht** | `amr`, `authenticator_count`, `trust_level`, `current_trust_level`, `highest_trust_level`, `user_role`, `idp_type`, `github_org`, `failed_attempts`, `skip_mfa_setup`, `has_owner_approval` |

**Der Adapter war also nie der Engpass — die Regeln sind es.** Sie wurden gegen eine erfundene Nutzlast geschrieben, und die Hälfte fragt nach Tatsachen, die Zitadel an dieser Stelle nicht mitschickt. Ein bloßer Formübersetzer hätte für die untere Zeile `denyIncomplete` geliefert und, weil die Hooks `Critical` und fail-closed sind, **jeden gebundenen Login abgelehnt**.

Die Lücke ist jetzt ausführbar statt Prosa. `TestContract_ActionsV2Webhooks` schickte bislang einen `target.TargetRequest` und erwartete 200 — ein Vertragstest, der sich nur mit sich selbst einig war. Er schickt jetzt einen echten Request-Umschlag, hält fest, dass der Signaturvertrag gilt, und hält fest, dass die Regel **unter Nennung der fehlenden Eingaben** ablehnt. Schließt sich die Lücke, ist das die Zusicherung, die sich ändern muss, und sie sagt es.

##### Was daraus folgt, in dieser Reihenfolge

1. **Pro Regel entscheiden, wohin sie gehört.** Aus einem Umschlag zu füttern; per Anreicherung aus Zitadels API zu holen, binnen 500 ms und fail-closed; oder Zitadels eigener Policy zu überlassen. §10.3-AM verlangt für die dritte Möglichkeit den Nachweis an der laufenden Instanz — nicht aus dem Changelog.
2. **Erst danach der Trigger→Regel-Tisch.** Der Dispatch liest den Regelnamen noch aus `payload["rule"]`, einem Feld, das der Absender schreibt. Es ist nicht ausnutzbar — der Rumpf ist HMAC-signiert und Zitadel sendet den Schlüssel nie, es fällt also ohnehin auf den Routentyp zurück —, aber es fällt weg, sobald der Auslöser die Regel bestimmt. Welche Methode welche Regel auslöst, ist zu messen, nicht zu erfinden.
3. **Und erst dann Executions binden.** Für Function-Bedingungen vorher den Antwortmodus messen (§10.3-AO).

---

#### 10.3-AQ Triage: wohin jede der vierzehn Regeln gehört

§10.3-AL wollte diese Triage und musste sie zurückstellen, weil der Nachweis fehlte: die nativen Kontrollen waren nicht konfiguriert (§10.3-AM). Das ist nicht mehr so — und der Nachweis ist inzwischen **strukturell**, nicht anekdotisch. `ApplyInstancePolicies` schreibt die Deklaration aus `identity/internal/zitadel/policies.go` und **liest sie zurück**; eine Abweichung ist ein Fehler, kein Logeintrag. Was dort steht, gilt an der Instanz oder der Deploy schlägt fehl.

Damit ist §10.3-AMs Bedingung erfüllt, ohne dass jemand von Hand messen muss. Vier Töpfe:

| # | Regel | Verdikt | Beleg |
|---|---|---|---|
| 1 | `webauthn_only_privileged` | **nativ, und stärker** | `SecondFactors: [U2F]` mit entzogenem OTP, dazu `ForceMFA: true`. Der einzige erlaubte zweite Faktor ist damit phishing-resistent — für alle Nutzer, nicht nur privilegierte. `AllowTOTPForPrivileged = false` sagt dasselbe. |
| 2 | `dual_authenticator_requirement` | **kein Pendant, falscher Ort** | Zitadel kennt keine Mindestzahl an Authenticatoren. Aber einen Login abzulehnen, weil jemand nur einen registriert hat, sperrt ihn vollständig aus — das gehört an die Registrierung, nicht an die Anmeldung. |
| 3 | `permanent_l3_no_downgrade` | **unser Token-Verifier** | Trust-Level entstehen in `identity/token` aus `amr`/`acr`; Zitadel kennt den Begriff nicht und kann ihn nicht mitschicken. |
| 4 | `secure_factor_registration` | **nativ ab 4.17.1** | Die Version bringt Berechtigungsprüfung beim Ausstellen von Passkey-Enrollment-Codes und einen MFA-Prompt vor der 2FA-Registrierung. |
| 5 | `no_self_service_reset` | **nativ, und stärker** | `HidePasswordReset: true` gilt instanzweit, nicht nur für privilegierte Konten. |
| 6 | `break_glass_audit` | **behalten** | Kein Pendant, und es ist kein Gate, sondern eine Aufzeichnung. Braucht die Rolle → Function-Bedingung mit `user_grants`. |
| 7 | `invite_rules` | **nativ, und stärker** | `strings.Contains(email, "@")` ist schwächer als Zitadels eigene Adressvalidierung. |
| 8 | `org_name_rules` | **bindbar, jetzt** | `request.name` aus `AddOrganization`; die Regel akzeptiert `name` neben `org_name` bereits. Die einzige, die heute an eine Execution kann. |
| 9 | `role_elevation_owner_approval` | **unsere API** | `has_owner_approval` ist unser Begriff mit eigenem Speicher (`release_approvals`), nicht etwas, das Zitadel beim Login weiß. |
| 10 | `github_upstream_policy` | **behalten, Bedingung messen** | Kein Pendant. `idp_type`/`github_org` müssen aus der IdP-Verknüpfung kommen; welche Bedingung sie trägt, ist ungemessen. |
| 11 | `user_login_must_be_domain` | **schwach und gedeckt** | Prüft, ob ein Punkt vorkommt. `AllowDomainDiscovery: false` und Zitadels Domain-Verifikation decken das eigentliche Anliegen. |
| 12 | `lockout_policy` | **sauberes Duplikat** | `LockoutPolicySpec.MaxPasswordAttempts` liest **dieselbe Konstante** `spolicy.MaxFailedPasswordAttempts`. Das ist die eine, die §10.3-AM schon gefunden hatte. |
| 13 | `mfa_init_skip_disallowed` | **nativ** | `MFAInitSkipLifetime: "0s"` — der Kommentar dort begründet genau diesen Punkt. |
| 14 | `impersonation_audit` | **schon durchgesetzt** | `token/exchange.go` prüft Begründungslänge und Höchstdauer gegen dieselben Konstanten, an der Stelle, an der Impersonation tatsächlich entsteht. |

**Sieben nativ, vier gehören woanders in unseren eigenen Code, eine ist bindbar, zwei bleiben.** Damit bestätigt sich die Schätzung aus §10.3-AL („sieben, vielleicht neun") — aber auf dem umgekehrten Weg: nicht weil Zitadel es schon konnte, sondern weil unsere eigene Provisionierung es inzwischen einschaltet und nachweist.

##### Nebenfund: eine Regel mit zwei Besitzern

`spolicy.ValidateImpersonationRequest` hat **genau einen Aufrufer** — den ungebundenen Hook. `token/exchange.go` prüft dieselbe Sache noch einmal von Hand gegen dieselben zwei Konstanten. Dass die Werte nicht auseinanderlaufen können, liegt nur daran, dass beide dieselben Konstanten lesen; die *Regel* ist trotzdem zweimal geschrieben. Sobald Regel 14 aus dem Hook verschwindet, hat die generierte Funktion gar keinen Aufrufer mehr.

Die naheliegende Auflösung — `exchange.go` ruft sie — **ist keine.** Die generierte Funktion gibt anonyme Fehler zurück (`errors.New`, `fmt.Errorf` ohne Sentinel), während `exchange.go` typisierte braucht: `ErrJustificationRequired`, `ErrLifetimeRequired` und `ErrExceededMaxExchangeLifetime` werden von der API auf Statuscodes abgebildet, und `exchange_test.go` prüft sie mit `errors.Is`. Ein Aufruf würde diese Unterscheidung verlieren.

Damit ist der Nebenfund der eigentliche: **ein generierter Policy-Validator, dessen Fehler nicht unterscheidbar sind, kann von keinem Aufrufer verschieden behandelt werden — und genau deshalb hat der einzige echte Aufrufer ihn nachgebaut.** Die Reparatur gehört in `cmd/policygen`: Sentinel-Fehler emittieren, dann kann `exchange.go` sie umschließen statt sie zu wiederholen.

##### Nachtrag II: der dritte Validator ist gelöscht, nicht verdrahtet

Der naheliegende Schritt wäre gewesen, `ValidateRoleElevation` in `SetRole` aufzurufen. Er wäre falsch gewesen, und die Prüfung zeigt warum:

| Hälfte der Regel | wer sie tatsächlich durchsetzt |
|---|---|
| `max_stepup_age_seconds: 300` | Der Katalog führt `step_up_max_age` **pro Permission**; `admin.role.update` deklariert `5m` — dieselben 300 Sekunden. Der Interceptor reicht den Wert an `StepUpGate`. Die Zahl aus `elevation.yaml` las niemand, und global ist ohnehin die falsche Form. |
| `require_owner: true` | `admin.role.update` deklariert `relation: owner`, und `core.fga` definiert `owner: [user]` als direkte Zuweisung. Nur ein Owner erreicht den Handler überhaupt. |

Und die zweite Zeile ist der eigentliche Punkt: **die Regel hätte einen `admin` zugelassen, das Modell verlangt `owner`.** Sie war also nicht bloß tot, sie war die *schwächere* Fassung einer lebenden Regel — an genau der Stelle, an der ein Leser die Regel sucht. Wer sie später „repariert", indem er sie aufruft, weitet damit still aus, wer einen Owner erzeugen darf, und es sieht dabei nach einer Verbesserung aus.

Gelöscht sind `ValidateRoleElevation`, `policy/rules/elevation.yaml` und die zugehörige Generator-Validierung. An ihre Stelle tritt `TestCatalog_RoleUpdateIsOwnerOnlyAndNeedsFreshAuth`, der die Aussage dort festnagelt, wo sie stimmt: `relation: owner`, `step_up: true`, `5m`, `L3`. Mutiert man den Katalog auf `relation: admin` und `step_up: false`, fällt er mit beiden Zeilen.

Der alte Test bewies, dass eine Funktion sich verhält wie geschrieben. Der neue beweist, dass die Richtlinie gilt.

##### Nachtrag: der dritte Validator hat gar keinen Aufrufer

Beim Umbau nachgezählt. `shared/policy` generiert drei Validatoren, und keiner davon steht so da, wie er sollte: `ValidateOrgName` wird richtig benutzt (drei Aufrufer), `ValidateImpersonationRequest` war vom handgeschriebenen Duplikat verdeckt — und **`ValidateRoleElevation` hat null Aufrufer**. Weder Produktions- noch Testcode.

Das ist mehr als toter Code: Regel 9 (`role_elevation_owner_approval`) prüft im Hook `has_owner_approval`, ein Feld, das kein Umschlag trägt. Der generierte Validator prüft daneben etwas anderes und Strengeres — Zielrolle gegen aktuelle Rolle plus Alter der Authentifizierung — und niemand ruft ihn. Die Elevation-Policy aus `policy/rules/elevation.yaml` wird also **an keiner Stelle durchgesetzt**. Das gehört zu Topf „unsere API" und ist der nächste Kandidat nach demselben Muster wie hier.

##### Reihenfolge

1. ~~**`policygen` emittiert Sentinel-Fehler**, danach löst `exchange.go` seine Kopie auf.~~ **Erledigt.** Drei Sentinels pro Refusal, `exchange.go` fragt den Validator und übersetzt in seine eigenen Fehlertypen — die API bildet sie auf verschiedene Statuscodes ab, deshalb ging es nur so. Zwei Tests: einer durch `ExchangeToken`, dass alles Abgelehnte abgelehnt bleibt, und ein paketinterner für den Durchreiche-Zweig, den kein externer Test erreicht und der genau das ist, was eine künftige YAML-Bedingung beißen lässt.
2. **Regel 8 an eine Execution binden** — `AddOrganization`, Request-Bedingung. Braucht die laufende Zelle.
3. **Die sieben nativen löschen**, nachdem ein Deploy die Policies angewandt *und verifiziert* hat. Der Drift-Detektor ist der Nachweis; ohne grünen Lauf ist er nicht erbracht.
4. **Die vier verlegen**, wo sie schon durchgesetzt sind (3, 9, 14) oder hingehören (2).
5. **Zwei bleiben** (6, 10) und brauchen die Anreicherung aus §10.3-AP.

---

#### 10.3-AR Befund und Plan: die Outbox hat keinen Konsumenten, und OpenFGA steht auf einem Knoten zu wenig

Anlass war die Frage, was ohne laufende Zelle als Nächstes ansteht. Der Backlog-Durchgang schließt sechs der acht Prüfpunkte aus §13 — P1 (keine doppelten `*_gen.go` mehr), P2 (der Typ heißt `tenant`, Conditions gibt es keine, und `sync/jit.go` dokumentiert die Korrektur), P3 (`site.yml:238` bindet die openfga-Rolle ein), P4, P5, P6. P7 entpuppt sich als zweizeiliger leerer Stub. Übrig bleibt P8, deine Entscheidung.

Der Rest dieses Abschnitts ist, was der Durchgang stattdessen zutage gefördert hat.

##### `identity-sync` ist fertig und wird nicht ausgerollt

`identity/deploy/nomad/jobs.yaml` lässt es aus und begründet das so: *„both files are TODO placeholders that Nomad rejects, because there is no artifact to schedule"*. **Für `identity-sync` stimmt das nicht mehr.** `identity/Dockerfile` baut das Binary und legt es nach `/usr/local/bin/identity-sync`; der Job ist 208 Zeilen ohne ein einziges TODO. Nur `celldir.nomad.hcl` ist noch ein 17-Zeilen-Platzhalter.

Was dadurch nicht läuft, sagt das Binary selbst: *„It is the second half of every write identity-api makes … until now it had no consumer, so the tuples were never written."* Jede Mitgliedschafts- und Rollenänderung liegt in `outbox_events` und wird nie zu einem OpenFGA-Tupel. **Die Autorisierung entscheidet gegen einen Store, der nie erfährt, wer wo Mitglied ist.**

Und es gibt keinen provisorischen Ersatz, den man ablösen müsste: `identity-migrate` bringt das Schema auf Stand und schreibt die Rollen-DSNs nach Vault. Outbox oder Tupel kommen dort nicht vor.

##### Die Vorbedingung: OpenFGA fehlt ein Knoten

Beide Verbraucher sprechen OpenFGA über `127.0.0.1:8180` an — Host-Networking, statischer Port, weil 8080 auf demselben Pool von registry-api belegt ist. Das heißt: **wer OpenFGA braucht, muss auf einem Knoten laufen, auf dem OpenFGA läuft.**

| Job | `instance_count` | `distinct_hosts` |
|---|---|---|
| `openfga` | **1** | ja |
| `identity-api` | **2** | ja |
| `identity-sync` | **2** | ja |

Die Zelle hat zwei Knoten. Das Phase-6-Protokoll vom 29.08. 02:47 zeigt die Folge unmittelbar: `openfga-cluster` wurde auf `7bd1388e` platziert, `identity-api` auf `3d2780c2` **und** `7bd1388e`. Die Allokation auf `3d2780c2` hat kein OpenFGA unter ihrem Loopback.

Das ist heute schon falsch und nur deshalb nicht aufgefallen, weil identity-api nie über die Schemaprüfung hinauskam (§10.3-AO). Es hätte sich als „die Hälfte der Autorisierungsentscheidungen scheitert" gezeigt — ein Fehlerbild, das man an vielen Stellen sucht und nicht an dieser. Der Kommentar an `openfga`s `instance_count` sagt die Regel bereits richtig hin („must not exceed the number of API nodes in the cell"), nur ist die Zahl kleiner als sie sein müsste, nicht größer.

##### Plan

1. **`openfga.instance_count` auf die Zahl der Identity-Knoten ziehen.** Mit `distinct_hosts` legt Nomad dann je eine Allokation pro Knoten, und jeder Loopback-Verbraucher findet eine. Das ist die Vorbedingung für alles Weitere und repariert zugleich identity-api. Die Zahl gehört nicht als Literal in den Job: die Zellgröße steht in der Topologie, und der Deploy-Stage setzt heute keinerlei `instance_count` — das ist die Stelle, an der eine Zahl aus der Topologie kommen müsste, statt in drei Jobdateien getrennt zu altern.
2. **`identity-sync` ins Manifest**, nach `identity-migrate` (Schema und die `outbox-worker`-Zugangsdaten) und nach `openfga-provision` (die Store-ID, die es aus `secret/data/identity/fga` liest). Als Artefakt-Job wie identity-api; dabei die Variable `image` auf `image_digest` ziehen, wie die drei anderen Artefakt-Jobs sie nennen.
3. **Den überholten Kommentar in `jobs.yaml` korrigieren.** Er begründet die Auslassung mit einem fehlenden Artefakt, das es gibt.
4. **`celldir` bleibt draußen** und behält seinen Platzhalter-TODO — dort stimmt die Begründung noch.

##### Was schon steht, und was das Bauen erspart

Die Verdrahtung ist vollständiger, als der TODO vermuten lässt. `identity-migrate` veröffentlicht `secret/data/projects/identity/db/outbox-worker`, genau die Rolle, unter der `identity-sync` sich verbindet. Migration 025 gibt eben dieser Rolle das `SELECT` auf `schema_migrations`, ohne das `identity-sync` beim Start abbräche — dieselbe Prüfung, an der identity-api achtmal starb. Und die Store-ID schreibt `openfga-provision` an den Pfad, den der Job liest.

Kein Konflikt mit `identity/internal/fga`: das ist die **Pro-Mandant**-Variante, und ihr eigener TODO nennt sie ausdrücklich einen anderen Meilenstein, unvereinbar mit der zellweiten `IDENTITY_OPENFGA_STORE_ID`, die identity-api verlangt. `identity-sync` nutzt `cellStore` hinter derselben Schnittstelle, damit der Tag, an dem eine zweite Zelle existiert, genau eine Stelle betrifft.

##### Umgesetzt

Alle vier Schritte sind drin. Die Allokationszahl kommt aus der Zelle statt aus drei Literalen, und **die Defaults sind weg**: der Deploy-Stage ist der einzige Aufrufer, und ein Default ist genau das, was die beiden Zahlen unbemerkt auseinanderlaufen ließ. `identity-sync` steht im Manifest, hinter `identity-migrate` und `openfga-provision`, und der überholte Kommentar ist korrigiert.

Zwei Testlücken kamen dabei heraus, beide von derselben Art wie der Fund selbst:

**Die Liste im `jobVars`-Test hatte zwei Einträge.** Sie prüft, dass jede übergebene Variable im Job deklariert ist und keinen Default trägt — abgedeckt waren `zitadel-setup` und `zitadel`. Dieselbe Schwäche, die `diffPolicy` an anderer Stelle mit Reflection umgeht: eine handgepflegte Liste kann einen Eintrag auslassen, und ein ausgelassener ist stillschweigend ungeprüft. Sie deckt jetzt alle fünf, und sie sucht eine Zuweisung statt des Wortes „default", damit eine Beschreibung sagen darf, was der Default gekostet hat.

**Nichts verglich die Jobdateien mit dem Manifest.** Deshalb konnte eine vollständige `identity-sync.nomad.hcl` neben einem Manifest liegen, das sie nicht nennt, ohne dass es auffiel. Der neue Test in `deployspec_test.go` prüft beide Richtungen — jede `.nomad.hcl` ist eingeplant oder mit Begründung ausgenommen, und ein Eintrag, dessen Datei eingeplant wurde oder verschwunden ist, fällt ebenfalls. Eine Ausrede kann das, was sie entschuldigt, nicht überleben.

##### Und eine Regression, die ich selbst eingebaut habe

Das Entfernen der Defaults hat einen Aufrufer gebrochen, den ich zuerst übersehen hatte: `docs/runbooks/fga_outage.md` startet `openfga.nomad.hcl` von Hand, ohne `-var`. Der Befehl scheitert seither — in einem Störungs-Runbook, also genau dort, wo jemand ihn unter Zeitdruck befolgt und die Fehlermeldung am wenigsten gebrauchen kann. Korrigiert, mitsamt einer Zeile, die sagt, woher die Zahl kommt.

Der Fund gehört hierher, weil er die Regel bestätigt, gegen die er verstößt: eine Zahl, die an zwei Stellen gebraucht wird, muss an einer stehen — und wer den Default entfernt, muss **jeden** Aufrufer kennen, nicht nur den, den die Änderung betrifft.

##### Wie man merkt, dass es wirkt

Nicht daran, dass der Job läuft. `identity-sync` bringt einen internen Endpunkt mit, der den letzten erfolgreichen Drain und den letzten Fehler führt; die Prüfung ist eine Mitgliedschaftsänderung über die API und danach ein `Check` gegen OpenFGA, der vorher „denied" sagte. Ohne diesen zweiten Schritt bewiese ein grüner Deploy nur, dass zwei Allokationen laufen — was sie auch täten, wenn der Drainer nie eine Zeile fände.

---

#### 10.3-AS Was als Nächstes ansteht, und was worauf wartet

Nach §10.3-AR sortiert sich die verbleibende Arbeit sauber in zwei Hälften.

##### Wartet auf einen grünen Deploy

Nicht auf Arbeit, sondern auf einen Nachweis, und in jedem Fall auf denselben: die laufende Zelle.

- **Die sieben nativen Duplikate löschen** (§10.3-AQ). Der Drift-Detektor *ist* der Nachweis, aber erbracht ist er erst, wenn ein Lauf ihn ausgeführt hat. Mit ihnen gehen Regel 3, 9 und 14 aus dem Hook, die anderswo längst durchgesetzt sind.
- **Regel 8 an eine Execution binden** — `AddOrganization`, Request-Bedingung. Die einzige der vierzehn, die ein echter Umschlag heute füttern kann.
- **Den Antwortmodus für Function-Bedingungen messen** (§10.3-AO). Ungemessen, und `writeDecision` antwortet allen Routen gleich.
- **Zitadel 4.17.1** einziehen, nachdem 4.16.2 einmal vollständig gelaufen ist.
- **`identity-sync` verifizieren**: eine Mitgliedschaftsänderung über die API, danach ein `Check`, der vorher „denied" sagte.

##### Geht ohne Cluster

- **Die öffentliche Route für `identity-api`.** `Caddyfile-identity.j2` proxyt die Identity-Domain vollständig an Zitadel auf 8080; 8082 (API) und 8083 (SCIM) sind zellintern. Der TODO im Job nennt es beim Namen: *„Giving it a public route is a decision about the public API surface, not a deployment detail."* Das ist der Unterschied zwischen einer Zelle, die läuft, und einer, die benutzbar ist — und es ist eine Entscheidung, keine Konfigurationsaufgabe.
- **`internal/vaultkv`**: zwei handgeschriebene Schreiber stehen neben dem gemeinsamen. Dasselbe Muster wie überall in diesem Abschnitt, diesmal beim Schreiben von Geheimnissen.
- **Regel 2 an ihren richtigen Ort.** `dual_authenticator_requirement` hat kein natives Pendant, gehört aber an die Registrierung: einen Login abzulehnen, weil jemand nur einen Authenticator hat, sperrt ihn vollständig aus.
- **`internal/fga`** und **`celldir`** sind eigene Meilensteine, beide groß, beide mit ihrer eigenen Begründung dokumentiert.
- **P7**: `policy/tests/matrix/expectations.yaml` ist ein leerer Stub, den nichts liest — füllen oder löschen.

##### Die Empfehlung

**Die öffentliche Route**, weil sie die einzige offene Frage ist, deren Antwort den nächsten Deploy verändert. Alles andere Unblockierte ist Aufräumen; das hier entscheidet, ob die Zelle nach dem nächsten grünen Lauf erreichbar ist oder nur läuft.

Zu entscheiden sind drei Dinge, und keines davon ist Caddy-Syntax: welche Pfade `identity-api` gehören (`/api/v1/*`), ob SCIM überhaupt öffentlich sein soll oder VPN-only wie die Admin-Konsole, und ob beides unter der Identity-Domain liegt oder unter einem eigenen Namen. Die dritte Frage ist die folgenreichste — eine Domain, die IdP und Anwendungs-API zugleich bedient, teilt deren Angriffsfläche und deren Ausfälle.

---

## 11. Optimierungspotenziale

Nicht Defekte, sondern Hebel — mehrere davon lösen gleich mehrere Befunde auf einmal.

| # | Maßnahme | Löst |
|---|---|---|
| **O1** | **FGA-Typ- und Relationskonstanten generieren.** `policygen` parst `policy/model/*.fga` und schreibt `shared/policy/fgatypes_gen.go` (`TypeTenant`, `RelMember`, `PermCanView`). Jede Tupel-Konstruktion nutzt sie. | § 5.6 wird zum **Compile-Fehler** statt zum Laufzeitfehler |
| **O2** | **Native `ListObjects`- und `BatchCheck`-API** von OpenFGA nutzen (Server ist bereits mit `MAX_CHECKS_PER_BATCH=100` konfiguriert). | § 6.1 — O(n) Roundtrips → O(1), Goroutinen-Fan-out entfällt |
| **O3** | **Verifikation über `canonical_json`** statt Neuserialisierung; Zeitstempel vor dem Hashen auf Mikrosekunden truncaten; Anker-basierte Verifikation ab Checkpoint. | § 4.2 vollständig — und macht Retention und Verifikation erstmals gleichzeitig möglich |
| **O4** | **Ein `identity/dbtx.Tx`** als neutraler Transaktionstyp. | `audit → sync` entfällt, Graph wird azyklisch |
| **O5** | **Katalog lastfähig machen:** `min_trust_level`, `step_up`, `sensitivity`, `cost`, `audit`, `impersonation_allowed` aus `spolicy` lesen statt als Aufrufparameter. | § 5.4, § 3.5, tote generierte Kataloge (`AuditSensitivityCatalog`, `RateLimitCostCatalog`) werden tragend |
| **O6** | **Konformitätstest Katalog ↔ Registry ↔ Handler** als Tabellentest: jede Permission hat genau einen Registry-Eintrag mit passendem Trust-Level; jeder registrierte Handler hat eine Permission. | Macht POL-05 zu einem echten Gate; § 2.3 kann nicht wiederkehren |
| **O7** | **Event-IDs als UUIDv7/ULID** (128 Bit, sortierbar) statt 32-Bit-Derivat. | § 4.3; zusätzlich wird die Outbox natürlich nach Zeit sortierbar |
| **O8** | **Circuit Breaker** über `sync/atomic` + Half-Open-Timer, oder eine Bibliothek. | § 2.2 und die Race |
| **O9** | **`gofmt`, `govet`, `errcheck`, `ineffassign`, `unused`, `staticcheck`, `bodyclose`, `noctx`** in `.golangci.yml`. | § 5.8, § 8.2, große Teile von § 3.5 mechanisch |
| **O10** | **Konstruktoren ohne Nil-Toleranz.** Pflichtabhängigkeiten sind Pflicht; `nil` ist ein Programmierfehler und gehört zum Startzeitpunkt gemeldet, nicht zur Laufzeit ersetzt. | § 3.7 als Klasse; `impersonation.NewManager` macht es bereits richtig (panic) — der Rest zieht nach |
| **O11** | **Ein Enforcement-Interceptor, generiert.** Stage 1 + Stage 2 in einem aus dem Katalog erzeugten Interceptor; alle handgeschriebenen Middlewares bis auf mTLS-Terminierung und BFF entfallen. | § 5.1, § 5.2, § 2.3 |
| **O12** | **X.509 Name Constraints** auf der Tenant-CA (oder Trust-Anchor pro Tenant) statt OU-Stringvergleich. | § 3.8 — Isolation wird zertifikatsseitig statt applikationsseitig |
| **O13** | **`http.MaxBytesReader`** auf `target/handler.go` (liest aktuell unbegrenzt vor der Signaturprüfung) und Replay-Fenster analog zu `sync/outbound.go` (`t=`-Timestamp). | DoS-Fläche und Replay auf dem Zitadel-Hook |
| **O14** | **Allow-Entscheidungen als Counter**, nicht als `slog.Info`; Deny weiterhin strukturiert loggen. | § 6.3 — Log-Volumen um Größenordnungen |
| **O15** | **Migrations-Runner** mit Versionstabelle, `.down.sql` und benannten Migrationen; Tests führen SQL gegen ein Wegwerf-Postgres aus statt `strings.Contains`. | § 2.1 dauerhaft |

---

## 12. Priorisierter Arbeitsplan

### Sprint 0 — Blocker (nichts anderes davor)

1. **Migration 008/009 reparieren** und, da grüne Wiese, das gesamte Set neu schneiden: `identity_app`-Rolle anlegen, Surrogatschlüssel dort ergänzen, wo Indexe sie brauchen, Down-Migrationen, Runner mit Versionstabelle. Tests führen SQL aus. (§ 2.1, O15)
2. **Circuit Breaker** atomar + Half-Open + Reset-Timer. (§ 2.2, O8)
3. **Policy-Registry** auf Permission-ID keyen, deterministisch sortiert aufbauen, `AutomaticHTTPInterceptor` entweder auf Permission-IDs umstellen oder löschen. (§ 2.3)
4. **`device.PollForToken`**-Variadic entfernen, Test anpassen. (§ 2.4)
5. **`shared/policy` Kompilierbarkeit klären**; `policygen` bei fehlenden/fehlerhaften Regel-YAMLs `log.Fatalf`. (§ 2.7)
6. **OpenFGA-Nomad-Job**: dynamischer Port oder eigener Pool, `distinct_hosts`, Ubicloud-CA, Template-Interpolation. (§ 2.6)

### Sprint 1 — Sicherheit

7. **DPoP an das Token binden**: `jkt` in `principal.Principal`, DPoP-Gate in `Stage1Chain`, Pflicht sobald `cnf.jkt` vorhanden. (§ 3.1)
8. **Trust-Level neu ableiten**: `user_presence`/`user_verification` aus der Menge entfernen, deduplizieren, L3 nur aus `acr` oder einem Authenticator-Zähler. Contract-Test korrigieren. (§ 3.2)
9. **AMR-Menge vereinigen** — eine Definition, von `federation` und `token` gemeinsam genutzt. (§ 3.3)
10. **Trust-Level für Zertifikate trennen**: eigene Dimension oder Gates, die zusätzlich auf `ActorType` prüfen. (§ 3.4)
11. **`target/rules.go`**: Payload-Schema validieren, fehlendes Feld ⇒ deny, Default-Branch ⇒ deny, GitHub-Org aus der Tenant-Konfiguration. (§ 3.5)
12. **SCIM**: Auth verpflichtend, konstanter Vergleich, `/scim/v2/{orgId}`, URN über `principal.FormatHumanURN` mit echter Zelle und echtem Tenant. (§ 3.6)
13. **Break-Glass**: Subjektformat korrigieren, Store aus dem Resolver, Condition tatsächlich schreiben oder TTL + Sweeper, Audit-Adapter. (§ 2.5)
14. **Alle Nil-Toleranzen** in Sicherheitskomponenten entfernen. (§ 3.7, O10)
15. **Secrets rotieren**, `.env.*` aus dem Arbeitsbaum entfernen, `coverage` löschen und ignorieren. (§ 3.8)

### Sprint 2 — Struktur und Determinismus

16. **`Pipeline` löschen**, `Stage1Chain` als einzige Kette; ein HTTP-Einstiegspunkt, ein Problem-Details-Schreiber, ein Tenant-Fehler. (§ 5.1, § 5.2, O11)
17. **Vokabular generieren** (O1) und alle Tupel-Writes umstellen. (§ 5.6)
18. **Audit-Hash konsolidieren**: eine Funktion, `id`/`seq`/`tenant`/`timestamp` gebunden, Verifikation über `canonical_json`, Anker-Konzept, Duplikate in `sync/deletion.go` entfernen. (§ 4.1, § 4.2, O3)
19. **Backoff-Overflow**, **Event-ID-Entropie**, **Revocation-Resync-Generation**, **`DecisionCache.InvalidateSubject`**. (§ 4.4, § 4.3, § 4.5, § 4.6)
20. **Org-Namen** und **Impersonationsgrenzen** auf `shared/policy` konsolidieren; `internal/orgs` und `celldir` umstellen. (§ 5.3, § 5.4)
21. **Nebenläufigkeit**: die acht Races aus § 7 schließen; `MemoryLeaderElector`-Globals entfernen und `LeaderElector` tatsächlich implementieren.
22. **Linter-Set erweitern** (O9) und die dadurch aufgedeckten Reste abräumen.
23. **Scheintests entfernen** (§ 9). Ein leeres File mit `// TODO` ist ehrlicher als ein Test, der nicht fehlschlagen kann.

### Sprint 3 — Substanz

24. Postgres-Implementierungen für Outbox, Approval, Tenant-Directory, Saga, BFF-Sessions, Break-Glass-Grants, PKI-Bootstrap-Invalidierung, Device-Kill-Switch.
25. `cmd/identity-api` mit Router und montierter Middleware; Nomad-Jobs für API, celldir, identity-sync.
26. Valkey-Verdrahtung; die vorhandenen `Valkey*`-Implementierungen an Konfiguration anschließen.
27. `justfile` an die reale Struktur anpassen; `fga model test` in `validate-policy`.
28. `backup/verifier.go` entweder an einen echten Restore anschließen oder die Metrik entfernen.

---

## 13. Offene Prüfpunkte

| # | Frage |
|---|---|
| P1 | Kompiliert `shared/policy`? Deklarieren `permissions_gen.go`/`endpoints_gen.go`/`gates_gen.go` dieselben Symbole wie `generated.go`? |
| P2 | Enthalten die `.fga`-Modelle einen Typ `organization`, eine Relation `break_glass_operator` und eine Condition `is_active_breakglass`? (Der Go-Code setzt alle drei voraus.) |
| P3 | Wird die Ansible-Rolle `openfga` von `site.yml` überhaupt eingebunden? |
| P4 | Interpoliert Nomad `${NOMAD_PORT_http}` innerhalb eines Heredoc-`template`-Blocks? |
| P5 | Existiert `docs/` (ADRs, Runbooks) außerhalb des Exports, oder ist es entfernt? |
| P6 | Prüft `shared/boundaries_test.go` auch die Feinschichtung innerhalb von `identity/`? |
| P7 | Führt irgendetwas `policy/tests/matrix/expectations.yaml` aus? |
| P8 | Sind die Credentials in `.env.dev`/`.env.staging` aktiv? Falls ja: sofort rotieren. |

---

## 14. Fazit

Die Bausteinqualität ist an mehreren Stellen hoch — `dpop`, `pki`, `internal/fga`, `token/exchange`, `sync/reconciler` sind sauber gebaut und gut getestet. Der Engpass ist nicht Handwerk, sondern **Integration**: der Code besteht aus korrekten Komponenten, die einander nicht erreichen, und aus einer Verdrahtungsschicht, die dort, wo sie existiert, nichtdeterministisch (`NewFleetPolicyRegistry`), umgehbar (DPoP) oder selbstblockierend (Circuit Breaker) ist.

Der Schwerpunkt ist deshalb nicht „mehr Sicherheit" und nicht „mehr Infrastruktur", sondern **einen einzigen, deterministischen, tatsächlich montierten Request-Pfad herstellen und alle Parallelimplementierungen löschen**. Danach ist jeder weitere Bereich messbar, testbar und einzeln behebbar. Vorher ist er es nicht.