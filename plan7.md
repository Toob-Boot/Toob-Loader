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
| **T-3.6.4** | **`internal/scim/mapping.go` schreibt Tupel auf `group:<id>`** — einen Typ, den das FGA-Modell nicht kennt (§ 5.6). | Gehört zur Vokabular-Generierung (O1). | § 5.6 |
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
| **T-4.1.4** | **`audit → sync` bleibt bestehen.** Für § 8.1 ein Fund, der dort Zeit spart: die naive Interface-Extraktion geht nicht auf, weil `OutboxWriter.WriteEvent` `(*sync.OutboxEvent, error)` zurückgibt — ein `audit`-seitiges Interface müsste den `sync`-Typ nennen. Es braucht `identity/dbtx` für `Tx` **plus** einen schmaleren Writer oder einen Adapter am Kompositionspunkt. | § 8.1, nicht § 4.1. | § 8.1 |

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
| **T-5.2.3** | **`mtls_termination.go` wählt an sieben Stellen Status und Code von Hand**, sechsmal `401/unauthorized` — darunter für `ErrUnresolvableTenant`, was keine Authentifizierungsfrage ist. Der Rand ist der letzte Ort, der am Taxonomie-Sentinel vorbei direkt auf den Low-Level-Schreiber geht. | Der mTLS-Rand hat eigene Fehlerwerte ohne Sentinel-Bezug; das Umhängen gehört zu einem Durchgang über `identity/middleware`. | § 5.2, § 3.8 |

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
| **T-5.5.1** | **Präfixvergleiche sind der zweite Grammatik-Besitzer.** `rotation.go`, `workload.go` und `zero_touch.go` wählen die SAN-URI per `strings.HasPrefix(uri.String(), "toob:device:")` aus mehreren SANs aus. Richtig wäre `ParseURN` plus eine Prüfung des Aktortyps — das ändert die Auswahlsemantik bei mehreren SANs. | Eigener Durchgang über die Zertifikatsauswertung. | § 5.5, § 3.8 |
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
| **T-5.8.2** | **Die Konsistenzstufe der FGA-Prüfung ist nicht wählbar.** `WithConsistencyMode` versprach `HIGHER_CONSISTENCY` und lieferte immer `MINIMAL_LATENCY`. Für Widerrufe ist das die Frage aus § 4.5: eine Prüfung mit minimaler Latenz darf veraltete Tupel sehen. `OpenFGAChecker.Check` braucht den Parameter. | Ändert die Port-Signatur und betrifft jede Prüfung. | § 5.8, § 4.5 |
| **T-5.8.3** | **Die Ratenbegrenzung ist nicht permissionsbezogen.** `RateLimitRequest.Permission` war die einzige Spur davon; `Cost` aus dem Katalog wird ausgewertet, die Permission selbst nicht, also teilen sich alle Operationen eines Tokens einen Eimer. | Gehört zur Verdrahtung des `MultiLimiter` mit dem Server (T-4.3.1). | § 5.8, STATE-02 |
| **T-5.8.4** | **`registry/.../middleware.ClaimsContextKeyVal` ist eine nackte Zeichenkette als Kontextschlüssel.** `identity/middleware` hatte dafür einen eigenen Typ — und genau diese Datei ist hier gelöscht, sodass die saubere Variante verschwindet und die kollisionsanfällige bleibt. | Registry-seitig, eigener Durchgang. | § 5.8 |
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
| **T-9.2** | **RLS-Policies werden als Text geprüft, nicht ausgeführt.** `rls_test.go` und `ledger_test.go` prüfen Migrations-SQL per `strings.Contains`. Das fängt eine gelöschte Zeile, aber keine vorhandene und falsche Policy — und eine semantisch gleiche Umformulierung macht es grundlos rot. | Braucht Postgres (Sprint 3); die Form existiert in `registry/test/integration`. | § 9, CELL-05 |
| **T-9.3** | **`identity/celldir` ist einmal sporadisch fehlgeschlagen** — in einem von vier `-race`-Gesamtläufen, in zehn weiteren Durchgängen nicht reproduzierbar. Ein sporadisch roter Test untergräbt jedes „alles grün". | Nicht reproduzierbar; braucht einen gezielten Lauf unter Last. | § 9, § 7 |
| **T-9.4** | **Saga-Wiederaufnahme über einen Prozessneustart ist nicht geprüft.** `persistedMap` ist prozesslokal, also endet der Nachweis bei „dieselbe Engine nimmt wieder auf". Ein echter Neustart braucht den persistenten Saga-Store. | Braucht Postgres (T-3.6.1). | § 9, CELL-07 |

---

## 10. DevOps und Betrieb

| Befund | |
|---|---|
| **Kein Identity-Binary** | Es gibt kein `cmd/identity-api`, keinen Router, keinen Server. Sämtliche Middleware ist nirgends montiert. |
| **CLIs melden Erfolg ohne Wirkung** | `cmd/fga-admin`: `rebuilder := fga.NewTupleRebuilder(nil,nil,nil); _ = rebuilder` → Ausgabe „REBUILD APPLIED SUCCESSFULLY". `cmd/cell-admin switch-tenant` → „completed successfully". `cmd/identity-sync` → druckt und kehrt zurück, DLQ-Replay arbeitet auf einem frischen Memory-Store. `cmd/celldir` → `fmt.Println`. `cmd/identity-seed` → druckt Tenants, die es nicht anlegt. |
| **`justfile` zeigt großflächig ins Leere** | `plan-infra` ruft `plan-tf "s3"/"cloudflare"/"database"/"control-plane"/"worker"` — vorhanden sind `identity`, `ops`, `staging`, `update`. `deploy` ruft `deploy/api/deploy.sh` (existiert nicht). `plan-app` liest `deploy/api/.last_tag`. `validate-policy` startet **nur** `go test ./shared/policy/...` und ruft nie `fga model test` — `policy/tests/*.fga.yaml` und `policy/tests/matrix/expectations.yaml` werden von nichts ausgeführt. |
| **Valkey ohne Anbindung** | Die Ansible-Rolle existiert; `ratelimit.ValkeyBackend`, `dpop.ValkeyReplayStore`, `revocation.ValkeyPubSubClient` haben außerhalb von Tests **keine Konstruktionsstelle**. Die verteilten Stores sind produktiv unerreichbar. |
| **Ansible-Rolle `openfga`** | `openfga_db_password` hat keine Quelle (kein Vault-Lookup, keine `vars`). Nutzt `vault_root_token`, während `nomad` auf AppRole umgestellt ist. `postgresql_user`/`postgresql_db` setzen ein lokal erreichbares Postgres voraus; die DB ist verwaltetes Ubicloud über TLS. `changed_when: false` überall ⇒ die Rolle meldet nie eine Änderung. |
| **`backup/verifier.go` erfindet Metriken** | `res.RowsRestored = fi.Size() / 100 // Estimate rows`, `res.DurationMs = 50`. Es wird nichts wiederhergestellt — nur `os.Stat`. Die Gauge `toob_db_restore_verification_success` meldet 1 für einen korrupten, aber nicht leeren Dump. Eine Metrik, der man vertraut, obwohl sie nichts misst, ist schlechter als keine. |
| **`coverage` im Repo-Root** | Verweist auf `shared/identity/token/verifier.go` — ein Pfad, den es nicht mehr gibt. Nicht in `.gitignore`. |
| **Kein `docs/`** | Weder ADRs noch Runbooks. `policygen` schreibt nach `docs/permissions.md` in ein Verzeichnis, das nicht existiert. |

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