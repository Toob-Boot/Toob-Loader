# OpenFGA in der Registry — Plan (D5)

Stand 2026-09-07. Ziel: die Registry entscheidet „darf diese Person das?" aus dem Berechtigungs-
katalog und OpenFGA, so wie es der Katalog seit POL-01 behauptet — und die 21 Admin-Routen hören
auf, 501 zu antworten. Der Plan wurde freigegeben und ist umgesetzt; was beim Bauen anders wurde,
steht in §6.

---

## 1. Befunde

Was ich beim Lesen gefunden habe, in der Reihenfolge, in der es den Plan bestimmt.

| # | Befund | Beleg | Folge |
|---|---|---|---|
| **F1** | **Stage 2 ist nirgends verdrahtet.** Weder der Interceptor der Identity-API noch die Registry ruft `authz.FGAClient.CheckPermission`; der einzige Produktionsaufrufer ist die Explain-Route. Die Katalogfelder `resource`/`relation` erreichen keine Entscheidung. | `identity/middleware/interceptor.go:201-275` (Stage 1, Ratenlimit, Handler — kein Check); `grep CheckPermission(` außerhalb `identity/authz` und Tests: leer | D5 ist nicht „die Registry holt nach, was Identity hat". Es gibt Stage 2 einmal zu bauen, für beide. |
| **F2** | **OpenFGA ist nur über Loopback erreichbar.** Host-Networking, statischer Port 8180, eine Allocation pro Identity-Knoten; identity-api spricht `127.0.0.1:8180`. Registry-Knoten sind ein anderer Pool. | `identity/deploy/nomad/jobs/openfga.nomad.hcl:8-9,89`, `platform/internal/stages/deploy.go:750-776` | Die Registry braucht einen Netzpfad oder eigene Allocations (D3). |
| **F3** | **`platform:global#staff` wird nirgends gesät.** `fga-admin` kennt `provision/purge/rebuild` pro Tenant; `openfga-provision` legt Store und Modell an. Kein Befehl schreibt ein Staff-Tupel. | `identity/cmd/fga-admin/main.go:12-16`, `identity/cmd/openfga-provision/main.go` | Staff-Routen wären auch mit FGA für jeden denied (D6). |
| **F4** | **Das FGA-Subjekt ist der ID-Teil der URN**, nicht die URN: `user:<userId>` für Menschen und Operatoren, `service_account:<id>` für CI. Die Registry führt Benutzer unter der vollen URN. | `identity/authz/client.go` `PrincipalToFGASubject` | Jedes Tupel der Registry muss dieselbe Ableitung benutzen — nie eine eigene. |
| **F5** | **Zwei Rollenvokabulare.** Registry: `owner`/`maintainer`/`member` (`domain.OrgRole`). Modell `registry.fga`: `admin`/`member`/`publisher`. Katalog: `namespace.member.add` → `admin`, `namespace.delete` → `admin`. `maintainer` existiert im Modell nicht. | `registry/internal/domain/organization.go:9-23`, `policy/model/registry.fga` | Modell und Katalog müssen die Registry-Rollen abbilden (D4). |
| **F6** | **Selbstbedienung läuft auf `tenant#self_user`**, und `self_user` ist im Kernmodell `owner`. Ein Benutzer aus dem Social Login ist Mitglied der gemeinsamen Zitadel-Org, nicht ihr Owner. Mit Stage 2 wären `GET /api/v1/me`, `POST /api/v1/tokens`, `billing/upgrade` für jeden denied. | `policy/permissions.yaml` (6 Einträge `relation: self_user`), `policy/model/core.fga:21` | Die Selbstbedienungs-Relation muss aus dem Token folgen (D5). |
| **F7** | **Die Registry hat keine Outbox und keinen Tupel-Schreiber.** Mitgliedschaften und Paket-Eigentum liegen nur in Registry-Postgres. | `grep -i outbox registry/internal`: leer; `registry/migrations/013_organizations.up.sql` | Entweder replizieren oder pro Anfrage beisteuern (D2). |
| **F8** | **`PolicyEngine` entscheidet in Code**, rollenbasiert, mit eigenem Vokabular (`OrgAction`, `PackageAction`). Das ist die zweite Wahrheit neben dem Katalog. | `registry/internal/server/authz/policy.go` | Wird durch Stage 2 ersetzt, bis auf die Namensregeln (D8). |
| **F9** | **Operator-URNs entstehen nur in Tests.** Der Verifier leitet den Actor-Typ aus einer URN-förmigen `sub` ab; Zitadel liefert eine numerische `sub`, also ist jeder echte Mensch `ActorHuman`. „Staff" ist heute kein Merkmal eines echten Tokens. | `identity/token/verifier.go:168`, `identity/test/tokens/issuer.go:140` | Staff wird durch das Tupel `platform:global#staff@user:<zitadelUserId>` definiert, durch nichts im Token (D6). |
| **F10** | **Ein Login, zwei Dienste — das geht schon.** Registry und Identity-API lesen dieselbe Audience aus `secret/data/identity/oidc-client`. | `platform/internal/stages/deploy.go:432-434` | Die CLI braucht keine zweite Anmeldung. Für die Identity-API fehlt ihr nur der Host (`accounts-…`) und ein Befehl, der dorthin spricht. |

---

## 2. Entscheidungen

### D1 — Stage 2 ist eine Bibliothek in `identity`, benutzt von beiden Diensten

Ein Paket `identity/enforce` bekommt neben `Stage1Chain` einen **`RelationGate`**: er nimmt den
verifizierten Principal (aus Stage 1), die Katalog-Permission (`resource`, `relation`,
`sensitivity`) und das **Objekt der Anfrage** und stellt genau eine Frage an `authz.FGAClient`.

Was eine Route dazu deklariert, ist eine Zeile in ihrer Tabelle:

```go
// identity/api/routes.go und registry/internal/server/router/routes.go — dieselbe Form
Object: middleware.ObjectFromTenant(),                       // tenant:<verifizierter Tenant>
Object: middleware.ObjectPlatform(),                         // platform:global
Object: router.NamespaceFromPath("name"),                    // namespace:<uuid>, Name → ID über den Store
Object: router.PackageFromPath("scope", "name"),
Object: middleware.ObjectSelf(),                             // Selbstbedienung, siehe D5
```

`ObjectSource` ist das Gegenstück zu `TenantSource`: eine Funktion, die aus der Anfrage das Objekt
holt — und die **kontextuellen Tupel**, die zu diesem Objekt gehören (D2). Eine Route ohne
`Object` wird von `VerifyRoutes` abgewiesen, wie heute eine ohne `Tenant`. Damit kann Stage 2 nicht
„vergessen" werden: die Tabelle ist vollständig oder der Prozess startet nicht.

Reihenfolge im Interceptor: Stage 1 → Ratenlimit → **Stage 2** → Handler. Das Ratenlimit vor Stage 2,
weil ein FGA-Aufruf Budget kostet und ein Angreifer sonst kostenlos Relationen abfragen könnte.

Was `RouteSecurityPolicy` dazu neu projiziert: `Resource`, `Relation`, `Sensitivity`. Sie stehen im
Katalog; die Projektion hat sie bisher fallen lassen.

### D2 — Die Beziehungen der Registry sind kontextuelle Tupel, keine Replikation

OpenFGA hält das **Modell**, die **Staff-Tupel** und die Tupel der Identity-Tenants (die
`identity-sync` heute schon schreibt). Was die Registry weiß — wer Owner welcher Org ist, welche Org
welches Paket besitzt — steuert sie **pro Anfrage** als kontextuelle Tupel bei, gelesen aus ihrer
eigenen Postgres:

```
namespace:<orgId>#owner@user:<userId>          aus organization_members
package:<pkgId>#namespace@namespace:<orgId>    aus packages.organization_id
package:<pkgId>#owner@user:<userId>            aus packages.publisher_id
```

Das ist ADR 0005 (Rollen als kontextuelle Tupel), angewandt auf die Registry. Abgewogen:

| | Replikation (Outbox → Tupel-Schreiber) | Kontextuelle Tupel (gewählt) |
|---|---|---|
| Wahrheit | zwei Kopien, die driften können | eine: Registry-Postgres |
| Neue Infrastruktur | Outbox-Tabelle, Daemon, Leader-Wahl, Reconciler — alles, was `identity/sync` ist, noch einmal | keine |
| Kosten pro Check | ein FGA-Aufruf | ein Postgres-Read (den `PolicyEngine` heute schon macht) + ein FGA-Aufruf |
| `ListObjects` („alle Pakete, die ich sehe") | möglich | nicht über FGA — bleibt die SQL-Abfrage, die es heute ist |
| Konsistenz | eventual, Sekunden | sofort |

Replikation wird nötig, wenn ein *anderer* Dienst nach Registry-Beziehungen fragen soll. Dann ist
die Outbox der Schritt, und der ist mit diesem Plan nicht verbaut: die kontextuellen Tupel sind
dieselben Tupel, nur mit anderem Lebensort.

### D3 — OpenFGA erreicht die Registry über Nomads Service Discovery

Zwei Optionen für F2:

| | A — ein OpenFGA, über das private Netz (gewählt) | B — OpenFGA-Allocations im Registry-Pool |
|---|---|---|
| Wie | OpenFGA bindet an die private Adresse des Knotens, registriert einen Nomad-Service; `registry-api` templated `{{ range nomadService "openfga" }}` | wie heute, nur auch auf Registry-Knoten; Loopback bleibt |
| Netz | Hub-and-Spoke-Netz der Zellen, Preshared-Key aus Vault, kein öffentlicher Port | keins |
| Datenbank | unverändert | `openfga-db` muss für die Registry-Zelle geöffnet werden (ubicloud-Firewall) |
| Warum Loopback gewählt war | „nur von einem Knoten, der es ausführt" — ein Sicherheitsargument, das mit Preshared-Key und privatem Netz erhalten bleibt | |
| Was bricht | `loopbackAllocations` (Anzahl = Identity-Knoten) wird für identity-api hinfällig; identity-api kann dieselbe Discovery nutzen | `distinct_hosts` und Zählung pro Pool |

A, weil es die Zahl der bewegenden Teile senkt statt erhöht, und weil identity-api davon gleich
mitprofitiert: der Zwang „genau eine Allocation pro Knoten" verschwindet.

Vault: `registry-api.hcl` liest zusätzlich `secret/data/identity/fga` (Store-ID, Preshared-Key).
Konfiguration: `REGISTRY_OPENFGA_URL`, `REGISTRY_OPENFGA_STORE_ID`, `REGISTRY_OPENFGA_API_TOKEN`,
alle Pflicht (`envcheck`), wie bei identity-api.

### D4 — Das Modell trägt die Rollen der Registry

`registry.fga` bildet `owner`/`maintainer`/`member` ab, weil das die Rollen sind, die in der
Datenbank stehen und die ein Mensch in der UI wählt. Der Katalog fragt Fähigkeiten, nicht Rollen:

```
type namespace
  relations
    define parent: [tenant]                      # optional, für Enterprise-Orgs mit Zitadel-Org
    define owner: [user] or admin from parent
    define maintainer: [user] or owner
    define member: [user, service_account] or maintainer
    define can_manage_roles: owner
    define can_manage_members: maintainer
    define can_delete: owner
    define can_view: member
    define can_publish: member

type package
  relations
    define namespace: [namespace]
    define owner: [user] or owner from namespace
    define public: [user:*, service_account:*]
    define can_publish: owner or can_publish from namespace
    define can_delete: owner
    define can_view: public or can_view from namespace or owner
```

Katalog-Änderungen (`registry.*`): `namespace.create` → `platform`? Nein — anlegen darf jeder aktive
Benutzer (§2.3 in `identity_login.md`); die Relation ist `tenant#member` mit dem Token-Tupel aus D5.
`namespace.read` → `namespace#can_view`, `namespace.delete` → `can_delete`, `member.add/remove` →
`can_manage_members`, `package.publish/promote` → `package#can_publish`, `unpublish/delete` →
`can_delete`, `package.read/job.read/list_own` → `can_view`. `policygen` prüft Relation gegen Modell;
`policy/tests/registry_test.fga.yaml` bekommt die Fälle „maintainer darf Mitglieder, nicht Rollen".

### D5 — Selbstbedienung: die Mitgliedschaft in der eigenen Org kommt aus dem Token

Für jeden Check steuert Stage 2 ein Tupel bei, das nicht aus einem Store stammt, sondern aus dem
Token, das Stage 1 verifiziert hat:

```
tenant:<p.OrgID>#member@user:<userId>
```

Das ist keine Abkürzung, sondern eine Tatsache mit Aussteller: der IdP hat gesagt, in welcher
Organisation die Person ist, und `TenantGate` hat es gegen den Pfad geprüft. Die sechs
Selbstbedienungs-Permissions der Registry (`token.*`, `account.read`, `billing.upgrade`,
`namespace.create`) wechseln von `self_user` auf `member`. `self_user` bleibt im Kernmodell für die
Identity-API, wo es „Owner der eigenen Organisation" tatsächlich bedeutet.

### D6 — Staff ist ein Tupel, gesät aus der Umgebung

`platform:global#staff@user:<zitadelUserId>` und `#security_admin` werden von `fga-admin` mit einer
neuen Aktion `staff` idempotent abgeglichen (schreiben, was fehlt; löschen, was nicht deklariert ist;
Dry-Run standardmäßig). Die Quelle ist `.env.<env>` → `STAFF_USER_IDS` / `SECURITY_ADMIN_USER_IDS`
(Zitadel-Benutzer-IDs, kommagetrennt), über `toob-ops` in den `openfga-provision`-Job. Eine leere
Liste ist in `prod` ein Fehler (`envcheck`), in `dev` erlaubt.

Warum nicht aus einer Zitadel-Rolle: die Rollen sind gerade abgeschafft (Q5), und ein Staff-Recht,
das in der IdP-Konsole zu vergeben ist, wäre die Abkürzung, die Q5 geschlossen hat.

### D7 — Fail-closed, aber als 503 unterscheidbar

`FGAClient` antwortet bei Ausfall mit `ErrFGAUnavailable` (Circuit Breaker, Timeout). Stage 2
übersetzt das in **503 `authz_unavailable` + `Retry-After: 2`**, nicht in 403: der Aufrufer hat
nichts falsch gemacht, und die CLI wiederholt nach dem Header. Eine Ablehnung ist 403
`permission_denied`, mit `resource` und `relation` im `detail` — ohne Aufzählung dessen, was die
Person stattdessen dürfte. Konsistenz: `sensitivity: critical|high` → `HIGHER_CONSISTENCY`, sonst
Store-Standard.

### D8 — `PolicyEngine` schrumpft auf Namensregeln

`AuthorizeOrgAction`, `AuthorizePackageAction`, `AuthorizePublishJobAction` und die Typen
`OrgAction`/`PackageAction`/`PublishJobAction`/`AuthzDecision` werden gelöscht — Stage 2 hat
entschieden, bevor der Handler läuft. Was bleibt, sind `AuthorizeScopeClaim` und
`AuthorizeNameClaim`: „darf dieser Name so heißen und wem gehört er" ist eine Regel über Namen, keine
Relation. Das Paket heißt dann `naming`, und `domain.Authorizer` beschreibt nur noch das.

Handler, die heute den Authorizer aufrufen (`download.go`, `organization.go`, `packages.go`,
`publish.go`), lesen stattdessen nichts mehr: sie laufen nur, wenn Stage 2 ja gesagt hat. Ein
Sonderfall bleibt `download.go`, das dev/staging-Pakete filtert — das ist Sichtbarkeit von
Listen, keine Berechtigung auf ein Objekt, und bleibt SQL.

---

## 3. Phasen

Jede Phase endet mit einem Build und den benannten Tests; nichts in Phase n hängt von Phase n+1.

### Phase 0 — Modell und Katalog (kein Laufzeitcode)

| Schritt | Dateien |
|---|---|
| `registry.fga` wie D4; Modelltests für maintainer/owner/member und Paket-Eigentum | `policy/model/registry.fga`, `policy/tests/registry_test.fga.yaml` |
| Katalog: Relationen auf `can_*`, Selbstbedienung auf `member` (D5) | `policy/permissions.yaml` |
| `policygen`: `Resource`/`Relation`/`Sensitivity` in die Regelprojektion (`rules_gen.go`) aufnehmen, damit `FleetPolicyRegistry` sie lesen kann | `identity/cmd/policygen/main.go` |
| `go generate ./shared/policy/`, Linter grün | `shared/policy/*_gen.go` |

### Phase 1 — Stage 2 in `identity`, verdrahtet in der Identity-API

| Schritt | Dateien |
|---|---|
| `RelationGate`: Eingang Principal + Policy + Objekt + kontextuelle Tupel; Ausgang Entscheidung; Fehlerklassen nach D7 | `identity/enforce/relation.go`, `relation_test.go` |
| `ObjectSource` + Standardquellen (`ObjectFromTenant`, `ObjectPlatform`, `ObjectSelf`); Token-Tupel nach D5 | `identity/middleware/object.go` |
| `RouteSecurityPolicy` um `Resource`, `Relation`, `Sensitivity` erweitern; Interceptor ruft Stage 2 nach dem Ratenlimit | `identity/middleware/interceptor.go` |
| `api.Route.Object` Pflichtfeld; `VerifyRoutes` weist Routen ohne Objekt ab; jede der 37 Routen deklariert eines | `identity/api/routes.go` |
| Seam-Test: eine Tenant-Route mit echtem FGA — Mitglied ja, Fremder nein, FGA weg → 503 | `identity/test/seam/relation_seam_test.go` |
| Integrationstests, die heute `unreachableAuthz` mounten, bekommen einen Store mit Tupeln oder deklarieren die Erwartung 503 | `identity/test/integration/*` |

Risiko dieser Phase: sie macht die Identity-API zum ersten Mal *streng*. Tenant-Routen, die bisher
für jedes Mitglied der Zitadel-Org offen waren, verlangen jetzt die Relation aus `core.fga`. Das ist
gewollt und der Grund, warum die Tests dieser Phase gegen einen echten Store laufen.

### Phase 2 — Deployment

| Schritt | Dateien |
|---|---|
| OpenFGA: Bind an die private Adresse, Nomad-Service `openfga`, `instance_count` entkoppelt von der Knotenzahl | `identity/deploy/nomad/jobs/openfga.nomad.hcl`, `platform/internal/stages/deploy.go` (`loopbackAllocations` → weg) |
| identity-api und registry-api: `OPENFGA_URL` aus `nomadService` | `identity/deploy/nomad/jobs/identity-api.nomad.hcl`, `registry/deploy/nomad/jobs/registry-api.nomad.hcl` |
| Vault: `registry-api.hcl` liest `secret/data/identity/fga`; Test wie `deployerpolicy_test.go` | `platform/deploy/vault/policies/registry-api.hcl`, `platform/internal/stages/registrypolicy_test.go` |
| `envcheck`: drei `REGISTRY_OPENFGA_*`-Pflichtwerte; `toob-ops` reicht `STAFF_USER_IDS`/`SECURITY_ADMIN_USER_IDS` durch | `platform/internal/engine/envcheck.go`, `platform/cmd/toob-ops/main.go` |
| `fga-admin staff` (D6), aufgerufen vom `openfga-provision`-Job nach dem Modell | `identity/cmd/fga-admin/staff.go`, `identity/deploy/nomad/jobs/openfga-provision.nomad.hcl` |
| Graph: die Kante identity-api → openfga wird eine Service-Kante statt Loopback | `platform/internal/graph/nomad.go` |

### Phase 3 — Die Registry

| Schritt | Dateien |
|---|---|
| Konfiguration + FGA-Client im App-Aufbau (dieselben Konstruktoren wie identity-api, `SingleStoreResolver` aus `identity/authz`) | `registry/internal/config`, `registry/internal/server/app/app.go` |
| `PolicyGate` ruft Stage 2 nach dem Ratenlimit; `Access.Object` Pflichtfeld; `VerifyRoutes` prüft es | `registry/internal/server/middleware/policy.go`, `router/routes.go` |
| Objektquellen der Registry: `NamespaceFromPath`, `PackageFromPath`, `JobFromPath` — Name → ID über die Stores, kontextuelle Tupel nach D2 | `registry/internal/server/router/objects.go`, `objects_test.go` |
| Admin-Routen: `ObjectPlatform()`, der 501-Zweig (`platformNotConfigured`) und `TODO(D5)` verschwinden | `router/routes.go` |
| `PolicyEngine` → `naming` (D8); Handler verlieren ihre Authorizer-Aufrufe; Tests folgen | `registry/internal/server/authz/` → `naming/`, `handler/*.go`, `domain/permission.go` |
| Routentabellen-Test: jede Route hat ein Objekt; jede Katalog-Relation existiert im Modell | `router/contract_test.go` |
| Registry-Integrationstest: Owner darf löschen, Member nicht; Staff erreicht `/admin/status`, Nicht-Staff bekommt 403; FGA weg → 503 | `registry/test/authz_integration_test.go` |

### Phase 4 — CLI und Dokumentation

| Schritt | Dateien |
|---|---|
| `403 permission_denied`: `detail` anzeigen, kein Retry; `503 authz_unavailable`: Retry nach Header (existiert für 429, wird auf 503 ausgedehnt) | `cli/toob-cli/internal/apiclient/client.go` |
| `identity_login.md` §5/§6/§8: Stage 2 ist verdrahtet, 501 ist weg; `identity_datamodel.md`: Modell; `plan7_backlog.md`: D5 erledigt | `docs/*.md` |

---

## 4. Was bewusst nicht in diesem Plan ist

- **Kein Tupel-Schreiber in der Registry.** Erst wenn ein anderer Dienst Registry-Beziehungen
  abfragen muss (D2).
- **Kein `ListObjects`.** Listen bleiben SQL; FGA entscheidet über Objekte, die die Anfrage nennt.
- **Kein Store pro Tenant.** `SingleStoreResolver` bleibt; die Registry nimmt denselben Store.
- **Kein zweiter Login für die Identity-API in der CLI.** Die Audience ist dieselbe (F10). Ein
  `toob identity …`-Befehl ist ein späterer, kleiner Schritt.

## 5. Offene Entscheidungen

| | Frage | Empfehlung |
|---|---|---|
| **E1** | Netzpfad zu OpenFGA: A (Service Discovery) oder B (Allocations im Registry-Pool)? | A |
| **E2** | Phase 1 macht die Identity-API streng. Jetzt, oder Registry zuerst (Phase 3 vor 1, mit Stage 2 nur dort)? | Jetzt. Der Katalog behauptet es seit Monaten; jede Woche ohne ist eine Woche, in der Tenant-Rollen nichts entscheiden. |
| **E3** | Staff-Quelle: `.env`-Liste (D6) oder eine Admin-Route `POST /api/v1/platform/staff` mit Vier-Augen? | `.env` jetzt; die Route, sobald es einen zweiten Staff gibt, der den ersten ernennen könnte. |
| **E4** | `maintainer` ins Modell (D4) oder die Registry-Rolle abschaffen? | Ins Modell. Die Rolle existiert in der Datenbank und in der UI. |

---

## 6. Umgesetzt (2026-09-07)

Der Plan ist gebaut, mit vier Abweichungen, die beim Bauen richtiger waren als das Geplante:

| | Plan | Gebaut | Warum |
|---|---|---|---|
| Objekte aus dem Body | nicht vorgesehen | `ObjectDeferred("package")` für `POST /api/v1/publish` und `/publish/promote`; der Handler fragt `relations.Publish`, sobald der Name gelesen ist | Der Paketname steht im Tarball bzw. im JSON. Eine Route, die ihr Objekt nicht kennt, kann Stage 2 nicht im Interceptor laufen lassen — die Deklaration in der Tabelle macht sichtbar, welche zwei das sind (`objects_test.go` pinnt sie). |
| Selbstbedienung | Token-Tupel `tenant:<org>#member` | genau so, in `enforce.RelationGate.withOwnOrganization`; Katalog: sechs Registry-Einträge auf `tenant#member` | — |
| Verlassen einer Namespace | nicht vorgesehen | eigene Route `DELETE /api/v1/orgs/{name}/membership` (`registry.namespace.leave`, `namespace#member`) | Eine Route trägt eine Relation; „Mitglied oder Verwalter" ist keine. Selbstentfernung über die Verwalter-Route wäre für ein einfaches Mitglied 403 gewesen. |
| Rollen vergeben | in `can_manage_members` | `registry.namespace.role.assign` (`namespace#can_manage_roles`), vom Handler gefragt, sobald die Rolle im Body bekannt ist | Ein Maintainer nimmt Mitglieder auf, macht aber niemanden zum Owner. |
| Unbeanspruchter Name | nicht vorgesehen | `relations.Publish` lässt einen unbeanspruchten, ungescopten Namen ohne Store-Frage zu | Kein Tupel könnte „ja" sagen; die Regel „wer zuerst veröffentlicht, dem gehört der Name" ist eine Regel über Namen und steht einmal, dort. |
| Modell | owner/maintainer/member, can_* | zusätzlich `package#reader: [user]` für `package_access` | Lesefreigaben auf ein noch nicht öffentliches Paket gab es in der Datenbank; das Modell musste sie aussprechen können. |
| Staff | `fga-admin staff` | im `openfga-provision`-Lauf (`--staff`, `--security-admins` aus `STAFF_USER_IDS`, `SECURITY_ADMIN_USER_IDS`), abgeglichen, leere Staff-Liste wird abgewiesen | Ein Lauf weniger, und die Tupel entstehen nach dem Modell, das sie brauchen. |
| Netzpfad (E1) | A: Nomad Service Discovery | A ist deklariert (`registry-api.nomad.hcl` liest `nomadService "openfga"`, OpenFGA registriert sich als Service). **Nicht gemessen:** ob Port 8180 der Identity-Knoten aus der Registry-Zelle über das private Netz erreichbar ist — die Zellen sind getrennte Hetzner-Projekte. | Das ist der erste Test nach dem nächsten Deploy; fällt er, ist es eine WireGuard-/Firewall-Regel, kein Code. |

Dazu die Vereinheitlichung der Mandanten, die beim Lesen aufgefallen war (F1–F10 oben, plus drei
neue): ein Tenant ist eine Zitadel-Organisation, ihre ID ist die Tenant-ID in Identity-API, Token,
URN, Store und Registry; `POST /api/v1/tenants` legt die Organisation in Zitadel an
(`identity/idp.OrganizationClient`, Service-User aus `zitadel-provision --apply-api-user`); CI-Token
tragen den Tenant der mintenden Person (`api_tokens.tenant_id`).

Was nicht in diesem Baum liegt: die Messung des Netzpfads, `ListObjects`, eine Outbox für
Registry-Tupel (D2 gilt weiter), und `platform/internal/stages/workers.go` — ein Import-Verstoß
aus einer anderen Sitzung, den `TestMonorepoImportBoundaries` meldet.
