# Social Login (GitHub, Google) und Berechtigungsstufen — Umsetzungsplan

Stand: 2026-09-04. Gegenstand: Anmeldung über GitHub und Google **auf der IdP-Ebene** (Zitadel),
und die Berechtigungsstufen, die dafür an der richtigen Stelle sitzen müssen. Gemessen am
`/quality`-Maßstab: fail-fast, keine Parallelpfade, Abstraktion nach tatsächlicher Nutzung, jede
Entscheidung aus dem Code rekonstruierbar.

Kein Code ist geändert. §8 listet die Entscheidungen, die vor dem Bau zu treffen sind.

---

## 0. Befund: wo die Berechtigungsstufen heute *nicht* sitzen

Der Plan aus dem Gespräch nannte zwei Zeilen — `ForceMFALocalOnly` und ein Publish-Gate. Beim
Lesen der Registry hat sich gezeigt, dass das zweite kein Gate ist, sondern ein fehlendes Modell.
Die Identity-API hat eines (`identity/api/routes.go` → Katalog → Gate-Kette). Die Registry hat
Middleware-Aufrufe von Hand, Datei für Datei.

| # | Fundstelle | Regel | Was falsch ist | Folge |
|---|---|---|---|---|
| F1 | `registry/internal/domain/permission.go:64` | Fail-fast, Integration | `HasPermission` gibt nur für `package:publish` und `org:create` `true`, für alles andere `false`. `RolePermissions` (Z. 33) wird von niemandem gelesen; `domain.User` hat kein Rollenfeld. | **Jede Admin-Route** (`routes_admin.go:22`, `RequirePermission`) antwortet jedem mit 403. Die Berechtigungstabelle ist toter Code, der eine Prüfung *vortäuscht*. |
| F2 | `registry/internal/server/middleware/auth.go:172` | Fail-fast | Der verifizierte `Principal` mit `TrustLevel` und `AuthTime` wird unter `ClaimsContextKeyVal` in den Kontext gelegt — **und von keiner Middleware gelesen.** | Ein L1-Token darf alles, was ein L3-Token darf. Publish (`handler/publish.go:98`) prüft nur `HasPermission`. |
| F3 | `registry/internal/server/authz/policy.go:203` | Fail-fast | `AuthorizeDataRead` vergleicht `usr.TrustLevel == L1`. `EnsureFromIdentity` (`postgres/users.go:64`) setzt das Feld nie, es gibt keine Spalte. Leer ≠ `"L1"`. | Die L1-Sperre für granulare Daten feuert nie — **fail-open**. Heute unerreichbar (kein Router montiert `DevicesHandler`), morgen ein Loch. |
| F4 | `registry/internal/server/router/routes_auth.go:14` + `middleware/auth.go:148` | Fail-fast | `POST /api/v1/tokens` prägt ein CI-Token aus jeder Sitzung. Ein CI-Token trägt **fest L2**. | **Trust-Laundering:** eine L1-Sitzung (GitHub-Login) erzeugt ein L2-Credential. Mit Social Login wird das vom Schönheitsfehler zur Eskalation. |
| F5 | `registry/internal/server/router/routes_public.go` | Integration | Öffentliche Routen sind öffentlich durch **Weglassen** der Middleware. Nichts sagt „diese Route braucht keine Anmeldung". | Ein Tippfehler beim Mounten macht eine Route still öffentlich. Identity kennt dafür `TenantNone()` — „no tenant is something a route *says*". |
| F6 | `registry/internal/server/router/*.go` | Abstraktion | Vier Dateien, drei verschiedene Wickelmuster (`handleAdmin`-Closure, `RequireAuth(RequireScope(...))`, nackt). Kein Tisch, keine Prüfung, kein Vertrag. 81 Muster, nichts zählt sie. | Genau der Zustand, den `identity/api/routes.go` mit `VerifyRoutes` und `ports.Surface` beendet hat. |
| F7 | `middleware/auth.go:219`, `scope.go:22` | Integration | Fehler als `http.Error(w, "{\"error\":…}")`. Kein Problem-Details, kein `WWW-Authenticate`. | Eine Step-Up-Challenge (RFC 9470) kann die Registry nicht aussprechen; `shared/errors` hat den Schreiber dafür. |
| F8 | `identity/token/verifier.go:236` | Fail-fast | Org-Scope Pflicht, niemand fordert ihn an (siehe `identity_login.md §8.1`). | Jeder echte Login wird verworfen. Social-Login-Nutzer landen in der Default-Org, deren ID kein Client kennt. |
| F9 | `identity/internal/zitadel/policies.go:126` | Produktentscheidung | `ForceMFALocalOnly: false` + `MFAInitSkipLifetime: "0s"`. | GitHub-Login → sofortige Passkey-Pflicht. Mauer statt Rampe. |
| F10 | `cli/toob-cli/internal/apiclient/` | Vollständigkeit | Kein Umgang mit `WWW-Authenticate: … insufficient_user_authentication`. | Sobald die Registry Step-Up verlangt, kann die CLI nicht mehr veröffentlichen. |

**Das Bild:** Die Registry hat einen Principal mit Trust Level und benutzt ihn nicht. Sie hat einen
Berechtigungskatalog (`shared/policy`) mit `registry.package.publish = L2, step_up 5m` und liest ihn
nicht. Sie hat eine Rollentabelle, die nie greift. Die „richtige Stelle" für Berechtigungsstufen
existiert in der Registry noch nicht — sie muss erst gebaut werden, und zwar als dasselbe Modell,
das die Identity-API schon hat.

---

## 1. Zielbild: eine Quelle, zwei Dienste, ein Vertrag pro Route

```
policy/permissions.yaml ──policygen──► shared/policy.PermissionCatalog
                                              │
                    ┌─────────────────────────┴──────────────────────────┐
                    ▼                                                    ▼
      identity/api/routes.go                             registry/.../router/routes.go   (NEU)
      Route{Pattern, PermissionID, Tenant, …}            Route{Pattern, Access{…}, Handler}
                    │                                                    │
      identity/ports.Surface  ◄── Test: Bijektion ──►    registry/internal/ports.Surface  (NEU)
```

Drei Eigenschaften, jede durch einen Test gehalten:

1. **Jede Route sagt, was sie verlangt.** Auch „nichts" ist eine Aussage (`Credential: Public`).
   Ein Nullwert ist ungültig, und `Mount` verweigert ihn.
2. **Die Stufe kommt aus dem Katalog, nicht aus der Route.** Eine Route nennt eine Permission-ID;
   `MinTrustLevel`, `StepUp`, `StepUpMaxAge`, `Audit`, `Cost` folgen daraus. Handgeschriebene Level
   neben dem Katalog wären die zweite Quelle, und Identity hat gezeigt, wohin das führt (§5.3 in
   plan7: sechs Namensregeln).
3. **Jede Route steht in `ports.Surface`**, und jeder Surface-Eintrag hat eine Route. Das ist die
   Liste „externer Kommunikation", die angefragt wurde — und der Test, „ob es gesetzt ist pro
   Markierung", ist die Bijektion plus `VerifyRoutes`.

**Warum die Berechtigung in der Routentabelle steht und nicht in `ports.go`:** `ports` beschreibt
*Formen* (was rein- und rausgeht) und darf keine Handler importieren. Die Routentabelle *montiert*
die Middleware und ist der einzige Ort, der die Permission wirklich liest. Stünde sie in beiden,
wären es zwei Besitzer; stünde sie nur in `ports`, müsste der Router von dort lesen und `ports`
würde zur Enforcement-Quelle — dann wäre `ports` nur noch ein zweiter Name für die Routentabelle.
Identity hat diese Trennung bereits, mit einem Test, der beide verbindet. Die Registry bekommt
dieselbe.

---

## 2. Arbeitspaket A — Registry: Zugriffsmodell

### A.1 Die Routentabelle

`registry/internal/server/router/routes.go`:

```go
// Credential says who may present themselves on a route. The zero value is not a credential:
// a route that names none is refused at mount time rather than mounted open.
type Credential int

const (
    credentialUnset Credential = iota
    Public                       // no Authorization header expected
    OptionalAuth                 // a credential is verified if present, the route serves without one
    Session                      // an identity token; CI tokens are refused (today: RequireSessionToken)
    SessionOrCI                  // an identity token or a CI token
)

type Access struct {
    Credential Credential
    // PermissionID names the shared/policy catalog entry a person exercises. Required for Session
    // and SessionOrCI, forbidden for Public and OptionalAuth — a public route with a permission
    // would state a requirement nothing checks.
    PermissionID string
    // CIPermissionID is the catalog entry a CI token exercises on the same route. Required for
    // SessionOrCI, forbidden otherwise. Two entries and not one, because the catalog describes one
    // actor per permission and the two are not the same actor: a person can be asked for a fresh
    // passkey, a machine cannot — enforce.StepUpGate refuses a service account outright, and
    // enforce.TrustGate never lets one above L1. A single human permission with step_up on a route
    // CI publishes through would refuse every CI publish; a single L1 permission would drop the
    // person's step-up. Naming both is what lets VerifyRoutes check each against its actor.
    CIPermissionID string
    // Scope is the API-token scope a CI token must carry ("publish", "read", …). Only meaningful
    // for SessionOrCI; identity sessions carry every scope.
    Scope string
}

type Route struct {
    Pattern string
    Access  Access
    Handler http.HandlerFunc
    // NonProductionOnly marks a route that exists for integration tests and staging checks. It
    // replaces the two `if !IsProduction()` blocks with a declaration the table can be checked for.
    NonProductionOnly bool
}

func Routes(h Handlers) []Route
func Mount(mux *http.ServeMux, deps MountDeps, routes []Route) error
func VerifyRoutes(routes []Route) error
```

`VerifyRoutes` (läuft beim Start *und* im Test mit `Handlers{}`):

- `Credential == credentialUnset` → Fehler mit Pattern.
- `Session`/`SessionOrCI` ohne `PermissionID` → Fehler. `Public`/`OptionalAuth` mit → Fehler.
- `PermissionID` nicht im Katalog → Fehler. Katalog-`ActorType` ohne Principal (`partner`) → Fehler
  (dieselbe Prüfung wie `identity/api.VerifyRoutes`). `ActorType` ohne Authenticator-Assurance
  (`service_account`) auf `PermissionID` → Fehler: die menschliche Seite der Route.
- `SessionOrCI` ohne `CIPermissionID` → Fehler; `CIPermissionID` bei anderem Credential → Fehler.
  `CIPermissionID` mit `ActorType != service_account`, `MinTrustLevel != L1` oder `StepUp` →
  Fehler **beim Start**, nicht per Anfrage: `TrustGate` und `StepUpGate` würden jede CI-Anfrage
  ohnehin abweisen, aber eine Tabelle, die etwas Unerfüllbares verlangt, ist ein Wiring-Fehler.
- `Scope` gesetzt bei etwas anderem als `SessionOrCI` → Fehler.
- Handler `nil` → Fehler (außer im Tabellen-Test).
- Danach `spolicy.VerifyEndpointPolicyCompleteness` über alle Session-Routen, genau wie Identity.

### A.2 Die Kette, die `Mount` baut

```
RequireAuth  →  [Session: refuse CI]  →  TrustGate(catalog)  →  StepUpGate(catalog)  →  [Scope]  →  Handler
```

**Wiederverwendung statt Nachbau.** Die Registry importiert bereits `identity/principal` und
`identity/token`. `identity/enforce.NewTrustGate()` und `NewStepUpGate(clk)` arbeiten auf
`(*enforce.Request, *principal.Principal)` und brauchen sonst nichts. `identity/middleware.
NewFleetPolicyRegistry()` projiziert den Katalog auf `RouteSecurityPolicy` und paniert bei
defektem Katalog beim Start — exakt das gewünschte Verhalten. Beides wird importiert, nicht
kopiert. Die Registry baut aus dem Principal im Kontext einen `enforce.Request{RequiredTrustLevel,
MaxStepUpAge}` und ruft die zwei Gates. Kein zweites Gate-Vokabular, keine zweite Step-Up-Semantik.

**P1, geklärt — und es ist strenger als angenommen.** `enforce/stepup.go:33`: ein Akteur ohne
Authenticator-Assurance bekommt bei gesetztem `MaxStepUpAge` ein **403**, keine Challenge und kein
Überspringen („a machine cannot perform one, so the answer is a plain refusal"). `enforce/trust.go:27`:
ab L2 wird ein solcher Akteur abgewiesen, **unabhängig** vom Level, das der Principal behauptet —
ausdrücklich gegen einen Extraktor, der eine Maschine falsch etikettiert. Genau das tut
`registry/.../auth.go:148`: `ciPrincipal.TrustLevel = L2`. Unter den wiederverwendeten Gates ist
ein CI-Token damit auf **jeder** L2-Route abgewiesen.

Die Konsequenz ist kein Sonderfall im Gate, sondern die Wahrheit im Modell: L1–L3 beschreiben die
Stärke einer *menschlichen* Zeremonie. Ein CI-Token ist **L1** — seine Sicherheit kommt aus dem
Credential (Scope, Widerruf, Bindung an einen Benutzer), nicht aus Assurance. Also: `ciPrincipal.
TrustLevel = L1`, und jede Route, die CI bedient, nennt eine **eigene** Katalog-Permission mit
`actor_type: service_account`, L1, ohne Step-Up (`CIPermissionID`, A.1). Der Katalog beschreibt
dann zwei Akteure ehrlich, statt dass die Registry einen davon still hochstuft.

Wer der Meinung ist, ein CI-Token solle *nicht* veröffentlichen dürfen, entfernt den
`CIPermissionID` von `POST /publish` — und `VerifyRoutes` verlangt dann `Credential: Session`.

**Antworten über `shared/errors`.** `serrors.WriteError` schreibt Problem Details und bei
`ErrStepUpRequired` die RFC-9470-Challenge. Die drei `http.Error`-Stellen in `auth.go`, `scope.go`
werden auf `serrors` umgestellt — nicht aus Schönheit, sondern weil die Challenge sonst nicht
existiert.

**P2, geklärt:** `cli/toob-cli/internal/apiclient/client.go:224` `extractError` liest die Felder
`error` und `message`; findet es keines, nimmt es den rohen Körper unter 512 Bytes. Problem Details
trägt `detail`, `title`, `code` — die CLI zeigt also künftig den JSON-Körper statt einer Zeile.
Nicht brechend, aber unschön; `extractError` lernt `detail` (ein Feld mehr im anonymen Struct,
Arbeitspaket F). Der `APIError`-Vertrag nach außen bleibt.

### A.3 Was aus dem Katalog kommt, und was neu hinein muss

Bestehende `registry.*`-Einträge (`policy/permissions.yaml`):

| ID | Stufe | Step-Up | Route |
|---|---|---|---|
| `registry.package.read` | L1 | — | `OptionalAuth`-Routen brauchen keine ID; für `GET /publish/jobs/*` |
| `registry.package.publish` | **L2** | **5 min** | `POST /api/v1/publish` |
| `registry.package.delete` | L3 | ja | — siehe D3 |
| `registry.namespace.create` | L2 | — | `POST /api/v1/orgs` |

Neue Einträge — mit Begründung, wo die Stufe nicht offensichtlich ist:

| ID | resource#relation | Stufe | Step-Up | Credential | Route |
|---|---|---|---|---|---|
| `registry.package.publish_automated` | package#publisher | L1 | — | **CI** (`publish`) | `POST /publish` — der CI-Zwilling von `publish`; `actor_type: service_account` |
| `registry.package.promote` | package#publisher | L2 | — | Session | `POST /publish/promote` |
| `registry.package.promote_automated` | package#publisher | L1 | — | **CI** (`publish:promote`) | dito |
| `registry.package.unpublish` | package#owner | L2 | — | Session | `DELETE /package/…` — *eigener* Dev-Stand, nicht `delete` (D3) |
| `registry.package.list_own` | package#viewer | L1 | — | Session | `packages/mine`, `check-name` |
| `registry.package.list_own_automated` | package#viewer | L1 | — | **CI** (`read`) | dito |
| `registry.job.read` | package#viewer | L1 | — | Session | `publish/jobs/{id}`, `…/stream` |
| `registry.job.read_automated` | package#viewer | L1 | — | **CI** (`read`) | dito |
| `registry.namespace.read` | namespace#member | L1 | — | Session | `orgs/{name}`, `orgs/mine`, `…/members` |
| `registry.namespace.delete` | namespace#admin | **L3** | ja | Session | `DELETE /orgs/{name}` |
| `registry.namespace.member.add` | namespace#admin | L2 | — | Session | `POST /orgs/{name}/members` |
| `registry.namespace.member.remove` | namespace#admin | L2 | ja | Session | `DELETE …/members/{user_id}` — wie `admin.member.remove` |
| `registry.token.create` | tenant#self_user | **L2** | **ja** | Session | `POST /tokens` — **F4**: prägt L2, verlangt L2 |
| `registry.token.list` | tenant#self_user | L1 | — | Session | `GET /tokens` |
| `registry.token.revoke` | tenant#self_user | L1 | — | Session | `DELETE /tokens/{id}` — Zurücknehmen darf nie mehr kosten als Halten |
| `registry.account.read` | tenant#self_user | L1 | — | Session | `GET /me` |
| `registry.account.read_automated` | tenant#self_user | L1 | — | **CI** | dito — `toob` prüft damit ein CI-Token |
| `registry.billing.upgrade` | tenant#self_user | L2 | — | Session | `POST /billing/upgrade` |
| `registry.admin.dashboard.read` | platform#staff | L2 | — | Session | `admin/status`, `admin/staging`, `admin/releases` |
| `registry.admin.matrix.update` | platform#staff | L3 | ja | Session | `matrix-update`, `matrix/generate`, `bump-format-version` |
| `registry.admin.cache.purge` | platform#staff | L2 | — | Session | `cache-purge` |
| `registry.admin.release.create` | platform#staff | L3 | ja | Session | `accept`, `reject`, `release`, `mirror-push` |
| `registry.admin.package.revoke` | platform#security_admin | L3 | ja | Session | `revoke`, `archive` |
| `registry.admin.plan.set` | platform#staff | L3 | ja | Session | `set-plan` |
| `registry.admin.ecosystem.release` | platform#staff | L3 | ja | Session | `releases/trigger`, `yank`, `unyank`, `{id}/publish`, `deprecate`, `release-jobs/{id}/cancel` |
| `registry.admin.test.webhook` | platform#staff | L2 | — | Session, NonProductionOnly | `mock-webhook` |

Die `_automated`-Zwillinge: fünf Einträge, alle `actor_type: service_account`, L1, kein Step-Up,
`impersonation_allowed: false`. Das Suffix ist die Konvention, an der `VerifyRoutes` nichts prüft —
geprüft wird der `ActorType`. Fünf Zeilen YAML sind der Preis dafür, dass der Katalog nicht
behauptet, eine Maschine führe eine Passkey-Zeremonie aus.

`platform#staff` und `platform#security_admin` existieren in `core.fga`. `tenant#self_user` ist
dort `owner` — für „handelt auf dem eigenen Konto" gibt es im Modell keinen genaueren Begriff; D4
entscheidet, ob einer eingeführt wird. Der Linter verlangt eine nicht-leere Relation ohne
`org_`/`tenant_`/`for_`-Präfix und prüft *nicht* gegen das Modell, also sind beide Wege gangbar.

Public-Routen (kein Katalogeintrag, `Credential: Public`): `registry/*`, `resolve/*`, `search`,
`releases/*/download/*`, `/packages/`, `auth/config`, `ecosystem/compilers` (NonProductionOnly),
`billing/webhook`, `health`, `ready`. `OptionalAuth`: `GET /api/v1/package/*`.

Webhook-Routen (`/webhook/*`) bleiben außerhalb der Tabelle — sie authentifizieren mit HMAC, nicht
mit einem Principal, und laufen auf einem eigenen Mux. Sie bekommen einen `Surface`-Eintrag mit
`Credential: Public` und der Bemerkung, dass `VerifyWebhookSignature` davor steht; so sind sie
sichtbar, ohne so zu tun, als trüge die Tabelle ihre Prüfung.

### A.4 Was gelöscht wird

Gelöscht, nicht adaptiert — „eine Form kann nicht von sich selbst abdriften":

- `domain.HasPermission`, `domain.RolePermissions`, `domain.Permission` und die `Perm*`-Konstanten
  (`permission.go:8–70`). Die drei Handler-Aufrufe (`publish.go:98, 281, 470`, `organization.go:58`)
  fallen weg: die Stufe steht vor dem Handler, der Handler prüft Stage 2 (`PolicyEngine`).
- `middleware.RequirePermission`, `middleware.RequireSessionToken` — beides wird von `Mount` aus
  `Access` abgeleitet.
- `domain.TrustLevel`, `domain.User.TrustLevel`, `TrustLevelContextKey` (`user.go:28–43`): eine
  zweite Trust-Level-Definition neben `principal.TrustLevel`, nie befüllt (F3). `AuthorizeDataRead`
  liest künftig den Principal aus dem Kontext.
- Die `handleAdmin`-Closure und die vier `register*Routes`-Funktionen — ersetzt durch die Tabelle.

`OrgAction`, `PackageAction`, `PolicyEngine` bleiben: das ist Stage 2 (Ressource), nicht Stage 1
(Assurance), und Identity trennt genau so.

### A.5 `registry/internal/ports`

Spiegel von `identity/ports`: `APIVersion`, `Contract{Request, Response, Pending}`, `Surface`.
Deklariert werden zunächst die Typen, die es schon gibt (`AuthConfigResponse`, `Profile`, die
Org-Antworten); der Rest ist `Pending` mit Grund. Die Tests aus `identity/api/contract_test.go`
werden übernommen:

- `TestSurface_CoversEveryRoute` gegen `router.Routes(Handlers{})` — beide Richtungen.
- `TestSurface_ReportsWhatIsStillUndeclared`, `TestSurface_DeclaredEntriesCarryTypes`,
  `TestPortTags_EveryFieldIsClassified`.
- **Neu:** `TestRoutes_VerifyWithoutHandlers` — `VerifyRoutes(Routes(Handlers{}))` bis auf den
  nil-Handler-Fehler, damit die Tabelle ohne Datenbank prüfbar ist.
- **Neu:** `TestRouter_NoRouteOutsideTheTable` — parst die Router-Dateien und weist jedes
  `mux.Handle`/`HandleFunc` außerhalb von `Mount` zurück. Dieselbe Technik wie
  `TestOrgRouteLiteralsAreReservedNames`. Ohne diesen Test kann die Tabelle umgangen werden, und
  eine umgehbare Pflicht ist keine.

Die CLI hält in `cli/toob-cli/internal/ports` bereits die Client-Seite mit Assertions gegen
`apiclient`. Ein Server-`ports` ist genau der Spiegel, den der Kommentar in `identity/ports`
„still open" nennt. Ein Vertragstest über beide Repos ist nicht baubar (getrennte Module); die
Kopplung bleibt das Pattern.

---

## 3. Arbeitspaket B — Token-Verifier: die Organisation, die jeder hat

`identity/token/verifier.go`, `extractOrgID`:

```go
const (
    orgScopePrefix     = "urn:zitadel:iam:org:id:"
    resourceOwnerClaim = "urn:zitadel:iam:user:resourceowner:id"
)
```

Regel: `resourceowner:id` ist die Organisation, in der der Benutzer *lebt*; der Org-Scope ist die,
in der er sich *angemeldet* hat. Beide vorhanden und verschieden → `ErrOrgClaimConflict` (ein Token,
das sich selbst widerspricht, wird nicht geraten). Nur eines → das. Keines → `ErrMissingOrgClaim`
bleibt. Der Verifier wird damit nicht weicher: die Anforderung „ein Token nennt seine Organisation"
bleibt, sie wird nur erfüllbar.

`registry/internal/server/handler/authconfig.go`, `requiredScopes` +=
`urn:zitadel:iam:user:resourceowner`. Die CLI liest die Scopes von dort und ändert sich nicht.

Tests: Vektor mit beiden Claims (gleich), mit beiden (verschieden → Fehler), nur Claim, nur Scope,
keines. `identity/test/tokens/issuer.go` erzeugt künftig beides, wie Zitadel.

→ **Prüfpunkt P3:** Claim-Name gegen 4.16.2 messen (ein Login, ein Token, ein Blick).

---

## 4. Arbeitspaket C — Zitadel: IdP-Provisionierung

### C.1 Die Deklaration

`identity/internal/zitadel/idps.go`:

```go
type IdPKind string
const (IdPGitHub IdPKind = "github"; IdPGoogle IdPKind = "google")

// IdPOptions is what Zitadel calls ProviderOptions, spelled the way the API returns it so the
// read-back can be compared field by field, like every policy struct in policies.go.
type IdPOptions struct {
    IsLinkingAllowed  bool   `json:"isLinkingAllowed"`
    IsCreationAllowed bool   `json:"isCreationAllowed"`
    IsAutoCreation    bool   `json:"isAutoCreation"`
    IsAutoUpdate      bool   `json:"isAutoUpdate"`
    AutoLinking       string `json:"autoLinking"`
}

type IdPSpec struct {
    Name    string      // adoption key
    Kind    IdPKind
    Scopes  []string
    Options IdPOptions
}

// IdPCredential is what the operator registered at the provider. It is read from Vault, handed to
// the write call, and appears in no report and no log. There is no field for it on IdPSpec so
// that nothing can put it there by configuration.
type IdPCredential struct{ ClientID, ClientSecret string }

func InstanceIdPs() []IdPSpec {
    return []IdPSpec{
        {Name: "github", Kind: IdPGitHub, Scopes: []string{"user:email"}, Options: socialOptions()},
        {Name: "google", Kind: IdPGoogle, Scopes: []string{"openid", "email", "profile"}, Options: socialOptions()},
    }
}

func socialOptions() IdPOptions {
    return IdPOptions{
        IsCreationAllowed: true,   // this *is* the self-registration, and it is only here
        IsAutoCreation:    true,   // a form between IdP and account would check nothing the IdP has not
        IsAutoUpdate:      true,   // name and avatar follow the provider
        IsLinkingAllowed:  false,  // linking happens from an authenticated session, after step-up
        AutoLinking:       "AUTO_LINKING_OPTION_UNSPECIFIED", // email-based linking is account takeover
    }
}
```

### C.2 Der Client

`ZitadelClient` (`provisioner.go`) wächst um:

```go
ListIdPs(ctx) ([]IdPRef, error)                                  // {ID, Name, Kind}
GetIdP(ctx, id) (IdPObserved, error)                             // {Name, Kind, ClientID, Scopes, Options} — kein Secret
AddIdP(ctx, spec IdPSpec, cred IdPCredential) (string, error)    // POST /admin/v1/idps/{github|google}
UpdateIdP(ctx, id string, spec IdPSpec, cred IdPCredential) error // PUT  /admin/v1/idps/{github|google}/{id}
```

Der HTTP-Client in `cmd/zitadel-provision/idps.go` nach dem Muster von `oidcapp.go` und
`policies.go` (`getWrapped`, `requireSuccess`). Die Pfade sind aus der Zitadel-Dokumentation und
**vor dem ersten Lauf zu messen** → **P4**. Was den Plan trotzdem tragfähig macht: ein falscher
Feldname ist wegen des Read-Back-Diffs ein *lauter* Fehler mit Feldname, kein stiller.

### C.3 Der Ablauf

`Provisioner.ProvisionIdPs(ctx, creds CredentialSource)`:

1. `creds.Credential(name)` aus Vault (`secret/data/identity/idp/<name>`, Felder `client_id`,
   `client_secret`). **Fehlt eines → Abbruch**, mit Pfad. Kein Provider ohne Credential.
2. `ListIdPs`; ein Eintrag gleichen Namens wird **adoptiert**. Gleicher Name, anderer `Kind` →
   Abbruch: das ist nicht der Provider, den dieses Deployment meint.
3. Adoptiert: `GetIdP` → `diffPolicy("idp/"+name, declared, observed)` über `Scopes`, `Options` und
   `ClientID` (Vault gegen Read-Back). Divergenz → `UpdateIdP` mit Spec und Credential; danach
   erneut lesen und vergleichen; verbleibende Divergenz → Abbruch mit Feldname.
4. Nicht vorhanden: `AddIdP`, dann Read-Back-Diff wie in 3.
5. `DetectPolicyDrift` wird um die IdPs erweitert, damit `--check-drift` einen in der Konsole
   geänderten Provider meldet.

Secret-Rotation ist **kein** Nebeneffekt: `UpdateIdP` wird nur bei Divergenz gerufen, und das
Secret ist nicht Teil des Diffs (Zitadel gibt es nicht zurück). Rotation = `--rotate-idp-secret
<name>` als expliziter Flag, der `UpdateIdP` unbedingt aufruft. Reihenfolge beim Provider: neues
Secret anlegen → Vault → Flag → altes löschen; GitHub und Google erlauben zwei gleichzeitig.

### C.4 Tests (`idps_test.go`, Mock-Client wie `oidcapp_test.go`)

adoptiert statt dupliziert · legt an, wenn keiner da ist · verweigert bei fehlendem Secret ·
verweigert bei Kind-Mismatch · Divergenz einer Option führt zu Update · verbleibende Divergenz ist
ein Fehler mit Feldname · **das Secret erscheint in keinem Report-String** (Test marshalt Report
und Fehler, sucht das Secret, erwartet Abwesenheit).

---

## 5. Arbeitspaket D — Instanz-Policy

`InstancePolicy()`: `ForceMFALocalOnly: true`. Eine Zeile, ein eigener Commit, weil sie allein die
Sicherheitslage verschiebt: IdP-Anmeldungen kommen als L1 herein, statt an der Passkey-Pflicht zu
scheitern. `ForceMFA`, `AllowRegister: false`, `MFAInitSkipLifetime: "0s"` bleiben.

Was das **nicht** ändert: `computeTrustLevel` kennt kein GitHub. Ein IdP-Token hat kein
phishing-resistentes `amr`, also L1 — fail-closed, ohne Codeänderung. Die Sicherheit sitzt danach
dort, wo A sie hinlegt: an der Permission.

---

## 6. Arbeitspaket E — Deploy, Vault, Caddy

- `platform/internal/stages/deploy.go:437`: `--apply-idps` neben `--apply-signin-app`, mit
  `--idp-vault-prefix secret/data/identity/idp`. Test analog `signinclient_test.go`: die
  Kommandozeile trägt den Flag.
- `platform/deploy/vault/policies/deployer.hcl`: `read` auf `secret/data/identity/idp/*`. Kein
  Schreibrecht — die Secrets legt der Operator an, der Deployer liest sie nur.
- Wizard/Prereq: die zwei Pfade werden als Voraussetzung geprüft wie das Origin-Zertifikat in
  §10.3-AT — vor Phase 6, mit Namen. Ein Deploy ohne sie scheitert am Tor, nicht in Zitadel.
- `Caddyfile-identity.j2`: **P5** — ob `respond /ui/login/register* 403` den Auto-Creation-Schritt
  des externen Logins trifft. Wenn ja, wird das Muster auf den lokalen Registrierungspfad verengt;
  gelöscht wird es nicht.

---

## 7. Arbeitspaket F — CLI: Step-Up

Mit A verlangt `POST /publish` für Menschen eine Anmeldung, die höchstens 5 Minuten alt ist
(Katalog). Die CLI muss die Challenge lesen:

`apiclient`: auf `401` mit `WWW-Authenticate` und `error="insufficient_user_authentication"` die
Werte `acr_values` und `max_age` parsen, einmal `oidc.StartBrowserLogin` mit `prompt=login` und
`max_age` wiederholen, Session speichern, Anfrage **einmal** wiederholen. Kein zweiter Versuch
danach — eine zweite Challenge ist ein Serverzustand, kein Timing. Nur für Sitzungen: trägt die
Anfrage ein CI-Token, gibt es nichts zu wiederholen, und der 403 aus dem Gate wird gezeigt.

`extractError` (`client.go:224`) lernt das Problem-Details-Feld `detail` (P2), damit die Meldungen
der umgestellten Registry wieder einzeilig ankommen.

→ **P6:** ob Zitadel bei `max_age` einen Nutzer *ohne* zweiten Faktor in die Registrierung führt
oder abweist. Davon hängt ab, ob die Rampe ein Redirect ist oder ein eigener Onboarding-Schritt in
der UI.

---

## 8. Entscheidungen

| # | Frage | Empfehlung | Warum |
|---|---|---|---|
| **D1** | Stufen aus dem Katalog oder lokale Tabelle in der Registry? | **Katalog.** | Der Katalog sagt schon `publish = L2`. Eine Tabelle daneben ist die zweite Quelle; welche gewinnt, wüsste niemand. |
| **D2** | Publish-Step-Up 5 min für Menschen beibehalten? | **Ja**, mit F. | Ein gestohlenes `credentials.json` (Refresh 8 h) könnte sonst 8 h lang veröffentlichen. Publish ist die Supply-Chain-Aktion. CI-Token laufen über `publish_automated` (L1, kein Step-Up) und sind nicht betroffen. |
| **D2b** | CI-Token als L1 etikettieren und für jede CI-Route einen `_automated`-Zwilling führen? | **Ja.** | P1: die wiederverwendeten Gates lassen keine Maschine über L1 und weisen sie bei Step-Up ab. Die Alternative — die Registry setzt Step-Up für Maschinen still aus — wäre eine zweite Step-Up-Semantik und ein Katalog, der lügt. |
| **D3** | Unpublish eines Dev-Standes: neues `registry.package.unpublish` L2 oder vorhandenes `delete` L3? | **Neu, L2.** | `delete` meint ein veröffentlichtes Paket. Den eigenen Entwurf zurückzuziehen mit L3 zu belegen, bestraft die falsche Handlung. |
| **D4** | Relation für Konto-Operationen (`tokens`, `me`, `billing`)? | `tenant#self_user` **vorerst**; sauberer wäre eine Relation `account#self` im Modell. | Modelländerung zieht durch Store-Provisionierung und Linter Rule 3. Erst benutzen, dann benennen — aber im YAML kommentieren, dass es ein Platzhalter ist. |
| **D5** | Wer ist `platform#staff`? Die Registry hat keinen FGA-Client. | **Eigenes Arbeitspaket:** FGA-Check über `identity/authz` (Store aus `secret/data/identity/fga`). Bis dahin montiert `Mount` Routen mit `platform`-Resource **nicht** und meldet das beim Start namentlich. | Heute sind sie ohnehin tot (F1) — der Unterschied ist, dass es ab jetzt *gesagt* wird. Ein `staff`-Flag in der Registry-DB wäre die dritte Rollenquelle. |
| **D6** | IdP-Menge je Umgebung gleich, Secrets Pflicht? | **Ja.** | dev/staging/prod haben je eigene OAuth-Apps; eine Umgebung ohne ist unfertig, nicht anders. Ein `--skip-idps` wäre der `failed_when: false` von §10.3-AK. |
| **D7** | `identity/enforce`-Gates und `FleetPolicyRegistry` in der Registry importieren oder nachbauen? | **Importieren.** | Registry → Identity ist bereits die Abhängigkeitsrichtung. Zwei Step-Up-Semantiken sind zwei Bugs. |

---

## 9. Reihenfolge und Prüfpunkte

| Welle | Inhalt | Offline testbar | Braucht |
|---|---|---|---|
| **0** | A (Routentabelle, Gates, Katalog-Einträge, `ports`, Löschungen) + B (Verifier) | ja | D1–D4, D7 |
| **1** | C (IdP-Provisionierung) + Tests | ja, Mock-Client | D6 |
| **2** | D (Policy) + E (Deploy, Vault) + F (CLI) | ja bis auf Caddy | D2, D5 |
| **3** | Messungen P1–P6 an der laufenden 4.16.2, dann erster `--apply-idps` | nein | grüner Deploy |

| P | Was | Wo |
|---|---|---|
| ~~P1~~ | **Geklärt:** StepUpGate weist Maschinen ab, TrustGate lässt sie nie über L1 → D2b | `enforce/stepup.go:33`, `trust.go:27` |
| ~~P2~~ | **Geklärt:** CLI liest `error`/`message`, fällt auf Rohkörper zurück → F lernt `detail` | `apiclient/client.go:224` |
| P3 | Name des Resource-Owner-Claims | ein Token der Instanz |
| P4 | Admin-API-Pfade und GET-Form für IdPs | ein `curl` gegen 4.16.2 |
| P5 | Trifft Caddys Register-Sperre den IdP-Callback? | ein Login-Versuch |
| P6 | Step-Up ohne zweiten Faktor → Enrollment oder Ablehnung? | ein Login-Versuch |

Vor Welle 3 ist nichts davon nötig; die Wellen 0–2 sind vollständig testbar und ändern für
Bestandsnutzer genau zwei Dinge, beide beabsichtigt: L1 kann nicht mehr veröffentlichen, und
Admin-Routen sagen, warum sie nicht antworten, statt still 403 zu geben.

---

## 10. Nicht enthalten

- `requires_signature: true` auf `registry.package.publish` (detached JWS über den DPoP-Schlüssel):
  die CLI hat kein DPoP. Der Katalog behauptet es, die Registry setzt es nicht durch — das wird im
  YAML als Kommentar benannt, nicht still ignoriert.
- Konto-Verknüpfung aus den Einstellungen heraus (Welle 5 des ursprünglichen Plans).
- GitHub-Org-Mitgliedschaft als Beitrittsnachweis (`github_upstream_policy`, `read:org`) — eigener
  Provider, eigener Zeitpunkt.
- Der FGA-Client in der Registry (D5).

---

## 11. Umgesetzt (2026-09-04)

Alle Wellen 0–2 sind gebaut und offline getestet. Was offen bleibt, sind die Messungen P3–P6
gegen die laufende Zitadel 4.16.2 und die Arbeitspakete, die der Plan ausdrücklich ausgenommen hat
(§10).

| Paket | Stand | Wo |
|---|---|---|
| **A** Registry-Zugriffsmodell | ✅ Routentabelle mit Pflichtfeld `Access`, `VerifyRoutes`, `Mount`; `PolicyGate` aus `identity/enforce` + `FleetPolicyRegistry`; `registry/internal/ports` mit Bijektions-Tests und Source-Guard; `HasPermission`, `RolePermissions`, `TrustLevel` auf `User`, `RequirePermission`, `RequireSessionToken`, `DevicesHandler`, `AuthorizeDataRead` gelöscht | `registry/internal/server/router/routes.go`, `middleware/policy.go`, `ports/ports.go` |
| **A** Katalog | ✅ 28 neue `registry.*`-Einträge, darunter fünf `_automated`-Zwillinge für CI (D2b); Katalogversion `V1Kog8ptO4LITqpk` | `policy/permissions.yaml` |
| **B** Verifier | ✅ liest `urn:zitadel:iam:user:resourceowner:id`; Org-Scope weiter akzeptiert; Widerspruch → `ErrOrgClaimConflict`; Registry veröffentlicht den Scope | `identity/token/verifier.go`, `registry/.../authconfig.go` |
| **C** IdP-Provisionierung | ✅ `IdPSpec`, `InstanceIdPs()`, `ProvisionIdPs`, `DetectIdPDrift`, `--apply-idps`, `--idp-vault-prefix`, `--rotate-idp-secret`; 10 Tests inkl. „Secret erscheint nirgends" | `identity/internal/zitadel/idps.go`, `identity/cmd/zitadel-provision/idps.go` |
| **D** Policy | ✅ `ForceMFALocalOnly: true` | `identity/internal/zitadel/policies.go` |
| **E** Deploy/Vault/Seed | ✅ `SEED_IDP_*` in envcheck, Container-Forwarding, Ansible (`mandatory`), `seed.sh` (`:?`), `deployer.hcl` read auf `secret/data/identity/idp/*`, Deploy-Stufe übergibt beide Flags; drei Konsistenztests | `platform/…`, `platform/internal/stages/idpcredentials_test.go` |
| **F** CLI | ✅ `extractError` liest `detail`; `StepUpRequired` aus `WWW-Authenticate`; `StartBrowserStepUp` (`prompt=login`, `acr_values`, `max_age`); `withStepUp` mit genau einer Wiederholung bei `publish` und `tokens create` | `cli/toob-cli/internal/apiclient`, `internal/oidc`, `cmd/stepup.go` |

**Abweichungen vom Plan, alle nach Befund:**

- **D2b (neu):** CI-Token sind L1 und jede CI-fähige Route trägt einen `_automated`-Zwilling — Folge
  von P1: `enforce.TrustGate` lässt keine Maschine über L1, `StepUpGate` weist sie ab.
- **D5, konkretisiert:** Admin-Routen werden montiert, laufen durch Stage 1 und antworten dann
  **501** mit Problem Details statt nicht montiert zu werden. Ein 501 sagt dem Aufrufer, *warum*;
  ein 404 könnte ein Tippfehler sein. Beim Start werden die betroffenen Routen namentlich geloggt.
  Markiert als `TODO(D5)` in `routes.go`.
- **`DevicesHandler` gelöscht** statt umgestellt: nirgends montiert, Demo-Daten, einziger Aufrufer
  von `AuthorizeDataRead`. Die Regel (L1 sieht Aggregate) steht im Katalog als
  `fleet.device.list`/`fleet.device.read_granular`.
- **Org- und Token-Verwaltung sind Session-only.** Vorher nahm `RequireAuth` dort auch CI-Token an.
  Ein CI-Token, das CI-Token prägt, wäre ein Credential, das sich selbst erneuert. Die
  Integrationsphasen (`registry/test/integration`), die mit `AliceAPIKey` Orgs anlegen, sind
  davon betroffen und waren durch F1 ohnehin bereits inkonsistent.
- **Secrets via `seed.sh` statt Deploy-Stufe** (Vorschlag DevOps): der bestehende Weg
  `.env.<env>` → `TOOB_<ENV>_`-Präfix → Container → Ansible → `seed.sh` → Vault wird benutzt,
  nicht ein zweiter Schreiber. Die Identity-Pfade werden nicht mehr nach `projects/registry/`
  gespiegelt.

**Vor dem ersten Lauf zu messen** (P3–P6, unverändert): Resource-Owner-Claim-Name, IdP-Admin-API
und Read-Back-Form, Caddys Register-Sperre gegen den IdP-Callback, Step-Up ohne zweiten Faktor.
