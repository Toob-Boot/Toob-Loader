# Toob Identity — Registrierung, Anmeldung, Token

Stand: 2026-09-03. Quelle ist der Code in `toob-infra/identity`, `toob-infra/registry`,
`toob-infra/platform/deploy` und `cli/toob-cli`, nicht die Planungsprosa — wo Plan und Code
auseinandergehen, steht der Code hier und der Plan in „Was noch fehlt".

Diese Datei ist für jemanden geschrieben, der einen **Login-Screen in einem anderen Repository**
baut und keinen Zugriff auf diesen Baum hat.

---

## 1. Wer hier was macht

Drei Bausteine, drei getrennte Zuständigkeiten:

| Baustein | Rolle | Läuft auf |
|---|---|---|
| **Zitadel** (v4.16.2) | Der Identity-Provider. Er hält Benutzer, Passwörter, Passkeys, MFA, Organisationen — und er **stellt die Token aus**. Er bringt seine eigene Login-UI mit. | Identity-Zelle, intern `localhost:8080` |
| **`identity-api`** (eigener Go-Dienst) | *Keine* Anmeldung. Er ist die **Governance-Fläche**: Organisationen, Mitglieder, Rollen, Audit, Break-Glass, Impersonation, SCIM-Token. Er *verifiziert* Zitadel-Token, er stellt keine aus. | Identity-Zelle, intern `:8082` (API) und `:8083` (SCIM) |
| **OpenFGA** | Die Autorisierung („darf dieser Principal das?"). Kein Login, keine Token. Wird aus Mitgliedschaftsänderungen über eine Outbox gefüttert. | Identity-Zelle, intern |

Merksatz: **Zitadel authentifiziert, OpenFGA autorisiert, `identity-api` verwaltet.**
Ein Login-Screen redet mit **Zitadel**, nicht mit `identity-api`.

### 1.1 Hostnamen

Bewusst drei getrennte Hosts, Geschwister und nicht Vater/Kind — ein Cookie mit
`Domain=id-dev.the-toob.com` würde auch an `api.id-dev.the-toob.com` gehen, deshalb keine Subdomain:

| Zweck | dev | staging | production |
|---|---|---|---|
| **IdP / Login-UI / OIDC** | `id-dev.the-toob.com` | `id-staging.the-toob.com` | `id.the-toob.com` |
| **Governance-API + SCIM** | `accounts-dev.the-toob.com` | `accounts-staging.the-toob.com` | `accounts.the-toob.com` |
| **Registry (Produkt-API)** | `registry-dev.the-toob.com` | `registry-staging.the-toob.com` | `registry.the-toob.com` |

Der Grund für die Trennung steht im Code (`platform/internal/topology`): *„an IdP sharing a cookie
domain with the application it authenticates is one cross-site scripting bug away from an
authentication bypass."*

**Der OIDC-Issuer ist `https://<identity-domain>`**, abgeleitet und nirgends doppelt konfiguriert
(`identity/token/endpoints.go`):

```go
Issuer(domain)  = "https://" + domain              // https://id-dev.the-toob.com
JWKSURL(domain) = Issuer(domain) + "/oauth/v2/keys"
```

Discovery liegt wie vom Protokoll verlangt unter
`https://id-dev.the-toob.com/.well-known/openid-configuration`.

---

## 2. Registrierung

Hier sind zwei Ebenen zu trennen, und sie werden leicht verwechselt:

| Ebene | Selbstregistrierung? |
|---|---|
| **Konto beim IdP** (Zitadel-Benutzer, Passkey, MFA) | **Nein.** Invitation-only, hart gesperrt (§2.1) |
| **Konto in der Registry** (Publisher, Pakete, Orgs) | **Ja, automatisch** beim ersten Login (§2.3) |

Anders gesagt: **wer sich anmelden kann, ist in der Registry sofort und ohne Antrag vollwertig
dabei.** Der Flaschenhals sitzt eine Ebene tiefer — beim Anlegen des IdP-Kontos.

### 2.1 Beim IdP gibt es keine Selbstregistrierung

**Ein „Sign up"-Button hat auf der IdP-Ebene keinen Endpunkt.** Zwei Stellen setzen das unabhängig
voneinander durch.

**1. Instanz-Policy** (`identity/internal/zitadel/policies.go`, `InstancePolicy()`):

```go
AllowRegister:          false   // keine Selbstregistrierung
AllowUsernamePassword:  true
AllowExternalIDP:       true    // Kunden-IdP (Okta, Entra, …) erlaubt
ForceMFA:               true
PasswordlessType:       "PASSWORDLESS_TYPE_ALLOWED"   // Passkeys
HidePasswordReset:      true    // kein Self-Service-Reset
IgnoreUnknownUsernames: true    // keine Konto-Enumeration
DisableLoginWithPhone:  true
MFAInitSkipLifetime:    "0s"    // MFA-Einrichtung ist nicht aufschiebbar
```

Zweiter Faktor: **nur `SECOND_FACTOR_TYPE_U2F`** (WebAuthn/FIDO2). OTP/TOTP ist bewusst
*entfernt* — `ForceMFA` verlangt nur *irgendeinen* zweiten Faktor, und mit erlaubtem OTP wäre die
Instanz nicht phishing-resistent.

Passwort-Policy, falls doch mit Passwort angemeldet wird: **16 Zeichen**, Groß, Klein, Ziffer,
Sonderzeichen; 90 Tage Maximalalter, 14 Tage Vorwarnung. Lockout nach
`spolicy.MaxFailedPasswordAttempts`.

**2. Caddy blockt die Endpunkte hart**
(`platform/deploy/ansible/roles/caddy/templates/Caddyfile-identity.j2`):

```
respond /ui/login/register*        "Registration is invitation-only"                403
respond /v2/users/register*        "Registration is invitation-only"                403
respond /v1/users/register*        "Registration is invitation-only"                403
respond /ui/login/password*        "Password authentication is disabled. Use Passkeys/WebAuthn" 403
respond /v2/users/*/password       "Password authentication is disabled"            403
respond /ui/login/password/reset*  "Self-service recovery is disabled …"            403
```

Zusätzlich sind `/ui/console*`, `/ui/admin*`, `/console*`, `/metrics*`, `/debug*` von außen 403 —
die Admin-Konsole ist **nur über WireGuard** (`10.9.0.0/16`, `10.20.0.0/16`) erreichbar.

### 2.2 Wie ein IdP-Konto also entsteht

Drei legitime Wege, alle ohne Beteiligung des Login-Screens:

1. **SCIM-Provisionierung durch den Kunden-IdP.** Der Mandant stellt sich über
   `POST /api/v1/tenants/{id}/scim-token` ein Bearer-Token aus und trägt
   `https://accounts-dev.the-toob.com/scim/v2/{tenantID}` in Okta/Entra ein. Deren SCIM-Connector
   legt Benutzer und Gruppen an (`identity/scim`). Eine Gruppe trägt dabei **keine Rolle** — die
   Rolle kommt aus einem Mapping, das ein Operator mit L2 und Step-Up setzt
   (`PUT /api/v1/tenants/{id}/scim-groups/{groupId}`). Eine ungemappte Gruppe gewährt nichts.
2. **Einladung durch einen Organisations-Admin**:
   `POST /api/v1/tenants/{id}/members` mit `{"user_id": …, "role": "owner"|"admin"|"member"}`.
   Nur diese drei Rollen sind direkt zuweisbar — `operator`, `manager`, `self_user`, `support`
   sind im FGA-Modell *berechnet*, `break_glass_operator` darf nie in den Store geschrieben werden.
   Die Zuweisung wird gegen das erzeugte Modell validiert (`ValidateMembershipRole`), nicht gegen
   eine Liste im Handler.
3. **Externer IdP (Federation).** `AllowExternalIDP: true`. Der Trust Level kommt auch hier aus
   `amr`/`acr` des ausgestellten Tokens (§4.4): ohne phishing-resistenten Wert vom fremden IdP
   bleibt die Sitzung L1, und jede L2-Route antwortet mit der Step-Up-Challenge (§5.3).

### 2.3 In der Registry gibt es sehr wohl Selbstregistrierung — und keinen Org-Zwang

Das ist die Antwort auf „wie meldet man sich normal an, ohne Organisation": **die Registry legt den
Benutzer beim ersten Login selbst an.**

`registry/internal/server/middleware/auth.go` → `EnsureFromIdentity`
(`registry/internal/server/postgres/users.go:64`):

```go
// EnsureFromIdentity records a person the identity provider has already authenticated.
//
// The registry does not keep accounts of its own: a user here is a projection of one over there,
// and a verified token is the assertion that the person exists. What this creates carries no roles
// and no organization membership, so the row grants nothing.
INSERT INTO users (id, username, display_name) VALUES ($1, $1, NULLIF($2, ''))
ON CONFLICT (id) DO UPDATE SET display_name = COALESCE(NULLIF(EXCLUDED.display_name,''), users.display_name)
```

Ablauf beim allerersten Login: Token verifiziert → `GetByID(urn)` findet nichts → Zeile wird
angelegt → `plan_tier` fällt auf `free`. **Keine Organisation nötig, kein Antrag, kein Freischalten.**
Wiedersehen aktualisiert nur den Anzeigenamen; Plan, Sperrstatus und alles, was die Registry selbst
entscheidet, bleibt unberührt.

Und was darf so ein frischer Benutzer? `registry/internal/domain/permission.go`:

```go
func HasPermission(user *User, perm Permission) bool {
	if user == nil || !user.IsActive() { return false }
	switch perm {
	case PermPackagePublish, PermOrgCreate:
		return true      // jeder aktive Benutzer
	default:
		return false
	}
}
```

**Veröffentlichen und eine Organisation anlegen kann jeder aktive Benutzer sofort.** Das ist genau
die niedrige Einstiegshürde, die man für schnelles Onboarding will.

### 2.4 Zwei Org-Welten — und nur eine davon braucht man am Anfang

Das ist die Stelle, an der man sich sonst verrennt: „Organisation" bedeutet an zwei Orten etwas
anderes, und die beiden sind heute **nicht** miteinander verbunden.

| | **Registry-Org** | **Identity-Tenant** |
|---|---|---|
| Endpunkt | `POST /api/v1/orgs` (Registry-Host) | `POST /api/v1/tenants` (accounts-Host) |
| Was passiert | Zeile in der Registry-DB | Mandant + FGA-Scope + Audit-Ledger + RLS |
| Wer darf | **jeder aktive Benutzer** | `admin.tenant.create`, L2 + Step-Up |
| Wofür | Paket-Namensraum, Mitglieder, Publishing | Governance, SCIM, Break-Glass, Impersonation |
| Quote | Plan: free **1**, pro 5, enterprise 999 | keine durchgesetzte |
| Code | `registry/internal/server/handler/organization.go:51` | `identity/api/tenants.go` |

Für den Produkteinstieg zählt **nur die linke Spalte**. `POST /api/v1/orgs` prüft Namensregel →
globale Eindeutigkeit → Plan-Quote → legt an, und macht den Aufrufer zum Owner. Kein Zitadel-Aufruf,
kein OpenFGA, kein Step-Up.

Die rechte Spalte ist die Enterprise-Fläche. Wer sie braucht, hat einen Vertrag; wer ein Paket
veröffentlichen will, braucht sie nicht.

> **Entschieden, nicht gebaut (plan7-Backlog E.1 Q4):** `identity/internal/orgs` — der Manager, der
> Zitadel-Org und lokalen Spiegel verband, samt `ProvisionPersonalOrganization` — ist gelöscht. Der
> persönliche Namensraum eines Entwicklers *ist* die Registry-Org (linke Spalte); ein Identity-Tenant
> ist die Enterprise-Fläche und entsteht über `POST /api/v1/tenants` durch Staff. Zwei Wege zu
> einer Organisation wären zwei Wahrheiten darüber, wer wozu gehört.

### 2.5 Social Login — GitHub und Google, deklariert und abgeglichen

Zwei Provider sind deklariert (`identity/internal/zitadel/idps.go`, `InstanceIdPs()`) und werden
von `zitadel-provision --apply-idps` in Phase 6 angelegt, adoptiert oder repariert — nach demselben
Muster wie die Instanz-Policies: schreiben, zurücklesen, Feld für Feld vergleichen, bei Abweichung
mit Feldnamen abbrechen. `--check-drift` meldet einen in der Konsole veränderten Provider als
Divergenz.

| | GitHub | Google |
|---|---|---|
| Scopes | `user:email` | `openid email profile` |
| Konto anlegen | ja, automatisch | ja, automatisch |
| Verknüpfen beim Login | **nein** | **nein** |
| Auto-Linking | aus | aus |

Das Linking-Verbot ist die Sicherheitsentscheidung: ein Provider-Konto mit fremder E-Mail-Adresse
darf sich nicht an ein bestehendes Konto hängen. Verknüpfen passiert aus einer authentifizierten
Sitzung heraus, nach Step-Up — und ist noch nicht gebaut (§8).

**Credentials.** Eine OAuth-App je Umgebung, nie geteilt. Client-ID und Secret stehen als
`SEED_IDP_GITHUB_CLIENT_ID`, `SEED_IDP_GITHUB_CLIENT_SECRET`, `SEED_IDP_GOOGLE_CLIENT_ID`,
`SEED_IDP_GOOGLE_CLIENT_SECRET` in `.env.<env>`, gehen in Phase 5 über `seed.sh` nach
`secret/identity/idp/<provider>` und werden in Phase 6 vom Provisionierer gelesen. Vault überlebt
keinen Teardown; deshalb der Weg über die Umgebungsdatei statt `vault kv put` von Hand. Fehlt ein
Wert, scheitert Phase 0 am Prerequisite-Check, nicht Phase 6 an einem leeren Provider. Ein neues
Secret erreicht die Instanz nur über `--rotate-idp-secret <provider>`; Zitadel gibt Secrets nie
zurück, also vergleicht der Drift-Check sie nicht.

**Was ein Social-Login im Vertrauensmodell ist: L1.** `computeTrustLevel` kennt kein GitHub; ein
Token ohne phishing-resistentes `amr` ist L1, egal was der Provider intern verlangt hat. Dafür ist
`ForceMFALocalOnly: true` gesetzt — lokale Konten registrieren beim ersten Login einen Passkey,
IdP-Konten kommen als L1 herein und werden beim ersten L2-Bedarf per RFC-9470-Challenge zum Passkey
geführt (§5.3). Das ist die Rampe.

Für das Frontend ändert sich am OIDC-Flow **nichts**: die Buttons erscheinen auf Zitadels
Login-Seite, sobald die Provider existieren, und der `authorization_endpoint` bleibt derselbe.

**Wichtig, was GitHub im Repo *sonst* bedeutet** — beides ist *kein* Login:

- `AllowedGitHubOrgs` am Mandanten (Migration 016, `PATCH /api/v1/tenants/{id}`) ist eine
  **Allowlist**: welche GitHub-Organisationen als Nachweis dafür gelten, einem Toob-Mandanten
  beizutreten. Die Richtung ist Absicht — der Mandant ist unserer, die GitHub-Org ist nur ein
  akzeptierter Beleg. Andersherum läge die Mandantengrenze in einem fremden Namensraum, in dem
  Namen freigegeben und neu vergeben werden.
- Der GitHub App-Client in der Registry (`GitHubAppID`, `GitHubAppPrivateKey` aus Vault) ist für
  Paket-Spiegelung und Repository-Zugriff.
- `toob:workload:github:<owner>/<repo>:<workflow>` ist die URN-Form einer Workload-Identität für CI (§4.3); ein Aussteller dafür existiert noch nicht.

Der alte GitHub-**OAuth**-Login der CLI (`/api/v1/auth/github`, `/api/v1/auth/token`) ist gelöscht —
die Registry hat nie OAuth-Code gehabt, die Endpunkte antworteten 404.

### 2.6 Sicherheit hochfahren im Laufe des Prozesses

Die Bausteine für eine Rampe sind da, sie sind nur nirgends als Onboarding-Ablauf verdrahtet:

| Stufe | Was der Benutzer hat | Was er darf |
|---|---|---|
| **L1** | Login ohne phishing-resistenten Faktor | Lesen; in der Registry: Benutzerzeile, `orgs/mine`, Support-Sessions sehen |
| **L2** | ein Passkey (`webauthn`/`fido2`/`passkey`/`phr` in `amr`) | der Normalbetrieb |
| **L2 + Step-Up** | ein Passkey und eine höchstens `step_up_max_age` alte Zeremonie | Rollen ändern, SCIM-Token, Break-Glass, Tenants, Freigaben |

Die Rampe entsteht dadurch, dass der Trust Level **pro Permission** im Katalog steht und die
Gate-Kette ihn erzwingt (§5.1) — nicht dadurch, dass der Login etwas abweist. Ein Frontend fährt
sie so: L1 sofort nutzbar machen, beim ersten L2-Bedarf die RFC-9470-Challenge (§5.3) in einen
„Passkey hinzufügen"-Schritt übersetzen, und beim ersten Step-Up-Bedarf in eine erneute
Passkey-Zeremonie — nie in eine Fehlermeldung.

Dazu passt der Backlog-Punkt aus §10.3-AS: *„`dual_authenticator_requirement` gehört an die
Registrierung. Einen Login abzulehnen, weil jemand nur einen Authenticator hat, sperrt ihn
vollständig aus."* Genau diese Regel ist der Unterschied zwischen einer Rampe und einer Mauer.

Was die Instanz-Policy dabei **nicht** verhandelt und was ein Onboarding-Screen deshalb einplanen
muss: `ForceMFA: true` mit `MFAInitSkipLifetime: "0s"` — MFA-Einrichtung ist beim ersten Login
fällig und nicht aufschiebbar, und der einzige erlaubte zweite Faktor ist WebAuthn/FIDO2. Die
niedrigste denkbare Einstiegshürde ist damit *ein Passkey*, nicht *nichts*.

---

## 3. Anmeldung

### 3.1 Die Login-UI ist Zitadels eigene

Es gibt **keine selbstgebaute Login-Seite** im Repository. Caddy proxyt `/ui/login*` auf Zitadel:

```
handle /ui/login* {
    header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; …; frame-ancestors 'none'"
    reverse_proxy localhost:8080
}
```

`frame-ancestors 'none'` und `X-Frame-Options: DENY` heißen: **die Login-Seite lässt sich nicht in
ein iframe einbetten.** Ein „Login-Screen" in einer eigenen Anwendung ist deshalb kein eingebettetes
Formular, sondern ein **Redirect** auf Zitadel — oder eine eigene Seite, die Zitadels
Session-API v2 direkt spricht (dann aber unter dem Identity-Host, siehe §9).

### 3.2 Flow A — Authorization Code + PKCE (der Normalfall)

Das ist der Weg für Web-Frontends *und* für die CLI. Referenzimplementierung:
`cli/toob-cli/internal/oidc/`.

**Schritt 0 — Konfiguration holen, nicht einbauen.** Der Client kennt genau *einen* Wert: die URL
der Registry. Alles andere fragt er ab:

```http
GET https://registry-dev.the-toob.com/api/v1/auth/config
```

```json
{
  "issuer":    "https://id-dev.the-toob.com",
  "audience":  "<Zitadel-Projekt-ID>",
  "client_id": "<Zitadel-Client-ID der App 'toob-cli'>",
  "scopes":    ["openid", "profile", "email", "offline_access"]
}
```

Unauthentifiziert und absichtlich öffentlich — nichts davon ist ein Geheimnis. `Cache-Control:
public, max-age=300`. Der Handler ist `registry/internal/server/handler/authconfig.go`.

**Schritt 1 — Discovery.**

```http
GET {issuer}/.well-known/openid-configuration
```

**Pflichtprüfung:** das zurückgegebene `issuer`-Feld muss *exakt* dem angefragten Issuer
entsprechen (RFC 8414). Ohne diesen Vergleich könnte ein manipuliertes Dokument den Login
woandershin schicken. Die CLI bricht sonst ab.

**Schritt 2 — Autorisierungsanfrage.**

```
{authorization_endpoint}
  ?response_type=code
  &client_id={client_id}
  &redirect_uri={redirect}
  &scope=openid%20profile%20email%20offline_access
  &state={32 zufällige Bytes, base64url}
  &code_challenge={S256(verifier)}
  &code_challenge_method=S256
  &audience={audience}
```

- **Nur `S256`.** `plain` schickt den Verifier als Challenge und schützt gegen nichts; ein Provider,
  der nur `plain` anbietet, ist einer, gegen den dieser Client den Login nicht abschließt.
- **`audience` ist in der Praxis nicht optional.** Ohne ihn stellt Zitadel unter Umständen ein Token
  aus, das nur für sein eigenes Userinfo gilt — und die Registry weist es ab. Alternativ akzeptiert
  Zitadel den reservierten Scope `urn:zitadel:iam:org:project:id:{projectID}:aud`.
- **`offline_access`** ist das, was einen Refresh-Token überhaupt möglich macht.
- Für ein Web-Frontend ist der `redirect_uri` eine registrierte HTTPS-URL; für die CLI ist es ein
  Loopback (siehe unten).

**Schritt 3 — Code einlösen** am `token_endpoint`, `grant_type=authorization_code`, mit
`code_verifier`. Der Client ist **public** — er hält kein Secret, PKCE ist der Schutz.

**Loopback-Besonderheit für native/CLI-Clients (RFC 8252 §7.3):** registriert sind
`http://127.0.0.1/callback` und `http://localhost/callback` **ohne Port**; der Provider ignoriert
den Port eines Loopback-Redirects, weil das Betriebssystem ihn zuteilt. Ein fester Port wäre ein
Login, der scheitert, sobald etwas anderes ihn hält.

### 3.3 Flow B — Device Authorization Grant (RFC 8628)

Für Maschinen ohne Browser (Server über SSH, Container). `toob login --device`.
`{device_authorization_endpoint}` → `user_code` + `verification_uri_complete` anzeigen → am
`token_endpoint` mit `grant_type=urn:ietf:params:oauth:grant-type:device_code` pollen, bis
`authorization_pending` aufhört. Ersetzt den deprecateten `urn:ietf:wg:oauth:2.0:oob`-Redirect.

> Die eigene Device-Flow-Implementierung (`identity/deviceflow`) ist gelöscht — die CLI benutzt
> Zitadels Device-Grant, und ein zweiter Aussteller ohne Route war nur Fläche. Nicht verwechseln mit
> `identity/pki`, das Zertifikate für *physische* Geräte ausstellt.

### 3.4 Sessions und Refresh

Token-Lebensdauern aus der Instanz-Policy:

| | Wert |
|---|---|
| Access Token | 900 s (15 min) |
| ID Token | 900 s |
| Refresh Token, absolut | 28800 s (8 h) |
| Refresh Token, idle | 1800 s (30 min) |
| Passwort-Check-Lifetime | 86400 s |
| Second-Factor-Check | 64800 s |
| Multi-Factor-Check | 43200 s |

Verhalten, das die CLI implementiert und das ein Frontend spiegeln sollte
(`cli/toob-cli/internal/apiclient/identity.go`):

- Refresh **serialisiert** — zwei parallele Einlösungen desselben rotierten Refresh-Tokens beenden
  die Session für beide.
- Ein Refresh, der **keinen** neuen Refresh-Token zurückgibt, behält den alten.
- Session wird **neben** dem API-Key gespeichert, nicht statt seiner: der Key ist die
  Maschinen-Credential (CI), ein interaktiver Login darf ihn nicht entwerten.
- Gespeichert wird zusammen mit `issuer` und `client_id` — damit ein Token, das zu einer anderen
  Umgebung gehört, auffällt statt losgeschickt zu werden.

### 3.5 Logout

Es gibt **keinen Server-Endpunkt zum Invalidieren**. Eine Session ist ein Token, das der Provider
ausgestellt hat; die Registry hat nichts zurückzunehmen. `toob logout` löscht die lokale Session und
lässt den API-Key stehen. Ein Web-Frontend nimmt den `end_session_endpoint` aus der Discovery
(RP-initiated Logout).

---

## 4. Das Token — was drinsteht und wie es gelesen wird

Verifiziert von `identity/token/verifier.go`. Ein Frontend muss das nicht selbst tun, sollte aber
wissen, was hinten geprüft wird, weil jede Abweichung als 401 ankommt.

### 4.1 Harte Prüfungen

| Prüfung | Verhalten |
|---|---|
| Algorithmus | Nur `RS256/384/512`, `ES256/384/512`, `EdDSA`. `HS*`, `none`, leer → sofort abgelehnt |
| `kid` | Pflicht; Schlüssel wird über JWKS geholt |
| `iss` | Muss exakt `https://<identity-domain>` sein |
| `aud` | Muss die konfigurierte Audience enthalten — **das ist die Zitadel-Projekt-ID**, kein selbstgewählter Name |
| `exp`/`nbf` | 5 s Leeway |
| Größe | Token-Size-Budget (ZIT-05) |
| **Org-Claim** | **Pflicht.** Fehlt er, ist das Token ungültig |

**Der Org-Claim ist ein Scope, kein eigenes Feld.** Gelesen wird aus `scope`, Präfix
`urn:zitadel:iam:org:id:{orgId}`. Ein Token ohne diesen Scope wird abgelehnt
(`ErrMissingOrgClaim`) — für ein Frontend heißt das: **den Org-Scope mit anfordern.**

> **Achtung, das ist ein scharfer Blocker und er zielt auf die falsche Sache.** Gemeint ist die
> **Zitadel**-Organisation (der `resource_owner` des Benutzers), nicht ein Toob-Mandant und schon
> gar nicht eine Registry-Org. Nichts auf dem Produktionspfad fordert diesen Scope an: die Registry
> veröffentlicht `["openid","profile","email","offline_access"]`, und `urn:zitadel:iam:org:id:` taucht
> im Repository nur in Tests auf. Ein echter Login
> liefert also ein Token, das der Verifier mit `ErrMissingOrgClaim` verwirft — **auch für die
> Registry, die selbst gar keine Organisation verlangt.** Für ein Frontend heißt das bis auf
> Weiteres: den Scope explizit mitschicken. Die saubere Lösung wäre Zitadels
> `urn:zitadel:iam:user:resourceowner` (liefert `…:resourceowner:id` ohne Vorwissen über die Org-ID),
> denn `urn:zitadel:iam:org:id:{orgId}` setzt voraus, dass der Client die Org-ID schon kennt — was
> ein frisch registrierter Mensch nie tut. Siehe §8.1.

### 4.2 Gelesene Claims

```
sub                  → Subject; wird zur URN
urn:zitadel:iam:user:resourceowner:id → OrgID (oder scope urn:zitadel:iam:org:id:{orgId})
acr                  → Trust Level, autoritativ
amr                  → phishing-resistente Methode?

auth_time            → für Step-Up-Frische
cnf.jkt              → DPoP-Bindung (RFC 9449)
act.sub / act_urn    → Impersonation
name | preferred_username | email → Anzeigename, in dieser Reihenfolge
```

### 4.3 URN

Interne kanonische Identität, aus `sub` und `orgID` gebildet, wenn `sub` nicht schon eine ist:

```
toob:human:<cell>:<orgId>:<userId>
toob:sa:<cell>:<orgId>:<saId>
toob:workload:github:<owner>/<repo>:<workflow>
toob:device:<cell>:<tenantId>:<deviceId>
```

### 4.4 Trust Level — L1/L2, und Step-Up statt L3

Das Modell, das über Schreibrechte entscheidet (`computeTrustLevel`):

1. Ein **explizites `acr`** vom IdP ist autoritativ. Genau ein anerkannter Wert:
   `urn:zitadel:iam:mfa:l2` → **L2**. Exakter Vergleich; ein unbekannter `acr` wird ignoriert.
2. Mit phishing-resistenter `amr`-Methode: **L2**, sonst **L1**, egal wie viele Faktoren.
   Phishing-resistent sind exakt: `webauthn`, `fido2`, `passkey`, `phr`.
   *Nicht* `hwk` und `pop` — Hardware-Speicherung sagt nichts über Origin-Binding.

**Es gibt kein L3 mehr** (plan7-Backlog E.1 Q1). Was das Modell früher L3 nannte — zwei registrierte
Authenticatoren, vom IdP in `authenticator_count` behauptet — hat kein IdP je behauptet. Eine
stärkere Handlung ist **L2 plus frischer Step-Up**: `step_up: true` und `step_up_max_age` stehen pro
Permission im Katalog, und `StepUpGate` prüft `auth_time` gegen sie. Ein Level ist eine Eigenschaft
der Sitzung; eine frische Zeremonie ist eine Eigenschaft der Anfrage, und nur die kann ein Gate sehen.

L2 wird nie aus der *Anzahl* der `amr`-Einträge abgeleitet. Eine einzige Passkey-Zeremonie meldet
legitim mehrere (`webauthn`, `user_presence`, `user_verification`).

Praktische Folge für den Login-Screen: **ein Passkey reicht für alles.** Ein zweiter ist eine
Recovery-Eigenschaft des Kontos, nicht eine Assurance-Eigenschaft der Sitzung — der Konto-Screen
empfiehlt ihn („1 von 2") über Zitadels `ListAuthenticationMethodTypes`, kein Gate verlangt ihn.

---

## 5. Mit dem Token gegen die APIs

### 5.1 Die Gate-Kette

Jede Anfrage an `identity-api` — und jede authentifizierte Anfrage an die Registry — läuft durch
sieben Gates in genau dieser Reihenfolge (`identity/enforce/gate.go`), danach durch das Ratenlimit
und dann durch **Stage 2**, die Relation des Katalogs auf dem Objekt der Route:

```
TokenGate → DPoPGate → ImpersonationGate → KillSwitchGate → TenantGate → TrustGate → StepUpGate
        → Ratenlimit → RelationGate (OpenFGA: resource#relation auf dem Objekt der Route)
```

1. **TokenGate** — das einzige Gate, das einen Principal erzeugt.
2. **DPoPGate** — Besitznachweis. Muss vor allem anderen stehen.
3. **ImpersonationGate** — validiert `act`, damit die effektive Identität feststeht.
4. **KillSwitchGate** — Revocation, bevor Policy ausgewertet wird.
5. **TenantGate** — Scope.
6. **TrustGate** — geforderte Assurance.
7. **StepUpGate** — zuletzt, weil sein Fehlschlag eine *Challenge* ist und kein Fehler.
8. **RelationGate** (`identity/enforce/relation.go`) — fragt OpenFGA, ob der Principal die
   Relation der Permission auf dem Objekt hält, das die Route deklariert (`Object:` in der
   Routentabelle; `VerifyRoutes` weist eine Route ohne Objekt ab). Die eigene Organisation des
   Tokens geht als kontextuelles Tupel `tenant:<org>#member` mit, damit Selbstbedienung ohne
   gespeicherte Relation funktioniert. Antworten: `403 permission_denied`, `503 authz_unavailable`
   mit `Retry-After` wenn der Store nicht antwortet — nie 403 für einen Ausfall.

### 5.2 DPoP — nur wenn das Token gebunden ist

`identity/enforce/dpop_gate.go`: **die Entscheidung folgt dem Token, nicht dem Request.**

- Token hat **kein** `cnf.jkt` → normales `Authorization: Bearer …` genügt.
  Wer trotzdem das Schema `DPoP` benutzt, wird **abgelehnt** (falsches Versprechen).
- Token hat `cnf.jkt` → ein passender DPoP-Proof im Header `DPoP` ist **Pflicht**. Fehlt er:
  401 mit SECURITY ALARM im Log. Geprüft werden `htm`, `htu` (gegen die absolute öffentliche URL)
  und Replay über einen gemeinsamen Store.

Ein Login-Screen, der keine DPoP-Schlüssel verwaltet, fordert schlicht keine gebundenen Token an —
dann greift der erste Zweig. Sobald man DPoP will, muss der Proof pro Anfrage neu erzeugt werden.

### 5.3 Step-Up — RFC 9470

Manche Permissions (z. B. `admin.role.update`, `admin.scim_token.*`) verlangen eine *frische*
Authentifizierung. Der Server antwortet dann **nicht** mit einem generischen 401, sondern mit einer
Challenge (`shared/errors/problem.go`):

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="insufficient_user_authentication",
                  acr_values="urn:toob:mfa:webauthn", max_age=300
Content-Type: application/problem+json
```

Das Frontend muss das erkennen und den Benutzer mit `acr_values` und `max_age` zurück zum
Authorization-Endpunkt schicken (`prompt=login` bzw. `max_age`), statt „Sitzung abgelaufen"
anzuzeigen.

### 5.4 Fehlerformat

Durchgängig **RFC 9457 Problem Details** (`application/problem+json`), eine einzige Klassifikation
für die ganze Plattform (`shared/errors.Classify`). Insbesondere ist eine mandantenübergreifende
Ablehnung von einem kaputten Token unterscheidbar — vorher war beides ein nacktes 401.

Das gilt seit dem Umbau der Registry-Handler auch dort ohne Ausnahme: Der `code` ist der Schlüssel
der Taxonomie (`shared/errors/codes.go`), der Status folgt aus ihm über eine Tabelle, und ein
Handler nennt nur noch den Code (`serrors.WriteProblem`). Das ältere `{"error": "…"}` der Registry
gibt es nicht mehr; die CLI liest entsprechend nur noch `detail` und `code`.

### 5.5 Der Abschlusstest nach dem Login

Die CLI beendet jeden Login mit:

```http
GET https://registry-dev.the-toob.com/api/v1/me
Authorization: Bearer <access_token>
```

Antwort: `{ id, username, display_name, orgs: [{id, name, role}] }`.

Das ist bewusst der einzige Schritt, der die *ganze* Kette durchläuft — richtiger Issuer, richtige
Audience, holbarer Signaturschlüssel, auflösbares Subject. Eine falsch konfigurierte Umgebung fällt
damit beim Anmelden auf und nicht beim ersten Veröffentlichen. **Ein Login-Screen sollte das
genauso machen.**

### 5.6 Governance-API

`https://accounts-<env>.the-toob.com/api/v1/*` — 27 Routen, alle unter `/api/v1/tenants/…` außer
`POST /api/v1/tenants`. Auszug:

```
POST   /api/v1/tenants                                   Organisation anlegen
GET    /api/v1/tenants/{id}                              lesen
PATCH  /api/v1/tenants/{id}                              u.a. GitHub-Org-Allowlist
GET    /api/v1/tenants/{id}/members                      Mitglieder
POST   /api/v1/tenants/{id}/members                      einladen
DELETE /api/v1/tenants/{id}/members/{userId}             entfernen
PUT    /api/v1/tenants/{id}/members/{userId}/role        Rolle ändern        (L2 + Step-Up)
POST   /api/v1/tenants/{id}/scim-token                   SCIM-Token ausstellen (L2 + Step-Up)
POST   /api/v1/tenants/{id}/signing-keys                 eigenen Signierschlüssel einschreiben (L2 + Step-Up, Besitznachweis)
GET    /api/v1/tenants/{id}/signing-keys                 eigene Schlüssel, auch widerrufene
DELETE /api/v1/tenants/{id}/signing-keys/{thumbprint}    Schlüssel widerrufen
PUT    /api/v1/tenants/{id}/scim-groups/{groupId}        Gruppe → Rolle
GET    /api/v1/tenants/{id}/audit                        Audit-Log
GET    /api/v1/tenants/{id}/audit/segment                Audit als Beweis
POST   /api/v1/tenants/{id}/break-glass                  Notfallzugang anfragen
POST   /api/v1/tenants/{id}/break-glass/{rid}/approve    freigeben (anderer Mensch)
GET    /api/v1/tenants/{id}/impersonation                Support-Sessions sehen  (L1!)
POST   /api/v1/tenants/{id}/authz/explain                „warum darf ich das nicht?"
```

Zwei Details, die für eine UI zählen:

- `GET …/impersonation` ist **L1** — die niedrigste Stufe der Tabelle, absichtlich. Jedes Mitglied
  der Organisation kann sehen, wenn Support hineinschaut, nicht nur Admins.
- `POST …/authz/explain` liefert die Begründung einer Ablehnung. Das ist das, was eine
  „Keine Berechtigung"-Seite anzeigen sollte, statt zu raten.

Alles, was der Host nicht trifft, ist ein ehrlicher **404** — anders als beim IdP-Host, der
Unbekanntes an Zitadel durchreicht.

---

## 6. Autorisierung — OpenFGA

Der Login sagt *wer*; OpenFGA sagt *darf*. Das Modell liegt in `policy/model/*.fga`.

Seit dem 2026-09-07 wird es auch gefragt: die Identity-API und die Registry entscheiden jede
authentifizierte Route in Stage 2 gegen den Store (§5.1). Die Registry repliziert dafür keine Tupel —
sie steuert pro Anfrage bei, was sie über das Objekt weiß (Owner, Maintainer, Member einer
Namespace; Eigentümer und Namespace eines Pakets; Lesefreigaben), als kontextuelle Tupel nach
ADR 0005 (`registry/internal/server/relations`). Der Store hält das Modell, die Staff-Tupel und die
Tupel der Identity-Tenants.

Ein **Tenant ist eine Zitadel-Organisation**, und ihre ID ist die Tenant-ID überall: im Token
(Resource Owner), in der URN, in `tenants.id` der Identity-API, als `tenant:<id>` im Store und als
`tenant_id` eines CI-Tokens in der Registry. `POST /api/v1/tenants` legt die Organisation zuerst in
Zitadel an (Service-User `toob-identity-api`, provisioniert von `zitadel-provision --apply-api-user`)
und dann die lokale Zeile mit derselben ID.

```
type tenant
  relations
    define platform: [platform]
    define owner:  [user]
    define admin:  [user] or owner
    define member: [user, service_account] or admin
    define operator: admin
    define manager:  admin
    define support:  support from platform
    define break_glass_operator: [user]     # nur kontextuell, nie im Store
    define impersonation_viewer: [user]     # nur kontextuell, read-only
    define can_manage_members: admin
    define can_view: member or support or break_glass_operator or impersonation_viewer
    define can_manage_billing: owner
```

Direkt zuweisbar sind nur `owner`, `admin`, `member`. Break-Glass und Impersonation werden **pro
Anfrage als kontextuelles Tupel** gewährt und nie persistiert — das Modell macht es unmöglich, dass
ein Mitarbeiter eine stehende Rolle in einer Kundenorganisation hält, statt dass Code daran denken
muss, etwas zu löschen.

Der Weg einer Mitgliedschaftsänderung: `POST /members` → DB-Zeile + Outbox-Event in *einer*
Transaktion → `identity-sync` schreibt das FGA-Tupel. Kein FGA-Write in der Transaktion, weil das
ein verteilter Schreibvorgang ohne Atomarität wäre. Für die UI heißt das: **eine Rollenänderung ist
kurz nach der 201-Antwort noch nicht wirksam.**

---

## 7. Zitadel Actions v2 — Hooks auf dem Anmeldepfad

`identity/target` bedient vier Hook-Routen mit vierzehn Regeln (WebAuthn-Pflicht für Privilegierte,
Trust-Level, Lockout, Organisationsnamen, Rollen-Elevation, Break-Glass-Audit …). Der Signaturheader
ist verifiziert korrekt: `Zitadel-Signature: t=<unix>,v1=<hex>`, HMAC-SHA256 über
`<timestamp>.<body>`, 300 s Toleranz, Replay-Fenster in beide Richtungen.

**Status:** Das Hook-Target wird provisioniert (`zitadel-provision --apply-hooks`, Signaturschlüssel
nach Vault). **Executions sind noch nicht gebunden** — die Regeln laufen also derzeit nicht auf dem
echten Anmeldepfad. Wichtig für das Verständnis der Semantik, falls das später greift:

| Antwort des Hooks | Wirkung auf den abgefangenen Aufruf |
|---|---|
| `200`, **leerer** Rumpf | geht unverändert durch |
| `200`, Rumpf = ursprüngliche `request` | geht unverändert durch |
| `200`, Rumpf = `{}` | **Anfrage wird ersetzt** → kaputt |
| nicht-2xx bei `interruptOnError` | Anfrage abgebrochen |

Erlauben heißt also `200` ohne Rumpf, Ablehnen heißt nicht-2xx.

**Deployment-Fallstrick:** Zitadel ≥ 4.15 sperrt per `ZITADEL_HTTPCLIENT_DENYLIST` alle privaten
Netze für Action-Ziele, und der Zielhostname muss **beim Anlegen** auflösen, nicht erst beim Aufruf.

---

## 8. Was noch fehlt — Dinge, um die ein Login-Screen herumplanen muss

Ehrlich benannt, weil sie die Frontend-Arbeit direkt betreffen:

1. ~~**Der Org-Scope wird verlangt und von niemandem angefordert.**~~ **Gelöst:** die Registry
   veröffentlicht zusätzlich `urn:zitadel:iam:user:resourceowner`, und der Verifier liest die
   Organisation aus `urn:zitadel:iam:user:resourceowner:id` — dem Claim, den Zitadel für jeden
   Benutzer liefert, ohne dass der Client die Org-ID vorher kennt. Der Org-Scope wird weiterhin
   akzeptiert; nennen beide verschiedene Organisationen, wird das Token abgewiesen
   (`ErrOrgClaimConflict`). Ein Login-Screen fordert einfach die Scopes aus `/api/v1/auth/config`
   an. Der Claim-Name ist gegen die laufende 4.16.2 zu messen (Prüfpunkt P3 im Umsetzungsplan).

2. **Bootstrap des ersten Identity-Tenants.** Von „Zitadel-Konto existiert" zu „darf
   `POST /api/v1/tenants`" führt kein Produktionspfad; `identity-seed` behilft sich mit
   Entwicklungstoken aus `identity/test/tokens`. Betrifft nur die Governance-Fläche — für das
   Produkt-Onboarding reicht `POST /api/v1/orgs` (§2.4).
3. **Persönliche Organisation ist gebaut, aber unaufgerufen.**
   `orgs.ProvisionPersonalOrganization` (AUTH-022) und `orgs.CreateOrganization` (AUTH-023, mit
   Quota-Guard und kompensierendem Rollback) haben außerhalb von Tests keinen Aufrufer. Wer den
   `npm`-artigen Einstieg „Login = eigener Namensraum" will, verdrahtet diese Funktion und
   entscheidet dabei T-5.3.1 (Benutzername `support`/`api`/`admin` kollidiert mit der
   Reserved-Liste).
4. ~~**Kein Social Login konfiguriert.**~~ **Gelöst** (§2.5): GitHub und Google werden von
   `zitadel-provision --apply-idps` deklariert und abgeglichen. Offen bleibt die Messung gegen die
   laufende Instanz: Admin-API-Pfade und die Form des Read-Backs (P4), und ob Caddys
   `respond /ui/login/register* 403` den Auto-Creation-Schritt eines IdP-Logins trifft (P5).
   Die Konto-Verknüpfung aus den Einstellungen heraus ist nicht gebaut.
4b. **Die Registry setzt jetzt Berechtigungsstufen durch.** Jede Route trägt in
   `registry/internal/server/router/routes.go` ein Pflichtfeld `Access` — Credential, Katalog-Permission,
   CI-Permission, Scope — und die Stufe kommt aus `policy/permissions.yaml`. Konsequenzen für einen
   Login-Screen: Publish verlangt L2 und eine höchstens 5 Minuten alte Anmeldung (Challenge, §5.3);
   `POST /api/v1/tokens` verlangt L2 mit Step-Up, weil es ein dauerhaftes Credential prägt;
   CI-Token sind L1 und laufen über eigene `*_automated`-Permissions. Die Admin-Routen fragen
   `platform:global#staff` in OpenFGA; wer Staff ist, steht in `STAFF_USER_IDS` der
   Umgebungsdatei und wird von `openfga-provision` bei jedem Lauf abgeglichen.
   Die Liste aller Routen samt Vertrag steht in `registry/internal/ports/ports.go`.
5. **Der BFF gehört ins Frontend-Repository** (plan7-Backlog E.1 Q6). `identity/bff` und
   `identity/session` sind gelöscht: sie implementierten das Cookie-Session-Muster vollständig und
   wurden außerhalb von Tests nie aufgerufen. Das Muster bleibt richtig — `__Host-`-Cookie, HttpOnly,
   SameSite=Strict, Anti-CSRF-Token, Access-Token nur serverseitig — und es gehört in den Prozess,
   der das Frontend ausliefert, nicht in die Identity-API.
6. **Für die Registry sind `IDENTITY_CLIENT_ID` und `IDENTITY_TOKEN_AUDIENCE` Pflichtvariablen.**
   Der Provisionierer dafür existiert (`zitadel-provision --apply-signin-app`, legt die OIDC-App
   `toob-cli` im Projekt `registry` an, schreibt Client-ID und Audience nach
   `secret/data/identity/oidc-client`). Ein Web-Frontend mit HTTPS-Redirect braucht **eine eigene
   App-Registrierung** — die Redirect-URIs der bestehenden sind reine Loopback-Adressen.
7. **Ein frisch projizierter Benutzer ist inhaltlich leer.** `EnsureFromIdentity` schreibt eine
   Zeile mit URN als `id` *und* als `username`, Anzeigename aus dem Token — mehr nicht. `/api/v1/me`
   liefert dann `orgs: []` und einen URN als Benutzernamen. Das ist korrekt, sieht in einer UI aber
   nach einem Fehler aus: ein Onboarding-Screen sollte Benutzernamen und Organisation an dieser
   Stelle erfragen statt eine URN anzuzeigen.
8. **Kein CORS.** Weder Caddy noch die Handler setzen CORS-Header. Ein Frontend auf einem anderen
   Origin als `accounts-*` kann `identity-api` heute nicht aus dem Browser aufrufen. Der
   Registry-Host ist separat zu prüfen.
9. **`dual_authenticator_requirement` gehört an die Registrierung, nicht an den Login.** Eine
   Anmeldung abzulehnen, weil jemand nur einen Authenticator hat, sperrt ihn vollständig aus.
   Der Enrollment-Screen ist der richtige Ort für diese Anforderung.

---

## 9. Kurzrezept für den Login-Screen

Für ein Web-Frontend, mit dem heute Vorhandenen:

1. `GET {registry}/api/v1/auth/config` → `issuer`, `audience`, `client_id`, `scopes`.
   Nichts davon hart einbauen.
2. `GET {issuer}/.well-known/openid-configuration`, **`issuer` im Dokument gegen den angefragten
   vergleichen**, sonst abbrechen.
3. PKCE `S256` erzeugen, `state` erzeugen, beide behalten.
4. Auf `{authorization_endpoint}` weiterleiten — **Redirect, kein iframe**
   (`frame-ancestors 'none'`). Mit `audience` und dem Org-Scope.
5. Callback: `state` vergleichen, Code am `{token_endpoint}` mit `code_verifier` einlösen.
6. `GET {registry}/api/v1/me` — der Beweis, dass die ganze Kette hält. Erst danach „eingeloggt"
   anzeigen.
7. Refresh vor Ablauf (15 min), serialisiert, alten Refresh-Token behalten wenn keiner kommt.
8. Auf `401` mit `WWW-Authenticate: … insufficient_user_authentication` **nicht** ausloggen,
   sondern Step-Up mit den genannten `acr_values`/`max_age` fahren.
9. Logout: lokale Session löschen + `end_session_endpoint`. Es gibt nichts serverseitig
   zu invalidieren.
10. Kein „Registrieren"- und kein „Passwort vergessen"-Link **auf der IdP-Ebene** — beide Endpunkte
    antworten 403. Der Registry-Benutzer entsteht dagegen von selbst (§2.3): nach dem ersten
    erfolgreichen `/api/v1/me` ist die Person vollwertig, ohne weiteren Schritt.
11. **Keine Organisation verlangen.** `/api/v1/me` liefert `orgs: []` für einen frischen Benutzer,
    und das ist der Normalfall, kein Fehlerzustand. Wer eine braucht, legt sie mit
    `POST /api/v1/orgs {"name": …}` an — jeder aktive Benutzer darf das, free-Plan erlaubt eine.
    Fehlerfälle, die die UI kennen sollte: `409` Name vergeben, `402` Quote erreicht
    (mit `(n/max unter Plan x)` im Text), `400` Namensregel — Kleinbuchstaben, 3–63 Zeichen, keines
    der 25 reservierten Wörter.

Für Token im Browser: ein BFF im Frontend-Prozess (§8, Punkt 5) — empfohlen — oder Access-Token nur
im Speicher halten und Refresh über diesen BFF laufen lassen. Token im `localStorage` widerspricht
dem Grund, aus dem IdP und Anwendung überhaupt getrennte Hosts haben.

---

## 10. Wo im Code was steht

| Thema | Datei |
|---|---|
| Issuer/JWKS-Ableitung | `toob-infra/identity/token/endpoints.go` |
| Token-Verifikation, Trust Level | `toob-infra/identity/token/verifier.go` |
| AMR/ACR-Vokabular | `toob-infra/policy/authn.yaml` → `shared/policy/authn_gen.go` |
| Gate-Kette | `toob-infra/identity/enforce/gate.go` |
| DPoP | `toob-infra/identity/enforce/dpop_gate.go` |
| Step-Up-Challenge | `toob-infra/shared/errors/problem.go` |
| Route-Tabelle Governance-API | `toob-infra/identity/api/routes.go` |
| Instanz-Policy (Login/MFA/Passwort) | `toob-infra/identity/internal/zitadel/policies.go` |
| OIDC-App-Provisionierung | `toob-infra/identity/internal/zitadel/oidcapp.go` |
| Hook-Target | `toob-infra/identity/internal/zitadel/hooks.go`, `identity/target/` |
| Ingress, 403-Sperren | `toob-infra/platform/deploy/ansible/roles/caddy/templates/Caddyfile-identity.j2` |
| Hostnamen | `toob-infra/platform/internal/topology/topology.go`, `platform/deploy/terraform/projects/identity/main.tf` |
| `auth/config`-Endpunkt | `toob-infra/registry/internal/server/handler/authconfig.go` |
| **JIT-Benutzer beim ersten Login** | `toob-infra/registry/internal/server/postgres/users.go:64` (`EnsureFromIdentity`) |
| **Was ein frischer Benutzer darf** | `toob-infra/registry/internal/server/router/routes.go` (Routentabelle mit Katalog-Permission) |
| **Registry-Orgs (der leichte Weg)** | `toob-infra/registry/internal/server/router/routes.go`, `handler/organization.go` |
| Plan-Limits (free/pro/enterprise) | `toob-infra/shared/plan/` |
| JIT für föderierte Kunden-IdP-Nutzer | `toob-infra/identity/sync/jit.go` |
| Org-Namensregel (25 reservierte Wörter) | `toob-infra/policy/rules/org_names.yaml` → `shared/policy` |
| **Operator-Signierschlüssel** | `toob-infra/identity/signingkey/`, `identity/api/signingkeys.go`, ADR 0019 |
| SCIM | `toob-infra/identity/scim/` |
| FGA-Modell | `toob-infra/policy/model/core.fga`, `registry.fga` |
| **Referenz-Client** | `cli/toob-cli/internal/oidc/`, `cli/toob-cli/cmd/login.go` |
