# E1 — Kundenmodell: das Konto ist global, der Tenant ist eine Mitgliedschaft

**Stand:** umgesetzt, 2026-09-24 — alle sieben Phasen; Entscheidungen in §8, Stand und Abweichungen in §9. **Bezug:** [plan3.md](../plan3.md) §6 (E1), Register
[ID-025](../toob-infra/docs/register.csv) ff.

Heute gilt: Tenant = Zitadel-Organisation = Resource Owner im Token. Wer in Tenant X handeln will,
muss mit einem Konto angemeldet sein, das in X *liegt* (`principal.MayActIn`). Eine Person hat damit
genau einen Tenant, und jedes Self-Signup liegt in der Default-Organisation, die kein Tenant ist. Für
ein Geschäft, das mit einer Selbstregistrierung beginnt und über einen Firmen-Tenant bezahlt wird,
ist das die falsche Grenze.

## 1. Entscheidung

| | (a) Zitadel-Org pro Kunde, Konto darin | (b) Tenant nur in identity, ohne Zitadel-Org | **(c) Tenant bleibt Zitadel-Org, Zugriff über Mitgliedschaft** |
|---|---|---|---|
| Einstieg per GitHub/Google, dann Firma anlegen | Zweitkonto nötig; ein GitHub-Login hängt über denselben Provider an genau einem Konto (Zitadel: Unique-Constraint auf IdP und externen Nutzer) | ein Konto | ein Konto |
| eine Person in mehreren Firmen (Dienstleister) | ein Konto pro Firma | ja | ja |
| Enterprise-SSO | nativ | Zuordnung SSO-Org → Tenant nötig | nativ: die Tenant-Org bekommt den Kunden-IdP |
| Isolation | Token trägt den Tenant | Relation + RLS | Relation + RLS |
| Umbau | wenig Code, viel Produkt | Tenant-IDs, Mandanten-Scope, SSO-Zuordnung neu | Gate-Regel für Menschen, Einladungen, Tenant-Liste |

**Empfehlung: (c).** Der Tenant behält seine Zitadel-Org als Hülle: Die ID bleibt dieselbe, die
Org trägt später Kunden-IdP, Domain und Login-Policy, und SSO-Nutzer liegen darin wie heute. Ob
eine Person in X handeln darf, entscheidet aber nicht mehr, wo ihr Konto liegt, sondern eine
Relation in X. Das ist das Modell von GitHub und Vercel. Es hält die gebauten Teile
(`tenants`, `tenant_members` → Outbox → OpenFGA, RLS über `app.tenant_id`, Entitlements pro Tenant,
Default-Org kein Tenant) und ändert die eine Regel, die Self-Service verhindert.

## 2. Zielbild

**Begriffe**
- **Konto:** ein Zitadel-Benutzer. Seine **Heim-Organisation** ist die Default-Organisation
  (Self-Signup) oder die Org eines SSO-Tenants.
- **Tenant:** eine `tenants`-Zeile mit Zitadel-Org derselben ID. Kunde, Plan, Geräte hängen daran.
- **Mitgliedschaft:** `tenant_members` (owner, admin, member), projiziert nach OpenFGA.
- **Aktiver Tenant:** der Tenant im Pfad (`/api/v1/tenants/{id}/…`). Kein Org-Wechsel im Token, kein
  Scope `urn:zitadel:iam:org:id:*`.

**Regeln**
1. Zugriff auf Tenant X entscheidet ausschließlich eine Relation in X. Die Heim-Org im Token
   entscheidet ihn nicht mehr, weder als Erlaubnis noch als Sperre.
2. Die Default-Organisation ist nie ein Tenant (bleibt, `TenantGate` → 404).
3. Permissions auf dem Plattform-Objekt gelten mandantenübergreifend (bleibt).
4. Ein Tenant hat vom ersten Augenblick an einen Owner; der letzte Owner kann nicht gehen (bleibt).
5. Rollen vergibt, ändert und entzieht jeder nur bis zum eigenen Rang (bleibt).
6. Maschinen (Workloads, Geräte, Service-Accounts eines Tenants) bleiben an ihre Org gebunden.
7. Der Plan gehört dem Tenant. Limits eines Tenants löst der Dienst serverseitig auf, nicht aus dem
   Token einer Person.

## 3. Änderungen

### 3.1 Zugriff — der Kern
- **`TenantGate`** ([tenant.go](../toob-infra/identity/enforce/tenant.go)): Menschen und Operatoren
  passieren jeden Tenant außer der Default-Org; Stage 2 entscheidet. Für Workloads, Geräte und
  Service-Accounts bleibt `MayActIn` (Org-Gleichheit). `ActsOnPlatform` wird damit für Menschen
  bedeutungslos und bleibt für Maschinen.
- **Relationen:** Jede Permission mit Tenant im Pfad verlangt eine Relation, die nur Mitglieder oder
  ausdrücklich Berechtigte halten. Eine Linter-Regel sichert das ab: `resource#relation` muss im
  Modell existieren (fehlt heute, siehe UP-003), und keine Tenant-Relation darf `user:*` zulassen.
- **`withOwnOrganization`** bleibt: SSO-Nutzer sind über ihre Heim-Org Mitglied ihres Tenants. Für
  die Default-Org ist der Beitrag harmlos, weil sie nie Tenant eines Pfads ist.
- **Kill-Switch** ([killswitch.go](../toob-infra/identity/enforce/killswitch.go)): prüft zusätzlich
  den angefragten Tenant. Ein widerrufener Tenant sperrt jeden Zugriff *auf ihn*, nicht nur Konten,
  die in ihm liegen.
- **Rate-Limit:** Der Tenant-Eimer zählt den angefragten Tenant; ohne Tenant im Pfad bleibt
  `ratelimit.TenantKey`.

### 3.2 Tenants selbst anlegen
- Self-Service: `POST /api/v1/me/tenants` mit der neuen Permission `identity.tenant.create` — Objekt
  `ObjectSelf` (jede angemeldete Person), L2 (erst nach dem ersten Passkey), Klasse `write`, Kosten
  hoch, Audit `critical`. Der Anlegende wird Owner.
- Staff: `POST /api/v1/tenants` (`admin.tenant.create`) bleibt und nimmt `owner_email`.
- In **einer** Transaktion: Zitadel-Org (wie heute, mit Kompensation), `tenants`-Zeile mit
  `created_by`, Owner-Mitgliedschaft, Entitlement `free`, Outbox `tenant.created` und `member.added`.
- `identity-sync` projiziert `tenant.created` auf `platform:global platform tenant:<id>`. Heute schreibt
  niemand dieses Tupel, deshalb greift `support from platform` nie. Bestehende Tenants bekommen das
  Ereignis einmalig per Migration.
- **Quote:** höchstens fünf selbst angelegte Tenants je Konto (`tenants.created_by`); Staff ohne Quote.
- Staff-Anlage mit `owner_email` erzeugt statt einer direkten Mitgliedschaft eine Owner-Einladung
  (§3.4). Damit bekommen auch die heute owner-losen Tenants ihren ersten Owner.

### 3.3 „Meine Tenants"
- RLS bekommt einen zweiten, permissiven Scope als `FOR SELECT`-Policy: `tenant_members` und `tenants`
  sind zusätzlich für `user_id = current_setting('app.user_id')` lesbar. `tenantdb.InUserTx` setzt nur
  diesen Scope; Schreiben bleibt an den Tenant gebunden.
- `GET /api/v1/me/tenants` → `[{id, name, role}]`, Permission `identity.account.read`. Die Route
  liegt unter `/me` wie das Anlegen, sodass das Forum-BFF sie ohne neue Weiterleitung erreicht.
- Das Forum setzt `orgs` in der Session daraus statt aus der Heim-Org.

### 3.4 Einladungen
- Tabelle `tenant_invitations`: `id`, `tenant_id`, `email` (normalisiert), `role`, `token_hash`
  (SHA-256 eines 32-Byte-Zufallswerts), `invited_by`, `created_at`, `expires_at`, `accepted_by`,
  `accepted_at`, `revoked_at`. RLS pro Tenant; höchstens eine offene Einladung je Tenant und E-Mail.
- Routen (Tenant im Pfad, `admin.member.invite` beschreibt schon „Send an invitation"):
  - `POST /api/v1/tenants/{id}/invitations` `{email, role}` — Rang ≤ eigener Rang, sendet die Mail.
    Die Antwort trägt den Token nicht.
  - `GET /api/v1/tenants/{id}/invitations` — offene Einladungen (admin).
  - `DELETE /api/v1/tenants/{id}/invitations/{invitationId}` — widerrufen (admin).
  - `POST /api/v1/me/invitations/accept` `{token}` — neue Permission `identity.invitation.accept`,
    `ObjectSelf`, L1. Der Handler findet die Einladung über eine `SECURITY DEFINER`-Funktion
    (Hash → Tenant, Rolle, Frist), öffnet den Scope des Einladungs-Tenants und schreibt
    Mitgliedschaft, Audit und Outbox in einer Transaktion. Einmalig, befristet.
- **Frist** aus `policy/rules/invite.yaml` (72 h). `initial_role: viewer` wird `member` (die Rolle
  `viewer` gibt es nicht), und policygen erzeugt die Regel statt sie als „not implemented" zu führen.
- **Bindung:** Der Besitz des Links genügt; die angenommene Einladung zeigt Admins, welches Konto sie
  eingelöst hat. Eine Bindung an die E-Mail-Domain kommt mit SSO (§3.9).
- **Versand:** Paket `identity/mail` (SMTP mit erzwungenem TLS), dieselbe Konfiguration
  `secret/data/identity/smtp` wie Zitadel; `identity-service.hcl` bekommt Lesezugriff.
- `POST /api/v1/tenants/{id}/members` (Rolle an eine User-ID) entfällt: Kunden kennen keine
  User-IDs. SCIM bleibt der zweite Weg hinein.

### 3.5 Mitgliederliste mit Namen
- `GET …/members` löst die IDs gebündelt über Zitadel auf (`POST /v2/users` mit `inUserIdsQuery`):
  Anzeigename für alle Mitglieder, E-Mail nur für admin und owner.

### 3.6 Plan
- `toob_plan` bedeutet künftig „höchste Stufe über alle Tenants der Person" (Token-Hook über
  `InUserTx`). Das Forum priorisiert Support danach, Oberflächen zeigen ihn an.
- Limits eines Tenants (Geräte, Tenant-Namensräume) löst der jeweilige Dienst serverseitig auf.
  identity veröffentlicht `entitlement.changed` über die Outbox an signierte Webhook-Empfänger
  ([outbound.go](../toob-infra/identity/sync/outbound.go), heute ohne Empfänger); ein Dienst hält eine
  Projektion und gleicht beim Start über einen internen Lesepfad ab. Erster Empfänger ist der
  Update-Service.

### 3.7 Registry
- Namensräume können einem Tenant gehören: Die bisher nie geschriebene Spalte
  `organizations.zitadel_org_id` wird zu `tenant_id` und beim Anlegen gesetzt (`POST /api/v1/orgs`
  mit `tenant_id`, nur für Tenant-Admins). Das Tupel `namespace#parent` trägt
  [relations.go](../toob-infra/registry/internal/server/relations/relations.go) schon bei; es wird zum
  ersten Mal wahr.
- Quoten eines Tenant-Namensraums kommen aus dem Plan des Tenants, persönliche Namensräume bleiben
  bei den persönlichen Limits.

### 3.8 Oberflächen
- `@toob/account`: `OrganizationsSection` (meine Tenants mit Rolle, anlegen, verlassen) und
  `OrganizationScreen` (Mitglieder mit Namen, Rollen, offene Einladungen, Plan). Beide hängen am
  Gateway, damit Forum und spätere Konsole (E5) sie teilen.
- Forum: `/settings/organizations/[id]` und `/invite/[token]` (meldet an, falls nötig, und löst ein);
  das BFF leitet die neuen Routen weiter.
- CLI: `toob org list|create|invite|leave` als eigener Schritt nach der Oberfläche.

### 3.9 Enterprise-SSO (eigene, spätere Phase)
- Die Tenant-Org bekommt den Kunden-IdP als Org-IdP und eine verifizierte Domain; Anmeldung über
  Domain-Discovery oder Org-Scope. SSO-Nutzer liegen in der Tenant-Org und sind über
  `withOwnOrganization` Mitglied. Optional: Tenant-Richtlinie „nur SSO-Konten" und
  E-Mail-Domain-Bindung für Einladungen.

## 4. Datenmodell

| Migration (identity) | Inhalt |
|---|---|
| `031_tenant_created_by` | `tenants.created_by` (URN), Index für die Quote |
| `032_user_scoped_memberships` | permissive Policies über `app.user_id` auf `tenant_members` und `tenants` |
| `033_tenant_invitations` | Tabelle, RLS, Unique-Index offener Einladungen, `SECURITY DEFINER`-Lookup |
| `034_tenant_created_backfill` | Outbox `tenant.created` für jeden bestehenden Tenant |

Registry (Phase 6): `organizations.zitadel_org_id` wird in `tenant_id` umbenannt.

## 5. Katalog

| Permission | Objekt | Relation | Trust | Step-up | Audit |
|---|---|---|---|---|---|
| `identity.tenant.create` | self | `tenant#member` (eigene Org, kontextuell) | L2 | nein | critical |
| `identity.invitation.accept` | self | `tenant#member` (eigene Org, kontextuell) | L1 | nein | write |
| `admin.member.invite` | Tenant | `admin` | L2 | nein | write — für Einladungen statt Direktvergabe |
| `admin.invitation.list` / `.revoke` | Tenant | `admin` | L1 / L2 | nein | read / write |
| `admin.tenant.create` | Plattform | `staff` | L2 | nein | critical — mit `owner_email` |

Das Modell ([core.fga](../toob-infra/policy/model/core.fga)) braucht keine neue Relation.

## 6. Reihenfolge

| Phase | Ergebnis | Abnahme | Umfang |
|---|---|---|---|
| 1 Zugriff | §3.1 | Seam-Test: Mitglied aus der Default-Org handelt in X, Nichtmitglied bekommt 403; widerrufener Tenant sperrt jeden Zugriff auf ihn | mittel |
| 2 Tenants | §3.2, §3.3 | Anlegen erzeugt Org, Owner, Entitlement, Plattform-Tupel atomar; Quote greift; `/me/tenants` zeigt nur eigene | mittel |
| 3 Einladungen | §3.4, §3.5 | Einladen → Mail → Annehmen → Mitglied; abgelaufen, widerrufen, doppelt eingelöst → abgewiesen; Rang greift | groß |
| 4 Oberfläche | §3.8 | Anlegen, Einladen, Annehmen, Verlassen im Forum durchspielbar | mittel |
| 5 Plan | §3.6 | `toob_plan` = höchste Stufe; `entitlement.changed` erreicht einen Test-Empfänger | mittel |
| 6 Registry | §3.7 | Tenant-Namensraum mit Tenant-Quote; Tenant-Admin verwaltet ihn ohne eigene Namensraumrolle | mittel |
| 7 SSO | §3.9 | Kunden-IdP-Anmeldung landet als Mitglied im Tenant | groß |

Wizard-Phasen je Lieferung: identity/registry → Phase 1 und 6; Vault-Policies → 5; Nomad-Jobs → 6.

## 7. Risiken

- **OpenFGA wird die einzige Grenze für Menschen.** Gegenmittel: RLS bleibt an den Pfad-Tenant
  gebunden, die Linter-Regel aus §3.1, und ein Seam-Test über echte Tupel je Tenant-Route.
- **Tenant-Spam:** L2, Quote, Rate-Limit `write`.
- **Weitergeleitete Einladungslinks:** einmalig, 72 h, rangbegrenzt, widerrufbar, im Audit sichtbar.
- **Größe des Plan-Claims:** nur eine Stufe, nicht die Liste der Tenants.
- **Migrationen ohne Rückweg:** 032 und 033 nur additiv; 034 schreibt ausschließlich Outbox-Zeilen.

## 8. Entschieden (2026-09-24)

1. Eine Einladung gilt nur für ein Konto, dessen verifizierte E-Mail der eingeladenen Adresse
   entspricht — zusätzlich zum Besitz des Links.
2. Höchstens fünf selbst angelegte Tenants je Konto. Mehr legt Staff an (`POST /api/v1/tenants` mit
   `owner_email`); die Fehlermeldung (402) verweist auf den Support, die Oberfläche auf eine
   Support-Anfrage im Forum.
3. Bezahlte Tenants heben die persönlichen Registry-Limits nicht an: Kapazität gehört den
   Namensräumen des Tenants.
4. E-Mail-Adressen der Mitglieder sehen nur admin und owner.
5. `POST /api/v1/tenants/{id}/members` entfällt.

## 9. Stand der Umsetzung

| Phase | Stand | Wo | Abnahme |
|---|---|---|---|
| 1 Zugriff | ✅ Menschen und Operatoren passieren das `TenantGate` (Default-Org bleibt 404), Maschinen bleiben an ihre Org gebunden; der Kill-Switch prüft auch den angefragten Tenant; der Tenant-Eimer zählt den Pfad-Tenant; Linter-Regel 10 (`resource#relation` muss im Modell existieren) und 11 (keine Wildcard auf `tenant`/`platform`), sechs Fleet-Permissions repariert (UP-003) | `identity/principal`, `identity/enforce`, `identity/middleware/ratelimit.go`, `shared/policy/linter.go` | Seam: `TestSeam_TenantAccessIsAMembership`, `TestSeam_RevokedTenantIsClosedToItsMembers` |
| 2 Tenants | ✅ `POST /api/v1/me/tenants` (L2, Quote fünf unter Advisory-Lock), `GET /api/v1/me/tenants` über `InUserTx`; identity-sync projiziert `tenant.created` auf `platform:global`; Staff-Anlage lädt den Owner ein | `identity/api/tenants.go`, `identity/sync/tenant.go`, Migrationen 031, 032, 034 | Seam: `TestSeam_CreatingATenantTiesItToThePlatform` |
| 3 Einladungen | ✅ `tenant_invitations`, Versand über `identity/mail` (SMTP, TLS erzwungen), Annehmen per Link; Mitgliederliste mit Namen über `POST /v2/users` | `identity/api/invitations.go`, `identity/api/members.go`, Migration 033 | Integration: `invitations_integration_test.go` |
| 4 Oberfläche | ✅ `@toob/account` (`OrganizationsSection`, `OrganizationScreen`, `AcceptInvitation`), Forum `/settings/organizations/[id]` und `/invite/[token]`, BFF-Weiterleitung, Mock mit Szenen-Buttons; CLI `toob org list\|create\|invite\|leave` | `community/web`, `community/internal/api/account.go`, `cli/toob-cli/cmd/org.go` | Typecheck, Lint, Contract-Test |
| 5 Plan | ✅ `toob_plan` = höchste Stufe über alle Tenants; `entitlement.changed` und `entitlement.snapshot` als signierte Webhooks (`shared/webhook`), Abgleich alle sechs Stunden | `identity/entitlement`, `identity/sync/entitlements.go`, Migration 035 | `TestTokenClaims_HighestPlanAcrossOrganizations`, Publisher-Tests |
| 6 Registry | ✅ Namensräume mit `tenant_id`, Projektion `tenant_plans` über den Webhook, Tenant-Quote aus dem Tenant-Plan, `registry.tenant_namespace.create` für Tenant-Admins | `registry/internal/server/handler`, Registry-Migrationen 040, 041 | `TestOrgCreate_ForATenant`, `TestPublish_TenantNamespaceCountsAgainstTheTenant` |
| 7 SSO | ✅ siehe §9.2 | `identity/api/sso.go`, `identity/internal/zitadel/sso.go`, Migration 036 | Seam: `TestSeam_ASignInThroughTheTenantsProviderIsAMember` |

### 9.1 Abweichungen vom Plan

- §3.2: Beim Anlegen entsteht keine Entitlement-Zeile `free`; ohne Zeile gilt `free`.
- §3.3: Das Forum führt `orgs` nicht mehr in der Session. Die Oberfläche liest die Mitgliedschaften
  live über `/me/tenants`; sonst hinge jede Anmeldung an identity-api.
- §3.4: Zusätzlich zur Bindung an den Link die an die verifizierte E-Mail (Entscheidung 1). Der Link
  findet die Einladung über den RLS-Scope `app.invitation_token_hash` statt über eine
  `SECURITY DEFINER`-Funktion.
- §3.6: Persönliche Registry-Limits kommen aus dem Plan, den die Registry zum Nutzer führt, nicht aus
  dem Token (Entscheidung 3); Tenant-Namensräume aus der Projektion `tenant_plans`.
- §3.9: SSO-Konten erscheinen in der Mitgliederliste über Zitadels Nutzerliste der Tenant-Org
  (`source: sso`), nicht über JIT-Zeilen.
- §4: dazu 035 (`entitlement.changed` aus der Outbox), 036 (`tenants.sso_required`), 037
  (`tenants.deleted_at`, `restorable_until`); Registry 040 (`tenant_plans`) und 041
  (`organizations.tenant_id`).
- §5: dazu `identity.membership.leave`, `registry.tenant_namespace.create`,
  `admin.tenant_domain.list`/`.manage` und `admin.tenant_sso.read`/`.manage` (owner, L2, Step-up
  5 min, Audit `critical`), `admin.tenant.delete` (owner) und `admin.tenant.restore` (Plattform-Staff),
  beide L2, Step-up 5 min, `critical` (§9.5).

### 9.2 Enterprise-SSO (Phase 7)

- **Domains.** `GET/POST /api/v1/tenants/{id}/domains`, `POST …/domains/{domain}/challenge` und
  `…/verify`, `DELETE …/domains/{domain}`. Bewiesen wird per TXT-Record `_zitadel-challenge.<domain>`.
  Die erste bewiesene Domain wird primär; eine primäre gibt die Rolle beim Entfernen an eine andere
  bewiesene oder an die von Zitadel erzeugte zurück. Die Instanz deklariert dafür
  `validateOrgDomains: true` (Domain-Policy mit Rücklesen) — Zitadels Standard hätte jede
  hinzugefügte Domain sofort als verifiziert geführt, und ein Tenant hätte die Anmeldungen einer
  fremden Firma zu seinem IdP umleiten können.
- **Provider.** `GET/PUT/DELETE /api/v1/tenants/{id}/sso`: ein generischer OIDC-IdP der Tenant-Org
  (PKCE, Anlegen beim ersten Login, Profil-Abgleich, kein Auto-Linking) und die deklarierte
  Org-Login-Policy `SSOPolicy`: kein Passwort, kein Passkey als erster Faktor (ein Passkey
  überlebte sonst den Austritt beim Kunden), nach dem IdP ein Sicherheitsschlüssel als zweiter
  Faktor — das ergibt `amr ["user","mfa"]` und damit L2. Unbekannte Adressen gehen zum IdP,
  Domain-Discovery ist an. Jede Änderung wird zurückgelesen. Der Kunde erlaubt bei seinem IdP
  `https://<identity-domain>/idps/callback`.
- **Drift.** `zitadel-provision` akzeptiert genau diese Org-Policy mit genau einem eigenen Provider
  der Org; jede andere Org-Policy bleibt ein Fehler. Die Organisationen liest es jetzt seitenweise.
- **Anmeldung.** Forum `/api/auth/login?sso=<Arbeitsadresse>` setzt den Scope
  `urn:zitadel:iam:org:domain:primary:<domain>`, `login_hint` und `prompt=login`; Login v2 leitet
  direkt zum IdP der Org. Zitadel nimmt dafür nur die *primäre* Domain der Org an.
- **Mitglied.** Das beim ersten Login angelegte Konto liegt in der Tenant-Org und ist über
  `withOwnOrganization` Mitglied (role `member`); Rollen darüber vergibt eine Einladung.
- **„Nur SSO-Konten"** (`sso_required`): Einladungen nur an Adressen bewiesener Domains, Annehmen nur
  mit einem Konto aus der Tenant-Org; bestehende Mitglieder bleiben. Setzen verlangt eine bewiesene
  Domain; die letzte bewiesene Domain oder das SSO selbst lassen sich erst nach Aufheben der Pflicht
  entfernen.
- **E-Mail-Vertrauen.** Ein Konto aus einer Tenant-Org gilt beim Annehmen nur für Adressen einer
  Domain, die seine Org bewiesen hat: ein Kunden-IdP kann jede Adresse als verifiziert melden.
- **Grenzen.** Aus dem Forum startet SSO nur mit der primären Domain. SSO-Konten bleiben nach dem
  Austritt beim Kunden oder dem Entfernen des SSO als Zitadel-Konten stehen (ID-038). SCIM nach
  Zitadel bleibt offen (ID-028). Login v2 erzwingt MFA bei `forceMfa: true` auch nach GitHub und
  Google (ID-036, an der Instanz zu prüfen).

### 9.3 Tests

Grün: Unit-Tests von identity (api, zitadel, zitadel-provision, migrations, middleware, contract),
shared (policy, dnsname, webhook, errors), registry, community (api, oidc) und der CLI; Typecheck
und Lint von `@toob/account` und Forum. Kompiliert, aber nicht gelaufen, weil sie Postgres, OpenFGA
oder Zitadel brauchen (Docker): `-tags integration` (u. a. `sso_integration_test.go`,
`tenant_lifecycle_integration_test.go`, Audit-Proben der SSO- und Lösch-Routen), `-tags seam` und
`-tags zitadelseam`
(`TestSeam_ATenantsSingleSignOnIsNotAnOverride`).

### 9.4 Ausrollen

- identity-api, identity-sync, zitadel-provision und registry-api neu bauen: Wizard-Phase 1, dann 6.
- identity-sync braucht seit dem Purge die DSN `secret/data/projects/identity/db/purger` (schreibt
  identity-migrate) und liest `secret/data/identity/zitadel-api` (Vault-Policy, Phase 5).
- Vault-Policies und `seed.sh` (`identity/smtp`, `identity/webhooks`): Phase 5.
- Nomad-Jobs (identity-api, identity-sync, registry-api): Phase 6; dort wendet
  `zitadel-provision` auch die Domain-Policy an.
- Plattform-Code (`platform/internal/stages/deploy.go`): Wizard neu starten.
- Forum und Website (`community/web`): Phase 1 baut die Images, Phase 6 rollt sie aus.

### 9.5 Organisation löschen (Feedback 2026-09-24)

- **Löschen.** `POST /api/v1/tenants/{id}/deletion` mit dem Namen der Organisation. In einer
  Transaktion: `deleted_at` und `restorable_until`, offene Einladungen widerrufen, SCIM-Token
  gelöscht, Revocation des Tenant-Schlüssels, Audit, Outbox `tenant.deleted` mit allen
  Mitgliedschaften; danach die Zitadel-Org deaktiviert. Der Kill-Switch sperrt jede Route, die den
  Tenant nennt, und jedes Konto aus der Tenant-Org; identity-sync entfernt Plattform- und
  Mitglieds-Tupel. `/me/tenants` und das Kontingent zählen gelöschte Tenants nicht.
- **Wiederherstellen.** `POST /api/v1/tenants/{id}/restore` durch Plattform-Staff bis
  `restorable_until` (7 Tage, `policy/rules/tenant_deletion.yaml`): Revocation aufgehoben,
  `tenant.restored` schreibt die Tupel zurück, Org reaktiviert. Einladungen und SCIM-Token legt der
  Kunde neu an; der Zugriff kehrt mit der nächsten Synchronisation der Revocation-Liste zurück
  (≤ 30 s).
- **Oberfläche.** „Danger zone" für Owner: vor jedem Löschen eine neue Passkey-Anmeldung
  (`prompt=login`, Rückkehr mit `?delete=1`), eine Aufklärung, die bis zum Ende gescrollt sein muss,
  bevor das Häkchen erreichbar ist, und der Name zweimal getippt.
- **Endgültig entfernen.** identity-sync fegt stündlich als Leader: Zitadel-Org entfernen (mit ihren
  Konten), alle Tupel auf `tenant:<id>` löschen, dann in einer Transaktion als `identity_purger`
  (Migration 038) die Zeilen des Tenants und zuletzt seine Zeile in `tenants`, mit dem Ledger-Eintrag
  `tenant.purged`. Die Rolle sieht nur Tenants mit abgelaufener Frist; restriktive DELETE-Policies
  verweigern alles andere, auch im Scope eines lebenden Tenants. Solange Outbox-Ereignisse des Tenants
  offen sind, wartet der Purge. Es bleiben das Audit-Ledger und die Tenant-Sperre (ohne
  Personenbezug). Die Registry erfährt davon nur über den Plan-Snapshot; ihre Namensräume sind RG-003.
