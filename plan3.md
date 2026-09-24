Das ist nur eine Analyse, geändert habe ich nichts. Die tragenden Aussagen habe ich selbst im Code nachgeprüft. Die Details zu Website, CLI, Deploy und `svc/update-service` stammen aus vier Suchläufen von Subagenten mit Zeilenbelegen.

## Kurzfassung

Deine Vermutung stimmt, und die Lage ist noch etwas härter:

- **Registrierung:** Die erste Anmeldung mit GitHub oder Google ist die Registrierung. Zitadel legt den Account automatisch an, und jede neue Person landet in derselben Org „Toob Alliance“, zusammen mit `admin` und den Maschinen-Usern. Dabei entsteht weder ein Tenant noch eine Mitgliedschaft noch ein Onboarding.
- **Organisationen:** Niemand kann selbst eine anlegen. Staff kann zwar einen Tenant erzeugen, danach aber weder einen Owner eintragen noch einen Plan setzen. Einladungen gibt es nicht.
- **Payments:** Es gibt weder einen Provider noch Zahlungsmethoden, Rechnungsdaten oder eine USt-ID-Prüfung. Einen Plan kann in Produktion derzeit **niemand** vergeben, weil der einzige Schreibweg dreifach blockiert ist.
- **Update-Service:** `toob-infra/update` ist ein leeres Skelett. Die eigentliche Logik liegt unverdrahtet im veralteten `svc/update-service`.

## 1. So läuft die Registrierung heute

**Zitadel und Backend**
- Die Login-Policy hat `AllowRegister: false` und `AllowExternalIDP: true`. MFA ist nur für lokale Accounts Pflicht ([policies.go:118-136](toob-infra/identity/internal/zitadel/policies.go#L118-L136)).
- GitHub und Google legen Accounts automatisch an, eine Verknüpfung beim Login ist aus ([idps.go:111-126](toob-infra/identity/internal/zitadel/idps.go#L111-L126)). Es gibt kein Formular, also weder Firma noch Namen.
- Kein Client fordert eine Org an, und `LoginDefaultOrg` wird nie gesetzt. Deshalb landet jeder in der Default-Org „Toob Alliance“ ([zitadel-setup.nomad.hcl:244-251](toob-infra/identity/deploy/nomad/jobs/zitadel-setup.nomad.hcl#L244-L251)). Das ist Zitadel-Verhalten, im Repo mehrfach so angenommen, aber nie live gemessen.
- Identity schreibt beim ersten Login nichts: keine Zeile, keinen Hook (`Routes()` liefert nil), kein Event. Nur Registry (`users`) und Forum (`forum_users`) legen Spiegelzeilen an.
- Die E-Mail-Verifikation steht nur in einem Kommentar. **SMTP ist nirgends konfiguriert**, Zitadel kann also weder Verifikations- noch Einladungsmails verschicken.
- Wer GitHub und Google nutzt, hat zwei getrennte Accounts, bis beide in den Settings (L2) verknüpft werden.

**Frontend**
- Der Forum-Login bietet GitHub, Google und Passkey, dazu den Satz „New here? Your account is created on your first sign-in — there is nothing to fill in.“ ([LoginClientView.tsx:328](toob-infra/community/web/apps/forum/src/app/login/LoginClientView.tsx#L328)). Einen Onboarding-Screen für Firma, Org, Plan oder AGB gibt es nicht.
- Der Untertitel „One account for the Update Service, Registry and Forum.“ ([:240](toob-infra/community/web/apps/forum/src/app/login/LoginClientView.tsx#L240)) verspricht einen Dienst, den es noch nicht gibt.
- Die Website läuft im Prelaunch-Modus:
  - „Launch List“ verschickt nichts.
  - „Login“ führt auf das Crowdfunding-Formular; die Seite `/danke` ist ein Mock.
  - „Pricing“ verlinkt nur die FAQ.
  - Die Forum-Links zeigen auf `http://localhost:3001`.

**CLI:** `toob login` holt sich `/auth/config` von der Registry und meldet per OIDC an (Browser mit PKCE oder Device Code). Befehle für Registrierung, Org oder Plan gibt es nicht.

## 2. Was ein neuer Account hat

| | Stand |
|---|---|
| Org | „Toob Alliance“, geteilt mit allen Self-Signups |
| Identität | `toob:human:shared:<AllianceOrgId>:<sub>` ([verifier.go:101-114](toob-infra/identity/token/verifier.go#L101-L114)) |
| Trust | L1; L2 erst nach einer Anmeldung mit Passkey |
| Plan | immer `free`: Ein Entitlement braucht per Fremdschlüssel eine `tenants`-Zeile ([027:17](toob-infra/identity/migrations/027_tenant_entitlements.up.sql#L17)), und für die geteilte Org kann keine entstehen |
| FGA | nichts gespeichert; pro Prüfung ein kontextuelles `member` der geteilten Org |

- **Mit L1:** Konto ansehen, Passkey hinzufügen, im Forum alles einschließlich privater Tickets, in der Registry lesen.
- **Mit L2:** Profil ändern, IdP verknüpfen, genau einen Registry-Namespace anlegen, publishen, Tokens anlegen.
- **Nie:** Tenant, Mitglieder, Plan, Geräte.

Zu deiner Frage: **Nein**, selbst zuweisen oder anlegen lässt sich nirgends etwas.
- `@toob/account` kann Profil, Anmeldemethoden, IdP-Links, Passkey und Sessions.
- Die Settings zeigen den Plan nur an; der Upgrade-Button fehlt bewusst (`TODO(billing)`, [SettingsClientView.tsx:128](toob-infra/community/web/apps/forum/src/app/settings/SettingsClientView.tsx#L128)).
- Die einzige „Organisation“, die man selbst anlegen kann, ist der Registry-Namespace (`POST /api/v1/orgs`). Dafür gibt es weder UI noch CLI-Befehl.

## 3. Organisationen, Mitglieder, Einladungen

Es gibt zwei Welten, die nicht miteinander verbunden sind.

**Identity-Tenant = Zitadel-Org** (daran hängen Plan und Mitgliedschaft)
- Anlegen kann ihn nur `platform#staff` mit L2. Die Docs nennen das bewusst „Sales, nicht Self-Service“ ([plan7_backlog.md:219](docs/plan7_backlog.md#L219)).
- Beim Anlegen entstehen die Zitadel-Org, eine `tenants`-Zeile und ein Audit-Eintrag ([tenants.go:67-149](toob-infra/identity/api/tenants.go#L67-L149)). Es entstehen **kein** Owner, kein FGA-Tupel und kein Entitlement. Die Onboarding-Saga wird nur von Tests aufgerufen.
- Danach ist der Tenant eine Sackgasse:
  - `TenantGate` lässt Menschen nur in der Org ihres Tokens handeln ([principal.go:93-107](toob-infra/identity/principal/principal.go#L93-L107)).
  - Staff sind in echten Tokens immer `ActorHuman` der „Toob Alliance“; `ActorOperator` entsteht nur in Test-Issuern. Staff kommen also an keinen Kunden-Tenant heran.
  - In die neue Zitadel-Org kommt auch niemand hinein, weil kein Code Zitadel-User anlegt oder einlädt.
- Die Mechanik für Mitgliedschaften existiert: Rollen owner/admin/member, Routen zum Auflisten, Hinzufügen, Entfernen und Rolle-Ändern, und der Weg Outbox → `identity-sync` → FGA.
- **„Invite“ ist keine Einladung.** `POST …/members` vergibt direkt eine Rolle an eine bestehende `user_id`, ohne Mail, Code, Frist oder Annehmen. `policy/rules/invite.yaml` wird nicht genutzt, und die darin genannte Rolle `viewer` gibt es gar nicht.
- **Grundwiderspruch:** Die Datenbank erlaubt eine Person in mehreren Tenants, der Token trägt aber genau eine Org. Eine Social-Person, die in Tenant X eingetragen ist, weist `TenantGate` auf X trotzdem ab.
- SCIM schreibt nur in identitys eigene `scim_users`. Diese Personen haben keinen Zitadel-Account und können sich nicht anmelden.

**Registry-Namespace**
- Das ist Self-Service (member und L2, Quota 1/5/999 je nach Plan), und wer ihn anlegt, wird Owner.
- Die Spalte `zitadel_org_id` existiert, wird aber nie geschrieben. „Leave“ ist nicht gemountet, und der letzte Owner ist nicht geschützt.

## 4. Payments, Pläne, Entitlements

**Vorhanden**
- Die Tiers `free/pro/enterprise`, mit Limits nur für die Registry ([plan.go](toob-infra/shared/plan/plan.go)).
- Entitlements in Identity: `tenant_entitlements` mit Historie und `valid_until`, gesetzt über `PUT /tenants/{id}/entitlement`.
- Ein Token-Hook schreibt `toob_plan` in jeden Token; Registry und Forum lesen ihn.
- Ein guter, aber **nicht gebauter** Entwurf für den Billing-Service ([devops_architecture.md §11](toob-infra/docs/devops_architecture.md#L783-L827)): eigene Schicht `billing/`, idempotente Webhooks vom Provider, Abgleich mit dem Provider, Trial und Grace als `valid_until`. Der Service schreibt nur das Entitlement.

**Zahlungsmethoden und Rechnungsdaten gibt es gar nicht.** Es fehlen Provider, Checkout, Kundenportal, ein Datenmodell für Adresse und USt-ID, die VIES-Prüfung, Rechnungen und jede UI dafür. Stattdessen läuft in Produktion ein Platzhalter ([billing.go](toob-infra/registry/internal/server/handler/billing.go)):
- `POST /billing/upgrade` liefert eine feste Mock-URL und darf schon von einem einfachen `member` aufgerufen werden. Die Relation `can_manage_billing: owner` nutzt keine Permission.
- `POST /billing/webhook` ist öffentlich, prüft keine Signatur und antwortet immer mit 200.

**Warum niemand einen Plan setzen kann:**
1. **Staff:** `TenantGate` weist jeden fremden Tenant ab.
2. **Künftiger Billing-Service-Account:** Er kommt durch `TenantGate`, scheitert aber an `TrustGate`, weil L2 für Maschinen unerreichbar ist ([trust.go:31](toob-infra/identity/enforce/trust.go#L31)); dazu kommt der Step-up.
3. **Self-Signups:** Eine `tenants`-Zeile ist für sie nicht möglich. Außerdem wäre ein Upgrade der geteilten Org ein Upgrade für alle.

**Weitere Planfehler**
- Die Registry deckelt jedes Limit auf `MAX_*_PACKAGES` (Default 10/5/5). Pro und Enterprise bekommen dadurch die Free-Limits ([publish.go:105-107](toob-infra/registry/internal/server/handler/publish.go#L105-L107)).
- Das Forum verspricht „private support“ nur für Pro, das Backend erlaubt ihn allen.

## 5. Stand des Update-Service

- **`toob-infra/update`:** zwei Hello-World-Binaries und eine kopierte `tenants`-Migration. Es gibt keine Routen, keine Authentifizierung, kein Deploy und keine Tests.
- **`svc/update-service` (veraltet):** Hier liegt die eigentliche Logik als Bibliothek, mit 44 Tests:
  - Check-in mit HMAC-Gerätetoken und Blob-Auslieferung;
  - Resolver mit Canary-Ramp und TBM1-Admission;
  - WORM-Store und SVN-Floor.

  Nichts davon ist gemountet. Das Schema kennt keinen Tenant, und die Ingest-Endpunkte haben keine Authentifizierung.
- **Geräte-Identität:** Es gibt zwei konkurrierende Entwürfe, HMAC-Token (im SDK gebaut) und mTLS-PKI (Identity-Bibliothek, Stores nur im Speicher).
- **Katalog:** Sechs Permissions können nie jemandem etwas erlauben (`fleet.device.*`, `fleet.channel.create`, `admin.killswitch.trigger`). `device#viewer`, `device#operator` und `channel#admin` fehlen im Modell, und `device#owner` nimmt keine User ([marketplace.fga:23-30](toob-infra/policy/model/marketplace.fga#L23-L30)). Der Linter prüft das nicht.
- **Deploy:** nicht im Wizard, keine Domain, kein Staging-CIDR, und systemd gegen Nomad ist offen. Die Vault-Policy erlaubt dem Update-Service sogar `transit/sign/update-firmware-signing`, was UPD-033 widerspricht.
- **Schon nutzbar:** die Vier-Augen-Release-Freigabe (`VerifyDeployable`), das Zitadel-Projekt `fleet` (noch ohne App) und die Revocation per Pub/Sub.
- **Lizenz:** BSL 2b erlaubt die kommerzielle Nutzung, wenn die Geräte „registered and actively connected … under an active paid subscription“ sind ([LICENSE.md:41](toob-infra/community/web/LICENSE.md#L41)). Der Update-Service muss also je Kunde Abo-Status und aktive Geräte kennen. Einen Preis mit Gerätebezug gibt es nirgends.

## 6. Was wir zum Anknüpfen brauchen

### Grundsatzentscheidungen vor der ersten Zeile Code

**E1 Kundenmodell – die wichtigste Entscheidung.** Heute gilt: Tenant = Zitadel-Org = Resource Owner im Token, also genau eine Org pro Person.
- **(a) Jeder Kunde bekommt eine eigene Zitadel-Org.**
  - Dafür: Das passt zum gebauten Code.
  - Dagegen: Wer sich per Social Login angemeldet hat, bräuchte für die eigene Firma einen zweiten Account, und wer für zwei Firmen arbeitet, zwei weitere.
- **(b) Die Person ist global, Kunde ist eine Mitgliedschaft** (wie bei GitHub und Vercel). Der aktive Tenant kommt aus Pfad oder Session und wird per `tenant#member` geprüft. `tenant_members`, `identity-sync` und `RelationGate` können das schon.
  - Umbauen müsste man `TenantGate`, die Rate-Limits pro Org, den Kill-Switch pro Org und das kontextuelle „jeder ist Member von Toob Alliance“.
  - Der Plan kann dann nicht mehr im Token stehen, sondern wird pro Tenant mit Cache nachgeschlagen.
  - Enterprise-SSO bekäme trotzdem eine eigene Zitadel-Org für den IdP des Kunden.
- **Empfehlung: (b).** Das Geschäftsmodell ist Self-Service mit Upgrade, und (a) erzwingt schon beim ersten Firmenkunden Zweitaccounts.

**E2 Payment-Provider.** Grundsatz: Zahlungsdaten, Rechnungsadresse und USt-ID liegen beim Provider, nie bei uns. Wir speichern nur Customer- und Subscription-IDs und leiten per Webhook das Entitlement ab, so wie §11 es vorsieht.
- **Empfehlung:** Stripe mit Checkout, Customer Portal, Tax und Meters für Gerätepreise.
- **Alternative:** ein Merchant of Record wie Paddle, wenn wir die USt-Haftung ganz abgeben wollen.

**E3 Preismodell:** pro Gerät, pro Seat oder nach Stufen. `shared/plan` braucht in jedem Fall Fleet-Limits.

**E4 Geräte-Authentifizierung:** HMAC oder mTLS, dazu **ein** Hostname. Heute nennen Docs und SDK drei verschiedene.

**E5 Konsole:** eine eigene App im `community/web`-Monorepo mit eigenem BFF, wie `plan7_backlog` E.3 es vorsieht. Sie nutzt `@toob/account` und `@toob/ui` mit.

### Bausteine in Abhängigkeitsreihenfolge

1. **Fundament** (klein, unabhängig von E1):
   - Defekte 2–6 und 8 aus Abschnitt 7;
   - SMTP einrichten;
   - den Fleet-Katalog gegen das Modell reparieren, dazu eine Linter-Regel.
2. **Organisationen** (nach E1):
   - „Organisation anlegen“ als Self-Service mit Quota. Tenant, Owner, FGA-Tupel und Entitlement `free` entstehen in einem Schritt.
   - Einladungen mit Token-Hash, E-Mail, Rolle, Frist, Annehmen, Widerrufen und einer Liste offener Einladungen.
   - Mitgliederliste mit Namen und ein Org-Wechsler in der Session.
   - Ein auditierter Weg, auf dem Staff in Kunden-Tenants arbeiten kann.
3. **Billing** (nach §11):
   - die Schicht `billing/` mit Checkout, Kundenportal, signierten und idempotenten Webhooks und dem Abgleich mit dem Provider;
   - für den Service-Account eine Zwillings-Permission ohne L2 und Step-up (`platform#billing`);
   - `can_manage_billing` an eine echte Permission hängen;
   - eine UI „Plan & Billing“ in den Org-Settings.
4. **Update-Service andocken** (nur Authentifizierung, Org und Plan, noch ohne Fleet-Features):
   - eine OIDC-App in Zitadel;
   - `toob-fleet` so verdrahten wie die Registry (Introspection, Gate-Kette, `RelationGate`);
   - `tenant_id` mit FORCE RLS auf allen Tabellen;
   - den Plan bei der Geräteanmeldung festhalten, weil Geräte keinen User-Token haben;
   - Gerätezahlen an Billing melden;
   - eine Wizard-Schicht, und die Signier-Berechtigung entfernen.

## 7. Defekte, die dabei aufgefallen sind

1. **Der Plan-Schreibweg ist tot** (siehe Abschnitt 4).
2. **Registry `users.id` ist vom Typ UUID** ([001_initial.up.sql:22](toob-infra/registry/migrations/001_initial.up.sql#L22), nie geändert), aber `EnsureFromIdentity` schreibt die URN hinein ([auth.go:187](toob-infra/registry/internal/server/middleware/auth.go#L187)). Die erste Registry-Anmeldung jeder echten Person endet damit sehr wahrscheinlich in einem 500. Zur Laufzeit habe ich das nicht geprüft, weil die Integrationstests eine Datenbank brauchen.
3. **`insufficient_trust_level` wird nie erzeugt**, `TrustGate` liefert `forbidden` ([trust.go:38-40](toob-infra/identity/enforce/trust.go#L38-L40)). Unsere Account-UI sperrt L2-Aktionen vorher über `canChange`; `needsPasskey` feuert dadurch aber nie, und CLI und Registry-Clients bekommen den falschen Code.
4. **Device-SDK:** Das 32-Byte-Binärtoken wird mit `%s` formatiert ([toob_network_client.c:291](sdk/os_client/src/toob_network_client.c#L291)). Das liest über das Array hinaus (CERT C STR32-C) und schreibt Rohbytes in den HTTP-Header. Der Rückgabewert von `snprintf` wird nicht geprüft.
5. Billing-Mock und ungeschützter Webhook laufen in Produktion.
6. Ein Admin kann Owner ernennen und Owner entfernen, und der letzte Owner ist nicht geschützt ([membership.go:100-187](toob-infra/identity/api/membership.go#L100-L187)).
7. **Die geteilte Org hat Nebenwirkungen:**
   - `admin.impersonation.list/stop` (member, L1) zeigt und beendet Support-Sitzungen über alle Self-Signups. Das ist derzeit latent, weil Impersonation in Produktion ohne Operator gar nicht startet.
   - Alle teilen sich einen Rate-Limit-Topf für Schreibzugriffe.
   - Der Kill-Switch der Org träfe alle.
8. `MAX_*_PACKAGES` deckelt Pro und Enterprise. `ResolvePlan` fällt bei kaputtem JSON still auf den Default zurück.
9. Kein SMTP, und „Leave“ in der Registry ist nicht gemountet.
10. **Doku und Texte sind veraltet:**
    - `identity_login.md` §2.1/2.3/2.4/7/8.3 stimmen nicht mehr.
    - `plan8.md` verweist auf ein Architektur-Dokument, das nicht existiert.
    - `platform#billing` (§11) passt nicht zu `entitlement_manager` (Modell).
    - Forum und Website versprechen Update-Service und Pro-Support.

Ich habe mir gemerkt, dass der Update-Service das Hauptgeschäft ist, und die offenen Entscheidungen E1–E5 dazu notiert. Soll ich E1–E5 als teilbare Entscheidungsseite aufbereiten?