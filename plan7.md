# Backlog — Identity-Integration in die Produkte

**Anschluss an:** `BACKLOG-zitadel-sicherheit.md` (abgeschlossen — Zitadel steht und ist
gehärtet), `ARCHITEKTUR-rollenmodell.md`, `ARCHITEKTUR-identity-zitadel.md`.

**Voraussetzung:** Kein laufendes Produktivsystem. Schema-Änderungen dürfen destruktiv sein,
es gibt keine Bestandsnutzer und keine ausgegebenen `toob_v1_`-Keys.

**Präfix `AUTH-`**, damit die Nummern nicht mit `IDP-`, `UPD-`, `OPS-` oder `BEF-` kollidieren.

---

# TEIL 1 — Die offenen Punkte, entschieden

## D1 — Kunden bekommen keinen Zitadel-Zugang

**Frage war:** Welches Zitadel-Primitiv trägt die org-gebundene Produktrolle — Projektrolle mit
Org-Grant, User-Grant oder Org-Member-Rolle?

**Entscheidung:** Project Grant plus User Grant, und **Kunden erhalten grundsätzlich keine
Zitadel-Konsolenrechte**.

```
Toob besitzt Projekt "fleet" mit Rollen viewer/operator/release-manager
  └─ Project Grant an Org @acme
       └─ User Grant: Anna erhält "release-manager" in @acme
```

Die Governance-Rollen (`owner`, `admin`, `member`) werden als drittes Projekt `governance`
modelliert, **nicht** über Zitadels eingebaute `ORG_OWNER`-Rollen.

**Warum das der wichtige Teil ist:** Zitadels `ORG_OWNER` darf die Login-Policy der eigenen
Organisation ändern. Ein Kunde mit dieser Rolle könnte die MFA-Anforderung aus `IDP-011b`
senken — genau das, was `IDP-005` verhindern soll. Indem Kunden gar keine Konsolenrechte
bekommen und ihre Mitglieder ausschließlich über **unsere** Oberfläche verwalten, ist die
Frage strukturell erledigt statt per Policy-Sperre.

Unsere Oberfläche ruft die Zitadel-API mit einem Dienstkonto. Das Dienstkonto darf Mitglieder
und Rollen verwalten, aber keine Policies ändern.

## D2 — Ein Token trägt genau eine Organisation

**Frage war:** Wer bei zwanzig Organisationen Mitglied ist, hat viele Rollen im Token. Ab
welcher Größe wird das zum Problem?

**Entscheidung:** Die Frage stellt sich nicht, weil ein Token **immer auf genau eine
Organisation** ausgestellt wird (`urn:zitadel:iam:org:id:{orgId}` als Scope).

- Die Fleet-Oberfläche hat einen Organisationswechsler; der Wechsel holt ein neues Token.
- Der CLI leitet den Kontext aus dem Paket-Scope ab: `@esp-alliance/foo` ⇒ Token für
  `@esp-alliance`.

**Der Sicherheitsgewinn ist größer als der Größenvorteil:** Ein Token für Mandant A kann
nichts in Mandant B — die Mandantengrenze steht im Token selbst, nicht erst in der
Autorisierungsschicht. Ein Fehler in `UPD-111` (Tenant-Kontext setzen) wäre damit nicht mehr
allein ausreichend für ein Leck.

## D3 — Ein persönlicher Scope *ist* eine Organisation

**Frage war:** `AuthorizeScopeClaim` vergleicht den persönlichen Scope `@annalogin` mit
`usr.GitHubLogin`. Was tun bei Nutzern ohne GitHub?

**Entscheidung:** Bei der Registrierung entsteht eine **persönliche Organisation** mit dem
gewählten Benutzernamen. Damit gibt es nur noch einen Mechanismus.

`AuthorizeScopeClaim` vereinfacht sich auf eine Zeile — „ist der Nutzer Mitglied der
Organisation, die dem Scope entspricht" — und der GitHub-Sonderfall verschwindet vollständig:

```go
// vorher: Sonderfall für persönlichen Scope
if strings.EqualFold(orgName, usr.GitHubLogin) { return allowed }
isMember, err := e.orgs.IsOrgMember(ctx, orgName, usr.ID)

// nachher: nur noch der eine Pfad
isMember, err := e.orgs.IsOrgMember(ctx, orgName, usr.ID)
```

Das ist das Modell, das GitHub selbst verwendet: Ein Nutzerkonto ist ein Namensraum, der sich
wie eine Organisation verhält. Nebeneffekt: Namensregeln und Eindeutigkeit gelten für
persönliche und Team-Scopes automatisch gleich.

## D4 — Organisationen entstehen durch das Produkt, nie direkt in Zitadel

**Frage war:** Die Org entsteht in Zitadel, das Kontingent kennt das Produkt. Wo prüfen?

**Entscheidung:** Der einzige Weg zu einer neuen Organisation führt über die Produkt-API. Sie
prüft in dieser Reihenfolge:

1. Namensregeln (`validate.ValidateOrgName`)
2. Eindeutigkeit gegen den Spiegel
3. Kontingent (`CountByOwner` gegen `plan.MaxOrgs`)
4. **erst dann** Zitadel-API aufrufen
5. Spiegel-Upsert abwarten, Ergebnis zurückgeben

Aus D1 folgt, dass es keinen Umgehungsweg gibt — Kunden haben keine Konsole. Damit braucht es
keine Zitadel-Action als zweite Verteidigungslinie, und die Namensregel steht an genau einer
Stelle.

## D5 — Spiegel per Webhook, abgesichert durch Abgleich

**Frage war:** Zitadel-Actions, Webhook oder Event-Stream für den Org-Spiegel?

**Entscheidung:** **Beides** — Push für Aktualität, periodischer Abgleich für Korrektheit.

- **Webhook** aus einer Zitadel-Action bei Mitgliedschafts- und Rollenereignissen. Latenz
  unter einer Sekunde.
- **Vollabgleich alle 15 Minuten**: Produkt zieht den Ist-Stand und korrigiert Abweichungen.

Webhooks gehen verloren — bei Neustarts, Netzproblemen, Fehlern im Empfänger. Ein System, das
nur auf Push vertraut, driftet unbemerkt. Der Abgleich meldet jede korrigierte Abweichung als
Metrik; ein Anstieg ist ein Alarm, kein Betriebsgeräusch.

## D6 — Token Exchange findet im Produkt statt

**Frage war:** Unterstützt Zitadel RFC 8693, oder tauscht das Produkt?

**Entscheidung:** Das **Produkt** tauscht (relevant erst für `AUTH-090`, Workload-Identity).

Der Grund ist inhaltlich, nicht technisch: Die Prüfung, ob `repository`, `ref` und `workflow`
des vorgelegten GitHub-Actions-Tokens für diesen Mandanten zugelassen sind, braucht die
Mandantenkonfiguration. Die liegt im Produkt. Zitadel müsste sie spiegeln, um dieselbe
Entscheidung zu treffen — und dann hätten wir sie zweimal.

## D7 — Kein Migrationspfad

**Aus der Voraussetzung folgend**, aber es gehört ausgesprochen: Die vier Phasen aus
`ARCHITEKTUR-identity-zitadel.md` §9 entfallen. Kein Doppelbetrieb, keine
Legacy-Token-Weiche, keine Deprecation-Messung.

Konkret entfällt damit auch `IDP-051` (Bestandsnutzer vorverknüpfen) — es gibt keine.

---

# TEIL 2 — Backlog

**Prio:** P0 blockierend · P1 vor dem ersten Kunden · P2 Robustheit · P3 später
**Typ:** `refactor` `feature` `security` `config` `cleanup` `test`

## Übersicht

| ID | Titel | Prio | Typ |
|---|---|---|---|
| **EPIC A — Abriss, solange es billig ist** |||
| AUTH-001 | Selbstgebauten OAuth-Fluss entfernen | P0 | cleanup |
| AUTH-002 | `toob_v1_`-Session-Keys ersatzlos entfernen | P0 | cleanup |
| AUTH-003 | `PermOrgAdminBypass` entfernen | P0 | security |
| AUTH-004 | `contributor` entfernen | P1 | refactor |
| **EPIC B — Gemeinsames Modul** |||
| AUTH-010 | Modul `toob-identity` anlegen | P0 | feature |
| AUTH-011 | JWKS-Client mit Ausfallverhalten | P0 | feature |
| AUTH-012 | Token-Verifikation und Claim-Extraktion | P0 | feature |
| AUTH-013 | Middleware: Auth, Vertrauensstufe, Step-up | P0 | feature |
| AUTH-014 | Spiegel-Empfänger und Abgleich | P0 | feature |
| AUTH-015 | Rollenvokabular als geteilter Typ | P1 | feature |
| **EPIC C — Zitadel-Modell anlegen** |||
| AUTH-020 | Projekte und Rollen als Code | P0 | config |
| AUTH-021 | Dienstkonto mit minimalen Rechten | P0 | security |
| AUTH-022 | Persönliche Organisation bei Registrierung | P1 | feature |
| AUTH-023 | Org-Erzeugung ausschließlich über die Produkt-API | P0 | feature |
| AUTH-024 | Organisationsbezogene Token | P0 | config |
| **EPIC D — Registry umbauen** |||
| AUTH-030 | Auth-Middleware auf das Modul umstellen | P0 | refactor |
| AUTH-031 | `organizations` zum Spiegel machen | P0 | refactor |
| AUTH-032 | `AuthorizeScopeClaim` vereinfachen | P1 | refactor |
| AUTH-033 | `User` auf Spiegelfelder reduzieren | P1 | refactor |
| AUTH-034 | Org-Handler auf Zitadel-Schreibpfad | P1 | refactor |
| AUTH-035 | Schema aufräumen | P1 | cleanup |
| AUTH-036 | CI-Tokens auf Org-Bindung erweitern | P1 | security |
| **EPIC E — Fleet-Seite** |||
| AUTH-040 | `tenants` an die Zitadel-Org-ID binden | P0 | feature |
| AUTH-041 | Fleet-Autorisierungsschicht | P1 | feature |
| AUTH-042 | Sichtbereich nach Vertrauensstufe | P1 | security |
| AUTH-043 | Step-up-Gate vor Geräteoperationen | P1 | security |
| AUTH-044 | Vier-Augen-Freigabe an Rollen binden | P1 | security |
| **EPIC F — Betrieb und Nachweis** |||
| AUTH-050 | Ausfalltest: Zitadel abschalten | P1 | test |
| AUTH-051 | Mandantentrennungs-Testsuite | P0 | test |
| AUTH-052 | Spiegel-Rückstand überwachen | P1 | security |
| AUTH-053 | Impersonation umsetzen | P1 | security |
| **EPIC G — Später** |||
| AUTH-090 | Workload-Identity-Federation | P3 | feature |
| AUTH-091 | Kunden-IdP über OIDC/SAML | P3 | feature |

---

# EPIC A — Abriss, solange es billig ist

> Ohne Produktivsystem ist Löschen ein Commit. Mit Produktivsystem wäre es ein Projekt.
> Diese Epic kommt deshalb zuerst und vollständig.

---

### AUTH-001 — Selbstgebauten OAuth-Fluss entfernen

**Prio:** P0 · **Typ:** cleanup

**Lösung**
Ersatzlos löschen:

| Datei | Umfang |
|---|---|
| `handler/auth.go` | vollständig |
| `handler/assets/oob.html` | vollständig |
| `postgres/oauth.go` | vollständig, inkl. AES-GCM |
| `domain.OAuthSession` | Struct |
| `migrations/014_oauth_sessions` | Tabelle |
| `secret/oauth-aes-key` | Vault-Eintrag |
| `cfg.GitHubClientID`, `GitHubClientSecret`, `GitHubURL`, `GitHubAPIURL` | Konfiguration |

Die Routen `/api/v1/auth/*` entfallen. Der CLI-Login läuft über den OIDC Device Flow.

**Akzeptanzkriterien**
- [ ] Kein Verweis auf `oauth_sessions` im Code.
- [ ] `grep -ri "github.com/login/oauth"` liefert nichts.
- [ ] Der Vault-Pfad `secret/*/oauth-aes-key` ist gelöscht.

---

### AUTH-002 — `toob_v1_`-Session-Keys ersatzlos entfernen

**Prio:** P0 · **Typ:** cleanup

**Lösung**
`domain.GenerateAPIKey`, der `case "v1"`-Zweig in `authenticate`, `users.api_key_hash`,
`InvalidateAPIKey`, `POST /auth/logout`.

**`VerifyAPIKey` bleibt** — CI-Tokens nutzen es weiter. Der bcrypt-Rückfallzweig darin kann
allerdings weg: Er existierte nur für Alt-Hashes, und die gibt es nicht.

Damit vereinfacht sich auch `verifyCached`: Nach dem Wegfall von bcrypt ist die Verifikation
ein SHA-256 über ein Volle-Entropie-Geheimnis, also ~1 µs. Der doppelt gepufferte Cache löst
dann ein Problem, das nicht mehr besteht.

> **Empfehlung:** Cache trotzdem behalten, aber vereinfacht auf eine Generation mit TTL. Er
> spart weiterhin den Datenbank-Roundtrip, und das ist der teure Teil.

**Akzeptanzkriterien**
- [ ] Ein Token mit Präfix `toob_v1_` wird abgelehnt, nicht verifiziert.
- [ ] `VerifyAPIKey` enthält keinen bcrypt-Pfad mehr.

---

### AUTH-003 — `PermOrgAdminBypass` entfernen

**Prio:** P0 · **Typ:** security

**Problem**
Die Berechtigung erlaubt Toob-Personal, in **jeder** Kundenorganisation zu handeln — Orgs
löschen, Mitglieder verwalten, Pakete lesen, Rollen ändern. Die einzige Spur ist eine
`slog.Info`-Zeile in unserem eigenen Log.

Der Kunde erfährt es nicht. Das steht `IDP-060` direkt entgegen.

**Lösung**
`PermOrgAdminBypass` und alle sechs Auswertungsstellen in `authz/policy.go` entfernen. Der
Ersatz ist die Impersonation aus `AUTH-053`: zeitbegrenzt, begründet, im Audit-Log des Kunden.

Zu prüfen ist dabei `AuthorizeOrgAction`: Die Behandlung von `ViaOverride` fällt weg, aber die
Logik in `RemoveMember` — Maintainer dürfen keine Owner entfernen, außer per Override — muss
ohne Override weiterhin korrekt sein. Ohne Override lautet die Regel schlicht: Maintainer
dürfen keine Owner entfernen. Punkt.

**Akzeptanzkriterien**
- [ ] `grep -r "AdminBypass"` liefert nichts.
- [ ] `AuthzDecision.ViaOverride` ist entfernt.
- [ ] Kein Codepfad erlaubt Handeln in einer fremden Org ohne Impersonation.

---

### AUTH-004 — `contributor` entfernen

**Prio:** P1 · **Typ:** refactor

**Problem**
`RoleContributor` gewährt `PermPackagePublish` — aber *was* publiziert werden darf, entscheidet
`AuthorizeScopeClaim`. Die Rolle prüft im Ergebnis nur, ob jemand eingeloggt ist.

**Lösung**
`Role` reduziert sich auf die Frage, ob jemand Plattformpersonal ist. `RolePermissions`
behält nur den `core`-Eintrag; `HasPermission` liefert für alle anderen bei
produktbezogenen Berechtigungen `true`, weil die Schranke woanders sitzt.

Sauberer: `PermPackagePublish` und `PermPackageUnpublish` ganz aus dem Permission-Modell
nehmen. Sie sind keine globalen Berechtigungen, sondern Ergebnisse einer Ressourcenprüfung.

**Akzeptanzkriterien**
- [ ] `RoleContributor` existiert nicht mehr.
- [ ] Ein authentifizierter Nutzer ohne besondere Rolle kann unter seinem persönlichen Scope
      publizieren.
- [ ] Ein Nutzer ohne Mitgliedschaft kann unter einem fremden Scope nicht publizieren.

---

# EPIC B — Gemeinsames Modul

---

### AUTH-010 — Modul `toob-identity` anlegen

**Prio:** P0 · **Typ:** feature

**Lösung**
Eigenes Go-Modul, importiert von Registry und Fleet:

```
toob-identity/
├── jwks/       Schlüsselabruf mit Cache
├── token/      Verifikation, Claims, Vertrauensstufe
├── middleware/ RequireAuth, RequireTrustLevel, RequireStepUp
├── mirror/     Webhook-Empfänger, Abgleich, Upsert
└── roles/      Governance- und Produktrollen
```

**Nicht enthalten:** `PolicyEngine`, Permission-Maps, alles, was Produkttabellen kennt.

**Akzeptanzkriterien**
- [ ] Das Modul importiert kein Produktpaket.
- [ ] Testabdeckung der Verifikationspfade über 90 %, inklusive Fehlerfälle.

---

### AUTH-011 — JWKS-Client mit Ausfallverhalten

**Prio:** P0 · **Typ:** feature

**Problem**
Der JWKS-Abruf ist der einzige Punkt, an dem ein Produkt Zitadel überhaupt kontaktiert. Wenn
er falsch gebaut ist, wird aus der Offline-Verifikation doch eine Laufzeitabhängigkeit — genau
das, was `ARCHITEKTUR-devops.md` P1 verbietet.

**Lösung**
- Schlüsselsatz beim Start laden, danach alle 15 Minuten im Hintergrund erneuern.
- **Bei Ausfall den letzten bekannten Satz weiterverwenden**, unbegrenzt, mit Alarm ab einer
  Stunde ohne erfolgreiche Erneuerung.
- Unbekannte `kid` lösen **einen** außerplanmäßigen Abruf aus, mit Rate-Limit gegen
  Aushungerung — ein Angreifer mit erfundenen `kid` darf keinen Abruf-Sturm erzeugen.
- Niemals bei Abruffehler die Verifikation als „gültig" behandeln.

**Akzeptanzkriterien**
- [ ] Zitadel 24 h abgeschaltet ⇒ bestehende Tokens verifizieren weiter.
- [ ] 1000 Tokens mit erfundener `kid` erzeugen höchstens einen Abruf pro Minute.
- [ ] Abruffehler führt nie zu einer positiven Verifikationsentscheidung.

---

### AUTH-012 — Token-Verifikation und Claim-Extraktion

**Prio:** P0 · **Typ:** feature

**Lösung**
Vollständige Prüfung, keine Abkürzungen: Signatur, `iss`, `aud`, `exp`, `nbf`, Algorithmus
gegen eine Allowlist (**kein `none`, kein Downgrade auf HMAC**).

Extrahiert werden: `sub`, Organisation, Governance-Rolle, Produktrollen, `auth_time`, `amr`,
`acr`, Vertrauensstufe.

**Die Organisation ist Pflicht.** Ein Token ohne Org-Claim wird abgelehnt — aus D2 folgt, dass
es keins geben darf, und ein fehlender Claim wäre sonst ein stiller Weg an der
Mandantengrenze vorbei.

**Akzeptanzkriterien**
- [ ] Token mit `alg: none` wird abgelehnt.
- [ ] Token mit falschem `aud` wird abgelehnt.
- [ ] Token ohne Org-Claim wird abgelehnt.
- [ ] Fuzzing-Harness auf dem Parser im CI.

---

### AUTH-013 — Middleware: Auth, Vertrauensstufe, Step-up

**Prio:** P0 · **Typ:** feature

**Lösung**
Drei zusammensetzbare Middlewares:

```go
RequireAuth()                          // gültiges Token, Kontext gefüllt
RequireTrustLevel(identity.L2)         // Stufe aus IDP-010
RequireStepUp(5 * time.Minute)         // auth_time frisch genug
```

`RequireStepUp` gibt bei zu altem `auth_time` einen maschinenlesbaren Hinweis zurück, den der
Client in eine Re-Authentifizierung übersetzt — keinen generischen `403`.

**Akzeptanzkriterien**
- [ ] Ein sechs Minuten altes `auth_time` scheitert an `RequireStepUp(5m)`.
- [ ] Die Antwort enthält den nötigen `acr`-Wert, damit der Client gezielt nachfordern kann.

---

### AUTH-014 — Spiegel-Empfänger und Abgleich

**Prio:** P0 · **Typ:** feature · **Ref:** D5

**Lösung**
- **Webhook-Empfänger**: signaturgeprüft (HMAC mit Secret aus Vault), idempotent über eine
  Ereignis-ID, Upsert in die Spiegeltabellen.
- **Vollabgleich alle 15 Minuten**: Ist-Stand von Zitadel holen, Abweichungen korrigieren,
  Zahl der Korrekturen als Metrik.

Die Metrik ist der eigentliche Wert: Ein Webhook, der still ausfällt, sieht aus wie ein
Webhook, bei dem nichts passiert. Der Abgleich unterscheidet die beiden.

**Akzeptanzkriterien**
- [ ] Doppelt zugestellter Webhook erzeugt einen Datensatz, keine zwei.
- [ ] Webhook ohne gültige Signatur wird verworfen und protokolliert.
- [ ] Abgleich mit absichtlich verfälschtem Spiegel korrigiert und zählt.

---

### AUTH-015 — Rollenvokabular als geteilter Typ

**Prio:** P1 · **Typ:** feature

**Lösung**
Governance-Rollen (`owner`, `admin`, `member`) und die Produktrollen beider Produkte als
Konstanten im Modul, mit `CanManageMembers()`/`CanManageRoles()` — dieselbe Semantik wie
`domain.OrgRole` heute, nur an einer Stelle.

---

# EPIC C — Zitadel-Modell anlegen

---

### AUTH-020 — Projekte und Rollen als Code

**Prio:** P0 · **Typ:** config · **Ref:** D1

**Lösung**

| Projekt | Rollen |
|---|---|
| `governance` | `owner`, `admin`, `member` |
| `registry` | `reader`, `publisher` |
| `fleet` | `viewer`, `operator`, `release-manager` |

Als Terraform oder versionierte API-Aufrufe, nicht per Konsole — analog zu `IDP-005`.

---

### AUTH-021 — Dienstkonto mit minimalen Rechten

**Prio:** P0 · **Typ:** security · **Ref:** D1

**Problem**
Unsere Oberfläche verwaltet Mitglieder über die Zitadel-API. Das Dienstkonto dafür ist ein
lohnendes Ziel: Wer es hat, kann sich in jeden Mandanten schreiben.

**Lösung**
Ein Dienstkonto, das genau darf: Organisationen anlegen, Mitglieder hinzufügen und entfernen,
User Grants verwalten.

Es darf **nicht**: Login-Policies ändern, Authentikatoren registrieren, IdP-Konfiguration
ändern, Instanz-Einstellungen anfassen. Der Schlüssel liegt in Vault mit der Plattform-TTL-Regel.

Jede Verwendung landet im Audit-Log mit der auslösenden Nutzeridentität — sonst sieht jede
Mitgliederänderung nach „Dienstkonto" aus statt nach der Person, die sie ausgelöst hat.

**Akzeptanzkriterien**
- [ ] Negativtest je verbotener Operation.
- [ ] Das Audit-Log nennt die auslösende Person, nicht nur das Dienstkonto.

---

### AUTH-022 — Persönliche Organisation bei Registrierung

**Prio:** P1 · **Typ:** feature · **Ref:** D3

**Lösung**
Bei der Registrierung wählt der Nutzer einen Benutzernamen; daraus entsteht eine persönliche
Organisation mit `governance: owner`. Der Name unterliegt denselben Regeln wie ein Team-Scope
und teilt sich mit diesen den Namensraum.

Damit gibt es nur einen Mechanismus, und `AUTH-032` kann den GitHub-Sonderfall streichen.

**Akzeptanzkriterien**
- [ ] Ein neuer Nutzer hat unmittelbar eine persönliche Org.
- [ ] Ein Team-Scope kann nicht denselben Namen wie eine persönliche Org bekommen.

---

### AUTH-023 — Org-Erzeugung ausschließlich über die Produkt-API

**Prio:** P0 · **Typ:** feature · **Ref:** D4

**Lösung**
Reihenfolge: Namensregeln → Eindeutigkeit → Kontingent → Zitadel-API → Spiegel-Upsert
abwarten → antworten.

Aus D1 folgt, dass es keinen Umgehungsweg gibt.

**Akzeptanzkriterien**
- [ ] Kontingentüberschreitung wird abgelehnt, **bevor** in Zitadel etwas entsteht.
- [ ] Bei Fehlschlag des Spiegel-Upserts wird die Zitadel-Org wieder entfernt oder als
      unvollständig markiert — keine verwaisten Organisationen.

---

### AUTH-024 — Organisationsbezogene Token

**Prio:** P0 · **Typ:** config · **Ref:** D2

**Lösung**
Alle Clients fordern Tokens mit `urn:zitadel:iam:org:id:{orgId}`. Die Fleet-Oberfläche hat
einen Organisationswechsler, der CLI leitet den Kontext aus dem Paket-Scope ab.

**Akzeptanzkriterien**
- [ ] Ein Token enthält Rollen für genau eine Organisation.
- [ ] Ein Token für Org A wird von einem Endpunkt, der Org B betrifft, abgelehnt — und zwar
      an der Middleware, nicht erst in der Datenbankabfrage.

---

# EPIC D — Registry umbauen

---

### AUTH-030 — Auth-Middleware auf das Modul umstellen

**Prio:** P0 · **Typ:** refactor

**Lösung**
Nach `AUTH-002` bleiben zwei Pfade:

```go
switch {
case strings.HasPrefix(tok, "toob_ci_"):  // produkteigen, DB, Cache
default:                                   // JWT über das Modul
}
```

Der Kontext trägt zusätzlich Organisation, Vertrauensstufe und `auth_time`.

---

### AUTH-031 — `organizations` zum Spiegel machen

**Prio:** P0 · **Typ:** refactor

**Lösung**
Lesemethoden bleiben. `CreateOrganization`, `AddOrgMember`, `RemoveOrgMember`, `Delete` werden
zu Zitadel-Aufrufen.

Die Tabellen bekommen `zitadel_org_id` als natürlichen Schlüssel und eine
`synced_at`-Spalte. Schreibrechte hat ausschließlich die Sync-Rolle:

```sql
REVOKE INSERT, UPDATE, DELETE ON organizations, organization_members FROM api;
GRANT  INSERT, UPDATE, DELETE ON organizations, organization_members TO   sync;
```

Damit ist „read-only im Produkt" nicht Absicht, sondern durchgesetzt.

**Akzeptanzkriterien**
- [ ] Ein `INSERT` aus der API-Rolle scheitert an der Datenbank.

---

### AUTH-032 — `AuthorizeScopeClaim` vereinfachen

**Prio:** P1 · **Typ:** refactor · **Ref:** D3

**Lösung**
Der GitHub-Sonderfall entfällt. Übrig bleibt die Mitgliedschaftsprüfung gegen den Spiegel.

**Akzeptanzkriterien**
- [ ] Ein Nutzer publiziert unter seinem persönlichen Scope über denselben Codepfad wie unter
      einem Team-Scope.
- [ ] `usr.GitHubLogin` wird in `authz/` nicht mehr gelesen.

---

### AUTH-033 — `User` auf Spiegelfelder reduzieren

**Prio:** P1 · **Typ:** refactor

**Lösung**
`User` behält: `ID` (Zitadel-Subject), `Username`, `DisplayName`, `PlanTier`,
`PlanOverrides`, `SuspendedAt`, `CreatedAt`.

Entfällt: `GitHubID`, `GitHubLogin`, `APIKeyHash`, `Role`.

`GitHubLogin` verschwindet vollständig — nach `AUTH-032` gibt es keinen Leser mehr, und GitHub
ist nur noch eine von mehreren Anmeldemethoden.

---

### AUTH-034 — Org-Handler auf Zitadel-Schreibpfad

**Prio:** P1 · **Typ:** refactor

**Lösung**
`Create`, `AddMember`, `RemoveMember`, `Delete` rufen Zitadel. Die Quotenprüfung bleibt lokal.

Die Regel aus `AUTH-003` gilt: Maintainer dürfen keine Owner entfernen, ohne Override-Zweig.
Die Prüfung „letzter Owner kann sich nicht selbst entfernen" bleibt — sie liest den Spiegel.

---

### AUTH-035 — Schema aufräumen

**Prio:** P1 · **Typ:** cleanup

**Lösung**
Eine destruktive Migration, solange das erlaubt ist:

```sql
DROP TABLE oauth_sessions;
ALTER TABLE users DROP COLUMN api_key_hash, DROP COLUMN github_id,
                  DROP COLUMN github_login, DROP COLUMN role;
ALTER TABLE users ADD COLUMN username TEXT UNIQUE NOT NULL;
ALTER TABLE organizations ADD COLUMN zitadel_org_id TEXT UNIQUE NOT NULL;
ALTER TABLE organization_members ADD COLUMN synced_at TIMESTAMPTZ NOT NULL DEFAULT now();
```

Die 30 bestehenden Migrationen bleiben unangetastet — eine neue kommt oben drauf. Ein
Zusammenfalten der Historie spart nichts und macht die Herkunft der Tabellen unlesbar.

---

### AUTH-036 — CI-Tokens auf Org-Bindung erweitern

**Prio:** P1 · **Typ:** security

**Problem**
`api_tokens` hängt an `user_id`. Ein CI-Token wirkt damit überall, wo sein Besitzer Mitglied
ist — auch in Organisationen, die mit der CI-Pipeline nichts zu tun haben.

Nach D2 trägt jedes JWT genau eine Organisation. Für CI-Tokens gilt dieselbe Grenze, sonst ist
der Maschinenpfad breiter als der menschliche.

**Lösung**
`api_tokens` bekommt `organization_id NOT NULL`. Bei der Erzeugung wählt der Nutzer die
Organisation; das Token wirkt nur dort. Verliert der Nutzer die Mitgliedschaft, wird das Token
ungültig.

**Akzeptanzkriterien**
- [ ] Ein CI-Token für Org A kann in Org B nichts.
- [ ] Entfernung aus der Org invalidiert die zugehörigen Tokens.

---

# EPIC E — Fleet-Seite

---

### AUTH-040 — `tenants` an die Zitadel-Org-ID binden

**Prio:** P0 · **Typ:** feature

**Lösung**
`tenants.id` **ist** die Zitadel-Org-ID. Keine eigene Vergabe, keine Zuordnungstabelle. Das
`tenant_id` aus `UPD-110` verweist darauf.

Der Spiegel aus `AUTH-014` legt Mandanten an, sobald eine Organisation eine
`fleet`-Projektzuweisung bekommt.

**Akzeptanzkriterien**
- [ ] Es existiert kein Mandant ohne Zitadel-Organisation.
- [ ] `SET LOCAL app.tenant_id` (`UPD-111`) wird aus dem Org-Claim gesetzt, nie aus einem
      Request-Parameter.

---

### AUTH-041 — Fleet-Autorisierungsschicht

**Prio:** P1 · **Typ:** feature

**Lösung**
Zentrale Middleware statt Prüfung je Handler (`S5` aus
`ARCHITEKTUR-identitaet-mandanten.md`): Jeder Endpunkt deklariert benötigte Rolle,
Vertrauensstufe und Ressourcentyp. Die Middleware lädt die Ressource, prüft
Mandantengleichheit und Rolle.

**Ein Handler ohne Deklaration kompiliert nicht** — Registrierung über eine Tabelle, nicht
über Konvention.

---

### AUTH-042 — Sichtbereich nach Vertrauensstufe

**Prio:** P1 · **Typ:** security · **Ref:** `IDP-011`

**Lösung**
L1 sieht Aggregate, L2+ sieht Einzeldaten. Durchgesetzt in der Autorisierungsschicht, nicht in
der UI — ein L1-Token bekommt Geräte-IDs, SBOM-Digests und Verschleißdaten auch über die API
nicht.

---

### AUTH-043 — Step-up-Gate vor Geräteoperationen

**Prio:** P1 · **Typ:** security · **Ref:** `IDP-040`

**Lösung**
`RequireStepUp(5m)` vor Artefakt-Publish, Channel-Wechsel, Rollout-Start, Killswitch und
Cloud-Command.

---

### AUTH-044 — Vier-Augen-Freigabe an Rollen binden

**Prio:** P1 · **Typ:** security · **Ref:** `IDP-041`, `IDP-043`

**Lösung**
Zwei verschiedene `release-manager` derselben Organisation, beide mit frischem Step-up. Der
Freigabenachweis ist an Artefakt-Digest und Channel gebunden und nicht wiederverwendbar.

Der Signing Service prüft ihn — nicht die Oberfläche.

---

# EPIC F — Betrieb und Nachweis

---

### AUTH-050 — Ausfalltest: Zitadel abschalten

**Prio:** P1 · **Typ:** test

**Lösung**
Zitadel herunterfahren, dann prüfen:

| Erwartung | |
|---|---|
| Geräte-Check-in | läuft |
| Firmware-Download | läuft |
| Registry-API mit gültigem Token | läuft |
| CI-Token-Pfad | läuft |
| Neuer Login | scheitert |
| Mitglied einladen | scheitert |

Ergänzt `PLAT-006` um die Identity-Dimension.

---

### AUTH-051 — Mandantentrennungs-Testsuite

**Prio:** P0 · **Typ:** test

**Lösung**
Zwei Mandanten mit absichtlich kollidierenden Bezeichnern — gleiche `product_id`, gleicher
Paketname, gleicher Channel. Für **jeden** Endpunkt der Nachweis, dass A nichts von B sieht,
auch bei absichtlich weggelassenem `WHERE`.

Läuft bei jedem PR. Ohne diese Suite ist Mandantentrennung eine Behauptung.

**Akzeptanzkriterien**
- [ ] Ein absichtlich entferntes `tenant_id`-Prädikat lässt die Suite rot werden.
- [ ] Ein Token für A gegen einen Pfad von B ⇒ `403`, nicht `404` mit Datenleck im Timing.

---

### AUTH-052 — Spiegel-Rückstand überwachen

**Prio:** P1 · **Typ:** security

**Lösung**
Metriken: Webhook-Latenz, Zahl der Abgleich-Korrekturen, Alter des letzten erfolgreichen
Abgleichs. Alarm bei Rückstand über fünf Minuten oder bei einem Anstieg der Korrekturen.

Ein entferntes Mitglied, dessen Token noch zehn Minuten gilt, ist ein akzeptiertes
Restrisiko. Ein Spiegel, der seit Stunden nicht abgeglichen hat, ist es nicht.

---

### AUTH-053 — Impersonation umsetzen

**Prio:** P1 · **Typ:** security · **Ref:** `IDP-060`

**Lösung**
Ersatz für den entfernten Admin-Bypass: begründungspflichtig, maximal vier Stunden, im
Audit-Log **des Kunden** sichtbar, Benachrichtigung an alle Org-Owner, niemals mit
`release-manager` — und impersonierte Sitzungen bestehen `RequireStepUp` nie.

**Akzeptanzkriterien**
- [ ] Impersonation ohne Begründung ist nicht möglich.
- [ ] Eine impersonierte Sitzung kann keine Geräteoperation auslösen.
- [ ] Der Kunde sieht den Vorgang in seinem eigenen Audit-Log.

---

# EPIC G — Später

**AUTH-090** Workload-Identity-Federation (`D6` — Tausch im Produkt, Prüfung von
`repository`, `ref`, `workflow`; Maschinenidentitäten erhalten nie `release-manager` für
Produktions-Channels).

**AUTH-091** Kunden-IdP über OIDC/SAML — mit der Auflage aus `IDP-052`: Liefert der Kunden-IdP
keinen nachweislich phishing-resistenten Faktor, bleibt für L3 ein lokaler Passkey nötig.

---

## Reihenfolge

**Sprint 1 — Abriss und Fundament:**
`AUTH-001` → `AUTH-002` → `AUTH-003` → `AUTH-010` → `AUTH-011` → `AUTH-012`

Der Abriss zuerst: Jeder Tag, den der alte Fluss noch steht, ist ein Tag, an dem jemand
darauf aufbaut.

**Sprint 2 — Modell und Modul:**
`AUTH-020` → `AUTH-021` → `AUTH-024` → `AUTH-013` → `AUTH-014` → `AUTH-015`

**Sprint 3 — Registry:**
`AUTH-030` → `AUTH-031` → `AUTH-035` → `AUTH-022` → `AUTH-023` → `AUTH-032` → `AUTH-033` →
`AUTH-034` → `AUTH-004` → `AUTH-036`

`AUTH-035` (Schema) früh, solange destruktive Migrationen erlaubt sind.

**Sprint 4 — Fleet:**
`AUTH-040` → `AUTH-051` → `AUTH-041` → `AUTH-042` → `AUTH-043` → `AUTH-044`

`AUTH-051` vor den Autorisierungstickets: Die Testsuite soll rot sein, bevor sie grün wird.

**Sprint 5 — Betrieb:**
`AUTH-050` → `AUTH-052` → `AUTH-053`

**Später:** `AUTH-090`, `AUTH-091`

---

## Merksatz

> Ohne Produktivsystem kostet Löschen einen Commit. Jedes Ticket aus EPIC A, das jetzt nicht
> erledigt wird, kostet später ein Wartungsfenster — und der Admin-Bypass kostet dann
> zusätzlich die Antwort auf die Frage, wer wann in den Daten des Kunden war.