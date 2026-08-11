# Toob Identity — Review Addendum: OpenFGA-Modell

**Prüfgrundlage:** `policy/model/*.fga`, `policy/model/fga.mod`, `policy/tests/*.fga.yaml` (Export 2026-08-07)
**Bezug:** Ergänzt „Toob Identity — Review des Umsetzungsstands", dort Punkt AUTHZ-02…05 (bisher ❓) und Prüfpunkt P6.

---

## 0. Vorbemerkung: Diese Dateien wurden nie an OpenFGA übergeben

Bevor es um Modellierung geht, das Ergebnis der Ladbarkeitsprüfung: **Das Modell kann in dieser Form nicht geschrieben werden.** Es gibt dafür mindestens zwei voneinander unabhängige Gründe (§ 1.1, § 1.2). Daraus folgt zwingend, dass

- `fga model write` / `fga model test` nie gegen diese Dateien gelaufen ist,
- die vier `*_test.fga.yaml` **nie ausgeführt** wurden (bestätigt P6 aus dem Hauptreview),
- und `just validate-policy` (`go test ./shared/policy/...`) das Modell nicht anfasst.

Die Go-Dateien `shared/policy/{core,fleet,marketplace,registry}_model_test.go` tragen die Modellnamen im Dateinamen. Falls sie die Modellsemantik in Go nachbauen, ist das eine **fünfte** Duplikationsstelle (Modell in DSL + Modell in Go + Erwartungen in YAML + Erwartungen in Go). Bitte prüfen — wenn sie stattdessen die `.fga`-Dateien parsen und gegen die YAMLs auswerten, wäre das die richtige Lösung, aber dann müssten sie die Fehler aus § 1 gefunden haben.

Schweregrade wie im Hauptdokument: **S1** blockierend · **S2** Sicherheits-/Semantikfehler · **S3** strukturell.

---

## 1. S1 — Das Modell ist nicht ladbar

### 1.1 `type device` ist doppelt deklariert

```fga
# core.fga
type device                      # ohne Relationen

# marketplace.fga
type device
  relations
    define owner: [end_customer, marketplace, tenant]
    …
```

Ob als Konkatenation oder als modulares Modell: ein Typ darf genau einmal definiert werden. In modularen Modellen wäre `extend type device` erforderlich. So wie es dasteht, bricht `WriteAuthorizationModel` mit einer Duplicate-Type-Fehlermeldung ab.

Ursache ist ein Modellierungskonflikt, kein Tippfehler: In `core.fga` ist `device` als **Akteurstyp** gedacht (Subjekt), in `marketplace.fga` als **Ressource**. Beides in einem Typ ist möglich, aber dann muss es eine Deklaration sein.

### 1.2 `fga.mod` passt zu keinem der beiden Formate

```yaml
schema: '1.1'
contents: [core.fga, registry.fga, fleet.fga, marketplace.fga]
```

- Als **modulares Modell**: OpenFGA erwartet `schema: '1.2'` in der `fga.mod`, und jede Moduldatei beginnt mit `module <name>` — nicht mit `model` / `schema 1.1`. Hier hat `core.fga` einen vollständigen Modell-Header, die drei anderen Dateien haben **gar keinen** und starten direkt mit `type channel` bzw. `type marketplace`.
- Als **einfache Konkatenation**: Dann ist `fga.mod` bedeutungslos und es müsste einen Build-Schritt geben, der die Dateien in der genannten Reihenfolge zusammenfügt. Ein solcher Schritt existiert nicht (weder im `justfile` noch in `policygen`).

▸ *Zu verifizieren:* Welche `fga`-CLI-Version ist im Einsatz? Der Fix hängt davon ab, ob modulare Modelle genutzt werden sollen (dann: `schema: '1.2'` + `module`-Header + `extend type`) oder ein Single-File-Modell (dann: `fga.mod` löschen, Header nur einmal, Konkatenation im Generator).

### 1.3 Heterogener Tupleset mit fehlenden Zielrelationen

```fga
type device
  relations
    define owner: [end_customer, marketplace, tenant]
    define self_user: self from owner
    define manager_user: manager from owner
    define operator_user: operator from owner
```

| Arrow | `end_customer` | `marketplace` | `tenant` |
|---|---|---|---|
| `self from owner` | ✅ `self` | ❌ | ❌ |
| `manager from owner` | ✅ `manager` | ❌ | ❌ |
| `operator from owner` | ❌ | ✅ `operator` | ❌ |

Die Grundregel für Arrows lautet: **Die berechnete Relation muss auf *jedem* Typ der Tupleset-Zuordnung existieren.** Hier existiert keine der drei auf allen drei Typen.

Je nach OpenFGA-Version ist das entweder ein Validierungsfehler beim Modell-Schreiben oder eine stille Leermenge zur Auswertungszeit. Die **semantische** Konsequenz ist in beiden Fällen dieselbe und ist der eigentliche Befund:

> Ein Gerät, dessen `owner` ein `tenant` ist, hat **keine Viewer und keine Manager**. Weder Tenant-Owner noch Tenant-Admin noch Plattform-Support können es sehen. Es ist für alle unsichtbar.

Der Testfall deckt das nicht auf, weil er nur `end_customer`-Besitz prüft.

---

## 2. S1 — Go-Code und Modell teilen kein Typvokabular

Das ist der folgenschwerste Befund dieses Addendums, weil er unabhängig von § 1 besteht und auch nach dem Ladbarmachen sofort wieder zuschlägt.

### 2.1 Drei Namen für denselben Typ

| Modell | Go-Code schreibt | Datei |
|---|---|---|
| `tenant` | `organization:<id>` | `sync/jit.go`, `internal/fga/rebuild_test.go`, `celldir/migration_test.go`, `sync/deletion.go` |
| — | `group:<id>` | `scim/mapping.go` |

```go
// sync/jit.go — JIT-Provisionierung
objectURN := "organization:" + user.TenantID
baselineTuples := []authz.TupleKey{{User: userSubject, Relation: "member", Object: objectURN}}
```

```go
// scim/mapping.go — SCIM-Gruppensync
objectURN := fmt.Sprintf("group:%s", group.ID)
```

Weder `organization` noch `group` existieren im Modell. **Jeder Tupel-Write aus dem Sync-Pfad wird von OpenFGA abgelehnt.** Damit sind SYNC-06 (SCIM-Gruppen → Tupel) und SYNC-07 (JIT-Provisionierung) funktionslos — beide haben grüne Tests, weil die Tests gegen `mockFGATupleWriter` laufen und nur prüfen, *dass* geschrieben wurde, nicht *was*.

### 2.2 `device` ist niemals ein gültiges Subjekt

`authz.PrincipalToFGASubject` erzeugt für `ActorDevice` das Subjekt `device:<id>`. Im gesamten Modell akzeptiert **keine einzige Relation** `[device]` als Subjekttyp.

Konsequenz: Ein Gerät kann sich per mTLS authentifizieren (und bekommt sogar TrustLevel L3, siehe Hauptreview § 9.7), aber **jeder Autorisierungs-Check für ein Geräte-Subjekt liefert `false`**. Für eine OTA-Plattform, deren Kernakteur das Gerät ist, ist das eine vollständige Lücke.

Was fehlt, ist die Subjektseite: Relationen wie `device_group.member: [device]` oder `channel.subscriber: [device]`, über die ein Gerät seinen Update-Kanal lesen darf.

### 2.3 `can_manage` existiert auf den meisten Typen nicht

`authz/explain.go` hartkodiert die Selbstautorisierung des Aufrufers:

```go
adminReq := CheckRequest{ …, ObjectType: req.ObjectType, Permission: "can_manage", … }
```

`can_manage` ist im Modell nur auf `end_customer` und `device` (marketplace.fga) definiert. Für `tenant`, `channel`, `release`, `device_group`, `namespace`, `package` existiert die Relation nicht — OpenFGA antwortet mit einem Validierungsfehler, den `CheckPermission` als `err != nil` behandelt und zu `ErrForbiddenExplain` verdichtet.

**Der Explain-Endpunkt (AUTHZ-11) funktioniert damit für keinen der wichtigen Objekttypen.** Der Test nutzt `ObjectType: "document"` — einen Typ, den es im Modell gar nicht gibt — gegen einen Mock-Checker.

### 2.4 GitHub-Workload-Subjekt weicht ab

`principal.FormatGitHubWorkloadURN` ⇒ `toob:workload:github:acme/repo:deploy`, `ParseURN` setzt `ID = "acme/repo:deploy"`, `PrincipalToFGASubject` erzeugt also `workload:acme/repo:deploy`.

Der Testfall in `fleet_test.fga.yaml` schreibt `workload:github:acme/repo:deploy` — ein Segment mehr. Zusätzlich enthält die ID Doppelpunkte und Schrägstriche; OpenFGA trennt Typ und ID am **ersten** Doppelpunkt, das funktioniert, ist aber fragil und macht jede spätere Zerlegung mehrdeutig.

▸ **Querschnittliche Ursache:** Es gibt keine gemeinsame Quelle für Typ- und Relationsnamen. Genau hier hätte die Policy-Pipeline greifen müssen: `policygen` sollte aus den `.fga`-Dateien ein `shared/policy/fgatypes_gen.go` mit Konstanten erzeugen (`TypeTenant`, `RelMember`, `PermCanView`, …), und jede Tupel-Konstruktion im Go-Code müsste diese verwenden. Dann wären § 2.1–2.4 Compile-Fehler statt Laufzeitfehler.

---

## 3. S2 — Semantische Fehler im Modell

### 3.1 Plattform-Support ist ein unbefristeter Standing Grant

```fga
type platform
  relations
    define support: [user]

type tenant
  relations
    define platform: [platform]
    define support: support from platform
    define can_view: member or support
```

Jeder Nutzer mit `support` auf `platform:global` hat **dauerhaft, unbefristet und ohne Begründung Leserecht auf jeden Tenant**. Der Test schreibt dieses Verhalten als gewünscht fest:

```yaml
- name: Platform support staff read access on tenant
    - user: user:charlie, relation: can_view, object: tenant:tenant_acme, result: true
```

Das steht in direktem Widerspruch zu IDP-060/061 und zu § 10.2 der Zielarchitektur: Support-Zugriff muss zeitgebunden, begründungspflichtig, für den Kunden sichtbar und ohne Standing Grants sein. Hier ist er das genaue Gegenteil.

Verschärfend im Zusammenspiel mit dem Go-Code: `authz/check.go` ersetzt bei Impersonation das Subjekt durch den **Operator**-URN. Impersonation schränkt also nicht ein — sie ist der Mechanismus, über den das globale Leserecht des Operators zur Anwendung kommt. Modell und Code erzählen dieselbe, falsche Geschichte konsistent.

**Korrekte Form** — Support ausschließlich über eine befristete Condition:

```fga
type tenant
  relations
    define support_session: [operator with non_expired_grant]
    define can_view: member or support_session

condition non_expired_grant(current_time: timestamp, grant_time: timestamp, grant_duration: duration) {
  current_time < grant_time + grant_duration
}
```

Damit läuft der Zugriff ohne Aufräumjob aus, und `platform.support` als Dauerrelation entfällt.

### 3.2 Marktplatz und Fleet sind nicht verbunden

```fga
type marketplace   { define parent: [tenant]; define operator: [user] or admin from parent }
type device_group  { define parent: [tenant]; define operator: [user] or admin from parent }
```

Beide hängen an `tenant`, aber **nicht aneinander**. Ein direkt zugewiesener Marktplatz-Operator (`user:alice` im Test) ist kein Tenant-Admin und hat damit auf `device_group` **keinerlei Rechte** — weder aggregierte noch granulare Sicht, kein Deployment.

Das Kernszenario der Zielarchitektur („Marktplatzbetreiber verwaltet die Geräte seiner Endkunden") funktioniert nur über den separaten `device`-Typ aus `marketplace.fga`, nicht über die Fleet-Struktur. Es gibt also **zwei unverbundene Gerätewelten**: `device_group` (Fleet, tenant-gebunden) und `device` (Marketplace, endkundengebunden). Kein Pfad verbindet sie; `device` hat keine `group`-Relation.

Ebenso: `channel.parent: [tenant]` — ein Marktplatz kann **keine eigenen Release-Kanäle** haben. Das ist die zentrale Produktfunktion des B2B2C-Szenarios.

**Korrekte Form** — heterogene Eltern über eine auf allen Elterntypen vorhandene Permission auflösen:

```fga
type tenant       { … define can_administer: admin }
type marketplace  { … define can_administer: operator }

type device_group
  relations
    define parent: [tenant, marketplace]
    define operator: [user] or can_administer from parent

type channel
  relations
    define parent: [tenant, marketplace]
    define operator: [user] or can_administer from parent
```

Das ist zugleich die generelle Regel gegen § 1.3: **Bei heterogenen Tuplesets zeigt der Arrow auf eine Permission, die auf jedem Elterntyp definiert ist.**

### 3.3 Öffentliche Pakete kollidieren mit Store-per-Tenant

```fga
type package
  relations
    define public: [user:*, service_account:*]
    define can_view: viewer or public
```

Der Test verlangt:
```yaml
- user: user:external_user, relation: can_view, object: package:public_driver, result: true
```

Das ist nur wahr, wenn der Check **gegen den Store von Acme** läuft. `authz.CheckPermission` löst den Store aber aus `req.TenantID` bzw. `principal.OrgID` auf — also aus dem Tenant des **Aufrufers**. Ein Nutzer von Tenant B fragt gegen den Store von B und bekommt `false`, weil das Paket dort nicht existiert.

Das ist keine Modellschwäche im engeren Sinne, sondern eine **Kollision zweier Architekturentscheidungen**: ADR-4 (Store pro Tenant) und die öffentliche Package-Registry (global). Sie wurde bisher nirgends aufgelöst.

Drei mögliche Auflösungen, in absteigender Empfehlung:

1. **Öffentlichkeit außerhalb von FGA entscheiden.** Ein `packages.visibility = 'public'`-Flag in der Produkt-DB wird *vor* dem FGA-Check ausgewertet; FGA wird nur für nicht-öffentliche Pakete gefragt. Einfach, schnell, und die Sichtbarkeit ist ohnehin ein Attribut, keine Beziehung.
2. **Dedizierter globaler Store** für den öffentlichen Registry-Index, zusätzlich zum Tenant-Store. Zwei Checks pro Leseanfrage.
3. Store-per-Tenant für die Registry-Domäne aufgeben. Widerspricht ADR-4.

In jedem Fall gehört die Entscheidung in ein ADR — aktuell existiert ein Test, der eine Eigenschaft behauptet, die der Client nicht liefern kann.

### 3.4 CI kann nicht publizieren

```fga
type namespace { define publisher: [user, service_account] or admin }
type package   { define publisher: [user, service_account] or publisher from namespace }
```

`workload` fehlt in beiden Listen. `PrincipalToFGASubject` erzeugt für GitHub-Actions-Tokens aber `workload:<id>`. Ein CI-Publish-Check ist damit **immer `false`**.

Gleichzeitig ist `workload` genau an einer Stelle im Modell zugelassen — `release.author: [user, workload]` — und diese Relation wird von **keiner Permission** referenziert. Der einzige Ort, an dem `workload` vorkommt, ist tot; der Ort, an dem er gebraucht wird, kennt ihn nicht.

Das ist die Modellseite der Supply-Chain-Story: „CI darf bauen und nach dev publizieren, aber nicht nach production promoten." Die zweite Hälfte ist korrekt umgesetzt (§ 5.1), die erste gar nicht.

### 3.5 Vier-Augen-Prinzip existiert im Modell nicht — und sonst auch nicht

`channel.can_approve: release_manager` ist ein einzelnes Boolean. Ein Release-Manager, eine Freigabe.

ReBAC kann Schwellwerte grundsätzlich nicht ausdrücken — das ist kein Modellfehler, sondern korrekt so. Der Punkt ist: Die Zielarchitektur hatte das Vier-Augen-Prinzip deshalb bewusst **außerhalb** von FGA verortet (ADR-13: 2-of-N-Signatur), und dieser Teil wurde nie gebaut (Hauptreview § 6.1).

Ergebnis: `can_approve` ist derzeit die **gesamte** Freigabeautorisierung. Damit ist die Release-Governance im Modell schwächer als im alten `identity/approval`-Paket, das Dual-Control und ein Soak-Fenster hatte.

### 3.6 Der Plattform-Link ist tenant-seitig schreibbar

```fga
type tenant
  relations
    define platform: [platform]
```

`platform` ist eine **direkt zuweisbare** Relation auf `tenant`. Wer Tupel im Tenant-Store schreiben darf, kann den Tenant auf ein anderes `platform`-Objekt zeigen lassen und damit die Support-Menge austauschen. Im Store-per-Tenant-Modell ist der Radius begrenzt, aber die Richtung stimmt nicht: Ein Tenant sollte die Plattform, unter der er hängt, nicht selbst bestimmen können.

Da `platform` faktisch ein Singleton ist (`platform:global`), gehört der Link entweder in eine Contextual Tuple (vom Enforcement gesetzt, nicht persistiert) oder das Tupel muss beim Bootstrap geschrieben und danach durch Schreibrechte geschützt werden. Aktuell gibt es weder das eine noch das andere.

---

## 4. S3 — Strukturelle Schwächen

### 4.1 Keine Rekursion — die versprochene Erweiterbarkeit besteht nicht

Die Zielarchitektur (§ 5.1) sagte zu: „Die Tiefe ist nicht auf diese vier Ebenen begrenzt. `parent`-Relationen sind rekursiv modelliert; eine fünfte Ebene ist ein Modell-Additiv, kein Umbau."

Im Modell ist jede Ebene **fest an einen konkreten Elterntyp gebunden**: `marketplace.parent: [tenant]`, `end_customer.marketplace: [marketplace]`, `device.owner: [end_customer, marketplace, tenant]`. Es gibt keine einzige rekursive Relation (`parent: [gleicher Typ]`).

Das Einfügen eines Distributors zwischen Marktplatz und Endkunde erfordert Änderungen an `end_customer.marketplace`, `end_customer.manager`, allen drei `*_user`-Relationen auf `device` und an jeder darauf aufbauenden Permission. Das ist genau der Umbau, den die Architektur ausgeschlossen hatte.

**Korrekte Form** — ein rekursiver Hierarchieknoten:

```fga
type org_node
  relations
    define parent: [org_node]
    define admin:  [user] or admin from parent
    define member: [user, service_account] or admin or member from parent
    define can_administer: admin
```
Tenant, Marketplace, Distributor und weitere Ebenen sind dann Instanzen desselben Typs; die Ressourcentypen hängen einheitlich an `parent: [org_node]`. Neue Ebenen sind reine Tupel — ohne jede Modelländerung.

### 4.2 Tote Relationen

| Typ | Relation | Referenziert von |
|---|---|---|
| `platform` | `staff` | nichts |
| `platform` | `security_admin` | nichts |
| `release` | `author` | nichts |
| `namespace` | `can_create_package` | keiner Permission-Katalogeintrag erkennbar [prüfen] |

`staff` und `security_admin` sind besonders auffällig: Sie waren in der Zielarchitektur die Träger der Plattform-Administration; jetzt existieren sie als Deklaration ohne Wirkung — dasselbe Muster wie `RequiredProductRole` im Go-Code (Hauptreview § 6.3).

### 4.3 Zwischenrelationen ohne Nutzen

```fga
define self_user:     self from owner
define manager_user:  manager from owner
define operator_user: operator from owner
define can_view: self_user or manager_user or operator_user
```

Die drei Zwischenrelationen tragen keine Semantik, verdoppeln die Traversierungstiefe und lesen sich wie zuweisbare Relationen (kein Typ-Suffix macht sichtbar, dass sie berechnet sind). Direkt in der Permission ist kürzer und schneller:

```fga
define can_view: can_view from owner
```
— nach Vereinheitlichung des Elterntyps gemäß § 3.2.

### 4.4 Keine Conditions definiert, obwohl der Code sie schreibt

`authz/breakglass.go` erzeugt Grants mit

```go
ConditionName: "is_active_breakglass",
ConditionParams: map[string]interface{}{ "current_time": …, "expires_at": … },
```

Im Modell ist **keine einzige `condition`** definiert. OpenFGA lehnt ein Tupel mit unbekannter Condition beim Schreiben ab. Der Break-Glass-Grant ist damit nicht nur unverdrahtet (Hauptreview § 5.4), er wäre auch nicht schreibbar.

Ebenso fehlen die in § 6.3 der Zielarchitektur vorgesehenen Conditions für befristete Grants und Regionsbindung.

### 4.5 Namenskollision `support`

`tenant.support` (berechnet) und `platform.support` (direkt) heißen gleich und stehen in derselben Zeile:

```fga
define support: support from platform
```

Das liest sich beim Überfliegen selbstreferenziell. `platform_support` auf dem Tenant oder `support_staff` auf der Plattform würde die Zeile eindeutig machen.

### 4.6 Fehlende Typen gegenüber dem Katalog

Aus dem Domänen-Mapping in `policygen`'s Markdown-Generator sind Katalogpräfixe erkennbar, für die es **keine Modellrelation** gibt:

| Katalogpräfix | Modellentsprechung |
|---|---|
| `admin.role.*` | keine — Rollenverwaltung ist nicht modelliert |
| `admin.*` (Impersonation, Audit) | keine |
| `release.*` (Emergency Controls) | nur `can_approve` |
| `registry.*` (package_version) | `package_version` fehlt als Typ |

Ein Abgleich Katalog ↔ Modell existiert nicht. Genau das wäre die Aufgabe des POL-06-Linters: *jede* Permission im Katalog muss auf eine im Modell vorhandene `(resource, relation)`-Kombination zeigen, und jede Modell-Permission sollte einen Katalogeintrag haben.

---

## 5. Was gut ist

Vier Dinge sind im Modell richtig gelöst und sollten beim Umbau erhalten bleiben:

### 5.1 CI-Produktionssperre im Typsystem ✅

```fga
define release_manager: [user]
define can_approve: release_manager
```

`can_approve` erbt **nicht** von `admin from parent` und akzeptiert nur `[user]`. Ein `workload` kann die Relation auf keinem Pfad erlangen — die Regel ist strukturell, nicht per Laufzeitprüfung. Genau ADR-15. Der Test beweist es explizit:

```yaml
- name: Machine Workload CANNOT approve release (type constraint test)
    result: false
```

Das ist die sauberste Stelle im gesamten Policy-Bereich.

### 5.2 Delegierte Administration am Marktplatz ✅

```fga
type end_customer
  relations
    define manager: operator from marketplace
```

Ein Marktplatz-Operator verwaltet automatisch auch Endkunden, die **nach** der Rechtevergabe angelegt werden. Der Test prüft genau diese Eigenschaft mit zwei Endkunden. Das ist die Kernanforderung aus § 5.3 der Zielarchitektur und korrekt umgesetzt.

### 5.3 Aggregat/Granular-Trennung ✅

```fga
define can_view_aggregate: viewer
define can_view_granular:  operator
```

Zwei getrennte Permissions statt eines Flags — richtig. Der Test prüft, dass ein Service-Account die aggregierte, nicht aber die granulare Sicht hat. (Dass kein Go-Code diese Permissions liest, ist ein Problem des Enforcements, nicht des Modells.)

### 5.4 Registry-Vererbungskette ✅

`tenant.owner → tenant.admin → namespace.admin → package.owner → can_delete` ist durchgängig und ohne Sprünge. Arrows zeigen auf Permissions bzw. auf direkt zuweisbare Relationen. Der Test prüft auch die Gegenrichtung (`user:alice` kann *nicht* löschen).

---

## 6. Testabdeckung des Modells

17 Checks in vier Dateien. Was geprüft wird, ist überwiegend sinnvoll (jeweils mit Negativfall). Was fehlt, ist die wichtigere Hälfte:

| Fehlende Prüfung | Hätte gefunden |
|---|---|
| Marktplatz-Operator auf `device_group` | § 3.2 (getrennte Gerätewelten) |
| `workload` auf `package.can_publish` | § 3.4 (CI kann nicht publizieren) |
| Gerät als Subjekt (`device:x can_view …`) | § 2.2 (Geräte nie autorisierbar) |
| `device` mit `owner: tenant:…` | § 1.3 (unsichtbares Gerät) |
| `can_manage` auf `tenant` / `channel` | § 2.3 (Explain unbrauchbar) |
| Tenant-übergreifender Check | Die zentrale Isolationsaussage — derzeit vollständig ungetestet |
| Substitution von `platform:global` | § 3.6 |

Zum letzten Punkt: Wenn Tenant-Isolation im Store-per-Tenant-Modell außerhalb des Modells liegt, gehört das als Kommentar in die Testdatei — sonst liest es sich wie eine Lücke.

Zusätzlich: Die Testdateien enthalten keine `model_file:`-Angabe. Die FGA-CLI erwartet in der Test-YAML entweder `model_file: ../model/fga.mod` oder einen Inline-`model:`-Block. Ohne das lässt sich `fga model test` gar nicht ausführen — ein weiteres Indiz für § 0.

---

## 7. Korrekturplan

Reihenfolge so, dass jeder Schritt den nächsten ermöglicht.

**Zuerst — ladbar machen und in CI verankern**

1. `type device` entwirren: In `core.fga` entfernen (`device` ist Ressource, nicht Akteur). Ressourcendefinition nach `fleet.fga`, wo auch `device_group` liegt.
2. `fga.mod` und Datei-Header auf ein Format bringen. Empfehlung: **einfaches Single-File-Modell** — `fga.mod` löschen, `policygen` konkateniert `core → registry → fleet → marketplace` zu einem `policy/model/model.fga`. Modulare Modelle lohnen sich erst bei mehreren Teams.
3. Heterogene Tuplesets auflösen (§ 3.2-Muster: `can_administer` auf jedem Elterntyp).
4. `model_file:` in allen vier Test-YAMLs ergänzen.
5. **`just validate-policy` erweitern:**
   ```
   fga model test --tests policy/tests/core_test.fga.yaml
   fga model test --tests policy/tests/registry_test.fga.yaml
   fga model test --tests policy/tests/fleet_test.fga.yaml
   fga model test --tests policy/tests/marketplace_test.fga.yaml
   go test ./shared/policy/...
   ```
   Ohne Schritt 5 wiederholt sich § 0 beim nächsten Mal.

**Dann — Vokabular erzwingen**

6. `policygen` erweitern: Typ-, Relations- und Permissionnamen aus dem Modell parsen und nach `shared/policy/fgatypes_gen.go` als Konstanten schreiben.
7. Alle Tupel-Konstruktionen im Go-Code auf diese Konstanten umstellen: `sync/jit.go`, `scim/mapping.go`, `internal/fga/*`, `celldir/migration.go`, `authz/explain.go`. Danach sind § 2.1–2.4 Compile-Fehler.
8. POL-06-Linter um den Katalog↔Modell-Abgleich erweitern (§ 4.6).

**Dann — Semantik korrigieren**

9. `platform.support` durch `tenant.support_session` mit Zeit-Condition ersetzen; `non_expired_grant` und `is_active_breakglass` als Conditions definieren (§ 3.1, § 4.4).
10. `workload` in `namespace.publisher` und `package.publisher` aufnehmen; `release.author` entweder an eine Permission anbinden oder entfernen (§ 3.4, § 4.2).
11. `channel.parent` und `device_group.parent` um `marketplace` erweitern; `device` mit `group: [device_group]` an die Fleet-Struktur anbinden (§ 3.2).
12. `device` als **Subjekt** zulassen, wo Geräte lesen dürfen (z. B. `channel.subscriber: [device]`) (§ 2.2).
13. Entscheidung zu öffentlichen Paketen treffen und als ADR festhalten (§ 3.3). Empfehlung: Sichtbarkeit vor dem FGA-Check in der Produkt-DB auflösen.
14. `platform`-Link auf Tenant als Contextual Tuple setzen statt persistieren (§ 3.6).

**Später — Erweiterbarkeit tatsächlich herstellen**

15. Auf rekursive Hierarchie umstellen (§ 4.1). Das ist der Schritt, der das Versprechen „neue Ebene = nur Tupel" einlöst. Solange er aussteht, ist die Aussage aus der Zielarchitektur zu Erweiterungsszenario 6 („fünfte Hierarchieebene, kein Code-Deploy") nicht gedeckt.
16. Zwischenrelationen auf `device` durch direkte Arrows ersetzen (§ 4.3).
17. Fehlende Testfälle aus § 6 ergänzen, insbesondere den Negativfall für Geräte-Sichtbarkeit und den Kommentar zur Tenant-Isolation.

---

## 8. Konsequenz für den Hauptbericht

Die Statuszeile im Hauptreview ändert sich:

| Ticket | vorher | jetzt |
|---|---|---|
| AUTHZ-02…05 Modelle | ❓ | 🔴 — Modell nicht ladbar, Vokabular unverbunden, drei semantische Kernlücken |
| P6 (werden die `.fga.yaml` ausgeführt?) | offen | **beantwortet: nein** |

Und die Prioritätenliste bekommt zwei neue Positionen weit oben, weil sie den Weg zu Gate B blockieren:

- **Neu vor Position 11:** Modell ladbar machen und `fga model test` in `just validate-policy` aufnehmen (§ 7.1–7.5).
- **Neu direkt danach:** Typkonstanten generieren und alle Tupel-Writes darauf umstellen (§ 7.6–7.7).

Der vertikale Durchstich aus Gate B ist ohne beides nicht erreichbar: Ein einziger echter FGA-Check gegen einen echten Store scheitert derzeit bereits beim Laden des Modells.