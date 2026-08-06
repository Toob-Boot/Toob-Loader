# Toob Identity — Umbau-Backlog

**Version:** 1.0
**Bezug:** „Toob Identity Layer — Architekturdokumentation" (Ist) und „Toob Identity & Authorization — Zielarchitektur" (Soll, v1.0)
**Randbedingungen:** Kein Produktivsystem. Keine Migrationszwänge, keine Bestandsnutzer, keine Rückwärtskompatibilität. Zitadel bleibt gesetzt.

---

## 0. Wie dieser Backlog zu lesen ist

### 0.1 Ticketformat

```
#### CODE-NN · Titel · Größe · ⟵ Abhängigkeiten
Problem  — warum das Ticket existiert
Umfang   — was konkret gebaut wird
Fertig wenn — prüfbare Akzeptanzkriterien
```

**Größen:** `S` ≤ 2 Tage · `M` ≤ 1 Woche · `L` ≤ 2–3 Wochen · `XL` aufteilen, bevor es startet.
**⟵** listet blockierende Vorgänger. Kein Eintrag = sofort startbar.

### 0.2 Globale Definition of Done

Gilt für **jedes** Ticket. Wird in der Review geprüft, nicht im Ticket wiederholt.

- [ ] Kein sicherheitsrelevanter Zustand im Prozessspeicher (P5).
- [ ] Alle Zeitabhängigkeiten über `shared/x/clock`, nie `time.Now()` direkt in Logik.
- [ ] Fehler folgen der Taxonomie aus `shared/errors` (RFC-9457-Problem-Details, stabile Error-Codes).
- [ ] Positiv- **und** Negativtest vorhanden. Sicherheitsregeln zusätzlich mit Reihenfolgen-Assertion (Mock-Aufrufzahl), nicht nur Rückgabewert.
- [ ] Import-Boundary-Test (`shared/boundaries_test.go`) grün.
- [ ] Neue oder geänderte Metriken registriert, SLO-relevante in `platform/deploy/monitoring/prometheus/rules/identity.yml`.
- [ ] Betriebsrelevantes Verhalten hat ein Runbook unter `docs/runbooks/`.
- [ ] Architekturrelevante Abweichung vom Zielbild ist als ADR unter `docs/adr/` festgehalten.
- [ ] Keine handgepflegte Regel, die auch generiert werden könnte (P2).
- [ ] Degradationsverhalten entspricht der Ausfallmatrix (Zielarchitektur § 14) und ist getestet.

### 0.3 Wellen und Gates

```
Welle 0  Fundament & Zustand      ── parallel startbar, blockiert alles Weitere
   │
  GATE A · Policy-Quelle steht: eine Permission ist deklariert, generiert und im Code nutzbar
   │
Welle 1  Policy + AuthZ + Zitadel ── vertikaler Durchstich
   │
  GATE B · Walking Skeleton: ein echter Endpunkt läuft Ende-zu-Ende über Stage 1 + FGA
   │
Welle 2  Enforcement + Sync + Zellen
   │
  GATE C · Eine Zelle ist reproduzierbar aus Terraform + Bootstrap erzeugbar
   │
Welle 3  Release-Governance, Audit, Device-Identity, Profile P2/P3
   │
  GATE D · Ausfallmatrix vollständig getestet, SLOs gemessen
   │
Welle 4  Rückbau & Lasttests
```

Die Gates sind Freigabepunkte, keine Termine. Ein Gate ist offen, wenn seine Kriterien nachweisbar erfüllt sind — nicht, wenn alle Tickets der Welle geschlossen sind.

### 0.4 Nachträgliche Ergänzungen zur Zielarchitektur

Beim Durchplanen sind dreizehn Punkte aufgefallen, die in der Zielarchitektur v1.0 fehlen oder zu vage waren. Sie sind unten als reguläre Tickets eingearbeitet; hier die Übersicht, damit die Architekturänderung sichtbar bleibt:

| # | Ergänzung | Ticket | Warum |
|---|---|---|---|
| 1 | **Shadow-Mode für Policy-Änderungen** | AUTHZ-10 | Modellwechsel parallel evaluieren und Abweichungen loggen, ohne durchzusetzen. Ohne das ist jede Modelländerung ein Blindflug. |
| 2 | **Explain-/Debug-Endpunkt** | AUTHZ-11 | „Warum darf mein Nutzer das nicht?" ist die häufigste Support-Frage bei ReBAC. Ohne Antwort wird der Support blind. |
| 3 | **Tupel-Rebuild-Werkzeug** | AUTHZ-12 | Disaster Recovery und Drift-Heilung. Ein Relationsgraph ohne Wiederaufbaupfad ist ein Single Point of Failure. |
| 4 | **Break-Glass als Erstklassenkonzept** | AUTHZ-13 | Heute nur eine JS-Action mit Alarm. Im Zielmodell: befristete Condition, Zwei-Personen-Aktivierung, Auto-Ablauf. |
| 5 | **Zell-Bootstrap (Henne-Ei)** | CELL-04 | Wer legt den ersten Owner an, wenn Autorisierung Tupel braucht und Tupel einen Owner? Klassisch vergessen. |
| 6 | **Clock-Injection** | FND-03 | Der Ist-Stand hat bereits einen Test, der nichts prüft, weil Zeit nicht vorspulbar ist. |
| 7 | **Fehler-Taxonomie (RFC 9457)** | FND-04 | Heute uneinheitliche JSON-Fehler. Clients brauchen maschinenlesbare, stabile Codes — besonders für Step-Up. |
| 8 | **Lokale Entwicklungsumgebung** | FND-05 | Zitadel + FGA + Postgres + Valkey lokal. Ohne das wird jede Änderung ein Integrationsritt. |
| 9 | **Idempotency-Keys für Mutationen** | FND-06 | Org-Erstellung, Einladungen, Tupel-Writes brauchen Wiederholsicherheit. |
| 10 | **Contract-Tests gegen Zitadel** | ZIT-09 | Zitadel-Upgrades brechen sonst still. Bei einem gesetzten IdP ist das die wichtigste Regressionsbremse. |
| 11 | **Mehrstufiges, kostenbasiertes Rate-Limiting** | STATE-02 | Heute nur Login-Fehlversuche. `ListObjects` und Batch-Checks sind teuer und brauchen eigene Budgets. |
| 12 | **DSGVO-Löschpfad** | SYNC-08 | Löschung über Zitadel, FGA, Mirror und Audit hinweg — mit Pseudonymisierung statt Löschung im Audit. |
| 13 | **Walking Skeleton als eigenes Ticket** | GATE-B01 | Ein vertikaler Durchstich vor der Breite verhindert, dass drei Schichten unabhängig „fertig" werden und nicht zusammenpassen. |

---

## 1. Welle 0 — Fundament

### FND · Querschnittliche Grundlagen

#### FND-01 · `identity/principal` als unterste Schicht · S
**Problem** Heute importiert `tenant` das HTTP-Package `middleware`, nur um an einen Context-Key zu kommen. Die Abhängigkeitsrichtung zeigt nach oben.
**Umfang** Neues Package ohne Abhängigkeiten außer stdlib: `Principal` (Subject-URN, Typ, OrgID, TrustLevel, ActURN, AuthTime, ExpiresAt), URN-Parser/Builder für alle sechs Akteursformen, `TrustLevel` mit `Rank() int`, Context-Key und Getter/Setter.
**Fertig wenn**
- [ ] `principal` importiert kein anderes Toob-Package.
- [ ] URN-Roundtrip für alle Akteurstypen getestet, inklusive Fehlerfälle bei Fremdformaten.
- [ ] `TrustLevel.Rank()` ist die einzige Ordnungsrelation im Repo; String-Vergleiche auf TrustLevel sind per Lint verboten.

#### FND-02 · Import-Boundary-Test erweitern · S · ⟵ FND-01
**Problem** `shared/boundaries_test.go` existiert, deckt die neue Schichtung aber nicht ab.
**Umfang** Regelwerk als Daten (erlaubte Kanten), Test scheitert bei jeder neuen unerlaubten Kante. Verbotene Kanten: alles → HTTP-Transport, `identity/*` → `identity/internal/*`, `identity/*` → `registry|update|platform`, `shared/*` → alles außer `shared/*`.
**Fertig wenn**
- [ ] Regelwerk ist deklarativ und ohne Testcode-Änderung erweiterbar.
- [ ] Ein absichtlich eingefügter Verstoß lässt den Test fehlschlagen (Meta-Test).

#### FND-03 · `shared/x/clock` · S
**Umfang** `Clock`-Interface (`Now`, `Since`, `After`, `NewTicker`), `SystemClock`, `FakeClock` mit `Advance`. Alle zeitabhängigen Komponenten nehmen eine Clock im Konstruktor.
**Fertig wenn**
- [ ] Kein `time.Now()` in `identity/**` außerhalb von `SystemClock` (Lint-Regel).
- [ ] Mindestens ein bisher nicht prüfbarer Zeittest (Mirror-Lag-Alarm, Soak-Window, DPoP-Fenster, Session-TTL) prüft jetzt tatsächlich.

#### FND-04 · Fehler-Taxonomie und Problem Details · M
**Problem** Heute uneinheitliche Fehlerobjekte (`{error, message}`, `TenantMismatchResponse`, `FleetSecurityResponse`, `StepUpResponse`). Clients können nicht generisch reagieren.
**Umfang** Ein Fehlermodell in `shared/errors`: RFC-9457-Problem-Details mit stabilem `type`-URI, `code`, `status`, optionalen Erweiterungsfeldern. Vordefinierte Codes für alle Ablehnungsgründe (`step_up_required`, `insufficient_trust_level`, `tenant_mismatch`, `permission_denied`, `impersonation_forbidden`, `revoked`, `rate_limited`, …). Helper für `WWW-Authenticate` nach RFC 9470.
**Fertig wenn**
- [ ] Jeder Ablehnungspfad im Identity-Layer liefert ein Problem-Details-Objekt.
- [ ] Error-Codes sind aus dem Permission-Katalog bzw. einer Konstantenliste generiert, nicht als Stringliteral verstreut.
- [ ] Ein Client-Contract-Test prüft: gleicher Fehler ⇒ gleicher `code` über alle Endpunkte.

#### FND-05 · Lokale Entwicklungsumgebung · M
**Umfang** `just dev-identity` startet Zitadel v4, OpenFGA, Postgres, Valkey lokal; Seed-Skript legt Instanz, zwei Tenants, einen Marktplatz, Rollen, FGA-Stores und Testnutzer an; Helper zum Ausstellen realistischer Tokens für jeden Akteurstyp.
**Fertig wenn**
- [ ] Vom frischen Checkout bis zum ersten authentifizierten Request < 5 Minuten.
- [ ] Der Seed ist idempotent und wird auch von der Integrationstest-Harness verwendet (kein zweiter Seed-Pfad).

#### FND-06 · Idempotency-Keys für Mutationen · M · ⟵ FND-04
**Umfang** `Idempotency-Key`-Header, Speicherung von Schlüssel + Anfrage-Hash + Antwort in Postgres mit TTL, Wiedergabe identischer Antworten, Konflikt bei gleichem Schlüssel und abweichendem Body.
**Fertig wenn**
- [ ] Doppelte Org-Erstellung mit identischem Schlüssel erzeugt genau eine Org und zweimal dieselbe Antwort.
- [ ] Gleicher Schlüssel mit anderem Body ⇒ definierter Konfliktfehler.

#### FND-07 · Repo-Layout: Identity wird vollwertiger Layer · S
**Umfang** Umstellung auf die Struktur aus Abschnitt 8: `identity/cmd`, `identity/internal`, `identity/migrations`, `identity/deploy`, `identity/test` analog zu `registry/` und `update/`. Rein mechanisch, aber vor allem anderen, damit spätere Tickets nicht zweimal verschieben.
**Fertig wenn**
- [ ] Struktur entspricht Abschnitt 8; `go build ./...` und alle Tests grün.
- [ ] `justfile` und CI-Pfade angepasst.

---

### STATE · Zustand aus dem Prozessspeicher

Dies ist der sicherheitskritischste Block. Solange er offen ist, sind mehrere Schutzmechanismen nominell vorhanden, aber im Mehrinstanzbetrieb wirkungslos.

#### STATE-01 · Session- und Token-Familien nach Postgres · L · ⟵ FND-03
**Problem** Refresh-Token-Familien liegen in einer Prozess-Map. Reuse-Detection greift bei zwei Instanzen nicht — der Schutz sieht vorhanden aus, existiert aber nicht.
**Umfang** Tabellen `token_families` und `consumed_tokens` (Hash, konsumiert-am), Rotation als **eine** Transaktion mit `SELECT … FOR UPDATE` bzw. Unique-Constraint-basierter Race-Absicherung, Familien-Revocation atomar, TTL-basiertes Aufräumen konsumierter Hashes und abgelaufener Familien.
**Fertig wenn**
- [ ] Zwei parallele Rotationen mit demselben Token führen zu genau einer erfolgreichen Rotation und einer Familien-Revocation (nebenläufiger Test, nicht sequenziell).
- [ ] Reuse-Detection funktioniert über zwei Prozesse hinweg (Integrationstest mit zwei Instanzen).
- [ ] Aufräumjob vorhanden; die Tabellen wachsen nicht unbegrenzt.

#### STATE-02 · Mehrstufiges Rate-Limiting auf Valkey · M · ⟵ FND-03, FND-04
**Problem** Heute nur Login-Fehlversuche, prozesslokal. Teure Endpunkte (`ListObjects`, BatchCheck, Suche) haben kein Budget.
**Umfang** Vier Dimensionen mit eigenen Budgets: Login-Fehlversuche pro Konto (progressives Delay, kein Lockout — Verhalten von heute erhalten), API-Requests pro Token, pro Tenant, pro Quell-IP; zusätzlich **kostenbasiertes** Budget, bei dem teure Permissions mehr Einheiten kosten (Gewicht aus dem Permission-Katalog). Implementierung als Sliding-Window oder Token-Bucket in Valkey, Fail-open bei Valkey-Ausfall (bewusst, siehe Ausfallmatrix).
**Fertig wenn**
- [ ] Progressives Delay und Alarmschwellen (10/100/1000) verhalten sich identisch zu heute, aber instanzübergreifend.
- [ ] Kosten pro Permission kommen aus dem generierten Katalog, nicht aus einer zweiten Tabelle.
- [ ] Valkey-Ausfall degradiert Rate-Limiting, blockiert aber keine Requests.

#### STATE-03 · Kill-Switch- und Revocation-Cache · M · ⟵ FND-03
**Umfang** Autoritative Liste widerrufener Subjekte/Sessions/Geräte in Postgres, Verteilung über Valkey Pub/Sub, prozesslokaler Cache mit Generationszähler und periodischem Full-Resync als Selbstheilung. Prüfung in Stage 1 ohne Netzwerk-Roundtrip.
**Fertig wenn**
- [ ] Zeit vom Widerruf bis zur Wirksamkeit auf allen Instanzen < 5 s (gemessen, nicht behauptet).
- [ ] Nach Neustart einer Instanz ist der Cache vor dem ersten bedienten Request vollständig — sonst startet der Prozess nicht (fail-closed beim Start).
- [ ] Verlust einer Pub/Sub-Nachricht wird durch den Resync korrigiert (Test mit unterdrückter Nachricht).

#### STATE-04 · DPoP-`jti`-Replay-Store · S · ⟵ STATE-03
**Umfang** Kurzlebiger Replay-Speicher (Valkey, TTL = Proof-Fenster + Toleranz) auf derselben Infrastruktur wie STATE-03.
**Fertig wenn**
- [ ] Zweite Verwendung derselben `jti` innerhalb des Fensters wird abgelehnt, instanzübergreifend.

#### STATE-05 · Event-Deduplizierung mit TTL · S
**Problem** `mirror.dedupCache` ist eine Map ohne Eviction — unbegrenztes Wachstum und nur instanzlokal.
**Umfang** Dedup-Tabelle mit Unique-Constraint auf Event-ID und TTL-Aufräumung; Idempotenz kommt aus dem Constraint, nicht aus einem Lookup-dann-Insert (das ist eine Race).
**Fertig wenn**
- [ ] Paralleles Zustellen desselben Events auf zwei Instanzen verarbeitet es genau einmal.
- [ ] Aufräumjob vorhanden und überwacht.

#### STATE-06 · Impersonation über Token Exchange · M · ⟵ ZIT-06
**Umfang** Ablösung der In-Memory-`Manager`-Sessions: Impersonation wird zu einem ausgetauschten Token mit `act`-Claim; Sitzungsmetadaten (Begründung, Ziel-Org, Ablauf, Benachrichtigungsstatus) in Postgres; Owner-Benachrichtigung über den Outbox-Pfad.
**Fertig wenn**
- [ ] Kein Impersonationszustand im Prozessspeicher.
- [ ] `act`-Claim erscheint in Token, Audit-Eintrag und Fehlermeldungen.
- [ ] Ablauf ist kryptografisch (Token-Lebensdauer), nicht nur ein Datenbankfeld.

#### STATE-07 · Freigabezustand persistieren · M · ⟵ FND-03
**Umfang** Zwischenschritt vor dem Signatur-Workflow: Freigaben, Approver, Soak-Fenster und Abbrüche in Postgres, damit ein Deploy während eines laufenden Soak-Fensters nichts verliert. Autorisierungsprüfung für `CancelRelease` ergänzen (fehlt heute vollständig).
**Fertig wenn**
- [ ] Neustart während eines Soak-Fensters ändert nichts am Freigabestatus.
- [ ] Abbruch durch einen Nicht-Owner wird abgelehnt und auditiert.

---

## 2. Welle 1 — Policy, Autorisierung, Zitadel

### POL · Policy-Pipeline

#### POL-01 · Policy-Verzeichnis und Schemata · M
**Umfang** `policy/` mit JSON-Schema für `actors.yaml`, `permissions.yaml`, `sensitivity.yaml` und `rules/*.yaml`; Validierung in CI; README, das erklärt, wie ein Eintrag hinzugefügt wird.
**Fertig wenn**
- [ ] Schema-Verstoß bricht CI mit verständlicher Meldung.
- [ ] Ein Beispiel-Pull-Request „neue Permission hinzufügen" ist dokumentiert und ohne Go-Kenntnisse nachvollziehbar.

#### POL-02 · Permission-Katalog vollständig erfassen · L · ⟵ POL-01
**Umfang** Jede heute existierende und jede aus der Zielarchitektur absehbare Berechtigung als Katalogeintrag: `id`, `resource`, `relation`, `min_trust_level`, `step_up`, `step_up_max_age`, `sensitivity`, `audit`, `cost`, `impersonation_allowed`, `requires_signature`, Beschreibung. Ableitung aus der bestehenden `RouteSecurityPolicy`-Registry, den 14 JS-Actions und dem Registry-/Fleet-Handlerbestand.
**Fertig wenn**
- [ ] Jeder heutige Endpunkt der Registry- und Fleet-API hat genau einen Katalogeintrag.
- [ ] Jede Permission hat eine Beschreibung, die ein Kunde versteht (der Katalog ist auch Kundendokumentation).
- [ ] Review durch zwei Personen, davon eine ohne Vorkenntnis der Altimplementierung.

#### POL-03 · Generator `identity/cmd/policygen` · L · ⟵ POL-02
**Umfang** Erzeugt nach `shared/policy/`: Permission-Konstanten, Endpoint-Registry, Stage-1-Gate-Konfiguration, Audit-Klassifikation, Rate-Limit-Kosten, Impersonationsregeln. Deterministische Ausgabe, `//go:generate`, generierte Dateien eingecheckt und in CI auf Aktualität geprüft.
**Fertig wenn**
- [ ] `go generate ./...` erzeugt bit-identische Ausgabe bei unverändertem Input.
- [ ] CI schlägt fehl, wenn generierte Dateien vom Input abweichen.
- [ ] Generierte Dateien tragen einen Kopfkommentar „nicht editieren" und sind vom Linter ausgenommen.

#### POL-04 · Regel-Generierung für IdP-Regeln · M · ⟵ POL-03
**Umfang** Validatoren für Org-Namen, Einladungsregeln, Faktor-Policy, Rollen-Elevation, Impersonationsgrenzen aus `policy/rules/*.yaml` nach Go generieren. Diese Validatoren sind später die Implementierung der Actions-v2-Targets.
**Fertig wenn**
- [ ] Die heute divergierende Org-Namensregel existiert genau einmal (Länge, Zeichensatz, Doppelbindestriche, Reserved Names) und ist gegen einen gemeinsamen Fixture-Satz getestet.
- [ ] Kein Validator ist handgeschrieben.

#### POL-05 · Vollständigkeitsprüfung zur Buildzeit · M · ⟵ POL-03
**Problem** Heute schlägt ein Endpunkt ohne Policy erst zur Laufzeit mit HTTP 500 fehl.
**Umfang** Handler deklarieren ihre Permission (Protobuf-Option bei Connect, Registrierung bei HTTP). Ein Prüfer vergleicht die Routen-Definition mit dem Katalog. Fehlend, unbekannt oder mehrdeutig ⇒ CI-Fehler. Die Laufzeitprüfung bleibt als Defense in Depth.
**Fertig wenn**
- [ ] Ein absichtlich undeklarierter Endpunkt bricht den Build (Meta-Test).
- [ ] Die Laufzeitprüfung feuert in der gesamten Testsuite kein einziges Mal.

#### POL-06 · Policy-Linter · M · ⟵ POL-02, AUTHZ-02
**Umfang** Prüft das FGA-Modell und den Katalog: Arrows zeigen auf Permissions statt auf Relationen; keine Rollennamen mit eingebautem Kontext; jede Permission hat mindestens einen Positiv- und einen Negativtest; jede Relation ist von mindestens einer Permission erreichbar (keine toten Relationen); Typ-Constraints sind explizit.
**Fertig wenn**
- [ ] Alle sechs Regeln implementiert, jede mit einem Meta-Test, der einen Verstoß erkennt.
- [ ] Linter läuft in CI vor dem Modell-Rollout.

#### POL-07 · Generierte Berechtigungsmatrix · S · ⟵ POL-03
**Umfang** `docs/permissions.md` aus dem Katalog erzeugen: Permission × Rolle × Trust-Level, gruppiert nach Domäne. Dient als Kundendokumentation und Audit-Nachweis.
**Fertig wenn**
- [ ] Dokument ist generiert, nicht gepflegt, und in CI aktuell gehalten.

---

### AUTHZ · Autorisierungs-Engine

#### AUTHZ-01 · OpenFGA-Betrieb · M
**Umfang** Nomad-Job, eigene Postgres-Datenbank, Schema-Migrationen im Deploy-Pfad, Secrets über Vault, Health- und Readiness-Checks, Ressourcenlimits, Ansible-Rolle. Co-Lokation mit App und Datenbank in derselben Zelle.
**Fertig wenn**
- [ ] FGA läuft in der lokalen Entwicklungsumgebung und in der Dev-Zelle identisch konfiguriert.
- [ ] Ausfall und Neustart sind runbook-dokumentiert.
- [ ] Backup/Restore der FGA-Datenbank ist getestet (analog zum bestehenden IDP-DB-Restore-Skript).

#### AUTHZ-02 · Modell `core` · M · ⟵ POL-01
**Umfang** `platform`, `tenant`, `user`, `service_account`, `workload` mit Governance-Relationen und Basis-Permissions. Typ-Constraints so eng wie möglich (z. B. `owner: [user]`, nicht `[user, service_account]`).
**Fertig wenn**
- [ ] Modell-Tests decken Owner/Admin/Member-Kaskade und Plattform-Support-Pfad ab.
- [ ] Ein `workload` kann keine Governance-Relation erhalten (Typ-Constraint, nicht Laufzeitprüfung).

#### AUTHZ-03 · Modell `registry` · M · ⟵ AUTHZ-02
**Umfang** `namespace`, `package`, `package_version`; Lesen/Publizieren/Verwalten; Sichtbarkeit öffentlicher Pakete über Tenantgrenzen hinweg sauber modelliert (öffentlich ≠ jedem Tenant zugeordnet).
**Fertig wenn**
- [ ] Ein öffentliches Paket ist lesbar, ohne dass ein tenant-übergreifendes Tupel nötig ist.
- [ ] Publizieren erfordert die Relation, nicht nur die Org-Zugehörigkeit.

#### AUTHZ-04 · Modell `fleet` · M · ⟵ AUTHZ-02
**Umfang** `channel`, `release`, `device_group`, `device`; aggregierte vs. granulare Sichtbarkeit als getrennte Permissions; `can_approve` typseitig auf `[user]` beschränkt.
**Fertig wenn**
- [ ] Modell-Test beweist: ein `workload` kann `can_approve` nicht erlangen, auch nicht über Vererbung.
- [ ] Aggregierte und granulare Sicht sind getrennte Permissions mit getrennten Tests.

#### AUTHZ-05 · Modell `marketplace` · M · ⟵ AUTHZ-02, AUTHZ-04
**Umfang** `marketplace`, `end_customer`; delegierte Administration über `operator from marketplace`; Geräte am Endkunden.
**Fertig wenn**
- [ ] Ein Betreiber-Operator verwaltet automatisch auch nach der Rechtevergabe angelegte Endkunden (Test legt Endkunden nach dem Grant an).
- [ ] Ein Endkunde sieht ausschließlich eigene Geräte, kein anderes Endkundenkonto desselben Marktplatzes.

#### AUTHZ-06 · Store-Provisionierung pro Tenant · M · ⟵ AUTHZ-01
**Umfang** Anlegen, Auflösen und Löschen von Stores; Zuordnung Tenant → Store-ID im Tenant Directory; Kompensation bei Teilausfall im Onboarding.
**Fertig wenn**
- [ ] Fehlgeschlagenes Onboarding hinterlässt keinen verwaisten Store (Fehlerinjektionstest).
- [ ] Store-Löschung ist Teil des DSGVO-Löschpfads.

#### AUTHZ-07 · Modell-Rollout über n Stores · M · ⟵ AUTHZ-06, POL-06
**Umfang** CI-Pipeline: Linter → Modell-Tests → Rollout in alle Stores der Zelle → Aufzeichnung der `authorization_model_id` je Store → Rollback-Kommando. Rollout ist gestaffelt (Canary-Store zuerst).
**Fertig wenn**
- [ ] Rollout ist idempotent und abbrechbar.
- [ ] Ein fehlgeschlagener Rollout lässt bestehende Stores auf der alten Version, ohne Mischzustand im laufenden Verkehr.

#### AUTHZ-08 · `identity/authz`-Client · L · ⟵ AUTHZ-02, FND-01
**Umfang** `Check`, `BatchCheck`, `ListObjects`; Contextual Tuples aus dem Token; explizite Konsistenzwahl pro Aufruf; Timeouts und Circuit Breaker; Fehlerklassifikation (unerreichbar ≠ verweigert); Store-Auflösung über `celldir`.
**Fertig wenn**
- [ ] „FGA unerreichbar" und „Zugriff verweigert" sind im Code und im Log unterscheidbar und werden nie verwechselt (Test).
- [ ] Jeder Aufruf trägt die Permission-ID als Attribut für Tracing und Metriken.
- [ ] Kein Aufrufer kann die Konsistenzwahl vergessen — sie ist Pflichtparameter, kein Default.

#### AUTHZ-09 · Decision-Cache · M · ⟵ AUTHZ-08, STATE-03
**Umfang** Cache ausschließlich für Lesepfade, TTL ≤ 30 s, Invalidierung bei Tupel-Writes über denselben Pub/Sub-Kanal wie der Kill-Switch. Schreib- und kritische Pfade sind vom Cache ausgenommen — durchgesetzt über das Katalogattribut, nicht über Aufrufer-Disziplin.
**Fertig wenn**
- [ ] Eine Permission mit `sensitivity: critical` ist nachweislich nicht cachebar (Test).
- [ ] Cache-Hit-Rate und Alter der ältesten Entscheidung sind Metriken.

#### AUTHZ-10 · Shadow-Mode für Modellwechsel · M · ⟵ AUTHZ-07, AUTHZ-08
**Umfang** Optionale Parallelauswertung gegen eine zweite Modellversion; Abweichungen werden mit Permission, Subjekt-Typ und Ressourcen-Typ geloggt und als Metrik gezählt; die durchgesetzte Entscheidung bleibt die der aktiven Version.
**Fertig wenn**
- [ ] Shadow-Auswertung ist pro Zelle abschaltbar und beeinflusst die Latenz des Hauptpfads nicht messbar (asynchron).
- [ ] Ein Modellwechsel mit bekannter Abweichung wird im Shadow-Report sichtbar, bevor er aktiv wird.

#### AUTHZ-11 · Explain-Endpunkt · M · ⟵ AUTHZ-08
**Umfang** Interner Endpunkt, der für eine konkrete Frage den Entscheidungspfad zurückgibt (FGA `Expand` plus Stage-1-Ergebnis). Selbst autorisiert: nur für Subjekte mit Verwaltungsrecht auf der betroffenen Ressource und nur innerhalb der eigenen Tenantgrenze.
**Fertig wenn**
- [ ] Ein Tenant-Admin kann für seine Nutzer erklären lassen, warum ein Zugriff scheitert.
- [ ] Der Endpunkt leakt keine Informationen über fremde Tenants oder über Existenz fremder Ressourcen (Negativtest).

#### AUTHZ-12 · Tupel-Rebuild-Werkzeug · M · ⟵ AUTHZ-06
**Umfang** `identity/cmd/fga-admin rebuild`: erzeugt aus Zitadel und Produkt-DB den Soll-Tupelstand eines Tenants, vergleicht mit dem Ist, meldet Differenzen und kann sie anwenden. Dry-Run ist der Default.
**Fertig wenn**
- [ ] Ein vollständig geleerter Store lässt sich aus den Quellsystemen rekonstruieren.
- [ ] Differenzen werden nach Kategorie berichtet (fehlend, überzählig, abweichend), nicht als Rohdiff.

#### AUTHZ-13 · Break-Glass · M · ⟵ AUTHZ-08, AUD-01
**Problem** Heute existiert nur eine JS-Action, die IAM_OWNER-Logins alarmiert. Es gibt keinen definierten Notfallpfad mit Ablauf.
**Umfang** Befristeter Grant über eine FGA-Condition; Aktivierung erfordert zwei Personen; automatischer Ablauf ohne Aufräumjob (die Condition läuft aus); Alarm bei Aktivierung und bei jeder Nutzung; Pflichtbegründung; eigener Audit-Eintrag der Klasse `critical`.
**Fertig wenn**
- [ ] Ein abgelaufener Break-Glass-Grant wirkt nicht mehr, ohne dass ein Job ihn entfernt hat.
- [ ] Aktivierung durch eine einzelne Person ist unmöglich (Test).
- [ ] Runbook `docs/runbooks/break_glass.md` beschreibt Aktivierung, Nutzung und Nachbereitung.

---

### ZIT · Zitadel-Neuaufbau

#### ZIT-01 · Zitadel v4 Deployment · M
**Umfang** Ansible-Rolle auf v4 heben; Config-Template und Vault-Agent-Rendering beibehalten (0400, Masterkey nur aus Datei); Valkey als Cache für Mehrknotenbetrieb; Instanz-Policies aus dem generierten Regelwerk ableiten.
**Fertig wenn**
- [ ] Zwei Knoten teilen konsistent den Cache.
- [ ] Masterkey erscheint weiterhin nicht in Umgebung, Prozessliste oder Logs (Prüfskript).
- [ ] Upgrade-Pfad und Rollback sind im Runbook beschrieben.

#### ZIT-02 · Instanz-, Org- und Projektmodell als Code · M · ⟵ ZIT-01
**Umfang** Provisionierung der drei Projekte mit **groben** Rollen; alles Feingranulare entfällt hier. Bestehende Shell-Skripte durch ein Go-Werkzeug ersetzen (idempotent, prüfbar, testbar).
**Fertig wenn**
- [ ] Provisionierung ist idempotent und meldet Drift statt sie stillschweigend zu überschreiben.
- [ ] Keine Rolle existiert in Zitadel, die nicht im Permission-Katalog referenziert wird.

#### ZIT-03 · Actions-v2-Target-Infrastruktur · L · ⟵ ZIT-01, FND-04
**Umfang** HTTP-Endpunkte im Identity-Layer, die Zitadel als Targets aufruft; Authentifizierung und Signaturprüfung der Aufrufe; Timeouts; definiertes Verhalten bei Nichterreichbarkeit (fail-closed für sicherheitsrelevante Hooks); Idempotenz.
**Fertig wenn**
- [ ] Target-Ausfall blockiert Logins für sicherheitsrelevante Hooks und lässt unkritische Hooks passieren — beides bewusst konfiguriert und getestet.
- [ ] Latenzbudget des Login-Pfads ist gemessen und dokumentiert.

#### ZIT-04 · Migration der 14 JS-Actions · L · ⟵ ZIT-03, POL-04
**Umfang** Jede Action wird durch ein Target ersetzt, das den generierten Validator aufruft. Kein JavaScript wird portiert. Betroffen: WebAuthn-only, Dual-Authenticator, permanentes L3, sichere Faktorregistrierung, kein Self-Service-Reset, Break-Glass-Audit, Einladungsregeln, Org-Namen, Rollen-Elevation, GitHub-Upstream-Policy.
**Fertig wenn**
- [ ] Für jede der 14 Regeln existiert ein Test, der das Verhalten gegen eine echte Zitadel-Instanz prüft.
- [ ] Kein JavaScript mehr im Repo außer Zitadel-eigenem Claim-Mapping.
- [ ] Die Org-Namensregel liefert in Go und im IdP-Pfad nachweislich identische Ergebnisse (gemeinsamer Fixture-Satz).

#### ZIT-05 · Token-Claim-Design · M · ⟵ FND-01, ZIT-02
**Umfang** Festlegung und Umsetzung: `sub` als URN, Org-Claim, grobe Rollen, `acr`/`amr`, `auth_time`, `act`, `jkt`. Größenbudget definieren und überwachen, da Rollen als Contextual Tuples mitfließen.
**Fertig wenn**
- [ ] Token-Größe wird gemessen; Überschreiten des Budgets bricht einen Test.
- [ ] Ein Token ohne Org-Claim wird abgelehnt (unverändert zu heute, aber gegen das neue Claim-Set getestet).
- [ ] Die Menge phishing-resistenter `amr`-Werte existiert genau einmal im Repo.

#### ZIT-06 · Token Exchange (RFC 8693) · M · ⟵ ZIT-05
**Umfang** Impersonation und Delegation über Token Exchange; `actor_token` verpflichtend; Ergebnistoken trägt `act`; Lebensdauer ≤ 4 h; Begründung als Claim oder verknüpfter Datensatz.
**Fertig wenn**
- [ ] Impersonation ohne `actor_token` ist unmöglich.
- [ ] Reifegrad der Zitadel-Implementierung ist geprüft und in einem ADR festgehalten (Annahme V5 aus der Zielarchitektur).

#### ZIT-07 · Device Authorization Grant für CLI · M · ⟵ ZIT-05, ENF-03
**Umfang** Device-Flow-Konfiguration; CLI-Client mit DPoP-Schlüsselerzeugung, sicherer lokaler Ablage und Rotation; Ablauf ohne Browser-Redirect-Server.
**Fertig wenn**
- [ ] Login am CLI funktioniert ohne lokalen Webserver.
- [ ] Der private DPoP-Schlüssel wird nie geloggt und liegt mit restriktiven Dateirechten.

#### ZIT-08 · SCIM-Service-Provider · M · ⟵ ZIT-01
**Umfang** SCIM-Endpunkt aktivieren, Idempotenz auf `externalId` und E-Mail härten, Gruppen-Mapping vorbereiten, Deprovisioning-Pfad an STATE-03 anbinden.
**Fertig wenn**
- [ ] Wiederholtes `POST /Users` mit gleichem `externalId` erzeugt genau einen Account.
- [ ] `active: false` widerruft Sessions innerhalb der Kill-Switch-Latenz.

#### ZIT-09 · Contract-Tests gegen Zitadel · M · ⟵ FND-05
**Umfang** Testsuite gegen eine echte Zitadel-Instanz in CI: Token-Format, Claims, JWKS, Token Exchange, Device Flow, SCIM, Actions-v2-Aufrufe. Läuft gegen die eingesetzte **und** die nächste Minor-Version.
**Fertig wenn**
- [ ] Ein Zitadel-Upgrade, das ein Claim-Format ändert, bricht CI statt Produktion.
- [ ] Die Suite ist Teil des Upgrade-Runbooks.

#### ZIT-10 · Secret- und Key-Rotation · M · ⟵ ZIT-01
**Umfang** Rotationsprozess für Masterkey, Service-Account-Keys, Webhook-Secrets, Transit-Keys. Überlappende Gültigkeit, Key-IDs, dokumentierter Ablauf, Probe in der Dev-Zelle.
**Fertig wenn**
- [ ] Jede Rotation ist ohne Ausfall durchführbar und mindestens einmal in Dev durchgeführt worden.
- [ ] Runbook `docs/runbooks/key_rotation.md` existiert.

#### ZIT-11 · Backup- und Restore-Verifikation aktualisieren · S · ⟵ ZIT-01, AUTHZ-01
**Umfang** Bestehendes Restore-Testskript auf Zitadel v4 und zusätzlich auf die FGA-Datenbank ausweiten; Prometheus-Textfile-Metrik je Datenbank.
**Fertig wenn**
- [ ] Für Zitadel-DB und FGA-DB existiert je ein Zeitstempel des letzten erfolgreichen Restores als Metrik mit Alarm bei Veralterung.

---

### GATE-B · Vertikaler Durchstich

#### GATE-B01 · Walking Skeleton · M · ⟵ POL-05, AUTHZ-08, ENF-04, ZIT-05
**Umfang** Genau **eine** echte Permission (Vorschlag: `fleet.device.read_granular`) läuft vollständig durch: Katalogeintrag → Generierung → Stage-1-Gate → FGA-Check → RLS-Query → Audit-Eintrag → Metrik → Fehlerpfad mit Problem Details. Inklusive Integrationstest über alle Schichten.
**Fertig wenn**
- [ ] Der Pfad funktioniert lokal und in der Dev-Zelle.
- [ ] Alle Ablehnungsgründe (kein Token, falscher Tenant, zu niedriges Trust-Level, fehlende Relation, widerrufen, Rate-Limit) liefern je einen unterscheidbaren, dokumentierten Fehler.
- [ ] Latenz von Stage 1 und Stage 2 ist getrennt gemessen.

**Dieses Ticket ist das Gate.** Erst danach wird die Breite ausgerollt.

---

## 3. Welle 2 — Enforcement, Sync, Zellen

### ENF · Enforcement-Schicht

#### ENF-01 · `identity/token` neu · M · ⟵ FND-01
**Umfang** Verifier liefert `principal.Principal` statt `TokenClaims`; Algorithmus-Allowlist beibehalten inklusive der bewussten Doppelprüfung; gemeinsame AMR-Menge; L3 erfordert zwei phishing-resistente Faktoren (heute genügt `webauthn` + `mfa`); toten Code entfernen (`VerifierConfig`).
**Fertig wenn**
- [ ] `alg: none` und HS* werden weiterhin mit spezifischem Fehler abgelehnt (Test bleibt).
- [ ] Trust-Level-Ableitung ist ein expliziter Zähler über eine benannte Menge, kein Flag-Automat.
- [ ] Fuzz-Test bleibt bestehen und deckt das neue Claim-Set ab.

#### ENF-02 · `identity/jwks` korrigieren · S
**Problem** `parsePublicKey` verwirft `crv` und erzeugt ECDSA-Schlüssel ohne Kurve — nicht verifizierbar, Nil-Dereference möglich.
**Umfang** `crv` auf `elliptic.P256/P384/P521` abbilden, unbekannte Kurven ablehnen; Test prüft tatsächliche Signaturverifikation statt Nicht-Nil; Offline-Fallback, Ratenbegrenzung und Fail-Fast unverändert erhalten; totes Feld `lastFetch` entfernen.
**Fertig wenn**
- [ ] Ein mit EC-Schlüssel signiertes Token wird erfolgreich verifiziert (Ende-zu-Ende-Test).
- [ ] Ein JWK ohne oder mit unbekanntem `crv` wird verworfen und geloggt, ohne den restlichen Schlüsselsatz zu verlieren.

#### ENF-03 · `identity/dpop` vollständig · L · ⟵ STATE-04
**Problem** Die Proof-Signatur wird heute nicht geprüft; der Thumbprint hasht rohe Bytes statt kanonischem JSON; kein Replay-Schutz.
**Umfang** Signaturprüfung gegen das eingebettete JWK; RFC-7638-konformer Thumbprint über kanonisches JSON; `htm`/`htu` exakt ohne Suffix-Fallback; `iat`-Fenster plus `jti`-Replay; Server-Nonce für sensible Endpunkte; Bindung `jkt` ↔ Access Token.
**Fertig wenn**
- [ ] Ein Proof mit gültigem Header und ungültiger Signatur wird abgelehnt (dieser Test schlägt gegen die heutige Implementierung fehl — er ist der Beweis, dass die Lücke geschlossen ist).
- [ ] Thumbprints stimmen mit einer unabhängigen Referenzimplementierung überein.
- [ ] Wiederverwendung eines Proofs innerhalb des Fensters wird instanzübergreifend abgelehnt.

#### ENF-04 · `identity/enforce` Stage-1-Gates · L · ⟵ POL-03, STATE-03, FND-01
**Umfang** Sechs Gates in fester Reihenfolge: Token, DPoP, Principal-Aufbau, Tenant-Match, Endpoint-Gate (Trust-Level, Step-Up, Impersonationsklasse), Kill-Switch. Konfiguration ausschließlich aus `shared/policy`. Kein I/O außer lokalen Caches.
**Fertig wenn**
- [ ] Kein Gate führt einen Netzwerkaufruf durch (Test mit blockiertem Netzwerk).
- [ ] p99 der Gate-Kette < 200 µs im Benchmark.
- [ ] Reihenfolge ist durch einen Test festgeschrieben, der bei Vertauschung fehlschlägt.

#### ENF-05 · Generierte Interceptors · M · ⟵ ENF-04, POL-05
**Umfang** Connect/gRPC- und HTTP-Interceptors werden aus der Endpoint-Registry generiert; kein handgeschriebenes Verdrahten pro Route.
**Fertig wenn**
- [ ] Ein neuer Endpunkt mit Katalogeintrag ist ohne Interceptor-Code geschützt.
- [ ] Der alte `RequireFleetSecurity`-Pfad ist vollständig ersetzt.

#### ENF-06 · Step-Up-Challenge nach RFC 9470 · S · ⟵ FND-04, ENF-04
**Umfang** `insufficient_user_authentication` mit `acr_values` und `max_age` im `WWW-Authenticate`-Header, dazu Problem Details im Body. Client-Contract dokumentieren.
**Fertig wenn**
- [ ] Header und Body sind konsistent und über alle Endpunkte identisch aufgebaut.
- [ ] Ein Beispielclient führt den Step-Up-Zyklus ohne Sonderwissen durch.

#### ENF-07 · BFF für die Web-UI · L · ⟵ ENF-04, STATE-01
**Umfang** Backend-for-Frontend: Tokens ausschließlich serverseitig, `__Host-`-Session-Cookie, CSRF-Schutz, Logout mit Token-Revocation, Session-Idle- und Absolut-Timeout.
**Fertig wenn**
- [ ] Kein Access- oder Refresh-Token erreicht den Browser (Test prüft Responses und Cookies).
- [ ] Logout widerruft die Token-Familie serverseitig, nicht nur das Cookie.

#### ENF-08 · Listen-Endpunkte · M · ⟵ AUTHZ-08
**Umfang** Verbindliches Muster: `ListObjects` wenn die Liste aus der Autorisierung entsteht, `BatchCheck` wenn eine Query gefiltert wird. Pflicht-Paging. Kein N+1-Check.
**Fertig wenn**
- [ ] Ein Lint- oder Review-Kriterium verhindert Einzelchecks in Schleifen.
- [ ] Für den größten Listen-Endpunkt ist die Anzahl der FGA-Aufrufe unabhängig von der Seitengröße konstant.

#### ENF-09 · Latenzbudget-Instrumentierung · S · ⟵ ENF-04, AUTHZ-08
**Umfang** Getrennte Spans und Histogramme für Stage 1, Stage 2, Datenzugriff; Anteil der Autorisierung am Gesamtrequest als abgeleitete Metrik.
**Fertig wenn**
- [ ] Für jeden Endpunkt ist der Autorisierungsanteil sichtbar; Überschreiten von 15 % erzeugt ein Warn-Signal.

---

### SYNC · Synchronisation und Provisioning

#### SYNC-01 · Transactional Outbox · M · ⟵ FND-03
**Umfang** Outbox-Tabelle, Writer, der in derselben Transaktion wie die Zustandsänderung schreibt; Ordering pro Aggregat (Tenant/Org), nicht global; Sequenznummer je Aggregat.
**Fertig wenn**
- [ ] Ein Rollback der Geschäftstransaktion verwirft auch das Event (Test).
- [ ] Reihenfolge innerhalb eines Aggregats ist garantiert und getestet.

#### SYNC-02 · Dienst `identity-sync` · L · ⟵ SYNC-01, STATE-05
**Umfang** Eigener Prozess: Outbox-Consumer, Retry mit exponentiellem Backoff, Dead-Letter-Queue, Metriken, Wiedereinspielung aus der DLQ, Leader-Election oder Partitionierung für Mehrinstanzbetrieb.
**Fertig wenn**
- [ ] Zwei Instanzen verarbeiten kein Event doppelt.
- [ ] DLQ-Tiefe ist eine Alarmquelle mit Runbook.
- [ ] Wiedereinspielung ist idempotent.

#### SYNC-03 · Zitadel → lokal über Events · L · ⟵ SYNC-02, ZIT-01
**Umfang** Ablösung des HMAC-Webhook-Pfads durch Zitadels Event-Quelle bzw. Actions-v2-Event-Hooks in die Outbox; Idempotenz über Event-ID; Lag-Messung.
**Fertig wenn**
- [ ] Ein Zitadel-Ausfall führt nach Wiederkehr zur vollständigen Nachverarbeitung ohne Datenverlust.
- [ ] Sync-Lag p95 < 30 s, Alarm > 5 min.

#### SYNC-04 · Reconciler v2 · M · ⟵ SYNC-03, AUTHZ-12
**Problem** Heute werden DB-Fehler und echte Drift identisch behandelt (Korrektur plus Zählerinkrement), und überzählige lokale Mitglieder werden nie entfernt.
**Umfang** Fehler und Drift strikt trennen; Soll/Ist als Mengenvergleich inklusive Entfernung überzähliger Einträge; Korrekturen nach Kategorie zählen; Reconciler deckt Mirror **und** FGA-Tupel ab.
**Fertig wenn**
- [ ] Ein DB-Fehler erzeugt keinen Drift-Zähler-Anstieg.
- [ ] Ein lokal überzähliges Mitglied wird entfernt (Test).
- [ ] Drift-Metriken sind nach Kategorie aufgeschlüsselt.

#### SYNC-05 · Ausgehende Kunden-Events · M · ⟵ SYNC-02, FND-04
**Umfang** Signaturschema mit Zeitstempel und Replay-Fenster; Retry und DLQ pro Empfänger; Kundendokumentation; Test-Endpunkt und Signatur-Verifikationsbeispiel; Rotation des Empfänger-Secrets.
**Fertig wenn**
- [ ] Ein Kunde kann die Signatur mit einer gängigen Standardbibliothek prüfen.
- [ ] Ein dauerhaft nicht erreichbarer Empfänger blockiert keine anderen Empfänger.

#### SYNC-06 · SCIM-Mapping und Deprovisioning · M · ⟵ ZIT-08, AUTHZ-05
**Umfang** SCIM-Gruppen auf FGA-Tupel abbilden (nicht auf Produkt-DB-Rollen); Deprovisioning löst Tupel-Entzug, Session-Revocation und Kill-Switch-Eintrag aus.
**Fertig wenn**
- [ ] Ein im Kundensystem deaktivierter Nutzer verliert den Zugang innerhalb der Kill-Switch-Latenz, nicht erst beim nächsten Login.
- [ ] Gruppenänderung ⇒ Tupeländerung ist Ende-zu-Ende getestet.

#### SYNC-07 · JIT-Provisioning bei Federation · S · ⟵ ZIT-01, AUTHZ-05
**Umfang** Erstes Login über einen Kunden-IdP legt Nutzer und Basistupel an; Rollenvergabe bleibt beim Betreiber.
**Fertig wenn**
- [ ] Ein neuer Nutzer erhält beim ersten Login exakt die Basisrelation, keine privilegierte Rolle.

#### SYNC-08 · Löschpfad · M · ⟵ AUTHZ-06, AUD-06
**Umfang** Löschen eines Nutzers, eines Endkunden und eines Tenants über alle Systeme: Zitadel, FGA-Tupel bzw. Store, Mirror, Outbox, Sessions. Audit-Einträge werden nicht gelöscht, sondern pseudonymisiert; die Hash-Kette bleibt verifizierbar.
**Fertig wenn**
- [ ] Nach der Löschung existiert kein Tupel, keine Session und kein Mirror-Eintrag mehr (automatisierter Nachweis).
- [ ] Die Audit-Kette verifiziert weiterhin, obwohl personenbezogene Felder pseudonymisiert sind.
- [ ] Löschung ist als Ablauf dokumentiert, inklusive Fristen.

---

### CELL · Tenancy und Zellmodell

#### CELL-01 · Tenant Directory · M · ⟵ FND-01
**Umfang** Kleiner Dienst plus Datenmodell: Domain und Tenant-ID auf Zell-Koordinaten (Issuer, JWKS, FGA-Endpunkt, Store-ID, DB-Referenz, Region, Profil). Nur lesend im heißen Pfad, aggressiv gecacht, keine Nutzerdaten.
**Fertig wenn**
- [ ] Ausfall des Directory beeinträchtigt laufenden Verkehr nicht (Cache), verhindert aber Onboarding.
- [ ] Es liegt nachweislich kein personenbezogenes Datum im Directory (Schema-Review).

#### CELL-02 · Zellkonfiguration und Auflösung · M · ⟵ CELL-01
**Umfang** Startparameter je Zelle; Store-Auflösung pro Request aus dem verifizierten Org-Claim über prozesslokalen Cache; kein Code-Pfad, der auf das Profil verzweigt.
**Fertig wenn**
- [ ] Eine Suche nach Profilverzweigungen im Code (`isEnterprise`, `dedicated`, …) liefert keinen Treffer — als CI-Regel.
- [ ] Dieselbe Binärdatei läuft unverändert in allen drei Profilen.

#### CELL-03 · Terraform-Modul `cell` · L · ⟵ AUTHZ-01, ZIT-01
**Umfang** Ein Modul erzeugt eine vollständige Zelle: Netz, Knoten, Zitadel, OpenFGA, Postgres-Instanzen, Valkey, Vault-Namespace und PKI-Pfade, Backup-Buckets, DNS. Parametrisiert über Profil und Region.
**Fertig wenn**
- [ ] Eine neue Zelle entsteht aus einem Modulaufruf ohne manuelle Schritte.
- [ ] Das bestehende Identity-Terraform-Projekt ist auf das Modul umgestellt.

#### CELL-04 · Zell-Bootstrap · M · ⟵ CELL-03, AUTHZ-06
**Problem** Henne-Ei: Autorisierung braucht Tupel, Tupel brauchen einen Owner, der Owner braucht Autorisierung.
**Umfang** Definierter Bootstrap: Erzeugung des ersten Plattform-Owners mit Hardware-Faktor, Seed der Basistupel, Anlage der Audit-Kette, Einrichtung des Break-Glass-Kontos. Einmalig, protokolliert, danach über einen Marker gesperrt.
**Fertig wenn**
- [ ] Bootstrap ist genau einmal ausführbar; ein zweiter Versuch schlägt fehl.
- [ ] Jeder Bootstrap-Schritt erzeugt einen Audit-Eintrag der Klasse `critical`.
- [ ] Runbook `docs/runbooks/cell_bootstrap.md` existiert und wurde in Dev durchgespielt.

#### CELL-05 · RLS-Härtung · M
**Umfang** `FORCE ROW LEVEL SECURITY` und `WITH CHECK` auf allen tenant-skopierten Tabellen; separate Applikationsrolle ohne Ownership; Composite-Indizes mit `tenant_id` an erster Stelle; Policy-Namen einheitlich.
**Fertig wenn**
- [ ] Der Tabellen-Owner umgeht die Policy nicht mehr (Test unter Owner-Rolle).
- [ ] Ein Schreibversuch in einen fremden Tenant schlägt fehl (Test).
- [ ] Für jede tenant-skopierte Tabelle existiert der Isolationstest — erzeugt durch QA-05, nicht handgeschrieben.

#### CELL-06 · Pool- und Transaktionsregeln · S · ⟵ CELL-05
**Umfang** `SET LOCAL` ausschließlich innerhalb einer Transaktion; Lint- oder Laufzeitprüfung gegen session-weites `SET`; PgBouncer-Konfiguration dokumentiert.
**Fertig wenn**
- [ ] Ein absichtlich session-weites `SET` wird von einem Test erkannt (Meta-Test).
- [ ] Nach Rückgabe einer Connection an den Pool ist `app.tenant_id` nachweislich leer.

#### CELL-07 · Tenant-Onboarding als persistierte SAGA · L · ⟵ AUTHZ-06, SYNC-01, CELL-01
**Problem** Heute läuft die SAGA im API-Prozess; scheitert die Kompensation, bleibt es bei einem Log-Eintrag.
**Umfang** Onboarding als persistierter Ablauf mit Schritten (Zitadel-Org, FGA-Store, Directory-Eintrag, Mirror-Zeilen, Audit-Kette, Basistupel), Wiederaufnahme nach Absturz, Kompensation mit Retry und Alarmierung bei endgültigem Scheitern. Quota- und Namensprüfung weiterhin **vor** dem ersten externen Aufruf.
**Fertig wenn**
- [ ] Prozessabsturz an jedem Schritt hinterlässt keinen inkonsistenten Zustand (Fehlerinjektion an jedem Schritt).
- [ ] Der Test, der prüft, dass bei Quota-Verletzung **kein** externer Aufruf erfolgt, bleibt erhalten und wird auf alle externen Systeme erweitert.

#### CELL-08 · Profil-Upgrade P1 → P2 · M · ⟵ CELL-03, ZIT-02
**Umfang** Umstellung eines Tenants auf eine eigene virtuelle Zitadel-Instanz: Custom Domain, eigene Login- und MFA-Policies, eigenes Branding, eigene IdP-Federation. Innerhalb derselben Zelle, ohne Datenumzug.
**Fertig wenn**
- [ ] Ein Testtenant wurde erfolgreich von P1 nach P2 gehoben, Nutzer konnten sich vorher und nachher anmelden.
- [ ] Der Ablauf ist als Runbook dokumentiert.

#### CELL-09 · Zell-Export und -Import · L · ⟵ CELL-07
**Umfang** Werkzeug für P2 → P3: konsistenter Export eines Tenants (Identitäten, Tupel, Produkt-Daten, Audit-Kette mit Checkpoints), Import in eine neue Zelle, Verifikation, Umschaltung im Directory. Offline mit Wartungsfenster — bewusst kein Live-Feature.
**Fertig wenn**
- [ ] Ein Testtenant wurde vollständig umgezogen; Stichprobenvergleich vorher/nachher ist identisch.
- [ ] Die Audit-Kette verifiziert nach dem Umzug weiterhin.
- [ ] Rollback auf die Quellzelle ist möglich, solange die Umschaltung nicht erfolgt ist.

#### CELL-10 · Isolationstest-Suite · M · ⟵ CELL-05, AUTHZ-06
**Umfang** Drei Isolationsebenen automatisiert prüfen: RLS (Zeilen), FGA (Store-Trennung), Routing (Zellgrenze). Läuft in CI gegen die Dev-Zelle.
**Fertig wenn**
- [ ] Jede Ebene hat mindestens einen Test, der bei absichtlich entfernter Schutzmaßnahme fehlschlägt.

---

## 4. Welle 3 — Governance, Audit, Geräte

### REL · Release-Governance

#### REL-01 · Signaturbasierte Freigabe · L · ⟵ STATE-07, AUD-01
**Umfang** Kanonisches Release-Statement (Release-ID, Artefakt-Digest, Kanal, Zeitstempel, Approver-URN); Signatur statt Datenbankeintrag; Bündelung als Attestation.
**Fertig wenn**
- [ ] Eine Freigabe ohne gültige Signatur ist nicht darstellbar.
- [ ] Manipulation eines Feldes im Statement invalidiert die Signatur (Test analog zum heutigen Tamper-Test).

#### REL-02 · 2-of-N mit personengebundenen Schlüsseln · L · ⟵ REL-01
**Umfang** Schwellwert-Signatur; Schlüssel pro Person in Vault Transit oder auf Hardware-Token; Zuordnung Person → Schlüssel; Widerruf eines Schlüssels; Rotation.
**Fertig wenn**
- [ ] Zwei Signaturen derselben Person erfüllen den Schwellwert nicht (Test).
- [ ] Ein Datenbankzugriff allein reicht nicht aus, um eine Freigabe zu erzeugen — belegt durch einen Test, der genau das versucht.

#### REL-03 · Soak-Window an die Uptane-Signatur koppeln · M · ⟵ REL-02
**Umfang** Die Auslieferungssignatur entsteht erst nach Ablauf des Fensters; Abbruch verhindert sie; das Fenster ist damit kryptografisch durchgesetzt, nicht durch einen Statuswert.
**Fertig wenn**
- [ ] Ein manipuliertes Zeitfeld in der Datenbank ermöglicht keine vorzeitige Auslieferung (Test).
- [ ] Abbruch während des Fensters führt zu keiner Signatur und zu einem Alarm.

#### REL-04 · CI-Produktionssperre im Typsystem · S · ⟵ AUTHZ-04
**Umfang** `can_approve` akzeptiert ausschließlich `[user]`; die heutige Laufzeitprüfung bleibt zusätzlich als zweite Schicht.
**Fertig wenn**
- [ ] Ein Modell-Test beweist, dass ein `workload` die Relation auf keinem Pfad erlangen kann.
- [ ] Der bestehende Laufzeittest bleibt grün.

#### REL-05 · Uptane-Rollen und Schlüsselverwahrung · L · ⟵ REL-02
**Umfang** Abbildung Root/Targets/Snapshot/Timestamp/Director auf Verwahrungsorte und Toob-Rollen; Root offline mit m-of-n; Erneuerungsprozesse; Notfallwiederherstellung.
**Fertig wenn**
- [ ] Für jede Rolle sind Verwahrung, Rotationsintervall und Wiederherstellungspfad dokumentiert und einmal geprobt.

#### REL-06 · Abbruchpfad mit Autorisierung · S · ⟵ STATE-07, AUTHZ-04
**Umfang** `CancelRelease` prüft die Berechtigung des Abbrechenden (fehlt heute vollständig), auditiert und alarmiert.
**Fertig wenn**
- [ ] Abbruch durch einen nicht berechtigten Akteur wird abgelehnt und auditiert.

---

### AUD · Audit und Nachweisbarkeit

#### AUD-01 · Audit-Schema und Hash-Kette · M · ⟵ FND-03, CELL-05
**Umfang** Append-only-Tabelle mit `prev_hash`/`entry_hash` über kanonisiertes JSON; schreibende Rolle ohne `UPDATE`/`DELETE`; eine Kette pro Tenant; Schreiben über die Outbox, damit der Request nicht blockiert.
**Fertig wenn**
- [ ] Nachträgliche Änderung eines Eintrags wird vom Verifikationswerkzeug erkannt.
- [ ] Die schreibende Datenbankrolle besitzt nachweislich kein `UPDATE`- oder `DELETE`-Recht.

#### AUD-02 · Checkpoints · M · ⟵ AUD-01, ZIT-10
**Umfang** Periodische Signatur des Kettenkopfs über Vault Transit; Ablage und optionale Publikation, sodass ein Kunde die Unveränderlichkeit ohne Vertrauen in uns prüfen kann.
**Fertig wenn**
- [ ] Checkpoints werden erzeugt, gespeichert und sind verifizierbar.
- [ ] Der Verifikationspfad ist ohne Zugriff auf unsere Datenbank durchführbar (nur Kette plus Checkpoint plus öffentlicher Schlüssel).

#### AUD-03 · Audit-Klassifikation aus dem Katalog · S · ⟵ POL-03, AUD-01
**Umfang** Die Klasse (`read`/`write`/`critical`/`authn`) kommt aus dem Permission-Katalog; kein handgepflegtes Mapping.
**Fertig wenn**
- [ ] Eine neue Permission ohne Audit-Klasse bricht die Generierung.

#### AUD-04 · Blockierendes Audit für kritische Aktionen · S · ⟵ AUD-01
**Umfang** Kann ein `critical`-Eintrag nicht geschrieben werden, wird die Aktion abgelehnt. Alle anderen Klassen puffern in der Outbox.
**Fertig wenn**
- [ ] Bei simuliertem Audit-Ausfall schlagen Freigaben fehl, normale Schreibvorgänge laufen weiter (entspricht der Ausfallmatrix).

#### AUD-05 · Verifikationswerkzeug · M · ⟵ AUD-02
**Umfang** Kommando zum Prüfen einer Kette gegen ihre Checkpoints; Ausgabe in maschinenlesbarer Form; Runbook für den Nachweis gegenüber Prüfern.
**Fertig wenn**
- [ ] Eine absichtlich manipulierte Kette wird mit Angabe des ersten abweichenden Eintrags erkannt.

#### AUD-06 · Aufbewahrung und Pseudonymisierung · M · ⟵ AUD-01
**Umfang** Aufbewahrungsfristen je Klasse; Pseudonymisierung personenbezogener Felder ohne Bruch der Kette; Archivierung älterer Segmente.
**Fertig wenn**
- [ ] Pseudonymisierung lässt die Kettenverifikation intakt (Test).
- [ ] Fristen sind konfiguriert und dokumentiert.

---

### DEV · Geräte- und Workload-Identität

#### DEV-01 · PKI-Hierarchie · L · ⟵ CELL-03
**Umfang** Root offline mit HSM; Zell-Intermediate und Tenant-Issuing-CAs in Vault PKI; Laufzeiten, Namensschema, Erneuerung.
**Fertig wenn**
- [ ] Die vollständige Kette lässt sich in der Dev-Zelle aufbauen und validieren.
- [ ] Kompromittierung einer Tenant-CA betrifft ausschließlich diesen Tenant (dokumentierte Analyse).

#### DEV-02 · SAN-URI-Schema · M · ⟵ DEV-01, FND-01
**Umfang** Einheitlicher Identifier für Geräte und Workloads; Verifikation bildet das Zertifikat auf einen `Principal` ab.
**Fertig wenn**
- [ ] Geräte- und Workload-Zertifikate durchlaufen denselben Verifikationspfad.
- [ ] Ein Zertifikat mit fremder Tenant-Kennung wird abgelehnt.

#### DEV-03 · Zero-Touch-Onboarding · L · ⟵ DEV-02
**Umfang** Werksseitiges Bootstrap-Zertifikat, Tausch gegen ein operatives Zertifikat beim ersten Kontakt, Entwertung des Bootstrap-Zertifikats, Anbindung an den eFuse-/Secure-Element-Pfad des Chip-Pakets.
**Fertig wenn**
- [ ] Ein zweiter Onboarding-Versuch mit demselben Bootstrap-Zertifikat scheitert.
- [ ] Der Ablauf funktioniert ohne Nutzerinteraktion.

#### DEV-04 · Automatische Rotation · M · ⟵ DEV-03
**Umfang** Erneuerung vor Ablauf mit Überlappungsfenster; Verhalten bei zeitweise offline befindlichen Geräten; Alarm bei Rotationsstau.
**Fertig wenn**
- [ ] Ein Gerät, das während des Überlappungsfensters offline war, rotiert nach der Rückkehr erfolgreich.
- [ ] Anteil der Geräte mit bald ablaufendem Zertifikat ist eine Metrik.

#### DEV-05 · mTLS-Terminierung und Principal-Mapping · M · ⟵ DEV-02
**Umfang** Terminierung am Edge, gesicherte Weitergabe der Client-Identität nach innen, Abbildung auf `Principal`, Schutz gegen Header-Spoofing von außen.
**Fertig wenn**
- [ ] Ein von außen gesetzter Identitäts-Header wird verworfen (Test).

#### DEV-06 · Geräte-Revocation ohne CRL · M · ⟵ DEV-05, STATE-03
**Umfang** Sperrung über den Kill-Switch; kurze Zertifikatslaufzeiten; Sperrgrund und Historie.
**Fertig wenn**
- [ ] Ein gesperrtes Gerät wird innerhalb der Kill-Switch-Latenz abgewiesen.

#### DEV-07 · Workload-Identität für interne Dienste · M · ⟵ DEV-01
**Umfang** Kurzlebige Zertifikate für Service-zu-Service-Verkehr; automatische Erneuerung; Ablösung statisch verteilter Tokens.
**Fertig wenn**
- [ ] Kein interner Dienst authentifiziert sich mehr mit einem langlebigen statischen Secret.

---

## 5. Welle 4 — Betrieb, Qualität, Rückbau

### OPS · Observability und Betrieb

#### OPS-01 · SLOs und Metriken · M · ⟵ ENF-09, AUTHZ-08
**Umfang** Verbindliche SLOs: Stage-1 p99 < 200 µs; FGA-Check p95 < 10 ms und p99 < 25 ms; Kill-Switch-Verbreitung < 5 s; Sync-Lag p95 < 30 s; Autorisierungsanteil ≤ 15 % des Requestbudgets; JWKS-Verfügbarkeit bei IdP-Ausfall 24 h. Je SLO eine Metrik und ein Alarm.
**Fertig wenn**
- [ ] Jedes SLO ist gemessen und hat einen Alarm mit Runbook-Verweis.

#### OPS-02 · Dashboards und Alarmregeln · M · ⟵ OPS-01
**Umfang** Grafana-Dashboards für Identity und Autorisierung; Prometheus-Regeln unter `platform/deploy/monitoring/prometheus/rules/identity.yml`; die bestehenden Sicherheitsalarme (Cross-Tenant, Token-Reuse, Mirror-Lag, L1 auf granulare Daten) bleiben erhalten und werden ergänzt um Drift nach Kategorie, DLQ-Tiefe, Shadow-Abweichungen, Break-Glass-Aktivierungen.
**Fertig wenn**
- [ ] Jeder Alarm hat ein Runbook; kein Runbook ohne Alarm und kein Alarm ohne Runbook.

#### OPS-03 · Runbooks · M
**Umfang** Neu: FGA-Ausfall, FGA-Modell-Rollback, Sync-DLQ-Abarbeitung, Break-Glass, Zell-Bootstrap, Zell-Umzug, Key-Rotation, Zitadel-Upgrade, Audit-Verifikation, Geräte-Massensperrung.
**Fertig wenn**
- [ ] Jedes Runbook wurde mindestens einmal in Dev durchgespielt und dabei korrigiert.

#### OPS-04 · Ausfallmatrix implementieren und testen · M · ⟵ OPS-01
**Umfang** Jede Zeile der Ausfallmatrix aus der Zielarchitektur § 14 wird zu einem automatisierten Testfall.
**Fertig wenn**
- [ ] Alle neun Ausfallszenarien sind als Test vorhanden und grün.
- [ ] Abweichungen zwischen dokumentiertem und tatsächlichem Verhalten sind entweder behoben oder das Dokument ist korrigiert.

#### OPS-05 · Fehlerinjektion in CI · M · ⟵ OPS-04
**Umfang** Regelmäßiger Lauf mit abgeschalteten Abhängigkeiten (Zitadel, FGA, Valkey, Audit) gegen die Integrationsumgebung.
**Fertig wenn**
- [ ] Der Lauf ist Teil der Pipeline und bricht bei unerwartetem Verhalten.

---

### QA · Testarchitektur

#### QA-01 · Permission-Matrix-Golden-Tests · L · ⟵ POL-02, AUTHZ-08
**Umfang** Für jede Permission × jeden relevanten Akteurstyp ein erwartetes Ergebnis; Abweichung bricht CI; die Matrix ist generiert, die Erwartungen sind gepflegt.
**Fertig wenn**
- [ ] Jede Permission hat mindestens einen Positiv- und einen Negativfall.
- [ ] Eine Modelländerung, die versehentlich Rechte ausweitet, wird von der Matrix erkannt (Meta-Test mit absichtlicher Ausweitung).

#### QA-02 · FGA-Modell-Tests je Modul · M · ⟵ AUTHZ-02…05
**Fertig wenn**
- [ ] Jedes Modul hat eine eigene Testdatei; Ausführung ist Teil des Rollouts.

#### QA-03 · Integrationsharness erweitern · L · ⟵ FND-05, AUTHZ-01
**Umfang** Bestehende Harness (`registry/test/integration`) um Zitadel, FGA und Zellkontext erweitern; Phasen für AuthN, AuthZ, Tenancy, Sync, Release, Device.
**Fertig wenn**
- [ ] Die Harness startet alle Abhängigkeiten selbst und ist auf einem frischen Rechner lauffähig.
- [ ] Bestehende Phasen laufen unverändert weiter.

#### QA-04 · Fuzzing ausweiten · M · ⟵ ENF-01, ENF-03
**Umfang** Bestehendes Token-Fuzzing erhalten; neu: DPoP-Proofs, SCIM-Payloads, Webhook-Payloads, URN-Parser.
**Fertig wenn**
- [ ] Jeder Parser an einer Vertrauensgrenze ist gefuzzt.

#### QA-05 · Isolationstest-Generator · M · ⟵ CELL-05
**Umfang** Aus dem Schema wird für jede tenant-skopierte Tabelle ein Isolationstest erzeugt (Lesen fremd, Schreiben fremd, Lesen eigen).
**Fertig wenn**
- [ ] Eine neue tenant-skopierte Tabelle ohne Isolationstest bricht CI.

#### QA-06 · Lasttests für die offenen Annahmen · M · ⟵ GATE-B01
**Umfang** Messung der sieben Annahmen aus der Zielarchitektur § 21 auf eigener Infrastruktur, insbesondere FGA-Latenz auf eigenem Postgres, Kosten erhöhter Konsistenz, Kill-Switch-Verbreitung, RLS-Overhead.
**Fertig wenn**
- [ ] Für jede Annahme liegt eine Messung vor; Abweichungen führen zu einem ADR mit Konsequenz.

---

### CLEAN · Rückbau

Erst wenn der Ersatz nachweislich läuft. Jedes Ticket entfernt Code und die zugehörigen Tests, nicht nur Aufrufe.

| Ticket | Was verschwindet | Größe | ⟵ |
|---|---|---|---|
| **CLEAN-01** | `identity/roles` | S | POL-03, AUTHZ-02 |
| **CLEAN-02** | `identity/middleware/*` (auth, trust, org_scoping, fleet_security) | M | ENF-04, ENF-05 |
| **CLEAN-03** | `identity/orgs` → `identity/internal/orgs` | M | CELL-07 |
| **CLEAN-04** | `identity/mirror` | M | SYNC-03, SYNC-04 |
| **CLEAN-05** | `identity/approval`, `identity/impersonation`, `identity/ratelimit` (alte Implementierungen) | M | REL-01, STATE-06, STATE-02 |
| **CLEAN-06** | 14 JS-Actions und die Shell-Provisionierungsskripte | S | ZIT-04, ZIT-02 |
| **CLEAN-07** | Toter Code: `token.VerifierConfig`, `middleware.ErrMissingAuthHeader`, `jwks.lastFetch`, unerreichbare Prüfung in `impersonation.CanExecuteOperation` | S | — |
| **CLEAN-08** | Migrationen 033–036 zu einem sauberen Initial-Set konsolidieren (grüne Wiese nutzen) | M | CELL-05 |

CLEAN-07 ist sofort startbar und sollte in Welle 0 mitlaufen.

---

## 6. Abhängigkeitsübersicht

```
FND-01 ──┬─► FND-02
         ├─► ENF-01 ──► ENF-04 ──┬─► ENF-05 ──► GATE-B01
         ├─► CELL-01 ──► CELL-02 │
         └─► DEV-02              │
                                 │
FND-03 ──┬─► STATE-01 ───────────┤
         ├─► STATE-02            │
         └─► STATE-03 ──┬─► STATE-04 ──► ENF-03 ─┘
                        └─► AUTHZ-09

FND-04 ──► ENF-06, ZIT-03, SYNC-05, FND-06

POL-01 ──► POL-02 ──► POL-03 ──┬─► POL-04 ──► ZIT-04
                               ├─► POL-05 ──► GATE-B01
                               ├─► POL-07
                               └─► AUD-03

AUTHZ-01 ──► AUTHZ-02 ──┬─► AUTHZ-03/04/05 ──► QA-02
                        ├─► AUTHZ-06 ──► AUTHZ-07 ──► AUTHZ-10
                        └─► AUTHZ-08 ──┬─► AUTHZ-09/11/12
                                       ├─► ENF-08
                                       └─► GATE-B01

ZIT-01 ──┬─► ZIT-02 ──► CELL-08
         ├─► ZIT-03 ──► ZIT-04
         ├─► ZIT-05 ──► ZIT-06 ──► STATE-06
         └─► ZIT-08 ──► SYNC-06

SYNC-01 ──► SYNC-02 ──┬─► SYNC-03 ──► SYNC-04
                      └─► SYNC-05

CELL-03 ──► CELL-04 ──► CELL-07 ──► CELL-09
CELL-05 ──► CELL-06, QA-05, AUD-01

AUD-01 ──► AUD-02 ──► AUD-05
       └─► AUD-04, AUTHZ-13

REL-01 ──► REL-02 ──► REL-03, REL-05
DEV-01 ──► DEV-02 ──► DEV-03 ──► DEV-04
```

**Kritischer Pfad zu GATE B:** `FND-01 → POL-01 → POL-02 → POL-03 → POL-05` parallel zu `AUTHZ-01 → AUTHZ-02 → AUTHZ-08` und `ENF-01 → ENF-04`, zusammengeführt in `GATE-B01`. Alles andere hängt daran oder ist parallelisierbar.

---

## 7. Was erfahrungsgemäß vergessen wird

Diese Liste ist die Gegenprobe zum Backlog. Jeder Punkt hat oben ein Ticket; hier steht, warum er leicht durchrutscht.

| # | Punkt | Ticket |
|---|---|---|
| 1 | **Bootstrap-Problem:** Wer autorisiert den ersten Owner? | CELL-04 |
| 2 | **Rebuild-Pfad:** Wie kommt der Relationsgraph nach Verlust zurück? | AUTHZ-12 |
| 3 | **Löschen:** DSGVO über vier Systeme hinweg, ohne die Audit-Kette zu brechen. | SYNC-08, AUD-06 |
| 4 | **Rotation:** Jeder Schlüssel und jedes Secret braucht einen erprobten Rotationsweg. | ZIT-10 |
| 5 | **Nebenläufigkeit:** Token-Rotation und Tupel-Writes brauchen Race-Tests, nicht nur sequenzielle. | STATE-01 |
| 6 | **Unterscheidung „nicht erreichbar" vs. „verweigert":** Wird oft zu „verweigert" zusammengefasst — und maskiert Ausfälle. | AUTHZ-08 |
| 7 | **Cache-Invalidierung bei Rechteentzug:** Ein 30-Sekunden-Cache ist ein 30-Sekunden-Zeitfenster. | AUTHZ-09 |
| 8 | **Token-Größe:** Contextual Tuples aus dem Token wachsen still bis zum Header-Limit. | ZIT-05 |
| 9 | **Listen-Endpunkte:** N+1-Checks entstehen unbemerkt beim ersten Feature nach dem Rollout. | ENF-08 |
| 10 | **Zeit in Tests:** Ohne Clock bleiben Soak-, TTL- und Lag-Tests wirkungslos. | FND-03 |
| 11 | **Entwicklungsumgebung:** Ohne lokalen Stack werden Regeln nur in CI getestet — und damit selten. | FND-05 |
| 12 | **IdP-Upgrades:** Ohne Contract-Tests brechen Claim-Formate still. | ZIT-09 |
| 13 | **Runbook-Lücke:** Alarme ohne Runbook werden zu ignoriertem Rauschen. | OPS-02, OPS-03 |
| 14 | **Generierte Dateien im Review:** Ohne Aktualitätsprüfung in CI driften sie vom Input ab. | POL-03 |
| 15 | **Rückbau:** Alter Code, der „nur noch für den Notfall" bleibt, wird zum zweiten Enforcement-Pfad. | CLEAN-01…08 |
| 16 | **Break-Glass:** Wird erst gebaut, wenn er gebraucht wird — also zu spät. | AUTHZ-13 |
| 17 | **Backup der neuen Datenbank:** FGA hat eine eigene DB, die niemand ins Backup-Konzept aufnimmt. | ZIT-11 |
| 18 | **Fehlercodes:** Ohne stabile Codes bauen Clients Parsing auf Fehlertexten auf. | FND-04 |

---

## 8. Ziel-Dateistruktur

Orientiert an der bestehenden Sortierung: `identity/` wird ein vollwertiger Layer wie `registry/` und `update/` (mit `cmd/`, `internal/`, `migrations/`, `deploy/`, `test/`), öffentliche Packages bleiben flach darunter, Querschnittliches liegt in `shared/`, Infrastruktur in `platform/deploy/`.

```
toob-infra/
│
├── policy/                                  ← NEU: einzige Regelquelle (P2)
│   ├── README.md                              wie man eine Permission hinzufügt
│   ├── actors.yaml                            Akteurstypen, Credential-Anforderungen
│   ├── permissions.yaml                       Permission-Katalog
│   ├── sensitivity.yaml                       Vertraulichkeitsstufen, Audit-Klassen, Kosten
│   ├── rules/
│   │   ├── org_naming.yaml
│   │   ├── invite.yaml
│   │   ├── factor_policy.yaml
│   │   ├── elevation.yaml
│   │   └── impersonation.yaml
│   ├── model/
│   │   ├── fga.mod                            Modulverbund
│   │   ├── core.fga
│   │   ├── registry.fga
│   │   ├── fleet.fga
│   │   └── marketplace.fga
│   └── tests/
│       ├── core_test.fga.yaml
│       ├── registry_test.fga.yaml
│       ├── fleet_test.fga.yaml
│       ├── marketplace_test.fga.yaml
│       └── matrix/
│           └── expectations.yaml              Golden-Matrix Permission × Akteur
│
├── identity/
│   ├── cmd/
│   │   ├── identity-sync/    main.go          Outbox-Consumer, Reconciler, SCIM-Bridge
│   │   ├── celldir/          main.go          Tenant Directory
│   │   ├── policygen/        main.go          Generator (policy/ → shared/policy/)
│   │   └── fga-admin/        main.go          Store-Provisionierung, Rollout, Rebuild, Explain
│   │
│   ├── principal/                             ← unterste Schicht, keine Abhängigkeiten
│   │   ├── principal.go
│   │   ├── urn.go
│   │   ├── urn_test.go
│   │   ├── trustlevel.go
│   │   ├── context.go
│   │   └── principal_test.go
│   │
│   ├── token/
│   │   ├── verifier.go
│   │   ├── claims.go                          Claims → Principal
│   │   ├── amr.go                             phishing-resistente AMR-Menge (einmalig!)
│   │   ├── verifier_test.go
│   │   └── verifier_fuzz_test.go
│   │
│   ├── jwks/
│   │   ├── client.go
│   │   ├── parse.go                           RSA + EC inkl. crv
│   │   ├── client_test.go
│   │   └── outage_test.go
│   │
│   ├── dpop/
│   │   ├── proof.go
│   │   ├── thumbprint.go                      RFC 7638, kanonisch
│   │   ├── replay.go                          jti-Store
│   │   ├── nonce.go
│   │   ├── proof_test.go
│   │   └── proof_fuzz_test.go
│   │
│   ├── enforce/                               ← Stage 1, kein I/O
│   │   ├── gate.go                            Kette und Reihenfolge
│   │   ├── tenant.go
│   │   ├── trust.go
│   │   ├── stepup.go
│   │   ├── impersonation.go
│   │   ├── killswitch.go
│   │   ├── interceptor_connect.go
│   │   ├── interceptor_http.go
│   │   ├── gate_test.go
│   │   └── order_test.go                      erzwingt die Reihenfolge
│   │
│   ├── authz/                                 ← Stage 2, FGA
│   │   ├── client.go
│   │   ├── check.go
│   │   ├── batch.go
│   │   ├── listobjects.go
│   │   ├── contextual.go                      Rollen aus dem Token als Tupel
│   │   ├── consistency.go                     Pflichtparameter, kein Default
│   │   ├── cache.go
│   │   ├── shadow.go
│   │   ├── explain.go
│   │   ├── errors.go                          unerreichbar ≠ verweigert
│   │   └── *_test.go
│   │
│   ├── session/
│   │   ├── store.go                           Interface
│   │   ├── postgres.go
│   │   ├── family.go
│   │   ├── rotation.go
│   │   └── *_test.go
│   │
│   ├── revocation/                            ← Kill-Switch
│   │   ├── store.go
│   │   ├── broadcaster.go
│   │   ├── cache.go
│   │   └── *_test.go
│   │
│   ├── ratelimit/
│   │   ├── limiter.go
│   │   ├── valkey.go
│   │   ├── budgets.go                         Login / Token / Tenant / IP / Kosten
│   │   └── *_test.go
│   │
│   ├── federation/
│   │   ├── workload.go                        CI-OIDC
│   │   ├── customer_idp.go
│   │   └── *_test.go
│   │
│   ├── celldir/
│   │   ├── client.go
│   │   ├── cache.go
│   │   ├── resolver.go                        Org-Claim → Store/DB/Issuer
│   │   └── *_test.go
│   │
│   ├── audit/
│   │   ├── entry.go
│   │   ├── chain.go
│   │   ├── writer.go
│   │   ├── checkpoint.go
│   │   ├── verify.go
│   │   └── *_test.go
│   │
│   ├── internal/                              ← nur für identity-eigene Dienste
│   │   ├── sync/
│   │   │   ├── outbox.go
│   │   │   ├── consumer.go
│   │   │   ├── dlq.go
│   │   │   ├── reconciler.go
│   │   │   ├── outbound.go                    signierte Kunden-Events
│   │   │   └── *_test.go
│   │   ├── scim/
│   │   │   ├── mapping.go
│   │   │   ├── idempotency.go
│   │   │   ├── deprovision.go
│   │   │   └── *_test.go
│   │   ├── zitadel/
│   │   │   ├── client.go
│   │   │   ├── events.go
│   │   │   ├── actions_target.go              Actions-v2-Endpunkte
│   │   │   ├── provision.go                   ersetzt die Shell-Skripte
│   │   │   ├── serviceaccount.go
│   │   │   └── *_test.go
│   │   ├── orgs/
│   │   │   ├── saga.go                        persistiert, wiederaufnehmbar
│   │   │   ├── onboarding.go
│   │   │   └── *_test.go
│   │   ├── fga/
│   │   │   ├── store.go                        Provisionierung
│   │   │   ├── rollout.go
│   │   │   ├── rebuild.go
│   │   │   └── *_test.go
│   │   └── celldir/
│   │       └── store.go
│   │
│   ├── migrations/
│   │   ├── 001_identity_core.up.sql            sessions, consumed_tokens, outbox, dedup
│   │   ├── 002_audit_chain.up.sql
│   │   ├── 003_tenant_directory.up.sql
│   │   ├── 004_idempotency.up.sql
│   │   ├── 005_onboarding_saga.up.sql
│   │   ├── 006_revocation.up.sql
│   │   └── migrations.go
│   │
│   ├── deploy/
│   │   └── nomad/jobs/
│   │       ├── identity-sync.nomad.hcl
│   │       ├── celldir.nomad.hcl
│   │       ├── openfga.nomad.hcl
│   │       └── openfga-migrate.nomad.hcl
│   │
│   └── test/
│       ├── integration/
│       │   ├── main_test.go
│       │   ├── harness/
│       │   │   ├── zitadel.go
│       │   │   ├── fga.go
│       │   │   ├── db.go
│       │   │   ├── valkey.go
│       │   │   ├── tokens.go                  Tokens je Akteurstyp
│       │   │   └── cell.go
│       │   └── phases/
│       │       ├── phase01_authn.go
│       │       ├── phase02_authz.go
│       │       ├── phase03_tenancy.go
│       │       ├── phase04_sync.go
│       │       ├── phase05_release.go
│       │       ├── phase06_device.go
│       │       └── phase07_degradation.go     Ausfallmatrix
│       ├── isolation/
│       │   ├── rls_test.go                    generiert
│       │   ├── fga_store_test.go
│       │   └── routing_test.go
│       ├── contract/
│       │   └── zitadel_contract_test.go
│       └── load/
│           └── authz_bench_test.go
│
├── shared/
│   ├── policy/                                ← GENERIERT, nicht editieren
│   │   ├── doc.go
│   │   ├── permissions_gen.go
│   │   ├── endpoints_gen.go
│   │   ├── gates_gen.go
│   │   ├── audit_gen.go
│   │   ├── ratelimit_gen.go
│   │   └── rules_gen.go
│   ├── errors/
│   │   ├── errors.go
│   │   ├── problem.go                         RFC 9457
│   │   └── codes_gen.go
│   ├── x/
│   │   ├── clock/
│   │   │   ├── clock.go
│   │   │   └── fake.go
│   │   ├── idempotency/
│   │   ├── retry/                             (bestehend)
│   │   └── …                                  (bestehend)
│   ├── signing/                               (bestehend, + Threshold/Attestation)
│   ├── audit/                                 (bestehend, an identity/audit angepasst)
│   ├── vault/                                 (bestehend, + PKI-Helper)
│   └── boundaries_test.go                     erweitertes Regelwerk
│
├── platform/deploy/
│   ├── ansible/roles/
│   │   ├── zitadel/                           v4, Actions v2, Valkey-Cache
│   │   ├── openfga/                           NEU
│   │   ├── valkey/                            NEU
│   │   └── …                                  (bestehend)
│   ├── terraform/
│   │   ├── modules/
│   │   │   ├── cell/                          NEU: vollständige Zelle
│   │   │   └── …                              (bestehend)
│   │   └── projects/
│   │       ├── identity/                      auf Modul cell umgestellt
│   │       └── …
│   └── monitoring/prometheus/rules/
│       └── identity.yml                       erweitert
│
├── docs/
│   ├── adr/
│   │   ├── 0001-rebac-engine-neben-zitadel.md
│   │   ├── 0002-zellmodell-und-profile.md
│   │   ├── 0003-fga-store-pro-tenant.md
│   │   ├── 0004-zweistufige-autorisierung.md
│   │   ├── 0005-rollen-als-contextual-tuples.md
│   │   ├── 0006-geraete-nicht-im-idp.md
│   │   ├── 0007-bff-und-dpop.md
│   │   ├── 0008-keine-langlebigen-pats.md
│   │   ├── 0009-eine-policy-quelle.md
│   │   ├── 0010-actions-v2-statt-js.md
│   │   ├── 0011-outbox-statt-webhooks.md
│   │   ├── 0012-vier-augen-als-signatur.md
│   │   ├── 0013-soak-window-kryptografisch.md
│   │   ├── 0014-ci-sperre-im-typsystem.md
│   │   ├── 0015-audit-hash-chain.md
│   │   ├── 0016-ausfallmatrix-normativ.md
│   │   ├── 0017-zellwechsel-offline.md
│   │   └── 0018-token-exchange-reifegrad.md   (aus ZIT-06)
│   ├── identity_architecture_ist.md           Ist-Analyse (Bestand)
│   ├── identity_target_architecture.md        Zielarchitektur (Bestand)
│   ├── identity_backlog.md                    dieses Dokument
│   ├── permissions.md                         GENERIERT
│   └── runbooks/
│       ├── break_glass.md                     NEU
│       ├── cell_bootstrap.md                  NEU
│       ├── cell_migration.md                  NEU
│       ├── fga_outage.md                      NEU
│       ├── fga_model_rollback.md              NEU
│       ├── sync_dlq.md                        NEU
│       ├── key_rotation.md                    NEU
│       ├── zitadel_upgrade.md                 NEU
│       ├── audit_verification.md              NEU
│       ├── device_mass_revocation.md          NEU
│       └── …                                  (bestehende Runbooks)
│
└── scripts/
    ├── test-restore-idp-db.sh                 erweitert
    ├── test-restore-fga-db.sh                 NEU
    └── …                                      (bestehend)
```

### 8.1 Erwartete Zeilenverteilung

| Bereich | Heute | Ziel | Bemerkung |
|---|---|---|---|
| `identity/` öffentliche Packages | 14 Packages, viel Logik | 12 Packages, deutlich dünner | Geschäftslogik wandert nach `internal/` und ins Modell |
| `identity/internal/` | — | neu | Sync, SCIM, Zitadel-Client, SAGA, FGA-Admin |
| `policy/` | — | neu | die eigentliche Regelmenge |
| `shared/policy/` | — | generiert | wächst mit dem Katalog, wird nie editiert |
| JavaScript | 14 Actions | 0 | vollständig durch Go-Targets ersetzt |
| Shell-Provisionierung | 3 Skripte | 0 | durch `internal/zitadel/provision.go` ersetzt |

---

## 9. Reihenfolge in einem Satz

Zuerst das Fundament (Principal, Clock, Fehler, lokale Umgebung) und den Zustand aus dem Prozessspeicher — beides ohne Diskussion, weil alles Weitere darauf steht. Dann die Policy-Quelle und die Autorisierungs-Engine parallel zum Zitadel-Neuaufbau, zusammengeführt in einem vertikalen Durchstich über genau eine Permission. Erst wenn dieser Durchstich in der Dev-Zelle läuft, wird in die Breite gebaut: Enforcement, Sync, Zellen. Governance, Audit und Geräte-Identität folgen als eigene Tracks, die auf dem Fundament aufsetzen, aber untereinander unabhängig sind. Der Rückbau kommt zuletzt und vollständig — halb entfernter Altcode ist ein zweiter Enforcement-Pfad und damit gefährlicher als gar kein Umbau.