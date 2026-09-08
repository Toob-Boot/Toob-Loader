# plan7 — Backlog-Durchgang

Stand: 2026-09-04. Jedes Ticket aus plan7 (`T-x.y.z`, `T-10.x`, die Wellen-Nachträge und §13),
gegen den Code geprüft. Drei Zustände:

- **offen** — nichts im Baum löst es.
- **prüfen** — der Code deutet auf erledigt, aber ich habe es nicht bis zum Beweis verfolgt.
- **erledigt** — im Code nachgewiesen oder in plan7 als ✅ markiert. Nur der Vollständigkeit halber
  gelistet, damit die Nummern nicht fehlen.

Die Empfehlung am Ende sortiert die offenen nach dem, was sie blockiert.

---

## A. Offen

### A.1 Login-Pfad und Hooks (Zitadel Actions v2)

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-3.2.1** | Zitadel muss den L3-Claim ausstellen: weder `acr` noch `authenticator_count` setzt die Instanz heute. Ohne das erreicht kein Mensch L3, egal wie viele Passkeys er hat. | Braucht eine Actions-Function (`preaccesstoken`/`preuserinfo`), die die Zahl der registrierten Authenticatoren ins Token schreibt. **Der wichtigste offene Punkt für das Sicherheitsmodell.** |
| **T-3.5.3** | Regeln lesen Felder, die Zitadel nicht schickt. Adapter (`ParseEnvelope`) steht (§10.3-AP); von 18 gelesenen Feldern liefert ein echter Umschlag 3. | Auflösung ist die Triage §10.3-AQ (unten), nicht ein weiterer Adapter. |
| **T-10.3** | Allowlist erlaubter Regeln pro Hook-Typ; der Dispatch liest den Regelnamen noch aus `payload["rule"]`. | Zu messen, welche Methode welche Regel auslöst. |
| **§10.3-AQ** | Die 14 Regeln: **7 löschen** (nativ: 1, 4, 5, 7, 11, 12, 13), **3 löschen** (in unserem Code durchgesetzt: 3, 9, 14), **1 verschieben** (2 an die Registrierung), **1 binden** (8, `AddOrganization`), **2 anreichern** (6, 10). | Löschen setzt einen grünen Deploy voraus, dessen Drift-Detektor gelaufen ist. |
| **§10.3-AO** | Antwortmodus bei Function-Bedingungen messen; `preaccesstoken` feuerte bei Client-Credentials nicht. | Messung. |
| **T-4.4.1** | Der progressive Login-Delay (`RecordLoginFailure`/`Success`) hat keinen Aufrufer. | Zitadel führt den Login; entweder als Hook binden oder löschen. |
| **T-3.3.1** | IDP-052 nicht verdrahtet: `ValidateCustomerIdPAuth` hat keinen Aufrufer. Ein Kunden-IdP ohne phishing-resistentes `amr` müsste vor privilegierten Operationen einen lokalen Passkey erzwingen. | Faktisch heute abgedeckt: ein solches Token ist L1 und kommt an keine L2-Route. Die Funktion ist damit ein Duplikat des Verifiers — löschen oder als Test der Verifier-Eigenschaft umschreiben. |
| **T-5.7.1** | Das Zitadel-Rollenmodell (8 Rollen) hat keinen Konsumenten: der Verifier verwirft `urn:zitadel:iam:org:project:roles`. | Entscheidung: Rollen ins Token bringen und lesen — oder das Projekt-Rollenmodell in Zitadel löschen, weil OpenFGA die Rollen hält. |
| **T-5.7.3** | Drift-Prüfung erkennt nicht referenzierte *Projekte* nicht, nur Rollen. | Klein. |
| **T-5.7.4** | Rollennamen stehen an fünf Stellen im Go-Code. | Schrumpft mit dem Löschen der Regeln. |

### A.2 Autorisierung (OpenFGA)

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-5.6.4** | `CheckPermission` übergibt die Berechtigungs-ID als FGA-Relation (`Relation: p.req.Permission`). Kein Typ definiert eine Relation `fleet.device.list`; die Abbildung Permission→Relation steht im Katalog. | **Prüfen, ob heute alle Aufrufer schon Relationen übergeben** — sonst ist jeder Check außer `explain` falsch. |
| **T-2.5.3** | Typ `rollout` fehlt im FGA-Modell; der Katalog deklariert `fleet.rollout.*` und `release.approval.*` auf `resource: rollout`. | Der Linter prüft Relationen nicht gegen das Modell. Modell ergänzen oder Katalog auf `release`/`channel` umstellen. |
| **T-5.6.3** | Geräte sind im Modell Objekte, keine Subjekte; `ActorDevice` existiert, keine Relation nimmt `[device]` an. | Design. |
| **T-4.6.1 / T-9.1** | `DecisionCache` hat keinen Aufrufer; die Ausfallmatrix verspricht „Reads within decision cache (≤ 30 s) succeed". | Anschließen braucht Invalidierungs-Hooks aus dem Widerrufspfad. |
| **T-6.1.2** | `FilterAuthorizedObjects` hat keinen Produktionsaufrufer (ENF-08). | Braucht eine Listen-Route, die es benutzt. |
| **T-6.1.4** | `ListObjects` ungebaut; der Server kann es (voll qualifiziert). | Entscheidung, ob nötig. |
| **T-6.2.1** | Schattenauswertung (AUTHZ-10) nicht verdrahtet. | |
| **T-6.2.3** | Prometheus-Label `permission` kommt ungeprüft aus dem Request — Kardinalität. | Klein: gegen den Katalog prüfen. |
| **T-10.12 / D5** | OpenFGA dort einbetten, wo Entscheidungen fallen — Registry und Flotte. Heute antworten die Admin-Routen der Registry mit 501, weil niemand `platform#staff` beantworten kann. | **Nächster großer Posten nach dem Login.** |
| **T-3.4.1** | `allowed_actors` je Permission positiv ausdrücken. | Teilweise erledigt: `actor_type` (einer pro Permission) und die `_automated`-Zwillinge. Eine Liste statt eines Werts wäre sauberer. |

### A.3 Registry

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-5.7.2** | `OrgRoleMaintainer` in der Registry; Zitadel und FGA kennen `admin`. Vier Vokabulare, eines weicht ab. | Umbenennen, Migration. |
| **T-5.3.1** | Persönliche Organisation scheitert bei reserviertem Benutzernamen (`support`, `api`). | Produktentscheidung — und `ProvisionPersonalOrganization` hat ohnehin keinen Aufrufer. |
| **T-5.3.3** | `ValidateQuotaAndOrgName` prüft zwei Dinge; auftrennen, wenn der Onboarding-Pfad gebaut wird. | Braucht den Pfad. |
| **T-10.1** | Quote für `POST /tenants` braucht eine Planquelle; identity hat keine. `shared/plan` hat `MaxOrgs`, die Route erzwingt nur den Namen. | |
| **T-10.10** | Der Release-Job hält nicht fest, was er gebaut hat; ohne das kann kein Gate auf ein Artefakt binden. | |
| **T-10.11** | Das Deployability-Gate: Port in der Registry, Klient gegen Identity, fail-closed. | Hängt an T-10.10. |
| **T-10.8** | `requires_signature` hat außer `release.approval.grant` keinen Konsumenten — auch nicht `registry.package.publish`. | Braucht ein Signaturverfahren für API-Klienten; DPoP in der CLI ist ohne IdP-Unterstützung nicht möglich (siehe D). |

### A.4 Sitzungen, DPoP, BFF

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-3.1.1** | BFF-Sessions sind nicht gebunden (kein DPoP/`cnf`); ADR 0007 ist ein Titel. | Der BFF ist ohnehin unmontiert (`NewBFFHandler` nur in Tests). Erst montieren, dann binden. |
| **T-3.1.2** | `require_dpop` im Katalog — heute passiert ein Token ohne `cnf.jkt` das Gate. | Sinnvoll für `fleet.device.delete`, `release.approval.grant`. |
| **T-10.6** | Ein Gruppenwechsel stuft einen bereits angemeldeten Nutzer erst beim Token-Refresh herab; sofort nur per Widerruf. | Designnotiz; Widerruf existiert. |
| **T-2.4.1 / T-2.4.2 / T-4.3.1** | `identity/deviceflow`: kein `TokenIssuer`, kein `slow_down`, kein Ratenlimit auf den Benutzercode. | **Das Paket ist unmontiert; die CLI nutzt Zitadels Device-Grant.** Empfehlung: löschen. |

### A.5 SCIM

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-3.6.5** | PATCH ist Read-Modify-Write ohne Sperre; RFC 7644 §3.14 verlangt `meta.version` + `If-Match`. | |
| **T-4.3.2** | `MemoryEventDeduplicator` ist prozesslokal (`consumer.go:61`), der Konsument aber mehrinstanzlich. | `processed_events`-Tabelle existiert — anschließen. |

### A.6 Audit-Ledger

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-4.1.1** | `AuditRedactor` hat keine Implementierung (nur das Interface in `sync/deletion.go`). | |
| **T-4.2.2** | DSGVO-Löschung gegen ein Append-only-Ledger: Migration 009 entzieht `UPDATE`/`DELETE`, die Pseudonymisierung schreibt um. | Design: eigene, auditierte Redaktionsrolle oder Pseudonymisierung als neuer Eintrag. |
| **T-4.2.3** | Eine Kette pro Aufbewahrungsklasse, sonst blockiert ein permanenter Eintrag jede Archivierung dahinter. | |
| **T-3.7.1** | Nicht-kritische Audits werden „DROPPED (NOT BUFFERED)" — ehrlich, aber ein echter Puffer fehlt. | |
| **T-3.8.6** | Herkunft des Pseudonymisierungsschlüssels aus Vault ist nicht verdrahtet. | |
| **T-10.7** | Checkpoints: Tabelle, Signer-Adapter (`VaultSignerInterface` hat keinen Implementierer), Vault im API-Prozess. | Erst nötig, wenn `retention.go` archiviert — und das ist unmontiert. |

### A.7 PKI und Zellen

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-3.8.2** | `BootstrapInvalidationStore` nur In-Memory; nach jedem Deploy ist jedes Werkszertifikat wieder einlösbar. | Postgres-Store. **Sicherheitsrelevant, sobald Geräte ausgeliefert werden.** |
| **T-3.8.3** | Echte X.509 Name Constraints (O12) — erst mit hostführenden SAN-URIs möglich. | Design. |
| **T-3.8.4** | Kein Edge-Pfad für Operator- und zellweite Workload-Zertifikate. | |
| **T-5.5.2** | `toob:workload:tenant:…` hat einen Erzeuger, aber keinen Produktionsaufrufer. | Benutzen oder löschen. |
| **T-5.8.5** | `ValidateWorkloadClaims` hat keinen Produktionsaufrufer (Token-Exchange-Pfad fehlt). | |
| **T-2.6.1** | `celldir.nomad.hcl` ist weiterhin `PLACEHOLDER` (identity-sync ist geschrieben). | |
| **T-9.4** | Saga-Wiederaufnahme über Prozessneustart ungeprüft — `persistedMap` ist prozesslokal. | Braucht den Postgres-Saga-Store. |
| **T-10.9** | `celldir` trägt zwei Aufgaben (Transaktionsbesitz, Zellmigration) und importiert deshalb `authz`. | Struktur. |

### A.8 Betrieb

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-3.8.1 / P8** | Secrets aus `.env.dev`/`.env.staging` rotieren; sie stehen seit `e26f47d` in der Historie. | **Nur der Betreiber kann das.** Heute dazugekommen: `SEED_GH_CLIENT_ID/SECRET` sind tot (alter OAuth-Login) und können nach der Rotation entfallen. |
| **T-2.6.2** | Die `openfga`-Ansible-Rolle nutzt `vault_root_token` statt AppRole. | |
| **T-6.1.6** | OpenFGA 1.18.3 ist in dev und im Job-Default; ein laufendes Staging/Prod auf 1.5.3 beantwortet `batch-check` mit 404. | Deploy-Reihenfolge. |
| **§10.3-AS** | Zitadel 4.17.1 einziehen, nachdem 4.16.2 vollständig gelaufen ist. | |
| **§10.3-AS** | `identity-sync` verifizieren: Mitgliedschaftsänderung → `Check`, der vorher `denied` sagte. | Messung. |
| **T-7.3** | Rotations-Überlappung (24 h) ist eine Konstante, kein Vertrag: der Empfänger erfährt nichts. | |
| **T-6.4.2** | Unbegrenzte In-Memory-Strukturen: `EventIngestor.seenEvents`, `MemoryEventDeduplicator`, `JITProvisioner.seenFederatedUsers`, `OnboardingSagaEngine.persistedMap`, `CellMigrationEngine.importedStores`, `bff.sessions`, `InMemoryDeviceKillSwitchRegistry`. (DLQ und `MemoryApprovalStore` sind inzwischen in Postgres.) | Antwort ist der persistente Store, nicht Eviction. |
| **T-7.1** | `MemoryLeaderElector` gibt Führung nie zurück. `identity-sync` nutzt inzwischen den Advisory-Lock — die Klasse existiert trotzdem noch. | Löschen, wenn kein Aufrufer. |

### A.9 Fehlerformat und Kleinkram

| Ticket | Inhalt | Anmerkung |
|---|---|---|
| **T-5.2.1** | `ProblemDetails.Instance` wird nirgends gesetzt — die Korrelations-ID gehört hinein. | Klein. |
| **T-5.2.2** | `Title` wiederholt den Maschinencode. | Klein. |
| **T-5.1.1** | ENF-09 (15-%-AuthZ-Latenzbudget) hat keine Implementierung mehr. | |
| **T-5.4.2** | Impersonations-Lebensdauer und Break-Glass-Fenster stehen zufällig beide auf 4 h. | Kosmetik. |
| **P7** | `policy/tests/matrix/expectations.yaml` ist ein leerer Stub. | Füllen oder löschen. |

### A.10 Heute neu benannt (2026-09-04)

| Punkt | Inhalt |
|---|---|
| **P3–P6** | Messungen gegen 4.16.2: Resource-Owner-Claim, IdP-Admin-API und Read-Back, Caddys Register-Sperre gegen den IdP-Callback, Step-Up ohne zweiten Faktor. |
| **Neues Gerät / neuer Standort** | Kein Signal, nirgends. Eigene Target-Route auf einer Session-Bedingung; deren Nutzlast ist zu messen. |
| **Benachrichtigungen** | Passkey hinzugefügt, CI-Token erzeugt, Provider verknüpft — nicht gebaut; was Zitadel nativ mailt, ist zu messen. |
| **DPoP in der CLI** | Setzt voraus, dass der IdP `cnf.jkt` ausstellt. Zitadel unterstützt DPoP nicht → nicht baubar, solange Zitadel der IdP ist. Festzuhalten als Befund, nicht als Aufgabe. |
| **Ratenlimit prozesslokal** | Registry hat kein Valkey; jedes Limit gilt pro Instanz. |

---

## B. Prüfen

| Ticket | Was der Code zeigt |
|---|---|
| **T-2.5.4** | `just validate-policy` existiert; ob es `fga model test` mit den Fixtures ausführt, habe ich nicht verfolgt. Der Seam-Test lädt das Modell echt. |
| **T-2.5.5 / T-2.5.6** | Break-Glass in `api/breakglass.go`; ob Aktivierung und Ledger seit §10.3-AH in einer Mutationsklammer laufen und das `action`-Feld sauber ist, nicht verifiziert. |
| **T-4.1.2** | `anchor_test.go` existiert — ob die Pseudonymisierung damit von Manipulation unterscheidbar ist, nicht verfolgt. |
| **T-4.5.2 / T-4.5.3** | `revocation/cache.go` kommentiert genau diese beiden Fälle; ob `ExpiresAt` für unbestätigte Einträge gesetzt wird, nicht verfolgt. |
| **T-5.6.1** | Vier Modell-Tests (`core/fleet/marketplace/registry_model_test.go`) existieren; ob alle 22 Katalog-Einträge auf existierende Relationen zeigen, hängt an T-2.5.3. |
| **T-9.3** | `celldir/race_test.go` existiert; ob der sporadische Fehlschlag weg ist, zeigt nur `-race` in Wiederholung. |

---

## C. Erledigt

Nachgewiesen im Code oder in plan7 markiert. Nur die Nummer und das Wo.

| Ticket | Wo |
|---|---|
| T-2.4.3 | `deviceflow` Sweep, `store_bounds_test` |
| T-2.4.4, T-2.5.1, T-2.7.2, T-3.1.3, T-3.1.4, T-3.4.2, T-3.6.3, T-3.6.4, T-3.7.2, T-3.8.5, T-3.8.7, T-4.1.3, T-4.1.4, T-4.2.4, T-5.2.3, T-5.5.1, T-5.8.2, T-5.8.4, T-6.1.1, T-6.1.3, T-6.2.4, T-6.4.1, T-9.2, T-9.6, T-9.7 | in plan7 ✅ |
| T-2.5.2 | `authz/breakglass_postgres.go`, Migration 021 |
| T-2.7.1 | `policygen` liest `factor_policy.yaml`; `invite.yaml` ist Regel 7 → nativ |
| T-3.2.2 | `policy/authn.yaml` → `authn_gen.go` |
| T-3.5.1 | §10.3-V Replay-Fenster |
| T-3.5.2 | Migration 016, `api/hooks.go` |
| T-3.6.1 | `scim/postgres.go`, Migration 018 |
| T-3.6.2 | `buildSCIM(scimDB, cfg.cellID, …)` |
| T-3.7.3, T-4.4.3 | `cmd/identity-api/sharedstate.go` (Valkey) |
| T-4.2.1 | `audit/ledger_postgres.go` |
| T-4.4.2, T-4.6.2 | `backend_bounds_test`, `cache_bounds_test` |
| T-4.5.1 | `main.go:351` |
| T-5.1.2 | `cmd/identity-api` montiert die Kette |
| T-5.3.2 | `shared/errors.ErrValidation` |
| T-5.4.1 | `api/impersonation.go` (§10.3-AC) |
| T-5.6.2 | Gruppen→Rolle-Mapping statt `group`-Typ (§10.3-AA) |
| T-5.8.1 | Advisory-Lock in `identity-sync` (§10.3-W) |
| T-5.8.3, T-10.5 | Identity §10.3-Z; **Registry heute** (`PolicyGate.charge`) |
| T-6.1.5 | §10.3-AF |
| T-9.5 | Migrationen 012, 024, 025 |
| T-10.4 | `celldir.InTenantTx` |
| P1–P7 | §10.3-AR |
| §10.3-AS „öffentliche Route" | §10.3-AT, `accounts-<env>` |

---

## D. Empfehlung: Reihenfolge

Sortiert nach dem, was es freischaltet — nicht nach Größe.

1. **Betreiber, heute:** T-3.8.1 / P8 (Secrets rotieren). Alles andere baut auf Credentials, die
   im Git-Verlauf stehen.
2. **Eine Messrunde an der laufenden 4.16.2** (ein Nachmittag): P3–P6, §10.3-AO, T-10.3, ob Zitadel
   `acr` liefert (T-3.2.1), was Zitadel nativ mailt, die Session-Nutzlast fürs Gerätesignal. Danach
   sind acht Tickets entscheidbar statt vermutbar.
3. **Aufräumen, das Sicherheit *erhöht*:** die 10 Regeln löschen (§10.3-AQ), `identity/deviceflow`
   löschen (T-2.4.x, T-4.3.1), `ValidateCustomerIdPAuth` und `MemoryLeaderElector` löschen
   (T-3.3.1, T-7.1). Weniger Code, der etwas *vortäuscht*.
4. **T-3.2.1 — L3 überhaupt erreichbar machen.** Ohne `authenticator_count` im Token gibt es kein
   L3, und damit keine Rollenänderung, keine SCIM-Token, keine Notfallfreigabe.
5. **T-5.6.4 und T-2.5.3 prüfen** — wenn `CheckPermission` wirklich die Permission-ID als
   Relation schickt, ist jede FGA-Entscheidung außer `explain` heute falsch.
6. **T-10.12 / D5 — FGA in der Registry**, damit die Admin-Routen aus dem 501 kommen.
7. **T-3.8.2 vor der ersten Geräteauslieferung.**

Der Rest ist Substanz in der Reihenfolge, in der die Pfade gebaut werden, die ihn brauchen.

---

## E. Login-System: der bereinigte Backlog, und was davon zu hinterfragen ist

Die Tickets oben wurden geschrieben, als Identity noch ein eigener Token-Aussteller werden sollte
und OpenFGA neben Zitadels Rollenmodell stand. Seitdem sind drei Dinge entschieden, die viele
davon verschieben: **Zitadel stellt die Token aus** (die CLI meldet sich direkt dort an),
**OpenFGA ist die einzige Autorisierungsquelle**, und **Social Login als L1-Einstieg** ist der
Produktpfad, mit der Registry-Org als persönlichem Namensraum. Jeder Punkt unten ist gegen diese
drei Tatsachen gehalten.

### E.1 Sieben Fragen, die vor dem nächsten Ticket beantwortet gehören

| # | Frage | Warum sie den Backlog verändert | Empfehlung |
|---|---|---|---|
| **Q1** | **Ist L3 = „zwei registrierte Authenticatoren" die richtige Definition?** | Jede L3-Permission im Katalog trägt *ohnehin* `step_up: true`. Ein zweiter Passkey macht die Sitzung nicht stärker — er macht den Kontoverlust unwahrscheinlicher. Das ist ein Recovery-Argument, kein Assurance-Argument. Und es kostet T-3.2.1: eine Actions-Function, die die Authenticator-Zahl ins Token schreibt, weil Zitadel weder `acr` noch einen Zähler liefert. | **L3 = phishing-resistent + frische Zeremonie (Step-Up).** Den Zähler streichen, `authenticator_count` aus dem Verifier nehmen, T-3.2.1 fällt weg. Das Recovery-Argument gehört ins Onboarding („registriere einen zweiten Passkey"), nicht ins Gate. |
| **Q2** | **Stellt Identity je eigene Token aus, oder bleibt Zitadel der einzige Aussteller?** | Daran hängen fünf Tickets: DPoP am BFF (T-3.1.1), `require_dpop` (T-3.1.2), `requires_signature` auf Publish (T-10.8), DPoP in der CLI, und der unmontierte RFC-8693-Token-Exchange. Zitadel kann kein `cnf.jkt`. Ohne eigenen Aussteller ist DPoP tot; mit einem (Token-Exchange: Zitadel-Token → gebundenes Toob-Token) ist es ein eigener Dienst mit eigenem Schlüsselmaterial. | **Entscheiden, nicht aufschieben.** Meine Einschätzung: kein eigener Aussteller. Der Schutz gegen ein gestohlenes `credentials.json` ist der Step-Up auf den kritischen Routen, den es seit heute gibt; DPoP kauft darüber hinaus wenig und kostet einen Dienst. Dann: T-3.1.2, T-10.8 (für Publish) und ADR 0007 streichen, `token/exchange.go` löschen. |
| **Q3** | **Brauchen wir die Actions-v2-Hooks überhaupt noch?** | Von 14 Regeln bleiben nach §10.3-AQ zwei (Break-Glass-Audit, GitHub-Org-Nachweis). Break-Glass wird seit §10.3-AC über die Governance-API mit Ledger-Eintrag abgewickelt — der Login-Hook dafür ist ein Duplikat. Der GitHub-Org-Nachweis ist ein Enterprise-Feature ohne Kunden. Bleibt: das Gerätesignal (neu) und ggf. Q1. | **Die Hook-Maschinerie auf das schrumpfen, was gemessen gebraucht wird** — realistisch null bis zwei Routen. Dann entfallen T-10.3, die SSRF-Denylist-Entscheidung und das 500-ms-Budget als Dauerthema. Der Target-Handler bleibt als Infrastruktur, die Regeln gehen. |
| **Q4** | **Eine Zitadel-Organisation pro Person?** | `orgs.ProvisionPersonalOrganization` legt pro Registrierung eine Zitadel-Org an (T-5.3.1, T-5.3.3, T-10.1 hängen daran). Zitadel-Orgs sind schwer: Policies, Domains, Rollen, ein FGA-Store pro Tenant. Tausend Selbstregistrierte wären tausend Mandanten. Die Registry-Org ist der persönliche Namensraum, und die funktioniert heute. | **Nein.** Zitadel-Org nur für Enterprise-Mandanten (SCIM, Kunden-IdP). `ProvisionPersonalOrganization` löschen, T-5.3.1 entfällt, T-10.1 wird zur Frage „wer darf einen Enterprise-Mandanten anlegen" — und das ist Vertrieb, kein Selbstservice. |
| **Q5** | **Wozu das Zitadel-Projekt-Rollenmodell (ZIT-02)?** | Acht Rollen in drei Projekten, angelegt und abgeglichen, und der Verifier verwirft sie (T-5.7.1). OpenFGA hält die Rollen (ADR 0001, 0005). Zwei Rollenquellen sind eine zu viel. | **Rollen aus der Provisionierung streichen**, Projekte behalten (das `registry`-Projekt ist die Token-Audience). T-5.7.1, T-5.7.3, T-5.7.4 entfallen. |
| **Q6** | **Wo lebt der BFF?** | `identity/bff` ist fertig und unmontiert. Der Login-Screen entsteht in einem anderen Repository, mit eigenem Server. Ein BFF ist die Rückseite *dieses* Frontends — Cookie-Sitzung, CSRF, Token-Injektion — und gehört dorthin, nicht in `identity-api`, das sonst Sitzungen für eine Anwendung hält, die es nicht kennt. | **BFF ins Frontend-Repository**, `identity/bff` löschen oder als Vorlage dorthin bewegen. T-3.1.1 entfällt (Q2). Bei Identity bleibt: der `accounts`-Host wird vom Frontend-Backend serverseitig angesprochen — dann braucht es kein CORS. |
| **Q7** | **Gibt es lokale Konten außerhalb von Enterprise?** | `AllowRegister: false`, Caddy sperrt Registrierung und Passwort-Reset, `IgnoreUnknownUsernames`. Wer legt ein lokales Konto an? Heute: niemand außer SCIM und Konsole. Mit Social Login als Einstieg ist das lokale Konto ein Enterprise-Artefakt. | **Ja, so lassen — und es aussprechen:** Einstieg = Provider, Passkey = Aufstieg, lokales Konto = SCIM. Dann sind Regel 2 (`dual_authenticator`), T-4.4.1 (Login-Delay) und der Passwort-Komplexitäts-Apparat nur noch für SCIM-Konten relevant. |

### E.2 Der fertige Backlog des Login-Systems

Unter der Annahme, dass die sieben Fragen wie empfohlen beantwortet werden. **Bleibt** heißt: so
bauen. **Umformuliert** heißt: das Ticket beschreibt ein anderes Problem, als es heute gibt.
**Streichen** heißt: durch eine Entscheidung erledigt, nicht durch Arbeit.

| Punkt | Verdikt | Inhalt nach heutigem Stand |
|---|---|---|
| Messungen P3–P6, §10.3-AO | **bleibt** | Resource-Owner-Claim, IdP-Admin-API, Caddy-Sperre vs. IdP-Callback, Step-Up ohne zweiten Faktor (→ Enrollment?), Function-Antwortmodus. Ein Nachmittag, schaltet alles Weitere frei. |
| Passkey-Enrollment als Step-Up-Ziel | **bleibt, neu** | Der Kern der Rampe. Wenn P6 „Ablehnung" ergibt, braucht der Login-Screen einen eigenen Enrollment-Schritt vor der ersten L2-Aktion. |
| Neues-Gerät-Signal | **bleibt, neu** | Eine Target-Route auf einer Session-Bedingung, Fingerprint-Vergleich, Mail. Nutzlast messen. Die einzige Hook-Route, die sicher gebraucht wird. |
| Benachrichtigungen (Passkey, Token, Provider) | **bleibt, neu** | Erst messen, was Zitadel nativ mailt; den Rest über denselben Mail-Pfad. |
| Konto-Verknüpfung aus den Einstellungen | **bleibt** | Passkey-Konto + GitHub, hinter Step-Up. Zitadels Link-API; UI im Frontend. |
| Ratenlimit: Concurrency-Shed + Tenant-Wert | **bleibt** | `load`-Klasse mit Gleichzeitigkeitsgrenze, 503 + `Retry-After`; Tenant-Bucket auf Firmengröße. |
| Registry: Limits prozesslokal → Valkey | **bleibt, klein** | Bei N Instanzen gilt jedes Limit N-mal. |
| T-10.12 / D5: FGA in der Registry | **bleibt** | Admin-Routen aus dem 501; `platform#staff` aus dem Store. |
| T-5.6.4, T-2.5.3 | **bleibt, prüfen zuerst** | Permission-ID als Relation; `rollout` fehlt im Modell. Autorisierung, nicht Login — aber jede Login-Verbesserung ist wertlos, wenn der Check dahinter falsch fragt. |
| Zitadel 4.17.1 | **bleibt** | Native Berechtigungsprüfung bei Passkey-Enrollment-Codes. |
| T-3.8.1 / P8 Secrets | **bleibt, Betreiber** | Rotation; danach `SEED_GH_CLIENT_*` entfernen. |
| T-3.2.1 L3-Claim | **streichen (Q1)** | L3 = L2 + Step-Up. `authenticator_count` aus Verifier und `authn.yaml`. |
| T-10.3, SSRF-Denylist, 500-ms-Budget | **streichen (Q3)** | Mit den Regeln geht die Notwendigkeit. |
| 10 Hook-Regeln, `identity/deviceflow`, `ValidateCustomerIdPAuth`, `MemoryLeaderElector`, T-4.4.1 | **streichen** | Löschen; Aufräumen, das Sicherheit erhöht. |
| T-3.1.1, T-3.1.2, T-10.8 (Publish), CLI-DPoP, `token/exchange.go`, ADR 0007 | **streichen (Q2)** | Ohne eigenen Aussteller kein DPoP. `requires_signature` bleibt nur für `release.approval.grant`, wo es mit einem separaten Schlüssel durchgesetzt wird. |
| `ProvisionPersonalOrganization`, T-5.3.1, T-5.3.3 | **streichen (Q4)** | Persönlicher Namensraum = Registry-Org. |
| T-5.7.1, T-5.7.3, T-5.7.4, Rollen in `PermissionCatalog()` | **streichen (Q5)** | Projekte bleiben, Rollen gehen. |
| `identity/bff`, CORS auf `accounts` | **umformuliert (Q6)** | Ins Frontend-Repository. |
| T-10.1 Tenant-Quote | **umformuliert (Q4)** | „Wer darf einen Enterprise-Mandanten anlegen" — Staff-Permission, kein Plan-Limit. |
| T-10.6 | **umformuliert** | Kein Ticket, eine Zusicherung: Rollenentzug wirkt sofort nur per Widerruf. In die Doku. |
| Regel 8 (`org_name_rules` binden) | **streichen (Q4)** | Zitadel-Orgs entstehen nur über unsere API, die den Namen bereits prüft. |
| Regel 10 (`github_upstream_policy`) | **parken** | Enterprise-Feature „GitHub-Org als Beitrittsnachweis". Kein Kunde, kein Provider mit `read:org`. Erst mit dem ersten Enterprise-Mandanten. |

**Was übrig bleibt, ist kurz:** vier Messungen, drei neue Features (Enrollment-Schritt, Gerätesignal,
Benachrichtigungen), zwei Verdrahtungen (FGA in der Registry, Concurrency-Shed), eine Prüfung
(T-5.6.4) und eine Betreiber-Aufgabe. Alles andere ist Löschen — vorausgesetzt, die sieben Fragen
werden so entschieden. Wird eine anders entschieden, kommt der zugehörige Block zurück, dann mit
einem Grund, den er heute nicht hat.

### E.3 Nachtrag: die Flotte

Identity bedient nicht nur die Registry, sondern das Flottenmanagement (OTA-Rollouts, Kill-Switch,
Freigaben). Das ändert die Richtung der sieben Antworten nicht, aber die Form von zweien:

| Frage | Was die Flotte ändert |
|---|---|
| **Q1** | Bleibt: L3 = phishing-resistent + frische Zeremonie. Die gefährlichen Flottenoperationen werden nicht durch einen zweiten Passkey sicherer, sondern durch **Vier-Augen** (`release.approval.grant`, ADR 0012) und **Aufgabentrennung** (`operator` ≠ `release_manager`, IDP-030) — beides steht im FGA-Modell. Zwei Passkeys werden im Konto **empfohlen und angezeigt** („1 von 2"), als Recovery-Eigenschaft; der Zähler dafür ist Zitadels User-API (`ListAuthenticationMethodTypes`), gelesen vom Konto-Screen, nicht vom Gate. |
| **Q2** | Bleibt: kein eigener Token-Aussteller, kein DPoP. **Aber:** `requires_signature` auf `release.approval.grant` und `admin.killswitch.trigger` setzt heute einen *tokengebundenen* Schlüssel voraus (§10.3-AD: „signed with the key their token is already bound to"). Ohne DPoP hat ein Mensch keinen. Die Signatur ist für die Flotte nicht verzichtbar — eine Freigabe muss nachweisbar von genau dieser Person kommen. Lösung ohne DPoP: **registrierte Operator-Signaturschlüssel** — ein Schlüsselpaar pro Operator, unter L3-Step-Up im Konto hinterlegt (`operator_keys`), die detached JWS wird gegen den hinterlegten öffentlichen Schlüssel geprüft. Signatur wird damit ein Credential-Typ, keine Token-Eigenschaft. Das ist die Form von T-10.8, die bleibt. |
| **Q3** | Eine Hook-Route jetzt (Gerätesignal). Der GitHub-Org-Nachweis (Regel 10) bleibt geparkt — Flottenkunden sind Firmen, und Firmen kommen über SCIM oder ihren IdP in ihren Mandanten; der GitHub-Weg ist die Abkürzung für Firmen ohne IdP und lohnt sich erst mit dem ersten, der danach fragt. |
| **Q4–Q7** | Unverändert. Flottenkunden *sind* Enterprise-Mandanten mit Zitadel-Org; ihre Rollen liegen in `fleet.fga`; ihre Konsole hat ihr eigenes Frontend mit eigenem BFF. |

Was die Flotte **dringender** macht, unabhängig von den Fragen: T-3.8.2 (der Bootstrap-
Invalidierungsspeicher ist In-Memory — nach jedem Deploy ist jedes Werkszertifikat wieder
einlösbar) und der Widerrufspfad für Geräte (`revocation`, Kill-Switch), weil ein Gerät im Feld die
eine Identität ist, die sich nicht per Step-Up neu beweisen kann. Geräte selbst sind über mTLS
(`identity/pki`) bereits schlüsselgebunden — dort ist DPoP nie die Frage gewesen.

### E.4 Umgesetzt (2026-09-07)

Die sieben Fragen sind wie empfohlen entschieden und der Backlog aus E.2/E.3 ist gebaut. Was
jeder Punkt geworden ist, und was bewusst offen bleibt:

| Punkt | Zustand | Wo |
|---|---|---|
| **Q1** L3 → L2 + Step-Up | **fertig.** `TrustLevelL3`, `authenticator_count`, `min_authenticators_for_l3` und der `acr`-Wert `…:l3` sind aus Verifier, Vokabular, Katalog und Linter entfernt; 20 Katalogeinträge stehen auf L2, alle bis auf `admin.breakglass.revoke` mit Step-Up. Zwei Passkeys sind eine Empfehlung des Konto-Screens. | `identity/principal/trustlevel.go`, `identity/token/verifier.go`, `policy/authn.yaml`, `policy/permissions.yaml` |
| **Q2** kein DPoP-Zwang, Operator-Signierschlüssel | **fertig.** `identity/token/exchange.go` gelöscht, ADR 0007/0014/0018 abgelöst. Neu: `identity/signingkey` (Migration 026, RLS), Routen `POST/GET/DELETE /api/v1/tenants/{id}/signing-keys` (Einschreiben unter L2 + Step-Up mit Besitznachweis, Widerruf ohne), `release.approval.grant` prüft die abgelöste Signatur gegen den eingeschriebenen Schlüssel. `requires_signature` nur noch auf `release.approval.grant` und `admin.killswitch.trigger`. | ADR 0019, `identity/api/signingkeys.go`, `identity/api/approval.go` |
| **Q3** Hook-Maschinerie | **fertig.** Die 14 Regeln, `github_policy.go`, `payload.go` und die Adapter in `api/hooks.go` sind gelöscht; die Route trägt ihre Regel selbst (`HookRoute.Evaluate`), die Tabelle ist leer, bis das Gerätesignal gemessen ist. HMAC, Envelope, Budget, Concurrency-Limit und Fail-closed-pro-Route bleiben und sind getestet. Das Target in Zitadel wird weiter adoptiert (Signaturschlüssel in Vault), Executions bindet niemand. | `identity/target/routes.go` |
| **Q4** persönliche Org | **fertig.** `identity/internal/orgs` gelöscht. | — |
| **Q5** Zitadel-Rollen | **fertig.** `PermissionCatalog()` deklariert drei Projekte ohne Rollen; Drift = fehlendes Projekt. | `identity/internal/zitadel/provisioner.go` |
| **D5 / Stage 2 (2026-09-07, zweiter Durchgang)** | **fertig.** Stage 2 ist eine Bibliothek in `identity/enforce` (`RelationGate`), von Identity-API und Registry benutzt; jede Route deklariert ihr Objekt, `VerifyRoutes` prüft es gegen die Katalog-Resource. Die Registry steuert ihre Beziehungen als kontextuelle Tupel bei (`registry/internal/server/relations`), `PolicyEngine` ist gelöscht, die Admin-Routen fragen `platform:global#staff`, gesät von `openfga-provision` aus `STAFF_USER_IDS`. Zwei Routen (Publish, Promote) entscheiden ihr Objekt im Handler und sind als `ObjectDeferred` in der Tabelle sichtbar. | `identity/enforce/relation.go`, `identity/middleware/object.go`, `registry/internal/server/relations/` |
| **Mandanten vereinheitlicht** | **fertig.** Tenant-ID = Zitadel-Organisations-ID in Identity-API (`POST /api/v1/tenants` legt die Org in Zitadel an, Kompensation: deaktivieren), Token, URN, Store und Registry (`api_tokens.tenant_id`, Migration 037; ein CI-Token ohne Tenant wird abgewiesen). `identity/tenant` gelöscht. Offen: der Netzpfad Registry → OpenFGA (Nomad-Service `openfga`, Port 8180 über das private Netz zwischen den Zellen) ist deklariert, aber nicht gegen die laufende Topologie gemessen. | `identity/idp`, `identity/internal/zitadel/organizations.go`, `registry/migrations/037` |
| **Q6** BFF | **fertig.** `identity/bff` und `identity/session` gelöscht; das Muster ist in `identity_login.md` §8 beschrieben und gehört ins Frontend-Repository. | — |
| Löschungen | **fertig.** `identity/deviceflow`, `identity/federation`, `MemoryLeaderElector`. | — |
| Concurrency-Shed + Tenant-Wert | **fertig.** Klasse `load` (256 gleichzeitig pro Prozess) in der Registry vor allen Gates, 503 + `Retry-After` + Code `overloaded`; `write.tenant` 600 → 3000 mit Begründung. | `policy/ratelimits.yaml`, `registry/internal/server/middleware/policy.go` |
| T-5.6.4 | **fertig.** `CheckRequest.Permission` heißt `Relation` — das Feld war immer eine Relation, jeder Aufrufer übergab eine. Explain-Body: `relation` statt `permission`. | `identity/authz` |
| T-2.5.3 | **fertig.** `rollout` gibt es im Modell nicht: `fleet.rollout.*` → `channel#can_deploy`, `release.approval.*` → `release#can_approve` / `can_view`. | `policy/permissions.yaml` |
| Messungen P3–P6, Enrollment-Schritt, Gerätesignal, Benachrichtigungen, Konto-Verknüpfung | **offen** — Frontend und Messung, kein Code in diesem Baum. | |
| D5: FGA in der Registry | **fertig** — siehe die Zeile „D5 / Stage 2" oben; offen bleibt nur die Messung des Netzpfads. | |
| Registry-Limits → Valkey, Zitadel 4.17.1, P8 Secrets | **offen** — Betreiber. | |
| Ableitung `tenant_github_orgs` | **offen** — die Spalte `allowed_github_orgs` bleibt als Mandantenattribut; nichts liest sie auf dem Anmeldepfad, seit Regel 10 geparkt ist. Fällt mit der Entscheidung über den GitHub-Org-Nachweis. | Migration 016 |

Integrationstests (`-tags integration`, `-tags seam`) brauchen eine Datenbank und sind hier nicht
gelaufen; die Unit-Suiten von `identity`, `shared` und `registry` sind grün.
