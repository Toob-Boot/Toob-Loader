# Community-Zelle: private Threads, Team-Login und das eine Rechtesystem

Stand 2026-09-07. Ergänzt [identity_l1_integration.md](identity_l1_integration.md) (der Login) um
die Frage, wer im Forum was sehen und tun darf. Kurzfassung: Zitadel liefert Konten und
Anmeldung, nicht Rechte an Inhalten; das Team wird eine Relation in OpenFGA, kein zweiter Login;
private Threads bleiben eine Regel der Forum-Datenbank.

---

## 1. Was Zitadel mitbringt, und was nicht

| Zitadel kann | Zitadel weiß nicht |
|---|---|
| Konten, Social Login (GitHub, Google), Passkeys, MFA | was ein Thread, ein Ticket, eine Kategorie ist |
| Organisationen mit eigener Login-Policy (`forceMfa`, `passwordless`) | wer ein Ticket eröffnet hat |
| Sessions, Refresh, Logout am IdP | welche Kategorie intern ist |
| Rollen im Token (`accessTokenRoleAssertion`), Benutzer-Metadaten | — |

Die Rollen im Token nutzen wir **absichtlich nicht** als Rechtesystem. Die Plattform hat sich für
ein einziges entschieden, OpenFGA mit Stage 2 (`enforce.RelationGate`), und der Provisionierer
legt seit der Vereinheitlichung keine Zitadel-Rollen mehr an. Ein Forum, das Zitadel-Rollen liest,
wäre die zweite Wahrheit, die wir gerade abgeschafft haben.

## 2. Ist-Zustand des Forums (`toob-infra/community`)

- **Team** ist, wer in einer Organisation aus `FORUM_TEAM_ORG_IDS` ist. Eine Org-Mitgliedschaft
  als Rollenersatz, entschieden beim Login, in der Session als `author_type: team`.
- **Private Support-Threads** (`is_private_support`) sind aus jeder Liste ausgeschlossen. Ein
  Ticket öffnet, wer sein Token hat (`X-Ticket-Token`, gehasht in der DB) oder Team ist.
- **Kategorien** tragen `is_private`, aber die Thread-Abfragen filtern nur `is_private_support`.
  Soweit ich sehe wird eine private Kategorie heute nicht durchgesetzt.
- Es gibt keine Ticket-Liste für das Team. Das Team sieht ein Ticket nur, wenn es die ID kennt.

## 3. Zielbild

Drei Sichtbarkeiten, zwei Rollen, eine Quelle für die Rolle.

| Sichtbarkeit | wer liest | wer schreibt |
|---|---|---|
| öffentlich | alle, auch ohne Login | angemeldet, Gäste bei Tickets |
| privat (Support-Ticket) | Ersteller über Token, Team | Ersteller, Team |
| intern (Kategorie `is_private`) | Team | Team |

| Rolle | Quelle |
|---|---|
| Mitglied | jede angemeldete Person (Token verifiziert, Profil vom IdP) |
| Team | `platform:global#support` oder `platform:global#staff` in OpenFGA |

`support` existiert bereits im Modell (`policy/model/core.fga`, Typ `platform`), neben `staff` und
`security_admin`, und wird bisher von niemandem besetzt. Das ist die Relation für Leute, die
Diskussionen überwachen und Tickets bearbeiten, ohne Plattform-Administration zu dürfen. Besetzt
wird sie wie `staff`: `openfga-provision` aus einer Umgebungsvariable (`SUPPORT_USER_IDS`).

Private Threads und Tickets bleiben **außerhalb** von OpenFGA. Ihre Regel ist „Ersteller oder
Team", und die Forum-DB kennt beide. Ein Tupel pro Thread würde jede Thread-Anlage zu einem
Schreibvorgang in einem anderen System machen, für eine Regel mit zwei Fällen. Sollte es einmal
Moderatoren pro Kategorie geben, ist das der Moment für einen Typ `forum` im Modell
(`category#moderator`), nicht vorher.

## 4. Wie das Forum die Relation fragt

`forum-api` hängt wie die Registry an OpenFGA: `OPENFGA_URL` über Nomad-Service-Discovery, Store-ID
und Schlüssel aus Vault, dieselbe Bibliothek (`enforce.NewRelationGate` über `authz.NewFGAClient`).
Gefragt wird **einmal pro Login und einmal pro Refresh**, nicht pro Request: das Ergebnis steht
als `author_type` in der Session. Damit ist die Latenz zwischen den Zellen egal, und ein Ausfall
des Stores ist ein Login mit `authz_unavailable` und `Retry-After`, wie bei der Registry — kein
stilles „nein", kein stilles „ja".

`FORUM_TEAM_ORG_IDS` entfällt damit. Eine Organisation sagt, wo jemand herkommt; die Relation
sagt, was jemand darf.

Verworfen: ein Endpunkt „meine Relationen" in identity-api. Das wäre eine neue öffentliche Fläche
für eine Frage, die die Stage-2-Bibliothek schon beantwortet, und ein zweiter Netzpfad.

## 5. Team-Login

Es gibt keinen zweiten Login. Dieselbe Seite, dieselbe OIDC-Anwendung `toob-forum-web`; wer nach
dem Login die Relation hält, ist Team. Was den Team-Zugang stärker macht, sind zwei Dinge, die
Zitadel bereits kann:

1. **Eigene Organisation für Toob.** Über identity-api (`POST /api/v1/tenants`) entsteht ein
   Enterprise-Tenant mit eigener Zitadel-Organisation. Für diese Organisation setzt der
   Provisionierer die Login-Policy auf `forceMfa` und `passwordless`: Toob-Leute melden sich mit
   Passkey an, Community-Mitglieder wie bisher.
2. **L2 für Team-Sessions.** Das Token einer Passkey-Anmeldung trägt `amr`; `forum-api` kann für
   eine Session mit `author_type: team` verlangen, dass der Verifier L2 meldet, und sonst die
   Session als Mitglied führen. Das hängt an der offenen Messung P6 (Zitadels `amr`-Vokabular,
   `plan7_backlog.md`); bis dahin bleibt Team L1 mit MFA-Pflicht der Organisation.

## 6. Schritte, in dieser Reihenfolge

| Schritt | Inhalt | Umfang |
|---|---|---|
| S1 | `forum-api` an OpenFGA; Relation `support`/`staff` bei Login und Refresh; `SUPPORT_USER_IDS` im Provisionierer; `FORUM_TEAM_ORG_IDS` weg | Config, Vault-Policy `forum-api.hcl`, Nomad-Template, ~100 Zeilen Go, Doku |
| S2 | private Kategorien durchsetzen: Listen und Lesen nur für Team; Schreiben ebenso | Store-Filter, zwei Handler, Vertrag |
| S3 | Ticket-Liste für das Team mit Status-Filter (`GET /api/v1/support/tickets?status=`), Statuswechsel durch das Team | Handler, Store, Vertrag, Seite |
| S4 | Toob-Organisation mit `forceMfa`/`passwordless`; Provisionierer-Flag für die Org-Policy | Provisionierer, Runbook |
| S5 | L2 für Team-Sessions, sobald P6 gemessen ist | `forum-api`, ~30 Zeilen |

Nicht geplant: ein Typ `forum` in OpenFGA. Erst, wenn jemand Rechte pro Kategorie oder pro Thread
an Personen vergeben soll, die nicht Team sind.

## 7. Offen

- Der Netzpfad `community` → OpenFGA zwischen den Hetzner-Projekten ist so wenig gemessen wie der
  der Registry. S1 ist der Anlass, beide zu messen.
- ~~`email` in der Forum-Session ist immer leer~~ — erledigt: `forum-api` liest Username, Name
  und E-Mail seit §10.114 aus dem Userinfo-Endpunkt des IdP und den Plan aus dem Token-Claim; die
  Registry wird beim Login nicht mehr gefragt.

---

## 8. Umgesetzt (Stand 2026-09-07, abends)

S1 bis S3 sind gebaut; S4 und S5 stehen aus.

**Rechte.** `platform#support` heißt im Modell jetzt `[user] or staff`, der Katalog hat
`community.support.act` (Ressource `platform`, Relation `support`), `openfga-provision` besetzt
die Relation aus `SUPPORT_USER_IDS` (optional; Staff hält sie ohnehin). `forum-api` hängt an
OpenFGA wie die Registry (`OPENFGA_URL` per Nomad-Service-Discovery, Store-ID und Schlüssel aus
Vault) und fragt die Relation über `community/internal/relations` beim Login und bei jedem
Refresh; das Ergebnis ist `author_type` in der Session. `FORUM_TEAM_ORG_IDS` ist weg. Ein Ausfall
des Stores ist ein fehlgeschlagener Login mit `authz_unavailable`, nie ein Login als jemand anderes.

**Arten.** Ein Thread trägt `kind` (`technical`, `billing`, `feedback`, `community`); die Tabelle
in `community/internal/store/kinds.go` sagt pro Art, in welcher Sektion er liegt und welche
Sichtbarkeiten sie zulässt (technical: öffentlich oder privat, billing: nur privat, feedback und
community: öffentlich). Eine fünfte Art ist eine Zeile dort und, falls sie eine eigene Sektion
braucht, eine Kategorie in einer Migration. Das Modal der Seite reicht die Art als `kind` durch;
`feedback` hat jetzt eine eigene Sektion (Migration 003).

**Sichtbarkeit.** Jede Lesestelle bekommt einen `Viewer` (URN, Team). Öffentliche Threads lesen
alle; einen privaten liest sein Autor über die Session oder das Team; eine private Kategorie
(`is_private`) listet, liest und beschreibt nur das Team. Angemeldete Personen können private
Threads eröffnen, ohne Token — die Session ist der Weg zurück; ein Gast eröffnet weiterhin ein
Ticket mit E-Mail und Geheimlink. `GET /api/v1/threads?mine=1` listet die eigenen, private
eingeschlossen.

**Tickets.** Ein Ticket ist der Tracking-Datensatz jedes privaten Threads, auch eines
angemeldeten Autors (dann ohne Token und ohne E-Mail). Neu: `GET /api/v1/support/tickets`
(Team-Inbox mit Status- und Art-Filter), `PATCH /api/v1/support/tickets/{id}` (Ticket-Workflow),
`PATCH /api/v1/threads/{id}` (öffentliches Status-Label, z. B. `planned`/`in_progress` für
Feedback). Eine Antwort verschiebt den Ticket-Status wie bisher.

**Abtasten.** Jede Route, die eine Ticket- oder Thread-ID trägt, antwortet Unbefugten mit `404`,
nie mit `403`: ein falsches Token, eine fremde Session und eine nicht existierende ID sind von
außen dieselbe Antwort. Nur die Inbox-Liste, die keine ID nennt, antwortet ehrlich `403`.

**Noch offen.** Die Team-Inbox als Seite (der API-Client hat `listTickets`, `setTicketStatus`,
`setThreadStatus`); S4 (Toob-Organisation mit `forceMfa`) und S5 (L2 für Team-Sessions); der Netzpfad `community` → OpenFGA ist so
ungemessen wie der der Registry.
