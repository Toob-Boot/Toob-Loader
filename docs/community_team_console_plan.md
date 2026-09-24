# Die Mitarbeiter-Oberfläche des Forums: Arbeitsvorrat, Zuständigkeit, Roadmap

Stand 2026-09-09. Ein Betriebskonzept, kein Bauplan: wie das Team Anfragen aus dem Forum schnell
und nachvollziehbar beantwortet, wie daraus die Roadmap wird, und was die Oberfläche dafür sein
muss. Es baut auf dem, was `toob-infra/community` und `community/web/apps/forum` heute können
(`community_frontend_api_map.md`, `community_authz_plan.md` §9), und nennt am Ende, was fehlt.

---

## 1. Was heute da ist

Das Forum kennt **ein Objekt**: den Thread. Alles andere ist eine Sicht darauf.

| Baustein | Stand |
|---|---|
| Arten (`kinds.go`) | `technical` (öffentlich oder privat), `billing` (nur privat), `feedback` (nur öffentlich), `community` |
| Ticket | der Tracking-Datensatz jedes privaten Threads; Status `open → awaiting_user → staff_replied → resolved → closed` |
| Thread-Status | 11 Werte: `open, awaiting_team, awaiting_response, under_review, planned, in_progress, solved, completed, closed, archived, duplicate` |
| Team-Postfach | `GET /support/tickets` (ohne `mine=1`): alle Tickets, Reihenfolge „was zuletzt bewegt wurde, zuerst“; Filter Status und Art |
| Verlauf | `thread_events` (bisher nur `status_change`), Benachrichtigungen (`reply`, `status_change`) — **nur an den Autor** |
| Roadmap | eine Sicht auf `kind=feedback`, gruppiert nach Status (Under Review / Planned / In Progress / Shipped / Closed) |
| Team | OpenFGA-Relation `platform:global#support` plus Trust Level aus dem Katalog (`community.support.act`, Schalter L1→L2) |
| Team-Werkzeuge | `StatusControl` (Status setzen), private Sektionen (`TeamOnly`), Pin/Lock als Felder ohne Endpunkt |

Was fehlt, ist nicht Technik, sondern **Betrieb**: niemand ist für etwas zuständig, nichts ist
fällig, nichts ist priorisiert, und wer einen Feedback-Thread auf `planned` setzt, erreicht damit
nur seinen Autor — nicht die 40 Leute, die dafür gestimmt haben.

---

## 2. Was die Praxis sagt

Vier Muster tauchen in jedem brauchbaren System auf, egal ob Helpdesk, Issue-Tracker oder Forum:

1. **Ein Postfach, eine Person.** Der häufigste Fehler ist der *Bystander-Effekt*: alle sehen das
   Ticket, keiner nimmt es. Die Gegenmittel sind explizite Übernahme („claim“) beim Triagieren
   oder automatische Zuteilung. Linear macht das mit **Triage** — einem Postfach *vor* dem
   Backlog, in dem jedes neue Issue wartet, bis jemand es annimmt oder ablehnt — und mit einer
   **Triage-Verantwortung** pro Tag (Round-Robin oder „benachrichtige alle“). Discourse macht es
   mit dem **Assign-Plugin**: Zuteilung ist nur für Staff sichtbar, jeder hat eine „mir
   zugeteilt“-Liste, und Zuteilung kann automatisch bei Erwähnung erfolgen.
2. **Fälligkeit statt Reihenfolge.** Priorität ergibt sich aus Dringlichkeit × Wirkung × Alter
   gegen ein Ziel (SLA). Die Kennzahlen, die zählen: Zeit bis zur ersten Antwort, Zeit bis zur
   Lösung, SLA-Einhaltung, Alter des Rückstands, Wiedereröffnungsquote. Ziele werden pro
   Prioritätsstufe gesetzt, nicht global.
3. **Antwort und Zustand sind ein Handgriff.** Gespeicherte Antworten (Makros), interne Notizen,
   und Zustandswechsel, die beim Antworten automatisch passieren. Discourse „Solved“: ein Beitrag
   wird als Lösung markiert, der Thread ist damit erledigt — sichtbar in der Liste.
4. **Feedback → Roadmap → Changelog ist eine Schleife, kein Bord.** Canny, Productboard, UserJot:
   ein Statuswechsel des Feedback-Eintrags *ist* die Roadmap-Änderung, und ein Wechsel auf
   „shipped“ benachrichtigt **alle Abstimmenden** und wird ein Changelog-Eintrag. Duplikate
   werden zusammengeführt, die Stimmen wandern mit.

Ein fünftes, kleineres: eine **„Sonstiges“-Eingangsschale**, die an eine erfahrene Person geht,
damit nichts Unkategorisierbares liegen bleibt — und die Kategorie eingeführt wird, sobald sich
etwas wiederholt.

Quellen: [Linear Triage](https://linear.app/docs/triage), [Linear: CX-Team in Linear](https://linear.app/now/cx-in-linear),
[Discourse Assign](https://www.discourse.org/plugins/assign), [Discourse Solved](https://www.discourse.org/plugins/solved),
[ClearFeed: Ticket Triage](https://clearfeed.ai/blogs/ticket-triage-guide), [Bitrix24: Help Desk Triage That Scales](https://www.bitrix24.com/articles/help-desk-triage-scales-rules.php),
[ITU: Managing Support SLAs](https://www.ituonline.com/blogs/managing-support-slas-best-practices-for-it-support-leaders/),
[Canny: Public roadmap](https://help.canny.io/en/articles/3828148-public-roadmap), [UserJot: Canny vs Productboard](https://userjot.com/blog/canny-vs-productboard).

---

## 3. Die Leitidee: kein zweites System, eine Arbeitsschicht über dem Forum

Drei Wege standen zur Wahl:

| | A. Externes Helpdesk (Plain, Zendesk) | B. Eigene Admin-App | C. Team-Schicht im Forum |
|---|---|---|---|
| Aufwand | klein am Anfang, Sync danach dauerhaft | zweites Frontend, zweiter Vertrag | Felder + eine Seite + eine Leiste |
| Kontext (Plan, Org, Gerät, Verlauf) | geht beim Sync verloren oder muss nachgezogen werden | vorhanden, aber doppelt gebaut | vorhanden, weil es dieselbe Seite ist |
| Öffentliche Fragen | außerhalb des Helpdesks — ein zweites Postfach | möglich | dasselbe Postfach |
| Roadmap-Schleife | getrennt (Canny o. ä. dazu) | eigene Sicht | dieselben Threads, dieselben Status |
| Daten | verlassen die Plattform | bleiben | bleiben |
| Langfristig | zwei Wahrheiten pro Anfrage | zwei Oberflächen für ein Objekt | **eine Wahrheit, eine Oberfläche, zwei Rollen** |

**C** ist die langfristig einzige, die nicht zwei Systeme über ein Objekt legt. Das Team sieht
genau die Seite, die der Nutzer sieht — plus eine Leiste, die nur die Relation `support` bekommt.
Die Oberfläche ist damit eine *Variante des Bestehenden*: die Discussions-Liste wird zum
Arbeitsvorrat, die Thread-Seite bekommt einen Arbeitsplatz am rechten Rand, die Roadmap bleibt,
was sie ist — eine Sicht auf Status.

Alles, was das Team tut, ist ein Event am Thread. Das ist zugleich Audit-Log, Zeitlinie für den
Nutzer (wo sichtbar), und Datenquelle für jede Kennzahl. Keine zweite Tabelle für Metriken.

---

## 4. Der Arbeitsvorrat (`/support` für das Team)

### 4.1 Was hinein gehört

Der Vorrat ist nicht „alle Tickets“, sondern **alles, wo das Team am Zug ist**:

- private Threads (Tickets) in `open` oder `awaiting_team`;
- öffentliche `technical`-Fragen ohne Team-Antwort (Status `open`/`awaiting_team`);
- `feedback` in `under_review`, das älter als der Prüfzyklus ist (§6.3);
- später: gemeldete Beiträge (Flag `reporting` existiert im Frontend, kein Endpunkt).

Ein Thread, der auf den Nutzer wartet (`awaiting_response` / `awaiting_user`), ist **nicht** im
Vorrat. Er kommt zurück, wenn der Nutzer schreibt — automatisch (§5.3). Damit ist der Vorrat
leer, wenn das Team fertig ist. Das ist der einzige Zustand, der sich gut anfühlt.

### 4.2 Reihenfolge: fällig zuerst, und der Grund steht dran

Die Sortierung ist eine Funktion, nicht ein Feld — berechnet im Backend, damit Liste und Zähler
dasselbe sagen:

```
Fälligkeit = awaiting_since + Ziel(Stufe)
Stufe      = max(Art, Sichtbarkeit, Plan, Eskalation)
```

| Stufe | Wann | Ziel erste Antwort | Ziel Lösung |
|---|---|---|---|
| P1 | `billing`; `enterprise`-Plan; manuell eskaliert | 4 h | 1 Werktag |
| P2 | privates `technical`; bezahlter Plan | 1 Werktag | 3 Werktage |
| P3 | öffentliches `technical`, `community` | 3 Werktage | bester Wille |
| — | `feedback` | kein Antwortziel; Prüfzyklus (§6.3) | — |

Die Ziele sind **interne** Ziele, keine Vertragszusagen — sie werden im Katalog gepflegt
(`policy/`, wie die Rate-Limit-Klassen), nicht im Code. Jede Zeile im Vorrat zeigt „fällig in 2 h“
oder „überfällig seit 1 d“ — die Zahl, nicht die Stufe, ist die Priorität. Upvotes brechen
Gleichstände innerhalb einer Stufe.

Manuelle Priorität gibt es nur als **eine** Flagge: *eskaliert*. Kein freies Prioritätsfeld —
das wird in kleinen Teams zur Meinungsäußerung, nicht zur Steuerung.

### 4.3 Zuständigkeit

- **Übernehmen (claim)**: ein Klick, oder automatisch bei der ersten Team-Antwort. Wer antwortet,
  hat es — Discourse' „assign by mention“, ohne Erwähnung.
- **Triage-Dienst**: eine Person pro Tag ist für *Unzugeteilt* verantwortlich (Linears Triage
  responsibility). Kein Round-Robin am Anfang — bei zwei bis fünf Leuten ist ein Dienstplan
  ehrlicher als ein Zufallsgenerator. Der Dienst steht als Konfiguration, nicht in der DB.
- **Sichtbarkeit**: Zuteilung ist nur für das Team sichtbar (wie bei Discourse). Der Nutzer sieht
  „das Team antwortet“, nicht wen.
- **Abgeben**: Zuteilung wechseln ist ein Event mit Kommentar (interne Notiz). Damit weiß die
  nächste Person, warum sie es hat.

### 4.4 Gespeicherte Sichten

Keine freie Filterkombination als Feature — fünf Tabs, die das Team tatsächlich braucht:

| Sicht | Inhalt |
|---|---|
| **Mein Schreibtisch** | mir zugeteilt, fällig zuerst |
| **Unzugeteilt** | niemandem zugeteilt — die Triage-Sicht |
| **Fällig** | alles überfällig oder in < 4 h fällig, egal wem |
| **Wartet auf Nutzer** | `awaiting_response`/`awaiting_user` — nur zum Nachsehen, nicht im Zähler |
| **Roadmap-Rückstand** | `feedback` in `under_review`, nach gewichteten Stimmen |

Der Sidebar-Zähler zeigt *Mein Schreibtisch + Unzugeteilt fällig*. Das ist die eine Zahl, die
morgens zählt.

---

## 5. Der Arbeitsplatz am Thread

Die Thread-Seite bleibt die Thread-Seite. Das Team bekommt rechts eine Leiste, und die Antwort-
Box drei Dinge mehr.

### 5.1 Die Leiste

- **Zuständig** (Übernehmen / Abgeben), **Status**, **Fälligkeit** als Uhr;
- **Wer fragt**: Plan, Org, Anmeldeart, Geräteziel (`mcu_target`), *und die anderen Threads dieser
  Person* — die Hälfte aller Rückfragen erübrigt sich, wenn man sieht, dass dieselbe Frage
  letzte Woche schon einmal gestellt wurde;
- **Verknüpfungen**: Duplikat von …, Feedback-Thread dazu, Lösung (Beitrag);
- **Interne Notizen**: Beiträge mit Sichtbarkeit `team` in derselben Zeitlinie, optisch abgesetzt.
  Kein zweiter Kanal — die Notiz steht dort, wo die Antwort steht.

### 5.2 Die Antwort

- **Gespeicherte Antworten**: ein Picker über der Box (`/` oder Tastenkürzel), Text mit
  Platzhaltern (`{name}`, `{mcu}`), teamweit gepflegt, im Forum selbst editierbar. Das ist das
  Werkzeug, das Antwortzeit halbiert — mehr als jede Sortierung.
- **Antworten & …**: der Senden-Knopf hat einen Zustand dabei. Standard „Antworten & auf Nutzer
  warten“; Alternativen „Antworten & lösen“, „Antworten & schließen“. Ein Handgriff, zwei Events.
  *Überholt (§11): gebaut und wieder entfernt, seit der Statuswechsel bestätigt wird. Den
  Standardfall — die Antwort gibt den Zug weiter — macht ohnehin das Backend (§5.3).*
- **Als Lösung markieren** am Beitrag: setzt `solved`, merkt sich den Beitrag
  (`solution_post_id`), zeigt ihn oben im Thread an. Für öffentliche Fragen ist das der
  Wissensspeicher — die nächste Suche findet die Antwort, nicht die Frage.

### 5.3 Automatische Übergänge

Der Status ist zu wichtig, um ihn dem Gedächtnis zu überlassen:

| Ereignis | Übergang |
|---|---|
| Team antwortet | `open`/`awaiting_team` → `awaiting_response` (Ticket: `staff_replied`) |
| Nutzer antwortet | `awaiting_response` → `awaiting_team` (Ticket: `open`) |
| Nutzer antwortet auf `solved`/`resolved` | → `awaiting_team` (Wiedereröffnung — zählt als Kennzahl) |
| 14 Tage `awaiting_response` ohne Antwort | → `closed`, mit Benachrichtigung „wir haben geschlossen, antworte, um wieder zu öffnen“ |

Manuelle Statuswechsel bleiben möglich; sie überstimmen die Automatik nie dauerhaft — das
nächste Ereignis gilt wieder.

---

## 6. Das Betriebskonzept: drei Schleifen, ein Objekt

```
   Support-Schleife          Community-Schleife          Produkt-Schleife
   privat, 1:1               öffentlich, 1:n             öffentlich, n:1

   Ticket ──► Antwort         Frage ──► Antwort            Feedback ──► under_review
     ▲          │               │         │                   ▲            │
     └──────────┘               ▼         ▼                   │            ▼
   awaiting_* wechselt        solved = Lösung              Stimmen      planned
   automatisch (§5.3)         (Wissensspeicher)          (gewichtet)      │
                                                              ▲            ▼
     „weiterleiten“ ──────────────────────────────────────────┘        in_progress
     (Ticket/Frage → Feedback verknüpfen oder anlegen)                      │
                                                                            ▼
                                                    completed ──► alle Abstimmenden
                                                                  + Changelog-Eintrag
```

### 6.1 Support → Produkt: weiterleiten statt abschreiben

Aus jedem Ticket und jeder Frage kann das Team **„als Feedback weiterleiten“**: entweder einen
bestehenden Feedback-Thread verknüpfen oder einen neuen anlegen (öffentlich, ohne private
Details — der Text wird vom Team geschrieben, nicht kopiert). Der Autor des Tickets wird
Teilnehmer des Feedback-Threads und stimmt implizit dafür. Das Ticket kann dann ehrlich
geschlossen werden: „Das ist ein Feature, hier verfolgst du es.“ Ohne diesen Handgriff sammelt
das Team Wünsche in Köpfen.

### 6.2 Duplikate: zusammenführen, Stimmen mitnehmen

`duplicate` existiert als Status, aber ohne Ziel. Mit `duplicate_of` wird der Thread auf das
Original umgeleitet, seine Stimmen zählen dort (ohne Doppelzählung pro Person), seine Teilnehmer
bekommen die Status-Benachrichtigungen des Originals. Das ist Cannys „merge“ — und das, was
eine Roadmap-Liste von 200 auf 40 Einträge bringt.

### 6.3 Roadmap-Pflege: ein wöchentlicher Termin, keine Dauerbaustelle

- **Täglich** (Triage-Dienst): Unzugeteilt leeren, neue `feedback`-Threads kurz einordnen —
  Duplikat? Klar genug? Dann bleibt es `open`; das Team setzt `under_review`, sobald es wirklich
  geprüft wird. `open` heißt „gesehen, noch nicht bewertet“ — ehrlicher als ein Bord, auf dem
  alles „under review“ ist.
- **Wöchentlich** (Roadmap-Review, 30 min): die Sicht *Roadmap-Rückstand*, sortiert nach
  gewichteten Stimmen (Stimme × Plan-Gewicht, z. B. free 1 / paid 3 / enterprise 10 — Gewichte im
  Katalog). Pro Eintrag eine Entscheidung: `planned`, `closed` mit Begründung, oder bleibt.
- **Statuswechsel auf der Roadmap brauchen einen Satz.** `planned`, `in_progress`, `completed`,
  `closed` ohne Kommentar werden abgelehnt (Backend). Der Satz ist die Benachrichtigung — nicht
  ein Badge, das sich ändert.
- **Benachrichtigung an alle Abstimmenden und Teilnehmer**, nicht nur den Autor. Das ist die
  einzige Änderung, die aus der Roadmap ein Versprechen macht.
- **`completed` ist der Changelog.** Ein Wechsel auf `completed` legt (oder verknüpft) einen
  Beitrag in *Announcements* an; die Roadmap-Spalte „Shipped“ und der Announcement-Thread
  sind derselbe Datensatz aus zwei Richtungen.

### 6.4 Wer darf was

Am Anfang **eine** Team-Relation (`platform#support`), L2 (Passkey) für jede Team-Handlung — der
Schalter ist gebaut. Zwei Dinge sind trotzdem heute schon zu trennen, weil sie sich nachträglich
schlecht trennen lassen:

- **Roadmap-Status** (`planned`, `in_progress`, `completed`) sind Produkt-Entscheidungen. Sie
  bekommen ein eigenes Permission-Objekt im Katalog (`community.roadmap.decide`), das vorerst
  dieselbe Relation trägt. Wenn später Support und Produkt verschiedene Leute sind, ändert sich
  eine Zeile in `permissions.yaml`, nicht der Code.
- **Gespeicherte Antworten pflegen** ist Team, nicht Person — ohne Besitz, mit Verlauf.

Jede Team-Handlung ist ein Event mit Akteur. Das ist das Audit-Log; ein zweites braucht es nicht.

### 6.5 Kennzahlen — aus Events, nicht aus Zählern

Fünf, mehr nicht, alle aus `thread_events` ableitbar, sobald Team-Antworten und Zuteilungen
Events sind:

| Kennzahl | Quelle |
|---|---|
| Zeit bis erste Team-Antwort (Median, P90) je Stufe | `created_at` → erstes `reply` mit `actor_type=team` |
| Zeit bis Lösung | `created_at` → `solved`/`resolved` |
| SLA-Einhaltung | Anteil der ersten Antworten vor Fälligkeit |
| Rückstandsalter | Alter des ältesten Eintrags im Vorrat |
| Wiedereröffnung | `solved` → `awaiting_team` innerhalb 14 d |

Eine Seite `/support/metrics`, Team-only, mit Wochenverlauf. Kein Dashboard-Tool daneben.

---

## 7. Was das Backend dafür braucht

In der Reihenfolge, in der es Wirkung hat. Jede Zeile ist ein eigener, kleiner Schritt mit
Vertrag (`openapi.yaml`), Migration und Test.

| # | Änderung | Wo |
|---|---|---|
| 1 | `threads.assignee_urn`; `PATCH /threads/{id}` nimmt `assignee` („me“ / leer); Event `assigned`; Listing-Filter `assigned=me\|none` | store, api, Migration 011 |
| 2 | Event `reply` mit `actor_type` (jede Antwort ist ein Event) — damit sind erste Antwort und Fälligkeit ableitbar | `CreatePost` |
| 3 | Automatische Übergänge (§5.3) in `CreatePost`; Sweep für die 14-Tage-Schließung neben `SweepViews` | store, `forum-api/main.go` |
| 4 | `GET /support/queue`: Tickets **und** öffentliche Threads, wo das Team am Zug ist; liefert `due_at`, `tier`, `assignee`; die fünf Sichten sind Filter darauf | api, `policy/support_targets.yaml` (Ziele, Gewichte) |
| 5 | Beiträge mit `visibility=team` (interne Notizen) — `reach` kennt `teamOnly` bereits, nur pro Post statt pro Sektion | store, Migration |
| 6 | `saved_replies` (Team-CRUD, Verlauf über `updated_by`) | store, api |
| 7 | `threads.solution_post_id`; `PATCH /posts/{id}` mit `solution=true` setzt `solved` | store, api |
| 8 | `threads.duplicate_of`; Stimmen und Benachrichtigungen werden umgeleitet | store |
| 9 | Status-Benachrichtigung an Abstimmende + Teilnehmer; Kommentar-Pflicht bei Roadmap-Status; `completed` legt Announcement an | `SetThreadStatus`, notifications |
| 10 | `GET /support/people/{urn}`: Plan, Org, Anmeldeart, letzte Threads — die Kontextkarte | api |
| 11 | `community.roadmap.decide` im Katalog; `setThreadStatus` prüft es für Roadmap-Status | `permissions.yaml`, api |
| 12 | `GET /support/metrics` aus Events | api |

Nicht dabei, bewusst: Round-Robin, Bulk-Aktionen, Slack-Anbindung, KI-Vorschläge. Alles davon
kann später auf die Events aufsetzen; nichts davon macht die erste Antwort schneller.

## 8. Was das Frontend dafür braucht

- `/support` verzweigt nach `author_type`: Nutzer sehen ihre Tickets (heute), das Team den
  Arbeitsvorrat mit den fünf Tabs — dieselbe `ThreadRow`, plus Fälligkeit und Zuständigkeit.
- Thread- und Ticket-Seite: die Team-Leiste (§5.1) als eine Komponente, die beide Seiten
  einbinden; `StatusControl` wird Teil davon.
- Antwort-Box: Notiz-Umschalter und Picker für gespeicherte Antworten. Kein Status am
  Senden-Knopf (§11): der Status wechselt an einer Stelle, und die fragt vorher.
- Roadmap: unverändert in der Sicht, aber Statuswechsel mit Pflichtkommentar und der Spalte
  „Shipped“ als Link auf den Announcement-Beitrag.
- Sidebar-Zähler: Team sieht den Vorrat, Nutzer die Benachrichtigungen.
- UI-Paket: `DueBadge` (Fälligkeit), `AssigneeControl`, `SavedReplyPicker` — drei Bausteine, die
  sonst nirgends existieren; alles andere gibt es.

## 9. Reihenfolge

1. **Antworten wird schnell** (#1–#4, Frontend Vorrat + Übernehmen + Automatik). Das ist der
   messbare Gewinn — danach gibt es eine Zahl, an der sich alles Weitere misst.
2. **Antworten wird gut** (#5–#7: Notizen, gespeicherte Antworten, Lösung markieren).
3. **Die Roadmap wird ein Versprechen** (#8, #9, #11: Duplikate, alle benachrichtigen,
   Kommentarpflicht, Changelog, Rechte).
4. **Das Team sieht sich selbst** (#10, #12: Kontextkarte, Kennzahlen).

Jeder Schritt ist für sich nützlich und abschaltbar; keiner setzt einen späteren voraus.

---

## 10. Umgesetzt (Stand 2026-09-09, abends)

Phase 1 ganz, von Phase 2 die internen Notizen:

- **Backend** (`community`): Migration 011 (`assignee_urn`, `escalated`, `awaiting_since`,
  `due_at`, `tier` am Thread; `team_only` am Post; Event-Arten `assigned`, `priority` mit
  `detail`); `store/desk.go` mit `teamsTurn`, `tierOf`, `nextStatus`, `settle`, `Desk` (fünf
  Sichten, Seek-Cursor, Zähler in jeder Antwort), `UpdateThread`; automatische Übergänge in
  `CreatePost`; Ticket-Status spiegelt sich in den Thread-Status (`threadStatusOfTicket`);
  `Events` für das Team vollständig, für alle anderen nur Statuswechsel; `personalize` blendet
  die Schreibtisch-Felder für Nicht-Team aus. Routen: `GET /support/desk`, `PATCH /threads/{id}`
  (Status, Zuteilung, Eskalation), `team_only` an `POST …/posts`. Anmeldung:
  `GET /api/auth/login?level=L2` fragt den Provider per `acr_values` nach dem Passkey — dem
  Wert, den `policy/authn.yaml` auf L2 abbildet, damit Anfrage und Verifikation dasselbe meinen.
- **Vertrag** (`community/web/openapi.yaml`): `DeskView`, `DeskCounts`, `DeskPage`,
  `UpdateThreadRequest`, die Team-Felder am `Thread`, `team_only` an `Post` und
  `CreatePostRequest`, `ThreadEvent` mit drei Arten und `detail`, `level` an `/api/auth/login`.
- **Frontend** (`apps/forum`): `/support` als Schreibtisch mit den fünf Tabs und Zählern
  (`DeskClientView`), `useDesk` (ein Hook für Seite und Sidebar-Zähler, `notifyDeskChanged`
  hält beide gleich; die letzte Antwort bleibt beim Sichtwechsel stehen, damit nur die Karten
  wechseln). Am Thread und am Ticket **eine** Zeile im Kopf des Eröffnungsbeitrags: Status,
  Fälligkeit, Zuständigkeit, Übernehmen, Eskalieren (`StatusControl` + `TeamDeskBar`); der Plan
  des Fragenden als Tag hinter dessen Namen. `StatusControl` ist der farbige Badge als Auslöser
  eines Menüs, das zu jedem Status sagt, was er bedeutet, und **vor** dem Wechsel fragt.
  `DueBadge` auf jeder Karte mit `due_at`, `ComposerModeSwitch` (Antwort oder interne Notiz),
  Notizen im Verlauf abgesetzt, `ThreadEventRow` für alle drei Event-Arten, Sidebar-Abschnitt
  „Team“ mit offener Zahl, Login-Knopf „Team sign-in with passkey“ (im Mock-Build die simulierte
  Team-Sitzung). Ziele der Stufen stehen als Tabelle in `store/desk.go`, mit `TODO(policy)` für
  den Umzug in den Katalog.

Am 2026-09-16 kam Migration 012 dazu, aus einer Prüfung des Protokolls heraus:

- **Eine private Konversation hat wieder einen Zustand.** `agreeOnTicket` hält Ticket- und
  Thread-Status in `settle` zusammen, in beide Richtungen. Vorher spiegelte nur eine, und eine
  Antwort setzte den Ticket-Status bedingungslos: ein geschlossener Thread konnte ein offenes
  Ticket tragen.
- **Zurückziehen statt Löschen.** `DELETE /posts/{id}` leert die Worte und lässt die Zeile stehen,
  damit die Antworten darunter lesbar bleiben. Der Eröffnungsbeitrag geht nicht; ein Thread wird
  mit einem Status beendet.
- **Die Bearbeitung fremder Worte hat einen Akteur.** `edited_by_name` am Beitrag und ein
  `moderated`-Ereignis am Thread. Damit ist §6.4 wieder wahr: jede Team-Handlung ist ein Ereignis
  mit Akteur.
- **Anheften, Sperren und das Duplikat-Ziel** (#8) sind drei weitere Felder an `PATCH
  /threads/{id}`, keine neuen Routen. Stimmenwanderung bei Duplikaten bleibt offen.
- Dazu drei Vertragsfehler: `bounty` raus, `sort` als 400 statt 500, `detail` ohne `omitempty`.

Noch nicht gebaut (Plan §7): Triage-Dienst, 14-Tage-Schließung (#3, Sweep), gespeicherte
Antworten (#6), Lösungs-Beitrag (#7), Benachrichtigung an Abstimmende und Kommentarpflicht (#9),
Kontextkarte (#10), `community.roadmap.decide` (#11), Kennzahlen (#12). Die Ziele der Stufen sind
Stunden, keine Werktage.

## 11. Abgewogen und verworfen

- **„Antworten & lösen/schließen“ am Senden-Knopf** (§5.2, kurz gebaut, wieder entfernt): Ein
  Statuswechsel wird seit der Bestätigung bewusst gefragt, weil er in die Historie geschrieben
  und im Postfach des Autors gelesen wird. Ein Senden-Knopf, der denselben Wechsel als
  Nebenwirkung ausführt, ist der eine Weg um diese Frage herum — und er tat zwei Dinge in zwei
  Anfragen, von denen die zweite scheitern konnte, nachdem die erste geschrieben war. Was eine
  Antwort ohnehin bedeutet, macht das Backend selbst (§5.3); alles darüber hinaus gehört an den
  Status und damit an eine Frage.

- **Externes Helpdesk anbinden** (Plain, Zendesk): schnell da, aber ab dem ersten Tag zwei
  Wahrheiten pro Anfrage, und die öffentlichen Fragen — die Hälfte der Arbeit — bleiben draußen.
- **Prioritätsfeld** (P1–P4 von Hand): in kleinen Teams zur Meinung verkommen; die berechnete
  Fälligkeit mit einer Eskalations-Flagge sagt dasselbe und stimmt immer.
- **Round-Robin-Zuteilung**: fair auf dem Papier, unfair bei unterschiedlicher Verfügbarkeit;
  Dienstplan + Übernehmen ist bei < 10 Leuten ehrlicher.
- **Getrennte Roadmap-Datenhaltung** (eigene Tabelle „Roadmap-Items“): dann sind Feedback und
  Roadmap-Eintrag zwei Dinge, die auseinanderlaufen. Der Feedback-Thread *ist* das Item.
- **Kennzahlen als eigene Zähler-Spalten**: driften; Events sind schon da und lügen nicht.
- **Auto-Antworten / KI-Entwürfe**: nach #6, wenn es gespeicherte Antworten gibt, aus denen ein
  Vorschlag gebaut werden kann — vorher gibt es nichts, worauf es aufsetzen könnte.
