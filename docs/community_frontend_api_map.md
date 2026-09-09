# Das Forum-Frontend: was es zeigt, was es braucht, was fehlt

Stand 2026-09-08. Eine Bestandsaufnahme der Forum-App (`toob-infra/community/web/apps/forum`)
gegen ihr Backend (`toob-infra/community`): welche Komponenten genutzt werden, welchen Aufruf
jede Seite macht, welche Felder sie davon anfasst — und welche Dinge die Oberfläche zeigt, für
die es bis heute keine Datenquelle gibt.

Der Vertrag ist `community/web/openapi.yaml` — er liegt im Frontend-Repository, damit die Seite
ihn selbst ändern kann; `TestRoutes_AreTheContracts` hält die Routen des Backends dagegen. Wie
dieser Kreislauf gemeint ist, steht dort daneben in `community/web/API.md`. Dieses Dokument ist
die Ebene darüber: es sagt, warum die Fläche so aussieht.

---

## 1. Was sich beim Aufräumen herausgestellt hat

Vier Befunde, die keine Meinungssache sind:

**Der Client hat bei jedem Fehler Mock-Daten zurückgegeben.** Jeder Aufruf in `lib/api.ts` war in
ein `try/catch` gehüllt, dessen `catch` erfundene Threads lieferte. Ein Backend-Ausfall sah damit
aus wie ein gut besuchtes Forum. Ebenso beim Schreiben: eine fehlgeschlagene Thread-Anlage
navigierte auf einen lokal erfundenen Thread, eine fehlgeschlagene Antwort hängte einen Beitrag
an, den niemand je erhalten hatte. Beides ist ersetzt: `real` wirft, `mock` ist ein bewusster
Schalter, und Schreibfehler stehen als Meldung im Formular.

**Der Browser hat gefiltert, sortiert und Daten erfunden.** `enrichThread` hat für jeden Thread
ohne Status einen erfunden (`reply_count > 2` → „in progress"), Teilnehmer aus einer festen Liste
mit den Namen „Markus E." und „Elena Rostova" ergänzt und Upvotes aus der Antwortzahl gerechnet.
Die Tabs waren ein zweiter Satz Filterregeln über Kategorie-Slugs, der von den Sektionen des
Backends abgewichen war. Das ist alles weg: das Backend liefert Teilnehmer und Upvotes, der Tab
ist eine Art (`kind`), und die Ansicht zeigt, was kommt.

**Serverseitige Aufrufe trugen kein Session-Cookie.** Die Seiten rendern auf dem Server und haben
dort ohne Zutun keinen Cookie. Jede serverseitig gerenderte Liste war damit die anonyme — keine
privaten Threads, keine Team-Sektionen, keine Vote-Markierungen — und änderte sich erst nach der
Hydration. Behoben mit `lib/serverApi.ts`, das den eingehenden Cookie weiterreicht.

**Upvotes lebten nur im Browser.** Ein Klick erhöhte eine Zahl im Zustand; nach dem Neuladen war
er weg. Jetzt sind es Zeilen in der Datenbank, eine pro Person und Thread bzw. Beitrag.

Dazu kam Debug-Werk in Produktionscode: `?test_attachments=1` füllte das Formular mit einem
erfundenen ESP32-Fall. Entfernt.

## 2. Komponenten

Vier Komponenten hatten keinen einzigen Importeur und sind gelöscht: `CategorySidebar`,
`ForumHeader`, `QuickAccessBox`, `ThreadFilterSwitch`. Dazu `BountiesClientView` samt CSS, dessen
Seite seit einiger Zeit nur noch auf `/discussions` weiterleitet.

Alle verbleibenden Komponenten haben mindestens einen Importeur. Die drei, die überall
auftauchen: `StationSidebar` (9 Seiten), `ThreadCard` (6), `StationHeader` (5).

**Stand 2026-09-09, nach dem Refactoring.** Was zwei Detailseiten doppelt hatten, ist ein Satz
Bausteine unter `components/`: `PostHeader` (Autor, Zeit, „edited", Rollen-Pille),
`PostActionsMenu` (Bearbeiten/Zitieren, Link kopieren, Text kopieren, Melden hinter Flag),
`InlinePostEditor` (Bearbeiten an Ort und Stelle, mit Secret-Prüfung), `StatusChangeRow` (ein
Statuswechsel in der Konversation), `VoteButton` (Hochstimmen, vom Backend bestätigt) und ein
`StatusBadge`, der das Vokabular des Forums (`lib/status.tsx`) auf den `StatusBadge` des
Packages abbildet. Die Zustandslogik dahinter sind Hooks in `lib/`: `useVote`, `useInlineEdit`,
`useReactions` (Flag), `useNotifications`, `useTickets`, `useThreads`. Gelöscht, weil das Package
sie hat: `UserAvatar` (→ `UserBadge`), `TicketStatusBadge`, die Forum-Kopie von
`PixelDataStreams`, der Re-Export `PixelArrow`.

`@toob/ui` exportiert 20 Module; `packages/ui/INDEX.md` beschreibt jedes mit Props, Varianten
und Defaults. Neu darin: `StatusBadge` (Töne statt Vokabular), `PixelDataStreams`, das
Token-Blatt `tokens.css`, das beide Apps in ihrem Layout einbinden. Weg: `Accordion` (kein
Importeur; die Website hat ein eigenes `SafetyAccordion`), die Aliase `Tabs` und
`CategoryPills`, die Altnamen `showClear`/`showKbd` der `SearchBar`.

Was die Seite kennt und das Backend nicht speichert, steht hinter Feature-Flags
(`lib/flags.ts`, `NEXT_PUBLIC_FLAGS`): Reaktionen, Folgen, Melden. Vorschau-Zustände zum
Anschauen (`?preview=upload_error,quote`, `lib/preview.ts`) gibt es nur in einem Build mit
`NEXT_PUBLIC_PREVIEW=1`; die `?test_*`-Parameter in den Komponenten sind weg. Und
`NEXT_PUBLIC_BACKEND_MODE` hat keinen Default mehr: `.env.development` setzt `mock`, das Image
`real` (`lib/config.ts`).

## 3. Was jede Seite anfordert

| Seite | Aufruf | Anmerkung |
|---|---|---|
| `/` | `getCategories`, `getThreads({})` | zeigt nur angeheftete Threads; Gesamtzahl = Summe der `thread_count` |
| `/discussions` | `getCategories`, `getThreads({kind, search, sort, status})` | Tab = Art |
| `/c/{slug}` | `getCategories`, `getThreads({category, search, sort})` | |
| `/feedback` | `getCategories`, `getThreads({kind:'feedback', sort, status})` | |
| `/roadmap` | `getCategories`, `getThreads({kind:'feedback', sort})` | ein Aufruf, Spalten nach `status` gruppiert |
| `/templates` | `getCategories`, `getThreads({category:'hardware-firmware', sort:'popular'})` | |
| `/integrations` | `getCategories`, `getThreads({})` | ordnet Threads einer statischen Integrationsliste per Titel zu |
| `/t/{slug}` | `getCategories`, `getThreadBySlug`, `voteThread`, `votePost`, `createPost` | |
| `/support` | `getCategories`, `createThread` \| `createGuestTicket` | öffentlich = Thread, privat = Ticket |
| `/support/ticket/{id}` | `getTicket`, `replyTicket` | Gast über Token, Autor über Session |
| `/login` | — | nur BFF-Navigation (`/api/auth/login`) |
| überall | `/api/auth/session` über `useSession` | Sidebar, Composer, Modal |

Nicht von einer Seite benutzt, aber im Client vorhanden und vom Backend bedient:
`listTickets`, `setTicketStatus`, `setThreadStatus`. Das ist die Team-Inbox, für die es noch
keine Oberfläche gibt (§5).

## 4. Welche Felder das Frontend anfasst

**`Thread` — vollständig genutzt** bis auf `category_id` (das Frontend arbeitet mit Slugs) und
`bounty` (siehe unten). `viewer_voted` und `participants` sind neu und ersetzen erfundene Werte.

**`Post`** — alle Felder; `upvote_count` und `viewer_voted` sind neu.

**`Category`** — `id`, `slug`, `name`, `description`, `icon`, `color`, `thread_count`.
Ungenutzt: `order_index` (das Backend sortiert bereits danach) und `is_private` (das Backend
listet private Sektionen nur dem Team, das Frontend muss nichts entscheiden).

**`SupportTicket`** — `id`, `status`, `mcu_target`, `created_at`, `thread`, `posts`.
Ungenutzt: `email`, `author_name`, `is_public`, `thread_id`.

Die alte Typdatei beschrieb ein anderes Backend als das laufende: `SupportTicket.status` kannte
`in_review` (gibt es nicht), dazu `priority`, `device_uuid`, `guest_email` und `access_token`
(gibt es alle nicht), und `GuestTicketResponse` nannte `access_token` statt `token`. Nichts davon
hätte je funktioniert; es fiel nur nicht auf, weil bei jedem Fehler Mock-Daten kamen.

## 5. Was die Oberfläche verlangt und das Backend nicht hat

Nach Dringlichkeit, so wie ich sie sehe:

**1. ~~Paginierung~~ — Backend erledigt am 2026-09-08; der Client liest seit dem 2026-09-09 die
erste Seite (`{items, next_cursor}`), das Nachladen in der Oberfläche ist offen (§8).**

**2. Suche nur über Titel.** `search` prüft `t.title ILIKE`. Der Beitragstext wird nicht
durchsucht, was für ein Support-Forum die halbe Suche ist. Vorschlag: Volltext über den ersten
Beitrag, später über alle (`tsvector`).

**3. Kein Filter auf `mcu_target`.** Das Feld wird gespeichert und angezeigt, ist aber nicht
filterbar. Die Integrations-Seite behilft sich damit, Threads per Titel-Textsuche einer
Hardware zuzuordnen, und die Templates-Seite nimmt ersatzweise eine ganze Kategorie. Vorschlag:
`?mcu_target=` als Filter — kleiner Eingriff, macht beide Seiten ehrlich.

**4. Das Team kann nichts anheften und nichts schließen.** `is_pinned` und `is_locked` stehen in
der Datenbank, werden gelesen und angezeigt, aber von keiner Route gesetzt. Die Startseite besteht
im Wesentlichen aus angehefteten Threads. Vorschlag: beide in `PATCH /api/v1/threads/{id}`.

**5. ~~Kein Bearbeiten~~, kein Löschen.** Bearbeiten gibt es seit dem 2026-09-09
(`PATCH /api/v1/posts/{id}`, `Post.edited_at`, `Post.viewer_is_author` sagt der Seite, wem der
Beitrag gehört). Löschen fehlt weiterhin — Thread wie Beitrag.

**6. Bounties.** Die Sektion ist deaktiviert, die Karte hat den Badge auskommentiert, und
`bounty` ist ein `int`, das immer 0 ist. Ein echtes Bounty braucht Betrag, Währung, Status
(offen/vergeben) und Empfänger — und dahinter das Guthabensystem, das es nicht gibt. Bis dahin
ist die Spalte ein Platzhalter, und ich habe sie als solchen dokumentiert statt sie zu füllen.

**7. Anhänge.** Der Editor bettet Bilder als `data:`-URI in den Inhalt ein; `PostContent` liest
zusätzlich eine Konvention `<!-- toob_attachments: … -->` aus dem HTML. Es gibt keinen
Upload-Endpunkt. Ein Screenshot zählt damit gegen das 20 000-Zeichen-Limit eines Beitrags, und
ein größeres Bild macht den Beitrag unschickbar. Vorschlag: Upload nach S3 wie bei den Paketen,
Beitrag verweist per URL.

**8. ~~Benachrichtigungen~~ — im Forum erledigt am 2026-09-09.** `GET /api/v1/me/notifications`
und `POST /api/v1/me/notifications/read`: eine Antwort im eigenen Thread, ein Statuswechsel durch
das Team (Migration 008). Offen bleibt der Versand per E-Mail; die Adresse des Gastes liegt am
Ticket, die der angemeldeten Person liefert der IdP seit §10.114.

**9. Keine Profile.** Ein Beitrag trägt `author_name` als Zeichenkette, keine URN. Das Frontend
kann niemanden verlinken und zwei Leute mit demselben Anzeigenamen nicht unterscheiden. Die URN
steht in der Datenbank (`author_urn`) und wird bewusst nicht ausgeliefert.

**10. `view_count` zählt jeden Aufruf.** Ohne Entprellung, ohne Unterscheidung von Bots. Die Zahl
steht auf der Detailseite.

**11. Keine aufsteigenden Sortierungen.** Die neue Suchmaske bietet „älteste zuerst" und
„wenigste Stimmen zuerst"; das Backend sortiert jede Liste absteigend. Beide fallen derzeit auf
ihr Gegenteil zurück. Eine Seite umzudrehen wäre falsch — das sind andere Zeilen, nicht dieselben
rückwärts. Vorschlag: eine Richtung pro Sortierung, mitsamt gedrehtem Vergleich im Cursor.

**12. ~~„Threads, an denen ich beteiligt bin"~~ — erledigt am 2026-09-09.** `voted=1` (was ich
hochgestimmt habe) und `replied=1` (worin ich geschrieben habe, ohne es eröffnet zu haben) neben
`mine=1`; die Reiter unter „My threads" sind je eine dieser Abfragen. „Following" hat weiterhin
kein Backend und steht hinter dem Feature-Flag `following` (`lib/flags.ts`).

**13. Status-Vokabular und Verlauf — erledigt am 2026-09-09.** Ein Thread kennt elf Status
(`ThreadStatus` im Vertrag, `store.ThreadStatuses`, Migration 007), der Filter zusätzlich `active`
und `done`. Jeder Statuswechsel wird als `ThreadEvent` festgehalten (Migration 008) und in
`events` der Thread- und Ticket-Antwort geliefert; die Detailseiten zeigen ihn in der Konversation.

**14. Reaktionen, Folgen, Melden.** Die Oberfläche hat Emoji-Reaktionen, einen Folgen-Knopf und
„Melden" im Menü; kein Backend speichert davon etwas. Alle drei stehen hinter Feature-Flags
(`reactions`, `following`, `reporting` in `lib/flags.ts`), die ein Produktionsbuild nicht setzt.

## 6. Wo Frontend und Backend jetzt die Grenze ziehen

- **Das Backend entscheidet, was in einer Liste steht und in welcher Reihenfolge.** Sichtbarkeit,
  Arten, Sortierung, angeheftet zuerst. Das Frontend stellt eine Anfrage und zeigt die Antwort.
- **Das Frontend gruppiert und stellt dar.** Die Roadmap-Spalten sind eine Gruppierung einer
  Antwort nach `status`, nicht drei Anfragen. Die Integrationsliste ist Inhalt der Seite.
- **HTML wird beim Schreiben bereinigt**, nicht beim Anzeigen (`store.SanitizeContent`,
  bluemonday). Ein zweiter Client bekommt damit denselben sicheren Inhalt, ohne es selbst zu tun.
- **Eine ID-tragende Route antwortet Unbefugten 404**, nie 403, damit sich Ticket-IDs nicht
  abtasten lassen. Einzige Ausnahme ist die Team-Inbox, die keine ID nennt.
- **Der Zustand „angemeldet" hat eine Quelle:** `/api/auth/session`. Kein `localStorage`, außer im
  Mock-Modus.

## 7. Nächste sinnvolle Schritte

1. Nachladen weiterer Seiten in der Oberfläche (§8) und Volltextsuche (§5.2).
2. `mcu_target` als Filter, dann Integrations- und Templates-Seite darauf umstellen (§5.3).
3. Anheften und Schließen in `PATCH /api/v1/threads/{id}` (§5.4).
4. Die Team-Inbox als Seite; der Client kann sie schon (`listTickets`, `setTicketStatus`), und das
   UI-Package hat seit dem 2026-09-09 `StatusBadge`, `UserBadge` und die Post-Bausteine des
   Forums (`PostHeader`, `PostActionsMenu`, `InlinePostEditor`, `StatusChangeRow`, `VoteButton`).
5. Löschen (§5.5), Reaktionen und Folgen mit Backend (§5.14).

---

## 8. Paginierung: Backend fertig, Client liest die erste Seite, Nachladen offen

Vorher war nichts paginiert. Threads und Tickets waren bei `LIMIT 200` hart abgeschnitten,
ohne Cursor und ohne Hinweis darauf, dass etwas fehlt; die Beiträge eines Threads waren
**völlig unbegrenzt** — ein Thread mit fünfhundert Antworten lieferte sie alle, bei jedem Aufruf.

Das Backend kann es jetzt. **Seek-Paginierung**, keine Offsets: eine Seite ist „alles, was nach
dieser Zeile einsortiert ist". Wer scrollt, während jemand schreibt, bekommt dadurch keine Zeile
doppelt und überspringt keine — bei `OFFSET` wäre genau das der Normalfall. Der Cursor ist
undurchsichtig und trägt die Sortierung in sich; wird er einer anders sortierten Liste vorgelegt,
antwortet sie `400`, statt unverwandte Zeilen zu liefern.

| Endpunkt | Parameter | Antwort |
|---|---|---|
| `GET /api/v1/threads` | `limit`, `cursor` | `{items, next_cursor}` |
| `GET /api/v1/threads/{slug}` | `limit`, `posts_cursor` | `{thread, posts, posts_next_cursor}` |
| `GET /api/v1/threads/{id}/posts` (neu) | `limit`, `cursor` | `{items, next_cursor}` |
| `GET /api/v1/support/tickets` | `limit`, `cursor` | `{items, next_cursor}` |
| `GET /api/v1/support/tickets/{id}` | `limit`, `posts_cursor` | Ticket mit `posts_next_cursor` |

`limit` ist 1 bis 100, ohne Angabe 30. Fehlt `next_cursor`, war das die letzte Seite — das ist
das einzige Signal, das ein unendlich scrollendes Frontend braucht. Migration 005 legt pro
Sortierung einen passenden Index an; ohne den wäre ein Seek so teuer wie ein Offset.

Zwei Entscheidungen, die erklärt gehören:

- **Die Antwort ist ein Objekt, keine Liste mehr.** Ein Cursor muss irgendwo hin, und ein Header
  ist für einen typisierten Client leicht zu übersehen. Das ist eine brechende Änderung.
- **Sortierung nach veränderlichen Spalten bleibt wackelig.** Wer nach Aufrufen oder Stimmen
  sortiert und dazwischen scrollt, kann eine Zeile doppelt sehen, weil sich der Wert bewegt hat.
  Das ist der Preis jeder Sortierung nach einer Zahl, die sich ändert, und niemand löst es anders.

**Was das Frontend jetzt tun muss** (andere Sitzung, nicht diese):

1. `ForumApi.getThreads` und `listTickets` geben `{items, next_cursor}` zurück, nicht `Thread[]`.
   Betroffen sind `lib/types.ts`, `lib/api.ts`, `lib/mockData.ts` und die sieben Server-Seiten,
   die `initialThreads` weiterreichen.
2. `getThreadBySlug` liefert zusätzlich `posts_next_cursor`; für weitere Beiträge gibt es
   `GET /api/v1/threads/{id}/posts`.
3. `useThreads` braucht ein Anhängen statt Ersetzen: bei neuem Cursor die Seite an die Liste
   hängen, bei geänderter Abfrage von vorn beginnen.
4. Der Auslöser fürs Nachladen gehört an einen Sentinel am Listenende (`IntersectionObserver`),
   nicht an ein Scroll-Ereignis.

Bis Schritt 1 gemacht ist, passt der laufende Client nicht mehr zum Backend: er erwartet ein
Array und bekommt ein Objekt, die Listen bleiben also leer. Der Vertrag in `openapi.yaml` und
`TestRoutes_AreTheContracts` sind auf dem neuen Stand.
