# Backlog — Zitadel: Sicherheitsentwurf und Aufbau

**Grundlage:** `ARCHITEKTUR-identity-zitadel.md` (der Schnitt gegen die Produkte),
`ARCHITEKTUR-devops.md` (der Identity-Spoke).

**Was dieses Dokument zusätzlich leistet:** Es entwirft das Sicherheitsmodell aus dem
Bedrohungsmodell heraus und leitet daraus die Tickets ab — nicht umgekehrt.

---

# TEIL 1 — Bedrohungsmodell und Entwurf

## 1.1 Was auf dem Spiel steht

Die Angriffskette ist kurz:

```
Konto kompromittiert (release-manager)
  → Artefakt hochladen
  → Signing Service signiert (er signiert, was autorisierte Aufrufer verlangen)
  → Channel publizieren
  → jedes Gerät der Flotte lädt und installiert
  → Signatur ist gültig, weil WIR sie erzeugt haben
```

Der Bootloader schützt hier nicht. Er prüft Ed25519 gegen den eFuse-Anker, und die Signatur
ist echt. Anti-Rollback greift nicht, weil die SVN höher ist. Das Gerät tut genau das, wofür
es gebaut wurde.

**Konsequenz für den Entwurf:** Es genügt nicht, Kontoübernahme schwer zu machen. Ein
einzelnes übernommenes Konto darf **nicht ausreichen**, um Firmware auszuliefern. Das ist
der Unterschied zwischen einem gut konfigurierten IdP und einem, der dieser Verantwortung
gerecht wird.

## 1.2 Angriffsflächen, systematisch

| # | Klasse | Konkret | Gegenmaßnahme |
|---|---|---|---|
| A1 | Credential | Spraying, Stuffing, Wiederverwendung | **Kein Passwort** für privilegierte Rollen |
| A2 | Phishing | AiTM-Proxy (Evilginx), relayed TOTP/Push | **WebAuthn** — Origin-gebunden, nicht relaybar |
| A3 | Wiederherstellung | „Passwort vergessen" → E-Mail → Übernahme | Keine Selbstbedienung für privilegierte Rollen |
| A4 | Sitzung | Token-Diebstahl, Replay, XSS | Kurze TTL, Step-up, Token-Bindung |
| A5 | Registrierung | Selbstregistrierung, Enumeration | Einladung mit Ablauf, Genehmigung durch Owner |
| A6 | Föderation | GitHub-Übernahme, Account-Linking-Angriff | Upstream reicht nicht für privilegierte Rollen |
| A7 | Admin-Ebene | `IAM_OWNER` kann alles in allen Orgs | Break-Glass-Konto, nie im Alltag |
| A8 | Insider | Toob-Mitarbeiter sehen Kundendaten | Zeitbegrenzte Impersonation, Kunde wird benachrichtigt |
| A9 | Infrastruktur | Masterkey, DB, Backups | Vault, Verschlüsselung, getrennte Sicherung |
| A10 | Lieferkette | Ein Konto → ganze Flotte | **Vier Augen + Verzögerung** |

Die letzte Zeile ist die wichtigste. A1 bis A9 machen Übernahme schwer; A10 macht sie
unzureichend.

## 1.3 Die fünf Entwurfsentscheidungen

### E1 — Passwortlos für alles, was Geräte berührt

Kein Passwort bedeutet: nichts zu erraten, nichts zu stuffen, nichts wiederzuverwenden, und
vor allem **kein Passwort-Reset-Fluss, den man angreifen kann**. Das eliminiert A1 vollständig
und schrumpft A3 erheblich.

Passkeys als primärer und einziger Faktor für `operator`, `release-manager`, `admin`, `owner`.

### E2 — Nur phishing-resistente Faktoren

TOTP und Push sind gegen einen AiTM-Proxy wirkungslos: Der Proxy leitet den Code in Echtzeit
weiter, der Nutzer merkt nichts. WebAuthn bindet die Assertion an den Origin — ein Proxy auf
`id.the-toob.corn` bekommt keine gültige Signatur.

**Für Rollen mit Geräteauswirkung: WebAuthn ohne Rückfallebene.** Eine Rückfallebene auf TOTP
macht WebAuthn wertlos, weil der Angreifer sie wählt.

`viewer` und Registry-`contributor` dürfen TOTP verwenden — dort ist der Schaden auf Lesen
bzw. Paketveröffentlichung begrenzt.

### E3 — Wiederherstellung ist nie Selbstbedienung

Der am häufigsten ausgenutzte Pfad in freier Wildbahn. Wer MFA erzwingt und dann einen
Reset per E-Mail erlaubt, hat MFA nicht erzwungen — er hat sie zu einer Unbequemlichkeit
gemacht.

Der Entwurf:
1. **Mindestens zwei Authentikatoren** registriert, bevor eine privilegierte Rolle aktiv wird.
   Verlust eines Schlüssels ist dann kein Notfall.
2. Verlust beider: Verifikation außerhalb des Kanals, **Wartezeit von 24 Stunden**,
   Benachrichtigung an alle Org-Owner. Die Wartezeit ist der Punkt — sie gibt dem echten
   Inhaber Zeit zu widersprechen.
3. **Wiederherstellung darf das Authentifizierungsniveau nicht senken.** Ein Fluss, der in
   „setze ein neues Passwort" endet, führt das Passwort wieder ein.

### E4 — Step-up vor gefährlichen Operationen

Eine Sitzung ist nicht dasselbe wie eine Freigabe. Selbst ein gestohlenes Session-Token soll
nicht ausreichen, um Firmware zu publizieren.

Vor Publish, Channel-Wechsel und Rollout-Start: **frische Re-Authentifizierung mit dem
phishing-resistenten Faktor**, maximal fünf Minuten alt. Der Angreifer mit gestohlenem Token
kann lesen — ausliefern kann er nicht.

### E5 — Ein Konto genügt nicht

Für Produktions-Channels mit Geräten im Feld:
- **Vier-Augen-Prinzip**: zwei verschiedene `release-manager` müssen freigeben, beide mit
  frischem Step-up.
- **Soak-Zeit**: zwischen Freigabe und Beginn der Auslieferung liegen mindestens 30 Minuten,
  in denen jeder Org-Owner abbrechen kann. Ein erfolgreicher Angriff hat damit ein
  Erkennungsfenster, bevor das erste Gerät installiert.

Beides ist pro Mandant konfigurierbar, aber **Default an** für jeden Mandanten mit Geräten in
Produktion.

## 1.4 Was das nicht leistet

Ehrlichkeit gehört zum Entwurf: Kein IdP ist unangreifbar. Was dieser Aufbau erreicht:

- Kontoübernahme erfordert **physischen Besitz** eines registrierten Authentikators.
- Ein übernommenes Konto reicht **nicht** für Firmware-Auslieferung (E5).
- Jeder erfolgreiche Angriff hat ein **Erkennungsfenster** vor der Wirkung.
- Der Radius eines kompromittierten Toob-Mitarbeiters ist begrenzt und sichtbar.

Was bleibt: ein Angreifer mit physischem Zugriff auf zwei Authentikatoren einer Person, oder
zwei kollaborierende Insider, oder eine Schwachstelle in Zitadel selbst. Gegen die ersten
beiden hilft nur Organisation, gegen die dritte nur zeitnahes Patchen (`IDP-090`).

---

# TEIL 2 — Backlog

**Legende**
**Prio:** P0 muss vor dem ersten echten Nutzer · P1 vor Produktivgang · P2 vor dem ersten
Kunden mit Flotte · P3 danach
**Typ:** `security` `config` `feature` `infra` `process` `detect`

**Reihenfolgeprinzip:** Alles, was sich nicht ohne Zeitfenster nachrüsten lässt, kommt zuerst.
Eine MFA-Policy nachträglich auf bestehende Konten anzuwenden, hinterlässt genau die Lücke,
die ein Angreifer sucht.

---

## Übersicht

| ID | Titel | Prio | Typ |
|---|---|---|---|
| **EPIC A — Fundament, vor dem ersten Nutzer** |||
| IDP-001 | Masterkey aus Vault, nie aus Datei | P0 | security |
| IDP-002 | Datenbank: eigene Instanz, verschlüsselte Backups, getrennter Bucket | P0 | infra |
| IDP-003 | Netz- und Edge-Härtung des Identity-Spokes | P0 | infra |
| IDP-004 | Selbstregistrierung aus, Enumeration verhindern | P0 | config |
| IDP-005 | Instanz-Policies vor der ersten Org festschreiben | P0 | config |
| **EPIC B — Authentifizierung** |||
| IDP-010 | Passkeys als primärer Faktor, passwortlos | P0 | config |
| IDP-011 | WebAuthn ohne Rückfallebene für Geräterollen | P0 | config |
| IDP-012 | Zwei Authentikatoren als Vorbedingung privilegierter Rollen | P0 | feature |
| IDP-013 | Rollenabhängige Authentifizierungsanforderung durchsetzen | P1 | feature |
| IDP-014 | Sitzungsdauer, Token-TTL, Refresh-Rotation | P1 | config |
| IDP-015 | Token-Bindung (DPoP oder mTLS) prüfen und aktivieren | P2 | security |
| **EPIC C — Wiederherstellung und Notfallzugang** |||
| IDP-020 | Selbstbedienungs-Reset für privilegierte Rollen abschalten | P0 | config |
| IDP-021 | Wiederherstellungsprozess mit Wartezeit und Benachrichtigung | P1 | process |
| IDP-022 | `IAM_OWNER` als Break-Glass-Konto | P0 | security |
| IDP-023 | Break-Glass-Übung und Protokoll | P2 | process |
| **EPIC D — Organisationen, Einladungen, Rollen** |||
| IDP-030 | Projekt- und Rollenmodell anlegen | P1 | config |
| IDP-031 | Einladungsfluss: einmalig, ablaufend, E-Mail-gebunden | P1 | feature |
| IDP-032 | Org-Namensregeln über Action durchsetzen | P1 | feature |
| IDP-033 | Rollenvergabe erfordert Owner-Genehmigung | P1 | feature |
| IDP-034 | Org-Spiegel in die Produkte pushen | P1 | feature |
| **EPIC E — Step-up und Freigabe** |||
| IDP-040 | Step-up-Authentifizierung vor Geräteoperationen | P1 | feature |
| IDP-041 | Vier-Augen-Freigabe für Produktions-Channels | P2 | feature |
| IDP-042 | Soak-Zeit zwischen Freigabe und Auslieferung | P2 | feature |
| IDP-043 | Signing Service verlangt Freigabenachweis | P2 | security |
| **EPIC F — Föderation** |||
| IDP-050 | GitHub als Upstream-IdP, mit Rollenschranke | P1 | config |
| IDP-051 | Bestandsnutzer vorverknüpfen | P1 | feature |
| IDP-052 | Kunden-IdP über OIDC/SAML | P3 | feature |
| IDP-053 | Workload-Identity-Federation für CI | P3 | feature |
| **EPIC G — Insider und Support** |||
| IDP-060 | Impersonation zeitbegrenzt, begründet, sichtbar | P2 | security |
| IDP-061 | Toob-Mitarbeiter ohne stehende Kundenrechte | P2 | process |
| **EPIC H — Erkennung** |||
| IDP-070 | Audit-Log nach Loki, unveränderlich, projektgetrennt | P1 | detect |
| IDP-071 | Alarme auf sicherheitsrelevante Ereignisse | P1 | detect |
| IDP-072 | Anomalie-Alarme: neue Geografie, neuer Authentikator | P2 | detect |
| IDP-073 | Rate-Limits ohne DoS-Nebenwirkung | P1 | security |
| **EPIC I — Nachweis** |||
| IDP-080 | Angriffssimulation: AiTM-Phishing | P2 | process |
| IDP-081 | Externe Sicherheitsprüfung vor dem ersten Kunden | P2 | process |
| IDP-090 | Patch-Prozess mit Frist | P1 | process |

---

# EPIC A — Fundament, vor dem ersten Nutzer

---

### IDP-001 — Masterkey aus Vault, nie aus Datei

**Prio:** P0 · **Typ:** security

**Problem**
Zitadel verschlüsselt Secrets in der Datenbank mit einem Masterkey. Wer Masterkey **und**
Datenbank hat, hat die Identitätsinfrastruktur — inklusive aller Client-Secrets und
IdP-Konfigurationen.

Der Standardweg legt ihn in eine Datei oder eine Umgebungsvariable. Beides landet in Backups,
Prozesslisten und Log-Ausgaben.

**Lösung**
Masterkey aus `secret/projects/identity/masterkey`, per Vault-Agent in ein Template gerendert,
Dateimodus `0400`, Eigentümer `zitadel`. Die Lease-Regel der Plattform gilt: **mindestens 30
Tage**, damit ein Vault-Ausfall den IdP nicht stoppt (`OPS-060`).

Der Schlüssel wird bei der Einrichtung genau einmal erzeugt und offline gesichert — er ist
nicht rotierbar, ohne die Datenbank neu zu verschlüsseln.

**Akzeptanzkriterien**
- [ ] Der Masterkey steht in keiner Umgebungsvariablen und in keinem Ansible-Vault-freien Pfad.
- [ ] `systemctl show zitadel` und `/proc/<pid>/environ` enthalten ihn nicht.
- [ ] Offline-Sicherung existiert und ihr Ort ist im Runbook vermerkt.

---

### IDP-002 — Datenbank, Backups, Bucket

**Prio:** P0 · **Typ:** infra

**Lösung**
Eigene Ubicloud-Instanz `toob-idp-db`, kein geteiltes Schema. `sslmode=verify-full` wie im
Bestand. Firewall-Pinning über den zentralen Pruner.

**Backups sind so sensibel wie der IdP selbst.** Eigener Bucket
`toob-idp-backups-<env>` — nicht der geteilte Vault-Bucket, dessen Löschpfad in `BEF-003`
auffiel. Verschlüsselung at rest, WORM, eigene Zugriffsschlüssel.

**Akzeptanzkriterien**
- [ ] Kein anderer Dienst hat Zugriff auf `toob-idp-db`.
- [ ] Backup-Bucket ist umgebungspräfigiert und von keinem Teardown-Pfad erfasst.
- [ ] Ein Restore ist getestet (analog `OPS-020`).

---

### IDP-003 — Netz- und Edge-Härtung

**Prio:** P0 · **Typ:** infra

**Lösung**
- Cloudflare vor `id.the-toob.com`, Origin-Cert, Full Strict. Ursprungs-IPs nur von
  CF-Ranges erreichbar (Hetzner-Firewall).
- **Admin-Konsole nicht öffentlich**: Zitadels Console-Pfad nur aus dem WireGuard-Netz
  erreichbar, per Caddy-Matcher auf Quell-IP. Der Login-Endpunkt bleibt öffentlich, die
  Verwaltungsoberfläche nicht.
- Security-Header wie im Registry-Caddyfile, CSP eng.
- Keine Introspection-Endpunkte öffentlich, wenn sie nicht gebraucht werden.
- WAF-Regel gegen bekannte Phishing-Kit-Signaturen und ungewöhnliche `redirect_uri`-Muster.

**Akzeptanzkriterien**
- [ ] Portscan von außen: nur 443.
- [ ] Console-Pfad aus dem Internet: `403`.
- [ ] Ein Aufruf mit fremdem `Host`-Header wird abgewiesen.

---

### IDP-004 — Selbstregistrierung aus, Enumeration verhindern

**Prio:** P0 · **Typ:** config

**Problem**
Offene Selbstregistrierung erzeugt Konten, die später über Einladungsfehler oder Social
Engineering in Organisationen wandern. Und unterschiedliche Fehlermeldungen für „Nutzer
existiert nicht" gegenüber „falsches Passwort" verraten, wer Kunde ist — für einen
gezielten Angriff auf einen bestimmten Hersteller ist das der erste Schritt.

**Lösung**
- Registrierung ausschließlich per Einladung (`IDP-031`).
- Login-Antworten und -Zeiten für existierende und nicht existierende Konten ununterscheidbar.
- Kein Hinweis darauf, welche Faktoren registriert sind, bevor die Identität feststeht.

**Akzeptanzkriterien**
- [ ] `POST` auf den Registrierungspfad ⇒ abgelehnt.
- [ ] Antwortzeit für existierendes und nicht existierendes Konto unterscheidet sich nicht
      messbar (Messung über 1000 Versuche).

---

### IDP-005 — Instanz-Policies vor der ersten Org

**Prio:** P0 · **Typ:** config

**Problem**
Zitadel-Organisationen erben Policies von der Instanz, können sie aber überschreiben. Werden
die Instanz-Defaults erst nach der ersten Org gesetzt, gilt für diese weiter der alte Stand —
und niemand merkt es.

**Lösung**
Alle Instanz-Policies festschreiben, **bevor** die erste Organisation existiert: Login-Policy,
Passwort-Policy (ungenutzt, aber restriktiv als Sicherheitsnetz), MFA-Policy, Lockout-Policy,
Domain-Policy. Als Terraform oder als versionierte API-Aufrufe, nicht per Klick.

Zusätzlich: **Org-eigene Policy-Überschreibung deaktivieren**, wo möglich. Ein Kunde soll die
MFA-Anforderung nicht senken können.

**Akzeptanzkriterien**
- [ ] Die Policy-Konfiguration liegt als Code vor und ist reproduzierbar anwendbar.
- [ ] Eine neu angelegte Org erbt alle Einschränkungen (Negativtest: Versuch, MFA in einer Org
      abzuschalten, schlägt fehl).

> **Zu verifizieren:** Welche Policies Zitadel org-seitig überschreibbar lässt und ob sich das
> instanzweit sperren lässt. Falls nicht, muss eine Action die Änderung zurücksetzen und
> alarmieren.

---

# EPIC B — Authentifizierung

---

### IDP-010 — Passkeys als primärer Faktor, passwortlos

**Prio:** P0 · **Typ:** config

**Lösung**
Passwortloser Login als Standard für alle neuen Nutzer. Kein Passwort gesetzt, keins
setzbar. Damit entfallen Credential-Stuffing, Spraying, Wiederverwendung und der gesamte
Passwort-Reset-Angriffspfad.

Registry-`contributor` dürfen übergangsweise über GitHub kommen (`IDP-050`) — auch dort ohne
lokales Passwort.

**Akzeptanzkriterien**
- [ ] Ein neuer Nutzer kann kein Passwort setzen.
- [ ] Der Login-Bildschirm bietet keine Passworteingabe an.

---

### IDP-011 — WebAuthn ohne Rückfallebene für Geräterollen

**Prio:** P0 · **Typ:** config

**Problem**
TOTP und Push sind gegen AiTM-Proxys wirkungslos — der Proxy leitet den Code in Echtzeit
weiter. WebAuthn bindet die Assertion an den Origin und ist deshalb nicht relaybar.

**Eine Rückfallebene macht die Maßnahme wertlos**, weil der Angreifer sie wählt. Wer TOTP als
Alternative anbietet, hat TOTP.

**Lösung**

| Rolle | Erlaubte Faktoren |
|---|---|
| `owner`, `admin`, `release-manager`, `operator` | **nur WebAuthn/Passkey** |
| `viewer`, Registry-`contributor` | WebAuthn oder TOTP |

Bevorzugt Authentikatoren mit User-Verification (PIN oder Biometrie), damit ein gestohlener
Schlüssel allein nicht genügt.

**Akzeptanzkriterien**
- [ ] Ein Konto mit `operator` kann TOTP nicht als einzigen Faktor verwenden.
- [ ] Der Versuch, für eine Geräterolle TOTP zu registrieren, wird abgelehnt.

---

### IDP-012 — Zwei Authentikatoren als Vorbedingung

**Prio:** P0 · **Typ:** feature

**Problem**
Passwortlos mit einem Schlüssel bedeutet: Laptop verloren, Konto verloren. Und eine
Notfall-Wiederherstellung ist der schwächste Punkt jedes Systems (`E3`).

Wer zwei Authentikatoren registriert hat, braucht die Notfallwiederherstellung nicht.

**Lösung**
Eine privilegierte Rolle wird **erst aktiv**, wenn mindestens zwei Authentikatoren registriert
sind. Empfohlen: ein Plattform-Passkey (Laptop, Telefon) und ein Hardware-Schlüssel im Safe.

Die Prüfung läuft über eine Action bei der Rollenvergabe. Fällt die Zahl unter zwei, wird die
Rolle suspendiert und der Nutzer benachrichtigt.

**Akzeptanzkriterien**
- [ ] Rollenvergabe an einen Nutzer mit einem Authentikator ⇒ Rolle bleibt inaktiv, Hinweis.
- [ ] Entfernen des zweiten Authentikators ⇒ Rolle wird suspendiert, Nutzer und Org-Owner
      werden benachrichtigt.

---

### IDP-013 — Rollenabhängige Anforderung durchsetzen

**Prio:** P1 · **Typ:** feature

**Problem**
Die Anforderung aus `IDP-011` muss **zum Zeitpunkt der Aktion** gelten, nicht nur beim Login.
Ein Nutzer, der als `viewer` mit TOTP eingeloggt ist und dann `operator` erhält, hat eine
Sitzung mit zu schwachem Niveau.

**Lösung**
Das Produkt prüft die `amr`- und `acr`-Claims des Tokens gegen die für die Aktion nötige
Stufe. Reicht sie nicht, folgt eine Re-Authentifizierung (`IDP-040`) statt einer Ablehnung.

**Akzeptanzkriterien**
- [ ] Eine mit TOTP begonnene Sitzung kann keine Geräteoperation auslösen.
- [ ] Der Nutzer bekommt eine Aufforderung zur Re-Authentifizierung, keine Fehlermeldung.

> **Zu verifizieren:** Wie Zitadel `amr`/`acr` befüllt und ob sich eigene ACR-Werte definieren
> lassen. Falls nicht, trägt eine Action einen eigenen Claim ein.

---

### IDP-014 — Sitzungsdauer, Token-TTL, Refresh-Rotation

**Prio:** P1 · **Typ:** config

**Lösung**

| Wert | Einstellung | Begründung |
|---|---|---|
| Access-Token | 15 min | Offline-Verifikation, Diebstahlfenster klein |
| Refresh-Token | 8 h, rotierend | Wiederverwendung eines rotierten Tokens = Diebstahl ⇒ Familie invalidieren |
| Sitzung (Browser) | 12 h absolut, 30 min inaktiv | Ein vergessener Laptop ist kein Dauerzugang |
| Step-up-Gültigkeit | 5 min | `IDP-040` |

Refresh-Token-Rotation mit Reuse-Detection ist der wichtigste Punkt: Wird ein bereits
eingelöster Refresh-Token erneut vorgelegt, wurde er gestohlen — die gesamte Token-Familie
wird invalidiert und der Nutzer alarmiert.

**Akzeptanzkriterien**
- [ ] Wiederverwendung eines rotierten Refresh-Tokens invalidiert die Familie und erzeugt einen
      Alarm.
- [ ] Cookies: `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`-Präfix.

---

### IDP-015 — Token-Bindung prüfen und aktivieren

**Prio:** P2 · **Typ:** security

**Problem**
Ein Bearer-Token ist so gut wie sein Besitz. Wer ihn stiehlt — Malware, XSS, Log-Leck — kann
ihn überall verwenden.

**Lösung**
DPoP (RFC 9449) bindet das Token an einen clientseitigen Schlüssel; ein gestohlenes Token ist
ohne den privaten Schlüssel wertlos. Alternativ mTLS-gebundene Tokens für Maschinenpfade.

> **Zu verifizieren:** DPoP-Unterstützung in Zitadel und in den Produkt-APIs. Falls nicht
> verfügbar, bleibt `IDP-040` (Step-up) die wirksame Kompensation — ein gestohlenes Token
> erlaubt dann Lesen, aber keine Auslieferung.

---

# EPIC C — Wiederherstellung und Notfallzugang

---

### IDP-020 — Selbstbedienungs-Reset abschalten

**Prio:** P0 · **Typ:** config

**Problem**
Der meistgenutzte Übernahmepfad in der Praxis. Wer MFA erzwingt und dann Reset per E-Mail
erlaubt, hat die MFA an das E-Mail-Konto delegiert.

**Lösung**
Für Konten mit privilegierten Rollen: kein Selbstbedienungs-Reset, kein Magic Link, keine
SMS. Für `viewer` und `contributor` zulässig, aber ohne Rollenerhöhung nach der
Wiederherstellung.

**Akzeptanzkriterien**
- [ ] „Zugang verloren" für ein `operator`-Konto führt zu einem Hinweis auf den Prozess aus
      `IDP-021`, nicht zu einem automatischen Fluss.

---

### IDP-021 — Wiederherstellungsprozess

**Prio:** P1 · **Typ:** process

**Lösung**
Vier Schritte, alle zwingend:

1. **Anfrage außerhalb des Kanals** — nicht über das kompromittierbare E-Mail-Konto allein.
2. **Verifikation durch einen Menschen** gegen eine bei Vertragsschluss hinterlegte
   Kontaktperson des Kunden.
3. **Wartezeit 24 Stunden**, in der alle Org-Owner benachrichtigt werden und widersprechen
   können. Das ist der eigentliche Schutz: Ein Angreifer, der die Verifikation besteht, hat
   trotzdem einen Tag, in dem der echte Inhaber es merkt.
4. **Registrierung neuer Authentikatoren**, mindestens zwei, ohne Absenkung des Niveaus.

Bei Widerspruch: sofortiger Abbruch, Sicherheitsvorfall, Sitzungen des betroffenen Kontos
invalidiert.

**Akzeptanzkriterien**
- [ ] Der Prozess ist im Runbook, mit Namen der verantwortlichen Rolle.
- [ ] Ein Testdurchlauf ist protokolliert.
- [ ] Die Wartezeit ist technisch erzwungen, nicht organisatorisch zugesagt.

---

### IDP-022 — `IAM_OWNER` als Break-Glass-Konto

**Prio:** P0 · **Typ:** security

**Problem**
Der Instanz-Administrator kann in Zitadel alles: jede Org verwalten, Nutzer anlegen, Policies
ändern, Rollen vergeben. Ein übernommenes `IAM_OWNER`-Konto ist die Kompromittierung
sämtlicher Kunden gleichzeitig.

**Lösung**
- Genau ein `IAM_OWNER`-Konto, **nicht im Alltag verwendet**.
- Zwei Hardware-Schlüssel, physisch getrennt verwahrt.
- Keine E-Mail-Adresse, die auch für anderes benutzt wird.
- **Jede Anmeldung erzeugt sofort einen Alarm** — nicht „bei Auffälligkeit", sondern immer.
- Alltägliche Toob-Arbeit läuft über org-gebundene Rollen (`IDP-061`).

**Akzeptanzkriterien**
- [ ] Es existiert genau ein Konto mit Instanz-Rechten.
- [ ] Eine Anmeldung damit erzeugt binnen 60 Sekunden einen Alarm im Betriebskanal.
- [ ] Kein Automatisierungspfad verwendet dieses Konto.

---

### IDP-023 — Break-Glass-Übung

**Prio:** P2 · **Typ:** process

**Lösung**
Halbjährlich: Zugriff mit dem `IAM_OWNER`-Konto herstellen, gemessene Zeit protokollieren,
Alarm verifizieren, Schlüssel zurück in die Verwahrung. Zusammen mit der Übung aus `OPS-023`.

Ein ungeübter Notfallpfad ist keiner — das gilt hier wie beim WireGuard-Hub.

---

# EPIC D — Organisationen, Einladungen, Rollen

---

### IDP-030 — Projekt- und Rollenmodell

**Prio:** P1 · **Typ:** config

**Lösung**
Zwei Zitadel-Projekte mit ihren Rollen:

| Projekt | Rollen |
|---|---|
| `registry` | `contributor`, `core` |
| `fleet` | `viewer`, `operator`, `release-manager`, `admin`, `owner` |

Die Trennung zwischen `release-manager` (darf signieren lassen) und `operator` (darf ausrollen)
ist Lieferkettenschutz: Ein übernommener Operator kann kein bösartiges Artefakt einschleusen,
nur ein vorhandenes falsch ausrollen — und das ist über den Assignment-Verlauf rekonstruierbar.

Als Code, nicht per Konsole.

> **Zu verifizieren:** Welches Zitadel-Primitiv die org-gebundene Rolle trägt — Projektrolle
> mit Org-Grant, Org-Member-Rolle oder User-Grant. Bestimmt die Claim-Struktur.

---

### IDP-031 — Einladungsfluss

**Prio:** P1 · **Typ:** feature

**Lösung**
- Einladung ist **einmalig einlösbar**, läuft nach 72 Stunden ab, ist an die eingeladene
  E-Mail gebunden.
- Der Einladende sieht, ob sie eingelöst wurde.
- Eine Einladung vergibt **niemals direkt** eine Rolle mit Geräteauswirkung — der Beitritt
  erfolgt als `viewer`, die Erhöhung braucht `IDP-033`.
- Widerruf jederzeit möglich.

**Akzeptanzkriterien**
- [ ] Ein zweiter Einlöseversuch derselben Einladung schlägt fehl.
- [ ] Eine Einladung, die auf eine andere E-Mail eingelöst wird, schlägt fehl.

---

### IDP-032 — Org-Namensregeln über Action

**Prio:** P1 · **Typ:** feature

**Problem**
Der Org-Name ist zugleich Paket-Scope (`@esp-alliance/foo`). Lässt Zitadel Namen zu, die
`validate.ValidateOrgName` ablehnt, entstehen Organisationen, die keinen gültigen Scope ergeben
— und der Fehler fällt erst beim ersten Publish auf.

**Lösung**
Action bei der Org-Erzeugung, die dieselbe Regel durchsetzt. Die Regel steht an einer Stelle
und wird von der Action konsumiert, nicht nachgebaut.

---

### IDP-033 — Rollenerhöhung braucht Owner-Genehmigung

**Prio:** P1 · **Typ:** feature

**Lösung**
Die Vergabe von `operator`, `release-manager` oder `admin` erfordert die Bestätigung eines
`owner` **mit frischem Step-up**. Alle Org-Owner werden benachrichtigt.

Damit reicht ein übernommener `admin` nicht, um sich still weitere Rechte zu verschaffen — der
Vorgang ist sichtbar.

**Akzeptanzkriterien**
- [ ] Rollenerhöhung ohne Owner-Bestätigung ist nicht möglich.
- [ ] Jede Erhöhung erzeugt eine Benachrichtigung an alle Owner.

---

### IDP-034 — Org-Spiegel in die Produkte

**Prio:** P1 · **Typ:** feature

**Lösung**
Push aus Zitadel in `toob-registry.organizations`/`organization_members` und
`toob-update.tenants`/`tenant_members`. Read-only im Produkt, geschrieben nur vom Sync.

Damit liest `PolicyEngine.AuthorizeOrgAction` weiter lokal — kein Netzaufruf, kein
Laufzeitpfad zum IdP.

**Akzeptanzkriterien**
- [ ] Eine Mitgliedschaftsänderung ist binnen 60 Sekunden im Produkt sichtbar.
- [ ] Sync-Rückstand über 5 Minuten erzeugt einen Alarm.
- [ ] Der Produktcode schreibt nachweislich nicht in die Spiegeltabellen (Grant-Test).

---

# EPIC E — Step-up und Freigabe

---

### IDP-040 — Step-up vor Geräteoperationen

**Prio:** P1 · **Typ:** feature

**Lösung**
Vor Artefakt-Publish, Channel-Wechsel, Rollout-Start und Killswitch: frische
Re-Authentifizierung mit phishing-resistentem Faktor, maximal fünf Minuten alt. Umgesetzt über
`prompt=login` mit `max_age` und Prüfung von `auth_time`.

**Wirkung:** Ein gestohlenes Session-Token erlaubt Lesen, aber keine Auslieferung. Das ist die
Kompensation, falls `IDP-015` nicht verfügbar ist.

**Akzeptanzkriterien**
- [ ] Publish mit einem sechs Minuten alten `auth_time` wird abgelehnt.
- [ ] Die Ablehnung führt zur Re-Authentifizierung, nicht zu einem Fehler.

---

### IDP-041 — Vier-Augen-Freigabe für Produktions-Channels

**Prio:** P2 · **Typ:** feature

**Problem**
Ohne diese Maßnahme genügt **ein** kompromittiertes Konto für die gesamte Flotte. Alles davor
macht das schwer — das hier macht es unzureichend.

**Lösung**
Ein Channel-Wechsel in Produktion erfordert die Freigabe von **zwei verschiedenen**
`release-manager`, beide mit frischem Step-up. Die zweite Freigabe kann nicht vom Ersteller
kommen.

Pro Mandant abschaltbar, aber **Default an**, sobald Geräte in Produktion registriert sind.

**Akzeptanzkriterien**
- [ ] Ein Nutzer kann nicht beide Freigaben erteilen.
- [ ] Die Abschaltung erfordert eine `owner`-Entscheidung und erzeugt einen Audit-Eintrag.

---

### IDP-042 — Soak-Zeit

**Prio:** P2 · **Typ:** feature

**Lösung**
Zwischen der zweiten Freigabe und dem ersten ausgelieferten Byte liegen mindestens 30 Minuten,
in denen jeder Org-Owner abbrechen kann. Alle Owner werden bei Freigabe benachrichtigt.

**Warum das wichtig ist:** Es verwandelt einen erfolgreichen Angriff von „sofort auf allen
Geräten" in „ein halbstündiges Erkennungsfenster". Für einen Angreifer, der auf Unauffälligkeit
angewiesen ist, ist das ein erheblicher Unterschied.

**Akzeptanzkriterien**
- [ ] Kein Gerät bekommt eine Zuweisung vor Ablauf der Soak-Zeit.
- [ ] Ein Abbruch innerhalb des Fensters verhindert jede Auslieferung.

---

### IDP-043 — Signing Service verlangt Freigabenachweis

**Prio:** P2 · **Typ:** security

**Problem**
Solange der Signing Service auf reine Rollenzugehörigkeit hin signiert, umgeht ein direkter
API-Aufruf die Freigabe aus `IDP-041`.

**Lösung**
Der Signing Service akzeptiert nur Anfragen mit einem Nachweis über zwei Freigaben und
frischen Step-up. Ohne diesen Nachweis wird nicht signiert — unabhängig davon, welche Rolle
der Aufrufer hat.

Damit ist die Vier-Augen-Regel technisch durchgesetzt und nicht nur in der UI abgebildet.

**Akzeptanzkriterien**
- [ ] Ein direkter Aufruf des Signing Service ohne Freigabenachweis wird abgelehnt.
- [ ] Der Nachweis ist an Artefakt-Digest und Channel gebunden, nicht wiederverwendbar.

---

# EPIC F — Föderation

---

### IDP-050 — GitHub als Upstream, mit Rollenschranke

**Prio:** P1 · **Typ:** config

**Problem**
GitHub-Login ist gute UX und ein Risiko: Eine GitHub-Übernahme wäre eine Toob-Übernahme, und
GitHubs eigene MFA kann SMS sein.

Zusätzlich das klassische **Account-Linking-Problem**: Ein Upstream, der E-Mail-Adressen nicht
verifiziert, erlaubt Verknüpfung mit einer fremden Identität.

**Lösung**
- GitHub bleibt Anmeldemethode für `contributor` und `viewer`.
- **Für Geräterollen genügt GitHub nicht** — dort ist zusätzlich ein lokaler Passkey
  erforderlich, unabhängig vom Anmeldeweg.
- Automatische Verknüpfung nur bei verifizierter E-Mail; sonst manuelle Bestätigung.

**Akzeptanzkriterien**
- [ ] Ein per GitHub angemeldeter Nutzer mit `operator` muss vor einer Geräteoperation den
      lokalen Faktor vorlegen.
- [ ] Verknüpfung mit unverifizierter Upstream-E-Mail ist nicht automatisch möglich.

---

### IDP-051 — Bestandsnutzer vorverknüpfen

**Prio:** P1 · **Typ:** feature

**Lösung**
Bestehende Registry-Nutzer über die Management-API anlegen und per `github_id` mit ihrer
GitHub-Identität verknüpfen, damit der erste Login sie wiedererkennt statt ein Duplikat
anzulegen.

Wichtig: Verknüpfung über die **numerische** `github_id`, nicht über den Login-Namen — Namen
sind änderbar und wiederverwendbar.

> **Zu verifizieren:** Ob die Management-API das Vorverknüpfen externer Identitäten erlaubt.
> Falls nicht, braucht der erste Login eine Action, die anhand der `github_id` zuordnet.

---

### IDP-052 — Kunden-IdP über OIDC/SAML

**Prio:** P3 · **Typ:** feature

Industriekunden wollen ihren eigenen IdP. Wichtig dabei: Auch dann bleibt die Anforderung aus
`IDP-011` bestehen — entweder der Kunden-IdP liefert nachweislich einen phishing-resistenten
Faktor (`amr`-Claim), oder es ist zusätzlich ein lokaler Passkey nötig.

Ein Kunde darf sein eigenes Sicherheitsniveau senken — aber nicht unbemerkt, und nicht für
Geräteoperationen.

---

### IDP-053 — Workload-Identity-Federation

**Prio:** P3 · **Typ:** feature

GitHub-/GitLab-OIDC-Token gegen kurzlebiges Toob-Token. Kein langlebiges Kundensecret mehr bei
uns.

Wichtig: Der Token-Tausch muss `repository`, `ref` und `workflow` prüfen — sonst kann jedes
Repository derselben Organisation Firmware publizieren. Und Maschinenidentitäten erhalten
**nie** `release-manager` für Produktions-Channels; sie können nach `dev` publizieren, die
Promotion bleibt menschlich.

---

# EPIC G — Insider und Support

---

### IDP-060 — Impersonation zeitbegrenzt und sichtbar

**Prio:** P2 · **Typ:** security

**Problem**
Die erste Frage eines Auditors: *Wer bei euch sieht unsere Flottendaten, und wie erfahren wir
davon?* Ohne dieses Ticket lautet die Antwort „jeder mit DB-Zugriff, und ihr erfahrt es nicht".

**Lösung**
Support-Zugriff läuft ausschließlich über eine explizite Impersonation:
- Begründung verpflichtend, freier Text
- Zeitlich begrenzt, maximal 4 Stunden
- Erscheint im **Audit-Log des Kunden**, nicht nur im unseren
- Benachrichtigung an alle Org-Owner beim Start
- Niemals mit `release-manager` — Support liest, Support liefert nicht aus

**Akzeptanzkriterien**
- [ ] Impersonation ohne Begründung ist nicht möglich.
- [ ] Der Kunde sieht den Vorgang in seinem eigenen Audit-Log.
- [ ] Impersonierte Sitzungen können keine Geräteoperationen auslösen.

---

### IDP-061 — Toob-Mitarbeiter ohne stehende Kundenrechte

**Prio:** P2 · **Typ:** process

**Lösung**
Kein Toob-Konto hat dauerhaft Rollen in Kundenorganisationen. Zugriff entsteht nur über
`IDP-060` und endet automatisch. Das Alltagskonto ist ein normales Konto mit Passkey.

---

# EPIC H — Erkennung

---

### IDP-070 — Audit-Log nach Loki

**Prio:** P1 · **Typ:** detect

**Lösung**
Zitadels Ereignisstrom nach Loki, mit `project=identity` und Mandanten-Label
(`X-Scope-OrgID` aus `BEF-009`). Aufbewahrung mindestens so lang wie die CRA-Retention der
Flottendaten.

Das Log ist selbst schützenswert: Es enthält, wer wann welche Flotte verwaltet hat.

**Akzeptanzkriterien**
- [ ] Alle Anmelde-, Rollen- und Policy-Ereignisse landen in Loki.
- [ ] Ein Mandant sieht ausschließlich seine eigenen Ereignisse.

---

### IDP-071 — Alarme auf sicherheitsrelevante Ereignisse

**Prio:** P1 · **Typ:** detect

| Ereignis | Schwere |
|---|---|
| `IAM_OWNER`-Anmeldung | **kritisch, immer** |
| Neuer Authentikator registriert | hoch — an Nutzer und Org-Owner |
| Privilegierte Rolle vergeben | hoch |
| MFA-Policy geändert | **kritisch** |
| Refresh-Token-Reuse erkannt | **kritisch** |
| Wiederherstellungsprozess gestartet | hoch |
| Impersonation gestartet | hoch, auch an den Kunden |
| Upstream-IdP-Konfiguration geändert | kritisch |

Der Alarm auf „neuer Authentikator" ist besonders wichtig: Das ist der Schritt, den ein
Angreifer nach der Übernahme unternimmt, um sich Persistenz zu verschaffen.

---

### IDP-072 — Anomalie-Alarme

**Prio:** P2 · **Typ:** detect

Neue Geografie oder neues ASN bei privilegierten Konten, ungewöhnliche Uhrzeit,
fehlgeschlagene WebAuthn-Versuche in Serie (deutet auf AiTM-Versuch hin — der Proxy bekommt
keine gültige Assertion und probiert weiter).

Kein automatisches Blockieren, sondern Benachrichtigung plus erzwungenes Step-up bei der
nächsten Aktion.

---

### IDP-073 — Rate-Limits ohne DoS-Nebenwirkung

**Prio:** P1 · **Typ:** security

**Problem**
Harte Kontosperren nach N Fehlversuchen sind selbst ein Angriff: Ein Angreifer sperrt gezielt
die Operatoren eines Kunden aus, kurz bevor ein Sicherheitsupdate ausgeliefert werden müsste.

**Lösung**
Progressive Verzögerung statt Sperre, kombiniert mit Alarmierung. Rate-Limits pro IP **und**
pro Konto, Cloudflare-Regel davor. Eine echte Sperre nur nach menschlicher Entscheidung.

**Akzeptanzkriterien**
- [ ] 1000 Fehlversuche gegen ein Konto sperren es nicht aus, erzeugen aber einen Alarm.
- [ ] Der legitime Inhaber kann sich während des Angriffs weiterhin anmelden.

---

# EPIC I — Nachweis

---

### IDP-080 — Angriffssimulation: AiTM-Phishing

**Prio:** P2 · **Typ:** process

**Lösung**
Ein kontrollierter Versuch mit einem AiTM-Proxy gegen ein Testkonto mit Geräterolle. Erwartetes
Ergebnis: **Der Angriff scheitert**, weil WebAuthn die Origin-Bindung durchsetzt.

Derselbe Versuch gegen ein `viewer`-Konto mit TOTP: Erwartetes Ergebnis: er gelingt — und
belegt damit, warum `IDP-011` keine Rückfallebene erlaubt.

**Akzeptanzkriterien**
- [ ] Beide Ergebnisse sind protokolliert.
- [ ] Der Versuch gegen das Geräterollen-Konto erzeugt die Alarme aus `IDP-072`.

---

### IDP-081 — Externe Sicherheitsprüfung

**Prio:** P2 · **Typ:** process

Vor dem ersten Kunden mit Geräten im Feld. Schwerpunkt: Wiederherstellungsfluss,
Einladungsfluss, Rollenerhöhung, Impersonation, Step-up-Umgehung.

Der Wiederherstellungsfluss zuerst — dort liegen erfahrungsgemäß die Findings.

---

### IDP-090 — Patch-Prozess mit Frist

**Prio:** P1 · **Typ:** process

**Problem**
Gegen eine Schwachstelle in Zitadel selbst hilft keine Konfiguration. Nur Geschwindigkeit.

**Lösung**
Abonnement der Zitadel-Sicherheitsmeldungen, feste Frist: kritische Lücken binnen 24 Stunden,
hohe binnen 72 Stunden. Der Rolling-Deploy über zwei Knoten macht das unterbrechungsfrei.

Ein Zitadel, das drei Versionen zurückliegt, macht jedes andere Ticket dieses Backlogs
wirkungslos.

---

## Reihenfolge

**Vor dem ersten echten Nutzer** — nicht nachrüstbar ohne Zeitfenster:
`IDP-001` → `IDP-002` → `IDP-003` → `IDP-004` → `IDP-005` → `IDP-010` → `IDP-011` →
`IDP-012` → `IDP-020` → `IDP-022`

**Vor Produktivgang:**
`IDP-030` → `IDP-031` → `IDP-032` → `IDP-033` → `IDP-050` → `IDP-051` → `IDP-034` →
`IDP-013` → `IDP-014` → `IDP-040` → `IDP-021` → `IDP-070` → `IDP-071` → `IDP-073` → `IDP-090`

**Vor dem ersten Kunden mit Flotte:**
`IDP-041` → `IDP-042` → `IDP-043` → `IDP-060` → `IDP-061` → `IDP-015` → `IDP-072` →
`IDP-023` → `IDP-080` → `IDP-081`

**Danach:** `IDP-052`, `IDP-053`

---

## Merksatz

> Alles vor `IDP-041` macht Kontoübernahme schwer. `IDP-041` bis `IDP-043` machen sie
> unzureichend. Nur zusammen ergeben sie eine Antwort auf die Frage, warum ein Hersteller
> uns die Kontrolle über hunderttausend Geräte anvertrauen sollte.