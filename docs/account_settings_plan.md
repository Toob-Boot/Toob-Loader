# Kontoeinstellungen für alle TOOB-Dienste

**Stand:** Plan, 2026-09-25. **Bezug:** Register [AC-001 … AC-034, ID-041, UP-007](../toob-infra/docs/register.csv),
[identity_customer_model_plan.md](identity_customer_model_plan.md) (E1).

Die Settings im Forum sind das Konto für Forum, Registry, Update-Service und CLI. Dieser Plan legt
fest, wie die 36 Punkte gebaut werden. Vorbilder sind GitHub, Google, Microsoft, Atlassian, Slack,
Vercel, Linear und Stripe; die Grenzen setzt Zitadel v4.16.2.

## 1. Was Zitadel trägt und was nicht

| Fähigkeit | Zitadel v4.16.2 | Folge |
|---|---|---|
| Passkeys und Sicherheitsschlüssel | auflisten, entfernen; nur `id`, `state`, `name` — kein Datum, kein Umbenennen | Daten und eigener Name in identity |
| Sitzungen | `SessionService.ListSessions` (pro Nutzer), `DeleteSession`; Refresh-Grant prüft das Sitzungsende **nicht** | Sitzungs-Widerruf in identity, über die Sitzungs-ID im Token |
| Anmeldehistorie, zuletzt aktiv | nicht gespeichert; Ereignisse `session.*`, `user.human.password.check.failed`, `oidc_session.*` | Actions v2 **Ereignis**-Ausführung → identity führt das Protokoll |
| Wiederherstellungscodes | API vorhanden, Login v2 ohne Oberfläche | eigener Wiederherstellungsweg |
| Konto löschen | `DeleteUser`, `DeactivateUser` | Karenzzeit in identity, dann Löschung |
| E-Mail ändern | `UpdateUser` mit Code, `VerifyEmail` | über identity; SSO-Konten gesperrt |
| Zugangstokens | nur für Maschinen-Nutzer; Token Exchange ohne fremde JWTs | eigener Credential-Dienst in identity |
| Login-Richtlinie pro Organisation | Management v1 `policies/login` pro Org, Faktoren, Lebensdauern | Sicherheitsrichtlinie über Zitadel |
| Maschinen-Nutzer pro Org | vollständig | Grundlage für Dienstkonten |
| Metadaten, bevorzugte Sprache | vorhanden; Login v2 nutzt die Sprache nicht | Präferenzen in identity, Sprache zusätzlich an Zitadel |

## 2. Entscheidungen

### 2.1 identity führt ein Sicherheitsprotokoll des Kontos
Zitadel meldet über eine Actions-v2-Ereignisausführung (Gruppe `session`, dazu
`user.human.password.check.failed`, `oidc_session.refresh_token.added/revoked`) an einen neuen
Hook in identity. identity speichert daraus:

- `account_sessions`: Zitadel-Sitzung, Client (Forum, Registry, CLI), Gerät (User-Agent), IP, Ort,
  angelegt, zuletzt gesehen, beendet;
- `account_sign_ins`: jede Anmeldung und jeder Fehlversuch mit Methode, Gerät, Ort;
- `account_credentials`: Passkeys und Schlüssel mit angelegt, zuletzt benutzt, eigenem Namen.

Darauf bauen AC-004 (Daten, Umbenennen), AC-005 (Sitzungsliste), AC-006 (Historie), AC-007
(Hinweis bei neuem Gerät), AC-029 (CLI-Anmeldungen), AC-032 (Aktivität der Mitglieder) und AC-025
(Frische der Bestätigung). **Ein** Einstieg statt sieben, und alles liegt dort, wo die Rechte und
das Ledger schon sind. Der Hook ist signiert und nicht-blockierend wie der Token-Hook.

### 2.2 Eine Sitzung beenden heißt: Zitadel-Sitzung löschen und (URN, auth_time) sperren
Am Quellcode v4.16.2 geprüft: Introspection und Access-Token tragen kein `sid`, `DeleteSession`
lässt den Refresh-Grant weiterlaufen. Jedes Token einer Sitzung trägt aber deren `auth_time`,
auch nach dem Refresh, und `oidc_session.added` meldet sie. identity sperrt deshalb den Schlüssel
`session:<urn>:<auth_time>` in der Revocation-Liste, die jeder Gate schon abfragt, und löscht die
Zitadel-Sitzung.

### 2.3 Ein Credential-Dienst für alles Nicht-Interaktive
Personen-Tokens (AC-009), CI ohne Geheimnis (AC-010), CLI-Anmeldungen (AC-029) und
Maschinen-Zugänge (AC-020) sind dieselbe Sache: ein Zugang ohne Browser. identity bekommt dafür
**ein** Modell `credentials` mit drei Arten — `personal` (gehört einer Person), `service` (gehört
einer Organisation), `federated` (kurzlebig, aus einem vertrauenswürdigen OIDC-Token getauscht) —
mit Rechten, Ablauf, zuletzt benutzt und Widerruf, und **einen** Verifier, den die Gates neben dem
Zitadel-Token kennen.

Verworfen: Zitadel-Maschinen-Nutzer als „Schatten“ jeder Person (zwei Identitäten pro Mensch in
Ledger und OpenFGA) und Token Exchange (nimmt keine fremden JWTs an). Zitadel bleibt für die
interaktive Anmeldung zuständig.

Regeln nach GitHub/Atlassian: Standard-Ablauf 30 Tage, höchstens 366; Geheimnis einmal angezeigt;
Anlegen nur mit Passkey (L2, Step-up); Credentials erreichen nie `requires_signature`-Handlungen
(Release-Freigaben bleiben interaktiv); eine Organisation kann Personen-Tokens erlauben, verbieten
oder freigabepflichtig machen.

### 2.4 Wiederherstellung ergibt höchstens einen neuen Passkey, mit Abkühlzeit
Wiederherstellungscodes (10, einmalig, als Datei) liegen gehasht in identity. Code **und** Code per
E-Mail öffnen eine Passkey-Einrichtung (wie heute über `StartPasskeyEnrolment`). Danach: alle
Sitzungen beendet, 72 Stunden keine kritischen Handlungen (Schlüssel, Freigaben, Löschen,
Eigentümerwechsel), Nachricht an das Konto und die Owner seiner Organisationen. So hebelt der
Rückweg L2 nicht aus.

### 2.5 Löschen mit Karenzzeit
Konto: deaktiviert sofort, gelöscht nach 14 Tagen (Atlassian), abbrechbar per E-Mail-Link;
gesperrt, solange es einziger Owner einer Organisation ist; Beiträge im Forum werden anonymisiert,
das Ledger bleibt; der Nutzername bleibt 90 Tage gesperrt (GitHub).

### 2.6 Präferenzen in identity, Benachrichtigungen als Katalog
Zeitzone, Sprache, Datumsformat liegen in identity (RLS, schnell), die Sprache zusätzlich im
Zitadel-Profil für dessen E-Mails. Benachrichtigungen: Themen stehen wie Permissions in einem
YAML-Katalog (`policy/notifications.yaml`, policygen), jeder Dienst meldet seine an; Kanäle E-Mail
und In-App; Thema *Sicherheit* ist fest an.

### 2.7 Org-Sicherheit über Zitadels Org-Richtlinie
Sitzungsdauer und erlaubte Faktoren schreibt identity als eigene Login-Richtlinie der Org nach
Zitadel (Management v1). SSO-Pflicht bleibt ID-040.

### 2.8 Freigabe-Regeln jetzt, Durchsetzung mit dem Update-Service
Regeln pro Kanal (Anzahl Freigaben, Teams oder Personen, kein Selbst-Freigeben, Wartezeit) liegen
in identity und OpenFGA. Durchgesetzt werden sie im Update-Service, der heute ein Skelett ist
(UP-001); bis dahin sind sie Konfiguration mit Audit.

### 2.9 Teams als Typ in OpenFGA
`type team` mit `member`, Kanal-Relationen nehmen `team#member`; SCIM-Gruppen füllen Teams später.

### 2.10 Webhooks aus der Outbox
identity liefert Org-Ereignisse aus seiner Outbox signiert (HMAC) aus, mit Zustellprotokoll
(7 Tage), erneutem Senden und Wiederholung mit Backoff (Stripe statt GitHub, das nicht wiederholt).

### 2.11 identity ist die Quelle, `@toob/account` das Frontend jedes Dienstes
Entschieden 2026-09-25: Das Konto liegt im Backend (identity), das Paket `@toob/account` ist das
einheitliche Frontend dafür. Jeder Dienst bindet es unter seinem eigenen `/settings` ein, mit
seinem BFF; Forum, Registry- und Update-Konsole zeigen dieselben Kontoseiten und daneben ihre
eigenen Abschnitte (AC-002). Eine eigene App unter neutraler Adresse wäre nur eine weitere
Einbindung desselben Pakets und bleibt jederzeit möglich.

## 3. Die Punkte

| Nr. | Punkt | Bau | Phase |
|---|---|---|---|
| AC-001 | Geltungsbereich | Kopfzeile pro Seite „Applies to all TOOB services“ / „This app only“ | 1 |
| AC-002 | Dienst-eigene Einstellungen | Navigationsgruppe pro Dienst, Abschnitte bringt die App | 1 |
| AC-003 | Links aus anderen Diensten | stabile Pfade in jeder App, `toob settings` (§2.11) | 1 |
| AC-027 | Sicherheits-Überblick | Checkliste mit Ampel (Google Security Checkup) | 2 |
| AC-028 | Suche | Suchfeld über Seiten und Abschnitte | 1 |
| AC-026 | Org-Kontext überall | Umschalter und Kopfzeile ins Paket, Links mit `?org=` | 1 |
| AC-004 | Passkeys verwalten | Liste mit Name, synchronisiert, angelegt, zuletzt benutzt; umbenennen, entfernen; letzter Weg gesperrt | 2 |
| AC-005 | Sitzungen und Geräte | Web-Sitzungen, CLI/Apps getrennt; „Diese Sitzung“; einzeln und „alle anderen“ beenden | 2 |
| AC-029 | CLI-Anmeldungen | eigener Abschnitt der Sitzungen | 2 |
| AC-006 | Anmeldehistorie | 90 Tage, Filter, „War ich das nicht?“ | 2 |
| AC-007 | Hinweis bei neuer Anmeldung | E-Mail bei neuem Gerät und geänderten Anmeldewegen, „Das war ich nicht“ → geführter Ablauf | 2 |
| AC-025 | Frische sichtbar | „Bestätigt vor 3 Minuten“ aus `auth_time` der Introspection | 2 |
| ID-041 | Wiederherstellung | §2.4 | 3 |
| AC-008 | Konto löschen | §2.5 | 3 |
| AC-013 | E-Mail ändern | Code an neue, Hinweis an alte Adresse; SSO gesperrt | 3 |
| AC-012 | Zeitzone, Sprache | §2.6; Zeiten im Forum in der Zeitzone | 3 |
| AC-011 | Benachrichtigungen | §2.6, Raster Thema × Kanal | 3 |
| AC-009 | Personen-Tokens | §2.3 | 4 |
| AC-010 | CI ohne Geheimnis | GitHub-Actions-Vertrauen wie npm/PyPI (Owner, Repo, Workflow-Datei, Environment) | 4 |
| AC-020 | Maschinen-Zugänge | Dienstkonten (§2.3); Geräte-Registrierung → §4 | 4 |
| AC-014 | Audit-Log | Tabelle mit Filtern, Export (auditiert), Kettenprüfung | 5 |
| AC-015 | Signaturschlüssel | Liste, anlegen, widerrufen (vorhandene API) | 5 |
| AC-016 | SCIM | Token einmal anzeigen, 1 Jahr Ablauf, Gruppen → Rollen/Teams; setzt ID-028 um | 5 |
| AC-017 | Support-Zugriff | an einem Ticket, 24 h, Zustimmung der Owner, widerrufbar; setzt ID-029 um | 5 |
| AC-019 | Eigentümerschaft | Übertragen; Hinweis bei nur einem Owner; letzter Owner kann nicht gehen | 5 |
| AC-024 | Sicherheitskontakt | Kontakte nach Kategorie (Google Essential Contacts), verifiziert, Testnachricht | 5 |
| AC-032 | Aktivität der Mitglieder | „Zuletzt aktiv“ in People, Filter „inaktiv seit 30 Tagen“ | 5 |
| AC-034 | Export der Organisation | Archiv für Owner, auditiert | 5 |
| AC-021 | Teams | §2.9 | 6 |
| AC-018 / UP-007 | Freigabe-Regeln | §2.8 (GitHub Environments: Prüfer, kein Selbst-Freigeben, Wartezeit) | 6 |
| AC-023 | Sicherheitsrichtlinie | §2.7 | 6 |
| AC-031 | Beitritt per Domain | Option pro bewiesener Domain, mit oder ohne Admin-Freigabe (Atlassian) | 6 |
| AC-030 | Webhooks | §2.10 | 6 |
| AC-022 | Abrechnung | Rechnungen, Zahlungsmittel, Kontakt, USt-ID über den Payment-Service (Mollie) → §4 | 7 |
| AC-033 | Nutzung und Grenzen | neben den Grenzen des Plans → §4 | 7 |

## 4. Entscheidungen und Abhängigkeiten

1. **Zahlungsanbieter: Mollie** (entschieden 2026-09-25). Mollie hat kein einbettbares
   Kundenportal; Rechnungen, Zahlungsmittel und Rechnungskontakt zeigt das Paket selbst über den
   Payment-Service. Phase 7 folgt dem Payment-Service (BI-001).
2. **Geräte-Identität** (UP-002, offen): Zertifikat pro Gerät (mTLS) oder geteiltes Geheimnis
   (HMAC) für die Geräte der Flotten. Bestimmt nur die Geräte-Registrierung in AC-020.
3. **Kontoadresse:** entschieden, §2.11.

## 5. An der Instanz geprüft (Quellcode v4.16.2, 2026-09-25)

- Introspection liefert kein `sid`, aber `auth_time` und `amr` (§2.2).
- Ereignisausführungen sind asynchron und werden nicht wiederholt; `session.added` trägt
  User-Agent und IP, `oidc_session.added` Client, Sitzung und `auth_time` (§2.1). Lücken sind
  möglich; die Seiten nennen, seit wann das Protokoll geführt wird.
- `ListSessions`/`DeleteSession` für fremde Nutzer: `session.read`/`session.delete`, in
  IAM_USER_MANAGER und ORG_USER_MANAGER enthalten.
