# Toob-Registry — Architektur- und Code-Dokumentation

> Vollständige technische Dokumentation der Control-Plane-/Data-Plane-Architektur
> des Toob-Registry-Backends (Go).

---

## Inhaltsverzeichnis

1. [Überblick & Motivation](#1-überblick--motivation)
2. [Das große Bild: Control Plane vs. Data Plane](#2-das-große-bild-control-plane-vs-data-plane)
3. [Die fünf Binaries (`cmd/`)](#3-die-fünf-binaries-cmd)
4. [Domänenmodell (`internal/domain`)](#4-domänenmodell-internaldomain)
5. [Der API-Server (Control Plane)](#5-der-api-server-control-plane)
6. [Der Worker-Daemon (Data Plane)](#6-der-worker-daemon-data-plane)
7. [Die Firecracker-VM (`vmrunner`)](#7-die-firecracker-vm-vmrunner)
8. [Validierung & Security-Scanning](#8-validierung--security-scanning)
9. [Der Autoscaler](#9-der-autoscaler)
10. [Subsystem-Modell & SemVer-Oracle](#10-subsystem-modell--semver-oracle)
11. [Datenbank & Migrationen](#11-datenbank--migrationen)
12. [Querschnitt: Sicherheitskonzepte](#12-querschnitt-sicherheitskonzepte)
13. [End-to-End-Datenflüsse](#13-end-to-end-datenflüsse)
14. [Glossar](#14-glossar)

---

## 1. Überblick & Motivation

**Toob-Registry** ist das Backend einer Paket-Registry für die Embedded-/MCU-Welt.
Verwaltet werden keine generischen Software-Pakete, sondern Bausteine aus dem
Build-Graph eines Bootloaders/SDKs: **Chips, Treiber (Driver), Krypto-Module,
Architekturen (Arch), Toolchains, Integrationen und SoCs**. Daneben werden auch
die "Ökosystem-Komponenten" CLI, Core-SDK und Compiler versioniert ausgeliefert.

Das System ist deutlich mehr als ein Datei-Server. Es kombiniert:

- **Supply-Chain-Sicherheit** — jedes eingereichte Paket wird in einer
  wegwerfbaren, netzwerklosen **Firecracker-microVM** kompiliert und statisch
  gescannt, bevor es in den öffentlichen Index gelangt.
- **Zero-Trust-Architektur** — die rechenintensiven, potenziell gefährlichen
  Build-Worker besitzen *keinerlei* dauerhafte Geheimnisse (keine DB-Credentials,
  keine S3-Keys, keine Vault-Tokens). Sie reden ausschließlich über **mTLS** mit
  einer vertrauenswürdigen Control Plane, die alle privilegierten Operationen
  ausführt.
- **Automatische Versionierung** — ein "SemVer-Oracle" leitet aus ABI-Symbolen
  (über `nm`) und Go-AST-Vergleichen automatisch ab, ob eine Änderung ein PATCH,
  MINOR oder MAJOR-Release ist.
- **Souveräne Infrastruktur** — gehostet auf Hetzner Cloud, orchestriert über
  Nomad, mit Vault als Secret-Store, Cloudflare als CDN-Edge und einem
  öffentlichen GitHub-Mirror-Repo.

### Das mentale Modell in drei Sätzen

> Entwickler laden Pakete hoch oder eröffnen Pull Requests. Eine *vertrauenswürdige
> Control Plane* nimmt sie entgegen, verteilt die eigentliche Validierung an
> *unvertrauenswürdige Worker*, die den Code in *Wegwerf-VMs* kompilieren, und
> promotet erfolgreiche Pakete über eine mehrstufige Pipeline (`dev → testing →
> staging → stable`) in einen öffentlichen, signierten und zwischengespeicherten
> Registry-Index.

---

## 2. Das große Bild: Control Plane vs. Data Plane

Die zentrale Architekturentscheidung ist die **strikte Trennung von Vertrauen**.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE                                 │
│                      (vertrauenswürdig)                                │
│                                                                        │
│   cmd/server  ──►  hält ALLE Secrets:                                  │
│                    • PostgreSQL-Credentials                            │
│                    • S3 Access/Secret Keys                             │
│                    • Vault-Token (AppRole, auto-renewed)               │
│                    • GitHub-App Private Key                            │
│                    • Cloudflare API Token                              │
│                                                                        │
│   Zwei HTTP-Server:                                                    │
│   ┌─────────────────────────┐    ┌──────────────────────────────┐     │
│   │  Public Server :8080    │    │  Internal Server :8443       │     │
│   │  (öffentliches API,     │    │  (mTLS, NUR Worker)          │     │
│   │   Auth via Bearer-Token)│    │   RequireAndVerifyClientCert │     │
│   └─────────────────────────┘    └──────────────────────────────┘     │
└───────────────────────────────────┬────────────────────────────────────┘
                                     │  mTLS
                                     │  (kurzlebige Zertifikate aus Vault PKI)
                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                           DATA PLANE                                   │
│                      (UNvertrauenswürdig)                              │
│                                                                        │
│   cmd/worker  ──►  hält KEINE Secrets. Nur eine mTLS-Identität.        │
│                    Alle privilegierten Operationen (Job claimen,       │
│                    Paket signieren, DB-Writes, GitHub-Status)          │
│                    werden an die Control Plane delegiert.              │
│                                                                        │
│   Startet pro Job eine Firecracker-microVM:                           │
│   ┌──────────────────────────────────────────────────────────┐        │
│   │  Firecracker microVM (cmd/vmrunner als PID 1)            │        │
│   │  • kein Netzwerk, kein gemeinsames Dateisystem           │        │
│   │  • I/O nur über ext4-Block-Devices (tar)                 │        │
│   │  • kompiliert & validiert untrusted PR-Code              │        │
│   └──────────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────────┘
```

**Warum dieser Aufwand?** Die Worker führen *fremden, nicht überprüften C-Code*
aus (aus Community-Pull-Requests). Würde ein Angreifer den Build-Schritt
kompromittieren, könnte er ohne diese Trennung an die gesamte Registry-Infrastruktur
gelangen. Durch das Zero-Trust-Modell gilt: Selbst eine vollständige Übernahme
eines Workers gibt dem Angreifer nur eine mTLS-Identität mit eng begrenzten,
delegierten Rechten — und keinen direkten Zugriff auf DB, Storage oder Signing-Keys.

### Die drei Job-Typen

Durch das System fließen drei unabhängige Job-Arten, jede mit eigener Queue,
eigener Tabelle und eigenem Worker-Polling-Pfad:

| Job-Typ            | Tabelle           | Auslöser                              | Zweck                                                       |
|--------------------|-------------------|---------------------------------------|------------------------------------------------------------|
| **Validation Job** | `validation_jobs` | GitHub PR-Webhook                     | Untrusted PR-Diff in VM validieren → Pakete ins Staging    |
| **Publish Job**    | `publish_jobs`    | Publisher promotet `dev → testing`    | Eigenes Paket kompilieren (Compile-Validierung)            |
| **Release Job**    | `release_jobs`    | Push auf `main` / SemVer-Oracle       | CLI/Core/Compiler-Releases bauen, taggen, mirrorn          |

---

## 3. Die fünf Binaries (`cmd/`)

Das Projekt kompiliert zu fünf eigenständigen Programmen. Drei davon sind
langlaufende Daemons, zwei sind kurzlebige Prozesse.

### 3.1 `cmd/server` — Der API-Server (Control Plane)

Das Herzstück. `main.go` macht zwei Dinge je nach Argument:

- **`server migrate`** — führt nur die DB-Migrationen aus (wird als Nomad-Prestart-Task
  vor dem eigentlichen Start gefahren) und beendet sich.
- **`server`** (ohne Argument) — startet den vollen Dienst.

Der Lebenszyklus von `run()`:

1. **Config laden** (`config.Load()`) — inkl. Vault-Authentifizierung und
   Secret-Beschaffung. `defer cfg.Vault.Close()` stoppt am Ende die Token-Erneuerung.
2. **Strukturiertes Logging** — JSON in Produktion (`TOOB_ENV=production`),
   sonst menschenlesbarer Text.
3. **Lifecycle-Context** — `signal.NotifyContext` auf `SIGINT`/`SIGTERM`. Dieser
   Context wird an *alle* Hintergrund-Goroutinen und den Router weitergereicht,
   sodass sie sauber herunterfahren.
4. **Datenbank-Pool** öffnen (`postgres.Connect`).
5. **Dependency-Wiring** (`app.Wire`) — instanziiert alle Stores, Services, Clients.
6. **Cache-Sync-Listener** starten — lauscht via PostgreSQL `LISTEN/NOTIFY` auf
   Registry-Updates (für horizontale Skalierung mehrerer API-Knoten).
7. **Hintergrund-Reaper** als Goroutinen starten (siehe unten).
8. **Router bauen** und den **Public-HTTP-Server** auf `:8080` starten.
9. Optional den **Internal-mTLS-Server** auf `:8443` starten (nur wenn die
   Worker-TLS-Konfiguration vollständig ist — sonst Fail-Closed-Fehler).
10. Auf `ctx.Done()` warten → **15 s Graceful Drain** (`IsShuttingDown` wird gesetzt,
    Health-Check meldet ab) → Server-Shutdown mit 10 s Deadline → auf das Flushen
    der Download-Counter-Worker warten.

Die im Server laufenden **Hintergrund-Reaper** (alle als eigene Goroutine):

- `runPublishJobReaper` — setzt Compile-Jobs zurück, die zu lange in `COMPILING`
  hängen (alle 2 min, max. 10 min Alter, max. 3 Retries).
- `runReleaseJobReaper` — analog für Release-Jobs (max. 20 min Alter, da
  VM-Builds länger dauern).
- `runOAuthSessionCleaner` — löscht abgelaufene Login-Sessions (jede Minute).
- `runAuditLogRetention` — löscht Audit-Einträge älter als 2 Jahre (täglich).

> **Eine subtile, aber wichtige Designentscheidung:** Migrationen laufen *nur*
> über das `migrate`-Subkommando, nicht beim normalen Start. Das verhindert, dass
> mehrere gleichzeitig hochfahrende API-Instanzen konkurrierende DDL ausführen.

### 3.2 `cmd/worker` — Der Worker-Daemon (Data Plane)

Der Kommentar im Code bringt es auf den Punkt:

> *„This binary holds NO database credentials, NO S3 keys, NO Vault tokens, and NO
> GitHub App secrets. It authenticates to the Control Plane API via mTLS using
> short-lived certificates issued by Vault PKI.“*

Ablauf:

1. Worker-Config aus Environment laden (`config.LoadWorker`) — rein host-lokale,
   nicht-geheime Pfade (Firecracker-Binary, Kernel, Rootfs) plus mTLS-Zertifikatspfade.
2. **mTLS-API-Client** initialisieren (`worker.NewAPIClient`).
3. Lokalen **Health-Check-Server** auf `:8081` starten (für Nomads
   Provider-Monitoring).
4. **Daemon** starten (Polling-Loop, siehe Kapitel 6).
5. Auf `SIGINT`/`SIGTERM` warten → `cancel()` → `daemon.Shutdown(5 min)`: wartet
   auf das Ende laufender VMs (hartes Limit 5 Minuten).

### 3.3 `cmd/autoscaler` — Der Autoscaler

Ein kleiner, eigenständiger Daemon, der die Anzahl der Worker-VMs auf Hetzner
Cloud anpasst. Verbindet sich mit einem *konservativ kleinen* DB-Pool (5
Verbindungen), liest Queue-Statistiken, fragt Nomad und Vault ab und provisioniert
bzw. entfernt VMs. Details in Kapitel 9.

### 3.4 `cmd/validator` — Standalone-Validator

Eine schlanke CLI, die die Validierungs-Pipeline (`validate.RunAll`) *außerhalb*
einer VM ausführt — z. B. für lokale Tests oder CI. Nimmt `--registry-dir` und
`--diff-file`, gibt das Ergebnis als JSON aus und setzt den Exit-Code (`1` bei
Fehler, `2` bei Argument-/Parse-Fehlern). Dieselbe Logik läuft auch im `vmrunner`.

### 3.5 `cmd/vmrunner` — Der Init-Prozess in der microVM

Das ist das technisch faszinierendste Binary. Es läuft als **PID 1** *innerhalb*
der Firecracker-microVM und ist `//go:build linux`-getaggt (existiert nur unter
Linux). Es validiert untrusted PR-Diffs gegen den aktuellen Registry-Zustand.

**Drive-Layout** (alle I/O läuft über ext4-Block-Devices — kein Netzwerk, kein
Shared Filesystem):

```
/dev/vda = rootfs     (read-only, enthält dieses Binary + busybox)
/dev/vdb = snapshot   (read-only, aktueller Registry-Zustand)
/dev/vdc = input      (read-only, enthält pr.diff)
/dev/vdd = output     (read-write, hier werden Ergebnisse hingeschrieben)
```

> **Lebenswichtiges Detail:** PID 1 darf nicht `exit()` aufrufen — das löst eine
> Kernel-Panic aus. Stattdessen ruft `shutdown()` am Ende `syscall.Sync()` und
> `reboot(POWER_OFF)` auf. Selbst im Fehlerfall wird zuerst das Ergebnis auf das
> Output-Device geschrieben, dann sauber heruntergefahren.

Der `vmrunner` kann zwei Arten von Jobs ausführen:
- **Publish-/Validation-Jobs** — Paket extrahieren, Validierung laufen lassen,
  optional kompilieren, Tarballs erzeugen.
- **Release-/SemVer-Jobs** (`semver.go`) — der „SemVer-Oracle“, der ABI- und
  AST-Diffs durchführt (Kapitel 10).

---

## 4. Domänenmodell (`internal/domain`)

Das `domain`-Paket enthält die *reinen* Geschäftsobjekte und Regeln — ohne
Abhängigkeit zur Datenbank, zu HTTP oder zu konkreten Treibern (z. B. pgx).
Dadurch bleibt die Geschäftslogik testbar und entkoppelt. Hier wohnen die
Konzepte, die das ganze System prägen.

### 4.1 Das Paket (`Package`) und sein Lebenszyklus

`Package` ist das zentrale Speichermodell für *alle* Registry-Inhalte. Statt für
jede Kategorie eine eigene Tabelle zu haben, gibt es **ein** vereinheitlichtes
Modell. Kategorie-spezifische Felder (Quellen, URLs, CFLAGS, Speicher-Footprint
usw.) leben als rohes JSONB im `Manifest`-Feld — nicht als typisierte Spalten.

```go
type Package struct {
    ID            string          // UUID, von der DB generiert — rein intern
    Name          string
    Version       string
    Category      Category        // chip, driver, crypto, arch, toolchain, ...
    Subcategory   string          // driver: flash/uart/...; crypto: backend/hash/pqc
    Stage         Stage           // dev → testing → staging → stable → ...
    StagingStatus *StagingStatus  // nil außer wenn Stage == staging
    PublisherID   *string         // UUID, nil für Core-Team-Seed-Daten
    Manifest      json.RawMessage // vollständiges, rohes Manifest
    TarballKey    string          // S3-Objekt-Key
    TarballSHA    string          // SHA-256-Hex des Tarballs
    Signature     string          // Ed25519-Signatur (base64)
    DownloadCount int64
    // ... Zeitstempel (PromotedAt, YankedAt, CreatedAt)
}
```

**Die `Category`** klassifiziert ein Paket nach seiner Rolle im Build-Graph:
`chip`, `driver`, `crypto`, `arch`, `toolchain`, `integration`, `soc`, `port`.
Die Map `ManifestFilenames` verbindet jeden kanonischen Manifest-Dateinamen
(`chip_manifest.json`, `driver_manifest.json` …) mit seiner Kategorie — so erkennt
das System anhand der Datei im Tarball automatisch, um welche Kategorie es sich
handelt.

**Die `Stage`** ist das Kernkonzept des Lebenszyklus. Ein Paket wandert durch die
Pipeline:

```
dev ──► testing ──► staging ──► stable ──► archived (deprecated)
                                       └─► revoked  (Security-Issue → Advisory)
```

- **`dev`** — privat, nur beim Publisher sichtbar.
- **`testing`** — automatische Compile-Validierung läuft in der Firecracker-VM.
- **`staging`** — wartet auf menschliche Core-Team-Review.
- **`stable`** — *nur diese* Pakete erscheinen im öffentlichen Registry-Index.
- **`archived`** — End-of-Life, wird nicht mehr verteilt.
- **`revoked`** — aus Sicherheitsgründen entfernt; löst ein Security-Advisory aus.

Die erlaubten Übergänge sind als Methode `CanTransitionTo` kodiert — und werden
zusätzlich auf DB-Ebene durch einen Trigger erzwungen (Migration 020). Das ist
**Defense-in-Depth**: Selbst wenn die Anwendungslogik einen Fehler hätte, ließe
die Datenbank einen ungültigen Stage-Übergang nicht zu.

**Scoped Packages** funktionieren wie bei npm (`@scope/name`). Die Helfer
`ParseScope` und `IsScoped` zerlegen bzw. erkennen solche Namen. Ein Scope wie
`@robin` muss entweder dem GitHub-Login des Publishers entsprechen oder einer
Organisation, in der er Mitglied ist (siehe Autorisierung).

### 4.2 Publisher, Rollen und Authentifizierung

Ein **`Publisher`** ist eine registrierte Entwickler-Identität. Authentifizierung
läuft über GitHub-OAuth, Autorisierung über API-Keys.

Es gibt zwei globale **Rollen** (`Role`):
- **`contributor`** — darf eigene Pakete veröffentlichen (dev-Stage).
- **`core`** — darf zusätzlich promoten, releasen und administrieren.

Besonders interessant ist die **API-Key-Erzeugung** (`GenerateAPIKey`). Das Format
ist `toob_v1_<PublisherUUID>_<64HexChars>`. Hex wird bewusst gewählt, damit das
Geheimnis keine `_`-Zeichen enthält, die mit dem Trennzeichen beim Parsen
kollidieren würden. Gespeichert wird nicht der Key selbst, sondern ein
**SHA-256-Hash** (Präfix `$sha256$`). Die Verifikation (`VerifyAPIKey`) nutzt
`subtle.ConstantTimeCompare`, um Timing-Angriffe zu verhindern. Aus
Abwärtskompatibilität wird auch noch bcrypt unterstützt.

Daneben gibt es **`APIToken`** für CI-Umgebungen (Format `toob_ci_<TokenID>_<Hex>`).
Diese sind *gescopt* — sie tragen eine Liste erlaubter Scopes (z. B. `publish`,
`read`) und können ein Ablaufdatum haben.

Die **`OAuthSession`** trackt temporäre CLI-Login-Flows mit PKCE (Code Challenge,
Redirect-URI usw.).

### 4.3 Permissions & der Authorizer

Das `permission.go` definiert ein fein granulares Berechtigungssystem.

**Atomare Permissions** (`Permission`) wie `package:publish`, `org:create`,
`registry:revoke`, `admin:dashboard`. Die Map `RolePermissions` ordnet jeder
globalen Rolle ihre erlaubten Permissions zu. `HasPermission` prüft, ob ein
Publisher eine bestimmte globale Permission besitzt.

Der **`Authorizer`** ist ein Interface, das alle kontextabhängigen
Autorisierungsentscheidungen kapselt:

```go
type Authorizer interface {
    AuthorizeOrgAction(...)        (AuthzDecision, error)
    AuthorizePackageAction(...)    (AuthzDecision, error)
    AuthorizePublishJobAction(...) (AuthzDecision, error)
    AuthorizeScopeClaim(...)       (AuthzDecision, error)
    AuthorizeNameClaim(...)        (AuthzDecision, error)
}
```

Die `AuthzDecision` trägt nicht nur „erlaubt ja/nein“, sondern auch, ob die
Entscheidung über einen **Admin-Override** (`ViaOverride`) zustande kam und welche
Org-Rolle relevant war. Die konkrete Implementierung lebt in `authz.PolicyEngine`
(siehe Abschnitt 5.5).

### 4.4 Organisationen

Eine **`Organization`** ist ein Team-Scope-Namespace (z. B. `@esp-alliance`). Die
**Org-Rollen** (`OrgRole`) sind:
- **`owner`** — volle Kontrolle (Mitglieder + Rollen verwalten).
- **`maintainer`** — kann Mitglieder hinzufügen/entfernen (außer Owner).
- **`member`** — kann unter dem Org-Scope veröffentlichen.

Die Methoden `CanManageMembers` und `CanManageRoles` kodieren diese Hierarchie
direkt am Rollen-Typ.

### 4.5 Die Job-Typen als Domänenobjekte

Für jeden der drei Job-Typen gibt es ein Domänenobjekt plus mehrere DTOs, die die
**Grenze zwischen Control Plane und Data Plane** definieren. Das Muster ist
durchgängig:

- **`ValidationJob`** / `ClaimedJob` / `UploadRequest` / `CompleteRequest`
- **`PublishJob`** / `PublishClaimedJob` / `PublishCompleteRequest`
- **`ReleaseJob`** / `ReleaseClaimedJob` / `ReleaseCompleteRequest`

Wichtig ist hier das **Zero-Trust-Prinzip in den Typen selbst**. Der Kommentar im
Code:

> *„These types define the boundary between Control Plane (API Server) and Data
> Plane (Worker Daemon). The worker receives only the data it needs for a single
> job — no credentials, no signing keys.“*

Ein `ClaimedJob` enthält z. B. nur Metadaten (PR-Nummer, Repo, SHA, Diff-URL) plus
einen **einmaligen Job-Token**, der *alle* nachfolgenden API-Calls für genau
diesen Job autorisiert. Sensible Felder wie `JobToken` in `ValidationJob` tragen
`json:"-"` und werden nie nach außen serialisiert.

### 4.6 Advisories, Revisionen und Pläne

- **`Advisory`** — wird ausgestellt, wenn ein Paket widerrufen (`revoked`) wird.
  Enthält Severity (`critical`/`high`/`medium`/`low`), betroffene Revisionen und
  dient dazu, alle Publisher zu benachrichtigen, die diese Revisionen synchronisiert
  haben. Das `SyncRecord` ist der Audit-Log, der das ermöglicht — es trackt, welcher
  Publisher welche Revision synchronisiert hat.

- **`Revision`** — eine monoton steigende Ganzzahl, die *jede* veröffentlichte
  Änderung trackt. Sie ersetzt klassische SemVer-Versionierung für den
  Registry-Index. CLI-Clients synchronisieren differenziell: „Gib mir alles seit
  Revision N.“ Jede Revision trägt einen `Changelog`.

- **`UserPlan`** — definiert Ressourcen-Limits (`free`/`pro`/`enterprise`).
  `DefaultPlan` liefert die Standard-Limits, `ResolvePlan` mischt tier-Defaults mit
  individuellen JSON-Overrides. So kann das Core-Team einzelnen Publishern höhere
  Kontingente geben, ohne den Code zu ändern.

- **`RegistryIndex`** — das exakte Wire-Format der `registry.json`, die unter
  `GET /api/v1/registry/index` ausgeliefert wird. Jede Kategorie hat ihren eigenen
  Eintrags-Typ (`ChipEntry`, `DriverEntry`, `CryptoEntry` usw.), der 1:1 die
  Struktur der jeweiligen Manifest-Datei abbildet.

### 4.7 Domänen-Fehler

`errors.go` definiert plattformunabhängige Sentinel-Fehler (`ErrNotFound`,
`ErrAlreadyExists`, `ErrUnauthorized`, `ErrForbidden` …). Das entkoppelt die
Handler-Schicht von konkreten DB-Treiber-Fehlern: Die Postgres-Stores übersetzen
pgx-spezifische Fehler (z. B. Unique-Violation `23505`) in diese Domänen-Fehler,
und die Handler reagieren nur auf die Domänen-Fehler.

---

## 5. Der API-Server (Control Plane)

Der API-Server unter `internal/server/` ist mit Abstand der umfangreichste Teil
des Systems. Er ist sauber in Schichten aufgeteilt: Konfiguration → Wiring →
Router → Middleware → Handler → Stores. Wir gehen sie der Reihe nach durch.

### 5.1 Konfiguration & Secrets (`config` + `vault`)

Die Philosophie der Konfiguration ist bemerkenswert: **Nur vier Umgebungsvariablen
tragen sicherheitsrelevantes Material**, und das auch nur, um an Vault zu kommen:

- `VAULT_ADDR` — wo Vault zu finden ist (muss HTTPS sein)
- `VAULT_ROLE_ID` — die AppRole-Identität dieses Servers
- `VAULT_SECRET_ID` — die einmalige Credential, die die Identität beweist
- `VAULT_CA_CERT` — optionaler CA-Zertifikatspfad für Vaults TLS

**Alle übrigen Geheimnisse** (DB-URL, GitHub-App-Key, S3-Keys, Cloudflare-Token,
Webhook-Secret, OAuth-AES-Key, Docker-Hub-Credentials) werden zum Startzeitpunkt
aus **Vault KV v2** geladen. Host-Level-Einstellungen (Ports, Bind-Adresse,
Kontingente, Repo-Namen, S3-Endpunkte) kommen aus dem Environment, weil sie keine
Geheimnisse sind.

`Load()` macht dies in klaren Schritten: Host-Env lesen → Vault-Auth (AppRole
*oder* Token-Fallback) → alle Secret-Gruppen aus Vault ziehen (`loadDatabaseSecrets`,
`loadGitHubAppSecrets`, …) → `Validate()`. Die abschließende `Validate()`-Methode
prüft die semantische Korrektheit jedes Feldes (Port-Bereiche, Log-Level,
DB-URL-Präfix, Existenz der TLS-Dateien usw.) und sorgt dafür, dass der Server bei
unsinniger Konfiguration gar nicht erst startet.

#### Der Vault-Client (`vault.Client`)

Der Vault-Client ist ein Musterbeispiel für sauberes Secret-Lifecycle-Management:

- **HTTPS-only** mit TLS 1.3 als Minimum.
- **Keine langlebigen Tokens** — AppRole-Login erzeugt ein TTL-gebundenes Token.
- **Die `SecretID` wird nach dem Login aus dem Speicher gelöscht** — sie wird
  bewusst *nicht* auf dem Struct gespeichert, sondern nur als Parameter
  übergeben und nach einmaligem Gebrauch der Garbage Collection überlassen.
- **Proaktive Token-Erneuerung** — der `renewLoop` erneuert das Token bei 50 %
  seiner TTL über `renew-self`. Bei Fehlschlag: exponentielles Backoff. Da die
  `SecretID` verworfen wurde, ist *keine* Re-Authentifizierung möglich — bei
  dauerhaftem Renewal-Fehler ist ein Prozess-Neustart mit frischer `SecretID`
  nötig. Das ist eine bewusste Sicherheitseigenschaft.

Es gibt zwei Konstruktoren: `NewClient` (AppRole-Login mit eigenem Renewal-Loop)
und `NewClientWithToken` (externes Token, z. B. von Nomad injiziert; startet bei
Bedarf einen `pollTokenFile`-Goroutine, der ein rotiertes Token aus einer Datei
nachlädt).

`ReadKV` liest Secrets aus KV v2 und **sanitisiert Fehlermeldungen** — Vault-Interna
landen nie in Logs oder Antworten. `MustGet` liest einen Pflicht-Schlüssel und
gibt einen Fehler zurück, wenn er fehlt oder leer ist.

### 5.2 Dependency Wiring (`app`)

`app.App` ist der **Dependency-Container**. Alle großen Services und Stores werden
*einmal* in `Wire()` instanziiert:

```go
type App struct {
    Config, DB, Stores
    ObjectStore   storage.ObjectStore     // S3
    Signer        crypto.Signer           // Vault Transit
    GitHubClient  *github.AppClient
    Cloudflare    *cloudflare.Client
    MirrorPusher  *mirror.Pusher
    PolicyEngine  *authz.PolicyEngine
    RegCache      *cache.RegistryCache
    RateLimiter   *middleware.RateLimiter
    AuthMiddleware *middleware.AuthMiddleware
    Ingestor      *ingest.Ingestor
    Notifier      *notify.Dispatcher
}
```

`Wire()` ist explizit und ohne „Magie“ — jeder Konstruktor wird von Hand
aufgerufen und Fehler werden umschlossen weitergereicht. Am Ende baut
`populateCache` den initialen Registry-Index-Cache auf, indem es die neueste
Revision, die Ökosystem-Versionen und alle stable-Pakete liest, den Index baut,
ihn marshalled und in den `RegistryCache` legt.

### 5.3 Router & Middleware (`router`)

Der Router (`NewRouter`) baut den kompletten HTTP-`ServeMux` und registriert die
Routen in modularen Gruppen: `registerPublicRoutes`, `registerAuthRoutes`,
`registerPublishRoutes`, `registerAdminRoutes`, `registerOrgRoutes`. Webhooks
laufen über einen separaten Mux mit eigener Signaturprüfung.

Die **Middleware-Kette** (`buildMiddlewareChain`) wird von innen nach außen
aufgebaut:

```
RateLimiter → Timeout → MaxBodySize → Compress → Recovery → Instrument → Logging
```

(Die Reihenfolge im Code ist umgekehrt notiert, weil jede Middleware die
*nächste* umschließt.) Die einzelnen Middlewares:

| Middleware                | Datei              | Zweck                                                                 |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| `Logging`                 | `logging.go`       | Loggt jede Anfrage mit Request-ID, Methode, Pfad, Status, Dauer, IP   |
| `Instrument`              | `metrics/`         | Prometheus-Zähler & -Histogramme pro Route                            |
| `Recovery`                | `recovery.go`      | Fängt Panics, gibt 500 zurück (wenn noch keine Header geschrieben)    |
| `Compress`                | `compress.go`      | gzip-Kompression (Pool von Writern); SSE-Streams ausgenommen          |
| `MaxBodySize`             | `bodylimit.go`     | Body-Limit (256 KB, dynamisch 10 MB für Upload/Webhook-Routen)        |
| `Timeout`                 | `timeout.go`       | Write-Deadline für Nicht-SSE-Routen (verhindert Slow-Writer-Angriffe) |
| `RateLimiter`             | `ratelimit.go`     | IP-basiertes Rate-Limiting                                            |
| `EdgeCache` / `WithETag`  | `edge_cache.go`    | Cloudflare-Caching-Header + ETag/304-Handling                        |

**Bemerkenswerte Details der Middlewares:**

- **`Compress`** schließt explizit `text/event-stream` aus — gzip-Pufferung würde
  Server-Sent-Events kaputt machen. Alle Wrapper implementieren sauber `Flush()`
  und `Unwrap()`, damit Streaming weiter funktioniert.

- **`RateLimiter`** ist erstaunlich ausgefeilt. Er hält pro IP einen
  `rate.Limiter` (Token-Bucket). Die Map ist auf 100.000 Einträge gedeckelt; bei
  Überschreitung läuft `evictBadly`: erst werden alle seit >1 Minute ungesehenen
  IPs gelöscht, dann (falls immer noch >80.000) die ältesten Einträge sortiert und
  abgeräumt. Ein periodischer `cleanup` (alle 5 min, an den Context gebunden)
  entfernt veraltete IPs. `getIP` berücksichtigt Cloudflare-/Proxy-Header
  (`CF-Connecting-IP`, `X-Forwarded-For`) — aber nur, wenn die direkte
  Verbindung von einem vertrauenswürdigen Proxy (Loopback/private Ranges) kommt.

- **`Timeout`** überspringt bewusst alle `/stream`-Routen, um langlebige
  SSE-Verbindungen nicht zu kappen.

#### Der Internal-Router (mTLS)

`NewInternalRouter` baut einen *separaten* Mux nur für die Worker-Endpunkte
(`/api/v1/worker/...`). Er ist durch `RequireWorkerMTLS` geschützt und hat eine
eigene, großzügigere Rate-Limit-Konfiguration (trusted Clients, aber Schutz gegen
einen kompromittierten Knoten). Wenn die Worker-CA-Datei fehlt, **panict** der
Router beim Bau — Fail-Closed.

### 5.4 Authentifizierung & Autorisierung

#### Auth-Middleware (`middleware/auth.go`)

Die `AuthMiddleware` parst den `Authorization: Bearer`-Header und verifiziert das
Token. Das Token-Format `toob_<type>_<uuid>_<secret>` wird zerlegt; der `type`
unterscheidet `v1` (Session-Token) von `ci` (gescoptes Token).

Das interessanteste Detail ist die **Verteidigung gegen bcrypt-CPU-DoS** in
`verifyCached`. Bcrypt/Hash-Vergleiche sind absichtlich teuer — ein Angreifer
könnte mit einer Flut von Müll-Keys die CPU lahmlegen. Die Lösung ist ein
**doppelt gepufferter Cache** (zwei Map-Generationen, „current“ und „previous“):

> Lesen prüft *beide* Maps; Schreiben geht in „current“. Wenn „current“ voll ist,
> wird „previous“ verworfen, „current“ wird zu „previous“, und ein frisches
> „current“ entsteht. Ein Angreifer, der Müll-Keys flutet, kann nur die
> „previous“-Generation verdrängen — gültige Einträge in „current“ überleben und
> umgehen weiterhin bcrypt.

Der Cache-Key ist ein SHA-256 aus Secret + Hash, Einträge leben 60 Sekunden.

Es gibt mehrere Middleware-Varianten:
- `RequireAuth` — verlangt gültige Authentifizierung.
- `OptionalAuth` — verifiziert nur, *wenn* ein Header da ist (für öffentliche
  Endpunkte, die bei eingeloggten Nutzern mehr zeigen).
- `RequirePermission(perm)` — verlangt eine bestimmte globale Permission.
- `RequireSessionToken()` — lehnt CI-Tokens ab (administrative Aktionen brauchen
  einen Session-Token).
- `RequireScope(scope)` (in `scope.go`) — prüft Token-Scopes mit Präfix-Semantik
  (Scope `publish` deckt `publish:promote` ab; `*` ist Wildcard).

#### Worker-mTLS (`middleware/mtls.go`)

`RequireWorkerMTLS` ist die zweite Verteidigungslinie für den Internal-Server. Es
prüft, dass die Verbindung ein gültiges Client-Zertifikat trägt, das von der
internen Vault-PKI-CA signiert ist. Selbst wenn die TLS-Konfiguration fehlerhaft
wäre, würde diese Middleware unauthentifizierte Verbindungen abweisen.

> **Vitaler Fix gegen Lateral Movement:** Es reicht nicht, dass das Zertifikat von
> der Nomad-Cluster-PKI stammt. Die Middleware prüft zusätzlich, dass der
> `CommonName` exakt `worker.global.nomad` ist — sonst könnte ein API-Knoten oder
> Server mit gültigem Cluster-Zertifikat sich als Worker ausgeben.

#### Webhook-Signaturen (`middleware/webhook.go`)

`VerifyWebhookSignature` validiert den `X-Hub-Signature-256`-Header (GitHubs HMAC)
mit `hmac.Equal` (konstante Zeit). Der Body wird gelesen, der HMAC berechnet und
verglichen; danach wird der Body neu eingewickelt, damit der Handler ihn nochmal
lesen kann.

#### Die Policy-Engine (`authz/policy.go`)

`PolicyEngine` implementiert das `domain.Authorizer`-Interface — hier wohnt die
eigentliche Autorisierungslogik. Sie nutzt zwei Reader-Interfaces
(`OrgMemberReader`, `PackageAccessReader`), um Mitglieds-Rollen und
Paket-Sharing-Grants nachzuschlagen.

Durchgängiges Muster: Erst wird die *normale* Rollen-Autorität geprüft; schlägt
diese fehl, wird auf einen **Admin-Override** (`PermOrgAdminBypass`) zurückgegriffen
— und *jeder* solche Override wird per `slog.Info("AUDIT: ...")` protokolliert.
Beispiel `AuthorizeOrgAction` für `OrgActionDelete`: Owner dürfen direkt; sonst
prüft die Engine, ob der Nutzer globale Delete- oder Admin-Bypass-Rechte hat, und
loggt im Erfolgsfall den Bypass.

`AuthorizePackageAction` für `PackageActionRead` zeigt die Lesbarkeitslogik:
stable-Pakete sind öffentlich; sonst muss man Eigentümer sein, Admin-Bypass haben
oder einen expliziten Package-Access-Grant besitzen. DB-Fehler werden propagiert
(keine stillen Fehlschläge).

`AuthorizeScopeClaim` und `AuthorizeNameClaim` regeln, wer einen `@scope/name`
beanspruchen darf: entweder der Scope entspricht dem GitHub-Login, oder man ist
Org-Mitglied — bei fremdem Eigentümer greift nur der Admin-Bypass.

---


## 6. Der Worker-Daemon (Data Plane)

Der Worker ist das Gegenstück zur Control Plane: ein langlaufender Daemon, der auf
dedizierten Hetzner-VMs läuft und die eigentliche, potenziell gefährliche Arbeit
verrichtet — das Kompilieren und Validieren von fremdem Code. Sein gesamtes Design
folgt einem einzigen Leitsatz: **Er besitzt nichts, was ein Angreifer stehlen
könnte.** Keine DB-Credentials, keine S3-Keys, kein Vault-Token, keinen
GitHub-App-Key. Seine einzige Identität ist ein mTLS-Client-Zertifikat, und jede
privilegierte Operation wird über die Worker-API an die Control Plane delegiert.

Der Code liegt unter `internal/worker/` (Config + Daemon) und `cmd/worker/`
(Entry-Point).

### 6.1 Das Zero-Trust-Prinzip in der Praxis

Was im Domänenmodell als Typ-Grenze beschrieben wurde (Kapitel 4.5), wird hier
mechanisch durchgesetzt. Der Worker hält pro Job nur:

- **Job-Metadaten** (PR-Nummer, Repo, SHA, Paket-ID …),
- einen **einmaligen Job-Token**, der genau diesen Job autorisiert,
- **kurzlebige presigned URLs**, die er von der Control Plane erhält, um Artefakte
  direkt nach S3 hochzuladen, ohne S3-Credentials zu besitzen.

Selbst wenn ein bösartiges Community-PR aus der VM ausbräche und den Worker
vollständig übernähme, fände der Angreifer dort nur das mTLS-Zertifikat mit eng
begrenzten, delegierten Rechten — und keinen Weg zu DB, Storage oder Signing-Key.

### 6.2 Worker-Konfiguration (`config/config.go`)

`WorkerConfig` wird ausschließlich aus Umgebungsvariablen geladen
(`LoadWorker()`) — es gibt *keinen* Vault-Zugriff. Die Felder zerfallen in vier
Gruppen:

|
 Gruppe                
|
 Felder                                                    
|
 Quelle / Default                                  
|
|
-----------------------
|
-----------------------------------------------------------
|
---------------------------------------------------
|
|
**
API (mTLS)
**
|
`APIURL`
, 
`CertFile`
, 
`KeyFile`
, 
`CAFile`
, 
`WorkerID`
|
 Env; Pflicht: 
`TOOB_API_URL`
 (muss HTTPS sein)    
|
|
**
Firecracker
**
|
`BinPath`
, 
`KernelPath`
, 
`RootfsPath`
, 
`SnapshotPath`
, 
`WorkDir`
|
 Env; Pfade müssen existieren                
|
|
**
Release-Pipeline
**
|
`MonorepoPath`
, 
`Capabilities`
|
 optional, nur auf release-fähigen Workern         
|
|
**
Ressourcen-Limits
**
|
`MaxConcurrent`
, 
`TimeoutSec`
, 
`VCPU`
, 
`MemMiB`
|
 Defaults: 2 / 120 s / 1 vCPU / 256 MiB            
|

Die abschließende `Validate()`-Methode ist bewusst streng und sorgt dafür, dass ein
falsch konfigurierter Worker gar nicht erst startet:

- Die API-URL muss `https://` sein (mTLS erfordert TLS).
- Alle Firecracker-Pfade *und* die drei mTLS-Dateien müssen per `os.Stat`
  erreichbar sein.
- Auf Linux wird zusätzlich geprüft, dass der **private Schlüssel nicht
  world-/group-readable** ist (`Perm()&0077 != 0` → Fehler). Das verhindert, dass
  die Worker-Identität versehentlich für andere Prozesse lesbar wird.

Zwei Details mit Praxisbezug:

- **`WorkerID`-Auto-Generierung:** Ist `TOOB_WORKER_ID` nicht gesetzt, bildet der
  Worker seine ID aus `hostname-pid`. Das ist wichtig für den Autoscaler, der
  beliebig viele Scale-out-Worker ohne explizite ID-Konfiguration startet —
  Identitätskollisionen sind damit ausgeschlossen.
- **`Capabilities`-Auto-Detection:** Ist kein `TOOB_WORKER_CAPABILITIES` gesetzt,
  aber ein `MonorepoPath` vorhanden, erhält der Worker die Capabilities
  `semver, core, cli`. Ist zusätzlich `docker` im PATH, kommt `compiler` hinzu.
  So entscheidet ein Worker selbst, welche Release-Jobs er übernehmen darf.

### 6.3 Der mTLS-API-Client (`daemon/apiclient.go`)

`APIClient` ist die einzige Brücke zur Außenwelt. Das entscheidende Designmerkmal
sind **zwei getrennte HTTP-Clients**:

```
┌─────────────────────────────────────────────────────────┐
│ APIClient                                                 │
│                                                           │
│  http      → mTLS-Client (Worker-Zertifikat)             │
│              ▸ NUR für Control-Plane-Calls                │
│              ▸ Timeout 30 s                               │
│                                                           │
│  external  → Plain-HTTPS-Client (KEIN Client-Zertifikat) │
│              ▸ für S3-Uploads & Diff-Downloads            │
│              ▸ Timeout 5 min (Uploads dauern länger)      │
└─────────────────────────────────────────────────────────┘
```

> **Warum die Trennung?** Würde der Worker seinen mTLS-Client auch für S3-Uploads
> oder GitHub-Diff-Downloads verwenden, sendete er sein Identitätszertifikat an
> Dritte (Hetzner, GitHub). Der `external`-Client sendet *kein* Client-Zertifikat
> und verhindert damit, dass die Worker-Identität an Drittsysteme leakt.

Beim Aufbau prüft der Konstruktor zusätzlich, dass das geladene Zertifikat **nicht
bereits abgelaufen** ist (`time.Now().After(leaf.NotAfter)`) — ein Worker mit
abgelaufenem Zertifikat scheitert sofort statt erst beim ersten API-Call.

Die Methoden bilden 1:1 die Worker-API-Endpunkte ab: `ClaimJob`,
`RequestUploadURLs`, `UploadToPresignedURL`, `CompleteJob`, `SendHeartbeat`,
`SendLogChunk`, `DownloadDiff` sowie die Publish- und Release-Pendants
(`PublishClaim`/`PublishComplete`, `ReleaseClaim`/`ReleaseComplete`/
`ReleaseUploadRequest`). `SendHeartbeat` ist dabei mehr als ein Lebenszeichen — die
Antwort (`HeartbeatResponse.CancelJobs`) trägt die IDs von Jobs, die der Worker
abbrechen soll (siehe 6.5).

### 6.4 Der Polling-Loop & Nebenläufigkeit (`daemon/daemon.go`)

`Daemon.Start(ctx)` ist das Herz des Workers. Es blockiert bis zum Context-Abbruch
und orchestriert mehrere Ticker:

```
Start(ctx)
  ├─ initialer Snapshot-Rebuild (im Hintergrund, blockiert den Start nicht)
  ├─ ticker        (3 s)   → Jobs pollen
  ├─ heartbeat     (10 s)  → Lebenszeichen + Cancel-Signale
  └─ rebuildTicker (24 h)  → Registry-Snapshot neu bauen
```

Die Nebenläufigkeit wird über ein **gepuffertes Semaphor-Channel** (`sem`) mit
Kapazität `MaxConcurrent` begrenzt. Bei jedem `ticker`-Tick versucht der Worker
*nicht-blockierend* je einen Slot für die drei Job-Arten zu belegen:

```go
select {
case sem <- struct{}{}:        // Slot frei?
    d.wg.Add(1)
    go func() {
        defer d.wg.Done()
        defer func() { <-sem }() // Slot freigeben
        d.processNextJob(ctx)    // bzw. processNextPublishJob / processNextReleaseJob
    }()
default:                        // kein Slot frei → diesen Tick überspringen
}
```

Damit gilt: Über *alle* Job-Arten hinweg laufen nie mehr als `MaxConcurrent`
microVMs gleichzeitig. Release-Jobs werden nur gepollt, wenn ein `MonorepoPath`
konfiguriert ist (reine Validation-Worker brauchen kein Monorepo).

Die `sync.WaitGroup` (`d.wg`) trackt alle laufenden VM-Jobs, sodass `Shutdown()`
sauber auf sie warten kann.

### 6.5 Heartbeat, Job-Cancellation & Health

Drei eng verzahnte Mechanismen sorgen für Beobachtbarkeit und kontrollierten
Abbruch:

- **Heartbeat:** Alle 10 s ruft der Worker `SendHeartbeat`. Der Server speichert
  `worker:<id>` mit Zeitstempel in `system_status` (genutzt vom Readiness-Check
  und vom Reaper, der prüft, ob ein Worker noch lebt).
- **Job-Cancellation:** Die Heartbeat-Antwort kann `CancelJobs` enthalten — etwa
  weil ein PR geschlossen oder ein Release-Job per Admin abgebrochen wurde. Der
  Worker hält in `activeJobs map[int64]context.CancelFunc` für jeden laufenden Job
  eine Cancel-Funktion bereit (`trackJob`/`untrackJob`) und ruft `cancelJobs(ids)`,
  was die Job-Contexts abbricht und damit die zugehörige VM beendet.
- **Health-Touch:** Nach erfolgreichem Heartbeat ruft der Worker `touchHealthy()`,
  das die Datei `<WorkDir>/.healthy` aktualisiert (`os.Chtimes`, bei Bedarf
  `Create`). Diese Datei dient externer Liveness-Überwachung (z. B. Nomad) als
  Beweis, dass der Daemon nicht nur läuft, sondern auch die Control Plane erreicht.

### 6.6 Die drei Verarbeitungspfade

Jeder Job-Typ hat einen eigenen `processNext*`-Pfad in `daemon/validation.go` bzw.
`daemon/release.go`. Alle folgen demselben Grundmuster — *claim → workspace →
input/output-Tar → VM → result.json → complete* —, unterscheiden sich aber im
Detail.

#### Validation-Jobs (`processNextJob`)

Validiert untrusted **PR-Diffs** aus Community-Beiträgen:

1. `ClaimJob` → Metadaten + Job-Token.
2. Workspace anlegen (`<WorkDir>/job_<id>`, am Ende `RemoveAll`).
3. PR-Diff über den `external`-Client von der `DiffURL` herunterladen
   (`DownloadDiff`, gedeckelt auf 10 MB via `io.LimitReader`).
4. `input.tar` (Diff + `allowed_domains.json`) und `output.tar` (50 MB Leerdatei)
   als Block-Devices erzeugen.
5. `executeVM` ausführen (Firecracker).
6. **`ingestAndUpload`**: `output.tar` extrahieren → `result.json` parsen → bei
   Erfolg pro erzeugtem Paket-Tarball SHA-256 berechnen → über
   `RequestUploadURLs` presigned-PUT-URLs holen → Tarballs direkt nach S3 laden →
   `CompleteJob` mit der Paketliste. Die Control Plane verifiziert dann erneut die
   Checksummen, signiert via Vault Transit und ingestiert die Pakete ins Staging.

Der doppelte Checksum-Check (Worker rechnet, Server rechnet erneut nach dem
S3-Download) stellt sicher, dass auf dem Weg über den nicht vertrauenswürdigen
Worker nichts manipuliert wird.

#### Publish-/Compile-Jobs (`processNextPublishJob`)

Kompiliert das **eigene** Paket eines Publishers (dev → testing):

1. `PublishClaim` → Metadaten (inkl. `PackageID`, `TarballKey`) + Token.
2. Tarball über den **mTLS**-Endpunkt
   `GET /api/v1/worker/packages/{id}/download` herunterladen
   (`downloadPackageTarball`) — das Paket existiert bereits in S3 aus dem
   ursprünglichen dev-Publish.
3. `input.tar`/`output.tar` erzeugen, `executeVM` ausführen.
4. `result.json` lesen → `PublishComplete` mit `PASSED`/`FAILED` + Compiler-Log.
   Bei Erfolg promotet die Control Plane das Paket nach Staging, bei Fehler zurück
   nach dev (mit Compiler-Feedback). **Hier findet kein S3-Upload statt** — der
   Worker liefert nur das Compile-Ergebnis.

#### Release-Jobs (`processNextReleaseJob`)

Der vielseitigste Pfad. Nach `ReleaseClaim` (mit den Worker-Capabilities) und einem
`git fetch --tags` wird nach `Component` verzweigt:

|
 Component   
|
 Methode                  
|
 Ausführungsort                          
|
|
-------------
|
--------------------------
|
------------------------------------------
|
|
`semver`
|
`executeSemverEnforcer`
|
**
VM
**
 (air-gapped ABI/AST-Analyse)      
|
|
`cli`
|
`executeCLIRelease`
|
 Host (Cross-Compilation Go)              
|
|
`core`
|
`executeCoreRelease`
|
 Host (
`toob build`
 + Packaging)          
|
|
`compiler`
|
`executeCompilerRelease`
|
 Host (
`build-compiler.sh --push`
)        
|

Wichtige Eigenheiten:

- **`gitMu`-Serialisierung:** Alle Host-Release-Pfade teilen sich das *eine*
  Monorepo-Verzeichnis und müssen Git-Operationen (`reset --hard`, `clean -fdx`,
  `checkout`) unter einem `sync.Mutex` (`gitMu`) serialisieren. Jeder Pfad räumt am
  Ende per `defer git checkout main` auf.
- **Credential-Injektion:** Host-Release-Schritte (insb. Compiler) erhalten ihre
  Secrets *dynamisch* über `job.Env` (von der Control Plane aus Vault befüllt) und
  injizieren sie via `cmd.Env`. Die Secrets liegen also nur zur Laufzeit im
  Speicher des Build-Prozesses, nie persistent auf dem Worker.
- **`executeSemverEnforcer`** ist der einzige Release-Pfad, der eine VM nutzt: Er
  ermittelt die letzten Tags (`gitLatestTag`), prüft per `gitHasChanges`, welche
  Subsysteme sich geändert haben, extrahiert `baseline`/`current` per
  `git archive`, gibt das `gitMu` *vor* dem VM-Lauf wieder frei (die VM braucht das
  Monorepo nicht) und reicht das Ergebnis (`TagsToPush`, modifiziertes
  Compiler-Manifest) an `ReleaseComplete` weiter. Die eigentliche Tag-Erzeugung
  passiert serverseitig (Kapitel 10).
- **`executeCLIRelease`** cross-kompiliert die CLI für `windows/amd64`,
  `linux/amd64` und `darwin/arm64` (`CGO_ENABLED=0`), verpackt sie (ZIP bzw.
  `tar.gz`), holt presigned-URLs und lädt die Artefakte nach S3 — die Control Plane
  erzeugt daraus einen GitHub-Draft-Release.
- **`executeCompilerRelease`** baut das Docker-Image und rootfs über
  `build-compiler.sh --push`, pushed ausschließlich den versionierten Tag
  (`:vX.Y.Z`) zu Docker Hub und das rootfs nach S3. Es gibt keinen `:latest`-Tag.

### 6.7 Firecracker-Lebenszyklus (`daemon/firecracker.go`)

`executeVM` kapselt den vollständigen microVM-Lifecycle über den **Jailer** (das
Firecracker-Sicherheits-Wrapper-Binary):

1. **Jail-Root** anlegen (`<workspace>/chroot/firecracker/job<id>/root`).
2. **Drives bereitstellen** — und hier liegt ein wichtiges Performance-/
   Sicherheits-Detail:
   - `rootfs.ext4` und `snapshot.ext4` werden als **Sparse-Kopie**
     (`copySparse`) dupliziert. `copySparse` liest blockweise, erkennt
     Null-Blöcke und überspringt sie per `Seek` — so bleibt die Datei dünn besetzt
     und das Kopieren schnell. Jede VM bekommt damit ihre *eigene* schreibbare
     Kopie der Read-only-Templates (Isolation).
   - `vmlinux`, `input.tar` und `output.tar` werden per **Hardlink** verbunden
     (kein Kopieren nötig, da Kernel read-only und Tar-Devices job-spezifisch).
3. **Eindeutige UID/GID pro Job:** `jailUID = 10000 + (jobID % 55536)` (Bereich
   10000–65535). Die GID nutzt die `kvm`-Gruppe, falls vorhanden. Unterschiedliche
   UIDs pro Job verhindern lateral movement zwischen VMs; die *echte* Isolation
   liefert der Jailer über Kernel-User-Namespaces.
4. **Jailer starten**, auf das API-Socket warten (`waitForSocket`, 5 s Deadline),
   die VM über die REST-API konfigurieren und booten (`configureAndStart`), dann
   auf `cmd.Wait()` warten. Der VM-Output wird über einen `LimitWriter` (Deckel
   5 MB, hängt bei Überschreitung einen Truncation-Hinweis an) in einen Puffer
   geschrieben.

### 6.8 Die Firecracker-REST-API (`daemon/vmapi.go`)

Firecracker wird über einen **Unix-Domain-Socket** mit einer minimalen REST-API
gesteuert — kein SDK nötig. Der `firecrackerClient` nutzt dafür einen
`http.Client`, dessen `DialContext` auf den Socket umgebogen ist. `configureAndStart`
sendet die Konfiguration in Abhängigkeitsreihenfolge:

|
 Schritt 
|
 Endpunkt          
|
 Inhalt                                                            
|
|
---------
|
-------------------
|
------------------------------------------------------------------
|
|
 1       
|
`PUT /boot-source`
|
 Kernel-Pfad + 
`console=ttyS0 reboot=k panic=1 pci=off init=/sbin/init`
|
|
 2       
|
`PUT /drives/{id}`
|
 4 Drives in fester Reihenfolge (siehe unten)                     
|
|
 3       
|
`PUT /machine-config`
|
`vcpu_count`
, 
`mem_size_mib`
|
|
 4       
|
`PUT /actions`
|
`action_type: InstanceStart`
|

Die **Drive-Reihenfolge bestimmt die Geräte-Zuordnung** im Gast und korrespondiert
exakt mit dem, was der `vmrunner` als PID 1 erwartet (Kapitel 7):

```
rootfs   → /dev/vda  (is_root_device, read-only)
snapshot → /dev/vdb  (read-only, aktueller Registry-Zustand)
input    → /dev/vdc  (read-only, pr.diff / package.tar.gz)
output   → /dev/vdd  (read-write, Ergebnisse)
```

`boot_args` enthält bewusst `panic=1` und `reboot=k`: Ruft PID 1 versehentlich
`exit()` statt `reboot()`, paniced der Kernel — und mit `panic=1` rebootet er nach
1 Sekunde, statt zu hängen. So kann eine fehlerhafte VM den Worker-Slot nicht
dauerhaft blockieren.

### 6.9 Registry-Snapshot-Rebuild (`daemon/snapshot.go`)

Die Validierungs-VM braucht den *aktuellen* Registry-Zustand für
Cross-Reference-Checks („existiert dieser Arch/Toolchain überhaupt?"). Diesen liefert
`/dev/vdb` als ext4-Image, das `RebuildSnapshot` periodisch (täglich + beim Start)
neu baut:

1. Shallow-Clone (`--depth 1`) des **öffentlichen Mirror-Repos**.
2. `.git`-Verzeichnis entfernen (nur der Registry-Inhalt zählt).
3. Benötigte Größe berechnen (`calcDirSize` + Headroom), `truncate` auf
   `<n>M`.
4. `mkfs.ext4 -F -d <repoDir>` — Image erstellen *und* in einem einzigen Schritt
   befüllen (der Kommentar weist darauf hin, dass dies Fork-Bomben vermeidet).
5. **Atomarer Rename** (`output.ext4.tmp` → finaler Pfad), damit der Worker nie ein
   halb geschriebenes Snapshot-Image liest.

### 6.10 S3-Cleanup-Cron (`daemon/cleanup.go`)

`StartS3CleanupCron` läuft täglich (mit 5 min Initialverzögerung) und entfernt
verwaiste Tarballs: Es listet alle Objekte im Bucket, überspringt alles, was jünger
als 2 Stunden ist (Race-Schutz mit aktiven Uploads), und löscht jedes Objekt, zu
dem `TarballExists` kein zugehöriges Paket in der DB findet. So sammeln sich keine
Leichen aus fehlgeschlagenen, gelöschten oder widerrufenen Paketen an.

---

## 7. Die Firecracker-VM (`vmrunner`)

Der `vmrunner` (`cmd/vmrunner/`) ist das wohl faszinierendste Binary des Projekts:
Es läuft als **PID 1 innerhalb** der wegwerfbaren microVM und ist
`//go:build linux`-getaggt. Es validiert untrusted Code in vollständiger Isolation —
**kein Netzwerk, kein gemeinsames Dateisystem**, jegliche Ein-/Ausgabe ausschließlich
über ext4-Block-Devices.

### 7.1 PID-1-Semantik

Als Init-Prozess unterliegt der `vmrunner` einer harten Regel:

> **PID 1 darf niemals `exit()` aufrufen** — das löst eine Kernel-Panic aus.
> Stattdessen ruft `shutdown()` am Ende `syscall.Sync()` (Buffer flushen) und
> `syscall.Reboot(LINUX_REBOOT_CMD_POWER_OFF)`.

Daraus folgt ein robuster Kontrollfluss in `main()`: Auch im Fehlerfall wird *zuerst*
das Ergebnis (über `writeFailure`) auf das Output-Device geschrieben, *dann*
`writeRawTarToDevice("/dev/vdd", …)` ausgeführt, und *erst danach* sauber
heruntergefahren. Der Host liest anschließend das `result.json` aus dem
Output-Device. Egal was schiefgeht — der Worker erhält immer eine auswertbare
Antwort.

### 7.2 Mount-Setup & Drive-Layout

`mountAll` richtet die VM-Umgebung ein:

```
mount proc      → /proc
mount /dev/vdb  → /registry          (ext4, read-only)
mount tmpfs     → /workspace         (tmpfs)
mkdir /workspace/input, /workspace/outputs
```

Die Registry-Snapshot (`/dev/vdb`) wird read-only eingehängt; der Arbeitsbereich ist
ein flüchtiges `tmpfs`. Die Input-/Output-Devices (`/dev/vdc`, `/dev/vdd`) werden
nicht gemountet, sondern als **rohe Tar-Streams** gelesen bzw. geschrieben
(`extractRawTar`/`writeRawTarToDevice`).

### 7.3 Job-Erkennung

Nach dem Mounten und dem Extrahieren des Input-Devices entscheidet `run()` anhand
der vorhandenen Dateien, welche Art Job vorliegt:

```
release_manifest.json vorhanden? → runReleaseJob   (SemVer-Oracle, Kapitel 10)
package.tar.gz vorhanden?        → Publish-Job      (extrahieren + kompilieren)
sonst                            → Validation-Job   (pr.diff anwenden)
```

Für Publish-Jobs wird das Paket extrahiert, sein Zielpfad bestimmt
(`determinePackagePath`) und in die Arbeitskopie der Registry einsortiert. Für
Validation-Jobs wird der Diff mit `patch -p1` (busybox-`patch` aus dem rootfs) auf
die Arbeitskopie angewendet (`applyDiff`).

### 7.4 Toolchain-Discovery & PATH

Bevor irgendetwas kompiliert wird, baut `run()` den `PATH` dynamisch auf: Standard-
Verzeichnisse plus alle vorgebackenen Toolchain-`bin/`-Verzeichnisse, die
`discoverToolchainBins("/root/.toob/toolchains")` findet. Die Suche spiegelt die
Toolchain-Auflösung der CLI wider: Sie iteriert über `{name}/{version}/` und sucht
darin via `findBinDir` (bis zu 3 Ebenen tief) ein `bin/`-Verzeichnis — robust auch
gegenüber verschachtelten Layouts wie `riscv32-esp-elf/13.2.0/riscv32-esp-elf/bin/`.
Zusätzlich wird `TOOB_COMPILER_DIR` auf das vorgeseedete Core-SDK gesetzt, damit die
CLF in der air-gapped VM keinen `git clone` versucht.

### 7.5 Paket-Extraktion & Pfad-Auflösung

`determinePackagePath` leitet aus der Kategorie (ermittelt über die
Manifest-Datei) den kanonischen Registry-Pfad ab:

|
 Kategorie     
|
 Pfad-Schema                                    
|
|
---------------
|
-------------------------------------------------
|
|
`chip`
|
`chips/<name>`
|
|
`arch`
|
`arch/<name>`
|
|
`toolchain`
|
`toolchains/<name>`
|
|
`integration`
|
`integration/<name>`
|
|
`port`
|
`ports/<name>`
|
|
`driver`
|
`drivers/<category>/<name>`
 (Kategorie aus Manifest) 
|
|
`crypto`
|
`crypto/<category[0]>/<name>`
 (erste Kategorie) 
|

Die Extraktion selbst läuft über `archiveutil.SafeExtract` (siehe 7.8), nicht über
die nackte `archive/tar`-API — alle Sicherheitsprüfungen sind damit zentralisiert.

### 7.6 Compile-Validierung

`runCompileValidation` ist der Kern des Publish-Jobs. Es sammelt alle Quellcodes
(`.c`, `.cpp`, `.S`, `.s`), bestimmt den Compiler und übersetzt jede Datei einzeln
(`gcc -c -o <obj> <src>`). Der Compiler wird aus dem Chip-Manifest abgeleitet
(`CompilerPrefix + "gcc"`), und genau hier sitzt ein wichtiger Sicherheitscheck:

```go
if strings.Contains(prefix, "/") || strings.Contains(prefix, "\\") || strings.Contains(prefix, ".") {
    return fmt.Errorf("invalid compiler prefix ...: directory separators and dots are forbidden")
}
matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]*$`, prefix)
if !matched { ... }
```

> Ohne diese Prüfung könnte ein bösartiges Manifest über einen `CompilerPrefix` wie
> `../../bin/evil` einen beliebigen Befehl als „Compiler" ausführen lassen. Der
> Filter erlaubt nur alphanumerische Zeichen, Unterstriche und Bindestriche und
> verbietet Pfadtrenner und Punkte. Fehlt der Compiler anschließend im PATH, ist
> das ein Build-Fehler (die Toolchains sind ins rootfs vorgebacken).

### 7.7 Tarball-Erzeugung & Result-Writing

Nach erfolgreicher Validierung gruppiert `createPackageTarballs` die geänderten
Dateien nach Paketverzeichnis (`packageDirFor` sucht aufwärts nach dem
Verzeichnis, das ein Manifest enthält) und erzeugt pro Paket ein `.tar.gz` auf dem
Output-Device. Das `VMResult` (Status, Step-Ergebnisse, Paket-Refs, optionaler
Fehler) wird als `result.json` geschrieben und vom Host-Worker ausgelesen.

### 7.8 `archiveutil`: Sichere Tar-Extraktion

`internal/archiveutil/archiveutil.go` ist die zentrale, an vielen Stellen
wiederverwendete Bibliothek für *sicheres* Auspacken von Tar-Archiven — im
`vmrunner`, in der Ingestion und im Mirror-Pusher. `SafeWalk` parst ein (optional
gzip-komprimiertes) Tar und prüft jede Eintragung gegen eine Reihe von Angriffen,
bevor es den Callback aufruft:

|
 Schutz                        
|
 Mechanismus                                                              
|
|
-------------------------------
|
--------------------------------------------------------------------------
|
|
**
Zip Slip / Path Traversal
**
|
 Ablehnung jedes Namens, der 
`..`
 enthält — 
*
vor
*
 dem 
`path.Clean`
|
|
**
Absolute Pfade
**
|
 Ablehnung von Namen mit führendem 
`/`
|
|
**
Symlinks / Hardlinks
**
|
 Ablehnung von 
`TypeSymlink`
/
`TypeLink`
|
|
**
Device-/FIFO-Dateien
**
|
 Ablehnung von 
`TypeBlock`
/
`TypeChar`
/
`TypeFifo`
|
|
**
Unbekannte Typen
**
|
 Ablehnung aller nicht explizit erlaubten Typeflags                        
|
|
**
Datei-Anzahl
**
|
`MaxFileCount`
-Limit                                                      
|
|
**
Negative Größen
**
|
 Ablehnung von 
`header.Size < 0`
|
|
**
Einzeldateigröße
**
|
`MaxFileSize`
-Limit + 
`io.LimitReader`
-Wrapping                          
|
|
**
Decompression Bomb
**
|
`countingReader`
 summiert die 
*
tatsächlich
*
 gelesenen Bytes gegen 
`MaxTotalSize`
|

`SafeExtract` baut darauf auf und fügt eine zweite Verteidigungslinie hinzu: Es
verifiziert nach `filepath.Join`, dass der Zielpfad tatsächlich ein Nachfahre des
Zielverzeichnisses ist (`strings.HasPrefix(targetPath, destDirClean)`), und maskiert
optional die Dateirechte (`maskPerms` → `mode & 0644`). So kann selbst ein Archiv,
das die erste Prüfung umginge, nicht aus dem Zielbaum ausbrechen.

---

## 8. Validierung & Security-Scanning

Die Validierung ist das qualitäts- und sicherheitskritische Nadelöhr der Registry.
Sie lebt unter `internal/validate/` und läuft an drei Orten mit *identischer* Logik:
im `vmrunner` (innerhalb der VM), im Standalone-`validator` (für CI/lokale Tests)
und — in einer verschärften Variante — bei der Ingestion auf der Control Plane
(`internal/server/ingest/`).

### 8.1 Das Step-Framework (`validate/step.go`)

Alle Prüfungen folgen einer einheitlichen Signatur. Ein `StepInput` bündelt den
gemeinsamen Kontext (`RegistryDir`, `DiffFile`, `ChangedFiles`,
`AllowedToolchainDomains`); jeder Step liefert ein `StepResult` mit Status
(`PASSED`/`FAILED`/`WARNING`), Dauer und Nachricht. Der `Run`-Wrapper trackt
automatisch die Laufzeit. `RunAll` führt die vier Steps in fester Reihenfolge aus:

```
ManifestValidation → DiffBumpCheck → IntegrityCheck → SecurityScan
```

`ParseDiffFileNames` extrahiert nebenbei die Liste der geänderten Dateien aus einem
Unified-Diff (über die `+++ b/`-Zeilen).

### 8.2 ManifestValidation (`validate/manifest.go`)

Die strukturelle Integritätsprüfung aller Registry-Manifeste. Sie lädt die
Kategorie-Allowlists (`driver_categories.json`, `crypto_categories.json`) und
prüft anschließend:

- **Toolchains/Archs:** Manifest existiert, Pflichtfelder (`name`/`version`)
  vorhanden.
- **Drivers/Crypto (rekursiver Walk):** Pflichtfelder vorhanden; die Kategorie aus
  der **Verzeichnisstruktur** muss in der Allowlist stehen *und* (bei Crypto) auch
  im Manifest deklariert sein.
- **Namenskollision:** Ein Name darf nicht gleichzeitig in `drivers` und `crypto`
  existieren.
- **Chips (Cross-Reference):** Jeder Chip muss einen existierenden `arch` und eine
  existierende `toolchain` referenzieren (abgeleitet aus `CompilerPrefix`).

### 8.3 DiffBumpCheck (`validate/diffbump.go`)

Eine Dry-Run-Versionskonsistenzanalyse: Sie vergleicht die *aktuellen*
Manifest-Versionen mit dem, was der Diff impliziert.

- **Downgrades** (`isDowngrade`) sind ein **FAILED** — eine Version darf nie
  zurückgehen.
- **Fehlende Bumps** (Code geändert, Version unverändert) sind eine **WARNING**,
  zusammen mit dem erwarteten Bump-Typ.
- Die Klassifizierung (`classifyBump`) ist heuristisch: gelöschte `.h`/`.ld` →
  MAJOR, neue `.h`/`.c` → MINOR, sonst PATCH.

Diese Prüfung ist die „leichtgewichtige" Schwester des vollwertigen SemVer-Oracles
(Kapitel 10), das per ABI-/AST-Diff die *exakte* Bump-Art ermittelt.

### 8.4 IntegrityCheck (`validate/integrity.go`)

Verifiziert, dass alle in Manifesten referenzierten Pfade auf der Platte existieren
und kein Path-Traversal versucht wird. Zwei Schwerpunkte:

- **Chip-Quellen:** Jeder referenzierte Pfad (`startup`, `platform`, `linker`,
  Treiber, Includes …) wird per `validatePath` geprüft — kein `..`, kein absoluter
  Pfad, und die Datei muss relativ zum Chip- *oder* Registry-Root existieren.
- **Toolchain-SHA256 & URL-Allowlist:** Jeder SHA256 muss dem 64-stelligen
  Hex-Muster entsprechen; ## 8. Validierung & Security-Scanning (Fortsetzung)

### 8.4 IntegrityCheck (`validate/integrity.go`)

> *Fortsetzung von oben.*

…jede Download-URL muss `https` sein und aus einer **Allowlist erlaubter Domains**
stammen. Die Default-Allowlist umfasst `github.com/Toob-Boot/`,
`github.com/espressif/`, `developer.arm.com/`, `gcc.gnu.org/`,
`releases.linaro.org/` und `ftp.gnu.org/`; sie ist über die Umgebungsvariable
`ALLOWED_TOOLCHAIN_DOMAINS` (kommagetrennt) überschreibbar und wird durch das
Input-Device als `allowed_domains.json` in die VM gereicht.

Die URL-Prüfung (`isAllowedToolchainURL`) ist bewusst strikt:

```go
u, _ := url.Parse(rawURL)
if u.Scheme != "https" { return false }      // kein HTTP, kein file://, kein ftp://
host := strings.ToLower(u.Hostname())
urlKey := host + path                         // Host UND Pfad-Prefix
for _, entry := range allowedDomains {
    if strings.HasPrefix(urlKey, entry) { return true }
}
```

> Der Allowlist-Eintrag enthält *Host plus Pfad-Prefix* (z. B. `github.com/Toob-Boot/`),
> nicht nur den Host. Damit lässt sich `github.com/Toob-Boot/` freigeben, ohne
> automatisch `github.com/evil-fork/` mitzuerlauben — ein reiner Host-Vergleich
> würde diese Trennung nicht leisten.

Die Pfad-Prüfung (`validatePath`) ist die zweite Säule und sichert jede in einem
Chip-Manifest referenzierte Quelle ab:

| Schutz | Mechanismus |
|--------|-------------|
| **Path Traversal** | Ablehnung jedes Pfads, der `..` enthält |
| **Absolute Pfade** | Ablehnung über `filepath.IsAbs` |
| **Existenz** | Datei muss relativ zum Chip- *oder* Registry-Root auflösbar sein |

Die Auflösung versucht zuerst `<chipRoot>/<refPath>`, dann `<registryRoot>/<refPath>`.
Erst wenn beide Kandidaten nicht existieren, ist es ein **FAILED**. Toolchain-SHA256-Werte
werden gegen `^[a-f0-9]{64}$` geprüft — alles, was nicht exakt 64 Hex-Zeichen ist,
gilt als manipuliert.

### 8.5 SecurityScan (`validate/security.go`)

Der letzte und schärfste Schritt. Er führt heuristische statische Analyse auf den
**geänderten Dateien** (nicht der gesamten Registry) durch und unterscheidet zwischen
**fatalen** Befunden (→ `FAILED`, PR wird abgelehnt) und **Warnungen**
(→ `WARNING`, wird geloggt, blockiert aber nicht).

#### Binärdatei-Erkennung (fatal)

`ForbiddenBinaryExts` verbietet jede kompilierte Artefakt-Endung kategorisch — ein
Community-PR darf niemals vorkompilierte Objekte einschleusen:

```
.o  .so  .elf  .bin  .a  .dylib  .dll  .exe  .ko  .out
```

#### Verbotene C-Muster (`CPatternRules`)

Jede Regel ist ein Regex mit menschenlesbarem Grund und einem `Fatal`-Flag:

| Kategorie | Muster (Auszug) | Schweregrad |
|-----------|-----------------|-------------|
| **Shell-Injection** | `system(`, `exec*(`, `popen(`, `dlopen(`, `fork(` | FATAL |
| **Netzwerk in HAL** | `<sys/socket.h>`, `<netinet/in.h>`, `<arpa/inet.h>` | FATAL |
| **Auto-Exec** | `__attribute__((constructor))` / `((destructor))` | FATAL |
| **Inline-Syscalls** | `int 0x80`, `svc #0`, `ecall`, `syscall` | WARNING |

> Die Logik dahinter: ein HAL-Treiber für einen MCU hat *niemals* einen legitimen
> Grund, einen Socket zu öffnen oder einen Prozess zu forken. Direkte Syscall-Opcodes
> sind nur Warnungen, weil sie in Arch-/Startup-Code gelegentlich legitim sein können
> — sie verdienen einen Reviewer-Blick, aber keinen automatischen Hard-Block.

#### Entropie-Analyse

Dateien ab `entropyMinSize` (256 Byte) werden auf ihre Shannon-Entropie geprüft.
Natürlicher C-Code liegt bei ~4,0–5,5 bit/Byte; ein Wert über `entropyThreshold`
(7,0) deutet auf verschlüsselte, komprimierte oder obfuskierte Inhalte hin und
erzeugt eine Warnung. Zusätzlich schlägt `Base64LongString` (≥256 zusammenhängende
Base64-Zeichen) als Warnung an — ein klassischer Träger für eingebettete Payloads.

#### Typosquatting (`LevenshteinDistance`)

Bei neuen Manifesten wird der Name gegen alle existierenden Paketnamen verglichen.
Die maximal erlaubte Edit-Distanz ist `TyposquatMaxDistance` (2), für kurze Namen
(< 5 Zeichen) verschärft auf 1. Ein zu ähnlicher Name (z. B. `esp32-c6` vs.
`esp32c6`) erzeugt eine Warnung für den Reviewer.

> **Anti-Bypass-Härtung:** Lesefehler des Scanners (`scanner.Err()`) werden als
> **fatal** behandelt, nicht ignoriert. Andernfalls könnte ein Angreifer eine Datei
> so konstruieren, dass der Scanner mit einem Fehler abbricht und die Prüfung still
> übersprungen wird. Der Scanner-Buffer ist außerdem auf 1 MB pro Zeile angehoben,
> um auto-generierten Code nicht künstlich zu zerschlagen.

### 8.6 Die Ingestion-Pipeline (`server/ingest/tarball_validate.go`)

Auf der **Control Plane** läuft eine verschärfte Variante. Statt einer Diff-basierten
Prüfung wird hier das gesamte Tarball als untrusted Blob behandelt und in einem
**Single-Pass** durch sechs Gatter geschickt (`ValidateTarball` /
`ValidateAndScanTarball`). Das Tarball wird dabei **niemals auf die Platte
extrahiert** — alle Prüfungen laufen streamend über `archiveutil.SafeWalk`.

| Gate | Prüfung | Limit |
|------|---------|-------|
| **1 — Archivstruktur** | Zip-Slip, Symlinks, Device-Dateien, Decompression-Bomb (über `SafeWalk`) | `MaxFileCount` 128, `MaxTotalSize` 20 MiB, `MaxFileSize` 1 MiB |
| **2 — Pfadstruktur** | Tiefe, Namenslänge, sichere Zeichen | `maxPathDepth` 8, `maxFileNameLen` 128, `safeNamePattern` |
| **3 — Endungs-Allowlist** | Nur explizit erlaubte Endungen + Basenames (`LICENSE`, `Kconfig`) | `allowedExtensions` |
| **4 — Manifest** | Genau *ein* Manifest, gültiges JSON, Pflichtfelder | `maxManifestDepth` 2, `validSemVer`, `validPackageNamePattern` |
| **5 — Binär-Heuristik** | Ablehnung bei >80 % Nicht-ASCII-Bytes | `isBinaryContent` |
| **6 — Security-Scan** | Forbidden-Exts, Entropie, Base64, C-Pattern-Rules, Source-Heuristiken | identisch zu 8.5 |

Besonderheiten gegenüber dem VM-Scan:

- **Manifest-Eindeutigkeit:** Mehrere Manifeste im selben Tarball sind ein harter
  Fehler. Der `category` wird aus dem Manifest-Dateinamen abgeleitet
  (`domain.ManifestFilenames`), nicht aus dem Inhalt.
- **Feldvalidierung:** `name`, `version` und `author` sind Pflicht. `name` muss
  `^(@[a-z0-9-]+/)?[a-z0-9-]+$` matchen (npm-Style-Scopes erlaubt), `version` strikten
  SemVer ohne führende Nullen.
- **Heuristische Warnungen** (`scanSourceHeuristics`) wie `system()` neben `stdlib.h`
  oder Inline-Assembler außerhalb von Arch-Paketen werden in das Manifest unter
  `ingestion_warnings` persistiert und im Staging-Review angezeigt — sie blockieren
  nicht, machen aber die Risikofläche für den Reviewer sichtbar.

---

## 9. Der Autoscaler

Der Autoscaler ist ein **eigenständiges Binary** (`cmd/autoscaler`), getrennt vom
API-Server. Er ist die einzige Komponente neben der Control Plane, die sowohl
DB-Zugriff (konservativer Pool von 5 Verbindungen) als auch einen Vault-Token besitzt
— denn er muss neue Worker-VMs mit frischen Credentials betanken.

### 9.1 Aufgabe

Worker-Knoten sind teuer (dedizierte vCPUs für stabiles KVM, Hetzner `ccx13`). Sie
sollen nur existieren, wenn Arbeit anliegt. Der Autoscaler hält die Anzahl der
Nomad-Worker-Knoten zwischen `MinWorkers` und `MaxWorkers` und skaliert prädiktiv auf
Basis der Queue-Tiefe.

### 9.2 Die Skalierungsschleife (`scaleIteration`)

Jeder Tick (`PollInterval`, Default 15 s) durchläuft:

1. **Queue-Statistik** — `countQueuedJobs` summiert `validation_jobs` und
   `publish_jobs` im Status `QUEUED`.
2. **Build-Zeit-Schätzung** — `getAverageBuildTime` mittelt die Laufzeit der letzten
   10 abgeschlossenen Builds (Fallback: 45 s).
3. **Nomad-Inventar** — alle Knoten mit Präfix `toob-worker-` werden gezählt und nach
   `ready`/`SchedulingEligibility` klassifiziert. Knoten, die bereits im
   Drain/Destroy stehen (`drainingNodes`), werden übersprungen.
4. **Busy/Idle-Erkennung** — `isWorkerBusy` fragt die DB, ob ein Worker einen Job in
   `RUNNING`/`COMPILING` hält. Idle-Knoten bekommen einen Zeitstempel in `idleStart`.

#### Prädiktives Modell

Die Kernformel schätzt die Wartezeit der Queue:

```
T_wait = (Q_queued × T_build) / W_active
```

- **Scale-Up** wird ausgelöst, wenn `Q_queued > 0` *und* `T_wait > bootTime` (30 s
  Baseline) *und* `W_active < MaxWorkers` *und* der Scale-Up-Cooldown (2 min) abgelaufen
  ist. Bei `W_active == 0` und vorhandener Queue wird `T_wait` auf 99999 gesetzt, um
  garantiert hochzuskalieren.
- **Scale-Down** wird ausgelöst, wenn `Q_queued == 0` *und* `W_active > MinWorkers`
  *und* ein Knoten länger als `IdleTimeout` (Default 5 min) idle ist.

### 9.3 Provisionierung (`scaleUp`)

Der heikelste Teil — ein neuer Worker muss authentifizierbar werden, ohne dass ein
langlebiges Geheimnis im Cloud-Init-Userdata landet:

1. **Wrapped SecretID** — `generateWrappedSecretID` fordert von Vault eine
   AppRole-SecretID mit `X-Vault-Wrap-TTL: 300` an. Zurück kommt nur ein
   *Wrapping-Token* mit 5 Minuten Gültigkeit.
2. **Cloud-Init** — `RenderUserData` füllt das eingebettete Template
   (`user_data.yaml.tmpl`) mit Wrapping-Token, Vault-Adresse, Role-ID (UUID) und
   Nomad-Gossip-Key.
3. **Hetzner-API** — `POST /v1/servers` erzeugt die VM aus dem Golden Image, hängt
   sie ins Control-Plane-Netz und an die Worker-Firewall.

> Das Wrapping-Token ist *single-use* und *kurzlebig*. Der Worker entpackt es beim
> Boot, tauscht es gegen die eigentliche SecretID und meldet sich per AppRole bei
> Vault an. Selbst wenn das Userdata abgefangen würde, wäre das Token nach 5 Minuten
> (oder nach erstmaligem Entpacken) wertlos.

### 9.4 Deprovisionierung (`scaleDown`)

Läuft asynchron, um die Hauptschleife nicht zu blockieren. Der Knoten wird sofort
unter Lock als `draining` markiert, um doppelte Trigger zu verhindern:

1. **Nomad-Drain** — `drainNomadNode` setzt den Knoten ineligibel und terminiert
   System-Jobs (10 min Deadline).
2. **Allocation-Monitoring** — bis zu 10 Minuten Polling, bis keine `running`/`pending`
   Allocation mehr existiert.
3. **Hetzner-Delete** — `deleteHCloudServer` entfernt die VM.
4. **Nomad-Purge** — `purgeNomadNode` löscht die Knotenregistrierung (Fehler werden
   ignoriert, da die VM bereits weg ist).

### 9.5 Startup-Resolution

Beim Start löst der Autoscaler einmalig auf: Hetzner-Netzwerk-Name → ID,
Firewall-Name → ID und die Worker-AppRole-RoleID (UUID) aus Vault. Schlägt eine
dieser Auflösungen fehl, terminiert der Daemon sofort — ein Fail-Fast, das einen halb
konfigurierten Autoscaler verhindert.

---

## 10. Subsystem-Modell & SemVer-Oracle

### 10.1 Das Subsystem-Register (`internal/subsystem`)

Drei Komponenten des Monorepos werden unabhängig versioniert und ausgeliefert:
**Core (SDK)**, **CLI** und **Compiler**. Statt diese Pfade über den Code zu verstreuen,
zentralisiert `subsystem.Registry` *alle* zugehörigen Pfade pro Komponente:

| Feld | Zweck |
|------|-------|
| `TagPrefix` | Git-Tag-Namespace (`core/`, `cli/`, `compiler/`) |
| `DBName` | Ökosystem-Identifier in der DB (`core_sdk`, `cli`, `compiler`) |
| `S3Folder` | Ordner für Artefakte (z. B. `core`, nicht `core_sdk`) |
| `ChangePaths` | Pfade für Git-Diff-Änderungserkennung |
| `ArchivePaths` | Verzeichnisse, die in die SemVer-VM extrahiert werden |
| `PackagePaths` | Verzeichnisse für das Release-Distributionsartefakt |
| `MirrorPrefixes` / `MirrorFiles` | Boundary für den Public-Repo-Mirror |
| `HeaderPatterns` | Glob-Muster für öffentliche API-Header (ABI-Diff) |
| `Libs` | Statische Libs für die ABI-Symbol-Extraktion |
| `KeyFiles` | Benannte Referenzdateien (z. B. `ports.go`, `compiler_manifest.json`) |

Helfer wie `NormalizeVersion` (strippt Tag-Präfix + führendes `v`), `ComponentForTag`
(mappt `compiler/v1.2.3` → `Compiler`) und `ResolveHeaderDirs` (Glob-Auflösung über
zwei Baseline-/Current-Bäume) machen das Modell zur Single Source of Truth für die
gesamte Release-Maschinerie.

### 10.2 Das SemVer-Oracle (`cmd/vmrunner/semver.go`)

Das Oracle beantwortet automatisch die Frage: *Welcher Versionssprung (PATCH/MINOR/MAJOR)
ist durch diese Änderung erzwungen?* Es läuft **innerhalb der air-gapped VM**, weil es
fremden Code kompilieren und analysieren muss. `executeSemverOracle` analysiert nur die
Komponenten, deren `ChangePaths` sich seit dem letzten Tag geändert haben.

#### 10.2.1 Core-SDK: ABI- + Header-Diff (`analyzeCoreSDK`)

Zweistufig:

- **Layer 1 — ABI-Symbole:** Baseline und Current werden nativ gebaut
  (`toob build --native`), dann werden über `nm --defined-only -g` die exportierten
  Symbole pro statischer Lib extrahiert. **Entferntes Symbol → MAJOR**, **neues Symbol
  → MINOR**.
- **Layer 2 — Header-Diff:** Über `HeaderPatterns` werden alle öffentlichen `.h`-Dateien
  rekursiv verglichen. Gelöschter Header → MAJOR, neuer Header → MINOR, geänderte
  Typdefinitionen (`extractDefs` sammelt `typedef`/`struct`/`enum`-Zeilen sortiert) →
  MINOR.

#### 10.2.2 CLI: Go-AST-Diff (`analyzeCLI`)

Die CLI definiert ihren Wire-Vertrag in `ports.go`. `parseInterface` baut daraus ein
strukturelles Modell (`InterfaceInfo`) und vergleicht Structs, Konstanten und
Type-Aliases. Entscheidend sind die `port:"required"`/`port:"optional"`-Tags:

| Änderung | Sprung |
|----------|--------|
| Required-Feld entfernt / Typ geändert / optional→required | **MAJOR** |
| JSON-Wire-Name oder -Optionen geändert | **MAJOR** |
| Optional-Feld entfernt | **MINOR** |
| Neues Required-Feld | **MAJOR** |
| Neues Optional-Feld | **MINOR** |
| Exportierte Konstante / Type-Alias entfernt oder geändert | **MAJOR** |

> Jedes Feld *muss* einen `port`-Tag tragen — fehlt er, ist die AST-Analyse ein
> harter Fehler. Bei MAJOR-Änderungen wird zusätzlich erzwungen, dass die
> `ProtocolVersion`-Konstante in `ports.go` inkrementiert wurde; andernfalls bricht
> das Oracle mit `[FATAL]` ab.

#### 10.2.3 Compiler: 7-dimensionale Abhängigkeitsanalyse (`analyzeCompiler`)

Der Compiler ist ein Container, der CLI + Core-SDK + Toolchains bündelt. Sein
`compiler_manifest.json` wird über sieben Dimensionen verglichen:

| Dim | Feld | Sprung bei Änderung |
|-----|------|---------------------|
| 1 | `protocol_version` | MAJOR |
| 2 | `cli.version` | erbt CLI-Sprung |
| 3 | `core_sdk.version` | Core MAJOR/MINOR → Compiler MINOR; Core PATCH → PATCH |
| 4 | `base_image.image` | MINOR |
| 5 | `system_packages` | MINOR |
| 6 | `python_packages` | MINOR |
| 7 | `registry.source.ref` | MINOR |

**Entkopplungslogik:** Ändert sich *ausschließlich* die eingebettete CLI-Version (keine
sonstige Manifest-Änderung, kein CLI-Code im selben Lauf, kein MAJOR), wird der
Compiler-Build *aufgeschoben* (`BumpNone`). Das verhindert eine Lawine von
Compiler-Releases bei jedem CLI-Patch.

#### 10.2.4 Versions-Arithmetik

`promoteBump` hebt immer auf den höchsten gefundenen Sprung an, `calculateNextTag` und
`bumpVersionString` berechnen die nächste Version (`major++` setzt minor/patch auf 0
etc.). Das Ergebnis ist eine Liste `TagsToPush`, die der Host-Worker nach Verifikation
der Commit-Ancestry tatsächlich als Git-Tags setzt (siehe 13.5).

---

## 11. Datenbank & Migrationen

### 11.1 Migrations-Mechanik (`postgres/db.go`)

Migrationen sind in `migrations/*.up.sql` eingebettet (`//go:embed`) und werden über
`migrations.All` in fester Reihenfolge ausgeführt. Der Runner ist gegen parallele
Instanzen abgesichert:

- **`pg_advisory_lock(42001)`** — blockiert, bis das Migrations-Lock erworben ist;
  verhindert konkurrierendes DDL aus mehreren API-Knoten.
- **`schema_migrations`-Tabelle** — trackt bereits angewandte Versionen, sodass jede
  Migration genau einmal läuft.
- **Idempotenz** — jede Migration nutzt `IF NOT EXISTS` oder PL/pgSQL-Exception-Handler
  (`duplicate_column`, `duplicate_object`), sodass auch ein erneuter Lauf gegen ein
  partiell migriertes Schema sauber durchläuft.

Migrationen laufen ausschließlich über das `migrate`-Subkommando (in Nomad als
Prestart-Task), nicht beim normalen Serverstart.

### 11.2 Zentrale Tabellen

| Tabelle | Rolle |
|---------|-------|
| `revisions` | Monotone Integer-Versionierung des gesamten Registry-Index (ersetzt SemVer) |
| `revision_snapshots` | Vollständiger Index-Snapshot pro Revision (historischer Audit) |
| `publishers` | GitHub-OAuth-Identitäten, API-Key-Hash, Rolle, Plan-Tier |
| `packages` | Einheitliches Speichermodell für alle Kategorien (UUID-PK) |
| `package_access` | Custom-Sharing-Grants für Dev-Pakete |
| `matrix_entries` | Kompatibilitätsmatrix (Chip × CLI × Core × Compiler) |
| `ecosystem_releases` | Versionen von CLI/Core/Compiler (Yank, Deprecation, Draft) |
| `validation_jobs` / `publish_jobs` / `release_jobs` | Die drei Job-Queues |
| `sync_log` | Welcher Publisher hat welche Revision synct (für Advisories) |
| `advisories` / `notifications` | Security-Advisories und ihre Zustellung |
| `organizations` / `organization_members` | Team-Scopes und Rollen |
| `oauth_sessions` | PKCE-Login-Flow mit AES-GCM-verschlüsseltem API-Key |
| `audit_log` | Unveränderliches Protokoll sicherheitskritischer Operationen |
| `system_status` | Heartbeats der Hintergrund-Daemons + Host-Metriken |
| `scopes` | V2-Fundament für Org-/Team-Namespaces |

### 11.3 Schema-Evolution — die wichtigen Sprünge

Die Migrationshistorie erzählt die Architekturentwicklung. Drei Migrationen sind
besonders prägend:

#### Migration 011 — UUID-PK & Deferred Name Claiming

Der ursprüngliche Composite-PK `(name, version)` wurde durch einen UUID-PK ersetzt.
Das ermöglicht, dass *mehrere* Publisher gleichnamige Pakete parallel im Dev-Stadium
entwickeln. Die Eindeutigkeit wird erst an der **Staging-Grenze** erzwungen — über zwei
partielle Unique-Indizes:

```sql
-- Pro Publisher eindeutig in dev/testing
CREATE UNIQUE INDEX idx_packages_publisher_name_ver_dev
    ON packages (name, version, publisher_id)
    WHERE stage IN ('dev', 'testing');

-- Global eindeutig in staging/stable (der eigentliche "Claim")
CREATE UNIQUE INDEX idx_packages_unique_name_ver_claimed
    ON packages (name, version)
    WHERE stage IN ('staging', 'stable');
```

> Dieses „Deferred Claiming" ist der Grund, warum der Worker-Complete-Handler eine
> `ErrUniqueViolation` abfangen und das Paket nach `dev` zurücksetzen muss: Ein zweiter
> Publisher könnte den Namen beanspruchen, *während* das eigene Paket noch im Testing
> war.

#### Migration 016 — Gehashte Job-Tokens

Job-Tokens werden nicht mehr im Klartext verglichen, sondern als SHA-256-Hash
gespeichert. Die Migration invalidiert beim Deployment alle aktiven Tokens
(`UPDATE ... SET job_token = NULL WHERE status = 'RUNNING'`), um Klartext-Kollisionen
während des Übergangs zu vermeiden.

#### Migration 020 — Stage-Transition-Trigger

Die Lifecycle-Übergänge werden nicht nur im Go-Code (`Stage.CanTransitionTo`), sondern
zusätzlich auf DB-Ebene durch einen `BEFORE UPDATE`-Trigger erzwungen:

```
dev      → testing | staging
testing  → dev | staging
staging  → dev | stable | revoked
stable   → archived | revoked
```

Jeder ungültige Übergang löst eine Exception aus. Defense in Depth: selbst ein
fehlerhafter Handler kann das Paket nicht in einen illegalen Zustand bringen.

### 11.4 Store-Schicht (`postgres/stores.go`)

Alle Repositories werden unter einem einzigen Pool in `Stores` gebündelt und über
`NewStores` initialisiert. Drei Muster prägen die Implementierung:

- **`SELECT ... FOR UPDATE SKIP LOCKED`** — alle drei Job-Stores nutzen dieses Muster,
  damit beliebig viele Worker dieselbe Queue gefahrlos parallel pollen können.
- **`LISTEN`/`NOTIFY`** — `registry_index_update` synchronisiert den In-Memory-Cache
  über horizontal skalierte API-Knoten; `publish_job_updates` speist die SSE-Streams.
  Der `jobNotifier` teilt sich *eine* DB-Verbindung über alle SSE-Clients, um den Pool
  zu schonen.
- **Advisory Locks** — `42002` (SemVer-Release), `42003` (Core-Release) serialisieren
  kritische Release-Sektionen über `ReleaseJobStore.Lock`.

---

## 12. Querschnitt: Sicherheitskonzepte

Sicherheit ist in Toob-Registry kein einzelnes Modul, sondern ein durchgängiges
Prinzip. Dieser Abschnitt bündelt die Konzepte, die über mehrere Schichten wirken.

### 12.1 Zero-Trust-Worker

Der Worker-Daemon hält **keine** dauerhaften Geheimnisse — kein DB-Credential, keinen
S3-Key, kein Vault-Token, kein GitHub-Secret. Das ist im Binary-Header explizit
dokumentiert und durch die Architektur erzwungen:

- Authentifizierung gegen die Control Plane ausschließlich über **mTLS** mit
  kurzlebigen, von Vault-PKI ausgestellten Zertifikaten.
- *Alle* privilegierten Operationen (Job-Claiming, Paket-Signierung, DB-Writes,
  GitHub-Status) werden über Worker-API-Endpunkte an die Control Plane delegiert.
- Für externe Requests (S3-Upload, Diff-Download) verwendet der Worker einen **zweiten,
  zertifikatslosen** HTTP-Client — die mTLS-Identität wird niemals an Dritte gesendet.

### 12.2 Job-Tokens

Beim Claimen eines Jobs generiert die DB ein 32-Byte-Zufallstoken, gibt den Klartext
einmalig an den Worker zurück und speichert nur den SHA-256-Hash. Dieses Token
autorisiert *alle* Folge-Calls für genau diesen Job (`X-Job-Token`-Header) und wird bei
Abschluss auf `NULL` gesetzt. Token-Validierung akzeptiert nur Jobs im aktiven Status —
für Release-Jobs existiert ein 5-Minuten-Grace-Fenster für idempotente Retries.

### 12.3 mTLS-Identitätsprüfung

Die `RequireWorkerMTLS`-Middleware prüft nicht nur, *dass* ein gültiges Client-Zertifikat
vorliegt, sondern dass dessen Common Name exakt `worker.global.nomad` ist:

> **Lateral-Movement-Schutz:** Ein gültiges Zertifikat aus der Nomad-PKI (etwa von
> einem API-Knoten oder Server) reicht nicht — nur die spezifische Worker-Identität
> wird akzeptiert. Damit kann ein kompromittierter API-Knoten nicht die Worker-Endpunkte
> ansprechen.

Der interne Listener verlangt zusätzlich `tls.RequireAndVerifyClientCert` mit TLS 1.3
Minimum und fail-closed-Konfiguration: fehlt die Worker-mTLS-Konfiguration teilweise,
verweigert der Server den Start.

### 12.4 Vault-Integration

- **AppRole mit Auto-Renewal** — der Vault-Client renewt seinen Token bei 50 % der TTL;
  die SecretID wird nach dem initialen Login verworfen und niemals gespeichert.
- **Wrapped SecretIDs** — der Autoscaler übergibt neuen Workern nur kurzlebige
  Wrapping-Tokens (siehe 9.3).
- **Transit-Signierung** — Pakethashes werden über die Vault-Transit-Engine signiert
  (`TransitSigner`); nur die Control Plane besitzt diesen Zugriff. Der Signer liest den
  Token bei *jedem* Request frisch aus dem Client, nutzt also nie einen veralteten.
- **Token-Datei-Polling** — wird der Token von Nomad injiziert, pollt der Client die
  Datei alle 30 s und lädt rotierte Tokens dynamisch nach.

### 12.5 Mehrschichtige Tarball-Verteidigung

Drei unabhängige Schichten greifen ineinander:

1. **`archiveutil.SafeWalk/SafeExtract`** (Kap. 7.8) — Zip-Slip, Symlinks,
   Decompression-Bomb, Größenlimits.
2. **Ingestion-Pipeline** (8.6) — Endungs-Allowlist, Manifest-Validierung,
   Binär-Heuristik.
3. **Security-Scan** (8.5) — verbotene C-Muster, Entropie, Typosquatting.

Selbst wenn eine Schicht umgangen würde, fängt die nächste den Angriff ab.

### 12.6 VM-Isolation

Die Validierung läuft in Firecracker-microVMs unter dem **Jailer**. Jeder Job bekommt
eine eindeutige UID/GID (`10000 + jobID % 55536`), die Lateral Movement zwischen VMs
verhindert; die echte Isolation liefern kernelseitige User-Namespaces. Die VM ist
netzwerklos — sämtliche I/O läuft über ext4-Block-Devices (rootfs RO, snapshot RO,
input RO, output RW). PID 1 *muss* `reboot(POWER_OFF)` aufrufen, nicht `exit()`, sonst
kernel-panic.

### 12.7 Weitere Härtungen

| Konzept | Mechanismus |
|---------|-------------|
| **bcrypt-DoS-Schutz** | Doppelt gepufferter Credential-Cache (`AuthMiddleware`): gültige Einträge überleben eine Garbage-Key-Flut |
| **Compiler-Prefix-Injection** | `CompilerPrefix` darf nur `[a-zA-Z0-9_-]` enthalten — keine Pfadtrenner/Punkte (Kap. 7.6) |
| **OAuth** | PKCE-Verifier (Constant-Time-Vergleich), Loopback-only Redirect-URIs, AES-256-GCM für transiente Session-Keys |
| **Webhook** | HMAC-SHA256-Verifikation (`X-Hub-Signature-256`, Constant-Time) |
| **Rate Limiting** | IP-basiert mit aggressiver Eviction bei >100k Einträgen; Cloudflare-/Proxy-Header nur von vertrauenswürdigen IPs akzeptiert |
| **Audit-Log** | Unveränderlich, 2-Jahre-Retention (täglicher Cleanup-Job) |
| **Tag-Push-Schutz** | Manuelle Tag-Pushes werden ignoriert; Releases nur intern durch das SemVer-Oracle ausgelöst |

---

## 13. End-to-End-Datenflüsse

### 13.1 Direkter Publish (`POST /api/v1/publish`)

```
Publisher → [Auth + publish-Scope] → Quota-Check (dev)
  → Tarball buffern → 6-Gate-Ingestion-Pipeline
  → Scope-Autorisierung → SHA256 + Duplikat-Check
  → Atomic DB-Write (UUID generiert) → S3-Upload (UUID-Fragment im Key)
  → Vault-Transit-Signatur → Metadaten finalisieren
  → 201 Created (Stage: dev)
```

Das Tarball ist die Single Source of Truth: das Manifest wird aus dem Archiv extrahiert,
nicht separat übergeben. Der S3-Key enthält ein UUID-Fragment, sodass zwei Publisher mit
gleichem `(name, version)` im Dev-Stadium kollisionsfreie Keys erhalten.

### 13.2 Promotion dev → testing (`POST /api/v1/publish/promote`)

```
Publisher → Paket in dev finden → Name-Ownership-Check
  → reference_build_context aus Manifest lesen
  → [Atomic TX] Quota-Check + dev→testing + Job enqueuen
  → Worker claimt Publish-Job → Tarball via mTLS laden
  → Firecracker-VM: runCompileValidation (gcc -c pro Quelldatei)
  → PublishComplete:
       PASSED → Promote testing→staging
       FAILED → RevertToDevWithFeedback (Compiler-Log sichtbar)
```

Der Fortschritt ist live über SSE (`/publish/jobs/{id}/stream`) verfolgbar, gespeist
durch den `jobNotifier` über `LISTEN publish_job_updates`.

### 13.3 PR-Validierung (`POST /webhook/pr`)

```
GitHub-Webhook → [HMAC-Verifikation]
  → Opt-In-Check (Publisher muss registriert sein)
  → Path-Guard (ListPRFiles → nur erlaubte Verzeichnisse)
  → validation_job enqueuen
  → Worker claimt → Diff downloaden → Firecracker-VM
  → RunAll (Manifest → DiffBump → Integrity → Security)
  → bei Erfolg: Tarballs pro Paket erzeugen
  → Worker fordert presigned-PUT-URLs → Upload zu S3
  → Worker meldet Complete → Control Plane:
       IngestPackage (Checksum-Verify, Re-Scan, Typosquat, Ownership, Sign)
       → Paket landet in staging
  → GitHub-Commit-Status gesetzt
```

> Die Ingestion auf der Control Plane prüft die Checksumme *erneut* und scannt das
> Tarball *erneut* — der Worker wird grundsätzlich nicht beim Wort genommen.

### 13.4 Admin-Release (staging → stable)

```
Core-Team → POST /api/v1/admin/accept (pro Paket)
  → POST /api/v1/admin/release
  → [Atomic] ReleaseBatch: staging→stable + neue Revision + Changelog
  → Cache-Rebuild via NOTIFY registry_index_update
  → [async] Mirror-Push: Tarballs aus S3 extrahieren
       → Git-Blobs/Tree/Commit auf Public-Repo (Fast-Forward)
       → registry.json + compatibility_matrix.json committen
  → Cloudflare PurgeEverything
```

### 13.5 SemVer-Oracle bei Push auf `main`

```
GitHub-Push (main) → semver-release_job enqueuen
  → Worker (MonorepoPath): git fetch --tags
  → Änderungserkennung pro Komponente (gitHasChanges)
  → git archive baseline+current → SemVer-VM
  → Oracle: ABI/AST/Manifest-Diff → TagsToPush
  → Worker handleSemverJobCompletion:
       Ancestry-Check (kein Reverse-Diff)
       → Compiler-Manifest committen (falls geändert)
       → Git-Tags via API setzen
       → Folge-Release-Jobs intern enqueuen (compiler/cli/core)
```

Die Folge-Jobs (CLI-Cross-Compile, Core-Mirror, Compiler-Docker-Build) laufen
host-seitig mit dynamisch aus Vault geladenen Credentials und laden ihre Artefakte über
presigned URLs nach S3 bzw. erzeugen GitHub-Draft-Releases.

### 13.6 Revocation & Advisory (`POST /api/v1/admin/revoke`)

```
Core-Team → Paket finden (TarballKey holen)
  → Revoke in DB (stage → revoked)
  → S3-Objekt löschen (alle Versionen)
  → betroffene Revisionen bestimmen
  → Advisory anlegen
  → betroffene Publisher (via sync_log) ermitteln → Notifications batchen
  → Cache-Rebuild + Mirror-Push + CDN-Purge
```

Die Zustellung erfolgt **in-band**: die CLI erhält offene Advisories als Antwort auf
`POST /api/v1/registry/ack` beim nächsten Sync.

### 13.7 Paket-Download (`GET /.../download`)

```
Client (optional Auth) → Paket nach Name+Version (any stage)
  → Authorizer.AuthorizePackageAction(Read)
       stable → öffentlich
       dev/staging → nur Owner / Org-Member / Admin (sonst uniform 404)
  → Download-Count (fire-and-forget, gepufferter Worker)
  → presigned-GET-URL (15 min) → 302 Redirect
```

> Der uniforme 404 für nicht autorisierte Zugriffe verhindert Namespace-Probing —
> ein Angreifer kann nicht unterscheiden, ob ein privates Paket existiert oder nicht.

---

## 14. Glossar

| Begriff | Bedeutung |
|---------|-----------|
| **Control Plane** | Vertrauenswürdiger API-Server, der alle privilegierten Operationen (DB, S3, Vault, GitHub, Signierung) ausführt. |
| **Data Plane / Worker** | Unvertrauenswürdiger Build-Knoten ohne dauerhafte Geheimnisse; führt Validierung in Wegwerf-VMs aus und delegiert alles Privilegierte. |
| **Zero-Trust** | Architekturprinzip: der Worker besitzt keine Credentials und wird grundsätzlich nicht beim Wort genommen (Re-Verifikation auf der Control Plane). |
| **Firecracker / microVM** | Leichtgewichtige VM zur Isolation untrusted Codes; netzwerklos, I/O nur über Block-Devices. |
| **Jailer** | Firecracker-Wrapper, der die VM in einem chroot mit eigener UID/GID und User-Namespace einsperrt. |
| **Job-Token** | Einmaliges, SHA-256-gehashtes Token, das alle API-Calls eines einzelnen Jobs autorisiert. |
| **mTLS** | Wechselseitige TLS-Authentifizierung; Worker und Control Plane weisen sich gegenseitig per Zertifikat aus. |
| **Vault Transit** | Vault-Engine zum Signieren von Hashes, ohne den privaten Schlüssel herauszugeben. |
| **AppRole** | Vault-Auth-Methode (RoleID + SecretID) für maschinelle Identitäten. |
| **Wrapped SecretID** | Kurzlebiges, single-use Vault-Wrapping-Token, mit dem ein neuer Worker eine SecretID abholt. |
| **SemVer-Oracle** | Komponente, die aus ABI-/AST-/Manifest-Diffs automatisch den Versionssprung (PATCH/MINOR/MAJOR) ableitet. |
| **ABI** | Application Binary Interface; hier über exportierte Symbole (`nm`) statischer Libraries verglichen. |
| **AST** | Abstract Syntax Tree; die CLI-Schnittstelle (`ports.go`) wird strukturell statt textuell verglichen. |
| **Revision** | Monotone Integer-Version des gesamten Registry-Index; Clients syncen „alles seit Revision N". |
| **Stage** | Position im Promotion-Pipeline: `dev → testing → staging → stable → archived/revoked`. |
| **Promotion** | Übergang eines Pakets in das nächste Stadium (z. B. nach erfolgreicher Compile-Validierung). |
| **Deferred Name Claiming** | Mechanismus, der gleichnamige Dev-Pakete erlaubt und Namens-Eindeutigkeit erst ab Staging erzwingt (zwei partielle Unique-Indizes). |
| **Ingestion** | Verschärfte 6-Gate-Tarball-Prüfung auf der Control Plane vor dem Eintrag in die DB. |
| **Mirror** | Öffentliches GitHub-Repo, in das stabile Pakete + `registry.json` per Git-Data-API gepusht werden (kein lokales Git, keine Disk-I/O). |
| **Manifest** | JSON-Beschreibung eines Pakets (`chip_manifest.json`, `driver_manifest.json`, …); Single Source of Truth für Metadaten. |
| **Chip / Driver / Crypto / Arch / Toolchain / Integration / SoC** | Die sieben Paketkategorien des Build-Graphen. |
| **Advisory** | Sicherheitshinweis, der bei Revocation eines Pakets erzeugt und an betroffene Publisher zugestellt wird. |
| **Yank** | Zurückziehen einer Ökosystem-Release aus dem öffentlichen Listing (mit Begründung), ohne sie zu löschen. |
| **Deprecation** | Markierung einer Release als veraltet mit optionaler Warnung; auslieferbar, aber mit Hinweis. |
| **Reaper** | Hintergrund-Goroutine, die in einem Worker-Crash hängengebliebene Jobs (Status `RUNNING`/`COMPILING`) nach Timeout zurücksetzt oder permanent fehlschlagen lässt. |
| **Dead-Man-Switch / Heartbeat** | `system_status`-Liveness-Stempel; ein veralteter Heartbeat (>30 s) markiert einen Worker als ungesund. |