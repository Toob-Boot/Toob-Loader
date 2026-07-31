# Backlog — `toob-infra` als Monorepo sortieren

**Ausgangslage:** `toob-infra/` enthält heute den Registry-Code, die Deploy-CLI und die
Deployment-Definitionen in einem gemeinsamen `internal/`-Baum ohne Grenzen zwischen ihnen.

**Ziel:** Vier Projekte unter einem Repository, mit **compilergeprüften** Grenzen — nicht mit
Konventionen.

**Präfix `MONO-`.**

---

# TEIL 1 — Der Entwurf

## 1.1 Zwei Beobachtungen, die vieles vereinfachen

**Von sechs Binaries ist genau eines nicht Registry.**

| Binary | Gehört zu | Warum |
|---|---|---|
| `server` | Registry | die Registry-API |
| `worker` | Registry | Firecracker-Validierungs-Daemon |
| `vmrunner` | Registry | PID 1 in der microVM |
| `autoscaler` | Registry | skaliert Registry-Worker |
| `validator` | Registry | Paket-Validierung |
| `toob-ops` | **Plattform** | Deploy-CLI |

Die Aufteilung ist damit kein Zerschneiden, sondern ein **Herausziehen von zwei Dingen** aus
einem Registry-Repository: der Plattform-Werkzeuge und der geteilten Bausteine.

**Der Identity Service hat keinen eigenen Go-Code.** Er *ist* Zitadel — ein fremdes Binary.
Was wir besitzen, ist die Client-Bibliothek (`shared/identity/`) und das Deployment
(`platform/deploy/`). Es gibt deshalb kein `identity/`-Projektverzeichnis mit Anwendungscode,
und das ist kein Versäumnis, sondern das erwartete Ergebnis der Entscheidung, Identität zu
adoptieren statt zu bauen.

## 1.2 Grenzen erzwingt der Compiler, nicht die Disziplin

Go beschränkt `internal/` auf den Teilbaum unterhalb des **Elternverzeichnisses** von
`internal`. Das lässt sich ausnutzen:

```
toob-infra/
├── go.mod                    ein Modul, keine go.work-Zeremonie
├── platform/
│   └── internal/             ← nur platform/ darf importieren
├── registry/
│   └── internal/             ← nur registry/ darf importieren
├── update/
│   └── internal/             ← nur update/ darf importieren
└── shared/                   ← kein internal/, für alle importierbar
```

`update/` kann `registry/internal/domain` **nicht** importieren — das ist ein Compilerfehler,
keine Code-Review-Anmerkung. Damit braucht es weder mehrere Module noch `go.work` noch eine
Vereinbarung, an die sich jemand erinnern muss.

Die einzige Richtung, die der Compiler nicht abdeckt, ist `shared/ → produkt/`. Dafür ein
Linter (`MONO-060`).

## 1.3 Zielstruktur

```
toob-infra/
├── go.mod
├── shared/
│   ├── identity/             AUTH-010: JWKS, Token, Middleware, Spiegel
│   ├── vault/                Client, von allen Produkten gebraucht
│   ├── signing/              Transit-Signatur
│   ├── storage/              S3/Object Storage
│   ├── metrics/              Prometheus-Collectors, HTTP-Middleware
│   ├── audit/                Audit-Ereignisse
│   ├── plan/                 Tarife und Kontingente
│   ├── errors/               ErrNotFound, ErrUnauthorized, ErrForbidden
│   └── x/                    envutil, strutil, retry, logx, subsystem
│
├── platform/
│   ├── cmd/toob-ops/
│   ├── internal/
│   │   ├── engine/  stages/  topology/  ui/  exec/  dashboard/  testrunner/
│   └── deploy/
│       ├── packer/  ansible/  terraform/  scripts/  runbooks/
│
├── registry/
│   ├── cmd/{server,worker,vmrunner,autoscaler,validator,registry-verify}/
│   ├── internal/
│   │   ├── domain/           Pakete, Revisionen, Jobs, Matrix, Advisories
│   │   ├── authz/            PolicyEngine — bleibt vollständig
│   │   ├── server/           handler, router, middleware, postgres, ingest, cache
│   │   ├── worker/           daemon, config
│   │   ├── autoscaler/
│   │   ├── validate/
│   │   ├── matrixgen/
│   │   └── jobtoken/
│   ├── migrations/
│   └── deploy/               Nomad-Jobspecs, seccomp-api.json
│
└── update/
    ├── cmd/{toob-edge,toob-fleet}/
    ├── internal/
    ├── migrations/
    └── deploy/               systemd-Units
```

## 1.4 Warum das Deployment gesplittet wird

**`platform/deploy/`** enthält die Maschinerie: Packer, Ansible-Rollen, Terraform-Module und
-Projekte, Skripte. Sie gilt für alle Produkte und wird als Einheit betrieben.

**`<produkt>/deploy/`** enthält Laufzeitartefakte, die mit dem Code versioniert gehören: die
Nomad-Jobspecs der Registry, die systemd-Units des Update Service, das Seccomp-Profil.

Der Test: Ändert sich die Datei, wenn sich der Anwendungscode ändert? Dann gehört sie zum
Produkt. Ändert sie sich, wenn sich die Infrastruktur ändert? Dann zur Plattform.

Ein Nomad-Jobspec mit `image_digest`-Variable und Health-Check-Pfad ändert sich mit dem Code.
Eine Ansible-Rolle für Caddy nicht.

---

# TEIL 2 — Backlog

**Prio:** P0 blockierend · P1 vor der Identity-Integration · P2 danach
**Typ:** `refactor` `cleanup` `feature` `test` `dx`

## Übersicht

| ID | Titel | Prio | Typ |
|---|---|---|---|
| **EPIC A — Vorbereitung** |||
| MONO-001 | Erst löschen, dann verschieben | P0 | cleanup |
| MONO-002 | Ausgangszustand absichern | P0 | test |
| MONO-003 | `git mv` statt Kopieren | P0 | dx |
| **EPIC B — Skelett** |||
| MONO-010 | Verzeichnisskelett anlegen | P0 | refactor |
| MONO-011 | `shared/x/` — die kleinen Helfer zuerst | P0 | refactor |
| **EPIC C — Shared extrahieren** |||
| MONO-020 | `errors`, `audit`, `plan` nach shared | P1 | refactor |
| MONO-021 | `vault`, `signing`, `storage` nach shared | P1 | refactor |
| MONO-022 | `metrics` nach shared | P1 | refactor |
| MONO-023 | `shared/identity/` anlegen | P1 | feature |
| **EPIC D — Plattform herausziehen** |||
| MONO-030 | `internal/ops/` nach `platform/` | P0 | refactor |
| MONO-031 | `list-compilers` und `test-build` in die Registry | P0 | refactor |
| MONO-032 | `deploy/` aufteilen | P1 | refactor |
| **EPIC E — Registry sortieren** |||
| MONO-040 | `internal/domain/` aufteilen | P1 | refactor |
| MONO-041 | Registry-Code nach `registry/internal/` | P1 | refactor |
| MONO-042 | `cmd/` je Produkt sortieren | P1 | refactor |
| MONO-043 | `migrations/` und `deploy/` zur Registry | P1 | refactor |
| **EPIC F — Update-Skelett** |||
| MONO-050 | `update/` anlegen | P2 | feature |
| **EPIC G — Grenzen durchsetzen** |||
| MONO-060 | Import-Linter für `shared/` | P1 | test |
| MONO-061 | Abhängigkeitsdiagramm im CI | P2 | test |
| MONO-062 | Ein Build-Ziel je Produkt | P1 | dx |

---

# EPIC A — Vorbereitung

---

### MONO-001 — Erst löschen, dann verschieben

**Prio:** P0 · **Typ:** cleanup

**Problem**
`AUTH-001` bis `AUTH-003` löschen `handler/auth.go`, `handler/assets/oob.html`,
`postgres/oauth.go`, `domain.OAuthSession`, `PermOrgAdminBypass` und die
`toob_v1_`-Pfade. Wer diese Dateien erst sortiert und dann löscht, sortiert doppelt — und die
Löschung ist danach schwerer nachzuvollziehen, weil sie über mehrere Verzeichnisse verstreut
passiert.

**Lösung**
`AUTH-001`, `AUTH-002` und `AUTH-003` **vor** `MONO-010` erledigen. Das sind reine Löschungen
ohne Ersatz und damit unabhängig vom Rest der Identity-Integration.

Was danach verschwindet, bevor irgendetwas bewegt wird:

| Weg | Umfang |
|---|---|
| `internal/server/handler/auth.go` | ~450 Zeilen |
| `internal/server/handler/assets/oob.html` | Template |
| `internal/server/postgres/oauth.go` | ~200 Zeilen inkl. AES-GCM |
| `internal/server/router/routes_auth.go` | wird stark kleiner |
| `internal/domain/user.go` | `OAuthSession`, `GenerateAPIKey` |
| `internal/domain/permission.go` | `PermOrgAdminBypass` |

**Akzeptanzkriterien**
- [ ] `AUTH-001` bis `AUTH-003` sind abgeschlossen.
- [ ] `go build ./...` und `go test ./...` sind grün.

---

### MONO-002 — Ausgangszustand absichern

**Prio:** P0 · **Typ:** test

**Problem**
Ein Umbau dieser Größe verschiebt hunderte Importpfade. Der Compiler fängt das meiste, aber
nicht alles: Reflection, Struct-Tags, `embed`-Pfade, SQL-Migrationsreihenfolge und
`go:generate`-Direktiven brechen still.

**Lösung**
Vor dem ersten `git mv`:
1. `go build ./...` und `go vet ./...` grün.
2. `go test ./...` grün, Ergebnis als Referenz festgehalten.
3. Ein Lauf gegen die Dev-Umgebung (`toob-ops wizard --env dev`) bis Phase 8, protokolliert.
4. Liste aller `//go:embed`-Direktiven und ihrer Pfade — die brechen bei Verschiebungen und
   der Compiler meldet es erst zur Buildzeit des betroffenen Pakets.

**Akzeptanzkriterien**
- [ ] Referenzergebnis liegt vor.
- [ ] `grep -rn "go:embed" --include="*.go"` ist dokumentiert.

---

### MONO-003 — `git mv` statt Kopieren

**Prio:** P0 · **Typ:** dx

**Lösung**
Jede Verschiebung mit `git mv`, damit `git log --follow` die Historie behält. Bei einem
Sicherheitsvorfall ist „wann kam diese Zeile rein" eine Frage, die man beantworten können
muss — und ein Copy-Delete löscht die Antwort.

Ein Paket pro Commit, Commit-Nachricht nennt Quelle und Ziel. Nach jedem Commit `go build ./...`.

**Akzeptanzkriterien**
- [ ] `git log --follow` funktioniert für eine Stichprobe verschobener Dateien.
- [ ] Kein Commit enthält gleichzeitig eine Verschiebung und eine inhaltliche Änderung.

---

# EPIC B — Skelett

---

### MONO-010 — Verzeichnisskelett anlegen

**Prio:** P0 · **Typ:** refactor

**Lösung**
Leere Struktur mit `.gitkeep` anlegen, `go.mod` bleibt an der Wurzel. Noch nichts verschieben —
das Skelett zuerst, damit die folgenden Tickets ein Ziel haben und nicht nebenbei über die
Struktur entscheiden.

```
shared/{identity,vault,signing,storage,metrics,audit,plan,errors,x}/
platform/{cmd/toob-ops,internal,deploy}/
registry/{cmd,internal,migrations,deploy}/
update/{cmd,internal,migrations,deploy}/
```

---

### MONO-011 — `shared/x/` — die kleinen Helfer zuerst

**Prio:** P0 · **Typ:** refactor

**Lösung**
Der einfachste Schritt, deshalb zuerst: `envutil`, `strutil`, `retry`, `logx`, `subsystem` und
`archiveutil` nach `shared/x/`.

Diese Pakete haben keine Abhängigkeiten nach oben und viele Konsumenten. Sie zu bewegen
bestätigt, dass der Ablauf aus `MONO-003` trägt, bevor es an die verflochtenen Teile geht.

> **Ausnahme prüfen:** `archiveutil` wird heute nur von `worker/daemon/archive.go` und
> `server/ingest` genutzt — beides Registry. Wenn kein zweiter Konsument absehbar ist, gehört
> es nach `registry/internal/`. Ein `shared/`-Paket mit einem Konsumenten ist kein geteilter
> Baustein, sondern ein verlegter.

---

# EPIC C — Shared extrahieren

---

### MONO-020 — `errors`, `audit`, `plan` nach shared

**Prio:** P1 · **Typ:** refactor

**Lösung**

| Von | Nach | Begründung |
|---|---|---|
| `domain/errors.go` | `shared/errors/` | `ErrNotFound`, `ErrUnauthorized`, `ErrForbidden` — jedes Produkt braucht sie |
| `domain/audit.go` | `shared/audit/` | Audit-Ereignisse sind produktübergreifend (`AUTH-053`, `IDP-070`) |
| `domain/plan.go` | `shared/plan/` | Tarife gelten für Registry-Kontingente **und** Flotten-Abrechnung |

`plan.go` ist der interessante Fall: `ResolvePlan(tier, overrides)` wird heute nur von der
Registry aufgerufen, aber `MaxOrgs` und die Flotten-Kontingente sind derselbe Mechanismus.
Hier lohnt sich die Vorwegnahme, weil sonst zwei Tarifmodelle entstehen.

---

### MONO-021 — `vault`, `signing`, `storage` nach shared

**Prio:** P1 · **Typ:** refactor

**Lösung**

| Von | Nach |
|---|---|
| `server/vault/client.go` | `shared/vault/` |
| `server/signing/transit.go` | `shared/signing/` |
| `server/storage/{object,s3}.go` | `shared/storage/` |
| `server/crypto/signer.go` | `shared/signing/` |

Alle drei braucht der Update Service unverändert: Vault für DB-Credentials und HMAC-Key,
Signing für die Firmware-Signatur, Storage für Artefakte.

**Wichtig für `shared/signing/`:** `stages/deploy.go` prüft, dass
`toob-image-signing-<env>` vom Typ `ecdsa-p256` ist — Cosign kann für Vault-Transit kein
Ed25519. Der Firmware-Schlüssel muss dagegen Ed25519 sein. Das geteilte Paket muss beide
Typen unterstützen und **darf keinen Default setzen**, sonst legt jemand den Firmware-Key als
P-256 an und kein Gerät akzeptiert die Signatur.

---

### MONO-022 — `metrics` nach shared

**Prio:** P1 · **Typ:** refactor

**Lösung**
`server/metrics/` nach `shared/metrics/`. Die HTTP-Middleware und die Collector-Registrierung
sind generisch; produktspezifische Metriknamen bleiben beim Produkt.

---

### MONO-023 — `shared/identity/` anlegen

**Prio:** P1 · **Typ:** feature

**Lösung**
Das Paket aus `AUTH-010`. Da Registry und Update im selben Modul liegen, ist **kein eigenes Go-Modul
nötig** — ein Paket unter `shared/` genügt.

> **Korrektur an `AUTH-010`:** Dort stand „eigenes Go-Modul". Das war unter der Annahme
> getrennter Repositories richtig. Im Monorepo ist es ein Paket, und `go.work` entfällt.
> Ein eigenes Modul würde erst nötig, wenn ein Konsument außerhalb dieses Repositories
> hinzukommt.

Inhalt: `jwks/`, `token/`, `middleware/`, `mirror/`, `roles/`.

Was hier **nicht** hineingehört und worauf beim Befüllen zu achten ist: `authz/policy.go`,
`domain/permission.go`, alles, was Produkttabellen kennt. Der Reiz, „die Autorisierung" an
einer Stelle zu haben, ist groß und führt geradewegs zu einem zweiten Domänenmodell.

---

# EPIC D — Plattform herausziehen

---

### MONO-030 — `internal/ops/` nach `platform/`

**Prio:** P0 · **Typ:** refactor

**Lösung**
`internal/ops/{engine,stages,topology,ui,exec,dashboard,testrunner}` nach
`platform/internal/`, `cmd/toob-ops/` nach `platform/cmd/toob-ops/`.

Nach der Verschiebung kann `platform/` die Registry-Internas nicht mehr importieren — das ist
der Punkt der Übung und der Grund, warum `MONO-031` unmittelbar folgen muss.

---

### MONO-031 — `list-compilers` und `test-build` in die Registry

**Prio:** P0 · **Typ:** refactor · **Ref:** `OPS-001`

**Problem**
`cmd/toob-ops/list_compilers.go` importiert `domain.CompilerVersion`; `test_build.go`
zusätzlich `domain.RegistryIndex` und `domain.VMResult`. Das sind die **einzigen** beiden
Stellen, an denen die Plattform-CLI Registry-Wissen braucht.

Nach `MONO-030` kompiliert das nicht mehr.

**Lösung**
Beide Kommandos werden ein eigenes Binary `registry/cmd/registry-verify/`. Inhaltlich gehören
sie ohnehin dorthin: Sie prüfen Compiler-Images und Rootfs-Builds — Registry-Produktfunktionen,
keine Infrastruktur.

`platform/cmd/toob-ops/` verliert damit seine letzte Produktkopplung und ist produktneutral.

**Akzeptanzkriterien**
- [ ] `platform/` importiert nichts aus `registry/`.
- [ ] `registry-verify` erfüllt beide Kommandos unverändert.
- [ ] Ein Aufruf über `toob-ops` ist nicht mehr nötig — die Dokumentation nennt das neue Binary.

---

### MONO-032 — `deploy/` aufteilen

**Prio:** P1 · **Typ:** refactor

**Lösung**

| Von | Nach | Regel |
|---|---|---|
| `deploy/{packer,ansible,terraform,scripts,runbooks}` | `platform/deploy/` | ändert sich mit der Infrastruktur |
| `deploy/nomad/jobs/registry-*.nomad.hcl` | `registry/deploy/nomad/` | ändert sich mit dem Code |
| `deploy/api/seccomp-api.json` | `registry/deploy/` | gehört zum API-Container |
| `deploy/api/toob-api-hardening.service` | `platform/deploy/ansible/roles/nomad/files/` | Host-Härtung |
| `deploy/release/` | `platform/deploy/release/` | `sign.sh`/`verify.sh` gelten für alle |

Der Nomad-Jobspec trägt `image_digest`, Health-Check-Pfad und Umgebungsvariablen des Servers —
er ändert sich mit dem Code und gehört deshalb zu ihm. Eine Ansible-Rolle für Caddy nicht.

---

# EPIC E — Registry sortieren

---

### MONO-040 — `internal/domain/` aufteilen

**Prio:** P1 · **Typ:** refactor

**Problem**
`domain/` ist der am stärksten verflochtene Teil: Es mischt Registry-Fachlichkeit,
Identitätstypen und geteilte Bausteine in einem Paket.

**Lösung**

| Datei | Nach | Anmerkung |
|---|---|---|
| `package.go`, `registry.go`, `revision.go`, `matrix.go` | `registry/internal/domain/` | |
| `job.go`, `publish_job.go`, `release_job.go`, `release.go` | `registry/internal/domain/` | |
| `advisory.go`, `ecosystem.go`, `admin.go`, `vmresult.go` | `registry/internal/domain/` | |
| `permission.go` | `registry/internal/domain/` | Registry-Berechtigungen, kein geteiltes Wissen |
| `errors.go`, `audit.go`, `plan.go` | `shared/` | siehe `MONO-020` |
| `user.go` | **aufteilen** | Spiegelfelder nach `shared/identity/`, `APIToken` bleibt Registry |
| `organization.go` | **aufteilen** | `OrgRole` nach `shared/identity/roles/`, Spiegel-Structs nach `shared/identity/mirror/` |

`user.go` und `organization.go` sind die einzigen echten Schnitte. Nach `AUTH-033` bleibt vom
`User` ohnehin wenig: Zitadel-Subject, Username, Anzeigename, Plan-Tier, Suspendierung. Das
ist ein Spiegeltyp und gehört nach `shared/identity/`.

`APIToken` und `GenerateAPIToken` bleiben Registry — CI-Tokens sind delegierte
Produktfähigkeit, nicht Identität.

---

### MONO-041 — Registry-Code nach `registry/internal/`

**Prio:** P1 · **Typ:** refactor

**Lösung**
Der große, aber mechanische Schritt:

```
internal/server/     → registry/internal/server/
internal/worker/     → registry/internal/worker/
internal/autoscaler/ → registry/internal/autoscaler/
internal/validate/   → registry/internal/validate/
internal/matrixgen/  → registry/internal/matrixgen/
internal/jobtoken/   → registry/internal/jobtoken/
```

Innerhalb von `registry/internal/server/` bleibt die Aufteilung wie sie ist — `handler`,
`router`, `middleware`, `postgres`, `ingest`, `cache`, `mirror`, `notify`, `github`,
`cloudflare`, `app`, `config`, `authz`. Diese Struktur funktioniert und wird nicht angefasst.

**Ausnahmen**, die nach `MONO-021`/`MONO-022` bereits weg sind: `vault`, `signing`, `crypto`,
`storage`, `metrics`.

---

### MONO-042 — `cmd/` je Produkt sortieren

**Prio:** P1 · **Typ:** refactor

```
cmd/server/     → registry/cmd/server/
cmd/worker/     → registry/cmd/worker/
cmd/vmrunner/   → registry/cmd/vmrunner/
cmd/autoscaler/ → registry/cmd/autoscaler/
cmd/validator/  → registry/cmd/validator/
cmd/toob-ops/   → platform/cmd/toob-ops/     (MONO-030)
                  registry/cmd/registry-verify/ (MONO-031)
```

`console_other.go` und `console_windows.go` bleiben bei `toob-ops` — sie sind
Windows-Terminal-Behandlung für die CLI.

---

### MONO-043 — `migrations/` und `deploy/` zur Registry

**Prio:** P1 · **Typ:** refactor

**Lösung**
`migrations/` nach `registry/migrations/`. Der Update Service bekommt einen eigenen Satz —
getrennte Datenbanken, getrennte Historien.

**Achtung bei `//go:embed`:** Die Migrationen werden vermutlich eingebettet. Der Embed-Pfad ist
relativ zum einbettenden Paket und bricht bei der Verschiebung. Das ist einer der Fälle aus
`MONO-002`, die der Compiler erst spät meldet.

---

# EPIC F — Update-Skelett

---

### MONO-050 — `update/` anlegen

**Prio:** P2 · **Typ:** feature

**Lösung**
Skelett mit `cmd/toob-edge/`, `cmd/toob-fleet/`, `internal/`, `migrations/`, `deploy/systemd/`.
Zwei Binaries entsprechend `ARCHITEKTUR-plattform-topologie.md` §8.

Noch keine Fachlichkeit — nur die Struktur, damit `MONO-060` und `MONO-061` gegen etwas
prüfen können und die Grenze von Anfang an steht statt nachträglich gezogen zu werden.

---

# EPIC G — Grenzen durchsetzen

---

### MONO-060 — Import-Linter für `shared/`

**Prio:** P1 · **Typ:** test

**Problem**
Der Compiler verhindert `update/ → registry/internal/`. Er verhindert **nicht**
`shared/ → registry/`.

Das ist die Richtung, die in der Praxis kaputtgeht: Jemand braucht in `shared/identity/` einen
Registry-Typ, importiert ihn, und aus dem geteilten Baustein wird ein Paket, das der Update
Service nicht mehr benutzen kann.

**Lösung**
`depguard` oder ein eigener CI-Check:

```
shared/**   darf importieren: shared/**, stdlib, externe Abhängigkeiten
            darf NICHT:       platform/**, registry/**, update/**
platform/** darf NICHT:       registry/**, update/**
```

**Akzeptanzkriterien**
- [ ] Ein absichtlicher Import von `registry/internal/domain` in `shared/identity` lässt das CI
      rot werden.
- [ ] Die Regel steht in einer Konfigurationsdatei, nicht in einer Konvention.

---

### MONO-061 — Abhängigkeitsdiagramm im CI

**Prio:** P2 · **Typ:** test

**Lösung**
`go list -deps` je Produkt, daraus ein Diagramm als CI-Artefakt. Die Frage „was zieht der
Update Service eigentlich alles mit" soll man ansehen können, statt sie zu rekonstruieren.

Nützlicher Nebeneffekt: Eine unerwartet große Abhängigkeitsmenge im Datenpfad ist ein
Angriffsflächen-Signal.

---

### MONO-062 — Ein Build-Ziel je Produkt

**Prio:** P1 · **Typ:** dx

**Lösung**

```
just build-registry     # alle fünf Registry-Binaries
just build-platform     # toob-ops
just build-update       # toob-edge, toob-fleet
just test-registry      # nur registry/... und shared/...
```

Der Sinn ist nicht Bequemlichkeit: Wenn `just build-update` versehentlich Registry-Code baut,
ist eine Grenze verletzt — und man sieht es an der Bauzeit, bevor `MONO-060` anschlägt.

---

## Reihenfolge

**Sprint 1 — Löschen und absichern:**
`AUTH-001` → `AUTH-002` → `AUTH-003` → `MONO-001` → `MONO-002` → `MONO-003` → `MONO-010` →
`MONO-011`

Der Abriss zuerst. Was gelöscht wird, muss nicht sortiert werden.

**Sprint 2 — Plattform herausziehen:**
`MONO-030` → `MONO-031` → `MONO-060`

`MONO-031` **unmittelbar** nach `MONO-030` — dazwischen kompiliert `toob-ops` nicht.
`MONO-060` direkt danach, damit die frisch gezogene Grenze sofort bewacht ist.

**Sprint 3 — Shared extrahieren:**
`MONO-020` → `MONO-021` → `MONO-022` → `MONO-023`

**Sprint 4 — Registry sortieren:**
`MONO-040` → `MONO-041` → `MONO-042` → `MONO-043` → `MONO-032`

`MONO-040` (domain aufteilen) vor `MONO-041`, sonst verschiebt man `domain/` einmal und
zerlegt es danach.

**Sprint 5 — Abschluss:**
`MONO-050` → `MONO-062` → `MONO-061`

---

## Was bewusst nicht getan wird

**Kein Umbau innerhalb von `registry/internal/server/`.** Die Aufteilung in `handler`,
`router`, `middleware`, `postgres`, `ingest` funktioniert. Ein Umbau währenddessen würde
Verschiebung und inhaltliche Änderung vermischen und die Historie unlesbar machen.

**Keine getrennten Go-Module.** `internal/` an der richtigen Stelle liefert dieselben Grenzen
ohne `go.work`, ohne Versionssprünge zwischen Modulen und ohne `replace`-Direktiven bei jeder
Änderung.

**Keine Zusammenfassung der 30 Migrationen.** Sie erzählen, wie das Schema entstanden ist. Ein
Zusammenfalten spart nichts und kostet die Herkunft.

---

## Merksatz

> Die Grenze zwischen den Produkten wird vom Compiler bewacht, nicht von der Aufmerksamkeit
> beim Review. Die einzige Richtung, die Go nicht abdeckt — `shared/` nach oben — bekommt
> deshalb einen Linter, und zwar in demselben Sprint, in dem die Grenze entsteht.