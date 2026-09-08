Hier ist die tiefgehende, selbstkritisch iterierte Architektur-Analyse und der Blueprint für ein **Refactoring des Service-Integrationsprozesses**.

---

# Teil 1: Kritische Schwachstellenanalyse des bisherigen Musters

Wenn wir ehrlich analysieren, wie Entwickler heute neue Services anbinden (oder bestehende wie die `registry` migrieren), treten **fünf systemische Reibungspunkte und Fehlerquellen** auf:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                             DIE 5 SCHWACHSTELLEN IM DETAIL                                       │
├──────────────────────────┬─────────────────────────────────────┬─────────────────────────────────┤
│ Schwachstelle            │ Ursache                             │ Risiko / Auswirkung             │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 1. Routing-Drift         │ Handgeschriebene Route-Slices       │ Entwickler vergisst `Mutates`,  │
│                          │ mit lose gekoppelten Permission-IDs │ vertauscht Trust-Levels oder    │
│                          │ und Pfad-Parametern.                │ mountet am Interceptor vorbei.  │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 2. Magische FGA-Strings  │ `CheckRequest{ ObjectType: "...",   │ Typo im String (`"packge"`)     │
│                          │  Permission: "can_publish" }`       │ führt zu lautloser Ablehnung    │
│                          │                                     │ oder falschen FGA-Abfragen.     │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 3. RLS-Bypass-Gefahr     │ Services halten rohes `*sql.DB` und │ Entwickler vergisst `InTenantTx`│
│                          │ müssen selbst an `set_config`       │ $\to$ Query liefert 0 Zeilen    │
│                          │ denken.                             │ oder leckt Daten ohne RLS.      │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 4. Fragmentierte         │ DB-Write, Audit-Ledger und          │ Bei DB-Fehlern entsteht ein     │
│    Mutationen            │ Outbox-Event werden manuell         │ Audit-Log ohne Daten oder Daten │
│                          │ nacheinander aufgerufen.            │ ohne Audit-Trail (Split-Brain). │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 5. Massive Boilerplate   │ ~300-400 Zeilen Verdrahtung in      │ Hohe kognitive Last, falsche    │
│    in `main.go`          │ jedem Service für Gates, Valkey,    │ Listener-Reihenfolge oder       │
│                          │ JWKS, DPoP, Caches, Outbox.         │ inkonsistente Timeouts.         │
└──────────────────────────┴─────────────────────────────────────┴─────────────────────────────────┘
```

---

# Teil 2: Die 5 Säulen der neuen Integrations-Architektur

Um Sicherheit **garantiert** und die Developer Experience (DX) **mühelos** zu machen, transformieren wir den Prozess von *"manueller Verdrahtung"* zu **"Compile-Time Gültigkeit & typisiertem Baukasten"**.

```
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                           DIE 5 CLEAN-FUTURE SÄULEN                                │
  ├─────────────────────────────────────────────────────────────────────────────────────┤
  │ 1. Typisierte Route-Registrare (Code-Generated via policygen)                       │
  │    Unmöglichkeit, HTTP-Methode, Permission, Idempotenz oder Pfad falsch zu mounten. │
  ├─────────────────────────────────────────────────────────────────────────────────────┤
  │ 2. Typsicherer FGA-Client (Aus policy/model/*.fga generiert)                        │
  │    fga.Package(id).CanPublish(ctx) statt fehleranfälliger String-Maps.              │
  ├─────────────────────────────────────────────────────────────────────────────────────┤
  │ 3. Zero-Bypass TenantDB & Boot-Time RLS-Guard                                       │
  │    Kein Zugriff auf rohes *sql.DB für Mandantendaten; Service bootet nur mit RLS.   │
  ├─────────────────────────────────────────────────────────────────────────────────────┤
  │ 4. Atomic Mutation Envelope (Unit of Work)                                         │
  │    Transaktion, Audit-Ledger & Outbox atomar in einer einzigen Methoden-Klammer.    │
  ├─────────────────────────────────────────────────────────────────────────────────────┤
  │ 5. Declarative ServiceKit                                                           │
  │    cmd/service/main.go schrumpft von 400 Zeilen Boilerplate auf < 30 Zeilen.       │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Säule 1: Code-Generated Typed Route Registrars (`policygen`)

### Das Problem bisher:
In `api/routes.go` muss der Entwickler manuell ein Struct befüllen:
`{ Pattern: "POST /api/v1/tenants/{id}/packages", PermissionID: spolicy.PermRegistryPackagePublish, Mutates: true, Tenant: middleware.TenantFromPath("id"), Handler: h.Publish }`.
Ein kleiner Fehler (z. B. `Mutates: false` vergessen oder `{tenantId}` statt `{id}`) führt zu subtilen Sicherheitslücken.

### Die Lösung:
`policygen` liest `permissions.yaml` und erzeugt für **jede Route einen typisierten Registrar**:

```go
// Generierter Code in shared/policy/routes_gen.go
type PackageRoutes interface {
    PublishPackage(ctx context.Context, tenantID string, p *principal.Principal, r *http.Request) (any, error)
    ReadPackage(ctx context.Context, tenantID string, packageID string, p *principal.Principal) (any, error)
}

func MountPackageRoutes(router *servicekit.Router, h PackageRoutes) {
    // Verknüpft automatisch Permission, HTTP-Methode, Pfad-Extraktion, Idempotenz,
    // Trust-Level (L1-L3) und Signature-Requirements aus permissions.yaml!
    router.RegisterMutation(
        "POST /api/v1/tenants/{id}/packages",
        PermRegistryPackagePublish,
        middleware.TenantFromPath("id"),
        h.PublishPackage,
    )
}
```

**DX-Gewinn:** Der Entwickler implementiert nur noch ein Go-Interface. Das Routing, die Gate-Kette, Idempotenz und Fehlerbehandlung (RFC 9457) sind **zu 100% zur Compile-Zeit garantiert**.

---

## Säule 2: Typsicherer FGA-Client (`fga-gen`)

### Das Problem bisher:
`fgaClient.CheckPermission(ctx, CheckRequest{ ObjectType: "package", ObjectID: pkgID, Permission: "can_publish" })`.
- Kein Compiler prüft, ob der Typ `"package"` existiert.
- Kein Compiler prüft, ob die Relation `"can_publish"` auf `"package"` existiert.
- Kein Entwickler weiß aus dem Kopf, ob `ObjectID` mit Prefix oder ohne erwartet wird.

### Die Lösung:
Ein schlanker Codegenerator liest `policy/model/*.fga` und erzeugt typsichere Fluent-Checkers:

```go
// Generierter Code:
type PackageAuthorizer struct { ... }

func (c *FGAClient) Package(packageID string) *PackageAuthorizer {
    return &PackageAuthorizer{client: c, id: packageID}
}

func (p *PackageAuthorizer) CanPublish(ctx context.Context, p *principal.Principal, tenantID string) (bool, error) {
    return p.client.check(ctx, p, tenantID, "package", p.id, "can_publish")
}

func (p *PackageAuthorizer) CanDelete(ctx context.Context, p *principal.Principal, tenantID string) (bool, error) {
    return p.client.check(ctx, p, tenantID, "package", p.id, "can_delete")
}
```

**Im Handler:**
```go
// Vorher: 10 Zeilen Struct-Allokation mit magischen Strings
// Nachher (Einzeiler, typsicher mit IDE-Autocomplete):
allowed, err := fga.Package(pkgID).CanPublish(ctx, caller, tenantID)
```

---

## Säule 3: Zero-Bypass `TenantDB` & Boot-Time RLS-Guard

### Das Problem bisher:
Wenn ein Entwickler ein Repository baut, nimmt er oft ein `*sql.DB` entgegen und vergisst im SQL-Query das `set_config('app.tenant_id', ...)` oder schreibt versehentlich Queries ohne Tenant-Filter.

### Die Lösung:

#### 1. Typ-Sperre gegen ungescopte Queries:
Business-Repositories erhalten **kein** rohes `*sql.DB`, sondern ausschließlich ein `TenantDB`:

```go
type TenantDB interface {
    // InTenantTx erzwingt die Ausführung im RLS-Mandantenscope
    InTenantTx(ctx context.Context, tenantID string, fn func(tx dbtx.Tx) error) error
}
```

#### 2. Der Boot-Time RLS-Guard (`VerifyDatabaseRLS`):
Beim Starten jedes Services scannt der Service automatisch den PostgreSQL-Katalog `pg_tables` & `pg_class`:
1. Besitzen **alle** Tabellen im Schema `FORCE ROW LEVEL SECURITY`?
2. Läuft die Verbindung unter einer unprivilegierten Anwendungsrolle (z. B. `identity_app`, `registry_app`) und **niemals** als DB-Superuser / Table-Owner?

```go
// In main.go / startup:
if err := servicekit.VerifyDatabaseSecurity(ctx, db, "registry"); err != nil {
    // Bricht sofort ab: "table 'packages' is missing FORCE ROW LEVEL SECURITY"
    slog.Error("CRITICAL: Database security check failed", "error", err)
    os.Exit(1)
}
```

---

## Säule 4: Atomic Mutation Envelope (Unit of Work)

### Das Problem bisher:
Ein Handler, der eine sicherheitskritische Mutation durchführt (z. B. Release freigeben, Mitgliedsrolle ändern), muss drei Dinge tun:
1. DB-Zeile schreiben
2. In `audit_ledger` loggen
3. In `outbox_events` stagen (für OpenFGA Sync)

Wenn Schritt 1 gelingt, aber der Server vor Schritt 2 oder 3 abstürzt, ist der Systemzustand korrupt.

### Die Lösung:
Eine **Unit-of-Work-Klammer (`Mutate`)**:

```go
err := uow.Mutate(ctx, tenantID, func(scope servicekit.MutationScope) error {
    // 1. Geschäftsdaten schreiben (über scope.Tx)
    if err := repo.CreatePackage(scope.Tx(), pkg); err != nil {
        return err
    }

    // 2. Audit-Log (wird in DIESELBE Postgres-Transaktion geschrieben)
    scope.Audit(audit.Event{
        Action:   spolicy.PermRegistryPackagePublish,
        Resource: "package:" + pkg.ID,
    })

    // 3. Outbox-Event (wird in DIESELBE Postgres-Transaktion geschrieben)
    scope.Outbox("package.published", pkgPublishedPayload{ID: pkg.ID})

    return nil
})
```
Alle 3 Operationen teilen sich **dieselbe atomare PostgreSQL-Transaktion**. Kein Split-Brain, keine vergessenen Audit-Einträge.

---

## Säule 5: Declarative `ServiceKit`

### Das Problem bisher:
`cmd/identity-api/main.go` benötigt 432 Zeilen für Signal-Handling, Konfigurations-Parsing, JWKS-Caching, DPoP-Replay-Stores, Valkey-PubSub, Rate-Limiting-Middleware und Multi-Listener-Setups. Jeder neue Service müsste das kopieren.

### Die Lösung:
Ein kanonisches `servicekit.App`-Paket:

```go
// Das gesamte cmd/registry-api/main.go schrumpft auf:
func main() {
    servicekit.Run(servicekit.AppConfig{
        Name:        "registry-api",
        Permissions: spolicy.PermissionCatalog,
        Mount: func(app *servicekit.App) error {
            // Repositories initialisieren
            packagesRepo := postgres.NewPackagesRepo(app.TenantDB())
            
            // Handler montieren
            api.MountRoutes(app.Router(), packagesRepo, app.FGA())
            return nil
        },
    })
}
```
`servicekit.Run` übernimmt automatisch:
- Sichere Konfigurationsladung (Fail-Fast bei fehlenden Env-Vars)
- Schema-Migrations-Prüfung & RLS-Security-Scan
- Listener-Initialisierung (L1 Public, L4 Health/Ready)
- JWKS- und Token-Verifier-Caching
- Graceful Shutdown aller Server & Worker-Pools

---

# Teil 3: DX-Vergleich & Vorher-Nachher

### Beispiel: Package Publishing in der Registry

#### ❌ Vorher (Fragil, manuell, 4 verschiedene Fehlerquellen):
```go
// Router:
mux.HandleFunc("POST /api/v1/tenants/{id}/packages", handler) // Keine Idempotenz, keine Gate-Kette

// Handler:
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
    // 1. Manuelle Token-Claims-Extraktion
    claims := r.Context().Value("claims").(*TokenClaims) 
    
    // 2. Fehleranfälliger FGA-Check mit String-Maps
    res, err := h.fga.Check(ctx, authz.CheckRequest{
        Principal:  claims.Principal,
        TenantID:   r.PathValue("id"),
        ObjectType: "packge", // ⚠️ Typo!
        ObjectID:   "my-pkg",
        Permission: "publish", // ⚠️ Falsche Relation!
    })
    
    // 3. Ungesicherte DB-Query ohne RLS-Scope
    _, err = h.db.ExecContext(ctx, "INSERT INTO packages ...") 
    
    // ⚠️ Audit-Log vergessen!
    // ⚠️ Outbox-Event vergessen!
}
```

#### ✅ Nachher (CleanFuture, typsicher, unfehlbar):
```go
// 1. Interface-Implementierung (Compiler erzwingt Signatur)
func (h *PackageHandler) PublishPackage(ctx context.Context, tenantID string, p *principal.Principal, r *http.Request) (any, error) {
    var req PublishRequest
    if err := servicekit.DecodeJSON(r, &req); err != nil {
        return nil, err
    }

    // 2. Typsicherer ReBAC-Check (Auto-Complete, Null Typos)
    if allowed, err := h.fga.Package(req.Name).CanPublish(ctx, p, tenantID); err != nil || !allowed {
        return nil, servicekit.ErrForbidden
    }

    // 3. Atomares Unit of Work: DB + Audit + Outbox
    return h.uow.Mutate(ctx, tenantID, func(scope servicekit.MutationScope) error {
        if err := h.repo.CreatePackage(scope.Tx(), req); err != nil {
            return err
        }
        scope.Audit(audit.Event{Action: spolicy.PermRegistryPackagePublish, Resource: req.Name})
        scope.Outbox("package.published", req)
        return nil
    })
}
```

---

# Zusammenfassende Empfehlung für das weitere Vorgehen

1. **Kein Big-Bang-Umbau nötig:** Das Refactoring kann modular eingeführt werden. `shared/policy` und `identity/enforce` sind bereits das Fundament.
2. **Schritt 1:** `policygen` erweitern, um typisierte Route-Interfaces und FGA-Checkers zu generieren.
3. **Schritt 2:** Das `TenantDB`-Interface und den `VerifyDatabaseSecurity`-Boot-Check in `identity/dbtx` bereitstellen.
4. **Schritt 3:** Bei der Anbindung der `registry` direkt das neue Muster anwenden – damit dient die Registry als Vorzeige-Referenz für alle künftigen Services (`update`, `billing`, etc.).

---

# Teil 4: Nachtrag aus der Umsetzung (Stand 13.08.)

Dieses Dokument war eine Ideation. Die Welle-2-Arbeit an der Identity-API (plan7 §10.3-AA bis -AG) hat inzwischen genug Material geliefert, um zwei der Säulen zu **belegen**, eine als **blockiert** auszuweisen und eine vierte um einen Fall zu erweitern, den die Ideation nicht kannte. Die Reihenfolge der Empfehlung oben ändert sich dadurch.

## N1 — Säule 4 ist belegt, aber anders als vermutet: der Umschlag existiert in *drei verschiedenen Formen*

Die Ideation nennt den Atomic Mutation Envelope als Verbesserung. Die Umsetzung zeigt etwas Schärferes als bloße Wiederholung: die Klammer ist an vier Stellen gebaut worden, aber **nicht viermal gleich** — sie zerfällt in drei Formen, und keine davon war eine Entscheidung, die jemand für diesen Fall getroffen hätte.

| Form | Stelle | Was in der Mandantentransaktion liegt |
|---|---|---|
| **A — vollständig** | `identity/api/membership.go` (`SetRole`) | Geschäftsdatum + `audit.Record` + `outbox.StageEvent` |
| **B — ohne Outbox** | `identity/api/groupmapping.go` | Geschäftsdatum + `audit.Record` |
| **C — ohne Audit** | `identity/api/breakglassstore.go`, `identity/api/approvalstore.go` | nur das Geschäftsdatum; der Audit-Eintrag läuft in einer **eigenen, vorher committeten** Transaktion über `audit.CriticalAuditAdapter` |

Form C ist die interessante. Ihre Begründung steht im Code (`identity/audit/breakglass_adapter.go:28`): „`identity/sync` importiert `identity/authz`, also kann `authz` niemals `identity/sync` zurück importieren" — der Aufrufer könne seine Transaktion deshalb nicht durchreichen. Das war richtig, **gilt aber nicht mehr**. `go list -deps ./identity/audit` liefert heute genau drei Pakete aus `identity/`: `dbtx`, `outbox`, `audit`. Der neutrale Transaktionstyp aus plan7 O4 hat den Zyklus aufgelöst; die Begründung des Adapters ist nie nachgezogen worden.

Konkret heißt das: **Break-Glass und Freigaben könnten ihren Audit-Eintrag heute in derselben Transaktion schreiben wie die Gewährung, und tun es nicht.** Die verbleibende Fehlermöglichkeit — ein Audit-Eintrag für eine Gewährung, die danach nicht gespeichert wurde — ist im Adapter bewusst als „die wahrhaftige Richtung" beschrieben, und als Notlösung war das die richtige Wahl. Als Dauerzustand ist sie eine, die nicht mehr nötig ist.

Damit ist Säule 4 nicht bloß Komfort, sondern die Auflösung von drei Formen zu einer. Dass die Formen auseinandergelaufen sind, hat außerdem **dieselbe Klasse von Fehler** viermal ermöglicht, und jedes Mal still:

- Der Break-Glass-Audit-Adapter rief `Begin(ctx)` **ohne Mandantenscope**. `audit_ledger` hat `FORCE ROW LEVEL SECURITY` — jeder Insert wurde abgewiesen. Unsichtbar, weil die Tests einen `MemoryOutboxStore` benutzten.
- `impersonation_sessions` trug zwei Spalten für einen Begriff (`target_org_id` vom Code geschrieben, `tenant_id` von RLS erzwungen). Der `PostgresStore` konnte nie eine Zeile schreiben; die Tabelle war beweisbar leer.
- `RevokeGrant` schrieb überhaupt keinen Audit-Eintrag. Gefunden hat das nicht ein Review, sondern der Drift-Wächter `TestAudit_EveryCriticalRouteReachesTheLedger` — und der musste erst gebaut werden.

Das ist das Argument für Säule 4 in seiner stärksten Form: **jede Variante der Klammer hat eine eigene Gelegenheit geschaffen, den Mandantenscope oder den Ledger zu vergessen, und beides schlägt still fehl.** Ein `Mutate`-Umschlag macht den Scope und den Ledger zu einer Eigenschaft der Klammer statt zu einer Aufgabe des Aufrufers.

**Korrektur an der Ideation:** `scope.Audit(...)` und `scope.Outbox(...)` als *sammelnde* Aufrufe, die am Ende geschrieben werden, wären falsch. Der Audit-Eintrag muss zum Zeitpunkt seines Aufrufs geschrieben werden und die Mutation bei Fehlschlag *scheitern lassen* — genau so macht es `SetRole` heute („Eine Elevation, die niemand nachweisen kann, ist schlimmer als eine, die nicht stattgefunden hat"). Ein gesammelter Eintrag verschöbe den Fehler ans Ende der Klammer, wo der Aufrufer ihn keiner Ursache mehr zuordnen kann.

**Ergänzung:** Der Umschlag braucht neben Audit und Outbox einen dritten Kanal, den die Ideation nicht hat — **`critical`-Audit**. `spolicy` unterscheidet `audit: read`/`write`/`critical`; kritische Einträge lösen zusätzlich eine Benachrichtigung aus. Wer das dem Aufrufer überlässt, bekommt wieder vier Kopien.

**Was beim Umzug der Stores (14.08.) auffiel und in Säule 4 hineinspielt:** Ein Mutationstest hat `AND first_approver_id <> $1` aus `PostgresApprovalStore.RecordSecondApproval` entfernt — und **keiner der zehn Freigabe-Tests wurde rot**. Das ist kein Loch, sondern gewollte Tiefenstaffelung: die Vier-Augen-Regel hat drei Eigentümer (`approval.go:199` lehnt die Selbstfreigabe ab, bevor der Store erreicht wird; das SQL-Prädikat; `ck_release_approvals_dual_control` in Migration 023). Der Store ist in keinem heutigen Pfad die entscheidende Schicht.

Der Punkt für Säule 4: **wenn der Umschlag Schichten zusammenlegt, darf er diese Staffelung nicht mit einsammeln.** Genau das wäre die naheliegende Vereinfachung — „die Regel steht schon im Handler, das Prädikat kann weg" — und sie würde die letzten beiden Linien auf eine reduzieren, ohne dass ein Test es sagt. Der Umschlag vereinheitlicht die *Klammer*, nicht die Regeln darin.

Der zweite Mutant (`revoked_at IS NULL` aus `PostgresGrantStore.ActiveFor` entfernt) starb dagegen in der Naht — dort ist der Store die einzige Schicht, und der Test weiß das.

**Umgesetzt 14.08.** — `identity/mutation`, sieben Commits (`f7420f4` … `40b2996`). Der ausführliche Ergebnisblock steht in plan7 §10.3-AH; hier nur, was den Plan selbst korrigiert:

- Die Ideation vermutete Wiederholung. Der Befund war **Umgehung**: zehn Aufrufstellen, sieben davon an der AUD-04-Matrix vorbei, drei mit hart verdrahteter Klasse, null Leser des Katalogs.
- Der dritte Kanal, den ich oben als „`critical`-Audit" ergänzt hatte, ist **kein eigener Kanal** geworden. `Scope.Audit` ist einer, und die Klasse entscheidet, was sein Fehlschlag kostet. Ein zweiter Aufruf für kritische Fälle hätte dem Aufrufer genau die Entscheidung zurückgegeben, die ihm abgenommen werden sollte.
- Die Klammer hat einen Zusatz bekommen, den die Ideation nicht hat und der am weitesten trägt: **eine Permission, deren Klasse nicht `read` ist, committet nicht ohne Ledger-Eintrag.** Damit ist die Katalogdeklaration an *jeder* Aufrufstelle tragend, nicht nur an den Routen, die ein Integrationstest zufällig abläuft.
- `Scope` ist eine Schnittstelle, nicht die konkrete Struktur aus der Skizze. Sonst hätten vierzehn Break-Glass-Unit-Tests eine Datenbank gebraucht, um an Regeln zu kommen, die mit Transaktionen nichts zu tun haben.

Die Warnung aus diesem Abschnitt — die Klammer vereinheitlicht die Klammer, nicht die Regeln darin — hat gehalten: die drei Eigentümer der Vier-Augen-Regel stehen unverändert, und die vier Tests aus `60a8bc0` halten sie fest.

## N2 — Säule 3 ist blockiert, und der Blocker ist konkret benennbar

`TenantDB` als Typ-Sperre setzt voraus, dass Repositories die Mandantentransaktion erreichen können. Das können sie heute nicht überall: **`identity/celldir` erfüllt zwei Aufgaben in einem Paket.**

- `pool.go` (111 Zeilen) ist die Mandantentransaktion — `InTenantTx`, `ExecInTenantTx`, `BeginTenantTx`. Es importiert nur `dbtx`.
- `migration.go` und `saga.go` sind die Zellmigration. `migration.go` importiert **`identity/authz`**.

Weil das Paket als Ganzes von `authz` abhängt, kann `authz` `celldir` nicht importieren. Genau daran ist W2.5 gestoßen: der Break-Glass-Store und der Approval-Store gehören fachlich zu `authz` bzw. `approval`, mussten aber in `identity/api` liegen, nur um an `celldir.BeginTenantTx` zu kommen. `identity/api/breakglassstore.go` und `identity/api/approvalstore.go` stehen dort aus Importgründen, nicht aus fachlichen.

**Der Schnitt ist mechanisch und klein:** `pool.go` wandert in ein eigenes Paket (`identity/tenantdb`), das nichts außer `dbtx` importiert. `celldir` behält Migration und Saga. Danach kann jedes Paket den Mandantenscope erreichen, ohne die Zellmigration mitzuziehen — und Säule 3 ist überhaupt erst baubar. Das ist zugleich **T-10.9** im plan7-Backlog.

**Umgesetzt 14.08.** (`bb40456`, `identity/tenantdb`). Eine Grenzregel in `shared/boundaries_test.go` hält die Eigenschaft fest, die den Schnitt trägt: `identity/tenantdb` darf aus diesem Repo nur `identity/dbtx` importieren. Ein einziger neuer Import stellt die Sperre für alles wieder her, was darunter liegt, und sonst würde es nichts merken.

Die Stores sind danach an ihren fachlichen Platz gezogen — `authz.PostgresGrantStore`, `approval.PostgresApprovalStore` — benannt nach ihrem Geschwister im selben Paket (`MemoryGrantStore`, `MemoryApprovalStore`), weil das die Wahl ist, die ein Leser vergleicht. `api.TenantTxSource` ist bewusst geblieben: siehe N1, er hat womöglich keine Zukunft.

**Der Boot-Time-RLS-Guard braucht eine Korrektur:** Die Ideation prüft „läuft unter einer unprivilegierten Rolle". Das reicht nicht. Es gibt fünf Rollen (`identity_migrator`, `identity_app`, `identity_api`, `identity_outbox_worker`, `identity_scim`), und der Fund aus W2.4 war nicht eine falsche Rolle, sondern eine **fehlende Berechtigung**: `identity_api` durfte `audit_ledger` nicht lesen. Der Guard muss deshalb prüfen, dass die Verbindungsrolle die Rechte hat, die ihre Routen brauchen — nicht bloß, dass sie nicht der Owner ist. Sonst startet der Dienst und die Route scheitert im Betrieb.

**Umgesetzt 14.08.** — `identity/dbguard`, Migration 024, `tenantdb.DB` (`6c812a1`, `2935853`, `8caa610`). Ausführlich in plan7 §10.3-AJ; hier, was diesen Abschnitt korrigiert:

- Der Befund war schärfer als „ungeprüfte Rolle": **alle vier Rollen waren `NOLOGIN`**, also unerreichbar, und Admin-API und SCIM teilten sich eine Verbindung. Die Trennung existierte nur in den Tests.
- Der **positive** Grant-Check aus dieser Notiz ist bewusst nicht gebaut. Er bräuchte eine Tabellenliste pro Binary neben dem Routentisch — ein zweiter Katalog, der driftet. Die negativen Invarianten brauchen keine Liste; der positive gehört später aus dem Routentisch abgeleitet.
- Die Ideation prüft „alle Tabellen haben FORCE RLS". Sechs haben es nicht, fünf davon zu Recht. Der Wert liegt deshalb nicht in der Prüfung, sondern in der **Ausnahmeliste**, und darin, dass sie *entschieden* von *unentschieden* trennt.
- Die Typsperre ist bewusst nicht ausgerollt: der Fehler, den sie verhindert, kommt nirgends vor, und nach dem Guard ist sie Tiefenstaffelung statt Grenze. Was Regression verhindert, ist ein Test, der für jedes rohe `*sql.DB` eine Begründung verlangt.

## N3 — Säule 2 hat einen Vorläufer, der bereits trägt

Die Ideation will Fluent-Checker aus `policy/model/*.fga`. Ein Teil davon existiert schon und hat sich bewährt: `shared/policy/fga_vocabulary.go` kennt die Relationen und markiert `contextualOnlyRelations` — Relationen, die **nur** als kontextueller Tupel auftreten dürfen und nie in den Store geschrieben werden (ADR 0005: Break-Glass und Impersonation). Beim Bau von W2.5 war das die Stelle, an der `impersonation_viewer` registriert werden musste.

Der Generator aus Säule 2 muss diese Unterscheidung **mitgenerieren**, sonst nimmt er sie weg: ein Fluent-Checker, der für jede Relation gleich aussieht, lädt dazu ein, eine kontextuelle Relation zu schreiben, und genau das verbietet ADR 0005. Vorschlag: kontextuelle Relationen bekommen gar keinen Schreibpfad im generierten Klienten.

`policygen` hat mit dem Katalog-Artefakt (§10.3-AG) außerdem gezeigt, wie ein generiertes Artefakt an einen Konsumenten außerhalb des Repos ausgeliefert wird: **Inhalt als Datei, Identität als Header.** Dasselbe Muster trägt für jeden weiteren Konsumenten — ein Service, der gegen eine Katalogversion gebaut wurde, kann zur Laufzeit merken, dass er gegen eine andere spricht, ohne den Katalog abzurufen.

## N4 — Säule 1 braucht eine Ergänzung, die aus W2.5 kommt

Der generierte Route-Registrar in der Ideation überträgt Permission, Methode, Idempotenz, Trust-Level und Signaturpflicht. Zwei Felder fehlen, die inzwischen tragen:

- **`impersonation_allowed`** — steht seit W2.5 in `RouteSecurityPolicy` und entscheidet, ob eine Support-Sitzung eine Route ausführen darf. Der Nullwert lehnt ab. Ein Generator, der das Feld nicht mitgibt, macht jede generierte Route für Impersonation dicht — oder, schlimmer, offen, falls jemand den Nullwert umdreht.
- **`requires_signature`** — verlangt eine abgesetzte JWS gegen `cnf.jkt` des Tokens (W2.6).

Beide waren vor W2.5/W2.6 **Deklarationen, die nach Kontrollen aussahen und von nichts gelesen wurden** — das ist der häufigste Befund dieses Projekts. Ein Generator, der sie überträgt, macht diese Klasse unmöglich; einer, der sie vergisst, stellt sie wieder her.

## N5 — Der Kompositionspunkt fehlt weiterhin dort, wo Säule 5 ihn braucht

`servicekit.Run` setzt voraus, dass es *einen* Weg gibt, einen Dienst zu bauen. Den gibt es seit W2.7 zum ersten Mal für die Identity-API: `identity-api` konstruiert einen `authz.NewFGAClient` mit beiden Providern und verlangt `IDENTITY_OPENFGA_URL`/`IDENTITY_OPENFGA_STORE_ID` als Pflicht.

Die Registry ist davon unberührt: `registry/internal/server/authz` ist ein vollständig eigenes, rollenbasiertes System, das OpenFGA nicht anfasst. Solange das so ist, wäre ein `servicekit`, das beide bedienen soll, eine Abstraktion über zwei Systeme, die sich nicht einig sind — und würde deren Unterschied konservieren statt auflösen. **Säule 5 kommt zuletzt**, nicht weil sie schwer ist, sondern weil sie erst dann etwas Gemeinsames beschreiben kann.

## N6 — Geänderte Reihenfolge

Die Empfehlung oben („Schritt 1: policygen erweitern") setzt am sichtbarsten Punkt an, nicht am tragendsten. Nach der Umsetzungserfahrung:

| # | Schritt | Grund |
|---|---|---|
| **1** | **`pool.go` aus `celldir` herauslösen** (`identity/tenantdb`) | Mechanisch, klein, entblockt Säule 3 und räumt die zwei Stores aus `identity/api` an ihren fachlichen Platz. → T-10.9 |
| **2** | ~~**Säule 4: Atomic Mutation Envelope**~~ **— umgesetzt 14.08.** | `identity/mutation`; alle Mutationsrouten der öffentlichen API gehen hindurch. Der SCIM-Listener bekommt die Katalogklasse statt der Klammer, weil seine Idempotenz die Lücke schließt — plan7 §10.3-AH und §10.3-AI. |
| **3** | ~~**Säule 3: `TenantDB` + Boot-Guard**~~ **— umgesetzt 14.08.** | Der Guard war der tragende Teil, nicht der Typ: die Rollen waren unerreichbar und die Verbindung ungeprüft. plan7 §10.3-AJ. |
| **4** | **Säule 2: FGA-Vokabular generieren** | Baut auf `fga_vocabulary.go` auf; kontextuelle Relationen ohne Schreibpfad (N3). |
| **5** | **Säule 1: Route-Registrare generieren** | Mit `impersonation_allowed` und `requires_signature` (N4). |
| **6** | **Säule 5: `ServiceKit`** | Erst wenn die Registry denselben Autorisierungsweg geht (N5, T-10.12). |