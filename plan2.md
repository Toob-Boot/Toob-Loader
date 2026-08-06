# Toob Identity & Authorization — Zielarchitektur

**Version:** 1.0 (Zielbild)
**Status:** Entwurf zur Freigabe. Kein Migrationsplan — der folgt separat.
**Vorgängerdokument:** „Toob Identity Layer — Architekturdokumentation" (Ist-Analyse, 2026-08-06)
**Randbedingungen:** Zitadel bleibt gesetzt. Kein Produktivsystem, keine Migrationszwänge. Go-Monorepo, Postgres, Vault, Nomad bleiben.

**Lesehinweis:** Dieses Dokument beschreibt den **Zielzustand**, nicht den Weg dorthin. Wo eine Entscheidung Konsequenzen für den späteren Umbau hat, ist das mit ▸ markiert. Abschnitt 18 (Requirement-Verortung) und Abschnitt 16 (Modulstruktur) sind die beiden Kapitel, auf denen der Migrationsplan aufsetzen wird.

---

## 1. Leitprinzipien

Zehn Axiome. Jede Detailentscheidung in diesem Dokument ist aus ihnen ableitbar; wo eine spätere Entscheidung einem Axiom widerspricht, ist entweder die Entscheidung oder das Axiom falsch.

| # | Prinzip | Konsequenz |
|---|---|---|
| **P1** | **Rollen sind Daten, nicht Code.** | Eine neue Rolle oder ein neuer Akteurstyp erzeugt Tupel und Modelländerungen, keinen neuen `if`-Zweig in n Services. |
| **P2** | **Eine Regelquelle, viele Ziele.** | Go-Enforcement, Autorisierungsmodell, IdP-Actions und Doku werden generiert. Handgepflegte Duplikate sind ein Bug. |
| **P3** | **Authentifizierung zentral, Autorisierung nah am Request.** | Zitadel entscheidet *wer*, die Enforcement-Schicht entscheidet *ob* — mit maximal einem Netzwerk-Hop in der Zelle. |
| **P4** | **Identitätsebenen bleiben getrennt.** | Mensch, Maschine/CI, Gerät sind eigene Namensräume mit eigenen Credential-Typen. Geräte gehören nicht in den IdP. |
| **P5** | **Zustand ist geteilt oder existiert nicht.** | Kein sicherheitsrelevanter Zustand im Prozessspeicher. Was nicht persistiert ist, darf nicht Grundlage einer Sicherheitsentscheidung sein. |
| **P6** | **Fail-closed bei Mutationen, definiert degradiert bei Lesevorgängen.** | Jeder Ausfallmodus ist explizit entschieden (§ 14), nicht Nebenprodukt der Implementierung. |
| **P7** | **Mandantengrenze ist mehrfach verankert.** | Token → Enforcement → Relationsgraph → RLS. Jede Schicht allein muss Cross-Tenant-Zugriff verhindern. |
| **P8** | **Zellzugehörigkeit ist Konfiguration, kein Code-Pfad.** | Es gibt keinen `if isEnterprise`-Zweig. Shared und Dedicated laufen denselben Code. |
| **P9** | **Kryptografie schlägt Datenbank-Flags.** | Vier-Augen-Freigabe, Soak-Window und Signaturbindung sind kryptografisch durchgesetzt, nicht durch ein Boolean in einer Zeile. |
| **P10** | **Kurzlebig statt widerrufbar.** | Langlebige Credentials sind die Ausnahme mit Begründung. Revocation ist der teure Sonderfall, nicht der Normalbetrieb. |

---

## 2. Systemüberblick

### 2.1 Vier Ebenen

Die heutige Vermischung aus „Zitadel + eine Go-Bibliothek, die alles macht" wird in vier Ebenen mit klaren Grenzen aufgelöst.

| Ebene | Verantwortung | Technologie | Autorität für |
|---|---|---|---|
| **E1 — Authentifizierung** | Wer bist du? Login, MFA/Passkeys, Federation, grobe Zugehörigkeit | Zitadel v4 | Identitäten, Credentials, Org-Mitgliedschaft, `acr`/`amr` |
| **E2 — Autorisierung** | Darf Subjekt S Aktion A auf Ressource R? | OpenFGA (self-hosted, Postgres) | Relationen, abgeleitete Permissions, Hierarchie & Delegation |
| **E3 — Enforcement** | Durchsetzung im Request-Pfad, Token-Handling, Tenant-Kontext | Go-Bibliothek + generierte Interceptors | Nichts (setzt E1/E2 durch) |
| **E4 — Device & Workload Identity** | Wer ist dieses Gerät / dieser Prozess? | X.509/mTLS aus Vault PKI, SPIFFE-artige SAN-URIs | Geräte- und Workload-Identitäten |

Die Trennung E1/E2 ist die zentrale Änderung gegenüber heute. Zitadel behält, was es gut kann (Identität, Credentials, Login-Policies), und verliert, wofür es nicht gebaut ist (tiefe Hierarchien, Ressourcen-granulare Entscheidungen, delegierte Administration über mehrere Ebenen).

### 2.2 Kontextdiagramm

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │ GLOBAL (zellübergreifend, klein, hochverfügbar)                      │
  │   Tenant Directory   Domain/TenantID → Cell-Koordinaten              │
  │   Plattform-Admin & Billing                                          │
  │   Transparency-Checkpoints (öffentlich verifizierbare Log-Heads)     │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ nur Routing-Metadaten, NIE Nutzerdaten
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
  ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
  │  CELL: shared │        │ CELL: ent-01  │        │ CELL: eu-west │
  │  (Standard)   │        │ (Enterprise)  │        │ (Residenz)    │
  └───────────────┘        └───────────────┘        └───────────────┘
        │  identischer Aufbau in jeder Zelle:
        ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  E1  Zitadel v4                                                      │
  │      Instanzen (virtuell) │ Orgs │ Projects │ Actions v2 (Go-Targets) │
  │      SCIM SP  │  Token Exchange  │  Device Flow  │  eigene Postgres   │
  └────────┬──────────────────────────────────┬──────────────────────────┘
           │ JWT (RS/ES/EdDSA), JWKS          │ Events → Outbox
           ▼                                  ▼
  ┌────────────────────────┐        ┌──────────────────────────────────┐
  │ E3  Enforcement        │        │  identity-sync (eigener Prozess) │
  │  Stage 1: lokal (µs)   │        │  Outbox/CDC │ Reconciler │ SCIM  │
  │  Stage 2: FGA (ms)     │◄──────►│  outbound Events (signiert)      │
  └────────┬───────────────┘        └──────────────────────────────────┘
           │ Check / BatchCheck / ListObjects
           ▼
  ┌────────────────────────┐        ┌──────────────────────────────────┐
  │ E2  OpenFGA            │        │  E4  Vault PKI                   │
  │  Modell (generiert)    │        │   Device-CA │ Workload-CA        │
  │  Tupel │ eigene DB     │        │   Transit (Signing) │ HSM-Root   │
  └────────────────────────┘        └──────────────────────────────────┘
           │                                  │ mTLS
           ▼                                  ▼
  ┌──────────────────────────┐      ┌──────────────────────────────────┐
  │ Produkt-DB (RLS, FORCE)  │      │  Geräte (Secure Element / eFuse) │
  │ Audit-DB (Hash-Chain)    │      │  CI-Workloads (OIDC → Exchange)  │
  └──────────────────────────┘      └──────────────────────────────────┘
```

### 2.3 Was bewusst gleich bleibt

Die Ist-Architektur hat mehrere Eigenschaften, die tragfähig sind und übernommen werden — sie sind hier explizit gelistet, damit sie im Umbau nicht versehentlich wegfallen:

- **Org-Claim ist Pflichtbestandteil jedes Tokens.** Ohne Tenant-Bindung existiert kein akzeptiertes Token.
- **Tenant-Kontext für RLS stammt ausschließlich aus verifizierten Claims**, niemals aus Header/Query/Body.
- **JWKS-Cache mit Offline-Fallback und ratenbegrenztem Cache-Miss-Refresh.** Der Verifikationspfad überlebt einen vollständigen IdP-Ausfall.
- **Fail-closed bei unregistrierten Endpunkten** — verschärft von Laufzeit auf Buildzeit (§ 7.3).
- **Progressives Rate-Limiting ohne Account-Lockout.**
- **CI darf nicht nach Produktion promoten.** Diese Grenze bleibt unbedingt.
- **Support-Impersonation ist zeitgebunden, begründungspflichtig, read-only und für den Kunden sichtbar.**

---

## 3. Deployment-Profile: Shared, Dedicated, Isoliert

Enterprise-Kunden sollen eine eigene Instanz bekommen können, ohne dass daraus zwei Codebasen werden. Die tragende Abstraktion dafür ist die **Zelle (Cell)**.

### 3.1 Definition

Eine **Zelle** ist ein vollständiger vertikaler Stack: Zitadel + OpenFGA + Produkt-DB + Audit-DB + Vault-Namespace + API-Endpunkte. Ein Tenant lebt in **genau einer** Zelle. Es gibt **keine zellübergreifenden Datenpfade** — kein Cross-Cell-Query, keine verteilte Transaktion, keine geteilte Session.

Global existiert nur das **Tenant Directory**: eine kleine, hochverfügbare, ausschließlich lesend genutzte Zuordnung `Domain | TenantID → Cell-Koordinaten` (Issuer-URL, FGA-Endpunkt, DB-Referenz, Region). Es enthält keine Nutzerdaten.

### 3.2 Drei Profile

| | **P1 — Shared Org** | **P2 — Dedicated Instance** | **P3 — Isolated Cell** |
|---|---|---|---|
| **Zielgruppe** | Standard, Self-Service | Enterprise mit Branding-/Policy-Anspruch | Datenresidenz, Air-Gap, Regulatorik |
| **Zitadel** | Org in geteilter Instanz | **eigene virtuelle Instanz** im geteilten Cluster | eigener Cluster |
| **Login-Domain** | `id.the-toob.com` | `id.kunde.com` (Custom Domain) | `id.kunde.com`, eigene Region |
| **Login-/MFA-Policy** | Plattform-Vorgabe | **eigene Policy** | eigene Policy |
| **Branding, SMTP** | Plattform | eigen | eigen |
| **IdP-Federation** | pro Org konfigurierbar | pro Instanz | pro Instanz |
| **OpenFGA** | geteilter Server, **eigener Store** | geteilter Server, eigener Store | eigener Server + DB |
| **Produkt-DB** | geteilt, RLS-isoliert | geteilt, RLS-isoliert | eigene DB |
| **Signing-Key (Releases)** | eigener Transit-Key | eigener Transit-Key | eigener Transit-Key, optional Kunden-HSM |
| **Audit-Kette** | pro Tenant eigene Kette | pro Tenant eigene Kette | eigene Kette + eigener Checkpoint |
| **Blast Radius** | Zelle | Zelle | Kunde |
| **Betriebskosten** | ~0 | gering | hoch (eigener Stack) |

Der entscheidende Punkt: **P1 → P2 ist ein Konfigurationswechsel innerhalb derselben Zelle**, kein Umzug. P2 → P3 ist ein Umzug (Export/Import), aber ein geplanter, kein Live-Migrationsfeature. Zellwechsel ist ein Batch-Vorgang mit Wartungsfenster — bewusst kein Online-Feature (§ 17, Anti-Pattern).

### 3.3 Warum eigener FGA-Store pro Tenant, auch im geteilten Profil

Ein OpenFGA-Store ist die Isolationsgrenze für Tupel. Ein Store pro Tenant statt eines globalen Stores mit tenant-präfigierten Objekten bringt:

- **Harte Isolation ohne Modellierungsdisziplin.** Ein Modellierungsfehler kann keine Tupel über Tenantgrenzen sichtbar machen — es gibt keine gemeinsame Tupelmenge.
- **Pro-Tenant-Modellversionierung.** Ein Enterprise-Kunde kann ein erweitertes Modell fahren (eigene Rollen), ohne dass alle anderen es bekommen.
- **Saubere Löschung.** DSGVO-Löschbegehren = Store löschen.

Preis: Modell-Rollouts müssen über n Stores ausgerollt werden (Automatisierung nötig, siehe § 6.5), und Plattform-übergreifende Abfragen („welche Tenants haben Nutzer X?") sind nicht über FGA beantwortbar — dafür ist das Tenant Directory und die Produkt-DB zuständig.

▸ *Konsequenz für den Umbau:* Store-Provisionierung wird Teil des Tenant-Onboarding-Workflows und muss dieselbe SAGA-Behandlung bekommen wie die Zitadel-Org-Erstellung heute (Kompensation bei Teilausfall).

### 3.4 Was die Applikation von Zellen wissen darf

Nichts, außer ihrer eigenen Zellkonfiguration beim Start. Die Bindung erfolgt über:

- **Domain-basiertes Routing am Edge:** `api.kunde.toob.com` → Zelle `ent-01`. Kein Cross-Cell-Routing im Datenpfad.
- **Zellkonfiguration als Startparameter** (Issuer, JWKS-URL, FGA-Endpoint + Store-Auflösung, DB-DSN, Vault-Pfad, Audit-Ketten-ID).
- **Store-Auflösung pro Request** aus dem verifizierten Org-Claim über einen prozesslokalen Cache, der aus dem Tenant Directory gefüttert wird.

Es gibt keinen Code-Pfad, der auf „Enterprise ja/nein" verzweigt (P8). Ein Feature, das nur im Enterprise-Profil existiert, ist entweder ein Konfigurationswert oder eine FGA-Relation — nie eine Compile-Zeit-Unterscheidung.

---

## 4. Identitätsmodell

### 4.1 Akteurstypen

| Typ | Credential | Lebt in | FGA-Typ | In Zitadel? |
|---|---|---|---|---|
| **Mensch (Plattform-Staff)** | Passkey, L3-Pflicht | Toob-Instanz | `user` | ja, eigene Org, **nie** in Kunden-Orgs |
| **Mensch (Tenant-Mitarbeiter)** | Passkey / föderiert | Tenant-Org | `user` | ja |
| **Mensch (Endkunde eines Marktplatzes)** | Passkey/Passwort, ggf. föderiert | Marketplace-Org | `user` | ja (oder föderiert) |
| **Service Account** | JWT-Profile / Private-Key-JWT | Tenant-Org | `service_account` | ja (Machine User) |
| **CI-Workload** | GitHub-Actions-OIDC → Token Exchange | — | `workload` | nein (nur transient) |
| **Interner Service** | mTLS mit SPIFFE-artiger SAN-URI | Vault PKI | `workload` | nein |
| **Gerät** | X.509 Client-Zertifikat, hardwareverankert | Vault PKI | `device` | **nein** |

Die Trennung ist nicht kosmetisch: Menschen brauchen Login-UX und MFA-Recovery, Maschinen brauchen kurze Lebensdauern und Attest-Claims, Geräte brauchen Offline-Fähigkeit und Rotation ohne Nutzerinteraktion. Ein System, das alle drei in einem Nutzerverzeichnis führt, optimiert für keines davon.

### 4.2 Subject-Identifier

Einheitliches URN-Schema für alle Akteure. Es taucht im `sub`-Claim, in FGA-Tupeln und im Audit-Log identisch auf — damit ist jede Aktion über alle drei Systeme hinweg korrelierbar, ohne Mapping-Tabelle.

```
toob:human:<cell>:<orgId>:<userId>
toob:sa:<cell>:<orgId>:<serviceAccountId>
toob:workload:github:<owner>/<repo>:<workflow>
toob:workload:svc:<cell>:<serviceName>
toob:device:<cell>:<tenantId>:<deviceId>
toob:operator:<staffId>                      ← Toob-Support, zellübergreifend eindeutig
```

Bei Impersonation trägt das Token zusätzlich einen `act`-Claim (RFC 8693) mit der Operator-URN. Das Audit-Log schreibt beide: wer nominell handelte und wer tatsächlich. ▸ Ersetzt das heutige boolesche `is_impersonated`.

### 4.3 Trust-Level

Das L1/L2/L3-Modell bleibt konzeptionell, wird aber präzisiert:

| Level | Bedingung (aus `acr`/`amr`) | Semantik |
|---|---|---|
| **L1** | ein Faktor + nicht-phishing-resistenter zweiter Faktor (Passwort + TOTP) | nur aggregierte Lesezugriffe |
| **L2** | genau ein phishing-resistenter Faktor (Passkey/WebAuthn/FIDO2) | volle Lesezugriffe |
| **L3** | ≥ 2 **registrierte, phishing-resistente** Authenticator und Authentifizierung mit einem davon | Schreibzugriffe, privilegierte Operationen |

Korrekturen gegenüber heute:
- Die Menge der phishing-resistenten `amr`-Werte wird **einmal** definiert (heute doppelt: `federation` und `token`) und geteilt.
- `mfa` allein zählt nicht als phishing-resistenter Faktor. L3 erfordert zwei Faktoren aus der phishing-resistenten Menge.
- Ordnung wird über `func (t TrustLevel) Rank() int` ausgedrückt, nie über String-Vergleich.

Das permanente L3-Downgrade-Verbot (Account, der L3 erreicht hat, kann nie wieder per Passwort authentifizieren; Faktorabfall unter 2 ⇒ Suspendierung statt Rückstufung) bleibt und zieht in ein Actions-v2-Target um.

---

## 5. Mandanten- und Hierarchiemodell

### 5.1 Die Kette

```
Platform (Toob)
   └── Tenant                      Kunde: Gerätehersteller, Softwareanbieter
         ├── Marketplace           optional, 0..n je Tenant: eigener Update-Marktplatz
         │     └── EndCustomer     Endkunde des Marktplatzbetreibers, eigenes Nutzerprofil
         │           └── Device    Gerät des Endkunden
         ├── Namespace             Registry-Paketnamensraum
         ├── Channel               dev / beta / production, je Marketplace oder Tenant
         └── Device                Gerät direkt am Tenant (ohne Marktplatz)
```

Die Tiefe ist **nicht** auf diese vier Ebenen begrenzt. `parent`-Relationen sind rekursiv modelliert; eine fünfte Ebene (z. B. Distributor zwischen Marketplace und EndCustomer) ist ein Modell-Additiv, kein Umbau.

### 5.2 Abbildung auf Zitadel und OpenFGA

| Konzept | Zitadel | OpenFGA | Produkt-DB |
|---|---|---|---|
| Tenant | Organization (P1) / Instance (P2, P3) | `tenant:<id>` | `tenants.id` = Zitadel-Org-ID, RLS-Schlüssel |
| Marketplace | Sub-Organization oder Org mit Project Grant | `marketplace:<id>` | eigene Tabelle, `tenant_id` als RLS-Schlüssel |
| EndCustomer | User in der Marketplace-Org | `user:<urn>` + `end_customer:<id>` | Mirror |
| Rolle | grobe Projekt-Rolle im Token | Relation | — |
| Feingranulares Recht | — | abgeleitete Permission | — |

Zitadel kennt die Hierarchie nur zwei Ebenen tief (Org + Project Grant). **Die Hierarchielogik lebt vollständig in E2.** Zitadel liefert Identität und die grobe Org-Zugehörigkeit; wer wen verwalten darf, ergibt sich aus dem Relationsgraph.

▸ *Konsequenz:* Der heutige Mirror (`organizations`, `organization_members`) bleibt als Read-Model bestehen, verliert aber seine Rolle als Autorisierungsquelle. Er dient nur noch Anzeige und Joins.

### 5.3 Delegierte Administration

Der Marktplatzbetreiber verwaltet seine Endkunden selbst, ohne Toob-Beteiligung. Das ist keine Sonderlogik, sondern fällt aus dem Modell heraus: `manager` auf `end_customer` ist definiert als `operator from marketplace`. Wer Betreiber-Operator ist, verwaltet automatisch alle Endkunden dieses Marktplatzes — auch die, die es zum Zeitpunkt der Rechtevergabe noch nicht gab.

Genauso fällt der Plattform-Support heraus: `platform_support` ist über `parent`-Kette bis zur Wurzel sichtbar, aber ausschließlich auf Lese-Permissions gemappt und zusätzlich durch die Impersonation-Gates (§ 8.4) beschränkt.

---

## 6. Autorisierungsmodell (E2)

### 6.1 Modellskizze

Ausschnitt in OpenFGA-DSL. Vollständig ausformuliert gehört das Modell nach `policy/model/*.fga` und wird modular pro Domäne gepflegt (`core`, `registry`, `fleet`, `marketplace`).

```
model
  schema 1.1

type user
type service_account
type workload
type device
  relations
    define owner: [end_customer, marketplace, tenant]
    define fleet: [device_group]

type platform
  relations
    define staff:          [user]
    define support:        [user]
    define security_admin: [user]

type tenant
  relations
    define platform:  [platform]
    define owner:     [user]
    define admin:     [user] or owner
    define member:    [user, service_account] or admin
    # Permissions
    define can_manage_members: admin
    define can_view:           member or support from platform
    define can_manage_billing: owner

type marketplace
  relations
    define parent:    [tenant]
    define operator:  [user] or admin from parent
    define viewer:    [user] or member from parent
    define can_manage_end_customers: operator
    define can_publish:              operator
    define can_view:                 viewer or support from parent

type end_customer
  relations
    define marketplace: [marketplace]
    define self:        [user]
    define manager:     operator from marketplace
    define can_view:    self or manager
    define can_manage:  manager

type channel
  relations
    define parent:           [tenant, marketplace]
    define release_manager:  [user]
    define operator:         [user] or operator from parent
    define can_deploy:       operator
    define can_approve:      release_manager

type release
  relations
    define channel:      [channel]
    define author:       [user, workload]
    define can_approve:  can_approve from channel
    define can_view:     can_view from channel

type device_group
  relations
    define parent:            [tenant, marketplace, end_customer]
    define can_view_aggregate: can_view from parent
    define can_view_granular:  operator from parent
    define can_deploy:         can_deploy from parent
```

Zwei Modellierungsregeln, die eingehalten werden müssen:

1. **Arrows zeigen auf Permissions, nicht auf Relationen.** `can_view from parent`, nicht `viewer from parent`. Der umgekehrte Fall erzwingt Vollgraph-Traversierung und ist die häufigste Performance-Falle in Zanzibar-Modellen.
2. **Keine Rollennamen mit eingebautem Kontext.** Nie `acme_marketplace_operator`. Kontext kommt aus der `parent`-Kette, nicht aus dem Bezeichner. Andernfalls explodiert die Tupelmenge und das Modell verrottet.

### 6.2 Permission-Katalog

Permissions sind die **einzige** Schnittstelle zwischen Autorisierungsmodell und Applikationscode. Der Code kennt `perm.FleetDeviceReadGranular`, nie eine Rolle.

Jede Permission ist im Katalog (`policy/permissions.yaml`) definiert mit:

```yaml
- id: fleet.device.read_granular
  resource: device_group
  relation: can_view_granular
  min_trust_level: L2
  step_up: false
  sensitivity: confidential
  description: Lesen granularer Gerätedaten inkl. SBOM und Telemetrie-Einzelwerten
  audit: read

- id: fleet.release.approve
  resource: release
  relation: can_approve
  min_trust_level: L3
  step_up: true
  step_up_max_age: 300s
  sensitivity: critical
  description: Zweite Freigabe eines Releases (Vier-Augen-Prinzip)
  audit: critical
  requires_signature: true
```

Aus diesem Katalog wird generiert: Go-Konstanten, die Endpoint-Registry, die Stage-1-Gate-Konfiguration, das Audit-Klassifikationsmapping und die Doku.

### 6.3 Kontextabhängige Bedingungen

OpenFGA-Conditions (ABAC-Elemente auf Tupeln) werden **sparsam** eingesetzt — nur wenn die Bedingung *pro Tupel* variiert, nicht wenn sie pro Endpunkt gilt:

| Anwendungsfall | Umsetzung |
|---|---|
| Endpunkt verlangt L2 | **Stage-1-Gate** (lokal, kein FGA-Roundtrip) |
| Endpunkt verlangt frischen Step-Up | **Stage-1-Gate** |
| Befristeter Grant („Zugriff bis 2026-09-30") | **FGA-Condition** auf dem Tupel |
| Break-Glass-Grant mit Zeitfenster | **FGA-Condition** |
| Zugriff nur aus bestimmter Region | **FGA-Condition** |

Die Regel dahinter: Alles, was aus dem Token allein entscheidbar ist, wird lokal entschieden. FGA wird nur gefragt, wenn die Antwort vom Relationsgraph abhängt.

### 6.4 Zitadel-Rollen → FGA-Tupel

Grobe Rollen bleiben in Zitadel (sie gehören zur Identität und erscheinen im Token) und werden in FGA gespiegelt:

```
Zitadel: user U hat Rolle "admin" in Org O
   ──► FGA-Tupel:  user:<urn(U)>  admin  tenant:<O>
```

Die Spiegelung läuft über denselben Sync-Pfad wie der DB-Mirror (§ 9) — Event-getrieben mit periodischer Reconciliation. Alternativ können Rollen aus dem Token als **Contextual Tuples** bei jedem Check mitgegeben werden; das vermeidet den Sync für diese Klasse von Tupeln vollständig.

▸ **Empfehlung:** Contextual Tuples für Org-Rollen aus dem Token (kein Sync nötig, immer aktuell), persistierte Tupel für alles, was nicht im Token steht (Ressourcen-Beziehungen, Delegationen, befristete Grants). Das halbiert die Sync-Oberfläche und eliminiert die Drift-Klasse „Token sagt admin, FGA sagt member".

### 6.5 Modellversionierung und Rollout

- Das Modell liegt versioniert im Monorepo, ist die Quelle, und wird per CI in alle Stores geschrieben.
- OpenFGA hält mehrere Modellversionen pro Store; Checks können gegen eine explizite `authorization_model_id` laufen. Rollout ist damit atomar pro Store und rückrollbar.
- **Modelländerungen sind additiv.** Entfernen einer Relation erfordert einen zweistufigen Prozess (erst nicht mehr nutzen, dann entfernen).
- Modell-Tests (Tupel + erwartete Check-Ergebnisse) laufen in CI gegen jedes Modul, bevor ein Rollout startet.

---

## 7. Policy-Pipeline (P2)

Die Regelduplikation Go ↔ Zitadel-JS, die heute bereits divergiert ist, wird strukturell unmöglich gemacht.

### 7.1 Eine Quelle

```
policy/
  actors.yaml            Akteurstypen, Credential-Anforderungen
  permissions.yaml       Permission-Katalog (§ 6.2)
  rules/
    org_naming.yaml      Namensregeln (Länge, Zeichensatz, Reserved Names)
    invite.yaml          TTL, Single-Use, Initialrolle
    factor_policy.yaml   Dual-Authenticator, L3-Downgrade-Verbot
    elevation.yaml       Owner-Approval, Step-Up-Fenster
  model/*.fga            FGA-Modellmodule
  tests/                 Modell-Tests + Konformitäts-Fixtures
```

### 7.2 Generierte Ziele

```
policy/  ──codegen──►  gen/policy/policy.go        Konstanten, Endpoint-Registry, Gate-Config
                       gen/policy/rules.go         Validatoren (Org-Namen, Invites, …)
                       gen/zitadel/targets.json    Actions-v2-Target-/Execution-Konfiguration
                       gen/docs/permissions.md     Berechtigungsmatrix für Kunden-Doku
                       gen/policy/fixtures_test.go Konformitäts-Fixtures
```

Die Zitadel-Actions v1 (JavaScript, im Zitadel-Prozess ausgeführt) entfallen. Actions v2 ruft stattdessen **Go-Targets** auf — dieselben Validatoren, die auch im API-Pfad laufen. Damit ist die Regel physisch identisch, nicht nur „inhaltlich gleich gemeint".

▸ *Konsequenz für den Umbau:* Die 14 JS-Actions werden nicht portiert, sondern durch Targets ersetzt, die den generierten Validator aufrufen. Der einzige verbleibende JS-Anteil ist ggf. Zitadels eigenes Token-Claim-Mapping.

### 7.3 Vollständigkeitsprüfung zur Buildzeit

Heute schlägt ein Endpunkt ohne registrierte Policy erst zur **Laufzeit** mit HTTP 500 fehl. Im Zielzustand ist das ein **Build-Fehler**:

- Jeder Handler deklariert seine Permission als Annotation (Protobuf-Option bei Connect/gRPC, Struct-Tag oder Registrierung bei HTTP).
- Ein Generator liest die Routen-Definition und prüft gegen den Permission-Katalog.
- Fehlende, unbekannte oder mehrdeutige Deklaration ⇒ Compile-/CI-Fehler.
- Die Laufzeitprüfung bleibt zusätzlich bestehen (Defense in Depth), sollte aber nie feuern.

Zusätzlich: ein Konformitätstest, der für jede Permission mindestens einen positiven und einen negativen Testfall verlangt. Eine Permission ohne Negativtest ist eine unbewiesene Behauptung.

---

## 8. Enforcement im Request-Pfad (E3)

### 8.1 Zweistufige Autorisierung

```
Request
  │
  ├─ Stage 0  Transport           mTLS-Terminierung, Zell-Routing (Edge)
  │
  ├─ Stage 1  LOKAL, kein I/O, Ziel p99 < 200 µs
  │     1. Token verifizieren     Signatur, alg-Allowlist, iss/aud, exp/nbf
  │     2. DPoP prüfen            Signatur, htm/htu, jti-Replay, Nonce   (§ 10.3)
  │     3. Principal bauen        Subject-URN, Org, TrustLevel, act-Claim
  │     4. Tenant-Match           claims.OrgID == Ziel-Tenant der Route
  │     5. Endpoint-Gate          min_trust_level, step_up, Impersonations-Regel
  │     6. Kill-Switch            Revocation-Cache aus CAEP-Signalen (§ 10.5)
  │        └─ jeder Fehlschlag ⇒ Abbruch ohne FGA-Roundtrip
  │
  ├─ Stage 2  RELATION, 1 Netzwerk-Hop in der Zelle, Ziel p95 < 10 ms
  │     Check / BatchCheck / ListObjects gegen FGA
  │     Decision-Cache (kurz-TTL) für idempotente Lesepfade
  │
  ├─ Stage 3  Datenzugriff
  │     SET LOCAL app.tenant_id  (aus verifizierten Claims)
  │     Query unter RLS
  │
  └─ Stage 4  Audit
        asynchron über Outbox, blockiert den Request nicht
```

Stage 1 fängt alles ab, was aus dem Token allein entscheidbar ist — und das ist die überwiegende Mehrheit aller abgelehnten Requests. Nur Anfragen, die diese Hürde nehmen, kosten einen Netzwerk-Hop.

### 8.2 Listen-Endpunkte

N Einzelchecks für eine Liste sind das Standard-Antipattern. Zwei Muster:

- **`ListObjects`** wenn die Liste aus der Autorisierung entsteht („zeige mir alle Geräte, die ich sehen darf") — FGA liefert die erlaubten IDs, die Query filtert darauf.
- **`BatchCheck`** wenn die Liste aus einer Query entsteht und gefiltert werden muss — ein Roundtrip für n Objekte.

Für sehr große Mengen: Vorfilterung über RLS + `BatchCheck` nur auf der Seite. Volle `ListObjects`-Ergebnisse werden nie ungepaged verwendet.

### 8.3 Caching und Konsistenz

| Ebene | TTL | Invalidierung |
|---|---|---|
| JWKS-Keys | bis Refresh (15 min) + Offline-Fallback | Hintergrund-Sync, ratenbegrenzter Miss-Refresh |
| Tenant→Cell-Routing | 5 min | TTL |
| Decision-Cache (Lesepfade) | ≤ 30 s | TTL + gezielte Invalidierung bei Tupel-Writes |
| Schreib-/kritische Pfade | **kein Cache** | Check mit erhöhter Konsistenz |

Erhöhte Konsistenz (Bypass des FGA-internen Caches) wird **gezielt** für sicherheitskritische Checks gesetzt, nie als Default — das kostet messbar Latenz. Kandidaten: Release-Freigabe, Geräte-Deployment, Rechteänderungen, Impersonation.

### 8.4 Impersonation

Präzisierung gegenüber heute, wo jede Impersonation pauschal jeden policy-geschützten Endpunkt blockiert (und damit auch die Lesezugriffe, für die sie gedacht ist):

| Permission-Klasse | Impersonierte Session |
|---|---|
| `sensitivity: public` / `internal`, `audit: read` | **erlaubt** |
| `sensitivity: confidential` | erlaubt, wenn `granular` nicht gesetzt |
| `step_up: true` oder `sensitivity: critical` | **verboten** |
| jede Mutation (`audit: write`/`critical`) | **verboten** |

Die Regel wird aus dem Permission-Katalog generiert, nicht im Middleware-Code kodiert. Impersonation erzeugt zusätzlich ein `act`-Claim, einen Audit-Eintrag beim Start und eine Benachrichtigung an alle Org-Owner.

---

## 9. Identitäts-Synchronisation & Provisioning

### 9.1 Drei Betriebsmodelle für Endkunden-Identitäten

Das vom Nutzer skizzierte Szenario („Kunde nutzt uns als Nutzer-DB" vs. „Kunde synchronisiert sein Backend") wird als drei explizite, konfigurierbare Modi umgesetzt — pro Marketplace wählbar:

| Modus | Wer ist Master | Mechanik | Typischer Kunde |
|---|---|---|---|
| **M1 — Managed** | Toob | Endkunden registrieren sich bei uns, Marktplatzbetreiber verwaltet sie über delegierte Rechte | kleiner Betreiber ohne eigenes Backend |
| **M2 — Federated** | Kunden-IdP | OIDC-Federation pro Marketplace, JIT-Provisioning beim ersten Login | Betreiber mit eigenem IdP |
| **M3 — Synchronized** | Kunden-Backend | SCIM 2.0 inbound (Kunde pusht) + signierte Outbound-Events (wir pushen zurück) | Betreiber mit eigener Nutzer-DB |

M2 ist die günstigste Variante und sollte der empfohlene Default für Betreiber mit eigenem System sein. **SCIM (M3) wird erst nötig, wenn Deprovisioning zeitnah garantiert sein muss** — ein Nutzer, der im Kundensystem gelöscht wird, muss bei uns den Zugang verlieren, ohne auf den nächsten Login-Versuch zu warten.

### 9.2 Inbound: SCIM 2.0

Zitadel stellt einen SCIM-Service-Provider-Endpunkt bereit. Kritische Implementierungsregeln:

- **Idempotenz auf `externalId` und E-Mail.** `POST /Users` bei IdP-Retry darf keinen zweiten Account erzeugen. Das ist die häufigste SCIM-Falle und produziert Duplikate, die später kaum zu bereinigen sind.
- **Gruppen → FGA-Tupel**, nicht → Produkt-DB-Rollen.
- **Deprovisioning ist Pflichtpfad**, nicht Nice-to-have: `active: false` ⇒ Session-Revocation + CAEP-Signal + Tupel-Entzug.

### 9.3 Outbound: Outbox statt Webhook-Direktversand

Der heutige Pfad (HMAC-Webhooks + 15-Minuten-Reconciler) garantiert weder Zustellung noch Reihenfolge. Zielzustand:

```
Zustandsänderung  ──(dieselbe TX)──►  outbox-Tabelle
                                          │
                        identity-sync (eigener Prozess)
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
             FGA-Tupel-Update      Produkt-DB-Mirror     Kunden-Webhook
                                                        (signiert, retry, DLQ)
```

Eigenschaften:
- **Transaktionale Outbox:** Event und Zustandsänderung committen gemeinsam. Kein „geschrieben, aber nicht gemeldet".
- **Ordering pro Aggregat** (Tenant/Org), nicht global.
- **Idempotenzschlüssel** je Event; Empfänger dedupliziert.
- **Retry mit exponentiellem Backoff + Dead-Letter-Queue**, DLQ-Tiefe ist ein Alarm.
- **Signatur nach einem etablierten Webhook-Signaturschema** (Timestamp + HMAC über kanonisierten Body, Replay-Fenster), damit Kunden Standard-Bibliotheken nutzen können.
- **Reconciler bleibt** als Sicherheitsnetz, aber mit klarer Trennung: Fehler ≠ Drift (heute wird beides gleich behandelt und verfälscht die Metrik), und Soll/Ist als Mengenvergleich inklusive Entfernung überzähliger lokaler Einträge.

### 9.4 Was NICHT synchronisiert wird

Credentials. Niemals. Weder Passwörter noch Passkey-Material verlassen den IdP oder werden in einen Kunden-Backend-Sync einbezogen. M3 synchronisiert Profildaten, Gruppen und Statusflags — nicht Authentifizierungsmittel.

---

## 10. Token-, Session- und Credential-Architektur

### 10.1 Credential-Matrix

| Akteur / Kanal | Flow | Access | Refresh | Bindung |
|---|---|---|---|---|
| **Web-UI (Mensch)** | OIDC AuthCode + PKCE, **BFF** | serverseitig | serverseitig, rotierend | `__Host-`-Cookie, SameSite |
| **CLI (Mensch)** | Device Authorization Grant | 15 min | 8 h, rotierend | **DPoP** |
| **CI/CD** | OIDC → Token Exchange (RFC 8693) | ≤ 10 min | — | Repo/Ref/Workflow-Claims |
| **Service Account** | Private-Key-JWT | 15 min | — | Key in Vault |
| **Interner Service** | mTLS | ≤ 1 h | — | SPIFFE-artige SAN-URI |
| **Gerät** | mTLS | 30–90 d Zertifikat | Auto-Rotation | Hardware-Root-of-Trust |
| **Support (Impersonation)** | Token Exchange mit `actor_token` | ≤ 4 h | — | `act`-Claim, auditiert |

### 10.2 BFF statt Tokens im Browser

Für die Web-UI werden Tokens **nicht** an den Browser ausgeliefert. Ein Backend-for-Frontend hält sie, der Browser bekommt ein Session-Cookie. Begründung: Refresh-Token-Rotation schützt nicht gegen bösartiges JavaScript im selben Origin — der Angreifer liest den Refresh im selben Moment mit, in dem die Anwendung ihn nutzt. Das ist der aktuelle Konsens der OAuth-Best-Current-Practice für Browser-Apps.

### 10.3 DPoP korrekt

Die heutige Implementierung parst den Proof, prüft aber die Signatur nicht — damit ist die Besitzgarantie, wegen der man DPoP überhaupt einsetzt, nicht vorhanden. Zielzustand umfasst vollständig:

1. Signaturprüfung gegen das im Header eingebettete JWK
2. Thumbprint nach RFC 7638 über die **kanonische** JSON-Repräsentation (sortierte Pflichtfelder, keine Whitespaces) — nicht über die rohen empfangenen Bytes
3. `htm`/`htu` exakt, kein Suffix-Fallback
4. `iat`-Fenster **plus** `jti`-Replay-Cache über die Fensterlänge
5. Server-Nonce (`DPoP-Nonce`) für sensible Endpunkte
6. Bindung `jkt` ↔ Access Token

### 10.4 Keine langlebigen Personal Access Tokens

PATs sind die häufigste Ursache für Supply-Chain-Kompromittierungen in Registries. Der Default ist: **es gibt sie nicht.**

- Menschen am CLI: Device Authorization Grant, kurzlebig, DPoP-gebunden.
- CI: OIDC-Federation („Trusted Publishing"-Muster) statt gespeicherter Tokens.
- Wenn ein Token trotzdem unvermeidlich ist: org-gebunden, permission-granular (nicht „alle Rechte des Nutzers"), Pflicht-Ablaufdatum ≤ 90 Tage, DPoP-gebunden, sichtbar in einer Tokenübersicht mit Last-Used.

### 10.5 Sofortige Revocation

JWTs sind bis zum Ablauf gültig — das ist bei 15-Minuten-Lebensdauer meist akzeptabel, bei einer kompromittierten Session oder einem entwendeten Gerät nicht. Deshalb:

- **Kill-Switch-Cache in Stage 1:** eine kompakte, in allen Prozessen replizierte Menge widerrufener Subjekte/Sessions/Geräte (Redis-Pub/Sub + lokaler Cache), geprüft ohne Netzwerk-Roundtrip im heißen Pfad.
- **Gespeist aus CAEP-artigen Ereignissen:** `session-revoked`, `credential-change`, `device-compliance-change`, SCIM-`active:false`.
- **Ausgehend ebenfalls:** Kunden mit eigenem IdP können unsere Signale abonnieren und umgekehrt.

Ziel-Latenz vom Auslöser bis zur Wirksamkeit: < 5 Sekunden zellweit.

---

## 11. Datenarchitektur und Isolation

### 11.1 Datenbanken pro Zelle

| DB | Inhalt | Isolation |
|---|---|---|
| **Zitadel-DB** | Identitäten, Credentials, Eventstore | eigene Instanz, `verify-full`, eigener Backup-Bucket |
| **FGA-DB** | Relationstupel, Modelle | eigene Instanz oder eigenes Schema, Store pro Tenant |
| **Produkt-DB** | Business-Daten, Mirror | RLS pro Tenant |
| **Audit-DB** | Hash-Chain-Log | append-only, eigene Rolle, kein DELETE/UPDATE-Recht |

### 11.2 RLS gehärtet

Die heutige Umsetzung (RLS nur auf `tenants`, ohne `FORCE`, ohne `WITH CHECK`) wird ersetzt durch:

```sql
ALTER TABLE <t> ENABLE  ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE   ROW LEVEL SECURITY;   -- gilt auch für den Owner

CREATE POLICY tenant_isolation ON <t>
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));
```

Ergänzend verbindlich:

- **Separate Applikationsrolle ohne Tabellen-Ownership.** Migrationen laufen unter einer anderen Rolle.
- **`SET LOCAL` ausschließlich innerhalb einer Transaktion.** Bei PgBouncer im Transaction-Mode ist ein session-weites `SET` ein Tenant-Leak an die nächste Connection — das ist die klassische Falle und muss durch Lint/Test abgesichert sein.
- **Composite-Indizes mit `tenant_id` an erster Stelle.** Ohne sie zwingt RLS den Planer zu Sequential Scans; mit ihnen liegt der Overhead im niedrigen einstelligen Prozentbereich.
- **Isolationstests als Pflichtbestandteil jeder Tabelle:** Lesen fremder Zeilen schlägt fehl, Schreiben in fremde Zeilen schlägt fehl, und die Gegenprobe (eigene Zeilen sind sichtbar) ist ebenfalls Teil des Tests.

### 11.3 Verhältnis RLS ↔ FGA

Beide Schichten prüfen Verschiedenes und ersetzen sich nicht:

- **RLS** ist die grobe, unumgehbare Mandantengrenze: „Diese Zeile gehört einem anderen Tenant."
- **FGA** ist die feine Ressourcen-Entscheidung: „Diese Zeile gehört deinem Tenant, aber du darfst sie nicht sehen."

RLS ist der Backstop, der auch dann hält, wenn im Applikationscode ein Check vergessen wurde. Deshalb bleibt es aktiv, auch wenn FGA jede Entscheidung ohnehin trifft.

---

## 12. Release-Governance und Supply Chain

### 12.1 Vier-Augen-Prinzip kryptografisch

Das heutige Modell (zwei Namen in einer Tabelle, Soak-Window als Zeitstempel, HMAC-Proof mit geteiltem Secret) wird auf Signaturen umgestellt:

```
Approver A ─┐
            ├─► 2-of-N Signaturen über ein kanonisches Release-Statement
Approver B ─┘   { release_id, artifact_digest, channel, timestamp, approver_urn }
                     │
                     ├─ Schlüssel: personengebunden (PIV/YubiKey) oder Vault Transit
                     │             pro Person, nie pro Rolle
                     ▼
              Attestation-Bundle (in-toto-Format)
                     │
                     │  ── Soak-Window läuft ──  Abbruch ⇒ kein nächster Schritt
                     ▼
              Uptane-Signatur (Targets/Director)  ⇒ erst jetzt auslieferbar
```

Die entscheidende Eigenschaft: **Das Soak-Window ist kryptografisch durchgesetzt, nicht durch ein Boolean.** Bytes werden erst auslieferbar, wenn die Uptane-Signatur existiert, und die entsteht erst nach Ablauf. Ein Datenbank-Update kann das nicht umgehen.

**Rolle ≠ Fähigkeit:** Die FGA-Relation `can_approve` berechtigt, eine Signatur beizusteuern. Der Schlüsselbesitz (Hardware-Token) ermöglicht sie. Beides ist nötig; keines allein reicht. Damit ist ein kompromittierter Datenbankzugriff wertlos für Release-Freigaben.

### 12.2 Uptane-Rollen-Mapping

| Uptane/TUF-Rolle | Schlüsselverwahrung | Toob-Rolle |
|---|---|---|
| Root | offline, HSM, m-of-n | Security-Admin (Plattform) |
| Targets | HSM / Vault Transit | Release-Manager des Tenants (2-of-N) |
| Snapshot / Timestamp | online, automatisiert | Release-Pipeline (Workload) |
| Director | online, pro Zelle | Fleet-Service |

### 12.3 CI-Grenze bleibt unbedingt

Machine-Workloads (GitHub Actions) können bauen, signieren (Provenance) und nach `dev`/`beta` publizieren. Die Promotion nach `production` ist unbedingt verboten — unabhängig von Rollen, Claims oder Konfiguration. Diese Regel ist kein Policy-Eintrag, sondern eine Invariante im Freigabepfad: Ein `workload`-Subjekt kann in FGA die Relation `can_approve` gar nicht erhalten (Typ-Constraint im Modell: `can_approve` akzeptiert nur `[user]`).

▸ Das ist ein Beispiel dafür, wie eine Sicherheitsregel vom Laufzeit-Check ins **Typsystem** wandert und damit nicht mehr durch Fehlkonfiguration umgehbar ist.

---

## 13. Device- und Workload-Identität (E4)

### 13.1 PKI-Hierarchie

```
Toob Root CA                       offline, HSM, sehr lange Laufzeit
 └── Cell Intermediate CA          pro Zelle, Vault PKI
      ├── Device Issuing CA        pro Tenant
      │    ├── Bootstrap-Zertifikat   werksseitig, nur für Onboarding gültig
      │    └── Operatives Zertifikat  30–90 d, automatische Rotation
      └── Workload Issuing CA      kurzlebig (≤ 1 h), interne Services
```

### 13.2 Identität und Onboarding

- **SAN-URI als einheitlicher Identifier:** `spiffe://<cell>/tenant/<t>/device/<id>` — Geräte und Workloads teilen sich einen Namensraum und damit dieselbe Verifikationslogik.
- **Verankerung im Hardware-Root-of-Trust** (Secure Element, eFuse, DICE), wo die Zielhardware es hergibt. Der bestehende `efuse`-Layer im Chip-Paket ist der Ansatzpunkt.
- **Zero-Touch-Onboarding:** werksseitig eingebranntes Bootstrap-Zertifikat, das beim ersten Kontakt gegen ein operatives Zertifikat der Tenant-CA getauscht wird und danach ungültig ist.
- **Rotation vor Ablauf**, automatisch, ohne Nutzerinteraktion, mit Überlappungsfenster.
- **Revocation ohne CRL:** Constrained Devices holen keine Sperrlisten. Stattdessen kurze Laufzeiten + serverseitige Sperrung (Kill-Switch-Cache, § 10.5). Ein gesperrtes Gerät wird an der Gegenstelle abgewiesen, nicht durch eigene Einsicht.

### 13.3 Geräte in FGA, nicht in Zitadel

Geräte erscheinen als `device:<urn>` im Relationsgraph (für Besitz- und Zugriffsbeziehungen), aber **nicht** als Nutzer im IdP. Begründung: Millionen kurzlebiger Maschinen-Identitäten sprengen ein CIAM-Modell, das für Login-Flows, MFA-Recovery und Session-Management optimiert ist — und vermischen zwei völlig verschiedene Bedrohungsmodelle.

---

## 14. Ausfall- und Degradationsverhalten

Jeder Ausfallmodus ist eine bewusste Entscheidung, keine Emergenz. Diese Tabelle ist normativ.

| Ausfall | Lesen | Schreiben | Neue Sessions | Begründung |
|---|---|---|---|---|
| **Zitadel nicht erreichbar** | ✅ (JWKS-Cache) | ✅ | ❌ | Laufende Rollouts dürfen nicht an einem IdP-Ausfall sterben |
| **JWKS-Key unbekannt** | ❌ für dieses Token | ❌ | — | Fail-closed, fail-fast, kein Blocking-Retry |
| **OpenFGA nicht erreichbar** | ⚠️ Decision-Cache ≤ 30 s, danach ❌ | ❌ **fail-closed** | ✅ | Kein Schreibvorgang ohne frische Entscheidung |
| **FGA-Store fehlt / Modell inkonsistent** | ❌ | ❌ | ✅ | Konfigurationsfehler ⇒ lauter Ausfall statt stiller Lücke |
| **Redis/Valkey weg** | ✅ | ✅ | ✅ | Rate-Limit degradiert (fail-open, ist Komfort); Sessions & Kill-Switch fallen auf Postgres zurück |
| **Postgres (Produkt) weg** | ❌ | ❌ | ✅ | — |
| **Vault Transit / HSM weg** | ✅ | ⚠️ ohne Signaturvorgänge | ✅ | Keine Freigaben, keine Zertifikatsausstellung; laufende Rollouts unberührt |
| **Tenant Directory weg** | ✅ (Routing-Cache) | ✅ | ✅ | Kein Tenant-Onboarding, kein Zellwechsel |
| **Audit-Pipeline weg** | ✅ | ⚠️ **nur für `audit: critical` blockierend** | ✅ | Kritische Aktionen ohne Nachweis sind nicht zulässig; normale Schreibvorgänge puffern in der Outbox |

Die letzte Zeile ist bewusst unbequem: Wenn die Freigabekette nicht protokolliert werden kann, darf keine Freigabe stattfinden. Das ist die Konsequenz aus regulatorischer Nachweispflicht — ein Release ohne Audit-Eintrag ist ein Release, den man später nicht verteidigen kann.

---

## 15. Audit, Nachweisbarkeit und Compliance

### 15.1 Manipulationsevidenter Audit-Log

```
entry_n:  { seq, timestamp, tenant, actor_urn, act_urn?, permission,
            resource_urn, decision, context_hash }
hash_n  = H( hash_{n-1} || canonical_json(entry_n) )

alle N Einträge oder alle 5 Minuten:
checkpoint = Sign_VaultTransit( { seq, hash_n, timestamp } )
```

- Eine Kette **pro Tenant** (in isolierten Zellen zusätzlich pro Zelle).
- Append-only auf DB-Ebene: die schreibende Rolle hat kein `UPDATE`/`DELETE`.
- Checkpoints sind extern publizierbar — ein Kunde kann verifizieren, dass sein Log nachträglich nicht verändert wurde, ohne uns vertrauen zu müssen.
- Ein voller Transparency-Log (Merkle-Tree mit Inklusionsbeweisen) ist die Ausbaustufe, nicht der Startpunkt (§ 17).

### 15.2 Was protokolliert werden muss

| Klasse | Beispiele | Aufbewahrung |
|---|---|---|
| `critical` | Release-Freigabe, Rollenerhöhung, Break-Glass, Impersonation-Start, Schlüsseloperation | ≥ Support-Periode des Produkts |
| `write` | Mutationen an Tenants, Geräten, Kanälen, Paketen | 24 Monate |
| `read` | granulare Datenzugriffe (nicht aggregierte) | 12 Monate |
| `authn` | Login, MFA-Änderung, Faktorregistrierung | 24 Monate |

Der Audit-Eintrag enthält immer beide Identitäten bei Impersonation (`actor_urn` = nominell, `act_urn` = tatsächlich) und den Permission-Identifier aus dem Katalog — nicht eine freitextliche Aktionsbeschreibung.

### 15.3 Regulatorischer Rahmen

Für eine OTA-Plattform mit EU-Kunden sind die relevanten Nachweise: signierte Updates, SBOM je Release, dokumentierte Freigabekette mit Personenbezug, Melde- und Reaktionsfähigkeit bei Schwachstellen, sowie Sicherheitsupdates über die deklarierte Support-Periode. Der Identity-Service liefert davon die **Freigabekette und die Zugriffs-Nachweise**; SBOM und Update-Signatur liegen in der Registry- bzw. Release-Pipeline.

Die konkreten Fristen und Meldepflichten (Cyber Resilience Act) sind terminlich relevant und sollten im Backlog als eigener, datumsgebundener Track geführt werden — nicht als Querschnittsaufgabe, die dann niemand besitzt.

---

## 16. Modul- und Repositorystruktur (Zielzustand)

Dieser Abschnitt ist die Vorlage für die spätere Umbauplanung.

```
policy/                       Single Source (§ 7.1)
gen/                          generiert, read-only, im Repo eingecheckt

identity/
  principal/       Principal, Subject-URN, TrustLevel, Context-Keys   ← unterste Schicht, keine Deps
  token/           JWT-Verifikation → Principal
  jwks/            Key-Cache, Offline-Fallback
  dpop/            vollständige RFC-9449-Implementierung
  enforce/         Stage-1-Gates: Tenant, TrustLevel, Step-Up, Impersonation, Kill-Switch
  authz/           FGA-Client, Batch/ListObjects, Decision-Cache, Interceptors
  session/         Store-Interface + Postgres/Redis-Implementierung
  federation/      Workload-OIDC, Customer-IdP-AMR
  celldir/         Tenant→Cell-Routing-Client

services/
  identity-sync/   Outbox-Consumer, Reconciler, SCIM-Bridge, Outbound-Events
  authz-proxy/     optional: Sidecar-Modus für Nicht-Go-Konsumenten

platform/deploy/
  terraform/cells/ Zell-Provisionierung als wiederverwendbares Modul
```

### 16.1 Abhängigkeitsregel

```
principal  ◄── token, enforce, authz, session, federation, celldir
token      ◄── enforce, authz
enforce    ◄── (nur Interceptor-Verdrahtung)
authz      ◄── (nur Interceptor-Verdrahtung)

VERBOTEN:  irgendein Package ──► middleware/HTTP-Transport
VERBOTEN:  identity/* ──► services/*
```

Der heutige Import `tenant → middleware` (nur wegen eines Context-Keys) entfällt, weil `principal` die Schlüssel besitzt. Die Regel wird durch den bestehenden `boundaries_test.go`-Mechanismus erzwungen und um die neuen Packages erweitert.

### 16.2 Was verschwindet

| Heute | Zielzustand |
|---|---|
| `identity/roles` (Rollenkonstanten + Prädikate) | ersetzt durch Permission-Katalog + FGA-Modell |
| `identity/middleware/fleet_security.go` | ersetzt durch generierte Interceptors + `enforce` |
| `identity/orgs` (SAGA im API-Prozess) | wandert nach `services/identity-sync` mit persistierter SAGA |
| `identity/approval` (In-Memory-Engine) | ersetzt durch Signatur-Workflow (§ 12.1) mit persistiertem Zustand |
| `identity/impersonation` (In-Memory) | Token Exchange + `act`-Claim, Zustand in Zitadel/Postgres |
| `identity/ratelimit` (In-Memory) | Redis-basiert, in `enforce` |
| 14 Zitadel-JS-Actions | Actions-v2-Targets auf generierte Go-Validatoren |
| `identity/mirror` (Webhook + Reconciler) | `services/identity-sync` mit Outbox/CDC |

---

## 17. Erweiterungsszenarien

Der Härtetest jeder Architektur: Was ändert sich, wenn sich die Anforderung ändert? Sechs Szenarien, jeweils mit der Frage „Code oder Konfiguration?".

| # | Szenario | Was sich ändert | Code-Deploy nötig? |
|---|---|---|---|
| **1** | Neue Rolle im bestehenden Typ (z. B. `security-auditor`) | `permissions.yaml` + `*.fga` + Tupel | **nein** (Modell-Rollout) |
| **2** | Neuer Akteurstyp: Endkunde des Marktplatzbetreibers | neuer FGA-Typ + Zitadel-Org-Struktur + SCIM-Mapping | **nein** für bestehende Endpunkte |
| **3** | Betreiber will eigenes Branding + Login-Domain | Profil-Upgrade P1→P2 innerhalb der Zelle | nein |
| **4** | Enterprise verlangt Datenresidenz / Air-Gap | neue Zelle per Terraform-Modul, Directory-Eintrag, Export/Import | nein |
| **5** | Kunde macht sein Backend zum Master der Endkunden | Modus M1→M3, SCIM inbound + Outbound-Events aktivieren | nein |
| **6** | Fünfte Hierarchieebene (Distributor) | neuer Typ mit `parent`-Relation, Permissions erben | **nein** |

Ein neuer **Endpunkt** braucht selbstverständlich Code. Ein neuer **Akteur, eine neue Rolle oder eine neue Hierarchieebene** nicht — das ist die eigentliche Antwort auf die Ausgangsfrage.

### 17.1 Konkret: der Marktplatz-Fall

Ein Kunde („Acme") will einen eigenen Update-Marktplatz betreiben, dessen Endkunden eigene Profile bekommen.

```
1. Tenant acme existiert bereits              (Zitadel-Org + FGA-Store)
2. Marketplace anlegen                        marketplace:acme-store, parent → tenant:acme
3. Betreiber-Operator benennen                user:alice  operator  marketplace:acme-store
   ⇒ Alice verwaltet ab sofort alle Endkunden, auch künftige
4. Identitätsmodus wählen                     M1 managed | M2 federated | M3 SCIM
5. Endkunde registriert sich / wird provisioniert
   ⇒ user:bob  self  end_customer:bob@acme-store
6. Gerät zuordnen                             device:xyz  owner  end_customer:bob@acme-store
7. Kanal & Freigaben                          channel:acme-store/production, parent → marketplace
```

Alles davon sind Tupel und Konfiguration. Kein Service wird neu deployt, kein Endpunkt geändert, kein `if customer_type == …` geschrieben.

---

## 18. Verortung der bestehenden Requirements

Damit der Migrationsplan weiß, wohin jede heutige Anforderung wandert.

| Req | Heute | Zielzustand |
|---|---|---|
| AUTH-013 | `middleware/auth.go` | `enforce` Stage 1, generierter Interceptor |
| AUTH-014 | `mirror.Reconciler` | `services/identity-sync`, Outbox + Reconciler v2 |
| AUTH-020 | `roles.go` + Provisioning-Skript | Permission-Katalog + FGA-Modell; Zitadel-Rollen nur noch grob |
| AUTH-021 | `serviceaccount` Pfad-Denylist | unverändert im Prinzip, Konfiguration aus `policy/` generiert |
| AUTH-022/023 | `orgs` SAGA in-process | `identity-sync`, persistierte SAGA inkl. FGA-Store-Provisionierung |
| AUTH-024 | `RequireOrgMatch` | `enforce` Stage 1, Schritt 4 |
| AUTH-031/035/036 | Migrationen 033–035 | unverändert; Mirror verliert Autorisierungsrolle |
| AUTH-040 | `tenant.SetTenantContext` | unverändert, RLS gehärtet (§ 11.2) |
| AUTH-041 | `FleetPolicyRegistry` | generierte Endpoint-Registry, Vollständigkeit zur Buildzeit |
| AUTH-042 | TrustLevel × DataVisibility | Permission-Katalog (`min_trust_level`, `sensitivity`) |
| AUTH-043 | `RequireStepUp` | Stage-1-Gate aus Katalog; RFC-9470-konforme Challenge |
| AUTH-050 | JWKS-Offline-Fallback | unverändert übernommen (§ 2.3) |
| AUTH-051 | `EnforceTenantBoundary` | Stage 1 + RLS `WITH CHECK` |
| AUTH-052 | `MirrorMonitor` | SLO-Metriken in `identity-sync`, Monitor nicht mehr global |
| AUTH-053 | Impersonations-Block | differenziert nach Permission-Klasse (§ 8.4) |
| AUTH-090 | Workflow-Claim-Prüfung | `federation`, unverändert |
| IDP-001/002 | Vault-Agent, dedizierte DB | unverändert, pro Zelle |
| IDP-004/005/010 | Instance Policies | pro Zitadel-Instanz; bei P2/P3 kundenspezifisch |
| IDP-011/011c/012 | 4 JS-Actions | Actions-v2-Targets auf generierte Validatoren |
| IDP-013 | `middleware/trust.go` | Stage-1-Gate, `Rank()`-basiert |
| IDP-014 | `session` in-memory | `session` mit Postgres/Redis-Store |
| IDP-015 | `dpop` unvollständig | vollständige RFC-9449-Implementierung (§ 10.3) |
| IDP-020/021/022 | JS-Actions | Actions-v2-Targets |
| IDP-030/031/032/033 | Provisioning + JS-Actions | `policy/rules/*` → generiert nach Go und Actions v2 |
| IDP-034 | Sync-Lag-Alarm | SLO in `identity-sync` |
| IDP-040…043 | `approval` in-memory + HMAC | Signatur-Workflow, Uptane-gekoppelt (§ 12.1) |
| IDP-050/052/053 | `federation` | unverändert; CI-Produktionssperre wandert ins FGA-Typsystem |
| IDP-060/061 | `impersonation` in-memory | Token Exchange, `act`-Claim, persistierter Zustand |
| IDP-073 | `ratelimit` in-memory | Redis-basiert |
| — | *neu* | Zellmodell, Tenant Directory, Device-PKI, Audit-Hash-Chain, CAEP/Kill-Switch |

---

## 19. Architekturentscheidungen

Kurzform: Entscheidung / Kontext / Alternativen / Konsequenz.

| # | Entscheidung | Kontext | Alternativen | Konsequenz |
|---|---|---|---|---|
| **A1** | ReBAC-Engine (OpenFGA) neben Zitadel | tiefes B2B2C, delegierte Administration | nur Zitadel-Rollen; ABAC/Policy-Engine; SpiceDB | zusätzlicher Dienst + Tupel-Sync; dafür Hierarchie ohne Codeänderung |
| **A2** | Zitadel = AuthN + grobe Rollen, nicht Fine-Grained-Authz | Zitadel-Orgs sind flach | Hierarchie in Zitadel nachbauen | klare Grenze; Zitadel-Rollen werden gespiegelt oder als Contextual Tuples übergeben |
| **A3** | Zellmodell mit drei Profilen | Enterprise-Isolationsbedarf ohne zweite Codebasis | pro Kunde eigener Cluster; alles shared | Zell-Provisionierung als Terraform-Modul; kein Cross-Cell-Datenpfad |
| **A4** | FGA-Store pro Tenant | Isolation, Löschbarkeit, Modellvarianten | ein globaler Store | Rollout über n Stores muss automatisiert sein |
| **A5** | Zweistufige Autorisierung (lokal → FGA) | Latenzbudget, Robustheit | jeder Check gegen FGA | Stage 1 ohne I/O fängt die Mehrheit ab |
| **A6** | Zitadel-Rollen als Contextual Tuples | Sync-Drift vermeiden | alles persistiert spiegeln | halbierte Sync-Oberfläche; Token wird etwas größer |
| **A7** | Geräte nicht im IdP | anderes Bedrohungsmodell, andere Skala | Machine-Users in Zitadel | eigene PKI-Ebene, eigener Lifecycle |
| **A8** | BFF für Web, DPoP für CLI | XSS-Realität, Token-Diebstahl | SPA mit Tokens im Browser | BFF-Komponente nötig; DPoP muss vollständig sein |
| **A9** | Keine langlebigen PATs | häufigste Supply-Chain-Ursache | PATs wie GitHub | Device Flow + OIDC-Federation als Ersatz, DX-Aufwand |
| **A10** | Eine generierte Policy-Quelle | bestehende Divergenz Go↔JS | Status quo; nur Konformitätstests | Codegen-Pipeline, Buildzeit-Vollständigkeitsprüfung |
| **A11** | Actions v1 (JS) → Actions v2 (Go-Targets) | JS schwer testbar, Divergenzquelle | JS beibehalten | Netzwerk-Hop im Login-Pfad; dafür identische Regel |
| **A12** | Outbox/CDC statt Direkt-Webhooks | keine Zustell-/Reihenfolgegarantie | Webhooks + Reconciler | eigener Sync-Prozess, DLQ-Betrieb |
| **A13** | Vier-Augen als 2-of-N-Signatur | DB-Flag ist umgehbar, nicht nachweisbar | HMAC-Proof wie heute | Hardware-Token-Beschaffung; dafür CRA-tauglicher Nachweis |
| **A14** | Soak-Window kryptografisch (Uptane-Signatur danach) | Zeitstempel ist manipulierbar | Boolean + Timer | Kopplung an Release-Pipeline |
| **A15** | CI kann `can_approve` typseitig nicht erhalten | Fehlkonfiguration soll unmöglich sein | Laufzeitprüfung wie heute | Regel wandert ins Typsystem |
| **A16** | Audit als Hash-Chain in Postgres, Checkpoints signiert | Nachweispflicht, kleines Team | Trillian/Transparency-Log; nur normales Logging | ausbaubar zu vollem Transparency-Log |
| **A17** | Ausfallverhalten normativ tabelliert | Degradation soll entschieden sein | implizites Verhalten | § 14 ist Teil des Akzeptanzkriteriums jedes Dienstes |
| **A18** | Zellwechsel offline, nicht live | Komplexität vs. Nutzen | Live-Migration zwischen Zellen | Wartungsfenster akzeptiert |

---

## 20. Bewusst nicht

- **Kein eigenes Zanzibar.** Die Unternehmen, die das gebaut haben, hatten dedizierte IAM-Teams. Eine fertige Engine nehmen.
- **Keine Geräte im IdP.** Skala und Bedrohungsmodell passen nicht.
- **Keine Rollenkonstanten im Applikationscode.** Der Code kennt Permissions, nie Rollen.
- **Keine Rollennamen mit eingebautem Kontext** (`acme_marketplace_operator`). Kontext kommt aus der `parent`-Kette.
- **Keine virtuelle Zitadel-Instanz pro Endkunde.** Instanzen sind für Tenants mit echtem Isolationsbedarf, nicht für jeden Marktplatz-Endnutzer.
- **Kein Transparency-Log/Blockchain zum Start.** Hash-Chain in Postgres reicht, bis ein Kunde externe Verifizierbarkeit vertraglich fordert.
- **Keine erhöhte FGA-Konsistenz als Default.** Sie kostet messbar Latenz und Cache-Wirkung; gezielt auf kritischen Pfaden setzen.
- **Kein Live-Zellwechsel.** Der Aufwand für konsistente Online-Migration eines vollständigen vertikalen Stacks steht in keinem Verhältnis zur Häufigkeit.
- **Kein SCIM als Default.** Erst wenn zeitnahes Deprovisioning gefordert ist; davor reicht Federation mit JIT.
- **Keine Cross-Cell-Queries.** Wenn eine Funktion sie zu brauchen scheint, ist entweder das Zellschnittmuster oder die Funktion falsch.

---

## 21. Zu validierende Annahmen

Diese Punkte sind Entscheidungsgrundlage, aber noch nicht auf der eigenen Infrastruktur gemessen. Sie gehören in einen frühen Spike, bevor der Umbau breit anläuft.

| # | Annahme | Messung | Kippt was, wenn falsch |
|---|---|---|---|
| **V1** | FGA-Check p95 < 10 ms auf eigenem Postgres in der Zelle | Lasttest mit realistischer Tupelmenge und Modelltiefe | Library-Embed statt Netzwerk-Hop; ggf. SpiceDB |
| **V2** | Erhöhte Konsistenz ist auf kritischen Pfaden latenzverträglich | Vergleichsmessung beider Modi | Revocation-Strategie verschiebt sich stärker auf Kill-Switch |
| **V3** | Kill-Switch-Verbreitung < 5 s zellweit | Ende-zu-Ende-Messung Auslöser → Wirksamkeit | kürzere Token-Lebensdauern nötig |
| **V4** | Zitadel trägt die geplante Org-/Instanzanzahl | Lasttest + Rücksprache mit Zitadel | früherer Wechsel zu P2/P3 für mehr Kunden |
| **V5** | Token Exchange in Zitadel ist produktionsreif genug für Impersonation | Reifegrad prüfen, Feature-Flags, Berechtigungsmodell | Impersonation bleibt vorerst applikationsseitig |
| **V6** | RLS-Overhead mit `tenant_id`-Composite-Index bleibt einstellig prozentual | Benchmark auf realistischem Datenvolumen | Index-Strategie oder Partitionierung nachziehen |
| **V7** | Outbox-Durchsatz reicht für Audit + Sync + Kunden-Events | Lasttest der Sync-Pipeline | getrennte Pipelines je Zweck |

---

## 22. Gesamtbild in einem Absatz

Zitadel authentifiziert und verwaltet Identitäten; OpenFGA beantwortet jede Berechtigungsfrage über einen Relationsgraph, dessen Modell aus einer einzigen versionierten Quelle generiert wird; eine dünne Go-Schicht setzt in zwei Stufen durch — erst lokal aus dem Token, dann über genau einen Hop in der Zelle; Geräte und Workloads leben in einer eigenen PKI-Ebene mit kurzlebigen Zertifikaten; jede Freigabe ist eine Signatur statt eines Datenbankfelds; alles läuft in Zellen, die von „eine Org unter vielen" bis „eigener Stack in eigener Region" dasselbe Bild und denselben Code haben. Neue Akteure, Rollen und Hierarchieebenen entstehen als Daten, nicht als Deployments.