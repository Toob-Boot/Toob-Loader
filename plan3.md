# Backlog — Umbau zur DevOps-Zielarchitektur

**Ziel:** `ARCHITEKTUR-devops.md`
**Ausgangspunkt:** Der bestehende `deploy/`-Stack im Repository `toob-registry`.

**Quellenlage:** Ursprünglich auf Basis des DevOps-Runbooks geschrieben, danach gegen den
tatsächlichen Code nachgezogen (`deploy/` und `internal/ops/`). Die ehemaligen
**[Dateien nötig]**-Markierungen sind aufgelöst; die betroffenen Tickets sind mit
**⟳ nachgezogen** gekennzeichnet und tragen die konkreten Datei- und Funktionsverweise.

**Begleitdokument:** `BACKLOG-devops-befunde.md` enthält zwanzig Punktbefunde aus demselben
Code-Durchgang (Präfix `BEF-`). Zwei davon sind Vorbedingungen für diesen Umbau und stehen
dort mit Begründung: **BEF-003** (der Teardown-Pfad löscht Produktions-Vault-Backups) und
**BEF-006** (der Backup-Bucket ist nicht umgebungsgetrennt). Beide müssen vor EPIC C erledigt
sein, weil sonst der Restore-Test auf einem Bucket aufsetzt, den ein Dev-Teardown wegräumen
kann.

**Leitgedanke der Reihenfolge:** Der Vault-Umzug (EPIC D) ist der einzige Schritt, der etwas
Unwiederbringliches anfassen kann. Alles davor existiert nur, um ihn zu entschärfen. Insbesondere
`OPS-020` (Restore-Test) ist eine harte Vorbedingung — nicht weil es Prozess ist, sondern weil
dort das einzige Mal billig herauskommt, ob der Snapshot überhaupt zurückspielbar ist.

---

## Legende

**Prio:** P0 blockierend · P1 für das Epic-Gate · P2 Robustheit · P3 Hygiene
**Typ:** `infra` `security` `refactor` `dx` `test` `cleanup`
**Aufwand:** S ≤ ½ Tag · M 1–2 Tage · L > 2 Tage
**Risiko:** ○ kein Eingriff in Bestand · ◐ reversibel · ● Wartungsfenster nötig

**Definition of Done (global):**
1. Jede Änderung ist in `toob-infra` versioniert. Kein Handgriff auf einem Server, der nicht in
   einer Rolle oder einem Modul steht.
2. Rückweg dokumentiert, bevor der Schritt beginnt. Bei ● zusätzlich: alte Ressource bleibt bis
   zur Bestätigung stehen.
3. Betroffener Abschnitt in `ARCHITEKTUR-devops.md` bestätigt oder im selben PR angepasst.
4. Kein Secret in Shell-History, Commit oder Terraform-Output.

---

## Ticket-Übersicht

| ID | Titel | Prio | Risiko | Aufw. |
|---|---|---|---|---|
| **EPIC A — Vorbereitung, kein Eingriff** |||||
| OPS-001 | Repository `toob-infra` anlegen, `deploy/` überführen | P0 | ○ | M |
| OPS-002 | Terraform-State der drei lokalen Module nach S3 | P0 | ◐ | S |
| OPS-003 | `api_origins` über `terraform_remote_state` | P2 | ○ | S |
| OPS-004 | Golden Image von Registry-Artefakten entkoppeln | P1 | ○ | M |
| OPS-005 | Monolith-Playbook in Rollen zerlegen | P1 | ○ | L |
| OPS-006 | Verbindlicher CIDR-Plan | **P0** | ○ | S |
| OPS-007 | `topology` um eine Projektdimension erweitern | **P0** | ○ | L |
| OPS-008 | `--project`-Flag, State-Dateien, Stage-Profile | **P0** | ○ | L |
| OPS-009 | Stages an Hub-and-Spoke anpassen | P1 | ○ | L |
| OPS-00A | Dashboards und Alert-Regeln projektfähig machen | P1 | ○ | M |
| OPS-00B | Cloudflare-Modul mehrprojektfähig | P1 | ◐ | M |
| **EPIC B — Kontrollebene aufbauen** |||||
| OPS-010 | Projekt `toob-ops`, Netz, Firewall-Baseline | P1 | ○ | M |
| OPS-011 | `ops-hub` mit WireGuard-Hub | P1 | ○ | M |
| OPS-012 | Peer-Registrierung und Admin-Profil | P1 | ○ | S |
| OPS-013 | `ops-ci` als Build- und Deploy-Runner | P1 | ○ | M |
| OPS-014 | Monitoring-Stack auf `ops-hub`, noch ohne Ziele | P1 | ○ | M |
| **EPIC C — Sicherheitsnetz vor dem Vault-Umzug** |||||
| OPS-020 | Restore-Test automatisieren | **P0** | ○ | M |
| OPS-021 | Backup-Metriken vereinheitlichen | P2 | ○ | S |
| OPS-022 | Break-Glass dokumentieren und einmal üben | P1 | ○ | S |
| **EPIC D — Vault-Migration** |||||
| OPS-030 | `ops-kms` aufsetzen, Unseal-Vault umziehen | P0 | ● | M |
| OPS-031 | `ops-vault-1/2/3`, Raft-Snapshot, drei Knoten | P0 | ● | L |
| OPS-032 | Vault-Pfade auf Projektstruktur | P1 | ◐ | M |
| OPS-033 | Transit-Key `update-firmware-signing` trennen | P0 | ◐ | S |
| OPS-034 | Cosign-Dauertoken durch Token-pro-Lauf ersetzen | P1 | ◐ | M |
| OPS-035 | Alte Vault-Instanzen abbauen | P2 | ◐ | S |
| **EPIC E — Beobachtung umziehen** |||||
| OPS-040 | Registry als ersten Spoke anbinden | P1 | ◐ | M |
| OPS-041 | Monitoring von `reg-api-fsn1` nach `ops-hub` | P1 | ◐ | L |
| OPS-042 | Zwei-Sonden-Muster für jeden öffentlichen Dienst | P1 | ○ | M |
| OPS-043 | Alert-Routing und Dead-Man-Switch pro Projekt | P1 | ○ | S |
| OPS-044 | Loki-Mandantentrennung vorbereiten | P2 | ○ | M |
| **EPIC F — Identity-Spoke** |||||
| OPS-050 | Projekt `toob-identity`, zwei Knoten | P1 | ○ | M |
| OPS-051 | Zitadel installieren, HA praktisch verifizieren | P1 | ○ | L |
| OPS-052 | Registry-Login auf Zitadel umstellen | P2 | ◐ | M |
| OPS-053 | Workload-Identity-Federation für Kunden-CI | P2 | ○ | M |
| **EPIC G — Modul und Staging** |||||
| OPS-060 | `project-baseline`-Terraform-Modul | P1 | ○ | L |
| OPS-061 | `toob-staging` als Nachweis des Moduls | P1 | ○ | M |
| OPS-062 | Promotion: derselbe Digest von Staging nach Produktion | P2 | ○ | M |
| **EPIC H — Update-Spoke** |||||
| OPS-070 | Projekt `toob-update` aus dem Modul | P1 | ○ | M |
| OPS-071 | systemd-Units, Caddy, Rolling-Deploy-Skript | P1 | ○ | M |
| OPS-072 | Blob-Route `fw.` direkt auf Object Storage | P0 | ○ | S |
| **EPIC I — Invarianten nachweisen** |||||
| OPS-080 | Abschalttest gegen Staging, zweimal manuell | P1 | ○ | M |
| OPS-081 | Abschalttest gegen Produktion, einmal manuell | P0 | ● | S |
| OPS-082 | Abschalttest automatisieren, wöchentlich | P1 | ○ | M |
| OPS-083 | P2-Nachweis: Portscan aller Projektnetze | P1 | ○ | S |
| OPS-084 | P3-Nachweis: Vault 24 Stunden abgeschaltet | P1 | ◐ | S |
| **EPIC J — Altlasten abbauen** |||||
| OPS-090 | Registry-Bastion abbauen | P2 | ◐ | S |
| OPS-091 | Nomad-Bootstrap-Token nach Vault | P2 | ◐ | S |
| OPS-092 | Secret-Seeding ohne Operator-Environment | P2 | ◐ | M |
| OPS-093 | Cloudflare-Token pro Projekt einschränken | P3 | ◐ | S |
| OPS-094 | DB-Firewall-Pruner als Plattformdienst | P3 | ◐ | S |

---

# EPIC A — Vorbereitung, kein Eingriff in den Bestand

---

### OPS-001 — Repository `toob-infra` anlegen

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** M

**Problem**
Der gesamte Infrastrukturcode liegt als `deploy/` **innerhalb** von `toob-registry`. Mit fünf
Projekten ist das nicht haltbar: Der Update-Service kann nicht aus dem Registry-Repo deployt
werden, ohne dass jeder mit Deploy-Rechten für den Update-Pfad auch Schreibrechte am
Registry-Quellcode braucht.

**Lösung**
Eigenes Repository mit dieser Struktur:

```
toob-infra/
├── packer/                    Golden Image (geteilt)
├── modules/
│   ├── project-baseline/      OPS-060
│   ├── spoke-node/
│   └── wg-peer/
├── projects/
│   ├── ops/       identity/   registry/   update/   staging/
├── ansible/
│   ├── roles/                 common, wg-peer, vault, monitoring, caddy, nomad, zitadel
│   └── playbooks/
├── scripts/                   restore-test, shutdown-test, rolling-deploy
└── runbooks/
```

Git-History der `deploy/`-Dateien per `git filter-repo` mitnehmen — bei einem
Infrastruktur-Repo ist die Historie der eigentliche Wert.

`toob-registry` behält nur, was zum Bauen der Anwendung gehört (`Dockerfile.api`,
`deploy/compiler/`, `deploy/worker/Makefile`). Die Grenze verläuft entlang „baut das Produkt"
gegen „stellt das Produkt bereit".

**⟳ nachgezogen — der exakte Schnitt**

| Bleibt in `toob-registry` | Wandert nach `toob-infra` |
|---|---|
| `deploy/api/Dockerfile.api` | `deploy/api/deploy.sh`, `seccomp-api.json`, `toob-api-hardening.service` |
| `deploy/compiler/` (vollständig) | `deploy/packer/`, `deploy/terraform/`, `deploy/ansible/` |
| `deploy/worker/Makefile` | `deploy/nomad/`, `deploy/caddy/`, `deploy/monitoring/`, `deploy/vault/` |

**Die offene Frage, die das Ticket bisher nicht stellte: wohin gehört `internal/ops/`?**

Die `toob-ops`-CLI liegt heute in `toob-registry` und ist an zwei Stellen an dessen
Domänenmodell gekoppelt: `cmd/toob-ops/list_compilers.go` importiert
`internal/domain.CompilerVersion`, `test_build.go` zusätzlich `domain.RegistryIndex` und
`domain.VMResult`. Alles andere — `engine`, `stages`, `topology`, `ui`, `exec`, `dashboard` —
ist produktunabhängig.

Drei Optionen:

| | Vorgehen | Bewertung |
|---|---|---|
| A | CLI bleibt in `toob-registry`, `toob-infra` wird nur Datenhaltung | Verfehlt den Zweck — Update-Deploys bräuchten weiter Registry-Checkout |
| B | CLI vollständig nach `toob-infra`, `list-compilers`/`test-build` entfallen dort | Diese beiden Kommandos sind registry-spezifische Verifikationswerkzeuge und gehören ohnehin nicht in ein Plattformwerkzeug |
| C | CLI nach `toob-infra`, Domänentypen in ein geteiltes `toob-types`-Modul | Drittes Repository für drei Structs |

**Empfehlung: B.** `list-compilers` und `test-build` bleiben als
`cmd/toob-registry-verify` im Registry-Repo — sie prüfen Compiler-Images und Rootfs-Builds,
also Registry-Produktfunktionen, nicht Infrastruktur. Der Rest der CLI wird produktneutral und
verliert damit seine einzige Kopplung.

**Akzeptanzkriterien**
- [ ] `terraform plan` aus dem neuen Repo zeigt für alle bestehenden Module keine Änderung.
- [ ] Ein Ansible-Lauf aus dem neuen Repo ist idempotent gegen den Bestand.
- [ ] `toob-registry` enthält kein Terraform mehr.
- [ ] `toob-infra` importiert nichts aus `github.com/Toob-Boot/Toob-Registry/internal/domain`.

---

### OPS-002 — Terraform-State der drei lokalen Module nach S3

**Prio:** P0 · **Risiko:** ◐ · **Aufwand:** S

**⟳ nachgezogen — weitgehend erledigt, Ticket wird zur Verifikation**

Das Runbook beschrieb einen älteren Stand. Im Code ist der Remote-State bereits verdrahtet:
`terraform/cloudflare/main.tf` enthält `backend "s3" {}`, und `stages/terraform.go` übergibt
die Konfiguration zur Laufzeit für **jedes** Modul der Liste
`{s3, database, control-plane, cloudflare}`:

```go
initArgs := []string{
    "init",
    fmt.Sprintf("-backend-config=bucket=%s", bucket),   // toob-terraform-state-<env>
    fmt.Sprintf("-backend-config=key=%s", key),         // <env>/<modul>/terraform.tfstate
    "-backend-config=region=fsn1",
    …
    "-reconfigure",
}
```

Zusätzlich legt `bootstrapStateBucket` den Bucket an und aktiviert Versionierung — der
Henne-Ei-Schritt aus dem Runbook ist automatisiert.

**Was bleibt**
1. Bestätigen, dass `database/main.tf` und `s3/main.tf` ebenfalls eine `backend "s3" {}`-Stanza
   haben. Ohne sie ignoriert Terraform die `-backend-config`-Flags stillschweigend und schreibt
   weiter lokal — das ist genau der Fall, den man nicht sieht, bis der State weg ist.
2. `terraform plan` aus einer **frischen** Arbeitskopie je Modul. Nur das beweist, dass der
   Remote-State vollständig ist.
3. Etwaige verbliebene `terraform.tfstate`-Dateien im Arbeitsverzeichnis sichern und entfernen.

**Nachrangig, aber im selben Zug:** `terraform/cloudflare/tfplan` liegt als Binärdatei im
Repository. Ein Plan-File enthält aufgelöste Variablenwerte — bei diesem Modul unter anderem
das Cloudflare-API-Token. Löschen und in `.gitignore` aufnehmen (siehe `BEF-002`).

```
control-plane/terraform.tfstate      (bestehend)
worker/terraform.tfstate             (bestehend)
cloudflare/terraform.tfstate         neu
database/terraform.tfstate           neu
s3/terraform.tfstate                 neu
```

Vor der Migration den lokalen State sichern. Danach ein `terraform plan` aus einer **frischen**
Arbeitskopie — nur das beweist, dass der Remote-State vollständig ist.

**Akzeptanzkriterien**
- [ ] Kein Modul mehr ohne Remote-Backend.
- [ ] `terraform plan` aus frischem Clone: keine Änderungen für alle fünf Module.
- [ ] Bucket-Versionierung auf dem State-Bucket ist aktiv.

Eine Stunde Arbeit, und das billigste Ticket im ganzen Backlog gemessen am vermiedenen Schaden.

---

### OPS-003 — `api_origins` über Remote State

**Prio:** P2 · **Risiko:** ○ · **Aufwand:** S

**Problem**
Runbook Phase 3.4 verlangt, die Public-IPs aus dem `control-plane`-Output von Hand ins
Cloudflare-Modul zu übertragen. Bei jedem Server-Replace veraltet das stillschweigend — der
Load-Balancer zeigt dann auf eine recycelte IP.

**Lösung**
`terraform_remote_state` wie im `worker`-Modul bereits vorhanden. Das Muster existiert im Repo,
es wird nur an einer Stelle nicht angewandt.

**Akzeptanzkriterien**
- [ ] Cloudflare-Modul hat keine `api_origins`-Variable mehr.
- [ ] Ein Server-Replace im control-plane-Modul aktualisiert die Origins ohne Handgriff.

---

### OPS-004 — Golden Image von Registry-Artefakten entkoppeln

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Problem**
`packer/image.pkr.hcl` spielt per `file`-Provisioner `build/worker` und `build/rootfs.ext4` ein
und bricht hart ab, wenn sie fehlen. Für `ops-hub`, `idp-*` und `upd-edge-*` sind Firecracker,
Jailer, der Gast-Kernel und das Worker-Binary toter Ballast — und jeder Registry-Rebuild würde
alle anderen Projekte zu einem neuen Image zwingen.

**Lösung**
Zwei Images aus gemeinsamer Basis:

| Image | Inhalt |
|---|---|
| `toob-base` | Ubuntu 24.04, Härtung, Docker, Caddy, node-exporter, Alloy, WireGuard |
| `toob-worker` | `toob-base` + Firecracker, Jailer, `vmlinux`, Worker-Binary, rootfs |

Die HashiCorp-Binaries (Nomad, Vault) mit GPG-Fingerprint-Pinning bleiben in `toob-base` — Vault
braucht `ops-vault-*`, Nomad braucht die Registry, und ein zusätzliches Image dafür lohnt nicht.

**Akzeptanzkriterien**
- [ ] `toob-base` baut ohne `build/worker` und `build/rootfs.ext4`.
- [ ] Ein Rebuild von `toob-worker` zwingt keine anderen Projekte zu einem Update.
- [ ] Beide Images tragen ein Label mit Build-Datum und Basis-Image-Digest.

---

### OPS-005 — Monolith-Playbook in Rollen zerlegen

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** L

**Problem**
`ansible/playbook.yml` enthält zehn Plays, die von der CA-Erzeugung über beide Vault-Inits bis
zum Nomad-ACL-Bootstrap alles in einer Datei erledigen. Für fünf Projekte mit unterschiedlichen
Rollenprofilen ist das nicht teilbar: `ops-hub` braucht Monitoring aber kein Nomad, `idp-*`
braucht Caddy aber kein Vault, `upd-edge-*` braucht beides nicht.

**Lösung**
Rollen mit klaren Grenzen:

| Rolle | Inhalt | Verwendet von |
|---|---|---|
| `common` | node-exporter, Textfile-Collector, `notify-failure@`, Alloy, Swap aus | alle |
| `wg-peer` | WireGuard-Client mit Dial-Out zum Hub | alle Spokes |
| `wg-hub` | Hub, `AllowedIPs` je Peer, Firewall | `ops-hub` |
| `vault-kms` | Unseal-Vault, Init-Zeremonie, Backup-Timer | `ops-kms` |
| `vault-primary` | Raft, Auto-Unseal, `init.sh`, `seed.sh` | `ops-vault-*` |
| `monitoring` | Prometheus, Loki, Grafana, Alertmanager | `ops-hub` |
| `caddy` | Origin-Cert, Reverse-Proxy, Header | alle mit Ingress |
| `nomad` | Server/Client, TLS-Rotation, ACL-Bootstrap | `reg-*` |
| `zitadel` | Zitadel + systemd | `idp-*` |

Die beiden Vault-Zeremonien (Runbook 5.3 und 5.4) bleiben unverändert als Abbruchpunkte
erhalten — sie sind kein Umbaukandidat.

**⟳ nachgezogen — der eigentliche Blocker**

Der Aufwand liegt nicht in der Zahl der Plays, sondern in einem durchgehenden Muster:
**Rollenzuordnung erfolgt über den hartkodierten Hostnamen `toob-api-fsn1`**, nicht über
Gruppen oder Variablen. Das Konstrukt

```yaml
when: inventory_hostname == 'toob-api-fsn1'
```

steht über das gesamte Playbook verteilt und entscheidet, wer Vault initialisiert, wer den
Monitoring-Stack bekommt, wer die Backup-Timer bekommt, wer den Token-TTL-Exporter bekommt
und wer den Nomad-ACL-Bootstrap ausführt. Dieselbe Kopplung steckt in der Nomad-Konfiguration
(`server.hcl` vs. `client.hcl` werden nach demselben Vergleich verteilt) und in
`stages/ansible.go`, das `inventory.ini` mit genau diesen Namen generiert.

Für fünf Projekte ist das nicht teilbar: `ops-vault-1` müsste „`toob-api-fsn1` sein", um die
Vault-Rolle zu bekommen.

**Zusätzlich zu entflechten:** Der Play „Setup and Initialize Primary Vault Nodes" vermischt
vier Belange — Vault-Init und -Seeding, den kompletten Monitoring-Compose-Stack, die
Backup-Timer für Vault und Nomad, und den Token-TTL-Exporter. In der Zielarchitektur landen
diese auf **zwei verschiedenen Projekten** (`ops-vault-*` und `ops-hub`).

**Vorgehen in dieser Reihenfolge**
1. `inventory_hostname ==`-Vergleiche durch Gruppen- oder Rollenzugehörigkeit ersetzen
   (`when: "'vault_primary' in group_names"`). Rein mechanisch, gegen den Bestand testbar.
2. Den großen Vault-Play entlang der vier Belange aufteilen.
3. Erst dann Rollen extrahieren.

Schritt 1 ist die Voraussetzung dafür, dass Schritt 3 überhaupt Sinn ergibt — und er ist
einzeln gegen die bestehende Dev-Umgebung verifizierbar.

**Akzeptanzkriterien**
- [ ] Kein `inventory_hostname ==`-Vergleich mehr im Playbook (Grep-Test).
- [ ] Der Bestand lässt sich mit den neuen Rollen idempotent reprovisionieren.
- [ ] Ein Play für `ops-hub` läuft ohne Nomad- und ohne Vault-Rolle durch.
- [ ] Keine Rolle setzt `/etc/hosts`-Einträge fremder Projekte.

**Verwandt:** `BEF-012` (Regex-`replace` auf Nomad-Konfigurationen) gehört in denselben
Arbeitsgang — die fünf `replace`-Tasks fallen weg, sobald `server.hcl` und `client.hcl`
Templates sind.

---

### OPS-006 — Verbindlicher CIDR-Plan

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** S

**Problem**
Die Projektnetze wurden bisher pro Ticket vergeben. Zwei Kollisionen sind so entstanden:
`toob-identity` auf `10.2.1.0/24` (belegt von registry/staging) und `toob-update` auf
`10.1.1.0/24` — bitgenau das Subnetz von registry/dev.

Am WireGuard-Hub ist das nicht heilbar: zwei Peers mit identischem `AllowedIPs` sind nicht
routbar, und WireGuard meldet keinen Fehler, sondern liefert an den zuletzt passenden Peer.
Der Fehler fällt als sporadisch nicht erreichbarer Knoten auf, nicht als Konfigurationsfehler.

**Lösung**
Ein Plan, festgeschrieben in `topology.go` und in `ARCHITEKTUR-devops.md`:

| Bereich | Belegung |
|---|---|
| `10.0.0.0/16` | registry / production (Bestand) |
| `10.1.0.0/16` | registry / dev (Bestand) |
| `10.2.0.0/16` | registry / staging (Bestand) |
| `10.9.0.0/16` | **ops** — einmalig, ohne Umgebungsvariante |
| `10.20.0.0/16` | identity / production |
| `10.21.0.0/16` | identity / dev |
| `10.30.0.0/16` | update / production |
| `10.31.0.0/16` | update / dev |

**Warum die Kontrollebene keine Dev-Variante bekommt:** Sie bedient alle Projekte einschließlich
deren Dev-Umgebungen. Ein zweiter Vault-Cluster und ein zweiter Hub nur für Dev-Spokes würden
die Zeremonien verdoppeln, ohne etwas zu isolieren — die Trennung läuft über Vault-Pfade und
Peer-`AllowedIPs`. Das entspricht dem Bestand, in dem ein Vault über `VAULT_ENV` alle
Umgebungen bedient.

**Akzeptanzkriterien**
- [ ] Eine Testfunktion in `topology` prüft alle Paare auf Überschneidung und schlägt fehl,
      wenn eine hinzukommt.
- [ ] Kein Ticket vergibt mehr ein Netz außerhalb dieses Plans.

---

### OPS-007 — `topology` um eine Projektdimension erweitern

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** L
**Datei:** `internal/ops/topology/topology.go`

**Problem**
`topology.Get(env)` liefert eine feste Struktur mit `BastionIP`, `UnsealVaultIP` und
`APINodes` — ein Modell mit genau einem Produkt und drei festen Rollen. Jede Stage liest
daraus: `terraform.go`, `ansible.go`, `vpn.go`, `verify.go`, `deploy.go`, `workers.go` und
`dashboard/poller.go`.

Solange das so bleibt, ist `toob-ops wizard --project identity` nicht aufrufbar, und die
Projekte aus EPIC F bis H müssten von Hand provisioniert werden — was `OPS-060` (Modul) und
`OPS-061` (Nachweis) ihren Sinn nimmt.

**Lösung**
```go
type Project struct {
    Name        string
    Environment string
    NetworkCIDR string
    SubnetCIDR  string
    Nodes       map[string]Node   // rolle → knoten
    Hostnames   map[string]string // zweck → fqdn
    Buckets     map[string]string
}

func Get(project, env string) Project
```

`Node` bekommt `Roles []string`, damit `reg-api-fsn1` gleichzeitig `nomad-server`, `caddy` und
`wg-peer` sein kann — genau die Mehrfachrolle, die heute über
`inventory_hostname == 'toob-api-fsn1'` ausgedrückt wird und in `OPS-005` verschwindet.

Die drei Bestandsumgebungen werden zu `Get("registry", env)` mit bitidentischen Werten. Die
Migration läuft damit in zwei Schritten: erst Struktur ohne Verhaltensänderung, dann neue
Projekte.

**Akzeptanzkriterien**
- [ ] `Get("registry", "dev")` liefert exakt die heutigen Werte.
- [ ] Ein Dev-Deployment nach dem Refactor erzeugt identische Terraform-Pläne.
- [ ] Keine IP-Literale mehr außerhalb des `topology`-Pakets (Grep-Test im CI).

---

### OPS-008 — `--project`-Flag, State-Dateien, Stage-Profile

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** L
**Dateien:** `cmd/toob-ops/main.go`, `internal/ops/engine/state.go`, `internal/ops/stages/prereqs.go`

**Problem**
Vier Stellen in der CLI sind auf ein Produkt festgelegt:

| Stelle | Heute | Problem |
|---|---|---|
| `DefaultStatePath(deployDir, env)` | `.toob-ops-state.<env>.json` | Kollidiert zwischen Projekten |
| `main.go` Stage-Registrierung | alle neun Stages, unbedingt | `ops-hub` braucht kein Packer, kein Workers |
| `AllEnvRequirements()` | ~40 Variablen, projektunabhängig `Required` | Ein Identity-Spoke bräuchte `SEED_GH_APP_ID`, `SEED_DOCKERHUB_*`, `NOMAD_GOSSIP_KEY` — Phase 0 blockiert |
| `mapCredentials()` | hartkodierte Key-Liste, Präfixe `TOOB_DEV_`/`TOOB_STAGING_`/`TOOB_PROD_` | Keine Projektdimension |

**Lösung**
1. `--project` mit Default `registry`, State- und Secrets-Pfad
   `.toob-ops-<project>.<env>.json`. Die Mismatch-Prüfung in `runWizard`
   (`state environment mismatch`) hat sich bewährt und wird um das Projekt erweitert.
2. Stage-Profil je Projekt:

   | Projekt | Stages |
   |---|---|
   | `registry` | alle neun, unverändert |
   | `ops` | prereqs, terraform, vpn, ansible, verify |
   | `identity` | prereqs, terraform, ansible, deploy, verify |
   | `update` | prereqs, terraform, ansible, deploy, verify |

   Die Phasennummern bleiben stabil — Einträge entfallen, sie verschieben sich nicht, damit
   State-Dateien und Logverzeichnisse vergleichbar bleiben.
3. `EnvRequirement` bekommt ein Feld `Projects []string`. Fehlt es, gilt die Variable für alle.
4. `mapCredentials` liest die Key-Liste aus dem Profil statt aus einem Literal.

**Akzeptanzkriterien**
- [ ] `--project registry` verhält sich in allen neun Phasen exakt wie heute.
- [ ] `--project identity` verlangt in Phase 0 keine Registry-spezifischen Variablen.
- [ ] Ein Profil ohne Packer-Stage läuft durch, ohne dass eine Precondition auf Phase 2 wartet.

---

### OPS-009 — Stages an Hub-and-Spoke anpassen

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** L
**Dateien:** `stages/vpn.go`, `stages/verify.go`, `stages/packer.go`, `dashboard/`

**Problem**
Vier Stellen setzen die heutige Topologie voraus und funktionieren nach dem Umbau nicht mehr:

**`stages/vpn.go`** — `EnsureVPN` und `ensureVPNForStatus` sondieren `topo.UnsealVaultIP:22`
und starten `wg-quick up wg0.<env>.conf`. Mit Dial-Out-Peers und zentralem Hub entfällt das
projektspezifische Client-Profil; die Sonde muss gegen einen Knoten des jeweiligen Projekts
gehen. Zusätzlich schreiben `ensureHostsMapping` und `setupHostsForStatus` fest
`vault.the-toob.com` → `api-fsn1` in `/etc/hosts` — nach `OPS-031` zeigt der Name auf
`ops-vault-*`.

**`stages/verify.go`** — prüft Vault-Seal-Status über `topo.APINodes` und die
Nomad-Erreichbarkeit unbedingt. Für Projekte ohne Vault und ohne Nomad muss die Prüfliste aus
dem Profil kommen.

**`stages/packer.go`** — `findExistingHetznerSnapshot` sucht nach Description
`toob-golden-image-<env>` und den Labels `name=toob-golden-image`. Mit `toob-base` und
`toob-worker` aus `OPS-004` braucht das eine Imagedimension, sonst wird das falsche Snapshot
wiederverwendet.

**`dashboard/render.go`** — baut die Knotenkarte aus den Literalen `toob-unseal-vault`,
`<prefix>-api-fsn1` und `<prefix>-api-hel1`. Für andere Projekte zeigt das Dashboard nichts.

**Lösung**
Alle vier auf `topology.Project` und das Stage-Profil aus `OPS-008` umstellen. Das Dashboard
rendert Knoten und deren Rollen generisch aus `Nodes`, statt sie zu erraten.

**Akzeptanzkriterien**
- [ ] `toob-ops status --project identity` zeigt die Identity-Knoten mit ihren Rollen.
- [ ] `verify` prüft für ein Projekt ohne Vault keine Seal-Status.
- [ ] Ein `toob-base`-Rebuild macht ein bestehendes `toob-worker`-Snapshot nicht ungültig.

---

### OPS-00A — Dashboards und Alert-Regeln projektfähig machen

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M
**Dateien:** `monitoring/prometheus/alert.rules.yml`, `monitoring/grafana/dashboards/*.json`

**Problem**
`OPS-043` routet Alarme über ein `project`-Label — das keine der 21 Regeln setzt. Ohne dieses
Ticket landet nach dem Umbau alles im Default-Empfänger.

Zusätzlich brechen mehrere Panels und Regeln durch den Umbau selbst:

| Stelle | Bricht durch |
|---|---|
| `ops-home.json`: `up{job="node-exporter", instance="bastion"}` | `OPS-090` (Bastion-Abbau) → dauerhaft rot |
| `ops-home.json`: `instance="unseal-vault"` | `OPS-030` → Knoten heißt `ops-kms` |
| `alert.rules.yml`: `blackbox-public` auf `registry.the-toob.com` | weitere Hostnames kommen dazu |
| `AutoscalerIneffective`: `job="registry-worker"` | bleibt registry-spezifisch, braucht Projektfilter |
| `VaultSealed`, `NomadTLSRotationFailed` | gelten nur für Projekte mit Vault bzw. Nomad |

**Lösung**
Regeln nach `common` (InstanceDown, DiskSpace, Backup, Watchdog) und projektspezifisch
aufteilen. `project` als Pflichtlabel in jeder Regelgruppe. Dashboards mit einer
`project`-Template-Variablen statt fester Instanznamen; die Statusmatrix rendert Zeilen aus
den vorhandenen Zielen, statt sie zu benennen.

**Akzeptanzkriterien**
- [ ] Jede Regel trägt ein `project`-Label.
- [ ] Nach dem Bastion-Abbau ist kein Panel dauerhaft rot.
- [ ] Ein neues Projekt erscheint im Ops-Home-Dashboard, ohne dass es angepasst wird.

---

### OPS-00B — Cloudflare-Modul mehrprojektfähig

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** M
**Datei:** `terraform/cloudflare/main.tf`

**Problem**
Das Modul ist auf die Registry zugeschnitten:
- `local.domain_map` kennt nur `registry.the-toob.com` und dessen Staging-/Dev-Varianten
- Load-Balancer, SSL-Einstellungen und Rate-Limits entstehen nur bei
  `var.environment == "production"` — Dev und Staging haben deshalb weder `ssl = strict` noch
  Rate-Limits
- `cloudflare_dns_record.cdn` zeigt fest auf `${name_prefix}-packages`
- Die Cache-Regel greift auf `/download`, was für `fw.` nicht passt

Die Hostnames `id.`, `ota.`, `api.` und `fw.` aus EPIC F bis H haben damit kein Modul, das sie
anlegt. `OPS-072` beschreibt die Regeln für `fw.`, aber nicht, wer sie erzeugt.

**Lösung**
Modul auf eine Hostname-Liste umstellen, die aus `topology.Project.Hostnames` gespeist wird.
Je Eintrag: Typ (LB oder CNAME), Ziel, Cache-Policy, Rate-Limit, Ruleset. Die
Zone-Einstellungen (`ssl = strict`, min TLS, TLS 1.3) sind zonenweit und gehören aus der
`environment == "production"`-Bedingung heraus — dass Dev heute ohne `strict` läuft, ist
vermutlich nicht beabsichtigt.

**Akzeptanzkriterien**
- [ ] `id.`, `ota.`, `api.` und `fw.` entstehen aus dem Modul, nicht von Hand.
- [ ] `fw.` hat Compress off, `immutable`, kein Redirect (Prüfung aus `OPS-072`).
- [ ] Getrennte Rulesets pro Hostname — ein WAF-Fehler auf `ci.` trifft `ota.` nicht.

---

# EPIC B — Kontrollebene aufbauen

> Alles in diesem Epic läuft parallel zum unveränderten Bestand.

---

### OPS-010 — Projekt `toob-ops`, Netz, Firewall-Baseline

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Eigenes Hetzner-Projekt mit eigenem API-Token. Netz `10.9.0.0/16`, Subnetz `10.9.1.0/24`
(bewusst weit weg von den Spoke-Bereichen `10.0–10.3`, damit eine Fehlkonfiguration nicht
zufällig überlappt).

Firewall-Baseline: **kein eingehender Port außer dem WireGuard-UDP-Port am Hub.** Kein SSH von
außen, auch nicht temporär.

**Akzeptanzkriterien**
- [ ] Portscan von außen: genau ein UDP-Port offen.
- [ ] Das Projekt hat ein eigenes `HCLOUD_TOKEN`, das keine anderen Projekte sieht.

---

### OPS-011 — `ops-hub` mit WireGuard-Hub

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
CX32 aus `toob-base`. Hub-Konfiguration mit einem Peer je **Projekt-Umgebung-Paar** plus
Admin-Peers:

```ini
[Interface]
Address = 10.9.9.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -o %i -j DROP

[Peer]                      # registry / production
AllowedIPs = 10.9.9.10/32, 10.0.1.0/24
[Peer]                      # registry / dev
AllowedIPs = 10.9.9.11/32, 10.1.1.0/24
[Peer]                      # registry / staging
AllowedIPs = 10.9.9.12/32, 10.2.1.0/24
[Peer]                      # identity / production
AllowedIPs = 10.9.9.20/32, 10.20.1.0/24
[Peer]                      # identity / dev
AllowedIPs = 10.9.9.21/32, 10.21.1.0/24
[Peer]                      # update / production
AllowedIPs = 10.9.9.30/32, 10.30.1.0/24
[Peer]                      # update / dev
AllowedIPs = 10.9.9.31/32, 10.31.1.0/24
```

**⟳ nachgezogen — zwei Korrekturen**

Die erste Fassung listete drei Peers mit den Netzen `10.0.1.0/24`, `10.1.1.0/24` und
`10.2.1.0/24` für registry, update und identity. Beide Annahmen waren falsch:

1. **Die Netze waren die der Registry-Umgebungen**, nicht die neuer Projekte. `10.1.1.0/24`
   ist registry/dev, `10.2.1.0/24` ist registry/staging. Der Hub hätte Update- und
   Identity-Verkehr in die Registry-Netze geroutet.
2. **Es ist ein Peer pro Projekt-Umgebung-Paar, nicht pro Projekt.** `mapCredentials` in
   `main.go` mappt `TOOB_DEV_HCLOUD_TOKEN`, `TOOB_STAGING_HCLOUD_TOKEN` und
   `TOOB_PROD_HCLOUD_TOKEN` — die drei Registry-Umgebungen sind bereits heute drei getrennte
   Hetzner-Projekte mit eigenen Netzen. Der Hub bedient also sieben Peers, nicht drei.

Die IP-Vergabe im Hub-Netz folgt demselben Schema wie die Subnetze: Zehnerblock pro Produkt,
Einerstelle pro Umgebung. Damit ist aus `10.9.9.31` ohne Nachschlagen ablesbar, dass es
update/dev ist.

Die `PostUp`-Regel ist der Kern: Sie unterbindet Peer-zu-Peer-Routing. Ohne sie kann ein
kompromittierter Registry-Knoten über den Hub ins Update-Netz.

**Akzeptanzkriterien**
- [ ] Ein Peer kann das Subnetz eines anderen Projekts nicht erreichen (aktiv getestet, nicht
      aus der Konfiguration abgeleitet).
- [ ] Der Hub verwirft eingehenden Verkehr von Peers bis auf den Loki-Port.

---

### OPS-012 — Peer-Registrierung und Admin-Profil

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** S

**Lösung**
Peer-Schlüssel werden beim Provisionieren eines Spoke-Knotens erzeugt, der öffentliche Teil
geht als Terraform-Output an das Hub-Modul. Kein manuelles Kopieren von Schlüsseln.

Ein Admin-Profil erreicht alle Subnetze — ein Profil statt fünf, kein Doppel-Hop.

**Akzeptanzkriterien**
- [ ] Ein neuer Spoke-Knoten ist ohne Handgriff am Hub erreichbar.
- [ ] Das Admin-Profil erreicht alle vier Spoke-Subnetze.

---

### OPS-013 — `ops-ci` als Build- und Deploy-Runner

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Problem**
Ein Build zieht Abhängigkeiten Dritter. Diese dürfen nicht im selben Prozessraum landen wie der
WireGuard-Hub und die Metriken aller Projekte — das wäre ein Supply-Chain-Pfad direkt in die
Kontrollebene.

**Lösung**
Eigener CX22, self-hosted Runner. Übernimmt schrittweise `deploy/api/deploy.sh` (Build → Cosign
→ Verify → Deploy) und später das Secret-Seeding (OPS-092).

Sparoption, falls das Budget drückt: mit `ops-hub` zusammenlegen. Dann aber mit einem Ticket zur
späteren Trennung, nicht stillschweigend.

**Akzeptanzkriterien**
- [ ] `deploy.sh all` läuft vollständig von `ops-ci`.
- [ ] `ops-ci` hat keinen Zugriff auf die Monitoring-Daten und keinen Hub-Schlüssel.

---

### OPS-014 — Monitoring-Stack auf `ops-hub`

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Prometheus, Loki, Grafana, Alertmanager als Compose-Stack, alle UIs an `127.0.0.1` gebunden
(Zugriff per WireGuard). Zunächst **ohne Scrape-Ziele** — der Bestand wird erst in OPS-041
umgehängt. Die fünf bestehenden Dashboards werden übernommen.

**Akzeptanzkriterien**
- [ ] Stack läuft, Grafana erreichbar über den Tunnel.
- [ ] Der Bestands-Stack auf `reg-api-fsn1` läuft unverändert weiter.

---

# EPIC C — Sicherheitsnetz vor dem Vault-Umzug

---

### OPS-020 — Restore-Test automatisieren

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** M

**Problem**
Das Runbook führt „periodisch Raft-Snapshot-Restore proben" als manuelle Daueraufgabe. Das
passiert erfahrungsgemäß genau einmal. `BackupStale` misst heute nur, ob eine Datei neu genug
ist — nicht, ob sie etwas enthält, das sich zurückspielen lässt.

**Vor OPS-031 ist das die einzige Absicherung, die zählt.**

**⟳ nachgezogen — Korrektur am ursprünglichen Entwurf**

Die erste Fassung dieses Tickets schrieb „Wegwerf-Vault-Container starten (File-Storage,
**eigener Unseal-Key**)". Das funktioniert nicht.

Ein Raft-Snapshot enthält den verschlüsselten Barrier-Zustand einschließlich des gewrappten
Master-Keys. Der Primary-Vault ist über `seal "transit"` gegen `ops-kms` versiegelt
(Key `autounseal-toob-registry`). Ein Ziel-Vault mit eigenem Unseal-Key kann diesen Master-Key
nicht auspacken — `snapshot restore -force` überspringt nur die *Konsistenzprüfung*, nicht die
kryptografische Voraussetzung. Das Ergebnis wäre ein Vault, der nach dem Restore unbrauchbar
ist, und ein Test, der zuverlässig rot leuchtet, ohne etwas über die Backups auszusagen.

**Korrigiertes Vorgehen**

```
1. Neuesten Snapshot aus toob-vault-backups-<env> ziehen
2. Wegwerf-Vault-Container starten, konfiguriert mit derselben
   seal "transit"-Stanza wie der Primary (ops-kms, gleicher Key)
3. vault operator raft snapshot restore
4. Prüfen: entsiegelt sich automatisch, secret/platform/canary lesbar,
   und transit/keys/toob-image-signing-<env> liefert denselben
   öffentlichen Schlüssel wie der Produktivcluster
5. Container zerstören, Ergebnis als Prometheus-Metrik
```

Schritt 4 prüft bewusst auch den Transit-Key: das ist der Wert, dessen Verlust in OPS-031
irreversibel wäre, und ein Snapshot, der ihn nicht mitbringt, ist für den Umzug wertlos.

**Was der Test damit beweist — und was nicht**

| Szenario | Abgedeckt |
|---|---|
| Primary-Cluster verloren, `ops-kms` lebt | ✓ automatisiert, monatlich |
| Primary **und** `ops-kms` verloren | ✗ — braucht das 3-von-5-PGP-Quorum |

Der zweite Fall lässt sich nicht automatisieren, weil er drei Menschen mit ihren PGP-Keys
erfordert. Er gehört deshalb in die halbjährliche Übung aus **OPS-022** und nicht hierher.
Beide zusammen ergeben die Aussage „wir könnten wiederherstellen"; einer allein nicht.

**Verwendbare Bausteine im Bestand**
- `vault/scripts/backup.sh` authentifiziert sich per `backup`-AppRole
  (`/opt/vault/config/backup-role-id` und `-secret-id`) und holt die S3-Credentials über
  `vault kv get secret/s3`. Der Restore-Test kann dieselbe AppRole nutzen.
- Das Textfile-Collector-Muster ist etabliert (`last_backup_timestamp_seconds`,
  `nomad_tls_rotation_timestamp_seconds`, `last_db_firewall_cleanup_success_timestamp_seconds`)
  und wird hier nur fortgesetzt.
- Der Kanarienvogel-Wert wird in `seed.sh` angelegt und nie geändert.

**Der KMS-Snapshot ist ein anderer Fall.** `backup-unseal.sh` sichert kein Raft-Snapshot,
sondern ein tar des File-Storage-Verzeichnisses, mit statischen S3-Credentials aus
`/etc/vault.d/backup-s3.env` — notwendigerweise, weil der KMS sich nicht selbst entsiegeln
kann, um sie aus Vault zu holen. Sein Restore-Test ist entsprechend simpler: entpacken,
starten, entsiegeln, prüfen dass `transit/keys/autounseal-toob-registry` existiert. Er gehört
mit ins Ticket, weil OPS-030 auf genau diesem Tarball aufsetzt.

**Akzeptanzkriterien**
- [ ] Der Lauf ist mit einem absichtlich beschädigten Snapshot rot.
- [ ] Der Lauf ist rot, wenn der Ziel-Vault eine abweichende Seal-Konfiguration hat
      (Negativtest gegen den ursprünglichen Denkfehler).
- [ ] Der wiederhergestellte Vault liefert denselben Transit-Public-Key wie der Produktivcluster.
- [ ] Der KMS-Tarball ist ebenfalls testweise zurückgespielt.
- [ ] Metrik `vault_restore_test_success` existiert und hat einen Alter-Alert.
- [ ] Ein grüner Lauf liegt vor, **bevor** OPS-030 beginnt.

**Abhängigkeit:** `BEF-006` (Backup-Bucket pro Umgebung trennen) und `BEF-003` (Teardown
löscht den Bucket) müssen davor liegen — sonst testet man gegen einen Bucket, den der nächste
Dev-Teardown entfernt.

---

### OPS-021 — Backup-Metriken vereinheitlichen

**Prio:** P2 · **Risiko:** ○ · **Aufwand:** S

**Lösung**
Alle Backup-Jobs (Primary Vault, Unseal-Vault, Nomad, künftig Zitadel) schreiben nach demselben
Muster in den Textfile-Collector: `toob_backup_last_success_timestamp{job="…",project="…"}`.
Ein Alert-Ausdruck statt vier.

---

### OPS-022 — Break-Glass dokumentieren und einmal üben

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** S

**Problem**
Mit dem zentralen Hub entsteht ein neues Risiko: Stirbt `ops-hub`, kommt niemand mehr irgendwo
hinein. Das gilt ab OPS-011, nicht erst am Ende des Umbaus.

**Lösung**
Zwei Pfade ins Runbook:
1. **Hetzner Cloud Console (VNC)** — funktioniert ohne jedes Netz, primärer Weg.
2. **Schlafendes WireGuard-Peer-Profil** je Projekt, offline hinterlegt, das erst nach manueller
   Aktivierung über die Console akzeptiert wird.

Einmal durchführen und die Zeit bis zum Zugriff protokollieren.

**Akzeptanzkriterien**
- [ ] Übung durchgeführt, Dauer notiert.
- [ ] Das Runbook liegt nicht ausschließlich in einem System, das selbst ausfallen kann.

---

# EPIC D — Vault-Migration

> Der einzige Teil mit echtem Risiko. `OPS-020` muss grün sein.

---

### OPS-030 — `ops-kms` aufsetzen, Unseal-Vault umziehen

**Prio:** P0 · **Risiko:** ● · **Aufwand:** M

**Lösung**
Der leichteste Teil: Der Unseal-Vault ist bereits ein eigenständiger Knoten mit File-Storage und
täglichem Tarball nach S3 (`backup-unseal.sh`).

```
1. ops-kms aus toob-base, Rolle vault-kms
2. Tarball aus toob-vault-backups/unseal-snapshots/ einspielen
3. TLS-Zertifikat mit neuen SANs, Firewall auf die künftigen ops-vault-IPs
4. seal "transit"-Stanza der bestehenden Primaries auf ops-kms zeigen lassen
5. Primary neu starten → entsiegelt sich über den neuen KMS
```

Zwischen Schritt 4 und 5 darf der Primary nicht unabsichtlich neu starten. Die alte Instanz
bleibt bis zur Bestätigung stehen.

**Akzeptanzkriterien**
- [ ] Primary entsiegelt sich nach kontrolliertem Neustart über `ops-kms`.
- [ ] `token-ttl-exporter.sh` meldet den Autounseal-Token des neuen KMS.
- [ ] Alte Instanz läuft noch und ist als Rückweg dokumentiert.

---

### OPS-031 — `ops-vault-1/2/3`, Raft-Snapshot, drei Knoten

**Prio:** P0 · **Risiko:** ● · **Aufwand:** L

**Problem**
Zwei Themen in einem Eingriff, weil sie denselben Umzug teilen:

1. Vault liegt im Netz des Systems, das fremden Code in Firecracker ausführt.
2. Der Cluster hat **zwei** Raft-Knoten. Quorum ist 2 — er verträgt null Ausfälle, exakt wie ein
   Einzelknoten, bei doppelter Ausfallfläche.

**Lösung**
Drei Knoten in `toob-ops`, verteilt auf fsn1/hel1/nbg1. Raft-Snapshot des Bestandsclusters
einspielen, Entsiegelung über `ops-kms`.

> **Die Transit-Keys dürfen unter keinen Umständen neu erzeugt werden.** Ihre öffentlichen
> Hälften sind Vertrauensanker in eFuses ausgelieferter Geräte und in signierten Images. Der
> Snapshot enthält sie. Wer hier `vault write -f transit/keys/…` tippt, hat jede
> Vertrauensbeziehung im Feld zerstört.

Danach die Clients umhängen: Vault-Agents auf den Registry-Knoten, `deploy.sh`, Backup-Skripte.

**⟳ nachgezogen — es sind drei Cluster, nicht einer**

Der Entwurf sprach von „dem Bestandscluster". Tatsächlich existieren nach `topology.go` drei
vollständige Vault-Installationen, je eine pro Umgebung:

| Umgebung | Primary | Unseal-Vault | Transit-Keys |
|---|---|---|---|
| production | `10.0.1.10` + `10.0.1.11` | `10.0.1.12` | `…-production` |
| dev | `10.1.1.10` | `10.1.1.12` | `…-dev` |
| staging | `10.2.1.10` | `10.2.1.12` | `…-staging` |

**Drei Raft-Snapshots lassen sich nicht in einen Cluster restoren** — ein Restore ersetzt den
gesamten Clusterzustand, er fügt nichts hinzu. Der Umzug ist deshalb kein einheitlicher
Vorgang, sondern zwei verschiedene:

**Produktion: Snapshot-Restore.** Nur hier sind die Transit-Keys unersetzbar — sie haben
Images signiert, die deployt sind, und Pakete, die veröffentlicht wurden. Der Snapshot
erhält sie.

**Dev und Staging: Inhaltskopie, neue Keys.** KV-Secrets per `vault kv get | put` in die
Pfade aus `OPS-032` übertragen, Transit-Keys neu erzeugen. Das ist zulässig, weil keine
Dev- oder Staging-Signatur außerhalb der jeweiligen Umgebung Vertrauen genießt.

> **Nebenwirkung, die ins Runbook gehört:** Nach dem Neuerzeugen der Dev-/Staging-Keys
> schlägt `deploy.sh verify` für bereits gebaute Images fehl, weil deren Signatur gegen den
> alten Schlüssel entstand. `deploy.sh all` ist unproblematisch — es signiert neu. Ein
> isoliertes `deploy.sh deploy` ohne vorheriges `sign` bricht ab, und das ist richtig so.

**Zusätzlich zu beachten — Schlüsseltypen unterscheiden sich:**
`stages/deploy.go` prüft vor jedem Deploy, dass `transit/keys/toob-image-signing-<env>` vom
Typ **`ecdsa-p256`** ist, und bricht sonst ab — Cosign unterstützt für Vault-Transit kein
Ed25519. Der Firmware-Schlüssel aus `OPS-033` muss dagegen **Ed25519** sein, weil der
Bootloader nichts anderes verifiziert. Wer beide über dieselbe Zeile anlegt, produziert
entweder einen Deploy, der abbricht, oder eine Firmware, die kein Gerät akzeptiert.

**Reihenfolge innerhalb des Tickets**
1. Produktions-Snapshot restoren, Clients umhängen, verifizieren.
2. Erst danach dev und staging inhaltlich übertragen — bei Problemen ist die Produktion
   dann schon stabil.

**Akzeptanzkriterien**
- [ ] `vault read transit/keys/toob-package-signing-production` liefert dieselbe Key-Version
      und denselben öffentlichen Schlüssel wie vorher.
- [ ] Ein Cosign-Verify eines **vor** der Migration signierten Produktions-Images ist gültig.
- [ ] Dev und Staging sind funktionsfähig, ihre Keys sind neu und als solche dokumentiert.
- [ ] Ausfall eines Vault-Knotens beeinträchtigt den Betrieb nicht (aktiv getestet).
- [ ] Angekündigtes Wartungsfenster, alte Cluster bleiben bis zur Bestätigung stehen.

---

### OPS-032 — Vault-Pfade auf Projektstruktur

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** M

**Lösung**
```
secret/projects/{registry,update,identity,staging}/…
secret/platform/…                          nur Kontrollebene
```

Eine AppRole je Projekt und Rolle, Zugriff auf genau den eigenen Präfix. Die bestehenden neun
Policies aus `init.sh` werden entsprechend umgeschrieben, die PKI bleibt registry-intern.

**Akzeptanzkriterien**
- [ ] Negativtest je Projekt: keine AppRole liest den Präfix eines anderen.
- [ ] `seed.sh` schreibt in die neuen Pfade.

---

### OPS-033 — Transit-Key `update-firmware-signing` trennen

**Prio:** P0 · **Risiko:** ◐ · **Aufwand:** S

**Problem**
Würde Firmware mit `toob-image-signing` oder `toob-package-signing` signiert, könnte ein
kompromittierter Registry-Release-Pfad Firmware signieren. Das ist die wichtigste
Einzelmaßnahme der Produkttrennung.

**Lösung**
Eigener Ed25519-Transit-Key mit eigener Policy, ausschließlich für den Signing-Pfad des Update
Service erreichbar.

**Akzeptanzkriterien**
- [ ] Die Registry-Release-Policy hat keinen Zugriff (Negativtest).
- [ ] Falls bereits mit einem geteilten Key signiert wurde: Migrationspfad für Bestandsgeräte
      ist dokumentiert — der alte öffentliche Schlüssel liegt in eFuses und wird nicht ersetzt,
      der neue kommt als zusätzlicher `key_index` in die Provisionierung.

---

### OPS-034 — Cosign-Token durch Token-pro-Lauf ersetzen

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** M

**Problem**
Runbook 5.6 erzeugt einen Token mit `-period=720h` für die Release-Pipeline, mit dem Hinweis,
ihn manuell zu erneuern — ein langlebiges Signier-Credential außerhalb von Vault.

**Lösung**
`ops-ci` authentifiziert sich per AppRole und zieht pro Lauf einen kurzlebigen Token. Das
Dauercredential entfällt ersatzlos.

**Akzeptanzkriterien**
- [ ] Kein Token mit Laufzeit über 24 h in der Pipeline.
- [ ] Ein Build ohne gültige AppRole-Credentials bricht ab, statt unsigniert zu deployen.

---

### OPS-035 — Alte Vault-Instanzen abbauen

**Prio:** P2 · **Risiko:** ◐ · **Aufwand:** S

Nach mindestens sieben Tagen stabilem Betrieb: alten Primary-Cluster und alte Unseal-Instanz
abbauen, Firewall-Regeln entfernen, Vault-Ports auf den Registry-Knoten schließen.

---

# EPIC E — Beobachtung umziehen

---

### OPS-040 — Registry als ersten Spoke anbinden

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** M

**Lösung**
`wg-peer`-Rolle auf `reg-api-fsn1` (aktiv) und `reg-api-hel1` (Standby), Dial-Out zum Hub,
Routing für `10.0.1.0/24` inklusive der Worker-Subnetze.

Die Registry ist bewusst der erste Spoke: Wenn das Muster dort trägt — mit dynamischen Workern,
die kommen und gehen — trägt es überall.

**Akzeptanzkriterien**
- [ ] `ops-hub` erreicht alle Registry-Knoten inklusive frisch skalierter Worker.
- [ ] Der bestehende Bastion funktioniert weiter (Abbau erst in OPS-090).

---

### OPS-041 — Monitoring nach `ops-hub` umhängen

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** L

**Lösung**
Scrape-Ziele über den Tunnel, inklusive `nomad_sd_configs` für die dynamischen Worker. Alloy auf
allen Registry-Knoten auf Push zum Hub-Loki umstellen (mTLS, Pflicht-Label `project=registry`,
Rate-Limit, Retention-Cap).

Der alte Stack auf `reg-api-fsn1` bleibt eine Woche parallel — beide Grafana-Instanzen müssen
dieselben Werte zeigen, bevor der alte abgebaut wird.

**Akzeptanzkriterien**
- [ ] Alle fünf Dashboards funktionieren gegen die neue Instanz.
- [ ] Ein neu skalierter Worker erscheint innerhalb von zwei Minuten in Prometheus.
- [ ] Ein Spoke kann über den Loki-Port keine anderen Hub-Dienste erreichen.

---

### OPS-042 — Zwei-Sonden-Muster

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Für jeden öffentlichen Dienst zwei unabhängige Sonden: interner Scrape über den Tunnel und
externe Blackbox-Probe über Cloudflare. Der Nutzen ist Diagnose:

| Extern | Intern | Diagnose |
|---|---|---|
| up | down | Tunnel oder Scrape-Konfiguration |
| down | up | Edge, DNS oder Zertifikat |
| down | down | der Dienst |

Ohne die zweite Sonde weiß man im Ernstfall nicht, wo zu suchen ist.

**Akzeptanzkriterien**
- [ ] Beide Sonden je Hostname, in einem Dashboard nebeneinander.
- [ ] Ein absichtlich abgeschalteter Tunnel erzeugt das Muster „extern up, intern down".

---

### OPS-043 — Alert-Routing und Dead-Man-Switch pro Projekt

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** S

**Problem**
Ein globaler Watchdog beweist nur, dass Alertmanager lebt. Er verdeckt, dass die Metriken eines
einzelnen Projekts seit Stunden fehlen.

**Lösung**
Routing über das `project`-Label, eigener Kanal je Projekt, eigener Heartbeat je Projekt.
Schweregrade nach Ausfallwirkung: `upd-edge` beide Knoten kritisch, `toob-identity` hoch,
Vault niedrig — dass Vault der niedrigste ist, bestätigt, dass P3 hält.

---

### OPS-044 — Loki-Mandantentrennung vorbereiten

**Prio:** P2 · **Risiko:** ○ · **Aufwand:** M

**Problem**
Sobald Kunden Grafana-Leserechte auf ihre Dashboards bekommen — ein erklärtes Ziel — müssen Logs
und Metriken mandantengefiltert sein. Heute enthalten sie Geräte-IDs aller Mandanten.

**Lösung**
Loki-Mandantentrennung über `X-Scope-OrgID`, Grafana-Datenquellen pro Ordner mit festem
Mandantenkontext. **Vor** der ersten Freischaltung für Kunden, nicht danach.

---

# EPIC F — Identity-Spoke

---

### OPS-050 — Projekt `toob-identity`, zwei Knoten

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Netz `10.20.0.0/16`, Subnetz `10.20.1.0/24`, zwei CX22 aus `toob-base` mit `wg-peer`- und
`caddy`-Rolle, Ubicloud-Instanz `toob-idp-db`. Cloudflare-Hostname `id.the-toob.com` mit
Geo-LB über beide Knoten.

> **Korrektur:** Die erste Fassung sah `10.2.1.0/24` vor. Das kollidiert mit
> `topology.Get("staging")`, das bereits `10.2.0.0/16` belegt. Verbindlicher Plan siehe
> `OPS-006`.

Zitadel liegt bewusst **nicht** in der Kontrollebene: Ein öffentlich erreichbarer Dienst mit
eigenem CVE-Strom gehört nicht in dasselbe Netz wie Vault und der WireGuard-Hub.

---

### OPS-051 — Zitadel installieren, HA praktisch verifizieren

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** L

**Lösung**
Zitadel als systemd-Unit auf beiden Knoten gegen dieselbe Postgres-Instanz, Caddy davor mit dem
jeweils anderen Knoten als Fallback.

> **Offener Punkt aus der Architektur:** Dass zwei Instanzen gegen eine Postgres-Instanz
> tragen, steht in der Dokumentation und ist praktisch zu bestätigen. Dieses Ticket ist
> erst fertig, wenn ein Knoten während eines Logins abgeschaltet wurde und die Session
> überlebt hat.

**Akzeptanzkriterien**
- [ ] Login funktioniert über beide Knoten.
- [ ] Abschalten eines Knotens während einer aktiven Session unterbricht diese nicht.
- [ ] Backup der Zitadel-Datenbank läuft und ist in OPS-021 eingehängt.
- [ ] Scrape und Blackbox-Probe nach OPS-042 sind eingerichtet.

---

### OPS-052 — Registry-Login auf Zitadel umstellen

**Prio:** P2 · **Risiko:** ◐ · **Aufwand:** M

**Lösung**
GitHub bleibt als *Anmeldemethode* erhalten, aber hinter Zitadel statt daneben. Industriekunden
haben nicht alle GitHub, und zwei Identitätsmodelle für dieselben Menschen sind ein
Dauerärgernis.

Grafana-SSO wandert mit — dann eine Identität für Registry, Grafana und später das
Fleet-Management.

**Akzeptanzkriterien**
- [ ] Bestehende Nutzer behalten ihre Zuordnung.
- [ ] Der alte OAuth-Pfad ist entfernt, nicht nur deaktiviert.

---

### OPS-053 — Workload-Identity-Federation für Kunden-CI

**Prio:** P2 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
GitHub-/GitLab-OIDC-Token gegen ein kurzlebiges Toob-Token eintauschbar. Damit braucht keine
Kunden-Pipeline ein langlebiges Secret bei uns — und wir haben keines zu rotieren.

---

# EPIC G — Modul und Staging

---

### OPS-060 — `project-baseline`-Terraform-Modul

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** L

**Lösung**
Ein Modul, das aus einem Projektnamen erzeugt: Netz, Subnetz, Firewall-Baseline, Knoten aus
`toob-base`, WireGuard-Peer mit Registrierung am Hub, Vault-Pfad mit Policies und AppRoles,
Ubicloud-Instanz mit Firewall-Pinning, Prometheus-Scrape-Job, Grafana-Ordner, Alert-Route,
Dead-Man-Switch, Backup-Eintrag, Terraform-State-Key.

Die bestehenden Projekte werden **nachträglich** auf das Modul umgestellt, nicht vorher — sonst
baut man das Modul gegen eine Annahme statt gegen die Realität.

**Akzeptanzkriterien**
- [ ] Ein neues Projekt entsteht aus einer Variablendatei, ohne manuelle Schritte außerhalb der
      dokumentierten Vault-Zeremonien.
- [ ] OPS-061 ist der Nachweis.

---

### OPS-061 — `toob-staging` als Nachweis

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Erster Spoke vollständig aus dem Modul, ein Knoten, kleinere Größen. Staging spiegelt die
Software, nicht die Topologie — der Zweck ist, Migrationen, Deploys und den Abschalttest zu
üben.

**Akzeptanzkriterien**
- [ ] Das Projekt entsteht ohne Handgriffe außerhalb des Moduls.
- [ ] Was am Modul nachgebessert werden musste, ist als Commit sichtbar.

---

### OPS-062 — Promotion statt Rebuild

**Prio:** P2 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Ein Artefakt wird einmal gebaut und signiert, durchläuft Staging und wandert mit **demselben
Digest** nach Produktion. Kein zweiter Build, kein „lokal ging es".

**Akzeptanzkriterien**
- [ ] Der Digest ist in beiden Umgebungen identisch (nachgewiesen, nicht angenommen).
- [ ] Ein Deploy nach Produktion ohne vorherigen grünen Staging-Lauf ist nicht möglich.

---

# EPIC H — Update-Spoke

---

### OPS-070 — Projekt `toob-update` aus dem Modul

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

Netz `10.30.0.0/16`, Subnetz `10.30.1.0/24`, `upd-edge-fsn1`, `upd-edge-hel1`, `upd-fleet`,
Ubicloud `toob-update-db`. Hostnames `ota.` (Geo-LB über beide Edge-Knoten) und `api.`
(auf `upd-fleet`).

> **Korrektur, und die schwerwiegendste im ganzen Dokument:** Die erste Fassung sah
> `10.1.1.0/24` vor. Das ist **bitgenau dasselbe Subnetz**, das `topology.Get("dev")` für die
> Registry-Dev-Umgebung belegt — inklusive `10.1.1.10` für `api-fsn1` und `10.1.1.12` für den
> Unseal-Vault. `upd-edge-fsn1` hätte dieselbe Adresse bekommen wie ein Registry-Dev-Knoten.
>
> Aufgefallen wäre das erst am WireGuard-Hub: Zwei Peers mit identischem `AllowedIPs` sind
> nicht routbar, und WireGuard meldet das nicht als Fehler — es liefert Pakete an den zuletzt
> passenden Peer. Verbindlicher Plan siehe `OPS-006`.

---

### OPS-071 — systemd-Units, Caddy, Rolling-Deploy

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

**Lösung**
Kein Nomad. Systemd mit `Restart=on-failure`, `NoNewPrivileges`, `ProtectSystem=strict`,
`CapabilityBoundingSet=`, cgroup-Grenzen. Caddy mit `lb_policy first` auf den Nachbarknoten.

Rolling Deploy als Skript in `scripts/rolling-deploy.sh`:

```
Knoten A aus dem Caddy-Upstream nehmen
Binary tauschen, Unit neu starten
/ready pollen bis grün (Timeout → Abbruch, kein Weitermachen)
Knoten A zurück in den Upstream
dasselbe für B
```

Rund fünfzig Zeilen. Die Ausfallfläche dieses Mechanismus ist bei Nichtbenutzung null — die
eines Orchestrators nicht.

**Akzeptanzkriterien**
- [ ] Ein Deploy erzeugt keine Unterbrechung (Lasttest während des Deploys).
- [ ] Ein fehlschlagender Health-Check bricht ab und lässt Knoten B unberührt.

---

### OPS-072 — Blob-Route `fw.` direkt auf Object Storage

**Prio:** P0 · **Risiko:** ○ · **Aufwand:** S

**Lösung**
Bucket `toob-firmware`, `fw.the-toob.com` als CNAME darauf, wie `cdn.` es für Pakete bereits
tut. Zwingende Regeln:

- **Compress off** — transparentes gzip verschiebt Bytegrenzen und zerstört jeden Resume.
- `Cache-Control: immutable`, Origin Cache Lock gegen den Miss-Sturm nach Publish.
- Kein Redirect — der MCU-HTTP-Client folgt ihnen nicht zuverlässig.
- Bucket-Listing aus, Lifecycle: **niemals löschen**, solange Geräte im Feld sind.

**Akzeptanzkriterien**
- [ ] `Range: bytes=999999999-` liefert `416`, nicht `200`.
- [ ] `Accept-Encoding: gzip` liefert trotzdem `identity`.
- [ ] Kein Response auf dieser Route hat Status `3xx`.

---

# EPIC I — Invarianten nachweisen

---

### OPS-080 — Abschalttest gegen Staging, zweimal manuell

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

`toob-ops` herunterfahren, prüfen dass die Staging-Endpunkte weiter antworten. Zweimal, weil der
erste Lauf erfahrungsgemäß etwas findet und man das Ergebnis der Behebung bestätigen will.

---

### OPS-081 — Abschalttest gegen Produktion, einmal manuell

**Prio:** P0 · **Risiko:** ● · **Aufwand:** S

Wartungsfenster mit niedrigem Verkehr. Geprüft wird, dass `ci.`, `ota.` und `fw.` antworten und
ein Geräte-Check-in durchläuft. Das Ergebnis muss **von außerhalb** erhoben werden — der eigene
Prometheus ist ja aus.

Ein Test, der beim ersten automatischen Lauf die Produktion trifft, ist selbst ein Risiko.

---

### OPS-082 — Abschalttest automatisieren

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** M

Wöchentlich, Ergebnis über eine externe Sonde. Negativtest: Baut man absichtlich eine
Laufzeitabhängigkeit ein, muss der Test rot werden — sonst prüft er nichts.

---

### OPS-083 — Portscan aller Projektnetze (P2-Nachweis)

**Prio:** P1 · **Risiko:** ○ · **Aufwand:** S

Von außerhalb: null offene Ports in allen Spoke-Projekten, genau ein UDP-Port in `toob-ops`.
Als wiederkehrender Job, nicht als einmalige Prüfung.

---

### OPS-084 — Vault 24 Stunden abgeschaltet (P3-Nachweis)

**Prio:** P1 · **Risiko:** ◐ · **Aufwand:** S

Beweist, dass kein Datenpfad-Secret unter 30 Tagen TTL liegt. Nach 24 Stunden müssen Check-in
und Download unverändert funktionieren.

Erst gegen Staging, dann gegen Produktion.

---

# EPIC J — Altlasten abbauen

---

### OPS-090 — Registry-Bastion abbauen

**Prio:** P2 · **Risiko:** ◐ · **Aufwand:** S

Nach OPS-040 ist er redundant. Server abbauen, öffentlichen WireGuard-Port schließen, Firewall
bereinigen.

---

### OPS-091 — Nomad-Bootstrap-Token nach Vault

**Prio:** P2 · **Risiko:** ◐ · **Aufwand:** S

`/root/nomad-bootstrap-token.txt` ist ein Management-Token im Klartext auf der Platte. Nach
`secret/platform/nomad-bootstrap`, Datei schreddern — analog zum Root-Token, der bereits
automatisch revoked wird.

---

### OPS-092 — Secret-Seeding ohne Operator-Environment

**Prio:** P2 · **Risiko:** ◐ · **Aufwand:** M

**Problem**
Der `SEED_*`-Mechanismus bedeutet, dass beim Bootstrap jedes Produktionsgeheimnis in der Shell
des Operators steht — inklusive History, sofern nicht bewusst abgeschaltet.

**Lösung**
Kurzfristig: Seeding aus einer `0600`-Datei via `vault kv put @file`.
Mittelfristig: `ops-ci` führt das Seeding aus und holt die Werte aus einem verschlüsselten
Repo-Secret. Kein Mensch sieht sie im Klartext.

---

### OPS-093 — Cloudflare-Token pro Projekt

**Prio:** P3 · **Risiko:** ◐ · **Aufwand:** S

Statt eines Tokens mit `Zone:Edit` und `LB:Edit` für alles: ein Token je Projekt, auf die
jeweiligen Hostnames und Regeln begrenzt.

---

### OPS-094 — DB-Firewall-Pruner als Plattformdienst

**Prio:** P3 · **Risiko:** ◐ · **Aufwand:** S

Vom Unseal-Vault nach `ops-hub`, bedient alle Ubicloud-Instanzen aller Projekte. Eine
Konfigurationszeile pro Projekt statt eines Timers pro Projekt. `STATIC_WHITELIST_IPS` bleibt
erhalten.

---

## Reihenfolge und Gates

| Phase | Tickets | Gate |
|---|---|---|
| **0 — Aufräumen** | OPS-001 … OPS-005 | `terraform plan` aus frischem Clone: keine Änderungen in allen fünf Modulen |
| **1 — Kontrollebene** | OPS-010 … OPS-014, OPS-022 | Admin erreicht `ops-hub`, Break-Glass einmal geübt |
| **2 — Sicherheitsnetz** | OPS-020, OPS-021 | **Restore-Test grün.** Ohne dieses Gate beginnt Phase 3 nicht |
| **3 — Vault** | OPS-030 … OPS-035 | Cosign-Verify eines alten Images gilt weiterhin |
| **4 — Beobachtung** | OPS-040 … OPS-044, OPS-090 | Beide Grafana-Instanzen zeigen eine Woche dieselben Werte |
| **5 — Identity** | OPS-050 … OPS-053 | Knotenausfall während einer Session unterbricht sie nicht |
| **6 — Modul + Staging** | OPS-060 … OPS-062 | Ein Projekt entsteht aus einer Variablendatei |
| **7 — Update-Spoke** | OPS-070 … OPS-072 | `fw.` liefert `416` und `identity` korrekt |
| **8 — Nachweise** | OPS-080 … OPS-084 | Alle vier Invarianten getestet, nicht behauptet |
| **9 — Hygiene** | OPS-091 … OPS-094 | — |

**Phase 0 und 1 laufen ohne jeden Eingriff in den Bestand.** Wer den Umbau abbrechen will, kann
es dort ohne Rückbau tun.

`toob-update` (Phase 7) hängt technisch nur an Phase 6. Wer den Update-Service früher braucht,
kann ihn nach Phase 1 bauen und übergangsweise Secrets aus dem alten Vault beziehen — die
Migration ist keine Vorbedingung, nur eine Aufräumarbeit, die man sonst später doppelt macht.

---

## Was ich für die Feinplanung bräuchte

Der Anhang kam leer an. Für drei Tickets ist die Schätzung ohne die tatsächlichen Dateien
unsicher:

| Ticket | Warum |
|---|---|
| OPS-001 | Der genaue Schnitt zwischen Build- und Deploy-Artefakten hängt an den Makefiles |
| OPS-005 | Der Aufwand der Rollen-Zerlegung folgt direkt aus der Struktur von `playbook.yml` |
| OPS-031 | Die Client-Liste (wer zeigt auf Vault) bestimmt den Umfang des Wartungsfensters |

Nützlich wären: `ansible/playbook.yml`, `terraform/control-plane/*.tf`, `api/deploy.sh`,
`packer/image.pkr.hcl` und die Liste der Vault-Policies aus `init.sh`.

---

## Merksatz

> Die riskanteste Stunde des ganzen Umbaus ist der Vault-Umzug, und die wertvollste ist der
> Restore-Test davor. Alles andere in diesem Backlog ist reversibel — die Transit-Keys sind es
> nicht.