# Struktur — `toob-infra`

**Zweck:** Zielstruktur für den heutigen `toob-registry/deploy/`-Baum, ausgerichtet auf
`ARCHITEKTUR-devops.md` (fünf Projekte, Kontrollebene `toob-ops`, Spokes für Registry,
Identity, Update, Staging).

**Ausgangslage:** Der Umbau ist weiter fortgeschritten, als die Backlogs annehmen. Erledigt
oder größtenteils erledigt sind `OPS-004` (Image-Split), `OPS-005` (Rollen), `OPS-020`
(Restore-Test), `OPS-060` (Baseline-Modul, angefangen), `BEF-007` (notify-recovery),
`BEF-008` (`versions.json`), `BEF-012` (Nomad-Templates).

---

## 1. Die drei Strukturprobleme

### P1 — Zwei parallele Terraform-Welten

```
terraform/cloudflare/     ┐
terraform/database/       │  nach Ressourcentyp — der alte Schnitt
terraform/s3/             │
terraform/worker/         ┘
terraform/modules/        ┐  nach Wiederverwendbarkeit — der neue Schnitt
terraform/projects/       ┘
```

Beide Strukturen existieren nebeneinander, und aus dem Baum ist nicht ablesbar, welche
autoritativ ist. `stages/terraform.go` iteriert über `{s3, database, control-plane,
cloudflare}` — also die alte Welt; `projects/` wird von der CLI noch gar nicht angefasst.

Solange das so bleibt, kann ein `terraform apply` in `projects/registry` und eines in
`terraform/database` dieselbe Ubicloud-Instanz beanspruchen.

**Auflösung:** Die vier alten Verzeichnisse werden zu Modulen, `projects/` komponiert sie.
Ein Projekt ist dann eine Datei, die sagt „ich brauche ein Netz, zwei Knoten, eine Datenbank
und zwei Hostnames" — und nicht fünf Verzeichnisse, die man in der richtigen Reihenfolge
anfassen muss.

### P2 — Hohle Rollen, die nach außen greifen

Alle zwölf Rollen enthalten ausschließlich `tasks/main.yml` (Ausnahmen: `wg-hub`, `wg-peer`,
`zitadel` haben Templates bzw. Handler). Die Dateien, die sie ausrollen, liegen daneben:
`caddy/Caddyfile.j2`, `monitoring/prometheus/*`, `vault/*.hcl.j2`, `nomad/*.j2`.

Die Rollen müssen also mit `src: "../../../caddy/Caddyfile.j2"` hinausgreifen — dasselbe
Muster wie im alten Monolith-Playbook. Eine Rolle, die das tut, ist nicht für sich testbar
und nicht in ein anderes Playbook übertragbar.

**Auflösung:** Was Ansible ausrollt, gehört in die Rolle. Was andere Werkzeuge konsumieren
(Terraform, Packer, Release-Skripte), bleibt außerhalb.

### P3 — Generiertes und Geheimes im Baum

| Pfad | Art |
|---|---|
| `.toob-ops-secrets.dev.json` | **Secrets** — siehe `BEF-001`, `BEF-002` |
| `.toob-ops-state.dev.json`, `.dryrun` | Laufzeitzustand |
| `terraform/*/tfplan` | **Plan-Dateien mit aufgelösten Variablenwerten**, u. a. das Cloudflare-Token |
| `terraform/*/.terraform/providers/**` | Provider-Binaries, hier für **zwei** Plattformen (`linux_amd64` und `windows_amd64`) |
| `terraform/*/.terraform/terraform.tfstate` | Backend-Cache |
| `packer/packer-manifest.json` | Build-Ausgabe |
| `api/.last_tag.dev` | Laufzeitzustand |
| `logs/dev/` | Laufzeitausgabe |

Die Provider-Binaries sind der größte Posten: `terraform-provider-cloudflare_v5.19.1.exe`
und `terraform-provider-aws_v5.100.0_x5` liegen jeweils in beiden Plattformvarianten. Das
sind mehrere hundert Megabyte, die bei jedem Clone mitkommen.

> **Zu prüfen:** Ob diese Pfade tatsächlich in Git stehen oder nur lokal existieren, kann ich
> aus dem Verzeichnisbaum nicht sehen. `git ls-files terraform/ | grep -c '\.terraform/'`
> beantwortet es. Falls sie getrackt sind, ist eine History-Bereinigung nötig — und für das
> Cloudflare-Token in `tfplan` gilt `BEF-001` sinngemäß.

---

## 2. Zielstruktur

```
toob-infra/
├── .gitignore                        ← neu, siehe §4
├── README.md                         Einstieg: welches Kommando für welchen Zweck
├── versions.json                     einzige Versionsquelle (Nomad, Vault, Terraform, …)
├── Dockerfile.ops                    Tooling-Container
│
├── terraform/
│   ├── modules/                      wiederverwendbar, kennen kein Projekt
│   │   ├── project-baseline/         Netz, Subnetz, Firewall-Baseline, WG-Peer-Eintrag
│   │   ├── spoke-nodes/              Knoten aus toob-base, Rollen-Meta, Platzierung
│   │   ├── ubicloud-postgres/        ← aus terraform/database/
│   │   ├── object-storage/           ← aus terraform/s3/
│   │   ├── edge-hostname/            ← aus terraform/cloudflare/, ein Hostname je Aufruf
│   │   └── nomad-workers/            ← aus terraform/worker/, nur Registry
│   │
│   └── projects/                     komponiert Module, kennt keine Ressourcendetails
│       ├── ops/                      main.tf, vault_cluster.tf, hub.tf
│       ├── registry/                 je Umgebung über Workspaces oder tfvars
│       ├── identity/
│       ├── update/
│       └── staging/
│
├── packer/
│   ├── base.pkr.hcl                  toob-base
│   ├── worker.pkr.hcl                toob-worker = base + Firecracker
│   └── scripts/
│       ├── install-base.sh
│       ├── install-binaries.sh       liest versions.json
│       └── install-worker.sh
│
├── ansible/
│   ├── ansible.cfg
│   ├── site.yml                      Verteiler auf die Projekt-Playbooks
│   ├── playbooks/
│   │   ├── ops.yml                   wg-hub, vault-kms, vault-primary, monitoring, ci-runner
│   │   ├── registry.yml              common, wg-peer, caddy, nomad
│   │   ├── identity.yml              common, wg-peer, caddy, zitadel
│   │   ├── update.yml                common, wg-peer, caddy, update-service
│   │   └── staging.yml
│   ├── group_vars/
│   │   ├── all.yml
│   │   └── <projekt>.yml
│   ├── inventory/                    generiert von toob-ops → .gitignore
│   └── roles/
│       └── <rolle>/
│           ├── defaults/main.yml     überschreibbare Werte
│           ├── tasks/main.yml
│           ├── handlers/main.yml
│           ├── templates/            .j2 dieser Rolle
│           └── files/                statische Dateien dieser Rolle
│
├── vault/                            was NICHT Ansible ausrollt
│   ├── policies/
│   │   ├── platform/                 autounseal, backup, monitoring, deployer, cosign
│   │   └── projects/
│   │       ├── registry/             registry-api, -worker, -autoscaler, nomad-*
│   │       ├── identity/             identity-service, workload-identity
│   │       └── update/               update-service
│   └── operator_gpg_keys/            → .gitignore, aber Verzeichnis mit .gitkeep
│
├── nomad/                            nur Registry — bewusst nicht projektabstrahiert
│   └── jobs/
│       ├── registry-api.nomad.hcl
│       ├── registry-migrate.nomad.hcl
│       ├── registry-worker.nomad.hcl
│       └── registry-autoscaler.nomad.hcl
│
├── monitoring/                       Konfiguration, die Ansible als Datei ausrollt
│   ├── prometheus/
│   │   ├── rules/
│   │   │   ├── common.yml            InstanceDown, DiskSpace, Backup, Watchdog
│   │   │   ├── registry.yml          Autoscaler, Worker-Queue, Nomad
│   │   │   ├── identity.yml
│   │   │   ├── update.yml
│   │   │   └── platform.yml          Vault, TLS-Rotation, Token-TTL, Restore-Test
│   │   └── blackbox.yml
│   └── grafana/
│       └── dashboards/
│           ├── platform/             ops-home, vault-security, infrastructure
│           └── projects/
│               ├── registry/         api-performance, worker-pipeline
│               ├── identity/
│               └── update/
│
├── release/                          ehemals api/deploy.sh, zerlegt
│   ├── sign.sh                       Cosign gegen Vault Transit — gemeinsam
│   ├── verify.sh                     gemeinsam
│   ├── deploy-nomad.sh               Registry
│   └── deploy-systemd.sh             Identity, Update (rolling)
│
├── scripts/
│   ├── break-glass.sh
│   ├── gen-admin-wg.sh
│   ├── restore-test.sh               ← aus vault/scripts/
│   └── shutdown-test.sh              OPS-080 ff.
│
└── runbooks/
    ├── vault-migration.md
    ├── break-glass.md
    ├── restore.md
    └── project-onboarding.md
```

**Bleibt in `toob-registry`** (baut das Produkt, deployt es nicht):
`api/Dockerfile.api`, `compiler/` vollständig, `worker/Makefile`, `worker/build-rootfs.sh`,
`worker/setup-host.sh`.

---

## 3. Verschiebetabelle

| Von | Nach | Begründung |
|---|---|---|
| `caddy/Caddyfile.j2` | `ansible/roles/caddy/templates/` | Rolle besitzt ihre Dateien |
| `caddy/caddy.service` | `ansible/roles/caddy/files/` | |
| `vault/vault.hcl.j2`, `vault.service`, `vault.logrotate` | `ansible/roles/vault-primary/{templates,files}/` | |
| `vault/unseal-vault.hcl.j2`, `unseal-vault.service` | `ansible/roles/vault-kms/{templates,files}/` | |
| `vault/scripts/init.sh`, `seed.sh` | `ansible/roles/vault-primary/files/` | von Ansible ausgeführt |
| `vault/scripts/init-unseal.sh` | `ansible/roles/vault-kms/files/` | |
| `vault/scripts/backup.sh` | `ansible/roles/vault-primary/files/` | als Timer ausgerollt |
| `vault/scripts/backup-unseal.sh` | `ansible/roles/vault-kms/files/` | |
| `vault/scripts/restore-test.sh` | `scripts/` | läuft auf `ops-hub`, nicht Teil einer Rolle |
| `vault/policies/*.hcl` | `vault/policies/{platform,projects/*}/` | Projektzuordnung sichtbar machen |
| `monitoring/**` (außer `grafana/`, `prometheus/rules`) | `ansible/roles/monitoring/{templates,files}/` | |
| `monitoring/systemd/notify-*` | `ansible/roles/common/files/` | jede Rolle nutzt `OnFailure` |
| `monitoring/alloy/config.alloy.j2` | `ansible/roles/common/templates/` | Alloy läuft überall |
| `nomad/{client,server}.hcl.j2`, `nomad.service` | `ansible/roles/nomad/{templates,files}/` | |
| `nomad/vault-agent*.hcl`, `templates/nomad-tls.json.tpl` | `ansible/roles/nomad/{files,templates}/` | |
| `nomad/scripts/*` | `ansible/roles/nomad/files/` | |
| `nomad/registry-*.nomad.hcl` | `nomad/jobs/` | von `release/deploy-nomad.sh` konsumiert, nicht von Ansible |
| `nomad/{client,server}.hcl` | **löschen** | Templates ersetzen sie (BEF-012) |
| `ansible/files/cleanup-db-firewall.py` | `ansible/roles/ubicloud-db/files/` | |
| `terraform/database/` | `terraform/modules/ubicloud-postgres/` | |
| `terraform/s3/` | `terraform/modules/object-storage/` | |
| `terraform/cloudflare/` | `terraform/modules/edge-hostname/` | ein Hostname je Aufruf (OPS-00B) |
| `terraform/worker/` | `terraform/modules/nomad-workers/` | |
| `api/deploy.sh` | `release/` (zerlegt, siehe §5) | |
| `api/seccomp-api.json`, `toob-api-hardening.service` | `ansible/roles/nomad/files/` | auf Nomad-Clients ausgerollt |
| `logs/` | **entfernen**, `.gitignore` | Laufzeitausgabe |

---

## 4. `.gitignore`

Vor allen Verschiebungen. Die Datei liegt separat als `gitignore-toob-infra.txt` bei.

Zwei Einträge sind sicherheitsrelevant und nicht optional:

```gitignore
.toob-ops-secrets.*.json      # Vault-Token, Nomad-Token, WireGuard-Keys
**/tfplan                     # aufgelöste Variablenwerte, u. a. Cloudflare-Token
```

Vier weitere sparen Volumen und Verwirrung:

```gitignore
**/.terraform/                # Provider-Binaries, zwei Plattformen
*.tfstate*
wg0.*.conf
packer/packer-manifest.json
```

---

## 5. Warum `deploy.sh` zerlegt wird

Heute macht `api/deploy.sh` vier Dinge: bauen, signieren, verifizieren, per Nomad ausrollen.
Für Identity und Update wird der mittlere Teil gebraucht — dieselbe Cosign-Logik gegen
denselben Vault-Transit-Pfad — aber weder Docker-Build noch Nomad.

Ohne Zerlegung dupliziert `OPS-071` (`rolling-deploy.sh`) die Signaturkette. Dann existiert
sie zweimal, und beim nächsten Cosign-Update wird eine davon vergessen.

```
release/sign.sh      ← cmd_sign      gemeinsam
release/verify.sh    ← cmd_verify    gemeinsam, inkl. der Retry-Schleife für
                                     Registry-Propagation
release/deploy-nomad.sh    ← cmd_deploy   Registry
release/deploy-systemd.sh                 Identity, Update
```

`cmd_build` wandert in die Registry-CI — es braucht `Dockerfile.api` und den Repo-Kontext,
beides Produkt und nicht Infrastruktur.

Bei der Gelegenheit gehört ein Kommentar an `verify.sh`: `--insecure-ignore-tlog` ist bei
einem selbstverwalteten Transit-Key richtig, weil die Signatur nie in Rekor landet — aber
der Flag-Name suggeriert das Gegenteil (`BEF-016`).

---

## 6. Was die Struktur bewusst *nicht* abstrahiert

**`nomad/` bleibt registry-spezifisch.** Nur die Registry hat dynamische Workloads. Ein
`nomad/jobs/<projekt>/`-Schema würde eine Projektdimension suggerieren, die es nicht gibt,
und die vier Jobspecs sind alle registry-eigen.

**Kein `projects/<name>/` als oberste Ebene.** Naheliegend, aber es würde Terraform, Ansible,
Monitoring und Release-Skripte pro Projekt vervielfachen — obwohl sich alle vier zu über
achtzig Prozent gleichen. Die Projektdimension gehört dahin, wo sie echte Unterschiede
trägt: `terraform/projects/`, `ansible/playbooks/`, `monitoring/*/projects/`,
`vault/policies/projects/`. Sonst nirgends.

**Umgebungen bekommen keine Verzeichnisebene.** Registry existiert dreifach
(prod/dev/staging), Identity und Update je zweifach. Das über Verzeichnisse abzubilden
erzeugt neun fast identische Bäume. Terraform-Workspaces oder `<projekt>.<env>.tfvars` sind
der richtige Ort — die CLI kennt die Dimension über `--env` bereits.

---

## 7. Reihenfolge

Jeder Schritt ist einzeln gegen `--env dev` verifizierbar.

| # | Schritt | Verifikation |
|---|---|---|
| 1 | `.gitignore`, generierte Dateien entfernen, History prüfen | `git ls-files` ist sauber |
| 2 | Rollen autark machen (Dateien hineinziehen) | Ansible-Lauf gegen dev ist idempotent |
| 3 | `terraform/{database,s3,cloudflare,worker}` → `modules/` | `terraform plan` je Modul: keine Änderung |
| 4 | `projects/*` auf die Module umstellen, alte Pfade entfernen | `plan` aus `projects/registry`: keine Änderung |
| 5 | `stages/terraform.go` auf `projects/` umstellen | `toob-ops wizard --env dev` läuft durch |
| 6 | `deploy.sh` zerlegen | Registry-Deploy unverändert, Signatur identisch |
| 7 | Monitoring nach `common`/`projects` aufteilen | jede Regel trägt `project` (`OPS-00A`) |
| 8 | `api/`, `compiler/`, `worker/` in `toob-registry` belassen, Rest nach `toob-infra` | `OPS-001` |

Schritt 5 ist der einzige, der die CLI anfasst — und er hängt an `OPS-007` und `OPS-008`,
weil `stages/terraform.go` die Modulliste heute fest verdrahtet hat.

---

## Merksatz

> Ansible-Rollen besitzen ihre Dateien, Terraform-Module kennen kein Projekt, und die
> Projektdimension existiert nur dort, wo sich Projekte tatsächlich unterscheiden. Alles
> andere wäre neunmal derselbe Baum.