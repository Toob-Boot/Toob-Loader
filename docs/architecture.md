# Toob-Registry — DevOps-Architektur & Deployment-Runbook

Diese Dokumentation beschreibt den vollständigen `deploy/`-Stack von Toob-Registry: die Architektur aller Schichten (Packer → Terraform → Ansible → Vault → Nomad → Build/Sign/Deploy → Monitoring) sowie ein vollständiges Runbook für ein Deployment „from scratch" — inklusive einer expliziten Liste aller Aktionen, die zwingend ein Mensch durchführen muss.

---

## Teil 1 — Architektur

### 1.1 Gesamtbild

Der Stack realisiert eine selbst-souveräne (kein AWS/GCP-KMS), zweistufig abgesicherte Plattform auf Hetzner Cloud mit Cloudflare als Edge, Ubicloud als Managed-Postgres und Hetzner Object Storage als S3. Das Kernprinzip ist Zero-Trust nach innen: jede Maschine-zu-Maschine-Kommunikation läuft über mTLS-Zertifikate aus einer eigenen Vault-PKI, alle Secrets kommen ausschließlich aus Vault, und der Firecracker-Worker (der nicht vertrauenswürdigen Code ausführt) hat keinerlei direkten Zugriff auf Datenbank, S3 oder Secrets.

```
                       Internet
                          │
            ┌─────────────┴──────────────┐
            │   Cloudflare (Edge)        │  DNS, Geo-LB, WAF/Rate-Limit,
            │   ci.the-toob.com          │  Cache (/download), TLS strict
            │   cdn.the-toob.com ────────┼──► Hetzner Object Storage (Pakete)
            └──────┬──────────────┬──────┘
        Origin-CA-TLS         Origin-CA-TLS
            ┌──────▼──────┐  ┌────▼────────┐        UDP 51820 (WireGuard)
            │ api-fsn1    │  │ api-hel1    │   ┌────────────────────────┐
            │ 10.0.1.10   │  │ 10.0.1.11   │   │ Bastion 10.0.1.2       │◄── Admin/CI
            │ Caddy:443   │  │ Caddy:443   │   │ (einziger öffentl.     │    (VPN)
            │ API:8080    │  │ API:8080    │   │  Zugangspunkt)         │
            │ Vault Raft  │  │ Vault Raft  │   └────────────────────────┘
            │ Nomad Srv+Cl│  │ Nomad Client│
            │ Monitoring  │  │             │
            │ Autoscaler  │  │             │
            └──────┬──────┘  └──────┬──────┘
                   │   Privatnetz 10.0.0.0/16 (Hetzner)
        ┌──────────┼─────────────────┼──────────────────────┐
        │          ▼                 ▼                      ▼
  ┌───────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
  │ unseal-vault      │   │ Ubicloud         │   │ worker-N 10.0.1.20+  │
  │ 10.0.1.12 (hel1)  │   │ Managed Postgres │   │ Firecracker microVMs │
  │ Transit-KMS für   │   │ (Firewall per    │   │ (Jailer, KVM, kein   │
  │ Auto-Unseal       │   │  Public-IP /32)  │   │  Netz im Gast)       │
  │ DB-FW-Pruner      │   └──────────────────┘   └──────────────────────┘
  └───────────────────┘
```

Werkzeugkette in Deploy-Reihenfolge:

1. **Lokale Builds** (`deploy/worker/Makefile`, `deploy/compiler/build-compiler.sh`) — erzeugen `build/worker`, `build/rootfs.ext4`, `build/autoscaler`.
2. **Packer** (`deploy/packer/`) — baut ein gehärtetes „Golden Image" (Ubuntu 24.04 + Docker + Nomad + Vault + Caddy + Firecracker + Worker-Binary).
3. **Terraform** (`deploy/terraform/{control-plane,cloudflare,database,s3,worker}`) — provisioniert Netz, Server, Firewalls, Edge, DB, Buckets.
4. **Ansible** (`deploy/ansible/playbook.yml`) — „Zero-Touch"-Provisionierung: CA/TLS, beide Vaults inkl. Init und Seeding, Monitoring-Stack, Caddy, Nomad-Cluster inkl. ACL-Bootstrap und Job-Deploys.
5. **deploy.sh** (`deploy/api/`) — Build → Cosign-Signatur (Vault Transit) → Verify → Nomad-Deploy (Digest-gepinnt, Migrations-Batch davor).
6. **Nomad** — Laufzeit-Orchestrierung von API-Container, Migrations-Job, Firecracker-Worker und Autoscaler.

### 1.2 Knoten, Netzwerk, Firewalls

| Knoten | Private IP | Standort | Image | Rollen |
|---|---|---|---|---|
| `toob-bastion-gateway` | 10.0.1.2 | fsn1 | ubuntu-24.04 (cloud-init) | WireGuard-VPN-Gateway; **einziger öffentlich erreichbarer Dienst** (UDP 51820). NAT/Forwarding ins Privatnetz. |
| `toob-api-fsn1` | 10.0.1.10 | fsn1 | Golden Image | Primärknoten: Vault-Raft-Node, Nomad **Server**+Client, Caddy, API-Container, kompletter Monitoring-Stack (Docker Compose), Autoscaler-Job, Backup-Timer, Token-TTL-Exporter |
| `toob-api-hel1` | 10.0.1.11 | hel1 | Golden Image | Sekundär: Vault-Raft-Peer (retry_join), Nomad Client, Caddy, API-Container |
| `toob-unseal-vault` | 10.0.1.12 | hel1 | Golden Image | Minimaler KMS-Vault (Transit-Engine, File-Storage, TLS 1.3) für Auto-Unseal des Primary-Vaults; außerdem DB-Firewall-Pruning-Timer |
| `toob-worker-N` | 10.0.1.20+N | fsn1 | Golden Image (cloud-init) | Dedizierte Firecracker-Hosts (ccx13), Nomad Client `pool=worker` |

Netz: `hcloud_network` 10.0.0.0/16, Subnetz 10.0.1.0/24 (Zone eu-central, spannt fsn1+hel1).

Firewall-Politik (Hetzner Cloud Firewalls):

- **API-Knoten:** 443/80 nur von Cloudflare-IP-Ranges (zur Apply-Zeit live von cloudflare.com/ips geladen); SSH 22, Nomad 4646–4648 (TCP+UDP), Worker-mTLS-API 8443, Vault 8200/8201, node-exporter 9100 ausschließlich aus 10.0.0.0/16.
- **Unseal-Vault:** SSH nur privat; 8200 nur von 10.0.1.10/32 und 10.0.1.11/32.
- **Worker:** ausschließlich SSH aus dem Privatnetz; keinerlei öffentliche Ports.
- **Bastion:** ausschließlich UDP-WireGuard-Port öffentlich. Kein öffentliches SSH irgendwo im Cluster — Verwaltung geht **nur über das VPN**.

Interne Namensauflösung ohne DNS-Server, rein über `/etc/hosts` (durch Ansible/cloud-init gesetzt):

- `vault.the-toob.com` → 10.0.1.10 und 10.0.1.11 (Primary-Vault-Cluster; Zertifikate tragen diesen SAN)
- `api.global.nomad` → 10.0.1.10 und 10.0.1.11 (mTLS-API-Endpunkt der Worker auf Port 8443)

Öffentliche Namen: `ci.the-toob.com` (Cloudflare Load Balancer, geo-steered, Health-Check `GET /health`), `cdn.the-toob.com` (CNAME auf den Object-Storage-Bucket, proxied/gecached).

### 1.3 Externe Dienste und ihre Funktion

| Dienst | Funktion | Credentials landen in |
|---|---|---|
| Hetzner Cloud | Server, Netz, Firewalls; Autoscaler erzeugt/zerstört Worker-VMs per API | TF-Var/`secret/hetzner` |
| Hetzner Object Storage | 3 Buckets: `toob-terraform-state` (TF-Backend), `toob-vault-backups` (Snapshots), `toob-registry-packages` (Paket-Tarballs, via cdn.* ausgeliefert) | `secret/s3` |
| Cloudflare | DNS, Geo-Load-Balancer über beide Origins, SSL strict, Cache- und Rate-Limit-Rulesets, Origin-CA-Zertifikate für Caddy | TF-Var/`secret/cloudflare`, `secret/cloudflare-origin` |
| Ubicloud | Managed PostgreSQL 16 (`toob-registry-db`); Ingress-Firewall wird dynamisch auf die /32-Public-IPs der API-Knoten gepinnt und periodisch um recycelte Hetzner-IPs bereinigt | `secret/database` (Connection-URL mit `sslmode=verify-full`) |
| Docker Hub | Registry für API-Image (Pull via `docker-auth.json` aus Vault) und Compiler-Image | `secret/dockerhub` |
| GitHub | GitHub-App (Webhooks, Installationen) + OAuth-App (Login) für die Registry; separate OAuth-App für Grafana-SSO (Org-gefiltert, Team `core-admins` → Admin) | `secret/github-app`, `secret/github-oauth`, Grafana-`.env` |
| Discord / Better Stack | Alertmanager-Receiver (critical/warning) bzw. Dead-Man-Switch-Heartbeat (Watchdog-Alert feuert dauerhaft) | Monitoring-`.env` |

### 1.4 Werkzeugschichten im Detail

#### 1.4.1 Packer — Golden Image (`deploy/packer/`)

`image.pkr.hcl` baut auf Hetzner einen Snapshot `toob-golden-image` aus Ubuntu 24.04. `install-binaries.sh` installiert dabei mit kryptografischer Verifikation:

- Docker CE (offizielles APT-Repo, GPG-signiert) — Container-Driver für Nomad auf den API-Knoten.
- Nomad 1.8.1 und Vault 1.16.2 als Binaries: HashiCorp-GPG-Key wird gegen den hartkodierten Fingerprint `7F0C…D22E` geprüft, dann SHA256SUMS-Signatur und Checksumme der Zips verifiziert.
- Caddy über das offizielle Cloudsmith-APT-Repo.
- Firecracker + Jailer v1.7.0 (Jailer bekommt setuid-root, damit der unprivilegierte Worker ihn starten kann), Gast-Kernel `vmlinux-5.10.77`.
- Die **vorab lokal gebauten** Artefakte `build/worker` und `build/rootfs.ext4` werden per `file`-Provisioner eingespielt — fehlen sie, bricht der Build hart ab.
- Unattended-Upgrades, SSH-Härtung (kein Passwort-Login), machine-id-Reset, History/apt-Cleanup.

Alle Server außer dem Bastion booten aus diesem Image; Terraform selektiert es über das Label `name=toob-golden-image, most_recent`.

#### 1.4.2 Terraform — 5 unabhängige Module (`deploy/terraform/`)

| Modul | State-Backend | Inhalt |
|---|---|---|
| `control-plane` | S3 `control-plane/terraform.tfstate` | Privatnetz, 2 API-Server, Unseal-Vault-Server, Bastion (cloud-init mit WireGuard-Konfig aus Template), alle Firewalls, Cloudflare-IP-Listen. Outputs: Public/Private-IPs, Netz-ID, `wg_client_config` (fertige Client-Konfiguration). |
| `cloudflare` | lokal | LB-Monitor (`/health`), Origin-Pool aus `var.api_origins` (manuell aus control-plane-Output befüllt), Geo-LB `ci.the-toob.com`, SSL `strict` + min TLS 1.2 + TLS 1.3, Cache-Rule für `/download`, Rate-Limit 30 req/min auf `/api/v1/auth/`, DNS `cdn`-CNAME. |
| `database` | lokal | `ubicloud_postgres` Instanz (PG16, standard-2, 20 GiB, HA optional). |
| `s3` | lokal | Bucket `toob-registry-packages`: Versioning, CORS für `https://ci.the-toob.com`, Public-Access-Block, SSE-AES256, Lifecycle (Temp-Releases 7 Tage, abgebrochene Multipart-Uploads 7 Tage). |
| `worker` | S3 `worker/terraform.tfstate` | N Worker-Server (ccx13) mit umfangreichem cloud-init (siehe 1.7); liest control-plane-State remote; Firewall; **generiert `deploy/ansible/inventory.ini` neu** (`local_file`), inkl. Worker-Sektion. |

Abhängigkeitskette: control-plane → (cloudflare, worker via remote state); worker zusätzlich → laufender Primary-Vault (wrapped SecretID als Input).

#### 1.4.3 Ansible — Zero-Touch-Playbook (`deploy/ansible/playbook.yml`)

Das Playbook läuft als root über das Privatnetz (Inventar enthält nur private IPs ⇒ Kontrollhost muss im WireGuard-VPN sein). Es ist idempotent und in folgende Plays gegliedert:

1. **CA-Erzeugung (localhost):** Eigene EC-P256-Root-CA `toob-vault-root-ca` unter `/tmp/toob-ca/`, plus pro API-Knoten ein Zertifikat mit `CN=vault.the-toob.com` und SANs (DNS + Node-IP + 127.0.0.1). Diese CA sichert den Primary-Vault.
2. **Common (alle Hosts):** prometheus-node-exporter + Textfile-Collector-Verzeichnis, `notify-failure@.service`-Mechanik (schreibt bei Unit-Failure eine Prometheus-Metrik), `/etc/hosts`-Mappings, Swap aus (laufend + fstab), Grafana Alloy (journald- und Nomad-Task-Logs → Loki auf 10.0.1.10:3100).
3. **Unseal-Vault (10.0.1.12):** Self-signed TLS, `unseal-vault.hcl` (File-Storage, nur Private-IP-Listener, TLS 1.3, kein UI), Start, dann `init-unseal.sh`:
   - Dev: Init 1/1, automatisches Unseal, Transit-Engine + Key `autounseal-toob-registry` (AES-256-GCM, Löschschutz), Policy `autounseal`, periodischer Orphan-Token (24h-Period) → wird vom Playbook aus dem Output geparst.
   - Production: Init 5/5-Shares mit **3-von-5-Schwelle, PGP-verschlüsselt** gegen 5 Operator-Keys (`op1.asc` zusätzlich Root-Token-Empfänger) → Playbook bricht kontrolliert ab: „OPERATOR ACTION REQUIRED" (manuelles Unseal nötig, siehe Runbook).
   - Täglicher Backup-Timer (`backup-unseal.sh`: tar des Datenverzeichnisses → S3, statische S3-Creds in `/etc/vault.d/backup-s3.env`).
4. **Public-IP-Ermittlung der API-Knoten** (ipify → icanhazip → ifconfig.me Fallback-Kette).
5. **Ubicloud-DB (localhost):** Firewall-Regeln /32 für beide Public-IPs anlegen (409 toleriert), veraltete auto-verwaltete Regeln löschen, Connection-Details abrufen, `db_url` mit `sslmode=verify-full&sslrootcert=/etc/ssl/certs/ubicloud-ca.pem` zusammensetzen, CA-Zertifikat nach `/tmp` holen.
6. **Primary Vault (beide API-Knoten):** TLS-Material verteilen, `vault.hcl.j2` templaten — Raft mit `retry_join` zum jeweils anderen Knoten und `seal "transit"`-Stanza mit dem KMS-Token. Nur auf `toob-api-fsn1`:
   - Init: Dev 1/1 nach `/root/vault-keys.json`; Production 5/3-PGP — Output (Recovery-Keys + verschlüsselter Root-Token) wird angezeigt, dann Abbruch bis `PRIMARY_VAULT_TOKEN` gesetzt ist.
   - `init.sh`: aktiviert KV-v2 (`secret/`), Transit (Keys `toob-package-signing` und `toob-image-signing`, beide Ed25519), PKI (Root-CA `global.nomad`, 10 Jahre; Rolle `nomad-cluster`, TTL 24h/max 72h, RSA-2048, IP-SANs erlaubt), AppRole-Auth, schreibt alle 9 Policies, legt 6 AppRoles an, erzeugt den Nomad-Server-Token (Policy `nomad-server`, 72h-Period, orphan → `/etc/nomad.d/nomad.env`), Token-Rolle `nomad-cluster`, Backup-AppRole-Credentials nach `/opt/vault/config/`, File-Audit-Log.
   - `seed.sh`: schreibt alle Anwendungs-Secrets aus `SEED_*`-Env-Variablen (Datenbank, GitHub-App/OAuth, Webhook-HMAC, Cloudflare API + Origin-Cert, S3, OAuth-AES-Key — wird generiert falls nicht gesetzt, liegt zentral in Vault und ist damit cluster-weit identisch —, Hetzner-Token, Docker-Hub). Übergabe an Vault per stdin-JSON, nie als CLI-Argument.
   - Zusätzlich: `secret/database` (mit der frisch ermittelten Ubicloud-URL), `secret/nomad` (Gossip-Key + Token), Monitoring-AppRole-Credentials.
   - Monitoring-Stack (nur fsn1): Verzeichnisse, Compose-File + Konfigs + 5 Grafana-Dashboards kopieren, Alertmanager templaten, `vault-agent-monitoring` (rotiert Prometheus-Vault-Token, Prometheus-mTLS-Client-Cert, Nomad-CA, pgweb-/Cloudflare-Exporter-Env), `.env` mit Grafana/Discord/BetterStack-Werten, `docker compose up -d`.
   - Backup-Timer für Primary-Vault-Raft-Snapshot und Nomad-Snapshot (täglich → S3), Token-TTL-Exporter-Timer (5 min).
7. **CA-Verteilung (api+workers):** Ubicloud-CA und Vault-CA nach `/etc/ssl/certs/` + System-Truststore (`update-ca-certificates`).
8. **API-Härtung (api):** `toob-api-hardening.service` (iptables-Block des Metadata-Endpoints 169.254.169.254 für Nicht-root → SSRF-Schutz), Cloudflare-Origin-Cert/-Key aus Vault holen und für Caddy ablegen, `Caddyfile.j2` (Details in 1.6), Caddy-Service (stark systemd-gehärtet, nur `CAP_NET_BIND_SERVICE`), `toob-autoscaler`-User + lokal gebautes Binary `../../build/autoscaler` nach `/opt/toob-autoscaler/bin/` (harter Fail wenn nicht vorhanden), Seccomp-Profil nach `/opt/toob-registry/seccomp-api.json`.
9. **DB-Firewall-Pruner (unseal_vault):** Python-Skript + Timer (alle 15 min): vergleicht alle Ubicloud-/32-Regeln mit den aktuell aktiven Hetzner-Server-IPs (paginiert) und löscht Regeln recycelter IPs; `STATIC_WHITELIST_IPS` schützt manuelle Regeln; schreibt Erfolgs-Timestamp als Prometheus-Metrik.
10. **Nomad (api+workers):** AppRole-Credentials je Knotentyp (`api-node-agent` bzw. `nomad-node-pki`) von fsn1 generieren und verteilen; `vault-agent-nomad` rendert ein **TLS-Bundle als einzelnes JSON** (Template `nomad-tls.json.tpl` — eine PKI-Issuance, damit Cert/Key garantiert zusammenpassen) und entpackt es via `unpack-nomad-tls.sh` atomar nach `/opt/nomad/tls/` + `systemctl reload nomad`; auf API-Knoten rendert der Agent zusätzlich `docker-auth.json` (Docker-Hub-Pull-Credentials). Dann: `server.hcl` (fsn1) bzw. `client.hcl` (Rest), Gossip-Key/Pool/Datacenter-Anpassung per regex, `raw_exec` überall aktivieren, Nomad als root starten, Leader abwarten, **ACL-Bootstrap** (Token nach `/root/nomad-bootstrap-token.txt`), Policies `prometheus` (read) und `autoscaler` (write) + scoped Tokens (Prometheus-Token in den Monitoring-Ordner, Autoscaler-Token nach `secret/nomad`), Jobs `registry-worker` und `registry-autoscaler` deployen, abschließend **Root-Token revoken und `/root/vault-keys.json` shredden**.

#### 1.4.4 Nomad — Cluster und Jobs (`deploy/nomad/`)

Topologie: Single-Server (`bootstrap_expect = 1`) auf fsn1, alle Knoten zugleich Clients; ACLs aktiv; volle TLS-Verschlüsselung (Zertifikate täglich von Vault-PKI rotiert, Alert wenn > 20h keine Rotation); Gossip-Verschlüsselung; Vault-Integration mit `create_from_role = "nomad-cluster"` — Nomad erstellt für Jobs Kind-Tokens mit den im Jobspec deklarierten Policies.

| Job | Typ | Constraint | Driver | Kern |
|---|---|---|---|---|
| `registry-api` | service, count 2, spread über DCs | `pool=api` | docker | Digest-gepinntes Distroless-Image, host-network 8080, read-only rootfs, `cap_drop ALL`, no-new-privileges, eigenes Seccomp-Whitelist-Profil, tmpfs `/tmp` (noexec). Vault-Templates rendern mTLS-Cert (`api.global.nomad`, IP-SANs) für den Worker-Kanal 8443. Rolling-Update max_parallel 1 mit auto_revert, Health-Check `/ready`. |
| `registry-migrate` | batch | `pool=api` | docker | Gleiches Image, `["/registry","migrate"]` — läuft von `deploy.sh` **vor** jedem API-Rollout. |
| `registry-worker` | system | `pool=worker` | raw_exec | Worker-Binary als `toob-worker`-User; Kette Nomad → worker → setuid-Jailer (chroot, AppArmor) → Firecracker/KVM → microVM (vm-runner als PID 1, kein Netz). mTLS-Client-Cert (`worker.global.nomad`) aus Vault, Health-HTTP auf 8081, SIGTERM-Drain. |
| `registry-autoscaler` | service, count 1 | `pool=api` | raw_exec | Binary unter `toob-autoscaler`-User; bekommt per Vault-Template HCLOUD-Token, DB-URL, Nomad-Gossip-Key + Nomad-ACL-Token sowie eigenes mTLS-Cert; skaliert Worker-VMs über die Hetzner-API anhand der Queue-Tiefe. |

#### 1.4.5 Build-/Release-Pipeline `deploy/api/deploy.sh`

`build` → `sign` → `verify` → `deploy` (oder `all`):

- **build:** `docker build --no-cache --pull` mit `Dockerfile.api` (Multi-Stage: golang:1.26-alpine → distroless/static, CGO=0, stripped, nonroot 65534, Kontext = Repo-Root) gegen `${REGISTRY}/toob-registry-api:<ts>-<gitsha>`; **`REGISTRY` ist Pflicht** (ohne Push gibt es keinen RepoDigest und Nomad könnte das Image nicht ziehen); Tag wird in `.last_tag` persistiert.
- **sign:** `cosign sign --key hashivault://toob-image-signing` — Cosign signiert den **Digest** über die Vault-Transit-Engine (Ed25519-Key, von `init.sh` angelegt). Benötigt `VAULT_ADDR` + einen Vault-Token mit der `cosign`-Policy.
- **verify:** `cosign verify` vor jedem Deploy (Schutz gegen lokale Manipulation); Abbruch bei Fehlschlag.
- **deploy:** zuerst `registry-migrate` (blocking, `-detach=false`), dann `registry-api`, beide mit `-var image_digest=<exakter sha256-Digest>` — keine mutable-Tag-Auflösung zur Laufzeit. Optional Grafana-Deploy-Annotation (erscheint in allen Dashboards).

#### 1.4.6 Compiler-/Rootfs-Builds (`deploy/compiler/`, `deploy/worker/`)

- `build-compiler.sh` erzeugt aus **einem** Dockerfile zwei Release-Artefakte: das Docker-Hub-Image `toob-compiler` (Cross-Compile-Umgebung; Pakete ausschließlich aus `compiler_manifest.json`, Toolchains SHA256-verifiziert via `install_toolchains.py`, Registry-Snapshot und Core-SDK vorgeseedet) und ein daraus exportiertes `rootfs-vX.ext4` für Firecracker (vm-runner als `/sbin/init`, BusyBox-Applets, Mount-Points), inkl. Checksummen; `--push` lädt nach Docker Hub + S3. `:latest`/`latest.txt` werden bewusst erst post-complete vom Daemon promotet.
- `build-rootfs.sh` ist ein Minimal-Rootfs **nur für lokale Entwicklung**.
- `setup-host.sh` ist die manuelle Alternative zur cloud-init-Provisionierung eines Worker-Hosts (heute weitgehend von Terraform/cloud-init abgelöst, Nomad übernimmt die Supervision).
- `Makefile`: `make worker`, `make autoscaler`, `make rootfs`, `make compiler-release`, `make deploy HOST=…`.

### 1.5 Secrets-Architektur (Vault, zweistufig)

**Stufe 1 — Unseal-Vault (KMS):** Eigenständiger, minimaler Vault auf 10.0.1.12. File-Storage, kein UI, keine Telemetrie, TLS 1.3, nur von den beiden API-Knoten erreichbar. Einzige Aufgabe: Transit-Key `autounseal-toob-registry`, mit dem der Primary-Vault seinen Master-Key wrappen/unwrappen kann (Policy `autounseal`: nur encrypt/decrypt auf genau diesem Key + Token-Self-Renewal). Der Zugriffstoken ist ein periodischer Orphan-Token (24h), der sich selbst erneuert, solange der Primary-Vault läuft.

**Stufe 2 — Primary-Vault:** Raft-HA über beide API-Knoten, Auto-Unseal via Transit → Reboots heilen sich selbst, ohne dass je ein Unseal-Key auf der Maschine liegen muss. In Production existieren nur PGP-verschlüsselte Recovery-Keys (5 Operatoren, Schwelle 3).

Engines: `secret/` (KV v2), `transit/` (Paket- und Image-Signierung, Ed25519), `pki/` (interne CA `global.nomad` für sämtliche mTLS-Zertifikate des Clusters, Kurzlebigkeit 24h erzwingt funktionierende Rotation).

Identitäten (AppRoles) und Policies — strikt least-privilege:

| AppRole / Konsument | Policies | Darf |
|---|---|---|
| `registry-api` (Nomad-Job) | registry-api, nomad-node-pki | Alle App-Secrets lesen, Pakete signieren/verifizieren, PKI-Certs ziehen |
| `registry-worker` (Nomad-Job) | registry-worker, nomad-node-pki | **Nur** PKI-mTLS-Certs + Token-Self-Mgmt — bewusst keine Secrets |
| `registry-autoscaler` (Nomad-Job) | registry-autoscaler | Hetzner-Token, DB-URL, Nomad-Secrets lesen; **wrapped SecretIDs für neue Worker erzeugen**; PKI |
| `api-node-agent` (Vault Agent, API-Hosts) | api-node-agent, nomad-node-pki | Docker-Hub-Pull-Creds, Nomad-TLS-Rotation |
| `nomad-node-pki` (Vault Agent, Worker-Hosts) | nomad-node-pki | Nur Nomad-TLS-Rotation |
| `monitoring` (Vault Agent Monitoring) | monitoring, nomad-node-pki | sys/metrics, DB-URL (pgweb/postgres-exporter), Prometheus-mTLS |
| `backup` (Backup-Skripte) | backup | Raft-Snapshot lesen, S3-/Nomad-Creds lesen |
| Nomad-Server-Token | nomad-server | Kind-Tokens über Token-Rolle `nomad-cluster` erzeugen (erlaubte Policies: registry-api/-worker/-autoscaler, nomad-node-pki) |

Worker-Bootstrap (Zero-Trust-Onboarding): Neue Worker erhalten ihre AppRole-SecretID nie im Klartext über cloud-init, sondern als **response-wrapped Token** (einmalig einlösbar). Cloud-init unwrapt sie gegen Vault; ein Diebstahl der user_data verrät damit kein nutzbares Secret, und ein bereits eingelöster Wrap fällt sofort auf.

### 1.6 Ingress-Pfad

Cloudflare (strict TLS, Geo-LB über beide Origins, Auth-Rate-Limit, Download-Cache) → Hetzner-Firewall (443 nur von CF-IPs) → **Caddy** pro API-Knoten:

- TLS-Terminierung mit Cloudflare-**Origin-CA**-Zertifikat (Full-Strict-Modus; Cert/Key kommen aus `secret/cloudflare-origin`).
- `trusted_proxies` = CF-Ranges; `X-Real-IP` aus `CF-Connecting-IP` (korrekte Client-IP fürs Rate-Limiting im Go-Server).
- Security-Header (HSTS preload, Frame-Deny, nosniff, CSP `default-src 'none'`; gelockerte CSP nur für das Admin-Dashboard), `/metrics*` öffentlich geblockt (403).
- Reverse-Proxy auf `localhost:8080` mit dem **anderen** API-Knoten als Fallback (`lb_policy first`) — Origin-seitige Cross-Node-Ausfallsicherung zusätzlich zum CF-LB; Health-Gate `/ready`; Slowloris-Timeouts; 6-MB-Body-Limit; JSON-Access-Log mit Rotation.

Metriken laufen **nicht** über Caddy: Prometheus scrapt die API direkt auf 8443 per mTLS (Client-Zertifikat aus der Nomad-PKI), Vault auf 8200 (Bearer-Token), Nomad auf 4646 (Token + mTLS).

### 1.7 Worker-Ausführungspfad (Firecracker)

Defense-in-Depth für die Ausführung nicht vertrauenswürdigen Codes:

```
Nomad (system-Job, pool=worker)
  └─ raw_exec → /opt/toob-worker/bin/worker  (User toob-worker, kein Login, /dev/kvm via ACL)
       └─ jailer (setuid root, AppArmor-Profil, chroot, per-Job-UID/GID, cgroups)
            └─ firecracker (KVM-Hardware-Isolation)
                 └─ microVM: vmlinux 5.10 + rootfs.ext4, vm-runner als PID 1
                    Mounts: /registry /input /output /workspace — KEIN Netzwerk im Gast
```

Host-Härtung via cloud-init-Service `toob-worker-hardening` (fail-closed, läuft vor Nomad bei jedem Boot): SMT aus (L1TF/MDS), Metadata-Endpoint-Block für Nicht-root, KVM-ACL, AppArmor-Profil laden. Der Worker spricht ausschließlich per mTLS mit `api.global.nomad:8443`; alle privilegierten Operationen (DB, S3) delegiert er an die Control-Plane gegen One-Time-Job-Tokens.

### 1.8 Monitoring, Logging, Alerting

Stack als Docker-Compose auf fsn1, alle UIs nur an 127.0.0.1 gebunden (Zugriff per VPN/SSH-Tunnel):

- **Prometheus** (30 d Retention): scrapt API (8443 mTLS), Vault (Token), Nomad (Token+mTLS), node-exporter aller statischen Knoten, **dynamische Worker via Nomad-Service-Discovery** (`nomad_sd_configs`, Filter `toob-worker-*` + ready, Port-Rewrite auf 9100), Blackbox-Probes (öffentlicher Endpoint via CF, direkte `/ready`-Origin-Checks, Seal-Status aller drei Vaults), postgres- und cloudflare-Exporter.
- **Textfile-Collector-Pattern** für Cron-/Oneshot-Telemetrie: Backup-Timestamps, Nomad-TLS-Rotations-Timestamp, Token-TTLs (`token-ttl-exporter.sh` alle 5 min: Autounseal-, Nomad-Server- und Agent-Token), Service-Failures (`OnFailure=notify-failure@%n`), DB-Firewall-Pruner.
- **Alertmanager:** 21 Regeln (InstanceDown, VaultSealed, 5xx-Rate > 5 %, p99 > 1 s, Backup > 26 h, TokenTTL < 24 h, AutoscalerIneffective, VersionDivergence, …, jede mit Runbook-URL) → Discord (critical/warning getrennt) + **Watchdog-Dead-Man-Switch** minütlich an Better Stack (stoppt der Heartbeat, ist die Monitoring-Ebene selbst tot). Inhibit-Regel: InstanceDown unterdrückt Folge-Alerts derselben Instanz.
- **Grafana** (GitHub-SSO, Org-gefiltert, Team-basierte Rollen, Admin-Passwort als Fallback): 5 provisionierte Dashboards (Ops-Home-Statusmatrix, API-Performance, Worker-Pipeline, Infrastructure, Vault & Security), Deploy-Annotationen.
- **Loki + Alloy:** Alloy auf jedem Knoten (auch Workern, via cloud-init) shippt journald-Logs (gelabelt nach Unit) und Nomad-Task-stdout/stderr (gelabelt nach alloc/task/stream); Loki single-binary, 15 d Retention via Compactor; Log-Panels in den Dashboards.
- **pgweb**: separates Compose-File, ausdrücklich nur on-demand (unauthentifizierter DB-Vollzugriff), Credentials kommen aus dem Vault-Agent-gerenderten `.env.pgweb`.

### 1.9 Backups & Recovery

| Was | Wie | Wohin | Frequenz |
|---|---|---|---|
| Primary-Vault | Raft-Snapshot via Backup-AppRole | S3 `toob-vault-backups/snapshots/` | täglich, 30 d lokal |
| Unseal-Vault | tar des File-Storage (statische S3-Creds, da der KMS sich nicht selbst entsperren kann) | S3 `…/unseal-snapshots/` | täglich |
| Nomad | `nomad operator snapshot save` (mTLS + ACL-Token aus Vault) | S3 `…/snapshots/` | täglich |
| Terraform-State | S3-Backend (encrypt) | `toob-terraform-state` | bei jedem Apply |
| Pakete/DB | Bucket-Versioning bzw. Ubicloud-Managed-Backups | extern | laufend |

Jeder Backup-Job schreibt seinen Erfolgs-Timestamp als Metrik; `BackupStale` (> 26 h) alarmiert kritisch. Worst-Case-Reihenfolge bei Totalverlust: Unseal-Vault aus Tarball wiederherstellen (oder neu initialisieren + Token-Rotation), Primary-Vault aus Raft-Snapshot restoren, Nomad-Snapshot restoren, Jobs re-deployen.

### 1.10 Sicherheitsmodell — Kurzfassung

Kein öffentliches SSH (nur WireGuard-Bastion); Edge nur über Cloudflare-IPs; intern überall mTLS aus eigener 24h-PKI; Secrets ausschließlich in Vault, geseedet per stdin, Root-Token wird am Ende des Bootstraps automatisch revoked und die Key-Datei geshreddert; Auto-Unseal souverän per zweitem Vault, Recovery nur per 3-von-5-PGP-Quorum; Supply-Chain: GPG-Fingerprint-Pinning der HashiCorp-Binaries, Cosign-Signatur + Verify + Digest-Pinning des API-Images, manifest-deklarierte und checksummen-verifizierte Compiler-Toolchains; Laufzeit: Distroless, Seccomp-Whitelist, cap_drop ALL, read-only rootfs, SSRF-Metadata-Block, Firecracker-Isolation mit Jailer/AppArmor/SMT-off; DB-Zugriff nur von gepinnten /32-IPs mit automatischem Pruning recycelter IPs und `sslmode=verify-full`.

---

## Teil 2 — Deployment von Grund auf (Runbook)

Konvention: 🧑 = Aktion, die zwingend ein Mensch durchführt (Entscheidung, Geheimnis, Zeremonie, Klick in einer fremden Konsole). Befehle ohne Symbol sind „nur ausführen".

### Phase 0 — Voraussetzungen (vollständig manuell)

**0.1 🧑 Konten & Ressourcen anlegen**

1. **Hetzner Cloud:** Projekt anlegen, API-Token erzeugen (`HCLOUD_TOKEN`), eigenen SSH-Public-Key hochladen (Name merken, z. B. `admin` → `ssh_key_name`).
2. **Hetzner Object Storage:** S3-Access-/Secret-Key erzeugen. Buckets **manuell** anlegen: `toob-terraform-state` (Henne-Ei: das Terraform-S3-Backend kann seinen eigenen State-Bucket nicht erzeugen) und `toob-vault-backups` (wird von keinem TF-Modul verwaltet). `toob-registry-packages` legt später das s3-Modul an.
3. **Cloudflare:** Zone `the-toob.com` (Nameserver umgestellt), Load-Balancing-Subscription aktivieren, API-Token mit Zone:Edit + LB:Edit, Account-ID und Zone-ID notieren. Im Dashboard ein **Origin-CA-Zertifikat** für `ci.the-toob.com` erzeugen (PEM + Key sichern → `SEED_CF_ORIGIN_CERT/KEY`). SSL-Modus wird später per TF auf „Full (strict)" gesetzt.
4. **Ubicloud:** Projekt anlegen, API-Token erzeugen (`UBICLOUD_API_TOKEN`, `UBICLOUD_PROJECT_ID`).
5. **Docker Hub:** Account + Access-Token; Repository für das API-Image (privat) und für `toob-compiler`.
6. **GitHub:** GitHub-App (App-ID, Private-Key-PEM, Webhook-Secret) und OAuth-App (Client-ID/-Secret) für die Registry; optional zweite OAuth-App für Grafana-SSO; GitHub-Org (default `Toob-Boot`) mit Team `core-admins`.
7. **Discord:** Webhook-URL für den Alert-Channel. **Better Stack:** Heartbeat anlegen (Erwartung ~1/min), URL notieren.

**0.2 🧑 Kryptomaterial erzeugen**

```bash
# WireGuard (Bastion + Client)
wg genkey | tee bastion.key | wg pubkey > bastion.pub
wg genkey | tee client.key  | wg pubkey > client.pub

# Nomad-Gossip-Key
nomad operator gossip keyring generate          # oder: openssl rand -base64 32

# Production-Vault: 5 Operator-PGP-Public-Keys exportieren
gpg --export --armor <op-key-id> > opN.asc      # exakt 5 Dateien
```

🧑 Die fünf `.asc`-Dateien nach `deploy/vault/operator_gpg_keys/` legen — **`op1.asc` muss der Operator sein, der später den Root-Token entschlüsseln darf** (alphabetisch erste Datei wird als Root-Token-PGP-Key verwendet). Für Dev/Staging entfällt dieser Schritt komplett (`VAULT_ENV=dev`).

**0.3 Werkzeuge auf dem Kontrollrechner** (oder CI-Runner): `terraform`, `packer`, `ansible` (+ `synchronize` ⇒ rsync auf beiden Seiten), `docker`, `go` ≥ 1.22, `nomad`- und `vault`-CLI, `cosign`, `jq`, `aws-cli`, `wireguard-tools`, `gpg`, `e2fsprogs`, `sudo` (Loop-Mounts beim Rootfs-Build).

### Phase 1 — Artefakte lokal bauen

```bash
cd toob-registry/deploy/worker
make worker        # → build/worker        (Pflicht für Packer)
make autoscaler    # → build/autoscaler    (Pflicht für Ansible-Play 8)
make rootfs        # → build/rootfs.ext4   (Dev-Variante; Pflicht für Packer)
```

🧑 Für Production stattdessen/zusätzlich das echte Compiler-Rootfs bauen (enthält die Toolchains, ohne die die Compile-Validierung leer wäre):

```bash
cd toob-registry/deploy/compiler
DOCKERHUB_USERNAME=… DOCKERHUB_TOKEN=… \
S3_ENDPOINT=https://fsn1.your-objectstorage.com S3_BUCKET=toob-registry-packages \
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… \
./build-compiler.sh --push
# Das erzeugte rootfs-vX.ext4 als build/rootfs.ext4 bereitstellen, bevor Packer läuft.
```

### Phase 2 — Golden Image (Packer)

```bash
cd toob-registry/deploy/packer
export HCLOUD_TOKEN=…
packer init image.pkr.hcl && packer build image.pkr.hcl
```

Ergebnis: Hetzner-Snapshot mit Label `name=toob-golden-image`. Bei jedem Rebuild ziehen sich Terraform-`data`-Quellen automatisch das neueste Image (nur für **neue** Server; bestehende werden nicht ersetzt).

### Phase 3 — Terraform-Basisinfrastruktur

Reihenfolge ist verbindlich:

```bash
# 3.1 Control-Plane (Netz, 2 API-Knoten, Unseal-Vault, Bastion, Firewalls)
cd deploy/terraform/control-plane
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…   # für das S3-State-Backend
terraform init
terraform apply \
  -var hcloud_token=… -var ssh_key_name=admin \
  -var wg_bastion_private_key=… -var wg_bastion_public_key=… \
  -var wg_client_private_key=…  -var wg_client_public_key=…
terraform output api_public_ips        # 🧑 notieren für Cloudflare
terraform output -raw wg_client_config # 🧑 sichern für Phase 4

# 3.2 Datenbank (Ubicloud)
cd ../database
export UBICLOUD_API_TOKEN=…
terraform init && terraform apply -var ubicloud_project_id=…

# 3.3 S3-Bucket für Pakete
cd ../s3
terraform init && terraform apply -var s3_access_key=… -var s3_secret_key=…

# 3.4 Cloudflare-Edge — 🧑 api_origins aus 3.1-Output von Hand übergeben
cd ../cloudflare
terraform init && terraform apply \
  -var cloudflare_api_token=… -var cloudflare_zone_id=… -var cloudflare_account_id=… \
  -var 'api_origins={"api-fsn1"="<public-ip-fsn1>","api-hel1"="<public-ip-hel1>"}'
```

Das `worker`-Modul **noch nicht** anwenden — es benötigt einen laufenden, initialisierten Vault (Phase 7).

### Phase 4 — 🧑 VPN-Zugang einrichten (Voraussetzung für alles Weitere)

Sämtliches SSH ist nur aus 10.0.0.0/16 erlaubt; Ansible adressiert ausschließlich private IPs. Die `wg_client_config` aus Phase 3.1 lokal installieren und Tunnel starten:

```bash
sudo install -m600 wg-toob.conf /etc/wireguard/wg-toob.conf
sudo wg-quick up wg-toob
ssh root@10.0.1.10   # Funktionstest
```

### Phase 5 — Ansible-Provisionierung (inkl. Production-Zeremonien)

**5.1 Umgebung setzen.** Alle benötigten Variablen exportieren (vollständige Referenz in Anhang A); minimal für Production:

```bash
export VAULT_ENV=production            # oder: dev (dann entfallen 5.3/5.4)
export NOMAD_GOSSIP_KEY=…
export UBICLOUD_API_TOKEN=… UBICLOUD_PROJECT_ID=…
export HCLOUD_TOKEN=…
export SEED_GH_APP_ID=… SEED_GH_PRIVATE_KEY="$(cat gh-app.pem)"
export SEED_GH_CLIENT_ID=… SEED_GH_CLIENT_SECRET=…
export SEED_WEBHOOK_SECRET=…
export SEED_CF_ZONE_ID=… SEED_CF_API_TOKEN=…
export SEED_CF_ORIGIN_CERT="$(cat origin.pem)" SEED_CF_ORIGIN_KEY="$(cat origin.key)"
export SEED_S3_ACCESS_KEY=… SEED_S3_SECRET_KEY=…
export SEED_HCLOUD_TOKEN=…
export SEED_DOCKERHUB_USERNAME=… SEED_DOCKERHUB_PASSWORD=…
export GRAFANA_ADMIN_PASSWORD=… DISCORD_WEBHOOK_URL=… BETTERSTACK_HEARTBEAT_URL=…
```

**5.2 Erster Lauf:**

```bash
cd toob-registry/deploy/ansible
ansible-playbook playbook.yml
```

In `dev` läuft das Playbook durch bis inkl. Nomad-Bootstrap und Job-Deploys. In `production` stoppt es planmäßig zweimal:

**5.3 🧑 Zeremonie 1 — Unseal-Vault (KMS) entsperren.** Das Playbook bricht mit „OPERATOR ACTION REQUIRED" ab; `/root/unseal-vault-keys.json` auf 10.0.1.12 enthält 5 PGP-verschlüsselte Shares + verschlüsselten Root-Token.

1. Mindestens 3 der 5 Operatoren entschlüsseln ihren Share (`echo <share> | base64 -d | gpg -d`).
2. Auf 10.0.1.12 dreimal `vault operator unseal <share>` (mit `VAULT_ADDR=https://10.0.1.12:8200`, `VAULT_CACERT=/etc/vault.d/tls/unseal-cert.pem`).
3. Operator 1 entschlüsselt den Root-Token.
4. `export KMS_VAULT_TOKEN=<root-token>` und Playbook erneut starten — `init-unseal.sh` richtet nun Transit/Policy/Auto-Unseal-Token ein.
5. 🧑 `/root/unseal-vault-keys.json` offline sichern (verschlüsselter USB o. ä.) und auf dem Server shredden (`shred -vfz -n 5 …`).

**5.4 🧑 Zeremonie 2 — Primary-Vault-Root-Token freigeben.** Das Playbook initialisiert den Primary-Vault auf fsn1 (5/3 PGP-Recovery-Keys, dank Transit-Auto-Unseal entsperrt er sich selbst), gibt das PGP-verschlüsselte Material im Task-Output aus und bricht ab.

1. 🧑 Output sichern; Recovery-Key-Shares an die 5 Operatoren verteilen (offline aufbewahren).
2. Operator 1 (op1.asc) entschlüsselt den Root-Token.
3. `export PRIMARY_VAULT_TOKEN=<root-token>` und Playbook erneut starten.

**5.5 Durchlauf bis zum Ende.** Der finale Lauf erledigt: `init.sh` + `seed.sh` (alle Secrets), Monitoring-Stack, Caddy mit Origin-Certs, Vault-Agents, Nomad-Start, **ACL-Bootstrap** (Management-Token → `/root/nomad-bootstrap-token.txt` auf fsn1 — 🧑 sicher ablegen, z. B. Passwortmanager), Prometheus-/Autoscaler-Tokens, Deploy von `registry-worker` und `registry-autoscaler`, und zuletzt **Revoke des Root-Tokens + Shred der Key-Datei**.

**5.6 🧑 Vor dem letzten Lauf: Cosign-Token erzeugen.** Da der Root-Token am Ende revoked wird, vorher (solange `PRIMARY_VAULT_TOKEN` gilt) einen langlebigen Token für die Release-Pipeline ziehen:

```bash
VAULT_ADDR=https://vault.the-toob.com:8200 VAULT_TOKEN=$PRIMARY_VAULT_TOKEN \
vault token create -policy=cosign -period=720h -orphan -display-name=ci-cosign
```

(Sicher im CI-Secret-Store ablegen; via Token-TTL-Alerting überwacht werden nur die Infrastruktur-Tokens — diesen Token periodisch erneuern.)

### Phase 6 — API bauen, signieren, deployen

Auf dem Kontrollrechner (im VPN):

```bash
cd toob-registry/deploy/api
export REGISTRY=docker.io/<org>                       # Pflicht!
export VAULT_ADDR=https://vault.the-toob.com:8200
export VAULT_TOKEN=<cosign-token aus 5.6>
export COSIGN_KEY=hashivault://toob-image-signing
export NOMAD_ADDR=https://10.0.1.10:4646
export NOMAD_CACERT=…/nomad-ca.pem                    # oder via VPN-Host kopieren
export NOMAD_TOKEN=$(ssh root@10.0.1.10 cat /root/nomad-bootstrap-token.txt)

./deploy.sh all     # build → push → cosign sign → verify → migrate-Batch → registry-api
nomad job status registry-api
```

Die API-Knoten ziehen das Image digest-gepinnt mit den Docker-Hub-Credentials, die der Vault-Agent nach `/etc/nomad.d/docker-auth.json` rendert.

### Phase 7 — Worker provisionieren

**7.1 🧑 Wrapped SecretID erzeugen** (kurzlebig, einmal einlösbar):

```bash
export VAULT_ADDR=https://vault.the-toob.com:8200 VAULT_TOKEN=<token mit approle-Rechten>
ROLE_ID=$(vault read -field=role_id auth/approle/role/registry-worker/role-id)
WRAPPED=$(vault write -field=wrapping_token -wrap-ttl=20m \
          -f auth/approle/role/registry-worker/secret-id)
```

⚠️ Ein Wrapping-Token ist **single-use**. `worker_count > 1` würde dieselbe wrapped SecretID an alle Worker geben — nur der erste kann sie einlösen. Daher: Seed-Worker mit `worker_count=1` provisionieren; weitere Worker erzeugt im Betrieb der **Autoscaler**, der pro Knoten eine frische wrapped SecretID generiert.

**7.2 Terraform-Worker-Modul:**

```bash
cd deploy/terraform/worker
terraform init
terraform apply \
  -var hcloud_token=… -var ssh_key_name=admin -var worker_count=1 \
  -var vault_addr=https://vault.the-toob.com:8200 \
  -var vault_role_id="$ROLE_ID" -var vault_wrapped_secret_id="$WRAPPED" \
  -var nomad_gossip_key=… \
  -var vault_ca_cert="$(cat /tmp/toob-ca/vault-ca.pem)"   # vom Ansible-Kontrollhost
```

Cloud-init übernimmt alles Weitere (Unwrap, Vault-Agent, Nomad-TLS, Hardening, Alloy, Nomad-Join); `registry-worker` ist ein system-Job und scheduled automatisch auf den neuen Knoten. Das Modul regeneriert außerdem `deploy/ansible/inventory.ini` inkl. Worker-Sektion für künftige Ansible-Läufe.

### Phase 8 — Verifikation

```bash
# Vault
VAULT_ADDR=https://10.0.1.10:8200 vault status          # Seal Type: transit, Sealed: false
# Nomad
nomad node status && nomad job status                    # api×2, autoscaler, worker laufen
# Edge
curl -sSI https://ci.the-toob.com/health                 # 200 über Cloudflare
```

🧑 Per VPN/SSH-Tunnel `http://10.0.1.10:3000` (Grafana) öffnen: Ops-Home-Statusmatrix komplett grün, Token-TTL-Balken befüllt, Backup-Alter < 24 h nach dem ersten Timer-Lauf; Better-Stack-Heartbeat empfängt den Watchdog; Test-Alert per `systemctl stop caddy` auf hel1 (Discord-Meldung) — danach wieder starten.

---

## Teil 3 — Checkliste: Was zwingend ein Mensch tun muss

**Einmalig vor dem Deployment**

1. Konten/Tokens anlegen: Hetzner (+ SSH-Key-Upload), Hetzner Object Storage (+ Buckets `toob-terraform-state`, `toob-vault-backups` von Hand), Cloudflare (Zone, LB-Subscription, API-Token, **Origin-CA-Cert+Key generieren**), Ubicloud, Docker Hub, GitHub-App + 1–2 OAuth-Apps, Discord-Webhook, Better-Stack-Heartbeat.
2. Kryptomaterial: 2 WireGuard-Keypaare, Nomad-Gossip-Key, **5 Operator-PGP-Keys** sammeln und nach `deploy/vault/operator_gpg_keys/` legen (op1 = Root-Token-Empfänger).
3. Build-Artefakte erzeugen (`make worker autoscaler rootfs`, ggf. `build-compiler.sh --push`) — Packer und Ansible verweigern sonst den Dienst.
4. Alle Secret-Werte als Env-Variablen bereitstellen (Anhang A) — das Playbook fragt nichts interaktiv ab, `mandatory`-Lookups brechen hart ab.

**Während des Deployments (Entscheidungs-/Zeremonienpunkte)**

5. `api_origins` von Hand aus dem control-plane-Output ins Cloudflare-Modul übertragen.
6. WireGuard-Clientkonfig installieren — ohne VPN kein SSH, kein Ansible.
7. `VAULT_ENV` festlegen (dev vs. production) — bestimmt, ob die PGP-Zeremonien stattfinden.
8. **Unseal-Zeremonie KMS-Vault:** 3 Operatoren entschlüsseln Shares, 3× `vault operator unseal` auf 10.0.1.12, Root-Token entschlüsseln, `KMS_VAULT_TOKEN` setzen, Playbook re-runnen.
9. **Primary-Vault:** PGP-Output sichern, Recovery-Shares an Operatoren verteilen, Root-Token entschlüsseln, `PRIMARY_VAULT_TOKEN` setzen, Playbook re-runnen.
10. Vor dem finalen Playbook-Ende einen **Cosign-Vault-Token** für die Release-Pipeline erzeugen (der Root-Token wird automatisch revoked).
11. Key-Material archivieren und vernichten: `unseal-vault-keys.json` offline sichern + auf dem Server shredden; Nomad-Bootstrap-Token (`/root/nomad-bootstrap-token.txt`) sicher hinterlegen.
12. Erster API-Release: `deploy.sh all` mit `REGISTRY`, Vault-/Nomad-Credentials.
13. Seed-Worker: wrapped SecretID generieren (single-use!) und worker-TF mit `worker_count=1` anwenden.
14. Abnahme in Grafana/Discord/Better Stack (Phase 8).

**Wiederkehrend im Betrieb (siehe Teil 4)**

15. Auf Alerts reagieren (TokenTTLLow, BackupStale, NomadTLSRotationFailed, …), Cosign-Token rotieren, Golden Image bei CVEs neu bauen, Compiler-Releases pushen, pgweb nur on-demand starten/stoppen, PGP-Quorum für Disaster-Recovery verfügbar halten.

---

## Teil 4 — Laufender Betrieb (manuelle Aufgaben)

- **Releases:** jeder API-Rollout via `deploy.sh all` (Mensch oder CI mit Cosign-Token + Nomad-Token). Migrations laufen automatisch als Batch davor; `auto_revert` rollt fehlgeschlagene Deploys zurück; `VersionDivergence`-Alert meldet hängende Rollouts.
- **Token-Hygiene:** Die periodischen Tokens (Autounseal 24h, Nomad-Server 72h, AppRole-Tokens 24h) erneuern sich selbst, solange die Konsumenten laufen. `TokenTTLLow` (< 24h) bedeutet: Renewal-Kette gerissen → Token über die jeweilige Quelle neu erzeugen (Autounseal: `init-unseal.sh` re-run mit KMS-Token; Nomad-Server: `vault token create -policy=nomad-server -period=72h -orphan` → `/etc/nomad.d/nomad.env`, Nomad restart).
- **Worker-Skalierung:** vollautomatisch durch den Autoscaler; `AutoscalerIneffective` (Queue > 0, 0 Worker, 15 min) erfordert manuelles Eingreifen (Hetzner-Limits, Autoscaler-Logs in Grafana/Loki).
- **Golden-Image-Pflege:** bei Nomad-/Vault-/Firecracker-Updates oder Kernel-CVEs Packer neu bauen; neue Server erhalten das Image automatisch, Bestandsserver per Replace (Terraform taint/replace) rollieren.
- **Compiler-Releases:** `make compiler-release` bei neuen Toolchain-/SDK-Versionen; Worker beziehen das Rootfs aus S3.
- **Backups testen:** periodisch Raft-Snapshot-Restore proben; `BackupStale` ist kritisch.
- **DB-Firewall:** läuft automatisch (15-min-Pruner); manuelle Debug-IPs in `STATIC_WHITELIST_IPS` eintragen, sonst werden sie weggeräumt.
- **pgweb:** nur bewusst per Compose starten und sofort wieder `down` — unauthentifizierter DB-Vollzugriff.
- **Recovery-Bereitschaft:** 3-von-5-PGP-Quorum organisatorisch sicherstellen (Schlüsselverlust einzelner Operatoren rechtzeitig durch Re-Key-Zeremonie kompensieren).

---

## Anhang A — Env-Variablen-Referenz

**Ansible-Playbook (`playbook.yml`)**

| Variable | Pflicht | Zweck |
|---|---|---|
| `VAULT_ENV` | ✔ | `production` (PGP 5/3) oder `dev` (1/1) — steuert beide Vault-Inits |
| `NOMAD_GOSSIP_KEY` | ✔ | Gossip-Verschlüsselung; landet auch in `secret/nomad` |
| `SEED_S3_ACCESS_KEY/SECRET_KEY` | ✔ | `secret/s3` **und** Backup-Creds des Unseal-Vaults |
| `UBICLOUD_API_TOKEN`, `UBICLOUD_PROJECT_ID` | ✔ | DB-Firewall + Connection-String; `UBICLOUD_DB_NAME/LOCATION` optional |
| `SEED_GH_APP_ID`, `SEED_GH_PRIVATE_KEY`, `SEED_GH_CLIENT_ID`, `SEED_GH_CLIENT_SECRET` | ✔ | `secret/github-app`, `secret/github-oauth` |
| `SEED_WEBHOOK_SECRET` | ✔ | `secret/webhook` (HMAC) |
| `SEED_CF_ZONE_ID`, `SEED_CF_API_TOKEN` | ✔ | `secret/cloudflare` (Exporter, Cache-Purge) |
| `SEED_CF_ORIGIN_CERT`, `SEED_CF_ORIGIN_KEY` | ✔ | `secret/cloudflare-origin` → Caddy-TLS |
| `SEED_HCLOUD_TOKEN` | ✔ | `secret/hetzner` (Autoscaler) |
| `SEED_DOCKERHUB_USERNAME/PASSWORD` | ✔ | `secret/dockerhub` → Image-Pull |
| `SEED_OAUTH_AES_KEY` | – | sonst generiert (liegt zentral in Vault, cluster-weit identisch) |
| `GRAFANA_ADMIN_PASSWORD` | ✔ | Grafana-Fallback-Login |
| `GRAFANA_GITHUB_CLIENT_ID/SECRET`, `GRAFANA_GITHUB_ALLOWED_ORG`, `GRAFANA_DOMAIN` | – | Grafana-SSO |
| `DISCORD_WEBHOOK_URL`, `BETTERSTACK_HEARTBEAT_URL` | ✔ | Alertmanager-Receiver |
| `HCLOUD_TOKEN` | ✔ | DB-Firewall-Pruner-Env auf dem Unseal-Vault |
| `STATIC_WHITELIST_IPS` | – | vom Pruner geschützte /32-Regeln |
| `KMS_VAULT_TOKEN` | Prod-Re-Run | entschlüsselter Root-Token des Unseal-Vaults |
| `PRIMARY_VAULT_TOKEN` | Prod-Re-Run | entschlüsselter Root-Token des Primary-Vaults (wird am Ende revoked) |
| `NOMAD_TOKEN` | – | initial leer; nach Bootstrap durch scoped Tokens ersetzt |

**deploy.sh:** `REGISTRY` (✔), `IMAGE_TAG` (–, sonst `<ts>-<gitsha>`), `COSIGN_KEY` (default `hashivault://toob-image-signing`), `VAULT_ADDR` + `VAULT_TOKEN` (✔, cosign-Policy), `NOMAD_ADDR` + `NOMAD_TOKEN` (✔) + ggf. `NOMAD_CACERT`, optional `GRAFANA_TOKEN`/`GRAFANA_ADMIN_PASSWORD`/`GRAFANA_URL`.

**Terraform:** control-plane: `hcloud_token`, `ssh_key_name`, 4× `wg_*`-Keys, `wg_port`; cloudflare: `cloudflare_api_token/zone_id/account_id`, `api_origins`; database: `ubicloud_project_id` (+ `UBICLOUD_API_TOKEN` als Env); s3: `s3_access_key/secret_key`; worker: `hcloud_token`, `ssh_key_name`, `worker_count`, `vault_addr`, `vault_role_id`, `vault_wrapped_secret_id`, `nomad_gossip_key`, `vault_ca_cert`, `toob_api_url`. Für S3-Backends zusätzlich `AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY` als Env. **Packer:** `HCLOUD_TOKEN`.

## Anhang B — Wichtige Pfade auf den Hosts

| Pfad | Host | Inhalt |
|---|---|---|
| `/root/nomad-bootstrap-token.txt` | fsn1 | Nomad-ACL-Management-Token (sicher extern hinterlegen) |
| `/root/autounseal-token.txt` | unseal-vault | Auto-Unseal-Token (Recovery-Quelle für Playbook-Re-Runs) |
| `/etc/vault.d/role-id`, `/etc/vault.d/secret-id` | alle Nomad-Knoten | AppRole-Credentials des Host-Vault-Agents |
| `/opt/nomad/tls/{ca,cert,key}.pem` | alle Nomad-Knoten | täglich rotierte Nomad-mTLS-Zertifikate |
| `/etc/nomad.d/nomad.env` | fsn1 | Nomad-Server-Vault-Token (72h-Period) |
| `/etc/nomad.d/docker-auth.json` | API-Knoten | Docker-Hub-Pull-Credentials (Vault-Agent-Template) |
| `/opt/toob-monitoring/` | fsn1 | Monitoring-Compose-Stack inkl. rotierter Tokens/Certs |
| `/opt/vault/config/backup-{role,secret}-id` | fsn1 | Backup-AppRole-Credentials |
| `/etc/caddy/certs/origin.{pem,key}` | API-Knoten | Cloudflare-Origin-CA-Material |
| `/opt/toob-worker/{bin,vmlinux,rootfs.ext4}` | Worker | Firecracker-Laufzeitumgebung (aus Golden Image) |
| `/var/lib/prometheus/node-exporter/*.prom` | alle | Textfile-Collector-Metriken (Backups, TTLs, Failures, Rotation) |