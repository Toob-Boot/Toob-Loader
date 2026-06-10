# Kurzeinordnung

Ich habe die `deploy/`-Seite (Ansible, Terraform, Packer, Nomad, Vault, Caddy, Monitoring) gegen die Go-Quellen (`internal/server`, `internal/worker`, `internal/autoscaler`, `migrations`, `cmd/*`) durchgespielt — Env-Vars, Vault-Pfade/Policies, mTLS-CNs, Ports, Hostnamen, Key-Namen, Image-Referenzen.

Vorab das Wichtigste: Es gibt **mehrere harte Boot-Blocker**, bei denen der API-Server gar nicht erst hochkommt, und der **Autoscaler ist in der verdrahteten Form praktisch funktionsunfähig**. Drei Querschnittsmuster ziehen sich durch fast alle Befunde:

1. **CA-Verteilung unvollständig** — selbstsignierte Vault-/Ubicloud-CAs landen auf dem Host unter `/etc/ssl/certs/`, werden aber weder in den distroless-Container gemountet noch via `update-ca-certificates` in den System-Trust-Store aufgenommen. Damit scheitert TLS auf beiden Ebenen.
2. **Container ≠ Host** — der API-Job läuft distroless/read-only ohne Volume-Mounts, viele Configs gehen aber von Host-Pfaden aus.
3. **Zwei divergierende Provisioning-Modelle für Worker** (Terraform+Ansible vs. Autoscaler-cloud-init), die getrennt gepflegt werden und auseinanderlaufen.

---

## P0 — Boot-/Grundblocker (System startet nicht)

**1. Signing-Key-Name divergiert (Code ↔ Vault ↔ Policy)**
`app.go`: `signing.NewTransitSigner(..., "toob-registry-ed25519")`. Aber `init.sh` erzeugt `transit/keys/toob-registry-signing`, die Policy `registry-api.hcl` erlaubt `transit/sign/toob-registry-signing`, und `deploy.sh` nutzt `hashivault://toob-registry-signing`. Der Code signiert also gegen einen Key, der weder existiert noch policy-seitig erlaubt ist → jeder Publish/Signaturvorgang failt mit 403/404.
**Fix:** In `app.go` auf `"toob-registry-signing"` umstellen (Deploy-Seite ist intern konsistent).

**2. `registry-api` Vault-Policy fehlt `secret/data/oauth-aes`**
`config.go` → `loadOAuthAESKey` liest `secret/oauth-aes` **unbedingt beim Start**. `registry-api.hcl` listet database/github-app/github-oauth/webhook/cloudflare/s3 — aber **nicht** oauth-aes. → `config.Load()` failt → Server (und der `migrate`-Prestart-Task) booten nicht. `seed.sh` seedet das Secret zwar, die Policy darf es nur nicht lesen.
**Fix:** `path "secret/data/oauth-aes" { capabilities = ["read"] }` ergänzen.

**3. `VAULT_CA_CERT` nicht gesetzt + Vault-CA nicht im Container**
Vault nutzt ein selbstsigniertes Cert (`/opt/vault/tls/fullchain.pem`). Das distroless-Image trägt nur öffentliche Roots. `config.go` kann via `VAULT_CA_CERT` eine CA laden, aber `registry-api.nomad.hcl` setzt die Var nicht und mountet die CA nicht. → TLS zu `vault.the-toob.com:8200` scheitert (`x509: unknown authority`) → Boot failt schon vor allem anderen.
**Fix:** Vault-CA via Nomad-`template`/`artifact` in `secrets/` schreiben und `VAULT_CA_CERT` darauf zeigen lassen. Gleiches gilt host-seitig: `vault-ca.pem` wird nach `/etc/ssl/certs/` kopiert, aber nie `update-ca-certificates` ausgeführt — auch Nomads eigene Vault-Anbindung (`server.hcl` `vault{}` ohne `ca_file`) scheitert dadurch.

**4. Docker ist auf den API-Nodes nirgends installiert**
`install-binaries.sh` (Packer) installiert nomad/vault/caddy + curl/jq/iptables — **kein Docker**. Die Playbook-Plays installieren ebenfalls kein Docker. Aber `server.hcl`/`client.hcl` aktivieren den `docker`-Driver und der `registry-api`-Job läuft `driver = "docker"`. → Job nicht platzierbar. (Die Monitoring-Compose-Files brauchen zusätzlich `docker compose`.)
**Fix:** Docker in den Golden-Image-Build aufnehmen.

**5. API-Image wird nie in eine Registry gepusht**
`deploy.sh` baut `toob-registry-api:latest` lokal, signiert den Digest und ruft `nomad job run -var image_digest=<digest>`. Es gibt **kein `docker push`** und keine Container-Registry in der Infra. Nomads docker-Driver auf den Nodes versucht den Digest zu *pullen* → schlägt fehl, weil das Image nur auf der CI-Maschine existiert. `get_digest` fällt zudem auf `.Id` (lokaler Digest) zurück, der remote ohnehin nicht auflösbar ist.
**Fix:** Registry (GHCR/Harbor) einführen, push vor `nomad job run`, Pull-Credentials im Job.

**6. `registry-api`-Job-Vault-Stanza ohne `nomad-node-pki`**
Der Job rendert ein mTLS-Server-Cert via `pki/issue/nomad-cluster`, deklariert aber nur `vault { policies = ["registry-api"] }`. `registry-api.hcl` enthält **kein** `pki/issue`. → Template-Render schlägt fehl → Task blockiert. (Der AppRole `registry-api` hat `registry-api,nomad-node-pki`, der Nomad-Job listet aber nur `registry-api`.)
**Fix:** `policies = ["registry-api", "nomad-node-pki"]`.

**7. DB-`sslrootcert` zeigt auf Host-Pfad, der im Container fehlt**
Das Playbook baut `...&sslmode=verify-full&sslrootcert=/etc/ssl/certs/ubicloud-ca.pem` und legt es in Vault `secret/database`. Im distroless-Container (read-only, kein Mount) existiert dieser Pfad nicht → pgx `verify-full` scheitert.
**Fix:** Ubicloud-CA via Nomad-Template in `secrets/` mounten und `sslrootcert` dorthin zeigen lassen.

---

## P1 — Integrations-Mismatches (Kernfeatures brechen)

**8. Worker→API mTLS: Hostname nicht im Server-Cert-SAN**
Worker verbinden sich zu `api.internal.the-toob.com:8443` (`TOOB_API_URL`). Das interne Server-Cert wird mit `common_name=api.global.nomad`, `alt_names=localhost`, `ip_sans=127.0.0.1` ausgestellt — `api.internal.the-toob.com` ist **kein SAN**. Zusätzlich verbietet die PKI-Role (`allowed_domains="global.nomad,localhost"`) das Ausstellen eines `the-toob.com`-SAN überhaupt. Umgekehrt ist `api.global.nomad` zwar im Cert, aber **nicht** in `/etc/hosts` (dort steht nur `api.internal.the-toob.com`). → Hostname-Verifikation scheitert in beide Richtungen.
**Fix:** Entweder `TOOB_API_URL` auf `https://api.global.nomad:8443` + `/etc/hosts`-Eintrag, oder per-Node-IP-SANs ins Cert + Verbindung über IP. (Der Daemon-`NewAPIClient`-TLS-Code liegt mir nicht vor — prüfen, ob dort evtl. `ServerName`/`InsecureSkipVerify` greift.)

**9. Autoscaler-Job läuft `raw_exec` — auf API-Nodes deaktiviert**
`registry-autoscaler.nomad.hcl`: `driver = "raw_exec"`, `constraint meta.pool = "api"`. Auf API-Nodes ist `raw_exec` aber `enabled = false` (nur Worker bekommen via Ansible `enabled = true`; `server.hcl` hat gar keinen raw_exec-Stanza). → Job nicht platzierbar.

**10. Autoscaler: kein `DATABASE_URL`, Policy verbietet DB-Secret**
`autoscaler/config.go` verlangt `DATABASE_URL` (sonst Fehler). Der Job-Template setzt HCLOUD/NOMAD/VAULT-Vars, **kein** `DATABASE_URL`. Und `registry-autoscaler.hcl` erlaubt nur `secret/data/hetzner` + approle-secret-id — **nicht** `secret/data/database`. → LoadConfig failt.

**11. Autoscaler-Policy nirgends geladen + nicht im Token-Role**
`init.sh` schreibt registry-api/registry-worker/backup/nomad-node-pki/nomad-server — **nicht** `registry-autoscaler`. Die Token-Role `nomad-cluster` erlaubt nur `registry-api,registry-worker,nomad-node-pki`. Der Job fordert `policies = ["registry-autoscaler"]` → Nomad kann den Vault-Token gar nicht erzeugen. `deploy/vault/policies/registry-autoscaler.hcl` ist eine **Waise**.

**12. Autoscaler ruft Nomad-API ohne Token — aber ACLs sind an**
`nomad.go` setzt keinen `X-Nomad-Token`. `server.hcl` hat `acl { enabled = true }`. → list-nodes/drain/purge → 403. (Config-Struct hat überhaupt kein Nomad-Token-Feld.)

**13. Autoscaler verwechselt AppRole-*Name* mit *role_id***
In `scaleUp` wird `RoleID: a.cfg.WorkerRoleID` (= `"registry-worker"`, der Rollen**name**) ins cloud-init geschrieben und als `VAULT_ROLE_ID` für den Vault-Agent des Workers verwendet. Das echte `role_id` ist aber eine UUID (`vault read auth/approle/role/registry-worker/role-id`). Für den Secret-ID-Pfad ist der Name korrekt, als role_id beim AppRole-Login ist er falsch → Worker-Vault-Auth scheitert. Der Terraform-Worker-Pfad nimmt `vault_role_id` korrekt als separate UUID — die beiden Pfade widersprechen sich.

**14. Caddy: nirgends ausgerollt/gestartet + Cert-Probleme**
Kein Play kopiert `Caddyfile`/`caddy.service` oder startet Caddy. `origin.pem`/`origin.key` (Cloudflare Origin CA) werden nicht provisioniert → `caddy validate` (ExecStartPre) failt. Und das Cert-Verzeichnis `/etc/caddy/certs` ist `0700 root:root`, Caddy läuft aber als User `caddy` → kann selbst bei vorhandenen Certs nicht lesen. → Der komplette Public-Ingress (TLS-Termination, Security-Header, Reverse-Proxy) ist nicht verdrahtet.

**15. Prometheus-Scrape der API trifft falschen Bind/Port**
`prometheus.yml` scrapt `http://10.0.1.10:8080/metrics` und `10.0.1.11:8080`. Aber der öffentliche Server bindet auf `BindAddress` (Default `127.0.0.1`), und der Nomad-Job setzt `BIND_ADDRESS` **nicht** → Server lauscht nur lokal, Cross-Node-Scrape failt. Zugleich deutet `main.go` (`"mTLS internal worker & metrics"`) darauf hin, dass `/metrics` evtl. auf dem internen `:8443`-mTLS-Server liegt — dann ist der `http://...:8080`-Scrape doppelt falsch. Caddy blockt `/metrics*` mit 403 (edge). → Klären, **wo** `/metrics` serviert wird, dann Bind/Port/Scheme angleichen.

**16. Golden-Image-Snapshot heißt nicht `toob-golden-image`**
`image.pkr.hcl` setzt kein `snapshot_name`/`snapshot_labels` → die hcloud-Snapshot bekommt einen Default-Namen. Der Autoscaler ruft aber `image: "toob-golden-image"` → Image-Lookup bei Hetzner scheitert → Scale-up failt. (Terraform-Worker nutzen `ubuntu-24.04` + Ansible; Autoscaler-Worker erwarten das Golden-Image mit vorinstallierten Binaries — wenn es fehlt/falsch heißt, haben die dynamischen Worker weder nomad/vault noch einen Ansible-Lauf.)

**17. `monitoring`-Policy + AppRole werden nie erzeugt**
`vault-agent-monitoring.hcl` braucht `/etc/vault.d/monitoring-role-id` + `monitoring-secret-id`. `init.sh` legt **keinen** `monitoring`-AppRole an und schreibt `monitoring.hcl` nicht. → vault-agent-monitoring scheitert → Prometheus-Vault-Token (`/etc/prometheus/vault-token`) wird nie rotiert/erzeugt → Vault-Scrape tot. Zweite Waisen-Policy.

**18. Monitoring-Stack wird nur kopiert, nie gestartet — und Env fehlt**
Das Playbook legt `/opt/toob-monitoring/*` ab, führt aber kein `docker compose up` aus. `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_GITHUB_CLIENT_ID/SECRET`, `DISCORD_WEBHOOK_URL` (compose + alerting.yml + alertmanager.yml) werden nirgends bereitgestellt. → Grafana/Alertmanager starten nicht bzw. ohne Alerting-Routing.

**19. `seed.sh` ist interaktiv, Playbook ruft es nicht-interaktiv**
Das Playbook setzt beim `seed.sh`-Aufruf nur `SEED_DB_URL`. Für alle anderen Secrets (`github-app`, `github-oauth`, `webhook`, `cloudflare`, `s3`) fällt `read` auf EOF zurück → **leere** Secrets werden geschrieben → später failt `vault.MustGet("app_id"/...)` im API-Boot. → Entweder alle `SEED_*`-Env-Vars im Play setzen oder `seed.sh` manuell laufen lassen (klar dokumentieren).

---

## P2 — Wahrscheinlich / explizit verifizieren

**20. Hetzner-Firewall öffnet 8200/8201/9100 im Privatnetz nicht.** `toob-api-firewall` öffnet 22/80/443/4646-4648/8443, aber nicht 8200 (Vault), 8201 (Raft-Cluster fsn1↔hel1) oder 9100 (node-exporter). Falls die Hetzner-Cloud-Firewall Privatnetz-Traffic filtert (was die privat-skopierten SSH/Nomad-Regeln nahelegen), scheitern Vault-Zugriff von hel1/Workern/Nomad-Clients, Raft-Clustering und sämtliche node-exporter/Vault-Scrapes. → Verhalten der Firewall im Privatnetz verifizieren, dann fehlende Ports ergänzen.

**21. Nomad-HTTP nur auf `127.0.0.1`, aber `deploy.sh` läuft remote.** `nomad job run` aus der CI braucht einen SSH-Tunnel (nicht in `deploy.sh` enthalten) **plus** einen ACL-Token (ACLs aktiv) — beides ist im Deploy-Flow nicht aufgelöst.

**22. `cdn.the-toob.com` nicht provisioniert.** `S3_PUBLIC_URL=https://cdn.the-toob.com` und `GetPublicURL`/`PutStream` geben diese Basis-URL zurück, aber Cloudflare-TF erzeugt nur `ci.the-toob.com` (LB). Kein DNS/Routing für cdn. Zudem ist die Download-Strategie uneinheitlich (Cloudflare-Cache-Rule auf `/download`, Code liefert teils `cdn.../key`, teils Presigned-GET).

**23. Vault-Raft `api_addr`/`cluster_addr` für beide Nodes identisch.** Das Playbook templatet nur die `listener address` pro Node, lässt aber `api_addr`/`cluster_addr = vault.the-toob.com:820x` (= beide IPs). Jeder Raft-Node muss seine eigene Adresse advertisen → HA-Leader-Election instabil.

**24. `/health` vs `/ready`.** Cloudflare-Monitor nutzt `/health`, Caddy + Nomad-Check nutzen `/ready`. Der Server muss **beide** servieren — im `router`-Code (nicht beigelegt) verifizieren.

**25. `registry_index_update`-NOTIFY-Quelle.** `cache_sync.go` LISTENt darauf; keine Migration legt einen NOTIFY-Trigger an. Prüfen, dass der App-Code `pg_notify('registry_index_update', ...)` bei Writes ausführt — sonst synchronisieren die API-Nodes ihren Cache nie.

**26. Gossip-Key-Konsistenz.** Ansible-Nodes erhalten ggf. einen operator-gesetzten `NOMAD_GOSSIP_KEY`; der Autoscaler-Job zieht den Key **nicht** aus Vault/Config und fällt auf den hartkodierten Default zurück → autoskalierte Worker mit abweichendem Key joinen nicht. (Außerdem ist `securegossipkey1234…==` als Default ein Security-Smell.)

**27. Dynamische Worker fehlen im Monitoring.** `prometheus.yml` node-exporter-Targets sind statisch (bastion/api/unseal-vault) — autoskalierte Worker werden nie gescrapt.

**28. Autoscaler-Binary + User nicht provisioniert.** Kein Build/Deploy für `/opt/toob-autoscaler/bin/autoscaler` (Makefile baut nur `worker`/`vm-runner`, `deploy.sh` nur die API). `setup-host.sh` legt `toob-worker` an, **nicht** `toob-autoscaler` (vom Job als `user` verlangt).

**29. `registry-snapshot.ext4` ungeklärt.** Der vm-runner mountet `/dev/vdb` als Registry-Snapshot und `worker/config.go` `Validate()` verlangt `SnapshotPath` existent. `build-rootfs.sh` baut nur `rootfs.ext4` — wer/wie `registry-snapshot.ext4` erzeugt und aktualisiert, ist nicht definiert.

**30. cosign ↔ ed25519 / CI-Signing-Token.** `deploy.sh` signiert Container-Images via `hashivault://toob-registry-signing` (ed25519-Key) — cosign-Transit-Support für ed25519 prüfen. Außerdem: welcher Vault-Token/Policy steht der CI für `transit/sign` zur Verfügung? (Nur `registry-api` hat den Pfad, gilt aber für die API-Nodes.)

---

## Was bereits sauber zusammenpasst (zur Einordnung)

Damit klar ist, dass das nicht durchgängig kaputt ist:

- **Auto-Unseal-Key-Name** ist über `vault.hcl` / `init-unseal.sh` / `autounseal.hcl` konsistent (`autounseal-toob-registry`).
- **Worker-mTLS-Identität**: `mtls.go` verlangt CN `worker.global.nomad`, exakt das stellt der Worker-Job aus (Trust-Kette via gemeinsamen `issuing_ca` passt — nur der Hostname-SAN in #8 nicht).
- **S3-Endpoint/Bucket/Public-URL** als Env + Credentials aus Vault `secret/s3` sind sauber getrennt und konsistent verdrahtet.
- **DB-Schema ↔ Autoscaler-Queries**: alle referenzierten Spalten/Stati (`worker_id`, `started_at`, `QUEUED/RUNNING/PASSED/FAILED`, `COMPILING`) existieren in den Migrationen 002/010/017.
- **`migrate`-Subcommand** ist korrekt als Nomad-Prestart-Task verdrahtet.
- **Zero-Trust-Worker**: minimale `registry-worker.hcl` (nur PKI-Issue, keine DB/S3/Vault-Secrets) deckt sich mit dem Daemon-Design.

---

Unterm Strich: Die schnellsten Wins für „lauffähig überhaupt" sind die **P0**-Punkte 1–7 (alle blockieren den API-Boot bzw. das Image-Deployment). Der **Autoscaler** (P1 9–13, P2 28) braucht eine eigene, zusammenhängende Überarbeitung — so wie er jetzt verdrahtet ist, kann er weder platziert noch authentifiziert werden noch korrekte Worker bootstrappen.

Den `router`- und `worker/daemon`-Code (Endpoints, `/health`/`/ready`, `NewAPIClient`-TLS, pg_notify) hatte ich nicht vorliegen — die damit verknüpften Punkte (#8, #15, #24, #25) sind als „verifizieren" markiert; wenn du die Dateien nachreichst, schließe ich die Lücken.

Wenn du das als abhakbare Markdown-Checkliste (mit Datei-/Zeilen-Referenzen pro Fix) willst, sag kurz Bescheid.
