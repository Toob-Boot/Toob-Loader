# Backlog — Befunde aus dem Deployment-Code

**Ergänzt:** `BACKLOG-devops-umbau.md`. Dieses Dokument löst die dort mit **[Dateien nötig]**
markierten Stellen auf und trägt nach, was erst aus dem tatsächlichen Code sichtbar wurde.

**Grundlage:** `toob-registry/deploy/` (Packer, Terraform, Ansible, Nomad, Monitoring, `deploy.sh`)
und `internal/ops/` (Stage-Engine, Stages, Topology, UI).

**Einordnung:** Der Stack ist besser gebaut, als das Runbook vermuten ließ. Die
Stage-Engine mit Preconditions/Postconditions/Teardown, die Plan-Gates mit
Destroy-Warnung, die Zeremonie-Gates über `TOOB_CEREMONY:`-Marker, die
Cross-Environment-Safety-Prüfung in `prereqs.go` und die Massenlöschbremse im DB-Pruner sind
Arbeit, die der Umbau erhält. Die Befunde unten sind punktuell, nicht strukturell — mit zwei
Ausnahmen (BEF-003, BEF-004), die vor allem anderen weg müssen.

**Präfix `BEF-`**, damit die Nummern nicht mit `OPS-` aus dem Umbau-Backlog kollidieren.

---

## Übersicht

| ID | Titel | Prio | Typ | Aufw. | Datei |
|---|---|---|---|---|---|
| BEF-001 | Geleakte Dev-Credentials rotieren | P0 | security | S | `.toob-ops-secrets.dev.json` |
| BEF-002 | Secrets- und State-Dateien aus dem Repo ausschließen | P0 | security | S | `deploy/` |
| BEF-003 | Teardown löscht Produktions-Vault-Backups | P0 | bug | S | `stages/terraform.go` |
| BEF-004 | Seccomp-Profil ist wirkungslos | P0 | security | M | `api/seccomp-api.json` |
| BEF-005 | `pgp_key_count` undefiniert — Prod-Vault-Init bricht ab | P0 | bug | S | `ansible/playbook.yml` |
| BEF-006 | Backup-Bucket nicht umgebungsgetrennt | P1 | security | M | `vault/scripts/backup.sh` u. a. |
| BEF-007 | Stale Failure-Metriken nach Wiederanlauf | P1 | bug | S | `monitoring/systemd/` |
| BEF-008 | Nomad-/Vault-Versionsdrift Tooling ↔ Server | P1 | bug | M | `Dockerfile.ops`, `install-binaries.sh` |
| BEF-009 | Loki ohne Authentifizierung | P1 | security | M | `monitoring/loki/loki.yml` |
| BEF-010 | Vault-PKI mit 24 h TTL im künftigen Datenpfad | P1 | security | M | `nomad/vault-agent*.hcl` |
| BEF-011 | Cloudflare-IP-Liste in Caddy driftet | P2 | bug | S | `caddy/Caddyfile.j2` |
| BEF-012 | Regex-`replace` auf Nomad-Konfigurationen | P2 | refactor | M | `ansible/playbook.yml` |
| BEF-013 | `OutputCapture.Write` paniert | P2 | bug | S | `ops/exec/capture.go` |
| BEF-014 | Teardown-`actionGoBack` mit fehlerhafter Indexlogik | P2 | bug | S | `ops/engine/engine.go` |
| BEF-015 | Ops-Container mit `--privileged` und Docker-Socket | P2 | security | M | `cmd/toob-ops/main.go` |
| BEF-016 | `--insecure-ignore-tlog` unbegründet | P2 | security | S | `api/deploy.sh` |
| BEF-017 | CIDR-Plan kollidiert mit Staging | P1 | infra | S | `ops/topology/topology.go` |
| BEF-018 | Tote Konfigurationsdateien neben Templates | P3 | cleanup | S | `monitoring/prometheus/` |
| BEF-019 | Cosign-Token nicht im TTL-Exporter | P2 | security | S | `token-ttl-exporter.sh.j2` |
| BEF-020 | `.env.<env>` wird zum Klartext-Secret-Store | P2 | security | M | `stages/prereqs.go` |

---

## BEF-001 — Geleakte Dev-Credentials rotieren

**Prio:** P0 · **Typ:** security · **Aufwand:** S

`deploy/.toob-ops-secrets.dev.json` wurde außerhalb des Systems geteilt. Enthalten sind ein
gültiger Vault-Token, ein Nomad-Management-Token und **beide WireGuard-Private-Keys**.

Der WireGuard-Client-Key wiegt am schwersten: er gewährt Netzzugang zu `10.1.0.0/16`, und dort
sind SSH auf allen Knoten und Vault auf `10.1.1.10:8200` erreichbar. Der Nomad-Token ist,
wenn es der Bootstrap-Token ist, ein Management-Token mit voller Job-Kontrolle.

**Lösung**
1. `vault token revoke` für den Vault-Token.
2. Nomad-Token löschen; falls Bootstrap-Token, ACL-Bootstrap zurücksetzen.
3. WireGuard-Keys neu erzeugen. Über die CLI: die Werte im Secrets-File leeren, dann Phase 3
   erneut laufen lassen — `ensureWireGuardKeys` in `stages/terraform.go` generiert sie dann
   neu über `crypto/ecdh`.
4. Prüfen, ob dieselben Werte in `.env.dev` oder in einer anderen Umgebung stehen. Die
   Cross-Environment-Prüfung in `prereqs.go` (`checkCrossEnvironmentSafety`) deckt genau das
   ab und sollte einmal bewusst gelaufen sein.

**Akzeptanzkriterien**
- [ ] Der alte Vault-Token liefert `403`.
- [ ] Das alte WireGuard-Profil baut keine Verbindung mehr auf.
- [ ] Kein Wert aus der Datei ist irgendwo noch gültig.

---

## BEF-002 — Secrets- und State-Dateien aus dem Repository ausschließen

**Prio:** P0 · **Typ:** security · **Aufwand:** S

Unter `deploy/` entstehen im Betrieb: `.toob-ops-secrets.<env>.json`,
`.toob-ops-state.<env>.json`, `wg0.<env>.conf`, `nomad-deployer-token.json`,
`vault-deployer-token.json` und `logs/<env>/*.log`.

Die beiden Deployer-Token-Dateien werden von `stages/ansible.go` nach dem Einlesen gelöscht —
das ist bereits richtig gemacht. Die übrigen bleiben liegen. Die Logs können Ausgaben
enthalten, die trotz `no_log` durchrutschen.

**Lösung**
`.gitignore`-Einträge für alle Muster, plus ein CI-Check, der den Index dagegen prüft. Falls
bereits committet: History bereinigen und für jeden betroffenen Wert BEF-001 anwenden.

---

## BEF-003 — Teardown löscht Produktions-Vault-Backups

**Prio:** P0 · **Typ:** bug · **Aufwand:** S · **Datei:** `internal/ops/stages/terraform.go`

**Problem**
In `cleanupStateBuckets`:

```go
buckets := []string{
    fmt.Sprintf("toob-terraform-state-%s", env),
    "toob-vault-backups",
}
```

Beide Buckets werden geleert — inklusive aller Objektversionen und unvollständiger
Multipart-Uploads — und anschließend gelöscht. `emptyNonStateBuckets` leert
`toob-vault-backups` zusätzlich vor dem Terraform-Destroy.

Der Bucket ist **nicht** umgebungspräfigiert: `backup.sh` und `backup-nomad.sh` haben
`S3_BUCKET="toob-vault-backups"` hartkodiert, und `bootstrapStateBucket` legt ihn ohne Suffix
an. Dev-, Staging- und Produktions-Snapshots liegen also im selben Bucket.

Konsequenz: **`toob-ops destroy --env dev` vernichtet die Vault-Snapshots der Produktion.**
Ein Aufräumvorgang in der Entwicklungsumgebung zerstört die Wiederherstellungsbasis der
Produktion — und zwar leise, weil der Teardown ansonsten wie erwartet durchläuft.

**Lösung**
Kurzfristig (Minuten): `"toob-vault-backups"` aus beiden Listen entfernen. Der Bucket wird von
keinem Terraform-Modul verwaltet und gehört nicht in den Teardown-Pfad.

Dauerhaft: BEF-006 trennt den Bucket pro Umgebung, danach kann er wieder in den Teardown —
mit einer Namensprüfung als zweiter Verteidigungslinie, die einen Bucket ohne Umgebungssuffix
ablehnt.

**Akzeptanzkriterien**
- [ ] Ein Teardown mit `--env dev` fasst keinen Bucket ohne `-dev`-Suffix an.
- [ ] Testlauf gegen einen Mock-S3-Endpunkt weist das nach.

---

## BEF-004 — Seccomp-Profil ist wirkungslos

**Prio:** P0 · **Typ:** security · **Aufwand:** M · **Datei:** `deploy/api/seccomp-api.json`

**Problem**
Die Datei dokumentiert im eigenen Kommentar:

> Default action: ERRNO (deny). Only the ~45 syscalls that a Go HTTP server actually uses are
> allowed. Everything else is blocked.
> Notable blocks: mount, ptrace, reboot, kexec_load, init_module, setns, unshare, pivot_root —
> prevents container escape, kernel module loading, and namespace manipulation.

und setzt dann:

```json
"defaultAction": "SCMP_ACT_ALLOW"
```

Damit ist jeder Syscall erlaubt und die Whitelist reine Dekoration. Keiner der als „notable
blocks" genannten Aufrufe ist blockiert. Das Profil ist im Nomad-Job unter
`security_opt = ["seccomp=/opt/toob-registry/seccomp-api.json"]` eingebunden und erzeugt in
jeder Sicherheitsbetrachtung den Eindruck einer Härtung, die es nicht leistet.

**Lösung**
Nicht direkt auf `SCMP_ACT_ERRNO` schalten — die Liste stammt laut Kommentar aus einem
`strace` und wird für aktuelle Go-Versionen unvollständig sein (`statx`, `openat2`,
`fchmodat2`, `membarrier` fehlen unter anderem).

Dreistufig:
1. `"defaultAction": "SCMP_ACT_LOG"` ausrollen.
2. Eine Woche Produktionslast, `auditd`-Log auswerten, fehlende Syscalls ergänzen.
3. `"defaultAction": "SCMP_ACT_ERRNO"`.

**Akzeptanzkriterien**
- [ ] `defaultAction` ist `SCMP_ACT_ERRNO`.
- [ ] Der API-Container bedient Last ohne Syscall-Fehler.
- [ ] Negativtest: ein Testcontainer mit demselben Profil kann `mount` nicht aufrufen.

---

## BEF-005 — `pgp_key_count` ist undefiniert

**Prio:** P0 · **Typ:** bug · **Aufwand:** S · **Datei:** `deploy/ansible/playbook.yml`

**Problem**
Die Task „Initialize Primary Vault (Production - PGP Encrypted)" hat als letzte Bedingung:

```yaml
- pgp_key_count.stdout | int == 5
```

`pgp_key_count` wird im gesamten Playbook nirgends registriert. Die vorangehende Task
registriert `pgp_keys_stat` (eine `stat`-Schleife über `op1.asc` … `op5.asc`), und die
Fail-Task dazwischen wertet korrekt `pgp_keys_stat.results` aus.

Ansible bricht bei einer undefinierten Variablen im `when` mit einem Fehler ab. Der
PGP-Initialisierungspfad des Primary-Vaults ist damit nie erfolgreich durchlaufen — was
erklärt, warum der State im Repository `dev` zeigt: in dev greift der andere Zweig
(`vault_env_tier != 'production'`, Init 1/1).

**Lösung**
Die Bedingung ist ohnehin redundant, weil die Fail-Task davor bereits abbricht, wenn nicht
alle fünf Schlüssel vorhanden sind. Ersatzlos streichen — oder, wenn eine explizite Prüfung
gewünscht ist:

```yaml
- pgp_keys_stat.results | selectattr('stat.exists') | list | length == 5
```

**Akzeptanzkriterien**
- [ ] Ein Lauf mit `VAULT_ENV=production` gegen eine Wegwerf-Umgebung erreicht die Zeremonie
      und bricht dort kontrolliert mit `TOOB_CEREMONY:PRIMARY_UNSEAL` ab.
- [ ] Ansible-Lint im CI meldet undefinierte Variablen in `when`-Blöcken.

---

## BEF-006 — Backup-Bucket nicht umgebungsgetrennt

**Prio:** P1 · **Typ:** security · **Aufwand:** M

**Problem**
`toob-vault-backups` ist an drei Stellen hartkodiert und für alle Umgebungen dieselbe:
`vault/scripts/backup.sh`, `nomad/scripts/backup-nomad.sh` und `bootstrapStateBucket` in
`stages/terraform.go`. Der Terraform-State ist dagegen korrekt präfigiert
(`toob-terraform-state-<env>`).

Das ist auch ohne BEF-003 eine Vermischung von Vertrauensbereichen: Dev-Credentials haben
Schreib- und Löschzugriff auf Produktions-Snapshots.

**Lösung**
`toob-vault-backups-<env>`, konsistent in allen drei Stellen sowie in `emptyNonStateBuckets`
und `cleanupStateBuckets`. Bestehende Objekte in den neuen Produktions-Bucket kopieren, bevor
der alte angefasst wird.

**Akzeptanzkriterien**
- [ ] Kein Bucket-Name ohne Umgebungspräfix im gesamten `deploy/`-Baum (Grep-Test im CI).
- [ ] Produktions-Snapshots sind im neuen Bucket restorebar (Nachweis über BEF-Restore-Test).

---

## BEF-007 — Stale Failure-Metriken nach Wiederanlauf

**Prio:** P1 · **Typ:** bug · **Aufwand:** S

**Problem**
`monitoring/systemd/notify-failure.sh` schreibt `service_failure_<unit>.prom` mit Wert 1.
Nur `nomad.service` räumt sie beim Start wieder weg:

```ini
ExecStartPost=-/bin/rm -f /var/lib/prometheus/node-exporter/service_failure_%n.prom
```

`caddy.service`, `vault.service`, die Vault-Agents und alle Backup-Timer haben zwar
`OnFailure=notify-failure@%n`, aber kein Gegenstück.

Konsequenz: Ein einmal fehlgeschlagener Dienst hält `SystemdServiceFailed` (Alert 2,
`severity: critical`) dauerhaft aktiv, auch nach erfolgreicher Wiederherstellung. Nach dem
zweiten Vorfall glaubt niemand mehr dem Alarm — und das ist der Alarm, der im Ops-Home-Dashboard
die Statusmatrix für Nomad und Caddy speist.

**Lösung**
Einheitlich über eine `notify-recovery@.service` als `ExecStartPost` in allen Units mit
`OnFailure`. Dann liegt die Logik an einer Stelle statt in jeder Unit-Datei.

**Akzeptanzkriterien**
- [ ] `systemctl stop caddy && systemctl start caddy` ⇒ Alarm löst aus und löst sich wieder auf.
- [ ] Jede Unit mit `OnFailure` hat einen Aufräumpfad (Prüfskript).

---

## BEF-008 — Versionsdrift zwischen Tooling und Servern

**Prio:** P1 · **Typ:** bug · **Aufwand:** M

**Problem**

| | Nomad | Vault |
|---|---|---|
| `Dockerfile.ops` (Tooling-Container) | 2.0.3 | 2.0.2 |
| `packer/scripts/install-binaries.sh` (Server) | 1.8.1 | 1.16.2 |

Eine Major-Version Unterschied zwischen CLI und Server. `deploy.sh` ruft `nomad job run` und
`nomad job status` gegen den Server, das Playbook ruft `vault operator init`, `vault kv put`
und `nomad acl bootstrap` — alles CLI gegen Server über die Versionsgrenze hinweg.

Dass es bisher funktioniert, ist kein Beweis für Kompatibilität, sondern dafür, dass die
verwendeten Kommandos stabil geblieben sind.

**Lösung**
Eine einzige Versionsquelle. Das Muster existiert im Repository bereits und funktioniert gut:
`compiler/compiler_manifest.json` ist die einzige Wahrheit für den Compiler-Build, wird von
`build-compiler.sh` gelesen und über ein Label verifiziert.

Analog: `deploy/versions.json`, gelesen von `Dockerfile.ops` (als Build-Arg) und
`install-binaries.sh`. Dazu ein Precondition-Check in Phase 0, der CLI- und Cluster-Version
vergleicht, sobald der Cluster erreichbar ist.

**Akzeptanzkriterien**
- [x] Nomad- und Vault-Version stehen an genau einer Stelle.
- [ ] Phase 0 warnt bei Major-Version-Abweichung.

> **Offener Punkt:** Der Phase-0-Precondition-Check (CLI- vs. Cluster-Version vergleichen)
> ist erst lauffähig, wenn der Cluster erreichbar ist (Phase 3+). Separates Ticket,
> nicht im Scope von BEF-008.

---

## BEF-009 — Loki ohne Authentifizierung

**Prio:** P1 · **Typ:** security · **Aufwand:** M · **Datei:** `monitoring/loki/loki.yml`

**Problem**
```yaml
auth_enabled: false
```

Der Port ist im Compose-Template auf die private IP gebunden
(`{{ ansible_host }}:3100:3100`), nicht auf localhost. Jeder Knoten im Privatnetz — inklusive
der Firecracker-Worker-Hosts, auf denen fremder Code ausgeführt wird — kann damit alle Logs
aller Dienste lesen und schreiben.

Solange alles ein Projekt ist, ist das eine bewusste Vereinfachung. In der Zielarchitektur
pushen mehrere Projekte in dieselbe Instanz, und die Kontrollebene erlaubt genau einen
eingehenden Port von den Spokes — diesen hier.

**Lösung**
`auth_enabled: true`, `X-Scope-OrgID` pro Projekt, Alloy sendet den Header (in
`config.alloy.j2` am `loki.write`-Block). Retention-Cap und Rate-Limit pro Mandant.
Grafana-Datenquellen pro Ordner mit festem Mandantenkontext.

**Reihenfolge:** Muss stehen, **bevor** ein zweites Projekt in dieselbe Instanz schreibt.
Danach ist es eine Datenmigration statt einer Konfigurationsänderung.

**Akzeptanzkriterien**
- [ ] Ein Push ohne `X-Scope-OrgID` wird abgelehnt.
- [ ] Eine Abfrage mit Mandant A liefert keine Logs von Mandant B.

---

## BEF-010 — Vault-PKI mit 24 h TTL im künftigen Datenpfad

**Prio:** P1 · **Typ:** security · **Aufwand:** M

**Problem**
`nomad/vault-agent.hcl` und `vault-agent-api.hcl` rendern über
`/etc/vault.d/templates/nomad-tls.json.tpl` ein TLS-Bundle aus `pki/issue/nomad-cluster`.
`init.sh` legt die Rolle laut Runbook mit TTL 24 h / max 72 h an. Alert 8
(`NomadTLSRotationFailed`) feuert bei über 20 Stunden ohne Rotation.

Für die Registry ist das die richtige Entscheidung — kurze TTLs erzwingen, dass Rotation
nachweislich funktioniert, und der Alarm ist scharf gestellt. Der Bundle-Ansatz (eine
Issuance, ein JSON, atomares Entpacken über `unpack-nomad-tls.sh`) ist zudem sauber gelöst und
vermeidet genau den Cert/Key-Mismatch, den Mehrfach-Templates erzeugen.

Für den künftigen Update-Datenpfad wäre dieselbe Konstruktion eine harte
Verfügbarkeitskopplung: Vault fällt aus, und spätestens 24 Stunden später reißt die
Firmware-Auslieferung.

**Lösung**
Regel für die Zielarchitektur: **kein Secret im Datenpfad eines Produkts mit TTL unter 30
Tagen.** Konkret bedeutet das für `toob-update` keine Vault-PKI, sondern langlebige
Zertifikate aus einer deploy-verteilten CA, plus DB-URL und Token-HMAC-Key mit langer Lease
und `exit_after_auth = false` im Agent.

Die Registry behält ihre 24-Stunden-PKI unverändert.

**Akzeptanzkriterien**
- [ ] Ein Precondition-Check listet die Leases des Datenpfads und schlägt bei zu kurzen an.
- [ ] Vault 24 h abgeschaltet ⇒ Update-Auslieferung unverändert.

---

## BEF-011 — Cloudflare-IP-Liste in Caddy driftet

**Prio:** P2 · **Typ:** bug · **Aufwand:** S · **Datei:** `caddy/Caddyfile.j2`

**Problem**
```
trusted_proxies static 173.245.48.0/20 103.21.244.0/22 … 2c0f:f248::/32
```

Eine statisch einkopierte Liste. Das Terraform-Control-Plane-Modul lädt dieselben Ranges laut
Runbook **zur Apply-Zeit live** von cloudflare.com/ips für die Hetzner-Firewall.

Zwei Quellen für dieselbe Liste, eine davon eingefroren. Driftet sie, akzeptiert die Firewall
Verkehr aus einem neuen Range, aber Caddy übernimmt `X-Real-IP` aus `CF-Connecting-IP` nicht
mehr — das serverseitige Rate-Limiting sieht dann die Cloudflare-IP statt der Client-IP und
limitiert alle Anfragen aus diesem Range gemeinsam.

**Lösung**
Die Liste im Ansible-Lauf aus derselben Quelle beziehen wie Terraform und ins Template
einsetzen. Ein Postcondition-Check vergleicht die ausgerollte Liste mit der aktuellen.

---

## BEF-012 — Regex-`replace` auf Nomad-Konfigurationen

**Prio:** P2 · **Typ:** refactor · **Aufwand:** M · **Datei:** `ansible/playbook.yml`

**Problem**
Fünf aufeinanderfolgende `replace`-Tasks manipulieren `/etc/nomad.d/nomad.hcl`:
Server-IP (`10\.0\.1\.10:4647`), Gossip-Key, Pool-Meta, Datacenter und die
`raw_exec`-Aktivierung. Zwei davon sind mehrzeilige `(?s)`-Regexe über HCL-Blöcke.

`replace` meldet keinen Fehler, wenn das Muster nicht vorkommt. Ändert sich `client.hcl` oder
`server.hcl`, schlägt die Anpassung **stillschweigend** fehl, und der Knoten läuft mit der
Default-Konfiguration — bei der Server-IP hieße das: der Client sucht `10.0.1.10:4647`, also
die Produktionsadresse, aus einer Dev-Umgebung heraus.

**Lösung**
`server.hcl` und `client.hcl` werden Jinja-Templates mit echten Variablen. Das ist ohnehin
Voraussetzung für die Projektparametrisierung — Pool, Datacenter und Server-Adresse werden
dann projektabhängig.

**Akzeptanzkriterien**
- [ ] Keine `replace`-Task mehr auf Nomad-Konfigurationen.
- [ ] Ein absichtlich falsch gesetzter Template-Wert lässt `nomad config validate` fehlschlagen.

---

## BEF-013 — `OutputCapture.Write` paniert

**Prio:** P2 · **Typ:** bug · **Aufwand:** S · **Datei:** `internal/ops/exec/capture.go`

```go
// Write implements [io.Writer].
func (c *OutputCapture) Write(p []byte) (n int, err error) {
	panic("unimplemented")
}
```

Der Typ erfüllt damit `io.Writer`, aber jeder Aufruf über dieses Interface stürzt ab. Aktuell
ungenutzt — `runner.go` verwendet `AppendLine`, der Testrunner einen eigenen `uiTestWriter`.

Es ist eine geladene Falle: `cmd.Stdout = capture` kompiliert und paniert zur Laufzeit.

**Lösung**
Entweder korrekt implementieren (zeilenweise puffern, `AppendLine` aufrufen — der Testrunner
hat die Logik bereits) oder die Methode entfernen, damit der Typ `io.Writer` nicht mehr
erfüllt. Zweiteres ist ehrlicher.

---

## BEF-014 — Teardown-`actionGoBack` mit fehlerhafter Indexlogik

**Prio:** P2 · **Typ:** bug · **Aufwand:** S · **Datei:** `internal/ops/engine/engine.go`

In `Teardown` läuft die Schleife rückwärts (`for i := len(e.stages) - 1; i >= 0; i--`). Im
Fehlerfall:

```go
if action == actionGoBack {
    prev := i + 1
    if prev >= len(e.stages) { prev = len(e.stages) - 1 }
    i = prev + 1
}
```

`i` wird auf `i+2` gesetzt, die Schleife dekrementiert auf `i+1`. Nahe dem Ende kann `prev+1`
außerhalb des Bereichs liegen. Zusätzlich wird `i++` bei `actionRetry` gesetzt, was in
Kombination mit dem Schleifen-Dekrement stimmt, aber nur durch Zufall lesbar ist.

**Lösung**
Die Schleife auf einen expliziten Index-Cursor umstellen statt `for`-Dekrement plus
Korrekturen im Rumpf. Ein Tabellentest, der jede Aktion an jeder Position durchspielt.

---

## BEF-015 — Ops-Container mit `--privileged` und Docker-Socket

**Prio:** P2 · **Typ:** security · **Aufwand:** M · **Datei:** `cmd/toob-ops/main.go`

**Problem**
`runInDockerIfNeeded` startet den Tooling-Container mit:

```go
"run", runFlags, "--privileged",
"-v", "//var/run/docker.sock:/var/run/docker.sock",
```

plus einem Read-only-Mount von `~/.ssh`, das im Container nach `/root/.ssh` kopiert wird.
`--privileged` mit Docker-Socket ist effektiv Root auf dem Host.

Für ein Entwicklerwerkzeug auf einem Windows-Arbeitsplatz ist das ein bewusster Kompromiss —
gebraucht wird es für die Loop-Mounts beim Rootfs-Bau (`mount -o loop` in
`build-compiler.sh` und `test_build.go`) und für `/dev/kvm` beim Firecracker-Test. Für einen
CI-Runner in der Kontrollebene wäre es nicht vertretbar.

**Lösung**
Zwei Profile: privilegiert für Artefakt- und Firecracker-Phasen, unprivilegiert für Terraform,
Ansible, Deploy und Status. Der künftige `ops-ci` läuft ausschließlich unprivilegiert.

**Akzeptanzkriterien**
- [ ] `toob-ops status` und ein Deploy-Lauf funktionieren ohne `--privileged`.
- [ ] Der Docker-Socket wird nur in den Phasen gemountet, die ihn brauchen.

---

## BEF-016 — `--insecure-ignore-tlog` unbegründet

**Prio:** P2 · **Typ:** security · **Aufwand:** S · **Datei:** `api/deploy.sh`

`cmd_verify` ruft `cosign verify --insecure-ignore-tlog`. Das schaltet die Prüfung gegen den
Transparency-Log ab.

Bei einem selbstverwalteten Vault-Transit-Schlüssel ohne Rekor-Eintrag ist das die einzige
Möglichkeit — die Signatur landet gar nicht im öffentlichen Log. Die Entscheidung ist
vermutlich richtig; sie steht nur nirgends, und der Flag-Name legt das Gegenteil nahe.

**Lösung**
Kommentar im Skript mit Begründung, eine Zeile im Sicherheitsmodell. Eigener Rekor-Betrieb als
offener Punkt vermerken, nicht als Aufgabe.

---

## BEF-017 — CIDR-Plan kollidiert mit Staging

**Prio:** P1 · **Typ:** infra · **Aufwand:** S · **Datei:** `internal/ops/topology/topology.go`

**Problem**
Belegt sind bereits: `10.0.0.0/16` (production), `10.1.0.0/16` (dev), `10.2.0.0/16` (staging).
Der Architekturentwurf sah `10.2.1.0/24` für `toob-identity` vor — das kollidiert mit Staging.

**Lösung**
Ein dokumentierter Plan, der Projekt und Umgebung trennt:

| Bereich | Belegung |
|---|---|
| `10.0.0.0/16` | registry / production (Bestand) |
| `10.1.0.0/16` | registry / dev (Bestand) |
| `10.2.0.0/16` | registry / staging (Bestand) |
| `10.10.0.0/16` | ops / production |
| `10.11.0.0/16` | ops / dev |
| `10.20.0.0/16` | identity / production |
| `10.21.0.0/16` | identity / dev |
| `10.30.0.0/16` | update / production |
| `10.31.0.0/16` | update / dev |

Zehnerschritte pro Projekt, Einerschritte pro Umgebung. Jeder Bereich ist damit auf einen
Blick zuzuordnen, und die WireGuard-`AllowedIPs` am Hub sind trivial zu schreiben.

**Akzeptanzkriterien**
- [ ] Der Plan steht als Tabelle in `topology.go` und im Architekturdokument.
- [ ] Eine Testfunktion prüft auf Überschneidung.

---

## BEF-018 — Tote Konfigurationsdateien neben Templates

**Prio:** P3 · **Typ:** cleanup · **Aufwand:** S

`monitoring/prometheus/prometheus.yml` existiert neben `prometheus.yml.j2`, ebenso
`docker-compose.monitoring.yml` neben `.yml.j2`. Das Playbook rollt die Templates aus.

Die statischen Varianten enthalten hartkodierte `10.0.1.x`-Adressen, also die
Produktionstopologie — für dev (`10.1.1.x`) schlicht falsch. Wer sie zum Nachlesen öffnet,
liest die falsche Umgebung.

Dasselbe gilt für `monitoring/prometheus/vault-token`, das einen Platzhaltertext enthält und
zur Laufzeit vom Vault-Agent überschrieben wird.

**Lösung**
Statische Varianten löschen. Templates sind die Referenz.

---

## BEF-019 — Cosign-Token nicht im TTL-Exporter

**Prio:** P2 · **Typ:** security · **Aufwand:** S · **Datei:** `token-ttl-exporter.sh.j2`

**Problem**
Der Exporter prüft drei Token: `autounseal`, `nomad_server`, `vault_agent`. Alert 18
(`TokenTTLLow`) feuert bei unter 24 Stunden.

Der Cosign-Token für die Release-Pipeline (`-period=720h`, laut Runbook manuell zu erneuern)
ist nicht dabei. Das langlebigste und am wenigsten überwachte Credential im Stack ist damit
das einzige, für das kein Alarm existiert.

**Lösung**
Kurzfristig: als vierten Eintrag in den Exporter. Dauerhaft besser: den Token ersatzlos
streichen, indem der CI-Runner sich per AppRole authentifiziert und pro Lauf einen kurzlebigen
Token zieht. Dann gibt es nichts zu überwachen.

---

## BEF-020 — `.env.<env>` wird zum Klartext-Secret-Store

**Prio:** P2 · **Typ:** security · **Aufwand:** M · **Datei:** `internal/ops/stages/prereqs.go`

**Problem**
Fehlende Pflichtvariablen werden interaktiv abgefragt und auf Nachfrage in `.env.<env>`
**angehängt**:

```go
f, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
```

Das ist bequem und gut gemacht — Dateimodus `0600`, Pfadangaben werden als Pfad gespeichert
statt als aufgelöster Inhalt, und die Reihenfolge folgt `AllEnvRequirements()`. Der Effekt ist
trotzdem, dass achtzehn Produktionsgeheimnisse im Klartext in einer Datei im Arbeitsverzeichnis
landen.

Verschärfend: `loadEnvFiles` setzt sie anschließend ins Prozess-Environment, und
`seed.sh` bekommt sie von dort. Beim Bootstrap steht damit jedes Geheimnis in der Shell des
Operators, inklusive History.

**Lösung**
Kurzfristig: `.env.<env>` in BEF-002 aufnehmen und in der Doku als „enthält
Produktionsgeheimnisse, niemals committen, niemals teilen" kennzeichnen. Das Speichern-Prompt
bekommt einen entsprechenden Hinweis.

Mittelfristig: `seed.sh` liest aus einer `0600`-Datei via `vault kv put @file` statt aus dem
Environment. Langfristig: der CI-Runner führt das Seeding aus und holt die Werte aus einem
verschlüsselten Repo-Secret.

---

## Einordnung in `BACKLOG-devops-umbau.md`

| Befund | Löst dort auf / ergänzt |
|---|---|
| BEF-003, BEF-006 | neu — war ohne Dateien nicht sichtbar |
| BEF-004, BEF-005 | neu — Widerspruch bzw. Bug nur im Code erkennbar |
| BEF-008, BEF-012, BEF-018 | ergänzt die mit **[Dateien nötig]** markierten Tickets |
| BEF-009, BEF-010 | konkretisiert die Loki- und TTL-Tickets mit Dateibezug |
| BEF-017 | korrigiert den CIDR-Vorschlag der Architektur |
| BEF-013, BEF-014, BEF-015, BEF-020 | neu — betreffen `internal/ops/`, das im Runbook nicht vorkam |

---

## Reihenfolge

**Heute:** `BEF-001` → `BEF-002` · `BEF-003`

BEF-003 ist eine Zeilenstreichung und verhindert einen Datenverlust, der beim nächsten
Dev-Teardown eintritt.

**Diese Woche:** `BEF-004` · `BEF-005` · `BEF-006` · `BEF-007`

**Vor dem Umbau:** `BEF-008` · `BEF-012` · `BEF-017` · `BEF-013` · `BEF-014` · `BEF-018`

Der Stack sollte in einem Zustand sein, in dem Alarme etwas bedeuten und Konfigurationen
nicht per Regex entstehen, bevor eine Projektdimension dazukommt.

**Während des Umbaus:** `BEF-009` (vor dem zweiten Projekt) · `BEF-010` (vor `toob-update`) ·
`BEF-015` (vor `ops-ci`) · `BEF-019` · `BEF-020` · `BEF-011` · `BEF-016`

---

## Merksatz

> Zwei Befunde sind keine Verbesserungsvorschläge, sondern Wartezeit auf einen Vorfall:
> ein Teardown-Pfad, der Produktions-Backups löscht, und ein Seccomp-Profil, das das
> Gegenteil von dem tut, was sein eigener Kommentar behauptet. Alles andere in diesem
> Dokument kann in eine Sprintplanung.