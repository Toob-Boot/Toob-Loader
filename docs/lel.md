Vorab zur Einordnung: Ich habe nur den `deploy/`-Export vorliegen, **nicht** den Go-Quellcode. Damit lässt sich Teil 2 des Feedbacks (Deployment-Gaps) direkt gegen die Konfiguration prüfen — Teil 1 (Architektur) referenziert `internal/...`-Dateien, die im Export fehlen, sodass ich die dort nur über Plausibilität bewerten kann.

Kurzfazit: Die vier Deployment-Findings sind im Kern alle korrekt, zwei davon mit Nuancen, die das Feedback unter- bzw. überzeichnet. Die Architektur-Punkte sind solides Standard-Refactoring, aber Geschmacks-/Aufwandsfragen. Wichtiger: Das Feedback **übersieht mehrere härtere Befunde** — allen voran, dass die Nomad-Orchestrierung vom Playbook gar nicht ausgerollt wird und dass der Production-Auto-Unseal-Pfad nicht durchverdrahtet ist.

---

## Teil 2 — Deployment-Gaps (verifizierbar)

**2.A — Autoscaled Worker starten keinen Nomad-Client. → KORREKT, HIGH.**
Bestätigt, und sogar schlimmer als beschrieben. Die `terraform/worker/cloud-init.yaml` (die der Autoscaler-Template strukturell entspricht) schreibt `worker-env`, führt `bootstrap.sh` aus und enabled `toob-worker-hardening` — aber sie schreibt weder `/etc/nomad.d/nomad.hcl` noch startet sie `nomad`. Da `registry-worker.nomad.hcl` ein `type = "system"`-Job mit `constraint meta.pool = "worker"` ist, joint die VM nie den Cluster und der Worker-Task wird nie platziert. Gleichzeitig enabled cloud-init auch nicht `registry-worker.service`. Ergebnis: Eine frisch hochskalierte Worker-VM bootet, härtet sich, holt die Vault-SecretID — und tut dann **nichts**. Beide möglichen Pfade (Nomad und systemd) laufen ins Leere. Die vorgeschlagene Mitigation ist richtig.

**2.B — Hardcodierte Single-API-IP bricht HA. → KORREKT, aber das eigentliche Problem ist größer. MEDIUM.**
`worker/main.tf` (`toob_api_url` default `https://10.0.1.10:8443`) und `registry-worker.nomad.hcl` (`TOOB_API_URL = "https://10.0.1.10:8443"`) pinnen beide auf api-fsn1. Bestätigt. Aber: Die im Feedback unterstellte „gesunde hel1-Redundanz" existiert so gar nicht. Der Nomad-**Server** läuft nur auf fsn1 (`bootstrap_expect = 1`), und der **Primary Vault** wird vom Playbook ausschließlich auf `api-fsn1` deployt. hel1 ist reiner Nomad-Client und hat keinen eigenen Vault. Heißt: Fällt fsn1 aus, ist nicht nur die Worker-Kommunikation tot, sondern Scheduling und Secret-Zugriff insgesamt. Die hardcodierte URL ist also ein Symptom eines fundamental single-homed Control Plane. Auffällig dazu: Die `unseal_vault`-Firewall erlaubt Port 8200 explizit von `10.0.1.10/32` **und** `10.0.1.11/32` mit Kommentar „accessible from primary Vaults (api-fsn1 and api-hel1)" — die Konfig *antizipiert* einen zweiten Primary Vault auf hel1, den das Playbook nie aufsetzt. Das ist echte Drift; entweder hel1 als zweiten Vault-Node nachziehen oder den Anspruch „geo-redundant" zurücknehmen.

**2.C — systemd vs. Nomad als Worker-Runner. → KORREKT im Kern, Detail unbelegt. MEDIUM.**
Beide Runner existieren (`worker/registry-worker.service` und `nomad/registry-worker.nomad.hcl`). Der genannte Zertifikatspfad `/etc/toob-registry/certs/worker.pem` taucht in der Service-Unit allerdings nicht auf — die Unit nutzt nur `EnvironmentFile=/etc/toob-registry/worker-env` plus statische `Environment=`-Firecracker-Pfade; das mTLS-Material holt offenbar das Worker-Binary selbst. Das Detail ist also leicht daneben, der Kern stimmt. Wichtig: Dieser „Clash" hängt direkt an 2.A — aktuell ist es kein Clash, sondern ein **ungelöstes Patt**, bei dem keiner der beiden Pfade automatisch anläuft. Entscheidung für Nomad ⇒ 2.A fixen (cloud-init muss Nomad starten); Entscheidung für systemd ⇒ cloud-init muss `registry-worker.service` enablen. Die obsolete Unit zu entfernen ist die saubere Antwort.

**2.D — DB-Firewall auf ephemere Public-IPs. → KORREKT, Severity aber überzeichnet. LOW–MEDIUM.**
Der Risiko-Mechanismus stimmt (Ansible öffnet Ubicloud-Ingress auf `public_ip/32`, Hetzner recycelt IPs). Das Feedback unterschlägt aber die bereits vorhandenen Mitigationen: Es gibt eine Cleanup-Task im Playbook **und** den `cleanup-db-firewall.py`-Timer, der alle 15 Minuten stale `/32`-Regeln gegen die aktiven Hetzner-IPs prunt. Das Expositionsfenster ist also ≤15 min, nicht „dauerhaft offen". Außerdem läuft die DB-Verbindung mit `sslmode=verify-full` + CA-Pinning und benötigt Credentials — eine durchgerutschte Fremd-IP bekäme **Netzwerk-Erreichbarkeit**, keine Authentifizierung. Der Langfrist-Fix (privates Networking/VPC-Peering) ist trotzdem richtig; ich würde ihn nur als „Hardening", nicht als „kritische Lücke" einstufen.

---

## Teil 1 — Architektur-Refactorings (nicht verifizierbar, da kein Go-Source im Export)

Plausibel und handwerklich sauber argumentiert, aber durchweg Aufwand-/Reife-Abwägungen, kein „muss":

- **1.C (slog-String-Matching)** ist der überzeugendste Punkt — `"no errors detected"` → Error-Level ist ein klassischer, realer Bug. Direkt auf strukturiertes `slog` migrieren, Adapter abschaffen. Lohnt sich.
- **1.D (State-Machine nur in App-Logik)** ist legitime Defense-in-Depth. Vorsicht: Vollständige Transition-Trigger in Postgres sind schwer; ich würde mit `CHECK`-Constraints auf erlaubte Zielzustände anfangen, nicht mit komplexen Triggern.
- **1.B (Cross-Store-Query in `dashboard.go`)** ist ein berechtigter Boundary-Verstoß; eigener `DashboardStore`/`QueryService` ist der richtige Schnitt.
- **1.A (DTO-Trennung)** ist Lehrbuch-Hexagonal, aber für ein kleines/Solo-Projekt potenziell Over-Engineering, solange Domain/DB/JSON nicht wirklich auseinanderdriften. Würde ich aufschieben.
- **1.E (CLI-Flag-Dedup)** ist Kosmetik, low risk, low value — „nice to have".

---

## Was das Feedback übersehen hat (die wertvolleren Befunde)

**HIGH — Die Nomad-Schicht wird vom Playbook überhaupt nicht provisioniert.**
Das `playbook.yml` deployt Vault, Monitoring, Hardening, DB-Firewall-Cleanup — aber **keine** Nomad-Konfiguration: kein Task kopiert `server.hcl`/`client.hcl` nach `/etc/nomad.d/nomad.hcl`, kein Task startet `nomad.service`, und der Platzhalter `{{ nomad_gossip_key }}` in beiden HCLs wird nie substituiert (`{{ GetPrivateIP }}` ist okay — das löst Nomad selbst auf, `nomad_gossip_key` aber nicht). `init.sh` schreibt zwar `/etc/nomad.d/nomad.env` mit dem Server-Token, setzt also Nomad voraus — aber das Aufsetzen selbst fehlt. Entweder geschieht das out-of-band (dann dokumentieren), oder die komplette Nomad-basierte Bereitstellung (API *und* Worker) kommt aus dem IaC so gar nicht hoch. 2.A ist nur der Spezialfall „Worker" eines viel breiteren Lochs.

**HIGH — Production-Auto-Unseal ist nicht durchverdrahtet.**
In `init-unseal.sh` macht der Production-Zweig `vault operator init` mit PGP und `exit 0` **vor** Transit-Setup und Token-Generierung. Beim Playbook-Lauf liefert das rc=0 mit „Initialized…" im stdout → die Folge-Task „Parse and Register Auto-Unseal Token" sucht per `regex_search` nach `=== AUTO-UNSEAL TOKEN ===`, findet nichts → `| first` läuft auf `None` und die Task **failt hart** (das `failed_when` deckt nur den Init-Step ab, nicht den Parse-Step). Der Token entsteht erst beim *zweiten* Lauf, nachdem Operatoren manuell mit PGP unsealed haben. Zwei Folgeprobleme dazu:
- **Recovery-Pfad ist falsch verdrahtet:** Die Task „Read Auto-Unseal Token … (recovery mode)" liest den Token nach `kms_root_token`, aber downstream konsumiert wird `hostvars['toob-unseal-vault']['autounseal_token']` — das wird nur im rc==0-Zweig gesetzt. Im Recovery-Fall bleibt `autounseal_token` undefiniert und die `replace`-Task auf der Primary-`vault.hcl` schlägt fehl bzw. ersetzt mit Leer.
- **Nicht idempotent:** Bei wiederholten Läufen (Vault bereits initialisiert+unsealed) läuft Step 6 jedes Mal und erzeugt einen **neuen** Periodic-Orphan-Token → Orphan-Token-Wildwuchs im Unseal-Vault.

**MEDIUM — Der systemd-vs-Nomad-Clash gilt genauso für die API, nicht nur den Worker.** Es gibt `api/registry-api.service` (AppRole via `VAULT_ROLE_ID`/`VAULT_SECRET_ID`) **und** `nomad/registry-api.nomad.hcl` (Vault-Token-Injection über `vault { policies }`). Zwei Supervisionsmodelle, zwei verschiedene Vault-Auth-Wege. 2.C hätte symmetrisch auch hier gezogen werden müssen.

**MEDIUM — seccomp-Pfad-Mismatch.** Ansible deployt das Profil nach `/opt/toob-registry/seccomp-api.json`. Der Nomad-Job referenziert korrekt `/opt/toob-registry/seccomp-api.json`, die systemd-Unit aber `/etc/toob-registry/seccomp-api.json`. Über den systemd-Pfad findet Docker das Profil nicht → Container startet nicht. Geringe Wirkung, *wenn* Nomad der reale Pfad ist — aber konkrete Inkonsistenz, die fürs Aufräumen der obsoleten Units relevant ist.

**MEDIUM — Doppeltes Alerting.** Prometheus-Alertmanager (`alert.rules.yml` + `alertmanager.yml`) **und** Grafana Unified Alerting (`provisioning/alerting/alerting.yml`) definieren überlappende Regeln (InstanceDown / SystemdServiceFailed / VaultSealed) und feuern beide auf denselben Discord-Webhook. Ergebnis: doppelte Benachrichtigungen pro Ereignis. Auf ein System festlegen.

**LOW/Verify — Cloudflare-Health vs. App-Health.** CF-Monitor prüft `GET /health`, Caddy- und Nomad-Checks prüfen `/ready`. Falls der Go-Server nicht beide Endpoints serviert, markiert die LB die Origins als down. Gegen den Quellcode verifizieren.

**LOW — Hardening-Inkonsistenzen.** Die Primary-`vault.service` nutzt `ProtectSystem=full`, die `unseal-vault.service` das strengere `ProtectSystem=strict` + explizite `ReadWritePaths` — die KMS-Wurzel ist also stärker gehärtet als der Primary; angleichen. Und `toob-api-hardening.service` setzt die iptables-Regel mit `-A` unbedingt (der Worker macht es idempotent via `-C || -A`) → Duplikat-Regeln bei Re-Runs.

---
