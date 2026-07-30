# Architektur — DevOps-Zielbild der Toob-Plattform

**Status:** Verbindliches Zielbild. Löst `ARCHITEKTUR-plattform-topologie.md` und
`ARCHITEKTUR-kontrollebene.md` vollständig ab; beide sollten gelöscht werden.
Die fachlichen Dokumente (`ARCHITEKTUR-update-service-v2.md`,
`ARCHITEKTUR-identitaet-mandanten.md`) bleiben gültig — dieses Dokument beschreibt, *worauf* sie
laufen, nicht *was* sie tun.

**Geltungsbereich:** Alle Projekte, Knoten, Netze, Secrets, Deployments und Betriebsabläufe.
Nicht enthalten: Anwendungslogik, Datenmodelle, API-Verträge.

**Adressat:** Wer diesen Stack von Grund auf aufbauen oder im Notfall wiederherstellen muss.

---

## 1. Leitprinzipien

Vier Sätze, aus denen sich der Rest ableitet. Jeder ist testbar formuliert, weil ein Prinzip
ohne Test eine Absichtserklärung ist.

**P1 — Die Kontrollebene baut und beobachtet, sie liefert nicht aus.**
Kein Datenpfad eines Produkts macht zur Laufzeit einen Netzaufruf nach `toob-ops`.
*Test:* `toob-ops` vollständig abschalten; `ci.`, `ota.` und `fw.` antworten weiter, ein
Geräte-Check-in läuft durch. Wöchentlich, automatisiert (§12.3).

**P2 — Vertrauen fließt von oben nach unten.**
Spokes wählen sich beim Hub ein und haben keinen eingehenden Port. `toob-ops` erreicht die
Spokes, nie umgekehrt — mit genau einer benannten Ausnahme (Log-Push, §5.3).
*Test:* Portscan gegen jedes Projektnetz von außen ergibt null offene Ports.

**P3 — Kein Secret im Datenpfad hat eine TTL unter 30 Tagen.**
Damit ist ein Vault-Ausfall ein Deploy-Problem und niemals ein Betriebsproblem.
*Test:* `vault lease lookup` über alle Datenpfad-Secrets; Vault 24 h abschalten.

**P4 — Was ausfallen darf, wird getrennt von dem, was nicht ausfallen darf.**
Die Registry führt fremden Code aus und darf Stunden stillstehen. Der Update-Datenpfad führt
keinen fremden Code aus und darf praktisch nicht stillstehen. Inverse Profile gehören nicht auf
dieselben Maschinen.

---

## 2. Projekt-Topologie

Fünf Hetzner-Projekte. Die Projektgrenze ist die Isolationsgrenze — nicht das Netz. Getrennte
Projekte bedeuten getrennte API-Tokens, getrennte Firewall- und Ressourcennamensräume und
getrennte Kostenzuordnung. Ein geleaktes `HCLOUD_TOKEN` kann genau ein Projekt zerstören.

| Projekt | Rolle | Öffentlicher Ingress | Orchestrierung |
|---|---|---|---|
| `toob-ops` | Kontrollebene: Secrets, Beobachtung, CI | **keiner** | systemd |
| `toob-identity` | Zitadel (IdP für alle Produkte) | `id.` | systemd |
| `toob-registry` | Paket-Registry, Firecracker-Builds | `ci.` | **Nomad** |
| `toob-update` | Update Service, Fleet-Management | `ota.`, `api.` | systemd |
| `toob-staging` | Vorproduktion, Übungsfläche | `stg.` | systemd |

`toob-identity` ist bewusst **kein** Teil der Kontrollebene, obwohl es wie sie
produktunabhängig geteilt wird. Zitadel muss aus jedem Operator-Browser erreichbar sein — ein
öffentlich exponierter Dienst mit eigenem CVE-Strom gehört nicht in dasselbe Netz wie Vault und
der WireGuard-Hub. Geteilt wie die Kontrollebene, isoliert wie ein Produkt.

---

## 3. Knoteninventar

### 3.1 `toob-ops`

| Knoten | Größe | Läuft darauf | Warum eigener Knoten |
|---|---|---|---|
| `ops-hub` | CX32 | WireGuard-Hub, Prometheus, Loki, Grafana, Alertmanager | RAM-Bedarf des Monitoring-Stacks; zentraler Netzknoten |
| `ops-ci` | CX22 | Build- und Deploy-Runner, Cosign | Ein Build zieht Abhängigkeiten Dritter. Diese dürfen nicht im selben Prozessraum wie der WireGuard-Hub und die Metriken landen |
| `ops-vault-1/2/3` | CX22 ×3 | Primary Vault (Raft) | Quorum |
| `ops-kms` | CX22 | Unseal-Vault (Transit) | Muss außerhalb des Clusters liegen, den er entsiegelt — sonst zirkulär |

**Warum drei Vault-Knoten.** Raft-Quorum ist `floor(n/2)+1`. Bei zwei Knoten ist es 2 — der
Cluster verträgt **null** Ausfälle, exakt wie ein Einzelknoten, aber mit doppelter Ausfallfläche.
Zwei ist die einzige Knotenzahl, die keinen Sinn ergibt. Drei verträgt einen Ausfall.

### 3.2 `toob-identity`

| Knoten | Größe | Läuft darauf |
|---|---|---|
| `idp-1`, `idp-2` | CX22 ×2 | Zitadel, Caddy, WireGuard-Peer |

Zwei Knoten hinter dem Cloudflare-Load-Balancer, jeder mit dem anderen als Caddy-Fallback.
Datenhaltung in `toob-idp-db` (Ubicloud).

### 3.3 `toob-registry` (Bestand, nach Migration entlastet)

| Knoten | Größe | Läuft darauf |
|---|---|---|
| `reg-api-fsn1` | CX22 | Caddy, registry-api, Nomad Server + Client, WireGuard-Peer |
| `reg-api-hel1` | CX22 | Caddy, registry-api, Nomad Client, WireGuard-Peer (Standby) |
| `reg-worker-N` | CCX13 | Firecracker, Jailer, Nomad Client, autoskaliert |

Diese Knoten **verlieren** in der Migration Vault und den Monitoring-Stack. Aus zwei Pets werden
zwei austauschbare Compute-Knoten — für die Registry selbst ein Gewinn, nicht nur für die
Trennung.

### 3.4 `toob-update`

| Knoten | Größe | Läuft darauf |
|---|---|---|
| `upd-edge-fsn1`, `upd-edge-hel1` | CX22 ×2 | Caddy, `toob-edge`, WireGuard-Peer |
| `upd-fleet` | CX22 | `toob-fleet` (Management-API + Web-UI) |

### 3.5 `toob-staging`

| Knoten | Größe | Läuft darauf |
|---|---|---|
| `stg-all` | CX22 | `toob-edge` + `toob-fleet` in einem Knoten |

Staging spiegelt die *Software*, nicht die Topologie. Der Zweck ist, Migrationen, Deploys und
den Abschalttest zu üben — nicht Lastverhalten zu messen.

### 3.6 WireGuard-Peers sind eine Rolle, kein Knoten

Kein Projekt bekommt einen dedizierten Gateway-Server. Der Peer läuft auf dem stabilsten Knoten
des Projekts und routet dessen Subnetz; ein zweiter Knoten hält einen Standby-Peer.

Der Einwand liegt auf der Hand: Bei der Registry hält damit ein Knoten den Tunnel, in dessen
Netz Firecracker fremden Code ausführt. Der Blast Radius ist trotzdem begrenzt — `AllowedIPs`
am Hub beschränkt jeden Peer auf sein eigenes Subnetz, und eingehend zum Hub ist nur der
Loki-Port offen. Ein dedizierter Gateway würde daran nichts ändern und vier Knoten kosten.

---

## 4. Netz und Vertrauensrichtung

```
Admin ──WireGuard──► ops-hub ──┬──► toob-identity   (10.2.1.0/24)
                               ├──► toob-registry   (10.0.1.0/24)
                               ├──► toob-update     (10.1.1.0/24)
                               └──► toob-staging    (10.3.1.0/24)
```

**Spokes wählen sich ein.** Jeder Projekt-Peer baut die Verbindung *ausgehend* zum Hub auf.
Konsequenz: kein Projektnetz hat einen eingehenden Port — auch kein SSH, auch kein WireGuard-
Listener. Das ist der Unterschied zum bisherigen Bastion-Modell, bei dem jedes Projekt einen
öffentlichen UDP-Port brauchte.

**Absicherung am Hub:**
- `AllowedIPs` pro Peer auf exakt das Subnetz des Projekts. Peer-zu-Peer-Routing ist deaktiviert.
- Die Hub-Firewall verwirft eingehenden Verkehr von Peers vollständig, bis auf den Loki-Ingest.
- Ein Admin-Profil erreicht alle Subnetze — ein Profil statt fünf, kein Doppel-Hop.

**Interne Namensauflösung** weiterhin über `/etc/hosts`, von Ansible gesetzt. Kein DNS-Server im
Cluster: eine Komponente weniger, die ausfallen kann, und die Namensmenge ist statisch.

---

## 5. Beobachtbarkeit

### 5.1 Richtung

| Signal | Mechanismus | Richtung | Konform zu P2 |
|---|---|---|---|
| Metriken | Prometheus scrapt über den Tunnel | ops → spoke | ✓ |
| Logs | Alloy pusht nach Loki | spoke → ops | **Ausnahme** |
| Alerts | Alertmanager in `ops-hub` | intern | ✓ |
| Dashboards | Grafana, Ordner pro Projekt | intern | ✓ |

Der Log-Push ist die einzige erlaubte Gegenrichtung. Die Alternative — Loki pro Projekt mit
Grafana als föderierter Abfrageschicht — wäre richtungsrein, verdreifacht aber die
Betriebsfläche. Ein kompromittierter Spoke, der Müll in Loki schreibt, ist niedrigschwellig und
wird durch mTLS, Pflicht-Label `project`, Rate-Limit und Retention-Cap eingefangen.

### 5.2 Zwei Sonden pro öffentlichem Dienst

Jeder öffentlich erreichbare Dienst wird **doppelt** überwacht:

1. **Interner Scrape** über den Tunnel — misst den Prozess.
2. **Externe Blackbox-Probe** über Cloudflare — misst den vollständigen Pfad.

Der Nutzen ist Diagnose, nicht Redundanz:

| Extern | Intern | Diagnose |
|---|---|---|
| up | up | alles in Ordnung |
| up | down | **Tunnel oder Scrape-Konfiguration**, nicht der Dienst |
| down | up | **Edge, DNS oder Zertifikat**, nicht der Dienst |
| down | down | der Dienst |

Mit nur einer Sonde weiß man im Ernstfall nicht, wo zu suchen ist. Das gilt für `id.`, `ota.`,
`api.`, `ci.` und `fw.` gleichermaßen.

### 5.3 Alarmierung pro Projekt

Routing über das `project`-Label, eigener Kanal je Projekt, **eigener Dead-Man-Switch je
Projekt**. Ein globaler Heartbeat beweist nur, dass Alertmanager lebt — er verdeckt, dass die
Metriken eines einzelnen Projekts seit Stunden fehlen.

Schweregrade folgen der Ausfallwirkung, nicht dem Gefühl:

| Ausfall | Schwere | Begründung |
|---|---|---|
| `upd-edge` beide Knoten | kritisch | Flotte bekommt keine neuen Zuweisungen |
| `toob-idp` beide Knoten | hoch | Operatoren gesperrt, Geräte unberührt |
| `upd-fleet` | hoch | kein Management, Auslieferung läuft |
| `reg-api` beide Knoten | mittel | Builds stehen |
| `ops-hub` | mittel | Blindflug, kein Betriebsausfall |
| Vault | niedrig | nur Deployments blockiert (P3) |

Dass ein Vault-Ausfall der *niedrigste* Schweregrad ist, ist kein Versehen — es ist die
Bestätigung, dass P3 funktioniert.

### 5.4 Textfile-Collector für Oneshot-Telemetrie

Beibehalten aus dem Registry-Stack und auf alle Projekte ausgeweitet: Backup-Zeitstempel,
Restore-Test-Ergebnis, Token-TTLs, Service-Failures via `OnFailure=notify-failure@%n`,
DB-Firewall-Pruner. Cron- und Timer-Ergebnisse werden zu Metriken, nicht zu Logzeilen, die
niemand liest.

---

## 6. Orchestrierung: wer beaufsichtigt was

| Projekt | Supervisor | Begründung |
|---|---|---|
| `toob-registry` | **Nomad** | Dynamische Firecracker-Worker, Autoscaling, Scheduling über einen heterogenen Pool |
| alle anderen | **systemd** | Fester Satz zustandsloser Prozesse |

**Nomad existiert in genau einem Projekt, weil genau ein Projekt dynamische Workloads hat.**
Ein Nomad im Identity- oder Update-Spoke bräuchte entweder einen eigenen Server — bei
`bootstrap_expect = 1` ein neuer Single Point — oder müsste in die Kontrollebene greifen, was P1
bricht: Scheduling und Service-Discovery sind Laufzeit.

Was systemd leistet: Neustart bei Fehlschlag, Startreihenfolge, cgroup-Ressourcengrenzen,
Härtung (`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet`), Failure-Metrik.

Was es nicht leistet, und wer es stattdessen tut:

| Fehlende Fähigkeit | Ersatz |
|---|---|
| Knotenübergreifendes Failover | Caddy mit `lb_policy first` auf den Nachbarknoten, Cloudflare-LB darüber |
| Rolling Deploy | Deploy-Skript: Knoten A aus dem Upstream, tauschen, `/ready` prüfen, zurück, dann B |
| Bin-Packing | nicht erforderlich, feste Zuordnung |
| Service-Discovery | `/etc/hosts`, statische Menge |

Der Rolling Deploy sind rund fünfzig Zeilen Bash. Die Ausfallfläche dieses Mechanismus ist bei
Nichtbenutzung exakt null — die eines Orchestrators nicht.

---

## 7. Identität und Secrets

### 7.1 Zwei getrennte Systeme, die oft verwechselt werden

| | Vault | Zitadel |
|---|---|---|
| Wofür | Maschinen-Secrets, Signierschlüssel, PKI | Menschen und Kunden-Workloads |
| Wer fragt | Deploy-Pipeline, Vault-Agents | Browser, Kunden-CI |
| Bei Ausfall | keine Deployments | kein Operator-Login |
| Datenpfad betroffen | nein (P3) | nein |

Beide sind *keine* Laufzeitabhängigkeit des Geräte-Pfads. Der Device-Token wird lokal per HMAC
gegen die Update-Datenbank geprüft und kennt weder Vault noch Zitadel.

### 7.2 Vault-Struktur für mehrere Projekte

Vault OSS kennt keine Namespaces. Mandantentrennung läuft über Pfade und Policies:

```
secret/projects/registry/…
secret/projects/update/…
secret/projects/identity/…
secret/projects/staging/…
secret/platform/…                      nur Kontrollebene

transit/keys/registry-package-signing
transit/keys/registry-image-signing
transit/keys/update-firmware-signing   ← eigene Policy, eigener Zugriffspfad
transit/keys/autounseal-platform

pki/                                   nur registry-intern (Nomad-mTLS)
```

**Die Trennung der Transit-Keys ist die wichtigste Einzelmaßnahme des gesamten Dokuments.** Ein
kompromittierter Registry-Release-Pfad darf keine Firmware signieren können. Die öffentlichen
Hälften dieser Schlüssel liegen in eFuses ausgelieferter Geräte — sie sind bei einer Migration
zu erhalten und niemals neu zu erzeugen.

**Keine Vault-PKI im Update-Datenpfad.** Die 24-Stunden-Zertifikate der Registry sind dort
richtig, weil kurze TTLs erzwingen, dass Rotation nachweislich funktioniert. Im Update-Pfad
wären sie eine Verletzung von P3.

### 7.3 Zwei-Stufen-Unseal, unverändert

`ops-kms` hält den Transit-Key, mit dem `ops-vault-*` sich selbst entsiegelt. Reboots heilen
sich, ohne dass je ein Unseal-Key auf einer Maschine liegt. In Produktion existieren nur
PGP-verschlüsselte Recovery-Keys, 5 Shares, Schwelle 3.

### 7.4 Zitadel

Organisationen bilden Mandanten ab. OIDC für die Web-UIs beider Produkte (Registry und
Fleet-Management), Workload-Identity-Federation für Kunden-CI — damit braucht keine
Kunden-Pipeline ein langlebiges Secret bei uns.

GitHub bleibt als *Anmeldemethode* erhalten, aber hinter Zitadel statt daneben. Industriekunden
haben nicht alle GitHub, und zwei Identitätsmodelle für dieselben Menschen sind ein
Dauerärgernis.

> **TODO:** Zitadel-HA-Modell verifizieren. Zwei Instanzen gegen eine Postgres-Instanz sind
> nach Dokumentation zulässig; das ist vor dem Produktivgang praktisch zu bestätigen, nicht
> anzunehmen.

---

## 8. Ingress und Edge

| Hostname | Ziel | Compute beteiligt |
|---|---|---|
| `ci.the-toob.com` | `reg-api` ×2, Geo-LB | ja |
| `cdn.the-toob.com` | Object Storage (Pakete) | **nein** |
| `ota.the-toob.com` | `upd-edge` ×2, Geo-LB | ja |
| `fw.the-toob.com` | Object Storage (Firmware) | **nein** |
| `api.the-toob.com` | `upd-fleet` | ja |
| `id.the-toob.com` | `idp` ×2, Geo-LB | ja |
| `stg.the-toob.com` | `stg-all` | ja |

**Die beiden Blob-Routen laufen an unserer Compute vorbei.** Das ist die wichtigste
Verfügbarkeitseigenschaft der Plattform: alle fünf Projekte können ausfallen, und laufende wie
wiederholte Firmware-Downloads funktionieren weiter.

Zwingende Cloudflare-Regeln auf `fw.`:
- **Compress off.** Transparentes gzip verschiebt Bytegrenzen und zerstört jeden Resume.
- `Cache-Control: immutable`, langes TTL, Origin Cache Lock gegen den Miss-Sturm nach Publish.
- Kein Redirect. Der MCU-HTTP-Client folgt ihnen nicht zuverlässig; ein `302` wäre ein stiller
  Fehlerpfad quer durch die Flotte.

Auf allen Compute-Routen: Caddy mit Cloudflare-Origin-CA (Full Strict), `trusted_proxies` auf
die CF-Ranges, `X-Real-IP` aus `CF-Connecting-IP`, Security-Header, `/metrics` öffentlich
geblockt. Metriken laufen nicht über Caddy, sondern direkt per mTLS vom Prometheus.

**Getrennte Rulesets und Rate-Limits pro Hostname.** Ein WAF-Regelfehler auf `ci.` darf `ota.`
nicht treffen.

---

## 9. Datenhaltung

| Instanz | Nutzer | Warum getrennt |
|---|---|---|
| `toob-registry-db` | Registry | Build-getrieben, selten geschrieben |
| `toob-update-db` | `toob-edge` + `toob-fleet` | Pro Gerät pro Boot geschrieben |
| `toob-idp-db` | Zitadel | Anderer Lebenszyklus, anderes Backup-Regime |
| `toob-staging-db` | Staging | Wegwerfbar |

`toob-edge` und `toob-fleet` teilen sich **eine** Instanz. Getrennte Datenbanken würden
verteilte Transaktionen erzwingen — die lazy Materialisierung einer Zuweisung und der
Outbox-Eintrag müssen atomar sein. Die Isolation kommt stattdessen über getrennte
Postgres-Rollen ohne `BYPASSRLS`.

**Object-Storage-Buckets:**

| Bucket | Inhalt | Lifecycle |
|---|---|---|
| `toob-firmware` | Firmware-Artefakte, mandantenpräfigiert | **niemals löschen**, solange Geräte im Feld sind |
| `toob-registry-packages` | Paket-Tarballs | Temp-Releases 7 Tage |
| `toob-vault-backups` | Snapshots | 30 Tage |
| `toob-terraform-state` | State aller Module | versioniert |

Der Firmware-Bucket hat eine andere Löschregel als alles andere: Ein Gerät, das drei Jahre im
Schrank lag, muss seinen Update-Pfad noch vorfinden.

**DB-Firewall-Pruner** wird zum Plattformdienst auf `ops-hub` und bedient alle Instanzen. Eine
Konfigurationszeile pro Projekt statt eines Timers pro Projekt.

---

## 10. Backup und Wiederherstellung

| Was | Wie | Wohin | Frequenz |
|---|---|---|---|
| Primary Vault | Raft-Snapshot | `toob-vault-backups` | täglich |
| Unseal-Vault | tar des File-Storage | `…/unseal-snapshots/` | täglich |
| Nomad | `operator snapshot save` | `…/snapshots/` | täglich |
| Postgres ×4 | Ubicloud Managed Backups | extern | laufend |
| Terraform-State | S3-Backend, versioniert | `toob-terraform-state` | bei jedem Apply |

**Alle Terraform-Module nutzen das S3-Backend.** Im Bestand laufen `cloudflare`, `database` und
`s3` auf lokalem State — der State für DNS, Load-Balancer, Produktionsdatenbank und Paket-Bucket
liegt damit auf einem Laptop. Geht er verloren, sind die Ressourcen verwaist und ein `apply`
versucht, sie neu anzulegen. Das ist ein Datenverlust-Szenario ohne Angreifer und der billigste
Fix im ganzen Dokument.

**Monatlicher automatischer Restore-Test.** Neuester Snapshot wird in einen wegwerfbaren
Vault-Container zurückgespielt, es wird geprüft, dass er entsiegelt und ein
Kanarienvogel-Schlüssel lesbar ist, Ergebnis als Metrik. Alarm bei Fehlschlag **und** bei
Ausbleiben.

Das hebt `BackupStale` von „eine Datei ist neu genug" auf „wir könnten tatsächlich
wiederherstellen". Ein Backup, das nie zurückgespielt wurde, ist eine Vermutung.

**Wiederherstellungsreihenfolge bei Totalverlust:** `ops-kms` aus Tarball → `ops-vault-*` aus
Raft-Snapshot (entsiegelt über den wiederhergestellten KMS) → Nomad-Snapshot → Jobs und
systemd-Units neu deployen → Datenbanken aus Ubicloud-Backups.

---

## 11. Deploy-Pipeline und Lieferkette

```
ops-ci ──build──► Image/Binary ──sign──► ops-vault (Transit) ──verify──► Deploy in den Spoke
```

**Schlüsselzugriff ausschließlich von `ops-ci`.** Kein Spoke-Knoten hat einen Netzpfad zum
Signierschlüssel. Ein kompromittierter `upd-edge` kann keine Firmware signieren, keine Images
signieren und keine Releases publizieren.

**Der Cosign-Token entfällt.** Bisher ein `-period=720h`-Dauercredential mit manueller
Erneuerung. `ops-ci` authentifiziert sich per AppRole und zieht **pro Lauf** einen kurzlebigen
Token.

**Digest-Pinning bleibt.** Deployments referenzieren `sha256:…`, nie einen mutable Tag. Für den
Update-Service gilt dasselbe Prinzip eine Ebene höher: Firmware-Artefakte sind content-adressiert.

**Promotion statt Rebuild.** Ein Artefakt wird einmal gebaut und signiert, durchläuft
`toob-staging` und wandert mit **demselben Digest** nach Produktion. Kein zweiter Build, kein
„lokal ging es".

**Secret-Seeding ohne Operator-Environment.** Der bisherige `SEED_*`-Mechanismus bedeutet, dass
beim Bootstrap jedes Produktionsgeheimnis in der Shell des Operators steht, inklusive History.
Kurzfristig: Seeding aus einer `0600`-Datei via `vault kv put @file`. Mittelfristig: `ops-ci`
führt das Seeding aus, kein Mensch sieht die Werte im Klartext.

**Cloudflare-Token pro Projekt** statt eines Tokens mit `Zone:Edit` für alles.

---

## 12. Betriebsroutinen

### 12.1 Projekt-Onboarding

Ein Terraform-Modul `project-baseline` erzeugt aus einem Projektnamen:
Netz, Firewall-Baseline, WireGuard-Peer-Registrierung am Hub, Vault-Pfade mit Policies und
AppRoles, Postgres-Instanz mit Firewall-Pinning, Prometheus-Scrape-Job, Grafana-Ordner,
Alert-Route, Dead-Man-Switch, Backup-Eintrag, Terraform-State-Key.

Damit kostet ein weiteres Projekt einen `terraform apply` und einen Ansible-Lauf. Das ist die
Voraussetzung dafür, dass kundendedizierte Stacks — ein Single-Tenant-Deployment ist ein
Multi-Tenant-Deployment mit genau einem Mandanten — ein Konfigurationsvorgang sind und kein Fork.

### 12.2 Break-Glass

Die Zentralisierung des Zugangs erzeugt ein neues Risiko: Stirbt `ops-hub`, kommt niemand mehr
irgendwo hinein. Zwei dokumentierte Notpfade:

1. **Hetzner Cloud Console (VNC)** — funktioniert ohne jedes Netz, für jeden Knoten, aus dem
   Webinterface. Primärer Weg, kostet nichts.
2. **Schlafendes WireGuard-Peer-Profil** je Projekt, offline hinterlegt, das erst nach manueller
   Aktivierung über die Console akzeptiert wird.

Halbjährliche Übung mit Protokoll und gemessener Zeit bis zum Zugriff. Ein ungeübter Notpfad
ist keiner.

### 12.3 Der Abschalttest

`toob-ops` wird vollständig heruntergefahren. Geprüft wird, dass `ci.`, `ota.` und `fw.`
weiter antworten und ein Geräte-Check-in durchläuft. Das Ergebnis muss **von außerhalb** erhoben
werden — der eigene Prometheus ist ja aus.

Einführung in drei Stufen: zweimal manuell gegen `toob-staging`, dann einmal manuell gegen
Produktion in einem Fenster mit niedrigem Verkehr, erst danach automatisiert und wöchentlich.
Ein Test, der beim ersten automatischen Lauf die Produktion trifft, ist selbst ein Risiko.

Nebenwirkung fürs Runbook: Der Test meldet Operatoren ab, weil Zitadel… nein — Zitadel liegt in
`toob-identity` und läuft weiter. Der Test unterbricht Deployments und Beobachtung, sonst nichts.
Genau das soll er beweisen.

### 12.4 Wiederkehrend

| Aufgabe | Frequenz | Automatisiert |
|---|---|---|
| Restore-Test | monatlich | ja |
| Abschalttest | wöchentlich | ja (nach Einführung) |
| Break-Glass-Übung | halbjährlich | nein |
| Golden Image neu bauen | bei CVE | nein |
| PGP-Quorum prüfen (5 Operatoren erreichbar) | halbjährlich | nein |
| Token-TTL-Alarme abarbeiten | ereignisgesteuert | Alarm ja, Behebung nein |

---

## 13. Ausfallmatrix

| Ausfall | Geräte-Updates | Builds | Operator-Login | Deployments |
|---|---|---|---|---|
| `toob-ops` komplett | **laufen** | laufen | läuft | blockiert |
| Vault | **laufen** | laufen | läuft | blockiert |
| `toob-identity` | **laufen** | laufen | **blockiert** | blockiert |
| `toob-registry` | **laufen** | blockiert | läuft | teilweise |
| `upd-edge` beide | Downloads laufen, keine neuen Zuweisungen | laufen | läuft | läuft |
| `toob-update-db` | Downloads laufen, Check-in `503` | laufen | läuft | läuft |
| `upd-fleet` | **laufen** | laufen | läuft | läuft |
| Object Storage | nur solange CDN-Cache trägt | blockiert | läuft | läuft |
| Cloudflare | blockiert | blockiert | blockiert | läuft |

Fünf von neun Ausfällen berühren die Flotte nicht. Das ist der Zweck der gesamten Struktur.

Zwei Zeilen verdienen einen Kommentar. **Der Check-in antwortet bei DB-Ausfall mit `503` und
nicht mit `204`** — ein `204` würde „kein Update vorhanden" behaupten und Geräte in falscher
Sicherheit lassen. Und **Cloudflare ist der einzige echte Single Point** der Plattform; der
Ausweichpfad (DNS direkt auf die Origins, Rate-Limiting entfällt) gehört ins Runbook, mit dem
ehrlichen Hinweis, dass er nur für Stunden trägt.

---

## 14. Kostenbild

Größenordnung, vor Umsetzung zu verifizieren.

| Posten | Monatlich |
|---|---|
| `toob-ops`: 6 Knoten | ~35 € |
| `toob-identity`: 2 Knoten | ~10 € |
| `toob-registry`: 2 Knoten + variable Worker | ~16 € + Last |
| `toob-update`: 3 Knoten | ~15 € |
| `toob-staging`: 1 Knoten | ~5 € |
| Managed Postgres ×4 | ~40–80 € |
| Object Storage + Traffic | volumenabhängig |
| **Grundlast** | **~120–160 €** |

Das ist ein deutlicher Anstieg gegenüber dem heutigen Registry-Stack. Zwei ehrliche
Einsparoptionen, beide mit benanntem Preis:

- **`toob-staging` weglassen.** Spart ~15 € und kostet die Übungsfläche für Migrationen und den
  Abschalttest. Für einen Dienst, dessen Fehler Flash-Erase-Budget im Feld verbrauchen, halte
  ich das für die schlechtere Wahl.
- **`ops-ci` mit `ops-hub` zusammenlegen.** Spart ~5 € und gibt die Trennung zwischen
  Build-Abhängigkeiten Dritter und dem WireGuard-Hub auf. Vertretbar in der Anfangsphase, mit
  einem Ticket zur späteren Trennung.

Der Traffic ist der eigentliche Skalierungsfaktor — und genau deshalb ist die Blob-Auslieferung
ohne eigene Compute (§8) die wichtigste Kostenentscheidung: Die Flottengröße skaliert nicht in
die Serverrechnung.

---

## 15. Migrationspfad

Reihenfolge ist bindend: `ops-kms` vor `ops-vault`, Restore-Test vor beidem.

| Schritt | Inhalt | Risiko | Rückweg |
|---|---|---|---|
| 1 | Projekt `toob-ops`, `ops-hub`, WireGuard-Hub | null — Bestand unberührt | Projekt löschen |
| 2 | Terraform-State der drei lokalen Module nach S3 | null | State-Datei behalten |
| 3 | Spoke-Peers in Registry, Dial-Out testen | niedrig | Bastion bleibt bis Schritt 6 |
| 4 | Restore-Test aufsetzen und grün bekommen | null | — |
| 5 | `ops-kms` aufsetzen, Tarball einspielen, Primary umschwenken | mittel | alte Instanz stehen lassen |
| 6 | `ops-vault-1/2/3`, Raft-Snapshot einspielen, Clients umziehen | **hoch** | alter Cluster bleibt |
| 7 | Monitoring nach `ops-hub`, Registry-Bastion abbauen | niedrig | Compose-Stack zurück |
| 8 | `toob-identity` aufsetzen, Registry-Login migrieren | mittel | GitHub-OAuth bleibt parallel |
| 9 | `project-baseline`-Modul, `toob-staging` als Nachweis | niedrig | — |
| 10 | `toob-update` als Spoke aus dem Modul | niedrig | — |
| 11 | Abschalttest manuell, dann automatisiert | mittel | — |

Schritt 6 ist der einzige wirklich heikle. Der Raft-Snapshot enthält die Transit-Keys, deren
öffentliche Hälften bereits Vertrauensanker in ausgelieferten Geräten sind — sie dürfen unter
keinen Umständen neu erzeugt werden. Angekündigtes Wartungsfenster, vorher grüner Restore-Test,
alter Cluster bleibt bis zur Bestätigung stehen.

`toob-update` kann bereits nach Schritt 1 gebaut werden und übergangsweise Secrets aus dem alten
Vault beziehen. Es gibt keinen Grund, die Migration abzuwarten.

---

## 16. Offene Punkte

| Punkt | Warum offen |
|---|---|
| Zitadel-HA gegen eine Postgres-Instanz | Dokumentation gelesen, nicht praktisch bestätigt |
| Cloudflare-Datenresidenz | Für den EU-Souveränitätsanspruch ist zu klären, ob Data Localization erforderlich wird — spätestens wenn der erste Kunde seinen Auditor mitbringt |
| Ubicloud-Preise und HA-Optionen | Kostenbild §14 basiert auf Schätzung |
| Loki-Mandantentrennung | Erforderlich, **bevor** Kunden Grafana-Leserechte bekommen, nicht danach |
| Vier-Augen-Prinzip für Produktions-Releases | Als Mandanten-Einstellung vorgesehen, Ablauf noch nicht entworfen |

---

## 17. Tragende Entscheidungen

1. **Fünf Projekte, Projektgrenze = Isolationsgrenze.**
2. **Kontrollebene über den Produkten, nicht in einem davon** — beseitigt die Asymmetrie, dass
   Vault im Netz des Systems liegt, das fremden Code ausführt.
3. **`toob-identity` als eigener Spoke**, nicht in der Kontrollebene — ein öffentlich
   erreichbarer Dienst gehört nicht neben Vault.
4. **Spokes wählen sich ein** — kein Projektnetz hat einen eingehenden Port.
5. **Keine Laufzeit-Secrets unter 30 Tagen** im Datenpfad — macht Vault teilbar ohne
   Verfügbarkeitskopplung.
6. **Nomad in genau einem Projekt**, weil genau eines dynamische Workloads hat.
7. **Zwei Sonden pro öffentlichem Dienst** — Diagnose statt Redundanz.
8. **Drei Vault-Knoten oder einer, niemals zwei.**
9. **Getrennte Transit-Keys pro Produkt** — die wichtigste Einzelmaßnahme.
10. **Blob-Auslieferung ohne eigene Compute** — alle Projekte können ausfallen, Downloads laufen.
11. **Restore-Test und Abschalttest sind automatisiert** — Invarianten ohne Test sind Hoffnungen.

---

## Merksatz

> Die Kontrollebene baut und beobachtet. Sie liefert nicht aus.
> Wenn man sie abschaltet und alle Produkte weiterlaufen, ist der Schnitt richtig — und genau das
> wird einmal pro Woche nachgewiesen, nicht angenommen.