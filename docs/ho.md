Dieses Repository ist architektonisch extrem ambitioniert und zeigt ein tiefes Verständnis für moderne Security-Konzepte (Zero-Trust-Worker, Hardware-Isolierung via Firecracker MicroVMs, HashiCorp Vault Transit-Auto-Unseal, mTLS, Seccomp).

Bei einer detaillierten Prüfung der Go-Logik, der Systemarchitektur und der DevOps-Pipelines offenbaren sich jedoch **katastrophale Blocker, Sicherheitslücken und operative Zeitbomben**.
Der Code **kompiliert in seinem jetzigen Zustand nicht**, Firecracker-VMs können nicht starten, und das System enthält gravierende Supply-Chain- sowie Denial-of-Service-Schwachstellen.

Hier ist der detaillierte Audit-Report, sortiert nach Kritikalität:

---

### 🛑 1. Fatale Blocker (System ist nicht lauffähig)

#### 1.1 Der Go-Code kompiliert nicht (`sync.WaitGroup` Fehler)

**Datei:** `internal/worker/daemon/firecracker.go`

```go
d.wg.Go(func() { ... })

```

**Problem:** `d.wg` ist als `sync.WaitGroup` der Standardbibliothek definiert. Diese Struct besitzt **keine** `Go()`-Methode (diese existiert nur in Paketen wie `golang.org/x/sync/errgroup`). Der Worker-Daemon wirft sofort einen Compiler-Fehler.
**Fix:** Klassisches Muster verwenden: `d.wg.Add(1); go func() { defer d.wg.Done(); ... }()`.

#### 1.2 Firecracker VMs crashen immer (KVM-ACL vs. Jailer)

**Dateien:** `deploy/worker/setup-host.sh` & `internal/worker/daemon/vmapi.go`
**Problem:** Das Host-Setup-Skript gewährt dem Linux-Nutzer `toob-worker` via ACL Zugriff auf `/dev/kvm`. Der Worker startet Firecracker jedoch über das Tool `jailer`. Der Jailer erzwingt zur Isolation einen Wechsel auf eine dynamisch berechnete UID (z. B. `10042`):

```go
jailUID := fmt.Sprintf("%d", 10000+(jobID%55536))

```

**Impact:** Da der User `10042` keinen ACL-Eintrag für `/dev/kvm` hat, erhält der Firecracker-Prozess sofort ein **"Permission Denied"** und stirbt. **Keine einzige VM wird jemals hochfahren.**

#### 1.3 Compile-Validation ist eine Placebo-Funktion (Fehlender Compiler)

**Dateien:** `cmd/vmrunner/main.go` & `deploy/worker/build-rootfs.sh`
**Problem:** Der Code in der VM verlangt zwingend einen C-Compiler (`exec.LookPath(compiler)`), andernfalls bricht er mit einem Error ab. Das Skript `build-rootfs.sh`, das die Firecracker-VM aufbaut, installiert jedoch **nur busybox und den vm-runner**.
**Impact:** Es gibt keinen GCC/Clang in der VM. Folglich wird *jeder einzelne Publish-Job* fehlschlagen. Das Veröffentlichen von Code ist in Production unmöglich.

---

### 🚨 2. Kritische Sicherheitslücken (Security & Supply Chain)

#### 2.1 Trivialer CPU-Exhaustion DoS (Bcrypt Cache-Bypass)

**Datei:** `internal/server/middleware/auth.go` (`verifyCached`)
**Problem:** Der Auth-Cache speichert die exakte Kombination aus gesendetem Secret und DB-Hash. Bei einem Cache-Miss fällt das System auf `domain.VerifyAPIKey` zurück, was **bcrypt** (Cost 12, ca. 250ms CPU-Zeit) ausführt.
**Exploit:** Ein Angreifer sendet API-Requests mit einer echten `PublisherID` (UUID), aber generiert für jeden Request ein *zufälliges, falsches* Secret (`Bearer toob_v1_<uuid>_<random>`). Jeder Request zwingt den Server in die langsame Bcrypt-Berechnung. Das Rate-Limit erlaubt 50 Requests/Sek. Ein einzelner Angreifer zwingt die API-Knoten sofort auf 100% CPU-Last und legt das komplette Netzwerk lahm.
**Fix:** API-Keys (256-Bit Zufall) benötigen kein Bcrypt-Salting! Ein einfacher HMAC-SHA256 Abgleich ist sicher und rasend schnell.

#### 2.2 Supply-Chain Attack via "Community PR Spoofing"

**Datei:** `internal/server/handler/worker.go` (`processPackageEntry`)
**Problem:** Wenn ein Nutzer einen Pull Request für ein Paket einreicht, das ihm nicht gehört, wertet das Backend dies als `isCommunityPR = true`.
Beim Speichern des Pakets im `staging`-Stage setzt die API die `PublisherID` auf die UUID des **Original-Besitzers** (`ownerID`).
**Exploit:** Ein Angreifer reicht einen PR mit versteckter Malware für ein populäres Core-Paket ein. Im Admin-Dashboard taucht das Paket nun als Update des *vertrauenswürdigen Original-Autors* auf. Der Admin genehmigt es ("Accept") und verteilt die Malware an alle Nutzer.

#### 2.3 Memory-Exhaustion (OOM) via Tarball-Header Manipulation

**Datei:** `internal/server/handler/tarball_validate.go` (`SecurityScanTarball`)
**Problem:** Im Security-Scanner wird ein Byte-Array auf Basis der im Tar-Header deklarierten Größe allokiert, **bevor** diese limitiert wird:

```go
content := make([]byte, 0, header.Size)

```

**Exploit:** Ein Angreifer lädt ein 1 KB kleines Tar-Archiv hoch, bei dem er `header.Size` auf 20 GB manipuliert. Der Go-Prozess versucht 20 GB RAM zu allokieren, der OS-OOM-Killer greift ein, der API-Server stürzt sofort ab.

#### 2.4 Webhook Path Traversal Bypass

**Datei:** `internal/server/handler/webhook.go` (`isAllowedPath`)
**Problem:** Die Erlaubnis-Prüfung für geänderte Dateien lautet lediglich `strings.HasPrefix(path, prefix)`.
**Exploit:** Ein Angreifer nennt eine Datei im PR `chips/../../../../etc/shadow`. Der Präfix `chips/` ist vorhanden, der Webhook winkt es durch. Der Worker wendet den Diff via `patch -p1` an und überschreibt potenziell Dateien außerhalb des Workspaces innerhalb der VM.

#### 2.5 Private Quellcodes im öffentlichen S3-Bucket (Data Leak)

**Datei:** `deploy/terraform/s3/main.tf`
**Problem:** Der Terraform-Code gibt dem gesamten Bucket die Policy `PublicReadGetObject`.
Gleichzeitig speichert das Backend unveröffentlichte `dev`-Pakete im Bucket. Der S3-Pfad endet auf `<shortID>.tar.gz` (`pkg.ID[:8]`). Da 8 Hex-Zeichen nur extrem schwache 32-Bit Entropie bieten, ist der Dateiname trivial per Brute-Force zu erraten. Jeder kann proprietären Code herunterladen.
**Fix:** Bucket zwingend auf "Private" stellen und für Downloads Pre-Signed URLs generieren.

---

### ⚠️ 3. Logik- & Datenbankfehler

#### 3.1 "Name Squatting" sperrt legitime Entwickler aus

**Datei:** `internal/server/postgres/packages.go` (`GetPackageOwner`)
**Problem:** Die Funktion sucht nach dem ältesten Paket mit einem Namen (`ORDER BY created_at ASC`), filtert aber **nicht** nach `stage`.
Ein Troll kann massenhaft leere Pakete mit bekannten Namen (z.B. `crypto`, `wifi`) in seinen `dev`-Bereich hochladen. Er ist fortan der offizielle "Besitzer". Echte Entwickler werden abgewiesen.

#### 3.2 Datenbank-Crash bei Core-Paketen

**Datei:** `internal/server/postgres/packages.go`
**Problem:** Stammt ein Paket vom Core-Team, ist `publisher_id IS NULL`. `GetPackageOwner` gibt dann den String `"core"` zurück. Reicht jemand einen PR dafür ein, versucht der Worker-Handler, den String `"core"` in die Spalte `publisher_id` (Typ: `UUID`) einzufügen.
**Impact:** PostgreSQL wirft `invalid input syntax for type uuid: "core"`. Permanent 500 Server Error.

#### 3.3 Staging Deadlock (Blockade durch abgelehnte Pakete)

**Datei:** `internal/server/postgres/packages.go`
Wird ein Paket in `staging` vom Admin abgelehnt (`RejectPackage`), erhält es den Status `rejected`, **bleibt aber in der Stage `staging**`.
Der Unique-Index in Postgres blockiert jedoch alle Name/Versions-Kombinationen für `stage IN ('staging', 'stable')`. Der Entwickler kann den Fehler im PR niemals korrigieren und dieselbe Version neu hochladen, da sie in der Datenbank für immer blockiert ist.

#### 3.4 Multi-Commit PRs werden unvollständig getestet

**Datei:** `internal/server/handler/worker.go`

```go
DiffURL: fmt.Sprintf("https://github.com/%s/commit/%s.diff", job.Repo, job.HeadSHA)

```

Diese GitHub-URL lädt **nur den Diff des allerletzten Commits** herunter. Hat ein PR 5 Commits, werden die ersten 4 ignoriert. Der Worker wendet unvollständigen Code an, der Build crasht grundlos. (Muss `/pull/%d.diff` lauten).

#### 3.5 ETag / Signatur Cache-Corruption

**Datei:** `internal/server/handler/registry.go`
Nach einem `Revoke` generiert die API eine Timestamp-Revision (`t1700000...`). Im Registry-Handler wird versucht, dies als Integer zu parsen (`fmt.Sscanf(rev, "%d", &revID)`), was fehlschlägt. `revID` bleibt `0`. Bei mehreren Updates hintereinander bleibt `revID` auf `0`. Das System denkt `cachedRev == revID` und liefert die **alte, ungültige Ed25519-Signatur für das neue JSON-Payload** aus. Clients verweigern den Sync.

---

### 💣 4. Infrastruktur- & DevOps-Zeitbomben

#### 4.1 Die 30-Tage Zeitbombe (Vault SecretIDs)

**Datei:** `deploy/vault/scripts/init.sh`
Die AppRoles für API und Worker werden mit `secret_id_ttl=720h` (30 Tage) angelegt.
Genau 30 Tage nach dem Deployment laufen diese SecretIDs ab. Startet danach ein API-Node neu, skaliert ein neuer Worker hoch oder will der Vault-Agent sein Token erneuern, schlägt die Authentifizierung fehl. **Das System stirbt nach 30 Tagen leise, aber unwiderruflich ab.** (Nutze `secret_id_ttl=0` in Kombination mit Bound-IPs für Infrastruktur-AppRoles).

#### 4.2 Autoscaler Endlos-Crash-Loop

**Datei:** `internal/autoscaler/autoscaler.go`
Der Autoscaler benennt Nodes nach dem Schema `toob-worker-X`. Im Nomad-Job der Worker (`registry-worker.nomad.hcl`) wurde jedoch vergessen, die Umgebungsvariable `TOOB_WORKER_ID` zu definieren!
Das Fallback generiert IDs wie `worker-12345`. Der Autoscaler fragt die DB nach `toob-worker-X` ab, sieht 0 laufende Jobs, stuft den Server als "Idle" ein und **löscht die VM in Hetzner**, während diese gerade stundenlange Validierungs-Jobs ausführt.

#### 4.3 HTTP 30-Sekunden Timeout bricht GitHub Mirror Push

**Datei:** `internal/server/handler/admin.go` (`Release`)
Der Admin-Endpoint ruft `executeMirrorPush` synchron auf. Diese Funktion lädt Tarballs herunter, entpackt sie und pusht jede Datei einzeln über die GitHub REST API. Gleichzeitig hat der HTTP-Server einen globalen Timeout von **30 Sekunden** (`middleware.Timeout`). Ein moderates Release läuft unweigerlich ins Timeout. Das GitHub-Repo bleibt asynchron zur Datenbank.

#### 4.4 RCE-Risiko: Cloud-Tokens auf Public API-Nodes

**Datei:** `deploy/api/toob-db-firewall-cleanup.service`
Das Ansible-Skript legt die hochprivilegierten Tokens für Hetzner (`HCLOUD_TOKEN`) und Ubicloud in `/etc/toob-registry/db-cleanup-env` auf den API-Servern ab. API-Server sind die exponiertesten Knoten (Public Facing). Wird die Go-App kompromittiert, hat der Angreifer volle Kontrolle über die Cloud-Infrastruktur. Solche Cronjobs gehören auf den abgeschotteten Bastion-Host.

#### 4.5 "e2cp" Fork-Bomb beim Snapshot Rebuild

**Datei:** `internal/worker/daemon/snapshot.go`
In `RebuildSnapshot` wird für *jede einzelne Datei* im geclonten Git-Repository ein eigener Prozess via `exec.CommandContext("e2cp", ...)` gestartet. Bei 10.000 Dateien in der Registry bedeutet das 10.000 Subprozess-Spawns in kürzester Zeit. Das sprengt die System-Ressourcen des Workers völlig unnötig.

### Zusammenfassung

Das Sicherheitskonzept (Vault, Firecracker, Seccomp) ist hervorragend. Bevor das System jedoch das Labor verlassen kann, müssen zwingend die Compiler-Fehler, der Bcrypt-DoS, die S3/Vault-Fehlkonfigurationen sowie die PR-Spoofing-Mechanismen korrigiert werden.