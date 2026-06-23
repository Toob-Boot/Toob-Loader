# Toob-Registry — Compiler- & Rootfs-Architektur

> Technische Dokumentation der Compiler-Build-Pipeline, der Rootfs-Distribution
> an Worker-Nodes und der Kompatibilitätsmatrix.

---

## Inhaltsverzeichnis

1. [Überblick & Motivation](#1-überblick--motivation)
2. [Das Compiler-Manifest als Single Source of Truth](#2-das-compiler-manifest-als-single-source-of-truth)
3. [Die Build-Pipeline (`build-compiler.sh`)](#3-die-build-pipeline-build-compilersh)
4. [Das Dockerfile (`Dockerfile.compiler`)](#4-das-dockerfile-dockerfilecompiler)
5. [Toolchain-Provisioning (`install_toolchains.py`)](#5-toolchain-provisioning-install_toolchainspy)
6. [Rootfs-Lifecycle: Build → Distribution → Cache → Nutzung](#6-rootfs-lifecycle-build--distribution--cache--nutzung)
7. [Rootfs-Distribution: Presigned-URL-Modell](#7-rootfs-distribution-presigned-url-modell)
8. [Validierung, Kompatibilitätsmatrix & Chip-Publishing](#8-validierung-kompatibilitätsmatrix--chip-publishing)
9. [SemVer-Oracle: Automatische Versionierung](#9-semver-oracle-automatische-versionierung)
10. [Release-Pipeline: Vom Git-Push zum veröffentlichten Artefakt](#10-release-pipeline-vom-git-push-zum-veröffentlichten-artefakt)
11. [Worker-Capabilities: Job-Routing & Berechtigung](#11-worker-capabilities-job-routing--berechtigung)
12. [CLI Build-Prozess (`toob build`)](#12-cli-build-prozess-toob-build)
13. [Sicherheitsmodell der Compiler-Kette](#13-sicherheitsmodell-der-compiler-kette)
14. [Glossar](#14-glossar)

---

## 1. Überblick & Motivation

Der **Toob-Compiler** ist kein klassischer Compiler, sondern eine deterministische
Build-Umgebung. Er bündelt CLI, Core-SDK, Cross-Compiler-Toolchains und einen
Registry-Snapshot in einem einzigen, reproduzierbaren Artefakt. Dieses Artefakt
existiert in zwei Auslieferungsformen:

| Artefakt | Zweck | Konsument |
|---|---|---|
| **Docker-Image** (`toob-compiler:vX.Y.Z`) | Cross-Compilation für externe Entwickler | Docker Hub, `docker run` |
| **rootfs.ext4** | Firecracker-microVM-Dateisystem für Worker | S3 → Worker-Nodes |

Die zentrale Architekturentscheidung: Beide Artefakte werden aus **einem
einzigen** Dockerfile gebaut. Das Docker-Image wird exportiert, mit `vmrunner`
(PID 1) und BusyBox überlagert und als ext4-Image verpackt. Damit ist
garantiert, dass Docker-Image und Firecracker-Rootfs denselben Inhalt haben —
unterschiedlich ist nur die Laufzeitumgebung (Container vs. VM).

### Warum das wichtig ist

Die rootfs.ext4 **ist die Trusted Computing Base** (TCB) der Firecracker-VM.
Wer die rootfs kontrolliert, kontrolliert:

- Den `vmrunner` (PID 1), der alle Validierungs- und Compile-Ergebnisse erzeugt.
- Die Toolchains, mit denen Community-Code kompiliert wird.
- Die Registry-Referenzdaten, gegen die Cross-References geprüft werden.

Ein manipuliertes Rootfs könnte Compile-Ergebnisse fälschen und Backdoors in
Pakete injizieren. Deshalb unterliegt die gesamte Rootfs-Kette den strengsten
Integritätsanforderungen des Systems.

---

## 2. Das Compiler-Manifest als Single Source of Truth

`compiler/compiler_manifest.json` deklariert **alle** Eingaben des
Compiler-Builds. Kein Paket, keine Abhängigkeit und keine Version darf in
das Artefakt gelangen, ohne in diesem Manifest aufgeführt zu sein.

```
compiler_manifest.json
├── format_version        → Manifest-Schema-Version
├── compiler_version      → SemVer der Compiler-Umgebung selbst
├── protocol_version      → Wire-Protokoll zwischen CLI ↔ Compiler (MAJOR-Breaking)
├── base_image            → Docker-Basisimage (deterministisch, z. B. "ubuntu:26.04")
├── cli                   → CLI-Version + Git-Ref + Artefakt-Name
├── core_sdk              → Core-SDK-Version + Git-Ref
├── registry              → Registry-Snapshot-Ref (für Pre-Seeding)
├── system_packages[]     → apt-get-Pakete (deklarativ, kein „latest")
├── python_packages[]     → pip-Pakete (mit Versionsconstraints)
├── scripts[]             → CI-Build-Wrapper-Skripte
└── distribution          → Docker-Hub-Repository + Plattformen
```

**Determinismus-Regel:** Keines der Versionsfelder darf `"latest"` sein.
`build-compiler.sh` validiert dies explizit und bricht mit `FATAL` ab,
wenn `compiler_version`, `cli.version`, `core_sdk.version` oder
`protocol_version` den Wert `"latest"` tragen.

Das Manifest wird vom SemVer-Oracle versioniert (Kapitel 9) und automatisch
committet, wenn sich eine der 7 Abhängigkeitsdimensionen ändert.

---

## 3. Die Build-Pipeline (`build-compiler.sh`)

Das Build-Skript (`toob-registry/deploy/compiler/build-compiler.sh`) erzeugt
beide Artefakte in einer durchgehenden Pipeline mit 11 Schritten. Es ist bewusst
als Bash-Skript implementiert (kein Makefile, kein CI-YAML), damit es sowohl
lokal als auch im Release-Job des Workers identisch läuft.

### 3.1 Pipeline-Übersicht

```
 1. Manifest lesen + Determinismus-Validierung
 2. Build-Context-Verzeichnis vorbereiten
 3. CLI cross-kompilieren (CGO_ENABLED=0, linux/amd64)
 4. Core-SDK-Quellen in den Context kopieren
 5. Registry-Snapshot in den Context kopieren
 6. Dockerfile + Manifest + Skripte in den Context kopieren
     (Dockerfile.compiler wird per sed-Templating mit exakten Versionen injiziert)
 7. Docker-Image bauen (--no-cache, Build-ARGs + OCI-Labels)
 8. Protocol-Label verifizieren (Roundtrip-Check über docker inspect)
 9. rootfs.ext4 erzeugen (Export → ext4 → vm-runner + BusyBox Overlay)
10. SHA-256-Checksummen generieren
11. Optional: Docker Hub Push + S3 Upload (--push)
```

### 3.2 Determinismus-Garantien

Vier Mechanismen verhindern, dass nicht-deterministische Eingaben in den Build
gelangen:

| Mechanismus | Was es verhindert |
|---|---|
| **`latest`-Blockade** (Schritt 1) | Manifest-Felder mit `"latest"` → sofortiger Abbruch |
| **`sed`-Templating** (Schritt 6) | Dockerfile-ARG-Defaults werden mit exakten Manifest-Werten ersetzt, bevor Docker den Build sieht |
| **`--no-cache`** (Schritt 7) | Docker-Layer-Cache wird nie wiederverwendet; jeder Build startet from scratch |
| **SHA-256-Verifikation** (Toolchains) | `install_toolchains.py` validiert jeden Download gegen die im Registry-Manifest deklarierte Checksumme |

### 3.3 Rootfs-Erzeugung (Schritt 9, Detail)

Die Rootfs-Erzeugung ist der technisch dichteste Abschnitt:

```
Docker-Image
    │
    ├─ docker create → Container-ID
    ├─ docker export → rootfs.tar (flaches Dateisystem, keine Layers)
    │
    ├─ vm-runner cross-kompilieren (CGO_ENABLED=0, linux/amd64)
    │
    ├─ truncate → leere ext4-Datei (Größe = Tar + 500 MB Headroom)
    ├─ mkfs.ext4 → Dateisystem formatieren
    ├─ mount -o loop → Loopback-Mount
    │
    ├─ tar -xf rootfs.tar → Dateisystem befüllen
    ├─ vm-runner → /sbin/init (PID 1 der VM)
    ├─ BusyBox → /bin/{busybox, patch, cp, mount, umount, sync, poweroff}
    ├─ mkdir → /proc, /registry, /input, /output, /workspace
    │
    ├─ umount → sauberes Dateisystem
    └─ sha256sum → Checksumme
```

> **Zwei subtile Designentscheidungen:**
>
> - **BusyBox-Applets werden als vollständige Kopien** installiert (nicht als
>   Symlinks). In einer Firecracker-VM mit Read-Only-Rootfs würden Symlinks,
>   die auf eine gelöschte Zieldatei zeigen, silent fails verursachen.
> - **Der Mount-Point `/workspace`** ist im rootfs als leerer Ordner angelegt,
>   wird aber zur Laufzeit als `tmpfs` gemountet. Das stellt sicher, dass der
>   Arbeitsbereich nach VM-Ende spurlos verschwindet.

### 3.4 Publikation (`--push`)

Bei `--push` werden zwei Artefakte veröffentlicht:

1. **Docker Hub** — nur der versionierte Tag (`v1.2.3`). Es gibt keinen
   `:latest`-Tag. Alle Konsumenten referenzieren die exakte Version.

2. **S3** — `rootfs-v{VERSION}.ext4` + `checksums.sha256` unter dem Pfad
   `compiler/v{VERSION}/`.

### 3.5 Cleanup-Trap

Das Skript registriert einen `EXIT`-Trap, der in jeder Terminierungssituation
aufräumt: Loop-Devices unmounten, Docker-Login-Credentials löschen und den
temporären Build-Context entfernen. Damit bleiben keine montierten Dateisysteme
oder gecacheten Credentials auf dem Build-Host zurück.

---

## 4. Das Dockerfile (`Dockerfile.compiler`)

Das Dockerfile baut das Docker-Image in einer Single-Stage-Pipeline (kein
Multi-Stage, da die Toolchains zu groß für die Zwischenschicht-Optimierung sind).

### 4.1 Layer-Struktur

```dockerfile
FROM ${BASE_IMAGE}                      # ubuntu:26.04 (deterministisch, kein :latest)

# 1. Systempakete + Python (deklarativ aus Manifest, kein interaktives apt)
RUN apt-get ... $(jq -r '.system_packages[]' manifest) ...
    pip3 install $(jq -r '.python_packages[]' manifest) ...

# 2. CLI-Binary (cross-compiled vom Build-Host)
COPY toob-linux-amd64 /usr/local/bin/toob

# 3. CI-Build-Wrapper
COPY toob-ci-build.sh /usr/local/bin/toob-ci-build

# 4. Registry-Snapshot (Pre-Seeded, vermeidet 200 MB Clone)
COPY registry/ /root/.toob/registry/versions/main/

# 5. Toolchains (SHA-256-verifiziert via install_toolchains.py)
RUN python3 install_toolchains.py ... && rm install_toolchains.py

# 6. Core-SDK-Quellen (Pre-Seeded, CLI überspringt git clone)
COPY core-sdk/ /opt/toob-core-sdk/
ENV TOOB_COMPILER_DIR=/opt/toob-core-sdk
```

Drei Designentscheidungen sind hier bemerkenswert:

- **`jq` wird am Ende wieder entfernt** (`apt-get purge -y --auto-remove jq`),
  um die Angriffsfläche im Image minimal zu halten.
- **`install_toolchains.py` wird nach Ausführung gelöscht** — es ist ein
  Build-Time-Tool, kein Runtime-Dependency.
- **ARG-Defaults sind bewusst `0.0.0`** statt `latest`. Das stellt sicher, dass
  ein Build *ohne* explizite Build-ARGs ein klar als ungültig erkennbares
  Artefakt erzeugt, nicht ein stillschweigend falsches.

### 4.2 Label-Konvention

Jedes Image trägt sowohl OCI-Standard-Labels (`org.opencontainers.image.*`)
als auch projektspezifische Labels (`toob.compiler_version`, `toob.cli_version`,
`toob.protocol_version`). Der Protocol-Label wird nach dem Build per
`docker inspect` roundtrip-verifiziert — stimmt er nicht, bricht das Skript ab.

---

## 5. Toolchain-Provisioning (`install_toolchains.py`)

Die Toolchain-Installation ist der sicherheitskritischste Schritt im Build,
denn hier werden externe Binaries heruntergeladen und ins Image extrahiert.

### 5.1 Ablauf

```
Registry-Snapshot → toolchains/{name}/toolchain_manifest.json
    │
    ├─ url: linux_amd64 Download-URL (https-only)
    ├─ sha256: linux_amd64 erwartete Checksumme
    │
    ├─ Download (mit Mirror-Fallback + Retry)
    ├─ SHA-256 Verify (fail-closed bei Mismatch)
    └─ Extract nach /root/.toob/toolchains/{name}/{upstream_version}/
```

### 5.2 Sicherheitsmaßnahmen

| Maßnahme | Implementierung |
|---|---|
| **SHA-256-Pflicht** | Keine Toolchain ohne deklarierten Hash wird installiert |
| **Fail-Closed auf Mismatch** | Hash-Abweichung → `sys.exit(1)`, partielle Installation wird aufgeräumt (`shutil.rmtree`) |
| **Retry mit Backoff** | 3 Versuche pro URL, 2/4 Sekunden Backoff (gegen transiente Netzfehler) |
| **Mirror-Support** | `TOOB_TOOLCHAIN_MIRROR` als Env-Variable; Mirror wird *vor* dem Upstream versucht |
| **Timeout** | 60 s Socket-Timeout global gesetzt |
| **Idempotenz** | Bereits installierte Toolchains werden übersprungen |
| **Keine externen Dependencies** | Nur Python-Stdlib (urllib, hashlib, tarfile, zipfile) |

### 5.3 Toolchain-Discovery in der VM

Der `vmrunner` findet die installierten Toolchains zur Laufzeit über
`discoverToolchainBins("/root/.toob/toolchains")`. Die Suche iteriert über
`{name}/{version}/` und findet `bin/`-Verzeichnisse bis 3 Ebenen tief — robust
auch gegenüber verschachtelten Layouts wie
`riscv32-esp-elf/13.2.0/riscv32-esp-elf/bin/`. Alle gefundenen `bin/`-Pfade
werden dem `PATH` vorangestellt.

---

## 6. Rootfs-Lifecycle: Build → Distribution → Cache → Nutzung

### 6.1 Ist-Zustand: Statische Rootfs

Im aktuellen Zustand wird die rootfs.ext4 statisch ins Packer-Golden-Image
gebacken und über Terraform an die Worker-Nodes verteilt:

```
build-compiler.sh → build/rootfs.ext4
    → Packer (install-binaries.sh → /opt/toob-worker/rootfs.ext4)
        → Terraform (VM aus Golden Image)
            → Nomad-Job (FIRECRACKER_ROOTFS=/opt/toob-worker/rootfs.ext4)
```

Dieses Modell hat eine zentrale Stärke — **keine Download-Logik auf dem Worker**
— aber auch klare Grenzen:

| Eigenschaft | Bewertung |
|---|---|
| Update-Zyklus | Langsam: Neues Packer-Image → `terraform apply` → Worker ersetzen |
| Multi-Version | ❌ Nicht möglich — genau eine rootfs pro Golden-Image |
| Compatibility-Matrix | ❌ Kann nicht mit verschiedenen Compiler-Versionen testen |

### 6.2 Zielzustand: Dynamische Rootfs via Presigned-URL

Das Kernproblem: Die Kompatibilitätsmatrix (Kapitel 8) erfordert, dass Worker
mit verschiedenen Compiler-Versionen arbeiten können. Dafür muss die rootfs
dynamisch beschafft werden — ohne das Zero-Trust-Modell zu kompromittieren.

Die Lösung nutzt das **identische Pattern**, das bereits für Paket-Downloads und
Diff-URLs existiert: zeitlich begrenzte, presigned S3-GET-URLs, ausgestellt
von der Control Plane. Die vollständige Architektur ist in Kapitel 7 beschrieben.

---

## 7. Rootfs-Distribution: Presigned-URL-Modell

### 7.1 Bedrohungsmodell

Der Worker führt fremden, nicht überprüften C-Code aus. Die bestehende
Isolationskette:

```
Nomad → raw_exec (toob-worker, kein root)
  → Jailer (setuid root, chroot, AppArmor, per-Job-UID/GID, cgroups)
    → Firecracker/KVM (Hardware-Isolation)
      → microVM: vmlinux 5.10 + rootfs.ext4, vmrunner als PID 1
        Mounts: /registry /input /output /workspace — KEIN Netzwerk im Gast
```

Jede Rootfs-Distributionsmethode muss zwei Invarianten wahren:

1. **Der Worker besitzt keine S3-Credentials** — er darf keine Objekte im Bucket
   auflisten, lesen oder schreiben, außer über zeitlich begrenzte, von der
   Control Plane ausgestellte URLs.
2. **Die Rootfs-Integrität wird kryptographisch verifiziert** — die Control
   Plane liefert die Checksumme als Root-of-Trust.

### 7.2 Verworfene Alternativen

| Option | Warum verworfen |
|---|---|
| **Worker lädt direkt von S3** | Bricht Zero-Trust: Worker bräuchte S3-Credentials. Ein kompromittierter Worker könnte beliebige Bucket-Objekte manipulieren (Paket-Tarballs, andere rootfs). |
| **Control Plane streamt rootfs** | Eine rootfs ist 500 MB–2 GB. Die API-Server als Streaming-Proxy zu missbrauchen, widerspricht deren Rolle als leichtgewichtige Steuerungsebene und skaliert nicht. |

### 7.3 Architektur: Presigned-URL mit SHA-256-Verifikation

```
  Worker                    Control Plane                 Hetzner S3
    │                            │                            │
    │  Job erfordert             │                            │
    │  rootfs v2.3.0             │                            │
    │                            │                            │
    │─── GET /api/v1/worker/ ──▶│                            │
    │    rootfs/v2.3.0           │                            │
    │    (mTLS, Job-Token)       │                            │
    │                            │──── Lookup: v2.3.0 ────┐  │
    │                            │     SHA-256 aus DB      │  │
    │                            │◀── Presigned GET URL ──┘  │
    │◀── 200 {url, sha256, ─────│                            │
    │        size}               │                            │
    │                            │                            │
    │─── GET presigned URL ──────┼──────────────────────────▶│
    │    (externer Client,       │                            │
    │     KEIN mTLS-Cert!)       │                            │
    │◀── rootfs-v2.3.0.ext4 ────┼────────────────────────────│
    │                            │                            │
    │  SHA-256 verify            │                            │
    │  (streaming, fail-closed)  │                            │
    │                            │                            │
    │  Atomarer Rename →         │                            │
    │  /opt/toob-worker/         │                            │
    │  rootfs/v2.3.0.ext4        │                            │
```

Dieses Schema nutzt **exakt die gleichen Sicherheitsmechanismen**, die bereits
für drei andere Datenflüsse im System etabliert sind:

| Bestehender Datenfluss | Client | Richtung |
|---|---|---|
| Diff-Download (`DownloadDiff`) | `external` (kein mTLS-Cert) | S3/GitHub → Worker |
| Paket-Upload (`UploadToPresignedURL`) | `external` (kein mTLS-Cert) | Worker → S3 |
| Paket-Download (`GET .../download`) | öffentlich | S3 → CLI-Nutzer |

### 7.4 Sicherheitseigenschaften

| Eigenschaft | Garantie |
|---|---|
| **Keine S3-Credentials auf dem Worker** | Der `external`-Client löst einen presigned GET ein — identisch zum Diff-Download |
| **Presigned URL ist zeitlich begrenzt** | TTL 15 Minuten, danach wertlos |
| **Kein Upload durch den Worker möglich** | Die URL ist ein GET, kein PUT |
| **SHA-256 als Root-of-Trust** | Checksumme kommt von der Control Plane (DB-backed), nicht aus der URL oder aus S3-Metadaten |
| **Man-in-the-Middle-Schutz** | S3-Download über HTTPS; Manipulation erkennbar durch SHA-256-Mismatch |
| **Kompromittierter S3-Bucket** | Kann keine manipulierte rootfs einschleusen, solange die DB-Checksumme integer ist |
| **mTLS-Identität bleibt geschützt** | Der `external`-Client sendet kein Client-Zertifikat an S3 |

### 7.5 Version kommt von der Control Plane

Die erforderliche Compiler-Version wird **nicht vom Worker gewählt**, sondern
kommt als Feld im Job-Claim von der Control Plane:

```go
type PublishClaimedJob struct {
    // ... bestehende Felder ...
    CompilerVersion string // z. B. "1.1.16" — diktiert von der Control Plane
}
```

Damit kann ein kompromittierter Worker keine ältere, potentiell verwundbare
rootfs-Version erzwingen. Die Control Plane entscheidet basierend auf dem
Build-Kontext des Pakets (`reference_build_context` im Manifest), welche
Compiler-Version passend ist.

### 7.6 Lokaler Cache auf dem Worker

```
/opt/toob-worker/rootfs/
├── v1.1.16.ext4          (gecached, verifiziert)
├── v1.1.16.ext4.sha256   (SHA-256-Sidecar für schnelle Re-Verifikation)
├── v1.1.15.ext4
├── v1.1.15.ext4.sha256
└── .tmp/                  (Downloads in progress)
```

**Cache-Mechanik:**

1. **Erster Request:** Rootfs nicht vorhanden → Pull über presigned URL →
   streaming SHA-256 → atomarer Rename aus `.tmp/`.
2. **Folge-Requests:** SHA-256-Sidecar vorhanden → schneller Vergleich →
   rootfs direkt verwenden.
3. **Daemon-Start:** Alle gecacheten rootfs werden gegen ihre Sidecar-Dateien
   re-verifiziert. Fehlschlag → Datei löschen, beim nächsten Job neu pullen.
4. **Eviction:** Maximal N Versionen (konfigurierbar, Default: 3). Älteste wird
   bei Überschreitung gelöscht. Das verhindert Disk-Erschöpfung.

**Atomares Download-Pattern:**

```
1. Download → /opt/toob-worker/rootfs/.tmp/v2.3.0.ext4.downloading
2. SHA-256 streaming verify (fail-closed)
3. os.Rename → /opt/toob-worker/rootfs/v2.3.0.ext4 (atomar auf ext4)
4. SHA-256-Sidecar schreiben: v2.3.0.ext4.sha256
```

Kein laufender Job sieht eine halb-geschriebene oder unverifizierte rootfs.

### 7.7 Datenmodell: `compiler_versions`

```sql
CREATE TABLE compiler_versions (
    id              BIGSERIAL PRIMARY KEY,
    version         TEXT NOT NULL UNIQUE,        -- "1.1.16"
    rootfs_sha256   TEXT NOT NULL,               -- hex, 64 chars
    rootfs_s3_key   TEXT NOT NULL,               -- "compiler/v1.1.16/rootfs-v1.1.16.ext4"
    rootfs_size     BIGINT NOT NULL,             -- Bytes
    cli_version     TEXT NOT NULL,               -- eingebettete CLI-Version
    core_version    TEXT NOT NULL,               -- eingebettete Core-SDK-Version
    protocol_version INTEGER NOT NULL,           -- Wire-Protokoll-Version
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`is_active` ermöglicht das sofortige Deaktivieren einer fehlerhaften Version,
ohne sie zu löschen (Audit-Trail). Ein deaktivierter Eintrag wird bei
`GET /api/v1/worker/rootfs/{version}` mit 404 beantwortet.

### 7.8 API-Endpunkte

| Methode | Pfad | Auth | Zweck |
|---|---|---|---|
| `POST` | `/api/v1/admin/compiler-versions` | Session-Token + `admin:manage` | Neue Compiler-Version registrieren |
| `GET` | `/api/v1/worker/rootfs/{version}` | mTLS + Job-Token | Presigned Download-URL + SHA-256 + Größe |
| `GET` | `/api/v1/admin/compiler-versions` | Session-Token + `admin:read` | Alle registrierten Versionen auflisten |
| `PATCH` | `/api/v1/admin/compiler-versions/{version}` | Session-Token + `admin:manage` | `is_active` togglen |

Der Worker-Endpunkt prüft:

1. Gültiges mTLS-Zertifikat mit CN `worker.global.nomad`.
2. Version existiert und `is_active = true`.
3. Presigned GET-URL wird mit TTL 15 min aus dem S3-Client erzeugt.

### 7.9 Konfigurationsänderungen

| Komponente | Vorher | Nachher |
|---|---|---|
| **Worker-Config** | `FIRECRACKER_ROOTFS` (einzelne Datei) | `FIRECRACKER_ROOTFS_DIR` (Cache-Verzeichnis) |
| **Nomad-Job** | `FIRECRACKER_ROOTFS = "/opt/toob-worker/rootfs.ext4"` | `FIRECRACKER_ROOTFS_DIR = "/opt/toob-worker/rootfs"` |
| **Packer** | rootfs.ext4 nach `/opt/toob-worker/rootfs.ext4` | Seed-rootfs nach `/opt/toob-worker/rootfs/v{SEED}.ext4` + Verzeichnis |
| **Cloud-Init** | `mkdir /opt/toob-worker/` | `mkdir -p /opt/toob-worker/rootfs/.tmp` |

**Abwärtskompatibilität:** Ist `FIRECRACKER_ROOTFS` (alter Pfad) gesetzt und
`FIRECRACKER_ROOTFS_DIR` nicht, fällt der Worker auf das statische Modell zurück.
Damit können bestehende Deployments ohne sofortige Änderung weiterlaufen.

### 7.10 Fallback bei unerreichbarer Control Plane

Die Packer-gebackene Seed-rootfs bleibt als Fallback erhalten. Ist die
Control Plane beim Boot nicht erreichbar und der Job keine explizite Version
diktiert, verwendet der Worker die neueste lokal gecachete Version. Der
Startup-Log meldet diesen Zustand als Warning.

---

## 8. Validierung, Kompatibilitätsmatrix & Chip-Publishing

### 8.1 Drei Job-Typen: Wer validiert was?

Das System hat drei verschiedene Ingest-Pfade mit unterschiedlichen Auslösern
und Validierungstiefen:

| Job-Typ | Auslöser | Was kommt rein | Validierungstiefe |
|---|---|---|---|
| **Validation-Job** | GitHub-PR auf das interne Monorepo | `pr.diff` (Unified-Diff) | Schema + Integrity + Security + `gcc -c` Smoke |
| **Publish-Job** | `toob publish` (CLI, externe Entwickler/Vendor) | `package.tar.gz` (Tarball) | Schema + Integrity + Security + Compile-Validierung |
| **Release-Job** | Git-Tag auf `main` (automatisch) | SemVer/CLI/Core/Compiler | Vollständiger Build + Cross-Compile + Artefakt-Signierung |

**Wichtig:** Es gibt kein PR-System für externe Packages. Wenn ein
Chip-Vendor ein Package einreicht, geschieht das über `toob publish` →
Publish-Job → Firecracker-VM. Die PR-basierte Validierung betrifft
ausschließlich **interne Änderungen** am Monorepo (Core-SDK, CLI,
Compiler-Manifest, Registry-Struktur).

### 8.2 Package-Kategorien und Validierungsstrenge

Nicht alle Packages sind gleich komplex. Das System kennt sieben Kategorien
(aus `domain.ManifestFilenames`): `chip`, `arch`, `driver`, `crypto`,
`toolchain`, `integration`, `port`. Chips sind die anspruchsvollste
Kategorie, weil sie von allen anderen abhängen:

```
chip (esp32c6)
  ├── arch (riscv32)            ← Architektur-Abstraktionsschicht
  ├── toolchain (riscv32-esp-elf) ← Cross-Compiler
  ├── drivers[]                 ← HAL-Treiber (GPIO, SPI, ...)
  ├── crypto.backend            ← Kryptographie-Implementierung
  ├── core-sdk                  ← OS-Kern-API (rp_* Funktionen)
  └── sources                   ← Startup, Platform, Linker-Script
        ├── startup.S           ← braucht arch-Header
        ├── platform.c          ← braucht Core-SDK API
        └── linker.ld           ← braucht Speicher-Layout des Chips
```

Ein einfaches Driver-Package (`gpio_driver`) hat keine solche Kaskade —
es kompiliert gegen definierte HAL-Interfaces und ist damit isoliert
testbar. Ein Chip-Package dagegen **definiert** diese Interfaces und
muss nachweisen, dass alles zusammenpasst.

### 8.3 Validierungsstufen nach Package-Kategorie

| Kategorie | Stufe 1: Strukturprüfung | Stufe 2: Compile-Smoke | Stufe 3: Full-Build | Stufe 4: Matrix |
|---|---|---|---|---|
| **driver** | Schema + Integrity + Security | `gcc -c` pro Datei | ❌ | ❌ |
| **crypto** | Schema + Integrity + Security | `gcc -c` pro Datei | ❌ | ❌ |
| **arch** | Schema + Integrity + Security | `gcc -c` pro Datei | ❌ | ❌ |
| **toolchain** | Schema + SHA-256 + URL-Allowlist | ❌ (keine Quelldateien) | ❌ | ❌ |
| **chip** | Schema + Integrity + Security | `gcc -c` pro Datei | **Full-Build Gate** | **Matrix-Befüllung** |

Chips werden **strenger** behandelt als alle anderen Package-Kategorien.

### 8.4 Dreistufiges Chip-Validierungsmodell

#### Stufe 1 — Publish-Validierung (Ist-Zustand)

Jeder Publish-Job durchläuft die Firecracker-VM mit identischen Prüfschritten:

1. **ManifestValidation:** `chip_manifest.json` hat alle Pflichtfelder
   (`name`, `version`, `arch`, `compiler_prefix`), referenzierte Architektur
   und Toolchain existieren in der Registry.
2. **IntegrityCheck:** Alle in `sources.*` referenzierten Pfade existieren
   (Startup, Platform, Linker, Drivers, Extra, Includes). Path-Traversal-Guard
   (`..` verboten).
3. **SecurityScan:** Keine Binaries, keine Symlinks, keine privilegierten
   Makros, keine unerlaubten `#include`-Pfade.
4. **DiffBumpCheck:** Version muss bei Änderung inkrementiert sein.
5. **Compile-Smoke:** `gcc -c` (mit dem im Manifest deklarierten
   `compiler_prefix`) pro `.c/.cpp/.S`-Datei, Include-Pfade aus
   `chip_manifest.includes`.

**Was das prüft:** Syntaktische Korrektheit, Manifest-Konsistenz,
Sicherheit, einzelne Dateien kompilieren.

**Was das NICHT prüft:** Ob das Chip-Package als Ganzes — mit Core-SDK,
Drivers, Crypto, Linker-Script — zu einer lauffähigen Firmware kompiliert.

#### Stufe 2 — Full-Build Gate (Zielzustand, TODO)

Für Chip-Packages muss der `vmrunner` einen vollständigen `toob build
--native` ausführen, bevor das Package als `VERIFIED` publiziert wird.
Dies erfordert:

- **CMake + Ninja im rootfs** (derzeit nicht enthalten)
- **Referenz-Projekte pro Chip** im Registry-Snapshot: ein minimaler
  `device.toml` + `main.c`, der die deklarierten Interfaces instantiiert
- Die CLI und der Core-SDK sind **bereits im rootfs** (`/usr/local/bin/toob`,
  `/opt/toob-core-sdk`) — es fehlt nur die Build-Engine

Der Full-Build-Test beweist:
- ✅ Alle Include-Pfade lösen über Registry-Grenzen korrekt auf
- ✅ Core-SDK-Symbole (z. B. `rp_gpio_init`) sind vorhanden und linkbar
- ✅ Crypto-Slots werden korrekt aufgelöst
- ✅ Linker-Script + Startup-Code + Platform-Init = gültiges ELF
- ✅ Toolchain-Flags und CPU-Architektur passen zusammen

**Publish-Entscheidung:** Nur wenn Stufe 1 + Stufe 2 bestehen, wird das
Chip-Package publiziert. Bei Nicht-Chip-Packages reicht Stufe 1.

#### Stufe 3 — Matrix-Befüllung (asynchron, nach Publish)

Nach erfolgreichem Publish werden automatisch Matrix-Jobs enqueued, die
das Chip-Package mit **verschiedenen Compiler- und CLI-Versionen** testen.
Das ist die Breitenvalidierung für Abwärtskompatibilität.

### 8.5 Kompatibilitätsmatrix

#### Zweck

Die Matrix beantwortet die Frage: *Funktioniert Chip X@Version mit
CLI-Version Y, Core-SDK Z und Compiler W?*

#### Combination-Key (4 Dimensionen)

Einträge werden als `combination_key` gespeichert:

```
chip=esp32c6@1.1.0::cli=v0.7.0::core=0.0.1::compiler=v1.1.16
```

Die vier Dimensionen sind:

| Dimension | Quelle | Warum relevant |
|---|---|---|
| **Chip + ChipVersion** | `chip_manifest.json` | Bestimmt Architektur, Drivers, Toolchain-Prefix |
| **CLI-Version** | `toob` Binary in der rootfs | Steuert die Build-Pipeline, Manifest-Compiler, Crypto-Resolution |
| **Core-SDK-Version** | `/opt/toob-core-sdk` | API-Symbole (`rp_*`), Header, ABI |
| **Compiler-Version** | rootfs-Tag (`v1.1.16`) | Toolchain-Versionen, System-Pakete, Python-Umgebung |

#### Statusmodell

| Status | Bedeutung |
|---|---|
| `PENDING` | Kombination angelegt, wartet auf Test-Job |
| `RUNNING` | Test-Job läuft gerade in einer Firecracker-VM |
| `VERIFIED` | Full-Build erfolgreich |
| `FAILED` | Full-Build fehlgeschlagen |

#### Datenmodell (`matrix_entries`)

```sql
CREATE TABLE matrix_entries (
    id              BIGSERIAL PRIMARY KEY,
    chip            TEXT NOT NULL,
    chip_version    TEXT NOT NULL,
    env_hash        TEXT NOT NULL,           -- Hash der Abhängigkeiten
    dependencies    JSONB NOT NULL,          -- Aufgelöste Abhängigkeiten als JSON
    combination_key TEXT NOT NULL UNIQUE,    -- "chip=...::cli=...::core=...::compiler=..."
    status          TEXT NOT NULL DEFAULT 'PENDING',
    tested_at       TIMESTAMPTZ,
    revision        BIGINT REFERENCES revisions(id)
);
```

#### Matrix-Befüllung (Flow)

```
1. Chip v1.2.0 wird publiziert (Stufe 2 bestanden)
2. Control Plane erzeugt matrix_entries für:
   - aktuelle CLI × aktueller Core × aktueller Compiler → PENDING
   - aktuelle CLI × aktueller Core × Compiler N-1       → PENDING
   - CLI N-1       × aktueller Core × aktueller Compiler → PENDING
   - (optional weitere Kombinationen)
3. Matrix-Jobs werden enqueued (spezielle Publish-Jobs mit expliziter
   CompilerVersion im Claim)
4. Worker lädt die passende rootfs (Cache oder Pull, Kapitel 7)
5. Firecracker-VM führt Full-Build aus
6. Ergebnis → matrix_entries.status = VERIFIED|FAILED
```

#### CLI-Abfrage

Die CLI fragt vor jedem Build die Matrix ab (Phase 6 im Build-Prozess,
Kapitel 12):

```
GET /api/v1/resolve/combination?chip=esp32c6&chip_version=1.1.0&cli=v0.7.0
```

| Matrix-Ergebnis | CLI-Verhalten |
|---|---|
| `VERIFIED` | Weiter (kein Output) |
| `FAILED` | **Harter Abbruch** — Build wird blockiert |
| Nicht in Matrix | Warnung — Build läuft weiter |
| Matrix unerreichbar | Warnung — Build läuft weiter |
| `--skip-checks` | Matrix wird gar nicht abgefragt |

### 8.6 Chip Publish-Readiness: Wann ist ein Chip "public"?

```
Publish-Request (toob publish):
  ✅ Stufe 1: Schema + Integrity + Security + gcc -c Smoke
  ✅ Stufe 2: Full-Build mit aktuellem Compiler + CLI + Core-SDK
    → Chip wird in der Registry publiziert
    → Matrix-Jobs werden automatisch enqueued

Post-Publish (asynchron):
  Matrix-Jobs laufen:
    ✅ compiler=v1.1.16 + cli=v0.7.0 + core=0.0.1 → VERIFIED
    ✅ compiler=v1.1.15 + cli=v0.6.0 + core=0.0.1 → VERIFIED
    ❌ compiler=v1.0.0  + cli=v0.5.0 + core=0.0.1 → FAILED
      → transparent für Nutzer via CLI-Warnung
```

Ein Chip ist **publish-ready**, sobald der Full-Build mit der **aktuellen**
Compiler/CLI/Core-Kombination erfolgreich durchläuft (Stufe 2). Die Matrix
(Stufe 3) validiert Abwärtskompatibilität und informiert Nutzer älterer
Tool-Versionen.

### 8.7 Integration mit Rootfs-Versioning

Die Multi-Version-Rootfs-Distribution (Kapitel 7) ist die technische
Voraussetzung für die Matrix-Befüllung. Um eine Kombination mit
`compiler=v1.0.0` zu testen, muss der Worker die rootfs `v1.0.0` laden
können — nicht nur die aktuelle Version.

---

## 9. SemVer-Oracle: Automatische Versionierung

Das SemVer-Oracle (`toob-registry/cmd/vmrunner/semver.go`, 985 Zeilen) läuft
**innerhalb einer air-gapped Firecracker-VM** (`//go:build linux`). Es wird
vom `vmrunner` aufgerufen, wenn ein `release_manifest.json` mit
`component: "semver"` auf dem Input-Block-Device liegt. Seine Aufgabe:
automatisch den korrekten SemVer-Sprung (PATCH/MINOR/MAJOR/None) für **drei
unabhängige Subsysteme** bestimmen — und dabei sicherstellen, dass
Breaking Changes nie ohne Protocol-Version-Bump durchrutschen.

### 9.1 Orchestrierung (`executeSemverOracle`)

Die drei Analysen laufen sequenziell, wobei die Ergebnisse **kaskadieren**:

```
1. analyzeCoreSDK  → coreBump (PATCH|MINOR|MAJOR|NONE)
2. analyzeCLI      → cliBump  (PATCH|MINOR|MAJOR|NONE)
3. analyzeCompiler(cliBump, coreBump) → compilerBump
     ↑ erbt die Bumps der vorherigen Stufen
```

Die Inputs kommen als Git-Archive (Baseline-Tag vs. aktueller Commit),
extrahiert vom Worker-Daemon auf dem Host (Kapitel 10) und als Block-Devices
in die VM gemountet. Das Oracle hat keinen Netzwerkzugriff.

### 9.2 Core-SDK-Analyse (`analyzeCoreSDK`)

Zweischichtig, prüft ABI-Stabilität auf Binärebene und Header-Ebene:

**Layer 1 — ABI-Symbolvergleich:**

1. Baseline und Current werden *innerhalb der VM* nativ gebaut (`toob build
   --native`).
2. Per `nm --defined-only -g` werden die exportierten Symbole aus jeder
   `.a`-Library extrahiert (nutzt `riscv32-esp-elf-nm` wenn vorhanden,
   Fallback auf `nm`).
3. Entferntes Symbol → **MAJOR**, neues Symbol → **MINOR**.

**Layer 2 — C-Header-Diff:**

1. Rekursiver Vergleich aller `.h`-Dateien in den `HeaderPatterns`-
   Verzeichnissen.
2. Gelöschter Header → **MAJOR**, neuer Header → **MINOR**.
3. Geänderte `typedef`/`struct`/`enum`-Zeilen (per Regex `^\s*(typedef\s|
   struct\s|enum\s|}\s*\w+)`) → **MINOR** (konservativ, da Feldlöschungen
   ohne Symboländerung erkannt werden müssen).

### 9.3 CLI-Analyse (`analyzeCLI`)

Parsing der Go-Datei `ports.go` (das Wire-Contract-Interface zwischen CLI und
Compiler) via Go's `go/parser` in ein `InterfaceInfo`-Modell:

```
InterfaceInfo
├── ProtocolVersion  int               (aus const ProtocolVersion = N)
├── Structs          map[name]fields   (jedes Feld: Name, Type, port-Tag, json-Tag)
├── Constants        map[name]value    (exportierte Konstanten)
└── TypeAliases      map[name]type     (exportierte Type-Aliase)
```

Die Vergleichsregeln:

| Änderung in `ports.go` | Bump |
|---|---|
| Struct entfernt | **MAJOR** |
| Required-Feld entfernt oder Typ geändert | **MAJOR** |
| `optional` → `required` Tag-Wechsel | **MAJOR** |
| JSON-Wire-Name oder Serialisierungsoptionen geändert | **MAJOR** |
| Neues Required-Feld hinzugefügt | **MAJOR** |
| Exportierte Konstante/TypeAlias entfernt oder Wert/Typ geändert | **MAJOR** |
| Optional-Feld entfernt | **MINOR** |
| Neues Optional-Feld, neuer Struct, neue Konstante/TypeAlias | **MINOR** |
| Keine strukturelle Änderung | **PATCH** |

**Harter Blocker bei MAJOR:** Erkennt das Oracle Breaking Changes, **muss**
`ProtocolVersion` in `ports.go` inkrementiert worden sein. Ist sie es nicht,
bricht die Analyse mit `[FATAL]` ab — der gesamte Release wird blockiert.
Das ist der automatische Enforcer, der verhindert, dass ein CLI-Release
ausgeht, der alte Compiler-Images inkompatibel macht.

**Port-Tag-Pflicht:** Jedes exportierte Feld in `ports.go`-Structs muss ein
`port:"required"` oder `port:"optional"` Tag tragen. Fehlt es, bricht der
Parser mit einem Fehler ab — keine unklassifizierten Felder erlaubt.

### 9.4 Compiler-Analyse (`analyzeCompiler`)

Vergleicht `compiler_manifest.json` (Baseline vs. Current) über sieben
Dimensionen:

| Dim | Feld | Sprung bei Änderung |
|---|---|---|
| 1 | `protocol_version` | **MAJOR** (Wire-Format-Bruch) |
| 2 | `cli.version` | Erbt den CLI-Sprung |
| 3 | `core_sdk.version` | Core MAJOR/MINOR → Compiler MINOR; Core PATCH → PATCH |
| 4 | `base_image.image` | **MINOR** |
| 5 | `system_packages[]` | **MINOR** (sortierter Vergleich) |
| 6 | `python_packages[]` | **MINOR** (sortierter Vergleich) |
| 7 | `registry.source.ref` | **MINOR** |

**Entkopplungslogik (Dim 2):** Ändert sich *ausschließlich* die eingebettete
CLI-Version (keine sonstige Manifest-Änderung, kein CLI-Code im selben
Release-Lauf, kein MAJOR), wird der Compiler-Build **aufgeschoben**
(`BumpNone`). Das verhindert eine Lawine von Compiler-Releases bei jedem
CLI-Patch — ein CLI-Patch ändert nichts an der Compile-Umgebung.

**Manifest-Rückschreibung:** Am Ende berechnet das Oracle die neue
`compiler_version` aus der Baseline + dem ermittelten Bump und gibt das
modifizierte Manifest als JSON-String im `ReleaseResult` zurück. Der
Host-Worker kann es dann committen.

### 9.5 Ergebnis-Ausgabe

Das SemVer-Oracle schreibt ein `result.json` auf das Output-Block-Device:

```json
{
  "status": "success",
  "subsystems": [
    { "component": "core", "bump": "MINOR", "old_tag": "core/v0.0.5",
      "new_tag": "core/v0.1.0", "messages": ["[MINOR] Symbol rp_foo added..."] },
    { "component": "cli", "bump": "PATCH", ... },
    { "component": "compiler", "bump": "MINOR", ... }
  ],
  "tags_to_push": ["core/v0.1.0", "cli/v0.7.1", "compiler/v1.2.0"],
  "compiler_manifest_content": "{...updated manifest JSON...}"
}
```

`tags_to_push` steuert, welche Folge-Release-Jobs die Control Plane anlegt.
Ist ein Subsystem unverändert, erscheint es nicht in `tags_to_push`.

---

## 10. Release-Pipeline: Vom Git-Push zum veröffentlichten Artefakt

Die Release-Pipeline verbindet das SemVer-Oracle (Kapitel 9) mit den
tatsächlichen Build- und Publish-Schritten. Die gesamte Orchestrierung
findet im Worker-Daemon (`internal/worker/daemon/release.go`, 620 Zeilen)
statt.

### 10.1 Ablauf

```
Push auf main
  → GitHub Webhook → Control Plane → release_jobs (component="semver")
    → Worker claimen den SemVer-Job (Capabilities-Filter, Kapitel 11)
      → SemVer-Oracle in Firecracker-VM (Kapitel 9)
        → result.json → Worker → Control Plane
          → handleSemverJobCompletion:
              ├─ Git-Tags setzen (tags_to_push)
              ├─ compiler_manifest.json committen (falls geändert)
              └─ Folge-Release-Jobs anlegen (component=cli|core|compiler)
                  → Worker mit passender Capability claimen
                    ├─ CLI:      executeCLIRelease
                    ├─ Core:     executeCoreRelease
                    └─ Compiler: executeCompilerRelease
```

### 10.2 Release-Job-Typen im Detail

#### SemVer-Job (`executeSemverEnforcer`)

1. `git fetch --tags origin` (auf dem Host, unter `gitMu`-Lock)
2. Letzte Tags für Core/CLI/Compiler ermitteln (`git tag -l`)
3. `gitHasChanges` prüft per `git diff --name-only`, ob relevante Pfade
   geändert wurden (definiert in `subsystem.Registry[...].ChangePaths`)
4. Git-Archive von Baseline- und Current-Stand extrahieren → Workspace
5. `gitMu` freigeben → VM starten (keine Git-Operationen in der VM)
6. Ergebnis aus `result.json` lesen → `ReleaseComplete` an Control Plane

#### CLI-Release (`executeCLIRelease`)

1. Monorepo auf den Release-Tag auschecken
2. Cross-Compile für 3 Plattformen:
   - `windows/amd64` (`.exe`, als `.zip`)
   - `linux/amd64` (als `.tar.gz`)
   - `darwin/arm64` (als `.tar.gz`)
3. Alle mit `CGO_ENABLED=0`, `-ldflags="-s -w"`, `-trimpath`
4. Upload-URLs von der Control Plane anfordern (presigned S3 PUTs)
5. Artefakte direkt nach S3 hochladen (externer Client, kein mTLS)
6. `ReleaseComplete` mit `artifacts`-Map (Object-Keys + Größen)

#### Core-Release (`executeCoreRelease`)

1. Monorepo auf den Release-Tag auschecken
2. Core-SDK nativ bauen → Kompilierbarkeit verifizieren
3. Öffentliche Quellen als `core-source.tar.gz` packen
4. Upload via presigned URL → S3
5. `ReleaseComplete` mit Artefakt-Map

#### Compiler-Release (`executeCompilerRelease`)

1. Monorepo auf den Release-Tag auschecken
2. `build-compiler.sh --push` ausführen (Kapitel 3)
3. Credentials kommen **nicht** aus dem Worker-Config, sondern werden pro
   Job von der Control Plane im `Env`-Feld der Claim-Response geliefert:
   `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `S3_ENDPOINT`, `S3_BUCKET`,
   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
4. `ReleaseComplete` → Control Plane registriert Version in
   `ecosystem_releases` + Docker-Hub-URL

### 10.3 Credential-Injection: Nur bei Bedarf

Die Control Plane injiziert Secrets **ausschließlich** in Compiler-Release-Jobs.
Alle anderen Job-Typen bekommen **keine** Credentials im `Env`-Feld:

| Job-Typ | `resp.Env` enthält |
|---|---|
| SemVer | `nil` (keine Secrets nötig, läuft in air-gapped VM) |
| CLI | `nil` (Upload über presigned URLs, keine direkten S3-Creds) |
| Core | `nil` (Upload über presigned URLs) |
| Compiler | DockerHub + S3 Credentials (für `docker push` + `aws s3 cp`) |

### 10.4 Dependency-Ordering: CLI vor Compiler

Die Control Plane erzwingt eine **Build-Reihenfolge**: Bevor ein Compiler-Job
an einen Worker ausgeliefert wird, prüft der Handler
(`worker_release.go:43–64`), ob die im `compiler_manifest.json` referenzierte
CLI-Version bereits als Release publiziert ist
(`h.ecosystem.IsPublished(ctx, ComponentCLI, version)`). Falls nicht, wird
der Job **re-queued** (`status = QUEUED`) und der Worker bekommt
`204 No Content`. Beim nächsten Poll-Zyklus wird erneut geprüft.

Das verhindert, dass ein Compiler-Image mit einer CLI-Version gebaut und
veröffentlicht wird, die selbst noch nicht publiziert wurde.

### 10.5 Git-Mutex (`gitMu`)

Alle Release-Jobs, die Git-Operationen auf dem lokalen Monorepo-Checkout
durchführen, laufen unter einem `sync.Mutex` (`d.gitMu`). Das verhindert
Race-Conditions zwischen parallelen `git checkout`/`git reset --hard`-Aufrufen.
Der SemVer-Job gibt den Lock frei, *bevor* die VM startet — damit bleibt
der Monorepo-Checkout für andere Jobs verfügbar, während die VM rechnet.

---

## 11. Worker-Capabilities: Job-Routing & Berechtigung

Nicht jeder Worker kann jeden Job ausführen. Das System unterscheidet drei
Job-Klassen (Validation, Publish, Release) und vier Release-Komponenten
(SemVer, CLI, Core, Compiler). Die Zuordnung erfolgt über ein
**Capabilities-System**.

### 11.1 Konfiguration (`internal/worker/config/config.go`)

```go
type WorkerConfig struct {
    MonorepoPath string   // Lokaler Git-Checkout (optional)
    Capabilities []string // z. B. ["semver", "compiler", "cli", "core"]
    // ...
}
```

Drei Quellen, in Prioritätsreihenfolge:

| Priorität | Quelle | Beispiel |
|---|---|---|
| 1 | `TOOB_WORKER_CAPABILITIES` Env | `"semver,core,cli,compiler"` |
| 2 | Auto-Detection | Wenn `MonorepoPath` gesetzt: `["semver", "core", "cli"]` + `"compiler"` falls `docker` im PATH |
| 3 | Leer | Kein Release-Polling (nur Validation + Publish) |

### 11.2 Worker-Typen in der Praxis

| Worker-Typ | Provisionierung | MonorepoPath | Docker | Capabilities | Kann ausführen |
|---|---|---|---|---|---|
| **Standard-Worker** | Autoscaler (cloud-init) | ❌ | ❌ | `[]` (leer) | Validation-Jobs + Publish-Jobs (Firecracker-VM) |
| **Release-Worker** | Manuell / Terraform | ✅ gesetzt | ❌ | `["semver", "core", "cli"]` | + SemVer-Oracle, CLI-Cross-Compile, Core-Release |
| **Full-Release-Worker** | Manuell / Terraform | ✅ gesetzt | ✅ | `["semver", "core", "cli", "compiler"]` | + Compiler-Release (`build-compiler.sh --push`) |

Der Autoscaler erstellt **ausschließlich Standard-Worker** — Release-Worker
werden bewusst manuell provisioniert, da sie Zugriff auf den Monorepo-
Checkout benötigen und im Compiler-Fall mit Docker-Hub- und S3-Credentials
umgehen.

### 11.3 Server-seitiges Filtering (SQL)

Der Worker sendet seine Capabilities bei jedem Release-Poll:

```
POST /api/v1/worker/release-claim
{ "worker_id": "worker-fsn1-42", "capabilities": ["semver", "core", "cli"] }
```

Der Server (`internal/server/postgres/release_jobs.go`) filtert per SQL:

```sql
SELECT ... FROM release_jobs
 WHERE status = 'QUEUED'
   AND component = ANY($1)      -- $1 = ["semver", "core", "cli"]
 ORDER BY id ASC
 LIMIT 1
 FOR UPDATE SKIP LOCKED
```

`ANY($1)` matched nur Jobs, deren `component`-Feld in der Capabilities-Liste
des Workers enthalten ist. `FOR UPDATE SKIP LOCKED` stellt sicher, dass bei
mehreren parallelen Workers kein Job doppelt vergeben wird.

Ein Worker ohne `"compiler"` in seiner Liste sieht **niemals** einen
Compiler-Job — unabhängig davon, wie viele in der Queue warten.

### 11.4 Leere Capabilities: Kein Release-Polling

Wenn `Capabilities` leer ist (Standardfall für Autoscaler-Worker), gibt
`ClaimNextWithToken` sofort `nil` zurück — der Worker pollt nicht einmal
die Datenbank. Das Release-Polling ist damit für Standard-Worker
vollständig deaktiviert.

### 11.5 Sicherheitsimplikationen

- **Kein Capability-Spoofing möglich:** Die Capabilities bestimmen nur,
  welche Jobs ein Worker *sieht*. Die tatsächliche Ausführung erfordert die
  passende Infrastruktur (Monorepo-Checkout, Docker, Credentials). Ein Worker,
  der fälschlicherweise `"compiler"` claimed, aber kein Docker hat, würde beim
  `build-compiler.sh`-Aufruf hart scheitern.
- **Credential-Isolation:** Nur Compiler-Jobs bekommen S3/DockerHub-Credentials
  von der Control Plane (Kapitel 10.3). Ein Worker, der einen SemVer-Job claimed,
  hat keinen Zugriff auf diese Secrets.
- **Release-Worker = höheres Vertrauen:** Release-Worker haben Zugriff auf
  den Monorepo-Checkout und (im Compiler-Fall) auf temporäre Credentials.
  Deshalb werden sie nicht automatisch skaliert, sondern manuell provisioniert.

---

## 12. CLI Build-Prozess (`toob build`)

Der `toob build`-Befehl (`cli/toob-cli/cmd/build.go`, 1134 Zeilen) ist der
Einstiegspunkt für Entwickler und CI. Er hat zwei Pfade: Docker-Build und
Native-Build.

### 12.1 Docker-Build (externe Entwickler)

Der einfachste Weg: Die CLI zieht das `toob-compiler`-Image und führt
`toob build --native` *innerhalb* des Containers aus.

```
toob build
  → docker pull toob-compiler:{lockfile-version}
  → Protocol-Handshake: docker inspect → toob.protocol_version Label
      prüfen gegen ProtocolVersion aus ports.go
  → docker run
      -v workspace:/workspace
      -v registry:/root/.toob/registry
      -v ccache/{version}:/ccache
      toob-compiler:{tag} toob build --native
```

Besonderheiten:

- **Compiler-Tag aus Lockfile:** `toob.lock → environment.compiler`. Muss
  explizit gesetzt sein — es gibt keinen `:latest`-Fallback.
- **Versionssegmentierter ccache:** Jede Compiler-Version hat ihren eigenen
  ccache-Mount unter `~/.toob/ccache/{tag}/`. Das verhindert Cache-Poisoning
  zwischen Compiler-Versionen.
- **Protocol-Handshake:** Vor dem Start wird per `docker inspect` das Label
  `toob.protocol_version` geprüft. Bei Mismatch: CLI zu alt → „Run `toob
  update`"; Image zu alt → „Run `docker pull`". Bei fehlendem Label (altes
  Image): Warnung, aber kein Abbruch.

### 12.2 Native-Build (11 Phasen)

Der Native-Build ist die eigentliche Build-Engine — er wird sowohl lokal
(mit `--native`) als auch innerhalb des Docker-Containers ausgeführt.

#### Phase 1: Lockfile-Enforcement

- Registry-Version aus `toob.lock` pinnen (`cache.SwitchVersion`)
- CLI-Kompatibilität gegen `registry.json:cli_compatibility` prüfen
  (SemVer-Constraint)

#### Phase 2: Manifest-Parsing & Chip-Resolution

- `device.toml` lesen → `chip`, `arch`, `compiler_prefix` extrahieren
- Chip-Manifest-Kaskade: Lokales Projekt → Registry-Cache
- Validierung: `arch` und `compiler_prefix` müssen gesetzt sein

#### Phase 3: Core-SDK-Version-Resolution

```
device.toml [build.core_sdk]
  │
  ├─ "" oder "latest" → git ls-remote → höchster core/vX.Y.Z Tag
  │     Fallback → chip_manifest.min_core_sdk
  │     Fallback → "main"
  ├─ explizite Version → Validierung gegen min_core_sdk
  └─ nicht lokal → git clone --depth 1 -b core/vX.Y.Z
```

#### Phase 4: Manifest-Compiler (Go-nativ)

`manifestpkg.Compile()` generiert CMake-Konfiguration aus `device.toml` +
`hardware.json`. Löst HAL-Chip-Pfade, Driver-Pfade und SoC-Pfade auf.

#### Phase 5: SUIT-CodeGen

Python-basierte Firmware-Update-Manifest-Generierung (`suit.Generate`).

#### Phase 6: Kompatibilitätsmatrix-Check (parallel)

Die Matrix wird **im Hintergrund** gefetcht (Goroutine ab Phase 2), damit
kein blockierender Netzwerk-Call im kritischen Pfad liegt. Ergebnis:

| Matrix-Ergebnis | Verhalten |
|---|---|
| `VERIFIED` | Weiter (kein Output) |
| `FAILED` | **Harter Abbruch** — Build wird nicht gestartet |
| Nicht in Matrix | Warnung — Build läuft weiter |
| Matrix unerreichbar | Warnung — Build läuft weiter |
| `--skip-checks` | Matrix wird gar nicht abgefragt |

#### Phase 7: Dynamische Crypto-Resolution

Drei-Slot-System (backend, hash, pqc) mit Kaskade:

```
device.toml [crypto] überschreibt → chip_manifest.json [crypto]
  → Registry-Index-Lookup → Validierung:
      ├─ chip_binding: Crypto-Paket nur für deklarierte Chips
      ├─ min_core_sdk: SemVer-Check
      └─ Deduplizierung: gleiches Paket in zwei Slots → nur einmal kompiliert
  → CMake-Variablen generieren (TOOB_CRYPTO_{BACKEND|HASH|PQC}_*)
```

#### Phase 8: Toolchain-Resolution

**Strikt hermetisch** — `findToolchainBin` sucht ausschließlich in
`~/.toob/toolchains/`, **nie** im System-PATH. Damit ist garantiert, dass
nicht versehentlich eine lokale GCC-Installation den Build kontaminiert.

Fallback-Kette:
1. Lockfile-Pin (`toob.lock → toolchains[name].version`)
2. Registry-Index (`idx.Toolchains[name].Version`)
3. `toolchain.GetExpectedVersion` (aus Registry-Dateien)
4. `toolchain.EnsureAvailable` — Auto-Download + SHA-256-Verify

Bei `--toolchain-path`: Explizite Pfadangabe + Version-Mismatch = **FATAL**.

#### Phase 9: CMake Configure

```bash
cmake -G Ninja -B {buildDir} -S {compilerRoot}
  -DCMAKE_TOOLCHAIN_FILE={registry-toolchain.cmake}
  -DTOOB_CHIP={chip} -DTOOB_ARCH={arch}
  -DTOOB_DEVICE_MANIFEST={device.toml}
  # + alle generierten Variablen aus Phase 4-8
```

#### Phase 10: Ninja-Build

`cmake --build {buildDir}` — Output wird in einen `ringBuffer` (1 MB,
bounded, allocation-free) geschrieben und gleichzeitig an einen
`LiveSpinner` weitergeleitet. Bei Fehler: `classifyBuildError` analysiert
den Output heuristisch und gibt eine kategorisierte Fehlermeldung
(HAL, Core-SDK, Crypto, App-Code, Toolchain, Unknown).

#### Phase 11: Lockfile-Update

Die tatsächlich verwendete Toolchain-Version wird zurück ins `toob.lock`
geschrieben. Damit ist der nächste Build reproduzierbar.

### 12.3 Build-Timing

Jede Phase wird mit einem `TimingTracker` gemessen. Am Ende gibt
`timings.Print()` eine formatierte Zusammenfassung aus — nützlich für die
Optimierung von CI-Pipelines und die Diagnose langsamer Builds.

### 12.4 Die CLI in drei Laufzeitumgebungen

Die CLI (`toob`) ist **identischer Code** — selbe Binary, selbe 11-Phasen-
Pipeline — an drei Orten. Der Unterschied liegt in der Umgebung:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Umgebung 1: Lokal auf dem Entwickler-Rechner                       │
│                                                                      │
│  toob build                    → startet Docker oder:                │
│  toob build --native           → nutzt lokale Toolchains             │
│                                                                      │
│  Core-SDK:     git clone nach ~/.toob/core/{version}/                │
│  Toolchains:   ~/.toob/toolchains/{name}/{version}/                  │
│  Registry:     ~/.toob/registry/ (git clone oder sync)               │
│  Netzwerk:     ✅ Verfügbar (für git clone, Matrix-Check, Sync)      │
│  Lockfile:     ✅ Wird gelesen und geschrieben                       │
│  Matrix-Check: ✅ Aktiv (Phase 6)                                    │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  Umgebung 2: Im Docker-Container (toob-compiler:vX.Y.Z)            │
│                                                                      │
│  docker run ... toob build --native                                  │
│                                                                      │
│  Core-SDK:     TOOB_COMPILER_DIR=/opt/toob-core-sdk (pre-seeded)     │
│  Toolchains:   /root/.toob/toolchains/ (pre-installed im Image)      │
│  Registry:     -v gemountet vom Host → /root/.toob/registry          │
│  Netzwerk:     ✅ Verfügbar (für Matrix-Check)                       │
│  Lockfile:     ✅ Wird gelesen und geschrieben (Host-Mount)          │
│  Matrix-Check: ✅ Aktiv (Phase 6)                                    │
│                                                                      │
│  → Kein git clone nötig, alles vorinstalliert                        │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  Umgebung 3: In der Firecracker-VM (rootfs.ext4)                    │
│                                                                      │
│  Nur vom SemVer-Oracle genutzt (ABI-Analyse, Kapitel 9.2):          │
│    toob build --native --manifest {subsystem-manifest}               │
│                                                                      │
│  Zukünftig für Full-Build Gate (Kapitel 8.4, Stufe 2, TODO):        │
│    toob build --native --skip-checks --manifest /workspace/device.toml│
│                                                                      │
│  Core-SDK:     TOOB_COMPILER_DIR=/opt/toob-core-sdk (pre-baked)      │
│  Toolchains:   /root/.toob/toolchains/ (pre-baked im rootfs)         │
│  Registry:     /root/.toob/registry/ (pre-seeded aus Snapshot)       │
│  Netzwerk:     ❌ Air-gapped (kein Netzwerk in der VM)               │
│  Lockfile:     ❌ Nicht relevant (Referenz-Build, kein User-Projekt) │
│  Matrix-Check: ❌ Deaktiviert (--skip-checks, kein Netzwerk)         │
│                                                                      │
│  → Alles pre-baked, kein git clone, kein Download, kein Netzwerk     │
└──────────────────────────────────────────────────────────────────────┘
```

**Schlüsselmechanismus:** Die CLI erkennt die Umgebung automatisch über
`TOOB_COMPILER_DIR`. Ist diese Variable gesetzt (Docker und VM), überspringt
Phase 5 den `git clone` und nutzt das vorinstallierte Core-SDK direkt
(`build.go:519–521`). Da Toolchains und Registry ebenfalls vorinstalliert
sind, braucht die CLI in der VM **kein Netzwerk**.

**Was die CLI in der VM generiert (identisch zu lokal):**

1. `manifestpkg.Compile()` → CMake-Konfiguration aus `device.toml` +
   `hardware.json` → `builds/generated/`
2. `suit.Generate()` → SUIT-Update-Manifest → `builds/generated/`
3. Crypto-Resolution → `toob_config.cmake` mit allen aufgelösten
   Crypto-Slots, HAL-Pfaden, Driver-Pfaden, Include-Paths
4. Toolchain-Resolution → PATH wird auf die vorinstallierten Toolchains gesetzt
5. CMake Configure + Ninja Build → vollständige Firmware-Kompilierung

### 12.5 Warum der Compiler maßgeblich durch die CLI bestimmt wird

Der Compiler (Docker-Image + rootfs) ist im Kern ein **Delivery Vehicle
für die CLI**. Die CLI *ist* die Build-Engine — sie macht die gesamte
Vorarbeit (Manifest-Kompilierung, Crypto-Resolution, Driver-Discovery,
Toolchain-Lookup), bevor cmake/ninja aufgerufen werden. Das Docker-Image
und die rootfs stellen lediglich sicher, dass die richtige CLI-Version
in einer determinierten Umgebung mit den richtigen Toolchains läuft.

#### Was der Compiler enthält und woher es kommt

| Inhalt | Quelle | Wer bestimmt die Version? |
|---|---|---|
| **CLI Binary** (`/usr/local/bin/toob`) | Cross-compiled in `build-compiler.sh` | `compiler_manifest.json → cli.version` |
| **Core-SDK** (`/opt/toob-core-sdk/`) | Git-Checkout bei Build-Time | `compiler_manifest.json → core_sdk.version` |
| **Toolchains** (`/root/.toob/toolchains/`) | `install_toolchains.py` + Registry-Snapshot | Registry `toolchain_manifest.json` |
| **Registry-Snapshot** (`/root/.toob/registry/`) | Git-Archive bei Build-Time | `compiler_manifest.json → registry.source.ref` |
| **System-Pakete** (cmake, python3, etc.) | `apt-get` im Dockerfile | `compiler_manifest.json → system_packages[]` |
| **Python-Pakete** | `pip3 install` im Dockerfile | `compiler_manifest.json → python_packages[]` |
| **Base-Image** | Docker Hub | `compiler_manifest.json → base_image.image` |

Jede Zeile in dieser Tabelle ist eine der 7 Dimensionen, die das
SemVer-Oracle (Kapitel 9.4) prüft, um zu entscheiden, ob ein neuer
Compiler-Release nötig ist.

#### Compiler-Release-Kopplung an die CLI

Der häufigste Auslöser für einen Compiler-Release ist eine CLI-Änderung,
weil die CLI die Build-Logik implementiert. Aber nicht jede CLI-Änderung
rechtfertigt einen Compiler-Rebuild:

```
Push auf main → SemVer-Oracle:

  1. analyzeCLI() → Ergebnis: cliBump
         │
  2. analyzeCompiler(cliBump, coreBump):
         │
         ├── compiler_manifest.json:
         │   cli.version: "0.6.0" → "0.7.0"  (Dim 2 geändert)
         │
         ├── Alle anderen Dims unverändert?
         │     │
         │     ├── JA + cliBump != MAJOR + kein CLI-Code geändert:
         │     │   → onlyCLIChanged = true
         │     │   → Compiler-Bump = NONE (aufgeschoben)
         │     │   → Kein Compiler-Release
         │     │   → "decoupled, compiler build deferred"
         │     │
         │     └── NEIN oder cliBump == MAJOR:
         │         → Compiler-Bump = promoteBump(bump, cliDiff)
         │         → Compiler-Release wird ausgelöst
         │
         ├── protocol_version geändert?
         │   → Compiler MAJOR Release (Wire-Format-Bruch)
         │
         └── base_image/system_packages/python_packages/registry.ref geändert?
             → Compiler MINOR Release
```

**Die Entkopplungslogik** (`semver.go:824–828`) ist der Schlüssel:

```go
if onlyCLIChanged && cliDiff != BumpMajor && cliBump == BumpNone {
    bump = BumpNone  // Compiler-Release aufgeschoben
}
```

Ein CLI-PATCH (z.B. Bugfix in der Fehlerausgabe) löst **keinen** Compiler-
Release aus, weil er die Build-Ergebnisse nicht beeinflusst. Erst wenn:

- Die CLI strukturelle Änderungen hat (neues Build-Phase, geänderte
  CMake-Variablen) → `cliBump >= MINOR` → Compiler-Release
- Das Protocol-Format sich ändert → `ProtocolVersion++` → Compiler-MAJOR
- Andere Manifest-Dimensionen sich ändern (Base-Image, Toolchains, etc.)

#### Compiler-Release-Flow (End-to-End)

```
1. Push auf main mit CLI-Änderung + compiler_manifest.json Update
2. SemVer-Oracle bestimmt: cliBump=MINOR, compilerBump=MINOR
3. tags_to_push: ["cli/v0.7.0", "compiler/v1.2.0"]
4. Control Plane: handleSemverJobCompletion()
     ├── Git-Tags setzen
     ├── compiler_manifest.json committen (neue compiler_version)
     ├── Release-Job: component=cli    → Worker baut CLI-Binaries
     └── Release-Job: component=compiler → Worker wartet bis CLI published
5. Dependency-Gate (Kapitel 10.4):
     → IsPublished("cli", "0.7.0") == false → 204, re-queue
     → ...CLI-Release fertig...
     → IsPublished("cli", "0.7.0") == true  → Compiler-Job ausgeliefert
6. Worker: executeCompilerRelease()
     → build-compiler.sh --push
       → cli.version=0.7.0 per sed ins Dockerfile injiziert
       → Docker-Image + rootfs.ext4 gebaut
       → Docker Hub Push + S3 Upload
7. Neuer Eintrag in ecosystem_releases
```

Der Compiler wird also **nicht manuell released** — das SemVer-Oracle
entscheidet automatisch, und der Dependency-Gate stellt sicher, dass die
CLI-Version, die im Compiler-Image eingebettet ist, auch wirklich
publiziert und downloadbar ist, bevor das Image veröffentlicht wird.

---

## 13. Sicherheitsmodell der Compiler-Kette

### 10.1 Supply-Chain-Integrität

Die Kette vom Quellcode bis zur laufenden VM hat sieben Vertrauensanker:

| # | Vertrauensanker | Wo geprüft |
|---|---|---|
| 1 | **Manifest-Determinismus** | `build-compiler.sh`: `"latest"` → FATAL |
| 2 | **Toolchain-Checksummen** | `install_toolchains.py`: SHA-256 gegen Registry-Manifest |
| 3 | **Docker-Image-Signatur** | `deploy.sh`: Cosign + Vault Transit (Ed25519) |
| 4 | **Docker-Image-Pinning** | Nomad-Job: Digest-gepinnt, keine mutable Tags |
| 5 | **Rootfs-SHA-256** | Worker: Streaming-Verify gegen Control-Plane-Checksumme |
| 6 | **VM-Runner-Integrity** | Rootfs enthält den vm-runner als `/sbin/init`; unveränderlich (RO-Mount) |
| 7 | **Compile-Ergebnis-Verify** | Control Plane: Re-Berechnung SHA-256 + Re-Scan nach S3-Upload |

### 10.2 Isolationsschichten

```
Internet (Cloudflare WAF, TLS 1.3, Rate-Limit)
  └─ Hetzner-Firewall (443 nur von CF-IPs)
       └─ Caddy (Origin-CA, Security-Header)
            └─ API-Server (Bearer-Auth / mTLS, Policy-Engine)
                 └─ Nomad (ACL, mTLS)
                      └─ Worker (toob-worker User, kein root)
                           └─ Jailer (chroot, AppArmor, per-Job-UID/GID)
                                └─ Firecracker/KVM (Hardware-Isolation)
                                     └─ microVM (eigener Kernel, KEIN Netzwerk)
                                          └─ vmrunner (PID 1, read-only rootfs)
```

### 10.3 CompilerPrefix-Injection-Schutz

Innerhalb der VM wird der Compiler-Name aus dem Chip-Manifest abgeleitet
(`CompilerPrefix + "gcc"`). Ein bösartiges Manifest könnte versuchen, über
einen Prefix wie `../../bin/evil` einen beliebigen Befehl als Compiler
auszuführen. Der `vmrunner` validiert daher den Prefix gegen `^[a-zA-Z0-9_-]*$`
und lehnt jede Zeichenfolge mit Pfadtrennern oder Punkten ab.

### 10.4 Toolchain-URL-Allowlist

Download-URLs für Toolchains müssen `https` sein und aus einer Allowlist
erlaubter *Host + Pfad-Prefix*-Kombinationen stammen:

```
github.com/Toob-Boot/
github.com/espressif/
developer.arm.com/
gcc.gnu.org/
releases.linaro.org/
ftp.gnu.org/
```

Die Allowlist enthält bewusst den Pfad-Prefix, nicht nur den Host. Damit lässt
sich `github.com/Toob-Boot/` freigeben, ohne automatisch
`github.com/evil-fork/` mitzuerlauben.

---

## 14. Glossar

| Begriff | Bedeutung |
|---|---|
| **Compiler-Manifest** | `compiler_manifest.json` — Single Source of Truth für alle Eingaben des Compiler-Builds. Versioniert vom SemVer-Oracle. |
| **rootfs.ext4** | Ext4-Dateisystem-Image, das als Read-Only-Root der Firecracker-microVM dient. Enthält vmrunner, BusyBox, Toolchains, CLI, Core-SDK und Registry-Snapshot. |
| **vmrunner** | Go-Binary, das als PID 1 in der microVM läuft. Validiert, kompiliert und schreibt Ergebnisse auf Block-Devices. |
| **Presigned URL** | Zeitlich begrenzte S3-URL (15 min), die der Control Plane einen einmaligen Download-Zugriff ohne S3-Credentials ermöglicht. |
| **Golden Image** | Packer-gebauter Hetzner-Snapshot mit allen Worker-Binaries, Kernel und einer Seed-rootfs vorinstalliert. |
| **Toolchain** | Cross-Compiler-Binärdistribution (z. B. `riscv32-esp-elf-gcc`), installiert nach `/root/.toob/toolchains/{name}/{version}/`. |
| **Protocol-Version** | Integer-Versionierung des Wire-Formats zwischen CLI und Compiler. Ein MAJOR-Bump in der Protocol-Version erzwingt einen Compiler-MAJOR-Release. |
| **Compatibility Matrix** | Datenbank-Tabelle `matrix_entries`, die den Teststatus jeder Kombination aus Chip × CLI × Core × Compiler trackt. |
| **Sparse-Kopie** | `copySparse` im Worker: blockweises Kopieren einer rootfs mit Überspringen von Null-Blöcken via `Seek`. Jede VM bekommt eine eigene beschreibbare Kopie. |
| **CI-Build-Wrapper** | `toob-ci-build.sh` — Entrypoint-Skript im Compiler-Image, das den Build-Modus (`pr`, `matrix`, `production`) steuert und die richtige Umgebung aufbaut. |
| **SemVer-Oracle** | Automatischer Versionssprung-Ermittler, der den Compiler über 7 Manifest-Dimensionen analysiert und den korrekten Bump (PATCH/MINOR/MAJOR/None) bestimmt. |

