Ein paar Grundideen:

-fdata-sections, -ffunction-sections, --gc-sections

- Statische Code-Analyse (SAST): C-Code muss zwingend mit Tools wie Cppcheck, Clang-Tidy oder kommerziellen Werkzeugen auf Buffer Overflows und Memory Leaks gescannt werden.
- Kryptografische Signaturprüfung (Secure Boot): Die Analogie zu signierten Base-Images. Der Bootloader muss die Signatur des zu ladenden Kernels mittels Hardware-Kryptographie (z. B. RSA/ECC im Secure Element) verifizieren, bevor er die Kontrolle übergibt.
- Stack Smashing Protection: Aktivieren von Compiler-Canaries (-fstack-protector-strong), um Pufferüberläufe auf dem Stack zu erkennen.W^X (Write Xor Execute): Speicherbereiche dürfen entweder beschreibbar oder ausführbar sein, niemals beides gleichzeitig. Der RAM-Bereich für Daten darf keine Befehle ausführen (Datenausführungsverhinderung / NX-Bit).
- Coolify oder Dokku

Das ist ein hochgradig ambitioniertes Infrastruktur-Projekt. Du baust im Kern eine Kombination aus npm/crates.io (Package Manager), GitHub Actions (Build-Pipeline) und Expo EAS (OTA Update Cloud). Da du Kunden-Code ausführst (Builds) und produktive Geräte aktualisierst (OTA), sind Sicherheit (Mandanten-Isolierung) und Ausfallsicherheit deine absoluten Kernprobleme.
Hier ist die strategische DevOps-Architektur und der Tech-Stack, um dieses System sicher, performant und Multi-Cloud-fähig aufzubauen.

---

## 1. Das Kernprinzip: Die 3 Säulen funktional trennen

Da die drei Komponenten völlig unterschiedliche Lastprofile und Risiken haben, musst du sie architektonisch strikt trennen:

[ API / Control Plane ] (Zentral gesteuert, z. B. auf Hetzner oder Railway)
│
├──> [ 1. Package Manager ] ──> Objekt-Speicher (S3 / Hetzner Object Storage)
├──> [ 2. OTA Cloud ] ──> Globales CDN (Cloudflare / Fastly)
└──> [ 3. Build-Pipeline ] ──> Ephemere Worker-VMs (Hetzner Cloud / AWS EC2)

1.  Package Manager & OTA Cloud: Extrem Lese-intensiv, muss global nah am Kunden/Gerät sein (Traffic-Kosten minimieren).
2.  Build-Pipeline: Extrem CPU/RAM-intensiv, potenziell unsicher (Kunden-Code), muss isoliert skalieren.

---

## 2. Der empfohlene Tech-Stack## Control Plane & API (Das Gehirn)

- Sprache: Go (Golang) oder Rust. Beide bieten exzellente Performance, niedrigen RAM-Verbrauch, statische Binaries und erstklassige Concurrency für Netzwerkprotokolle.
- Datenbank: PostgreSQL als primäre Datenquelle (Metadaten, Benutzerverwaltung). Für hohe Verfügbarkeit im Cluster (z. B. mit Patroni).
- Caching/Queues: Valkey (Open-Source-Nachfolger von Redis) oder NATS.io (perfekt für Cloud-Native Messaging und Orchestrierung der Build-Worker).

## 1. Package Manager & 2. OTA Update Cloud

- Speicher: S3-kompatibler Object Storage. Bei Hetzner nutzt du deren Object Storage, für AWS-Kunden AWS S3.
- Edge / Ausfallsicherheit: Schalte zwingend ein CDN wie Cloudflare davor. OTA-Updates und Packages ändern sich nach dem Upload nie wieder (Immutable). Wenn dein Hetzner-Server für 10 Minuten ausfällt, liefert Cloudflare die Updates weiterhin weltweit aus dem Cache aus. Deine Uptime ist damit nahezu 100%.

## 3. Build-Pipeline (Die Execution Engine)

- Isolierung: Firecracker MicroVMs (von AWS entwickelt) oder gVisor.
- Warnung: Nutze niemals Standard-Docker-Container für Public Builds. Böswilliger Kunden-Code kann via Kernel-Exploits aus Docker ausbrechen. Firecracker startet echte, minimalistische Linux-Kernel in Millisekunden und isoliert sie hardwareseitig.
- Orchestrierung: Nomad (by HashiCorp). Nomad ist deutlich leichtgewichtiger als Kubernetes und eignet sich perfekt, um ephemere (kurzlebige) Build-Jobs auf verschiedenen Servern zu starten.

---

## 3. DevOps-Handhabung: Multi-Cloud & Deployment

Um Hetzner als Standard zu nutzen, aber AWS/Google Cloud und Railway flexibel zu integrieren, musst du deine Infrastruktur strikt abstrahieren.

## Infrastruktur als Code (IaC)

- Setze konsequent auf Terraform oder OpenTofu.
- Schreibe modulare Manifeste: Ein Modul für provider "hcloud" (Hetzner) und eines für provider "aws".
- Wenn ein Enterprise-Kunde eine dedizierte Instanz auf AWS wünscht, änderst du nur die Umgebungsvariablen, und Terraform rollt dieselbe Architektur auf AWS EC2 und AWS RDS aus.

## Wo passt Railway in dieses Setup?

Railway glänzt als Control Plane für dein Entwickler-Team.

- Du kannst deine zentrale Management-API, das Dashboard für deine Kunden und die Webhooks auf Railway laufen lassen. Das gibt deinem Team maximalen "Deployment-Speed" (Git Push $\rightarrow$ Live).
- Aber: Die eigentlichen Build-Worker (die CPUs, die den Kunden-Code kompilieren) und der OTA-Traffic dürfen nicht auf Railway laufen. Die Ressourcen- und Traffic-Kosten würden dich sofort ruinieren. Railway steuert also via API/NATS nur die Worker auf Hetzner oder AWS an.

---

## 4. Das Sicherheits- und Zuverlässigkeits-Konzept## Sicherheit (Security-first)

1.  Unveränderlichkeit (Immutability): Ein einmal hochgeladenes Package oder OTA-Update darf niemals überschrieben werden. Nur neue Versionsnummern sind erlaubt. Das verhindert Supply-Chain-Angriffe.
2.  Kryptografische Signierung: Jedes OTA-Update muss auf deinen Servern (oder vom Kunden lokal) mit einem privaten Schlüssel signiert werden. Das Endgerät muss vor dem Entpacken den Hash gegen den Public Key prüfen. Selbst wenn dein Server gehackt wird, können keine manipulierten Updates auf die Geräte geschleust werden.
3.  Network Sandboxing: Build-Worker dürfen keinen Zugriff auf dein internes Netzwerk haben. Sie müssen in einer isolierten VPC / einem isolierten VLAN leben und dürfen nur das öffentliche Internet erreichen, um Abhängigkeiten zu laden.

## Zuverlässigkeit (Uptime)

- Anycast & CDN: Nutze Cloudflare Enterprise oder Fastly für die OTA-Auslieferung.
- Multi-Region bei Hetzner: Verteile deine API-Knoten auf die Hetzner-Rechenzentren Falkenstein (DE), Helsinki (FI) und Ashburn (US). Fällt ein Rechenzentrum aus, routet der Load Balancer den Traffic um.

---

## Zusammenfassender DevOps-Fahrplan

1.  Phase 1 (Architektur): Definiere die API-Schnittstellen mit gRPC oder REST. Verwende Go oder Rust.
2.  Phase 2 (Storage & CDN): Setze den Package-Speicher auf S3-Basis auf und kapsele ihn komplett hinter Cloudflare. Damit ist die OTA-Auslieferung ab Tag 1 unzerstörbar.
3.  Phase 3 (Die Pipeline-Sicherheit): Investiere Zeit in Firecracker oder Nomad. Das ist das komplexeste Puzzleteil. Jede Build-Anfrage startet eine frische MicroVM, baut das Artefakt, lädt es in den S3-Storage und zerstört sich selbst.

Möchtest du tiefer in die Funktionsweise von Firecracker für die Build-Pipeline eintauchen, oder interessiert dich primär das Datenbank-Design für die OTA-Mandantenfähigkeit (Multi-Tenancy)?

Das Szenario, das du beschreibst (kontaminierte Caches, die nachfolgende Pipeline-Läufe infizieren und Tokens stehlen), greift eines der größten aktuellen Probleme in der CI/CD-Security auf – ähnlich den realen Angriffen auf Codecov oder xz-utils. Wenn dein Package-Manager aktuell noch rein auf einem GitHub-Repository basiert, ist dieses Risiko extrem hoch, da GitHub Actions standardmäßig sehr langlebige Caches (actions/cache) nutzt.
Um Supply-Chain-Angriffe bei einer Package-Manager-Infrastruktur und angeschlossenen Test-Runnern für Pull Requests (PRs) systematisch zu verhindern, musst du das Prinzip der „Zero-Trust Ephemeral Pipelines“ (flüchtige Pipelines ohne blindes Vertrauen) etablieren.
Hier ist das DevOps-Sicherheitskonzept, wie du deine Runner und die Infrastruktur absicherst:

---

## 1. Das Cache-Poisoning-Problem lösen (Kein geteilter Schreibzugriff)

Das Hauptproblem bei PR-Test-Runnern: Ein Angreifer sendet einen Schadcode-PR. Der Runner führt npm install oder Tests aus. Der schädliche Code nistet sich im globalen Build-Cache (z. B. .cargo/registry, .npm/\_cacache oder Compiler-Caches wie ccache) ein. Der PR wird geschlossen, aber der infizierte Cache wird für den nächsten regulären Build hochgeladen.
Die DevOps-Lösung:

- Isolierte Cache-Scopes per Branch/PR: Ein PR darf niemals den Haupt-Cache (main/release) überschreiben. Bei GitHub Actions ist das standardmäßig so geregelt, dass PRs den Cache der Base-Branch nur lesen, aber nicht dorthin schreiben dürfen.
- Schreibrechte für Caches entziehen: Für PRs von externen Forks (Public Contributors) musst du das Caching für Schreibzugriffe komplett deaktivieren.
- Cache-Verschlüsselung & Hashing: Der Cache-Schlüssel muss strikt an den kryptografischen Hash der Lock-Datei (package-lock.json, Cargo.lock) gebunden sein. Ändert ein PR eine Abhängigkeit, wird zwingend ein komplett neuer, isolierter Cache-Pfad erzeugt.

---

## 2. Ephemere Runner (Wegwerf-Infrastruktur)

Ein Angreifer darf keine Artefakte auf dem Host-System hinterlassen können.

- Keine persistenten Runner: Nutze auf deinen Hetzner-Servern für die PR-Tests niemals langlebige VM-Runner, die mehrere Jobs nacheinander ausführen.
- Einmal-Runner (Ephemeral): Nutze Tools wie den GitHub Actions Runner Controller (ARC) oder eigene Scripts via Hetzner-API. Ein Runner wird für genau einen Job gestartet. Sobald der Job fertig ist (egal ob erfolgreich oder fehlgeschlagen), wird die komplette VM/MicroVM (wiederum idealerweise Firecracker) restlos gelöscht. Ein Hinterlassen von Schadcode für den nächsten Job ist physisch unmöglich.

---

## 3. Expositions-Schutz für Secrets (GitHub Tokens & Credentials)

Dass Angreifer GitHub-Tokens stehlen, liegt meist an einer fehlerhaften Rechtevergabe (Scope) in der CI/CD-Konfiguration.

- pull_request_target verbieten: Nutze für unvertrauenswürdige PRs niemals den GitHub-Trigger pull_request_target. Dieser läuft im Kontext der Haupt-Branch und hat Zugriff auf Write-Tokens und Secrets. Nutze stattdessen strikt pull_request (dieser läuft isoliert und hat standardmäßig nur Read-Rechte).
- Minimale GitHub-Permissions: Konfiguriere das Workflow-File so, dass der GITHUB_TOKEN standardmäßig keinerlei Schreibrechte hat:

permissions:
contents: read
packages: read

- OIDC (OpenID Connect) statt statischer Secrets: Hinterlege keine langlebigen AWS-, Hetzner- oder Railway-API-Keys in den GitHub Secrets. Nutze stattdessen OIDC. Der GitHub-Runner fordert dabei für jeden Job ein kurzlebiges, nur für wenige Minuten gültiges Token direkt beim Cloud-Provider an. Selbst wenn dieses Token gestohlen wird, ist es nutzlos, bevor der Angreifer es missbrauchen kann.

---

## 4. Netzwerk-Ebene absichern (Egress-Filter)

Ein Test-Runner muss im Normalfall Code kompilieren und Tests ausführen. Er muss dafür Abhängigkeiten laden (z.B. von npm oder deinem eigenen Package-Manager). Er muss aber nicht mit unbekannten IPs im Internet kommunizieren, um Daten abzufischen (Exfiltration).

- Strikte Firewall für Runner (Egress-Whitelisting): Blockiere auf Netzwerkebene (z.B. via Hetzner Cloud Firewall oder iptables auf dem Host) jeglichen ausgehenden Datenverkehr der Runner. Erlaube ausschließlich Domains, die zwingend gebraucht werden (z. B. github.com, registry.npmjs.org, deine eigene Domain).
- Versucht der Schadcode, gestohlene Tokens an einen Server des Angreifers zu senden, läuft der Request ins Leere.

---

## 5. Übergang vom GitHub-Repo zur echten Package-Manager-Infrastruktur

Da du aktuell noch auf einem GitHub-Repository aufbaust, solltest du den Übergang zu einer professionellen Infrastruktur wie folgt planen, um Supply-Chain-Angriffe zu verhindern:

1.  Immutable Storage: Die Pakete müssen als komprimierte Tarballs (.tar.gz) auf einem S3-Speicher liegen. Sie dürfen nach dem Upload (Publish) unter dieser Version nie wieder verändert oder überschrieben werden können (S3 Object Locking aktivieren).
2.  Kryptografische Signaturen (Code Signing): Jedes Paket muss beim Veröffentlichen mit dem privaten Schlüssel des Entwicklers oder einer verifizierten Pipeline (z. B. via Sigstore/Cosign) signiert werden. Deine CLI (die das Paket später auf den Geräten installiert) akzeptiert das Paket nur, wenn die Signatur valide ist.
3.  Zwei-Faktor-Authentifizierung (2FA) & Webauthn: Erzwinge für jeden Entwickler, der Pakete pushen darf, 2FA. Viele Supply-Chain-Angriffe passieren schlicht, weil Entwickler-Accounts gehackt und Schadcode in legitime Pakete eingeschleust wird.

---

## Nächster Schritt für dein Setup

Wenn du das aktuell auf Hetzner via GitHub-Runnern aufbauen willst, wäre das sicherste Setup: Ein Hetzner-Server, der via Docker-in-Docker (DinD) oder Podman nach jedem PR-Lauf den kompletten Container-State verwirft, kombiniert mit einer strikten Hetzner-Cloud-Firewall, die ausgehenden Traffic der Test-Container blockiert.
Möchtest du ein konkretes Beispiel sehen, wie man eine GitHub Actions Workflow-Datei so absichert (mit OIDC und restriktiven Permissions), dass Token-Diebstahl fast unmöglich wird?

Um die extrem einfache Developer Experience (DX) von GitHub beizubehalten, aber die Sicherheit und Robustheit einer echten Registry (wie du sie für Embedded-Hardware, Krypto-Module und RTOS-Zusammenstellungen brauchst) im Hintergrund zu haben, nutzen wir einen Trick: Git als Interface, die Registry als Single-Source-of-Truth.
Deine Entwickler und Nutzer merken im Alltag überhaupt nicht, dass im Hintergrund eine hochsichere SQL-Datenbank und ein geschützter S3-Speicher laufen. Sie interagieren weiterhin so einfach mit dem System wie mit GitHub.
Hier ist das Konzept, wie wir die DX von GitHub mit der Produktionsreife deines Setups verschmelzen.

---

## 1. Das "Git-as-Interface"-Konzept für die Entwicklung

Wenn du oder andere Entwickler neue Chips, HALs oder RTOS-Module entwickeln, nutzt ihr weiterhin euer zentrales GitHub-Monorepo (toob-registry).
Jedes Modul (egal ob Chip, Treiber oder Crypto-Lib) ist einfach ein Ordner mit den C-Dateien und einer simplen Manifest-Datei (toob.json).

## Beispiel für die Verknüpfung im Manifest (toob.json für einen Chip):

{
"name": "stm32f4-secure-core",
"type": "chip",
"architecture": "cortex-m4",
"toolchain": "arm-none-eabi-gcc",
"dependencies": {
"rtos": "zephyr-rtos@^3.5.0",
"crypto": "mbedtls-hardware-accelerated@^2.28.0",
"driver": "display-ssd1306"
}
}

Der Workflow für Entwickler ist denkbar einfach:

1.  Code im lokalen Git-Repo schreiben oder ändern.
2.  Version in der toob.json hochzählen.
3.  git push zu GitHub.

## Ab hier übernimmt die DevOps-Pipeline, um die Produktionssicherheit zu garantieren.

## 2. Die automatische Sync-Pipeline (Brücke zur Registry)

Sobald der Push auf GitHub eingeht, läuft eine automatisierte GitHub Action. Diese Action validiert die Abhängigkeiten, packt die Dateien und lädt sie in deine sichere Hetzner-Infrastruktur hoch. Für den Entwickler fühlt es sich an, als wäre "GitHub die Registry", aber technisch sichern wir es im Hintergrund ab:

[ Entwickler pusht zu GitHub ]
│
▼
[ GitHub Action (CI) ]

1. Prüft: Ist die Abhängigkeit (z.B. zephyr-rtos) valide?
2. Kompiliert einen Test-Build (stimmen Crypto-Config und Chip-HAL?).
3. Signiert den Code-Ordner.
   │
   ▼
   [ Toob-API (Hetzner) ]
4. Speichert das Paket als 'stm32f4-secure-core-v1.0.0.tar.gz' auf S3.
5. Trägt den Abhängigkeitsbaum (Matrix aus Chip ➔ RTOS ➔ Crypto) in PostgreSQL ein.

---

## 3. Die CLI für den Nutzer: "Zero Research" beim Compilen

Für den Endnutzer, der ein Projekt aufbaut, darf es keine Recherche-Arbeit geben. Er sollte nicht mühsam suchen müssen, welche Krypto-Bibliothek zu welcher Toolchain passt.
Du baust eine kleine, extrem schlanke Go- oder Rust-basierte CLI namens toob. Der Nutzer konfiguriert sein Projekt in einer lokalen Datei und die CLI übernimmt das dependency-Auflösen über deine API.

## Wie der Nutzer es verwendet:

# 1. Projekt für einen bestimmten Chip initialisieren

toob init --chip stm32f4-secure-core

# 2. Die CLI fragt die Hetzner-API ab: "Was braucht dieser Chip?"# Die API antwortet: "Er braucht arm-none-eabi-gcc, Zephyr-RTOS und mbedtls."# Die CLI lädt vollautomatisch genau diese Versionen als unveränderliche Tarballs herunter.

# 3. Projekt compilen

toob compile

## Warum das die DX revolutioniert: Die CLI baut den Include-Pfad (-I im GCC-Compiler) für den Krypto-Code, das RTOS und die HAL-Treiber vollautomatisch im Hintergrund zusammen. Der Entwickler muss keine Makefiles oder CMake-Dateien mehr händisch anpassen.

## 4. Das "GitHub-Sichtbarkeits"-Feature (Das Beste aus beiden Welten)

Wenn du die Inhalte trotzdem unbedingt auf GitHub sehen und durchsuchen willst (weil die GitHub-Code-Suche und die UI genial sind), kannst du ein Public Read-Only Mirror-Repo anlegen.
Deine Hetzner-API spiegelt den Zustand der produktionsreifen Registry vollautomatisch zurück in ein öffentliches GitHub-Repository (toob-public-registry).

- Wenn ein Paket über die API freigegeben wird, pusht ein Bot den Code in dieses öffentliche GitHub-Repo.
- Nutzer können im Web-Browser den C-Code durchsuchen, Issues schreiben oder den Code lesen.
- Aber (Sicherheit!): Die Endgeräte und die toob-CLI laden den Code niemals direkt von GitHub herunter. Sie nutzen immer die von Cloudflare gecachte, kryptografisch signierte S3-Struktur deiner Hetzner-Infrastruktur.

## Fällt GitHub aus oder wird ein GitHub-Token kompromittiert, sind deine Compiler-Pipelines und Updates auf den Geräten zu 100 % geschützt und laufen ungestört weiter.

## Zusammenfassung der Architektur für dein Vorhaben

1.  Eingabe (DX): Ein einfaches Git-Monorepo mit Ordnern für chips/, crypto/, rtos/ und drivers/.
2.  Validierung (Sicherheit): GitHub Actions testet die Kombinationen (bricht ab, wenn eine Krypto-Lib nicht zum Chip-Core passt) und schützt vor Cache-Poisoning durch ephemere Runner.
3.  Auslieferung (Performance): Die toob-CLI zieht verifizierte, unveränderliche Tarballs über deine Hetzner-API (geschützt durch Cloudflare CDN).

Wenn wir das so aufbauen, hat dein Team den gewohnten GitHub-Komfort, aber du erfüllst die höchsten Sicherheitsstandards für Embedded- und Krypto-Infrastrukturen.
Sollen wir als Nächstes ein konkretes Beispiel für den Aufbau der toob.json Manifest-Datei entwerfen, um zu sehen, wie die Abhängigkeiten zwischen Chip, RTOS und Krypto-Bibliothek sauber definiert werden?

Um eine Infrastruktur aufzubauen, die maximal ausfallsicher (High Availability) und gleichzeitig extrem kosteneffizient (Hetzner-Preise) ist, nutzen wir das Prinzip der strikten Trennung von Status und Berechnung.
Indem wir die rechenintensive Build-Pipeline von der leichtgewichtigen API trennen und ein globales CDN vorschalten, bleibt das System selbst bei extremem Traffic günstig und stabil.
Hier ist die DevOps-Infrastruktur-Architektur für dein finales Setup auf Hetzner:

---

## 1. Das globale Sicherheitsnetz: Cloudflare (Kostenlos bis sehr günstig)

Bevor ein einziger Request deine Hetzner-Server erreicht, läuft der gesamte Traffic durch Cloudflare.

- Ausfallsicherheit: Cloudflare cached die globalen Registry-Revisions-Anfragen und die Paket-Tarballs. Wenn deine API oder dein S3-Speicher für ein paar Minuten offline sind, liefert Cloudflare die Downloads einfach weiter aus. Deine Uptime ist für den Endnutzer nahezu 100 %.
- Kostenschutz: Cloudflare filtert DDoS-Angriffe und spart dir massiv Traffic-Kosten auf deine Server.

---

## 2. Die Hetzner-Infrastruktur (Server & Storage)

                       [ CLOUDFLARE CDN ] (Edge Caching)
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ API-Server 1 ]                [ API-Server 2 ]  (Hetzner Cloud CX22 - Shared CPU)
       (Falkenstein, DE)               (Helsinki, FI)
               │                               │
               ├───────────────────────────────┴───────────────┐
               ▼                                               ▼
     [ PostgreSQL Managed DB ]                      [ Hetzner Object Storage ]
     (Master + Read-Replica)                        (S3-kompatibel / Unveränderlich)
                                                               ▲
                                                               │ (Upload Artefakte)
                                                    [ Ephemere Build-Worker ]
                                                    (Hetzner Cloud CCX22 - Dedicated CPU)

## A. Die Control Plane: 2x Günstige API-Server

Du betreibst deine Go/Rust-API nicht auf einem großen Server, sondern teilst sie auf zwei kleine, geografisch getrennte Hetzner Cloud Instanzen auf (z. B. CX22 für ~4 €/Monat pro Server).

- Server 1 steht im Rechenzentrum Falkenstein (Deutschland).
- Server 2 steht im Rechenzentrum Helsinki (Finnland).
- Der DevOps-Vorteil: Fällt ein ganzes Rechenzentrum aus, merkt die CLI davon nichts, weil Cloudflare den Traffic automatisch auf den verbleibenden Server im anderen Land umleitet. Da Go/Rust-APIs kaum RAM verbrauchen, reichen diese kleinen Instanzen völlig aus.

## B. Die Datenbank: Hetzner Managed PostgreSQL

Betreibe die PostgreSQL-Datenbank für ein produktives System nicht selbst auf derselben VM. Nutze das Managed Database Angebot von Hetzner.

- Hetzner übernimmt automatisch die Backups, Sicherheitsupdates und das Clustering (Hochverfügbarkeit mit Read-Replicas). Deine Revisionsnummern und Kompatibilitätsmatrizen sind hier absolut sicher vor Datenverlust geschützt.

## C. Der Speicher: Hetzner Object Storage (S3)

Deine API speichert die .tar.gz-Pakete und OTA-Firmwares im S3-kompatiblen Object Storage von Hetzner.

- Sicherheit: Aktiviere zwingend Object Locking (WORM) im Bucket. Einmal hochgeladene Versionen können selbst von einem kompromittierten API-Server nicht gelöscht oder überschrieben werden.
- Kosten: Object Storage ist pro Gigabyte extrem günstig und skaliert unendlich, ohne dass du Festplatten vergrößern musst.

---

## 3. Das Build-Runner Setup (Expo-Style)

Das größte Kostenrisiko sind die Compiler-Runner. Würden diese 24/7 durchlaufen, wäre das pure Geldverschwendung. Deshalb nutzen wir On-Demand Auto-Scaling.

1.  Die Runner-VMs (Dedicated vCPU): Für die Build-Pipeline nutzt du Hetzner Cloud Instanzen mit dedizierten Kernen (z. B. CCX-Serie). Compiler brauchen rohe CPU-Leistung.
2.  Das Ephemere Prinzip (Wegwerf-VMs):

- Geht ein Build-Job (über eine Queue wie NATS.io oder GitHub Webhooks) ein, triggert deine API über die Hetzner-API das sekundengenaue Starten einer neuen Worker-VM.
  - Auf dieser VM startet eine isolierte Firecracker MicroVM mit dem passenden Docker-Compiler-Image aus deinem Repo.
  - Der Code wird kompiliert, das fertige Artefakt direkt in den S3-Speicher hochgeladen und die Signatur an die API übermittelt.
  - Sofort danach fährt die Worker-VM wieder herunter und löscht sich selbst. Du zahlst bei Hetzner für die teuren CPU-Server somit nur die exakten Minuten, in denen tatsächlich Code kompiliert wird.

---

## 4. CI/CD: Wie kommt neuer Code auf deine API-Server?

Wenn dein Kern-Team Code im privaten toob-core-monorepo ändert, sieht der Deployment-Prozess wie folgt aus:

1.  GitHub Actions baut ein minimales Docker-Image der neuen API (oder kompiliert das statische Go/Rust-Binary).
2.  Per Rolling Update wird erst API-Server 1 in Deutschland aktualisiert, während API-Server 2 in Finnland den Live-Traffic hält. Danach umgekehrt.
3.  Zero Downtime: Deine Nutzer erleben absolut keine Unterbrechung während eines Updates deines Systems.

## Fazit der Kosten-Nutzen-Rechnung

Dieses Setup kostet dich in der Basis-Konfiguration (ohne aktive Build-Last) unter 30 € im Monat (2x kleine API-Server, 1x kleine Managed DB, S3-Grundgebühr, Cloudflare Free). Es ist jedoch durch die Multi-Region-Aufteilung und Cloudflare so robust aufgebaut, dass es problemlos zehntausende CLI-Anfragen und OTA-Geräte gleichzeitig bedienen kann. Kosten entstehen erst dann linear skaliert, wenn deine Kunden tatsächlich viele Cloud-Builds anfordern – und diese Kosten gibst du direkt an sie weiter.
Möchtest du als Nächstes ein konkretes Beispiel für ein Terraform-Skript sehen, mit dem du diese zwei API-Server und die Firewall-Regeln bei Hetzner vollautomatisch mit einem Befehl hochfahren kannst?

Es ist absolut großartig, dass du diesen Schritt jetzt gehst. Ein MVP auf GitHub-Basis ist für den Start völlig legitim, aber für hardwarenahen Code (HALs) und kryptografische Komponenten ist der Wechsel auf eine valide Control Plane mit echter Datenbank der kritische Wendepunkt zur Produktionsreife.
Wenn du alles automatisiert „durchwinken“ würdest, öffnest du Tür und Tor für Supply-Chain-Angriffe. Hier ist der präzise, hochsichere und DevOps-konforme Ablauf von dem Moment an, in dem ein Entwickler einen Pull Request (PR) stellt, bis das Paket sicher in der CLI und im Public-Repo landet.

---

## Der präzise Workflow: Vom PR bis zur Freigabe

[ 1. PR eingereicht ] ➔ [ 2. Isolierte CI-Matrix (Dry-Run) ] ➔ [ 3. Peer Review & Merge ]
│
[ 6. CLI & Public-Mirror aktiv ] 🤹 [ 5. Datenbank & S3 Sync ] 🤷 [ 4. Release-Pipeline (Signierung) ]

## Schritt 1: Der PR wird ausgestellt

Ein Entwickler (oder ein externer Contributor) möchte einen neuen Treiber oder eine Krypto-Optimierung für einen Chip hinzufügen. Er reicht einen PR gegen dein internes Entwickler-Monorepo ein.

- Sicherheits-Regel: Der PR triggert einen GitHub-Workflow, der keinerlei Zugriff auf Produktions-Secrets (S3-Keys, DB-Passwörter) hat. Er läuft mit minimalen Leserechten.

## Schritt 2: Die isolierte CI-Matrix (Der Härtetest)

Die GitHub Action analysiert, welche Ordner sich geändert haben (z. B. crypto/mbedtls-opt/).

1.  Linting & Statische Analyse: Der C-Code wird via clang-tidy und Krypto-Scanner (z. B. auf Hardcoded Keys) geprüft.
2.  Die Kompatibilitätsmatrix (Dry-Run): Die Pipeline baut Testprojekte. Sie nimmt den neuen Krypto-Code, kombiniert ihn mit den betroffenen Chips (z. B. ESP32, STM32) und den RTOS-Varianten.
3.  Wichtig: Es wird nichts hochgeladen. Es wird nur lokal im Runner kompiliert, um zu sehen, ob der Compiler fehlerfrei durchläuft.

## Schritt 3: Das Vier-Augen-Prinzip (Peer Review & Merge)

Kein automatischer Merge! Gerade bei Krypto- und HAL-Code muss zwingend ein menschlicher Maintainer (oder ein Kern-Entwickler deines Teams) den Code sichten.

- Erst wenn die CI-Matrix „Grün“ anzeigt und mindestens ein zertifizierter Reviewer den PR freigibt, wird der PR in den main-Branch gemergt.

## Schritt 4: Die Release-Pipeline (Der geschützte Core)

Sobald der Code im main-Branch landet, triggert die eigentliche Release-Pipeline. Diese läuft in einer geschützten Umgebung und hat (über OIDC/Kurzzeit-Tokens) Zugriff auf deine Hetzner-Infrastruktur.

1.  Paketierung: Der betroffene Ordner wird in einen Tarball gepackt (toob-package.tar.gz).
2.  Kryptografische Signierung: Die Pipeline sendet den Hash des Tarballs an einen internen Key-Management-Service (KMS) auf Hetzner. Dieser signiert den Hash mit dem privaten Schlüssel der toob-registry.

## Schritt 5: Die Übergabe an API, DB und S3

Die Release-Pipeline sendet den signierten Tarball und die extrahierten Metadaten aus der toob.json per gesichertem API-Call an deine Hetzner-Control-Plane.
Deine Go/Rust-API führt nun folgende atomare Schritte aus:

1.  S3-Upload: Der Tarball wird in den Hetzner Object Storage hochgeladen (/packages/crypto/mbedtls-opt-v2.0.0.tar.gz). Der Storage hat Object Locking aktiv – die Datei kann nie wieder verändert werden.
2.  Datenbank-Eintrag: Die API schreibt die neue Version und die Kompatibilitäts-Matrix in die PostgreSQL-Datenbank.
3.  Cache-Invalidierung: Cloudflare wird angewiesen, die Paket-Metadaten im globalen Edge-Netzwerk zu aktualisieren.

## Schritt 6: Sichtbarkeit (CLI & Public-Repo)

Ab genau diesem Millisekunden-Zeitpunkt passiert zweierlei parallel:

1.  Sofort per CLI findbar: Ein Entwickler tippt irgendwo auf der Welt toob search mbedtls-opt. Die CLI fragt deine Cloudflare-Edge/Hetzner-API ab. Die API liest blitzschnell den neuen Eintrag aus PostgreSQL und liefert ihn aus. Die CLI sieht: Version 2.0.0 ist da, kompatibel mit ESP32 und Zephyr-RTOS.
2.  Der Public-Mirror wird aktualisiert: Ein asynchroner Worker auf deinem Hetzner-Server nimmt den neuen Code-Stand und pushed ihn automatisiert in das öffentliche, schreibgeschützte GitHub-Repository (toob-public-registry). Dort dient es ab sofort als reine Lese- und Durchsuchungs-Plattform für die Community.

---

## Warum dieses Setup deine Probleme im Vergleich zum MVP löst

- GitHub bricht weg? Kein Problem. Sollte GitHub morgen down sein, funktioniert deine toob-CLI und die komplette Auslieferung für deine Kunden ungestört weiter, weil alles auf Hetzner und PostgreSQL läuft.
- Schadcode-Schutz: Da die API den Upload validiert und signiert, kann kein Angreifer ein manipuliertes Paket einschleusen, selbst wenn er Schreibzugriff auf das öffentliche GitHub-Mirror-Repo erlangen würde. Die CLI würde die fehlende oder falsche Signatur sofort bemerken.
- Saubere Matrix: Deine Kompatibilitäten sind echte Zeilen in einer SQL-Datenbank (z. B. über eine Relationstabelle chip_crypto_compatibilities). Du musst keine unzuverlässigen Skripte mehr schreiben, die Textdateien auf GitHub parsen.

Möchtest du sehen, wie das Datenbank-Design (die Tabellen) für diese Kompatibilitätsmatrix aussehen muss, damit die API der CLI in Millisekunden sagen kann, welche Kombinationen erlaubt sind?

Okay, ich erkläre mal die neue Architektur, wie sie angedacht ist:

Das Registry ist jetzt eigentlich eine S3-Object Storage von Hetzner und managed Postgres DB von Hetzner. Die DB ist für die Abfragen und registrierung, die storage Box speichert .tar.gz der einzelnen Packages (Driver, Chip etc.).

Dann haben wir davor mehrere API-Server (ausfallsicherheit) und davor schalten wir Cloudflare CDN.

Die registry bekommt keine Semver-Vererbung mehr, sondern einfach nur einen steigenden integer.

Und es gibt dieses public-registry-Repo, wo nur die registry-Inhalte ohne test-scrupts und co. angezeigt werden (hier merged die Community ihre PRs rein).

Das Kern-Team hat ein Mono-repo. Wie aktuell hier. Wenn jemand einen PR mergen will, dann spiegelt Github-Actions in einem isolierten Branch des MOnorepos da die neuen Änderungen mit rein und führt hier dann scripts aus. Ohne Cache. Über Test-Runner auf einem CI-Server werden dann tests durchgeführt in isolierten Runner-Images. Wenn das durchgeht, wird das bei den checks in dem pull-request angezeigt und wie eben die neue Semver von dann ist (Patch, Minor, Major). Erst wenn diese Changes vom Kern-Team reviewed werden und co. dann kann der request gemerged werden. Wenn er remerged wird, wird ein automatierter Export-Zyklus angestoßen womit es dann auf die DB, Object storage und somit der API verfügbar wird. + es wird in der public registry dann angezeigt.

Registry Sync funktioniert dann immernoch, aber eben nicht mit semver sondern einfachen Integern, die pro Änderung an der Registry +1 rechnen, so dass man alles syncen kann lokal.

Und trotz dem, dass die registry nicht mehr über Github verwaltet wird, kann man sie dort genau so aktuell öffentlich ansehen.
