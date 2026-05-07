# Toob Hub API (Interpreter Service)

Das Toob Hub API (intern auch "Interpreter Service" genannt) ist das zentrale Package-Management-Backend für das Toob Ökosystem. Es ersetzt die alte Notwendigkeit, das gesamte Git-Repository der Registry klonen zu müssen.

Der Service läuft als Teil des `toob-ci` Daemons auf unserem Hetzner-Server und fungiert als "Interpreter". Er hält die `version_index.json` und die `compatibility_matrix.json` dauerhaft im RAM und beantwortet Auflösungsanfragen (Resolving) von Clients wie der Toob CLI oder den Compiler-Containern.

---

## 1. Architektur & Lifecycle

Der Interpreter-Service lädt die `version_index.json` selbstständig von GitHub.
- **Zero-Downtime Context Switching:** Der Service hält immer maximal 3 Versionen des Indexes im RAM. Wenn eine neue `version_index.json` über GitHub veröffentlicht wird, lädt der Service diese im Hintergrund herunter, setzt sie als primären Index (Context Switch) und behält die alte Version kurzfristig, damit laufende Downloads von Clients nicht fehlschlagen.
- **ZIP-Extraction:** Statt Git-Historien auszuliefern, leitet die API die Clients intelligent auf die offiziellen `.zip` Source-Code Archive von GitHub um. Ein Client (z.B. CLI) lädt nur eine winzige 2MB ZIP-Datei herunter, entpackt diese und hat die Registry in wenigen Millisekunden bereit.

---

## 2. API Endpoints

Der Service ist aktuell unter `http://178.105.106.59:9000` (wird zukünftig durch eine Domain wie `api.toob.dev` abgelöst) erreichbar.

### 2.1 Registry auflösen
Gibt die exakte ZIP-Download-URL für eine angeforderte Registry-Version zurück.

**Endpoint:** `GET /api/v1/resolve/registry`

**Query Parameter:**
- `version` (optional, Default: `latest`): Kann `latest`, `main` oder ein spezifischer Tag wie `v1.0.8` sein.

**Beispiel-Request:**
```bash
curl -s "http://178.105.106.59:9000/api/v1/resolve/registry?version=latest"
```

**Response (200 OK):**
```json
{
  "version": "main",
  "download_url": "https://github.com/Toob-Boot/Toob-Registry/archive/refs/heads/main.zip"
}
```

---

### 2.2 Chip Abhängigkeiten auflösen
Sucht in der `version_index.json` nach der Registry-Version, die eine spezifische Chip-Version eingeführt hat. Dies ist nützlich, wenn die `device.toml` eines Projekts keine Registry-Version angibt, aber einen bestimmten Chip verlangt.

**Endpoint:** `GET /api/v1/resolve/chip`

**Query Parameter:**
- `name` (required): Der Name des Chips (z.B. `esp32c6`).
- `version` (optional): Die exakte Version des Chips (z.B. `1.1.0`). Wenn weggelassen, wird in der neuesten Registry gesucht.

**Beispiel-Request:**
```bash
curl -s "http://178.105.106.59:9000/api/v1/resolve/chip?name=esp32c6&version=1.0.0"
```

**Response (200 OK):**
```json
{
  "chip": "esp32c6",
  "chip_version": "1.0.0",
  "found_in_registry_version": "v1.0.6",
  "registry_download_url": "https://github.com/Toob-Boot/Toob-Registry/archive/refs/tags/v1.0.6.zip"
}
```

---

### 2.3 Environment/Matrix Empfehlungen (in Entwicklung)
Gibt eine Empfehlung aus, welches `toob-compiler` Docker-Image und welches `core_sdk` für eine bestimmte Kombination aus Chip und Toob-CLI am besten geeignet ist, basierend auf der Compatibility Matrix.

**Endpoint:** `GET /api/v1/resolve/environment`

**Query Parameter:**
- `chip` (required): Der Ziel-Chip (z.B. `esp32c6`).
- `cli_version` (required): Die Version der Toob-CLI (z.B. `v1.1.0`).

**Beispiel-Request:**
```bash
curl -s "http://178.105.106.59:9000/api/v1/resolve/environment?chip=esp32c6&cli_version=v1.1.0"
```

**Response (200 OK):**
```json
{
  "status": "COMPATIBLE",
  "recommended_compiler": "latest",
  "recommended_core_sdk": "v1.0.1"
}
```

---

## 3. Integration in die Toob CLI

Die Toob CLI integriert diese API über die Umgebungsvariable `TOOB_HUB_URL` (Fallback auf Hetzner-IP).
Wenn ein Entwickler `toob init` ausführt, passiert folgendes unter der Haube:
1. CLI fragt `GET /api/v1/resolve/registry?version=latest`.
2. CLI lädt die `download_url` (ZIP) in den Speicher.
3. CLI entpackt das ZIP lokal unter `~/.toob/registry/versions/main/`.
4. Der Build-Prozess nutzt diese lokalen Files ohne jegliche Git-Befehle oder Locks auszuführen.

Das Resultat ist eine superschnelle, skalierbare Package-Resolution Architektur!
