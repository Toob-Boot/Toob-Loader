> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/CMake.md`


# 04. CMake Build Pipeline Features

Dieses Dokument beschreibt die konkreten CMake-Build-Features, Einschränkungen und Build-Pipelines des Bootloader-Systems. Diese Extraktion basiert streng auf Checklist-Architektur-Verträgen.

## 1. Build-Environment & Security Constraints
- [ ] **In-Source Build Prevention:** Der Build-Prozess verbietet strikt die Ausführung im Source-Verzeichnis. `CMAKE_SOURCE_DIR` == `CMAKE_BINARY_DIR` bricht den Vorgang mit einer expliziten Warnung sofort ab.
- [ ] **CMake Presets als Single Source of Truth:** Wiederkehrende Target-Konfigurationen und Flash-Geometrien werden bevorzugt in strukturierter `CMakePresets.json` abgelegt statt in unstrukturierten Makefiles.
- [ ] **Benutzerdefinierte Overrides (`CMakeUserPresets.json`):** System lädt automatisch lokale Entwickler-Overrides (wie Toolchain-Pfade `ARM_GCC_BIN`), die explizit von der VCS-Versionierung ausgeschlossen werden müssen (via `.gitignore`), um lokale Host-Eigenschaften abzukapseln.

## 2. `.config` Legacy Support
- [ ] **Dot-Config Parser Pipeline:** Das Flag `-DUSE_DOT_CONFIG=ON` (oder das Vorhandensein einer validen `.config` Datei) aktiviert einen internen CMake-Parser, der sequenziell Legacy-Make-Assignments (wie `SIGN=ECC256`) in dynamische CMake-Variablen übersetzt.
- [ ] **Config-To-Preset Converter:** Das Python-Tooling `tools/scripts/config2presets.py` wandelt Legacy-Text-Konfigurationen vollautomatisiert in standardisierte CMake-Presets im JSON-Format um.

## 3. Kompilierungs-Steuerung (Command Line Overrides)
Kommandozeilen-Flags (`-D` Parameter), die die Build-Architektur dynamisch biegen:

| CMake Parameter | Beschreibung / Vertrag |
|-----------------|------------------------|
| `BUILD_TEST_APPS=yes` | Befiehlt der Pipeline, nicht nur den ungesicherten Bootloader, sondern synchron auch die Payload-Firmware (Target-App) zu kompilieren und direkt via `sign` Tooling zu authentifizieren. |
| `PYTHON_KEYTOOLS=yes` | Setzt das Crypto-Tooling-Interface auf Python-Skripte um, anstatt die C-basierten Binäries in der Keystore-Phase neu zu kompilieren. |
| `HAL_DRV` | Erlaubt die dynamische Injektion von Pfaden zu externen Hardware-Treibern (z.B. STM32 HAL) außerhalb des Projektbaums. |
| `HAL_CMSIS_DEV` / `CORE`| Injektion der Base-Cortex-Header-Pfade bei ARM-Architekturen zur Laufzeit. |

## 4. Factory Image Assembly Pipeline (Target-Flow)
Der Lebenszyklus der CMake Build-Targets ist in eine strikte Kausalkette unterteilt. Jeder Block muss abgeschlossen sein, bevor der nächste feuert:

- [ ] **Build-Phase 1: `keystore` / `public_key`**
  - Toolchain kompiliert das `keygen` Executable.
  - Das Executable generiert aus dem leeren Verzeichnis heraus den privaten Schlüssel für die Firmwaresignatur.
  - Das System übersetzt den öffentlichen Schlüssel in die C-Sourcen (`keystore.c`), welche in das Target `public_key.a` assembliert werden.
- [ ] **Build-Phase 2: `hal` und `cryptocore`**
  - Kompiliert die assemblierten Hardware-Treiber (z.B. Cortex Flash APIs) zu `libbootloaderhal.a`.
  - Kompiliert das stark isolierte mathematische Cryptography-Subsystem zu `libcryptocore.a`.
- [ ] **Build-Phase 3: `bootloader`**
  - Statisches Verlinken von `keystore`, `hal` und `cryptocore` mit den Haupt-Entrypoints des Bootloaders.
- [ ] **Build-Phase 4: `image` (Test-App)**
  - Kompilierung der auszuführenden Ziel-Payload, die um `+256` Bytes verschobene Entry-Points (ab `BOOTLOADER_PARTITION_BOOT_ADDRESS`) besitzt.
- [ ] **Build-Phase 5: `image_signed`**
  - System feuert den Executable-Hook für das Tool `sign` auf das Target `image`.
  - Tool berechnet den SHA256-Digest, unterschreibt ihn asymmetrisch mit dem privaten Payload-Schlüssel und klebt Size-Header, Type-Signaturen und Trailer-Flags fest an die Datei.
- [ ] **Build-Phase 6: `binAssemble` & `image_boot` (Das Factory Image)**
  - Kompiliert das Byte-Stitching-Tool.
  - Generiert (konkateniert) das End-Image für den initialen JTAG-Flash zur Fabrikation: Bootloader-Code am Beginn der Sektorgrenze + `0xFF` Flash-Padding-Bytes exakt bis zum Beginn des Boot-Offsets + die signierte App-Payload (`image_signed`).
