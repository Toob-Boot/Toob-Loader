> **Quelle/Referenz:** Analysiert aus `wolfBoot/README.md & wolfBoot/docs/README.md`


# 01. Bootloader Core Features (From Root Documentation)

Dieses Dokument fungiert als lückenloser Backlog aller Funktionalitäten, Komponenten, Workflows und Konfigurations-Makros, die im Root-Dokument des originalen Bootloaders dokumentiert sind. Nichts wurde ausgelassen. Die Spezifikation wurde komplett generifiziert (herstellerunabhängig) und abstrahiert.

## 1. System Core Features
- [ ] **Multi-Slot Flash Partitioning:** Der Flash-Speicher wird strikt in Partitionen (Slots) unterteilt, um Firmware sicher upzudaten.
- [ ] **In-Place Chain-Loading:** System führt die Firmware aus dem primären Slot "in-place" aus.
- [ ] **Copy/Swap Mechanism:** Firmware-Updates finden zwischen Secondary-Slots und Primary-Slots statt (Images werden aus dem sekundären in den primären kopiert/getauscht).
- [ ] **Minimalist HAL Interface:** Minimalistische Hardware-Abstraktionsschicht, beschränkt auf:
  - IAP Flash Zugriff (Lese-/Schreibzugriffe).
  - Clock Settings für die MCU.
- [ ] **Bare-Metal & Memory Safe:** Keine Verwendung dynamischer Speicherallokationen (kein malloc/free in kritischen Pfaden), keine Bindung an Standard-C-Libs (nur an die native Cryptographic Core Engine).
- [ ] **Anti-Rollback Protection:** Schutz vor Downgrades der Firmware-Versionen über integrierte Versionsnummern im Header.

## 2. Bootloader Toolkit & Components
Das System besteht aus mehreren gekapselten Komponenten, die zusammen iterieren:

| Komponente | Dateipfad / Referenz | Beschreibung |
|------------|----------------------|--------------|
| **Core Bootloader** | `src/` | Die ablaufende Bare-Metal Applikation (Chain-Loader + Verifier). |
| **lib_bootloader** | `src/lib_bootloader.c` | Kleine Library, die in die Ziel-Applikation integriert wird, um mit dem Bootloader IPC-/Flash-seitig zu kommunizieren (Update triggern etc.). |
| **Cryptographic Core** | (Modul) | Bereitstellung der Crypto-Primitive (Signatur-Verifikation, Hashing). |
| **Key Generator Tool** | `tools/keytools/keygen` | Erstellt asymmetrische Schlüssel-Paare. Option `--no-overwrite` zum Schutz bestehender Keys. |
| **Image Signing Tool** | `tools/keytools/sign` | Signiert Firmware-Images. Hängt den formatierten Header (inklusive Image-Size) und Trailer an. |
| **OTP Primer & Gen** | `otp_primer`, `otp_gen` | Hilfs-Images/Tools zum Provisionieren von Keystores direkt in Einmal-Speichern (OTP). |
| **Filesystem CLI** | `library_fs` / MTD | Tool/Target zum Auslesen und Verwalten des Partition-Status im Storage/MTD. |

## 3. Workflows & Prozesse

### 3.1 Initiales Setup & Integration (Developer Workflow)
Diese Schritte müssen beim Portieren des Systems auf eine App erfolgen:
- [ ] HAL Implementierung für das Zielsystem bereitstellen.
- [ ] Flash-Partitionierungs-Strategie definieren und in Header-Konfiguration (z.B. `target.h`) hart codieren.
- [ ] Entry-Point der Ziel-Applikation anpassen, damit dieser die Präsenz des Bootloaders berücksichtigt (Offset-Verschiebung).
- [ ] Applikation zwingend mit der Interaktions-Lib verlinken.
- [ ] Konfigurationsdefinitionen (`.config` Makros) setzen.
- [ ] Erzeugung von Signierschlüsseln (via Make-Targets wie `make keytools`).
- [ ] "Key clean" Kommando (z.B. `make keysclean`) bereitstellen zum harten Löschen asynchroner Keys.

### 3.2 Factory Image Erzeugung (Build-System)
Der Compile-Prozess automatisiert die Erstellung des Factory-Images (Geräte-Auslieferungszustand):
1. Key-Pair wird generiert.
2. The Public Key wird fest in den Build des Bootloaders einkompiliert.
3. Firmware-Image (Test-App) wird kompiliert.
4. Firmware wird umgelinkt (Start=Primary Partition).
5. Firmware wird signiert.
6. Factory Image entsteht durch feste Konkatenation: `Bootloader-Binary + Signed-Firmware-Binary`.

### 3.3 Firmware Upgrade Lifecycle (Over-The-Air / Lokal)
Jeder Zyklus eines Updates durchläuft folgende API-Aufrufe/Abläufe:
1. Neue Firmware kompilieren + linken auf Primary-Start-Adresse.
2. Signieren mit privatem Schlüssel.
3. Payload an Secondary Slot auf Flash/Gerät übertragen (Protokoll unabhängig).
4. `bootloader_update_trigger()` (aus der Interaktions-Lib) aufrufen.
5. System-Reboot auslösen.
6. Bootloader übernimmt -> Verifikation -> Copy/Swap zum Primary Slot -> Boot.
7. Ziel-App bootet und MUSS `bootloader_success_confirm()` aufrufen, um das Update permanent zu bestätigen (sonst Fallback/Rollback beim nächsten Power-Cycle).

## 4. Erweiterte Update Features
- [ ] **Delta Updates (Incremental Updates):** Update auf Basis von Base-Version-SHA (Diff-Patches statischer Images zur Ersparnis von Bandbreite). Invalid Base Versions werden aktiv verworfen. Optionale externe Verschlüsselung der Deltas.
- [ ] **External Flash Routing:** Updates können aus Remote-UART-Speichern oder externen SPI-Flashes installiert werden. SPI Memory Execution ist als Option (aus RAM laufend) verankert.
- [ ] **Encrypted Updates:** Bootloader unterstützt Ende-zu-Ende verschlüsselte Update-Partitionen.
- [ ] **Disable Backup / NO_BACKUP:** Fallback-Mechanismus kann abgeschaltet werden. Modus ist power-fail safe.
- [ ] **Recovery via Flash Write-Once (`NVM_FLASH_WRITEONCE`):** Spezieller Flash-Modus (Append-Only) für Memory ohne konsekutive Read-Erase Cycles.
- [ ] **Non-Contiguous ELF Loading:** Scatter-Loading von ELF-Dateien, ideal um RAM, XIP und Code über externe Flash-Referenzen in einer ELF Datei zu verteilen.

## 5. System Configurations & Makros (Flags)
Makros, die das Verhalten hart konfigurieren:
| Macro / Flag / Option | Beschreibung |
|-----------------------|--------------|
| `BOOTLOADER_PARTITION_BOOT_ADDRESS` | Spezifiziert exakt die Einsprungsadresse (Muss identisch zum App-Linker-Script sein). |
| `SIGN=NONE` | Sicherheit [Deaktiviert Secure Boot] am Compile-Time (Für Dev-Testing / Simulator). |
| `BOOTLOADER_SMALL_STACK` | Nutzt hartkodierte, pre-allokierte Puffer, ohne große Stack-Variablen aufzubauen (Speicher-Optimierung). |
| `FLAGS_HOME` | Speichert UPDATE-Flags direkt in der BOOT-Partition statt auf dem Secondary Slot. |
| `BOOTLOADER_RESTORE_CLOCK` | Konfiguration, um Clocking-States nach HAL-Operationen beim Boot zurückzusetzen. |
| `CSU_DEBUG` | Aktiviert JTAG zur Laufzeit in Secure/Enclave (Xilinx HW). |

## 6. Hardware Security Module & TPM Integration
- [ ] **TPM 2.0 Integration:** Bootloader unterstützt handelsübliche Hardware TPMs (z.B. Infineon Serie) via SPI/I2C zur Root of Trust-Kapselung.
- [ ] **Measured Boot (PCR Extensions):** Statt nur Signatur zu prüfen, hashet der Bootloader das gestartete Image und legt den Hash in einen TPM Platform Configuration Register (PCR).
- [ ] **TPM NV Operations:** Nutzen von NV-Storage als Root of Trust, passwortgeschützte Slots, Sealing/Unsealing auf Basis extern signierter PCR-Policies.
- [ ] **PKCS11 Engine:** In TrustZone-M Systemen kann der Bootloader als Secure-Mode Supervisor laufen, der Krypto-Primitive via PKCS11-API für die Non-Secure App exponiert.
- [ ] **HSM Client/Server Modus:** Zertifikatsketten-Autorisierung (x509) über Hardware Security Module (HSM).
- [ ] **Custom TLVs:** Manifest-Header unterstützt freie "Type-Length-Value" Tags für proprietäre Zusatz-Authentifizierungs-Payloads oder Key-Exchanges.
