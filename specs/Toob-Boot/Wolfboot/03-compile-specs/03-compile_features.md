> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/compile.md`


# 03. Bootloader Build & Configuration Features

Dieses Dokument fungiert als lückenloser Backlog aller Compile-Time-Features, Konfigurationsmakros und Build-Pipeline-Spezifikationen. Es wurde im exakten Checklist- & Tabellenformat erstellt, um eine lückenlose Referenz für die Implementierung nach `/create-specs` zu garantieren.

## 1. Build System & Toolchain Automation
- [ ] **Interactive Configuration:** Das Tooling unterstützt ein `make config` Target, welches dialogbasiert Default-Parameter (in Form einer `.config` Datei) abfragt und lokal persistiert.
- [ ] **Command Line Overrides:** Alle in der `.config` definierten Parameter können via CLI (`make PARAM=1`) beim Aufruf überschrieben werden.
- [ ] **Auto-Key-Provisioning:** Wenn keine Keys beim ersten Build-Vorgang hinterlegt sind, generiert das System automatisiert ein asymmetrisches Schlüsselpaar und kompiliert den Public-Key direkt in den Bootloader-Keystore (`keystore.c`).
- [ ] **Externally Managed Keys:** Build-System akzeptiert die Injektion externer privater/öffentlicher Keys über die Variablen `USER_PRIVATE_KEY` und `USER_PUBLIC_KEY` zur Laufzeit.
- [ ] **Certificate Chain Injection:** Über `USER_CERT_CHAIN` kann eine x509-Zertifikatskette via Build-Argument injected werden, wenn `CERT_CHAIN_VERIFY=1` aktiv ist.

## 2. Speichergeometrie & Partitions-Konfigurationen
Folgende Variable definieren die physische Aufteilung des Flashs und **müssen** zwingend gesetzt werden (Verträge der Flash-Geometrie):

| Konfigurations-Makro | Typ / Beschreibung |
|----------------------|--------------------|
| `BOOTLOADER_SECTOR_SIZE` | Definiert die zugrundeliegende minimale Lösch-Einheit des Flashs. Ist das Maß für den benötigten Swap-Platz. (Beispiel: `0x20000` = 128KB). |
| `BOOTLOADER_PARTITION_BOOT_ADDRESS` | Startadresse der Primary-Partition auf dem MCU-Flash. |
| `BOOTLOADER_PARTITION_UPDATE_ADDRESS` | Startadresse der Secondary-Partition (kann auch Offset auf Remote-Flash sein). |
| `BOOTLOADER_PARTITION_SWAP_ADDRESS` | Startadresse des 1-Sektor-großen Swap-Speichers für Update-Übertragungen. |
| `BOOTLOADER_PARTITION_SIZE` | Symmetrische Maximal-Größe für BOOT und UPDATE Partition (z.B. `0x40000`). |

## 3. Architecture & Hardware Tuning (Makros)
- [ ] **Interrupt Vector Relocation Disable (`VTOR=0`):** Deaktiviert die interne Vector-Table-Neupositionierung. Notwendig, wenn ein externes OS/Pre-Boot-System das Relocating übernimmt.
- [ ] **RAM-Execution (`RAM_CODE=1`):** Erzwingt die Ausführung schreibkritischer IAP (In-Application Programming) Flash-Zugriffe aus dem RAM. Verhindert Lese-/Schreibkollisionen auf dem gleichen Speichermedium.
- [ ] **Disable Assembly / Fallback (`NO_ASM=1` / `NO_ARM_ASM=1`):** Deaktiviert hardwarenahe Assembler-Optimierungen zugunsten eines reduzierten C-Footprints.
- [ ] **Multi-Sector Erase (`FLASH_MULTI_SECTOR_ERASE=1`):** Erlaubt das gebündelte Löschen (Erase) von großen Flash-Bereichen ohne einzelnes Durchiterieren durch Sektoren (beschleunigt Swap massiv bei kompatibler HAL).
- [ ] **Hardware Assisted Swap (`DUALBANK_SWAP=1`):** System nutzt bei Dual-Bank-Speichern direkte Hardware-Register, um Bänke zu vertauschen, statt Sektoren softwarebasiert umzukopieren.

## 4. Speicher- & Stack-Optimierungen
| Stack-Makro | Beschreibung der Speicherverwaltung |
|-------------|-------------------------------------|
| `(Default)` | Das System alloziiert Speicher temporär und flexibel direkt auf dem Cortex-M Execution-Stack. Laufzeit-Checks auf Overflow. |
| `BOOTLOADER_SMALL_STACK=1` | Erzeugt statisch prä-allokierte Arrays ("Pools") im `.bss`/`.data` Segment, woraus Cryptography-Variablen bedient werden. Reduziert drastisch die dynamische Laufzeit-Stack-Tiefe für RAM-arme Systeme. |
| `BOOTLOADER_HUGE_STACK=1` | Umgeht die Sicherheitschecks des Compilers, falls bestimmte Krypto-Algos (RSA-4096) massive Mengen an temporärem Speicher erfordern, der Stack aber vom Nutzer garantiert ausreichend groß dimensioniert wurde. |

## 5. Security Checklists (Cryptography Selectors)
Das System nutzt `SIGN=...` zur Auswahl des Krypto-Algorithmus:
- [ ] **`SIGN=ED25519`**: Default Algorithmus (Elliptic Curve).
- [ ] **`SIGN=ECC256 / 384 / 521`**: ECDSA Support Formate.
- [ ] **`SIGN=RSA2048 / 3072 / 4096`**: RSA Verifikation.
- [ ] **`SIGN=ED448`**: Erweiterter Curve Support.
- [ ] **`SIGN=NONE`**: Deaktiviert die Authentifizierungsfunktion komplett (nur Hash-Verifikation oder ungeprüftes Laden). Für Testing/Simulatoren.

## 6. Update & Persistenz Features (Flash-Logik)
- [ ] **External Flash Routing (`EXT_FLASH=1`):** UPDATE- und SWAP-Partitionen können in Remote-Storage ausgelagert werden.
  - Sub-Option: `SPI_FLASH=1` mappt externe Partitionen auf SPI.
  - Sub-Option: `UART_FLASH=1` bezieht Updates on-demand als seriellen Stream von einem Nachbar-Chip.
- [ ] **Encrypted Remote Partitions (`CHACHA20`):** Die auf einem ungeschützten Speicherbaustein (External Flash) liegenden Update-Images können Ende-zu-Ende verschlüsselt werden und werden bei Transfer in den sicheren internen MCU-Flash "on-the-fly" vom Bootloader entschlüsselt.
- [ ] **Incremental / Delta Updates (`DELTA_UPDATES=1`):** Bootloader kann Update-Archive applizieren, die nur die bitweisen Diffs zwischen der Current- und Target-Version beinhalten (Bandbreitenschonung).
- [ ] **Flags in Primary Boot Slot (`FLAGS_HOME=1`):** Modifiziert die Tracking-Logik: Update-Tracking-Flags, die normalerweise im Remote-Speicher (UPDATE Slot) liegen, werden nun am Schwanz der gesicherten BOOT-Partition im internen Flash abgelegt.
- [ ] **Inverted Flash Erase (`FLAGS_INVERT=1`):** Wenn ein Chipsatz nach einem Flash-Erase alle Bytes auf `0x00` (statt `0xFF`) zieht, invertiert dieses Flag die gesamte Flag-Auswertungslogik. Custom Padding-Bytes können via `FILL_BYTE` gesetzt werden.

## 7. Edge-Cases und Fallback-Handling
- [ ] **No-Fallback Updates (`DISABLE_BACKUP=1`):** Das Backup des alten Systems zum Rollback-Zweck wird nicht angefertigt. Sparrt die Hälfte der Swap-Writes, ist aber non-recoverable nach bad Updates. Ist jedoch immer noch Power-Loss safe (keine Korruption des Primary-Slots vor Abschluss).
- [ ] **Append-Only NVM Support (`NVM_FLASH_WRITEONCE=1`):** Wenn ein Flash keine mehrfachen Bit-Changes ohne Page-Erase erlaubt, bedient sich das System einer Append-Only Flag Architektur. Warnung: Tearing-Safe (Power Loss) Garantien existieren bei Aktivierung nicht mehr.
- [ ] **Downgrade Security Breach (`ALLOW_DOWNGRADE=1`):** Deaktiviert Anti-Rollback Integrität für Testzwecke, um ältere Firmware-Versionen installieren zu lassen.
