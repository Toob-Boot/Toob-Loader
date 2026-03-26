> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/firmware_update.md`


# 11. Firmware Update Mechanismen & ELF-Loading

Dieses Dokument spezifiziert die vertraglichen Abläufe aller unterstützten Update-Szenarien (Self-Updates, Delta-Patches, Scatter-Loading). Alles ist als strukturierte Feature-Checklist verfasst.

## 1. Der Standard Update-Lifecycle (Vertrag)
Die strikte Reihenfolge eines erfolgreichen Over-The-Air (OTA) Updates definiert sich wie folgt:
- [ ] **Transfer & Triggering:** Ziel-OS speichert gültiges Signature-Image in die `UPDATE` Partition und ruft `bootloader_update_trigger()` auf.
- [ ] **Validation:** Beim Neustart prüft der Bootloader Signatur & Hash des UPDATE-Slots, **vor** jeglicher Flash-Erase Operation.
- [ ] **Swap Phase:** Die `BOOT` und `UPDATE` Partitionen werden über den 1-Sektor-Swap ausgetauscht.
- [ ] **Testing-State:** Das OS bootet. Im Hintergrund wird der Boot-Slot als `STATE_TESTING` markiert.
- [ ] **Confirmation / Rollback:** Das OS meldet `bootloader_success()`. Geschieht dies nicht vor einem Neustart, dreht der Bootloader den Swap im nächsten Boot-Zyklus rigoros um (Rollback-Security).

## 2. Bootloader Self-Update Capability
Das System erlaubt die risikobehaftete Aktualisierung des Bootloaders im Feld.
- [ ] **RAM-Execution Requirement:** Das Ersetzen des Bootloaders greift auf seine eigenen Flash-Sektoren zu. Dies erfordert zwingend, dass der Flash-Treiber ins RAM geladen wird (`RAM_CODE=1`).
- [ ] **In-Place Erase (No Swap):** Ein Self-Update führt **keinen** sicheren Swap durch. Es löscht den alten Bootloader und schreibt den neuen sofort in-place. Dies ist **nicht** Power-Fail-Safe (Gefahr eines harten Totalausfalls bei Stromtrennung).

### 2.1 Monolithische Updates (`SELF_UPDATE_MONOLITHIC=1`)
Erlaubt das gleichzeitige Updaten von Bootloader und Ziel-Applikation als ein ineinander verkettetes Blob-Image.
- [ ] **Struktur:** Bootloader-Binary + Padding bytes bis zur App-Flash-Grenze + Ziel-Firmware.
- [ ] **Locking:** Ein monolithisches Image erzwingt, dass beide Teile in exakt dieser Kombination verifiziert werden. Eine isolierte Aktualisierung der Ziel-Firmware ohne Repackaging des gesamten Blobs invaldiert den hinterlegten Hash-Vertrag.

## 3. Incremental / Delta Updates (`DELTA_UPDATES=1`)
Gegenstück zum Transfer ganzer Megabyte-Binaries: Der Bootloader kann winzige Diff-Patches applizieren, die auf einer "Base-Version" aufbauen.
- [ ] **Two-Step Verification:** Zuerst wird die Signatur des (winzigen) Delta-Archivs selbst geprüft. Im Anschluss rekonstruiert der Algorithmus im RAM/Flash das neue Target-Binary und verifiziert danach die resultierende Hash-Signatur des Gesamtwerks.
- [ ] **Rollback-Patching:** Die Delta-Engine beinhaltet Reverse-Patches. Sollte das `STATE_TESTING` fehlschlagen, patcht sich das Image mathematisch wieder auf die Base-Version zurück.

## 4. ELF-Loading (Scatter Execution)
Normalerweise sind Firmwares "flat binaries". Toob-Boot unterstützt jedoch den direkten Umgang mit ELF-Dateien.

| ELF Execution Mode | Beschreibung & Contracts |
|--------------------|--------------------------|
| **RAM ELF Loading** (`BOOTLOADER_ELF`) | Der Updater liest die kompilierte ELF Datei, verifiziert ihre Signatur im Flash, zerlegt die Memory-Mapped-Sections (LMA) und kopiert sie logisch übersetzt in das Executable-RAM, bevor er in den Entry-Point springt. |
| **Flash Scatter Loading** (`BOOTLOADER_ELF_FLASH_SCATTER`) | Zerlegt Loadable-Regions einer ELF-Datei und schreibt sie an nicht-zusammenhängende (scattered) Adressen physisch hart in den Flash (z.B. für getrennte Code- und Asset-Areas). |
| **Dual-Layer Verification** | Bei Flash-Scatter wird zunächst das gepackte ELF-Archiv-Hash validiert. Danach berechnet der Bootloader eine "Scattered Hash" Kontrolle über *alle* verstreuten Flash-Bänke, um zu prüfen, ob das Deployment erfolgreich war. |

## 5. Externe Verifikation (HSM & TPM)
Sondermodi, abseits vom regulären Ed25519-Self-Check:
- [ ] **Certificate Chain (`CERT_CHAIN_VERIFY=1`):** Das Manifest enthält keine Public-Keys, sondern eine vollständige x509-Zertifikatskette. Toob-Boot prüft die Chain bis zu einer intern assemblierten Root-CA (meist gekoppelt an ein Hardware Security Module / TPM) und traut nur dem so zertifizierten Image.
- [ ] **HSM Boot-Skip (`SKIP_BOOT_VERIFY=1`):** *Hochriskante Optimierung:* Wenn das System von einem mächtigem Krypto-Coprocessor (Hardware-Root-of-Trust) ummantelt ist, der ohnehin den gesamten Startvorgang blockiert, deaktiviert dieses Flag **alle** laufzeitbedingten Toob-Boot Signatur-Checks beim Starten (Performance), verlässt sich aber weiterhin komplett auf die Swap/Update-Installations-Mechanik.
