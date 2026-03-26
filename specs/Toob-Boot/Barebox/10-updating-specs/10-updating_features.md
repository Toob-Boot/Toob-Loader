> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/updating.rst`

# 10. Barebox Firmware Updating

Dieses Dokument behandelt das Risiko und die Mechanismen des Flashens des Bootloaders selbst (Self-Update). Da ein zerstörter Bootloader die Platine sofort unbrauchbar macht (Bricking), warnt Barebox strikt davor, nackte Lese/Schreib-Befehle (`cp` oder `erase`) zu verwenden.

## 1. Das `barebox_update` Framework
Als Schutzschicht existiert der Befehl `barebox_update`. Er verlagert das Wissen über die Partitionen aus dem Userspace in den C-Code des Board Support Packages (BSP).

- [ ] **Update Handlers:** Das Platinen-Profil in Barebox registriert "Update Handler" (`barebox_update -l`). Jeder Handler ist an ein physikalisches Speichermedium gebunden (z.B. `mmc` für SD-Karten, `spinor` für SPI Flash). Barebox markiert automatisch das Medium als "Default"-Handler, von welchem es physikalisch gestartet wurde.
- [ ] **Image Metadata (IMD) Checks:** Bevor der Handler den `erase` Befehl auf dem Flash auslöst, parst er das eingehende Update-Image. Er sucht nach eingebetteten "Barebox Image Metadata" (`imd`), um kryptografisch oder logisch zu validieren, ob die entgegengenommene `.img` Datei tatsächlich ein kompatibler Barebox-Bootloader für exakt diese Hardware ist.
- [ ] **Redundant Image Repair (`-r`):** Da SoCs (wie z.B. bestimmte i.MX Prozessoren) von Haus aus die Möglichkeit bieten, *mehrere* redundante Bootloader-Images (A/B Bootloader Kopien auf ROM-Ebene) im Flash abzulegen, unterstützt der Handler dies nativ. Wird der Befehl mit dem Flag `-r` aufgerufen, kann er defekte Haupt-Images aus den redundanten Informationen heraus selbst "reparieren" und frisch flashen.
