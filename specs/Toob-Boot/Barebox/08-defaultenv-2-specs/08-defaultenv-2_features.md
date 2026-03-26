> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/defaultenv-2.rst`

# 08. Barebox Default Environment 2

Dieses interne Dokument offenbart einen der stärksten Architekturvorteile von Barebox gegenüber alten Bootloadern (wie U-Boot): Die Konfiguration ist kein roher Hex-Block aus Variablen, sondern ein echtes, virtuelles **Dateisystem**!

## 1. Das "In-Memory Tarball" Prinzip
Sämtliche Skripte, Netzwerk-Settings und Boot-Vorgaben liegen im Pfad `/env/`. 

- [ ] **Compiled-in Fallback:** Das Environment verhält sich wie ein *Tar-Archiv*. Beim Start entpackt Barebox dieses Archiv aus dem non-volatile Speicher (siehe State Framework). Ist dieser Speicher leer, kaputt oder gelöscht, stürzt Barebox nicht ab! Es entpackt stattdessen vollautomatisch das sogenannte *Compiled-in default environment* – ein hart in das Barebox-Binary gelinktes, unveränderliches Backup-Archiv!
- [ ] **Overlay Build-Mechanismus:** Während der Kompilierung von Barebox wird das Archiv aus vielen Layern übereinandergelegt. Zuerst die *base files*, dann z.B. *menu files*, dann *reboot-mode* Settings, und ganz zum Schluss *board specific overlays*. Existiert eine Datei (z.B. `/env/config`) in mehreren Layern, überschreibt der spätere Layer den vorherigen.

## 2. Die Ordner-Struktur (The Filesystem Contracts)
Das virtuelle Dateisystem von Barebox folgt strikten Pfad-Konventionen, ähnlich einem `/etc/` in Linux.

| Ordner / Datei | Barebox-Vertrag & Skript-Logik |
|----------------|--------------------------------|
| `/env/bin/init` | Das *Init-Skript*. Bestimmt den 3-Sekunden Auto-Boot Timeout. Ist per Default in purem `C` geschrieben, kann aber vom User durch ein eigenes Bash-artiges Shell-Script an genau diesem Pfad **ohne Neukompilierung** überschrieben werden! *Warnung:* Ein Bug in diesem Skript brickt das Board, da es vor jedem Tastendruck ausgeführt wird. |
| `/env/init/` | Das "SysV-Init" von Barebox! Alle Skripte in diesem Ordner werden beim Start strikt **alphabetisch** ausgeführt. Perfekt, um Treiber-Settings frühzeitig zu setzen. |
| `/env/boot/` | Heimat der Boot-Scenarios. Die Eingabe `boot mmc` auf der Barebox-Konsole führt schlicht physikalisch das Skript `/env/boot/mmc` aus. |
| `/env/config` | Die zentrale Einstellungsdatei. Hier stehen globale Konstanten wie `global.autoboot_timeout=3` oder `global.linux.bootargs`. (Muss via Befehl `saveenv` manuell neu in den Speicher geflusht werden, wenn es im Live-Betrieb editiert wurde!). |
| `/env/network/` | (Netzwerk-Interfaces). Das File `eth0` deklariert, ob DHCP (`ip=dhcp`) oder Static (`ipaddr=...`) verwendet wird. |
| `/env/bmode/` | **Reboot-Mode Skripte!** Wenn Linux einen Hardware-Reboot mittels `reboot bootloader` oder `reboot recovery` absetzt, nutzt Barebox diese Info beim Aufwachen und führt – passend zum Linux-Intent – gezielt Unter-Skripte aus diesem Pfad aus. Eine saubere Brücke zwischen OS und Bootloader. |
