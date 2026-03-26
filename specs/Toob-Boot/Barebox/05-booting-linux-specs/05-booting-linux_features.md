> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/booting-linux.rst`

# 05. Booting Linux & Bootloader Specification (blspec)

Dieses Dokument spezifiziert, wie Barebox als First- oder Second-Stage Bootloader die Ausführung an das eigentliche Betriebssystem (Linux) übergibt. Es offenbart starke Komfort-Features, die weit über das reine Laden von Binärdaten hinausgehen.

## 1. Low-Level Booting (`bootm`)
Das Herzstück des Kernel-Starts ist das `bootm` Kommando. Es verarbeitet vollautomatisch zImages, ARM64 Images, U-Boot uImages, Barebox Binaries und FIT Images.

- [ ] **Dynamic Kernel Arguments (`CONFIG_FLEXIBLE_BOOTARGS`):** Barebox setzt Linux-Bootparameter (`bootargs`) nicht als statischen Monolith zusammen. Es aggregiert alle Variablen unterhalb von `global.linux.bootargs.*`. 
- [ ] **MTD-Partition Mapping:** Barebox übersetzt seine eigenen physischen Flash-Partitionierungen (via `addpart`) vollautomatisch in gültige `mtdparts=` Strings für den startenden Linux-Kernel, damit dieser exakt dieselbe Partitions-Sicht hat!
- [ ] **Append Root Magic (`global.bootm.appendroot`):** Barebox kann den benötigten `root=` Parameter für den Kernel vollautomatisch berechnen, abhängig davon, woher der Kernel geladen wurde (z.B. generiert es `root=PARTUUID=deadbeef-1` für SD-Karten oder `root=/dev/nfs nfsroot=...` für Netzwerk-Boots).

## 2. High-Level Booting (`boot` & Scripts)
Der `boot` Befehl abstrahiert `bootm` durch Skripte und Fallbacks.

| Konzept | Verhalten & Invariante |
|---------|------------------------|
| **Boot Scripts** | Skripte unter `/env/boot/` setzen die Pfade zusammen. *Wichtige Invariante:* Skripte **MÜSSEN** temporäre Kernel-Parameter im Namespace `.dyn` ablegen (z.B. `global.linux.bootargs.dyn.root`). Dieser `.dyn` Namespace wird von Barebox strikt geleert, bevor ein neues Skript getestet wird, um "Leaking" von toten Bootargs bei Boot-Fehlschlägen zu verhindern. |
| **Generic Targets** | Die Eingabe `boot storage.removable` zwingt Barebox dazu, alle angesteckten Laufwerke (SD-Karten/USB-Sticks) abzusuchen und zu booten. |
| **Network Boot (TFTP/NFS)** | Skripte wie `boot net` laden Devicetree und Kernel via TFTP anhand von `global.user` und `global.hostname`. Danach übergibt Barebox die exakt verhandelte IP oder den DHCP-Status via `ip=` Flag an den Kernel und mountet das Root-Filesystem als NFS! |

## 3. Bootloader Specification (blspec)
Barebox ist standard-konform zur Linux "Boot Loader Specification", dem System, das von Systemd vorangetrieben wird. Er muss also keine Custom-Skripte nutzen.

- [ ] **Auto-Discovery:** Barebox scannt alle FAT/EXT4 Partitionen nach Dateien unter `/loader/entries/*.conf`.
- [ ] **Inhalt:** Diese Config-Files definieren `title`, `version`, `linux=...` und `initrd=...`. Barebox listet diese auf und kann aus ihnen Menüs generieren oder sie direkt starten.
- [ ] **barebox Extension (`linux-appendroot`):** Das Barebox-System erweitert den BLSPEC-Standard. Ist dieser Boolean auf `true`, ignoriert Barebox statische `root=` Pfade im Config-File und injectet hardware-spezifische Device-Pfade (`PARTUUID=...`), was ein und dasselbe rootfs-Image portabel zwischen komplett anderen Platinen macht!
