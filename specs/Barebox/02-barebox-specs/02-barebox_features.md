> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/barebox.rst`

# 02. Barebox Kconfig Architecture & Runtime

Dieses Dokument extrahiert die Kern-Architektur des Build-Systems, das Startverhalten sowie die Integration der interaktiven Shell in Barebox. Es zeigt klar, dass Barebox quasi ein skalierter Linux-Microkernel ist, der auf Bootloader-Aufgaben spezialisiert wurde.

## 1. Kbuild & Multi-Board Architektur
Anstatt Custom CMake Setups nutzt Barebox knallhart die Infrastruktur von Linus Torvalds.

- [ ] **Kconfig/Kbuild Heritage:** Alle Einstellungen werden analog zum Kernel via `make menuconfig` und `Kconfig` verwaltet. Es zwingt den Aufbau von `ARCH` und `CROSS_COMPILE` Systemvariablen beim Build.
- [ ] **Multi-Image Build (`multi_image`):** Ein massiver Architekturvorteil: Ein einzelner Build-Run mit einer `defconfig` (z.B. `imx_v7_defconfig`) flusht nicht nur *ein* Binary heraus, sondern kompiliert parallel dutzende fertig gelinkte Images für dutzende verschiedene Platinen gleichzeitig in den Ordner `images/`.

## 2. Chainloading & Second-Stage Contracts
Barebox beansprucht nicht zwingend den absoluten Power-On (ROM) Vektor. Es ist darauf konzipiert, als Payload anderer Systeme zu laufen.

| Chainload Formate | Bootloader-Vertrag & Verhalten |
|-------------------|--------------------------------|
| `barebox-dt-2nd.img` | Barebox maskiert sich als "Linux Kernel". Ein First-Stage Bootloader (wie z.B. U-Boot) kann Barebox laden, ein Device Tree File (`.dtb`) in den Arbeitsspeicher legen und Barebox über klassische Kernel-Einsprünge (`bootz`, `booti`) starten. |
| **PBL / Self-Chainload** | Barebox kann sich im laufenden Betrieb einfach selbst chainloaden, um upzudaten. Der Befehl `bootm /mnt/tftp/barebox.bin` überschreibt den Live-Bootloader mit dem neuen Payload aus dem Netzwerk. |
| **Sandbox Tools** | Nutzt man als Target die Pseudo-Architektur `ARCH=sandbox`, kompiliert Barebox nicht für Bare-Metal Hardware, sondern als Linux *Userspace* Tool (`hosttools_defconfig` & `targettools_defconfig`). So lassen sich Boot-Tools und Environment-Editoren cross-kompilieren und im nativen Gast-OS betreiben! |

## 3. Die Interaktive "Hush" Shell
Die UX von Barebox im Live-Betrieb.

- [ ] **Die 3-Sekunden Regel:** Wie beim großen Bruder Linux gibt es ein standardmäßiges 3-Sekunden Autoboot Fenster. Wird dies unterbrochen, crasht man **nicht**, sondern fällt in eine voll interaktive Shell (`hush`).
- [ ] **Hardware-Aware Auto-Completion:** Ein massives Feature der Barebox Shell. Bei der Tab-Completion wird nicht dumm Text ergänzt, sondern die Shell validiert aktiv gegen Hardware: erwartet ein Befehl ein Device, ergänzt die Tab-Taste ausschließlich existierende Mount-Pfade oder registrierte **Devicetree Nodes**!
