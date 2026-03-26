> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/devel/architecture.rst`

# 03. Barebox Core Architecture (PBL & FDT)

Dieses Dokument ist das architektonische Meisterwerk von Barebox. Es erklärt, wie Barebox es schafft, als plattformunabhängiges System (ähnlich wie der Linux-Kernel) direkt auf nacktem Silizium zu booten, ohne von Firmware abhängig zu sein.

## 1. Die Zweiteilige Binär-Architektur
Jedes Barebox-Image wird in der Regel aus zwei physikalisch getrennten, aber aneinandergehängten Binaries assembliert:

- [ ] **1. Prebootloader (PBL):** Ein winziges, extrem Hardware-spezifisches Stück Code. Er läuft unter brutalsten Hardware-Einschränkungen direkt aus dem kleinen On-Chip SRAM (oft nur 10-50 KiB groß). Seine *einzige* Aufgabe: Einen rudimentären C-Stack aufbauen, das große, externe DRAM der Platine initialisieren (z.B. DDR4), und den Hardware-Bauplan (FDT) bereitlegen.
- [ ] **2. Barebox Proper:** Das ist der eigentliche, riesige Bootloader. Er ist völlig plattform-agnostisch! Er erwartet, dass beim Start-Sprung das DRAM bereits funktioniert. Er entpackt sich selbst in das DRAM und fängt dann an, basierend auf dem FDT, abstrakte Treiber zu matchen und das Filesystem hochzufahren.

## 2. Flattened Device Tree (FDT) als Wahrheit
Barebox hat keine hardcodierten Treiber-Adressen. All seine Magie speist sich aus dem Devicetree.
- [ ] **FDT Inversion:** Linux erwartet, dass der Bootloader ihm den Devicetree (.dtb) in den RAM legt. Da Barebox selbst der Bootloader ist, übernimmt hier der kleine *PBL* die Rolle, dem großen *Barebox Proper* den Devicetree zu überreichen. Ohne FDT weiß Barebox Proper weder wie groß der RAM ist, noch auf welcher Bus-Adresse Hardware-Timer liegen.

## 3. BootROM Strategien & Limits
Weil die Hersteller von Mikroprozessoren (SoCs) ihre BootROMs (den absolut ersten Code nach Power-ON) dramatisch unterschiedlich bauen, muss der PBL sich wie ein Chameleon anpassen:

| BootROM Strategie | Barebox Architektur & Mechanik |
|-------------------|--------------------------------|
| **1. Built-in DCD (Direct RAM)** | (z.B. `imx_v7`): Die BootROM selbst führt Bytecode aus einem Header aus, der den DDR-Speicher sofort initialisiert. Hier kann Barebox Proper als "Single Binary" direkt komplett in den gigantischen RAM geladen und gestartet werden. Das PBL macht hier fast nichts. |
| **2. SRAM Offset Loader** | (z.B. `imx_v8`): Die BootROM kopiert blind einfach die "ersten X Bytes" der Festplatte in den Mini-SRAM. Nur das PBL passt rein. Das PBL initialisiert das DDR-RAM, liest dann **selbst** den Rest der Festplatte (Barebox Proper) ins RAM, springt dorthin und ruft sich ironischerweise ein zweites Mal selbst auf, um alles freizugeben. |
| **3. FAT Filesystem ROM** | (z.B. alte Texas Instruments OMAP): Die ROM verlangt eine Datei namens `MLO` in einer FAT-Partition, limitiert auf wenige KiB. Das PBL wird als `MLO` kompiliert, mountet das primitive FAT-Filesystem und liest das große `barebox.bin` manuell dort heraus (Multi-Binary Setup). |
