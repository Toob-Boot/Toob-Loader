> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/multi-image.rst`

# 12. Barebox Multi-Image Support

Dieses Dokument beschreibt eine der beeindruckendsten Fähigkeiten von Barebox im Vergleich zu klassischen Bootloadern: Die Fähigkeit, aus einem einzigen Kompiliervorgang sofort maßgeschneiderte Firmwares für völlig verschiedene Mainboards zu generieren.

## 1. Das "Defconfig" Problem
Klassische Bootloader benötigen für jede noch so kleine Mainboard-Variante (z.B. RevA vs RevB, 1GB vs 2GB RAM) eine eigene Konfigurationsdatei (`defconfig`) und einen komplett eigenen Kompilierungs-Lauf (`make`). Bei Dutzenden Boards skaliert das nicht mehr und die Config-Files geraten out-of-sync. 

- [ ] **Multi-Selection:** Wenn Multi-Image Support aktiv ist, kann der Entwickler in `make menuconfig` plötzlich dutzende Boards *gleichzeitig* ankreuzen. Barebox baut am Ende in das Verzeichnis `/images/` Dutzende separate, fertig geflashte Binaries aus einem einzigen Aufruf!

## 2. Der Linker-Trick (Architecture)
Um beim Kompilieren nicht ewig zu brauchen, wendet Barebox einen brillanten Linker-Architekturtrick an:

| Komponente | Architektonische Trickserei |
|------------|-----------------------------|
| **Shared Binary (`barebox.bin`)** | Barebox baut die riesige Haupt-Software ("Barebox Proper") nur exakt **einmalig**! Aller Mainboard-spezifische C-Code wird dort hineingelinkt, aber durch If-Abfragen geschützt (`if (!of_machine_is_compatible("...")) return;`). Diese gigantische Payload ist plattformübergreifend. |
| **PBL Linker-Stripping (`ld -e`)** | Die Magie passiert beim Prebootloader (PBL). Alle PBL C-Dateien haben unterschiedliche Einsprungspunkte (Macros). Der C-Compiler baut daraus einen riesigen "PBL-Objekt-Topf". Jetzt ruft das Build-System den Linker (`ld`) schlicht 20-mal mit 20 verschiedenen Startadressen auf (`-e <entry-point>`). Der Linker wirft automatisch allen toten C-Code weg, der von diesem Startpunkt aus nicht erreichbar ist. Das Resultat: 20 winzige, hochspezifische PBL-Stubs, die jeweils an die große Shared-Binary geklebt werden! |
