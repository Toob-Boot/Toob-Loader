> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/ubi.rst`

# 11. Barebox UBI / UBIFS Storage

Dieses Dokument spezifiziert das Handling von "Unsorted Block Images" (UBI). UBI ist die De-Facto Standard-Schicht im Linux-Ökosystem, um Lebensdauer und "Wear-Leveling" (Verschleißausgleich) auf blanken NAND/NOR Flash-Chips zu handhaben.

## 1. UBI API Contracts (The Anti-Bricking Defense)
Barebox spiegelt die exakten UBI Kommandozeilen-Tools des Linux-Kernels (`ubiformat`, `ubiattach`, `ubidetach`). 

- [ ] **Erase Counter Preservation:** Barebox warnt eindringlich davor, klassische `erase`-Befehle auf einem UBI-vorbereiteten Flash-Baustein auszuführen! Der physikalische `erase`-Befehl zerstört unweigerlich die "Erase Counters" im Flash-Header (welche mitzählen, wie oft ein Hardware-Block schon genullt wurde). Ohne diese Counter kann der Algorithmus die Abnutzung nicht steuern und der Flash stirbt frühzeitig. Es MUSS zwingend `ubiformat` zum Löschen verwendet werden!
- [ ] **Hardware-Awareness:** Im Gegensatz zu dummen Block-Devices (wie SD-Karten) muss der Entwickler das Image (mittels `mkfs.ubifs`) offline kompilieren und dabei die harten physikalischen Limitierungen des Speichers genau kennen (z.B. `min-io-size=512`, Logical Erase Block Sizes etc., abrufbar über `devinfo ubi`). 

## 2. Boot-Zeit Optimierung: UBI Fastmap
Da UBI normalerweise beim Start (`ubiattach`) *jeden einzelnen Block* des Flash-Bausteins einlesen muss (was bei Multi-Gigabyte NANDs Sekunden dauern kann), implementiert Barebox das "Fastmap" Feature aus Linux 3.7.

| Fastmap Mechanismus | System-Verträge & Constraints |
|---------------------|-------------------------------|
| **Index-Header** | Fastmap speichert ein gecachtes Inhaltsverzeichnis zwingend in den allerersten Blöcken des Flashs. Dadurch bootet das System in Millisekunden statt Sekunden. |
| **Aktivierungs-Ritual** | Fastmap bricht zusammen, wenn man RAW-Images blind von außen auf den Chip flasht (weil es den ersten freien PEB-Block nicht findet). Der harte Vertrag lautet: Um Fastmap zu aktivieren, **muss** Barebox nach dem Formatieren *einmalig* `ubiattach` und danach sofort `ubidetach` aufrufen. Erst in der Sekunde des Detach-Vorgangs wird der rettende Fastmap-Header auf das Silizium geschrieben! |
