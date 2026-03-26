> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/driver-model.rst`

# 18. Barebox Device Driver Model

Dieses Dokument beendet unsere Reise durch die Architektur von Barebox. Es zeigt, wie der Bootloader die Hardware-Komponenten, die er (zumeist über den Devicetree) gefunden hat, verwaltet und wie er mit langsamer Peripherie umgeht, um extrem schnelle Bootzeiten (Fastboot) zu erreichen.

## 1. On-Demand Device Detection
Typische PC-BIOS oder auch U-Boot Derivate initialisieren beim Einschalten oft stur alle USB-Ports, Netzwerk-PHYs und SD-Karten-Slots. Das kostet wertvolle Sekunden.

- [ ] **Lazy Probing (`detect`):** Barebox geht einen weitaus moderneren Weg. Es initialisiert primär nur den Kern-SoC. Langsame Peripherie (USB-Busses, MMC/SD-Controller, SATA) wird zwar erkannt, aber *nicht* geprobt/gestartet! Sie liegen schlafend im System (`detect -l`). 
- [ ] **Manueller Trigger:** Erst wenn ein Boot-Skript (oder der User) explizit Dateien von der SD-Karte laden möchte, muss es vorab zwingend den Befehl `detect mmc0` absetzen. Erst in dieser Millisekunde läuft der Treiber (Driver Probe) wirklich an, dreht den physikalischen SD-Bus auf und liest die Partitionen ein. Dies garantiert Bootzeiten im Millisekundenbereich, wenn man die Peripherie für diesen spezifischen Boot-Pfad gerade nicht braucht.

## 2. Das Objektorientierte Parameter-System
Barebox verbindet sein Shell-Environment (siehe Batch 08) extrem clever mit den C-Treibern der Hardware. Geräte ("Devices") sind in der Shell effektiv Objekte.

| Mechanismus | Eigenschaften & Verträge |
|-------------|--------------------------|
| **Device Variables** | Jedes im System registrierte Device exportiert seine Einstellungen als beschreibbare Shell-Variablen. Der Netzwerk-Treiber für den Port 0 (`eth0`) erzeugt magisch die Variable `${eth0.ipaddr}`. Ein Skript kann diese Eigenschaft simpel per Assignment konfigurieren (`eth0.ipaddr=192.168.1.1`). |
| **Type-Safety** | Im Gegensatz zu Dummen Bash-Skripten, wo alles nur Strings sind, sind Barebox Device Parameter strikt "Typed" (z.B. Integer, Enum, IP-Address, Boolean). Weist ein Skript den fehlerhaften String `eth0.ipaddr="Test"` zu, schlägt das Assignment sofort mit einem Fehler fehl (`Invalid argument`), da der darunterliegende C-Treiber die Zuweisung verweigert. Dies verhindert fehlerhaft konfigurierte Hardware durch Tippfehler in Shell-Skripten. |
