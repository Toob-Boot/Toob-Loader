> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/Loader.md`


# 08. Bootloader Entry-Point & Staging Architektur

Dieses Dokument beschreibt die strukturellen Komponenten des Payload-Handlings (Staging) und die Loader-Mechanismen, mit denen "Toob-Boot" auf verschiedene RAM/Flash-Architekturen reagiert.

## 1. Core Loader- & Updater-Delegation (Components)
Das System nutzt ein modulares Entry-Point-Design, bei dem ein Haupt-Loader je nach Plattform die spezifische Update-Engine (Updater) verwendet:

- [ ] **Default Loader (`loader.c`):** Der klassische Einsprungpunkt nach dem Reset-Handler. Orchestriert den Secure-Boot Verifizierungs-Prozess und delegiert Schreib-/Update-Operationen an ein spezifisches _Updater_ Backend.
- [ ] **Flash-Based Updater (`update_flash.c`):** Das Standard-Backend. Liest Firmware aus der UPDATE-Flash-Partition, schreibt auf die BOOT-Flash-Partition (Kopier/Swap Operationen im physikalischen Non-Volatile Memory).
- [ ] **RAM-Based Updater (`update_ram.c`):** Alternativer Updater für Architekturen, die Firmware-Komponenten im Cache/RAM entpacken oder verwalten, bevor geflasht oder ausgeführt wird.
- [ ] **Hardware-Assisted Updater (`update_flash_hwswap.c`):** Delegierter Updater, der dedizierte Speicher-Controller Switches (Dual-Bank Hardware Swap wie in Item `05` evaluiert) ansteuert, um Software-Sektor-Copies zu vermeiden.

## 2. Multi-Stage Loading (Stage 1 Loader)
Für Hardware-Plattformen, bei denen der Flash **nicht** memory-mapped (XIP - eXecute In Place) an den CPU-Bus angebunden ist (z.B. externe NAND Flashes wie beim PowerPC e500v2), operiert das System mit einem _Stage-1 Loader_ Mechanismus.

- [ ] **Stage 1 Fallback (`loader_stage1.c`):** 
  - Eine extrem kleine (z.B. 4KB) Bootstrap-Payload, die beim Kaltstart initial ins RAM der CPU kopiert/gebootet wird.
  - Ihre einzige Aufgabe ist es, das eigentliche Toob-Boot Binary aus dem nicht memory-mapped Flash via SPI/Treiber in den Arbeitsspeicher zu kopieren und anschließend per Pointer-Jump in den echten Bootloader abzuspringen (Chain-Load).

### Stage 1 Memory-Spezifikationen (Makros)
Um den Stage-1 Loader zu kompilieren (Target `make stage1`), müssen folgende Verträge zwingend bedient werden:

| Konfigurations-Makro | Beschreibung der Speicherzuweisung |
|----------------------|------------------------------------|
| `BOOTLOADER_STAGE1_SIZE` | Hard-Limit der Größe des initialen Stage-1 Loaders (Muss auf die Hardware-Limitierung der Boot-ROMs angepasst sein). |
| `BOOTLOADER_STAGE1_FLASH_ADDR` | Die physische absolute Adresse auf dem Target-ROM/Flash, auf welcher das Stage-1 Binary zum Kaltstart-Zeitpunkt liegt. |
| `BOOTLOADER_STAGE1_BASE_ADDR` | Die RAM-Adresse, auf welcher die MCU den Stage-1 Loader initial zum Ausführen fallen lässt. |
| `BOOTLOADER_STAGE1_LOAD_ADDR` | Die RAM-Zieladresse, zu welcher der Stage-1 Loader das **echte** Toob-Boot Binary aus dem Flash kopieren soll. |
| `BOOTLOADER_LOAD_ADDRESS` | Die RAM-Zieladresse, an der letztendlich die finale "User Applikation" abgelegt und ausgeführt werden muss. |
