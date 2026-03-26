> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/flash_partitions.md`


# 06. Flash Partitionierung & Layout-Architektur

Dieses Dokument beschreibt die strukturellen Vorgaben für die Aufteilung des Flash-Speichers und die interne State-Machine (Zustandsverwaltung) des Bootloaders. Es definiert die hochdetaillierten Checklist-Verträge für eine lückenlose Neuentwicklung.

## 1. Geometrie-Verträge (Data Contracts)
Die Flash-Geometrie unterliegt harten mathematischen Limitierungen, die in der Konfiguration als Makros definiert werden:

- [ ] **Symmetrie-Zwang (`BOOTLOADER_PARTITION_SIZE`):** Die primäre Partition (BOOT) und sekundäre Partition (UPDATE) **MÜSSEN** exakt dieselbe Größe aufweisen.
- [ ] **Swap-Dimensionierung (`BOOTLOADER_SECTOR_SIZE`):** Die Größe der SWAP-Partition **MUSS** exakt so groß dimensioniert sein, wie der *größte physische adressierte Sektor* innerhalb der BOOT- oder UPDATE-Partition. 
- [ ] **Address-Alignment:** Alle Partitionsgrenzen (`BOOT_ADDRESS`, `UPDATE_ADDRESS`, `SWAP_ADDRESS`, `SELF_HEADER_ADDRESS`) **MÜSSEN** zwingend an den physischen Start-Sektoren des Chips (Sector-Aligned) bündeln.
- [ ] **Linker-Offset:** Die finale Payload-Applikation muss ab `BOOT_ADDRESS + 256` (bzw. System-Header-Größe) verlinkt werden, da die ersten Bytes vom Bootloader-Meta-Header blockiert sind.

## 2. Trailer State-Machine (Update Lifecycle)
Der Status jedes Updates operiert über eine exakt fixierte State-Machine, am äußersten Schwanz der jeweiligen Partition.

| Trailer System-State | Beschreibung & Power-Loss Fallback Logik |
|----------------------|------------------------------------------|
| `IMG_STATE_NEW (0xFF)` | Initiale Leere. Keine Operationen anstehend. (Factory Zustand nach Erase). |
| `IMG_STATE_UPDATING (0x70)` | **Nur UPDATE:** Firmware ist signaturgeprüft und zur Übertragung auf den BOOT-Slot im nächsten Power-Cycle markiert. |
| `IMG_STATE_TESTING (0x10)` | **Nur BOOT:** Update war erfolgreich, App bootet zum ersten Mal. Rebootet das System *jetzt* (Crash/Power-Loss), springt Toob-Boot rein, liest den `TESTING` State und initiiert einen automatisierten, deterministischen Rollback. |
| `IMG_STATE_SUCCESS (0x00)` | **Nur BOOT:** Bestätigtes, lauffähiges Payload-OS. Update offiziell erfolgreich angewandt (Bootloader stoppt Überwachung). |

## 3. Sub-Sektor Anti-Tearing & Security Features
- [ ] **Sub-Sektor Tracking:** Updates tracken via 4-Bit-Blöcken (rückwärts vom State-Byte geschrieben) den exakten Sektor-Swap-Fortschritt pro physischem Schreibvorgang. Wird das System hart vom Strom getrennt, rekonstruiert die Toob-Boot HAL den genauen Punkt anhand dieser Flags und nimmt das Überschreiben nahtlos nach dem Booten wieder auf.
- [ ] **Bootloader Self-Header (`BOOTLOADER_SELF_HEADER=1`):** Optionale Flash-Partition (`SELF_HEADER_ADDRESS`), beginnend an Sektorgrenze, auf der sich ein signiertes Manifest über den Bootloader Code selbst befindet. (Dient primär für externe HSMs & Trusts, um den Bootloader validieren zu dürfen).
- [ ] **Custom Trailer Hooks (`CUSTOM_PARTITION_TRAILER`):** Zwingt den Build-Prozess dazu, die Standard Trailer-Logik ("BOOT" am Trailer-Ende) auszulassen und dem Dev C-Callbacks (`get_trailer_at`, `set_partition_magic`) freizuschalten, um proprietäre Formate zu unterstützen.
