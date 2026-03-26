> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/HAL.md`


# 23. Hardware Abstraction Layer (HAL) Integration

Dieses Dokument spezifiziert die systemnahe Portierungsebene von Toob-Boot. Es listet alle C-Verträge, die ein Entwickler erfüllen muss, um den Bootloader auf einem völlig neuen Mikrocontroller (MCU) lauffähig zu machen. 

## 1. System Architektur & Clock-Management
Um Signaturprüfungen (RSA/ECDSA) in akzeptabler Zeit auszuführen, greift Toob-Boot tief in das Clock-Tree-Management der Hardware ein.

- [ ] **Erste Anweisung (`hal_init()`):** Bootloader-Eintrittstür. Die Implementierung **MUSS** hier den Prozessor sofort auf seine exakte Maximal-Taktfrequenz (PLL/Clock Config) hochziehen, um die Berechnungszeiten der Kryptografie bestmöglich zu verkürzen.
- [ ] **Letzte Anweisung (`hal_prepare_boot()`):** Wird Millisekunden vor dem endgültigen Absprung (Chain-Load) in das Gast-OS aufgerufen. Die Implementierung **MUSS** den Systemtakt und Peripherie hier auf den Default-Hardware-Zustand zurücksetzen, damit das OS eine saubere Reset-Umgebung vorfindet. *(Ausnahme: `WOLFBOOT_RESTORE_CLOCK=0` verbietet diese Rücksetzung).*

## 2. Der Internal Flash Vertrag (IAP)
Toob-Boot liest Flash direkt über CPU-Adressen, aber für Schreib/Löschangriffe feuert es 4 C-Aufrufe, die zwingend von der Hardware In-Application Programming (IAP) Schnittstelle abgedeckt werden müssen:

| Funktion | Vertrag (Contract) & Invariante |
|----------|---------------------------------|
| `hal_flash_unlock()` | Wird exakt **vor** jedem Write/Erase ausgeführt, um Hardware-Schutz aufzuheben. |
| `hal_flash_lock()` | Wird exakt **nach** jedem Write/Erase ausgeführt, um die IAP-Engine wieder blind zu schalten. |
| `int hal_flash_erase(address, len)` | Address ist immer an `WOLFBOOT_SECTOR_SIZE` ausgerichtet. Länge ist immer ein Vielfaches davon. Alle Sektoren im Raum müssen gelöscht werden. |
| `int hal_flash_write(...)` | Erhält `address`, `*data`, `len`. **Wichtig:** Muss Schreib-Zugriffe in JEDER Größe/Alignment akzeptieren. Falls die Hardware minimal z.B. 4 Bytes schreiben darf, **MUSS** das HAL einen Read-Modify-Write Puffer für einzelne Bytes simulieren! |

## 3. External Flash Bridge (`EXT_FLASH=1`)
Falls die Firmware-Images nicht auf den internen Chip, sondern "Out-of-Chip" (z.B. I2C/SPI) gespeichert werden, lagert Toob-Boot exakt die Partitionen `UPDATE` und/oder `SWAP` komplett aus.
*Bedingung: Dieser Modus ist mit `NVM_FLASH_WRITEONCE` inkompatibel!*

- [ ] **Die 5 External-Treiber Callbacks:** Entwickler müssen hier die Funktionen `ext_flash_write()`, `ext_flash_read()`, `ext_flash_erase()`, `ext_flash_lock()` und `ext_flash_unlock()` bereitstellen. Toob-Boot leitet IO-Zugriffe für markierte Partitionen (`PART_UPDATE_EXT`) dann komplett über diesen SPI-Treiber, anstatt intern in den Flash zu schreiben.

## 4. Hardware Dual-Bank Support (`DUALBANK_SWAP=1`)
Manche Premium-MCUs bieten exakt spiegelbildlich aufgebaute, in Hardware voneinander getrennte Flash-Bänke (Bank 1 / Bank 2). Die Architektur sieht dann einen Bank-Swap auf Platinenebene vor, statt Bytes im Speicher umzukopieren.

- [ ] **Dual-Bank Flip (`hal_flash_dualbank_swap()`):** Zündet den Hardware-Switch. Auf vielen Architekturen zwingt dies einen Hardware-Reboot ("never returns").
- [ ] **Bootloader Cloner (`fork_bootloader()`):** Zwingend nötig. Damit beim Flip der Bank der Chip wieder bootfähig ist, kopiert/klont der Bootloader sich über diese Funktion selbst in das Spiegelbild der fremden Bank. Die Funktion muss sofort und verifizierend zurückkehren, falls der Clone dort bereits exakt übereinstimmt.
