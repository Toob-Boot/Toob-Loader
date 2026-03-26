> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/remote_flash.md`


# 12. Remote Flash Spezifikation (UART Extension)

Dieses Dokument erfasst die hochspezialisierte Funktion des Bootloaders, physisch nicht-existente Flash-Speicher über serielle Schnittstellen (UART) zu emulieren. Alles ist wie gefordert in Checklist/Table Verträge übersetzt.

## 1. Architektonisches Konzept
Das Toob-Boot System erlaubt es, in asynchronen Multi-Prozessor Architekturen (z.B. ein kleiner Mikrocontroller neben einem fetten Linux-SoC) die speicherfressenden `UPDATE` und `SWAP` Partitionen physisch auf den benachbarten Linux-Chip auszulagern und via UART-Leitung transparent anzusprechen.

- [ ] **Transparentes Mapping:** Bootloader-Logik (State-Machine, Rollback, Anti-Tearing Flags) behandelt die Remote-Partition *exakt genau so*, als handele es sich um einen lokalen internen/SPI Flash. Das Routing geschieht verdeckt im HAL.

## 2. Compile-Time Contracts
Damit die UART-Auslagerung greift, müssen zwingende Makros im Build-System verschränkt werden:
- [ ] **`EXT_FLASH=1`**: Das Basis-Subsystem für ausgelagerte State-Machines muss aktiviert sein (Prä-Requisit).
- [ ] **`UART_FLASH=1`**: Aktiviert den dedizierten UART-Treiber-Link auf die External-Flash Schnittstelle.

## 3. Hardware Abstraction Layer (HAL) Verträge
Ein Entwickler **MUSS** auf C-Ebene im HAL-Layer (z.B. in `hal/uart`) genau drei atomare Funktionen implementieren, damit der Bootloader die Hardware-Schnittstelle ansprechen kann. Fehlt eine, schlägt der Linker Alarm:

| C-Funktionssignatur | Anforderung / Vertrag |
|---------------------|-----------------------|
| `int uart_init(uint32_t bitrate, uint8_t data, char parity, uint8_t stop)` | Initialisiert die physischen Pins und Baudrate der seriellen Controller-Einheit. |
| `int uart_tx(const uint8_t c)` | Blockierender oder gebufferter Sendevorgang für exakt 1 Byte auf die TX-Leitung. |
| `int uart_rx(uint8_t *c)` | Empfangsvorgang von exakt 1 Byte vom RX-Puffer. Muss Timing-Garantien bedienen. |

## 4. Host-Side Server Vertrag (Daemon)
Da Toob-Boot nur simple Streams abstrahiert, benötigt das Empfänger-SoC (z.B. Linux) zwingend eine Gegenstelle.
- [ ] **UART Flash Server:** Der externe Partner-Chip, der den Speicher zur Verfügung stellt, muss einem proprietären Protokoll gehorchen. Hierfür stellt Toob-Boot einen Beispiel-Daemon (`tools/uart-flash-server`) bereit, der die Flash-Sektor Read/Write/Erase Kommandos über die serielle Line-Discipline dekodiert und stumpf in eine Flatfile (`.bin`) auf das EXT4-Dateisystem des Host-OS schreibt.
