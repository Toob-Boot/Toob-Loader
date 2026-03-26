> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/Targets.md`


# 05. Hardware Targets & Architektur-Constraints

Dieses Dokument fasst die plattformspezifischen Sicherheits- und Architekturverträge zusammen, in hochdetaillierter Checklist-Form. Anstatt jede MCU-Generation einzeln aufzulisten, extrahieren wir die strukturellen Hardware-Fähigkeiten, die das Toob-Boot Projekt nativ unterstützen muss.

## 1. Hardware Security & Memory Isolation (Verträge)
- [ ] **TrustZone-M Isolation (`TZEN=1`):** Das System muss auf Cortex-M33 Layouts (z.B. STM32L5/U5, nRF5340) operativ trennen:
  - Bootloader Code und asymmetrische Keys werden physikalisch in das *Secure Memory* Segment (über Option Bytes z.B. `SECWM1`) geflasht.
  - Ziel-Applikation und UPDATE Partition liegen physisch im *Non-Secure Memory* (`SECWM2`).
- [ ] **Secure Hide Protection (Code-Sichtbarkeitsschutz):** Auf Systemen ohne TrustZone (STM32G0/C0) nutzt der Bootloader Controller-spezifische Sicherheitsregister (`FLASH_CR:SEC_PROT`), um:
  - Seine eigenen Speichersektoren kurz vor dem Jump-to-App physisch gegen Lese-/Schreibzugriffe hart abzuriegeln.
  - *Vertrag:* Diese Abriegelung erfordert zwingend RAM-Code Execution (`RAM_CODE=1`), da das Ausführen des Sperr-Befehls aus dem Flash sonst sofort zum Hardfault führt.

## 2. Speicher-Controller Optimierungen
- [ ] **Hardware Dual-Bank Swapping (`DUALBANK_SWAP=1`):** Besitzt die MCU Architektur echte getrennte Flash-Banken (z.B. STM32F7 / STM32L5), überspringt Toob-Boot das langsame bitweise Software-Sektor-Swapping und delegiert den Slot-Tausch an den Speicher-Controller per Register-Umschaltung über Adress-Mapping.
- [ ] **Sub-Sector und Architektonisches Alignment:** Die Konstante `BOOTLOADER_SECTOR_SIZE` orientiert sich im Bootloader-Code **nicht** an der durchschnittlichen Size, sondern **immer** zwingend an der größten adressierten Swap-Hardware-Blockgröße der MCU.

## 3. Prozessorarchitektur-Scope (Unterstützte Target-Typen)
Die HAL muss das Abstraktions-Set so halten, dass diese Target-Kategorien lauffähig bleiben:

| Prozessorarchitektur | Target-Beispiele / Eigenarten |
|----------------------|-------------------------------|
| **ARM Cortex-M Serie** | (M0, M3, M4, M7, M23, M33). Bietet Option Bytes, TrustZone, FPU Integration. |
| **ARM Cortex-A Serie** | A53 Controller (Raspberry Pi, Zynq Ultrascale) mit komplexer MMU (Memory Management Unit). |
| **RISC-V (32/64-Bit)** | SiFive HiFive1, Microchip PolarFire SoC (4x App Cores, 1x Monitor Core Layout). |
| **PowerPC (PPC)** | NXP QoriQ Serien. |
| **Intel x86-64** | UEFI/EFI und Intel Firmware Support Package (FSP) Setups. |

## 4. Debug-Hooks & Exception Handling
- [ ] **GDB Vector Stack-Relocation:** Da der Payload-Code nach einem Offset startet, liefert der Bootloader deterministische Memory-Maps für Hardware-Debugger (JTAG/SWD). Beispielsweise kann ein GDB-Server via `add-symbol-file` an dem Header-Offset der Applikation nahtlos breaken und weiter debuggen.
- [ ] **Runtime-Fault Tearing:** Bei Abbruch (Crash) während des TrustZone Aufrufs oder beim Bootloader RAM-Execution Switch müssen die Hardware Relocations 100% transaktionell abgesichert sein.
