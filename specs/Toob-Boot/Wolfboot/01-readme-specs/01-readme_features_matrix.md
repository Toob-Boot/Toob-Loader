> **Quelle/Referenz:** Analysiert aus `wolfBoot/README.md & wolfBoot/docs/README.md`


# 01. Bootloader Feature Support Matrix

Da für das "Toob-Boot" Secure Bootloader System Features je nach Architektur oder Controller variieren können (Hardware-Beschleunigung, Dual-Bank Handling etc.), bildet diese Matrix alle im Original-Root-Dokument erwähnten Kompatibilitäten und Krypto-Algorithmen detailliert ab. Sie ist vollkommen hardware-abstrakt beschrieben.

## 1. Crypto Algorithms Support Matrix

| Algorithmus/Krypto-Feature | Beschreibung & Spezifikationen | Implementierung (Hardware/Soft) |
|----------------------------|--------------------------------|---------------------------------|
| **Ed25519** | Standard Base Signatur (Default in Tooling). | Software (Crypto-Engine) / Hardware |
| **ECC-256, 384, 521, Ed448**| Erweiterte Signaturprüfungen. | Software / Hardware |
| **RSA-2048, 3072, 4096** | RSA Signatur-Verifikation. (RSA4096 nutzt interne SP Math). | Software / Hardware |
| **SHA-3, SHA2-384** | Hash-Funktionen für Image-Integrität & Measured Boot. | Software (Hardware accel. z.B. CSU-Engines)|
| **AES-128, AES-256** | Verschlüsselung (E2E) der Update-Archive (Encrypted Updates).| Software (ARMASM accel.) / Hardware |
| **LMS / HSS** | Post-Quantum Cryptography (Stateful Hash-Based). | Native Einbindung der Crypto-Library |
| **XMSS / XMSS^MT** | Post-Quantum Cryptography (Stateful Hash-Based). | Native Einbindung der Crypto-Library |
| **ML-DSA** | Post-Quantum Signaturverfahren. | Native Einbindung der Crypto-Library |
| **Hybrid Authentication** | Kombination aus einem Post-Quantum Schema plus ECC oder RSA. | Native Einbindung |

---

## 2. Hardware Architecture & MCU Support Matrix

**Legende:**
- **TZ**: TrustZone-M (Secure/Non-Secure Isolation)
- **HW-Crypto**: Unterstützt spezifische Hardware-Cryptographic Module.
- **DB**: Dual-Bank Support in Hardware (Flash Swap ohne expliziten Software-Copy via Address-Swapping).
- **MPU**: Memory Protection Unit Support (Speicherzugriffsschutz).

| Architektur (Core) | Target / MCU | Besondere Hardware-Features |
|--------------------|--------------|-----------------------------|
| **ARM Cortex-M0/M4/A** | Generic | MPU Support, ARMASM, ARMv8 64-bit Linux staging/device tree. Unaligned access support. |
| **ARM Cortex-M33** | Generic | TrustZone (TZEN), Secure-Mode Supervisor via PKCS11. |
| **x86_64** | Generic, Intel TigerLake | UEFI EFI-app, FSP (Firmware Support Package), GDT, PCI enumeration, SATA lock, Multiboot2 Payload Support. |
| **RV32 RISC-V** | SiFive HiFive-1 (FE310) | |
| **PowerPC 32/64** | NXP T2080, QoriQ P1021, T1084 | Echtzeit OS (DEOS) Integration, PIC execution, RAM boot, eSPI TPM Support, eLBC NAND, MMU fähig. |
| **Cortex-R/R5** | Generic, TI TMS570LC435 | `NVM_FLASH_WRITEONCE` Support für Append-Only Speicherung. |
| **STMicroelectronics** | STM32L0, G0, C0, F103 | G0 Secure memory mode. |
| **STMicroelectronics** | STM32F4, F411 | Spezifischer Clock-Tree config (multi-speed). |
| **STMicroelectronics** | STM32F7 | **DB** (Hardware-assisted dual-bank), Cache handling routines. |
| **STMicroelectronics** | STM32H7, U5, H5 | **DB**, OTP Primer (One-Time Programmable Keystore), TrustZone-M (H5), QSPI/OCTOSPI Support, Flash Error Correction. |
| **STMicroelectronics** | STM32WB55 | **HW-Crypto** (PKA - Public Key Accelerator). |
| **STMicroelectronics** | STM32L4, L5xx | **DB** (Dual-bank). |
| **NXP i.MX-RT** | RT1060, RT1050, RT1064, RT1040, RT1061 | HAB (High Assurance Boot) Support, DCACHE invalidation, spezieller DCD (Device Configuration Data). |
| **NXP LPC / Kinetis** | LPC54xx, MCXA153, MCXW716, Kinetis K82F | **HW-Crypto** (PKHA Accelerator). |
| **Nordic Semiconductor**| nRF52, nRF5340 | SPI Driver Modus, TrustZone-M Modus (nRF5340). |
| **Renesas** | RX72N, RA6M4, RZ/N2L, RX-Family | **HW-Crypto** (TSIP, SCE, RSIP-Engines), Encrypted Updates direkt via Hardware-Kryptoanbindung. |
| **Xilinx** | Zynq+, UltraScale+ (ZynqMP) | eFuse (PUF-Hardware zur Unique Key Generation), QSPI DMA, CSU Hardware SHA3 Engine, FIT image support. (JTAG runtime Steuerung). |
| **Infineon** | AURIX TriCore TCxxx | Multi-sector write operations per HAL Modul gekapselt. |
| **Cypress** | psoc6 | **HW-Crypto** Accelerator nativ eingebunden. |
| **Microchip** | ATSAM-R21, ATSAM-E51, ATSAMA5D3 | **DB** (Hardware Bank Switch). |
| **Microchip** | PIC32CX, PIC32CZ | Base Support. |
| **Raspberry Pi** | Raspberry Pi (A), Pi Pico 2 (RP2350) | UART Support, Pi Pico ARM Cortex-M33 mit nativem TrustZone Support. RAM Cache für beschleunigte Flash writes. |
| **Vorago** | VA416x0 | JTAG / Bootflags Support via custom HAL. |

---

## 3. Storage & Interface Hardware Feature Matrix

| Subsystem / Interface | Feature / Controller Limitierung | Target Kompatibilität / Anwendungsfall |
|-----------------------|----------------------------------|----------------------------------------|
| **SPI / QSPI / OCTOSPI**| Externe Flash-Anbindung (Read, Update Partition). | STM32, Zynq, Nordic nRF52. Kann Updates via SPI Memory Execution aus externem RAM triggern. |
| **UART Serial Link** | Remote Update Partition via UART Buffer empfangen. | STM32L0x3, Raspberry Pi (Remote Update Demos). |
| **eSPI / LPC** | Low Pin Count interface für TPM 2.0 Hardwares. | NXP QoriQ (PowerPC Plattformen). |
