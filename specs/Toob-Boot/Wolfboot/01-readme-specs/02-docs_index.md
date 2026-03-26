> **Quelle/Referenz:** Analysiert aus `wolfBoot/README.md & wolfBoot/docs/README.md`


# 02. Architecture Documentation Index

*(Extracted from `docs/README.md`, genericized list of structural architecture topics)*

Dieses Dokument listet das grundlegende Inhaltsverzeichnis aller existierenden Architektur-Subsysteme, die in der Dokumentation beschrieben werden. Dies entspricht der funktionalen Modul-Aufteilung des "Toob-Boot" Systems:

## 1. Core System & Data Structures
- **API:** Übersicht der öffentlichen API-Schnittstellen für das Interaction-Interface.
- **Loader:** Verhalten der sekundären Loader-Stufe und der Handoff (Übergabe) an die Ziel-Applikation.
- **Interaction Library (lib):** Verwendung des Bootloaders als einbindbare Bibliothek sowie Vorgaben zum Linking.
- **Firmware Image:** Exaktes Format, Layout und Metadaten-Struktur der Firmware-Images.
- **Hooks:** Mechanismus zur Injektion benutzerdefinierter Logik in den Boot-Prozess (Custom Logic Injection).

## 2. Storage & Partitions
- **Flash Partitions:** Partitionierungsschema des lokalen Speichers.
- **Firmware Update:** Detaillierter Ablaufplan: Slot-Verwaltung, Verifikations-Abläufe, Recovery und Rollback.
- **Encrypted Partitions:** Erstellung und Verwaltung vollständig verschlüsselter Firmware/Daten-Slots.
- **Remote Flash:** Anbindung externer Flash-Bausteine (SPI/QSPI), Adress-Mapping und Zugriffs-Routinen.
- **Flash OTP:** Verwaltung von One-Time Programmable (OTP) Bereichen zur Ablage sensibler Daten.
- **ATA Security:** ATA spezifische Sicherheitsfeatures (Festplatten Lock/Unlock via Passwords).

## 3. Cryptography & Trust
- **Signing:** Workflows zur Signaturen- und Schlüsselerstellung.
- **Keystore:** Design der internen Schlüsselspeicher (Keystore) und Zugriffsstrategien.
- **Measured Boot:** Architektur zum Aufzeichnen von System-Measurements und deren Ablage (z.B. in PCRs).
- **Post-Quantum Cryptography (PQ):** Integration von PQC-Algorithmen.
- **Remote Key Management:** Nutzung von Cloud-Key-Vaults (z.B. Azure) zum Signieren.

## 4. Hardware Integrations (HAL / Targets)
- **HAL:** Überlegungen zur Architektur des Hardware Abstraction Layers und deren Portierungsprozess.
- **Targets:** Plattformspezifische Konfigurationen.
- **TrustZone (Armv8-M):** Setup zur Isolation in Secure/Non-Secure Welten.
- **Hardware-Spezifika:** (z.B. Renesas, STM32) Eigenheiten der Controller-Serien.
- **TPM:** Hardware-TPM-Integration, Attestierungs-Abläufe.
- **HSM:** Integration von Hardware Security Modulen für dezentrale Schlüssel-Operationen.

## 5. Build System
- **Compile / CMake:** Kompilierung, Make-Targets, Compiler-Optionen und Toolchain-Integration.
