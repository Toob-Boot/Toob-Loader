> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/flash-OTP.md`


# 14. One-Time Programmable (OTP) Keystore Spezifikation

Dieses Dokument spezifiziert das Verfahren, um asymmetrische Public-Keys (für die Signaturprüfung) physisch vom Bootloader-Binary zu entkoppeln und sie in unveränderlichen One-Time Programmable Sektoren (OTP) des Mikrocontrollers zu verankern.

## 1. OTP Keystore Architektur
Im Standard-Modus linkt "Toob-Boot" den generierten C-Array der erlaubten Public-Keys (`keystore.c`) einfach als `.rodata` in sein eigenes Binary. Dies kann ein Sicherheitsrisiko sein, falls der Bootloader-Speicher modifiziert wird.

- [ ] **OTP Offloading (`FLASH_OTP_KEYSTORE=1`):** Schaltet die interne Key-Speicherung ab. Der Bootloader wird extrem klein und erwartet stattdessen die Public-Keys starr an einer konfigurierten, hardware-gesicherten OTP-Speicheradresse des Chips.
- [ ] **Data Contract (OTP Header):** Die OTP Speicherbank darf nicht *nur* die roh-kaskadierten Keys enthalten. Die Bank **MUSS** exakt mit einem strukturieren **16-Byte Header** beginnen. Dieser enthält die Metadaten: Anzahl der hinterlegten Keys, Größe der jeweiligen Keys und Parsing-Informationen für den Bootloader.

## 2. Provisionierungs-Verträge (Factory Setup)
Um die MCU initial im Werk für diesen Modus bereitzumachen, stellt Toob-Boot zwei vertraglich definierte Tooling-Wege zur Verfügung:

| Provisionierungs-Methode | Tooling / Build Target | Beschreibung & Gefahren |
|--------------------------|------------------------|-------------------------|
| **1. Binäres Image (Host-Side)** | `make otpgen`<br>(Tool: `otp-keystore-gen`) | Generiert auf dem Entwickler-Rechner eine exakte `otp.bin` Abbildung des OTP-Bereichs (inklusive 16B Header + Keys). Diese Datei wird dann per JTAG/SWD (z.B. STM32CubeProgrammer) hart auf die OTP-Adresse des Chips geflasht. *Sicherste Methode.* |
| **2. Primer-Applikation (Target-Side)** | `make otp`<br>(Tool: `otp-keystore-primer`) | Generiert eine winzige C-Applikation (`otp-keystore-primer.bin`), in welche die Keys einkompiliert sind. Führt man diese App auf der MCU aus, schreibt diese Applikation via Hardware-Registern den C-Array unwiderruflich selbst in den OTP Sektor und lockt ihn. <br>**(⚠ CAUTION: Hochgefährliche Einweg-Aktion. Gehen die zugehörigen Private-Keys verloren, ist der Chip gebrickt).** |
