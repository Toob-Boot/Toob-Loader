# Provisioning & Device Onboarding Guide

> Zwingend vorgeschriebene Prozesse zur Vorbereitung unbeschriebener Silizium-Chips für die Produktionsebene.

Um P10 und CRA Compliance zu garantieren, ist Code-Sicherheit alleine nutzlos, wenn die MCU Root-of-Trust (RoT) offen steht. Dieser Prozess muss auf der Factory-Linie durchlaufen werden.

## 1. Hardware Lifecycle Management (eFuses / OTP)
Bevor `Toob-Boot` auf den Chip (MCU) geschrieben wird, müssen die Hardware-Sicherungen der MCU permanent (unwiderruflich) durchgebrannt werden:

1. **JTAG / SWD Deaktivierung**: Der Debug-Port MUSS physikalisch getrennt oder per Passwort im BootROM gelockt werden. GAP-23: Die eFuse-Brennvorgänge sind extrem power-sensibel. Der Flasher-Client MUSS zwingend eine Retry/Rollback Logik mit Zero-Verification implementieren, um halb gebrannte (partial atomicity failure) Key-Bits auf der Produktionslinie sofort zu erkennen und zu markieren (Binning/Ausschuss).
2. **Flash Readout Protection (RDP)**: STM32 RDP Level 1 (besser Level 2). Die interne Firmware darf nicht mehr dumpbar sein.
3. **Burn Public Key**: Der primäre Ed25519 Public Key (32 Byte) wird in das Hardware-OTP Field eingebrannt. Er dient als unerschütterlicher Anker.
4. **Burn DSLC**: Ein "Device Specific Lock Code" (Zufallswert, Factor 1) wird eingebrannt, den nur der Hersteller im Fleet-Management speichert. Nötig für das Serial-Rescue Auth-Token. GAP-45: Zusätzlich kann über das gleiche Ed25519 Auth-Token ein persistenter RMA-Mode (Return Merchandise Authorization) freigeschaltet werden, welcher die JTAG-eFuses logisch (via OTP-Lock) für den einmaligen OEM-Refurbishment-Prozess temporär wieder entriegelt (sofern die MCU Hardware das unterstützt).

## 2. Toobfuzzer3 Kalibrierung
Bevor das Bootloader-Binary final kompiliert wird, durchläuft die Zielhardware die `toobfuzzer3` Pipeline:
- Der Fuzzer ermittelt die **exakte** `sector_size`, `max_erase_time_us`, und `write_alignment`.
- Er ermittelt den VDD-Drop (Brownout-Penalties) für das `min_battery_mv` Limit.
- Generierung des `aggregated_scan.json`.

## 3. Kompilierung (Manifest Compiler)
Das `aggregated_scan.json` File wird in den Manifest-Compiler geworfen. 
Dieser webt die Limits als C-Makros (`#define`) sicher in die Datei `chip_config.h` ein. 

Das fertig kompilierte Toob-Boot Binary (`.elf` / `.bin`) ist damit 100% maßgeschneidert auf Varianzen in genau dieser Platinen-Charge.

## 4. Final Flash & Handoff
Das Bootloader-Image wird bei Adresse `0x0000` (bzw. je nach Architektur) geflasht.
Danach sendet die Factory über einen Bootloader-Command das Initial-OS (Golden Image). Der Bootloader bestätigt sich selbst und die Hardware darf im Markt ausgerollt werden (Lifecycle "SEALED").
