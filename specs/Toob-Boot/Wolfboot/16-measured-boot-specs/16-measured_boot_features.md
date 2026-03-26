> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/measured_boot.md`


# 16. Measured Boot Spezifikation (TPM 2.0)

Dieses Dokument erfasst die "Measured Boot" Architektur, mit welcher Toob-Boot eine kryptografisch sichere, manipulierbare Historie (Log) des Boot-Vorgangs für das Ziel-OS in Hardware-Registern hinterlässt. Die Spezifikation basiert auf dem Checklist-Vertragsformat.

## 1. Das Konzept & Hardware Trust-Anchor
Während "Secure Boot" entscheidet, *ob* ein OS booten darf, sorgt "Measured Boot" dafür, dass das gestartete OS später unabhängig beweisen kann, *unter welchen Umständen* es gestartet wurde.

- [ ] **Hardware-Abhängigkeit (`MEASURED_BOOT=1`):** Das System integriert sich nativ in TPM 2.0 Chips. Es liest und schreibt in Platform Configuration Registers (PCR). Diese Hardware-Register können nicht überschrieben, sondern nur "erweitert" (PCR Extend) werden. Ein Reset ist nur durch physischen System-Kaltstart (Power-On) möglich.

## 2. Measurement Targets (Was wird gemessen?)
Toob-Boot kann konfiguriert werden, verschiedene Instanzen des Startprozesses in das TPM zu verankern bevor das OS übernimmt:

- [ ] **Bootloader Self-Measurement (Default):** Ist Measured-Boot aktiv, misst (hasht) Toob-Boot standardmäßig **sich selbst** und schreibt das Ergebnis in einen PCR. Damit kann das startende Ziel-OS den TPM befragen und lückenlos nachweisen, dass der vorgeschaltete Bootloader intakt und unverändert war.
- [ ] **Application Measurement (`MEASURED_BOOT_APP_PARTITION=1`):** Schaltet Toob-Boot in den Legacy-Modus. Anstatt sich selbst zu messen, hasht es die Payload der Applikation (die `BOOT` Partition) und extended diesen Hash in das TPM, bevor es in die Applikation springt.

## 3. PCR Register Zuweisungs-Verträge
Damit das spätere Ziel-OS (z.B. Linux IMA oder Windows Bitlocker) beim Auslesen des TPMs nicht kollidiert, **MUSS** der Entwickler das genutzte Register via Makro exakt deklarieren.

| Konfigurations-Makro | Empfohlene Index-Werte | Architektur-Eignung / Bemerkung |
|----------------------|------------------------|---------------------------------|
| `MEASURED_PCR_A=16` | **16** | **Development Only.** Für Test-Routinen (DEBUG) reserviert, nicht für Produktion nutzen. |
| `MEASURED_PCR_A=[0-15]` | **0 bis 11** | Empfohlen für **Bare-Metal / RTOS**. Die Register 0-11 decken Core-Roots, BIOS, Master Boot Records (MBR) und State-Transitions ab. Keine Kollision in einfachen Systemen. |
| `MEASURED_PCR_A=[12-15]` | **12 bis 15** | Empfohlen für **Rich OS (Linux / Windows)**. Diese PCRs sind als "Available for any use" spezifiziert und verhindern Kollisionen mit Microsoft Bitlocker (PCR 11), Linux IMA oder TEE-Systemen (PCR 17-23). |

*(Achtung: Die DRTM und Trusted OS PCRs (17 bis 23) sollten vom Bootloader in Produktion keinesfalls berührt werden, da sie von TrustZone-Engines verriegelt werden).*
