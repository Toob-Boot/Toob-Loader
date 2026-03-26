> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/STM32-TZ.md`


# 25. ARM TrustZone-M (STM32-TZ) Architektur

Dieses Dokument fasst die harte Speicherschutz-Infrastruktur für ARMv8-M Architekturen (wie den STM32L5/H5) zusammen. TrustZone separiert das System physisch in eine hochsichere "Secure" Welt (Toob-Boot) und eine feindliche "Non-Secure" Welt (Betriebssystem / Firmware).

## 1. Non-Secure Callable (NSC) APIs
Wenn `TZEN=1` und `WOLFCRYPT_TZ=1` gesetzt sind, schottet Toob-Boot seinen kompletten Krypto-Zustand ab. Damit das Gast-Betriebssystem dennoch Verschlüsselungen nutzen kann, öffnet Toob-Boot strukturierte Brücken (NSC APIs) für das OS.

| API Flag | API Standard | Beschreibung & Vertrag |
|----------|--------------|------------------------|
| `WOLFCRYPT_TZ_PKCS11` | PKCS11 Interface | Stellt dem OS eine vollständige PKCS11-Schnittstelle zur Verfügung. Das OS kann Toob-Boot auffordern, Payload z.B. für TLS-Verbindungen zu ver- und entschlüsseln. Die dafür nötigen Keys liegen hermetisch gesichert im "Secure Flash" und werden niemals in den RAM der Non-Secure Applikation geladen. |
| `WOLFCRYPT_TZ_PSA` | PSA Crypto API | Verhält sich exakt wie das PKCS11 Flag, nutzt jedoch das ARM-natürliche Platform Security Architecture (PSA) API Protokoll für Signatur und Storage. |
| (Auto via PSA) | PSA Attestation | Sobald PSA aktiv ist, kann das Gast-OS über die NSC API einen DICE hardware-verankerten Beweis (COSE_Sign1 Token) anfordern (Siehe Item 19: DICE). |

## 2. Speicherarchitektur & Interrupt-Alignment
Ein extrem kritischer Hardware-Vertrag: Bei ARM Cortex-M33 Cores hängt die Größe des Boot-Headers (`IMAGE_HEADER_SIZE`) **zwingend** an der Anzahl der physischen Hardware-Interrupts! Das muss beim Signieren streng beachtet werden!

- [ ] **Vector Table Alignment Logic:** ARM verlangt, dass die Interrupt-Tabelle auf die nächste *Potenz von 2* aligned ist.
- [ ] **Rechenbeispiel (STM32H5):** Der Chip hat 146 Interrupts. Die nächste magische 2er-Potenz ist 256. Jeder Interrupt-Vektor verbraucht 4 Bytes. Das ergibt `256 x 4 = 1024 Bytes`.
- [ ] **Signage Constraint:** Folglich **MUSS** das Tooling beim Signieren einer Target-App den Header künstlich aufblähen: `IMAGE_HEADER_SIZE=1024 sign --sha256 ...`.  Fehlt dieser C-Vertrag, crasht der Core sofort beim Versuch, den Interrupt-Vektor der Ziel-Applikation zu mappen.

## 3. Hardware Deployment & Option Bytes
TrustZone ist kein reines Software-Feature. Das pure Silicon des STM32 muss geflasht und umkonfiguriert werden.

- [ ] **Option Bytes Tooling:** Das Script `tools/scripts/set-stm32-tz-option-bytes.sh` liest die Bootloader-Konfiguration und zwingt den Microcontroller via `STM32CubeProg` physisch auf Board-Level in den TrustZone State (Memory Protection).
- [ ] **Flash-Separation:** Der Bootloader `wolfboot.bin` wird in einen komplett anderen Adressraum geflasht (z.B. die Secure Bank `0x0C000000`) als das unsichere Gast-Betriebssystem (z.B. Non-Secure Bank `0x08040000`).
