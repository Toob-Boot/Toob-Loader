> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/Renesas.md`


# 26. Renesas Hardware Security (TSIP/RSIP/SCE)

Dieses Dokument spezifiziert die komplexe Integration der kryptografischen Hardwaremodule der Renesas Microcontroller (RX, RA, RZ). Renesas verbietet strikt die Nutzung von "rohen" Schlüsseln im Speicher. Jeder Schlüssel muss über eine proprietäre Infrastruktur kryptografisch gekapselt ("Key Wrapping") werden.

## 1. Das Key Wrapping Modell (SKMT)
Um Public-Keys (für Signaturprüfung) oder AES-Keys (für Firmware-Entschlüsselung) im System nutzbar zu machen, muss zwingend ein 4-stufiger Offline-Prozess über das Security Key Management Tool (SKMT) absolviert werden.

| Schritt | Aktion | Kryptografischer Vertrag |
|---------|--------|--------------------------|
| **1. Factory PGP Exchange** | PGP Key Exchange | Kommunikation mit Renesas. Man erhält deren Factory PGP-Public Key (max RSA-3072). |
| **2. UFPK Generierung** | `random(32)` | Der Entwickler generiert einen zufälligen 32-Byte User Factory Programming Key (UFPK). |
| **3. UFPK Verschlüsselung** | GPG Encryption | Der UFPK wird mit dem Renesas PGP-Key kryptografisch verschlüsselt. |
| **4. Cloud Wrapping** | Renesas DLM Portal | Das verschlüsselte Paket wird an das Portal gesendet. Die Cloud verknüpft es mit dem siliconspezifischen *Hidden Root Key (HRK)* des Microcontrollers und schickt ein "Wrapped-UFPK" Profil zurück. |

## 2. Bootloader Key Binding
Mit dem zurückkehrenden Wrapped-UFPK kann die Entwicklung nun sicher (offline) weitergehen.

- [ ] **Public Key Encapsulation (`PKA=1`):** Das SKMT CLI Tool nutzt den Wrapped-UFPK, um den generierten ECDSA P-256/384 Public-Key zu verschlüsseln. Daraus entsteht eine Motorola S-Record HEX-Datei (`.srec`) oder eine `key_data.c`. Das C-Array enthält niemals den echten Key, sondern nur den verschlüsselten Blob.
- [ ] **Flash Installation Address:** Das generierte Public-Key `.srec` Hexfile **MUSS** physisch an die exakte Adresse `0xFFFF0000` (Default) geflasht werden. Dies wird vertraglich in der `user_settings.h` unter `RENESAS_TSIP_INSTALLEDKEY_ADDR` und im Hal-Linker-Script (`hal/rx72n.ld`) erzwungen. Toob-Boot liest blind von diesem Vektor.

## 3. Firmware Encryption Contract
Möchte das System Firmware-Updates verschlüsselt verteilen, gilt auch hier das Wrapping-Gesetz.
- [ ] **Wrapped AES-Keys (`ENCRYPT_WITH_AES256=1`):** Es wird ein 32-Byte AES Schlüssel + 16-Byte IV konfiguriert und durch das SKMT Tool gejagt. Offset: Das daraus resultierende `.srec` wird zwingend mit einem Offset von `0x100` hinter den Publik-Key geflasht (`RENESAS_TSIP_INSTALLEDKEY_ADDR + 0x100`).

## 4. Hardware Lockdown in Produktion
Um die Architektur gegen JTAG-Hacker abzusichern, hat Toob-Boot für Renesas strikte Invarianten verfasst, die während der Produktion im Chip verriegelt werden müssen:
- [ ] **Serial Programmer:** Der SPI/JTAG Debugger Pin muss hardwareseitig deaktiviert werden (`SPCC.SPE = 0`).
- [ ] **Flash Access Window (FAW):** Das FAW Register muss genullt werden (`FAW.FSPR = 0`). Diese Aktion ist "One-Way" und vernichtet die Möglichkeit, Schreib-Rechte jemals wieder zurückzuerlangen.
- [ ] **ROM Code Protection & Trusted Memory:** Die ROM Protection (`ROMCODE.CODE[31:0]`) muss auf 0 stehen. Zusätzlich muss `TMEF[2:0] = b000` gesetzt werden. Dies sperrt alle lesenden RAM-Zugriffe auf die physischen Blöcke 8 und 9, wo Renesas heimlich seine Schlüsseloperationen ausführt.
