> **Quelle/Referenz:** Analysiert aus `barebox/Documentation/user/security.rst`

# 15. Barebox "Verified Boot" Architecture

Dieses Dokument destilliert die harten Verträge für ein echtes "Verified Boot" Setup. Nur weil man Signaturen prüft, ist ein System noch nicht sicher. Barebox warnt eindringlich davor, dass die Angriffsfläche des Bootloaders oft gnadenlos unterschätzt wird.

## 1. TrustZone & Hardware Root of Trust
Die Kette der kryptografischen Verifikation muss im physikalischen Silizium beginnen.
- [ ] **Hardware eFuses:** Der Barebox SoC muss ab Werk sogenannte eFuses (One-Time-Programmable) gebrannt bekommen haben. Die interne MaskROM der Platine verifiziert anhand dieser eingebrannten Hash-Werte zuerst den Barebox-Prebootloader (PBL).
- [ ] **Locking:** Der Integrator **muss** über Barebox-Kommandos (wie `hab`) die restlichen Fuses der Hardware durchbrennen, um ehemals legale Einfallstore wie JTAG-Debugger oder USB-Recovery ("FEL") für immer hardwareseitig zu sperren.
- [ ] **OP-TEE (TrustZone) Handoff:** Wenn ein sicheres Betriebssystem wie OP-TEE verwendet wird, MUSS Barebox dieses bereits in seinen allersersten PBL-Instruktionen hochladen und starten. Würde Barebox OP-TEE erst spät kurz vor Linux starten, hätte Barebox die gesamte Boot-Laufzeit über unbeschränkte TrustZone "Ring-0"-Rechte – ein gefundenes Fressen für ROP-Exploits. 

## 2. Reduktion der Angriffsvektoren
Ein fertig produziertes Barebox-Binary für den Endkunden (Produktion) muss massiv kastriert werden.

| Angriffsvektor | Barebox Security Vertrag |
|----------------|--------------------------|
| **Interactive Shell** | Die Shell ist viel zu mächtig. Sie muss komplett deaktiviert werden (`CONFIG_SHELL_NONE=y`) oder der UART-RX Input muss per Pin-Muxing zur Not totgelegt werden, damit kein Angreifer Tippfehler/Skripte einwerfen kann. |
| **Mutable Environment** | Das Auslesen des Environments aus dem NV-Speicher (Flash) **MUSS** verboten werden (`CONFIG_ENV_HANDLING` deaktiviert). Andernfalls könnte ein Angreifer mit einem SPI-Flasher von außen die Boot-Argumente für Linux umschreiben (z.B. Root-Mount-Parameter). Barebox darf in Produktion nur auf sein intern einkompiliertes `defaultenv-2` (siehe Spec 08) vertrauen! |
| **File Systems** | Dateisystem-Driver (Ext4, FAT, etc.) sind historisch gesehen voller C-Parser-Bugs. Ein Angreifer könnte einen USB-Stick mit einem manipulierten FAT-Header einstecken und Barebox beim Parsen crashen. Vertrag: Barebox darf in einem Secure-Boot System **unter keinen Umständen Dateisysteme mounten**! Zertifizierte FIT-Images containing Linux müssen zwingend auf nackten, rohen Block-Partitionen liegen. |

## 3. Debugging von gelockten Produktions-Boards (JWT)
Oftmals will man als Entwickler im Feld z.B. bei zurückgesendeten kaputten Systemen doch auf die Shell einer ausgelieferten Platine.
- [ ] **Kein Debug-Bootloader:** Es ist verboten, intern einfach eine "Debug-Version" des Bootloaders zu bauen und bereitzuhalten. Wenn so ein Image leakt, wird es sofort in freier Wildbahn genutzt, um andere Boards zu entsperren.
- [ ] **JSON Web Tokens (JWT):** Die Lösung: Barebox unterstützt das Prüfen von JSON Web Tokens gegen einen einkompilierten RSA-Public-Key. Will der Entwickler sich einloggen, muss er ein JWT-Zertifikat signieren, welches *exakt und nur* die Seriennummer dieses einen beschädigten Platinen-Chips enthält (wird via USB-Stick übergeben). Passt die signierte UID im Zertifikat zur Hardware-UID des Chips, schaltet das System die Shell temporär frei.
