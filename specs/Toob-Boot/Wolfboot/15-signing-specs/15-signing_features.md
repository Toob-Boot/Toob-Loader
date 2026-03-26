> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/Signing.md`


# 15. Krypto-Toolset & Manifest-Signierung

Dieses Dokument abstrahiert die Eigenschaften der Host-seitigen CLI-Tools (`keygen` und `sign`), welche dafür verantwortlich sind, Firmware-Images in das von Toob-Boot lesbare, kryptografisch gesicherte Manifest-Format zu konvertieren. Die Parametrisierung dieser Tools definiert die kryptografischen Hard-Contracts für das gesamte OS-Lifecycle-Management.

## 1. Das `keygen` Tool (Keystore Provider)
Generiert asymmetrische Schlüsselpaare und baut das "Trust-Anchor" (`keystore.c` oder `keystore.img`), welches in den Bootloader einkompiliert wird.

- [ ] **Erstellung (`-g`):** Generiert deterministische Private-Keys im DER-Format und einen C-Array.
- [ ] **Import (`-i`):** Erlaubt das Einbetten von kryptografischen Public-Keys in den Bootloader, deren Private-Keys der Entwickler gar nicht mehr besitzt (z.B. Keys von Drittanbietern).
- [ ] **Zeroized HSM Keys (`--nolocalkeys`):** Wenn ein Hardware Security Module (HSM) verbaut ist, generiert dieses Flag einen leeren (zeroized) Platzhalter im C-Array. Der Bootloader greift dann später rein über Hardware-Referenzen auf die echten Public-Keys im HSM-Vault zu.

## 2. Das `sign` Tool (Image Packager)
Dieses Tool verkettet das rohe Binary (`.bin`) mit dem TLV-Header (siehe Item `07`) und erzeugt die asymmetrische Signatur.

### Signatur Algorithmen & Hash Options
Zwingende Parameter für die Cipher-Suite:
| Hash-Algorithmus Flag | Public-Key Signatur Algorithmus Flag |
|-----------------------|--------------------------------------|
| `--sha256` (Default) | **Elliptic Curve:** `--ed25519` (Default), `--ed448`, `--ecc256`, `--ecc384`, `--ecc521` |
| `--sha384` | **RSA (Legacy):** `--rsa2048`, `--rsa3072`, `--rsa4096` |
| `--sha3` | **Post-Quantum:** `--lms` (LMS/HSS), `--xmss` (XMSS/XMSS^MT) |
| `-` | **None:** `--no-sign` (Zerstört Secure-Boot Vertrauen komplett; nur für Debugging). |

### Operations- & Payload Modifier
Zusätzliche Mechanismen (wie Self-Updates oder Encryption), die vom Signer erzeugt werden können:
- [ ] **Target ID (`--id N`):** Bestimmt, in welchen Image-Slot das Payload später darf. Standard ist `N=1` (Main Applikation).
- [ ] **Bootloader Self-Update (`--wolfboot-update`):** Alias für `--id 0`. Signiert das Image so, dass es zwingend die Bootloader-Partition überschreiben wird.
- [ ] **Standalone Bootloader Header (`--header-only`):** Emittiert **nur** den kryptografischen Header (ohne das Firmware-Binary). Wird im System genutzt, um ihn extern für HSM-Messungen (`SELF_HEADER`) an absoluten Flash-Adressen zu fixieren.
- [ ] **Delta Creation (`--delta BASE.bin`):** Erzwingt die Bentley-McIlroy Diff-Engine. Das Tool liest das alte Binary ein, erzeugt einen minimalen Patch zum neuen Binary, und signiert nur den Patch als OTA-Paket.
- [ ] **End-To-End Encryption (`--encrypt KEYFILE.bin`):** Verschlüsselt den Firmware-Teil symmetrisch. Erfordert `--chacha` (44 Byte Keyfile), `--aes128` (32 Byte Keyfile) oder `--aes256` (48 Byte Keyfile).

## 3. Remote HSM Signing (Three-Step Process)
Toob-Boot ermöglicht "Air-Gapped" Signing. Anstatt dem `--sign` Tool den empfindlichen Private-Key am Entwickler-PC direkt geben zu müssen, existiert ein dreistufiger Vertrag:

1. **Hash Creation (`--sha-only`):** Das Tool kriegt als Input nur den Public-Key. Es baut den fertigen Header und berechnet den rohen Ziel-Hash über das Image (`_digest.bin`).
2. **Offline/HSM Signing:** Der Entwickler schickt den berechneten Hash (`_digest.bin`) über ein isoliertes Netzwerk an einen Hardware-Tresor oder Cloud-Provider (wie Azure Key Vault). Dieser berechnet isoliert die asymmetrische mathematische Signatur und schickt die rohen Bytes als `IMAGE.SIG` zurück.
3. **Firmware Stitching (`--manual-sign`):** Das Sign-Tool wird ein drittes Mal gestartet. Es nimmt das Image, den Public-Key, und die `IMAGE.SIG` Datei und verklebt sie (stitch) zu einem verifizierbaren Final-Binary, ohne den Private-Key jemals berührt zu haben.
