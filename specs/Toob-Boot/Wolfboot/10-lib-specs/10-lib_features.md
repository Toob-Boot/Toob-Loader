> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/lib.md`


# 10. Bootloader-as-a-Library (Baal) & CLI Tooling

Dieses Dokument spezifiziert die extrem mächtige Eigenschaft des Systems, **nicht** als Standalone-Binary ausgeführt zu werden, sondern seine kryptografische Verifikations-Logik als importierbare C-Library für existierende Fremd-Bootloader (wie z.B. U-Boot oder UEFI) oder User-Space Applikationen bereitzustellen. Es folgt dem strikten Checklist- und Tabellenformat.

## 1. Library-Mode Integration (Features)
- [ ] **Third-Party Bootloader Insertion:** Toob-Boot kann über das Target `make lib` als statische Bibliothek assembliert werden. Ein fremder "Dumpty-Loader" nutzt dann Toob-Boot nur, um Secure-Boot-Verifikationen durchzuführen, führt aber das Springen und Hardware-Routing selbst durch.
- [ ] **Partition-less Configuration:** Wenn Toob-Boot als reine Crypto-Lib läuft, **MUSS** das Makro `BOOTLOADER_NO_PARTITIONS` im `target.h` Header definiert sein, da die Library dann keine aktiven Sektor-Erase Operationen steuert.

## 2. Die C-Library API für Fremd-Systeme
Eine einbettende Applikation muss folgende Low-Level Pointer-Operationen aufrufen, um ein Image im RAM oder XIP-Speicher validieren zu lassen:

| Library Funktion | Aufgabe & Rückgabevertrag |
|------------------|---------------------------|
| `bootloader_open_image_address(struct *img, uint8_t* image)` | Parst den TLV-Header ab dem übergebenen Memory-Pointer (RAM oder Flash-Offset).<br>**Return `0`:** Header & Magic-Bytes valide.<br>**Return `-1`:** Magic ungültig oder Firmware-Größe überschreitet die konfigurierte `BOOTLOADER_PARTITION_SIZE`. |
| `bootloader_verify_integrity(struct *img)` | Kalkuliert den kryptografischen Hash (z.B. SHA-256) über den Payload live neu und vergleicht ihn mit dem Digest im extrahierten Header.<br>**Return `0`:** Hash-Übereinstimmung (Valide).<br>**Return `-1`:** Hash-Mismatch (Daten manipuliert). |
| `bootloader_verify_authenticity(struct *img)` | Liest die asymmetrische Signatur aus dem Payload und testet sie nacheinander gegen alle der Library einkompilierten Public-Keys.<br>**Return `0`:** Vertrauenswürdig (Zertifikats-Pass).<br>**Return `-1`:** Interner Fehler / Datenmüll.<br>**Return `-2`:** Signatur intakt, konnte aber durch keinen Public Key autorisiert werden (Falscher Key). |

## 3. Die CLI Partition-Manager Applikation (`lib-fs`)
Das Framework liefert neben der Firmware-Steuerung (aus Item `09`) auch eine **Linux User-Space CLI**, mit der ein großes Host-Betriebssystem via `/dev/mtdX` direkt die rohen Partition-Trailer der Mikrocontroller-Architektur steuern kann.

- [ ] **Status Monitoring:** CLI Tooling (`lib-fs status`, `get-boot`, `get-update`) parst die End-of-Partition Flags im MTD direkt in der Shell und gibt die 0x-Hex Codes aus (`NEW`, `UPDATING`, `SUCCESS`, `TESTING`).
- [ ] **User-Space CLI Triggers:**
  - `lib-fs update-trigger`: Modifiziert das Byte der Hardware-Partition im Char-Device (`/dev/mtdX`) auf `0x70` (UPDATING), sodass Toob-Boot beim nächsten Linux-Reboot anspringt.
  - `lib-fs success`: Setzt das Hardware-Flag permanent auf SUCCESS (verhindert Boot-Loops).
- [ ] **Offline File Verification:** Mit Befehlen wie `verify-boot` und `verify-update` berechnet die CLI die Ed25519/RSA-Signaturen direkt auf dem Linux-Host gegen die Blockgeräte, *bevor* das System überhaupt neustartet.

## 4. Test-Lib Example Integration
- [ ] **Example: `test-lib`:** Mitgeliefertes POSIX-kompatibles Test-Programm. Demonstriert, wie `bootloader_open_image_address` genutzt wird, um lokal gebaute `.bin`-Binaries (z.B. `empty_v1_signed.bin`) einfach auf dem Host-Rechner via `make test-lib` auf kryptografische Formatierung Validität zu prüfen.
