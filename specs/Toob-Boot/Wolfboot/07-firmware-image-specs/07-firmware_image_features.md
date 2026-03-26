> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/firmware_image.md`


# 07. Firmware Image Format & Header-Struktur

Dieses Dokument spezifiziert das exakte binäre Format der Firmware-Images, den Aufbau des Krypto-Headers und die Parsing-Verträge für das Zielsystem.

## 1. Firmware Entry & Alignment Contracts
- [ ] **Vector Table Relocation Offset:** Der Bootloader zwingt die Ziel-Firmware, an einem exakten 256-Byte Alignment (`BOOT_ADDRESS + 256`) zu beginnen.
  - *Vertrag:* Die Header-Struktur (Signaturen, Digests, Metadaten) wird automatisiert durch Padding auf das nächste 256-Byte Vielfache aufgerundet. Dies garantiert, dass die Interrupt-Vector-Tabellen (VTOR) des Cortex-M nahtlos auf den App-Offset umgelegt werden können.
- [ ] **Variable Header-Size (`IMAGE_HEADER_SIZE`):** Die Größe des Headers ist nicht statisch. Sie wächst relativ zur Breite der gewählten Public-Key / Hashing Kryptografie (z.B. RSA-4096 produziert wesentlich breitere Header als Ed25519). Die Size wird als C-Makro dynamisch in den Bootloader kompiliert.

## 2. Der Image Manifest Header (Binärstruktur)
Der Header existiert am Anfang des auszuführenden Firmware-Slots. Er besteht aus festen Feldern und dynamischen TLV-Elementen (Type-Length-Value). Alle Daten liegen zwingend in **Little-Endian (LE)** Formatierung!

| Byte Offset | Feld / Tag | Datentyp | Beschreibung |
|-------------|------------|----------|--------------|
| `0x00` | **Magic Number** | 4-Byte (Uint32) | Identifikations-Konstante des gültigen Bootloader-Archivs. |
| `0x04` | **Image Size** | 4-Byte (Uint32) | Die exakte Byte-Länge der Payload-Firmware (ohne den Header). |
| `0x08+` | **TLV-Liste** | Array | Dynamische Aneinanderreihung von Type/Size/Value Tupeln. |

### TLV-Parsing Logik (Type-Length-Value)
Der Decoder iteriert ab Offset `0x08` über die TLV-Struktur basierend auf folgendem Pattern:
- **Type:** 2 Bytes (Uint16)
- **Size:** 2 Bytes (Uint16) -> Länge der nachfolgenden Daten
- **Value:** `Size` Bytes langes Byte-Array.
- **Sonderregel (Padding):** List der Parser als Type den Wert `0xFF`, interpretiert er dies als einzelnes Padding-Byte. Es existiert folglich _kein_ Size-Feld für `0xFF`. Der nächste reguläre TAG beginnt 1 Byte später.

## 3. Obligatorische System-Tags (Mandatory TLVs)
Für einen erfolgreichen Secure-Boot MÜSSEN folgende TLVs zwingend im Header vorhanden und kryptografisch validierbar sein (Fehlt einer, bricht Toob-Boot sofort mit Fehler ab):

- [ ] **`0x0001` (Version):** 4 Bytes. Beinhaltet die Versionierung des Images (wird z.B. gegen Anti-Rollback Parameter der Current-Version geprüft).
- [ ] **`0x0002` (Timestamp):** 8 Bytes. Unix-Timestamp in Sekunden (Erstellungszeitpunkt der Binärdatei).
- [ ] **`0x0003` (SHA Digest):** X Bytes (Abhängig vom Algo, z.B. 32 Bytes bei SHA-256). Der Integritäts-Hash der Ziel-Firmware.
- [ ] **`0x0010` (Public Key Hint Digest):** 32 Bytes. Enthält den Hash des verwendeten öffentlichen Schlüssels. Erlaubt dem Bootloader in Systemen mit _mehreren_ verbauten Public-Keys auf dem Chip massenhaft Keystores durchzusuchen, um gezielt den passenden Verifikations-Key zu selektieren.
- [ ] **`0x0020` (Firmware Signature):** X Bytes (Abhängig vom Algo, z.B. 64 Bytes für Ed25519). Die asymmetrische Signatur, gerechnet über den Digest.
- [ ] **`0x0030` (Firmware Type):** 2 Bytes. Identifiziert den Payload-Typ sowie die verwendete Authentifizierungs-Mechanik der Kette.

## 4. Custom Metadata Injection (Erweitertes Verhalten)
Das Format erlaubt die Injektion willkürlicher Hersteller-Daten (Custom TLVs).

- [ ] **Cryptographic Inclusion:** Benutzerdefinierte Tags (z.B. proprietäre Hardware-UUIDs oder Customer-IDs) verankern sich **vor** der Signaturberechnung fest im Image Header. Modifiziert ein Attacker diese Header-Werte offline, bricht die Signatur bei der Installation auf der MCU irreparabel!
- [ ] **Runtime-API Access (`bootloader_find_header`):** Die gestartete Ziel-Applikation kann zur Laufzeit mittels der bereitgestellten Interaktions-Lib durch den eigenen Flash-Header iterieren und ihre eigenen Custom-Tags im RAM auflösen (Pointer zurückliefern).

## 5. Self-Header Mechanismus
- [ ] **Bootloader Verification Manifest (`BOOTLOADER_SELF_HEADER`):** Toob-Boot nutzt dasselbe Manifest-Format, um sich selbst zu beschreiben. Es legt diese Manifeststruktur an der System-Sektorengrenze (`SELF_HEADER_ADDRESS`) ab. Externe Controller können dieses Standard-Format auslesen und Toob-Boot asymmetrisch verifizieren.
