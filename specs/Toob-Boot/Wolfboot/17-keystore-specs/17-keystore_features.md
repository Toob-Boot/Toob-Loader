> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/keystore.md`


# 17. Keystore Struktur & Multi-Key Management

Dieses Dokument spezifiziert die interne Datenstruktur (`keystore.c`), mit der Toob-Boot asymmetrische Public-Keys im Speicher organisiert, verwaltet und berechtigt. Es ist im strikten Checklist- und Tabellenformat aufgebaut.

## 1. Keystore Data Structure (Contracts)
Die Public-Keys kompilieren in C-Arrays, die aus einer statisch definierten C-Struktur bestehen (`struct keystore_slot`). Jeder Key, unabhängig von seiner Herkunft, wird vertraglich so kodiert:

| Feld / Variable | Typ | Beschreibung & Invariante |
|-----------------|-----|---------------------------|
| `slot_id` | `uint32_t` | Inkrementelle ID des Speicher-Slots (beginnend bei 0). |
| `key_type` | `uint32_t` | Der Algorithmus-Typ. Z.B. `AUTH_KEY_ED25519` oder `AUTH_KEY_RSA2048`. |
| `part_id_mask` | `uint32_t` | Berechtigungs-Bitmap. Definiert streng, welche Partition durch diesen Key befugt verifiziert werden darf. |
| `pubkey_size` | `uint32_t` | Die Byte-Länge des nachfolgenden Key-Buffers. |
| `pubkey` | `uint8_t[]` | Der rohe Bytestream des Public-Keys. |

## 2. Berechtigungs-Modell (Permissions Mask)
Anstelle von simplen Signaturprüfungen bringt Toob-Boot eine bitbasierte Access Control List (ACL) für Public-Keys mit:
- [ ] **Bit 0 (Self-Update):** Das Bit 0 ist zwingend und exklusiv für Bootloader-Aktualisierungen reserviert (`--wolfboot-update`).
- [ ] **Bit 1+ (Apps):** Die nachfolgenden Bits referenzieren reguläre Firmware-Slots.
- [ ] **Restricted Keys:** Beim Genieren (z.B. `keygen --id 3`) setzt das Tooling die `part_id_mask` zwingend auf `0x0008`. Versucht jemand, mit diesem Key die Partition 1 zu verifizieren, blockiert die Authentifizierung hart. (Standard ohne Parameter ist `KEY_VERIFY_ALL`).

## 3. Universal Keystore (`WOLFBOOT_UNIVERSAL_KEYSTORE=1`)
Normalerweise ist das Framework aus Platzgründen extrem rigoros: Ein kompilierter Bootloader unterstützt immer **nur exakt eine** einkompilierte Kryptoengine (z.B. nur Ed25519).

- [ ] **Mixed-Algorithm Support:** Schaltet der Entwickler das Universal-Makro ein, kann der Bootloader mehrere Krypto-Bibliotheken gleichzeitig linken. Er darf dann im Keystore-Array eine wilde Durchmischung aus (z.B.) RSA-2048 Keys (für Fallback) und ECC-384 Keys verwalten, und leitet den Signatur-Check dynamisch anhand der `key_type` Variable an die richtige Engine.

## 4. Externe Hardware Vaults & HSMs
Falls das System nicht den internen Flash nutzt, sondern die Public-Keys extern gelesen werden müssen:

- [ ] **Interface API Abstraktion:** Entwickler können den einkompilierten Keystore komplett weglassen. Sie **MÜSSEN** dann jedoch die Funktionen `keystore_num_pubkeys()`, `keystore_get_size(id)`, `keystore_get_buffer(id)` und `keystore_get_mask(id)` als I/O-Treiber implementieren, damit der Bootloader Keys dynamisch auslesen kann (z.B. aus I2C-Security Chips).
- [ ] **Zeroized HSM Keys (`--nolocalkeys`):** Extremer Hardware-Fallback. Handelt es sich beim Chip um ein vollwertiges HSM (Hardware Security Module) wie `wolfHSM`, übergibt das Tooling einen Keystore, in dem der `pubkey` Puffer komplett "genullt" (Zeroized) wurde. Das ist Absicht. Die Struktur verrät dem C-Code nur die `pubkey_size` und den `key_type`. Der Bootloader delegiert die mathematische Signaturprüfung komplett blind an das HSM, wodurch die sensiblen echten Key-Bytes absolut niemals in den RAM der Host-CPU kopiert werden.
