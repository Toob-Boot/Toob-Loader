> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/encrypted_partitions.md`


# 13. Verschlüsselte Partitionen & Ende-zu-Ende Security

Dieses Dokument abstrahiert die Eigenschaften für Ende-zu-Ende verschlüsselte Update-Partitionen (`ENCRYPT=1`). Anstatt Klartext im Flash zu belassen, nutzt das System dynamische symmetrische Verschlüsselung auf Sektor-Ebene.

## 1. Das "Transparent Encryption" Modell
- [ ] **On-the-Fly Decryption:** Ist Feature aktiviert, routet der Bootloader sämtliche Lese- und Schreibzugriffe der `UPDATE` und `SWAP` Partitionen durch eine Stream-Cipher-Engine. Das System (und Angreifer) sehen physisch nur Ciphertext. Die `BOOT`-Partition bleibt zwingend unverschlüsselt (Klartext), da die MCU dieses sonst nicht nativ ausführen könnte (XIP/Memory Mapped limitiert).
- [ ] **Pre-Encryption per Tooling:** Der Entwickler kann das Factory-Update via Keygen-Tooling (Parameter `--encrypt`) bereits offline am Laptop verschlüsseln. Die Ziel-Applikation lädt den Ciphertext herunter und schreibt ihn "raw" logisch in den UPDATE-Flash, ohne ihn selbst entschlüsseln zu können.

## 2. Der Temporary-Key Lifecycle (Verträge)
Toob-Boot besitzt den vertraglichen Update-Schlüssel **nicht** dauerhaft!
- [ ] **Single-Ticket Usage:** Die Ziel-Applikation erhält den symmetrischen Verschlüsselungs-Key über einen sicheren Tunnel, speichert in via der API `bootloader_set_encrypt_key()` in einer gesicherten Zone des Bootloaders und triggert das Update. Der Bootloader nutzt den Key **genau ein einziges Mal** beim Reboot für den Swap, und führt danach zwingend `bootloader_erase_encrypt_key()` aus.
- [ ] **Custom Key Storage (`CUSTOM_ENCRYPT_KEY=1`):** Das System erlaubt dem Entwickler, die C-Routinen `get_encrypt_key`, `set_encrypt_key` und `erase_encrypt_key` selbst zu deklarieren, falls der Key stattdessen in dedizierter Hardware (z.B. eFuses oder TPMNV) abgelegt/abgeholt werden soll.

## 3. Symmetrische Kryptografie (Algorithmen)
Die Verschlüsselung arbeitet ausschließlich im Counter-Mode (Stream), damit Random-Access Flash-Operationen funktionieren.

| Algorithmus Flag | Key Size | Nonce / IV Size | Bemerkung |
|------------------|----------|-----------------|-----------|
| `ENCRYPT_WITH_CHACHA=1` | 32 Bytes | 12 Bytes | Default-Auswahl. Extrem performant auf Software-Basis (keine Hardware-AES-Einheit nötig). |
| `ENCRYPT_WITH_AES128=1` | 16 Bytes | 16 Bytes | AES im CTR-Mode. |
| `ENCRYPT_WITH_AES256=1` | 32 Bytes | 16 Bytes | AES im CTR-Mode. Höchste NIST Compliance. |

## 4. Hardware Security & TrustZone Integration
Spezialisiertes Handling für Architekturen mit Hardware-Zonen:
- [ ] **PKCS#11 Vault-Mapping (`ENCRYPT_PKCS11=1`):** Läuft Toob-Boot als TrustZone-Master, übergibt die Applikation der API `bootloader_set_encrypt_key()` **nicht** den echten Key! Sie schiebt den echten Key via PKCS#11 API in den Secure Vault und übergibt dem Bootloader lediglich die referenzierende Target-ID (`CKA_ID`). Der Bootloader greift dann sicher über diese ID auf den Key zu.

## 5. Self-Updates und Memory Constraints
Wenn sich Toob-Boot selbst updaten soll, greifen harte Linker-Verträge, da Flash-Sektoren des Bootloaders beschrieben werden.
- [ ] **RAM-Relocation (`RAM_CODE=1`):** Sämtliche Objekt-Dateien der Krypto-Algorithmen (wie `*chacha.o` oder `*aes.o`) **MÜSSEN** zwingend im Linker-Script via Anweisung in das RAM (`.data` Block) exkludiert werden. Führt die MCU Stream-Cipher-Operationen aus dem selben Flash-Block aus, den sie gerade löscht oder beschreibt, crasht der Instruction-Cache (HardFault).
- [ ] **Sektor RAM-Cache (`ENCRYPT_CACHE`):** Verschlüsselung auf Flash-Ebene erfordert zwingend einen RAM-Puffer in der Exakt gleichen Block-Größe wie der physische Flash-Cache. Via `ENCRYPT_CACHE=0x20010000` kann Entwickler die Memory-Addresse hart pinnen (an einen Bereich, der den OS Start überlebt).
