> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/ata_security.md`


# 27. ATA Storage Security (Full Disk Locking)

Dieses Dokument spezifiziert die "Full Disk Lock" Mechanismen von Toob-Boot. Das System bindet sich direkt an die Hardware-Schnittstellen (ATA) von SSDs/HDDs, um Datenträger auf Hardwareebene vor dem Bootvorgang zu verriegeln.

## 1. Static Disk Locking
Die einfachste Art, die Ziel-Festplatte vor externen Abgriffen zu schützen.

- [ ] **Hardcoded Password (`DISK_LOCK=1`):** Der Entwickler definiert ein statisches Passwort (`DISK_LOCK_PASSWORD=...`), welches direkt in den Bootloader kompiliert wird.
- [ ] **First-Boot Invariant:** Findet Toob-Boot beim ersten Systemstart eine *unlocked* ATA-Festplatte vor, sendet es sofort den ATA Security Command, um das Laufwerk mit diesem Passwort unwiderruflich zu sperren. Bei allen Folgestarts fungiert Toob-Boot als Schlüsselhalter und entsperrt das Laufwerk, bevor es das native OS von der Platte lädt.

## 2. TPM-Sealed Disk Locking (High Security)
Dies ist die Blaupause für "Bitlocker"-ähnliche Full-Disk-Verschlüsselung auf Hardwareebene, welche die Features aus [Item 20 (TPM Sealing)](/specs/Toob-Boot/20-tpm-specs/20-tpm_features.md) nutzt.

Anstatt eines anfälligen Hardcoded-Passworts, agiert das TPM als hardwarebasiertes Sicherheitsmodul für das ATA Laufwerk:
- [ ] **Secret Generation:** Beim allerersten Start generiert Toob-Boot ein **randomisiertes** Passwort und sperrt damit die angeschlossene ATA-Platte physisch weg.
- [ ] **TPM Sealing:** Dieses randomisierte Passwort wird vom Bootloader niemals im Flash gespeichert, sondern in den NV Index des TPMs "ge-sealed" (`ATA_UNLOCK_DISK_KEY_NV_INDEX`). Die Bedingung des TPMs zur Herausgabe dieses Schlüssels ("Unseal") wird strikt an den kryptografischen Zustand des Systems geknüpft (`WOLFBOOT_TPM_SEAL_KEY_ID`).
- [ ] **Zusatz-Vertrag (`WOLFBOOT_DEBUG_REMOVE_SEALED_ON_ERROR`):** Zerstörungs-Mechanismus. Schlägt die Entschlüsselung beim Booten fehl (z.B. weil jemand den Bootloader auf einen illegalen Stand geflasht hat und das TPM blockiert), flusht Toob-Boot das Geheimnis komplett aus dem TPM-Speicher und verfällt in den Halt-Zustand (`panic()`).

## 3. Disable / Recovery Mode
Soll ein Laufwerk aus dem Verkehr gezogen oder repariert werden, erzwingt Toob-Boot einen speziellen Recovery-Boot:

- [ ] **Disable Flag (`WOLFBOOT_ATA_DISABLE_USER_PASSWORD=1`):** Das System wird so neukompiliert, dass es niemals das OS bootet.
- [ ] **Master Unlock:** Wenn das passende Master-Passwort (`ATA_MASTER_PASSWORD=...`) übergeben wurde, sendet der Bootloader ein einziges Mal den ATA "Disable Security" Command an die Festplatte.
- [ ] **Halt-State:** Unmittelbar danach crasht sich der Bootloader absichtlich selbst (`panic()`). Die Festplatte ist nun unverschlüsselt und die Hardware kann sicher ausgebaut werden.
