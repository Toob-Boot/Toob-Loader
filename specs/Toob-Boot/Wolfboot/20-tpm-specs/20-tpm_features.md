> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/TPM.md`


# 20. TPM Hardware Features & Sealing

Dieses Dokument klassifiziert das Zusammenspiel zwischen Toob-Boot und vollwertigen Trusted Platform Modulen (TPMs). Das Subnetz (`WOLFTPM=1`) abstrahiert nicht nur "Measured Boot", sondern massiv komplexe Enterprise-Features wie Hardware-Offloading und Sealing/Unsealing.

## 1. Hardware Root of Trust (RoT)
Die stärkste Form der Key-Speicherung, die Toob-Boot bietet.
- [ ] **Hash-Anchoring (`WOLFBOOT_TPM_KEYSTORE=1`):** Anstatt die Public-Keys direkt zu speichern, brennt das System lediglich einen kryptografischen **Hash des Public-Keys** in den Non-Volatile (NV) Memory des TPM-Chips. Der Bootloader darf Firmware nur starten, wenn der vorliegende Key exakt diesem TPM-Hash-Anker entspricht.
- [ ] **Passwort-Schutz (`WOLFBOOT_TPM_KEYSTORE_AUTH`):** NV-Zugriffe auf das TPM können (und sollten) im Bootloader durch ein Password gesichert werden, welches zusätzlich auf dem I2C/SPI-Bus verschlüsselt übertragen wird.

## 2. Cryptographic Offloading (Hardware Beschleunigung)
Toob-Boot kann massiv an RAM/Flash-Größe einsparen, indem es die extrem teure asymmetrische Signaturprüfung einfach den Krypto-Zellen des TPMs überlässt.
- [ ] **Hardware-Verifikation (`WOLFBOOT_TPM_VERIFY=1`):** Schiebt die gesamte Mathematik für RSA-2048 und ECC-256/384 out-of-band in den TPM-Prozessor.
- [ ] **RSA Encoding Zwang:** Da reine TPM-Hardware einen exakten ASN.1-Encoding Standard verlangt, muss der Entwickler das Image zwingend via `SIGN=RSA2048ENC` signieren (anstelle des raw-Modes).

## 3. Sealing & Unsealing Contracts
Eine der mächtigsten Funktionen: Der Bootloader kann ein Geheimnis (z.B. den Linux Disk-Decryption-Key) sicher wegschließen ("Seal") und nur ausgeben ("Unseal"), wenn die Hardware sich in einem exakt vordefinierten Zustand (PCR-State) befindet.

| Feature Flag & Storage | C-API Funktionen | Beschreibung & Bedingungen |
|------------------------|------------------|----------------------------|
| `WOLFBOOT_TPM_SEAL=1` | `bootloader_seal_auth(...)`<br>`bootloader_unseal_auth(...)`| Bindet ein Geheimnis (`secret`, bis zu 32 Bytes) untrennbar an bestimmte PCR-Werte. Dies verhindert Angriffe im Field, da sich die Hardware bei Modifikation querstellt. |
| `WOLFBOOT_TPM_SEAL_NV_BASE` | `0x01400300` (Default) | Die physische TPM Non-Volatile (NV) Basisadresse, unter der "Sealed Blobs" im Silicon strukturiert weggespeichert werden. |

### 3.1 Policy Signing (The Sealing Pipeline)
Das Unsealing (Entriegeln) erfordert zwingend eine asymmetrisch signierte Berechtigung, die "Policy".
- [ ] **Policy Extract:** Mittels dem Tool `tools/tpm/policy_create` wird die aktuelle TPM-Mask (die zu loggenden PCRs) und ihr Hash abgegriffen.
- [ ] **Policy Signing (`--policy`):** Dieser Policy-Hash muss offline mit dem Private-Key signiert werden. Das Standard `sign`-Tool injiziert dann die 32-Bit Maske + Signature exakt in den `HDR_POLICY_SIGNATURE` TLS-Eintrag des Boot-Manifest-Headers. Der Bootloader leitet diesen direkt ans TPM weiter, welches das Geheimnis entriegelt.
