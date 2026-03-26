> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/wolfHSM.md`


# 21. Hardware Security Module (wolfHSM) Integration

Dieses Dokument abstrahiert die Integration von dedizierten Hardware Security Modulen ("wolfHSM"). Sie stellen das absolute Maximum physischer MCU-Sicherheit dar, da sowohl Speicherung als auch kryptografische Mathematik die Host-CPU komplett verlassen.

## 1. Topologische Betriebsmodi
Das System kann architekturell zwei sich gegenseitig ausschließende Zustände einnehmen:

- [ ] **Client Mode (`WOLFBOOT_ENABLE_WOLFHSM_CLIENT=1`):** Toob-Boot agiert als dummer Client. Jeder Crypto-Schritt und Key-Zugriff wird über den System-Bus per Remote Procedure Call (RPC) an ein völlig isoliertes Hardware-Modul gesendet, welches die Antwort liefert.
- [ ] **Server Mode (`WOLFBOOT_ENABLE_WOLFHSM_SERVER=1`):** Toob-Boot hostet den HSM-Server lokal abstrahiert in seinem eigenen Adressbereich und liefert direkte NVM-Integration.

## 2. HSM Hardware Offloading Contracts
Verifizierungs-Mathematik wird strikt aus Toob-Boot ausgelagert, um Angriffsfläche zu minimieren.
Folgende Algorithmen werden vom "Host"-System zum "Server"-HSM zur Berechnung weitergeleitet:
- **Asymmetrisch:** RSA (2048/3072/4096), ECDSA (P-256/384/521), ML-DSA (Post-Quantum Level 2/3/5).
- **Symmetrisch/Hashing:** SHA256 (für Image Integrity Verification).
- *(Hinweis: Verschlüsselte Update-Partitionen werden in Kombination mit wolfHSM aktuell mathematisch NICHT unterstützt).*

## 3. Remote Key Storage & Identity
Die sicherste Art der Schlüsselverwaltung: Public Keys existieren **absolut nicht** im RAM der Host-CPU.
- [ ] **Zeroized Keystore (`WOLFBOOT_USE_WOLFHSM_PUBKEY_ID=1`):** Wird erzwungen. Toob-Boot wird mit einem genullten C-Array (`--nolocalkeys`) einkompiliert. Bei einem Firmware-Start überträgt das System nur den zu prüfenden Sub-Hash an das HSM. Das HSM verifiziert intern gegen einen Key mit einer statischen ID (`hsmKeyIdPubKey`) aus seinem Tresor.
- [ ] **Debug-Ephemeral-Mode:** Fehlt das Flag, liest Toob-Boot Keys aus dem statischen C-Code, überträgt sie für den Validierungscheck kurzzeitig ungeschützt in den Server und löscht (evicted) sie danach. (Nur für Test/Entwicklung, in Produktion fatal).

## 4. Full PKI: Certificate Chain Verification
Toob-Boot kann in Verbindung mit HSMs von statischen "Raw Keys" auf Infrastruktur-Zertifikate (x.509 PKI) aufrüsten.
- [ ] **Zeritfikats-Auflösung (`WOLFBOOT_CERT_CHAIN_VERIFY=1`):** Das Update-Image (signiert via `--cert-chain`) trägt nicht nur eine Signatur, sondern eine komplette Zertifikatskette aus Leaf- und Root-CAs.
- [ ] **Root-Of-Trust Anchoring:** Bevor das Image validiert wird, überträgt Toob-Boot die Kette an das HSM. Der HSM-Manager (`WOLFHSM_CFG_CERTIFICATE_MANAGER`) matcht die Route gegen sein physisch gespeichertes Root-CA Zertifikat (`hsmNvmIdCertRootCA`). Ist der Pfad vertrauensvoll validiert, cacht Toob-Boot den im Leaf-Zertifikat ausgestellten Public-Key, und das Firmware-Image darf starten. 

## 5. HAL Implementierungs-Vertrag
Um die RPC Bridge zu bauen, müssen Hardware-Integratoren den HAL zwingend um folgende C-Schnittstellen erweitern:

| HAL Requirement | Typ / Signatur | Beschreibung & Vertrag |
|-----------------|----------------|------------------------|
| `hsmClientCtx` / `hsmServerCtx` | Global Variable | Globaler State-Context Memory für das Subsystem. Für den Bootloader unveränderlich (Read-Only). |
| `hsmDevIdHash`, `hsmKeyIdPubKey`| Global Variable | Physische Memory-Mapper IDs, um auf die Vault-Daten des TPM-Silicons zuzugreifen. |
| `hal_hsm_init_connect()` | Function | Initialisiert die RPC-Verbindung. |
| `hal_hsm_disconnect()` | Function | Kappt RPC, gibt Speicherkontexte frei (Shutdown-Phase). |
