> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/PQ.md`


# 18. Post-Quantum (PQ) Signaturen & Hybrid Mode

Dieses Dokument spezifiziert die Unterstützung für kryptografische Verfahren, die mathematisch resistent gegen quantencomputerbasierte Angriffe sind (NSA CNSA 2.0 / FIPS 204). Es übersetzt die Parametrierung in verbindliche Checklist-Verträge.

## 1. Lattice-Based Methoden (ML-DSA)
Gitterbasierte Kryptografie nach FIPS 204 (ehemals CRYSTALS-DILITHIUM).
- [ ] **Eigenschaften:** Bietet extrem schnelle Verifikation und Schlüsselgenerierung, resultiert aber in massivem Platzbedarf für Header und Public-Keys.
- [ ] **Level-Deklaration (`ML_DSA_LEVEL=<num>`):** Der Entwickler muss sich für ein starres Sicherheitslevel entscheiden, welches exakte Buffer-Sizes (`IMAGE_SIGNATURE_SIZE`) verlangt:
  - `Level 2` (ML-DSA-44): Signature Size = 2420 Bytes.
  - `Level 3` (ML-DSA-65): Signature Size = 3309 Bytes.
  - `Level 5` (ML-DSA-87): Signature Size = 4627 Bytes.
- [ ] **Draft vs Final:** Das Subnetz baut standardmäßig gegen final-FIPS 204. Für Legacy-Kompatibilität kann `WOLFSSL_DILITHIUM_FIPS204_DRAFT` erzwungen werden.

## 2. Stateful Hash-Based Signatures (HBS)
Baumbasierte Hash-Signaturen nach NIST SP 800-208 (XMSS & LMS).
- [ ] **Eigenschaften:** Winzige Public Keys, aber variable und teilweise massive Signaturgrößen. Die Private-Keys sind **zustandsbehaftet (stateful)**! Wird derselbe Key-State beim Signagezweimal benutzt, zerbricht die mathematische Sicherheit ("One-Time Signature" Charakteristik im Tree).

| Signatur Typ | Build Variable | Konfigurations-Makros | Tooling-Helper |
|--------------|----------------|-----------------------|----------------|
| **LMS/HSS** | `SIGN=LMS` | Erfordert zwingend exakte Angaben zu: `LMS_LEVELS`, `LMS_HEIGHT`, `LMS_WINTERNITZ` | `tools/lms/lms_siglen.sh` (Berechnet die variablen Puffer-Arrays auf die genaue Bytezahl). |
| **XMSS/XMSS^MT**| `SIGN=XMSS` | Erfordert zwingend String-Deklaration `XMSS_PARAMS` (z.B. `'XMSS-SHA2_10_256'`). | `tools/xmss/xmss_siglen.sh` (Übersetzt das String-Set in die finale ByteArray-Größe). |

## 3. Hybrid Mode Contracts (Classic + PQ)
Toob-Boot erlaubt einen graduellen Übergang in die Post-Quantenwelt, ohne die Sicherheit der klassischen ECC/RSA Algorithmen sofort aufgeben zu müssen. Ein Firmware-Update kann doppelt signiert und auch doppelt verifiziert werden.

- [ ] **Data Contract (`SECONDARY_SIGN=...`):** Das System deklariert einen zweiten Algorithmus, der in Folge direkt nach dem primären validiert werden muss.
- [ ] **Zwingendes Makro (`WOLFBOOT_UNIVERSAL_KEYSTORE=1`):** Beide Algorithmus-Engines (z.B. RSA2048 und ML-DSA) müssen logischerweise gleichzeitig einkompiliert und ihre asymmetrischen Keys im selben Array (`keystore.c`) verwaltet werden.
- [ ] **Tooling-Verification:** Der Sign-Befehl fordert in diesem Modus vertraglich die Angabe von **zwei** Encryption-Flags und **zwei** Private-Keys parallel auf der Kommandozeile (`sign --ml_dsa --ecc384 --sha256 app.bin key-pq.der key-ecc.der 1`), um ein singuläres Hybrid-Blob zu erzeugen.
