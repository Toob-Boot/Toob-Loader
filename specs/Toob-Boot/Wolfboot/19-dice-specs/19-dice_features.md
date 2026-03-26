> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/DICE.md`


# 19. DICE Attestation & PSA Certified API

Dieses Dokument spezifiziert das Device Identifier Composition Engine (DICE) Modell in Toob-Boot. Es befähigt das Gerät, kryptografisch fälschungssichere Identitätsnachweise (EAT Token) über seinen Boot-Zustand an Drittsysteme (z.B. Cloud-Server) auszustellen.

## 1. PSA Certified Attestation Token (Contract)
Wenn die Ziel-Applikation nach dem Booten einen Attestierungs-Beweis anfragt, antwortet die sichere Toob-Boot Service-Instanz verbindlich mit einem **COSE_Sign1-wrapped EAT (Entity Attestation Token)**.

Dieser Token garantiert per Vertrag folgende Claims:
- [ ] **Nonce Binding (Challenge):** Kryptografischer Schutz gegen Replay-Angriffe.
- [ ] **Device Identity (UEID):** Eine einzigartige, feste Hardware-Identität.
- [ ] **Lifecycle & Implementation ID:** Der aktuelle Lebenszyklus-Zustand der Firmware.
- [ ] **Measured Boot Claims:** Die kryptografischen Hashes des Bootloaders **und** der geladenen Ziel-App, die Toob-Boot ohnehin zur Verifikation berechnet hat.

## 2. Keying Models (Derivate vs. Provisioned)
Wie kommt Toob-Boot an den Private-Key, mit dem er diesen Hardware-Beweis unterschreibt? Es gibt zwei legitime Wege:

- [ ] **DICE Derived Key (Zero-Provisioning):** Der Default-Weg. Toob-Boot liest auf unterster Hardware-Ebene einen "Unique Device Secret" (UDS / HUK) ein, der vom Chiphersteller reingebrannt wurde. Unter Nutzung der Boot-Messwerte (Hashes) als deterministischen Input jagt Toob-Boot diesen UDS durch eine HKDF-Funktion. Das finale Ergebnis ist ein frisches Attestation-Keypair (CDI). Genial: Da es mathematisch deterministisch ist, braucht das System keine Key-Speicherung, sondern generiert die Keys "on the fly" beim Booten!
- [ ] **Provisioned IAK:** Die klassische Variante. Der Hersteller injiziert in der Fabrik einen "Initial Attestation Key" (IAK) in eine gesicherte Speicherzone der MCU. Der Bootloader ruft ihn lediglich per HAL-Hook ab und signiert damit.

## 3. HAL Integrations-Verträge für DICE
Damit DICE auf einem nackten Board funktioniert, **MÜSSEN** Board-Integratoren (bzw. das "Team B") folgende C-Hooks im HAL anbieten:

| HAL C-Signatur | Vertrag & Zweck |
|----------------|-----------------|
| `hal_uds_derive_key(uint8_t *out, size_t out_len)` | Liefert den UDS/HUK zurück. (*Achtung: Für Testzwecke darf man `WOLFBOOT_UDS_UID_FALLBACK_FORTEST=1` nutzen, um ihn unsicher aus der Chip-UID abzuleiten. Verboten in Produktion!*) |
| `hal_attestation_get_ueid(...)` | Liefert die stabile System UEID. Schlägt dies fehl, nutzt DICE zwingend den UDS als Derive-Seed. |
| `hal_attestation_get_implementation_id(...)` | (Optional) Gibt eine Projekt/Hersteller-Identifikation zurück. |
| `hal_attestation_get_lifecycle(...)` | (Optional) Gibt System-Lifecycle zurück. |
| `hal_attestation_get_iak_private_key(...)` | Zwingend **NUR**, wenn das Provisioned-IAK Modell gewählt wurde. |

## 4. Ziel-Hardware Besonderheiten (STM32H5 OBKeys)
Für STM32H5 Architekturen, welche TrustZone implementieren, existiert ein vordefinierter Weg (`WOLFBOOT_UDS_OBKEYS=1`):
- [ ] **HDPL1 Isolation:** Der UDS muss zwingend über das ST "TrustedPackageCreator" Tool (via `.obk` Files) als iRoT-Key (Immutable Root of Trust) in den abgeschirmten HDPL1-Speicher injiziert werden. Toob-Boot greift per Hook gezielt dorthin, bevor die MCU den Sicherheits-Zustand (Lifecycle) schließt.

## 5. Non-Secure Callable (NSC) Bridging
Da Toob-Boot als Secure-Master in der TrustZone läuft, die Ziel-Applikation jedoch nicht:
- [ ] **Non-Secure API (NSC):** Die Applikation darf die Funktion `psa_initial_attest_get_token()` ausführen. Da Toob-Boot TrustZone-Wrappers (`arm_tee_attest_api.c`) implementiert, tunnelt dieser Aufruf sicher über den Hardware-Bus zum Bootloader zurück, ohne dass die Ziel-App auf den Speicher des Bootloaders zugreifen kann.
