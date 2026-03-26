> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/azure_keyvault.md`


# 22. Cloud HSM Signing (Azure Key Vault)

Dieses Dokument spezifiziert die Integration von Toob-Boot in Microsoft Azure Key Vault. Es beweist die "Three-Step-Signing" Architektur (siehe Dokument 15), da der private Signatur-Schlüssel in der Cloud liegt und diese absolut niemals verlässt.

## 1. Cloud Key Provisioning
Anstatt die Public-Keys am lokalen Entwickler-PC zu generieren, zieht das System sie aus dem Azure Tresor.
- [ ] **ASN.1 / DER Download:** Via Azure CLI (`az keyvault key download -e DER`) können Infrastruktur-Admins den Cloud-Public-Key laden.
- [ ] **Bootloader Stitching:** Über den bekannten Importer (`keygen -i public-key-1.der`) wird dieser Cloud-Key in den C-Quellcode des Bootloaders verwoben.

## 2. Der Azure REST-API Vertrag (Three-Step Pipeline)
Um zukünftige Firmware-Binaries zu signieren, **MÜSSEN** CI/CD Pipelines den folgenden dreistufigen HTTP-Vertrag einhalten:

| Phase | Aktion / Tools | Datenaustausch-Format & Cloud-Mechanik |
|-------|----------------|----------------------------------------|
| **1. Digest Creation** | `sign --sha-only` | Das Sign-Tool hasht das reine Binary (z.B. Test-Image). Dieser Hash (`_digest.bin`) muss danach zwingend ins **Base64URL** Format konvertiert werden. |
| **2. Azure HTTPS Auth & Sign** | `curl POST` & `az account` | Die Pipeline holt via Azure-Identity ein OAuth-Bearer Token für den Tresor. Danach fordert ein HTTPS-Call an den Endpunkt (`/keys/test-signing-key/sign`) eine asymmetrische Signatur des Digests an (z.B. JSON Payload: `{"alg":"ES256", "value":"<base64-hash>"}`). Azure liefert ein JSON-Ojekt (`.value`) mit der rohen Signatur zurück. |
| **3. Decoding & Packaging** | `sign --manual-sign` | Die JSON-Antwort wird extrahiert und von Base64URL zurück in eine `.sig` Binärdatei dekodiert. Das Sign-Tool "klebt" das ursprüngliche Binary und die Azure-Signatur zusammen in das valide Toob-Boot Manifest-Format ein. |
