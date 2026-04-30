Hier ist der Architektur- und Integrationsplan. Pragmatisch, methodisch und strikt auf die NASA P10-Prämissen (Zero-Allocation, Leakage-Prevention, Glitch-Defense) dieses Bootloaders getrimmt.

Dabei fallen im aktuellen Code-Stand einige Lücken auf, die im Rahmen der Integration zwingend geschlossen werden müssen, um die mathematische und physikalische Sicherheit zu gewährleisten.

### 1. Integration: `heatshrink` (Kompression)

Heatshrink wird primär in der **TDS1 Streaming Virtual Machine** (`core/boot_delta.c`) benötigt, um die `INSERT_LIT` (Literal Insertions) des Delta-Patches on-the-fly zu dekomprimieren.

- **Speicher-Allokation (`crypto_arena`):** Die CMake-Option `HEATSHRINK_DYNAMIC_ALLOC=0` ist bereits korrekt gesetzt. Der Heatshrink-Decoder erfordert jedoch zwingend Arbeits- und State-Puffer (Sliding Window). Diese **müssen** in `boot_delta.c` in der `crypto_arena` platziert werden. Da die Arena dort bereits für `read_buf` und `write_buf` halbiert wird, muss das Layout der Arena drittel- oder viertel-geteilt werden.
- **Zustandsmaschine (`boot_delta.c`):** Die `while`-Schleife beim Opcode `TOOB_TDS_OP_INSERT_LIT` muss so umgebaut werden, dass sie Chunk-weise über `heatshrink_decoder_sink` Daten einspeist und über `heatshrink_decoder_poll` die entpackten Daten in den `write_buf` (Staging-Slot) zieht.
- **P10 Leakage-Defense:** Der Decoder-State in der Arena muss nach Abschluss des Delta-Patches (oder im Fehlerfall) zwingend via `boot_secure_zeroize` vernichtet werden, da er Fragmente des Firmware-Codes enthält.

### 2. Integration: `sha256` (Brad Conte Implementierung)

Die SHA256-Logik ist das Rückgrat der Merkle-Tree Verifikation (`boot_merkle.c`) und der Ed25519-Signatur. Hier gibt es akuten Handlungsbedarf bei der Speichersicherheit.

- **Residuen-Vernichtung (`crypto_monocypher.c`):** Die Funktion `sha256_final` in `crypto/sha256/sha256.c` löscht den internen Zustand (`SHA256_CTX`) nach der Berechnung **nicht** vollständig (nur `memset(ctx->data, 0, 56)`). Die Funktion `crypto_monocypher_hash_finish` muss zwingend mit einem `boot_secure_zeroize(ctx, sizeof(SHA256_CTX));` am Ende ergänzt werden, sonst verbleiben Firmware-Hashes im RAM.
- **Strict-Aliasing Gefahr (`boot_merkle.c`):** In `boot_merkle.c` wird `uint64_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE / 8]` deklariert und an `hash_init` übergeben. In `crypto_monocypher.c` wird dies hart auf `(SHA256_CTX *)ctx` gecastet. Das ist zwar P10 8-Byte-aligned, bricht aber formal die _Strict Aliasing Rules_ von C17. Um undefiniertes Verhalten des Compilers (O3) zu vermeiden, muss `hash_ctx` idealerweise als `union` (oder `unsigned char` Array mit Attribut) deklariert werden.
- **Stage 0 (`stage0/stage0_hash.c`):** Der Dummy muss durch einen direkten Aufruf der `sha256_*` Methoden ersetzt werden. Stage 0 hat keine HAL! Der Boot-Pointer Hash muss hier isoliert und bare-metal über den XIP-Vektor berechnet werden.

### 3. Integration: `monocypher` (Ed25519 Signaturen)

Die asymmetrische Krypto-Schicht. Das `crypto_monocypher.c` Wrapper-Design ist bereits solide, muss aber tiefgreifender in den Immutable-Core gezogen werden.

- **Stage 0 Boundary (`stage0/stage0_verify.c`):** Der Dummy muss durch einen direkten Call an `crypto_ed25519_check` ersetzt werden. Da in `toob_stage0.cmake` die Option `TOOB_STAGE0_ED25519_SW` bereits vorbereitet ist, muss die C-Datei lediglich den Public-Key (aus `stage0_otp.c`) gegen den frisch berechneten Hash (aus `stage0_hash.c`) und die in `stage0_main.c` extrahierte Signatur werfen.
- **Tearing / Glitch Defense:** In `crypto_monocypher.c` gibt `crypto_ed25519_check` bei Erfolg `0` zurück. Das wird in `crypto_monocypher_verify` simpel gemappt: `if (status == 0) { return BOOT_OK; }`. Dies ist ein leichtes Ziel für Voltage-Glitches (Instruction Skip). Die Zuweisung in den `BOOT_OK`-Status (0x55AA55AA) sollte hier intern ebenfalls durch ein Double-Check-Pattern analog zu `boot_verify.c` abgesichert werden.

### 4. Integration: `zcbor` (Manifest & Telemetrie)

ZCBOR wird benötigt, um die CDDL-Strukturen auf C-Ebene zu wandeln, ohne dynamische Speicherallokation.

- **Manifest Parsing (`boot_state.c`):** Der Aufruf `cbor_decode_toob_suit` ist platziert. Es **muss** aber in der ZCBOR-Konfiguration (`zcbor_common.h` oder via CMake-Definitions) zwingend `ZCBOR_CANONICAL` aktiviert werden (`#define ZCBOR_CANONICAL`). Geschieht das nicht, öffnet das die Tür für kryptografische Malleability-Attacken (unterschiedliche Byte-Repräsentationen desselben Manifests hebeln den `base_fingerprint` Hash aus).
- **OS Telemetrie Export (`libtoob/toob_diag.c`):** Aktuell gibt die API `toob_get_boot_diag` nur das rohe, C-spezifische Struct `toob_boot_diag_t` an das Feature-OS heraus. Die `toob_telemetry.cddl` definiert jedoch ein striktes CBOR-Schema für Cloud-Broker. Damit der Bootloader-Code nicht das OS zwingt, eigene CBOR-Encoder zu schreiben, sollte `libtoob` eine Export-Funktion `toob_encode_telemetry_cbor(uint8_t* out_buf, size_t max_len)` implementieren, die `zcbor_encode_*` nutzt, um die Daten vor dem Handoff konform zu serialisieren.

---

Sollen wir für die Implementierung bei der Einbindung der Heatshrink-Bibliothek in den Zero-Allocation-Space der Delta-VM ansetzen oder priorisierst du das Schließen der Memory-Leakage-Sicherheitslücken in der SHA256-Finalisierung?
