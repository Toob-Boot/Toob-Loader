# Toob-Boot Speicher & Merkle-Verifikation

> Chunk-basierte Streaming-Verifikation zur Einhaltung des RAM-Budgets auf speicherlimitierten Microcontrollern.

Da moderne OS-Images (z.B. 4 MB) nicht auf einmal in das SRAM (z.B. 64 KB) eines Microcontrollers geladen werden können, nutzt Toob-Boot eine **Streaming-Verifikation** auf Basis von Chunk-Hashes (Merkle-Tree Derivat).

## 1. Das Problem: RAM-Erschöpfung
Ein monolithischer Hash über ein 4MB großes Image erfordert, dass man 4MB am Stück ausliest. Bricht währenddessen der Strom ab, oder schlägt ein einzelnes fehlerhaftes Flash-Byte (Bit-Rot) fehl, muss der komplette 4MB Hash beim nächsten Start neu berechnet werden. Das blockiert den Watchdog und verlangsamt den Boot-Prozess erheblich.

## 2. Die Lösung: Chunk-Hashes (Merkle-Liste)
Das `toob-sign` Host-Tool teilt das OS-Image in feste Blöcke (typisch 4 KB oder 8 KB) auf. Das SUIT-Manifest enthält nicht nur den Gesamthash, sondern ein Array der Einzel-Hashes für jeden Chunk. 
**(GAP-F17 Chunk-Size Constraint):** Die `chunk_size` MUSS zwingend `≤ kleinste sector_size` aus dem `aggregated_scan.json` betragen und durch das Page-Alignment teilbar sein, da Sektor-weise Verifikation (bspw. nach Delta-Patch-Rollback) sonst asynchron zum Flash-Layout verläuft! Der Manifest-Compiler blockiert Builds bei Zuwiderhandlung.

```json
{
  "image_size": 1048576,
  "chunk_size": 4096,
  "chunk_hashes": [
     "a1b2...", 
     "c3d4...",
     ...
  ],
  "envelope_signature": "ed25519_sig..."
}
```

### Der Verifizierungs-Ablauf im Core (`boot_verify.c`):
1. **Envelope Check**: Der Bootloader verifiziert *zuerst* die Ed25519-Signatur über das gesamte Manifest (Sign-then-Hash).
2. **Chunk Loop / GAP-08 Stream-Hashing**: In einer gebundenen `for`-Schleife liest der Bootloader exakt Chunk-weise (z.B. 4 KB) aus dem physischen SPI-Flash via `flash_hal.read()` direkt in einen Ring-Buffer im SRAM. Das Manifest selbst (und sein riesiges `chunk_hashes`-Array) verbleibt im Flash (wir verbieten strikt das Laden ins SRAM, O(n) Limit!).
3. **Chunk Hash**: Er berechnet via `crypto_hal.hash_update()` den SHA-256 über die gelesenen 4 KB im RAM.
4. **Vergleich**: Der berechnete Hash wird Stream-weise gegen den aktuellen Slot im speicherabgebildeten Flash-Manifest (`chunk_hashes[i]`) validiert.
5. **Watchdog**: Vor dem nächsten Loop-Durchlauf resettet der Core den Hardware-Watchdog via `wdt_hal.kick()`.

## 3. Vorteile für die Delta-Patching Architektur
Wenn ein fehlerhafter Boot vorliegt (Edge-Recovery) oder `detools` ein In-Place Patching anwendet, kann der Bootloader exakt referenzieren, **welcher** 4KB-Block beschädigt ist. Die Reparatur muss nicht das ganze Image verwerfen, sondern kann über den WAL-Rescue-Sektor gezielt fehlende Blöcke nachladen oder die Verifikation bei Stromausfällen genau dort fortsetzen lassen, wo sie abgebrochen wurde, anstatt von 0 zu starten.
