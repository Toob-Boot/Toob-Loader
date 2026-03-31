# Toob-Boot Speicher & Merkle-Verifikation

> Chunk-basierte Streaming-Verifikation zur Einhaltung des RAM-Budgets auf speicherlimitierten Microcontrollern.

Da moderne OS-Images (z.B. 4 MB) nicht auf einmal in das SRAM (z.B. 64 KB) eines Microcontrollers geladen werden können, nutzt Toob-Boot eine **Streaming-Verifikation** auf Basis von Chunk-Hashes (Merkle-Tree Derivat).

## 1. Das Problem: RAM-Erschöpfung
Ein monolithischer Hash über ein 4MB großes Image erfordert, dass man 4MB am Stück ausliest. Bricht währenddessen der Strom ab, oder schlägt ein einzelnes fehlerhaftes Flash-Byte (Bit-Rot) fehl, muss der komplette 4MB Hash beim nächsten Start neu berechnet werden. Das blockiert den Watchdog und verlangsamt den Boot-Prozess erheblich.

## 2. Die Lösung: Chunk-Hashes (Merkle-Liste)
Das `toob-sign` Host-Tool teilt das OS-Image in feste Blöcke (typisch 4 KB oder 8 KB) auf. Das SUIT-Manifest enthält nicht nur den Gesamthash, sondern ein Array der Einzel-Hashes für jeden Chunk. 

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
2. **Chunk Loop**: In einer gebundenen `for`-Schleife liest der Bootloader exakt 4 KB in den RAM (Swap-Buffer).
3. **Chunk Hash**: Er berechnet via `crypto_hal.hash_update()` den SHA-256 über die 4 KB.
4. **Vergleich**: Der berechnete Hash wird direkt gegen den `chunk_hashes[i]` Slot validiert.
5. **Watchdog**: Vor dem nächsten Loop-Durchlauf resettet der Core den Hardware-Watchdog via `wdt_hal.kick()`.

## 3. Vorteile für die Delta-Patching Architektur
Wenn ein fehlerhafter Boot vorliegt (Edge-Recovery) oder `detools` ein In-Place Patching anwendet, kann der Bootloader exakt referenzieren, **welcher** 4KB-Block beschädigt ist. Die Reparatur muss nicht das ganze Image verwerfen, sondern kann über den WAL-Rescue-Sektor gezielt fehlende Blöcke nachladen oder die Verifikation bei Stromausfällen genau dort fortsetzen lassen, wo sie abgebrochen wurde, anstatt von 0 zu starten.
