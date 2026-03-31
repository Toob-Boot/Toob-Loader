# Serial Rescue & Stage 1.5 (UART Recovery)

> Diese Spezifikation definiert das XMODEM/COBS Protokoll für Offline-Updates über serielle Schnittstellen (Schicht 4a), wenn das OS irreparabel beschädigt ist ("Zero-Day Brick").

## 1. Architektur-Einordnung
Die **Serial Rescue** Stage (Schicht 4a im `concept_fusion.md`) wird extrem isoliert betrieben. Sie darf niemals unautorisierten Zugriff auf das System gewähren.
Sie wird aktiviert, wenn:
1. `get_reset_reason()` einen tiefen Brownout / Edge-Failure meldet und alle Boot-Counter erschöpft sind.
2. Ein Hardware-Recovery-Pin (Stiftleiste) beim Kaltstart physisch auf `GND` gezogen wird.

## 2. Kryptografisches Auth-Token
Bevor Toob-Boot auch nur ein einziges Byte Flash löscht oder empfängt, muss der Techniker ein kryptografisches Challenge-Response-Token an die serielle Konsole senden.
Der Bootloader gibt einen 32-Byte Zufallswert (Nonce via `crypto_hal.random()`) über UART XMODEM/COBS aus. 

Der Techniker signiert diese Nonce zusammen mit der Hardware-DSLC (Device Specific Lock Code) via Ed25519.
Die Verifikation im Bootloader:
```c
bool is_authorized = platform->crypto->verify_ed25519(
    nonce_and_dslc, 64,  /* Eingabe-Message */
    received_sig,        /* UART Payload */
    embedded_pubkey      /* eFuse / Config PubKey */
);
```

## 3. COBS Framing & Ping-Pong
Da serielle Ports oft rauschen oder 0x00 Bits im Leerlauf produzieren, wird der gesamte Stream via **COBS (Consistent Overhead Byte Stuffing)** kodiert.
- Jedes Paket wird sauber mit `0x00` separiert.
- Im Payload selbst existieren keine `0x00` Bytes.

**Flow Control (Ping-Pong):**
Der Empfangspuffer auf MCUs ist winzig (z.B. 1 KB RAM). 
Toob-Boot sendet ein `READY` Paket. Der Host darf exakt einen Chunk (z.B. 1 KB) senden. Toob-Boot empfängt, validiert, schreibt ins Flash und antwortet mit `ACK`. 
Wenn der Host sendet, bevor ein `READY`/`ACK` kam, verwirft Toob-Boot die Bytes blind (Drop).

## 4. XMODEM Payload Transfer
Für den reinen binären Flash-Transfer greifen wir auf das bewährte XMODEM-CRC Protokoll zurück, jedoch streng über COBS eingepackt.
Bei erfolgreicher Übertragung triggert Toob-Boot ein `NVIC_SystemReset()`. Das Gerät bootet autonom in die frisch geflashte Partition (Stage 2).
