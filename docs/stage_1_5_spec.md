# Serial Rescue & Stage 1.5 (UART Recovery)

> Diese Spezifikation definiert das XMODEM/COBS Protokoll für Offline-Updates über serielle Schnittstellen (Schicht 4a), wenn das OS irreparabel beschädigt ist ("Zero-Day Brick").

## 1. Architektur-Einordnung
Die **Serial Rescue** Stage (Schicht 4a im `concept_fusion.md`) wird extrem isoliert betrieben. Sie darf niemals unautorisierten Zugriff auf das System gewähren.
Sie wird aktiviert, wenn:
1. `get_reset_reason()` einen tiefen Brownout / Edge-Failure meldet und alle Boot-Counter erschöpft sind.
2. Ein Hardware-Recovery-Pin (Stiftleiste) beim Kaltstart physisch auf aktives Level gezogen wird. GAP-28: Die C-Spezifikation schreibt hierfür zwingend einen Hardware/Software Pull-Up/Down Widerstand (`GPIO_PULLUP`/`PULLDOWN`) vor! Floating Pins (High-Z) bei offener Stiftleiste lösen sonst in EMV-rauen Umgebungen randomisierte Serial-Rescue-Boots aus.

## 2. Kryptografisches Auth-Token
Bevor Toob-Boot auch nur ein einziges Byte Flash löscht oder empfängt, muss der Techniker ein kryptografisches Challenge-Response-Token an die serielle Konsole senden.
Der Bootloader gibt einen 32-Byte Zufallswert (Nonce via `crypto_hal.random()`) über UART COBS aus. 

GAP-17: Der Techniker signiert diese Nonce zusammen mit der Hardware-DSLC (Device Specific Lock Code) UND der exakten Target-Slot-ID (Slot A oder B) via Ed25519. Dies verhindert, dass ein kompromittierter Host einen gültigen Recovery-Payload in den falschen Slot (oder gar überschreibend über das Recovery-OS selbst) forciert.
Die Verifikation im Bootloader:
```c
bool is_authorized = platform->crypto->verify_ed25519(
    nonce_and_dslc, 64,  /* Eingabe-Message */
    received_sig,        /* UART Payload */
    embedded_pubkey      /* eFuse / Config PubKey */
);
```

**(GAP-C06 Mitigation): Um DoS-Angriffe via UART Ed25519-Signatur-Spamming (~15ms CPU-Lock pro Fehlertoken) zu verhindern, MUSS `boot_panic.c` bei fehlschlagenden Authentifizierungen einen exponentiellen Penalty-Sleep ($T_{penalty} = 2^{failures} \times 100\text{ms}$) implementieren, bevor der RX-Buffer wieder abgefragt wird. Der WDT muss während des Sleeps zwingend gefüttert werden!**

## 3. COBS Framing & Ping-Pong
Da serielle Ports oft rauschen oder 0x00 Bits im Leerlauf produzieren, wird der gesamte Stream via **COBS (Consistent Overhead Byte Stuffing)** kodiert.
- Jedes Paket wird sauber mit `0x00` separiert.
- Im Payload selbst existieren keine `0x00` Bytes.

**Flow Control (Ping-Pong):**
Der Empfangspuffer auf MCUs ist winzig (z.B. 1 KB RAM). 
Toob-Boot sendet ein `READY` Paket. Der Host darf exakt einen Chunk (z.B. 1 KB) senden. Toob-Boot empfängt, validiert, schreibt ins Flash und antwortet mit `ACK`. 
Wenn der Host sendet, bevor ein `READY`/`ACK` kam, verwirft Toob-Boot die Bytes blind (Drop).

## 4. Naked COBS Payload Transfer
GAP-12: Die V4-Analyse hat ergeben, dass XMODEM-Overhead im S1-Bootloader zu viel Arch-Bloat (doppelte Framing/CRC-Logik) erzeugt. Wir nutzen stattdessen rohes "Naked COBS" Framing für den reinen binären Flash-Transfer. Die Integritätssicherung übernimmt ohnehin der bereits existierende Ed25519-SUIT-Envelope!
Bei erfolgreicher Übertragung triggert Toob-Boot ein `NVIC_SystemReset()`. Das Gerät bootet autonom in die frisch geflashte Partition (Stage 2).
