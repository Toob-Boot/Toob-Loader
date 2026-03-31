# Toob-Boot: Gap-Analyse der Architektur (Phase 2)

Basierend auf der aktualisierten `docs/concept_fusion.md` (und den darin bereits behobenen ursprünglichen Design-Schwächen) wurde eine weitere, tiefgreifende Architektur- und Logik-Evaluierung durchgeführt. Folgende weitere Schwachstellen (Edge-Cases, Krypto-Desynchronisationen, Hardware-Fallstricke) fallen als kritische Gaps für den Productive-Einsatz auf:

---

## 1. Boot-Logik & State Machine (Security & Resilience)

### Gap 1.1: Stage 0 "Trial Boot" Endlosschleife
**Problem:** S1 setzt ein `BOOT_SLOT_B_TENTATIVE` Flag im RTC-RAM. Stage 0 liest dieses und bootet Slot B. Wenn Slot B durch einen inkompatiblen ABI-Crash oder Stack-Fehler *sofort* crasht (noch bevor S1 den Start intern loggen kann), greift der Hardware-Watchdog ein und resettet den Chip. Stage 0 startet wieder, liest erneut das ungelöschte TENTATIVE-Flag und springt unwiderruflich wieder in den fehlerhaften Slot B. Das Gerät hängt in einer permanenten Stage-0 Endlosschleife und brickt.
**Mitigation (BEST):** Stage 0 muss zwingend das `RESET_REASON` Register in Kombination mit dem Flag auswerten. Erkennt Stage 0 das TENTATIVE-Flag *zusammen* mit einem vorherigen `WATCHDOG_RESET` oder `SOFTWARE_PANIC`, MUSS Stage 0 das Flag im RAM sofort vernichten und sicher auf den funktionierenden Slot A zurückfallen.

### Gap 1.2: Boot-Nonce Amnesie nach dem Soft-Reset
**Problem:** Der Core generiert bei jedem Update eine einmalige 32-Bit Boot-Nonce, die das OS zur Bestätigung zurückschreiben muss. Wenn das OS danach jedoch den geforderten *Soft-Reset* (Hardware-Neustart) durchführt, gehen der S1-SRAM und alle Nonce-Zwischenspeicher verloren. Nach dem erneuten Aufwachen hat Stage 1 keine Ahnung mehr, welche Nonce es generiert hatte, und kann den Confirm-Verify nicht mehr mathematisch beweisen.
**Mitigation (BEST):** Bevor Stage 1 in das unbestätigte Update-OS bootet, MUSS die generierte `EXPECTED_NONCE` als permanenter State (z. B. als `NONCE_INTENT`) verschlüsselt ins WAL-Journal geflasht werden. Nur so kann S1 nach dem Reboot die Rückmeldung aus dem RTC-RAM verifizieren.

## 2. Flash-Verschleiß & Wear Leveling (Efficiency)

### Gap 2.1: WAL Write-Amplification Flash Death bei Delta-Patches
**Problem:** Das "Stateful WAL-Checkpointing" fordert, dass S1 bei jedem Sektor-Commit den aktuellen Kompressions-Status (~4 KB `compression_context` für Heatshrink) in das WAL flasht, um stromausfallsichere Wiederherstellung zu bieten. Bei typischen MCUs mit 4KB Sektor-Größe bedeutet dies: Auf jeden geschriebenen 4KB App-Speicherblock flasht die Engine erneut 4KB in das Journal. Die Write-Amplification zerstört die dedizierten WAL-Sektoren exponentiell schnell und tötet den Flash-Speicher weit vor seiner Zeit.
**Mitigation (BEST):** Keine RAM-Snapshots in den Flash! Delta-Patches (vom Backend) MÜSSEN in unabhängige Chunks/Blöcke (z.B. 16 KB) unterteilt werden. Zu Beginn jedes Chunks reseted sich das Decompressor-Dictionary nativ. Das WAL muss dann lediglich die winzige 8-Byte Pointer-Referenz (`Chunk_ID`, `Offset`) speichern, um genau an einer deterministischen Wörterbuch-Reset-Grenze neu anzusetzen.

### Gap 2.2: Physische Schwachstelle bei TMR (Triple Modular Redundancy)
**Problem:** Das Boot-Status Flag wird 3x auf den Flash geschrieben (Majority-Vote). Wenn die Implementation diese drei Kopien direkt hintereinander auf die identische Flash-Page (z. B. Sektor 0) schreibt, wird ein fehlschlagender Hardware-Sektor-Erase oder ein physischer Bit-Rot auf diesem Stück Silizium *alle drei* Kopien zeitgleich zerfetzen. Die Redundanz wäre rein logisch, nicht aber hardware-ausfallsicher.
**Mitigation (BEST):** Die drei Instanzen des TMR-Datenblocks MÜSSEN strikt "gestrided" (verteilt) über *mindestens zwei*, im besten Fall drei physisch getrennte Flash-Sektoren (Erase-Blocks) abgelegt werden.

## 3. Power-Management & Hardware Connectivity

### Gap 3.1: Die Energy Guard "Sleep-Illusion" vs. Reale Brownouts
**Problem:** Wenn die Batterie unter Last abfällt, pauset der Bootloader proaktiv in einen `Low-Power Sleep`, um der Batterie eine "chemische Regeneration" zu erlauben. Wenn ein Akku aber extrem schwach/leer ist oder von einem Nutzer kurz vor dem Abklemmen steht, regeneriert dort nichts. Das Gerät verbleibt mitten in einer offenen WAL-Transaction im Sleep. Fällt der Strom final auf 0V, verliert das RAM die Puffer und der Status verrottet bei teilgelöschtem Flash.
**Mitigation (BEST):** Chemische Entspannung ist kein Allheilmittel. Bei Feststellung massiver Unterspannung unter Last darf nicht endlos geschlafen werden: Der Bootloader muss die aktuelle Transaction bewusst als `TXN_ROLLBACK` abschließen, den Speicher konsistent hinterlassen und sofort auf das alte, stabile App-Image ausweichen (inkl. Flag `UPDATE_FAILED_LOW_BATTERY`), damit das OS dem Nutzer eine "Bitte Aufladen" Warnung zeigen kann.

### Gap 3.2: Multi-Core "Forced Reset Hold" Bus-Deadlock
**Problem:** Es ist vorgeschrieben, Secondary-Cores vor Flash-Writes hart im Reset zu halten (`FORCE_RESET_HOLD`). Wenn dieser Secondary-Core exakt in der Mikrosekunde, in der Stage 1 die Reset-Leitung zieht, eine aktive Operation auf der Shared-Bus-Matrix (z. B. DMA-Transfer, IPC-Mailbox Lock) durchführte, friert der unvollständige Transfer den Matrix-Bus ein. Stage 1 (Primary Core) könnte sich aufhängen, wenn es versucht, auf blockierte Peripherie zuzugreifen.
**Mitigation (BEST):** Stage 1 muss vor dem Anlegen der `FORCE_RESET_HOLD` zwingend eine Architektur-spezifische Bus-Säuberung anstoßen (z. B. Reset der AHB/APB Bridges für den Secondary Core oder Clearing offener DMA-Kanäle), um hängende Bus-Transaktionen physikalisch abzubrechen.

### Gap 3.3: Unmöglichkeit des WDT-Kicks bei Vendor-ROM Erases
**Problem:** Das Konzept verbietet Timeouts größer als `longest_OP + 2x_Marge` und verlangt Kicks "zwischen" Operationen. Ein Vendor-Erase (z. B. `SPIEraseSector`) wird jedoch als monolithische, blockierende C-Funktion über den geforderten ROM-Pointer (`0x40062CCC`) ausgeführt. Diese kann intern 3 Sekunden dauern. Ein "Dazwischen-Kicken" ist auf Instruktionsebene bei kompiliertem ROM Black-Box-Code unmöglich.
**Mitigation (BEST):** Die Spezifikation muss explizit fordern, dass große Sektor-Löschungen in kleinere Sub-Block-Erases (z. B. 4KB statt 64KB Blöcke) gestückelt werden, zwischen denen gekickt wird. Unterstützt die Vendor-ROM dies nicht verschachtelt, MUSS die HAL zwingend kurz vor Aufruf der ROM-Funktion den Watchdog-Prescaler temporär auf das absolute ROM-Maximum hochskalieren und direkt danach wieder verkleinern.

## 4. Usability, Dev Experience & Flottenwartung (Maintainability)

### Gap 4.1: Erzwungener Soft-Reset (UX-Katastrophe)
**Problem:** Das OS MUSS das Flag schreiben und einen sofortigen `SOFTWARE_PANIC` / Soft-Reset durchführen, damit S1 den Start verifiziert. Einen frischen Boot (inkl. Peripherie-Setup und Netzwerk-Auth) nach Sekundenbruchteilen sofort wieder durch einen Hardware-Reset niederzuknüppeln, provoziert doppelte Loading-Screens beim Enduser, Netzwerkanomalien und massiven Batterieverschleiß. Es gibt keinen guten Grund, warum das System sofort neustarten muss!
**Mitigation (BEST):** **Asynchrones Confirming**. Das OS schreibt das Flag via HAL in das RTC/NV-RAM. Das Update gilt fortan als gesichert ("Tentatively Alive"). Stage 1 erzwingt KEINEN frischen Reboot. Die Verifizierung und Archivierung (Freigabe des Staging-Flashs) nimmt Stage 1 passiv und geräuschlos erst beim *nächsten, natürlichen Kaltstart* vor. (Optional kann das OS durch Interprozesskommunikation signalisieren, dass S1 den Flash bereinigen darf).

### Gap 4.2: Permanent "Rescue Only Lock" killt Remote-Installationen
**Problem:** Wenn das Recovery-OS in einer Crash-Schleife läuft, verfällt das System in den "Halt-State / Rescue Only Lock" und wartet auf ein serielles Kabel. Bei Edge-Nodes (auf Windrädern, an Bojen) bedeutet der absichtliche Halt eine Garantie für enorme Wartungskosten ("Truck-Roll"), da dort niemals spontan ein Service-Mitarbeiter vorbeiläuft.
**Mitigation (BEST):** Einführung eines `edge_unattended_mode` im Manifest. Ist dieser aktiv, nutzt Stage 1 anstelle des permanenten Lockouts einen **Exponential Backoff-Timer** (1h, 4h, 12h, 24h). Das System fällt tief schlafen und versucht den Recovery-Boot nach Ablauf erneut. Bei Umweltbedingungen (Hitze, temporäre Funkstörer) kann sich ein Fehler später von selbst beheben.

### Gap 4.3: Serial Protocol 0xA5 Preamble Collision
**Problem:** Der Serial-Rescue-Stream verlässt sich auf eine statische Preamble (`0xA5 0x5A`) zur Resynchronisation verlorener Bytes. Da die folgenden Payloads (Ed25519-Signaturen, Hashes) echte rohe, hoch-entropische Kryptodaten sind, besteht eine statistische Wahrscheinlichkeit, dass die Preamble im Payload vorkommt. Das zerreißt die Byte-State-Machine unweigerlich und bockt das Rescue-Protokoll dauerhaft aus dem Tritt.
**Mitigation (BEST):** Das Serial-Protokoll der Stage 1 muss über **COBS (Consistent Overhead Byte Stuffing)** kodiert werden. COBS garantiert mathematisch, dass das Frame-Trennzeichen (z. B. `0x00`) *niemals* in den Payload-Bytes auftauchen kann. Verlust-Synchronisation ist durch dieses Framing zu 100% ohne False-Positives gegeben.

### Gap 4.4: DICE / CDI Cloud-Lockout (Offline Orphan)
**Problem:** Das Firmware-Update ändert die kryptografische Identität (CDI). Das alte OS empfängt das Update, empfängt den "Intent", und bootet das neue OS. Durch unglückliches Timing fällt das lokale LoRa-GW oder WLAN am Standort des IoT-Geräts jedoch exakt jetzt für 4 Tage aus. "Das Backend muss ein TTL von max 72h setzen". Das Backend wirft den Intent nach 72h weg. Am 4. Tag kommt das Gerät online und präsentiert seine neue, upgedatete Identität. Das Backend lehnt sie ab! Das Gerät ist permanent aus der Cloud ausgeschlossen.
**Mitigation (BEST):** Ein lokales **Bootloader-Fallback Pattern für das OS**. Das neue OS MUSS erfolgreich online gehen und den Zwei-Wege-Handshake (Bestätigung der neuen CDI im Netzwerk) abschließen. Erst WENN das Backend die neue Identität bestätigt hat, schreibt das OS das "Update_Confirmed"-Flag auf Hardware-Ebene. Scheitert das OS über X Tage am Cloud-Login, löscht es absichtlich das Confirm-Flag (oder setzt es gar nicht erst) und erzwingt einen Reset, um über den Bootloader einen strikten Rollback auf Slot A (mit der alten, noch bekannten CDI) auszulösen!
