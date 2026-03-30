# Toob-Boot: Gap-Analyse der Architektur (Concept Fusion)

Diese Gap-Analyse evaluiert das "Toob-Boot Master-Konzept" (`docs/concept_fusion.md`) in Kombination mit der HAL-Architektur auf Produktionsrealitäten und IoT-Standardkonformität. Dabei wurden Logic-Gaps, Sicherheitsschwachstellen (Edge-Cases) und strukturelle Engpässe identifiziert. 

---

## 1. Zyklen & Watchdog (Efficiency & Maintainability)

### Gap 1.1: Falsche Watchdog-Timeout Berechnung & Kicking-Strategie
**Problem:** Das Konzept besagt (Schicht 5): Der Watchdog-Timeout wird auf Sektor-Ebene berechnet als `flash_erase_time * sectors`. Da manche Chips (z.B. STM32H7) 2 Sekunden für einen großen Sector-Erase benötigen, würde der resultierende Watchdog-Timeout astronomische Ausmaße annehmen (z.B. >20 Sekunden bei 10 Sektoren). Dies ist sicherheitstechnisch inakzeptabel: Ein hängendes System bliebe viel zu lange tot, bevor der WDT triggert.
**Mitigation (BEST):** Der berechnete WDT-Timeout darf maximal `längste_Einzeloperation (Sector_Erase) + 2x_Marge` betragen (z.B. 4-5 Sekunden). Die Lösung liegt *nicht* im Erhöhen des Timeouts, sondern darin, dass der Core zwingend **zwischen jedem** einzelnen Sector-Erase und Sector-Write ein explizites `wdt_hal.kick()` ausführt, anstatt den Timeout die Dauer aller Gesamtschritte abdecken zu lassen.

---

## 2. Boot & Confirm-Mechanismen (Security & Logic)

### Gap 2.1: Confirm-Flag Glitching / "Hardcoded Magic Bytes"
**Problem:** In Schicht 1B wird von einem Magic-Byte (`0x42` o.Ä.) im RTC-RAM gesprochen, welches das OS schreibt, um Stage 1 ein Boot-Confirm zu signalisieren. Ein attacker könnte durch gezieltes Spannungs-Glitching oder einen JTAG-Ansatz während des instabilen Boot-Phasenübergangs genau dieses einfache Bit-Muster erzeugen, um so einen kompromittierten Bootloader-Flash als "valide" festzuschreiben (Bypass der Signaturen auf fehlerhaftem Code).
**Mitigation (BEST):** Das Confirm-Flag darf kein statischer Wert sein. Stage 1 generiert bei jedem Boot eine kryptografisch sichere 32-Bit-Zufalls-Identität (Boot-Nonce). Das Feature-OS muss genau diese Nonce über die Library zurück in das Survival-RAM oder das dedizierte Register schreiben.

### Gap 2.2: Umgehung des Auto-Rollbacks durch physikalischen Button (PIN_RESET)
**Problem:** Der Core prüft laut Dokument nach dem Start: "Wenn Grund `WATCHDOG_RESET` / `SOFTWARE_PANIC`, wird ein Confirm-Flag gnadenlos ignoriert." Was passiert aber, wenn das neue OS in der UI einfriert oder anderweitig blockiert und der Nutzer instinktiv den Reset-Button am Gerät drückt? Die HAL gibt `PIN_RESET` zurück. Da `PIN_RESET` im Konzept nicht als "Fail" definiert ist, akzeptiert der Bootloader die defekte Firmware fälschlicherweise als stabil.
**Mitigation (BEST):** Erweiterung der Reject-Regel: Befindet sich das System im "Unconfirmed-State" (d.h. der erste Bootversuch nach Update), MÜSSEN auch physische Resets (`PIN_RESET`) und Unterspannungen (`BROWNOUT_RESET`) als Fehler-Trigger für ein Rollback bewertet werden.

---

## 3. Storage & Delta-Patching (Maintainability & Usability)

### Gap 3.1: Speicherlecks (RAM) beim Delta-Patching (Preflight Check)
**Problem:** Die Preflight-Gleichung zur Sicherung des 14-KB-RAM-Footprints (`Peak_SRAM = merkle.chunk_size + ...`) vergisst den Speicherbedarf des Dekompressions-Algorithmus. Für Heatshrink (non-overlapping) wird zwingend ein History/Sliding-Window im RAM benötigt (`Compression_Context`, meist 4 KB). Ohne dessen Einrechnung wird die Firmware kompilieren, aber zur Runtime einen Stack-Overflow erleiden.
**Mitigation (BEST):** Die Formel in `device.toml` / Manifest-Compiler muss zwingend um `delta.window_size` (oft 2 bis 8 KB) erweitert werden, bevor die RAM-Validierung durchstartet.

### Gap 3.2: Delta-Updates scheitern fatal an Bit-Rot (Resilience)
**Problem:** Wenn die in Slot A liegende Basis-Firmware auf dem Flash durch Hardware-Alterung leichte Defekte aufweist (Bit-Rot), schlägt der 8-Byte Base-Fingerprint-Check des Delta-Patchers korrekterweise fehl. Das bewahrt das System vor einem defekten In-Place-Mashing. Das Gerät ist dadurch aber **für immer von zukünftigen Delta-Updates ausgeschlossen**, da Slot A dauerhaft beschädigt bleibt.
**Mitigation (BEST):** Einführung eines "Fallback-to-Full" Intent im WAL-System. Weist der Bootloader ein Delta wegen eines Basisfehlers ab, protokolliert er dies persistent als Zustandsausnahme. Das Recovery-OS (oder der nächste Verbindungsversuch zum Backend) liest den Status und triggert einen **Full-Image Download** anstelle des inkrementellen Patches.

### Gap 3.3: Exponentieller Verschleiß der WAL-Sektoren (Wear-Leveling)
**Problem:** Das Journal ist als Append-Only Ring Buffer über *genau* 2 pre-erased Flash-Sektoren definiert. Da bei Delta-Patches durch "Stateful WAL-Checkpointing" massiv Daten (z. B. 4 KB Kompression-Status pro Sektor-Commit) geflasht werden, erreichen diese beiden Sektoren ihre Lebensgrenze rasant schnell, lange bevor die riesige App-Partition kaputtgeht.
**Mitigation (BEST):** Der WAL muss als "Sliding Window" über einen Pool von z.B. 4 bis 8 Sektoren migrieren können. Sobald der Erase-Counter der dedizierten Sektoren ein kritisches Limit erreicht (z.B. 80.000), verschiebt die Logik den physischen Startpunkt des Ring-Buffers dauerhaft um einen Block weiter.

### Gap 3.4: "Halb gelöschte" Sektoren nach Stromausfall (Brownout Fallback)
**Problem:** Ein Flash_Erase nimmt millisekunden bis sekunden in Anspruch. Fällt die Spannung im exakten Moment des Sektor-Löschvorgangs ab, können im Flash eingeschlossene Ladungen inkonsistente Zustände ("weder 0xFF noch 0x00") erzeugen. Wenn das WAL bei Reboot den Intent "Sektor 5 wird gelöscht" sieht und prüft, und der Zustand zufällig als "leer" interpretiert wird, zerschießt der anschließende partielle Flash-Schreibvorgang die Paritätsbits intern.
**Mitigation (BEST):** Die WAL Recovery Runtime darf niemals raten. Auch wenn ein Zielsektor optisch bereits "vermeintlich gelöscht" wirkt, **MUSS** ein unbestätigter Erase-Intent beim Reboot zwingend noch einmal von Vorn durch das harte Hardware-`EraseSector` iterieren, bevor `Write`-Operationen freigegeben werden.

---

## 4. Multi-Core & Hardware Architektur (Security)

### Gap 4.1: Bus-/Hardware-Kollision im Multi-Core Lock-Step
**Problem:** Bei asymmetrischen SoCs (wie nRF5340) fordert Toob-Boot eine "Lock-Step" Aktualisierung beider Firmware-Partitionen durch den Main-Core (App). Wenn die App (Stage 1) den Flash des Network-Cores aktualisiert, während dieser noch aktiv ist, kann dies zu physischen Flash Arbitration Faults, Memory-Bus Kollisionen und IPC-Speicherfehlern führen.
**Mitigation (BEST):** Stage 1 benötigt in der `hal_init()` ein Hardware-Constraint: Bevor irgendein Flash-Schreibvorgang eines Secondary-Images initiiert wird, **MUSS** der begleitende sekundäre SoC-Kern physisch in das Reset gehalten (forced reset hold) werden, um ihn vollständig vom internen Matrix-Bus zu entkoppeln (z.B. mittels `__HAL_RCC_C2_FORCE_RESET()`).

### Gap 4.2: Timing-Sidechannels durch OTFDEC Hashing (Hardware Crypto)
**Problem:** Es ist in Schicht 1B (Flash HAL) spezifiziert, dass On-the-Fly Entschlüsselung (OTFDEC) den Plaintext transparent zum Hashing in den RAM holt. Wenn Stage 1 die noch **nicht verifizierte** Signatur des Images (aus dem Staging Bereich) durch die echte Hardware-Krypto-MMU zieht, öffnet dies eklatante Timing-Side-Channel Angriffsvektoren, da manipulierter Ciphertext ungeschützt durch die Silizium-Hardware gepusht wird.
**Mitigation (BEST):** Die Verify-Hash-Logik muss asymmetrisch arbeiten: Die SUIT-Signatur validiert das Update über den **verschlüsselten** Text (Ciphertext-Envelope). Die Hardware-Entschlüsselung bleibt offline/deaktiviert! Das Root-OS (Backend) berechnet und signiert im Vorfeld exakt den Hash des Ciphertexts, sodass der Payload niemals von bösartigen Hardware-Engine-Entschlüsselungen profitiert.

### Gap 4.3: Unsauberes Stage-1 Self-Update "Trial" (Anti-Brick)
**Problem:** "Zwingend für Self-Updates... S1a / S1b". Ein robuster Bootloader benötigt einen Weg, um sicher sein zu können, dass ein neu geflashtes Stage-1-Image (Bank B) auch tatsächlich bootfähig ist, *bevor* der OTP Boot-Pointer in Stage 0 für immer umgelegt wird. Fehlt dieser, so fängt man sich den Super-Brick.
**Mitigation (BEST):** Stage 0 (Immutable Layer) muss eine flüchtige Fallback-Mechanik beinhalten. Nach dem Flash in Bank B aktualisiert S1 einen flüchtigen Status (z.B. `BOOT_SLOT_B_TENTATIVE`) im RTC-RAM. Stage 0 startet probeweise Bank B. Schmiert Bank B ab, triggert der WDT Stage 0, welche erkennt, dass die Freigabe des flüchtigen Registers fehlte, und bootet danach wieder stabil in Bank A. 

---

## 5. Kommunikations- und Rescue-Resilience

### Gap 5.1: Serial Rescue Desynchronisation ("Lost Bytes")
**Problem:** Das "Serial Rescue (4a)" Token verlangt laut Konzept exakt 104 Bytes zur Krypto-Authentifikation. Da der UART treiber (polling-basiert in der HAL) bei rauen Umgebungsbedingungen einzelne Bits/Bytes verlieren kann (Rauschen, Jitter am Laptop USB-Kabel), desynchronisiert der Empfang auf ewig, da der Bootloader blind jeden Byte-Chunk iterativ einlest, bis 104 Bytes erreicht sind. Der Flow würde hängen, da der Token nie komplettiert/erkennt wird.
**Mitigation (BEST):** Das Serial-Protokoll in Stage 1 muss einen strengen Magic-Preamble Sync-Header (z.B. `0xA5 0x5A`) sowie eine definierte Length-Information enthalten. Ein fehlerhaftes (oder zu kurzes) Paket kann so problemlos durch Resynchronisation ("Werfe Rest weg und warte auf neues Preamble") verworfen werden.

### Gap 5.2: Endlosschleife im Recovery-OS (Anti-Roach Motel)
**Problem:** Fällt das System zu oft wegen OS-Crashes auf Recovery zurück, triggert "Stage 1 bootet zwangsweise Recovery-OS". Aber was passiert, wenn das hinterlegte Recovery-OS ebenfalls einen tiefen Stack-Fehler enthält und kontinuierlich Watchdog-Resets ausführt? Das Gerät bliebe in einer Dauerschleife zwischen Stage 1 und crashendem Recovery hängen, was langfristig den Akku oder FlashWear killt.
**Mitigation (BEST):** Einführung eines `Recovery_OS_Failure_Counter`. Akkumuliert das Recovery-OS nacheinander N WDT-Resets (**ohne** einen `RECOVERY_RESOLVED`-Intent), deaktiviert die Stage-1 sofort sämtliche Boot-Vorgänge (auch das App-Image und das Recovery), stoppt im **Halt-State (Endlosschleife)** und aktiviert nur die Serial Rescue Konsole sowie eine warnende blinkende LED ("Rescue Only Lock").

### Gap 5.3: Energy Guard Lücken während des Flash-Vorgangs
**Problem:** Der "Energy-Guard" checkt die Batterie laut Dokument "VOR" dem Update. Da Update-Vorgänge aber erhebliche Mengen Strom (z.B. >200 mA über Wi-Fi und Flash auf ESP32) ziehen können, kann die Batteriespannung *während* der Flash-Berechnung katastrophal auf ein kritisches Brownout-Level abfallen, was ungewollte System-Panics verursacht.
**Mitigation (BEST):** Das Battery-Polling in `power_hal.c` muss aktiv gebatched (interleaved) werden. Der Core sollte zwingend zwischen z.B. allen 10 `Write`-Vorgängen oder jedem Hardware-`Erase` eine `battery_level_mv()` Prüfung im aktiven Modus durchführen. Fällt der Wert, pauset (Suspend) die State Machine *proaktiv* in einen Low-Power Sleep (`enter_low_power`), um dem Akku eine Chemische-Regeneration zu ermöglichen, bevor der eigentliche Brownout-Circuit eingreift.

---

## 6. Datenhaltung und Skalierung

### Gap 6.1: Isolation der Memory-Map in der '.noinit' Diagnose (Dev Experience/Security)
**Problem:** "Sammelt... in einer exklusiven `.noinit` Shared-RAM Sektion." Diese Bereiche überstehen den Boot, aber was passiert nach einem willkürlichen WDT Reset mitten in einer fehlerhaften Speicherberechnung des OS? Die `.noinit` Sektion kann mit zufälligem Garbage überschrieben sein. Liest Stage 1 oder das OS diese Daten nun als "valide Telemetrie" aus, explodieren nachfolgende Parser im Cloud-Backend.
**Mitigation (BEST):** Eine harte Struct-Contract Validierung: Die Telemtriedaten fordern zwingend eine Struktur aus Magic Number, Boot Session ID Vektor, Payload Length und einem CRC-16 Checksummen-Trailer. Frequenzüberschneidende "Garbage-Reste" des RAMs werden so sofort maskiert und beim Boot sicher abgewiesen.

### Gap 6.2: Anti-Rollback (SVN) E-Fuse Limitierung
**Problem:** "SVN (Monotonic Counter) ... veraltete Firmware rigoros abweist". Hardware E-Fuses, die SVNs absichern, haben endliche Bit-Reserven (z.B. oft nur 64 oder 256 mögliche Schritten). Was, wenn bei täglichen C-IoT-Updates das Maximum des Chips nach 3 Jahren physisch ausgeschöpft ist? Die Hardware wird un-updatable.
**Mitigation (BEST):** Implementierung einer hybriden SVN-Methodik (Minor und Major Updates). Alltags-Updates werten ihre Version lediglich durch kryptografische Logs in WAL-Einträge auf, die Minor-Inkremente speichern ("Virtual SVN"). Nur, wenn ein essenzieller CVE/Exploit auftritt (Major Security Bump = Epoch Change), fordert das SUIT Manifest via Flag ein manuelles, stark limitiertes Durchbrennen der Hardware E-Fuses, um das physische Rollback-Schott zu verschließen.

### Gap 6.3: Key-Revocation Fehlt (Sicherheit der Supply-Chain)
**Problem:** Die Dokumentation nennt eine "Key-Index Rotation via OTP-eFuses", jedoch fehlt der Workflow, **wer** oder **wann** diese Roterung initiiert wird, sollte ein Root-Key des Herstellers abhandenkommen.
**Mitigation (BEST):** Erweiterung des SUIT-Manifest Parsers in Schicht 3 um ein PFLICHT-Feld: `Required_Key_Epoch`. Erkennt Stage 1, dass das erfolgreich verifizierte Image eine neuere Schlüssel-Epoche `N+1` vorschreibt, als die Hardware derzeit zulässt (`Epoch N`), befiehlt der Bootloader via HAL sofortiges eFuse-Brennen in die nächste Stufe und revoziert so physisch die Gültigkeit entwendeter Alt-Signierschlüssel.
