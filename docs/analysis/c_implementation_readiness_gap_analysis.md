# C-Implementation Readiness Gap Analysis

> Generiert durch die Workflow-Anweisung /gap-analysis. 
> Fokus: Übergang von den konzipierten Toob-Boot Spezifikationen zur tatsächlichen C17-Produktionsimplementierung. Identifikation und Lösung von "Reibungspunkten" und Low-Level Architektur-Fallen.

Dieses Dokument führt die identifizierten architektonischen Restrisiken auf, die vor oder während der C-Implementierung gelöst werden müssen, um P10-Compliance und absolute Hardware-Robustheit zu garantieren.

---

### GAP-C01: TMR Striding vs. Asymmetric Sector Waste (Efficiency)
*   **The Problem:** Triple Modular Redundancy (TMR) sichert langlebige State-Werte durch dreifache Kopien. Die Spezifikation fordert aus Sicherheitsgründen die Trennung auf drei physikalisch isolierte Erase-Sektoren. Auf Chips mit riesigen Hauptsektoren (z.B. STM32H7: 128 KB) würde die dreifache Speicherung eines winzigen 4-Byte `Current_Primary_Slot` Wertes absurd große **384 KB Flash-Speicher zunichtemachen**.
*   **The Mitigation:** Wir integrieren die TMR-Kopien formal in das existierende Write-Ahead-Log (WAL) Journal. Da das Journal (bestehend aus 4 bis 8 rotierenden Sektoren) ohnehin Wear-Leveling und Ring-Buffer Garantien bietet, können die drei TMR-Kopien versetzt in die Header von drei sequenziellen WAL-Sektoren geschrieben werden. Dies kostet 0 zusätzliche Flash-Sektoren und erreicht dennoch perfekte physikalische Isolation (`wal_sector[n]`, `wal_sector[n+1]`, `wal_sector[n+2]`).

### GAP-C02: Monolithic Flash Erase vs. nRF52 WDT Lockup (Security / Robustness)
*   **The Problem:** Wie in `hals.md` erwähnt, kann der WDT auf einigen Plattformen (nRF52) nach Start nicht mehr gestoppt oder pausiert werden (`suspend_for_critical_section` ist ein No-Op). Das Löschen einer 1 MB großen App-Partition über Hardware-Makros kann bis zu 22 Sekunden blockieren. Der WDT (typ. 3-5 Sek) schlägt unaufhaltsam zu.
*   **The Mitigation:** Der C-Core (`boot_swap.c` und `boot_rollback.c`) **DARF NIEMALS** eine Range größer als `CHIP_FLASH_MAX_SECTOR_SIZE` auf einmal an die `flash_hal->erase_sector` übergeben. Jede Bulk-Erase Operation MUSS zwingend als C-Schleife (Bounded Loop) über Einzel-Sektoren implementiert werden. Nach exakt jedem Schleifendurchlauf rufen wir `wdt_hal->kick()` auf.

### GAP-C03: WAL Struct Padding & Write Alignment Corruptions (Integrity / Maint.)
*   **The Problem:** Verschiedene Hardware-Plattformen zwingen zu rigiden Write-Alignments (ESP: 4 Byte, STM32L4: 8 Byte, NXP: 16 Byte). Die C17-Strukturen der WAL-Einträge (`wal_entry_t`) werden vom Compiler oft dicht gepackt (z.B. auf 20 Bytes). Ein nackter Write einer 20-Byte Struct über einen 8-Byte Aligned HAL Driver löst direkt HardFaults aus oder korrumpiert die verbleibenden 4 Bytes des Flash-Worts.
*   **The Mitigation:** Die WAL C-Structs nutzen das `CHIP_FLASH_WRITE_ALIGN` Macro aus dem gerenderten Manifest. Wir nutzen eine `union` innerhalb der Struct, die das Padding gegenüber dem Alignment-Limit auffüllt:
    ```c
    typedef union {
        struct {
            uint32_t magic;
            uint32_t type;
            uint64_t payload;
        } data;
        uint8_t raw_align[ ((sizeof(data) + CHIP_FLASH_WRITE_ALIGN - 1) / CHIP_FLASH_WRITE_ALIGN) * CHIP_FLASH_WRITE_ALIGN ];
    } wal_entry_t;
    ```
    Dazu ein statischer Assert: `_Static_assert(sizeof(wal_entry_t) % CHIP_FLASH_WRITE_ALIGN == 0, "WAL Align Error");`

### GAP-C04: PQC Stack Overflow in the Bootloader (Stability)
*   **The Problem:** Die Spezifikation ermöglicht Post-Quantum Cryptography (PQC wie ML-DSA-65) als hybrides Fallback. ML-DSA erfordert während der Matrix-Multiplikation temporär rund 10 KB bis 30 KB Working-Memory. Eine Allokation dieses Bereichs als reguläre lokale Variable (`uint8_t matrix[15000];`) reißt den MCU-Callstack ein und bricked den Bootloader via Stack-Overflow.
*   **The Mitigation:** Exakte Definition im Core: PQC-Module MÜSSEN den vom Linker bereitgestellten Pointer auf die statische BSS `crypto_arena[BOOT_CRYPTO_ARENA_SIZE]` konsumieren. Die `verify_pqc` HAL-Signatur erhält einen zwingenden Scratchpad-Pointer als Argument, damit die PQC-Engine strikt in diesem dedizierten Memory rechnet.

### GAP-C05: Delta-Patch Dictionary Stateful Resets (Dev Experience / Logic)
*   **The Problem:** Ein laufender In-Place Delta-Patch bricht aufgrund eines Power-Loss ab. Der komprimierte Patch-Stream (z.B. via `detools`) baut über die Zeit ein gleitendes Entkomprimierungs-Wörterbuch (LZ/Dictionary) im SRAM auf. Startet die MCU neu, ist das SRAM weg. Ein Fortsetzen des Patches mitten im Stream würde nur Garbage erzeugen.
*   **The Mitigation:** Der Python `delta_builder.py` des Host-Toolings segmentiert Delta-Patches zwingend in unabhängige Frame-Gatter (Reset-Intervalle von 16 KB oder der `max_sector_size`). Die Bootloader C-Logik (`boot_delta.c`) loggt im WAL nur vollständige 16 KB Frames. Nach einem Brownout beginnt der Bootloader exakt am Start des letzten nicht abgeschlossenen 16 KB Frames, woraufhin sich das Decompressor-SRAM durch den gezielten Reset sauber neu synchronisiert.

### GAP-C06: Serial Rescue DoS durch Ed25519 Spamming (Security)
*   **The Problem:** Stage 1.5 (Serial Recovery) fragt nach einem 104-byte Auth-Token. Ein Angreifer könnte tausende gefälschte Ed25519-Signaturen via UART Spammen. Die Berechnung eines Ed25519 Verifys kostet auf Cortex-M4 ca. ~9ms. Währenddessen ist das System ausgelastet, Puffer könnten überlaufen oder legitime Tokens werden gedroppt (Denial of Service).
*   **The Mitigation:** Implementierung eines Penalty-Timers in `boot_panic.c`. Nach der Evaluierung einer ungültigen Signatur legt sich der UART-RX Polling-Loop für eine Zeit $T_{penalty} = 2^{failures} \times 100\text{ms}$ schlafen (wobei der WDT weiterhin gekickt wird). Der Buffer wird vorher sicher geflusht.

### GAP-C07: End-Of-Life (EOL) Survival Mode Lockout Loop (Maintainability)
*   **The Problem:** Ein Gerät erreicht 80.000 (oder MAX) Flash-Erase-Zyklen. Die Spezifikation verlangt, dass das System in einen `STATE_READ_ONLY` fällt, also den Wear-Leveling-Totalkollaps aufhält. Würde dieser neue Read-Only Status jedoch persistiert, müsste das WAL dazu selbst noch einen Flash-Erase/Write ausführen – und verletzt damit direkt die eigene Grenze, was potenziell eine Endlos-Exception auslöst.
*   **The Mitigation:** Der `STATE_READ_ONLY` wird niemals auf den Flash geschrieben. Beim Kaltstart lädt der Bootloader den Erase-Counter aus dem Journal. Ist der Wert `>= MAX_LIFECYCLE`, schaltet der C-State der State-Machine (`boot_state_t`) logisch in den Read-Only Modus (Ram-based state) und füllt das `diag._noinit` mit dem Warn-Ident. Hardware-Writes werden ab hier abgewiesen.

### GAP-C08: Zero-Verification Read after Confirm Clear (Integrity)
*   **The Problem:** Das OS-Handoff verlässt sich darauf, dass das Bestätigungs-Flag gelöscht ist (`confirm_hal->clear()`). Nutzt das Gerät Flash als Backup und der Löschvorgang schlägt durch "Silent Bit-Rot" oder einen kapazitiven Spannungsabfall fehl, könnte das System beim nächsten WDT-Reset eine falsche (noch alte, scheinbar gültige) Boot-Nonce lesen.
*   **The Mitigation:** Striktes Zero-Verification Lesen als Vertrag der HAL:
    Jede Implementierung von `confirm_hal.clear()` MUSS das Flag physikalisch lesen, nachdem sie es gelöscht hat. Ist das Flag ungleich `0x00`/`0xFF` (erased logic), returnt die HAL `BOOT_ERR_FLASH`. S1 geht sofort in den atomaren Panic-State und meldet den Totalschaden, anstatt in ein instabiles und unkontrollierbares OS zu springen. 
