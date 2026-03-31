# Testing Requirements & P10 Verification

> Validierungsprotokoll für die Toob-Boot Architektur nach P10 Standards.

Da Fehler im Bootloader Bricks bei tausenden Geräten verursachen können, muss die C-Implementierung strikten Validierungsgates unterzogen werden, bevor sie in Produktion geht.

## 1. Link-Time Mocking (Software Integration Tests)
Um die gesamte Logik (WAL, TMR, State-Machine) von `Toob-Boot` auf dem Host (`x86`/`ARM64`) ohne Silizium zu testen, wird die Hardware weggemockt.
- GNU Linker Option: `--wrap=flash_hal_read` etc. wird verwendet, um die `hals.md` Calls abzufangen.
- RAM-Disk: Die Flash-Calls lesen und schreiben in eine 4MB dicke mmap-Simulationsdatei (`flash.bin`).

**Pflicht-Szenarien (SIL):**
- Abbruch des Updates bei 0%, 50%, 99% → Sicherstellung, dass WAL-Rollbacks greifen.
- Injektion von "0x00" oder "0xFF" Bytes in das OS-Image (Bit-Rot Simulator) → Sicherstellung, dass `boot_verify` anschlägt.
- Erschöpfung des Exponential Backoffs → Recovery-OS Einstieg bestätigen.

## 2. HIL Fault-Injection (Hardware In Loop)
Neben SIL muss Toob-Boot in einem physischen Test-Rack validiert werden.
Mittels Stromverteiler-Relais werden gezielte "Power-Loss" (Brownout) Szenarien an den Ziel-MCUs erzeugt.
1. Flash-Write unterbrechen: Das Relais kappt die VDD exakt 20µs nach einem SPI Write.
2. Der Folge-Reset **muss** den `wdt_hal` aktivieren und den korrupten SPI-Sektor dank WAL sauber recovern.

## 3. P10 Code-Standards (Statische Analyse)
Für die C-Core (`boot_*.c`) gelten folgende statische Regeln, validiert durch CI-Parser (OSVisualizer / Clang-Tidy):
- **Keine dynamische Allokation:** `malloc`, `free`, `realloc` sind als Build-Fehler deklariert. Alles nutzt das statische SRAM (BSS/DATA).
- **Keine ungebundenen Schleifen:** Jedes `while()` / `for()` benötigt ein statisches Upper-Bound, um Dauerläufer auszuschließen.
- **Rückgabewert-Zwang:** Jede returnende Funktion vom Typ `boot_status_t` muss im Parent via `if(result != BOOT_OK) return result;` eskaliert werden. 

Erfüllen alle Tests 100% Durchlauf, gilt der Stand als "Mission-Critical Ready".
