# ESP32 Bare-Metal Hardware Hacks & Technical Debt

*Status: March 2026 - Toobfuzzer3 Flash Hardening Pipeline*

Dieses Dokument erfasst alle hardware-spezifischen ESP32-Hacks ("Schmutzige Workarounds"), die derzeit aktiv im Fuzzer-Code oder in den generierenden Python-Skripten (`chip_generator2.py`) liegen, um den Fuzzer nach hartnäckigen Silicon-Freezes zu stabilisieren. 

Diese Workarounds verstoßen aktuell gegen die "100% Hardware-Agnostik" Regel der Architektur und müssen zukünftig aus dem Python-Code entkoppelt und als sauberes Data-Driven-Design in die `blueprint.json` migriert werden.

## 1. Das MMU Seizure Konzept (ESP32 `read_c`)

### Der Absturz (Symptom)
Wenn der ESP32 im nackten Bare-Metal läuft, frieren BootROM Lese-Befehle (z. B. `esp_rom_spiflash_read`) reproduzierbar das System ein ("Arbiter Deadlock"), weil sie tief auf nicht mehr existierende OS-Strukturen (`.bss` RAM des ESP-IDF) zugreifen.

### Der aktuelle Hack
Wir umgehen das Lesen über ROM vollkommen: In `chip_generator2.py` (Ziele 235+) haben wir eine rein physische Umschreibung der ESP32 Memory Management Unit (MMU) hardcodiert.
Wir biegen live die Virtual Page 13 (`0x400D0000`, fester IROM0-Bereich) auf die gewünschte physikalische SPI-Flash Zeile um und lesen dann roh einen C-Pointer aus (`*out_val = *((volatile uint32_t*)(0x400D0000 + p_offset));`).
*(Früherer Bug: Der Versuch, Virtual Page 12 `0x400C0000` zu nehmen, crashte die Matrix, weil dieser Bereich intern ins RTC fast-IRAM geroutet ist).*

### Wie es agnostisch gelöst wird
Momentan liegt dieser Code in `chip_generator2.py` in einem hässlichen `if chip_name == "esp32":` Block.
**Lösung:** Wir fügen der `blueprint.json` für den ESP32 das Attribut `"read_word_sequence": [...]` hinzu. In dieses JSON-Array wird dieser gesamte MMU-Code portiert (als abstraktes Sequence-Literal). Das Python-Skript wird bereinigt und baut dann nur noch dumm die Sequenz aus der JSON zusammen. Andere Mikrocontroller (STM32, NRF) haben ein leeres (oder triviales Pointer-Read) Sequence-Feld in ihrer JSON.

---

## 2. DPORT Hardware Cache Bypass (Arbiter Deadlocks)

### Der Absturz (Symptom)
Während extrem vieler `Erase` oder `Write` Operationen (welche `SPI1` über BootROM nutzen) friert das System stumm ein. Ursache: Die ESP32 Xtensa CPU hat eine "Speculative Fetch" Pipeline. Sie versucht ungefragt den Flash-Cache (`SPI0`) im IROM vorausladen, *während* `SPI1` gerade auf dem Flash-Chip feuert. Diese Hardware-Kollision im SPI-Arbiter führt sofort zum Totalschaden des Busses.
Die logische Lösung – den Cache via BootROM `Cache_Read_Disable(0)` herunterzufahren – führt **ebenfalls** zum Absturz, da auch diese ROM-Funktion den fehlenden `.bss`-Bereich erwartet.

### Der aktuelle Hack
Wir greifen brutal auf Bit-Ebene in das Hardware-Register ein, um den Cache ohne ROM-Funktionen den Saft abzudrehen (sog. DPORT Bit-Banging):
```c
#define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040
#define HW_CACHE_DISABLE() (*((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3));
#define HW_CACHE_ENABLE()  (*((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3));
```
Diese Macros umklammern aktuell universal *jeden* `erase` und `write` Befehl, der von `chip_generator2.py` erzeugt wird, auch wenn es für einen STM32 kompiliert wird! Das ist hochgradig destruktiv für non-ESP Architekturen.

### Wie es agnostisch gelöst wird
Diese DPORT-Locks sind astreines ESP32-Siliziumwissen. Sie gehören ausschließlich in das `blueprint.json` des ESP32, gekapselt als Pre- und Post-Commands in den JSON-Arrays `"erase_sector_sequence"` und `"write_word_sequence"`.
Umsetzung:
1. `HW_CACHE_DISABLE()` als Register-Write Sequenzschritt `VOR` dem eigentlichen Erase einfügen.
2. `HW_CACHE_ENABLE()` als Register-Write Schritt `NACH` dem eigentlichen Erase einfügen.
Der Python-Code kriegt davon nichts mit und generiert einfach stur die Sequenzen aus dem JSON.

---

## FAZIT & NEXT STEPS
Sobald der Fuzzer-Test endgültig einen stabilen, 100-prozentigen Durchlauf über den 4MB ESP32 Flash vermeldet, haben wir die Silizium-Ebene besiegt. 
Der unmittelbar nächste Schritt ist dann das Entkernen von `chip_generator2.py` und das Ausformulieren der sauberen JSON-Datenstruktur, um Toobfuzzer3 wieder **strikt agnostisch** zu machen.
