# Hardware Quirks Architecture (100% Hardware-Agnostik)

*Status: March 2026 - Toobfuzzer3 Core Architecture*

## 1. Das Problem: Silizium-Wissen vs. KI-Extrahierung
Der Toobfuzzer3 basiert auf einem KI-gestützten `gemini_parser.py`, der aus 3000-seitigen Technical Reference Manuals (TRMs) einen standardisierten `blueprint.json` generiert.
Während die KI Konstanten und Standard-Register aus Datenblättern perfekt extrahiert, **scheitert sie an undokumentierten Hardware-Bugs und Silizium-Spezialwissen** (den sogenannten Quirks).

Ein TRM dokumentiert nicht, dass der SPI-Arbiter eines ESP32 abstürzt ("Deadlock"), wenn der Hardware-DPORT-Cache nicht auf Transistorebene hart totgeschaltet wird, *während* der ROM-Chip gelöscht wird. 

Früher wurden solche Hacks direkt als schmutzige `if chip == "esp32"` Blöcke im Python-Compiler (`chip_generator2.py`) fest programmiert. Dies machte den Fuzzer jedoch unbrauchbar für saubere, herstellerübergreifende Portierungen (wie NXP oder Nordic).

---

## 2. Die Lösung: Die `quirks/` Ebene
Um den Fuzzer **strikt chip-agnostisch** zu halten, wurde die "Quirks JSON-Ebene" eingezogen.

Die Pipeline `pipeline_core.py` generiert den Blueprint mithilfe des LLM-Modells. **BEVOR** der C-Code jedoch kompiliert wird, führt das System einen "Deep-Merge" mit einer eventuell vorhandenen Datei unter `blueprints/quirks/{chip_name}.json` durch.

### Der Workflow für schmutzige Workarounds
1. Die Hardware stürzt bei einem neuen Chip durch unbekannte Flash/MMU/Cache-Eigenheiten ab.
2. Der Entwickler analysiert das Problem per Bare-Metal Hard-Faults oder Oszilloskop.
3. Der gefundene Hardware-Hack (z. B. das Umlegen einer magischen Speicher-Page oder das Deaktivieren der Cache-Pipeline) wird als statisches Rezept in eine dedizierte `quirks/{chip_name}.json` Datei geschrieben.
4. Der Python-Compiler (`chip_generator2.py`) übersetzt diese Datei völlig blind in nacktes C.

---

## 3. Die DSL: Der `"raw_c"` Befehl
Um dem Entwickler zu ermöglichen, im JSON auch komplexe Pointer-Mathematik auszudrücken (die sich nicht mit einem einfachen `set_bit` oder `clear_bit` abdecken lässt), wurde der `"raw_c"` DSL-Befehl eingeführt.

### Beispiel: ESP32 DPORT Cache Kill vs BootROM
```json
"erase_sector_sequence": [
    {
        "type": "raw_c",
        "code": "#define DPORT_PRO_CACHE_CTRL_REG 0x3FF00040\n    *((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) &= ~(1<<3);",
        "desc": "Kill Hardware DPORT Prefetch Pipeline to prevent SPI Arbiter Collisions"
    },
    { 
        "type": "rom_function_call", 
        "function_name": "SPIEraseSector", 
        "rom_address": "0x40062CCC", 
        "args_csv": "sector_addr / 4096", 
        "requires_physical_offset": true
    },
    {
        "type": "raw_c",
        "code": "*((volatile uint32_t*)DPORT_PRO_CACHE_CTRL_REG) |= (1<<3);",
        "desc": "Restore Hardware DPORT Pipeline"
    }
]
```

Dabei ist es völlig legal, dass die `quirks/<chip>.json` ganze Sequenz-Arrays aus der generierten Blueprint komplett überschreibt!

---

## 4. Zielerreichung: C-Compiler ohne Architekturbewusstsein
Durch die Quirk-Dateien in Verbindung mit der `pipeline_core.py` Deep-Merge-Logik verbleibt `chip_generator2.py` als dumme, ausführende Schreibmaschine. Die eigentliche Lösung komplexer Silizium-Probleme (wie MMU Seizures oder Cache Bypasses) obliegt einem reinen, portablen JSON-Rezept, das durch die Repowatt-Community für jeden exotischen Microcontroller (NXP i.MX, TI CC1352, NRF52) dezentral via Pull Requests beigesteuert werden kann.
