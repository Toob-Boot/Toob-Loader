# Toobfuzzer3 & Manifest Compiler Integration

> **Status:** Architektur-Gedanken & Integrations-Strategie
> **Ziel:** Ablösung der statischen `chip_database.py` durch empirisch bewiesene und KI-generierte Hardware-Wahrheiten aus dem `toobfuzzer3`.

---

## 1. Die Ausgangslage

Der **Manifest-Compiler** (Schicht 5) verlangt ultimative Hardware-Wahrheiten, um deterministische Linker-Scripte, RAM-Budgets und Flash-Sektorengrenzen zu berechnen.
Bisher war der Plan, diese Wahrheiten per Hand in einer Python-Datei (`chip_database.py`) zu pflegen.

Das Problem: Es skaliert nicht für Custom-Boards und hunderte Microcontroller-Revisionen.

Die Lösung liegt im **Toobfuzzer3**, der auf zwei Ebenen exakt diese Wahrheiten ermittelt:

### A. KI-gestütztes Parsing (`<xyz>_chip.json`)
*   **Fokus:** CPU-Execution, Memory-Mapping, Security-Rings & Toolchain.
*   **Liefert:**
    *   Exakte SRAM/ROM-Ausführungsgrenzen (`memory.memory_regions` inkl. Permissions)
    *   ABI-Initialisierungs-Assembly (z.B. RISC-V `__global_pointer$` Setup)
    *   Watchdog-Register (Exakte Hex-Adressen und Magic-Unlock-Werte)
    *   Security-Register (JTAG-Locks, Flash-Encryption)
    *   **Toolchain-Requirements** (z.B. Make-Targets, Compiler-Prefixe und `esptool.py` Flash-Scripte)
*   *Warum wertvoll:* Spart Wochen an Recherche. Liefert nicht nur Code, sondern konfiguriert das CMake-Buildsystem des OS komplett automatisch.

### B. Empirischer Hardware-Scan (`aggregated_scan.json`)
*   **Fokus:** Physische Speicherstruktur (Flash & RAM).
*   **Liefert:**
    *   Sektor für Sektor die **reale** Speicherstruktur des Chips (z.B. `1073741824` → Sektorgröße `4096`).
    *   Prüft durch `run_ping` und `run_pong`, ob Sektoren wirklich persistieren und beschreibbar sind.
*   *Warum wertvoll:* Liefert die `sector_sizes` und das absolute Flash-Layout, ohne sich auf oft falsche Hersteller-PDFs verlassen zu müssen.

---

## 2. Die neue TOML-Integration: Registry-Logik & `[hardware_profile]`

Um den Toobfuzzer3 strukturell mit der Manifest-Pipeline zu verheiraten, ohne das `device.toml` unübersichtlich aufzublähen, nutzen wir ein **Zwei-Stufen Registry-System**:

### A. Core-Lib (Built-in)
Das sind die offiziellen, von uns getesteten Chips (ESP32, STM32, NRF). Sie liegen fest im Manifest-Compiler (`chip_database.py` oder interne JSONs).
Wenn der User `chip = "esp32s3"` schreibt, wird immer diese priorisiert.

### B. Custom/Community-Lib (Lokale Registry)
Wenn ein User einen exotischen Chip hat, legt er (oder der Toobfuzzer!) eine JSON-Datei nach unserem Standard-Format in einen lokalen Projektordner ab, z.B. `.toob/chips/custom_nuvoton.json`. **WICHTIG:** Die Quelle dafür ist das detaillierte AI-Run-Ergebnis aus dem Toobfuzzer (z.B. `esp32-c6_chip.json`).

In der `device.toml` steht dann einfach:
```toml
[device]
chip = "custom_nuvoton" # Compiler findet es in der lokalen Registry!
```

**Alternativer Fallback:** Für absolute Edge-Cases (oder zum schnellen Ausprobieren ohne extra Datei) kann der User die Wahrheit auch weiterhin hart in die `device.toml` als `[hardware_profile]` Block schreiben. Die Priorität lautet:
1. `[hardware_profile]` Override in der TOML
2. Lokale Custom-Registry (`.toob/chips/`)
3. Core-Lib Registry (Built-in)

---

## 3. Die Bridge-Pipeline (Workflow)

Wie kommt das Wissen vom Fuzzer in den Compiler?

1.  **Fuzzing-Phase (Auf dem Board):**
    Der Entwickler führt `toobfuzzer3` auf einem neuen STM32WBA Board aus.
    Ergebnis: `<xyz>_chip.json` (AI-Extraction Master) und `aggregated_scan.json` (Hardware-Brute-Force Ping/Pong) entstehen.
2.  **Aggregation (Converter-Skript):**
    Wir schreiben ein kleines, eigenständiges Tool `toobfuzz2toml` (z.B. in Python oder als Teil des Manifest-Compilers).
    Das Tool liest beide JSONs ein, formatiert die Sektor-Arrays und Startup-Instruktionen und generiert den fertigen `[hardware_profile]` TOML-Block.
3.  **Toob-Boot Compile-Phase:**
    Der Manifest-Compiler liest die `device.toml`. Er sieht `chip="custom"` und parst den `[hardware_profile]` Block.
    *Ergebnis:* Der Manifest-Compiler kann nun sein RAM-Budget, sein Flash-Layout und die Assembly generieren – völlig deterministisch und auf empirisch bewiesenen Hardware-Wahrheiten basierend.

---

## 4. Was wir weiterhin brauchen (Die Lücken)

Einige High-Level-Informationen muss der Entwickler in der `device.toml` manuell ergänzen, da der Fuzzer sie nicht (oder nur schwer) herausfinden kann:
*   **Crypto-Engines:** Existiert ein Hardwarebeschleuniger für Ed25519 (z.B. CC310)? (Für `verify_mode = "ed25519-hw"`).
*   **State-Retention:** Welcher RAM-Bereich (z.B. RTC FAST MEM) überlebt einen Watchdog-Reset zuverlässig? (Erforderlich für den `confirm`-Handoff).

## 5. Fazit

Indem wir den Manifest-Compiler so bauen, dass er Hardware-Wahrheiten direkt aus der TOML-Datei liest (via `[hardware_profile]`), machen wir die `chip_database.py` optional.
Das System wird **zu 100% zukunftssicher**, da jeder neue Chip durch den `toobfuzzer3` empirisch vermessen und per Knopfdruck in Toob-Boot als neues Target eingebunden werden kann.
