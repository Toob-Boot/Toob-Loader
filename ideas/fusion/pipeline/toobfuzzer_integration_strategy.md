# Toobfuzzer3 & Manifest Compiler Integration

> **Status:** Architektur-Gedanken & Integrations-Strategie
> **Ziel:** Ablösung der statischen `chip_database.py` durch empirisch bewiesene und KI-generierte Hardware-Wahrheiten aus dem `toobfuzzer3`.

---

## 1. Die Ausgangslage

Der **Manifest-Compiler** (Schicht 5) verlangt ultimative Hardware-Wahrheiten, um deterministische Linker-Scripte, RAM-Budgets und Flash-Sektorengrenzen zu berechnen.
Bisher war der Plan, diese Wahrheiten per Hand in einer Python-Datei (`chip_database.py`) zu pflegen.

Das Problem: Es skaliert nicht für Custom-Boards und hunderte Microcontroller-Revisionen.

Die Lösung liegt im **Toobfuzzer3**, der auf zwei Ebenen exakt diese Wahrheiten ermittelt:

### A. KI-gestütztes Parsing (`chips.json`)
*   **Fokus:** CPU-Execution & Security-Rings.
*   **Liefert:**
    *   SRAM-Ausführungsgrenzen (`iram.origin`, `dram.origin`)
    *   ABI-Initialisierungs-Assembly (z.B. RISC-V `__global_pointer$` Setup)
    *   Watchdog-Register (Exakte Hex-Adressen und Magic-Unlock-Werte)
    *   Security-Register (JTAG-Locks, Flash-Encryption)
*   *Warum wertvoll:* Spart Wochen an TRM-Recherche. Liefert die Basis für das `_start.S` Assembly.

### B. Empirischer Hardware-Scan (`aggregated_scan.json`)
*   **Fokus:** Physische Speicherstruktur (Flash & RAM).
*   **Liefert:**
    *   Sektor für Sektor die **reale** Speicherstruktur des Chips (z.B. `1073741824` → Sektorgröße `4096`).
    *   Prüft durch `run_ping` und `run_pong`, ob Sektoren wirklich persistieren und beschreibbar sind.
*   *Warum wertvoll:* Liefert die `sector_sizes` und das absolute Flash-Layout, ohne sich auf oft falsche Hersteller-PDFs verlassen zu müssen.

---

## 2. Die neue TOML-Integration: `[hardware_profile]`

Um den Toobfuzzer3 strukturell mit der `device.toml` Spec zu verheiraten, ohne beide Repositories physisch mischen zu müssen, führen wir einen neuen Block in der `device.toml` ein.

Anstatt `chip = "esp32s3"` zu deklarieren und auf die Python-DB zu hoffen, kann der User (oder ein Skript) die durch Toobfuzzer ermittelten Daten direkt injizieren:

```toml
[device]
chip = "custom"
vendor = "nuvoton"

# ── Dieser Block generiert sich aus dem Toobfuzzer-Output! ──
[hardware_profile]
arch = "riscv32"

# 1. Empirisch bewiesen durch 'aggregated_scan.json'
[hardware_profile.flash]
sector_sizes = ["4KB", "4KB", "4KB", "64KB", "128KB"] # Ermittelt aus Scan-Blocks
flash_origin = "0x40000000"
write_align = 4

# 2. KI-extrahiert durch 'chips.json'
[hardware_profile.memory]
iram_origin = "0x40800000"
dram_origin = "0x40800000"
ram_total = "512KB"

[hardware_profile.startup]
watchdog_kill_addr = "0x600080B4"
watchdog_unlock_val = "0x50D83AA1"
watchdog_disable_val = "0x00000000"
abi_inits = [
    "la sp, _stack_top",
    ".option push",
    ".option norelax",
    "la gp, __global_pointer$",
    ".option pop"
]
```

---

## 3. Die Bridge-Pipeline (Workflow)

Wie kommt das Wissen vom Fuzzer in den Compiler?

1.  **Fuzzing-Phase (Auf dem Board):**
    Der Entwickler führt `toobfuzzer3` auf einem neuen STM32WBA Board aus.
    Ergebnis: `chips.json` und `aggregated_scan.json` entstehen.
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
