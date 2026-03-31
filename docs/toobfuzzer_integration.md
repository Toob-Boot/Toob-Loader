# Toobfuzzer Integration Strategy (Toob-Boot)

Dieses Dokument beschreibt den finalen, hardware-abstrakten Workflow, mit dem `Toob-Boot` die extrahierten Daten des `toobfuzzer3` konsumiert. Ziel ist es, die mühsame und fehleranfällige manuelle Treiberschicht ("Hardware Quirks") zu **90 % vollständig zu automatisieren**, anstatt 64 KB Hardcoding oder Monolith-Libraries wie ESP-IDF in den Bootloader zu hieven.

---

## 1. Das Konzept: Trennung von Logik und Physik

Ein klassischer Bootloader scheitert meist beim Portieren auf einen neuen SoC, weil Hardware-Limitierungen (z. B. "Der Erase-Sektor ist 128 KB groß" oder "Das Write-Alignment fordert 32 Bytes") fest im C-Algorithmus verankert ("hardcoded") sind.

Toob-Boot trennt diese Logik konsequent:
*   **Die Bootloader C-Logik (`core/`)** kennt *niemals* fixe Hardware-Grenzen. Das WAL (Write-Ahead-Log) berechnet seine Algorithmen ausschließlich anhand der dynamischen Felder aus der `flash_hal_t` Struktur (z. B. `platform->flash->get_sector_size(addr)` und `CHIP_FLASH_MAX_SECTOR_SIZE`).
*   **Der Toobfuzzer (`toobfuzzer3/`)** deckt die realen, blutigen physikalischen Limitierungen eines SoCs iterativ (durch Brute-Force Black-Box-Fuzzing und LLM-Synthese) auf.

---

## 2. Die Datenquellen aus dem Fuzzer

Der Toobfuzzer generiert nach einem erfolgreichen Scan-Zyklus auf echter Zielhardware zwei essenzielle Artefakte, die als direkte "Single Source of Truth" in das Toob-Boot Build-System einfließen:

### A. `aggregated_scan.json` (Der physische Speicher-Beweis)
Der Fuzzer verlässt sich nicht auf das Datenblatt, sondern schreibt, liest und löscht hart auf dem Silizium. Das Ergebnis ist eine auf das Byte genaue Map der tatsächlich funktionierenden und löschbaren Speicherblöcke:
```json
// GAP-46, F25: Spezifiziertes Schema für aggregated_scan.json Segmente
{
    "schema_version": "1.0",
    "segments": {
        "262144": {
            "start_addr": 262144,                 // Int: Absolute Start-Adresse
            "end_addr": 266239,                   // Int: Absolute End-Adresse (inclusive)
            "start_hex": "0x40000",               // String: Lesbare Start-Adresse
            "end_hex": "0x40fff",                 // String: Lesbare End-Adresse
            "size": 4096,                         // Int: Sektor-Größe in Bytes
            "fallback": false,                    // Bool: Wurde auf logische Fallbacks ausgewichen?
            "verification_method": "Physical...", // String: Validierungs-Methode
            "run_ping": "erased",                 // String: Standard Erase-Muster ("erased" = 0xFF, "zeroed" = 0x00)
            "max_erase_time_us": 45000            // Int: Gemessene physikalische Max-Erase-Time (GAP-40 Basis)
        }
    }
}
```
*Nutzen:* Garantiert uns vor dem C-Compile auf Sektor-Ebene exakt die kleinste funktionierende Lösch-Einheit (Page Size vs. Sector Size vs. Bank Size) und identifiziert defekte Speicherbereiche out-of-the-box.

### B. `blueprint.json` (Die Logik- & ROM-Landkarte)
Generiert durch die **Stage 4 Injection**. Hier stehen die Architektur-Grenzwerte und extrem wertvolle ROM-Pointer, die es Toob-Boot ermöglichen, den SDK-Bloatware-Treiber komplett zu umgehen:
```json
// GAP-46, F01, F02, F18, F23, F25: Spezifiziertes Master-Schema für blueprint.json
{
    "schema_version": "1.0",
    "flash_capabilities": {
        "write_alignment_bytes": 4,           // Int: Nötiges RAM-Alignment für Payload-Buffer
        "app_alignment_bytes": 65536,         // Int: Nötiges Flash-Alignment für Execute-In-Place (XIP) Vector-Tables
        "base_address": "0x08000000",         // String: Absolute Start-Adresse des Flashs
        "is_dual_bank": false,                // Bool: Hat der Flash zwei getrennte Bänke?
        "read_while_write_supported": false,  // Bool: Read-While-Write capability
        "timing_safety_factor": 2.0           // Float: Manifest-Compiler-interne Marge für WDT (GAP-40)
    },
    "flash_controller": {
        "erase_sector_sequence": [
            {
                "function_name": "SPIEraseSector",  // String: ABI Name der Vendor-ROM Funktion
                "rom_address": "0x40062CCC",        // String: Absolute Hex-Adresse des Entry-Points
                "return_convention": "0_success"    // String: F13 Convention für Status-Mapping
            }
        ]
    },
    "reset_reason": {
        "register_address": "0x3FF44038",     // String: Hex-Adresse des Reset-Cause Registers
        "wdt_reset_mask": "0x08",
        "power_on_reset_mask": "0x01",
        "software_reset_mask": "0x04"
    },
    "watchdog": {
        "feed_register": "0x3FF5F014",
        "kick_value": "0x80000000"
    },
    "crypto_capabilities": {
        "hw_sha256": true,
        "hw_aes": true,
        "hw_ed25519": false,
        "hw_rng": true,
        "pka_present": true
    },
    "survival_mechanisms": {
        "recommended_storage_type": "rtc_ram",// Enum: rtc_ram | backup_register | retained_ram | flash
        "address": "0x50000000",              // String: Hex-Adresse des Confirm-Storages
        "needs_vbat_pin": false
    },
    "factory_identity": {
        "has_mac_address": true,
        "uid_address": "0x1FFF7590"           // String: Hex-Adresse der Hardware-UID / DSLC
    },
    "multi_core_topology": {
        "is_multi_core": false,
        "ipc_mechanism": "shared_ram",        // Enum: shared_ram | mailbox | none
        "coprocessors": [
            {"name": "net_core", "flash_base": "0x01000000", "app_alignment_bytes": 2048}
        ]
    }
}
```
*Nutzen:* Liefert direkte Zeiger in die fest eingebrannte BootROM der MCU für Flash/Krypto-Operationen, was unfassbar viel Flash/RAM spart. (F11: Die frühere **Stage 4** Spec in `request.md` ist hiermit veraltet. Alle Prompts befinden sich direkt im `toobfuzzer3` Repo. Dieses Schema hier ist die absolute "Single Source of Truth").

---

## 3. Der Integrations-Workflow (Layer 5)

So wird aus dem Fuzzer-JSON fertiger, hochoptimierter Bare-Metal C-Code:

1. **User Request (`device.toml`):** Der Entwickler definiert seine Feature-App und sagt: `target = "esp32s3"`.
2. **Die Magic Bridge (`tools/manifest_compiler/`):**
   * Das Python `manifest_compiler`-Plugin liest die Anforderung.
   * **(F26)** Discovery-Pfad: Das Plugin sucht die JSON-Artefakte in `./fuzzer_output/<chip>/` und fällt sonst auf `~/.toob/cache/<chip>/` zurück. Fehlen sie, bricht der Build mit einem klaren Fehler ab (Toobfuzzer-Lauf gefordert).
   * Das Skript liest die JSON-Werte aus und bereitet sie ohne Floats für C vor.
3. **Auto-Wiring & Code-Gen (`chip_config.h` & `libtoob_config.h`):** Das Plugin generiert vollautomatisch die C-Header-Konfiguration.
   **(F05, F06, F15)** Exaktes Mapping für Bootloader (`chip_config.h`) und OS (`libtoob_config.h`):
   
   | JSON Quelle | Manifest-Compiler Logik | C Macro (Header) |
   |-------------|-------------------------|------------------|
   | `aggregated_scan[*].size` (Maximalwert) | Aggregiert den O(n) Swap-Maximalwert | `CHIP_FLASH_MAX_SECTOR_SIZE` |
   | `flash_capabilities.app_alignment_bytes`| 1:1 Kopie | `CHIP_APP_ALIGNMENT_BYTES` |
   | `flash_capabilities.write_alignment_bytes`| 1:1 Kopie | `CHIP_FLASH_WRITE_ALIGN` |
   | `flash_controller.rom_address` | String-Hex Injection | `ROM_PTR_FLASH_ERASE` |
   | `max_erase_time_us * timing_safety_factor` | **(F03, F04)** Float intern, in C als reiner `uint32_t` Millisekunden-Wert! | `BOOT_WDT_TIMEOUT_MS` |
   | `survival_mechanisms.address` | Handoff-RAM / OS Boundary | `ADDR_CONFIRM_RTC_RAM` (`libtoob_config.h`) |
   | WAL-Base + Size | Fuzzer-Segment Allocation | `WAL_BASE_ADDR` (`libtoob_config.h`) |
   | `run_ping` | **(F07)** `"erased" -> 0xFF`, `"zeroed" -> 0x00` | `CHIP_FLASH_ERASURE_MAPPING` |

4. **Platform-HAL Assemblierung (`chip_platform.c`):** **(F28)** Im letzten Schritt nutzt Toob-Boot C-Templates. In `hal/vendor/esp/chip_platform.c` inkludiert der von uns manuell geschriebene C-Code schlicht die generierte `chip_config.h` und weist die Makros den Pointern der `flash_hal_t`-Struktur zu (Keine Jinja2-Magie in den `.c` Dateien).

### Ergebnis
**(F09, F21, F22)** Der C17-Bootloader-Kern iteriert dynamisch zur Laufzeit über `get_sector_size()`, nutzt aber das generierte `CHIP_FLASH_MAX_SECTOR_SIZE` für die statische RAM-Allokation der Swap-Buffer. So sind 90 % der hardware-spezifischen **Konfigurationskonstanten** (nicht der Adapter-Code selbst!) absolut fehlerfrei auto-generiert parametrisiert.

---

## 4. Revisions- & Änderungsverlauf

- **V4 Gap-Analyse Härtung:**
  - `GAP-40`: Einführung des `timing_safety_factor` im Manifest-Compiler zur Watchdog-Absicherung.
  - `GAP-46`: Explizite JSON-Schema Dokumentation für bessere Tool-Kompatibilität.
  - `F01-F30`: Massives Integrations-Update, Komplettierung der HAL-Datenpunkte (Multi-Core, Crypto, RTC) und Konsolidierung der Mappings zwischen Veralteter `request.md` und Bootloader C-Headern.
