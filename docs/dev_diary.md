# Toob-Boot Developer Diary

> Fortlaufende Dokumentation von Design-Entscheidungen, Implementierungs-Schritten und "Lessons Learned" während der C-Entwicklung.

## Phase 0: Fundament & Interfaces

### 1. Synthese der Bootloader Types (`boot_types.h`)

**Was wurde getan?**
Die Erstellung der absoluten Kern-Typen für den Bootloader (`boot_status_t`, `toob_handoff_t`, `reset_reason_t`). Das beinhaltete die Konsolidierung sämtlichen Kontextes aus *allen* 12 Spezifikationsdokumenten (`hals.md`, `concept_fusion.md`, `libtoob_api.md`, etc.) in eine einzige "Single Source of Truth" Header-Datei. 

**Wieso wurde es so gebaut (Architekturentscheidungen)?**
- **Glitch-Resistant Returns:** Anstatt `0 = OK` zu verwenden, nutzen wir `BOOT_OK = 0x55AA55AA`. Bei `0` auszuwerten, lädt Hacker zu "Voltage-Glitching" Angriffen ein, bei denen ein einzelner Bit-Flip einen Access-Check umgeht. Der Hex-Wert zwingt die Angreifer dazu, exakt 16 Bits *gleichzeitig* physikalisch fälschen zu müssen (High Hamming Distance).
- **Struct Alignment für RAM-Handoff (GAP-39):** Das `toob_handoff_t` Struct wird im `.noinit` Shared-RAM zwischen Bootloader und OS deponiert. 64-Bit OS-Architekturen (wie AArch64) crashen beim Zugriff auf nicht alignierte Daten (Unaligned Memory Access). Deshalb wurde das Struct nicht nur durch `__attribute__((aligned(8)))` markiert, sondern manuell via `_padding` Variable auf absolut exakte `32 Bytes` geglättet.
- **P10 Compile-Time Defense:** Statt Fehler erst zur Laufzeit zu bemerken, überwachen knallharte `_Static_assert` Anweisungen direkt nach der Struct-Definition, dass die Speicherlänge und das Alignment von keinem Ziel-Compiler (weder GCC noch MinGW noch Clang) verbogen werden.

**Lessons Learned:**
- **Abstraktions-Konsolidierung:** Spezifikationen wachsen historisch über viele Dokumente. Beim direkten Transfer in validen C17-Code merkt man schnell, dass Hardware-Reset-Gründe, Telemetrie-Offsets und API-Statuscodes streng voneinander separiert bleiben müssen, um Zirkelbezüge (`#include`-Loops) späterer Module zu verhindern. Mit `boot_types.h` existiert jetzt ein universelles Fundament, das selbst keine anderen Header importieren muss.
