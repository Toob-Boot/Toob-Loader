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

### 2. Die Hardware Abstraction Layer (`boot_hal.h`)

**Was wurde getan?**
Die Übersetzung der "Heiligen 7" Traits aus `hals.md` (Flash, Confirm, WDT, Crypto, Clock, Console, SoC) in strikt P10-getypte C-Structs aus Funktionspointern (Interfaces).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**
- **ABI Versionierung (V2):** Das Start-Feld `uint32_t abi_version` zwingst jeden assemblierten Hardware-Treiber künftig dazu, sich auf eine Datenstrom-Gültigkeit festzulegen. Sollte ein Hersteller sein ROM verändern, detektiert Toob-Boot sofort eine zerschossene Architektur-Abhängigkeit statt stumpf Pointer für Segfaults zu verdrehen.
- **WDT-Kapselung statt Suicide:** Anstatt (wie in fast allen alten Embedded-Systemen) das tödliche `wdt_hal.disable()` einzubauen, haben wir ausschließlich `suspend_for_critical_section()` und `resume()` aufgesetzt. Das zwingt HAL-Programmierer dazu, Watchdogs über dynamische Prescaler legal zu überbrücken, wenn monströse Flash-ROM Limits den Bus lahmlegen.
- **Zero-Trust Handoff (`deinit`):** Bootloader vergiften häufig das OS-WLAN durch liegengebliebene DMAs. Die Interfaces fordern nun zwingend in *jedem* Trait eine Shutdown-Routine (`deinit`), um OTFDEC (Verschlüsselungs-Engines) oder Peripherie vor dem App-Jump sicher abzukapseln und zu resetten!

### 3. Absolute ABI-Fixierung (Full-Spec Umsetzung)

**Was wurde getan?**
Sämtliche als "Phase 5 TODOs" deklarierten Struct-Elemente wurden vorgezogen und als harte, kompilierbare Felder in die `boot_types.h` gebrannt.

**Wieso wurde das umgesetzt?**
- **Verhinderung von Struct-Tearing (GAP-39):** Wären die Wear-Counters (Flash-Abnutzung) erst in Phase 5 in `toob_handoff_t` eingebaut worden, hätte sich die Größe der Daten im `.noinit` Shared-Memory plötzlich von 40 auf 56 Bytes verschoben. Ältere OS-Versionen wären beim RAM-Read unweigerlich in einen Hard-Fault gelaufen (Alignment Crash). Durch die initiale Vollausstattung plus striktem `56 Byte` Padding ist die RAM-Grenze eingefroren.
- **CBOR Telemetrie-Sicherheit:** Das `toob_boot_diag_t` Struct spiegelt jetzt zu 100% die definierten Felder (SBOM-Digest, WDT-Kicks etc.) aus Phase 5 wider, damit OS-Entwickler sofort mit dem echten Memory-Footprint planen können, bevor echte Daten existieren.

### 4. M-TYPES Audit & P10 Interface Alignment

**Was wurde getan?**
Ein tiefgreifendes Code-Audit der `boot_hal.h` und `boot_types.h` gegen unsere Master-Spec `hals.md`. Dabei wurden gravierende Abweichungen im ersten Architekturentwurf detektiert und in einer großen "Operation" ausgemerzt.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**
- **Sicheres Enum-Mapping:** Der `boot_status_t` wurde von negativen Werten (z.B. `-2`) vollständig auf positive Werte gemäß Spec migriert und um den hardwarenahen NMI-Zustand `BOOT_ERR_ECC_HARDFAULT` erweitert.
- **PQC Zero-Allocation (GAP-C04):** Wir haben radikal Kontext-Pointer (`void *ctx`) in Hardware-Crypto-Routinen erzwungen. Die Bootloader-Umgebung hat knappen Stack-Memory. Ein Hardware-Hersteller darf bei PQC-Signaturen (ML-DSA) unter keinen Umständen massive C-Arrays oder State-Variablen allokieren. Die HAL muss unseren statischen `.bss` Buffer (`crypto_arena`) nutzen.
- **Fuzzer Limit-Injection:** Die struct `flash_hal_t` verfügt nun explizit über Variablen (wie `max_sector_size`), die vom dynamischen Manifest-Compiler gefüttert werden können. Ohne diese Integration wäre die Zero-Bloat Architektur (Ausschluss großer SDKs) nicht möglich.
- **Integer Typecast Protection:** Die serielle `getchar` Methode MUSS einen `int` zurückgeben. Ein `uint8_t` würde den Leer-Status `-1` in ein völlig valides `0xFF` Datenbyte der Rescue-Payload verwandeln und damit die Serial Recovery stumm lahmlegen.

**Lessons Learned:**
- **Spezifikations-Drift:** Bei der Übersetzung von konzeptionellen Markdown-Tabellen in harte C-Signaturen gehen schnell essenzielle Meta-Anforderungen (wie Pointer-Arithmetik oder Rückgabe-Typen) verloren. Eine Spec im Nachgang nochmals granular per Audit-Workflow gegen den generierten Code abzugleichen, hat uns vor monatelangen Debug-Sessions mit abstürzenden Hardware-Mocks gerettet.
