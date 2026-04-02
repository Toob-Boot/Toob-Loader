# Toob-Boot Developer Diary

> Fortlaufende Dokumentation von Design-Entscheidungen, Implementierungs-Schritten und "Lessons Learned" während der C-Entwicklung.

## Phase 0: Fundament & Interfaces

### 1. Synthese der Bootloader Types (`boot_types.h`)

**Was wurde getan?**
Die Erstellung der absoluten Kern-Typen für den Bootloader (`boot_status_t`, `toob_handoff_t`, `reset_reason_t`). Das beinhaltete die Konsolidierung sämtlichen Kontextes aus _allen_ 12 Spezifikationsdokumenten (`hals.md`, `concept_fusion.md`, `libtoob_api.md`, etc.) in eine einzige "Single Source of Truth" Header-Datei.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Glitch-Resistant Returns:** Anstatt `0 = OK` zu verwenden, nutzen wir `BOOT_OK = 0x55AA55AA`. Bei `0` auszuwerten, lädt Hacker zu "Voltage-Glitching" Angriffen ein, bei denen ein einzelner Bit-Flip einen Access-Check umgeht. Der Hex-Wert zwingt die Angreifer dazu, exakt 16 Bits _gleichzeitig_ physikalisch fälschen zu müssen (High Hamming Distance).
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
- **Zero-Trust Handoff (`deinit`):** Bootloader vergiften häufig das OS-WLAN durch liegengebliebene DMAs. Die Interfaces fordern nun zwingend in _jedem_ Trait eine Shutdown-Routine (`deinit`), um OTFDEC (Verschlüsselungs-Engines) oder Peripherie vor dem App-Jump sicher abzukapseln und zu resetten!

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

### 5. M-BUILD & Toolchain Architektur (`CMakeLists.txt`, `toolchains`)

**Was wurde getan?**
Das Fundament des Build-Systems wurde hochgezogen. Die root `CMakeLists.txt` verankert globale C17 Limitierungen. Die Sandbox-Toolchain (`toolchain-host.cmake`) ermöglicht native P10-Testausführungen (ASAN, Coverage, mmap). Die erste Cross-Compiler Pipeline (`cmake/toolchain-arm-none-eabi.cmake` für Cortex-M) wurde rigoros gemäß unseren Bare-Metal Limits konfiguriert.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Sichere Flag-Isolierung (`toob_apply_strict_flags`):** Wir injizieren unsere -Werror / C17 / -fstack-protector-strong Flags NICHT über das globale `add_compile_options()`, sondern via dedizierter CMake-Function per `target_compile_options`. Das verhindert, dass Third-Party Bibliotheken (wie Monocypher oder zcbor) im Root unseren strikten NASA-Regeln unterworfen werden und den Compile töten.
- **Zero-Allocation Limitierung auf Root-Ebene:** Das `#define malloc=MALLOC_FORBIDDEN` etc. wurde hart für das Gesamtprojekt in `CMakeLists.txt` geankert. Niemand kann ab jetzt dynamischen Speicher nutzen, ohne dass der C-Präprozessor sofort eskaliert.
- **Bare-Metal Try-Compile Bypass:** Bei Cross-Compilern wie `arm-none-eabi` prüft CMake zur Initialisierung, ob es ein lauffähiges `.out` Executable mit dem Compiler linken kann. Auf Bare-Metal ohne fertige `.ld` Flash-Map crasht dies immer ("Compiler is not able to compile a simple test program"). Wir zwingen CMake mit `set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)` dazu, lediglich statische Archiv-Integrität zu prüfen.

**Lessons Learned / Gaps:**

- **Cross-Compiler Host-Bleed:** Während unserer Gap-Analyse fiel auf, dass der `STATIC_LIBRARY` Bypass fatale Folgen haben kann. Ohne manuelles Definieren von `CMAKE_AR` und `CMAKE_RANLIB` als `arm-none-eabi-ar` versuchen einige Host-Maschinen, das Bare-Metal-Objekt mit ihrem `/usr/bin/ar` (Host-Archiver) zu verpacken. **Ergebnis:** Abbruch wegen Formatfehlern. _Lesson learned:_ Jeder noch so kleine Teil einer Toolchain muss explizit geprefixed gemappt werden.
- **HAL-Separation für Hardware-Flags:** Man ist schnell versucht, ein `-mcpu=cortex-m4` in die arm-Toolchain zu werfen. Da ein STM32H7 aber Cortex-M7 ist, wurde konsequent entschieden: Die Toolchain definiert _nur_ den Compiler und das Bare-Metal Environment (nosys/nano.specs). Hardwarespezifische CPU/FPU-Flags kommen streng in die Ebene 1 abstrakte `toob_hal.cmake`.

### 6. M-BUILD Toolchain Matrix Komplettierung (RISC-V & Xtensa)

**Was wurde getan?**
Die Bare-Metal Toolchains für RISC-V (`toolchain-riscv32.cmake`) und Xtensa (`toolchain-xtensa-esp.cmake`) wurden finalisiert, wodurch die M-BUILD Toolchain-Matrix vollflächig abgeschlossen ist.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Sichere XIP/Flash Addressierungen (RISC-V `medany`):** Bei ESP32-C3/C6 Chips liegt der Flash oft bei absoluten Adressen wie `0x4000_0000`, was das standardmäßige RISC-V `medlow` Code-Modell (limitiert auf +/- 2GB) beim Linken sofort sprengt. Wir haben hier harte TODOs gesetzt, zwingend `-mcmodel=medany` in der HAL zu setzen!
- **Isolierter C-Footprint (`nodefaultlibs`):** Im Kontext des "malloc_forbidden"-Paradigmas musste bei beiden Toolchains zwingend `-nodefaultlibs` parallel zu `-nostartfiles` gesetzt werden, da besonders generische Toolchains sonst heimlich implizite libc Stubs in das statische Binary pressen.
- **Xtensa Toolchain Präfixe & Longcalls:** Xtensa (ESP32-S2/S3) Compiler sind extrem Hardware-gebunden, weshalb der Präfix (Default `xtensa-esp32s3-elf-`) per GUI/CLI überschreibbar blieb. Zwingende Warnungen fordern zudem in der HAL `-mlongcalls` für weite Jumps aus dem SPI-Flash/XIP ins BootROM sowie `-mtext-section-literals` für das Pooling der Konstanten!

## Phase 3: Modul-Assemblierung (Das CMake-Skelett)

### 7. Die Drei-Ebenen Firmware-HAL (`toob_hal.cmake`)

**Was wurde getan?**
Die Übersetzung der architektonischen Philosophie ("Architektur -> Vendor -> Chip") in ein physikalisches `CMakeLists`-Manifest. Drei aufeinander aufbauende statische Libraries (`toob_arch`, `toob_vendor`, `toob_chip`), die via `target_link_libraries` transitiv gekoppelt wurden.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Sicherer GLOB (P10):** Statt jede `.c` Datei fest in CMake zu verankern (was zu permanenten Merge-Konflikten bei neuen Ports führt), nutzt CMake `file(GLOB)`. Allerdings injizieren wir strikt `CONFIGURE_DEPENDS`, damit CMake Änderungen am Verzeichnisbaum über reines Parsen erkennt und P10 Build-Reproduzierbarkeit für CI/CD beibehält.
- **Xtensa Hardware-Schutz (ABI & FPU):** Der Xtensa-Chip (ESP32-S3) wurde auf unterster CMake-Ebene gehärtet. `-mcall0` (Windowed ABI Abschaltung) rettet extrem wertvollen RAM in Interrupt-Handlern, die keine Window-Exits überleben. Das strikte Separieren der Floating-Point-Unit per Software-Float (`-msoft-float`), wenn kein Hardware-Single-Float vorliegt, stoppt tödliche Kernel-Panics bei simplen Divisionen.

### 8. PQC Hardware-Isolation (`toob_crypto.cmake`)

**Was wurde getan?**
Eine scharfe Build-Achtungstrennung zwischen dem Toob-Boot Code (`crypto_monocypher.c`), der strengste `-Werror` Anforderungen befolgen MUSS, und den Third-Party Upstream-Libraries, die fehlerhafte Legacy-Syntax haben könnten.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Constant-Time Execution (-O3):** Einer der gefährlichsten Fehler bei eingebetteter Kryptografie ist Compiler-Optimierung für ROM-Size (`-Os`), da GCC dabei häufig zeitaufwändige Branching-Tricks (wie Loops statt unrolled Instructions) nutzt und damit massive Timing-Sidechannels in Monocypher öffnet! Wir haben `toob_crypto_upstream` gnadenlos von LTO befreit und `-O3` erzwungen, um Ed25519 Side-Channels Hardware-seitig auszumerzen.
- **Verbot dynamischer Arenas:** Das PQC ML-DSA-65 System bedarf ~30 KB Arbeitsspeicher. Diese Buffer wurden hart in den statischen Bereich gezwungen (über den `crypto_arena` Array-Zeiger). Niemand dar jemals den Stack in S1 derart belasten!

### 9. Das Immutable Binary (`toob_stage0.cmake`)

**Was wurde getan?**
Die Konfiguration des isolierten, hochkritischen `stage0` (Immutable Core). Dieses Binary wurde vollkommen vom `toob_core` (Update-Engine) getrennt und als atomares `add_executable` definiert.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Stack-Protector-Verbot (GAP-Fix):** Der Footprint-Report spezifiziert hart ein 4-8 KB Limit für die Stage 0 Sektion. Globale Flags wie `-fstack-protector-strong` würden diesen winzigen Platz vernichten. Daher haben wir dieses System sicher via `-fno-stack-protector` ausschließlich für dieses eine Target abgeschaltet, um nicht in eine ROM-Falle zu geraten.
- **Dead-Code Beseitigung (Architectural Slop):** Nach einem dedizierten `@check-code` Audit wurde für `toob_stage0` strikt `-Wl,--gc-sections` erzwungen. So kann S0 die mächtigen C-Kapseln der `toob_chip` (Hardware-Abstraktion) erben (etwa RTC RAM Reads für den Retry-Counter), reißt aber nicht versehentlich 12 KB Flash-Erase-Routinen in sein Mini-Binary!
- **Startup C-Kollision gelöst:** Da S0 auf Base+0 und S1 auf Base+N liegt, erben initial beide Binaries dieselbe Vektortabelle. Durch die dynamische `SCB->VTOR` Relokation auf der `startup.c` (Cortex-M) springt S0 direkt in sein Segment, während S1 sauber autark relokalisiert. Eine architektonische Meisterleistung, ohne Assembler-Scripts verdoppeln zu müssen!
- **Crypto-Agility in Stage 0:** Optionale Integration (`TOOB_STAGE0_ED25519_SW`) des Ed25519-Softwarestacks eingeführt, um den Bootpointer-Hash für Hochsicherheitsanwendungen direkt per Signatur zu prüfen.
- **Raw-Binary Objekt-Extraktion:** Das `add_executable` liefert per se nur `.elf`-Dateien. Wir haben den nötigen POST-BUILD Command vermerkt, der per `objcopy -O binary` das rein physische `.bin` Image abzieht, welches der Manifest-Compiler am Ende auswirft.

### 10. OS Boundary Library (`toob_libtoob.cmake` & `libtoob_api.h`)

**Was wurde getan?**
Die Definition der C-Library `toob_libtoob`, die dem Feature-OS assembliert überreicht wird (inklusive Telemetrie-Zcbor-Parser).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Sicherheits-Entkopplung (Zero-Bloat):** Die Library darf _unter keinen Umständen_ die `toob_hal` oder `toob_chip` linken. Würde sie das tun, zöge sie hunderte Kilobyte Bootloader-Treiber in das OS-Binary des Kunden.
- **Der `weak` Flash Shim:** Um der Library dennoch zu erlauben, WAL-Einträge in den Flash zu schreiben, wurde in `libtoob_api.h` die API-Signatur `__attribute__((weak)) toob_os_flash_write` eingeführt. Das Kunden-OS biegt diese Funktion auf seine eigenen Treiber (z.B. Zephyr NVS/Flash) um.

### 11. CI/CD Pipeline & Hardware Matrix (`ci.yml`)

**Was wurde getan?**
Eine feingranulare GitHub Actions Pipeline, die den Host-Sandbox Testrunner (SIL) und eine breite Cross-Compile Hardware-Matrix (Espressif + ARM) vereint.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Split-Environments (Docker vs. APT):** Die Espressif IDF Toolchains (Xtensa/RISC-V) umfassen Gigabytes. Um die CI nicht lahmzulegen, läuft der ESP-Job direkt in offiziellen `espressif/idf` Docker-Containern. Die ARM-Cortex-M Compiler hingegen werden ressourcenschonend via `apt-get` nativ auf den Ubuntu-Runnern installiert.
- **P10 Double-Check & Gaps:** Ein strenges Audit der Test-Vorgaben deckte auf, dass der reine C-Unit-Test nicht reicht. Um das "Bit-Rot" und "0/50/99% Brownout" zu verifizieren, fordert die CI jetzt via TODOs dediziert Python (`pytest`) an, was die Host-Sandbox auf HIL-Ebene massakriert.

### 12. M-BUILD Blocker-Resolution (CMake "Zero-Slop")

**Was wurde getan?**
Vor dem Start in die reine C-Implementierung (Phase 5) wurden alle "No rule to make target" CMake-Blocker ausgemerzt.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Custom-Command Manifest Injection:** `toob_core.cmake` erwartet nun strikt das globale Target `generate_manifest`. Hierdurch wird das (noch aufzubauende) `suit/generate.sh` getriggert, welches den CDDL/Zephyr Parser und die Headers on-the-fly vor dem C-Compile generiert. Ein Bash-Stub hält das System lauffähig.
- **Die x86_64 Sandbox-Rettung (`boot_secure_zeroize_host.c`):** Da wir auf dem Host (Mac/Linux) kompilieren, kollidieren unsere `boot_secure_zeroize.S` (ARM/Xtensa Assembler) Dateien gravierend mit dem GCC des Betriebssystems. Der Host-Mock löst dieses Problem mit einer simplen, GCC-Optimierungs-sicheren `volatile` Pointer-Schleife.
- **Binary-Extraction (`objcopy`):** Bare-Metal Chips laden keine `.elf` Dateien. In `toob_stage0.cmake` greift nun direkt ein `POST_BUILD` Command ein, der den Strip und Dump zum fertigen `.bin` automatisiert.

**Phase 3 & 4: Abgeschlossen!** Wir weiten das Arbeitsfeld von der Infrastruktur nun direkt in die C-Header und Sourcen (Phase 5) aus.

## Phase 5: Hardware-Virtualisierung & "Zero Code Slop" Testability

### 13. M-SANDBOX SIL-Testing & Hardware-Mocks

**Was wurde getan?**
Die Übersetzung der gesamten physischen MCU-Peripherie auf Host-native C17 Mocks für das "M-SANDBOX" Software-in-the-Loop Environment (`test/mocks/`). Umgesetzt wurden `mock_flash`, `mock_rtc_ram`, `mock_wdt`, `mock_clock`, `mock_efuses`, `mock_console` und der `--wrap` Interceptor `mock_crypto_policy`.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Deterministisches Fault-Injection Fuzzing:** Jedes HAL-Modul wurde hardwarenah mit der globalen Fehler-Injection `chip_fault_inject.c` gekoppelt. Anstatt C-Code via unübersichtlicher `#ifdef TEST_MODE` Makros (Architektur-Slop) zu verunreinigen, liest die Sandbox zur Laufzeit Umgebungsvariablen (wie `TOOB_FLASH_FAULT`, `TOOB_EFUSE_LIMIT`, `TOOB_WDT_DISABLE_FORBIDDEN` oder `TOOB_UART_RX_FILE`). Ein Fuzzer-Runner (Python) kann somit jeden beliebigen Hardware-Fehler bis zum Brownout auf Register-Ebene reproduzierbar feuern, indem er schlicht den Environment-Kontext des Subprocesses kippt.
- **Zeiterfassung vs. Host CPU-Locking:** Ein 500MHz Host-PC rennt zehntausendfach schneller durch Polling-Loops als eine 48MHz Cortex-M MCU. `mock_console` implementiert auf das leere Polling von Bytes hin einen harten Sleep (`sandbox_clock_hal.delay_ms()`), um eine 100% CPU Auslastung zu unterbinden (welche ansonsten Fuzzing-Timeouts drastisch sabotieren würde), erfüllt aber gleichzeitig die P10 Hard-Timing Specs.
- **GNU Linker Interceptors (`--wrap`):** Um die extrem teuren Ed25519 und ML-DSA Krypto-Operationen im CI-Runner zu umgehen (welche Hochgeschwindigkeits-Fuzzing komplett ausbremsen würden), greifen wir auf das `-Wl,--wrap` Flag des GCC Linkers zurück. Validierung kann umgeleitet oder mit `BOOT_ERR_CRYPTO` abgebrochen werden. Das wahrt das _Zero Code Slop_ Entwicklungsgebot: Der Original C17 Quellcode bleibt unangetastet.
- **Sichere File-Pointer-Resets:** Um "State Leaks" (offene File-Handles, weiterzählende Dummy-Watchdogs etc.) bei tausenden aufeinanderfolgenden Testläufen des Fuzzers zu eliminieren, bietet jeder Mock einen `_reset_state()` Bailout, der zwischen Tests den Puffer knallhart leer fegt.

- **Pointer-Safety rettet SIL-Systeme:** In C ist ein fehlender `NULL`-Pointer Check besonders in Mocks gefährlich. Greift `fopen` auf ein undefiniertes Environment (`NULL`) File zu, killt das den gesamten Bootloader Test-Prozess mit einem Segfault. Die konsequente P10 Boundary-Prüfung (`if (*len < 16) return BOOT_ERR_INVALID_ARG;`) an den Eintrittskanten (z.B. in `mock_efuses.c`) ist auf dem PC Host genauso überlebenswichtig wie später auf dem Silizium.

### 14. Native Integration-Verifikation & Compiler-Matrix (GCC 15)

**Was wurde getan?**
Um die funktionale Integrität von M-SANDBOX final zu prüfen, wurde ein natives Test-Binary (`test_sandbox.c`) erstellt, welches das `boot_platform_t` M-SANDBOX Layout direkt auf dem Host kompiliert und ausführt. Parallel dazu wurde das GitHub C++ Misclassification Problem behoben (`.gitattributes`).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Sicherstellung des HAL-Contracts (`BOOT_STATUS_T`):** Die isolierte Kompilierung brachte zutage, dass die ursprünglichen Monocypher Crypto-Wrapper `void` anstatt `boot_status_t` zurückgaben, was durch den strict-typing Compiler (GCC 15.2) hart abgefangen wurde. GCC 15.2 (UCRT) für Windows wurde absichtlich als Referenzcompiler gewählt, da dessen statische Checks unter `-std=c17 -Werror` exzellent auf subtile Struct- und Typisierungs-Fehler reagieren (so wie auch `.abi_version` statt `.version` entdeckt wurde).
- **GitHub Linguist Fix (`.gitattributes`):** Repositories mit generischen `.h` Headern oder Submodulen (wie externem Code mit `#ifdef __cplusplus`) bewirken, dass GitHub das Projekt als "C++" flaggt, was fälschlicherweise OOP-Müll impliziert. Durch ein explizites `*.h linguist-language=C` und `linguist-vendored` in `.gitattributes` stellen wir glasklar sicher, dass die Welt Toob-Loader als das anerkennt, was es ist: Pures, ultra-abgespecktes C17.

**Lessons Learned:**

- **Der Wert von Standalone-Kompilaten:** Wenn man ein großes CMake-Skelett für physische Chips vor sich hat, lässt man sich leicht dazu verleiten, kleine Zwischenstände nicht zu testen, weil "der Cross-Compiler noch nicht eingerichtet ist". Durch das isolierte Zusammenziehen der Sandbox-Mocks und Crypto-Files in ein einzelnes GCC-Kommando (`gcc test_*.c hal_*.c mock_*.c -o test.exe`) entlarvt man Pointer-Fehler sofort. Das bewahrt uns davor, solche Bugs später auf den Kern des State-Machines (WAL/Boot main) zurückzuführen.

## Phase 6: Core Engine Hardening (Stufe 2)

### 15. Die Write-Ahead-Log Engine (boot_journal.c)

**Was wurde getan?**
Die Implementierung des WALs (Ringpuffer). Dieses Modul ist das Herzstück der "Single Source of Truth" bei Crashs.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Ringpuffer Erase-Grenzen:** Anstatt den Flash nach Erreichen der 1-Sektor-Grenze endlos rotieren zu lassen, wurde P10-strikt die Zähllogik implementiert, um einen Overflow präzise abzufangen.
- **Transaktions-Padding (OOB-Defense):** Bei jedem Schreibzugriff wurde konsequent das Ende des Frames (0x1B Alignment Padding) geschrieben und ausgewertet. Wenn der Flash korrumpiert ist, wehrt das System den illegalen Memory Ausbruch dank eines definierten Frames direkt ab.
- **Glitch-Sicherheit:** Alle Operationen stützen sich auf boot_secure_flag_t Arrays bzw. die Error-Codes. Keine blinden Return-Values.

### 16. Streaming Verifikation - "Flat-Hash-List" (toot_merkle.c)

**Was wurde getan?**
Die kryptografische Stream-Verifikation per Hash-Slices. Anstatt große 4GB Sektoren in Tree-Strukturen zu zwingen, wurde die effiziente O(1) Slice-Prüfung umgesetzt.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Compiler-sicheres Constant-Time (constant_time_memcmp):** Da LTO/GCC Optimierer simple XOR-Absicherungen für Memcmps oft einkürzen, wurde der Accumulator explizit als volatile uint8_t result erzwungen (
  esult |= a[i] ^ b[i]). So kann ein timing-messender Angreifer nicht Bit-by-Bit den Hash knacken.
- **Multi-Gigabyte Overflow Protection:** Striktes Abfangen von Sektoren-Überläufen if (num_chunks > UINT32_MAX / chunk_size), um Integer-Wraparounds (y = 0) bei böswillig großen Updates zu blocken.
- **Zero-Allocation Krypto (BOOT_MERKLE_MAX_CTX_SIZE):** Der Crypto-Status bedient sich sicher auf bis zu 256 P10-Bytes (SRAM) statt den Stack zu fragmentieren.

### 17. Glitch-Resistance Signatur Checks (toot_verify.c)

**Was wurde getan?**
Der Gatekeeper: Physische Verifikation der Kryptografie (Ed25519) und des Fallbacks auf Post-Quantum (ML-DSA).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Voltage-Glitch Double Check:** Das bloße Warten auf einen booleschen Code lässt sich per Spike (Brownout am PCB) skippen. Hier wurde das exzellente Konstrukt aus den Delay NOPs **asm** volatile ("nop; nop; nop;"); nebst secure_flag_1 / 2 implemetiert. Der Chip müsste exakt zweimal denselben 16-Bit Hamming-Abstand auf Millisekunde fälschen, um durchzuwutschen.
- **Anchored Payload (PQC-Hybrid):** ML-DSA Keys (3 KB) sprengen OTPs. Der Trick: Der PQC Public Key wird _in_ dem bereits per Ed25519 (OTP gesicherten) Signaturblock geliefert. Wenn Edge-Conditioning zuschlägt oder die Puffer-Arithmetik out of Bounds aus dem SRAM springt, hagelt es den Rollback.
- **Secure Zeroization:** P10 Contract -> Die OTP Root-Keys werden auf Assembler-Level via toot_secure_zeroize sofort genullt, um Side-Channel Memory Dumps abzuführen (Cold-Boot Attack Resilienz).

### 18. Endless-Boot Loop Prevention (toot_confirm.c)

**Was wurde getan?**
Die finalen Handoff Evaluations-Routinen, die entscheiden ob ein frisches Update den Survival-Mode überstanden hat, oder wir in den alten Backup-Slot zurückrollen (Fallback).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Das Whitelist Paradigma:** Anstelle eine endlose Blacklist von Fehlerursachen (WATCHDOG, SOFTWARE, FAULT, UNKNOWN) zu generieren, vertrauen wir der C-Basis NICHT. Im Code ist nun fixiert: Validiert (und somit nicht zurückgesetzt) bleiben Flags NUR dann, wenn der Boot-Grund POWER_ON, PIN_RESET oder ein harmloser BROWNOUT (Batterie war leer) war. Jeder andere Code stirbt im Rollback-Abgrund!
- **Watchdog Umarmung:** Da externe I2C Bausteine das Confirm-Flag u.U. sehr langsam speichern, wurden alle check_ok und clear Interaktionen streng mit wdt->kick(); umschlungen (Defense-In-Depth Pattern). Alle Pointer werden zudem einzeln validiert, bevor auch nur ins OS Gesprungen wird.

_(Phase 6 vervollständigt die Core Update Logik. M-State & Haupt-Orchestrierung folgen!)_

### 19. SUIT Manifest & ZCBOR CodeGen (suit/generate.sh)

**Was wurde getan?**
Die P10-konforme und CI-kompatible Integration des SUIT (Software Update for the Internet of Things) Manifest-Layers. Die CDDL-Schemata (`toob_suit.cddl`, `toob_telemetry.cddl`) wurden an die C-API angepasst und eine stark gehärtete `generate.sh` Bash-Bridge errichtet, welche `zcbor` anwirft und sichere Mocks für Host-Sandboxing ausspuckt.

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Zero-Allocation Parser:** Alle Felder in den CDDL-Dateien wurden mit strikten Bound-Limits versehen, damit der ZCBOR Parser OOM-sichere, nested C-Structs allokiert. Dynamische Typen wie Cbor-Maps wurden bewusst durch Structs abgelöst, um Tree-Parsing in S1 zu vermeiden.
- **Fail-Secure Mocking in CI:** Falls `zcbor` im CMake-Container fehlt, wirft `generate.sh` nicht einfach leere C-Funktionen ab. Es generiert ODR-konforme und Memory-sichere C-Mock Arrays (`return false;`), verankert Hardware-Dummy Pointer (`toob_mock_reg_...` im Host RAM via C-Files) und bewahrt den Code-Compiler vor `incomplete type` Abstürzen, indem es ABI-verträgliche Fallback-Typen (z.B. `uint8_t schema_version`) deklariert.
- **CMake Race-Condition Protection:** Die Einbindung in die `toob_core.cmake` erfolgt geschirmt durch ein fixes `add_dependencies()`, um Ninja daran zu hindern, die C-Sources zu kompilieren, bevor das Bash-Skript die ZCBOR Header vollständig abgeworfen hat.
- **In-Tree Vendoring:** Drittanbieter-Code von `zcbor` (v0.8.1) wurde isoliert (ohne Encoder und Test-Bloat) ins Projektverzeichnis kopiert statt eines Git-Submodules, um das extrem knappe "Zero-Slop" Build-Sandboxing vor dem riesigen Upstream-Zephyr-Ökosystem zu schützen.

### 20. Architektonischer Lückenschluss: ZCBOR Encoder (Telemetrie)

**Was wurde getan?**
Die sofortige Reintegration des zcbor-Encoders (`zcbor_encode.c`) in das `toob_zcbor` Target sowie die Anweisung an das Bash-Skript (`suit/generate.sh`), für das Telemetrie-Skelett (`toob_telemetry.cddl`) zwingend einen `--encode` Parser-Zweig zu erzeugen (anstatt nur `--decode`).

**Wieso wurde es so gebaut (Architekturentscheidungen)?**

- **Bootloader-to-OS Boundary Codec (GAP-Fix):** Der Bootloader verarbeitet eingehende SUIT-Manifeste zwar rein lesend (Decodierung), muss aber im Anschluss seine eigene Crash-Vergangenheit (`toob_boot_diag_t`) als kompaktes CBOR in den Shared-RAM (.noinit) verpacken. Ohne den physikalischen Encoder im C-Tree existierte eine Designlücke zwischen Boot-Engine (die CBOR schreiben soll) und dem OS (`libtoob`), welches dieses CBOR abholen und decodieren muss (`toob_get_boot_diag()`). Dieser Pipeline-Bruch wurde damit endgültig repariert.
