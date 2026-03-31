# Toob-Boot: Gap Analysis für HAL-Spezifikation (hals.md)

Dieses Dokument umfasst eine rigorose Gap-Analyse der `hals.md` im direkten Konzept- und Architekturvergleich zu `concept_fusion.md`. Es deckt funktionale Widersprüche, fehlende Abstraktionen für Hardware-Sicherheit und Fehler in der Ressourcenplanung auf. 

## 1. Logic Gaps & Architektur-Widersprüche

### 1.1 Fehlende `deinit()` Lifecycle-Hooks (Security/Stabilität)
**Problem:** `concept_fusion.md` beschreibt als zwingende Sicherheitsrichtlinie ein striktes `hal_deinit()`, um "Peripherie-Vergiftungen" für das App-OS auszumerzen. In `hals.md` existiert in keiner einzigen Struktur (`flash_hal_t`, `crypto_hal_t`, `clock_hal_t`) eine `deinit()`- oder `shutdown()`-Methode. Ein ins App-OS weitergegebener, nicht genullter Krypto-Context, drehende Hardware-Timer oder anstehende SPI-DMA-Register verursachen unmittelbar beim Boot des Systems schwere Isolations- oder Hardware-Faults.
**Mitigation:** Jede HAL-Komponente in `hals.md` MUSS um eine `void (*deinit)(void)`-Methode erweitert werden. Die `boot_main` Iteration ruft diese zwingend in umgekehrter Init-Reihenfolge ab, bevor der CPU-Arm in das App-OS springt. Alternativ muss die `boot_platform_t` globale Deinitialisierer abbilden.

### 1.2 WDT-Skalierung für monolithische Vendor-Erase-Aufrufe fehlt (Stabilität)
**Problem:** `concept_fusion.md` verbietet lange Blockaden und fordert: Bietet die ROM nur monolithische Löschfunktionen an, die den WDT überschreiten, muss die HAL "den WDT-Prescaler hochskalieren". Die reale Spezifikation der `wdt_hal_t` in `hals.md` besitzt jedoch nur `init`, `kick` und `disable`. Dem Toob-Boot Core fehlt die Möglichkeit, via HAL vor einen ununterbrechbaren `ROM_PTR_FLASH_ERASE` Aufruf den WDT temporär zu pausieren oder sein Limit zu skalieren.  
**Mitigation:** Erweitung der `wdt_hal_t` um `void (*suspend_for_critical_section)(void)` und `void (*resume)(void)`. Hiermit kann der Core den WDT für das 2,5-sekündige STM32 ROM-Erase auskoppeln (oder den Prescaler via Hardware Register erweitern) und danach konform reaktivieren.

### 1.3 `confirm_hal_t`: Dead-Code durch inkorrekte System-Grenzen (Effizienz/Architektur)
**Problem:** `hals.md` definiert `set_ok()` und `is_update_pending_confirm()` im Bootloader-Interface, ergänzt aber als Warnung: "Wird NIE vom Bootloader aufgerufen! Nur vom Feature-OS...". Dies ist architektonischer "Slop". Wenn das App-OS via `libtoob` den Direktzugriff auf das Flash-WAL durchführt, haben C-Funktionspointer dafür im Speicher und Interface des isolierten Bootloaders nichts verloren. Dies verschwendet Byte-Overhead und verwirrt die API-Strukturen.
**Mitigation:** `set_ok` und `is_update_pending` restlos aus `hals.md` (und dem Bootloader-C-Code) löschen. Die Bootloader-HAL behält nur `check_ok()` und `clear()`. Die Schreib-Spezifikation für das App-OS gehört in ein separates `libtoob_hal.md` Konzept, strikt jenseits der `boot_platform_t` Zuständigkeit.

### 1.4 Blind Spot: Multi-Core Bus Sanitization / Handoff fehlt (Hardware Control)
**Problem:** `concept_fusion.md` erwähnt zwingend atomare Multi-Core Update Groups und verlangt vor dem Ausführen der Operationen "einen Forced Hardware-Reset-Hold für alle Sub-Cores (z.B. C2 auf STM32)" sowie eine "Architektur-spezifische Bus-Säuberung (AHB/APB Reset)". `hals.md` blendet die gesamte Existenz von Multi-Core/Secondary-Cores in seiner Abstraktion aus. Es gibt keine HAL-Methoden, um Nebenprozessoren oder DMA-Matrixen sicher zurückzusetzen.
**Mitigation:** `power_hal_t` oder `clock_hal_t` (oder ein neues `soc_hal_t`) muss zwingend Hooks für Multi-Core Architekturen anbieten: `assert_secondary_cores_reset()` und `flush_bus_matrix()`. Der Bootloader Core MUSS diese bei Vorhandensein ausrufen, bevor er erste Schreibvorgänge via `flash_hal_t` in geteilte Speicherregionen tätigt.

### 1.5 Fehlende OTP-Persistenz für Serial Rescue / DSLC (Sicherheit)
**Problem:** Der Recovery-Handshake über Schicht 4a (Serial) fordert den Zugriff auf einen Hardware-DSLC und das Schreiben eines monotonen Counters (Anti-Replay) explizit *außerhalb* des zirkulären Flash-WALs in Option Bytes / eFuses (`NVRAM_Highest`). Dennoch bieten weder `crypto_hal_t` noch `flash_hal_t` Methoden für Secure Storage Access an. Wäre der Counter im regulären Flash implementiert, würde dessen Erase-Verschleiß die Recovery-Funktion zerstören.
**Mitigation:** `crypto_hal_t` MUSS um die Methoden `boot_status_t (*read_dslc)(uint8_t *buffer, size_t *len)` und Hardware-Counter Integration `(*read_monotonic_counter)(uint32_t *ctr)` sowie `(*advance_monotonic_counter)()` ergänzt werden. Dies erzwingt die Verlagerung des Anti-Replay Schutzes in NVRAM/OTP per Hardware-Layer.

### 1.6 UART `getchar` Deadlock auf WDT-locked Hardware (nRF52) (Logic Error)
**Problem:** `console_hal_t.getchar(timeout_ms)` aus `hals.md` hat blockierende Natur (wartet z.B. 10.000 ms auf Techniker-Input). Gleichzeitig legt `hals.md` fest, dass der nRF52 WDT physikalisch unmöglich über `wdt_hal_t.disable()` abgeschaltet werden kann (No-Op). Wenn `getchar()` in der Console-HAL hart blockiert, während der WDT unaufhaltsam tickt, resettet der Bootloader deterministisch während der Diagnose-Eingabe.
**Mitigation:** `getchar()` darf Hardware-übergreifend niemals CPU-Ringe via blockierendem Polling absperren, ohne den WDT zu kicken. Entweder reicht der Core einen Callback `(*wdt_kick_cb)` in `getchar()` hinein, ODER `getchar()` wandelt sich architektonisch in eine rein asynchron gepolltes non-blocking API (`BOOT_ERR_AGAIN`), womit der Core-Loop selbst periodisch `wdt->kick()` antriggert. Letzteres ist Best-Practice.

### 1.7 Crypto Memory Allocation: Stack vs. Arena (Speichersicherheit)
**Problem:** `concept_fusion.md` erlässt in "Schicht 2" ein "Absolutes Verbot von malloc/free" und erzwingt, dass Layer 3 Kryptografie strikt über ein "System-Linker garantiertes statisches `uint8_t crypto_arena[1024]`" abläuft. Im Widerspruch fordert `hals.md` in `hash_init(ctx, ctx_size)`: "Der Context wird vom Aufrufer auf dem Stack allokiert". Bei großen State-Maschinen (PQC, SHA-512) crasht der 14KB RAM-Footprint durch Stack-Overflow in unbestimmbaren Aufrufkaskaden.
**Mitigation:** `hals.md` muss korrigiert werden. Der `ctx` Pointer in `hash_init` wird nicht als Stack-Allokierung der C-Runtime spezifiziert, sondern der Core stellt der HAL zwingend einen garantierten Pointer aus seiner globalen singulären `crypto_arena` zur Verfügung.

### 1.8 OTFDEC Mode Toggling fehlend (Hardware-Sidechannels)
**Problem:** Gemäß Architektur darf für die Signaturprüfung keine On-The-Fly Decryption (OTFDEC) genutzt werden ("roher abgetasteter Ciphertext"), um Timing Side-Channels zu eliminieren. `hals.md` befiehlt: "OTFDEC bleibt deaktiviert", liefert aber dem Core (oder dem Sprung ins App-OS) keinerlei API, um die Hardware-Matrix zwischen "Raw-Mode" und "Decrypted-XIP-Mode" hin und her zu wechseln. 
**Mitigation:** `flash_hal_t` benötigt ein Interface wie `set_otfdec_mode(bool enable)`. Das OS wird beim Boot abstürzen, wenn Stage 1 ohne OTFDEC agiert und danach beim App-Start vergisst, die XIP-Memory-Map vor dem Einsprung für das verschlüsselte Betriebssystem transparent scharfzuschalten.

### 1.9 Mangelhafte Diagnose-Granularität (Dev Experience / Telemetrie)
**Problem:** Das Fehler-Mapping (`boot_status_t`) vereint gewaltige Hardware-Status-Diskrepanzen hinter simplen Schirmen (z.B. `BOOT_ERR_FLASH` oder `BOOT_ERR_CRYPTO`). Wenn das Startup abbricht, generiert Schicht 4b (`boot_diag`) Telemetrie. Ohne das echte Status-Register (z.B. `STM32_HAL_FLASH_ERROR_WRP` statt nur `BOOT_ERR_FLASH`) ist Remote-Debugging bei Fleet-Managern an der Cloud unmöglich.
**Mitigation:** Alle betroffenen HAL-Methoden können durch einen Parameter `uint32_t *vendor_error` ergänzt werden, oder jede HAL liefert explizit `uint32_t (*get_last_vendor_error)(void)` an. Dies leakt keine Vendor-Bloatware ins C-Struct, erlaubt es der SUIT-Diags-Schicht jedoch, präzise 32-Bit Hex-Registerzustände für das Backend im Log abzulegen.

### 1.10 Flash `write()` Atomare Vorbedingung (Fehlertoleranz)
**Problem:** `hals.md` formuliert bei `write()`: "Die HAL DARF optional prüfen (ob der Bereich gelöscht ist)... MUSS aber nicht." Für Production-Grade Aerospace (NASA P10) System-Logik ist das kritisch nachsichtig. Ein versehentlich übersprungenes Erase im WAL führt zu einer korrupten `0` vs `1` Bitmaskierung (In-Place Bit-Rot) ohne das der Bootloader das aktiv stoppt – die Fehler treten erst im Merkle-Check des App-OS mit 3 Stunden Verzögerung auf.
**Mitigation:** Der `boot_status_t` muss um ein `BOOT_ERR_FLASH_NOT_ERASED` ergänzt werden. Vor kritischen Write-Operationen verifiziert die HAL durch einen rigorosen Blank-Check (Lesen in 32-Bit Chunks == `erased_value`), ob Sektoren real gelöscht sind. Dies opfert zwar ein wenig Performance bei kleinen Writes, senkt das Risiko des stummen Bit-Verschleierns (Shadow-Bricking) bei instabilen EEPROMs aber radikal ab.
