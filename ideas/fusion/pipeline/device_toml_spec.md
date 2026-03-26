# ╔════════════════════════════════════════════════════════════════════╗

# ║ TOOB-BOOT device.toml — API-Vertrag & Referenz-Spezifikation ║

# ║ ║

# ║ Dieses Dokument definiert JEDES gültige Feld, seinen Typ, ║

# ║ seine Constraints, und was der Manifest-Compiler daraus ║

# ║ ableitet. Es ist gleichzeitig die Spec UND ein lauffähiges ║

# ║ Beispiel (IoT-Powerbank auf ESP32-S3). ║

# ╚════════════════════════════════════════════════════════════════════╝

#

# DESIGN-PRINZIPIEN:

#

# 1. "Declare intent, not implementation"

# → Der User sagt WAS er will (z.B. "1.5 MB App-Slot").

# Der Compiler berechnet WIE (Adressen, Alignment, Linker-Sections).

#

# 2. "Fail loud before compile, not silent at runtime"

# → Jede Constraint-Verletzung (RAM, Alignment, Flash-Größe)

# bricht den Build ab MIT erklärender Fehlermeldung.

#

# 3. "Sensible defaults, explicit overrides"

# → 80% der Felder haben Defaults die aus `chip` abgeleitet werden.

# Power-User können alles überschreiben.

#

# 4. "Hardware-Wahrheit, nicht Wunschdenken"

# → Felder wie write_align und sector_sizes existieren, weil echte

# Chips (STM32H7: 128 KB Sektoren!) diese Constraints erzwingen.

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [device] — Geräte-Identifikation & Chip-Auswahl

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# Das `chip`-Feld ist der EINZIGE Pflicht-Eintrag. Daraus leitet der

# Manifest-Compiler via chip_database.py ab:

# → architecture (arm_cortex_m | riscv32 | xtensa)

# → vendor (stm32 | nrf | esp | sandbox)

# → toolchain (gcc-arm | gcc-riscv | esp-idf | host)

# → flash.defaults (Sektorgröße, Write-Alignment, erased_value)

# → ram.defaults (SRAM-Größe, Stack-Limit)

# → crypto.hw_capabilities (cc310 | sha_hw | none)

# → confirm.default_mechanism (rtc_ram | backup_reg | flash_sector)

#

# Alle abgeleiteten Werte können explizit überschrieben werden.

[device]
name = "iot-powerbank-v2" # Frei wählbar, erscheint in SUIT-Manifest
vendor = "dabox" # Hersteller-ID für SUIT vendor_id
chip = "esp32s3" # ← PFLICHT. Lookup-Key in chip_database.

# Optionale Overrides (normalerweise automatisch aus chip abgeleitet):

# architecture = "xtensa"

# vendor_family = "esp"

# toolchain = "esp-idf"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [flash] — Physische Flash-Geometrie

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# WARUM das so detailliert sein muss:

#

# ESP32: Extern SPI-NOR, uniforme 4 KB Sektoren, 1/4 Byte Write-Align

# STM32L4: Intern, uniforme 2 KB Pages, 8 Byte (Doppelwort) Write-Align

# STM32H7: Intern, uniforme 128 KB Sektoren (!), 32 Byte Write-Align

# STM32F4: Intern, VARIABLE Sektoren (16/64/128 KB gemischt!)

# nRF52: Intern, uniforme 4 KB Pages, 4 Byte Write-Align

#

# Die `sector_sizes` Liste ist essentiell für Chips mit nicht-uniformen

# Sektoren (STM32F4, STM32F7). Für uniforme Chips reicht `sector_size`.

[flash]
total_size = "8MB" # Gesamtgröße des Flash-Bausteins
type = "external-spi" # internal | external-spi | external-qspi

# ── Uniforme Sektoren (Default für die meisten Chips) ──

sector_size = "4KB" # Einheitliche Sektorgröße
write_align = 4 # Bytes. ESP32=4, STM32L4=8, STM32H7=32
erased_value = 0xFF # Was nach Erase in jeder Zelle steht

# ── Nicht-uniforme Sektoren (STM32F4/F7-Spezialfall) ──

# Wenn gesetzt, überschreibt `sector_sizes` das uniforme `sector_size`.

# Der Compiler berechnet daraus den maximalen Sektor für den Swap-Buffer.

#

# sector_sizes = ["16KB", "16KB", "16KB", "16KB", "64KB", "128KB", "128KB"]

#

# PREFLIGHT-CHECK: Der Compiler warnt wenn sector_sizes gemischt sind

# und schlägt vor, den Swap-Buffer an den größten Sektor zu binden.

# ── Dual-Bank-Architektur (STM32-spezifisch) ──

# dual_bank = false # Default: false

#

# Wenn true:

# → Read-While-Write (RWW) ist möglich (eine Bank flashen, andere lesen)

# → Der Compiler kann Stage-1 Dual-Bank-Update nutzen statt Dual-Slot

# → Flash-Layout wird auf zwei Banken aufgeteilt

# → PREFLIGHT: Prüft ob alle Partitionen korrekt auf Banken verteilt sind

#

# STM32L4 mit 1 MB: Bank1 = 0x08000000-0x0807FFFF, Bank2 = 0x08080000+

# STM32H7 mit 2 MB: Bank1 = 0x08000000-0x080FFFFF, Bank2 = 0x08100000+

# STM32U5: Immer Dual-Bank (hardware-erzwungen)

# ── Flash-Verschlüsselung (ESP32 / STM32 OTFDEC) ──

encryption = "none" # none | transparent | manual

#

# "transparent": Hardware ver/entschlüsselt automatisch (ESP32 Flash Encryption,

# STM32 OTFDEC). Die flash_hal_t Implementierung liefert immer Plaintext

# an den Core. Merkle-Hashes werden über Plaintext berechnet.

#

# "manual": Der Bootloader muss selbst ent/verschlüsseln.

# (Ungewöhnlich, aber für Custom-HW-Setups mit externem Crypto-Chip.)

#

# PREFLIGHT-CHECK: Bei encryption != "none" warnt der Compiler wenn

# der Chip keinen HW-Crypto-Accelerator hat (→ Performance-Einbruch).

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [ram] — SRAM Budget & Shared-Memory-Vertrag

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# Der Bootloader teilt sich SRAM mit nichts — er ist der einzige Code

# der läuft. Aber das RAM-Budget ist hart begrenzt und muss für

# Stack + Merkle-Chunks + WAL-Buffer + Crypto-Scratch reichen.

[ram]
total_size = "512KB" # Gesamt-SRAM des Chips
bootloader_budget = "32KB" # Wieviel SRAM Stage 1 nutzen darf

#

# PREFLIGHT-CHECK: Der Compiler berechnet:

# peak_usage = stack_size

# + merkle.chunk_size

# + (merkle_tree_depth \* 32) # Sibling-Hashes

# + wal_buffer_size # = max(sector_size, 4KB)

# + crypto_scratch # ~2 KB für Ed25519 Verify

# + delta_dictionary # heatshrink window (2^W Bytes)

#

# Wenn peak_usage > bootloader_budget → BUILD BRICHT AB mit:

# "ERROR: Peak SRAM usage (38.2 KB) exceeds bootloader_budget (32 KB).

# Reduce merkle.chunk_size from 8KB to 4KB or increase bootloader_budget."

stack_size = "4KB" # Mindest-Stack für Stage 1

# ── .noinit Shared-RAM (Diagnostik-Handoff an OS) ──

[ram.noinit]
enabled = true
size = "256B" # Bytes die vor hal_deinit() geschützt werden

#

# Der Manifest-Compiler generiert im Linker-Script eine dedizierte

# `.noinit` Section am Ende des SRAM. Stage 1 schreibt boot_diag-Daten

# (Timing-IDS, SBOM-Hash, Boot-Counter) hierhin. Das Feature-OS liest

# sie nach dem Start aus, ohne dass Flash-Writes nötig sind.

#

# PREFLIGHT-CHECK: noinit.size + bootloader_budget <= total_size

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [partitions] — Flash-Layout (Declare Intent, nicht Adressen)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# DER KERN DER INNOVATION: Der User deklariert nur Partitions-NAMEN

# und -GRÖSSEN. Der Manifest-Compiler berechnet:

# → Offsets (sektorausgerichtet)

# → Swap-Buffer-Größe (= max_sector_size)

# → Journal-Größe (2-4 KB je nach WAL-Konfiguration)

# → Preflight-Validierung aller Alignment-Constraints

#

# Reihenfolge im TOML = Reihenfolge im Flash (top-down).

[partitions]

# Stage 0 — Immutable First Stage

[partitions.stage0]
size = "8KB"

# PREFLIGHT: Prüft ob size >= mindest-Footprint für stage0.verify_mode.

# hash-only: min 2 KB

# ed25519-sw: min 8 KB

# ed25519-hw: min 4 KB

# Stage 1 — Dual-Slot (A/B) für Self-Updates

[partitions.stage1]
size = "24KB" # Pro Slot. Compiler allokiert 2x.

# GENERIERT: stage1a bei Offset X, stage1b bei Offset X + size.

# App — Das Feature-OS / Anwendung

[partitions.app]
size = "1536KB"

# ESP32-Constraint: App-Partitionen müssen 64 KB-aligned sein.

# STM32H7-Constraint: App muss an 128 KB Sektorgrenzen starten.

# PREFLIGHT: Compiler prüft alignment automatisch basierend auf chip.

entry_point = "auto" # "auto" = Offset + Header-Size (256 Bytes)

# Manuell: entry_point = "0x20100"

# Staging — Empfangs-Bereich für neue Firmware / Delta-Patches

[partitions.staging]
size = "1536KB"

# Bei Delta-Updates kann Staging deutlich kleiner sein als App:

# size = "256KB" # Reicht für 3-5x Delta-Kompression

# Recovery — Optionales minimales Rettungs-OS

[partitions.recovery]
enabled = false # true aktiviert Recovery-OS-Slot
size = "512KB"

# PREFLIGHT: Warnt wenn recovery.size < 256KB ("zu klein für Zephyr+WiFi")

# NVS — Non-volatile Storage für App-Daten (optional, OS-verwaltet)

[partitions.nvs]
enabled = true
size = "16KB"

# Journal + Swap werden AUTOMATISCH berechnet:

#

# journal_size = 2 \* flash.sector_size (Ring-Buffer braucht 2 Sektoren)

# + 4 KB (Transfer-Bitmap + TMR-Flags + Erase-Counter)

#

# swap_buffer_size = max(flash.sector_sizes)

# (Bei uniformen Sektoren = sector_size)

# (Bei STM32F4: = 128 KB wegen größtem Sektor!)

#

# Der User kann swap und journal NICHT manuell setzen. Das verhindert

# die häufigste Fehlerklasse: falsch dimensionierte Swap-Bereiche.

#

# PREFLIGHT OUTPUT:

# "Flash allocation:

# Stage 0: 0x000000 — 0x001FFF (8 KB)

# Stage 1a: 0x002000 — 0x007FFF (24 KB)

# Stage 1b: 0x008000 — 0x00DFFF (24 KB)

# App: 0x010000 — 0x18FFFF (1536 KB) [64KB-aligned]

# Staging: 0x190000 — 0x30FFFF (1536 KB)

# NVS: 0x310000 — 0x313FFF (16 KB)

# Journal: 0x314000 — 0x31BFFF (32 KB) [auto: 2×4KB + bitmap]

# Swap Buffer: 0x31C000 — 0x31CFFF (4 KB) [auto: max_sector_size]

# ─────────────────────────────────────────────

# Used: 3,188 KB / 8,192 KB (38.9%)

# Free: 5,004 KB"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [security] — Kryptografie, Secure Boot, Anti-Rollback

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[security]
sign_algorithm = "ed25519" # ed25519 | ecdsa-p256 (für Legacy-Kompatibilität)
hash_algorithm = "sha256" # sha256 | blake2b (wenn Monocypher-native)
pqc_hybrid = false # true → Stage 1 lädt ML-DSA zusätzlich

# Stage 0 Verifikationsmodus

[security.stage0]
verify_mode = "hash-only" # hash-only | ed25519-sw | ed25519-hw
key_slots = 3 # Anzahl OTP-Key-Slots (für Key-Rotation)

#

# "hash-only": SHA-256(Stage1) gegen OTP-gespeicherten Hash. ~2 KB Code.

# → Pro: Winzig, universell. Contra: Jedes S1-Update braucht neuen OTP-Slot.

#

# "ed25519-sw": Software Ed25519-Verify. ~8 KB Code.

# → Pro: Unbegrenzte S1-Updates. Contra: Passt nicht in 4 KB Stage 0.

# → PREFLIGHT: Erzwingt partitions.stage0.size >= "8KB"

#

# "ed25519-hw": Hardware-Crypto Ed25519 (CC310, ESP32 DS Peripheral).

# → Pro: ~4 KB Code. Contra: Chip-spezifisch.

# → PREFLIGHT: Prüft ob chip HW-Crypto hat (aus chip_database).

# Anti-Rollback

[security.anti_rollback]
enabled = true
svn_storage = "otp" # otp | flash

#

# "otp": SVN wird in One-Time-Programmable eFuses gespeichert.

# Maximal 32-64 Bumps (je nach Chip). Sicherster Weg.

# "flash": SVN wird in einem dedizierten Flash-Sektor gespeichert.

# Weniger sicher (Flash ist beschreibbar), aber unbegrenzte Bumps.

# Sinnvoll für Entwicklung oder Chips ohne eFuses.

#

# Recovery-OS hat einen SEPARATEN SVN-Counter (svn_recovery_storage).

# Das verhindert, dass ein App-SVN-Bump das Factory-Recovery blockt.

svn_recovery_storage = "flash" # Recovery-SVN immer in Flash (eFuse zu kostbar)

# Debug-Port-Lockdown

[security.debug]
jtag_lock = "efuse" # efuse | option_bytes | software | none

#

# "efuse": Permanent, nicht rückgängig machbar. Für Produktion.

# "option_bytes": STM32 RDP Level 2. Permanent.

# "software": Nur Defense-in-Depth. Race-Condition möglich!

# "none": Nur für Entwicklung. PREFLIGHT WARNT LAUT.

# DSLC (Device Specific Lock Code) Quelle

[security.identity]
dslc_source = "mac" # mac | efuse | factory_otp | custom

#

# "mac": WiFi/BLE MAC-Adresse als Device-ID

# "efuse": Dedizierter eFuse-Block (ESP32: BLOCK3, nRF: FICR)

# "factory_otp": Hersteller-OTP (STM32 UID96)

# "custom": User implementiert boot_hal_get_dslc() selbst

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [update] — OTA-Strategie & Delta-Patching

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[update]
strategy = "in-place" # in-place | overwrite

#

# "in-place": Staging → Swap-Buffer → App (sektorweise, WAL-gesichert)

# Effizienteste Nutzung, erfordert Swap-Buffer.

#

# "overwrite": Staging → App (direkt überschreiben, KEIN Rollback möglich)

# Nur für Development oder Chips mit extremem Flash-Mangel.

# PREFLIGHT: Warnt "No rollback protection! For development only."

delta_updates = true
max_boot_retries = 3 # Fehlgeschlagene Boots bevor Rollback

[update.merkle]
chunk_size = "4KB" # MUSS <= flash.sector_size sein

#

# Der Compiler berechnet daraus:

# tree_depth = ceil(log2(app.size / chunk_size))

# sibling_ram = tree_depth \* 32 Bytes

# manifest_overhead = (app.size / chunk_size) \* 32 Bytes

#

# PREFLIGHT:

# "Merkle tree: 384 chunks, 9 levels, 288 Bytes peak sibling RAM"

# "Manifest Merkle overhead: 12,288 Bytes (12 KB)"

#

# Wenn chunk_size > ram.bootloader_budget \* 0.5 → BUILD BRICHT AB

# (Chunk muss komplett ins RAM passen + Platz für Stack + Crypto)

[update.delta]
compression = "heatshrink" # heatshrink | none
window_size = 8 # heatshrink -w Parameter (2^W Bytes)
lookahead = 4 # heatshrink -l Parameter

#

# RAM-Kosten des Decompressors: 2^window_size + 2^lookahead Bytes

# PREFLIGHT: Prüft ob delta-RAM + merkle-RAM + stack <= bootloader_budget

#

# Checkpoint-Intervall für Brownout-Recovery:

checkpoint_interval = "sector" # "sector" | "N chunks"

#

# "sector": Nach jedem App-Sektor-Commit wird der compression_context

# ins WAL-Journal geflusht (~4 KB). Maximal sicher.

#

# Bei "4 chunks": Seltener flushen, schneller, aber bei Crash

# gehen bis zu 4 Chunks Dekompressions-Fortschritt verloren.

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [confirm] — Boot-Bestätigung & Reset-Diagnostik

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[confirm]
mechanism = "auto" # auto | rtc_ram | backup_register | flash

#

# "auto" wählt basierend auf chip:

# ESP32\*: rtc_ram (RTC-FAST-MEM, 8 KB, überlebt Soft-Reset)

# STM32\*: backup_register (RTC-Domain, überlebt Reset, braucht VBAT)

# nRF52\*: retained_ram (RAMRET Register)

# Sandbox: file (/tmp/toob_confirm)

#

# "flash": Fallback für Chips ohne Retained-RAM/Backup-Register.

# Nutzt dedizierten Sektor mit Wear-Leveling (~100 Bytes pro Boot).

# PREFLIGHT: Warnt "Confirm via Flash: ~365 writes/year × 10 years =

# 3,650 cycles. Well within NOR-Flash limits (100K), but consider

# battery-backed RAM if available."

watchdog_timeout_ms = "auto"

#

# "auto": Manifest-Compiler berechnet:

# wdt_min = max(

# flash_erase_time_per_sector × sectors_per_swap_step × 2, # Safety margin

# boot_timeout_ms,

# 5000 # Absolute Minimum

# )

#

# Typische Ergebnisse:

# ESP32 (4 KB Sektor, ~45ms Erase): → 5000 ms (Minimum greift)

# STM32L4 (2 KB Page, ~25ms Erase): → 5000 ms

# STM32H7 (128 KB Sektor, ~2s Erase): → 8000 ms (!)

#

# PREFLIGHT: "Watchdog timeout: 8000 ms (calculated from 128 KB sector erase)"

# "WARNING: STM32H7 128KB sectors require long WDT timeout."

boot_timeout_ms = 5000 # Max. Zeit bis Stage 1 zum OS springt

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [rescue] — Serial Recovery & Anti-Softbrick

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[rescue]
serial_enabled = true
protocol = "uart" # uart | usb-dfu
baudrate = 115200

# Anti-Softbrick GPIO

recovery_pin = "GPIO0" # Hardware-Pin für Force-Recovery
recovery_pin_active = "low" # low | high (wann gilt der Pin als aktiv?)
recovery_pin_hold_ms = 3000 # Muss N ms gehalten werden (Entprellung)

# Offline 2FA-Auth für Serial Rescue

[rescue.auth]
enabled = true

#

# Wenn true, erfordert Serial Rescue einen signierten Auth-Token.

# Stage 1 prüft: Ed25519(DSLC + Timestamp) gegen Root-Key.

# Timestamp muss monoton steigend sein (Highest-Seen-Timestamp Pattern).

#

# Wenn false, ist Serial Rescue offen (nur für Entwicklung!).

# PREFLIGHT: Warnt "Serial rescue without auth! For development only."

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [diagnostics] — Boot-Telemetrie & Timing-IDS

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[diagnostics]
structured_log = true # JSON-formatierte Boot-Logs
log_level = "info" # error | warn | info | debug
timing_ids = true # Boot-Phasen-Timings messen

# SUIT CRA Compliance

[diagnostics.compliance]
sbom_digest = true # sbom_digest Feld im SUIT-Manifest erzwingen

#

# Wenn true, MUSS jedes SUIT-Manifest ein sbom_digest Feld enthalten.

# Das sign-tool bricht ab wenn kein --sbom-hash angegeben wird.

# boot_diag loggt den Hash bei jedem Boot → Fleet-Manager-Abfrage.

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [images] — Multi-Image-Konfiguration (für Multi-Core-SoCs)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# Für Single-Core-Chips (ESP32, STM32, nRF52840) wird nur [images.app]

# definiert. Für Multi-Core-SoCs (nRF5340: App-Core + Net-Core)

# werden mehrere Images als Atomic Update Group verwaltet.

#

# ARCHITEKTUR-REGEL: Toob-Boot flasht und verifiziert ALLE Images,

# aber bootet NUR den Main-Core. Secondary Boot Delegation obliegt

# dem Feature-OS.

[images.app]
partition = "app" # Referenz auf [partitions.app]

# entry_point bereits in [partitions.app] definiert

# ── Nur für Multi-Core-SoCs (z.B. nRF5340) ──

# [images.netcore]

# partition = "netcore" # Braucht eigene Partition-Definition!

# flash_address = "0x01000000" # Net-Core Flash ist separat addressiert

# size = "256KB"

# atomic_group = "main" # Alle Images in "main" rollen zusammen zurück

#

# PREFLIGHT: Prüft ob ALLE Images in der gleichen atomic_group

# sind (verhindert half-baked Multi-Core-Updates)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [power] — Energy Guard (optional, für batteriebetriebene Geräte)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[power]
enabled = true
min_battery_mv = 3300 # Minimale Spannung VOR Update-Start
measure_under_load = true # Dummy-Load vor Messung (LiPo-Realismus)
abort_on_low = true # Update abbrechen wenn Batterie während Update fällt

# ADC-Konfiguration

adc_channel = "ADC1_CH3" # Chip-spezifischer ADC-Kanal
voltage_divider_ratio = 2.0 # R1/(R1+R2) Spannungsteiler auf dem PCB

#

# Der Manifest-Compiler generiert in boot_config.h:

# #define BOOT_POWER_ADC_CHANNEL 3

# #define BOOT_POWER_VDIV_RATIO_X100 200 // \* 100 für Integer-Arithmetik

# #define BOOT_POWER_MIN_MV 3300

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [build] — Build-System & Toolchain

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[build]
optimization = "size" # size | speed | debug
sandbox = true # Parallel Host-Native-Binary bauen

# OS-Shim Auswahl

os_shim = "baremetal" # baremetal | zephyr | freertos | nuttx

# Toolchain (normalerweise aus chip abgeleitet)

# toolchain = "esp-idf"

# cross_compile = "xtensa-esp32s3-elf-"

# Vendor-Plugin (normalerweise aus chip abgeleitet)

# vendor_plugin = "esp32"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# [suit] — IETF SUIT Manifest-Konfiguration

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[suit]
enabled = true
vendor_id = "dabox.io"
class_id = "iot-powerbank"

# device_id wird aus security.identity.dslc_source abgeleitet

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# PREFLIGHT-REPORT (Beispiel-Output des Manifest-Compilers)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# $ toob-manifest compile manifests/dabox_iot_powerbank.toml

#

# ══════════════════════════════════════════════════

# Toob-Boot Preflight Report

# Device: iot-powerbank-v2 (ESP32-S3)

# Arch: xtensa | Vendor: esp | Toolchain: esp-idf

# ══════════════════════════════════════════════════

#

# ── Flash Layout ──────────────────────────────────

# ✓ Stage 0: 0x000000 — 0x001FFF 8 KB

# ✓ Stage 1a: 0x002000 — 0x007FFF 24 KB

# ✓ Stage 1b: 0x008000 — 0x00DFFF 24 KB

# ✓ App: 0x010000 — 0x18FFFF 1536 KB [64KB-aligned ✓]

# ✓ Staging: 0x190000 — 0x30FFFF 1536 KB

# ✓ NVS: 0x310000 — 0x313FFF 16 KB

# ✓ Journal: 0x314000 — 0x31BFFF 32 KB [2 × 4KB ring + bitmap]

# ✓ Swap Buffer: 0x31C000 — 0x31CFFF 4 KB [= max_sector_size]

# ─────────────────────────────────────────────

# Used: 3,188 KB / 8,192 KB (38.9%)

# Free: 5,004 KB

#

# ── RAM Budget ────────────────────────────────────

# ✓ Stack: 4,096 B

# ✓ Merkle chunk: 4,096 B

# ✓ Merkle siblings: 288 B (9 levels × 32 B)

# ✓ WAL buffer: 4,096 B

# ✓ Crypto scratch: 2,048 B

# ✓ Delta dictionary: 256 B (heatshrink w=8, l=4)

# ─────────────────────────────────────────────

# Peak usage: 14,880 B / 32,768 B (45.4%) ✓

#

# ── Security ──────────────────────────────────────

# ✓ Stage 0: hash-only (SHA-256 vs OTP), 3 key slots

# ✓ Stage 1: Ed25519 (Monocypher), SHA-256

# ✓ Anti-Rollback: SVN via OTP

# ✓ Debug lock: eFuse

# ✓ DSLC source: MAC address

# ⚠ PQC hybrid: disabled (enable for CNSA 2.0 compliance by 2033)

#

# ── Update Engine ─────────────────────────────────

# ✓ Strategy: in-place with WAL journaling

# ✓ Delta: heatshrink (w=8, l=4), sector checkpoints

# ✓ Merkle: 384 chunks, 9 levels, 288 B sibling RAM

# ✓ Max boot retries: 3 → rollback → recovery

#

# ── Timing ────────────────────────────────────────

# ✓ Watchdog timeout: 5,000 ms (auto-calculated)

# ✓ Boot timeout: 5,000 ms

# ✓ Est. verify time: ~45 ms (software SHA-256, 1.5 MB)

#

# ── Power Guard ───────────────────────────────────

# ✓ Min battery: 3,300 mV (under load)

# ✓ ADC: CH3, divider ratio 2.0

#

# ── Rescue ────────────────────────────────────────

# ✓ Serial: UART @ 115200

# ✓ Recovery pin: GPIO0 (active low, 3s hold)

# ✓ Auth: Offline 2FA enabled

#

# ── Generated Files ───────────────────────────────

# → build/generated/flash_layout.ld

# → build/generated/boot_config.h

# → build/generated/stage0_config.h

# → build/generated/platform.resc

#

# BUILD READY. Run: cmake -B build -DTOOB_MANIFEST=manifests/dabox_iot_powerbank.toml
