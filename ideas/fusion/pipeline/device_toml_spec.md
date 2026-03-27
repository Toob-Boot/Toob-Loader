# TOOB-BOOT `device.toml` — API-Vertrag & Referenz-Spezifikation

Dieses Dokument definiert **jedes gültige Feld**, seinen Typ, seine Constraints, und was der Manifest-Compiler daraus ableitet. Es dient als Spezifikation für den Toob-Boot Compiler.

---

## 🚀 1. TL;DR: Ein typisches Beispiel (ESP32-S3 IoT Node)

Im absoluten Standardfall (wenn der Chip in der Core-Registry bekannt ist), ist die `device.toml` extrem kurz. 90% der Hardware-Constraints werden automatisch vom Compiler abgeleitet. Der User definiert nur **Namen und Größen**.

```toml
[device]
# ── PFLICHTFELDER ──
name = "smart-sensor-v1" 
vendor = "dabox"         
chip = "esp32s3"         

[flash]
# ── OPTIONAL (Überschreibt Chip-Default) ──
total_size = "8MB"       
auto_skip_holes = true   # Überspringt physikalisch kaputte Blöcke

[manifest]
# ── PFLICHTFELDER (EU-CRA & SUIT) ──
vendor_id = "c0812be2-2cb5-455b-80a5-2964e59f48ac" 
class_id = "0c476db8-2fcc-4589-a279-d2b512e987bf"  
# sbom_path = "./build/sbom-cyclonedx.json" # (OPTIONAL)

[partitions]
# ── PFLICHTFELDER ──
[partitions.stage0]
size = "4KB"

[partitions.stage1]
size = "24KB"            # Compiler baut daraus automatisch Slot A und B

# NEU: Beliebig viele Images im Lock-Step (Atomic Update Group)
[partitions.images.main_os]
size = "2048KB"          # Haupt-App (Compiler baut Slot A und B)
entry_point = "auto"
staging_size = "512KB"   # Eigener Delta-Download Bereich

# [partitions.images.net_core] # Beispiel für asymmetrischen Dual-Core
# size = "256KB"
# staging_size = "128KB"

[partitions.nvs]
# ── OPTIONAL ──
enabled = true
size = "16KB"

[security]
# ── OPTIONAL (Defaults greifen) ──
sign_algorithm = "ed25519"
hash_algorithm = "sha256"

[security.stage0]
verify_mode = "hash-only"
```

> **Was fehlt hier?** Wo sind `journal` und `swap`? Wo sind die Hex-Offsets (`0x10000`)?  
> **Antwort:** Der Manifest-Compiler berechnet all das automatisch aus der gewählten Flash-Geometrie des ESP32-S3. Der User darf sich hieran nicht die Finger verbrennen.

---

## 🛠 2. Die komplette Spezifikation (Field-by-Field)

Alle folgenden Felder können deklariert werden. Felder, die als **(OPTIONAL)** markiert sind, fallen auf einen sicheren "Chip-Default" zurück, falls sie weggelassen werden.

### 📌 [device] — Identifikation & Chip Registry System

```toml
[device]
name = "iot-powerbank"   # (PFLICHT) Erscheint im generierten SUIT-Manifest.
vendor = "dabox"         # (PFLICHT) Hersteller-ID.
chip = "esp32s3"         # (PFLICHT) Der Lookup-Key für die Registry.

# ── OPTIONALE OVERRIDES ──
# Wenn gesetzt, ignorieren diese Felder die Registry-Werte:
# architecture = "xtensa"          # (OPTIONAL) z.B. arm_cortex_m, xtensa, riscv32
# vendor_family = "esp"            # (OPTIONAL) z.B. stm32, nrf, esp
# toolchain = "esp-idf"            # (OPTIONAL) gcc-arm, esp-idf
```

**🔍 Wie funktioniert die Chip-Suche? (Prioritäten-Liste)**
1. **Fallback (Prio 1):** Liegt in der TOML ein `[hardware_profile]` Block vor?
2. **Community (Prio 2):** Liegt ein Toobfuzzer-File unter `.toob/chips/<chip>.json`?
3. **Core (Prio 3):** Gibt es eine Core-Lib `toob-manifest/core_chips/<chip>.json`?

---

### 🔌 [hardware_profile] — Custom Chip Definition

Dieser Block ist **(KOMPLETT OPTIONAL)**. 
Er ist nur als schneller "Hack" gedacht, wenn man einen völlig unbekannten Chip testen will, ohne vorher eine `.json` in `.toob/chips/` abzulegen. 

```toml
[hardware_profile]
arch = "riscv32"
# Hier würden alle Toobfuzzer-Outputs (aus der <xyz>_chip.json) eingefügt werden.
# Wenn dieser Block existiert, ignoriert der Compiler alle Registries.
```

---

### 💾 [flash] — Physische Flash-Geometrie

```toml
[flash]
total_size = "8MB"        # (OPTIONAL) Wenn weggelassen, prüft der Compiler nicht ob das Layout den Chip sprengt.
type = "external-spi"     # (OPTIONAL) internal | external-spi | external-qspi

auto_skip_holes = true    # (OPTIONAL) Default: false. Wenn true, überspringt der Compiler physikalisch kaputte/gesperrte 
                          # Flash-Sektoren automatisch, aber NUR wenn diese exakt zwischen zwei Partitionen liegen. 
                          # Trifft eine Partition eine Lücke intern, bricht der Build sofort ab (Safety First!).

# Die folgenden Felder kommen standardmäßig aus der Registry (chip="...").
# Wenn sie hier deklariert werden, überschreiben sie das Registry-Wissen:
sector_size = "4KB"       # (OPTIONAL) z.B. 4096 (Bytes). 
write_align = 4           # (OPTIONAL) Bytes. ESP32=4, STM32L4=8, STM32H7=32.
erased_value = 0xFF       # (OPTIONAL) Was nach Erase in der Zelle steht.
encryption = "none"       # (OPTIONAL) none | transparent | manual
```

---

### 🧠 [ram] — SRAM Budget & Shared-Memory

```toml
[ram]
bootloader_budget = "32KB"     # (OPTIONAL) Default: Aus Registry. Peak-RAM für Stage 1. 
stack_size = "4KB"             # (OPTIONAL) Minimal-Stack.

[ram.noinit]
enabled = true                 # (OPTIONAL) Default: false. Schützt RAM vor OS-Start.
size = "256B"                  # (PFLICHT wenn enabled) Wieviel RAM für Diagnostik reserviert wird.
```

---

### 🗄️ [partitions] — Flash-Layout (Multi-Image)

Das ist das architektonische Herzstück. Hier konfigurierst du deine Atomic-Update-Group (Lock-Step Updates) für einen oder beliebig viele Cores.

```toml
[partitions]

[partitions.stage0]
size = "8KB"              # (PFLICHT) Größe des unantastbaren Stage 0.

[partitions.stage1]
size = "24KB"             # (PFLICHT) Größe *eines* Slots. Der Compiler baut 2x 24KB!

# Definition ALLER bootbaren Images (Multi-Core Support!)
[partitions.images.main_os]
size = "1536KB"           # (PFLICHT) Größe *eines* Slots. Compiler baut A und B.
entry_point = "auto"      # (OPTIONAL) "auto" setzt den Offset_Header automatisch.
staging_size = "512KB"    # (PFLICHT) Eigener Download-Bereich für diesen Core.

[partitions.images.net_core]
size = "256KB"            # (PFLICHT) Zweites Image (z.B. Netzwerk Coprozessor). Beide Images werden als atomare Gruppe geupdatet!
staging_size = "128KB"    # (PFLICHT) Jeder Core braucht aus Safety-Gründen sein eigenes, strikt isoliertes Download-Areal.
```

---

### 📜 [manifest] — EU-CRA Regulatorik & SUIT

Sämtliche Device-Bindungen und Verifikationen, die der Payload über den Kopf "gestülpt" werden.

```toml
[manifest]
vendor_id = "c0812be2-2cb5-455b-80a5-2964e59f48ac" # (PFLICHT) RFC4122 UUID
class_id = "0c476db8-2fcc-4589-a279-d2b512e987bf"  # (PFLICHT) Identifiziert die Produktlinie
sbom_path = "./build/sbom-cyclonedx.json"          # (OPTIONAL) Liefert CRA-Integrität. Der Compiler schiebt den SHA-256 Hash der SBOM als 'diagnostic' in das SUIT-Manifest.

[partitions.recovery]
enabled = false           # (OPTIONAL) Default: false. Minimales Rettungs-OS.
size = "512KB"            # (PFLICHT wenn enabled).

[partitions.nvs]
enabled = true            # (OPTIONAL) Default: false. Non-volatile Storage für App-Daten.
size = "16KB"             # (PFLICHT wenn enabled).
```

---

### 🛡️ [security] — Kryptografie & Secure Boot

```toml
[security]
sign_algorithm = "ed25519" # (OPTIONAL) ed25519 | ecdsa-p256. (Default: ed25519)
hash_algorithm = "sha256"  # (OPTIONAL) sha256 | blake2b. (Default: sha256)
pqc_hybrid = false         # (OPTIONAL) Lädt ML-DSA Modul zusätzlich. (Default: false)

[security.stage0]
verify_mode = "hash-only"  # (OPTIONAL) hash-only | ed25519-sw | ed25519-hw. (Default aus Registry)
key_slots = 3              # (OPTIONAL) OTP-Key-Slots zur Key-Rotation. (Default: 3)

[security.anti_rollback]
enabled = true                 # (OPTIONAL) Default: true.
svn_storage = "otp"            # (OPTIONAL) otp | flash. (Default: otp)
svn_recovery_storage = "flash" # (OPTIONAL) App-Counter blockt nie Factory-Recovery.

[security.debug]
jtag_lock = "efuse"        # (OPTIONAL) efuse | option_bytes | software | none. (Default aus Registry)

[security.identity]
dslc_source = "mac"        # (OPTIONAL) mac | efuse | factory_otp | custom. (Default aus Registry)
```

---

### 🔄 [update] — OTA & Delta-Patching (WAL)

```toml
[update]
strategy = "in-place"      # (OPTIONAL) in-place (Swap) | overwrite (Kein Rollback!). Default: in-place
delta_updates = true       # (OPTIONAL) Default: true.
max_boot_retries = 3       # (OPTIONAL) Fehlgeschlagene Boots bevor S1 Rollback auslöst. Default: 3.

[update.merkle]
chunk_size = "4KB"         # (OPTIONAL) MUSS <= flash.sector_size sein. Default: sector_size.

[update.delta]
compression = "heatshrink"     # (OPTIONAL) heatshrink | none. Default: heatshrink.
window_size = 8                # (OPTIONAL) RAM-Fenster für Dekomprimierung. Default: 8.
lookahead = 4                  # (OPTIONAL) RAM-Lookahead. Default: 4.
checkpoint_interval = "sector" # (OPTIONAL) "sector" | "4 chunks". Default: "sector".
```

---

### 🤝 [confirm] — OS Handoff & Boot-Bestätigung

```toml
[confirm]
mechanism = "auto"           # (OPTIONAL) auto | rtc_ram | backup_register | flash. (Default: auto)
watchdog_timeout_ms = "auto" # (OPTIONAL) Auto = aus Sektor-Erase Dauer berechnet.
boot_timeout_ms = 5000       # (OPTIONAL) Dauer bis Stage 1 die App lädt. Default: 5000.
```

---

### 🛠 [rescue] & 🔋 [power] — Notfall & Energy Guard

```toml
[rescue]
serial_enabled = true      # (OPTIONAL) Default: false (aus Security-Gründen).
protocol = "uart"          # (OPTIONAL) uart | usb-dfu. Default: uart.
baudrate = 115200          # (OPTIONAL) Default: 115200.

recovery_pin = "GPIO0"     # (OPTIONAL) Hardware-Pin für Force-Recovery.
recovery_pin_active = "low" # (OPTIONAL) low | high.
recovery_pin_hold_ms = 3000 # (OPTIONAL) Default: 3000.

[rescue.auth]
enabled = true             # (OPTIONAL) Offline 2FA-Auth für Serial Rescue! Default: true.

[power]
enabled = true                 # (OPTIONAL) Verhindert Flash-Brownouts. Default: false.
min_battery_mv = 3300          # (PFLICHT wenn enabled)
measure_under_load = true      # (OPTIONAL) Default: true.
abort_on_low = true            # (OPTIONAL) Default: true.
adc_channel = "ADC1_CH3"       # (PFLICHT wenn enabled)
voltage_divider_ratio = 2.0    # (PFLICHT wenn enabled)
```
