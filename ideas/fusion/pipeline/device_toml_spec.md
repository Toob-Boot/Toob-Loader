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

[partitions]
# ── PFLICHTFELDER ──
[partitions.stage0]
size = "4KB"

[partitions.stage1]
size = "24KB"            # Compiler baut daraus automatisch Slot A und B

[partitions.app]
size = "2048KB"          # App muss 64KB-aligned sein (Compiler regelt das)
entry_point = "auto"

[partitions.staging]
size = "512KB"           # Reicht für Delta-Updates

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
# Hier würden alle Toobfuzzer-Outputs eingefügt werden.
# Wenn dieser Block existiert, ignoriert der Compiler alle Registries.
```

---

### 💾 [flash] — Physische Flash-Geometrie

```toml
[flash]
total_size = "8MB"        # (OPTIONAL) Wenn weggelassen, prüft der Compiler nicht ob das Layout den Chip sprengt.
type = "external-spi"     # (OPTIONAL) internal | external-spi | external-qspi

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

### 🗄️ [partitions] — Flash-Layout

Das ist das Herzstück. Hier sagst du dem Compiler, WIE GROSS deine Slots sein sollen.

```toml
[partitions]

[partitions.stage0]
size = "8KB"              # (PFLICHT) Größe des unantastbaren Stage 0.

[partitions.stage1]
size = "24KB"             # (PFLICHT) Größe *eines* Slots. Der Compiler baut 2x 24KB!

[partitions.app]
size = "1536KB"           # (PFLICHT) Größe deines Main-OS (z.B. Zephyr).
entry_point = "auto"      # (OPTIONAL) "auto" setzt den Offset_Header automatisch.

[partitions.staging]
size = "1536KB"           # (PFLICHT) Download-Areal für Updates.

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
