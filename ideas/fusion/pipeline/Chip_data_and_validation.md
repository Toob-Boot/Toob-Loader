# ╔═══════════════════════════════════════════════════════════════╗

# ║ VALIDATION_RULES — Manifest Compiler Preflight Engine ║

# ║ ║

# ║ Dieses Dokument definiert JEDE einzelne Validierungs-Regel, ║

# ║ die der Manifest-Compiler prüft, bevor er das OS baut. ║

# ║ Zudem dient das CHIP_DATABASE Dict als Struktur-Referenz ║

# ║ für generierte '<xyz>_chip.json' Registry-Files. ║

# ╚═══════════════════════════════════════════════════════════════╝

CHIPS = {

    # ── Espressif (Xtensa) ───────────────────────────────
    "esp32": {
        "arch": "xtensa",
        "vendor": "esp",
        "toolchain": "esp-idf",
        "flash": {
            "type": "external-spi",
            "sector_size": 4096,
            "write_align": 4,
            "erased_value": 0xFF,
            "app_align": 65536,       # App-Partitionen müssen 64KB-aligned sein
            "encryption_support": True,
        },
        "ram": {
            "total": 520 * 1024,      # 520 KB (SRAM + RTC)
            "default_budget": 32768,
        },
        "confirm": {
            "default": "rtc_ram",
            "rtc_ram_size": 8192,     # 8 KB RTC-FAST-MEM
        },
        "crypto": {
            "hw_sha256": True,
            "hw_aes": True,
            "hw_ed25519": False,
            "hw_rng": True,
        },
        "identity": {
            "mac_available": True,
            "efuse_blocks": 4,        # BLOCK0-3
            "uid_bits": 0,            # Kein UID96 wie STM32
        },
        "reset_reason": {
            "register": "RTC_CNTL_RESET_CAUSE_REG",
            "wdt_value": 0x01,       # TG0WDT_SYS_RST
            "por_value": 0x01,       # POWERON_RESET
            "sw_value": 0x03,        # SW_SYS_RST
        },
        "debug": {
            "jtag_lock": "efuse",     # JTAG_DISABLE eFuse
        },
        "notes": [
            "Flash ist extern via SPI — Read-While-Write immer möglich",
            "Dual-Core (PRO + APP), aber ein einziges Image",
        ],
    },

    # ── Espressif (Xtensa, neuere Serie) ─────────────────
    "esp32s3": {
        "arch": "xtensa",
        "vendor": "esp",
        "toolchain": "esp-idf",
        "flash": {
            "type": "external-spi",   # Auch OSPI bei -R8 Varianten
            "sector_size": 4096,
            "write_align": 4,
            "erased_value": 0xFF,
            "app_align": 65536,
            "encryption_support": True,
            "max_size": 16 * 1024 * 1024,  # Bis 16 MB unterstützt
        },
        "ram": {
            "total": 512 * 1024,
            "default_budget": 32768,
        },
        "confirm": {
            "default": "rtc_ram",
            "rtc_ram_size": 8192,
        },
        "crypto": {
            "hw_sha256": True,
            "hw_aes": True,
            "hw_ed25519": False,       # Kein DS Peripheral für Ed25519
            "hw_rng": True,
        },
        "identity": {
            "mac_available": True,
            "efuse_blocks": 11,        # BLOCK0-10 (mehr als ESP32)
        },
        "debug": {
            "jtag_lock": "efuse",      # JTAG über USB-OTG oder Pins
        },
    },

    # ── Espressif (RISC-V) ───────────────────────────────
    "esp32c3": {
        "arch": "riscv32",             # ← RISC-V statt Xtensa!
        "vendor": "esp",
        "toolchain": "esp-idf",        # Gleicher Toolchain, anderes Target
        "flash": {
            "type": "external-spi",
            "sector_size": 4096,
            "write_align": 4,
            "erased_value": 0xFF,
            "app_align": 65536,
            "encryption_support": True,
        },
        "ram": {
            "total": 400 * 1024,       # Weniger RAM als S3
            "default_budget": 24576,   # Konservativer Default
        },
        "confirm": {
            "default": "rtc_ram",
            "rtc_ram_size": 8192,
        },
        "crypto": {
            "hw_sha256": True,
            "hw_aes": True,
            "hw_ed25519": True,        # Digital Signature Peripheral!
            "hw_rng": True,
        },
        "identity": {
            "mac_available": True,
            "efuse_blocks": 11,
        },
        "debug": {
            "jtag_lock": "efuse",
        },
        "notes": [
            "Single-Core RISC-V",
            "Hat DS Peripheral für HW-Ed25519 → stage0 ed25519-hw möglich",
        ],
    },

    "esp32c6": {
        "arch": "riscv32",
        "vendor": "esp",
        "toolchain": "esp-idf",
        "flash": {
            "type": "external-spi",
            "sector_size": 4096,
            "write_align": 4,
            "erased_value": 0xFF,
            "app_align": 65536,
            "encryption_support": True,
        },
        "ram": {
            "total": 512 * 1024,
            "default_budget": 32768,
        },
        "confirm": {"default": "rtc_ram", "rtc_ram_size": 8192},
        "crypto": {
            "hw_sha256": True, "hw_aes": True,
            "hw_ed25519": True, "hw_rng": True,
        },
        "identity": {"mac_available": True, "efuse_blocks": 11},
        "debug": {"jtag_lock": "efuse"},
        "notes": ["802.15.4 (Thread/Zigbee) + WiFi6 + BLE5"],
    },

    # ── STMicroelectronics (Cortex-M4, Page-Flash) ──────
    "stm32l4": {
        "arch": "arm_cortex_m",
        "vendor": "stm32",
        "toolchain": "gcc-arm",
        "flash": {
            "type": "internal",
            "sector_size": 2048,       # 2 KB Pages (uniform)
            "write_align": 8,          # Doppelwort (64 bit)!
            "erased_value": 0xFF,
            "app_align": 2048,         # Kein spezielles App-Alignment
            "dual_bank": True,         # 1 MB = 2 × 512 KB Banken
            "bank_size": 512 * 1024,
            "rww": True,               # Read-While-Write bei Dual-Bank
            "encryption_support": False,
        },
        "ram": {
            "total": 320 * 1024,       # STM32L4R5: 640 KB, L476: 128 KB
            "default_budget": 24576,
        },
        "confirm": {
            "default": "backup_register",
            "backup_reg_count": 32,    # 32 × 32-bit Backup-Register
            "needs_vbat": True,        # Braucht VBAT-Pin für Retention!
        },
        "crypto": {
            "hw_sha256": False,        # Kein HW-SHA auf L4 (außer L4Sxx)
            "hw_aes": True,            # AES-256 HW-Beschleuniger
            "hw_ed25519": False,
            "hw_rng": True,            # True Random Number Generator
        },
        "identity": {
            "mac_available": False,    # Kein WiFi/BLE MAC
            "uid96": True,             # 96-bit Unique ID (Factory)
            "uid_address": 0x1FFF7590, # STM32L4-spezifisch
        },
        "reset_reason": {
            "register": "RCC_CSR",
            "wdt_value": "IWDGRSTF",
            "por_value": "PORRSTF",
            "sw_value": "SFTRSTF",
            "pin_value": "PINRSTF",
        },
        "debug": {
            "jtag_lock": "option_bytes",  # RDP Level 2 = permanent
        },
        "notes": [
            "Doppelwort-Write (8 Bytes) — WAL-Entries müssen 8B-aligned sein!",
            "VBAT für Backup-Register — ohne Knopfzelle confirm via Flash",
        ],
    },

    # ── STMicroelectronics (Cortex-M7, Sector-Flash) ────
    "stm32h7": {
        "arch": "arm_cortex_m",
        "vendor": "stm32",
        "toolchain": "gcc-arm",
        "flash": {
            "type": "internal",
            "sector_size": 131072,     # 128 KB Sektoren (!)
            "write_align": 32,         # 256 bit = 32 Bytes Flash-Word
            "erased_value": 0xFF,
            "app_align": 131072,       # App muss an 128KB-Grenze starten
            "dual_bank": True,
            "bank_size": 1024 * 1024,  # 2 MB = 2 × 1 MB
            "rww": True,
            "encryption_support": True, # OTFDEC auf H7Bx
        },
        "ram": {
            "total": 1024 * 1024,      # 1 MB SRAM (AXI + DTCM + ITCM)
            "default_budget": 65536,   # 64 KB — Chip hat genug
        },
        "confirm": {
            "default": "backup_register",
            "backup_reg_count": 32,
            "needs_vbat": True,
        },
        "crypto": {
            "hw_sha256": True,         # HASH Peripheral
            "hw_aes": True,            # CRYP Peripheral
            "hw_ed25519": False,
            "hw_rng": True,
        },
        "identity": {"uid96": True, "uid_address": 0x1FF1E800},
        "debug": {"jtag_lock": "option_bytes"},
        "notes": [
            "128 KB Sektoren! Swap-Buffer ist 128 KB!",
            "WDT-Timeout muss ~8s sein wegen langsamer Sektor-Erase",
            "32-Byte Write-Align — JEDER WAL-Entry muss 32B-padded sein",
            "OTFDEC: On-the-fly Decryption für externen Flash",
        ],
    },

    "stm32u5": {
        "arch": "arm_cortex_m",
        "vendor": "stm32",
        "toolchain": "gcc-arm",
        "flash": {
            "type": "internal",
            "sector_size": 8192,       # 8 KB Pages
            "write_align": 16,         # 128 bit = 16 Bytes (Quad-Word)
            "erased_value": 0xFF,
            "app_align": 8192,
            "dual_bank": True,         # Immer Dual-Bank auf U5
            "rww": True,
            "encryption_support": True, # OTFDEC
            "trustzone": True,         # TrustZone-M
        },
        "ram": {
            "total": 786 * 1024,       # 786 KB
            "default_budget": 32768,
        },
        "confirm": {"default": "backup_register", "needs_vbat": True},
        "crypto": {
            "hw_sha256": True, "hw_aes": True,
            "hw_ed25519": False, "hw_rng": True,
            "pka": True,               # Public Key Accelerator!
        },
        "identity": {"uid96": True, "uid_address": 0x0BFA0700},
        "debug": {"jtag_lock": "option_bytes"},
        "notes": [
            "TrustZone-M: Stage 0 kann in Secure World laufen",
            "PKA: Hardware Public-Key-Accelerator für ECDSA/Ed25519",
            "16-Byte Write-Align (Quad-Word)",
        ],
    },

    # ── Nordic Semiconductor (Cortex-M4) ────────────────
    "nrf52840": {
        "arch": "arm_cortex_m",
        "vendor": "nrf",
        "toolchain": "gcc-arm",
        "flash": {
            "type": "internal",
            "sector_size": 4096,       # 4 KB Pages
            "write_align": 4,          # Wort-Write
            "erased_value": 0xFF,
            "app_align": 4096,
            "dual_bank": False,        # Single-Bank
            "rww": False,              # Kein RWW! Flash stalls bei Write.
            "encryption_support": False,
        },
        "ram": {
            "total": 256 * 1024,       # 256 KB
            "default_budget": 24576,
        },
        "confirm": {
            "default": "retained_ram",
            "retained_ram_size": 4096, # RAMRET: beliebige RAM-Bereiche retainen
        },
        "crypto": {
            "hw_sha256": True,         # CC310 CryptoCell
            "hw_aes": True,            # CC310
            "hw_ed25519": True,        # CC310 kann Ed25519!
            "hw_rng": True,            # CC310 RNG
            "cc_version": 310,
        },
        "identity": {
            "mac_available": True,     # BLE Device Address
            "ficr_device_id": True,    # FICR.DEVICEID (64-bit)
        },
        "reset_reason": {
            "register": "RESETREAS",
            "wdt_value": "DOG",
            "por_value": "RESETPIN",   # Oder SREQ
            "sw_value": "SREQ",
        },
        "debug": {
            "jtag_lock": "efuse",      # APPROTECT in UICR
        },
        "notes": [
            "CC310 hat HW-Ed25519 → stage0 ed25519-hw ideal",
            "Kein RWW: Während Flash-Write ist CPU blockiert!",
            "APPROTECT muss in UICR gesetzt werden (nicht eFuse im STM32-Sinn)",
        ],
    },

    # ── Nordic Semiconductor (Cortex-M33, Multi-Core) ───
    "nrf5340": {
        "arch": "arm_cortex_m",
        "vendor": "nrf",
        "toolchain": "gcc-arm",
        "flash": {
            "type": "internal",
            "sector_size": 4096,
            "write_align": 4,
            "erased_value": 0xFF,
            "app_align": 4096,
            "dual_bank": False,
            "rww": False,
        },
        "ram": {
            "total": 512 * 1024,       # App-Core: 512 KB
            "default_budget": 32768,
        },
        "confirm": {"default": "retained_ram"},
        "crypto": {
            "hw_sha256": True,
            "hw_aes": True,
            "hw_ed25519": True,
            "hw_rng": True,
            "cc_version": 312,         # CC312 (neuer als CC310)
        },
        "identity": {"ficr_device_id": True, "mac_available": True},
        "debug": {"jtag_lock": "efuse"},
        "multi_core": {
            "cores": ["app", "net"],
            "net_core_flash": {
                "base_address": 0x01000000,
                "size": 256 * 1024,
                "sector_size": 2048,   # Net-Core hat 2 KB Pages!
            },
            "ipc_mechanism": "shared_ram",
        },
        "notes": [
            "Dual-Core: App (Cortex-M33) + Net (Cortex-M33)",
            "Net-Core hat eigenen Flash mit ANDEREN Sektorgrößen!",
            "IPC über Shared-RAM → Atomic Update Groups zwingend",
            "TrustZone auf App-Core verfügbar",
        ],
    },

    # ── Host-Sandbox (Entwicklung & CI) ─────────────────
    "sandbox": {
        "arch": "host",
        "vendor": "sandbox",
        "toolchain": "host",
        "flash": {
            "type": "simulated",
            "sector_size": 4096,
            "write_align": 1,          # Keine HW-Constraints im Host
            "erased_value": 0xFF,
            "app_align": 4096,
        },
        "ram": {
            "total": 1024 * 1024 * 1024,  # "Unbegrenzt"
            "default_budget": 32768,       # Aber wir simulieren Constraints!
        },
        "confirm": {"default": "file"},
        "crypto": {
            "hw_sha256": False,
            "hw_ed25519": False,
            "hw_rng": False,           # /dev/urandom stattdessen
        },
        "identity": {"dslc": "SANDBOX-DEV-0000"},
        "debug": {"jtag_lock": "none"},
        "notes": ["Alle Flash-Operationen gehen gegen eine mmap'd Datei"],
    },

}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# PREFLIGHT VALIDATION RULES

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#

# Diese Regeln werden vom validator.py gegen die TOML + chip_database

# geprüft. Jede Verletzung → Build-Abbruch mit Erklärung.

VALIDATION_RULES = [ # ── Flash-Alignment ──
{
"id": "FLASH_001",
"check": "partition.offset % chip.flash.sector_size == 0",
"message": "Partition '{name}' offset {offset} is not sector-aligned "
"(sector_size={sector_size}). Must be multiple of {sector_size}.",
"severity": "error",
},
{
"id": "FLASH_002",
"check": "partition.app.offset % chip.flash.app_align == 0",
"message": "App partition must be {app_align}-byte aligned on {chip}. "
"Current offset: {offset}.",
"severity": "error",
},
{
"id": "FLASH_003",
"check": "sum(all_partitions) <= chip.flash.total_size",
"message": "Partitions exceed flash capacity! "
"Used: {used} / {total} ({percent}%).",
"severity": "error",
},
{
"id": "FLASH_004",
"check": "merkle.chunk_size <= chip.flash.sector_size",
"message": "Merkle chunk_size ({chunk}) exceeds sector_size ({sector}). "
"Chunks must fit within a single sector.",
"severity": "error",
},

    # ── Write-Alignment ──
    {
        "id": "WRITE_001",
        "check": "wal_entry_size % chip.flash.write_align == 0",
        "message": "WAL entry size ({entry_size}B) is not aligned to "
                   "write_align ({align}B) on {chip}. "
                   "Pad WAL entries to {padded}B.",
        "severity": "error",
        "note": "STM32H7 braucht 32B-aligned WAL-Entries!",
    },

    # ── RAM-Budget ──
    {
        "id": "RAM_001",
        "check": "peak_sram <= ram.bootloader_budget",
        "message": "Peak SRAM usage ({peak}B) exceeds budget ({budget}B). "
                   "Reduce merkle.chunk_size or increase bootloader_budget.",
        "severity": "error",
    },
    {
        "id": "RAM_002",
        "check": "ram.noinit.size + ram.bootloader_budget <= ram.total_size",
        "message": ".noinit reservation ({noinit}B) + bootloader budget ({budget}B) "
                   "exceeds total SRAM ({total}B).",
        "severity": "error",
    },

    # ── Stage 0 Footprint ──
    {
        "id": "S0_001",
        "check": "stage0_min_size(verify_mode) <= partitions.stage0.size",
        "message": "Stage 0 partition ({s0_size}) too small for verify_mode "
                   "'{mode}'. Minimum: {min_size}.",
        "severity": "error",
    },

    # ── Sicherheit ──
    {
        "id": "SEC_001",
        "check": "security.debug.jtag_lock != 'none'",
        "message": "JTAG/SWD debug port is UNLOCKED! "
                   "Set security.debug.jtag_lock for production.",
        "severity": "warning",
    },
    {
        "id": "SEC_002",
        "check": "rescue.auth.enabled == true",
        "message": "Serial rescue without authentication! "
                   "Enable rescue.auth for production.",
        "severity": "warning",
    },

    # ── Hardware-Kompatibilität ──
    {
        "id": "HW_001",
        "check": "stage0.verify_mode != 'ed25519-hw' or chip.crypto.hw_ed25519",
        "message": "{chip} has no hardware Ed25519 support. "
                   "Use verify_mode='hash-only' or 'ed25519-sw'.",
        "severity": "error",
    },
    {
        "id": "HW_002",
        "check": "confirm.mechanism != 'backup_register' or chip.confirm.needs_vbat",
        "message": "{chip} backup registers require VBAT pin. "
                   "Ensure battery/supercap is connected, or use confirm.mechanism='flash'.",
        "severity": "warning",
    },
    {
        "id": "HW_003",
        "check": "not chip.flash.dual_bank or partitions_respect_bank_boundary",
        "message": "Partition '{name}' crosses flash bank boundary at {boundary}. "
                   "Dual-bank chips require partitions within a single bank.",
        "severity": "error",
    },

    # ── STM32H7-Spezifische Warnung ──
    {
        "id": "H7_001",
        "check": "chip != 'stm32h7' or confirm.watchdog_timeout_ms >= 8000",
        "message": "STM32H7 has 128KB sectors with ~2s erase time. "
                   "Watchdog timeout should be >= 8000ms (currently {wdt_ms}ms).",
        "severity": "warning",
    },

    # ── Multi-Core ──
    {
        "id": "MC_001",
        "check": "all images in same atomic_group",
        "message": "Image '{img}' is not in an atomic_group. "
                   "Multi-core updates MUST be atomic to prevent IPC crashes.",
        "severity": "error",
    },

    # ── Toobfuzzer-Wahrheiten ──
    {
        "id": "FUZZ_001",
        "check": "partition within scan_bounds",
        "message": "Partition '{name}' extends into an unknown or broken flash region at {offset}. "
                   "Toobfuzzer 'aggregated_scan.json' did not confirm this sector as readable/erased.",
        "severity": "error",
    },
    {
        "id": "FUZZ_002",
        "check": "svd_addresses_exist",
        "message": "Hardware addresses [UART=0x{uart}, WDT=0x{wdt}] declared in hardware_profile "
                   "do not exist in the Toobfuzzer SVD extraction.",
        "severity": "warning",
    },

]
