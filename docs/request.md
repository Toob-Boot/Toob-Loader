# Toobfuzzer3 Gemini Prompts: Die Stage 4 Injection

Um die bestehenden Pipeline-Prompts (`prompt_stage1` bis `prompt_stage3`) in `toobfuzzer3/linker_gen/gemini_parser.py` nicht zu überladen und das **Instruction Following (Determinismus)** des LLMs bei den komplexen Memory-Maps nicht zu vergiften, lagern wir alle Toob-Boot-spezifischen Edge-Cases (Reset-Register, Multi-Core, Flash-Hardware) in eine isolierte **Stage 4** aus.

Damit wird die alte, statische `Chip_data_and_validation.md` restlos obsolet.

---

## 🛠️ Der Python-Patch (`gemini_parser.py`)

Füge exakt diesen Python-Block direkt unter `prompt_stage3` (ca. Zeile 153) in die `gemini_parser.py` ein:

```python
    # STAGE 4: Toob-Boot Specific Hardware Physics
    prompt_stage4 = f"""
    Continuing the bare-metal analysis for the {chip_name} ({architecture}), focus STRICTLY on the physical controller constraints, survival mechanisms, and asynchronous SoC topologies required for building an atomic A/B Bootloader.

    Address the following core areas:
    1. Flash Constraints: Does the flash controller mandate specific write packages (e.g., STM32H7 needs 32-byte Double-Words, ESP32 needs 4)? Are there proprietary BootROM restrictions stating executable caching must be strictly aligned to large sectors (e.g., 64KB on ESP32)? Can the internal flash erase Bank B while actively executing code from Bank A (Read-While-Write capability)?
    2. Reset Reason Extraction: What is the EXACT register address and specific hexadecimal Bit-Masks to detect if the MCU woke up due to a Power-On Reset (POR), a Hardware Watchdog Timer (WDT) Exception, or a Software Request? This is critical for rolling back from fatal firmware loops.
    3. Hardware Identity & Crypto: Do any of the silicon's hardware modules natively accelerate AES, SHA256, Ed25519 (e.g., PKA or Cryptocell CC310)? Does the factory burn a unique ID (UID96) or BLE MAC address into the eFuses/Option Bytes, and if so, at what address?
    4. Reboot Survival: Toob-Boot needs to pass a 'Boot Confirm' flag across a reboot. What is the most reliable hardware register/RAM block (RTC SRAM, 32-bit Backup Registers, Retained RAM) that survives a standard Watchdog Reset without requiring a CMOS/V_BAT pin?
    5. Multi-Core (Asymmetrical) Layout: If this chip holds an alien Coprocessor (e.g., nRF5340 Net-Core), does it have an independent flash base address and different cache alignment bounds? What is the IPC mechanism (Shared RAM vs. Mailbox)?

    OUTPUT ONLY VALID JSON matching this exact structure (no markdown):
    {{
        "{chip_name}": {{
            "flash_capabilities": {{
                "write_alignment_bytes": 4,
                "app_alignment_bytes": 65536,
                "is_dual_bank": false,
                "bank_size_bytes": 0,
                "read_while_write_supported": false
            }},
            "reset_reason": {{
                "register_address": "0x...",
                "wdt_reset_mask": "0x...",
                "power_on_reset_mask": "0x...",
                "software_reset_mask": "0x..."
            }},
            "crypto_capabilities": {{
                "hw_sha256": true,
                "hw_aes": true,
                "hw_ed25519": false,
                "hw_rng": true,
                "pka_present": true
            }},
            "survival_mechanisms": {{
                "recommended_storage_type": "rtc_ram",  // Enum: rtc_ram | backup_register | retained_ram | flash
                "needs_vbat_pin": false
            }},
            "factory_identity": {{
                "has_mac_address": true,
                "uid_address": "0x1FFF7590" // Hex-Adresse oder null
            }},
            "multi_core_topology": {{
                "is_multi_core": false,
                "ipc_mechanism": "shared_ram", // Enum: shared_ram | mailbox | none
                "coprocessors": [
                    {{"name": "net_core", "flash_base": "0x01000000", "app_alignment_bytes": 2048}}
                ]
            }}
        }}
    }}
    """
```

---

## 🔒 Executor Integration

Im Caching- und Request-Block deiner Pipeline (weiter unten in der `gemini_parser.py`) musst du nun nur noch den Call für Stage 4 aufnehmen:

```python
            # ... vorhandener code
            
            prompt_stage4_res = executor.submit(
                execute_prompt,
                prompt_stage4,
                "Stage 4: Topology & Boot Physics",
                run_num,
                runs
            )
            
            # ... dict merging code
            if prompt_stage4_res.result():
                 # merge the advanced keys into final_blueprint
                 pass
```

### Der strategische Vorteil
Mit dieser Lösung vergiften wir nicht das LLM-Memory des ultra-kritischen RAM/ROM Alignments (Stage 1), behalten eine kristallklare Prompt-Trennung und decken **jede einzelne Hardwarefalle**, die ein Bootloader erfahren kann, 100% deterministisch aus dem Datenblatt ab.
