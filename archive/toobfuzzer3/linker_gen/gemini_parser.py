import os
import sys
import json
import argparse
import hashlib
from google import genai
from google.genai import types

# Configure your API key. In a real environment, this should be an environment variable.
# For our testing purposes, we'll try to pick it up from the environment or require passing it.
GENAI_API_KEY = os.environ.get("GEMINI_API_KEY")
gemini_client = None


def configure_gemini(api_key):
    global gemini_client
    if not api_key:
        print("[!] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)
    gemini_client = genai.Client(api_key=api_key)


def validate_blueprint_integrity(chip_root, chip_name):
    """
    Acts as a mandatory Validation Layer (TÜV) to catch missing values
    before triggering bare-metal toolchains that will fail or hang permanently.
    """

    def assert_key(d, key, path):
        if key not in d:
            raise RuntimeError(
                f"Validation Error: The LLM failed to extract critical key '{path}.{key}'."
            )

    # 1. Memory Block
    assert_key(chip_root, "memory", "")
    mem = chip_root["memory"]
    assert_key(mem, "memory_regions", "memory")
    if not isinstance(mem["memory_regions"], list) or len(mem["memory_regions"]) == 0:
        raise RuntimeError(
            "Validation Error: 'memory.memory_regions' cannot be an empty array."
        )
    assert_key(mem, "executable_segment", "memory")
    assert_key(mem, "data_segment", "memory")

    # 2. Boot Vectors
    assert_key(chip_root, "boot_vectors", "")
    bv = chip_root["boot_vectors"]
    assert_key(bv, "rom_base", "boot_vectors")

    # 3. Toolchain
    assert_key(chip_root, "toolchain_requirements", "")
    tc = chip_root["toolchain_requirements"]
    assert_key(tc, "packaging", "toolchain_requirements")
    if not isinstance(tc["packaging"], list):
        raise RuntimeError(
            "Validation Error: 'toolchain_requirements.packaging' must be an array."
        )
    assert_key(tc, "flashing", "toolchain_requirements")
    assert_key(tc["flashing"], "write_command", "toolchain_requirements.flashing")

    # 4. Watchdog List (must exist, even if functionally empty '[]' due to no watchdogs)
    if "watchdog_kill_registers" not in chip_root:
        raise RuntimeError(
            "Validation Error: 'watchdog_kill_registers' must exist (at least as an empty array '[]')."
        )
    if not isinstance(chip_root["watchdog_kill_registers"], list):
        raise RuntimeError(
            "Validation Error: 'watchdog_kill_registers' must be a List/Array."
        )

    # 5. Core Security / Mechanics
    assert_key(chip_root, "reset_reason", "")
    assert_key(chip_root["reset_reason"], "register_address", "reset_reason")
    assert_key(chip_root, "survival_mechanisms", "")
    assert_key(
        chip_root["survival_mechanisms"],
        "recommended_storage_type",
        "survival_mechanisms",
    )


def generate_chip_definition(chip_name, architecture, context_file_path=None, runs=3):
    """
    Prompts the Gemini model to act as a Datasheet Engineer, extracting precise
    hardware addresses to generate our chips.json definition for the Auto-Linker.
    Uses a TWO-STAGE prompting architecture to maximize model determinism inside massive PDFs.
    """
    system_prompt = (
        "You are an embedded systems engineer and compiler expert. "
        "Your task is to provide JSON-formatted technical data for bare-metal compilation "
        "(raw ROM boot without an RTOS). Output ONLY valid JSON, no markdown blocks or surrounding text. "
        "INSTRUCTION: Extract exact Hexadecimal constants. You may compute base+offset addresses if explicitly defined in the datasheet, but do not guess purely blindly. If a feature (like RDP) does not exist on this chip, return null."
    )

    # STAGE 1: Physical Memory & ABI
    prompt_stage1 = f"""
    I am building an extremely minimalist 'bare-metal' C application for the {chip_name} ({architecture} architecture).
    The program uses NO RTOS, NO HAL, and NO vendor SDKs. It is loaded directly by the 
    hardware ROM bootloader into internal RAM and executed there (or executed in-place from Flash).

    Please search the official Technical Reference Manuals (TRM) and Datasheets for the {chip_name} 
    and provide the precise raw hardware constants required for a bare-metal boot, formatted STRICTLY as JSON.
    
    Address the following core areas:
    1. Memory Map: Extract an array of ALL raw memory regions available on the chip (e.g. Instruction ROM, Data ROM, Cache blocks, Instruction RAM, Data RAM, RTC RAM) and their specific access permissions (rx, rw, rwx).
       CRITICAL: Do NOT guess. Use the exact origins and lengths defined in the TRM. 
       CRITICAL: If a physical SRAM block described in the TRM contains a hardware Cache or reserved memory (at its base or end address), you MUST mathematically split it! Create a separate region in `memory_regions` for the cache/reserved area (e.g. `{{"name": "hardware_reserved_cache", "permissions": "-"}}`), and calculate the remaining true origin and length for the application-safe regions. Do NOT simply omit the reserved bytes from the JSON; the visualizer depends on seeing the full physical footprint mapped.
    2. Region Roles: Which of the extracted regions is meant to be the primary `executable_segment` (Instruction RAM) for bare-metal code? Which is meant to be the primary `data_segment` (Data RAM) for variables?
    3. Memory Offsets: Does the chip's hardware ROM bootloader persistently reserve the bottom of the data RAM block (e.g., for stack or USB descriptors)? If the manufacturer's TRM implies the ROM will crash if its internal variables are overwritten during the ELF load phase, specify the exact physical reservation size in `bootrom_reserved_data_bytes`. Do the same for `vector_table_offset_bytes` if the vector table must perfectly align.
    4. Architecture Vectors: What is the exact architecture-specific section name required for aligning the interrupt vector table?
       Does the architecture forcibly reserve a chunk of space at the very start of the Instruction RAM for a Hardware Vector Table or Boot Header? If yes, define its exact size in logically derived bytes (e.g., the size of the required vector space) so the linker can cleanly shift the entry point. Otherwise, set it to 0.
    5. Alignment & Bin-Headers: What alignment (e.g., 16-byte) does the ROM bootloader require for DMA transfers?
    6. Startup Assembly: What is the optimal initial stack pointer address? Does it require specific ABI setup?
       CRITICAL: NEVER include flow-control instructions (like 'call', 'jump', 'b', 'bl', 'jal') in the `abi_initialization_instructions` array to prevent infinite bootloops! Our orchestrator natively links the main C root entry point automatically.
    7. Hardware Watchdogs: What are the exact Hex addresses for the Main and RTC Watchdog Unlock & Config registers? What constants disable them?
       CRITICAL: For the 'address' field, provide the EXACT memory-mapped register address for the Write Protection Unlock Key (e.g., WDTWPROTECT_REG). Do NOT provide the base address of the entire peripheral block. Writing the unlock key to a primary config/base address will corrupt the clock matrix and trigger an immediate SW_CPU_RESET!

    OUTPUT ONLY VALID JSON matching this exact structure (no markdown, no explanations):
    {{
        "{chip_name}": {{
            "arch": "{architecture}",
            "memory": {{
                "memory_regions": [
                    {{"name": "irom", "permissions": "rx", "origin": "0x...", "length": "..."}},
                    {{"name": "iram", "permissions": "rwx", "origin": "0x...", "length": "..."}},
                    {{"name": "dram", "permissions": "rw", "origin": "0x...", "length": "..."}}
                ],
                "executable_segment": "iram",
                "data_segment": "dram",
                "alignment_bytes": 16,
                "vector_alignment_section": "e.g., .isr_vector",
                "vector_table_offset_bytes": 0,
                "bootrom_reserved_data_bytes": 8192
            }},
            "startup": {{
                "stack_top_expression": "e.g., ORIGIN(dram) + LENGTH(dram)",
                "abi_initialization_instructions": ["instr 1", "instr 2"],
                "bss_init_required": true
            }},
            "watchdog_kill_registers": [
                {{"name": "TIMG0_WDT", "address": "0x...", "unlock_val": "0x...", "config_addr": "0x...", "disable_val": "0x0"}}
            ]
        }}
    }}
    """

    # STAGE 2: Security & Boot Profiles
    prompt_stage2 = f"""
    Continuing the bare-metal analysis for the {chip_name} ({architecture}), focus STRICTLY on the Security and Boot configurations.
    
    Address the following core areas:
    1. Flash Encryption / eFuses: What is the exact register address and bit mask that indicates if Flash Encryption is globally enabled or enforced?
    2. JTAG/Debug Locks: What is the register address and bit mask indicating JTAG/SWD is permanently disabled?
    3. Readout Protection (RDP): For chips like STM32, what is the Option Byte / FLASH_OPTR address that holds the RDP level? If not applicable to {architecture}, return null.
    4. Boot Vectors: What is the Base Address of the hardware ROM Bootloader vs the standard User Application Flash sector?

    OUTPUT ONLY VALID JSON matching this exact structure (no markdown):
    {{
        "{chip_name}": {{
            "security_registers": {{
                "flash_encryption": {{"register_addr": "0x...", "bit_mask": "0x...", "active_if_true": true}},
                "jtag_disabled": {{"register_addr": "0x...", "bit_mask": "0x...", "active_if_true": true}},
                "rdp_level": {{"register_addr": "0x... or null", "bit_mask": "0x... or null"}}
            }},
            "boot_vectors": {{
                "rom_base": "0x...",
                "user_app_base": "0x..."
            }}
        }}
    }}
    """

    # STAGE 3: Toolchain & Packaging Requirements
    prompt_stage3 = f"""
    Continuing the bare-metal analysis for the {chip_name} ({architecture}), focus STRICTLY on the tooling required to compile for, sign, and flash this specific microcontroller.
    
    Address the following core areas:
    1. Compiler Prefix: What is the exact standard GNU/LLVM compiler prefix used for this architecture's bare-metal C-development?
    2. Flashing Tool: What is the standard command-line tool used by the silicon vendor to flash binaries to this chip over physical UART or SWD interfaces? Provide the exact execution command. 
       CRITICAL: The deployment `flash_offset` MUST be the absolute hardware ROM Bootloader's expected entry point mapped to physical flash. NEVER dictate an application OTA offset for a raw bare-metal payload! Use {{binary_path}} as a placeholder for the compiled image.
    3. Payload Packaging (Sequential Array!): Does the vendor's boot infrastructure require the raw `.elf` binary to be format-converted, wrapped in a proprietary header, provisioned, or signed BEFORE it can be actively flashed or booted? 
       CRITICAL: If the architecture demands proprietary wrapping tools instead of just standard GNU objcopy, you MUST output this exact CLI command as a step with "condition": "ANY". This command MUST strictly guarantee the generation of exactly ONE single, unified output binary at {{binary_path}} (no scattered segments or address-based file suffixes).
       CRITICAL: If the architecture uses `esptool.py elf2image` (Espressif), you MUST provide explicit bare-metal SPI flash parameters (e.g. `--flash_mode dio --flash_freq 40m --flash_size 4MB`). Do not let it default to QIO mode, as many physical DevBoards leave QIO pins floating, causing fatal BootROM Checksum read-failures (Calculated 0xef stored 0xff).
       If Secure Boot algorithms dictate mandatory cryptographic wrapping (e.g., vendor signing algorithms or standard imgtool), add them sequentially with "condition": "PROFILE_SECURE_BOOT_ONLY". Provide the exact CLI scripts, binding variables precisely to {{binary_path}}, {{elf_path}}, and {{private_key_path}}.

    OUTPUT ONLY VALID JSON matching this exact structure (no markdown):
    {{
        "{chip_name}": {{
            "toolchain_requirements": {{
                "compiler_prefix": "...",
                "core_architecture": "{architecture}",
                "flashing": {{
                    "tool": "...",
                    "method": "...",
                    "flash_offset": "0x...",
                    "write_command": "..."
                }},
                "packaging": [
                    {{
                        "condition": "PROFILE_SECURE_BOOT_ONLY",
                        "tool": "...",
                        "command": "..."
                    }},
                    {{
                        "condition": "PROFILE_SECURE_BOOT_ONLY",
                        "tool": "...",
                        "command": "..."
                    }}
                ]
            }}
        }}
    }}
    """

    # STAGE 4: Toob-Boot Specific Hardware Physics
    prompt_stage4 = f"""
    Continuing the bare-metal analysis for the {chip_name} ({architecture}), focus STRICTLY on the physical controller constraints, survival mechanisms, and asynchronous SoC topologies required for building an atomic A/B Bootloader.

    Address the following core areas:
    1. Flash Constraints: Does the flash controller mandate specific physical write boundaries (e.g., 32-byte Double-Words vs 4-byte boundaries)? Are there proprietary BootROM restrictions stating executable caching must be strictly aligned to large hardware sectors? Can the internal flash erase Bank B while actively executing code from Bank A (Read-While-Write capability)?
    2. Reset Reason Extraction: What is the EXACT register address and specific hexadecimal Bit-Masks to detect if the MCU woke up due to a Power-On Reset (POR), a Hardware Watchdog Timer (WDT) Exception, or a Software Request? This is critical for rolling back from fatal firmware loops.
    3. Hardware Identity & Crypto: Do any of the silicon's hardware modules natively accelerate AES, SHA256, or Ed25519 cryptography? Does the factory burn a unique identity (UID, MAC) into the permanent hardware fuses or Option Bytes, and if so, at what precise address?
    4. Reboot Survival: Toob-Boot needs to pass a 'Boot Confirm' flag across a reboot. What is the most reliable hardware register/RAM block (RTC SRAM, 32-bit Backup Registers, Retained RAM) that survives a standard Watchdog Reset without requiring a dedicated external battery pin? The `recommended_storage_type` must be strictly one of these Enums: "rtc_ram", "backup_register", "retained_ram", "flash", or "none".
    5. Multi-Core (Asymmetrical) Layout: If this chip hosts a separate silicon Coprocessor, does it possess an independent flash base address and divergent cache alignment bounds? What is the physical IPC bridge mechanism? The `ipc_mechanism` must be strictly one of these Enums: "shared_ram", "mailbox", or "none".

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
                "recommended_storage_type": "rtc_ram",
                "needs_vbat_pin": false
            }},
            "factory_identity": {{
                "has_mac_address": true,
                "uid_address": "0x1FFF7590"
            }},
            "multi_core_topology": {{
                "is_multi_core": false,
                "ipc_mechanism": "shared_ram",
                "coprocessors": [
                    {{"name": "net_core", "flash_base": "0x01000000", "app_alignment_bytes": 2048}}
                ]
            }}
        }}
    }}
    """

    # STAGE 5: Declarative Flash HAL Generation
    prompt_stage5 = f"""
    Continuing the bare-metal analysis for the {chip_name} ({architecture}), your final task is to extract the EXACT procedural register sequence required to unlock, erase, and write the internal Flash memory, outputting it as a declarative instruction array.

    Address the following core areas:
    1. Flash Controller Base Address: What is the main memory-mapped peripheral base address for the hardware Flash Controller?
    2. Unlock Sequence: Which specific register offsets require magic keys to be written before erasing or programming is permitted?
    3. Sector Erase Sequence: What is the exact sequence of register writes/bit-sets/bit-clears to execute a single physical sector erase? Include the logically required `poll_bit_clear` steps to wait for busy flags. If the hardware STRICTLY dictates the use of BootROM APIs (like ESP32), you may use the "rom_function_call" type, BUT you must provide the exact numeric 32-bit BootROM memory address for the function pointer.

    Define the sequence items strictly using one of these Enums for the `type` field:
    - `"poll_bit_clear"`: A `while (REG & bit_mask)` blocking loop. Provide `offset` (hex string) and `bit_mask` (hex string).
    - `"set_bit"`: A `REG |= bit_mask` operation. Provide `offset` and `bit_mask`.
    - `"clear_bit"`: A `REG &= ~bit_mask` operation. Provide `offset` and `bit_mask`.
    - `"write_addr"`: A `REG = value` operation. Provide `offset`. Provide `value_hex` if writing a constant magic number, OR `value_source` if the value is a dynamic runtime variable (strictly enum: `"sector_addr"` or `"data_word"`).
    - `"rom_function_call"`: Invoke a hardware ROM pointer directly. You MUST provide `function_name` (for logging), `args_csv` (like `"sector_addr / 4096"`), AND crucially `rom_address` (exact hex memory address, e.g., `"0x40062CCC"`). If the ROM strictly requires an absolute 0-indexed physical offset instead of the CPU memory-mapped address (like ESP32), set `"requires_physical_offset": true`. DO NOT omit `rom_address`, as our linker cannot resolve names.

    CRITICAL RULE FOR ESP32 AND OTHERS: If the TRM does not document exact physical SPI Flash registers and instead forces you to use built-in BootROM APIs (like `esp_rom_spiflash_erase_sector`), YOU MUST NOT RETURN AN EMPTY ARRAY. You MUST output a `rom_function_call` sequence. If you absolutely cannot find the exact numeric `rom_address` in the document, you MUST provide "UNKNOWN_ADDRESS" as the `rom_address`. DO NOT abort or return empty sequences. You must attempt to map the sequence and include read/write/erase arrays containing the ROM calls. Use the `analytical_notes` field to explain what context is missing for a human engineer to improve the prompt.

    OUTPUT ONLY VALID JSON matching this exact structure (no markdown):
    {{
        "{chip_name}": {{
            "flash_controller": {{
                "analytical_notes": "...",
                "base_address": "0x...",
                "unlock_sequence": [
                    {{"type": "write_addr", "offset": "0x...", "value_hex": "0x...", "desc": "Write Key 1"}}
                ],
                "erase_sector_sequence": [
                    {{"type": "poll_bit_clear", "offset": "0x...", "bit_mask": "0x...", "desc": "Wait BSY"}},
                    {{"type": "set_bit", "offset": "0x...", "bit_mask": "0x...", "desc": "Set SER"}},
                    {{"type": "write_addr", "offset": "0x...", "value_source": "sector_addr", "desc": "Write Addr"}},
                    {{"type": "set_bit", "offset": "0x...", "bit_mask": "0x...", "desc": "Start"}},
                    {{"type": "rom_function_call", "function_name": "SPIEraseSector", "rom_address": "0x40062CCC", "args_csv": "...", "requires_physical_offset": true, "desc": "Or ROM Call Instead"}}
                ],
                "write_word_sequence": []
            }}
        }}
    }}
    """

    # Document Understanding: Handle File Upload with Caching Strategy
    gemini_file = None
    if context_file_path and os.path.exists(context_file_path):
        import hashlib

        def get_file_md5(filepath):
            hasher = hashlib.md5()
            with open(filepath, "rb") as f:
                buf = f.read(8192)
                while buf:
                    hasher.update(buf)
                    buf = f.read(8192)
            return hasher.hexdigest()

        os.makedirs("ai_history", exist_ok=True)
        cache_path = os.path.join("ai_history", "remote_file_cache.json")
        file_cache = {}

        if os.path.exists(cache_path):
            with open(cache_path, "r") as f:
                try:
                    file_cache = json.load(f)
                except:
                    pass

        file_hash = get_file_md5(context_file_path)

        if file_hash in file_cache:
            cached_name = file_cache[file_hash]
            print(f"[*] Found cached remote file lookup: {cached_name}. Verifying...")
            try:
                gemini_file = gemini_client.files.get(name=cached_name)
                print(f"[*] Verification complete. Reusing attached Gemini File.")
            except Exception as e:
                print(
                    f"[*] Cached remote file expired (48h limit) or deleted. Re-upload required."
                )
                gemini_file = None

        if not gemini_file:
            print(f"[*] Uploading large document to Gemini: {context_file_path}...")
            try:
                gemini_file = gemini_client.files.upload(file=context_file_path)
                print(f"[*] Upload complete: {gemini_file.name}. Tracking in cache.")
                file_cache[file_hash] = gemini_file.name
                with open(cache_path, "w") as f:
                    json.dump(file_cache, f, indent=4)
            except Exception as e:
                print(f"[!] File upload failed: {e}")
                gemini_file = None

    import concurrent.futures
    import threading

    print_lock = threading.Lock()

    def safe_print(msg):
        with print_lock:
            print(msg)

    def execute_prompt(prompt_text, stage_name, run_num, runs=3):
        contents = [prompt_text]
        if gemini_file:
            contents.append(gemini_file)

        print(
            f"[*] Initiating model inference ({stage_name}) with {runs}x Self-Consistency Voting (Parallel)..."
        )

        results = []

        def single_request(run_id, retries=3):
            import time
            for attempt in range(retries):
                safe_print(f"    -> {stage_name} [Run {run_id}/{runs}] Request fired (Attempt {attempt+1}/{retries})...")
                try:
                    response = gemini_client.models.generate_content(
                        model="gemini-3.1-pro-preview",
                        contents=contents,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            response_mime_type="application/json",
                            temperature=0.0,
                        ),
                    )
                    return json.loads(response.text)
                except Exception as e:
                    safe_print(f"    [!] {stage_name} [Run {run_id}] Error (Attempt {attempt+1}): {e}")
                    if attempt < retries - 1:
                        time.sleep(3 ** attempt)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=runs) as executor:
            futures = [executor.submit(single_request, i + 1) for i in range(runs)]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)

        if not results:
            print(f"[!] All {runs} runs failed for {stage_name}.")
            return None, None

        # Field-by-Field Majority Voting Algorithm
        def field_majority_vote(values):
            import collections

            if not values:
                return None, None
            # If diving into a dictionary
            if all(isinstance(v, dict) for v in values if v is not None):
                res = {}
                conf = {}
                all_keys = set()
                for d in values:
                    if d:
                        all_keys.update(d.keys())
                for k in all_keys:
                    k_vals = [d.get(k) for d in values if d is not None and k in d]
                    r_val, c_val = field_majority_vote(k_vals)
                    res[k] = r_val
                    conf[k] = c_val
                return res, conf

            # For lists or scalars, vote on the exact string representation
            valid_vals = [v for v in values]
            if not valid_vals:
                return None, None
            str_vals = [json.dumps(v, sort_keys=True) for v in valid_vals]
            counter = collections.Counter(str_vals)
            most_common_str, count = counter.most_common(1)[0]
            val = json.loads(most_common_str)
            return val, f"{count}/{len(values)}"

        stage_data, stage_conf = field_majority_vote(results)

        # Save raw results for the user's historical QA database
        safe_stage = stage_name.replace(":", "").replace(" ", "_").lower()
        hist_dir = os.path.join("ai_history", chip_name)
        run_dir = os.path.join(hist_dir, f"run_{run_num}")
        os.makedirs(run_dir, exist_ok=True)

        hist_path = os.path.join(run_dir, f"{safe_stage}.json")
        with open(hist_path, "w") as f:
            json.dump(results, f, indent=4, sort_keys=True)

        safe_print(f"    [->] {stage_name} Raw {runs}x Runs saved to {hist_path}")
        return stage_data, stage_conf

    print(
        f"\n[*] Launching all 5 Stages concurrently (Total {5 * runs} API Threads)..."
    )

    # Determine the run folder synchronously before launching threads
    hist_dir = os.path.join("ai_history", chip_name)
    os.makedirs(hist_dir, exist_ok=True)
    shared_run_num = 1
    while os.path.exists(os.path.join(hist_dir, f"run_{shared_run_num}")):
        shared_run_num += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as stage_executor:
        f1 = stage_executor.submit(
            execute_prompt,
            prompt_stage1,
            "Stage 1: Memory & ABI",
            shared_run_num,
            runs,
        )
        f2 = stage_executor.submit(
            execute_prompt,
            prompt_stage2,
            "Stage 2: Security Rings",
            shared_run_num,
            runs,
        )
        f3 = stage_executor.submit(
            execute_prompt,
            prompt_stage3,
            "Stage 3: Toolchain & Packaging",
            shared_run_num,
            runs,
        )
        f4 = stage_executor.submit(
            execute_prompt,
            prompt_stage4,
            "Stage 4: Topology & Boot Physics",
            shared_run_num,
            runs,
        )
        f5 = stage_executor.submit(
            execute_prompt,
            prompt_stage5,
            "Stage 5: Declarative Flash Sequences",
            shared_run_num,
            runs,
        )

        stage1_data, stage1_conf = f1.result()
        stage2_data, stage2_conf = f2.result()
        stage3_data, stage3_conf = f3.result()
        stage4_data, stage4_conf = f4.result()
        stage5_data, stage5_conf = f5.result()

    if (
        not stage1_data
        or not stage2_data
        or not stage3_data
        or not stage4_data
        or not stage5_data
    ):
        raise RuntimeError("One or more pipeline stages failed comprehensively.")

    try:
        # Merge safely to prevent LLM hallucinations from clobbering other stages
        chip_root = stage1_data.get(chip_name, {})
        chip_conf = stage1_conf.get(chip_name, {})

        if chip_name in stage2_data:
            s2 = stage2_data[chip_name]
            for key in ["security_registers", "boot_vectors"]:
                if key in s2:
                    chip_root[key] = s2[key]

            s2_c = stage2_conf[chip_name]
            for key in ["security_registers", "boot_vectors"]:
                if key in s2_c:
                    chip_conf[key] = s2_c[key]

        if chip_name in stage3_data:
            s3 = stage3_data[chip_name]
            if "toolchain_requirements" in s3:
                chip_root["toolchain_requirements"] = s3["toolchain_requirements"]

            s3_c = stage3_conf[chip_name]
            if "toolchain_requirements" in s3_c:
                chip_conf["toolchain_requirements"] = s3_c["toolchain_requirements"]

        if chip_name in stage4_data:
            s4 = stage4_data[chip_name]
            stage4_keys = [
                "flash_capabilities",
                "reset_reason",
                "crypto_capabilities",
                "survival_mechanisms",
                "factory_identity",
                "multi_core_topology",
            ]
            for key in stage4_keys:
                if key in s4:
                    chip_root[key] = s4[key]

            s4_c = stage4_conf[chip_name]
            for key in stage4_keys:
                if key in s4_c:
                    chip_conf[key] = s4_c[key]

        if chip_name in stage5_data:
            s5 = stage5_data[chip_name]
            if "flash_controller" in s5:
                chip_root["flash_controller"] = s5["flash_controller"]

            s5_c = stage5_conf[chip_name]
            if "flash_controller" in s5_c:
                chip_conf["flash_controller"] = s5_c["flash_controller"]

        # ENFORCE SCHEMA VALIDITY BEFORE PASSING IT TO THE COMPILER
        validate_blueprint_integrity(chip_root, chip_name)

        return stage1_data, stage1_conf
    except Exception as e:
        raise RuntimeError(f"Error during JSON merge: {e}")


def main():
    parser = argparse.ArgumentParser(description="Toobloader: AI Datasheet Parser")
    parser.add_argument("chip", help="Target chip name (e.g., esp32c6, esp32)")
    parser.add_argument(
        "arch",
        help="Target architecture (e.g., RISC-V, Xtensa Dual-Core, ARM Cortex-M4)",
    )
    parser.add_argument(
        "--context-file", help="Path to a text file containing raw datasheet snippets"
    )
    parser.add_argument("--out", default="chips.json", help="Output JSON file")
    parser.add_argument(
        "--runs", type=int, default=3, help="Number of self-consistency runs per stage"
    )

    args = parser.parse_args()

    configure_gemini(GENAI_API_KEY)

    context_path = None
    if args.context_file and os.path.exists(args.context_file):
        context_path = args.context_file

    print(
        f"[*] Querying Gemini for {args.chip} ({args.arch}) specifications [Runs: {args.runs}]..."
    )
    spec, conf = generate_chip_definition(
        args.chip, args.arch, context_path, runs=args.runs
    )

    # Merge with existing if present
    existing_data = {}
    existing_conf = {}
    if os.path.exists(args.out):
        with open(args.out, "r") as f:
            try:
                existing_data = json.load(f)
            except:
                pass

    conf_file = args.out.replace(".json", "_confidence.json")
    if os.path.exists(conf_file):
        with open(conf_file, "r") as f:
            try:
                existing_conf = json.load(f)
            except:
                pass

    existing_data.update(spec)
    existing_conf.update(conf)

    # ALWAYS use sort_keys=True for hyper-deterministic file formats
    with open(args.out, "w") as f:
        json.dump(existing_data, f, indent=4, sort_keys=True)

    with open(conf_file, "w") as f:
        json.dump(existing_conf, f, indent=4, sort_keys=True)

    print(f"[*] Successfully wrote specifications to {args.out}")
    print(f"[*] Successfully wrote voting tracking to {conf_file}")


if __name__ == "__main__":
    main()
