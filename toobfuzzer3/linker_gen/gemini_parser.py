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
       CRITICAL: If the hardware ROM bootloader actively reserves space at the bottom of the Data RAM for its own stack or variables during the boot process (e.g., Boot ROM data), output that exact reserved byte size as `bootrom_reserved_data_bytes`. If no space is reserved, output 0. Do NOT manually shrink the region lengths array for this, just provide the offset.
    3. Architecture Vectors: What is the exact architecture-specific section name required for aligning the interrupt vector table?
       Does the architecture forcibly reserve a chunk of space at the very start of the Instruction RAM for a Hardware Vector Table or Boot Header? If yes, define its exact size in logically derived bytes (e.g., the size of the required vector space) so the linker can cleanly shift the entry point. Otherwise, set it to 0.
    4. Alignment & Bin-Headers: What alignment (e.g., 16-byte) does the ROM bootloader require for DMA transfers?
    5. Startup Assembly: What is the optimal initial stack pointer address? Does it require specific ABI setup?
    6. Hardware Watchdogs: What are the exact Hex addresses for the Main and RTC Watchdog Unlock & Config registers? What constants disable them?
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
    1. Compiler Prefix: What is the standard GCC prefix used for this architecture (e.g., 'riscv32-esp-elf-', 'arm-none-eabi-', 'xtensa-esp32-elf-')?
    2. Flashing Tool: What is the standard command-line tool used by the vendor to flash binaries to this chip over serial or SWD? Include its exact write command. 
       CRITICAL: The deployment `flash_offset` MUST be the hardware ROM Bootloader's expected entry point for the compiled firmware. (e.g., 0x1000 or 0x0 for ESP32 bootloaders, 0x08000000 for STM32). NEVER dictate an application OTA offset like 0x10000 for a bare-metal payload! Use {{binary_path}} as a placeholder for the file.
    3. Payload Packaging (Sequential Array!): Does the vendor require the raw `.elf` binary to be converted, wrapped in a specific header, provisioned, or signed BEFORE it can be flashed/booted? 
       CRITICAL: If the physical ROM bootloader requires a proprietary image header (e.g., ESP32 needs 'esptool.py elf2image --flash_mode dio --flash_freq 40m --flash_size 2MB -o {{binary_path}} {{elf_path}}'), you MUST output this as a step with "condition": "ANY". Do NOT assume just objcopy is sufficient if the vendor mandates a specific header.
       If Secure Boot requires additional steps (e.g., 'espsecure.py sign_data' or MCUboot's 'imgtool sign'), add them sequentially with "condition": "PROFILE_SECURE_BOOT_ONLY". Provide the exact CLI commands replacing variables with {{binary_path}}, {{elf_path}}, and {{private_key_path}}.

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

        def single_request(run_id):
            safe_print(f"    -> {stage_name} [Run {run_id}/{runs}] Request fired...")
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
                safe_print(
                    f"    [!] {stage_name} [Run {run_id}] Failed or malformed JSON: {e}"
                )
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
        f"\n[*] Launching all 3 Stages concurrently (Total {3 * runs} API Threads)..."
    )

    # Determine the run folder synchronously before launching threads
    hist_dir = os.path.join("ai_history", chip_name)
    os.makedirs(hist_dir, exist_ok=True)
    shared_run_num = 1
    while os.path.exists(os.path.join(hist_dir, f"run_{shared_run_num}")):
        shared_run_num += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as stage_executor:
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

        stage1_data, stage1_conf = f1.result()
        stage2_data, stage2_conf = f2.result()
        stage3_data, stage3_conf = f3.result()

    if not stage1_data or not stage2_data or not stage3_data:
        raise RuntimeError("One or more pipeline stages failed comprehensively.")

    try:
        # Merge Stage 1, Stage 2, and Stage 3 into a unified blueprint
        if chip_name in stage2_data:
            stage1_data[chip_name].update(stage2_data[chip_name])
            stage1_conf[chip_name].update(stage2_conf[chip_name])

        if chip_name in stage3_data:
            stage1_data[chip_name].update(stage3_data[chip_name])
            stage1_conf[chip_name].update(stage3_conf[chip_name])

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
