import json
import os


def _parse_size(val):
    if isinstance(val, int):
        return val
    val = str(val).lower().strip()
    if val.endswith("k"):
        return int(val[:-1], 0) * 1024
    if val.endswith("m"):
        return int(val[:-1], 0) * 1024 * 1024
    return int(val, 0)


def generate_linker_script(spec, chip_name, out_dir):
    os.makedirs(out_dir, exist_ok=True)

    memory_cfg = spec["memory"]
    regions = memory_cfg.get("memory_regions", [])
    exec_seg = memory_cfg.get("executable_segment", "iram")
    data_seg = memory_cfg.get("data_segment", "dram")
    align_bytes = memory_cfg.get("alignment_bytes", 16)
    vec_sec = memory_cfg.get("vector_alignment_section", ".text.entry")

    ld_path = os.path.join(out_dir, f"{chip_name}.ld")

    arch_lower = spec["arch"].lower()
    is_riscv = "risc-v" in arch_lower or "riscv" in arch_lower

    vec_offset = memory_cfg.get("vector_table_offset_bytes", 0)
    boot_offset = memory_cfg.get("bootrom_reserved_data_bytes", 0)

    # RISC-V specific linker additions
    data_section_extras = ""
    if is_riscv:
        data_section_extras = "\n        __global_pointer$ = . + 0x800; /* RISC-V GP */"

    # Some basic heuristics to handle memory
    exec_seg = memory_cfg.get("executable_segment", "iram")
    data_seg = memory_cfg.get("data_segment", "dram")
    align_bytes = memory_cfg.get("alignment_bytes", 16)
    vec_sec = memory_cfg.get("vector_alignment_section", ".vectors")

    # Apply offsets explicitly to the executable and data segments
    for reg in regions:
        if reg.get("name") == exec_seg and vec_offset > 0:
            origin_int = _parse_size(reg.get("origin", "0x0"))
            length_int = _parse_size(reg.get("length", "0x0"))

            # The executable space shrinks and shifts down
            reg["origin"] = f"0x{(origin_int + vec_offset):08X}"
            reg["length"] = f"0x{(length_int - vec_offset):X}"

        elif reg.get("name") == data_seg and boot_offset > 0:
            origin_int = _parse_size(reg.get("origin", "0x0"))
            length_int = _parse_size(reg.get("length", "0x0"))

            # The data space shrinks and shifts down (protecting BootROM stack)
            reg["origin"] = f"0x{(origin_int + boot_offset):08X}"
            reg["length"] = f"0x{(length_int - boot_offset):X}"

    # Construct the full MEMORY block
    memory_lines = []
    for reg in regions:
        # Expected e.g. {"name": "iram", "permissions": "rwx", "origin": "0x...", "length": "..."}
        name = reg.get("name", "unknown")
        perms = reg.get("permissions", "rwx")
        origin = reg.get("origin", "0x0")
        length = reg.get("length", "0x0")
        memory_lines.append(
            f"    {name} ({perms}) : ORIGIN = {origin}, LENGTH = {length}"
        )

    memory_block = "\n".join(memory_lines)

    ld_content = f"""/* Auto-Generated Bare-Metal Linker Script for {chip_name} ({spec['arch']}) */
ENTRY(_start)

MEMORY
{{
{memory_block}
}}

SECTIONS
{{
    .text : ALIGN({align_bytes})
    {{
        _text_start = .;
        *({vec_sec}) /* Architecture-specific Vector/Entry Alignment */
        *(.literal.entry)
        *(.text.entry) /* Startup assembly goes here */
        *(.literal .literal.*)
        *(.text .text.*)
        _text_end = .;
    }} > {exec_seg}

    .data : ALIGN({align_bytes})
    {{
        _data_start = .;{data_section_extras}
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r.*)
        _data_end = .;
    }} > {data_seg}

    .bss (NOLOAD) : ALIGN({align_bytes})
    {{
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    }} > {data_seg}

    /* Stack calculation dynamically anchored to data segment end */
    _stack_top = ORIGIN({data_seg}) + LENGTH({data_seg});
}}
"""
    with open(ld_path, "w") as f:
        f.write(ld_content)

    print(f"[*] Generated Linker Script: {ld_path}")
    return ld_path


def generate_startup_assembly(spec, chip_name, out_dir):
    s_path = os.path.join(out_dir, f"{chip_name}_startup.S")

    arch = spec["arch"].lower()
    asm_lines = []

    # --- RISC-V ASSEMBLY GENERATOR ---
    if "risc-v" in arch or "riscv" in arch:
        asm_lines.append(".section .text.entry")
        asm_lines.append(f".global _start")
        asm_lines.append("_start:")

        # Insert AI provided ABI init (like GP setup)
        for inst in spec["startup"].get("abi_initialization_instructions", []):
            asm_lines.append(f"    {inst}")

        asm_lines.append("    /* Stack setup from Linker */")
        asm_lines.append("    la sp, _stack_top")

        asm_lines.append("\n    /* Watchdog Sterilization (AI Extracted) */")
        for wd in spec.get("watchdog_kill_registers", []):
            asm_lines.append(f"    /* Disable {wd['name']} */")
            if wd.get("unlock_val") and wd["unlock_val"] != "0x0":
                asm_lines.append(f"    li a0, {wd['unlock_val']}")
                asm_lines.append(f"    li a1, {wd['address']}")
                asm_lines.append(f"    sw a0, 0(a1)")

            if wd.get("config_addr"):
                asm_lines.append(f"    li a0, {wd['disable_val']}")
                asm_lines.append(f"    li a1, {wd['config_addr']}")
                asm_lines.append(f"    sw a0, 0(a1)")

        if spec["startup"].get("bss_init_required", False):
            asm_lines.append("\n    /* Zero BSS */")
            asm_lines.append("    la t0, _bss_start")
            asm_lines.append("    la t1, _bss_end")
            asm_lines.append("1:")
            asm_lines.append("    bgeu t0, t1, 2f")
            asm_lines.append("    sw zero, 0(t0)")
            asm_lines.append("    addi t0, t0, 4")
            asm_lines.append("    j 1b")
            asm_lines.append("2:")

        asm_lines.append("\n    /* Jump to C payload */")
        asm_lines.append("    call main")
        asm_lines.append("3:  j 3b /* Infinite loop on exit */")

    # --- ARM CORTEX-M ASSEMBLY GENERATOR ---
    elif "arm" in arch or "cortex" in arch:
        asm_lines.append(".syntax unified")
        asm_lines.append(
            ".cpu cortex-m4"
        )  # Will be overridden by GCC flags, just structural
        asm_lines.append(".thumb")
        asm_lines.append("")
        asm_lines.append(".section .text.entry")
        asm_lines.append(".global _start")
        asm_lines.append("_start:")

        for inst in spec["startup"].get("abi_initialization_instructions", []):
            asm_lines.append(f"    {inst}")

        asm_lines.append("    ldr sp, =_stack_top")

        asm_lines.append("\n    /* Watchdog Sterilization (AI Extracted) */")
        for wd in spec.get("watchdog_kill_registers", []):
            asm_lines.append(f"    /* Disable {wd['name']} */")
            if wd.get("unlock_val") and wd["unlock_val"] != "0x0":
                asm_lines.append(f"    ldr r0, ={wd['unlock_val']}")
                asm_lines.append(f"    ldr r1, ={wd['address']}")
                asm_lines.append(f"    str r0, [r1]")

            if wd.get("config_addr"):
                asm_lines.append(f"    ldr r0, ={wd['disable_val']}")
                asm_lines.append(f"    ldr r1, ={wd['config_addr']}")
                asm_lines.append(f"    str r0, [r1]")

        if spec["startup"].get("bss_init_required", False):
            asm_lines.append("\n    /* Zero BSS */")
            asm_lines.append("    ldr r0, =_bss_start")
            asm_lines.append("    ldr r1, =_bss_end")
            asm_lines.append("    movs r2, #0")
            asm_lines.append(".L_zero_bss_loop:")
            asm_lines.append("    cmp r0, r1")
            asm_lines.append("    bge .L_zero_bss_done")
            asm_lines.append("    str r2, [r0]")
            asm_lines.append("    adds r0, r0, #4")
            asm_lines.append("    b .L_zero_bss_loop")
            asm_lines.append(".L_zero_bss_done:")

        asm_lines.append("\n    bl main")
        asm_lines.append(".L_end: b .L_end")

    # --- XTENSA (ESP32 Classic) ASSEMBLY GENERATOR ---
    elif "xtensa" in arch:
        asm_lines.append('.section .text.entry, "ax"')
        asm_lines.append(".global _start")
        asm_lines.append("_start:")

        for inst in spec["startup"].get("abi_initialization_instructions", []):
            asm_lines.append(f"    {inst}")

        asm_lines.append("    movi a1, _stack_top")

        asm_lines.append("\n    /* Watchdog Sterilization (AI Extracted) */")
        for wd in spec.get("watchdog_kill_registers", []):
            asm_lines.append(f"    /* Disable {wd['name']} */")
            if wd.get("unlock_val") and wd["unlock_val"] != "0x0":
                asm_lines.append(f"    movi a2, {wd['unlock_val']}")
                asm_lines.append(f"    movi a3, {wd['address']}")
                asm_lines.append(f"    s32i a2, a3, 0")

            if wd.get("config_addr"):
                asm_lines.append(f"    movi a2, {wd['disable_val']}")
                asm_lines.append(f"    movi a3, {wd['config_addr']}")
                asm_lines.append(f"    s32i a2, a3, 0")

        if spec["startup"].get("bss_init_required", False):
            asm_lines.append("\n    /* Zero BSS */")
            asm_lines.append("    movi a2, _bss_start")
            asm_lines.append("    movi a3, _bss_end")
            asm_lines.append("    movi a4, 0")
            asm_lines.append(".L_clear_bss:")
            asm_lines.append("    bgeu a2, a3, .L_bss_done")
            asm_lines.append("    s32i a4, a2, 0")
            asm_lines.append("    addi a2, a2, 4")
            asm_lines.append("    j .L_clear_bss")
            asm_lines.append(".L_bss_done:")

        asm_lines.append("\n    call4 main")
        asm_lines.append("3:  j 3b /* Infinite loop */")

    else:
        asm_lines.append(
            f"/* Architecture '{arch}' not yet implemented in startup generator */"
        )

    s_content = "\n".join(asm_lines)

    with open(s_path, "w") as f:
        f.write(s_content)

    print(f"[*] Generated Startup Assembly: {s_path}")
    return s_path


def generate_toolchain_files(chip_name, chips_json_path, out_dir):
    with open(chips_json_path, "r") as f:
        db = json.load(f)

    if chip_name not in db:
        raise ValueError(f"Chip {chip_name} not found in {chips_json_path}")

    spec = db[chip_name]
    ld_path = generate_linker_script(spec, chip_name, out_dir)
    s_path = generate_startup_assembly(spec, chip_name, out_dir)

    return ld_path, s_path
