import os
import sys
import json
import subprocess
import glob
from tool_locator import ToolLocator


class ToobfuzzerBuilder:
    """
    The Universal Toolchain Runner (Phase 6).
    100% Data-Driven: It knows nothing about ESP, STM, or nRF.
    It purely executes the commands defined in chips.json, locating tools dynamically.
    """

    def __init__(
        self,
        chip_name,
        blueprint_path,
        profile="BARE_METAL_OPEN",
        private_key_path=None,
        debug_mode=False,
    ):
        self.chip_name = chip_name
        self.blueprint_path = blueprint_path
        self.profile = profile
        self.private_key_path = private_key_path
        self.debug_mode = debug_mode
        self.blueprint = self._load_blueprint()
        self.toolchain_reqs = self.blueprint.get("toolchain_requirements", {})

    def _load_blueprint(self):
        if not os.path.exists(self.blueprint_path):
            raise FileNotFoundError(f"Missing AI Blueprint: {self.blueprint_path}")
        with open(self.blueprint_path, "r") as f:
            data = json.load(f)
            # The structure from gemini_parser is { "chip_name": { ... } }
            return data.get(self.chip_name, {})

    def _execute_command(self, tool_name, command_template, env=None, cwd=None):
        """Locates the tool and executes the template string."""
        print(f"[*] Preparing execution for: {tool_name}")
        
        # Enforce CWD to the toobfuzzer3 root so relative paths (core/*.c) hit the fuzzer, not the bootloader
        if cwd is None:
            cwd = os.path.dirname(os.path.dirname(__file__))


        # 1. Locate the actual binary path
        tool_path = ToolLocator.find_tool(tool_name)

        # 2. Format the template variables
        # We define a standard set of variables the LLM can use in its command strings
        formatting_vars = {
            "binary_path": f"build/{self.chip_name}/run_latest/toobfuzzer.bin",
            "elf_path": f"build/{self.chip_name}/run_latest/toobfuzzer.bin.elf",
            "private_key_path": self.private_key_path or "dummy_key.pem",
            "build_dir": f"build/{self.chip_name}/run_latest",
            "profile": self.profile,
        }

        # Ensure build dir exists
        os.makedirs(formatting_vars["build_dir"], exist_ok=True)

        # Format the command
        try:
            formatted_args = command_template.format(**formatting_vars)
        except KeyError as e:
            raise KeyError(f"The chips.json requested an unknown format variable: {e}")

        # Universally strip redundant tool names from the beginning of the command string
        # to prevent `"esptool.exe" esptool.py --chip` doubling.
        cmd_parts = formatted_args.split()
        if cmd_parts:
            # Drop the extension (if any) and normalize
            first_tok_base = os.path.splitext(os.path.basename(cmd_parts[0]))[0].lower()
            tool_base = os.path.splitext(os.path.basename(tool_name))[0].lower()
            if first_tok_base == tool_base:
                formatted_args = " ".join(cmd_parts[1:])

        full_command = f'"{tool_path}" {formatted_args}'
        print(f"    [>] Executing: {full_command}")

        # 3. Execute
        try:
            result = subprocess.run(
                full_command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=cwd,
            )
            print("    [+] Success.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"    [!] Execution Failed (Exit {e.returncode})")
            print(f"    [!] STDERR: {e.stderr.strip()}")
            return False

    def stage_1_compile(self):
        """Compiles the raw firmware using the LLM-defined compiler prefix."""
        prefix = self.toolchain_reqs.get("compiler_prefix", "arm-none-eabi-")
        gcc_tool = f"{prefix}gcc"

        # A generalized GCC command building core/ and arch/
        # In a real scenario, this command string would also be driven by chips.json,
        # but for safety/stability we keep the C-core compilation semi-fixed here.
        fz_root = os.path.dirname(os.path.dirname(__file__))
        c_files = " ".join(glob.glob(os.path.join(fz_root, "core/*.c")))
        s_files = " ".join(glob.glob(os.path.join(fz_root, "arch/*.S")))
        hal_files = " ".join(glob.glob(os.path.join(fz_root, "hal/*.c")))
        mock_files = " ".join(glob.glob(os.path.join(fz_root, "mocks/*.c")))


        # Include dynamically generated C and Assembly files from the AI pipeline
        generated_c = (
            f"build/{self.chip_name}/run_latest/capabilities_{self.chip_name}.c"
        )
        generated_s = f"build/{self.chip_name}/run_latest/{self.chip_name}_startup.S"
        keelhaul_c = f"build/{self.chip_name}/run_latest/keelhaul_svd.c"
        hal_flash_c = f"build/{self.chip_name}/run_latest/hal_flash_{self.chip_name}.c"
        keelhaul_inc = f"build/{self.chip_name}/run_latest/"

        # Hyphen-resilient fallback: If the user named the SVD esp32c6 but the run esp32-c6 (or vice versa)
        if not os.path.exists(os.path.join(fz_root, keelhaul_c)):
            alt_chip = self.chip_name.replace("-", "")
            alt_keelhaul_c = f"build/{alt_chip}/run_latest/keelhaul_svd.c"
            if os.path.exists(os.path.join(fz_root, alt_keelhaul_c)):
                keelhaul_c = alt_keelhaul_c
                keelhaul_inc = f"build/{alt_chip}/run_latest/"

        all_src_files = f"{c_files} {s_files} {hal_files} {mock_files}"
        if os.path.exists(os.path.join(fz_root, generated_c)):
            all_src_files += f" {os.path.join(fz_root, generated_c)}"
        if os.path.exists(os.path.join(fz_root, generated_s)):
            all_src_files += f" {os.path.join(fz_root, generated_s)}"
        if os.path.exists(os.path.join(fz_root, keelhaul_c)):
            all_src_files += f" {os.path.join(fz_root, keelhaul_c)}"

        has_true_hal = False
        if os.path.exists(os.path.join(fz_root, hal_flash_c)):
            all_src_files += f" {os.path.join(fz_root, hal_flash_c)}"
            has_true_hal = True

        all_src_files = all_src_files.strip()

        # Architecture-aware compilation flags
        # Xtensa chips need -mlongcalls, RISC-V chips (esp32-c*, esp32-h*) do not.
        is_riscv = self.chip_name.startswith("esp32-c") or self.chip_name.startswith(
            "esp32-h"
        )
        arch_flags = "" if is_riscv else "-mlongcalls "
        if has_true_hal:
            arch_flags += "-DHAS_TRUE_SPI_HAL=1 "

        if self.debug_mode:
            arch_flags += "-DFZ_DEBUG_MODE=1 "

        compile_cmd = (
            f"-O2 -nostdlib -ffreestanding {arch_flags}"
            f"-T build/{self.chip_name}/run_latest/{self.chip_name}.ld "
            f"-I core/ -I arch/ "
            f"-I build/{self.chip_name}/run_latest/ "
            f"-I {keelhaul_inc} "
            f"-o {{elf_path}} {all_src_files}"
        )

        print("\n=== STAGE 1: COMPILATION ===")
        success = self._execute_command(gcc_tool, compile_cmd)
        if not success:
            return False

        return True

    def stage_2_packaging(self):
        """Iterates through the LLM packaging array and runs tools matching the active Profile."""
        packaging_steps = self.toolchain_reqs.get("packaging", [])

        print(f"\n=== STAGE 2: PACKAGING (Profile: {self.profile}) ===")

        valid_steps = []
        for step in packaging_steps:
            condition = step.get("condition", "ANY")
            if condition == "ANY" or condition == self.profile:
                valid_steps.append(step)

        if not valid_steps:
            print(
                "[-] No vendor packaging steps defined. Falling back to generic GNU objcopy..."
            )
            prefix = self.toolchain_reqs.get("compiler_prefix", "")
            objcopy_tool = f"{prefix}objcopy"
            objcopy_cmd = "-O binary {elf_path} {binary_path}"
            return self._execute_command(objcopy_tool, objcopy_cmd)

        for step in valid_steps:
            tool_name = step.get("tool")
            command = step.get("command")

            # Feature Extension: Handling "Interactive" commands or Pauses if requested
            if tool_name.upper() == "SYS_PAUSE":
                input(f"[II] PAUSE REQUESTED: {command}. Press Enter to continue...")
                continue

            # Fix for Gemini hallucinating 'detect' on elf2image, and enforcing aggressive SPI flash modes
            # that cause BootROM Checksum Failures (Calculated 0xef stored 0xff) due to hardware mismatch.
            if "elf2image" in command:
                command = command.replace("--flash_size detect", "")
                command = command.replace("--flash_mode dio", "")
                command = command.replace("--flash_freq 80m", "")

            success = self._execute_command(tool_name, command)
            if not success:
                return False

        return True

    def stage_3_deploy(self):
        """Executes the specific flashing tool defined by the LLM."""
        flash_config = self.toolchain_reqs.get("flashing", {})
        if not flash_config:
            print("[!] No flashing configuration found in Blueprint.")
            return False

        tool_name = flash_config.get("tool")
        command = flash_config.get("write_command")

        print("\n=== STAGE 3: DEPLOYMENT ===")
        return self._execute_command(tool_name, command)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("chip_name")
    parser.add_argument("blueprint_path")
    parser.add_argument("--profile", default="BARE_METAL_OPEN")
    args = parser.parse_args()

    builder = ToobfuzzerBuilder(args.chip_name, args.blueprint_path, args.profile)
    if builder.stage_1_compile():
        if builder.stage_2_packaging():
            builder.stage_3_deploy()
