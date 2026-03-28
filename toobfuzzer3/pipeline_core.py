import enum
import time
import sys
import os
import json
import tkinter.messagebox as messagebox
from dotenv import load_dotenv

import sys
import importlib

sys.path.append(os.path.join(os.path.dirname(__file__), "linker_gen"))
import linker_gen.gemini_parser
import linker_gen.ld_generator
importlib.reload(linker_gen.gemini_parser)
importlib.reload(linker_gen.ld_generator)

from linker_gen.gemini_parser import generate_chip_definition, configure_gemini
from linker_gen.ld_generator import generate_toolchain_files

# Load .env file
load_dotenv()


class PipelineState(enum.Enum):
    INIT = 0
    GENERATE = 1
    COMPILE = 2
    DEPLOY = 3
    LISTEN = 4
    SUCCESS = 5
    FAILED = 6


class StateContext:
    """Holds data passed between states in the pipeline."""

    def __init__(self, chip, arch, datasheet_path, runs=3):
        self.chip = chip
        self.arch = arch
        self.datasheet_path = datasheet_path
        self.runs = runs
        self.compiler_errors = []
        self.hardware_dumps = []
        self.attempt_count = 0
        self.ping_pong_triggered = False
        self.ping_pong_fired = False
        self.run_id = 1
        self.memory_map = {}


class ToobfuzzerPipeline:
    def __init__(self, context: StateContext, gui_callback=None):
        self.state = PipelineState.INIT
        self.ctx = context
        self.gui_callback = gui_callback  # Function to update UI phases

    def run(self):
        """The main autonomous loop."""
        self.state = PipelineState.GENERATE

        # Attempt to resume memory map if this is a Re-Run and an artifact exists
        scan_json_path = os.path.join(
            os.path.dirname(__file__),
            "blueprints",
            self.ctx.chip,
            f"run_{self.ctx.run_id}",
            "aggregated_scan.json",
        )
        if os.path.exists(scan_json_path) and not self.ctx.memory_map:
            try:
                with open(scan_json_path, "r") as f:
                    raw_data = json.load(f)
                    # Keys from JSON are strings, convert back to integer addresses
                    self.ctx.memory_map = {int(k): v for k, v in raw_data.items()}
                print(
                    f"[*] Resumed Memory Map state containing {len(self.ctx.memory_map)} sectors."
                )
            except Exception as e:
                print(f"[!] Failed to resume memory map: {e}")

        while self.state not in [PipelineState.SUCCESS, PipelineState.FAILED]:
            try:
                if hasattr(sys.stdout, "set_log_file"):
                    log_dir = os.path.join(
                        os.path.dirname(__file__),
                        "blueprints",
                        self.ctx.chip,
                        f"run_{self.ctx.run_id}",
                    )
                    if os.path.exists(log_dir):
                        sys.stdout.set_log_file(
                            os.path.join(log_dir, "terminal_output.txt")
                        )

                if self.state == PipelineState.GENERATE:
                    self._update_gui(2)
                    self._state_generate()
                elif self.state == PipelineState.COMPILE:
                    self._update_gui(3 if self.ctx.run_id == 1 else 5)
                    self._state_compile()
                elif self.state == PipelineState.DEPLOY:
                    self._update_gui(4 if self.ctx.run_id == 1 else 6)
                    self._state_deploy()
                elif self.state == PipelineState.LISTEN:
                    self._update_gui(4 if self.ctx.run_id == 1 else 6)
                    self._state_listen()
            except Exception as e:
                import traceback

                traceback.print_exc()
                print(f"[!] Critical Pipeline Fault: {e}")
                self.state = PipelineState.FAILED

        if self.state == PipelineState.SUCCESS:
            self._update_gui(7)  # All Green
            print("\n[SUCCESS] Factory achieved Bare-Metal Execution. Schema Locked.")
            if hasattr(self.ctx, "memory_map") and self.ctx.memory_map:
                self._generate_memory_map_report()

    def _update_gui(self, phase_index):
        if self.gui_callback:
            self.gui_callback(phase_index)

    def _state_generate(self):
        print(
            f"[GENERATE] Requesting Gemini to parse TRM context for {self.ctx.chip} ({self.ctx.arch})..."
        )
        print(
            "[GENERATE] Please wait, extracting: Memory Layout, Alignment, Watchdogs, ABI Setup..."
        )

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print("[!] Critical Error: GEMINI_API_KEY is missing from .env file.")
            self.state = PipelineState.FAILED
            return

        configure_gemini(api_key)

        # Document Understanding: Pass the file path directly to the upgraded parser
        if self.ctx.datasheet_path and os.path.exists(self.ctx.datasheet_path):
            print(
                f"[GENERATE] Ingesting attached document: {os.path.basename(self.ctx.datasheet_path)}"
            )

        try:
            # Query the AI Oracle (File API handles the upload)
            spec_json, conf_json = generate_chip_definition(
                self.ctx.chip, self.ctx.arch, self.ctx.datasheet_path, self.ctx.runs
            )

            print("\n" + "=" * 50)
            print("[GEMINI PARSER RESULT]")
            print("=" * 50)
            print(json.dumps(spec_json, indent=4, sort_keys=True))
            print("=" * 50 + "\n")

            # Save the result to a run-specific blueprint for mobility and tracking
            blueprint_base_dir = os.path.join(
                os.path.dirname(__file__), "blueprints", self.ctx.chip
            )
            os.makedirs(blueprint_base_dir, exist_ok=True)

            run_num = 1
            while os.path.exists(os.path.join(blueprint_base_dir, f"run_{run_num}")):
                run_num += 1

            self.ctx.run_id = run_num
            blueprint_dir = os.path.join(blueprint_base_dir, f"run_{run_num}")
            os.makedirs(blueprint_dir, exist_ok=True)

            if hasattr(sys.stdout, "set_log_file"):
                sys.stdout.set_log_file(
                    os.path.join(blueprint_dir, "terminal_output.txt")
                )

            blueprint_path = os.path.join(blueprint_dir, f"blueprint.json")
            conf_path = os.path.join(blueprint_dir, f"confidence.json")

            with open(blueprint_path, "w") as f:
                json.dump(spec_json, f, indent=4, sort_keys=True)

            with open(conf_path, "w") as f:
                json.dump(conf_json, f, indent=4, sort_keys=True)

            print(
                f"[GENERATE] Blueprint {run_num} successfully persisted to {blueprint_path}"
            )
            print(f"[GENERATE] Confidence matrix saved to {conf_path}")

            self.state = PipelineState.COMPILE

        except Exception as e:
            print(f"[!] Gemini AI Request Failed: {e}")
            self.state = PipelineState.FAILED

    def _state_compile(self):
        phase_name = (
            "PONG PHASE"
            if getattr(self.ctx, "ping_pong_fired", False)
            else "PING PHASE"
        )
        print(
            f"\n[{phase_name}] [COMPILE] Invoking Universal Toolchain Runner for {self.ctx.chip}..."
        )

        # Determine the latest blueprint path correctly based on our new history layout
        blueprint_base_dir = os.path.join(
            os.path.dirname(__file__), "blueprints", self.ctx.chip
        )
        run_num = 1
        while os.path.exists(os.path.join(blueprint_base_dir, f"run_{run_num+1}")):
            run_num += 1
        override = getattr(self.ctx, "blueprint_override", None)
        if override and os.path.exists(override):
            latest_blueprint = override
        else:
            latest_blueprint = os.path.join(
                blueprint_base_dir, f"run_{run_num}", "blueprint.json"
            )

        if not os.path.exists(latest_blueprint):
            print(f"[!] Cannot compile. Missing blueprint: {latest_blueprint}")
            self.state = PipelineState.FAILED
            return

        # GENERATE the Toolchain bindings (.ld and .S) and Capabilities (.c)
        with open(latest_blueprint, "r") as f:
            spec_json = json.load(f)

        import linker_gen.ld_generator
        import linker_gen.chip_generator2
        importlib.reload(linker_gen.ld_generator)
        importlib.reload(linker_gen.chip_generator2)
        
        from linker_gen.ld_generator import generate_toolchain_files
        from linker_gen.chip_generator2 import generate_chip_capabilities, generate_flash_hal

        print(
            f"[{phase_name}] [*] Compiling JSON Blueprint to Toolchain Syntax & C Profiles..."
        )
        build_dir = os.path.join(
            os.path.dirname(__file__), "build", self.ctx.chip, "run_latest"
        )
        ld_path, s_path = generate_toolchain_files(
            self.ctx.chip, latest_blueprint, build_dir
        )
        # Define the Fuzzer's expected worst-case footprint for Self-Preservation & Ping-Pong Relocation
        self.ctx.fuzzer_footprint_bytes = 0x40000  # 256KB is safer for smaller MCUs

        c_path = generate_chip_capabilities(
            spec_json[self.ctx.chip], self.ctx.chip, build_dir, footprint_size=self.ctx.fuzzer_footprint_bytes
        )
        
        hal_path = generate_flash_hal(
            spec_json[self.ctx.chip], self.ctx.chip, build_dir
        )

        print(
            f"[*] Emitted: {os.path.basename(ld_path)} | {os.path.basename(s_path)} | {os.path.basename(c_path)}"
        )

        # Add scripts to path to load builder
        scripts_dir = os.path.join(os.path.dirname(__file__), "scripts")
        if scripts_dir not in sys.path:
            sys.path.append(scripts_dir)

        from build_core import ToobfuzzerBuilder

        # We start by testing the most permissive profile
        self.builder = ToobfuzzerBuilder(
            self.ctx.chip, latest_blueprint, profile="BARE_METAL_OPEN"
        )

        if not self.builder.stage_1_compile():
            print("[!] Compilation Failed.")
            print(
                "    [?] To trigger the AI Self-Healing loop, implement error parsing here."
            )
            self.state = PipelineState.FAILED
            return

        if not self.builder.stage_2_packaging():
            print("[!] Packaging Failed.")
            self.state = PipelineState.FAILED
            return

        self.state = PipelineState.DEPLOY

    def _state_deploy(self):
        phase_name = (
            "PONG PHASE"
            if getattr(self.ctx, "ping_pong_fired", False)
            else "PING PHASE"
        )
        print(f"\n[{phase_name}] [PAUSE] The Pipeline has prepared the Fuzzer binary.")
        print(
            "[?] Please connect your device and put it into BOOTLOADER mode (if required)."
        )

        # Hardcoded pause requested by user to prepare physical hardware
        if not messagebox.askokcancel(
            "Ready for Hardware",
            f"The binary for {self.ctx.chip} is compiled and ready!\n\nPlease connect your device and put it into Bootloader/Download Mode.\n\nClick OK to execute the Flashing toolchain.",
        ):
            print("[-] Flashing aborted by user.")
            self.state = PipelineState.FAILED
            return

        flash_offs = "Unknown Offset"
        if hasattr(self, "builder") and self.builder:
            flash_offs = self.builder.toolchain_reqs.get("flashing", {}).get(
                "flash_offset", flash_offs
            )

        phase_name = (
            "PONG PHASE"
            if getattr(self.ctx, "ping_pong_fired", False)
            else "PING PHASE"
        )
        print(
            f"[{phase_name}] [DEPLOY] Flashing binary to {self.ctx.chip} BootROM at offset {flash_offs} using Data-Driven tools..."
        )
        if not hasattr(self, "builder"):
            print("[!] Builder context lost!")
            self.state = PipelineState.FAILED
            return

        if not self.builder.stage_3_deploy():
            print("[!] Flashing Failed.")
            self.state = PipelineState.FAILED
            return

        self.state = PipelineState.LISTEN

    def _state_listen(self):
        phase_name = (
            "PONG PHASE"
            if getattr(self.ctx, "ping_pong_fired", False)
            else "PING PHASE"
        )
        print(f"\n[{phase_name}] [LISTEN] Opening COM Port. Awaiting Fuzzer Oracle...")

        try:
            import serial
            import serial.tools.list_ports
        except ImportError:
            print("[!] pyserial missing. Please run: pip install pyserial")
            self.state = PipelineState.FAILED
            return

        ports = serial.tools.list_ports.comports()
        if not ports:
            print("[!] No active COM ports found for Fuzzer telemetry.")
            self.state = PipelineState.FAILED
            return

        # Attempt to use the first available port (zero-config)
        target_port = ports[0].device
        print(f"[LISTEN] Attaching to {target_port} at 115200 baud...")

        try:
            with serial.Serial(target_port, 115200, timeout=120) as ser:
                print("[LISTEN] UART Connection Established.")

                # Wait for BOOT_OK
                booted = False
                for _ in range(50):
                    line = ser.readline().decode("utf-8", errors="ignore").strip()
                    if line:
                        print(f"[{phase_name}] [{self.ctx.chip}] {line}")
                    if "OSV_ORACLE_READY" in line:
                        booted = True
                        break

                if not booted:
                    print("[!] Hardware timeout. Boot sequence failed.")
                    self.state = PipelineState.FAILED
                    return

                print(
                    f"[{phase_name}] [LISTEN] Dispatching SCAN (0xA1) to {self.ctx.chip}..."
                )
                ser.write(b"\xa1")

                print(f"[{phase_name}] [LISTEN] Awaiting Oracle Stream...")
                rolling_log = []
                while True:
                    raw_line = ser.readline()
                    if not raw_line:
                        # True 10-second timeout with zero bytes read
                        print(
                            "\n[!] 💥 Hardware Watchdog Panic or Silenced CPU Detected."
                        )
                        print(
                            f"[!] Capturing trailing telemetry and aborting Pipeline."
                        )

                        crash_dump = "\n".join(rolling_log[-50:])
                        self.ctx.hardware_dumps.append(
                            {
                                "run_id": self.ctx.run_id,
                                "attempt": self.ctx.attempt_count,
                                "telemetry": crash_dump,
                            }
                        )
                        self.ctx.attempt_count += 1
                        self.state = PipelineState.FAILED
                        break

                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue  # Just a blank newline emitted by the device

                    rolling_log.append(line)

                    # Live Progress Calculation & Clean Console Output
                    printed_clean = False
                    if line.startswith("[CORE] {"):
                        try:
                            scan_data = json.loads(line.replace("[CORE] ", ""))
                            if scan_data.get("status") == "scan_start":
                                self.ctx.scan_base = int(scan_data["base"], 16)
                                self.ctx.scan_limit = int(scan_data["limit"], 16)
                                self.ctx.scan_total_size = (
                                    self.ctx.scan_limit - self.ctx.scan_base
                                )
                                print(
                                    f"[{self.ctx.chip}] [Flash Fuzz] Discovered Bounds: {scan_data['base']} -> {scan_data['limit']}"
                                )
                                printed_clean = True
                            elif scan_data.get("region") in [
                                "FLASH_SECTOR",
                                "FLASH_BLINDSPOT",
                            ]:
                                if (
                                    hasattr(self.ctx, "scan_base")
                                    and self.ctx.scan_total_size > 0
                                ):
                                    addr = int(scan_data["address"], 16)
                                    pct = int(
                                        (
                                            (addr - self.ctx.scan_base)
                                            / self.ctx.scan_total_size
                                        )
                                        * 100
                                    )
                                    status = scan_data.get("status", "skipped")
                                    print(
                                        f"[{self.ctx.chip}] [Flash Fuzz] {pct}% Complete ({hex(addr)} / {hex(self.ctx.scan_limit)}) - {status}"
                                    )
                                    printed_clean = True
                        except Exception:
                            pass
                    
                    if "Discovered Valid Boundary:" in line:
                        if not hasattr(self.ctx, "ram_fuzzed_boundaries"):
                            self.ctx.ram_fuzzed_boundaries = []
                        parts = line.split("Boundary: 0x")
                        if len(parts) > 1:
                            addr_str = parts[1].strip()
                            try:
                                if addr_str.startswith("0x"):
                                    addr_str = addr_str[2:]
                                self.ctx.ram_fuzzed_boundaries.append("0x" + addr_str)
                            except Exception:
                                pass

                    elif line.startswith(("+0x", "-0x", "S0x")):
                        try:
                            # Handle dynamic " [size: 0x...]" suffixes
                            parts = line.split()
                            addr_str = parts[0][1:]
                            addr = int(addr_str, 16)

                            sector_size = 4096
                            if (
                                len(parts) >= 3
                                and parts[1] == "[size:"
                                and parts[2].startswith("0x")
                            ):
                                sector_size = int(parts[2].strip("]"), 16)

                            if (
                                hasattr(self.ctx, "scan_base")
                                and self.ctx.scan_total_size > 0
                            ):
                                pct = int(
                                    (
                                        (addr - self.ctx.scan_base)
                                        / self.ctx.scan_total_size
                                    )
                                    * 100
                                )
                                if line.startswith("+"):
                                    status = "erased"
                                    is_fallback = False
                                elif line.startswith("-"):
                                    status = "fault"
                                    is_fallback = True
                                else:
                                    status = "skipped"
                                    is_fallback = False
                                    self.ctx.ping_pong_triggered = True

                                fallback_str = (
                                    " (FALLBACK APPLIED)" if is_fallback else ""
                                )
                                print(
                                    f"[{self.ctx.chip}] [Flash Fuzz] {pct}% Complete ({hex(addr)} / {hex(self.ctx.scan_limit)}) - {status} [measured_size: {hex(sector_size)}]{fallback_str}"
                                )
                                printed_clean = True

                                if not hasattr(self.ctx, "memory_map"):
                                    self.ctx.memory_map = {}

                                if addr not in self.ctx.memory_map:
                                    self.ctx.memory_map[addr] = {
                                        "start_addr": addr,
                                        "end_addr": addr + sector_size - 1,
                                        "start_hex": hex(addr),
                                        "end_hex": hex(addr + sector_size - 1),
                                        "size": sector_size,
                                        "fallback": is_fallback,
                                        "verification_method": "Physical Fuzzing (Bare-Metal)",
                                    }
                                else:
                                    # Always keep the most accurate (largest known) sector measurement
                                    if sector_size > self.ctx.memory_map[addr].get(
                                        "size", 4096
                                    ):
                                        self.ctx.memory_map[addr]["size"] = sector_size
                                        self.ctx.memory_map[addr]["end_addr"] = addr + sector_size - 1
                                        self.ctx.memory_map[addr]["end_hex"] = hex(addr + sector_size - 1)

                                    # If any run succeeded (no fallback), mark it as such
                                    if not is_fallback:
                                        self.ctx.memory_map[addr]["fallback"] = False
                                        self.ctx.memory_map[addr]["verification_method"] = "Physical Fuzzing (Bare-Metal)"

                                run_key = (
                                    "run_pong"
                                    if getattr(self.ctx, "ping_pong_fired", False)
                                    else "run_ping"
                                )
                                self.ctx.memory_map[addr][run_key] = status

                                # Print clean progress for every sector without JSON overhead
                                print(
                                    f"[{self.ctx.chip}] [Flash Fuzz] {pct}% Complete ({hex(addr)} / {hex(self.ctx.scan_limit)}) - {status}"
                                )
                                printed_clean = True
                                
                                # Auto-save intermediate progress JSON
                                try:
                                    bp_dir = os.path.join(os.path.dirname(__file__), "blueprints", self.ctx.chip, f"run_{self.ctx.run_id}")
                                    os.makedirs(bp_dir, exist_ok=True)
                                    
                                    export_map = dict(self.ctx.memory_map)
                                    if hasattr(self.ctx, "ram_fuzzed_boundaries"):
                                        export_map["metadata"] = {
                                            "ram_fuzzed_boundaries": self.ctx.ram_fuzzed_boundaries
                                        }
                                        
                                    with open(os.path.join(bp_dir, "aggregated_scan.json"), "w") as f:
                                        json.dump(export_map, f, indent=4)
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    if not printed_clean:
                        print(f"[{self.ctx.chip}] {line}")

                    # Phase 11: Ping-Pong Oracle Hook
                    if '"skipped": true' in line:
                        self.ctx.ping_pong_triggered = True

                    # Fuzzer Mathematical Output
                    if "status" in line and "complete" in line:
                        if self.ctx.ping_pong_triggered and not getattr(
                            self.ctx, "ping_pong_fired", False
                        ):
                            print(
                                "\n[PING-PONG] Fuzzer successfully completed Ping Phase, but skipped its own memory."
                            )
                            print(
                                "[PING-PONG] Initiating autonomous Pong Phase (Relocating Firmware)..."
                            )

                            # Deep-copy and mutate the latest blueprint to shift the firmware +512KB for a clean scan
                            import shutil

                            bp_dir = os.path.join(
                                os.path.dirname(__file__), "blueprints", self.ctx.chip
                            )
                            run1_bp = os.path.join(
                                bp_dir, f"run_{self.ctx.run_id}", "blueprint.json"
                            )
                            run2_dir = os.path.join(
                                bp_dir, f"run_{self.ctx.run_id}_pong"
                            )
                            os.makedirs(run2_dir, exist_ok=True)
                            run2_bp = os.path.join(run2_dir, "blueprint.json")

                            with open(run1_bp, "r") as f:
                                bp_data = json.load(f)

                            # Architecturally Agnostic Relocation:
                            # We leave the logical/physical Flash origin completely alone. Pong will boot exactly
                            # like Ping at 0x1000. It will run strictly from IRAM.
                            # We merely spoof the `user_app_base` constant in the C-header.
                            # This causes Pong's self-preservation algorithm to protect +512KB and BLINDLY erase
                            # its own physical flash footprint, completing the 100% scan!
                            old_base_str = bp_data[self.ctx.chip]["boot_vectors"][
                                "user_app_base"
                            ]
                            new_base = int(old_base_str, 16) + self.ctx.fuzzer_footprint_bytes
                            bp_data[self.ctx.chip]["boot_vectors"][
                                "user_app_base"
                            ] = f"0x{new_base:08X}"

                            with open(run2_bp, "w") as f:
                                json.dump(bp_data, f, indent=4)

                            # Point to the modified Pong blueprint
                            self.ctx.blueprint_override = run2_bp
                            self.ctx.ping_pong_fired = True
                            self.ctx.ping_pong_triggered = False
                            self.state = PipelineState.COMPILE
                        else:
                            print(
                                "\n[LISTEN] 🏁 Memory Mapping Complete. 100% of Flash Space cataloged."
                            )
                            self.state = PipelineState.SUCCESS
                        break
        except Exception as e:
            print(f"[!] Serial Communication Error: {e}")
            self.state = PipelineState.FAILED

    def _generate_memory_map_report(self):
        print("\n" + "=" * 65)
        print("[REPORT] Ping-Pong Aggregated Flash Map")
        print("=" * 65)

        map_data = getattr(self.ctx, "memory_map", {})
        if not map_data:
            return

        sorted_addrs = sorted(map_data.keys())
        merged_regions = []
        current_region = None

        for addr in sorted_addrs:
            ping_stat = map_data[addr].get("run_ping", "unknown")
            pong_stat = map_data[addr].get("run_pong", "unknown")
            sector_size = map_data[addr].get("size", 4096)

            if ping_stat == "erased" and pong_stat == "erased":
                effective = "erased (both)"
            elif ping_stat == "erased":
                effective = "erased (ping)"
            elif pong_stat == "erased":
                effective = "erased (pong)"
            elif ping_stat == "fault" and pong_stat == "fault":
                effective = "fault (both)"
            elif ping_stat == "fault":
                effective = "fault (ping)"
            elif pong_stat == "fault":
                effective = "fault (pong)"
            else:
                effective = "skipped"

            is_fallback = map_data[addr].get("fallback", False)

            # Check if this block is contiguous with the current region
            if (
                current_region
                and current_region["status"] == effective
                and current_region.get("fallback", False) == is_fallback
                and (current_region["end"] + current_region["last_size"]) == addr
            ):
                current_region["end"] = addr
                current_region["total_size"] += sector_size
                current_region["last_size"] = sector_size
            else:
                if current_region:
                    merged_regions.append(current_region)
                current_region = {
                    "start": addr,
                    "end": addr,
                    "status": effective,
                    "last_size": sector_size,
                    "total_size": sector_size,
                    "fallback": is_fallback,
                }
        if current_region:
            merged_regions.append(current_region)

        for reg in merged_regions:
            icon = (
                "✓"
                if "erased" in reg["status"]
                else "X" if "fault" in reg["status"] else "-"
            )
            size_kb = reg["total_size"] / 1024.0
            print(
                f" [{icon}] {hex(reg['start']):<10} -> {hex(reg['end'] + 4095):<10} | {size_kb:>8.1f} KB | {reg['status'].upper()}"
            )

        print("=" * 65)

        bp_dir = os.path.join(
            os.path.dirname(__file__),
            "blueprints",
            self.ctx.chip,
            f"run_{self.ctx.run_id}",
        )
        report_path = os.path.join(bp_dir, "aggregated_scan.json")
        try:
            with open(report_path, "w") as f:
                json.dump(map_data, f, indent=4)
            print(f"[*] Aggregated JSON report saved to {report_path}\n")
        except Exception:
            pass
