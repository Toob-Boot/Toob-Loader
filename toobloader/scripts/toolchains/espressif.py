import os
import shutil
import subprocess
from .base import Toolchain

class EspressifToolchain(Toolchain):
    """Handles auto-loading the ESP-IDF environment required for Xtensa/RISC-V targets."""
    
    def __init__(self, target_info, args, config):
        super().__init__(target_info, args, config)
        self.export_script = self._find_export_script()

    @property
    def cmake_generator_args(self) -> list:
        return ["-G", "Ninja"]
        
    def check_prerequisites(self):
        import shutil, sys
        if not self.export_script and not shutil.which(self.compiler):
            print(f"[!] ERROR: Compiler '{self.compiler}' is not in PATH and no ESP-IDF export script was found.")
            print("    Please install ESP-IDF (v5.0+) or manually run its 'export.bat / export.sh' script.")
            sys.exit(1)

    def _find_export_script(self):
        idf_path = os.environ.get("IDF_PATH")
        if not idf_path:
            # Common default installation locations
            search_paths = [
                os.path.expanduser("~/esp/esp-idf"),    # Linux/Mac
                r"C:\Espressif\frameworks\esp-idf"      # Windows Custom
            ]
            for path in search_paths:
                if os.path.exists(path):
                    idf_path = path
                    break
            
            # Auto-detect newest ESP-IDF version on Windows Standard Installer
            if not idf_path and os.path.isdir(r"C:\Espressif\frameworks"):
                base_dir = r"C:\Espressif\frameworks"
                dirs = [d for d in os.listdir(base_dir) if d.startswith("esp-idf-v")]
                if dirs:
                    dirs.sort(reverse=True)
                    idf_path = os.path.join(base_dir, dirs[0])
                    
        if idf_path:
            script_name = "export.bat" if os.name == "nt" else "export.sh"
            script_path = os.path.join(idf_path, script_name)
            if os.path.exists(script_path):
                return script_path
                
        return None

    def execute(self, cmd_str: str, cwd: str) -> int:
        # If the compiler and ninja are already in PATH, run natively
        if shutil.which("ninja") and shutil.which(self.compiler):
            return subprocess.call(cmd_str, cwd=cwd, shell=True)
            
        # If not, inject the ESP-IDF environment using the export script
        if self.export_script:
            print(f"[*] Auto-loading ESP-IDF environment from {os.path.dirname(self.export_script)}...")
            if os.name == "nt":
                # Windows requires chaining in the same subshell
                wrapped_cmd = f'"{self.export_script}" >nul 2>&1 && {cmd_str}'
            else:
                wrapped_cmd = f'. "{self.export_script}" && {cmd_str}'
            return subprocess.call(wrapped_cmd, cwd=cwd, shell=True)
            
        # Fallback (will likely fail but show errors to the developer)
        return subprocess.call(cmd_str, cwd=cwd, shell=True)

    def flash(self, build_dir: str):
        import sys
        flash_offset = self.target_info.get("flash_offset", "0x0")
        flash_cmd_template = self.target_info.get("flash_cmd")
        if not flash_cmd_template and self.family in self.config.get("families", {}):
            flash_cmd_template = self.config["families"][self.family].get("flash_cmd", "")
            
        rel_build_dir = os.path.relpath(build_dir, os.getcwd())
        port_arg = f"--port {self.args.port}" if self.args.port else ""
        binary = f"{rel_build_dir}/toobloader{self.binary_extension}"
        
        cmd_str = flash_cmd_template.format(chip=self.args.chip, port_arg=port_arg, offset=flash_offset, binary=binary).replace("  ", " ").strip()
        
        if not self.args.flash:
            print(f"[*] To flash this device, run: toobl --chip {self.args.chip} --flash")
            return
            
        print(f"[*] Executing Native Toolchain Command: {cmd_str}")
        print(f"\n[*] Flashing to {self.args.chip} at offset {flash_offset}...")
        # For Espressif, esptool is provided by ESP-IDF, so we MUST use self.execute() 
        # to ensure the IDF environment variables are properly loaded.
        if self.execute(cmd_str, os.getcwd()) != 0:
            print("[!] Bootloader Flashing Sequence Failed.")
            sys.exit(1)
        print("[*] Flashing successfully completed!")
