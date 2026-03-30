import subprocess
from .base import Toolchain

class GenericToolchain(Toolchain):
    """Handles standard GCC-based toolchains (e.g., STM32, nRF) using the system PATH."""
    
    @property
    def cmake_generator_args(self) -> list:
        import os, shutil
        cmake_args = []
        if shutil.which("ninja"):
            cmake_args.extend(["-G", "Ninja"])
            return cmake_args

        if os.name == "nt":
            # User observation: ESP-IDF already installs Ninja. Let's hijack it!
            esp_ninja_base = r"C:\Espressif\tools\ninja"
            if os.path.exists(esp_ninja_base):
                versions = os.listdir(esp_ninja_base)
                if versions:
                    versions.sort(reverse=True)
                    esp_ninja_path = os.path.join(esp_ninja_base, versions[0])
                    # Inject ESP-IDF's Ninja into the local Python PATH for this process
                    os.environ["PATH"] = f"{esp_ninja_path};" + os.environ.get("PATH", "")
                    cmake_args.extend(["-G", "Ninja"])
                    print(f"[*] Auto-discovered Espressif Ninja at: {esp_ninja_path}")
                    return cmake_args
            if shutil.which("mingw32-make"):
                cmake_args.extend(["-G", "MinGW Makefiles"])
                return cmake_args
        else:
            if shutil.which("make"):
                cmake_args.extend(["-G", "Unix Makefiles"])
                return cmake_args
                
        return cmake_args

    def check_prerequisites(self):
        import shutil, sys, os
        if not shutil.which(self.compiler):
            # Attempt Zero-Touch Auto-Discovery for Windows ARM GCC
            if os.name == "nt" and "arm-none-eabi" in self.compiler:
                search_dirs = [r"C:\Program Files (x86)\Arm", r"C:\Program Files\Arm"]
                found = False
                for base_dir in search_dirs:
                    if os.path.exists(base_dir):
                        for root, dirs, files in os.walk(base_dir):
                            if self.compiler + ".exe" in files:
                                os.environ["PATH"] = root + ";" + os.environ.get("PATH", "")
                                print(f"[*] Auto-discovered ARM Compiler at: {root}")
                                found = True
                                break
                        if found:
                            break
            # Attempt Zero-Touch Auto-Discovery for Linux/macOS ARM GCC
            elif os.name != "nt" and "arm-none-eabi" in self.compiler:
                linux_paths = ["/usr/local/bin", "/opt/arm/bin", "/opt/homebrew/bin", os.path.expanduser("~/gcc-arm-none-eabi/bin"), "/usr/bin"]
                for p in linux_paths:
                    if os.path.exists(os.path.join(p, self.compiler)):
                        os.environ["PATH"] = p + ":" + os.environ.get("PATH", "")
                        print(f"[*] Auto-discovered ARM Compiler at: {p}")
                        break
                            
            if not shutil.which(self.compiler):
                print(f"[!] ERROR: Required compiler '{self.compiler}' is not installed or not in PATH.")
                print(f"    Please install it to build for {self.family.upper()} generic ARM targets.")
                sys.exit(1)
            
        if not self.cmake_generator_args:
            print("[!] ERROR: No supported build generator found (Ninja or Make).")
            print("    Please install Ninja (recommended) or Make.")
            sys.exit(1)

    def execute(self, cmd_str: str, cwd: str) -> int:
        return subprocess.call(cmd_str, cwd=cwd, shell=True)

    def flash(self, build_dir: str):
        import sys, os, shutil
        flash_offset = self.target_info.get("flash_offset", "0x0")
        flash_cmd_template = self.target_info.get("flash_cmd")
        if not flash_cmd_template and self.family in self.config.get("families", {}):
            flash_cmd_template = self.config["families"][self.family].get("flash_cmd", "")
            
        # Generic targets require external tools (st-flash, nrfjprog). Validate installation.
        base_tool = flash_cmd_template.split()[0] if flash_cmd_template else ""
        if base_tool and not shutil.which(base_tool):
            print(f"[!] Required flashing utility '{base_tool}' is not installed or not in PATH.")
            print(f"    Please install it to enable automatic flashing for {self.family.upper()} targets.")
            if self.args.flash:
                sys.exit(1)
                
        rel_build_dir = os.path.relpath(build_dir, os.getcwd())
        binary = f"{rel_build_dir}/toobloader{self.binary_extension}"
        
        cmd_str = flash_cmd_template.format(family=self.family, offset=flash_offset, binary=binary).replace("  ", " ").strip()
        
        if not self.args.flash:
            print(f"[*] To flash this device, run: toobl --chip {self.args.chip} --flash")
            return
            
        print(f"[*] Executing Native Toolchain Command: {cmd_str}")
        print(f"\n[*] Flashing to {self.args.chip} at offset {flash_offset}...")
        if subprocess.call(cmd_str, shell=True) != 0:
            print("[!] Bootloader Flashing Sequence Failed.")
            sys.exit(1)
        print("[*] Flashing successfully completed!")
