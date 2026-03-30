import os
import sys
import subprocess
from abc import ABC, abstractmethod

class Toolchain(ABC):
    """Abstract base class for compiling target firmware families."""
    
    def __init__(self, target_info, args, config):
        self.target_info = target_info
        self.args = args
        self.config = config
        self.compiler = target_info.get("compiler", "")
        self.arch = target_info.get("arch", "")
        self.family = target_info.get("family", "")

    @property
    def binary_extension(self) -> str:
        """Default binary extension for flashing. Can be overridden by subclasses."""
        return ".bin"

    @abstractmethod
    def execute(self, cmd_str: str, cwd: str) -> int:
        """Executes a build command within the correct environment context."""
        pass
        
    @abstractmethod
    def check_prerequisites(self):
        """Validates that compilers and generators are available before building."""
        pass
        
    @property
    def cmake_generator_args(self) -> list:
        """Returns generator arguments for CMake. Overridden by subclasses."""
        return []
        
    def configure(self, bootloader_dir: str, build_dir: str):
        """Generates the CMake build files."""
        self.check_prerequisites()
        
        cache_file = os.path.join(build_dir, "CMakeCache.txt")
        if os.path.exists(cache_file):
            os.remove(cache_file)
            
        cmake_cmd = [
            "cmake", 
            *self.cmake_generator_args,
            "-S", f'"{bootloader_dir}"',
            "-B", f'"{build_dir}"',
            f"-DBOOTLOADER_CHIP_FAMILY={self.target_info.get('base_target', self.args.chip)}",
            f"-DBOOTLOADER_EXACT_CHIP={self.args.chip}",
            f"-DBOOTLOADER_ARCH={self.arch}",
            "-DBOOTLOADER_STANDALONE=ON",
            f"-DCMAKE_C_COMPILER={self.compiler}",
            f"-DCMAKE_ASM_COMPILER={self.compiler}",
            "-DCMAKE_SYSTEM_NAME=Generic",
            "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=1"
        ]
        
        flash_size = self.target_info.get("flash_size")
        if flash_size:
            cmake_cmd.append(f"-DBOOT_FLASH_SIZE={flash_size}")
            
        ram_size = self.target_info.get("ram_size")
        if ram_size:
            cmake_cmd.append(f"-DBOOT_RAM_SIZE={ram_size}")
        
        if self.args.rec_pin is not None:
            cmake_cmd.extend([
                f"-DTOOBLOADER_RECOVERY_PIN={self.args.rec_pin}",
                f"-DTOOBLOADER_RECOVERY_LEVEL={self.args.rec_level}"
            ])
            
        if getattr(self.args, "dev", False):
            cmake_cmd.extend([
                "-DBOOTLOADER_MOCK_EFUSE=ON",
                "-DTOOBLOADER_DEV_MODE=ON"
            ])
            
        cmake_cmd_str = " ".join(cmake_cmd)
        print(f"[*] Configuring for {self.args.chip} ({self.arch}) using {self.compiler}...")
        if self.execute(cmake_cmd_str, build_dir) != 0:
            print("[!] CMake generation failed.")
            sys.exit(1)

    def build(self, build_dir: str):
        """Compiles the firmware."""
        print(f"[*] Building toobloader.elf and generating target binaries...")
        if self.execute("cmake --build .", build_dir) != 0:
            print("[!] Compilation failed.")
            sys.exit(1)

    def flash(self, build_dir: str):
        """
        Flashes the generated firmware to the target device.
        Must be implemented by platform-specific toolchain subclasses.
        """
        raise NotImplementedError("Subclasses must implement flash()")
