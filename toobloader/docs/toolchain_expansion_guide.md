# Toobloader Toolchain Expansion Guide

The **Toobloader Standalone Build Ecosystem** utilizes an Object-Oriented Toolchain Architecture to support a multitude of architectures (ARM, RISC-V, Xtensa) and chip vendors without bloating the main build script.

This guide explains the data model (Families, Architectures, Chips) and provides a step-by-step tutorial on how to implement new vendor toolchains (like STM32 or nRF).

---

## 0. Prerequisites & Environment Setup

Because the Toobloader relies on native architecture cross-compilation, your host system must have the correct toolchains installed in its `%PATH%` (or automatically discoverable, in the case of ESP-IDF) before running `build_standalone.py`.

### For Espressif Targets (ESP32, S2, C3, S3, C6, H2)

The script uses the `EspressifToolchain` which automatically searches for an existing **ESP-IDF** installation on your system (usually `~/esp/esp-idf` or `C:\Espressif\frameworks\esp-idf`).

- You **MUST** have the ESP-IDF installed.
- The script will automatically locate `export.bat` / `export.sh` and inject the Xtensa/RISC-V compilers and `Ninja` into the active subshell.
- You do **not** need to manually run `export.bat` before calling the build script.

### For STM32 & nRF Targets (Generic ARM Cortex-M)

The script uses the `GenericToolchain` which relies on your global system `%PATH%`.

- **Compiler**: You **MUST** have `arm-none-eabi-gcc` installed globally.
  - Download: [Arm GNU Toolchain Downloads](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
  - _Windows_: Download the `.msi` Windows installer for the **AArch32 bare-metal target (arm-none-eabi)**. (An `.msi` file is a standard setup wizard).
  - _macOS_: Use the PKG installer for **AArch32 bare-metal target** or install via Homebrew (`brew install --cask gcc-arm-embedded`).
  - _Linux_: Install simply via your package manager (e.g., `sudo apt install gcc-arm-none-eabi`).
- **Build Generator**: You **MUST** have either `ninja` or `make` in your `%PATH%` (or `$PATH`).
  - Download Ninja: [Ninja GitHub Releases](https://github.com/ninja-build/ninja/releases)
  - _macOS / Linux_: `brew install ninja` or `sudo apt install ninja-build`.
  - The script auto-detects which one is available and passes the correct `-G` flag to CMake. _(Note: It will also smartly auto-discover ESP-IDF Ninja installations on Windows if found!)_
- **Flashing Utility**: For `stm32` targets, the default JSON configuration attempts to use `st-flash` (from the stlink toolkit). For `nrf` targets, it attempts to use `nrfjprog`.
  - **STM32 (`st-flash`) Installation**:
    - _Windows_: Download the official [ST-LINK Utility](https://www.st.com/en/development-tools/stsw-link004.html) or use MSYS2 (`pacman -S mingw-w64-x86_64-stlink`).
    - _macOS_: `brew install stlink`
    - _Linux_: `sudo apt install stlink-tools`
  - **nRF (`nrfjprog`) Installation**: Download the [nRF Command Line Tools](https://www.nordicsemi.com/Products/Development-tools/nrf-command-line-tools/download) from Nordic Semiconductor.

---

## 1. The Core Concepts

To abstract hardware complexities, Toobloader uses three hierarchical concepts defined in `scripts/targets.json`:

- **Family (`family`)**: The vendor or broader ecosystem that dictates _how_ the chip is flashed and built (e.g., `esp`, `stm`, `nrf`).
  - _Families are directly tied to Python Toolchain Classes._
- **Architecture (`arch`)**: The instruction set architecture of the chip (e.g., `arm`, `riscv`, `xtensa`).
  - _Architectures dictate which `arch/` C-folder is dynamically linked during compilation._
- **Chip (`chip`)**: The specific silicon target (e.g., `esp32c6`, `stm32f4`).
  - _Chips dictate the specific HAL mapping (`chip/esp/esp32c6/boot_hal_esp32c6.c`) and compiler tripplet (e.g., `riscv32-esp-elf-gcc`)._

---

## 2. The Toolchain Architecture (IoC)

The `scripts/build_standalone.py` script acts purely as a Router. It parses the command line, looks up the target chip in `targets.json`, and asks the **Toolchain Factory** for the correct handler.

The logic is split across 5 core Python files:

1.  **`build_standalone.py` (The Router)**: Knows nothing about how to build. It just calls `.configure()`, `.build()`, and `.flash()` on the Toolchain object.
2.  **`toolchains/base.py` (The Architect)**: Defines the Abstract Base Class `Toolchain`. It enforces the standard CMake configurations required by Repowatt-OS and handles the generic `configure`, `build`, and `flash` phases.
3.  **`toolchains/espressif.py` (The Specialist)**: Handles the complex `export.bat`/`export.sh` loading sequence for ESP-IDF environments before executing any commands.
4.  **`toolchains/generic.py` (The Minimalist)**: Executes commands directly via subprocess, assuming standard GCC tools (`arm-none-eabi-gcc`) are already in the system `%PATH%`.
5.  **`toolchains/__init__.py` (The Registry)**: The Python init file that exports the classes for easy importing.

---

## 3. How to Add a New Toolchain

If you are adding support for a new vendor (e.g., STM32) that requires a specific file extension (like `.hex` instead of `.bin`) or custom pre-build environment steps, follow this guide.

### Step 1: Create the Toolchain Class

Create a new file in the `scripts/toolchains/` directory, for example, `stm32.py`.

```python
# scripts/toolchains/stm32.py
import subprocess
from .base import Toolchain

class STM32Toolchain(Toolchain):
    """
    Handles STM32 builds using standard ARM GCC toolchains.
    Customizes the flash extension from .bin to .hex.
    """

    @property
    def binary_extension(self) -> str:
        # Override the default extension (.bin) for flashing
        return ".hex"

    def execute(self, cmd_str: str, cwd: str) -> int:
        # Standard execution. If STM32 required an environment load script,
        # you would implement that logic here (similar to EspressifToolchain).
        return subprocess.call(cmd_str, cwd=cwd, shell=True)
```

### Step 2: Register it in the Initializer

Add your new class to `scripts/toolchains/__init__.py` so it is cleanly exported.

```python
# scripts/toolchains/__init__.py
from .base import Toolchain
from .espressif import EspressifToolchain
from .generic import GenericToolchain
from .stm32 import STM32Toolchain    # <-- Add this

__all__ = [
    "Toolchain",
    "EspressifToolchain",
    "GenericToolchain",
    "STM32Toolchain"                 # <-- Add this
]
```

### Step 3: Wire it in the Factory

Tell the main script to route requests for your family to the new class. Update `scripts/build_standalone.py`:

```python
# Inside scripts/build_standalone.py

from toolchains import Toolchain, EspressifToolchain, GenericToolchain, STM32Toolchain

def get_toolchain_for_target(args, config, target_info) -> Toolchain:
    family = target_info.get("family", "")
    if family == "esp":
        return EspressifToolchain(target_info, args, config)
    elif family == "stm":
        return STM32Toolchain(target_info, args, config)  # <-- Add this mapping
    else:
        # Fallback for simple PATH-based toolchains (e.g., nRF)
        return GenericToolchain(target_info, args, config)
```

### Step 4: Define the Flash Command in `targets.json`

Ensure that the `stm` family in `targets.json` defines your preferred flashing utility. The toolchain will automatically read this and substitute `{binary}` with `toobloader.hex`.

```json
{
  "families": {
    "esp": {
      "flash_cmd": "python -m esptool --chip {chip} {port_arg} write_flash {offset} {binary}"
    },
    "stm": {
      "flash_cmd": "st-flash --reset write {binary} {offset}"
    }
  }
}
```

---

By leveraging this Inversion of Control (IoC) architecture, you can infinitely scale Toobloader's hardware support without ever touching or copy-pasting the massive 100-line CMake configuration block in the core build router!
