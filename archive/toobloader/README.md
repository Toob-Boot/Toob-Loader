# Standalone Toobloader (Stable Release)

To build the Toobloader as a standalone, flashable executable (`toobloader.bin`) natively on your operating system (Windows, Linux, or macOS), you must install the following prerequisites.

**Zero-Container Target**: The toobloader uses a completely independent, bare-metal HAL. You do **NOT** need the full host OS CLI, Docker containers, or WSL (Windows Subsystem for Linux) to build this binary. It compiles 100% natively on the host OS.

## Prerequisites

### 1. CMake (Requires: v3.16+)

The bootloader build process is orchestrated by CMake. Minimum version required is `3.16` for cross-compilation support.

- **Download**: [https://cmake.org/download/](https://cmake.org/download/)
- **Installation**: Download the installer for your corresponding OS.
- **IMPORTANT**: During installation, ensure that CMake is added to your system `PATH`.

### 2. Compiler Toolchains

The bootloader compiles natively for different architectures depending on your target chip. You only need to install the toolchain relevant to your target:

#### A: Espressif Targets (ESP32, S3, C6, etc.)

Requires an **ESP-IDF Environment** (v5.0+):

- **Download**: [https://dl.espressif.com/dl/esp-idf/](https://dl.espressif.com/dl/esp-idf/)
- The build script will automatically detect your ESP-IDF installation and inject the Xtensa/RISC-V compilers and `Ninja` into its build environment. _You do not need to run export.bat manually._

#### B: Generic ARM Cortex-M Targets (STM32, nRF)

Requires the **ARM GNU Toolchain** and a Build Generator:

- **Compiler**: Install `arm-none-eabi-gcc` globally on your system.
  - Download: [Arm GNU Toolchain Downloads](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
  - _Windows_: Download the `.msi` Windows installer for the **AArch32 bare-metal target (arm-none-eabi)**. (An `.msi` file is a standard setup wizard—just double-click it to install). **NOTE: The current installer no longer adds itself to the `PATH` automatically. You MUST manually add the `bin` folder (e.g., `C:\Program Files (x86)\Arm GNU Toolchain arm-none-eabi\15.2 rel1\bin`) to your Windows Environment Variables!**
  - _macOS_: Download the PKG installer for **AArch32 bare-metal** or run `brew install --cask gcc-arm-embedded`.
  - _Linux_: Install via your package manager (e.g., `sudo apt install gcc-arm-none-eabi`).
- **Generator**: Install `ninja` or `make` globally. The script will auto-detect which generator to pass to CMake.
  - Download Ninja: [Ninja GitHub Releases](https://github.com/ninja-build/ninja/releases)
  - _macOS / Linux_: Install natively via package manager (e.g., `brew install ninja` or `sudo apt install ninja-build`).
  - _Note: If you already have ESP-IDF installed on Windows, the build script will smartly auto-discover its bundled Ninja binary! You do not need to download it twice._

### 3. Python (Requires: v3.8+) & Flashing Utilities

The build process is wrapped in a Python script (`build_standalone.py`) which invokes CMake and then uses flashing utilities to convert the `.elf` file into a flashable binary or flash it directly to the board.

- **Python Requirements**: Python `3.8` or newer must be installed on your system.
- **For Espressif Targets (`esptool`)**: Install it via pip: `pip install esptool`
- **For STM32 Targets (`st-flash`)**: Install the ST-LINK Utility (Windows), `brew install stlink` (macOS), or `sudo apt install stlink-tools` (Linux).
- **For Nordic nRF Targets (`nrfjprog`)**: Download the nRF Command Line Tools from Nordic Semiconductor.

---

## Building the Toobloader

Once all prerequisites are installed:

**Note**: The `build/` directory and its contents are automatically created by the build script.

1. Open your terminal and **activate the ESP-IDF environment** (e.g., via the ESP-IDF Command Prompt on Windows, or by sourcing `export.sh` on Linux/macOS).
2. Navigate to the `toobloader` directory:
   ```bash
   cd /path/to/your/cloned/toobloader
   ```
3. Run the standalone builder script for your target chip:

   **For ESP32 (Xtensa):**

   ```bash
   toobl --chip esp32
   ```

   **For ESP32-C6 (RISC-V):**

   ```bash
   toobl --chip esp32c6
   ```

   **To force a clean build:** (Useful when switching CMake configurations or compilers)

   ```bash
   toobl --chip esp32c6 --clean
   ```

4. If successful, the script will output the compiled binaries (`toobloader.elf` and `toobloader.bin`) in the dynamically created `build/build_esp32` or `build/build_esp32c6` directory.
5. If you provided the `--flash` argument (e.g., `toobl --chip esp32c6 --flash`), the script will automatically invoke the corresponding flashing tool to flash the bootloader to the correct hardware offset for the specified chip architecture. You can optionally specify a target port with `--port` (e.g., `--port COM3`).

### Under the Hood: The Flashing Pipeline

When using the `--flash` argument, the `build_standalone.py` script dynamically constructs the flashing command based on the target chip and its family, as defined in `scripts/targets.json`.

Supported families and their underlying tools:

- **ESP Families** (esp32, esp32c6, esp32s3, etc.): Uses `esptool.py`.
  - Command: `python -m esptool --chip <chip> --port <port> write_flash <offset> <binary>`
- **STM Families** (stm32f1, stm32f4, stm32h7, etc.): Uses `st-flash` (from STLINK tools).
  - Command: `st-flash --reset write <binary> <offset>`
- **nRF Families** (nrf52): Uses `nrfjprog` (from Nordic Command Line Tools).
  - Command: `nrfjprog -f <family>52 --program <binary> --sectorerase --reset`

**Note:** You must have the corresponding flashing tool installed and available in your system `PATH` to use the `--flash` argument for the respective hardware family.

---

## End-to-End Payload Encryption (E2EE)

The Toobloader natively enforces confidentiality and IP-protection via **ChaCha20-256 stream encryption**. Firmware payloads are encrypted on the host and decrypted in-flight by the bootloader during the Over-The-Air (OTA) verification phase.

### Built-in Tooling (`toobcrypt`)

When building standalone, you can automatically encrypt the output binary:

1. **Option 1 (.env)**: Create a `.env` file in the `toobloader` directory and define `TOOBLOADER_FEK=<64-char-hex-key>`. The build script will automatically detect and use it.
2. **Option 2 (CLI)**: Explicitly pass the key via `--encrypt <64-char-hex-key>`.
3. **Option 3 (Global)**: Build systems (like `rpwt`) can export the environment variable `TOOBLOADER_FEK` before launching the build.

This zero-dependency approach generates a `.bin.encrypted` file mathematically guaranteed to align with the IETF RFC 7539 specifications, which the microcontrollers decrypt natively using their secure eFuse keys.

---

## Anti-Brick OTA Architecture (Slot Swapping)

Toobloader employs a deterministic, **power-outage-safe A/B Slot Swapping** logic to prevent device bricking during OTA updates. This ensures the device always boots into a valid, cryptographically verified state.

1. **Passive Download**: The Repowatt-OS downloads the new encrypted firmware in the background and writes it safely into **Slot B**.
2. **Reboot Flagging**: The OS sets a boot magic flag in the Triple Modular Redundant (TMR) boot sector indicating a pending update and reboots.
3. **Bootloader Verification**: The Toobloader detects the flag, dynamically decrypts Slot B in 1024-byte chunks, and verifies the Ed25519 signature against the hardware `ROOT_KEY`. It also enforces **Anti-Rollback Protection** by comparing the payload's `version` against a persistent Monotonic Counter.
4. **Atomic Swap**: If the signature and version match, the Toobloader carefully erases block-by-block and streams the decrypted plaintext into **Slot A**. The persistent Monotonic Counter is then updated. If a power loss occurs here, the bootloader resumes the copy on the next boot.
5. **Execution**: The boot state is cleared, and Slot A executes.

---

## Hardware Verification & Recovery API

When the Toobloader is flashed to an empty or corrupted chip, its deterministic state machine will fall back to the **Stage 2 Recovery (Panic Firmware)**. Connect a Serial Monitor at **115200 Baud** and press the Reset button. You will see:

```text
=== TOOBLOADER SECURE RECOVERY ===
[RECOVERY] Locked. Awaiting 104-Byte 2FA Token...
```

To unlock the flash and stream a new Kernel, the host must send a **104-Byte 2FA Token** over the Serial/UART connection:

1. **8 Bytes**: UNIX Timestamp (Anti-Replay)
2. **32 Bytes**: DSLC (Device Lock Code - Possession Factor)
3. **64 Bytes**: Ed25519 Signature of `[Timestamp + DSLC]`, signed by the `ROOT_KEY` (Authorization Factor)

Upon successful validation, the bootloader responds with an `ACK` and initiates a standard **XMODEM** (CRC16-CCITT) file transfer to stream a new `kernel.bin` directly into Slot A, followed by a hard reboot.
