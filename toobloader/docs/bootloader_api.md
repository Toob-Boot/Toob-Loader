# Toobloader Architecture & Internal API

The Toobloader is an immutable, mathematically perfect bootloader (Stage 0 -> Stage 1) designed for NASA Power of 10 compliance and mission-critical reliability. This document outlines the core architecture, the deterministic state machine, and the Stage 2 Recovery API.

## Bootloader Flow State Machine

The boot process is structured as a deterministic state machine without nested loops or recursion, executed within `boot_main.c`. It runs in a strict sequence:

1. **`BOOT_STATE_INIT`**: Native hardware initialization (setting up clocks, disabling watchdogs, or configuring the MMU if necessary) via the `boot_hal_init()` abstraction.
2. **`BOOT_STATE_LOAD_TMR`**: Loading the Triple Modular Redundant (TMR) Boot State. The bootloader parses three redundant sectors to determine the active Kernel slot, voting on the majority to guarantee resilience against bit-rot or random power cycling.
3. **`BOOT_STATE_CHECK_LOOP`**: Linear evaluation of the candidate slots. For each slot (Slot A, Slot B), the system invokes the cryptographic validation pipeline.
4. **`BOOT_STATE_EVALUATE`**: Slot signature verification (Ed25519) and CRC bounds validation via `boot_validate_slot`. If a slot is completely valid, it is marked as the target.
5. **`BOOT_STATE_JUMP`**: Disabling interrupts, resetting peripherals, and securely jumping to the validated Kernel payload's entry point.
6. **`BOOT_STATE_RECOVERY`**: If all slots are invalid, empty, or corrupted, the system falls back to the Stage 2 Recovery (Panic Firmware).
7. **`BOOT_STATE_HALT`**: Absolute failure fallback. Indefinite hardware looping.

## A/B Partitioning & Rollback (OTA)

The Toobloader natively provides full resilience against corrupted Over-The-Air (OTA) updates using a dual-slot architecture:

- `Slot A` (e.g., `0x00008000`)
- `Slot B` (e.g., `0x00028000`)

Toobloader uses a **Triple Modular Redundant (TMR)** boot state array to persistently remember which slot is currently "active".

**How It Enables Safe OTA Updates:**
The Bootloader's architecture empowers any Operating System, firmware, or payload to perform zero-risk updates in the field:

1. **Background Deployment**: While running from the active slot (e.g., Slot A), the OS/payload downloads an update in the background and flashes it into the _passive_ slot (Slot B).
2. **Commit & Reboot**: The OS then writes a new TMR state setting the active target to Slot B and reboots the hardware.
3. **Cryptographic Gateway**: Upon boot, the Toobloader reads the TMR state and begins its strict cryptographic validation (Stage 4) of the newly updated Slot B.
4. **Anti-Rollback Protection**: The Bootloader checks the payload's `version` against the hardware Monotonic Counter stored in the TMR state. If an attacker attempts to downgrade the device to an older, vulnerable firmware version, the validation instantly fails.
5. **Automated Rollback**: If the new OTA image is mathematically corrupted, compromised, crashes during download, fails the Anti-Rollback check, or is missing its valid Ed25519 signature, the validation instantly fails.
6. **Recovery**: The Bootloader detects the failure, gracefully prints `[BOOT] ROLLBACK triggered`, and automatically falls back to validating and booting the previously known-good slot (Slot A).

This mechanism ensures the hardware is virtually un-brickable by faulty software updates. Only if _both_ Slot A and Slot B are entirely destroyed will the Toobloader trap into the Emergency XMODEM Recovery (Stage 6).

## Internal APIs (`boot_hal`)

To maintain zero runtime dependencies on vendor SDKs, the Toobloader relies on a narrow Hardware Abstraction Layer defined in `include/boot_arch.h`.

| API Function              | Purpose                 | Implementation Requirement                           |
| :------------------------ | :---------------------- | :--------------------------------------------------- |
| `boot_hal_init()`         | Hardware Initialization | Set up vector tables, clocks, and disable watchdogs. |
| `boot_flash_read()`       | Raw Flash Read          | Map to vendor ROM or MMIO registers.                 |
| `boot_flash_write()`      | Raw Flash Write         | Must handle alignment/boundaries natively.           |
| `boot_flash_erase()`      | Raw Flash Erase         | Erase 4KB sectors dynamically.                       |
| `boot_hal_get_root_key()` | Root of Trust           | Extract 32-Byte Ed25519 PubKey (Usually eFuses).     |
| `boot_hal_get_dslc()`     | Physical Presence Token | Extract 32-Byte Device Lock Code.                    |

### Hardware Mocking (Link-Time Injection)

During development, repeatedly burning One-Time-Programmable (OTP) eFuses or dealing with external Secure Elements is impractical. Toobloader handles this uniquely:

Instead of inserting `#ifdef DEV_MODE` blocks (which violate NASA P10 functional purity and introduce "Architectural Slop"), Toobloader uses the **GNU Linker (`-Wl,--wrap=symbol`)**.

- A developer creates a mock implementation (e.g., `__wrap_boot_hal_get_root_key` in `mocks/dev_keys.c`).
- When CMake builds the bootloader with `-DTOOBLOADER_MOCK_EFUSE=ON`, the Linker intercepts any call to `boot_hal_get_root_key` and violently redirects the execution pointer to the mock function in fast SRAM.
- **The Result**: The core C logic (`boot_validate.c`, `panic_main.c`) compiles identical to production, but reads dummy developer-keys from RAM instead of blowing real silicon eFuses.

### Developer Mode (Signature Bypass)

In addition to mocking hardware secrets, Toobloader features a built-in `DEV_MODE`. During rapid iteration, continuously signing kernel payloads with Ed25519 keys can be tedious.
By configuring `--dev-mode` or `-DTOOBLOADER_DEV_MODE=ON`, the Linker wraps `boot_verify_signature` and violently intercepts it with a mock policy (`dev_policy.c`).
This results in the bootloader skipping the mathematical verification entirely and forcing a success return, allowing an unsigned kernel to boot while leaving the actual production C validation code untouched and fully audited.

## Stage 2 Recovery (Panic Firmware)

If the Kernel is completely missing or mathematically corrupted, the bootloader traps into `panic_main()`. This triggers an offline, physical recovery mode designed for extreme field conditions.

### Hardware Recovery Button

Because Production environments often prevent access to the internal ROM Bootloader (to secure the device against malicious reflashing), the Toobloader supports a dedicated Hardware Recovery Feature.

By dynamically associating a pin through the build system (e.g., `--rec-pin 0`), the Bootloader checks the physical electrical level of this specific GPIO _during the very first microsecond of the boot state machine_.

- **If pressed:** The bootloader instantly bypasses the A/B slot evaluation and drops into the Stage 2 Recovery XMODEM Listener.
- **Production Safety:** This pin logic is completely data-driven via CMake macros and MMIO (Memory-Mapped I/O) bare-metal reads. It does not load external SDKs, guaranteeing zero performance impact and 100% NASA P10 compliance. Furthermore, it is **fully available in Production**, ensuring that even an entirely bricked product in the field can be reset to factory condition via a discrete physical button press (like a router reset button).

### The USB/UART Protocol

1. **Passive Wait**: The bootloader spins on `boot_uart_getc_timeout()`, awaiting exactly **104 Bytes**.
2. **The 2FA Token**:
   - `[0-7]`: 8-Byte UNIX Timestamp (Anti-Replay).
   - `[8-39]`: 32-Byte DSLC (Device Lock Code) proving physical possession.
   - `[40-103]`: 64-Byte Ed25519 Signature verifying the Timestamp and DSLC against the hardware `ROOT_KEY`.
3. **The XMODEM Stream**: Upon validation, the bootloader transmits an `ACK` and awaits an XMODEM-CRC transfer.
   - Flashes data in real-time, handling 4KB sector erasure dynamically.
   - Uses an `O(1)` memory overhead CRC16-CCITT algorithm for packet validation.
   - Once the EOT (End of Transmission) is received, the system reboots natively into the newly flashed image.
