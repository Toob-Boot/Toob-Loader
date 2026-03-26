# Toobloader Bootloader: Link-Time Mocking (Zero-Code Modification)

## The Problem

Developing and testing cryptographic features (like Ed25519 kernel signature verification or Stage 2 Recovery) requires identical execution relative to the production hardware.

However, repeatedly burning hardware eFuses on physical ESP32 or STM32 ICs during the continuous integration (CI) or testing loops is impossible (eFuses are One-Time-Programmable).

The naive approach is inserting `#ifdef DEV_MODE` macros throughout the hardware abstraction layers (HALs) and core cryptography loops.
**This is strictly prohibited in Toobloader.** It introduces "Architectural Slop" and actively violates NASA P10 coding rules, as the code executed in the test matrix differs from the code executing in production.

## The Solution: GNU LD `--wrap`

Toobloader solves this using the GNU Linker's (GCC LD) `--wrap=symbol` option. This allows us to transparently intercept hardware register reads at link-time without modifying a single line of C code.

### 1. The Pure HAL

In production, files like `bootloader/chip/esp/esp32c6/boot_hal_esp32c6.c` read memory-mapped registers directly.

```c
// boot_hal_esp32c6.c
void boot_hal_get_root_key(uint8_t out_key[32]) {
    // Reads from physical eFuse Register 0x60007050
}
```

### 2. The Mock Implementation

We provide a separate object file `bootloader/mocks/dev_keys.c` that implements a wrapped version of these HAL routines, prefixing the name with `__wrap_`.

```c
// bootloader/mocks/dev_keys.c
void __wrap_boot_hal_get_root_key(uint8_t out_key[32]) {
    // Copies a hardcoded, public 32-byte test key into memory
}
```

### 3. Link-Time Injection (CMake)

When a developer builds the bootloader with the `BOOTLOADER_MOCK_EFUSE=ON` CMake flag, CMake injects the following instructions to the linker:
`-Wl,--wrap=boot_hal_get_root_key`

**The result:**
When `signature_verify.c` or `panic_main.c` attempts to call `boot_hal_get_root_key()`, the GNU Linker intercepts the symbol resolution. Instead of linking to the physical eFuse implementation in `boot_hal_esp32c6.o`, it violently routes the execution pointer into our `__wrap_boot_hal_get_root_key()` function located in SRAM.

### Summary

- **Zero `ifdef` pollution.** The core C code remains absolutely identical between Development and Production.
- **100% NASA P10 Compliant.**
- **Hardware Isolation.** The development keys are stored in a separate directory (`mocks/`) and are completely excluded from production binary builds.
