# Toobloader Chip & Architecture Expansion Guide

Repowatt-OS is designed for extreme portability. Adding support for a new microcontroller (e.g., STM32F4, nRF52) or a new architecture requires extending a few key directories and configuration files.

This guide explains the exact anatomy of a chip integration and where code needs to go.

---

## 1. The 5 Pillars of a Chip Integration

To perfectly integrate a new chip `XYZ99`, you must satisfy five distinct areas in the `toobloader` tree:

1. **`targets.json` (The Metadata)**
2. **`arch/` (The CPU Architecture Abstraction)**
3. **`chip/` (The Hardware Abstraction Layer & Startup)**
4. **`ld/` (The Memory Map / Linker Scripts)**
5. **`CMakeLists.txt` (The Standalone Build Logic)**

---

## Pillar 1: Configuration (`targets.json`)

Before anything compiles, the build system needs to know the chip exists. Open `toobloader/scripts/targets.json` and register your chip under the `targets` object.

**Example for a theoretical `stm32f407` chip:**

```json
"stm32f407": {
  "family": "stm",
  "arch": "arm",
  "compiler": "arm-none-eabi-gcc",
  "flash_offset": "0x08000000",
  "recovery_pin_rules": {
    "supported": true,
    "max_pin": 144,
    "blacklist": [13, 14]
  }
}
```

---

## Pillar 2: Architecture (`arch/<arch_name>`)

The architecture layer houses code that applies to _all_ chips using a specific CPU core (e.g., all ARM Cortex-M4 chips, or all RISC-V cores), regardless of the vendor. Examples include context switching, stack initialization, or assembly-level CPU halts.

**Path:** `arch/arm/` (if targeting `arch: "arm"`)
**Required Files:** Any `.c` or `.S` files placed in this folder are automatically compiled thanks to the dynamic glob in `CMakeLists.txt`:

```cmake
set(BOOT_ARCH_DIR "arch/${BOOTLOADER_ARCH}")
file(GLOB ARCH_SRC "${BOOT_ARCH_DIR}/*.c")
```

If the architecture folder (`arch/arm/`) already exists (because another chip uses it), you likely don't need to add anything here!

---

## Pillar 3: Hardware Abstraction Layer (`chip/`)

Repowatt-OS employs a highly optimized **3-Tier HAL Architecture** to absolutely minimize the boilerplate required to port a new chip.

### Tier 1: Global Common Layer (`src/common/hal_common.c`)

This layer provides the mathematical backbone for **all chips**. You do not need to rewrite any of this. It includes:

- **Universal Entry Vector** (`boot_startup_vector`): Automatically zeroes BSS and jumps to standard C execution. No `start_<chip>.c` assembly files are needed!
- **NASA P10 Timeouts**: Safe waiting loops for UART so the bootloader never hangs.
- **Weak Fallbacks**: Safe `<stdbool.h>` default returns (e.g., returning `false` for the recovery pin if your chip doesn't have one).

### Tier 2: Vendor Common Layer (`chip/<vendor>/common/`)

Manufacturers often reuse identical internal ROM functions across massive chip families (e.g., ESP32 and ESP32-C6 use the exact same ROM UART functions).
If you put `.c` files in `chip/stm/common/`, CMake will automatically discover and link them to **all** STM32 chips, eliminating duplicated code across the vendor's line.

### Tier 3: Chip Specific Layer (`chip/<vendor>/<chip>/boot_hal_<chip>.c`)

This is the **only** file you legally must provide. It contains the absolute, bare-metal hardware primitives (Memory Mapped Registers) unique to your exact silicon die.

**Example Path:** `chip/stm/stm32f407/boot_hal_stm32f407.c`

```c
#include "boot_hal_api.h"
#include <stdint.h>

// 1. Primitive for the Generic UART Iterator
void boot_hal_uart_tx_char(char c) {
    // STM32 specific UART transmission logic
}

// 2. Primitive for the Generic Recovery Pin Logic (Optional)
uint8_t boot_hal_gpio_get_level(uint32_t pin) {
    // STM32 GPIO Read Array
    return (GPIOA->IDR & (1 << pin)) ? 1 : 0;
}

// 3. Infinite CPU Sleep
void boot_arch_halt(void) {
    while(1) { __asm__ volatile("wfi"); }
}
```

_Note: CMake automatically finds this file based on the `targets.json` chip name. The Global Common Layer (`hal_common.c`) will automatically link against your primitives!_

---

## Pillar 4: Linker Scripts (`ld/`) & Memory Maps

The build system maps the standalone bootloader into the correct hardware memory addresses. Repowatt-OS supports two approaches:

### A: Dynamic Generation (STM32, nRF)

For standard ARM Cortex-M architectures with continuous memory blocks, the `CMakeLists.txt` automatically generates the linker map on-the-fly! You simply define the `flash_size` and `ram_size` in `targets.json`.
You **do not** need to provide an `.ld` file manually.

### B: Static ROM Maps (ESP32)

For chips with fragmented memory or pre-flashed ROM functions (like Espressif), you must copy those `.rom.ld` files directly into your chip's `ld/` directory. Do not point to external installations. This guarantees the bootloader repo stays 100% self-contained.

**Path:** `chip/<family>/<chip_name>/ld/`
**Example:** `chip/esp/esp32/ld/esp32.ld`

---

## Pillar 5: Modifying CMakeLists.txt (Not Needed!)

Thanks to the **Universal Dynamic CMake Architecture**, adding a new chip does **not** require modifying the core `toobloader/CMakeLists.txt`.

The build system automatically parses your `targets.json`, dynamically instantiates the correct `Toolchain` class (see the Toolchain Expansion Guide), maps the right `arch/` layer, includes your `boot_hal_<chip>.c`, and either generates the `.ld` memory map dynamcially or auto-globs the static `.ld` scripts inside your chip's private `ld/` directory.

Your environment is guaranteed to recompile purely from its own source tree. No hardcoded paths. No `if(arch == xtensa)`.

---

## Summary of Expansion

1. Read **0. Prerequisites & Environment Setup** in `toolchain_expansion_guide.md`
2. Register in `scripts/targets.json` (add `ram_size` / `flash_size` if using dynamic mapping)
3. Implement your Toolchain class (if creating a new Family, see `toolchain_expansion_guide.md`)
4. Create `arch/<arch_name>/` (if new architecture)
5. Create `chip/<family>/<chip>/boot_hal_<chip>.c`
6. Create `chip/<family>/<chip>/ld/` ONLY if your chip uses fragmented Static ROM maps.
7. Build! (No CMake modifications needed).

---
