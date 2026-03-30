cmake_minimum_required(VERSION 3.16)
project(toobloader C ASM)

# CMake build for the Toobloader
# This defines the Stage 1 immutable bootloader.

# Determine the chip architecture from the environment or parent build
if(NOT DEFINED BOOTLOADER_CHIP_FAMILY)
    set(BOOTLOADER_CHIP_FAMILY "esp32") # Default for testing
endif()

# We use add_library/add_executable here depending on the overarching
# build system. For now, we collect the source files.
set(BOOTLOADER_SRC
    src/boot_main.c
    src/boot_state.c
    src/boot_swap.c
    src/boot_validate.c
    src/common/rp_stdlib.c
    src/common/hal_common.c
    third_party/compact25519/src/compact_ed25519.c
    third_party/chacha20/chacha20.c
)

# Determine the architecture layer
if(NOT DEFINED BOOTLOADER_ARCH)
    set(BOOTLOADER_ARCH "xtensa") # Default
endif()

# -----------------------------------------------------------------------------
# Dynamic Link-Time Feature Gating (Hardware Abstraction Layer)
# The Toobloader CLI passes BOOTLOADER_CHIP_FAMILY (e.g., "esp32", "stm32f4").
# We dynamically locate the chip support folder using GLOB_RECURSE
# so it supports both depth=2 (chip/esp) and depth=3 (chip/esp/esp32c3).
# -----------------------------------------------------------------------------

file(GLOB_RECURSE BOOT_HAL_FILE "chip/*/boot_hal_${BOOTLOADER_CHIP_FAMILY}.c")

if(BOOT_HAL_FILE)
    list(GET BOOT_HAL_FILE 0 FIRST_SRC)
    get_filename_component(BOOT_CHIP_DIR ${FIRST_SRC} DIRECTORY)
    
    # Find all C files together in that specific chip directory
    file(GLOB CHIP_SRC "${BOOT_CHIP_DIR}/*.c")
    list(APPEND BOOTLOADER_SRC ${CHIP_SRC})
    
    # NEW: Automatically link the Vendor Common Layer (e.g., chip/esp/common)
    get_filename_component(VENDOR_DIR "${BOOT_CHIP_DIR}" DIRECTORY)
    get_filename_component(VENDOR_NAME "${VENDOR_DIR}" NAME)
    
    file(GLOB VENDOR_COMMON_SRC "${VENDOR_DIR}/common/*.c")
    if (VENDOR_COMMON_SRC)
        list(APPEND BOOTLOADER_SRC ${VENDOR_COMMON_SRC})
        message(STATUS "[Bootloader] Linked Vendor Common Layer from ${VENDOR_DIR}/common")
    endif()
    
    if (VENDOR_NAME STREQUAL "stm")
        list(APPEND BOOTLOADER_INCLUDES "${VENDOR_DIR}/include/cmsis_core")
        list(APPEND BOOTLOADER_INCLUDES "${BOOT_CHIP_DIR}/include")
        message(STATUS "[Bootloader] Linked Native Hermetic CMSIS Directories")
    endif()
    
    # Capitalize the family name for the C-preprocessor definition
    string(TOUPPER "${BOOTLOADER_CHIP_FAMILY}" FAMILY_UPPER)
    add_compile_definitions(BOOT_PLATFORM_${FAMILY_UPPER})
    
    message(STATUS "[Bootloader] Dynamically linked HAL for chip family: ${BOOTLOADER_CHIP_FAMILY} from ${BOOT_CHIP_DIR}")
else()
    message(FATAL_ERROR "[Bootloader] Unsupported chip family: ${BOOTLOADER_CHIP_FAMILY}. No boot_hal_${BOOTLOADER_CHIP_FAMILY}.c found.")
endif()

# -----------------------------------------------------------------------------
# Dynamic Link-Time Architecture Gating
# -----------------------------------------------------------------------------

set(BOOT_ARCH_DIR "arch/${BOOTLOADER_ARCH}")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${BOOT_ARCH_DIR}")
    file(GLOB ARCH_SRC "${BOOT_ARCH_DIR}/*.c")
    list(APPEND BOOTLOADER_SRC ${ARCH_SRC})
    message(STATUS "[Bootloader] Dynamically linked Arch layer: ${BOOTLOADER_ARCH}")
else()
    message(FATAL_ERROR "[Bootloader] Unsupported architecture: ${BOOTLOADER_ARCH}. Directory '${BOOT_ARCH_DIR}' not found.")
endif()

# -----------------------------------------------------------------------------
# Link-Time Development Mocks (eFuse Simulation)
# -----------------------------------------------------------------------------

option(BOOTLOADER_MOCK_EFUSE "Enable Link-Time Mocking of Hardware eFuses" OFF)

if(BOOTLOADER_MOCK_EFUSE)
    list(APPEND BOOTLOADER_SRC "mocks/dev_keys.c")
    message(STATUS "[Bootloader] WARNING: Link-Time eFuse Mocking ENABLED (-Wl,--wrap). Development keys in use.")
endif()

# -----------------------------------------------------------------------------
# Link-Time Developer Mode (Signature Bypass)
# -----------------------------------------------------------------------------

option(TOOBLOADER_DEV_MODE "Enable Link-Time Signature Bypass for Development" OFF)

if(TOOBLOADER_DEV_MODE)
    list(APPEND BOOTLOADER_SRC "mocks/dev_policy.c")
    message(STATUS "[Bootloader] WARNING: Developer Mode ENABLED (-Wl,--wrap). Signatures are NOT enforced!")
endif()

add_library(core_bootloader STATIC ${BOOTLOADER_SRC})

# Provide the Recovery Partition Address if configured
if(DEFINED BOOT_RECOVERY_ADDR)
    target_compile_definitions(core_bootloader PRIVATE RECOVERY_SLOT_ADDR=${BOOT_RECOVERY_ADDR})
endif()
if(DEFINED BOOTLOADER_EXACT_CHIP)
    target_compile_definitions(core_bootloader PRIVATE BOOTLOADER_EXACT_CHIP="${BOOTLOADER_EXACT_CHIP}")
endif()

target_include_directories(core_bootloader PRIVATE include)
if (BOOTLOADER_INCLUDES)
    target_include_directories(core_bootloader SYSTEM PRIVATE ${BOOTLOADER_INCLUDES})
endif()

# -----------------------------------------------------------------------------
# Golden Perfection: Compiler-Level Resilience (NASA P10 Rule 10 & Stack Canaries)
# -----------------------------------------------------------------------------
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(core_bootloader PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -O2
        -fstack-protector-strong
    )
    if(BOOTLOADER_ARCH STREQUAL "xtensa")
        target_compile_options(core_bootloader PRIVATE -mlongcalls)
    elseif(BOOTLOADER_ARCH STREQUAL "arm")
        target_compile_options(core_bootloader PRIVATE -mthumb)
        if(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32f1")
            target_compile_options(core_bootloader PRIVATE -mcpu=cortex-m3)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32f4" OR BOOTLOADER_CHIP_FAMILY MATCHES "^stm32g4")
            target_compile_options(core_bootloader PRIVATE -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32h7")
            target_compile_options(core_bootloader PRIVATE -mcpu=cortex-m7 -mfloat-abi=hard -mfpu=fpv5-d16)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32u5")
            target_compile_options(core_bootloader PRIVATE -mcpu=cortex-m33 -mfloat-abi=hard -mfpu=fpv5-sp-d16)
        endif()
    endif()
endif()

# -----------------------------------------------------------------------------
# Standalone Bootloader Executable (Optional)
# -----------------------------------------------------------------------------
option(BOOTLOADER_STANDALONE "Build a standalone bootable binary" OFF)

if(BOOTLOADER_STANDALONE)
    # 1. Standalone Executable (Entry vector is now inside core_bootloader lib)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/standalone_dummy.c" "")
    add_executable(toobloader.elf "${CMAKE_CURRENT_BINARY_DIR}/standalone_dummy.c")
    target_link_libraries(toobloader.elf -Wl,--whole-archive core_bootloader -Wl,--no-whole-archive)
    
    if(BOOTLOADER_ARCH STREQUAL "arm")
        target_compile_options(toobloader.elf PRIVATE -mthumb)
        if(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32f1")
            target_compile_options(toobloader.elf PRIVATE -mcpu=cortex-m3)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32f4" OR BOOTLOADER_CHIP_FAMILY MATCHES "^stm32g4")
            target_compile_options(toobloader.elf PRIVATE -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32h7")
            target_compile_options(toobloader.elf PRIVATE -mcpu=cortex-m7 -mfloat-abi=hard -mfpu=fpv5-d16)
        elseif(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32u5")
            target_compile_options(toobloader.elf PRIVATE -mcpu=cortex-m33 -mfloat-abi=hard -mfpu=fpv5-sp-d16)
        endif()
    endif()
    
    # 2. Dynamic Linker Script Loader
    if (VENDOR_NAME STREQUAL "stm")
        if(NOT DEFINED BOOT_FLASH_SIZE OR NOT DEFINED BOOT_RAM_SIZE)
            message(FATAL_ERROR "[Bootloader] BOOT_FLASH_SIZE and BOOT_RAM_SIZE must be defined for STM32 targets.")
        endif()
        
        set(STM_LD_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/stm32_generated.ld")
        file(WRITE ${STM_LD_SCRIPT} "
/* Dynamically generated Linker Script for STM32 */
MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = ${BOOT_FLASH_SIZE}
  RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = ${BOOT_RAM_SIZE}
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

ENTRY(boot_startup_vector)

SECTIONS
{
  .text : {
    KEEP(*(.isr_vector))
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } >FLASH

  .data : {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } >RAM AT> FLASH
  
  _sidata = LOADADDR(.data);

  .bss : {
    . = ALIGN(4);
    _bss_start = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _bss_end = .;
  } >RAM
}
")
        target_link_options(toobloader.elf PRIVATE "-T${STM_LD_SCRIPT}")
        message(STATUS "[Bootloader] Generated Dynamic Linker Map for STM32: ${BOOT_FLASH_SIZE} Flash, ${BOOT_RAM_SIZE} RAM")
    else()
        # Auto-glob all .ld files from the chip's private ld/ directory.
        file(GLOB CHIP_LD_SCRIPTS "${BOOT_CHIP_DIR}/ld/*.ld")
        
        if (NOT CHIP_LD_SCRIPTS)
            message(FATAL_ERROR "[Bootloader] No linker scripts (.ld) found in ${BOOT_CHIP_DIR}/ld/")
        endif()

        foreach(LD_SCRIPT ${CHIP_LD_SCRIPTS})
            target_link_options(toobloader.elf PRIVATE "-T${LD_SCRIPT}")
            message(STATUS "[Bootloader] Linked Hardware Memory Map: ${LD_SCRIPT}")
        endforeach()
    endif()

    # 3. Core Native Executable Flags
    target_link_options(toobloader.elf PRIVATE
        "-nostdlib"
        "-Wl,--gc-sections"
    )
    if(BOOTLOADER_ARCH STREQUAL "arm")
        target_link_options(toobloader.elf PRIVATE "-mthumb")
        if(BOOTLOADER_CHIP_FAMILY MATCHES "^stm32f4")
            target_link_options(toobloader.elf PRIVATE "-mcpu=cortex-m4" "-mfloat-abi=hard" "-mfpu=fpv4-sp-d16")
        endif()
    endif()

    if (BOOTLOADER_MOCK_EFUSE)
        target_link_options(toobloader.elf PRIVATE "-Wl,--wrap=boot_hal_get_root_key" "-Wl,--wrap=boot_hal_get_dslc" "-Wl,--wrap=boot_hal_get_firmware_key")
    endif()

    if (TOOBLOADER_DEV_MODE)
        target_link_options(toobloader.elf PRIVATE "-Wl,--wrap=boot_verify_signature")
    endif()

    # 4. Post-build Binary Generation
    if (VENDOR_NAME STREQUAL "esp")
        add_custom_command(TARGET toobloader.elf POST_BUILD
            COMMAND python -m esptool --chip ${BOOTLOADER_CHIP_FAMILY} elf2image $<TARGET_FILE:toobloader.elf>
            COMMENT "Generating toobloader.bin using esptool..."
        )
    elseif(VENDOR_NAME STREQUAL "stm" OR VENDOR_NAME STREQUAL "nrf")
        add_custom_command(TARGET toobloader.elf POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toobloader.elf> toobloader.bin
            COMMENT "Generating toobloader.bin using objcopy..."
        )
    endif()
endif()
