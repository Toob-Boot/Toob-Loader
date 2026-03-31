# ==============================================================================
# Toob-Boot Master Build Script
# 
# Relevant Specs: 
# - docs/structure_plan.md (Global C-flags, Malloc limits, Project Structure)
# - docs/dev_plan.md (M-BUILD Setup, P10 Verification)
# - docs/testing_requirements.md (P10 Verification, Zero Allocation)
# ==============================================================================
cmake_minimum_required(VERSION 3.22)
project(toob-boot C ASM)

# ------------------------------------------------------------------------------
# 1. Manifest Compiler Bridge (Auto-Generated Device Topology)
# ------------------------------------------------------------------------------
# Try to include the auto-generated CMake config from the manifest compiler.
# If it doesn't exist (e.g. standalone sandbox run), fallback to testing defaults.
if(EXISTS "${CMAKE_BINARY_DIR}/generated/toob_config.cmake")
    include("${CMAKE_BINARY_DIR}/generated/toob_config.cmake")
else()
    message(STATUS "No generated toob_config.cmake found. Falling back to Sandbox mode.")
    set(TOOB_ARCH "host")
    set(TOOB_VENDOR "sandbox")
    set(TOOB_CHIP "sandbox")
    
    # In Sandbox mode, we optionally load the host toolchain if no cross-compiler is set
    if(NOT CMAKE_TOOLCHAIN_FILE)
        set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/cmake/toolchain-host.cmake")
    endif()
endif()

# ------------------------------------------------------------------------------
# 2. Global Safety Limits (P10 / NASA Standards)
# ------------------------------------------------------------------------------
# Enforce C17 Strict
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Zero-Allocation: Absolute Ban of malloc/free/realloc
add_compile_definitions(
    malloc=MALLOC_FORBIDDEN 
    free=FREE_FORBIDDEN
    realloc=REALLOC_FORBIDDEN
    calloc=CALLOC_FORBIDDEN
)

# ------------------------------------------------------------------------------
# 3. Security & Anti-Slop Compiler Flags
# ------------------------------------------------------------------------------
# Function to apply modular, ultra-strict P10 flags to all our proprietary targets.
# This prevents poisoning third-party libraries (like 'zcbor' oder 'monocypher')
# and allows us to conditionally disable stack-protector (e.g. for Stage 0).
function(toob_apply_strict_flags TARGET_NAME ALLOW_STACK_PROTECTOR)
    target_compile_options(${TARGET_NAME} PRIVATE
        -Wall 
        -Wextra 
        -Werror 
        -Wconversion 
        -Wshadow
        -Wformat=2 
        -Wstrict-prototypes 
        -Wmissing-prototypes
        -fno-common
        # Dead Code Elimination (linker will gc later)
        -ffunction-sections 
        -fdata-sections
    )
    
    # WICHTIG: Link options must be applied to the final executable normally,
    # but applying them to libraries ensures they are tracked safely.
    target_link_options(${TARGET_NAME} PRIVATE
        -Wl,--gc-sections
    )

    if(ALLOW_STACK_PROTECTOR)
        target_compile_options(${TARGET_NAME} PRIVATE -fstack-protector-strong)
    endif()
endfunction()

# ------------------------------------------------------------------------------
# 4. Modular Assembly (Submodules)
# ------------------------------------------------------------------------------
# Here we assemble the architecture. The individual files contain the actual 
# implementation plans for the architecture -> vendor -> chip layers, core, etc.

include(cmake/toob_hal.cmake)
include(cmake/toob_core.cmake)
include(cmake/toob_crypto.cmake)
include(cmake/toob_stage0.cmake)
include(cmake/toob_libtoob.cmake)

# ------------------------------------------------------------------------------
# 5. Final Executable & Post-Build Hooks (TODO)
# ------------------------------------------------------------------------------
# TODO: [Phase 3 / M-BUILD-Post] Include directory for generated headers
#       Add include_directories(${CMAKE_BINARY_DIR}/generated) so that features
#       like '#include "chip_config.h"' can be resolved by the C-Compiler!

# TODO: [Phase 3 / M-BUILD-Post] Auto-Generation Custom Target
#       Add add_custom_command() to automatically invoke 'toob-manifest compile'
#       if the generated headers or toob_config.cmake are missing/outdated.

# TODO: [Phase 3 / M-BUILD-Post] Define CMAKE_BUILD_TYPE fallback logic
#       Set a default build type (Release/Debug) if none is provided via CLI.

# TODO: [Phase 3 / M-BUILD-Post] Define the final bootloader executable target (toob_stage1)
#       This will link against toob_core, toob_chip, and toob_crypto.
#       Example: add_executable(toob_stage1 src/boot_main.c)

# TODO: [Phase 3 / M-BUILD-Post] Linker script integration
#       Apply the manifest-compiler generated flash_layout.ld to the final executable:
#       target_link_options(toob_stage1 PRIVATE -T${CMAKE_BINARY_DIR}/generated/flash_layout.ld)

# TODO: [Phase 3 / M-BUILD-Post] Firmware Image Generation (.elf -> .bin/.hex)
#       Add custom commands to run arm-none-eabi-objcopy or esptool.py (elf2image)
#       to generate the raw binaries required for flashing.

# ------------------------------------------------------------------------------
# 6. Software Integration Testing / SIL (TODO)
# ------------------------------------------------------------------------------
# TODO: [Phase 4 / M-SANDBOX] Enable testing and add test subdirectories for
#       Link-Time Mocking environment validation.
#       Example: enable_testing() 
#                add_subdirectory(test)

# TODO: [Phase 4 / M-SANDBOX] Link-Time Mocking Flags
#       Apply linker flags like '-Wl,--wrap=flash_hal_read' globally for the test 
#       executable to wrap hardware calls into test/mocks/mock_flash.c
