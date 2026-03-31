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
# 5. Final Executable & Post-Build Hooks
# ------------------------------------------------------------------------------

# 5.1 CMAKE_BUILD_TYPE Build Fallback Logic
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type selected, defaulting to Release.")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

# 5.2 Define the final bootloader Target (toob_stage1)
add_executable(toob_stage1 core/boot_main.c)

# 5.3 Architektur-Spezifische P10 Limitierungen und Globale Libraries
toob_apply_strict_flags(toob_stage1 TRUE)
target_link_libraries(toob_stage1 PRIVATE toob_core)

if(TARGET toob_chip)
    target_link_libraries(toob_stage1 PRIVATE toob_chip)
endif()

if(TARGET toob_crypto_upstream)
    target_link_libraries(toob_stage1 PRIVATE toob_crypto_upstream)
endif()

# 5.4 Linker Script Integration
if(NOT TOOB_ARCH STREQUAL "host")
    target_link_options(toob_stage1 PRIVATE -T${CMAKE_BINARY_DIR}/generated/flash_layout.ld)

    # 5.5 Firmware Image Generation (.elf -> .bin)
    add_custom_command(
        TARGET toob_stage1 POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_stage1> $<TARGET_FILE_DIR:toob_stage1>/toob_stage1.bin
        COMMENT "Generating flashable RAW binary toob_stage1.bin..."
    )
endif()

# ------------------------------------------------------------------------------
# 6. Software Integration Testing / SIL (TODO)
# ------------------------------------------------------------------------------
# TODO: [Phase 4 / M-SANDBOX] HIL / SIL Unit Testing via toob-test-runner
