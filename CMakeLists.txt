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
