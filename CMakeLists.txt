cmake_minimum_required(VERSION 3.20)
project(Toob-Boot LANGUAGES C)

# ------------------------------------------------------------------------------
# 1. Compiler Standards & Hardening
# ------------------------------------------------------------------------------
# We enforce absolutely strict C17 as detailed in concept_fusion.md
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The "DO NOT SHIP SLOP" Compiler Policy
add_compile_options(
    -Wall -Wextra -Werror -Wconversion -Wshadow
    -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
    -ffunction-sections -fdata-sections
)

# ------------------------------------------------------------------------------
# 2. Target Platform Control
# ------------------------------------------------------------------------------
if(NOT DEFINED TOOB_TARGET)
    message(FATAL_ERROR "[Toob-Boot] No TARGET defined! Use -DTOOB_TARGET=sandbox|esp32s3|stm32l4")
endif()

message(STATUS "[Toob-Boot] Building for Target: ${TOOB_TARGET}")

# TODO: Include proper toolchains depending on target
if(TOOB_TARGET STREQUAL "sandbox")
    # Host Environment
    add_compile_definitions(TOOB_SANDBOX=1)
endif()

# ------------------------------------------------------------------------------
# 3. Source Assembly
# ------------------------------------------------------------------------------
include_directories(core/include)
include_directories(hal/include)

# The generic core (Layer 3)
set(CORE_SOURCES
    core/src/boot_main.c
    # core/src/boot_journal.c
    # core/src/boot_merkle.c
)

# ------------------------------------------------------------------------------
# 4. Binary Generation
# ------------------------------------------------------------------------------
add_executable(toob_boot_${TOOB_TARGET} ${CORE_SOURCES})

# Dead code elimination for the linker
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(toob_boot_${TOOB_TARGET} PRIVATE -Wl,--gc-sections)
endif()
