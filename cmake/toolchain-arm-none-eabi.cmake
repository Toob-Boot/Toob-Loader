# ==============================================================================
# Toolchain: ARM Cortex-M (STM32, nRF)
# 
# Relevant Specs: 
# - docs/structure_plan.md (Arch-Vendor-Chip Mapping für arm_cortex_m)
# - docs/provisioning_guide.md (Hardware Target Constraints)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. System Definition (Bare-Metal Cross-Compiling)
# ------------------------------------------------------------------------------
# CMAKE_SYSTEM_NAME "Generic" signalisiert CMake, dass wir uns in einem 
# OS-losen Bare-Metal Umfeld befinden.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# ------------------------------------------------------------------------------
# 2. Toolchain Discovery & Paths
# ------------------------------------------------------------------------------
# Prefix für alle Command-Line Tools
set(TOOLCHAIN_PREFIX "arm-none-eabi-")

# Compiler setzen
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})

# Utilities für Binary-Weaving und Analyse (z.B. OSV / P10 Checks)
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}objcopy CACHE INTERNAL "Objcopy tool")
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}objdump CACHE INTERNAL "Objdump tool")
set(CMAKE_SIZE ${TOOLCHAIN_PREFIX}size CACHE INTERNAL "Size tool")

# BUGFIX/GAP: Da wir CMAKE_TRY_COMPILE_TARGET_TYPE auf STATIC_LIBRARY setzen,
# MÜSSEN wir zwingend den ARM-Archiver setzen. Ansonsten nutzt CMake auf machen
# Hosts `/usr/bin/ar` (Host-AR), was bei ARM-Objektdateien sofort zu Inkompatibilitäts-
# Fehlern führt und den CMake-Init crasht!
set(CMAKE_AR ${TOOLCHAIN_PREFIX}ar CACHE INTERNAL "Archiver tool")
set(CMAKE_RANLIB ${TOOLCHAIN_PREFIX}ranlib CACHE INTERNAL "Ranlib tool")
set(CMAKE_STRIP ${TOOLCHAIN_PREFIX}strip CACHE INTERNAL "Strip tool")

# ------------------------------------------------------------------------------
# 3. Compiler Test Bypass (Kritisch für Bare-Metal)
# ------------------------------------------------------------------------------
# Wenn CMake initialisiert wird, testet es den Compiler durch das 
# Erstellen eines Executables (a.out). Da uns an diesem Punkt die 
# Chip-spezifischen Linker-Scripts (flash_layout.ld) fehlen, schlägt das 
# hart fehl. 
# Mit STATIC_LIBRARY sagen wir CMake, dass es beim Test einen Archiv-Build 
# (ar) statt eines Executables bauen soll, was immer funktioniert.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ------------------------------------------------------------------------------
# 4. Architektur-unabhängige Bare-Metal Compiler/Linker Flags
# ------------------------------------------------------------------------------
# NOTE: Chip-spezifische Flags wie "-mcpu=cortex-m4" und "-mthumb" MÜSSEN in 
# der `cmake/toob_hal.cmake` injiziert werden! (Abhängig vom Target).
# NOTE: FPU (Floating Point Unit) Konfiguration ("-mfloat-abi=hard" / "-mfpu=...") 
# muss ebenfalls in der HAL Ebene konfiguriert werden, da ein STM32L4 eine
# fpv4-sp-d16 hat, ein STM32H7 aber evtl. dp-fpu. Fehlt dies, crasht der Linker!

set(TOOB_ARM_C_FLAGS 
    "-ffunction-sections" 
    "-fdata-sections"
    "-fno-common"
    "-fno-builtin"
)

# Newlib-Nano und Nosys Specs (Zero-Allocation / No POSIX Calls)
set(TOOB_ARM_LINK_FLAGS 
    "-Wl,--gc-sections" 
    "--specs=nano.specs" 
    "--specs=nosys.specs"
    "-nostartfiles"
    "-nodefaultlibs"
)

# Listen zu CMake-Strings formatieren
string(REPLACE ";" " " TOOB_ARM_C_FLAGS_STR "${TOOB_ARM_C_FLAGS}")
string(REPLACE ";" " " TOOB_ARM_LINK_FLAGS_STR "${TOOB_ARM_LINK_FLAGS}")

# Initiale Flags an CMake übergeben
set(CMAKE_C_FLAGS_INIT "${TOOB_ARM_C_FLAGS_STR}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${TOOB_ARM_LINK_FLAGS_STR}")
