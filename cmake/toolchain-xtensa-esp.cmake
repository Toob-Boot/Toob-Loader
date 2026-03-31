# ==============================================================================
# Toolchain: Xtensa (ESP32-S3, ESP32-S2)
# 
# Relevant Specs: 
# - docs/structure_plan.md (Arch-Vendor-Chip Mapping für xtensa)
# - docs/provisioning_guide.md (Hardware Target Constraints)
# ==============================================================================

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR xtensa)

# ------------------------------------------------------------------------------
# 1. Compiler Base Setup & Prefixing
# ------------------------------------------------------------------------------
# HINWEIS: Im Gegensatz zu ARM/RISC-V haben Xtensa SDKs extrem chip-spezifische 
# Prefixe (ESP32-S3 hat nen anderen als S2). Wir verankern hier `esp32s3` als Default.
# Der tools/manifest_compiler/vendors/esp32.py überschreibt das via -DTOOLCHAIN_PREFIX
# dynamisch, wenn ein S2 oder reiner ESP32 gefordert ist!
set(TOOLCHAIN_PREFIX "xtensa-esp32s3-elf-" CACHE STRING "Xtensa ESP Toolchain Prefix")

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})

# Utilities für Binary-Weaving und Analyse
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}objcopy CACHE INTERNAL "Objcopy tool")
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}objdump CACHE INTERNAL "Objdump tool")
set(CMAKE_SIZE ${TOOLCHAIN_PREFIX}size CACHE INTERNAL "Size tool")

# BUGFIX/GAP: Da wir CMAKE_TRY_COMPILE_TARGET_TYPE = STATIC_LIBRARY nutzen,
# crasht CMake, wenn es den nativen Host-Archiver `/usr/bin/ar` auf Xtensa-Objekte wirft!
set(CMAKE_AR ${TOOLCHAIN_PREFIX}ar CACHE INTERNAL "Archiver tool")
set(CMAKE_RANLIB ${TOOLCHAIN_PREFIX}ranlib CACHE INTERNAL "Ranlib tool")
set(CMAKE_STRIP ${TOOLCHAIN_PREFIX}strip CACHE INTERNAL "Strip tool")

# ------------------------------------------------------------------------------
# 2. Compiler Test Bypass (Kritisch für Bare-Metal & ESP)
# ------------------------------------------------------------------------------
# Da das Dreigeteilte ESP32-Linker-Script vom Vendor-Builder zur Build-Zeit
# assembliert wird, fehlschlägt ein CMake `.out` Try-Compile initial.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ------------------------------------------------------------------------------
# 3. Architektur-unabhängige Bare-Metal Compiler/Linker Flags
# ------------------------------------------------------------------------------

# TODO: Xtensa PFLICHT für `cmake/toob_hal.cmake`:
# 1. `-mlongcalls` MUSS vergeben werden. Ohne das crasht der Linker auf ESP32
#    sofort bei Jumps > 24-Bit über Flash-Grenzen (Call0/Window-ABI).
# 2. `-mtext-section-literals` MUSS für XIP Execution vergeben werden!
# 3. Chip-Flags wie `-mcpu=esp32s3` MÜSSEN in toob_hal geladen werden.
# 4. FPU Konfiguration: Der ESP32-S3 besitzt eine FPU & PIE, der ESP32-S2 NICHT. 
#    Hier muss zwingend `-mhard-float` vs `-msoft-float` auf HAL-Ebene separiert werden!
# 5. ABI Selektion: Bootloader nutzen aus RAM- und Trap-Handling-Gründen oft
#    `-mcall0` (Call0 ABI) anstelle der Xtensa-typischen Windowed-ABI (`-mwindowed`).
#    Dies muss evaluiert und in der Ebene 1 HAL verankert werden.

set(TOOB_XTENSA_C_FLAGS 
    "-ffunction-sections" 
    "-fdata-sections"     
    "-fno-common"         
    "-fno-builtin"        
)

# Newlib/Nano Specs Isolierung (Kein Malloc-Overhead aus der libc)
set(TOOB_XTENSA_LINK_FLAGS 
    "--specs=nano.specs" 
    "--specs=nosys.specs"
    "-Wl,--gc-sections"
    "-nostartfiles"
    "-nodefaultlibs"
)

# Listen zu CMake-Strings formatieren
string(REPLACE ";" " " TOOB_XTENSA_C_FLAGS_STR "${TOOB_XTENSA_C_FLAGS}")
string(REPLACE ";" " " TOOB_XTENSA_LINK_FLAGS_STR "${TOOB_XTENSA_LINK_FLAGS}")

# Initiale Flags an CMake übergeben
set(CMAKE_C_FLAGS_INIT "${TOOB_XTENSA_C_FLAGS_STR}")
set(CMAKE_ASM_FLAGS_INIT "${TOOB_XTENSA_C_FLAGS_STR}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${TOOB_XTENSA_LINK_FLAGS_STR}")
