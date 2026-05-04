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
# Der tools/cli/manifest_compiler/vendors/esp32.py überschreibt das via -DTOOLCHAIN_PREFIX
# dynamisch, wenn ein S2 oder reiner ESP32 gefordert ist!
set(TOOLCHAIN_PREFIX "xtensa-esp32s3-elf-" CACHE STRING "Xtensa ESP Toolchain Prefix")

set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})

# Utilities für Binary-Weaving und Analyse
find_program(CMAKE_OBJCOPY NAMES ${TOOLCHAIN_PREFIX}objcopy)
find_program(CMAKE_OBJDUMP NAMES ${TOOLCHAIN_PREFIX}objdump)
find_program(CMAKE_SIZE NAMES ${TOOLCHAIN_PREFIX}size)

# BUGFIX/GAP: Da wir CMAKE_TRY_COMPILE_TARGET_TYPE auf STATIC_LIBRARY setzen,
# MÜSSEN wir zwingend den Archiver explizit setzen, da sonst der Host-Archiver crasht.
find_program(CMAKE_AR NAMES ${TOOLCHAIN_PREFIX}ar)
find_program(CMAKE_RANLIB NAMES ${TOOLCHAIN_PREFIX}ranlib)
find_program(CMAKE_STRIP NAMES ${TOOLCHAIN_PREFIX}strip)

# ------------------------------------------------------------------------------
# 2. Compiler Test Bypass (Kritisch für Bare-Metal & ESP)
# ------------------------------------------------------------------------------
# Da das Dreigeteilte ESP32-Linker-Script vom Vendor-Builder zur Build-Zeit
# assembliert wird, fehlschlägt ein CMake `.out` Try-Compile initial.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ------------------------------------------------------------------------------
# 3. Architektur-unabhängige Bare-Metal Compiler/Linker Flags
# ------------------------------------------------------------------------------



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
