# ==============================================================================
# Submodule: toob_hal (Drei-Ebenen Hardware Abstraction)
# 
# Relevant Specs: 
# - docs/structure_plan.md (Architektur -> Vendor -> Chip Konzept)
# - docs/hals.md (Die 7 Interface Traits)
# - docs/hal_layering.md (Ebenen-Design)
# - docs/toobfuzzer_integration.md (chip_config.h Makro-Bridging)
# ==============================================================================

# ------------------------------------------------------------------------------
# Ebene 1: Architektur-Abstraktion (CPU ISA)
# ------------------------------------------------------------------------------
# P10/Ninja-GAP: Niemals nacktes GLOB nutzen! `CONFIGURE_DEPENDS` zwingt das
# Buildsystem, bei neu hinzugefügten Architektur-Files CMake neu auszuführen.
file(GLOB_RECURSE ARCH_SOURCES CONFIGURE_DEPENDS "hal/arch/${TOOB_ARCH}/*.c")

# GAP-Integration: Sandbox Crash-Protection
# Die Sandbox (Host) hat keine arch-Dateien ("kein arch/vendor"). 
# Der if-Block bewahrt CMake vor einem FATAL ERROR.
if(ARCH_SOURCES)
    add_library(toob_arch STATIC ${ARCH_SOURCES})
    target_include_directories(toob_arch PUBLIC 
        hal/arch/${TOOB_ARCH}/include
        core/include                  # Unverzichtbar für boot_hal.h!
        ${CMAKE_BINARY_DIR}/generated # Unverzichtbar für chip_config.h!
    )
endif()

# ------------------------------------------------------------------------------
# Ebene 2: Vendor-Abstraktion (Hersteller Familie)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE VENDOR_SOURCES CONFIGURE_DEPENDS "hal/vendor/${TOOB_VENDOR}/*.c")

if(VENDOR_SOURCES)
    add_library(toob_vendor STATIC ${VENDOR_SOURCES})
    target_include_directories(toob_vendor PUBLIC 
        hal/vendor/${TOOB_VENDOR}/include
        core/include
        ${CMAKE_BINARY_DIR}/generated
    )
    if(TARGET toob_arch)
        target_link_libraries(toob_vendor PUBLIC toob_arch)
    endif()
endif()

# ------------------------------------------------------------------------------
# Ebene 3: Chip-Abstraktion (Spezifisches Ziel-Silicon)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE CHIP_SOURCES CONFIGURE_DEPENDS "hal/chips/${TOOB_CHIP}/*.c")
# GAP-Integration: Analog zu arch_sources bewahrt uns dieser Block davor,
# den Build auf der Host-Sandbox zu crashen, da TOOB_CHIP dort leer ist.
if(CHIP_SOURCES)
    add_library(toob_chip STATIC ${CHIP_SOURCES})

    # Sichtbarkeit der Bootloader Core-Interfaces für die Chip-Ebene
    target_include_directories(toob_chip PUBLIC 
        hal/chips/${TOOB_CHIP}
        core/include
        ${CMAKE_BINARY_DIR}/generated
    )

    if(TARGET toob_vendor)
        target_link_libraries(toob_chip PUBLIC toob_vendor)
    endif()
endif()

# GAP-Integration: Custom-Target Dependency `generate_manifest` 
# Da `chip_platform.c` die Datei `chip_config.h` aus `${CMAKE_BINARY_DIR}/generated/`
# importiert, müssen wir verifizieren, dass der Manifest-Compiler/Script Davor lief.
if(TARGET generate_manifest AND TARGET toob_chip)
    add_dependencies(toob_chip generate_manifest)
endif()

# ------------------------------------------------------------------------------
# Architektur-spezifische GAPs / Hardware-Limits patchen
# ------------------------------------------------------------------------------
if(TOOB_ARCH STREQUAL "xtensa")
    # GAP-ABI: Call0 ist für Bare-Metal Bootloader auf Xtensa elementar, 
    # andernfalls crasht das System bei tiefen Stacks durch Window-Overflows.
    target_compile_options(toob_arch PUBLIC -mcall0)
    
    # GAP-FPU: Dynamisches Hard-Float für S3 Chips, andernfalls Hardware-Crashes
    # auf S2 Chips (die keine FPU haben). Toolchains machen das meist NICHT auto.
    if(TOOB_CHIP STREQUAL "esp32s3")
        target_compile_options(toob_arch PUBLIC -mhard-float)
        target_compile_definitions(toob_arch PUBLIC TOOB_XTENSA_HARD_FLOAT_ENABLED=1)
    else()
        target_compile_options(toob_arch PUBLIC -msoft-float)
    endif()
endif()

# ------------------------------------------------------------------------------
# P10 Härtung (Stack-Protector für HAL erlaubt)
# ------------------------------------------------------------------------------
if(TARGET toob_arch)
    toob_apply_strict_flags(toob_arch TRUE)
endif()

if(TARGET toob_vendor)
    toob_apply_strict_flags(toob_vendor TRUE)
endif()

if(TARGET toob_chip)
    toob_apply_strict_flags(toob_chip TRUE)
endif()
