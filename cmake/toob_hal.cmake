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
file(GLOB_RECURSE ARCH_SOURCES CONFIGURE_DEPENDS "${TOOB_HAL_ARCH_DIR}/*.c")

# GAP-Integration: Sandbox Crash-Protection
# Die Sandbox (Host) hat keine arch-Dateien ("kein arch/vendor"). 
# Der if-Block bewahrt CMake vor einem FATAL ERROR.
if(ARCH_SOURCES)
    add_library(toob_arch STATIC ${ARCH_SOURCES})
    target_include_directories(toob_arch PUBLIC 
        ${TOOB_HAL_ARCH_DIR}/include
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include                  # Unverzichtbar für boot_hal.h!
        ${CMAKE_BINARY_DIR}/generated # Unverzichtbar für chip_config.h!
        ${TOOB_SDK_DIR}/libtoob/include
    )
endif()

# ------------------------------------------------------------------------------
# Ebene 2 & 3: Chip- und Driver-Abstraktion (Flat BOM)
# ------------------------------------------------------------------------------
get_filename_component(TOOB_HAL_ROOT "${TOOB_HAL_CHIP_DIR}/../.." ABSOLUTE)
set(CHIP_MANIFEST "${TOOB_HAL_CHIP_DIR}/chip_manifest.json")

set(FLAT_BOM_SOURCES "")
set(FLAT_BOM_INCLUDES "")

if(EXISTS ${CHIP_MANIFEST})
    file(READ ${CHIP_MANIFEST} MANIFEST_JSON)
    
    # 1. Startup, Platform
    string(JSON CHIP_STARTUP ERROR_VARIABLE JSON_ERR GET ${MANIFEST_JSON} sources startup)
    if(NOT JSON_ERR AND CHIP_STARTUP)
        list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${CHIP_STARTUP}")
    endif()
    
    string(JSON CHIP_PLATFORM ERROR_VARIABLE JSON_ERR GET ${MANIFEST_JSON} sources platform)
    if(NOT JSON_ERR AND CHIP_PLATFORM)
        list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${CHIP_PLATFORM}")
    endif()
    
    # 2. Extra Chip Sources
    string(JSON NUM_EXTRA ERROR_VARIABLE JSON_ERR LENGTH ${MANIFEST_JSON} sources extra)
    if(NOT JSON_ERR AND NUM_EXTRA GREATER 0)
        math(EXPR LAST_EXTRA "${NUM_EXTRA} - 1")
        foreach(IDX RANGE 0 ${LAST_EXTRA})
            string(JSON EXTRA_PATH GET ${MANIFEST_JSON} sources extra ${IDX})
            list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${EXTRA_PATH}")
        endforeach()
    endif()

    # 3. Drivers
    string(JSON NUM_DRIVERS ERROR_VARIABLE JSON_ERR LENGTH ${MANIFEST_JSON} sources drivers)
    if(NOT JSON_ERR AND NUM_DRIVERS GREATER 0)
        math(EXPR LAST_DRIVER "${NUM_DRIVERS} - 1")
        foreach(IDX RANGE 0 ${LAST_DRIVER})
            string(JSON DRIVER_PATH GET ${MANIFEST_JSON} sources drivers ${IDX})
            if(DRIVER_PATH MATCHES "^drivers/")
                list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_ROOT}/${DRIVER_PATH}")
            else()
                list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${DRIVER_PATH}")
            endif()
        endforeach()
    endif()

    # 4. Includes
    string(JSON NUM_INCLUDES ERROR_VARIABLE JSON_ERR LENGTH ${MANIFEST_JSON} includes)
    if(NOT JSON_ERR AND NUM_INCLUDES GREATER 0)
        math(EXPR LAST_INC "${NUM_INCLUDES} - 1")
        foreach(IDX RANGE 0 ${LAST_INC})
            string(JSON INC_PATH GET ${MANIFEST_JSON} includes ${IDX})
            if(INC_PATH MATCHES "^(drivers|arch|soc)/")
                list(APPEND FLAT_BOM_INCLUDES "${TOOB_HAL_ROOT}/${INC_PATH}")
            else()
                list(APPEND FLAT_BOM_INCLUDES "${TOOB_HAL_CHIP_DIR}/${INC_PATH}")
            endif()
        endforeach()
    endif()
endif()

if(FLAT_BOM_SOURCES)
    add_library(toob_chip STATIC ${FLAT_BOM_SOURCES})

    # Sichtbarkeit der Bootloader Core-Interfaces für die Chip-Ebene
    target_include_directories(toob_chip PUBLIC 
        ${TOOB_HAL_CHIP_DIR}
        ${FLAT_BOM_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated
        ${TOOB_SDK_DIR}/libtoob/include
        ${TOOB_CRYPTO_DIR}/monocypher
    )
    if(TOOB_CHIP STREQUAL "sandbox")
        target_include_directories(toob_chip PUBLIC test/mocks)
    endif()

    if(TARGET toob_arch)
        target_link_libraries(toob_chip PUBLIC toob_arch)
    endif()
endif()

# GAP-Integration: Custom-Target Dependency `generate_manifest` 
# Da `chip_platform.c` die Datei `chip_config.h` aus `${CMAKE_BINARY_DIR}/generated/`
# importiert, müssen wir verifizieren, dass der Manifest-Compiler/Script Davor lief.
if(TARGET generate_manifest AND TARGET toob_chip)
    add_dependencies(toob_chip generate_manifest)
endif()


if(TARGET toob_arch)
    toob_apply_strict_flags(toob_arch TRUE)
endif()


if(TARGET toob_chip)
    toob_apply_strict_flags(toob_chip TRUE)
endif()
