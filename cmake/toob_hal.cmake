# ==============================================================================
# Submodule: toob_hal (Three-Layer Hardware Abstraction)
# 
# Relevant Specs: 
# - docs/structure_plan.md (Architecture -> Vendor -> Chip layout)
# - docs/hals.md (HAL interface traits)
# - docs/hal_layering.md (Layering design)
# - docs/toobfuzzer_integration.md (chip_config.h macro bridging)
# ==============================================================================

# ------------------------------------------------------------------------------
# Layer 1: Architecture Abstraction (CPU ISA)
# ------------------------------------------------------------------------------
# CONFIGURE_DEPENDS forces CMake to re-evaluate when architecture sources change.
if(DEFINED TOOB_ARCH_SOURCES)
    set(ARCH_SOURCES ${TOOB_ARCH_SOURCES})
else()
    file(GLOB_RECURSE ARCH_SOURCES CONFIGURE_DEPENDS "${TOOB_HAL_ARCH_DIR}/*.c")
endif()

# Host SIL has no bare-metal architecture sources; guard target creation.
if(ARCH_SOURCES)
    add_library(toob_arch STATIC ${ARCH_SOURCES})
    target_include_directories(toob_arch PUBLIC 
        ${TOOB_HAL_ARCH_DIR}/include
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated
        ${TOOB_SDK_DIR}/libtoob/include
    )
endif()

# ------------------------------------------------------------------------------
# Layer 2 & 3: Chip and Driver Abstraction (Flat BOM)
# ------------------------------------------------------------------------------
if(NOT DEFINED TOOB_HAL_ROOT OR "${TOOB_HAL_ROOT}" STREQUAL "")
    get_filename_component(TOOB_HAL_ROOT "${TOOB_HAL_CHIP_DIR}/../.." ABSOLUTE)
endif()
set(CHIP_MANIFEST "${TOOB_HAL_CHIP_DIR}/chip_manifest.json")

set(FLAT_BOM_SOURCES "")
set(FLAT_BOM_INCLUDES "")

# Helper: Generic <stem>_real.c <-> <stem>_mock.c TU mutual exclusion for
# standalone CMake invocations when TOOB_DRIVER_SOURCES is not pre-resolved.
function(toob_resolve_tu_list IN_LIST OUT_VAR ENABLE_MOCK)
    set(_resolved "")
    foreach(_src IN LISTS ${IN_LIST})
        if(ENABLE_MOCK)
            if(_src MATCHES "_real\\.c$")
                string(REGEX REPLACE "_real\\.c$" "_mock.c" _mock_cand "${_src}")
                if(EXISTS "${_mock_cand}")
                    set(_src "${_mock_cand}")
                endif()
            endif()
        else()
            if(_src MATCHES "_mock\\.c$")
                string(REGEX REPLACE "_mock\\.c$" "_real.c" _real_cand "${_src}")
                if(EXISTS "${_real_cand}")
                    set(_src "${_real_cand}")
                else()
                    continue()
                endif()
            endif()
        endif()
        list(APPEND _resolved "${_src}")
    endforeach()
    list(REMOVE_DUPLICATES _resolved)
    set(${OUT_VAR} "${_resolved}" PARENT_SCOPE)
endfunction()

if(DEFINED TOOB_CHIP_SOURCES OR DEFINED TOOB_DRIVER_SOURCES)
    list(APPEND FLAT_BOM_SOURCES ${TOOB_CHIP_SOURCES})
    if(EXISTS ${CHIP_MANIFEST})
        file(READ ${CHIP_MANIFEST} MANIFEST_JSON)
        string(JSON CHIP_PLATFORM ERROR_VARIABLE JSON_ERR GET ${MANIFEST_JSON} sources platform)
    endif()
    if((JSON_ERR OR NOT CHIP_PLATFORM) AND EXISTS "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
        list(APPEND FLAT_BOM_SOURCES "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
    endif()
    list(APPEND FLAT_BOM_SOURCES ${TOOB_DRIVER_SOURCES})
    list(REMOVE_DUPLICATES FLAT_BOM_SOURCES)
    list(APPEND FLAT_BOM_INCLUDES ${TOOB_CHIP_INCLUDES} ${TOOB_DRIVERS})
elseif(EXISTS ${CHIP_MANIFEST})
    file(READ ${CHIP_MANIFEST} MANIFEST_JSON)
    
    # 1. Startup, Platform
    string(JSON CHIP_STARTUP ERROR_VARIABLE JSON_ERR GET ${MANIFEST_JSON} sources startup)
    if(NOT JSON_ERR AND CHIP_STARTUP)
        list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${CHIP_STARTUP}")
    endif()
    
    string(JSON CHIP_PLATFORM ERROR_VARIABLE JSON_ERR GET ${MANIFEST_JSON} sources platform)
    if(NOT JSON_ERR AND CHIP_PLATFORM)
        list(APPEND FLAT_BOM_SOURCES "${TOOB_HAL_CHIP_DIR}/${CHIP_PLATFORM}")
    else()
        if(EXISTS "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
            list(APPEND FLAT_BOM_SOURCES "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
        endif()
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

    toob_resolve_tu_list(FLAT_BOM_SOURCES FLAT_BOM_SOURCES "${TOOB_MOCK_HW}")

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
    list(APPEND FLAT_BOM_INCLUDES ${TOOB_DRIVERS})
endif()

if(FLAT_BOM_SOURCES)
    add_library(toob_chip STATIC ${FLAT_BOM_SOURCES})

    # Expose bootloader core and generated interfaces to the chip HAL layer
    target_include_directories(toob_chip PUBLIC 
        ${TOOB_HAL_CHIP_DIR}
        ${TOOB_HAL_ROOT}
        ${FLAT_BOM_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${TOOB_CORE_DIR}/utils/include
        ${CMAKE_BINARY_DIR}/generated
        ${TOOB_SDK_DIR}/libtoob/include
        ${TOOB_CRYPTO_BACKEND_DIR}
        ${TOOB_CRYPTO_HASH_DIR}
    )
    if(DEFINED TOOB_CRYPTO_PQC_DIR AND NOT "${TOOB_CRYPTO_PQC_DIR}" STREQUAL "")
        target_include_directories(toob_chip PUBLIC ${TOOB_CRYPTO_PQC_DIR})
    endif()
    if(TOOB_CHIP STREQUAL "sandbox")
        target_include_directories(toob_chip PUBLIC test/mocks)
    endif()

    if(TARGET toob_arch)
        target_link_libraries(toob_chip PUBLIC toob_arch)
    endif()
endif()

# Ensure generated headers exist before compiling chip HAL sources.
if(TARGET generate_manifest AND TARGET toob_chip)
    add_dependencies(toob_chip generate_manifest)
endif()


if(TARGET toob_arch)
    toob_apply_strict_flags(toob_arch TRUE)
endif()


if(TARGET toob_chip)
    toob_apply_strict_flags(toob_chip TRUE)
endif()
