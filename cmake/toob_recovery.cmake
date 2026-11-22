# ==============================================================================
# Submodule: toob_recovery (OTA-Only Recovery Application)
# ==============================================================================

# 1. Target Definition
set(TOOB_RECOVERY_SRC_FILES
    ${CMAKE_SOURCE_DIR}/recovery/main.c
    ${CMAKE_SOURCE_DIR}/toobloader/core/utils/boot_crc32.c
)
if(TOOB_RECOVERY_SOURCES)
    list(APPEND TOOB_RECOVERY_SRC_FILES ${TOOB_RECOVERY_SOURCES})
else()
    list(APPEND TOOB_RECOVERY_SRC_FILES ${CMAKE_SOURCE_DIR}/recovery/recovery_port.c)
endif()

if(EXISTS "${TOOB_HAL_CHIP_DIR}/startup.c")
    list(APPEND TOOB_RECOVERY_SRC_FILES "${TOOB_HAL_CHIP_DIR}/startup.c")
    list(APPEND TOOB_RECOVERY_SRC_FILES "${CMAKE_SOURCE_DIR}/toobloader/core/boot_platform_bringup.c")
endif()

if(TOOB_RECOVERY_DRIVER_SOURCES)
    list(APPEND TOOB_RECOVERY_SRC_FILES ${TOOB_RECOVERY_DRIVER_SOURCES})
elseif(TOOB_RECOVERY_DRIVERS)
    foreach(DRV_DIR IN LISTS TOOB_RECOVERY_DRIVERS)
        file(GLOB DRV_SOURCES "${DRV_DIR}/*.c" "${DRV_DIR}/*.S")
        list(FILTER DRV_SOURCES EXCLUDE REGEX "_mock\\.c$")
        list(APPEND TOOB_RECOVERY_SRC_FILES ${DRV_SOURCES})
    endforeach()
endif()

set(REC_CHIP_MANIFEST "${TOOB_HAL_CHIP_DIR}/chip_manifest.json")
set(REC_HAS_CHIP_PLATFORM FALSE)
if(EXISTS "${REC_CHIP_MANIFEST}")
    file(READ "${REC_CHIP_MANIFEST}" REC_MANIFEST_JSON)
    string(JSON REC_CHIP_PLATFORM ERROR_VARIABLE REC_JSON_ERR GET ${REC_MANIFEST_JSON} sources platform)
    if(NOT REC_JSON_ERR AND REC_CHIP_PLATFORM)
        set(REC_HAS_CHIP_PLATFORM TRUE)
    endif()
endif()
if(NOT REC_HAS_CHIP_PLATFORM AND EXISTS "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
    list(APPEND TOOB_RECOVERY_SRC_FILES "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
endif()

add_executable(toob_recovery ${TOOB_RECOVERY_SRC_FILES})
target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_BUILD=1)

if(TARGET generate_manifest)
    add_dependencies(toob_recovery generate_manifest)
endif()

# Apply strict compilation flags
toob_apply_strict_flags(toob_recovery TRUE)

# Include directories
target_include_directories(toob_recovery PRIVATE
    ${CMAKE_SOURCE_DIR}/recovery
    ${CMAKE_SOURCE_DIR}/common/include
    ${CMAKE_SOURCE_DIR}/toobloader/core/include
    ${CMAKE_SOURCE_DIR}/toobloader/core/utils/include
    ${CMAKE_SOURCE_DIR}/sdk/libtoob/include
    ${CMAKE_BINARY_DIR}/generated
    ${TOOB_HAL_CHIP_DIR}
    ${TOOB_HAL_ROOT}
)
if(TOOB_RECOVERY_INCLUDES)
    target_include_directories(toob_recovery PRIVATE ${TOOB_RECOVERY_INCLUDES})
endif()
if(TOOB_RECOVERY_DRIVERS)
    target_include_directories(toob_recovery PRIVATE ${TOOB_RECOVERY_DRIVERS})
endif()

# Link modular libraries
target_link_libraries(toob_recovery PRIVATE toob_libtoob)
if(TARGET toob_chip)
    target_link_libraries(toob_recovery PRIVATE toob_chip)
endif()
if(TARGET toob_arch)
    target_link_libraries(toob_recovery PRIVATE toob_arch)
endif()

# Dedicated Recovery Crypto Targets (CRIT-62):
# Compile and link ONLY recovery backend/hash slots (never Stage-1 PQC such as ml_dsa_65).
set(_REC_CRYPTO_SOURCES "")
set(_REC_CRYPTO_INCLUDES "")
set(_REC_CRYPTO_WRAPPERS "")
set(_REC_BACKEND_CFLAGS "")
set(_REC_HASH_SOURCES "")
set(_REC_HASH_CFLAGS "")
set(_REC_HASH_ACTIVE FALSE)

# 1) Recovery Backend Slot (unless "rom" or "none")
if(NOT TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "rom" AND NOT TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "none")
    if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_DIR OR DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_SOURCES OR DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_WRAPPER)
        if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_SOURCES AND NOT "${TOOB_RECOVERY_CRYPTO_BACKEND_SOURCES}" STREQUAL "")
            list(APPEND _REC_CRYPTO_SOURCES ${TOOB_RECOVERY_CRYPTO_BACKEND_SOURCES})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_DIR)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_RECOVERY_CRYPTO_BACKEND_DIR})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_INCLUDES)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_RECOVERY_CRYPTO_BACKEND_INCLUDES})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_WRAPPER)
            list(APPEND _REC_CRYPTO_WRAPPERS ${TOOB_RECOVERY_CRYPTO_BACKEND_WRAPPER})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_BACKEND_CFLAGS)
            set(_REC_BACKEND_CFLAGS ${TOOB_RECOVERY_CRYPTO_BACKEND_CFLAGS})
        endif()
    elseif(TOOB_CRYPTO_BACKEND_ENABLED)
        if(DEFINED TOOB_CRYPTO_BACKEND_SOURCES AND NOT "${TOOB_CRYPTO_BACKEND_SOURCES}" STREQUAL "")
            list(APPEND _REC_CRYPTO_SOURCES ${TOOB_CRYPTO_BACKEND_SOURCES})
        endif()
        if(DEFINED TOOB_CRYPTO_BACKEND_DIR)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_CRYPTO_BACKEND_DIR})
        endif()
        if(DEFINED TOOB_CRYPTO_BACKEND_INCLUDES)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_CRYPTO_BACKEND_INCLUDES})
        endif()
        if(DEFINED TOOB_CRYPTO_BACKEND_WRAPPER)
            list(APPEND _REC_CRYPTO_WRAPPERS ${TOOB_CRYPTO_BACKEND_WRAPPER})
        endif()
        if(DEFINED TOOB_CRYPTO_BACKEND_CFLAGS)
            set(_REC_BACKEND_CFLAGS ${TOOB_CRYPTO_BACKEND_CFLAGS})
        endif()
    endif()
endif()

# 2) Recovery Hash Slot (unless "none")
if(NOT TOOB_RECOVERY_CRYPTO_HASH STREQUAL "none")
    if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_DIR OR DEFINED TOOB_RECOVERY_CRYPTO_HASH_SOURCES OR DEFINED TOOB_RECOVERY_CRYPTO_HASH_WRAPPER)
        set(_REC_HASH_ACTIVE TRUE)
        if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_SOURCES AND NOT "${TOOB_RECOVERY_CRYPTO_HASH_SOURCES}" STREQUAL "")
            list(APPEND _REC_CRYPTO_SOURCES ${TOOB_RECOVERY_CRYPTO_HASH_SOURCES})
            set(_REC_HASH_SOURCES ${TOOB_RECOVERY_CRYPTO_HASH_SOURCES})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_DIR)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_RECOVERY_CRYPTO_HASH_DIR})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_INCLUDES)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_RECOVERY_CRYPTO_HASH_INCLUDES})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_WRAPPER)
            list(APPEND _REC_CRYPTO_WRAPPERS ${TOOB_RECOVERY_CRYPTO_HASH_WRAPPER})
        endif()
        if(DEFINED TOOB_RECOVERY_CRYPTO_HASH_CFLAGS)
            set(_REC_HASH_CFLAGS ${TOOB_RECOVERY_CRYPTO_HASH_CFLAGS})
        endif()
    elseif(TOOB_CRYPTO_HASH_ENABLED)
        set(_REC_HASH_ACTIVE TRUE)
        if(DEFINED TOOB_CRYPTO_HASH_SOURCES AND NOT "${TOOB_CRYPTO_HASH_SOURCES}" STREQUAL "")
            list(APPEND _REC_CRYPTO_SOURCES ${TOOB_CRYPTO_HASH_SOURCES})
            set(_REC_HASH_SOURCES ${TOOB_CRYPTO_HASH_SOURCES})
        elseif(DEFINED TOOB_CRYPTO_BACKEND_SOURCES AND DEFINED TOOB_CRYPTO_HASH_DIR AND DEFINED TOOB_CRYPTO_BACKEND_DIR AND "${TOOB_CRYPTO_HASH_DIR}" STREQUAL "${TOOB_CRYPTO_BACKEND_DIR}")
            # Stage-1 hash slot reused the Stage-1 backend package; pull its upstream sources when recovery backend was disabled/ROM.
            list(APPEND _REC_CRYPTO_SOURCES ${TOOB_CRYPTO_BACKEND_SOURCES})
        endif()
        if(DEFINED TOOB_CRYPTO_HASH_DIR)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_CRYPTO_HASH_DIR})
        endif()
        if(DEFINED TOOB_CRYPTO_HASH_INCLUDES)
            list(APPEND _REC_CRYPTO_INCLUDES ${TOOB_CRYPTO_HASH_INCLUDES})
        endif()
        if(DEFINED TOOB_CRYPTO_HASH_WRAPPER)
            list(APPEND _REC_CRYPTO_WRAPPERS ${TOOB_CRYPTO_HASH_WRAPPER})
        endif()
        if(DEFINED TOOB_CRYPTO_HASH_CFLAGS)
            set(_REC_HASH_CFLAGS ${TOOB_CRYPTO_HASH_CFLAGS})
        endif()
    endif()
endif()

if(_REC_CRYPTO_SOURCES)
    list(REMOVE_DUPLICATES _REC_CRYPTO_SOURCES)
endif()
if(_REC_CRYPTO_INCLUDES)
    list(REMOVE_DUPLICATES _REC_CRYPTO_INCLUDES)
endif()
if(_REC_CRYPTO_WRAPPERS)
    list(REMOVE_DUPLICATES _REC_CRYPTO_WRAPPERS)
endif()

if(_REC_CRYPTO_SOURCES)
    add_library(toob_recovery_crypto_upstream STATIC ${_REC_CRYPTO_SOURCES})
    target_include_directories(toob_recovery_crypto_upstream PUBLIC
        ${_REC_CRYPTO_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${TOOB_CORE_DIR}/utils/include
    )
    set(_REC_UPSTREAM_CFLAGS -fno-lto -ffunction-sections -fdata-sections)
    if(_REC_BACKEND_CFLAGS)
        list(APPEND _REC_UPSTREAM_CFLAGS ${_REC_BACKEND_CFLAGS})
    else()
        list(APPEND _REC_UPSTREAM_CFLAGS -Os)
    endif()
    target_compile_options(toob_recovery_crypto_upstream PRIVATE ${_REC_UPSTREAM_CFLAGS})
    if(_REC_HASH_SOURCES AND _REC_HASH_CFLAGS)
        string(REPLACE ";" " " _REC_HASH_CFLAGS_STR "${_REC_HASH_CFLAGS}")
        set_source_files_properties(${_REC_HASH_SOURCES} PROPERTIES COMPILE_FLAGS "${_REC_HASH_CFLAGS_STR}")
    endif()
    target_compile_definitions(toob_recovery_crypto_upstream PRIVATE TOOB_COMPACT_ED25519=1)
endif()

if(_REC_CRYPTO_WRAPPERS)
    add_library(toob_recovery_crypto STATIC ${_REC_CRYPTO_WRAPPERS})
    target_compile_definitions(toob_recovery_crypto PRIVATE TOOB_RECOVERY_BUILD=1)
    target_include_directories(toob_recovery_crypto PUBLIC
        ${_REC_CRYPTO_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated
        ${TOOB_SDK_DIR}/libtoob/include
    )
    if(TARGET toob_recovery_crypto_upstream)
        target_link_libraries(toob_recovery_crypto PUBLIC toob_recovery_crypto_upstream)
    endif()
    if(COMMAND toob_apply_strict_flags)
        toob_apply_strict_flags(toob_recovery_crypto TRUE)
    endif()
endif()

if(TARGET toob_recovery_crypto)
    target_link_libraries(toob_recovery PRIVATE toob_recovery_crypto)
endif()
if(TARGET toob_recovery_crypto_upstream)
    target_link_libraries(toob_recovery PRIVATE toob_recovery_crypto_upstream)
endif()

if(NOT _REC_HASH_ACTIVE)
    target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_HASH_NONE=1)
    if(TARGET toob_recovery_crypto)
        target_compile_definitions(toob_recovery_crypto PRIVATE TOOB_RECOVERY_HASH_NONE=1)
    endif()
endif()

# Set recovery crypto preprocessor flags
if(TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "rom")
    target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_CRYPTO_ROM=1)
    if(TARGET toob_recovery_crypto)
        target_compile_definitions(toob_recovery_crypto PRIVATE TOOB_RECOVERY_CRYPTO_ROM=1)
    endif()
elseif(TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "none")
    target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_CRYPTO_NONE=1)
    if(TARGET toob_recovery_crypto)
        target_compile_definitions(toob_recovery_crypto PRIVATE TOOB_RECOVERY_CRYPTO_NONE=1)
    endif()
endif()

# If not host, specify linker script and post-build targets (HIGH-90)
if(NOT TOOB_ARCH STREQUAL "host")
    if(EXISTS "${TOOB_HAL_CHIP_DIR}/${TOOB_CHIP}_recovery.ld")
        set(TOOB_RECOVERY_LINKER_SCRIPT "${TOOB_HAL_CHIP_DIR}/${TOOB_CHIP}_recovery.ld")
    elseif(EXISTS "${CMAKE_BINARY_DIR}/generated/recovery_layout.ld")
        set(TOOB_RECOVERY_LINKER_SCRIPT "${CMAKE_BINARY_DIR}/generated/recovery_layout.ld")
    else()
        message(FATAL_ERROR "No recovery linker script found for chip '${TOOB_CHIP}'!")
    endif()

    target_link_options(toob_recovery PRIVATE -T${TOOB_RECOVERY_LINKER_SCRIPT} -L${CMAKE_BINARY_DIR}/generated)
    set_target_properties(toob_recovery PROPERTIES LINK_DEPENDS "${TOOB_RECOVERY_LINKER_SCRIPT}")

    set(_TOOB_HAS_RECOVERY_BUDGET TRUE)
    if(EXISTS "${CMAKE_BINARY_DIR}/generated/generated_memory.ld")
        file(READ "${CMAKE_BINARY_DIR}/generated/generated_memory.ld" _TOOB_GEN_MEM_LD)
        if(_TOOB_GEN_MEM_LD MATCHES "__RECOVERY_SLOT_LENGTH[ \t]*=[ \t]*0x00000000;")
            set(_TOOB_HAS_RECOVERY_BUDGET FALSE)
        endif()
    endif()

    if(_TOOB_HAS_RECOVERY_BUDGET)
        add_custom_command(
            TARGET toob_recovery POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_recovery> $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.raw.bin
            COMMAND ${TOOB_CLI_PATH} sign image $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.raw.bin -o $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.bin
            COMMAND ${TOOB_CLI_PATH} budget --toml "${TOOB_DEVICE_MANIFEST}" --stage recovery --bin $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.bin
            COMMENT "Generating flashable Toob-tagged binary toob_recovery.bin and checking recovery flash budget..."
        )
    else()
        add_custom_command(
            TARGET toob_recovery POST_BUILD
            COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_recovery> $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.raw.bin
            COMMAND ${TOOB_CLI_PATH} sign image $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.raw.bin -o $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.bin
            COMMENT "Generating flashable Toob-tagged binary toob_recovery.bin..."
        )
    endif()
endif()
