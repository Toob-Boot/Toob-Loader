# ==============================================================================
# Submodule: toob_recovery (OTA-Only Recovery Application)
# ==============================================================================

# 1. Target Definition
set(TOOB_RECOVERY_SRC_FILES ${CMAKE_SOURCE_DIR}/recovery/main.c)
if(TOOB_RECOVERY_SOURCES)
    list(APPEND TOOB_RECOVERY_SRC_FILES ${TOOB_RECOVERY_SOURCES})
else()
    list(APPEND TOOB_RECOVERY_SRC_FILES ${CMAKE_SOURCE_DIR}/recovery/recovery_port.c)
endif()

if(TOOB_RECOVERY_DRIVERS)
    foreach(DRV_DIR IN LISTS TOOB_RECOVERY_DRIVERS)
        file(GLOB DRV_SOURCES "${DRV_DIR}/*.c" "${DRV_DIR}/*.S")
        list(APPEND TOOB_RECOVERY_SRC_FILES ${DRV_SOURCES})
    endforeach()
endif()

add_executable(toob_recovery ${TOOB_RECOVERY_SRC_FILES})

# Apply strict compilation flags
toob_apply_strict_flags(toob_recovery TRUE)

# Include directories
target_include_directories(toob_recovery PRIVATE
    ${CMAKE_SOURCE_DIR}/recovery
    ${CMAKE_SOURCE_DIR}/common/include
    ${CMAKE_SOURCE_DIR}/toobloader/core/include
    ${CMAKE_SOURCE_DIR}/sdk/libtoob/include
    ${CMAKE_BINARY_DIR}/generated
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

# Conditionally link crypto only if not using ROM or NONE crypto stubs
if(TARGET toob_crypto_upstream AND NOT TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "rom" AND NOT TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "none")
    target_link_libraries(toob_recovery PRIVATE toob_crypto toob_crypto_upstream)
endif()

# Set recovery crypto preprocessor flags
if(TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "rom")
    target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_CRYPTO_ROM=1)
elseif(TOOB_RECOVERY_CRYPTO_BACKEND STREQUAL "none")
    target_compile_definitions(toob_recovery PRIVATE TOOB_RECOVERY_CRYPTO_NONE=1)
endif()

# If not host, specify linker script and post-build targets
if(NOT TOOB_ARCH STREQUAL "host")
    if(EXISTS "${CMAKE_BINARY_DIR}/generated/flash_layout.ld")
        set(TOOB_LINKER_SCRIPT "${CMAKE_BINARY_DIR}/generated/flash_layout.ld")
    elseif(EXISTS "${TOOB_HAL_CHIP_DIR}/${TOOB_CHIP}_stage1.ld")
        set(TOOB_LINKER_SCRIPT "${TOOB_HAL_CHIP_DIR}/${TOOB_CHIP}_stage1.ld")
    endif()

    if(TOOB_LINKER_SCRIPT)
        target_link_options(toob_recovery PRIVATE -T${TOOB_LINKER_SCRIPT} -L${CMAKE_BINARY_DIR}/generated)
    endif()

    add_custom_command(
        TARGET toob_recovery POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_recovery> $<TARGET_FILE_DIR:toob_recovery>/toob_recovery.bin
        COMMENT "Generating flashable RAW binary toob_recovery.bin..."
    )
endif()
