# ==============================================================================
# Submodule: toob_libtoob (OS Boundary C-Library)
# 
# Relevant Specs: 
# - docs/libtoob_api.md (API, Handoff-Memory Definition)
# - docs/concept_fusion.md (Confirm-Flag System, Telemetry)
# - docs/toob_telemetry.md (Telemetry Extraction)
# - docs/structure_plan.md (Directory tree `sdk/libtoob/`)
# ==============================================================================

# ------------------------------------------------------------------------------
# PURPOSE: toob_libtoob is the OS boundary library linked into the Guest OS
# (Zephyr, FreeRTOS, NuttX).
# 
# ARCHITECTURE RULE: This target must NEVER link against toob_chip, toob_hal, or
# toob_core. It communicates strictly via the .noinit shared-RAM handoff region
# and flash WAL appends.
# ------------------------------------------------------------------------------

add_library(toob_libtoob STATIC
    ${TOOB_SDK_DIR}/libtoob/toob_confirm.c
    ${TOOB_SDK_DIR}/libtoob/toob_update.c
    ${TOOB_SDK_DIR}/libtoob/toob_mailbox.c
    ${TOOB_SDK_DIR}/libtoob/toob_cloud_submit.c
    ${TOOB_SDK_DIR}/libtoob/toob_diag.c
    ${TOOB_SDK_DIR}/libtoob/toob_handoff.c
    ${TOOB_SDK_DIR}/libtoob/toob_ota.c
    ${TOOB_SDK_DIR}/libtoob/toob_crc32.c
)

# 1. Public includes exposed to the Guest OS
target_include_directories(toob_libtoob PUBLIC
    ${TOOB_SDK_DIR}/libtoob/include
    ${CMAKE_SOURCE_DIR}/common/include
)

# 2. Private includes (generated manifest flash offsets and handoff addresses)
target_include_directories(toob_libtoob PRIVATE
    ${CMAKE_BINARY_DIR}/generated
)

if(TARGET generate_manifest)
    add_dependencies(toob_libtoob generate_manifest)
endif()

# 3. Match Guest OS ABI (disable forced stack-protector while keeping -Werror)
if(COMMAND toob_apply_strict_flags)
    toob_apply_strict_flags(toob_libtoob FALSE)
endif()
