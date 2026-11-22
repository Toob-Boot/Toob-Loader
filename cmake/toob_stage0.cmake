# ==============================================================================
# Submodule: toob_stage0 (Immutable Boot-Pointer Stage)
#
# Relevant Specs:
# - docs/concept_fusion.md (Stage 0: Immutable Core, Boot-Pointer, Fallback)
# - docs/structure_plan.md (Directory tree `toobloader/stage0/`)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 0 is a standalone immutable binary (4-8 KB budget) that validates and
# dispatches the TMR Boot-Pointer and Tentative-Flag without sharing Stage 1 WAL.
# ------------------------------------------------------------------------------

option(TOOB_STAGE0_DEV_BYPASS "Allow Stage 0 signature bypass when DSLC==0 (Dev/Bringup ONLY)" OFF)

# 1. Target Definition (Executable)
set(S0_CHIP_MANIFEST "${TOOB_HAL_CHIP_DIR}/chip_manifest.json")
set(S0_HAS_CHIP_PLATFORM FALSE)
if(EXISTS "${S0_CHIP_MANIFEST}")
    file(READ "${S0_CHIP_MANIFEST}" S0_MANIFEST_JSON)
    string(JSON S0_CHIP_PLATFORM ERROR_VARIABLE S0_JSON_ERR GET ${S0_MANIFEST_JSON} sources platform)
    if(NOT S0_JSON_ERR AND S0_CHIP_PLATFORM)
        set(S0_HAS_CHIP_PLATFORM TRUE)
    endif()
endif()

set(TOOB_STAGE0_SRC_FILES
    ${TOOB_STAGE0_DIR}/stage0_main.c
    ${TOOB_STAGE0_DIR}/stage0_hash.c
    ${TOOB_STAGE0_DIR}/stage0_verify.c
    ${TOOB_STAGE0_DIR}/stage0_otp.c
    ${TOOB_STAGE0_DIR}/stage0_boot_pointer.c
    ${TOOB_STAGE0_DIR}/stage0_tentative.c
    ${TOOB_CORE_DIR}/boot_platform_bringup.c
    ${TOOB_CORE_DIR}/utils/boot_crc32.c
)
if(NOT S0_HAS_CHIP_PLATFORM AND EXISTS "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
    list(APPEND TOOB_STAGE0_SRC_FILES "${CMAKE_BINARY_DIR}/generated/generated_platform_wiring.c")
endif()

add_executable(toob_stage0 ${TOOB_STAGE0_SRC_FILES})

if(NOT TOOB_ARCH STREQUAL "host")
    target_sources(toob_stage0 PRIVATE ${TOOB_CORE_DIR}/utils/boot_secure_zeroize.S)
else()
    target_sources(toob_stage0 PRIVATE ${TOOB_CORE_DIR}/utils/boot_secure_zeroize_host.c)
    target_compile_definitions(toob_stage0 PRIVATE
        TOOB_WAL_SECTOR_ADDRS={0x4000,0x5000,0x6000,0x10000}
    )
endif()

target_compile_definitions(toob_stage0 PRIVATE
    TOOB_MINIMAL_CRYPTO=1
    TOOB_STAGE0_BUILD=1
    TOOB_COMPACT_ED25519=1
)

if(TOOB_STAGE0_DEV_BYPASS)
    message(WARNING "SECURITY WARNING: TOOB_STAGE0_DEV_BYPASS=ON permits unsigned Stage 1 boot when DSLC==0!")
    target_compile_definitions(toob_stage0 PRIVATE TOOB_ALLOW_DEV_BYPASS=1)
else()
    target_compile_definitions(toob_stage0 PRIVATE TOOB_ALLOW_DEV_BYPASS=0)
endif()

# 2. Core and generated headers
target_include_directories(toob_stage0 PRIVATE
    ${TOOB_STAGE0_DIR}/include
    ${CMAKE_SOURCE_DIR}/common/include
    ${TOOB_CORE_DIR}/include
    ${TOOB_CORE_DIR}/utils/include
    ${CMAKE_BINARY_DIR}/generated
)

# 3. Link static chip and crypto HAL libraries
if(TARGET toob_chip)
    target_link_libraries(toob_stage0 PRIVATE toob_chip)
endif()

if(TARGET toob_crypto)
    target_link_libraries(toob_stage0 PRIVATE toob_crypto toob_crypto_upstream)
endif()

# 4. Strict Compliance Flags (NASA P10) with Freestanding Stack-Protector
if(COMMAND toob_apply_strict_flags)
    toob_apply_strict_flags(toob_stage0 TRUE)
endif()

# 5. Enforce Flash/RAM footprint optimizations (<= 8 KB budget)
target_compile_options(toob_stage0 PRIVATE
    -Os
    -ffunction-sections
    -fdata-sections
)

# 6. Dead-code elimination and Stage 0 linker script
target_link_options(toob_stage0 PRIVATE
    "-Wl,--gc-sections"
    "-T${CMAKE_BINARY_DIR}/generated/stage0_layout.ld"
    "-L${CMAKE_BINARY_DIR}/generated"
)

set_target_properties(toob_stage0 PROPERTIES 
    LINK_DEPENDS "${CMAKE_BINARY_DIR}/generated/stage0_layout.ld"
)

if(TARGET generate_manifest)
    add_dependencies(toob_stage0 generate_manifest)
endif()

# ==============================================================================
# Flashable Raw Binary Generation (.bin) & Budget Check
# ==============================================================================
# Host SIL runs ELF binaries directly; bare-metal targets boot from raw flash images.
if(NOT TOOB_ARCH STREQUAL "host")
    add_custom_command(
        TARGET toob_stage0 POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_stage0> $<TARGET_FILE_DIR:toob_stage0>/toob_stage0.bin
        COMMAND ${TOOB_CLI_PATH} budget --toml "${TOOB_DEVICE_MANIFEST}" --bin $<TARGET_FILE_DIR:toob_stage0>/toob_stage0.bin --stage stage0
        COMMENT "Generating flashable RAW binary toob_stage0.bin and checking flash budget..."
    )
endif()
