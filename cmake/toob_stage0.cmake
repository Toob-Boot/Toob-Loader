# ==============================================================================
# Submodule: toob_stage0 (Immutable Boot-Pointer Stage)
# 
# Relevant Specs: 
# - docs/concept_fusion.md (Stage 0: Immutable Core, Boot-Pointer, Fallback)
# - docs/structure_plan.md (Verzeichnisbaum `stage0/`)
# ==============================================================================

# ------------------------------------------------------------------------------
# ZWECK: Stage 0 ist ein hardwarenahes, eigenständiges Binary (4-8 KB Limit).
# Es teilt sich mit Stage 1 keine Logik (kein WAL, keine riesigen Parser), sondern
# validiert und assembliert lediglich den TMR Boot-Pointer und das Tentative-Flag.
# ------------------------------------------------------------------------------

# Option: Wenn per Manifest 'stage0.verify_mode == ed25519-sw' gefordert ist, MUSS
# CMake angewiesen werden, die Krypto-Quellen direkt in S0 zu bündeln, da S0 
# physikalisch völlig separiert von Stage 1 (und damit toob_crypto_upstream) ist!
option(TOOB_STAGE0_ED25519_SW "Bundle full Ed25519 stack into Stage 0 (Footprint ~12 KB)" OFF)

# 1. Target Definition (Executable, keine Library)
# Stage 0 stellt den Entry-Point der kompletten Firmware nach ROM-Exit dar.
add_executable(toob_stage0
    stage0/stage0_main.c
    stage0/stage0_hash.c
    stage0/stage0_verify.c
    stage0/stage0_otp.c
    stage0/stage0_boot_pointer.c
    stage0/stage0_tentative.c
)

if(TOOB_STAGE0_ED25519_SW)
    # GAP-Integration: Performance & Constant-Time in S0.
    set_source_files_properties(
        crypto/monocypher/monocypher.c 
        crypto/monocypher/monocypher-ed25519.c 
        PROPERTIES COMPILE_FLAGS "-O3 -fno-lto"
    )
    target_sources(toob_stage0 PRIVATE
        crypto/monocypher/monocypher.c
        crypto/monocypher/monocypher-ed25519.c
    )
    target_include_directories(toob_stage0 PRIVATE crypto/monocypher)
endif()

# 2. Toob-Boot Core-Includes verfügbar machen (boot_types.h) + Generiertes Config
target_include_directories(toob_stage0 PRIVATE
    stage0/include
    core/include
    ${CMAKE_BINARY_DIR}/generated
)

# 3. Hardware Abstraktion verlinken (toob_chip)
# ARCHITEKTUR-LÖSUNG: Beide Binaries (S0 & S1) benutzen die statische HAL.
if(TARGET toob_chip)
    target_link_libraries(toob_stage0 PRIVATE toob_chip)
endif()

# 4. Strict Compliance Flags (NASA P10) OHNE Stack-Protectors
if(COMMAND toob_apply_strict_flags)
    toob_apply_strict_flags(toob_stage0 TRUE)
endif()

# GAP Fix: Striktes Verbot des Stack-Protectors für Stage 0!
target_compile_options(toob_stage0 PRIVATE
    -fno-stack-protector
)

# 5. Maximale RAM & Flash Size Optimierungen (Footprint <= 8 KB erzwingen)
target_compile_options(toob_stage0 PRIVATE
    -Os
    -ffunction-sections
    -fdata-sections
)

# 6. Dead-Code Elimination und Stage-spezifisches Linker-Skript
target_link_options(toob_stage0 PRIVATE
    "-Wl,--gc-sections"
    "-T${CMAKE_BINARY_DIR}/generated/stage0_layout.ld"
)

# Linker-Trigger:
set_target_properties(toob_stage0 PROPERTIES 
    LINK_DEPENDS "${CMAKE_BINARY_DIR}/generated/stage0_layout.ld"
)

if(TARGET generate_manifest)
    add_dependencies(toob_stage0 generate_manifest)
endif()

# ==============================================================================
# M-BUILD GAP-Fix: Flashable Raw-Binary Generation (.bin)
# ==============================================================================
# Die Sandbox benötigt keine Binary-Dumps, Bare-Metal Cortex-M und Xtensa hingegen
# starten exklusiv aus entpacktem Flash-RAM ohne ELF-Header.
if(NOT TOOB_ARCH STREQUAL "host")
    add_custom_command(
        TARGET toob_stage0 POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:toob_stage0> $<TARGET_FILE_DIR:toob_stage0>/toob_stage0.bin
        COMMENT "Generating flashable RAW binary toob_stage0.bin..."
    )
endif()
