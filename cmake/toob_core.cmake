# ==============================================================================
# Submodule: toob_core (Hardware-Freier Bootloader Kern)
# 
# Relevant Specs: 
# - docs/concept_fusion.md (Schicht 3: Core Engine, Schicht 4b: Diagnostics)
# - docs/structure_plan.md (Verzeichnisbaum `core/`)
# - docs/merkle_spec.md (Chunk-based Verification)
# - docs/stage_1_5_spec.md (UART Recovery)
# - docs/wal_internals.md (Write-Ahead Log)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Externes Tooling / Vendored Third-Party
# ------------------------------------------------------------------------------
# Wir isolieren Third-Party Code absichtlich in eigene statische Targets.
# Dadurch bewahren wir diese Bibliotheken davor, von unserem knallharten
# `-Werror` & P10-Regelwerk aus `toob_apply_strict_flags` zerrissen zu werden.

# zcbor (Apache-2.0)
add_library(toob_zcbor STATIC 
    lib/zcbor/src/zcbor_decode.c
    lib/zcbor/src/zcbor_common.c
)
target_include_directories(toob_zcbor PUBLIC lib/zcbor/include)

# heatshrink (ISC License)
add_library(toob_heatshrink STATIC 
    lib/heatshrink/heatshrink_decoder.c
)
# WICHTIG (Zero-Allocation Limit): Ohne dieses Define würde heatshrink via malloc
# dynamisch Dictionary-Speicher anfordern, was das P10-Setup hart crashen würde!
target_compile_definitions(toob_heatshrink PUBLIC HEATSHRINK_DYNAMIC_ALLOC=0)
target_include_directories(toob_heatshrink PUBLIC lib/heatshrink)

# ------------------------------------------------------------------------------
# 2. Toob-Boot Kern (Die State-Machine)
# ------------------------------------------------------------------------------

# Die SUIT-Manifest Parser C-File wird via zcbor Compiler-Tool dynamisch
# anhand von device.toml generiert. Daher müssen wir CMake warnen, dass
# die Datei zur Evaluierungszeit evtl. noch gar nicht im Filebaum liegt.
set(GENERATED_SUIT_C "${CMAKE_BINARY_DIR}/generated/boot_suit.c")
set_source_files_properties(${GENERATED_SUIT_C} PROPERTIES GENERATED TRUE)

# M-BUILD GAP-Fix: Custom Command zum Aufrufen der SUIT & Config Generation
add_custom_command(
    OUTPUT ${GENERATED_SUIT_C}
           ${CMAKE_BINARY_DIR}/generated/toob_telemetry_decode.c
           ${CMAKE_BINARY_DIR}/generated/chip_config.h
           ${CMAKE_BINARY_DIR}/generated/stage0_layout.ld
           ${CMAKE_BINARY_DIR}/generated/chip_config_mock.c
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/generated
    
    # -------------------------------------------------------------------------
    # SUIT & Config Mocking / Generation Bridge
    # -------------------------------------------------------------------------
    # Führt das Shell-Skript aus, welches intelligent prüft, ob ZCBOR vorhanden ist.
    # Fehlt Python oder ZCBOR, generiert das Skript C-Mocks und das rettende
    # `stage0_layout.ld` Dummy-File, um Windows-Linker Abstürze zu verhindern.
    # -------------------------------------------------------------------------
    COMMAND bash ${CMAKE_SOURCE_DIR}/suit/generate.sh ${CMAKE_BINARY_DIR}/generated
    COMMENT "Executing SUIT ZCBOR CodeGen & Config-Bridge..."
)

# Dieses Target wird von toob_chip und toob_stage0 erwartet!
add_custom_target(generate_manifest
    DEPENDS ${GENERATED_SUIT_C}
            ${CMAKE_BINARY_DIR}/generated/toob_telemetry_decode.c
            ${CMAKE_BINARY_DIR}/generated/chip_config.h
            ${CMAKE_BINARY_DIR}/generated/stage0_layout.ld
            ${CMAKE_BINARY_DIR}/generated/chip_config_mock.c
)


add_library(toob_core STATIC
    core/boot_main.c
    core/boot_state.c
    core/boot_journal.c
    core/boot_verify.c
    core/boot_merkle.c
    core/boot_swap.c
    core/boot_delta.c
    core/boot_rollback.c
    core/boot_panic.c
    core/boot_confirm.c
    core/boot_diag.c
    core/boot_energy.c
    core/boot_multiimage.c
    core/boot_delay.c
    ${GENERATED_SUIT_C}
)

# Harte Abhängigkeits-Schranke: Schützt vor Race-Conditions bei parallelen Builds (ninja -j8)!
# toob_core MUSS zwingend warten, bis die generate.sh alle Header & Mocks abgeworfen hat.
add_dependencies(toob_core generate_manifest)

# Architektur-bedingter Ausschluss: In der Sandbox (x86 host) können wir 
# keine Bare-Metal (ARM/Xtensa) Assembler-Anweisungen ausführen.
if(NOT TOOB_ARCH STREQUAL "host")
    target_sources(toob_core PRIVATE core/boot_secure_zeroize.S)
else()
    # M-BUILD GAP-Fix: Sandbox Host-Mock für Assembler-Dateien und Hardware Pointers!
    target_sources(toob_core PRIVATE 
        core/boot_secure_zeroize_host.c
        ${CMAKE_BINARY_DIR}/generated/chip_config_mock.c
    )
endif()

# ------------------------------------------------------------------------------
# 3. Include-Pfade & Linking & Härtung
# ------------------------------------------------------------------------------

target_include_directories(toob_core PUBLIC 
    core/include 
    ${CMAKE_BINARY_DIR}/generated
)

# Bindung an Third-Party Libs und dynamische Feature-Verwendung
target_link_libraries(toob_core PRIVATE toob_zcbor toob_heatshrink)

# P10 Härtung anwenden (TRUE: wir erlauben -fstack-protector-strong für den Core,
# da hier Arrays bearbeitet werden, anders als in der winzigen Stage 0)
toob_apply_strict_flags(toob_core TRUE)
