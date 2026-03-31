# ==============================================================================
# Submodule: toob_libtoob (OS Boundary C-Library)
# 
# Relevant Specs: 
# - docs/libtoob_api.md (API, Handoff-Memory Definition)
# - docs/concept_fusion.md (Confirm-Flag System, Telemetrie)
# - docs/toob_telemetry.md (CBOR Extraction)
# - docs/structure_plan.md (Verzeichnisbaum `libtoob/`)
# ==============================================================================

# ------------------------------------------------------------------------------
# ZWECK: toob_libtoob ist die Code-Grenzschicht (Boundary), die dem Feature-OS
# (Zephyr, FreeRTOS, NuttX) vom Bootloader aus mitgeliefert wird.
# 
# ARCHITEKTUR-REGEL: Dieses Target darf *NIEMALS* gegen toob_chip, toob_hal oder
# toob_core linken! Eine Kopplung würde hunderte Kilobyte Bootloader-Code in 
# das OS des Kunden zwingen. Die Library kommuniziert ausschließlich passiv über 
# die .noinit Shared-RAM Sektion und WAL-Appends in den Flash.
# ------------------------------------------------------------------------------

add_library(toob_libtoob STATIC
    libtoob/toob_confirm.c
    libtoob/toob_update.c
    libtoob/toob_diag.c
    libtoob/toob_handoff.c
    # GAP-Integration: Die Datei `toob_telemetry_decode.c` wird von `suit/generate.sh` (via `generate_manifest` Target) erstellt.
    ${CMAKE_BINARY_DIR}/generated/toob_telemetry_decode.c
)

# GAP-Fix OS Shim:
# Die OS Shim Integration für `toob_os_flash_write` wurde nun formal in
# `libtoob/include/libtoob_api.h` als `__attribute__((weak))` deklariert.

# 1. Public Includes für das Feature-OS
# Wenn ein RTOS gegen toob_libtoob linkt, erbt es automatisch libtoob_api.h.
target_include_directories(toob_libtoob PUBLIC
    libtoob/include
)

# 2. Private Includes (Generierte Manifest-Brücke)
# Das OS SDK braucht die vom Manifest-Compiler injizierten Flash-Offsets 
# (z.B. WAL_BASE_ADDR, ADDR_CONFIRM_RTC_RAM), um zu wissen, WO es hinschreiben soll.
target_include_directories(toob_libtoob PRIVATE
    ${CMAKE_BINARY_DIR}/generated
)

if(TARGET generate_manifest)
    add_dependencies(toob_libtoob generate_manifest)
endif()

# GAP-Fix: Das `generate_manifest` Custom-Target in `toob_core.cmake` kümmert
# sich bereits automatisch um die CDDL Zcbor-Erzeugung.

# 3. Telemetry CBOR-Parser Boundary (zcbor)
# Das Boot-Diagnostics Struct (toob_boot_diag_t) wird gepackt als CBOR im 
# Shared-RAM übergeben. Das OS muss dieses Parsen können.
#
# LÖSUNG (Symbol-Kollision-Mitigation): Wir linken zcbor strikt als PRIVATE 
# Dependency. Wenn das Feature-OS intern selbst zcbor nutzt, verhindert die 
# Build-Pipeline so eine "Redeclaration of Symbols" auf Include-Ebene.
if(TARGET zcbor)
    target_link_libraries(toob_libtoob PRIVATE zcbor)
endif()

# 4. Compiler-Limits auf OS-Niveau abstimmen
if(COMMAND toob_apply_strict_flags)
    # WICHTIG: FLAG=FALSE! Wir nutzen für die OS-Library keine aggressiven 
    # OS-ausschließenden Compiler-Direktiven (wie -fno-stack-protector), 
    # da dieses Binary am Ende vom RTOS-Stack des Kunden geschluckt wird 
    # und dessen ABI-Regeln blind folgen muss. Warnungen (-Werror) bleiben aktiv.
    toob_apply_strict_flags(toob_libtoob FALSE)
endif()
