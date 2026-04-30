# ==============================================================================
# Submodule: toob_crypto (Pluggable Crypto Backends)
# 
# Relevant Specs: 
# - docs/concept_fusion.md (Schicht 2: Pluggable Crypto, crypto_arena)
# - docs/structure_plan.md (Verzeichnisbaum `crypto/`)
# - docs/hals.md (crypto_hal_t)
# ==============================================================================

# Option für PQC-Hybrid Modus, wie in concept_fusion.md & hals.md gefordert.
# Wenn OFF, wird der ML-DSA Code vom CMake komplett abgewehrt (Footprint-Sicherheit).
option(TOOB_FEATURE_PQC_HYBRID "Enable PQC ML-DSA-65 Hybrid Mode" OFF)

# Neu: Option zum restlosen Entfernen des Monocypher-Cores, WENN ein SoC 
# (z.B. STM32U5) zu 100% Hardware-Crypto für Hash (SHA-512) UND Ed25519 besitzt!
# ACHTUNG: Monocypher Ed25519 benötigt intern immer SHA-512. Für gewöhnliche ESP32
# HW-SHA256 Chips darf dies NICHT deaktiviert werden!
option(TOOB_CRYPTO_DISABLE_SW_ENGINE "Disable Monocypher SW Engine completely" OFF)

# ------------------------------------------------------------------------------
# 1. Target: toob_crypto_upstream (Third-Party / Vendored Code)
# ------------------------------------------------------------------------------
# ZWECK: Wird isoliert kompiliert, um "-Werror -Wconversion" Warnungen aus 
# bit-intensivem Third-Party Code (wie Monocypher) von unserem P10 Build wegzuhalten.
add_library(toob_crypto_upstream STATIC)

if(NOT TOOB_CRYPTO_DISABLE_SW_ENGINE)
    target_sources(toob_crypto_upstream PRIVATE
        crypto/monocypher/monocypher.c
        crypto/monocypher/monocypher-ed25519.c
        crypto/sha256/sha256.c
    )
    target_include_directories(toob_crypto_upstream PUBLIC 
        crypto/monocypher
        crypto/sha256
        core/include
    )
    
    # GAP Fix: Performance & Constant-Time Guarantee
    # Erzwinge O3 für ~9ms Ed25519 Latenz und blockiere globales LTO (-fno-lto),
    # was bewiesenermaßen Constant-Time Algorithmen kaputt-inlinen kann.
    target_compile_options(toob_crypto_upstream PRIVATE -O3 -fno-lto)
endif()

# Optionaler PQC Code (Zero-Allocation ML-DSA)
if(TOOB_FEATURE_PQC_HYBRID)
    target_sources(toob_crypto_upstream PRIVATE
        crypto/pqc/ml_dsa_65.c
    )
    target_include_directories(toob_crypto_upstream PUBLIC 
        crypto/pqc
    )
    target_compile_definitions(toob_crypto_upstream PUBLIC TOOB_FEATURE_PQC_HYBRID=1)
    
    # Auch PQC profitiert massiv von -O3. LTO ist bei PQC wegen gigantischer 
    # Matrizen ein noch rücksichtsloseres Risiko für Stack-Overflow Inlinings.
    target_compile_options(toob_crypto_upstream PRIVATE -O3 -fno-lto)
    
    # WICHTIG (Architektur-Notiz zu Arena-Validation): 
    # Da boot_config.h erst durch `generate_manifest` zur *BUILD*-Zeit existiert, 
    # verlagern wir den PQC Arena-Sizes Check in den C-Code ('crypto_pqc.c') als:
    # _Static_assert(BOOT_CRYPTO_ARENA_SIZE >= 30000, "Arena too small for PQC");
endif()

# WICHTIGE GAP-DEFENSE: Upstream-Code GANZ BEWUSST von unseren strikten P10-Regeln befreien!
# Das verhindert, dass Warnungen durch Drittanbieter-Code den Build bricken.
# Deshalb rufen wir toob_apply_strict_flags() hier absichtlich NICHT auf!

# ------------------------------------------------------------------------------
# 2. Target: toob_crypto (Toob-Boot Wrapper / HAL Adapter)
# ------------------------------------------------------------------------------
# ZWECK: P10-konformer Wrapper, der das crypto_hal_t Interface implementiert.
add_library(toob_crypto STATIC
    crypto/monocypher/crypto_monocypher.c
)

# Wrapper-Erweiterung für PQC, falls im Manifest aktiviert
if(TOOB_FEATURE_PQC_HYBRID)
    target_sources(toob_crypto PRIVATE
        crypto/pqc/crypto_pqc.c
    )
    target_compile_definitions(toob_crypto PUBLIC TOOB_FEATURE_PQC_HYBRID=1)
endif()

# Toob-Boot Core-Referenzen einspeisen (für boot_hal.h und generierte Header wie chip_config.h)
target_include_directories(toob_crypto PUBLIC
    core/include
    ${CMAKE_BINARY_DIR}/generated
    libtoob/include
)

# Linke den entspannten Upstream in unseren strengen Wrapper
target_link_libraries(toob_crypto PUBLIC toob_crypto_upstream)

# WICHTIG: Auf UNSEREN Wrapper-Code wenden wir P10 / NASA-Rules in voller Härte an!
if(COMMAND toob_apply_strict_flags)
    toob_apply_strict_flags(toob_crypto TRUE)
endif()
