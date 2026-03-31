# ==============================================================================
# Toolchain: Sandbox Host (x86_64 / ARM64 macOS / Linux)
# 
# Relevant Specs: 
# - docs/sandbox_setup.md (Host-basiertes Testing, Link-Time Mocking)
# - docs/testing_requirements.md (SIL / Software Integration Tests)
# - docs/structure_plan.md (Target Matrix)
# ==============================================================================

# WICHTIG: Setze KEINEN CMAKE_SYSTEM_NAME, damit CMake auto-detect läuft!
# Dadurch verhält sich das System exakt wie der native Mac/Linux Kernel.

# ------------------------------------------------------------------------------
# 1. Compiler Discovery (inklusive Fuzzing Overrides)
# ------------------------------------------------------------------------------
# Wenn $CC gesetzt ist (z.B. afl-gcc / afl-clang-fast durch AFL++), greift 
# CMake diesen automatisch auf. Ansonsten forcieren wir einen vernünftigen Default.
if(NOT DEFINED ENV{CC})
    set(CMAKE_C_COMPILER gcc)
endif()

# ------------------------------------------------------------------------------
# 2. Host / Sandbox Makros (Architektur Identifikation)
# ------------------------------------------------------------------------------
# Hiermit signalisieren wir dem C-Code, dass er in der SIL-Simulationsumgebung 
# liegt und z.B. /dev/urandom nutzen oder via "--wrap" gemockt werden darf.
add_compile_definitions(TOOB_TARGET_SANDBOX=1)

# ------------------------------------------------------------------------------
# 3. Testing, Coverage & Sanitizer Flags (libasan / libfuzzer)
# ------------------------------------------------------------------------------
option(TOOB_ENABLE_ASAN "Enable Address Sanitizer for Host-Testing" OFF)
option(TOOB_ENABLE_COVERAGE "Enable Gcov Code-Coverage for Host-Testing" OFF)

if(TOOB_ENABLE_ASAN)
    # Aktiviert ASAN & UBSAN für Unit-Tests & Fuzzing (GAP-F19)
    # Das O0 und -g3 ist Pflicht für stack-traces und genaue Fehlerorte!
    add_compile_options(-fsanitize=address,undefined -g3 -O0 -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(TOOB_ENABLE_COVERAGE)
    # Generiert .gcno / .gcda Dateien für LCOV Auswertungen
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(-lgcov)
endif()

# ------------------------------------------------------------------------------
# 4. POSIX Support für Sandbox-OS Features (GAP Fix)
# ------------------------------------------------------------------------------
# Da Toob-Boot strikt mit -std=c17 kompiliert (siehe Root CMakeLists.txt), 
# blendet der Host-GCC alle POSIX-Funktionen wie mmap() aus. Die Sandbox 
# benötigt aber O(1) RAM-Disk Simulation via mmap (siehe testing_requirements.md).
# Wir müssen die POSIX-Sichtbarkeit erzwingen!
add_compile_definitions(
    _POSIX_C_SOURCE=200809L
    _GNU_SOURCE=1
)

# ------------------------------------------------------------------------------
# 5. LibFuzzer Architektur (NOTE)
# ------------------------------------------------------------------------------
option(TOOB_ENABLE_LIBFUZZER "Enable LLVM libFuzzer (-fsanitize=fuzzer) for fuzz targets" OFF)

# NOTE: [Phase 4 / Fuzzing] LibFuzzer Linkage Implementierung
#       Wenn TOOB_ENABLE_LIBFUZZER ON ist, darf -fsanitize=fuzzer NICHT global 
#       angewendet werden, da es eine eigene main() injiziert und die regulären 
#       SIL-Tests zerstören würde. 
#       Es muss eine Toolchain-spezifische Variable bereitgestellt werden 
#       (z.B. TOOB_FUZZER_FLAGS), die *nur* exklusiv an die LibFuzzer-Targets 
#       (wie fuzz_suit_parser) weitergereicht wird.
