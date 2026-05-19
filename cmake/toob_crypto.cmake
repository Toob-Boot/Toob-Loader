# ==============================================================================
# Submodule: toob_crypto (Pluggable Crypto Backends)
#
# This CMake module is a generic engine that consumes per-slot crypto variables
# injected by the CLI via generated/toob_config.cmake. It builds two targets:
#
#   toob_crypto_upstream  — Third-party source code, compiled with relaxed flags
#   toob_crypto           — P10-compliant HAL wrappers, compiled with strict flags
#
# The CLI resolves crypto packages from registry.json and emits:
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_ENABLED   ON/OFF
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_SOURCES   Semicolon-separated source file list
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_WRAPPER   Path to the HAL wrapper C file
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_CFLAGS    Semicolon-separated compiler flags
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_INCLUDES  Semicolon-separated include dirs
#   TOOB_CRYPTO_{BACKEND,HASH,PQC}_DIR       Package root directory
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Collect sources from all enabled slots (before creating targets)
# ------------------------------------------------------------------------------
set(_CRYPTO_ALL_SOURCES "")
set(_CRYPTO_ALL_INCLUDES "")
set(_CRYPTO_ALL_WRAPPERS "")

# --- Backend Slot ---
if(TOOB_CRYPTO_BACKEND_ENABLED)
    if(DEFINED TOOB_CRYPTO_BACKEND_SOURCES AND NOT "${TOOB_CRYPTO_BACKEND_SOURCES}" STREQUAL "")
        list(APPEND _CRYPTO_ALL_SOURCES ${TOOB_CRYPTO_BACKEND_SOURCES})
    endif()
    if(DEFINED TOOB_CRYPTO_BACKEND_DIR)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_BACKEND_DIR})
    endif()
    if(DEFINED TOOB_CRYPTO_BACKEND_INCLUDES)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_BACKEND_INCLUDES})
    endif()
    if(DEFINED TOOB_CRYPTO_BACKEND_WRAPPER)
        list(APPEND _CRYPTO_ALL_WRAPPERS ${TOOB_CRYPTO_BACKEND_WRAPPER})
    endif()
endif()

# --- Hash Slot ---
if(TOOB_CRYPTO_HASH_ENABLED)
    if(DEFINED TOOB_CRYPTO_HASH_SOURCES AND NOT "${TOOB_CRYPTO_HASH_SOURCES}" STREQUAL "")
        list(APPEND _CRYPTO_ALL_SOURCES ${TOOB_CRYPTO_HASH_SOURCES})
    endif()
    if(DEFINED TOOB_CRYPTO_HASH_DIR)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_HASH_DIR})
    endif()
    if(DEFINED TOOB_CRYPTO_HASH_INCLUDES)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_HASH_INCLUDES})
    endif()
    if(DEFINED TOOB_CRYPTO_HASH_WRAPPER)
        list(APPEND _CRYPTO_ALL_WRAPPERS ${TOOB_CRYPTO_HASH_WRAPPER})
    endif()
endif()

# --- PQC Slot ---
if(TOOB_CRYPTO_PQC_ENABLED)
    if(DEFINED TOOB_CRYPTO_PQC_SOURCES AND NOT "${TOOB_CRYPTO_PQC_SOURCES}" STREQUAL "")
        list(APPEND _CRYPTO_ALL_SOURCES ${TOOB_CRYPTO_PQC_SOURCES})
    endif()
    if(DEFINED TOOB_CRYPTO_PQC_DIR)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_PQC_DIR})
    endif()
    if(DEFINED TOOB_CRYPTO_PQC_INCLUDES)
        list(APPEND _CRYPTO_ALL_INCLUDES ${TOOB_CRYPTO_PQC_INCLUDES})
    endif()
    if(DEFINED TOOB_CRYPTO_PQC_WRAPPER)
        list(APPEND _CRYPTO_ALL_WRAPPERS ${TOOB_CRYPTO_PQC_WRAPPER})
    endif()
endif()

# Deduplicate (handles backend+hash pointing to same package)
if(_CRYPTO_ALL_SOURCES)
    list(REMOVE_DUPLICATES _CRYPTO_ALL_SOURCES)
endif()
if(_CRYPTO_ALL_INCLUDES)
    list(REMOVE_DUPLICATES _CRYPTO_ALL_INCLUDES)
endif()
if(_CRYPTO_ALL_WRAPPERS)
    list(REMOVE_DUPLICATES _CRYPTO_ALL_WRAPPERS)
endif()

# ------------------------------------------------------------------------------
# 2. Guard: Only create targets if there are sources to compile
# ------------------------------------------------------------------------------
# CMake requires STATIC libraries to have at least one source file.
# If no crypto is configured, skip target creation entirely.
if(NOT _CRYPTO_ALL_SOURCES AND NOT _CRYPTO_ALL_WRAPPERS)
    message(STATUS "[toob_crypto] No crypto packages configured. Skipping crypto targets.")
    return()
endif()

# ------------------------------------------------------------------------------
# 3. Target: toob_crypto_upstream (Third-Party / Upstream Code)
# ------------------------------------------------------------------------------
# Compiled with relaxed flags to avoid -Werror breaking bit-intensive third-party code.
if(_CRYPTO_ALL_SOURCES)
    add_library(toob_crypto_upstream STATIC ${_CRYPTO_ALL_SOURCES})

    target_include_directories(toob_crypto_upstream PUBLIC
        ${_CRYPTO_ALL_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
    )

    # Apply per-slot compiler flags
    set(_CRYPTO_UPSTREAM_CFLAGS -fno-lto -ffunction-sections -fdata-sections)
    if(TOOB_CRYPTO_BACKEND_ENABLED AND DEFINED TOOB_CRYPTO_BACKEND_CFLAGS)
        list(APPEND _CRYPTO_UPSTREAM_CFLAGS ${TOOB_CRYPTO_BACKEND_CFLAGS})
    else()
        list(APPEND _CRYPTO_UPSTREAM_CFLAGS -Os)
    endif()
    target_compile_options(toob_crypto_upstream PRIVATE ${_CRYPTO_UPSTREAM_CFLAGS})

    if(TOOB_FEATURE_PQC_HYBRID)
        target_compile_definitions(toob_crypto_upstream PUBLIC TOOB_FEATURE_PQC_HYBRID=1)
    endif()
endif()

# ------------------------------------------------------------------------------
# 4. Target: toob_crypto (Toob-Boot Wrapper / HAL Adapter)
# ------------------------------------------------------------------------------
# P10-compliant wrapper implementing the crypto_hal_t interface.
if(_CRYPTO_ALL_WRAPPERS)
    add_library(toob_crypto STATIC ${_CRYPTO_ALL_WRAPPERS})

    if(TOOB_FEATURE_PQC_HYBRID)
        target_compile_definitions(toob_crypto PUBLIC TOOB_FEATURE_PQC_HYBRID=1)
    endif()

    target_include_directories(toob_crypto PUBLIC
        ${_CRYPTO_ALL_INCLUDES}
        ${CMAKE_SOURCE_DIR}/common/include
        ${TOOB_CORE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated
        ${TOOB_SDK_DIR}/libtoob/include
    )

    # Link upstream into the wrapper
    if(TARGET toob_crypto_upstream)
        target_link_libraries(toob_crypto PUBLIC toob_crypto_upstream)
    endif()

    # Apply strict P10 flags to the wrapper code
    if(COMMAND toob_apply_strict_flags)
        toob_apply_strict_flags(toob_crypto TRUE)
    endif()
endif()
