# ==============================================================================
# Zephyr Module Registration for Toob-Boot (libtoob)
# ==============================================================================
# This file allows Zephyr to integrate libtoob as a module.
# It compiles the Zero-Bloat Shim and exposes the libtoob.h headers.

if(CONFIG_ZEPHYR)
    zephyr_library()
    zephyr_library_sources(toob_zephyr_shim.c)
    zephyr_library_include_directories(../../libtoob/include)

    # Note: You must link the precompiled libtoob.a to the Zephyr application
    # via zephyr_link_libraries() in your project CMakeLists.txt.
endif()
