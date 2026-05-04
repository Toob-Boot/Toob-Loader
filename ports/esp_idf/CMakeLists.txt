# ==============================================================================
# ESP-IDF Component Registration for Toob-Boot (libtoob)
# ==============================================================================
# This file allows ESP-IDF to integrate libtoob as a native IDF component.
# It compiles the Zero-Bloat Shim and exposes the libtoob.h headers to the OS.

if(ESP_PLATFORM)
    idf_component_register(
        SRCS "toob_esp_idf_shim.c"
        INCLUDE_DIRS "../../libtoob/include"
        REQUIRES spi_flash
    )

    # Note: You must link the precompiled libtoob.a to this component 
    # in your main project CMakeLists.txt or configure it via the CLI.
endif()
