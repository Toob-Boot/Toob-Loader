cmake_minimum_required(VERSION 3.16.0)

if(DEFINED ENV{ZEPHYR_BASE} OR DEFINED ZEPHYR_BASE)
    # -------------------------------------------------------------------------
    # Zephyr OS Build Integration (Out-of-Tree Module, fixed TDR1/TCI1 wire)
    # -------------------------------------------------------------------------
    zephyr_library(toob_network_client)
    zephyr_library_sources(
        src/toob_network_client.c
        src/toob_device_cred.c
    )
    zephyr_library_include_directories(
        include
        ../libtoob/include
        ../../common/include
    )

elseif(DEFINED ENV{IDF_PATH} OR DEFINED IDF_PATH)
    # -------------------------------------------------------------------------
    # ESP-IDF Build Integration (Component, fixed TDR1/TCI1 wire)
    # -------------------------------------------------------------------------
    idf_component_register(
        SRCS
            "src/toob_network_client.c"
            "src/toob_device_cred.c"
        INCLUDE_DIRS
            "include"
            "../libtoob/include"
            "../../common/include"
    )
else()
    # -------------------------------------------------------------------------
    # Generic / Host / POSIX Build (GAP-16)
    # -------------------------------------------------------------------------
    add_library(toob_network_client STATIC
        src/toob_network_client.c
        src/toob_device_cred.c
    )
    target_include_directories(toob_network_client PUBLIC
        include
        ../libtoob/include
        ../../common/include
    )
endif()
