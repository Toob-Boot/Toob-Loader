cmake_minimum_required(VERSION 3.16.0)

if(DEFINED ENV{ZEPHYR_BASE} OR DEFINED ZEPHYR_BASE)
    # -------------------------------------------------------------------------
    # Zephyr OS Build Integration (Out-of-Tree Module)
    # -------------------------------------------------------------------------
    zephyr_library(toob_network_client)
    zephyr_library_sources(src/toob_network_client.c)
    
    zephyr_library_include_directories(include)
    
    # GAP-04 / GAP-N14: CBOR parsing requires zcbor
    zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/include)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/src/zcbor_decode.c)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/src/zcbor_common.c)
    
elseif(DEFINED ENV{IDF_PATH} OR DEFINED IDF_PATH)
    # -------------------------------------------------------------------------
    # ESP-IDF Build Integration (Component)
    # -------------------------------------------------------------------------
    idf_component_register(
        SRCS 
            "src/toob_network_client.c"
        INCLUDE_DIRS 
            "include"
        REQUIRES 
            "zcbor"
    )
else()
    # -------------------------------------------------------------------------
    # Generic / Fuzzer / POSIX Build (GAP-16)
    # -------------------------------------------------------------------------
    add_library(toob_network_client STATIC 
        src/toob_network_client.c
    )
    target_include_directories(toob_network_client PUBLIC include)
endif()
