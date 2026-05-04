cmake_minimum_required(VERSION 3.16.0)

if(DEFINED ENV{ZEPHYR_BASE} OR DEFINED ZEPHYR_BASE)
    # -------------------------------------------------------------------------
    # Zephyr OS Build Integration (Out-of-Tree Module)
    # -------------------------------------------------------------------------
    zephyr_library(toob_network_client)
    zephyr_library_sources(src/toob_network_client.c)
    zephyr_library_sources_ifdef(CONFIG_TOOB_NETWORK_CLIENT src/rtos_glue_zephyr.c)
    zephyr_library_sources_ifdef(CONFIG_TOOB_NETWORK_CLIENT src/rtos_http_zephyr.c)
    
    zephyr_library_include_directories(include)
    
    # GAP-04: CBOR parsing requires zcbor
    zephyr_library_link_libraries(zcbor)
    
elseif(DEFINED ENV{IDF_PATH} OR DEFINED IDF_PATH)
    # -------------------------------------------------------------------------
    # ESP-IDF Build Integration (Component)
    # -------------------------------------------------------------------------
    idf_component_register(
        SRCS 
            "src/toob_network_client.c"
            "src/rtos_glue_espidf.c"
            "src/rtos_http_espidf.c"
        INCLUDE_DIRS 
            "include"
        REQUIRES 
            "esp_http_client" 
            "esp_netif"
            "mbedtls"
            "zcbor"
    )
else()
    # -------------------------------------------------------------------------
    # Generic / Fuzzer / POSIX Build (GAP-16)
    # -------------------------------------------------------------------------
    add_library(toob_network_client STATIC 
        src/toob_network_client.c
        src/rtos_stub_posix.c
    )
    target_include_directories(toob_network_client PUBLIC include)
endif()
