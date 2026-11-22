idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES files os_client esp_driver_uart esp_timer freertos esp_system
)

if(NOT DEFINED APP_FW_VER_STR)
    set(APP_FW_VER_STR "1.0.0")
endif()

if(NOT DEFINED APP_SIMULATE_HANG)
    set(APP_SIMULATE_HANG 0)
endif()

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    APP_FW_VER_STR="${APP_FW_VER_STR}"
    APP_SIMULATE_HANG=${APP_SIMULATE_HANG}
)
