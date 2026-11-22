cmake_minimum_required(VERSION 3.16)

get_filename_component(TOOB_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

set(TOOB_SDK_ROOT "${TOOB_REPO_ROOT}/sdk" CACHE PATH "Path to Toob SDK root")
set(TOOB_COMMON_INCLUDE_DIR "${TOOB_REPO_ROOT}/common/include" CACHE PATH "Path to Toob common headers")
set(TOOB_ESPIDF_DIRECT_XIP ON CACHE BOOL "Enable Toob Direct-XIP handoff" FORCE)

list(APPEND EXTRA_COMPONENT_DIRS
    "${TOOB_REPO_ROOT}/toob-infra/registry/packages/integrations/espidf/files"
    "${TOOB_REPO_ROOT}/sdk/os_client"
)

set(COMPONENTS
    main
    files
    os_client
    esp_driver_uart
    esptool_py
    partition_table
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(toob_espidf_qemu_app)
