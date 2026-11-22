# SPDX-License-Identifier: Apache-2.0
# Toob-Boot Wave 4C Real Zephyr RTOS + sdk/os_client nRF52840 E2E Application

cmake_minimum_required(VERSION 3.20.0)

get_filename_component(
    _default_toob_repo_root
    "${CMAKE_CURRENT_SOURCE_DIR}/../../.."
    ABSOLUTE
)
set(TOOB_REPO_ROOT "${_default_toob_repo_root}" CACHE PATH "Toob-Loader repository root")

list(PREPEND EXTRA_ZEPHYR_MODULES
    "${TOOB_REPO_ROOT}/toob-infra/registry/packages/integrations/zephyr"
    "${TOOB_REPO_ROOT}/sdk/os_client"
)

if(NOT DEFINED DTC_OVERLAY_FILE)
    set(DTC_OVERLAY_FILE
        "${TOOB_REPO_ROOT}/toob-infra/registry/packages/integrations/zephyr/files/app.overlay"
        "${CMAKE_CURRENT_SOURCE_DIR}/boards/nrf52840dk_nrf52840.overlay"
    )
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(toob_zephyr_nrf52840_e2e LANGUAGES C)

set(APP_FW_VERSION_STR "1.0.0" CACHE STRING "Application firmware semantic version")
set(APP_BAD_UNCONFIRMED "0" CACHE STRING "Set to 1 to skip boot confirm and starve hardware WDT")

target_include_directories(app PRIVATE "${CMAKE_BINARY_DIR}")
target_compile_definitions(app PRIVATE
    DEFAULT_APP_FW_VERSION_STR="${APP_FW_VERSION_STR}"
    DEFAULT_APP_BAD_UNCONFIRMED=${APP_BAD_UNCONFIRMED}
)

target_sources(app PRIVATE src/main.c)
