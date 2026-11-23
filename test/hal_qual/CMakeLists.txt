cmake_minimum_required(VERSION 3.22)
project(toob_hal_qual C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

get_filename_component(TOOB_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(HAL_QUAL_INCS
    "${CMAKE_CURRENT_LIST_DIR}"
    "${TOOB_ROOT}/test/fuzz/include"
    "${TOOB_ROOT}/common/include"
    "${TOOB_ROOT}/toobloader/core/include"
    "${TOOB_ROOT}/toobloader/core/utils/include"
    "${TOOB_ROOT}/sdk/libtoob/include"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw"
)

add_library(toob_hal_qual STATIC
    "${CMAKE_CURRENT_LIST_DIR}/qual_crypto.c"
    "${CMAKE_CURRENT_LIST_DIR}/qual_entropy.c"
    "${CMAKE_CURRENT_LIST_DIR}/qual_flash.c"
    "${CMAKE_CURRENT_LIST_DIR}/qual_keystore_soc.c"
)
target_include_directories(toob_hal_qual PUBLIC ${HAL_QUAL_INCS})
target_compile_options(toob_hal_qual PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)

add_executable(hal_qual_selftest
    "${CMAKE_CURRENT_LIST_DIR}/hal_qual_main.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_crc32.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_identity.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_secure_zeroize_host.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/monocypher.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/monocypher-ed25519.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/crypto_monocypher.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw/sha256.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw/crypto_sha256.c"
)
target_include_directories(hal_qual_selftest PRIVATE ${HAL_QUAL_INCS})
target_link_libraries(hal_qual_selftest PRIVATE toob_hal_qual)
target_compile_options(hal_qual_selftest PRIVATE -Wall -Wextra -Werror)
