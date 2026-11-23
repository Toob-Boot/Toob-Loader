cmake_minimum_required(VERSION 3.22)
project(toob_fuzz C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(TOOB_FUZZ_LIBFUZZER "Build targets with -fsanitize=fuzzer instead of standalone corpus runner" OFF)
option(TOOB_FUZZ_ENABLE_SANITIZERS "Enable -fsanitize=address,undefined when supported" ON)

get_filename_component(TOOB_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(FUZZ_INCLUDE_DIRS
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/include"
    "${TOOB_ROOT}/common/include"
    "${TOOB_ROOT}/common/lib/heatshrink"
    "${TOOB_ROOT}/toobloader/core/include"
    "${TOOB_ROOT}/toobloader/core/utils/include"
    "${TOOB_ROOT}/sdk/libtoob"
    "${TOOB_ROOT}/sdk/libtoob/include"
    "${TOOB_ROOT}/recovery"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw"
)

set(HS_DEFS
    HEATSHRINK_DYNAMIC_ALLOC=0
    HEATSHRINK_STATIC_INPUT_BUFFER_SIZE=128
    HEATSHRINK_STATIC_WINDOW_BITS=8
    HEATSHRINK_STATIC_LOOKAHEAD_BITS=4
)

add_library(fuzz_third_party STATIC
    "${TOOB_ROOT}/common/lib/heatshrink/heatshrink_decoder.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/monocypher.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/monocypher-ed25519.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/backend/monocypher/crypto_monocypher.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw/sha256.c"
    "${TOOB_ROOT}/toob-infra/registry/packages/crypto/hash/sha256_sw/crypto_sha256.c"
)
target_include_directories(fuzz_third_party PUBLIC ${FUZZ_INCLUDE_DIRS})
target_compile_definitions(fuzz_third_party PUBLIC ${HS_DEFS})
target_compile_options(fuzz_third_party PRIVATE -O1 -g)

add_library(fuzz_core_common STATIC
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_platform.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_crc32.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_identity.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_secure_zeroize_host.c"
)
target_include_directories(fuzz_core_common PUBLIC ${FUZZ_INCLUDE_DIRS})
target_compile_definitions(fuzz_core_common PUBLIC ${HS_DEFS})
target_compile_options(fuzz_core_common PRIVATE -Wall -Wextra -Werror -O1 -g)

function(toob_add_fuzz_target TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})
    target_include_directories(${TARGET_NAME} PRIVATE ${FUZZ_INCLUDE_DIRS})
    target_compile_definitions(${TARGET_NAME} PRIVATE ${HS_DEFS} $<$<PLATFORM_ID:Windows>:_CRT_SECURE_NO_WARNINGS=1>)
    target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -Werror -O1 -g -fno-omit-frame-pointer)
    target_link_libraries(${TARGET_NAME} PRIVATE fuzz_core_common fuzz_third_party)

    if(TOOB_FUZZ_LIBFUZZER)
        target_compile_options(${TARGET_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(${TARGET_NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
    else()
        target_compile_definitions(${TARGET_NAME} PRIVATE TOOB_FUZZ_STANDALONE=1)
        if(TOOB_FUZZ_ENABLE_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "Clang")
            target_compile_options(${TARGET_NAME} PRIVATE -fsanitize=address,undefined)
            target_link_options(${TARGET_NAME} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

toob_add_fuzz_target(fuzz_tbm1
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_tbm1.c"
    "${TOOB_ROOT}/toobloader/core/boot_tbm1.c"
    "${TOOB_ROOT}/toobloader/core/boot_verify.c"
)

toob_add_fuzz_target(fuzz_tcc1
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_tcc1.c"
    "${TOOB_ROOT}/toobloader/core/boot_cloud_cmd.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
    "${TOOB_ROOT}/toobloader/core/boot_rstore.c"
)

toob_add_fuzz_target(fuzz_kdm
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_kdm.c"
    "${TOOB_ROOT}/toobloader/core/boot_cloud_cmd.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
    "${TOOB_ROOT}/toobloader/core/boot_rstore.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_cobs.c"
)

toob_add_fuzz_target(fuzz_wal_journal
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_wal_journal.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
)

toob_add_fuzz_target(fuzz_cobs_mailbox
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_cobs_mailbox.c"
    "${TOOB_ROOT}/toobloader/core/utils/boot_cobs.c"
    "${TOOB_ROOT}/toobloader/core/boot_mailbox.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
)

toob_add_fuzz_target(fuzz_xmodem
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_xmodem.c"
    "${TOOB_ROOT}/sdk/libtoob/toob_ota.c"
    "${TOOB_ROOT}/sdk/libtoob/toob_update.c"
    "${TOOB_ROOT}/sdk/libtoob/toob_mailbox.c"
    "${TOOB_ROOT}/sdk/libtoob/toob_handoff.c"
    "${TOOB_ROOT}/sdk/libtoob/toob_crc32.c"
)

toob_add_fuzz_target(fuzz_decomp_delta
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_decomp_delta.c"
    "${TOOB_ROOT}/toobloader/core/boot_decomp.c"
    "${TOOB_ROOT}/toobloader/core/boot_delta.c"
    "${TOOB_ROOT}/toobloader/core/boot_swap.c"
    "${TOOB_ROOT}/toobloader/core/boot_effect.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
)

toob_add_fuzz_target(fuzz_multiimage
    "${CMAKE_CURRENT_LIST_DIR}/fuzz_multiimage.c"
    "${TOOB_ROOT}/toobloader/core/boot_multiimage.c"
    "${TOOB_ROOT}/toobloader/core/boot_verify.c"
    "${TOOB_ROOT}/toobloader/core/boot_swap.c"
    "${TOOB_ROOT}/toobloader/core/boot_effect.c"
    "${TOOB_ROOT}/toobloader/core/boot_journal.c"
)
