# CMakeLists.txt for Panic Firmware (Stage 2 USB Recovery)

set(RECOVERY_SRC
    panic_main.c
)

add_library(core_recovery STATIC ${RECOVERY_SRC})

# We link against the same minimal HAL and headers as Stage 1 Bootloader,
# plus the Ed25519 verification library for the 2FA Handshake.
target_include_directories(core_recovery PRIVATE 
    ../include
    ../third_party/compact25519/include
)
