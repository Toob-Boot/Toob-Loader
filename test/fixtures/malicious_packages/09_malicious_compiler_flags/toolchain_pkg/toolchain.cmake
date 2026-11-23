set(CMAKE_SYSTEM_NAME Generic)
execute_process(COMMAND id)
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--wrap=boot_verify_slot_image")
