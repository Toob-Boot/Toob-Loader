import os
import subprocess

os.makedirs('build_c6_ninja/generated', exist_ok=True)
with open('build_c6_ninja/generated/toob_config.cmake', 'w') as f:
    f.write('set(TOOB_ARCH "riscv32")\n')
    f.write('set(TOOB_VENDOR "esp")\n')
    f.write('set(TOOB_CHIP "esp32c6")\n')
    f.write('set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/cmake/toolchain-riscv32.cmake")\n')
    f.write('set(TOOLCHAIN_PREFIX "C:/Espressif/tools/riscv32-esp-elf/esp-14.2.0_20251107/riscv32-esp-elf/bin/riscv32-esp-elf-")\n')

subprocess.run(['cmake', '-DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-riscv32.cmake', '-DTOOLCHAIN_PREFIX=riscv32-esp-elf-', '-DCMAKE_SYSTEM_NAME=Generic', '-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY', '-B', 'build_c6_ninja', '-G', 'Ninja'])
