# Toob-Boot FreeRTOS Port

Unlike Zephyr and ESP-IDF, FreeRTOS does not provide a universal Flash Hardware Abstraction Layer (HAL).
Because Toob-Boot requires the OS to implement physical flash reads/writes to persist updates into the Write-Ahead Log (WAL), you must implement these for your specific chip vendor.

## Integration Steps

1. Modify `toob_freertos_shim.c`.
2. Include your vendor's specific HAL header (e.g., `stm32_hal_flash.h`, `fsl_flash.h` for NXP, etc.).
3. Implement `toob_os_flash_read` and `toob_os_flash_write` using the vendor HAL.
4. Compile `toob_freertos_shim.c` alongside your FreeRTOS application tasks.
5. Ensure that the `libtoob/include` directory is added to your compiler's include path.
6. Link the precompiled `libtoob.a` library into your final application binary.
