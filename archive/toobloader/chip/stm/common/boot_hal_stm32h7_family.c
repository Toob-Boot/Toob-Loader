#ifdef BOOT_PLATFORM_STM32H7
#include "../../../include/boot_config.h"
#include <stdbool.h>
#include <stdint.h>

#define STM32H743xx
#include "stm32h7xx.h"

// 1. UART
void boot_hal_uart_tx_char(char c) {
  (void)c;
}

// 2. Recovery Pin GPIO Primitive
uint8_t boot_hal_gpio_get_level(uint8_t pin) {
  (void)pin;
  return 0;
}

// 3. Hardware Watchdog
void boot_hal_feed_watchdog(void) {}

// 4. Crypto Secrets (Bootloader Stage 2 Auth)
void boot_hal_get_root_key(uint8_t out_key[32]) {
  (void)out_key;
}

void boot_hal_get_dslc(uint8_t out_key[32]) {
  (void)out_key;
}
#endif

typedef int dummy_stm32h7_iso_c_fix;
