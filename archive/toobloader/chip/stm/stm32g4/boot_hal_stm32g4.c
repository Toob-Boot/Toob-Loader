#include "../../../include/boot_config.h"
#include "../../../include/common/kb_tags.h"
#include <stdbool.h>
#include <stdint.h>

KB_CORE()
int32_t boot_flash_read(uint32_t addr, uint8_t *buf, uint32_t len) {
  (void)addr;
  (void)buf;
  (void)len;
  return 0;
}

KB_CORE()
static int32_t __attribute__((unused)) boot_flash_erase_sector(uint32_t addr) {
  (void)addr;
  return 0;
}

KB_CORE()
static int32_t __attribute__((unused)) boot_flash_write_raw(uint32_t addr, const uint8_t *data,
                                    uint32_t len) {
  (void)addr;
  (void)data;
  (void)len;
  return 0;
}

void boot_uart_puts(const char *msg) {
  (void)msg;
}

KB_FEATURE("boot_hal_stm32g4")
void boot_hal_init(void) {}
