#include <stdbool.h>
#include <stdint.h>

// Safe read prototype (implemented in assembly to catch hardware faults)
// Default mock implementation always succeeds
bool probe_read32(uint32_t addr, uint32_t *out_val) {
  if (out_val) {
    *out_val = 0xDEADBEEF;
  }
  return true;
}

// Abstract Flash Sector erase prototype
bool chip_flash_erase(uint32_t sector_addr) {
  (void)sector_addr;
  return true;
}

// Abstract Flash Sector write prototype
bool chip_flash_write32(uint32_t addr, uint32_t val) {
  (void)addr;
  (void)val;
  return true;
}

// Bare-metal GCC compiler intrinsic satisfaction
void *memcpy(void *dest, const void *src, uint32_t n) {
  char *d = dest;
  const char *s = src;
  while (n--) {
    *d++ = *s++;
  }
  return dest;
}
