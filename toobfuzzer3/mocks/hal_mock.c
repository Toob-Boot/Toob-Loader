#include <stdbool.h>
#include <stdint.h>

// Real physical read prototype. On advanced architectures, this should be an assembly stub to catch LoadProhibited faults.
bool probe_read32(uint32_t addr, uint32_t *out_val) {
  if (out_val) {
    if (addr == 0x0) return false; // Null pointer protection
    // Perform a genuine, raw hardware memory dereference
    *out_val = *((volatile uint32_t *)addr);
  }
  return true;
}

// Abstract Flash Sector erase prototype
// Returns false because we do not have a bare-metal SPI Flash driver for this chip yet!
bool chip_flash_erase(uint32_t sector_addr) {
  (void)sector_addr;
  return false; // Tells the algorithm that the hardware rejected/ignored the erase command
}

// Abstract Flash Sector write prototype
// Returns false because we cannot write bare-metal flash without a vendor SPI sequence
bool chip_flash_write32(uint32_t addr, uint32_t val) {
  (void)addr;
  (void)val;
  return false;
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
