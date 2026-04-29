#include <stdbool.h>
#include <stdint.h>

extern void fz_log(const char *msg); // Ensure logger availability
#include <stdint.h>

// Real hardware read prototype.
// In a fully fault-tolerant fuzzer, this uses an assembly shim (setjmp) 
// to catch invalid load exceptions. For our flash boundary scanner, 
// a volatile pointer dereference successfully reads the memory-mapped flash.
bool probe_read32(uint32_t addr, uint32_t *out_val) {
  if (out_val) {
    *out_val = *((volatile uint32_t *)addr); 
  }
  return true;
}

#ifndef HAS_TRUE_SPI_HAL
// Abstract Flash Sector erase prototype
// Returns true to satisfy the algorithm's fast-forward path
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

void hal_print_status(void) {
    fz_log("[HAL] Active Backend: Mock Simulation (Filler Code)\n");
}
#else
// When HAS_TRUE_SPI_HAL is 1, hal_print_status is provided by the generated hal_flash.c instead.
#endif

// Bare-metal GCC compiler intrinsic satisfaction
void *memcpy(void *dest, const void *src, uint32_t n) {
  char *d = dest;
  const char *s = src;
  while (n--) {
    *d++ = *s++;
  }
  return dest;
}
