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

// Bare-metal GCC compiler intrinsic satisfaction
void *memcpy(void *dest, const void *src, uint32_t n) {
  char *d = dest;
  const char *s = src;
  while (n--) {
    *d++ = *s++;
  }
  return dest;
}
