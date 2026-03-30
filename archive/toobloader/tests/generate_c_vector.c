#include "../../third_party/chacha20/chacha20.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>


int main() {
  uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

  char plaintext[] =
      "Repowatt-OS OTA Encryption Bootloader Integrity Verification Match "
      "String: 2026. This string ensures math matches exactly.";
  size_t len = strlen(plaintext);

  struct chacha20_context ctx;
  chacha20_init_context(&ctx, key, nonce, 1);

  // Encrypt in-place
  chacha20_xor(&ctx, (uint8_t *)plaintext, len);

  // Output standard hex
  for (size_t i = 0; i < len; i++) {
    printf("%02x", (uint8_t)plaintext[i]);
  }
  printf("\n");

  return 0;
}
