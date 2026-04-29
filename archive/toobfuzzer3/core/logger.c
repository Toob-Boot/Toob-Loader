#include "logger.h"
#include "fz_profiles.h"

// The active policy context
static fz_profile_t g_active_profile;

// External dumb hardware HAL
extern void hal_uart_tx_byte(char c);
extern bool hal_uart_rx_byte(uint8_t *c);

static const char hex_chars[] = "0123456789ABCDEF";

void fz_logger_init(fz_profile_t *active_profile) {
  if (active_profile) {
    g_active_profile = *active_profile;
  }
}

static bool is_logging_allowed(void) {
  // Determine policy based on profile
  switch (g_active_profile.id) {
  case PROFILE_SECURE_BOOT_ONLY:
  case PROFILE_FLASH_ENCRYPTED:
  case PROFILE_RDP_LEVEL1:
  case PROFILE_READONLY_HARDENED:
    // Mute UART physically to avoid Watchdog or Security Monitor panics
    return false;

  case PROFILE_BARE_METAL_OPEN:
  case PROFILE_BOOTLOADER_MEDIATED:
  case PROFILE_EMULATION_ONLY:
  default:
    return true;
  }
}

void fz_log(const char *str) {
  if (!is_logging_allowed()) {
    return; // Silent Fuzzing
  }

  while (*str) {
    hal_uart_tx_byte(*str++);
  }
}

void fz_log_hex(uint32_t val) {
  if (!is_logging_allowed()) {
    return;
  }

  fz_log("0x");
  for (int i = 7; i >= 0; i--) {
    uint8_t nibble = (val >> (i * 4)) & 0x0F;
    char c = hex_chars[nibble];
    hal_uart_tx_byte(c);
  }
}

bool fz_uart_rx_byte(uint8_t *c) {
  if (!is_logging_allowed()) {
    return false;
  }
  return hal_uart_rx_byte(c);
}
