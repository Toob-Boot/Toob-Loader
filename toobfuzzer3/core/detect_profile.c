#include "fz_profiles.h"

fz_profile_t detect_profile(fz_caps_t caps) {
  fz_profile_t profile = {
      .caps = caps, .id = PROFILE_UNKNOWN, .name = "UNKNOWN"};

  // 1. Immutable / RDP Level 2 (Blackbox)
  if (caps.rdp_level >= 2) {
    profile.id = PROFILE_READONLY_HARDENED;
    profile.name = "READONLY_HARDENED";
    return profile;
  }

  // 2. Flash Encryption (ESP32-C3/C6, nRF53)
  if (caps.flash_encrypted) {
    profile.id = PROFILE_FLASH_ENCRYPTED;
    profile.name = "FLASH_ENCRYPTED";
    return profile;
  }

  // 3. User-Flash only (STM32 RDP Level 1)
  if (caps.rdp_level == 1) {
    profile.id = PROFILE_RDP_LEVEL1;
    profile.name = "RDP_LEVEL1";
    return profile;
  }

  // 4. JTAG Locked but Firmware boots (Bootloader Mediated)
  if (!caps.debug_access) {
    profile.id = PROFILE_BOOTLOADER_MEDIATED;
    profile.name = "BOOTLOADER_MEDIATED";
    return profile;
  }

  // 5. Default Fallback
  profile.id = PROFILE_BARE_METAL_OPEN;
  profile.name = "BARE_METAL_OPEN";
  return profile;
}
