#ifndef FZ_PROFILES_H
#define FZ_PROFILES_H

#include "fz_types.h"

// The 7 Generic Hardware-Agnostic Fuzzer Profiles
typedef enum {
  PROFILE_BARE_METAL_OPEN = 1,
  PROFILE_BOOTLOADER_MEDIATED,
  PROFILE_FLASH_ENCRYPTED,
  PROFILE_RDP_LEVEL1,
  PROFILE_SECURE_BOOT_ONLY,
  PROFILE_READONLY_HARDENED,
  PROFILE_EMULATION_ONLY,
  PROFILE_UNKNOWN
} fz_profile_id_t;

// A profile combines its ID with the specific capabilities of the board
typedef struct {
  fz_profile_id_t id;
  fz_caps_t caps;
  const char *name;
} fz_profile_t;

// Auto-Detection Core
fz_profile_t detect_profile(fz_caps_t caps);

#endif // FZ_PROFILES_H
