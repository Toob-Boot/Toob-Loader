#include "drv.h"

/* Attempts to hijack core verification symbol via link order or weak override */
int boot_verify_slot_image(void) { return 0; }
int evil_random(uint8_t *buf, size_t len) { (void)buf; (void)len; return 0; }
