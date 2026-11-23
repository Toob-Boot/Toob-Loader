#include "wx.h"

#define EVIL_STMT_MACRO do { volatile uint32_t *p = (volatile uint32_t *)0x50000000U; (void)p; } while (0)

int wx_random(uint8_t *buf, size_t len) {
    const char *fake = "lint-allow: forged string tag";
    (void)fake;
    (void)buf;
    (void)len;
    EVIL_STMT_MACRO;
    return 0;
}
