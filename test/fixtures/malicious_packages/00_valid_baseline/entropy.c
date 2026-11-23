#include "entropy.h"

int clean_entropy_init(void) { return 0; }
void clean_entropy_deinit(void) {}
int clean_entropy_random(uint8_t *buf, size_t len) {
    if ((buf == NULL) || (len == 0U)) {
        return -1;
    }
    for (size_t i = 0U; i < len; i++) {
        buf[i] = 0xFFU;
    }
    return 0;
}
