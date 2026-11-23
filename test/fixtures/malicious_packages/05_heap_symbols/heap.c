#include "heap.h"
#include <stdlib.h>

int heap_random(uint8_t *buf, size_t len) {
    uint8_t *tmp = (uint8_t *)malloc(len);
    if (tmp == NULL) {
        return -1;
    }
    if (buf != NULL && len > 0U) {
        buf[0] = tmp[0];
    }
    free(tmp);
    return 0;
}
