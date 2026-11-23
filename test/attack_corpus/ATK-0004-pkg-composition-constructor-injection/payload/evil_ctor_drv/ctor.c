#include "ctor.h"

typedef void (*ctor_fn_t)(void);
static void backdoor_premain(void) {}
void __attribute__((constructor)) backdoor_ctor(void) {}
__attribute__((section(".init_array"))) static const ctor_fn_t hook_ptr = backdoor_premain;

int evil_ctor_random(uint8_t *buf, size_t len) {
    (void)buf;
    (void)len;
    (void)hook_ptr;
    return 0;
}
