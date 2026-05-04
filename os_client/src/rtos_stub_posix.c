#include "toob_network_client.h"

/* GAP-16: POSIX/Fuzzer stub for rtos_http functions */
#if !defined(__ZEPHYR__) && !defined(ESP_PLATFORM)

#include <string.h>

/* GAP-N04: Implement correct rtos_http_get stub signature */
toob_status_t rtos_http_get(const char* url, uint32_t resume_offset,
                            toob_http_chunk_cb_t callback, void* ctx) {
    (void)url; (void)resume_offset; (void)callback; (void)ctx;
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_network_init(void) {
    return TOOB_ERR_NOT_SUPPORTED;
}

#endif
