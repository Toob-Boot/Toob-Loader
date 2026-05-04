#include "toob_network_client.h"

/* GAP-16: POSIX/Fuzzer stub for rtos_http functions */
#if !defined(__ZEPHYR__) && !defined(ESP_PLATFORM)

#include <string.h>

toob_status_t rtos_http_check_update(const char* url, uint32_t current_svn,
                                     toob_update_info_t* out_info) {
    (void)url; (void)current_svn;
    if (out_info) memset(out_info, 0, sizeof(toob_update_info_t));
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t rtos_http_download_payload(const char* url, uint32_t resume_offset) {
    (void)url; (void)resume_offset;
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_network_init(void) {
    return TOOB_ERR_NOT_SUPPORTED;
}

#endif
