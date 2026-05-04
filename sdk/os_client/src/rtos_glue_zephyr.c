#include "toob_network_client.h"

#if defined(__ZEPHYR__)
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>

/* GAP-N08: Declare instead of register to avoid duplicates */
LOG_MODULE_DECLARE(toob_client, LOG_LEVEL_INF);

static const char *TAG = "toob_network";

toob_status_t toob_network_init(void) {
    struct net_if *iface = net_if_get_default();
    if (!iface) {
        TOOB_LOGE(TAG, "No default network interface found");
        return TOOB_ERR_NOT_FOUND;
    }
    
    if (!net_if_is_up(iface)) {
        TOOB_LOGW(TAG, "Network interface is down");
        return TOOB_ERR_STATE; 
    }

    /* GAP-N17: Check if interface has a valid IP assigned */
    if (!net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED)) {
        TOOB_LOGW(TAG, "No IP address assigned");
        return TOOB_ERR_STATE;
    }

    return TOOB_OK;
}

#endif /* __ZEPHYR__ */
