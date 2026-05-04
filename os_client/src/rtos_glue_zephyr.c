#include "toob_network_client.h"

#if defined(__ZEPHYR__)
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>

static const char *TAG = "toob_network";

toob_status_t toob_network_init(void) {
    /* 
     * Zephyr specific network initialization.
     * We verify if we have a default interface and if it's up to pass the L1 Smoke Test.
     */
    struct net_if *iface = net_if_get_default();
    if (!iface) {
        TOOB_LOGE(TAG, "No default network interface found");
        return TOOB_ERR_NOT_FOUND;
    }
    
    if (!net_if_is_up(iface)) {
        TOOB_LOGW(TAG, "Network interface is down");
        return TOOB_ERR_STATE; 
    }
    
    /* In Zephyr, net_if_is_up typically implies L1 readiness. 
     * Full IP verification is deferred to L2 DNS Smoke Test. */
    
    return TOOB_OK;
}

#endif /* __ZEPHYR__ */
