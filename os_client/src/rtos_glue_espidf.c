#include "toob_network_client.h"

#if defined(ESP_PLATFORM)
#include "esp_netif.h"
#include "esp_event.h"

static const char *TAG = "toob_network";

toob_status_t toob_network_init(void) {
    /* GAP-14: Iterate all interfaces instead of hardcoding WiFi */
    esp_netif_t *netif = NULL;
    esp_netif_ip_info_t ip_info;
    bool found_active = false;

    while ((netif = esp_netif_next(netif)) != NULL) {
        if (!esp_netif_is_netif_up(netif)) {
            continue;
        }
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            found_active = true;
            break;
        }
    }

    if (!found_active) {
        TOOB_LOGW(TAG, "No active network interface with IP found");
        return TOOB_ERR_STATE;
    }

    return TOOB_OK;
}

#endif /* ESP_PLATFORM */
