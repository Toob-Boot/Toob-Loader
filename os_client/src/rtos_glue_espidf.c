#include "toob_network_client.h"

#if defined(ESP_PLATFORM)
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <string.h>

static const char *TAG = "toob_network";

toob_status_t toob_network_init(void) {
    /*
     * ESP-IDF specific network initialization.
     * Usually the user application calls esp_netif_init() and sets up WiFi.
     * We just verify if we have an IP address to pass the L1 Smoke Test.
     */
     
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) {
        TOOB_LOGE(TAG, "No default WiFi interface found");
        return TOOB_ERR_NOT_FOUND;
    }

    if (!esp_netif_is_netif_up(netif)) {
        TOOB_LOGW(TAG, "Network interface is down");
        return TOOB_ERR_STATE;
    }
    
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        TOOB_LOGW(TAG, "No IP address assigned");
        return TOOB_ERR_TIMEOUT;
    }

    return TOOB_OK;
}

#endif /* ESP_PLATFORM */
