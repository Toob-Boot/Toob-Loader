#include "toob_network_client.h"
#include "libtoob.h"
#include <stddef.h>
#include <string.h>

/* PLATFORM ABSTRACTION HEADERS */
#if defined(__ZEPHYR__)
    #include <zephyr/kernel.h>
    #include <zephyr/net/socket.h>
#elif defined(ESP_PLATFORM)
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"
#else
    #include <sys/socket.h>
    #include <unistd.h>
    #include <netdb.h>
#endif

/* Default Server URL via Kconfig or fallback */
#ifndef CONFIG_TOOB_SERVER_URL
#define CONFIG_TOOB_SERVER_URL "https://api.toob.io/v1/update"
#endif

#ifndef CONFIG_TOOB_POLL_INTERVAL_SEC
#define CONFIG_TOOB_POLL_INTERVAL_SEC 86400
#endif

static const char *TAG = "toob_client";

/* 
 * The actual HTTP download logic is outsourced to rtos_http_*.c 
 * to guarantee Zero-Bloat by re-using the Host-OS native HTTP/TLS clients.
 */

toob_status_t toob_network_trigger_ota(const char* server_url) {
    if (!server_url) {
        server_url = CONFIG_TOOB_SERVER_URL;
    }
    
    /* 1. L1 Smoke Test: Ensure network interface is physically UP and has IP (implemented in rtos_glue) */
    toob_status_t init_stat = toob_network_init();
    if (init_stat != TOOB_OK) {
        TOOB_LOGE(TAG, "L1 Smoke Test failed. Network Interface is DOWN.");
        return init_stat;
    }
    TOOB_LOGI(TAG, "L1 Smoke Test passed. Link is UP.");
    
    /* 2. L2 Smoke Test: Extract hostname and resolve DNS (Anti-Lagerhaus Trap) */
    const char *host_start = strstr(server_url, "://");
    host_start = (host_start) ? (host_start + 3) : server_url;

    const char *host_end = strchr(host_start, '/');
    size_t len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
    
    char hostname[64];
    if (len >= sizeof(hostname)) {
        len = sizeof(hostname) - 1; /* Clamp to prevent overflow */
    }
    memcpy(hostname, host_start, len);
    hostname[len] = '\0';

#if defined(__ZEPHYR__)
    struct zsock_addrinfo *res;
    struct zsock_addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    if (zsock_getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        TOOB_LOGE(TAG, "L2 Smoke Test (DNS) failed for host %s", hostname);
        return TOOB_ERR_TIMEOUT;
    }
    zsock_freeaddrinfo(res);
#else
    struct addrinfo *res;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        TOOB_LOGE(TAG, "L2 Smoke Test (DNS) failed for host %s", hostname);
        return TOOB_ERR_TIMEOUT;
    }
    freeaddrinfo(res);
#endif
    TOOB_LOGI(TAG, "L2 Smoke Test passed. DNS resolved for %s", hostname);

    /* 3. Download and stream to libtoob using native RTOS HTTP stack */
    return rtos_http_download(server_url);
}

_Noreturn void toob_network_daemon_loop(void) {
    while (1) {
        /* Run OTA Check */
        (void)toob_network_trigger_ota(NULL);
        
        /* Sleep until next poll */
#if defined(__ZEPHYR__)
        k_sleep(K_SECONDS(CONFIG_TOOB_POLL_INTERVAL_SEC));
#elif defined(ESP_PLATFORM)
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TOOB_POLL_INTERVAL_SEC * 1000));
#else
        sleep(CONFIG_TOOB_POLL_INTERVAL_SEC);
#endif
    }
}
