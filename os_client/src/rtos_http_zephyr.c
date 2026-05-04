#include "toob_network_client.h"

#if defined(__ZEPHYR__)
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include "libtoob.h"

static const char *TAG = "toob_http";

/* Der Puffer muss statisch oder aus dem Heap sein, da Zephyr HTTP asynchron liest */
static uint8_t recv_buffer[1024];

static void response_cb(struct http_response *rsp,
                        enum http_final_call final_data,
                        void *user_data)
{
    if (rsp->data_len > 0) {
        toob_status_t stat = toob_ota_process_chunk(rsp->recv_buf, rsp->data_len);
        if (stat != TOOB_OK) {
            TOOB_LOGE(TAG, "OTA chunk processing failed: %d", stat);
            toob_ota_abort();
        }
    }
    
    if (final_data == HTTP_DATA_FINAL) {
        if (toob_ota_finalize() != TOOB_OK) {
            TOOB_LOGE(TAG, "OTA finalize failed");
        } else {
            TOOB_LOGI(TAG, "OTA payload downloaded and verified.");
        }
    }
}

toob_status_t rtos_http_download(const char* url) {
    toob_status_t stat = toob_ota_begin(0xFFFFFFFF, 0); 
    if (stat != TOOB_OK) return stat;

    /* 
     * In Zephyr, we must manually resolve the host, open a TLS socket (IPPROTO_TLS_1_2), 
     * set the SEC_TAG (TLS_SEC_TAG_LIST) for the Trusted CA, connect(), and then pass 
     * the socket to http_client_req().
     */
    
    const char *host_start = strstr(url, "://");
    host_start = (host_start) ? (host_start + 3) : url;

    const char *host_end = strchr(host_start, '/');
    size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);
    const char *path = host_end ? host_end : "/";
    
    char hostname[64];
    if (host_len >= sizeof(hostname)) host_len = sizeof(hostname) - 1;
    memcpy(hostname, host_start, host_len);
    hostname[host_len] = '\0';

    struct zsock_addrinfo *res;
    struct zsock_addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    
    if (zsock_getaddrinfo(hostname, "443", &hints, &res) != 0) {
        TOOB_LOGE(TAG, "Failed to resolve host %s for HTTPS", hostname);
        toob_ota_abort();
        return TOOB_ERR_NOT_FOUND;
    }

    int sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (sock < 0) {
        TOOB_LOGE(TAG, "Failed to create TLS socket");
        zsock_freeaddrinfo(res);
        toob_ota_abort();
        return TOOB_ERR_STATE;
    }

    /* P10 Security: Binde TLS Credentials. 
     * Note: TLS_SEC_TAG 1 must be provisioned with the Server Root CA via tls_credential_add()
     * earlier in the Zephyr boot process. */
    sec_tag_t sec_tag_list[] = { 1 };
    zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
    zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, hostname, strlen(hostname));

    if (zsock_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        TOOB_LOGE(TAG, "TLS connect failed");
        zsock_close(sock);
        zsock_freeaddrinfo(res);
        toob_ota_abort();
        return TOOB_ERR_TIMEOUT;
    }
    zsock_freeaddrinfo(res);

    struct http_request req = {
        .method = HTTP_GET,
        .url = path,
        .host = hostname,
        .protocol = "HTTP/1.1",
        .response = response_cb,
        .recv_buf = recv_buffer,
        .recv_buf_len = sizeof(recv_buffer),
    };

    TOOB_LOGI(TAG, "Starting native Zephyr TLS download from %s", url);
    int ret = http_client_req(sock, &req, 15000, NULL);
    
    zsock_close(sock);

    if (ret >= 0) {
        return TOOB_OK;
    } else {
        TOOB_LOGE(TAG, "HTTP client request failed: %d", ret);
        toob_ota_abort();
        return TOOB_ERR_STATE;
    }
}
#endif /* __ZEPHYR__ */
