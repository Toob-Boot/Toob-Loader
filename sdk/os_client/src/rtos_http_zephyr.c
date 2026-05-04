#include "toob_network_client.h"

#if defined(__ZEPHYR__)
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <string.h>
#include <stdio.h>

/* GAP-N08: Declare instead of register to avoid duplicates */
LOG_MODULE_DECLARE(toob_client, LOG_LEVEL_INF);

static const char *TAG = "toob_http";

#ifndef CONFIG_TOOB_TLS_SEC_TAG
#define CONFIG_TOOB_TLS_SEC_TAG 1
#endif

typedef struct {
    toob_http_chunk_cb_t callback;
    void*                ctx;
    toob_status_t        stat;
    bool                 status_checked;
} zephyr_http_ctx_t;

static void _http_response_cb(struct http_response *rsp,
                              enum http_final_call final_data,
                              void *user_data) {
    zephyr_http_ctx_t *ctx = (zephyr_http_ctx_t *)user_data;

    if (!ctx->status_checked) {
        ctx->status_checked = true;
        if (rsp->http_status_code == 204) {
            /* 204 No Content is valid, no data to process */
            return;
        }
        if (rsp->http_status_code != 200 && rsp->http_status_code != 206) {
            TOOB_LOGW(TAG, "Unexpected HTTP status: %d", rsp->http_status_code);
            ctx->stat = TOOB_ERR_NOT_FOUND;
            return;
        }
    }

    if (ctx->stat != TOOB_OK) return;

    if (rsp->data_len > 0) {
        /* GAP-N20: Explicit narrowing cast to avoid ABI warnings on 64-bit platforms */
        ctx->stat = ctx->callback((const uint8_t *)rsp->recv_buf, (uint32_t)rsp->data_len, ctx->ctx);
        if (ctx->stat != TOOB_OK) {
            TOOB_LOGE(TAG, "Callback rejected chunk: 0x%08X", ctx->stat);
        }
    }
    (void)final_data;
}

toob_status_t rtos_http_get(const char* url, uint32_t resume_offset, 
                            toob_http_chunk_cb_t callback, void* cb_ctx) {
    if (!url || !callback) return TOOB_ERR_INVALID_ARG;

    /* URL Parsing */
    const char *host_start = strstr(url, "://");
    host_start = (host_start) ? (host_start + 3) : url;

    const char *host_end = strchr(host_start, '/');
    const char *path = host_end ? host_end : "/";

    /* GAP-N09: URL Port Parsing */
    const char *port_start = strchr(host_start, ':');
    char port_str[8] = "443";
    size_t host_len = host_end ? (size_t)(host_end - host_start) : strlen(host_start);

    if (port_start && (!host_end || port_start < host_end)) {
        host_len = (size_t)(port_start - host_start);
        size_t port_len = host_end ? (size_t)(host_end - port_start - 1) : strlen(port_start + 1);
        if (port_len < sizeof(port_str)) {
            memcpy(port_str, port_start + 1, port_len);
            port_str[port_len] = '\0';
        }
    }

    char hostname[64];
    if (host_len >= sizeof(hostname)) host_len = sizeof(hostname) - 1;
    memcpy(hostname, host_start, host_len);
    hostname[host_len] = '\0';

    /* DNS & Socket Setup */
    struct zsock_addrinfo *res;
    struct zsock_addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    
    if (zsock_getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        TOOB_LOGE(TAG, "DNS failed for %s:%s", hostname, port_str);
        return TOOB_ERR_TIMEOUT;
    }

    int sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (sock < 0) {
        zsock_freeaddrinfo(res);
        return TOOB_ERR_STATE;
    }

    sec_tag_t sec_tag_list[] = { CONFIG_TOOB_TLS_SEC_TAG };
    zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list, sizeof(sec_tag_list));
    zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, hostname, strlen(hostname));

    /* GAP-N22: Socket Timeout for TCP/TLS Connect */
    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
    zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    zsock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (zsock_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        TOOB_LOGE(TAG, "TLS connect failed");
        zsock_close(sock);
        zsock_freeaddrinfo(res);
        return TOOB_ERR_TIMEOUT;
    }
    zsock_freeaddrinfo(res);

    /* HTTP Request Setup */
    zephyr_http_ctx_t ctx = {
        .callback = callback,
        .ctx = cb_ctx,
        .stat = TOOB_OK,
        .status_checked = false
    };

    uint8_t recv_buffer[1024];
    struct http_request req = {
        .method = HTTP_GET,
        .url = path,
        .host = hostname,
        .protocol = "HTTP/1.1",
        .response = _http_response_cb,
        .recv_buf = recv_buffer,
        .recv_buf_len = sizeof(recv_buffer),
    };

    /* GAP-N05 / N21: optional_headers expects a NULL-terminated array of strings, not a single char* */
    char range_hdr[48] = {0};
    const char *headers[] = { range_hdr, NULL };
    
    if (resume_offset > 0) {
        snprintf(range_hdr, sizeof(range_hdr), "Range: bytes=%u-\r\n", resume_offset);
        req.optional_headers = headers;
        TOOB_LOGI(TAG, "HTTP GET %s (Range: bytes=%u-)", url, resume_offset);
    } else {
        TOOB_LOGI(TAG, "HTTP GET %s", url);
    }

    int ret = http_client_req(sock, &req, 30000, &ctx);
    zsock_close(sock);

    if (ret < 0) {
        TOOB_LOGE(TAG, "HTTP download failed: %d", ret);
        return TOOB_ERR_TIMEOUT;
    }

    return ctx.stat;
}

#endif /* __ZEPHYR__ */
