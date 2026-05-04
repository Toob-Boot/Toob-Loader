# OTA Network Integration Gap Analysis (2026-05-04)

Kritische Prüfung des gesamten `os_client/` Moduls (Header, Core, HTTP ESP-IDF, HTTP Zephyr, Glue, POSIX Stub, Build, Kconfig).

---

## GAP-N01: `zcbor_new_decode_state()` — Falsche Signatur (SHOWSTOPPER)

**Problem:** Die Funktion `zcbor_new_decode_state()` erwartet laut `zcbor_decode.h` (Zeile 27-29) **7 Parameter:**
```c
void zcbor_new_decode_state(zcbor_state_t *state_array, size_t n_states,
    const uint8_t *payload, size_t payload_len, size_t elem_count,
    uint8_t *elem_state, size_t elem_state_bytes);
```

Unser Aufruf in `toob_network_client.c` (Zeile 73) hat aber nur **5 Parameter:**
```c
zcbor_new_decode_state(state, 2, data, len, 1);
```

Die fehlenden Parameter `elem_state` und `elem_state_bytes` werden als Garbage-Werte vom Stack interpretiert. Das ist ein **harter Kompilierungsfehler** oder ein **Undefined Behavior Crash** zur Laufzeit.

**Fix:**
```c
zcbor_new_decode_state(state, 2, data, len, 1, NULL, 0);
```

---

## GAP-N02: `zcbor_list_or_map_end()` — Funktion existiert nicht (SHOWSTOPPER)

**Problem:** Die Funktion `zcbor_list_or_map_end()` wird in `toob_network_client.c` (Zeile 82) aufgerufen. Sie existiert aber **nicht** in der zcbor API (`zcbor_decode.h`). Die korrekte Funktion heißt `zcbor_array_at_end()` (Zeile 261):
```c
bool zcbor_array_at_end(zcbor_state_t *state);
```

**Fix:**
```c
while (ok && !zcbor_array_at_end(state)) {
```

---

## GAP-N03: Fehlende Error Codes — `TOOB_ERR_STATE`, `TOOB_ERR_TIMEOUT`, `TOOB_ERR_NOT_SUPPORTED` (SHOWSTOPPER)

**Problem:** `libtoob_types.h` definiert die folgenden `toob_status_t` Enums:
`TOOB_OK`, `TOOB_ERR_NOT_FOUND`, `TOOB_ERR_WAL_FULL`, `TOOB_ERR_WAL_LOCKED`, `TOOB_ERR_FLASH`, `TOOB_ERR_INVALID_ARG`, `TOOB_ERR_VERIFY`, `TOOB_ERR_REQUIRES_RESET`, `TOOB_ERR_COUNTER_EXHAUSTED`, `TOOB_ERR_FLASH_HW`.

Die folgenden Codes werden im `os_client/` Code verwendet, **existieren aber nicht** in der Typ-Definition:
- `TOOB_ERR_STATE` (in `rtos_http_espidf.c:30`, `rtos_http_zephyr.c:83`, `rtos_glue_espidf.c:27`, `rtos_glue_zephyr.c:22`)
- `TOOB_ERR_TIMEOUT` (in `rtos_http_espidf.c:46,86`, `rtos_http_zephyr.c:77,94,131`)
- `TOOB_ERR_NOT_SUPPORTED` (in `rtos_stub_posix.c:12,17,21`)

Das bedeutet: **Keiner dieser Files kompiliert fehlerfrei** gegen den offiziellen `libtoob_types.h` Header.

**Fix:** Fehlende Codes in `libtoob_types.h` ergänzen (mit Hamming-distanten Hex-Werten):
```c
TOOB_ERR_STATE         = 0xEAA01CAE,
TOOB_ERR_TIMEOUT       = 0xEBB01CAE,
TOOB_ERR_NOT_SUPPORTED = 0xECC01CAE,
```

---

## GAP-N04: POSIX Stub — Veraltete Funktionssignaturen (SHOWSTOPPER)

**Problem:** `rtos_stub_posix.c` implementiert die alten Funktionen `rtos_http_check_update()` und `rtos_http_download_payload()`. Diese existieren im aktuellen Header `toob_network_client.h` nicht mehr. Der aktuelle Vertrag erfordert `rtos_http_get()`.

Außerdem fehlt die `rtos_http_get()` Implementierung komplett, was einen **Linker-Fehler** verursacht.

**Fix:** Komplett ersetzen:
```c
toob_status_t rtos_http_get(const char* url, uint32_t resume_offset,
                            toob_http_chunk_cb_t callback, void* ctx) {
    (void)url; (void)resume_offset; (void)callback; (void)ctx;
    return TOOB_ERR_NOT_SUPPORTED;
}

toob_status_t toob_network_init(void) {
    return TOOB_ERR_NOT_SUPPORTED;
}
```

---

## GAP-N05: Zephyr `optional_headers` — Falscher Typ (Bug)

**Problem:** In `rtos_http_zephyr.c` (Zeile 120) wird der `Range` Header so gesetzt:
```c
req.optional_headers = range_hdr;
```
Aber `optional_headers` in Zephyr's `struct http_request` ist vom Typ `const char **` (ein NULL-terminiertes Array von Strings), **nicht** `const char *`.

Die Zuweisung eines einzelnen `char[]` an einen `const char **` Pointer verursacht entweder einen Kompilierungsfehler oder einen Crash bei der Dereferenzierung.

**Fix:**
```c
const char *headers[] = { range_hdr, NULL };
if (resume_offset > 0) {
    snprintf(range_hdr, sizeof(range_hdr), "Range: bytes=%u-\r\n", resume_offset);
    req.optional_headers = headers;
}
```
Außerdem muss der Header im HTTP-Format sein: `Range: bytes=X-\r\n`, nicht nur `bytes=X-`.

---

## GAP-N06: Staler Comment in `toob_network_client.c` (Cosmetic)

**Problem:** Zeile 7: `/* Assume zcbor is available as requested */`. Dies ist ein Platzhalter-Kommentar, der für Produktion unangemessen ist.

**Fix:** Ersetzen durch einen sachlichen Architektur-Kommentar.

---

## GAP-N07: ESP-IDF `content_length` Return-Wert ungeprüft (Defect)

**Problem:** In `rtos_http_espidf.c` (Zeile 49) liefert `esp_http_client_fetch_headers()` den Content-Length als `int`. Der Rückgabewert kann aber `-1` sein (bei fehlenden Headern oder Chunked Transfer Encoding), und die Variable wird danach nur für ein optionales Log genutzt. Die Variable `content_length` wird aber als **signed int** deklariert, und der Vergleich `content_length > 0` funktioniert zwar, aber der Wert ist bei Chunked Transfer `-1`, was nie geloggt wird.

**Fix:** Kein Code-Change nötig, aber für Transparenz beim Logging:
```c
if (content_length > 0) {
    TOOB_LOGI(TAG, "Streaming %d bytes...", content_length);
} else {
    TOOB_LOGI(TAG, "Streaming (chunked/unknown length)...");
}
```

---

## GAP-N08: Zephyr doppelte `LOG_MODULE_REGISTER` (Linker-Konfikt)

**Problem:** Das Zephyr Logging-Modul `toob_http` wird in `rtos_http_zephyr.c` (Zeile 10) registriert:
```c
LOG_MODULE_REGISTER(toob_http, LOG_LEVEL_INF);
```
Und ein anderes Modul `toob_client` wird in `toob_network_client.c` (Zeile 13) registriert:
```c
LOG_MODULE_REGISTER(toob_client, LOG_LEVEL_INF);
```
Und ein drittes `toob_network` in `rtos_glue_zephyr.c` (Zeile 9):
```c
LOG_MODULE_REGISTER(toob_network, LOG_LEVEL_INF);
```

Das sind **drei** separate Logging-Module für eine einzige Library. Das ist zwar kein Fehler, aber architektonisch fragwürdig und erschwert die Filterung. Standard-Praxis ist ein einziges `LOG_MODULE_REGISTER` pro Library und `LOG_MODULE_DECLARE` in den anderen Dateien.

**Fix:**
- `rtos_glue_zephyr.c` und `rtos_http_zephyr.c`: Ändern zu `LOG_MODULE_DECLARE(toob_client, LOG_LEVEL_INF);`
- Nur `toob_network_client.c` behält `LOG_MODULE_REGISTER(toob_client, LOG_LEVEL_INF);`

---

## GAP-N09: Zephyr URL Parser ignoriert Port-Nummern (Defect)

**Problem:** Der URL-Parser in `rtos_http_zephyr.c` (Zeilen 58-69) erkennt keinen Port in der URL. Bei `https://api.toob.io:8443/v1/update` wird `api.toob.io:8443` als Hostname an DNS übergeben, was sofort fehlschlägt. Der Port `443` ist außerdem hardcoded (Zeile 75).

**Fix:** Port-Parsing hinzufügen:
```c
const char *port_start = strchr(host_start, ':');
const char *port = "443"; /* Default HTTPS */
if (port_start && (!host_end || port_start < host_end)) {
    host_len = (size_t)(port_start - host_start);
    port = port_start + 1; /* Zeigt auf den numerischen Port-String */
}
```

---

## GAP-N10: `check_url` Buffer-Overflow bei langen Server-URLs (Security)

**Problem:** In `toob_network_client.c` (Zeile 162-163):
```c
char check_url[256];
snprintf(check_url, sizeof(check_url), "%s/check?svn=%u", server_url, current_svn);
```
Wenn `CONFIG_TOOB_SERVER_URL` bereits nahe 256 Zeichen lang ist, wird die URL abgeschnitten und der Request geht an eine falsche Adresse. Gleiches gilt für `download_url` (Zeile 208-209).

**Fix:** Mindestens einen Rückgabewert-Check hinzufügen:
```c
int written = snprintf(check_url, sizeof(check_url), "%s/check?svn=%u", server_url, current_svn);
if (written < 0 || (size_t)written >= sizeof(check_url)) {
    TOOB_LOGE(TAG, "URL truncated");
    return TOOB_ERR_INVALID_ARG;
}
```

---

## GAP-N11: `toob_network_init()` wird bei jedem Poll aufgerufen (Ineffizienz)

**Problem:** `toob_network_trigger_ota()` ruft bei jedem Durchgang `toob_network_init()` auf (Zeile 147). Bei ESP-IDF iteriert das über alle Netzwerkinterfaces. Bei Zephyr wird `net_if_get_default()` aufgerufen. Das ist bei jedem 24h-Poll unnötiger Overhead.

**Fix:** Einen `static bool s_net_initialized` Guard einbauen, oder die Funktion im Daemon-Loop einmal vor dem `while(1)` aufrufen, anstatt in `toob_network_trigger_ota`.

---

## GAP-N12: Kein Reboot nach erfolgreichem OTA (Missing Feature)

**Problem:** Nach einem erfolgreichen OTA-Download loggt `toob_network_trigger_ota()` (Zeile 225): `"OTA update staged successfully. Rebooting..."`. Aber es wird **kein Reboot durchgeführt**. Die Funktion kehrt einfach mit `TOOB_OK` zurück und der Daemon schläft dann 24 Stunden.

**Fix:** Entweder tatsächlich rebooten:
```c
#if defined(__ZEPHYR__)
    sys_reboot(SYS_REBOOT_COLD);
#elif defined(ESP_PLATFORM)
    esp_restart();
#endif
```
Oder die Log-Nachricht korrigieren, falls der Reboot dem Aufrufer überlassen wird (dann z.B. `"OTA staged. Reboot required."`).

---

## GAP-N13: ESP-IDF CMakeLists — Fehlende `esp_event` Abhängigkeit (Build)

**Problem:** `rtos_glue_espidf.c` inkludiert `esp_event.h` (Zeile 5), aber `CMakeLists.txt` listet `esp_event` nicht in den `REQUIRES`. Abhängig vom Build-Graph kann das funktionieren (transitive Dependency), aber es ist nicht deterministisch garantiert.

**Fix:**
```cmake
REQUIRES 
    "esp_http_client" 
    "esp_netif"
    "esp_event"
    "mbedtls"
    "zcbor"
```

---

## GAP-N14: Zephyr CMakeLists — `zcbor` Link-Methode fragil (Build)

**Problem:** `zephyr_library_link_libraries(zcbor)` funktioniert nur, wenn `zcbor` als Zephyr-Module korrekt registriert ist. Da wir `zcbor` lokal unter `lib/zcbor/` haben und nicht als Zephyr-Modul, wird der Linker das Symbol nicht finden. In Zephyr wird zcbor typischerweise über das SDK bereitgestellt (es ist Teil der Zephyr SDK-Distribution).

**Fix:** Prüfen ob `zcbor` als Zephyr-Modul über `west.yml` eingebunden ist. Falls unsere lokale Kopie gemeint ist, muss der Include-Pfad und die Source-Files explizit registriert werden:
```cmake
zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/include)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/src/zcbor_decode.c)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/../lib/zcbor/src/zcbor_common.c)
```

---

## GAP-N15: `toob_update_info_t` Struct — Kein Padding-Assert (ABI)

**Problem:** `toob_update_info_t` in `toob_network_client.h` hat kein `__attribute__((aligned(8)))` und keinen `_Static_assert` für die Struct-Größe. Im Vergleich dazu haben **alle** anderen Boundary-Structs in `libtoob_types.h` strenge ABI-Assertions.

**Fix:**
```c
typedef struct __attribute__((aligned(4))) {
    uint32_t total_size;
    uint8_t  sha256[32];
    uint8_t  image_type;
    uint8_t  _padding[3];
    uint32_t remote_svn;
    bool     update_available;
    uint8_t  _padding2[3];
} toob_update_info_t;
_Static_assert(sizeof(toob_update_info_t) == 48, "toob_update_info_t ABI size drift");
```

---

## GAP-N16: `_manifest_chunk_cb` — Integer Overflow bei `mbuf->len + len` (Security)

**Problem:** In `toob_network_client.c` (Zeile 62):
```c
if (mbuf->len + len > sizeof(mbuf->buf)) {
```
`mbuf->len` ist `size_t`, `len` ist `uint32_t`. Auf einer 32-Bit Plattform kann `mbuf->len + len` theoretisch wrappen (z.B. `len = 0xFFFFFF00, mbuf->len = 0x200`), wodurch der Guard umgangen wird und `memcpy` in den Stack schreibt.

**Fix:**
```c
if (len > sizeof(mbuf->buf) || mbuf->len > sizeof(mbuf->buf) - len) {
    return TOOB_ERR_INVALID_ARG;
}
```

---

## GAP-N17: Zephyr Glue — Kein IP-Adressen-Check (Asymmetrie)

**Problem:** Die ESP-IDF Glue prüft ob ein Interface eine gültige IP hat (`ip_info.ip.addr != 0`). Die Zephyr Glue prüft nur `net_if_is_up()`, aber nicht ob eine IP zugewiesen wurde. Ein Interface kann `up` sein ohne eine DHCP-Adresse zu haben.

**Fix:**
```c
struct net_if_addr *unicast = net_if_ipv4_addr_lookup_by_index(iface, 0);
if (!unicast || net_ipv4_is_addr_unspecified(&unicast->address.in_addr)) {
    TOOB_LOGW(TAG, "No IP address assigned");
    return TOOB_ERR_STATE;
}
```
Oder die einfachere Zephyr-API:
```c
if (!net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED)) {
    TOOB_LOGW(TAG, "No IP address assigned");
    return TOOB_ERR_STATE;
}
```

---

## GAP-N18: Zephyr `module.yml` — `cmake` Pfad zeigt auf `.` (Build)

**Problem:** In `os_client/zephyr/module.yml` steht `cmake: .`. Das bedeutet das CMake-Root ist `os_client/zephyr/`, aber die `CMakeLists.txt` liegt in `os_client/`. Der Pfad müsste `..` sein.

**Fix:**
```yaml
build:
  cmake: ..
  kconfig: zephyr/Kconfig
```

---

## GAP-N19: `vTaskDelay` Overflow bei großen `sleep_sec` Werten (ESP-IDF Crash)

**Problem:** In `toob_network_client.c` (Zeile 246):
```c
vTaskDelay(pdMS_TO_TICKS((uint64_t)sleep_sec * 1000));
```
`pdMS_TO_TICKS` returniert einen `TickType_t` (typischerweise `uint32_t`). Bei `sleep_sec = 86400` (24h) ergibt das `86400000 ms`. Mit `configTICK_RATE_HZ = 1000` sind das `86400000` Ticks — passt noch in uint32. Aber bei `configTICK_RATE_HZ = 100` (Standard bei vielen Boards) sind es `8640000` Ticks — auch ok.

**Aber:** Der Cast auf `uint64_t` vor der Multiplikation ist gut, aber `pdMS_TO_TICKS` kann intern auf 32-bit wrappen. Sicherer ist es, den Sleep in kürzere Intervalle aufzuteilen.

**Fix:** Defensiver Sleep in Blöcken:
```c
#define TOOB_MAX_SLEEP_TICKS pdMS_TO_TICKS(60000) /* 1 Minute pro Iteration */
uint32_t remaining = sleep_sec;
while (remaining > 0) {
    uint32_t chunk = (remaining > 60) ? 60 : remaining;
    vTaskDelay(pdMS_TO_TICKS(chunk * 1000));
    remaining -= chunk;
}
```

---

## GAP-N20: Zephyr `recv_buf` wird als `uint8_t*` an `rsp->recv_buf` übergeben (Type Mismatch)

**Problem:** In `rtos_http_zephyr.c` (Zeile 46):
```c
ctx->stat = ctx->callback(rsp->recv_buf, rsp->data_len, ctx->ctx);
```
`rsp->recv_buf` ist typischerweise `uint8_t *`, `rsp->data_len` ist `size_t`. Unser Callback erwartet `uint32_t len`. Auf einer 64-Bit Plattform wird `size_t` (64 bit) auf `uint32_t` (32 bit) verengt, was bei Payloads > 4GB Daten verloren gehen lässt. In der Praxis bei IoT-Firmware ist das zwar kein realistisches Szenario, aber der implicit Cast erzeugt Compiler-Warnings.

**Fix:** Expliziter Cast:
```c
ctx->stat = ctx->callback((const uint8_t *)rsp->recv_buf, (uint32_t)rsp->data_len, ctx->ctx);
```

---

## GAP-N21: ESP-IDF `Range` Header Format inkorrekt (Bug)

**Problem:** In `rtos_http_espidf.c` (Zeile 35):
```c
snprintf(range_hdr, sizeof(range_hdr), "bytes=%u-", resume_offset);
esp_http_client_set_header(client, "Range", range_hdr);
```
Das ist korrekt, weil `esp_http_client_set_header` den Key und Value getrennt akzeptiert. Der Wert `bytes=X-` ist das korrekte Format für den `Range` Header-Value.

In der Zephyr-Version (Zeile 119) wird aber der gleiche Wert-String verwendet, obwohl `optional_headers` (oder `optional_headers_cb`) den **vollständigen** Header inkl. Key erwartet: `"Range: bytes=X-\r\n"`.

**Fix:** Bereits in GAP-N05 behandelt.

---

## GAP-N22: Kein Socket-Timeout in Zephyr (Reliability)

**Problem:** In `rtos_http_zephyr.c` wird kein `SO_RCVTIMEO` / `SO_SNDTIMEO` auf dem Socket gesetzt. Falls der Server nach dem TLS-Handshake aufhört zu antworten, blockiert `http_client_req()` bis zum internen Timeout (30 Sekunden in Zeile 126), aber der `zsock_connect()` Call (Zeile 90) hat keinen Timeout und kann ewig blockieren.

**Fix:**
```c
struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
zsock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
```

---

## GAP-N23: `Kconfig` Duplizierung (Maintenance)

**Problem:** Es gibt zwei Kconfig-Dateien:
- `os_client/Kconfig` (für ESP-IDF)
- `os_client/zephyr/Kconfig` (für Zephyr)

Beide definieren die gleichen Symbole (`TOOB_SERVER_URL`, `TOOB_POLL_INTERVAL_SEC`), aber `os_client/zephyr/Kconfig` hat zusätzlich `TOOB_TLS_SEC_TAG`. ESP-IDF hat kein TLS-Tag-Äquivalent, was architektonisch konsistent ist (ESP nutzt `esp_crt_bundle`). Aber die Duplizierung ist ein Wartungs-Risiko.

**Fix:** Akzeptabel, da ESP-IDF und Zephyr fundamental verschiedene Kconfig-Systeme nutzen. Aber einen Kommentar in beide Dateien einfügen: `# Mirrored in os_client/zephyr/Kconfig resp. os_client/Kconfig`.

---

## Zusammenfassung

| Prio | GAP | Schwere | Beschreibung |
|------|-----|---------|-------------|
| 🔴 | N01 | SHOWSTOPPER | `zcbor_new_decode_state()` — 2 Parameter fehlen |
| 🔴 | N02 | SHOWSTOPPER | `zcbor_list_or_map_end()` existiert nicht |
| 🔴 | N03 | SHOWSTOPPER | 3 fehlende Error Codes in `libtoob_types.h` |
| 🔴 | N04 | SHOWSTOPPER | POSIX Stub hat veraltete Signaturen |
| 🔴 | N05 | Bug | Zephyr `optional_headers` Typ-Mismatch |
| 🟡 | N06 | Cosmetic | Staler "Assume" Kommentar |
| 🟡 | N07 | Defect | ESP-IDF `content_length = -1` nicht geloggt |
| 🟡 | N08 | Arch | Zephyr: 3 separate LOG_MODULE_REGISTER |
| 🟡 | N09 | Defect | Zephyr URL Parser ignoriert Ports |
| 🟠 | N10 | Security | URL Buffer Truncation ohne Check |
| 🟡 | N11 | Effizienz | `toob_network_init()` bei jedem Poll |
| 🟠 | N12 | Missing | Kein Reboot nach OTA, Log sagt "Rebooting" |
| 🟡 | N13 | Build | ESP-IDF `esp_event` nicht in REQUIRES |
| 🟡 | N14 | Build | Zephyr zcbor Link-Pfad fragil |
| 🟡 | N15 | ABI | `toob_update_info_t` kein Padding Assert |
| 🟠 | N16 | Security | Integer Overflow in `_manifest_chunk_cb` |
| 🟡 | N17 | Asymmetrie | Zephyr Glue prüft kein IP Assignment |
| 🔴 | N18 | Build | `module.yml` CMake-Pfad falsch |
| 🟡 | N19 | Overflow | `vTaskDelay` Overflow bei großem Intervall |
| 🟡 | N20 | Warn | `size_t` → `uint32_t` implicit narrowing |
| — | N21 | Duplikat | Bereits in N05 behandelt |
| 🟡 | N22 | Reliab. | Zephyr Socket ohne Connect-Timeout |
| ⚪ | N23 | Maint. | Kconfig Duplizierung |
