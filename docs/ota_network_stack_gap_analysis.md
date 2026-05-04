# OTA / Network Stack – Gap-Analyse (Code-basiert)

Erstellt: 2026-05-04  
Scope: `os_client/`, `libtoob/toob_ota.c`, `ports/`, `libtoob/include/`

---

## GAP-01: `toob_ota_begin(0xFFFFFFFF, 0)` – Sentinel-Wert bricht `_ota_begin_core` Validierung

**Problem:** Sowohl `rtos_http_espidf.c:44` als auch `rtos_http_zephyr.c:36` rufen `toob_ota_begin(0xFFFFFFFF, 0)` auf. In `toob_ota.c:165` prüft `_ota_begin_core` exakt `total_size > CHIP_STAGING_SLOT_SIZE`. Da `CHIP_STAGING_SLOT_SIZE` bei keinem realen Chip 4 GB groß ist, wird `TOOB_ERR_INVALID_ARG` zurückgegeben. **Der Download startet nie.**

**Fix:** Das Zwei-Phasen-Modell korrekt implementieren: Zuerst das SUIT-Manifest herunterladen (kleiner HTTP-Request), den `Content-Length` daraus extrahieren, und dann erst `toob_ota_begin(manifest.payload_size, manifest.image_type)` mit den echten Werten aufrufen. Bis das Manifest-Parsing fertig ist, sollte ein dedizierter API-Endpunkt existieren (z.B. `/v1/update/check`), der Metadaten (size, sha256, version) als JSON zurückgibt, bevor der Payload heruntergeladen wird.

---

## GAP-02: `toob_ota_finalize()` wird aus einem Event-Callback gerufen – Reentrancy-Risiko

**Problem:** In `rtos_http_espidf.c:23` wird `toob_ota_finalize()` aus dem `HTTP_EVENT_ON_FINISH` Callback des `esp_http_client` gerufen. Dieser Callback wird intern aus dem `esp_http_client_perform()` Kontext ausgelöst. `toob_ota_finalize()` führt Flash-Writes (WAL Append via `toob_set_next_update`) durch. Sollte ESP-IDF intern den Event-Handler in einem anderen Thread-Kontext ausführen oder zeitlich versetzt dispatchen, drohen Race Conditions auf den `s_state` File-Scoped Globals in `toob_ota.c`.

**Fix:** `toob_ota_finalize()` niemals aus einem Callback aufrufen. Stattdessen im Callback nur ein Flag setzen (z.B. `s_download_complete = true`), und nach `esp_http_client_perform()` den Finalize synchron im Haupt-Thread aufrufen. Gleiches Muster für die Zephyr-Seite.

---

## GAP-03: Doppelte DNS-Auflösung (L2 Smoke Test + HTTP Download)

**Problem:** `toob_network_client.c:64-80` löst den Hostnamen bereits via `getaddrinfo/zsock_getaddrinfo` auf (L2 Test). Danach wird die URL an `rtos_http_download()` weitergereicht, wo der HTTP-Client den Hostnamen intern ein zweites Mal auflöst. In `rtos_http_zephyr.c:60` geschieht dies sogar explizit nochmals via `zsock_getaddrinfo`. Das ist doppelter Netzwerk-Traffic und doppelte Latenz.

**Fix:** Die L2-DNS-Auflösung im `toob_network_client.c` sollte die aufgelöste IP-Adresse als `struct sockaddr` an `rtos_http_download()` weiterreichen, anstatt nur `TOOB_OK` zurückzugeben. Alternativ: Die DNS-Auflösung nur einmal in `rtos_http_download` machen und dort das Ergebnis als impliziten L2-Test werten (wenn DNS fehlschlägt, ist der L2-Test auch fehlgeschlagen).

---

## GAP-04: `rtos_http_download` Signatur passt nicht zum Zwei-Phasen-Download

**Problem:** `rtos_http_download(const char* url)` nimmt nur eine URL entgegen. Für einen echten OTA-Flow braucht man:
1. Erst einen Check-Endpunkt (`/v1/update/check`) der Metadaten liefert (Version, Size, SHA256).
2. Dann den Payload-Endpunkt (`/v1/update/download`).
3. Optional: Ein `Range: bytes=X-` Header für Resume-Support.

Die aktuelle Signatur kann weder die erwartete SHA-256 Summe transportieren (für `toob_ota_begin_verified`), noch den Resume-Offset (für `Range`-Header), noch unterscheiden ob ein Check oder ein Download gemeint ist.

**Fix:** Das API in mehrere Phasen gliedern:
```c
toob_status_t rtos_http_check_update(const char* url, toob_update_info_t* out_info);
toob_status_t rtos_http_download_payload(const char* url, uint32_t resume_offset);
```
Wobei `toob_update_info_t` die Felder `total_size`, `sha256[32]`, `image_type`, `version` enthält.

---

## GAP-05: Resume-Support nicht im HTTP-Layer implementiert

**Problem:** `libtoob` hat den brillanten `toob_ota_resume()` API-Aufruf und WAL-Checkpoints. Aber kein einziger HTTP-Client setzt den `Range: bytes=X-` Header. Nach einem Reboot wird der gesamte Download von vorne begonnen, obwohl die Infrastruktur für partiellen Resume bereits im Bootloader existiert.

**Fix:** Vor dem Download `toob_ota_resume(&offset)` aufrufen. Wenn `TOOB_OK` zurückkommt und `offset > 0`, den HTTP-Header `Range: bytes={offset}-` setzen. In ESP-IDF: `esp_http_client_set_header(client, "Range", range_str)`. In Zephyr: Als zusätzlichen Header in der `http_request` Struktur einfügen.

---

## GAP-06: `toob_ota_abort()` wird in `HTTP_EVENT_DISCONNECTED` bedingungslos aufgerufen

**Problem:** In `rtos_http_espidf.c:30` wird bei JEDEM Disconnect `toob_ota_abort()` gerufen. ESP-IDF feuert `HTTP_EVENT_DISCONNECTED` auch nach einem **erfolgreichen** Download, wenn der Server die Verbindung ordnungsgemäß schließt (z.B. nach `Connection: close`). Das bedeutet: Nach einem perfekt abgeschlossenen Download wird der gesamte OTA-State gelöscht, bevor `toob_ota_finalize()` je aufgerufen werden kann.

**Fix:** Den Abort nur auslösen, wenn der Download noch nicht als vollständig markiert wurde (s_state != DONE). Am besten den Disconnect-Handler komplett entfernen und stattdessen die Error-Codes nach `esp_http_client_perform()` auswerten.

---

## GAP-07: ESP-IDF `esp_http_client` hat `is_async` standardmäßig auf false – keine Chunk-Streaming Garantie

**Problem:** Wenn `is_async` nicht explizit auf `true` gesetzt ist (was es aktuell nicht ist), puffert `esp_http_client_perform()` den gesamten Response in den internen Buffer (`buffer_size = 2048`). Wenn die Firmware-Datei z.B. 512 KB groß ist, wird der `HTTP_EVENT_ON_DATA` Callback zwar aufgerufen, aber ESP-IDF versucht unter Umständen, den gesamten Body in den RAM zu laden, bevor die Chunks an den Callback ausgeliefert werden.

**Fix:** In der `esp_http_client_config_t` explizit `.is_async = false` und `.disable_auto_redirect = true` setzen. Alternativ: Den Download manuell mit `esp_http_client_open()` / `esp_http_client_read()` in einer Schleife durchführen, anstatt `esp_http_client_perform()` zu nutzen. Das gibt volle Kontrolle über das Chunk-Streaming.

---

## GAP-08: Zephyr Logging (`LOG_MODULE_REGISTER`) fehlt

**Problem:** Die Logging-Makros `TOOB_LOGI`/`TOOB_LOGE` mapppen auf Zephyr's `LOG_INF`/`LOG_ERR`. Aber Zephyr's Logging-System erfordert zwingend ein `LOG_MODULE_REGISTER(toob_network, LOG_LEVEL_INF)` am Anfang jeder `.c`-Datei, die das Logging nutzt. Ohne dieses Makro kompiliert der Code unter Zephyr nicht oder loggt in ein undefiniertes Modul.

**Fix:** In jeder Zephyr-kompilierten `.c`-Datei am Anfang (nach den Includes) `LOG_MODULE_REGISTER(toob_network, LOG_LEVEL_INF);` einfügen. Da dies RTOS-spezifisch ist, am besten hinter einem `#if defined(__ZEPHYR__)` Guard.

---

## GAP-09: `toob_network_daemon_loop()` hat keine Error-Backoff-Strategie

**Problem:** Wenn `toob_network_trigger_ota()` fehlschlägt (z.B. kein Internet), wartet der Daemon exakt `CONFIG_TOOB_POLL_INTERVAL_SEC` (Default: 24h) und versucht es dann erneut. Es gibt weder:
- Exponentielles Backoff bei wiederholten Fehlern (um Batterie zu schonen).
- Schnelleres Retry bei temporären Fehlern (um eine kurze Netzwerk-Unterbrechung rasch aufzuholen).
- Einen Jitter (um Thundering-Herd Probleme auf dem Server zu vermeiden, wenn 10.000 Geräte gleichzeitig pollen).

**Fix:** Eine Retry-State-Machine einbauen: Bei Erfolg: normales Intervall. Bei Fehler: Exponentielles Backoff (z.B. 30s → 60s → 2min → 5min → 30min → 24h cap). Plus ein zufälliger Jitter von ±10% auf das Intervall.

---

## GAP-10: ESP-IDF Shim (`ports/esp_idf/`) fehlt `toob_os_flash_erase`

**Problem:** `libtoob.h:249` deklariert `toob_os_flash_erase()` als Linker-Contract. `toob_ota.c:185` ruft es in `_ota_begin_core` auf. Aber `ports/esp_idf/toob_esp_idf_shim.c` implementiert nur `flash_read` und `flash_write`. **Der Linker wird mit "undefined symbol: toob_os_flash_erase" fehlschlagen.**

**Fix:** `toob_os_flash_erase` in allen drei Port-Shims implementieren:
- ESP-IDF: `esp_flash_erase_region(NULL, addr, len)`
- Zephyr: `flash_erase(flash_dev, addr, len)`
- FreeRTOS: Template mit TODO

---

## GAP-11: Zephyr/FreeRTOS Shims fehlen `toob_os_sha256_*` Hooks

**Problem:** `libtoob.h:259-261` deklariert drei SHA-256 Hooks als Linker-Contracts. `toob_ota.c:207` nutzt `toob_os_sha256_init` in `toob_ota_begin_verified()`. **Keiner der drei Port-Shims implementiert diese.** Wenn ein Nutzer `toob_ota_begin_verified()` aufruft, schlägt der Linker fehl.

**Fix:** SHA-256 Hooks in allen Shims implementieren:
- ESP-IDF: `mbedtls_sha256_*` (ist im ESP-IDF eingebaut).
- Zephyr: `<zephyr/crypto/hash.h>` oder `tc_sha256.h` (TinyCrypt, standardmäßig in Zephyr).
- FreeRTOS: Template mit TODO.

---

## GAP-12: `CONFIG_TOOB_SERVER_URL` Inkonsistenz zwischen Kconfig und C-Fallback

**Problem:** `zephyr/Kconfig:9` definiert `TOOB_SERVER_URL` (ohne `CONFIG_` Prefix – Zephyr mappt es automatisch). In `toob_network_client.c:22` wird per `#ifndef CONFIG_TOOB_SERVER_URL` ein Fallback definiert. Aber: ESP-IDF hat kein Kconfig-System, das `CONFIG_TOOB_SERVER_URL` definiert. Der ESP-IDF Nutzer hat aktuell keine offizielle Möglichkeit, die Server-URL zu konfigurieren, außer das `#define` manuell im Code zu ändern.

**Fix:** Für ESP-IDF ein `menuconfig`-Equivalent anlegen: In der `CMakeLists.txt` einen `Kconfig`-ähnlichen Mechanismus über `idf_build_set_property()` oder eine dedizierte `Kconfig` Datei integrieren (ESP-IDF unterstützt das nativ mit einer `Kconfig`-Datei im Component-Root).

---

## GAP-13: `rtos_http_download` hat keine HTTP Status-Code Validierung in Zephyr

**Problem:** In `rtos_http_espidf.c:73` wird der HTTP Status-Code korrekt geprüft (`status_code == 200`). In `rtos_http_zephyr.c:105` wird hingegen nur geprüft, ob `http_client_req` `>= 0` zurückgibt. Es gibt keine Prüfung auf HTTP 200 vs. 301/302 (Redirect), 403 (Forbidden), 404 (Not Found), oder 503 (Server Down). Ein 404-Response würde als gültiger "erfolgreicher" Download behandelt und der 404-HTML-Body würde als Firmware in den Flash geschrieben.

**Fix:** In der Zephyr `response_cb` den HTTP Status-Code aus `rsp->http_status_code` prüfen, bevor Daten an `toob_ota_process_chunk` weitergegeben werden. Bei Status != 200: Die Chunks ignorieren und den OTA-Prozess abbrechen.

---

## GAP-14: `rtos_glue_espidf.c` hardcoded WiFi Interface Key

**Problem:** `rtos_glue_espidf.c:18` nutzt `esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")`. Das funktioniert nur, wenn das Gerät WLAN nutzt. Ethernet-basierte ESP32-Geräte (z.B. ESP32-Ethernet-Kit, WT32-ETH01) oder Geräte mit SIM7600 LTE-Modems werden hier `NULL` zurückbekommen und der L1-Test schlägt fehl, obwohl das Gerät perfekt online ist.

**Fix:** Zuerst `esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")` versuchen. Falls `NULL`: Fallback auf `esp_netif_get_handle_from_ifkey("ETH_DEF")`. Falls auch `NULL`: Fallback auf `esp_netif_next(NULL)` (gibt das erste verfügbare Interface zurück). Oder besser: Alle Interfaces iterieren und das erste mit einer gültigen IP zurückgeben.

---

## GAP-15: Kein Mechanismus zum Übermitteln der aktuellen Firmware-Version an den Server

**Problem:** `toob_network_trigger_ota()` fragt den Server an, aber übergibt keine Information darüber, welche Firmware-Version aktuell läuft. Der Server kann also nicht entscheiden, ob ein Update nötig ist. Der Client würde bei jedem Poll den gesamten Payload herunterladen, selbst wenn er bereits aktuell ist.

**Fix:** Die aktuelle `current_svn` aus `toob_boot_diag_t` extrahieren und als Query-Parameter oder HTTP-Header an den Check-Endpunkt senden (z.B. `GET /v1/update/check?svn=42&chip=esp32c6`). Der Server antwortet dann mit 200 + Metadaten oder 204 (No Content / Up-to-Date).

---

## GAP-16: Kein `rtos_http_download` für den POSIX/Fuzzer Build

**Problem:** Die `CMakeLists.txt:34-42` definiert den Fallback-Build für Generic/Fuzzer/POSIX, kompiliert aber nur `toob_network_client.c`. Darin wird `rtos_http_download()` aufgerufen, das aber in keiner Datei für den Fallback-Build definiert ist. **Der Linker wird fehlschlagen.**

**Fix:** Entweder einen `rtos_http_posix.c` Stub hinzufügen, der `rtos_http_download` mit `return TOOB_ERR_NOT_SUPPORTED;` implementiert, oder die Funktion als `__attribute__((weak))` im Header deklarieren mit einem Default-Stub.

---

## GAP-17: Zephyr `recv_buffer` ist statisch – nicht Thread-Safe

**Problem:** In `rtos_http_zephyr.c:12` ist `recv_buffer[1024]` als `static` deklariert. Wenn der OTA-Daemon in einem dedizierten Thread läuft (was er in Produktion tun sollte) und gleichzeitig ein anderer Thread eine HTTP-Anfrage macht, teilen sich beide denselben Buffer.

**Fix:** Da der Daemon-Loop sowieso single-threaded designed ist, ist das akzeptabel, solange es dokumentiert ist. Bessere Alternative: Den Buffer als lokale Variable auf dem Stack von `rtos_http_download` deklarieren (1024 Bytes Stack sind in Zephyr typisch für Netzwerk-Threads).

---

## GAP-18: `module.yml` verweist auf falsche CMake-Root

**Problem:** `module.yml` sagt `cmake: .` und `kconfig: zephyr/Kconfig`. Das `cmake: .` zeigt auf `os_client/` (korrekt). Aber der `kconfig` Pfad ist relativ zum `cmake` Pfad, also sucht Zephyr nach `os_client/zephyr/Kconfig`. Da die Kconfig-Datei tatsächlich dort liegt, funktioniert es – **aber nur**, wenn das Modul als Root-Level West-Projekt eingebunden wird. Wird es in einem Unterordner (z.B. `modules/toob/os_client/`) eingebunden, kann der relative Pfad brechen.

**Fix:** Sicherstellen, dass die `west.yml` des Nutzerprojekts den `path` korrekt auf das Root des `os_client/` Ordners mappt. In der Dokumentation explizit darauf hinweisen.

---

## GAP-19: `toob_network_client.c` inkludiert unnötige Platform-Header

**Problem:** Zeilen 7-19 inkludieren `<zephyr/kernel.h>`, `<zephyr/net/socket.h>`, `"freertos/FreeRTOS.h"`, `"lwip/sockets.h"` etc. Der einzige Grund dafür war der ehemalige POSIX-HTTP-Code, der inzwischen entfernt wurde. Die Socket-Header werden nur noch für den DNS-Check gebraucht (`getaddrinfo`/`zsock_getaddrinfo`). Für Zephyr reicht `<zephyr/net/socket.h>`, für ESP-IDF reicht `"lwip/netdb.h"`. Die übrigen Includes (FreeRTOS, sockets, kernel) sind Bloat.

**Fix:** Die Platform-Includes auf das Minimum reduzieren: Zephyr braucht `<zephyr/kernel.h>` (für `k_sleep`) und `<zephyr/net/socket.h>` (für DNS). ESP-IDF braucht `"freertos/task.h"` (für `vTaskDelay`) und `"lwip/netdb.h"` (für DNS). Alles andere entfernen.

---

## GAP-20: Hash-Vergleich in `toob_ota_finalize()` ist nicht konstant-zeitig

**Problem:** `toob_ota.c:361-364` nutzt eine `for`-Schleife mit einem `bool hash_ok` Flag, setzt dieses aber nie auf `break`. Das ist zwar nicht anfällig für Timing-Attacks (da es komplett durchläuft), aber der Kommentar "Constant-time (or near enough)" ist irreführend, weil der Compiler die Schleife theoretisch optimieren und bei `hash_ok = false` short-circuiten könnte.

**Fix:** Einen echten Constant-Time-Vergleich nutzen: `volatile uint8_t diff = 0; for (int i = 0; i < 32; i++) { diff |= final_hash[i] ^ s_expected_sha256[i]; }` und dann `diff == 0` prüfen. Alternativ eine Assembler-Barriere am Ende der Schleife.

---

## GAP-21: Zephyr `sec_tag_t` ist hardcoded auf `1`

**Problem:** In `rtos_http_zephyr.c:77` ist der TLS Security Tag auf `1` hardcoded. Das ist ein Magic Number, die der Nutzer mit dem korrekten Root-CA Zertifikat provisionieren muss. Es gibt weder Dokumentation noch ein Kconfig-Symbol dafür.

**Fix:** Ein neues Kconfig-Symbol `CONFIG_TOOB_TLS_SEC_TAG` (default: 1) anlegen und im Code referenzieren. In der Dokumentation erklären, wie der Nutzer das Server-CA Zertifikat über `tls_credential_add(CONFIG_TOOB_TLS_SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_cert, sizeof(ca_cert))` provisioniert.

---

## GAP-22: Kein HTTP Redirect Handling

**Problem:** Weder der ESP-IDF noch der Zephyr HTTP Client sind für Redirects konfiguriert. In `rtos_http_espidf.c` fehlt `.max_redirection_count`. Falls der OTA-Server einen 301/302-Redirect auf einen CDN sendet (was bei Cloud-Deployments extrem üblich ist), wird der Download fehlschlagen.

**Fix:** ESP-IDF: `.max_redirection_count = 3` in der Config setzen. Zephyr: Da der native HTTP-Client keine automatischen Redirects unterstützt, muss ein manueller Redirect-Handler implementiert werden (Status 301/302 → `Location` Header lesen → neuen Request starten).
