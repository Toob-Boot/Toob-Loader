# Gap Analysis: OTA Networking & Rollback Architecture
## Analysiertes Dokument: `docs/ota_networking_architecture.md`

---

## GAP-1: Keine Staging Slot Erase-Strategie vor dem Download

**Problem:**  
`toob_ota_begin()` initialisiert den State und fängt an zu schreiben, aber der Staging-Slot wird vorher nie gelöscht. Flash-Speicher muss vor dem Schreiben sektorweise gelöscht werden (Erase-before-Write). Die aktuelle Implementierung in `toob_ota.c` ruft nur `toob_os_flash_write()` auf, was auf einem nicht-gelöschten Sektor physisch Garbage produziert (Bits können nur von 1→0 gesetzt werden, nicht umgekehrt).

**Lösung:**  
`toob_ota_begin()` muss den gesamten Staging-Slot (oder zumindest die Sektoren, die das Update umfasst) vor dem Empfang löschen. Dafür muss ein `toob_os_flash_erase(uint32_t addr, uint32_t len)` Hook in `libtoob.h` als dritter Linker-Contract hinzugefügt werden. Der Erase muss sektorweise und WDT-sicher ablaufen.

---

## GAP-2: Kein Fortschritts-Checkpointing bei partiellem Download (Tearing)

**Problem:**  
Wenn der Download bei 60% durch einen Brownout, Netzwerk-Timeout oder sonstigen Fehler abbricht, muss das Gerät nach dem Reboot den gesamten Download von Byte 0 wiederholen. Es gibt keinen Resume-Mechanismus. Bei großen Updates über eine langsame Verbindung (z.B. LTE-M mit 10 KB/s) bedeutet das massive Verschwendung von Bandbreite, Zeit und Akku.

**Lösung:**  
Der `toob_ota` State Machine braucht ein Checkpointing-Mechanismus im WAL. Nach jedem erfolgreich geflashten `TOOB_OTA_BUF_SIZE` Block sollte ein `WAL_INTENT_DOWNLOAD_CHECKPOINT` mit dem aktuellen `s_bytes_queued` geschrieben werden (oder in größeren Intervallen, z.B. alle 64 KB, um WAL-Wear zu schonen). Eine neue API `toob_ota_resume(uint32_t *resume_offset)` erlaubt dem OS, nach einem Reboot abzufragen, ob ein partieller Download vorliegt und ab wo er fortfahren kann. Die Network-App setzt dann einen HTTP `Range: bytes=<offset>-` Header.

---

## GAP-3: Smoke-Test Timeout-Wert ist nicht konfigurierbar und physisch nicht definiert

**Problem:**  
Das Dokument erwähnt "z.B. 5 Minuten" als Smoke-Test Timeout. Dieser Wert ist nirgendwo in der Codebasis definiert. Er hängt massiv vom Use-Case ab: Ein Gerät in einem Aufzug mit intermittierender Konnektivität braucht vielleicht 30 Minuten, während ein stationäres WLAN-Gerät mit 30 Sekunden auskommt. Ein hardcodierter Wert ist ein Brick-Risiko.

**Lösung:**  
Den Timeout als `TOOB_SMOKE_TEST_TIMEOUT_MS` Konfigurationswert definieren, der:
1. Über das SUIT-Manifest pro Update vom Server mitgeliefert werden kann (damit der Server "dieses kritische Update braucht 10 Minuten Konnektivität-Check" bestimmen kann).
2. Einen sicheren Default-Wert hat (z.B. 300000 ms = 5 Minuten).
3. In `libtoob_types.h` oder `generated_boot_config.h` deklariert wird.

---

## GAP-4: Fehlende Differenzierung im Smoke-Test zwischen "kein Netzwerk" und "Server down"

**Problem:**  
Der Smoke-Test schlägt fehl, wenn das OS den Server nicht erreicht. Aber: Was ist, wenn das WLAN und der Treiber perfekt funktionieren, aber der Toob-Update-Server gerade offline ist (DDoS, Wartung, DNS-Ausfall)? In diesem Fall würde das Gerät fälschlicherweise einen Rollback ausführen, obwohl das Update korrekt ist. Bei einem Server-Ausfall von 2 Stunden und einem Retry-Limit von 3 würde die gesamte Flotte rollbacken.

**Lösung:**  
Den Smoke-Test in **zwei Stufen** aufteilen:
1. **L1 (Netzwerk-Check)**: Kann das Gerät eine IP-Adresse per DHCP beziehen und einen DNS-Lookup auflösen? Wenn ja, ist der Treiber intakt.
2. **L2 (Server-Check)**: Kann das Gerät den `Toob-Update-Backend` erreichen?

Nur wenn **L1 fehlschlägt**, wird der `boot_failure_counter` inkrementiert. Wenn L1 klappt aber L2 nicht (Server down), geht das Gerät in einen "Server Unreachable" Backoff-Modus (exponentieller Retry alle 15/60/300 Sekunden), *ohne* den Rollback-Mechanismus zu triggern.

---

## GAP-5: Keine CRC/Hash-Prüfung des Downloads VOR dem WAL-Intent

**Problem:**  
`toob_ota_finalize()` schreibt den `WAL_INTENT_UPDATE_PENDING` sofort nach dem letzten Byte-Flush in den WAL. Es findet vorher keine Integritätsprüfung des heruntergeladenen Payloads statt. Wenn die TCP-Verbindung während des Downloads korrupte Bytes liefert (TCP Checksum ist nur 16-bit), schreibt das OS ein defektes Image ins Staging und der Bootloader wird erst beim nächsten Boot den SUIT-Signatur-Check ausführen und das Image verwerfen. Das ist kein Brick-Risiko, aber es verschwendet einen vollständigen Boot-Zyklus (inklusive Flash-Erase).

**Lösung:**  
Der HTTP-Response sollte einen `Content-SHA256` Header (oder ein Feld im JSON der Update-API) mitliefern. `toob_ota_process_chunk()` akkumuliert einen SHA-256 Stream-Hash über alle empfangenen Bytes. `toob_ota_finalize()` vergleicht den finalen Hash mit dem erwarteten Wert und schreibt den WAL-Intent nur bei Match. Das spart Bootloader-Zyklen und Flash-Wear.

**Hinweis:** Dies ist ein OS-seitiger Convenience-Check, keine Sicherheitsgarantie. Die kryptographische Verifikation bleibt beim Bootloader (Ed25519 SUIT). Ein SHA-256 Streaming-Hash ist aber im OS-Kontext vertretbar (die `libtoob` kann dafür eine optionale `toob_ota_begin_verified()` Variante anbieten).

---

## GAP-6: `toob_accumulate_net_search()` wird im Networking-Dokument nicht referenziert

**Problem:**  
In `libtoob.h` existiert bereits die Funktion `toob_accumulate_net_search(uint32_t active_search_ms)`, die explizit als "Anti-Lagerhaus Lockout" Mechanismus dokumentiert ist. Das OTA Networking Dokument erwähnt diesen Mechanismus mit keinem Wort. Das `net_search_accum_ms` Feld im Handoff existiert bereits und wird im Bootloader in `boot_state_run()` ausgewertet (Z. 800).

Die Architektur hat also bereits einen Network-Watchdog TTL (siehe `GAP-07: Network Watchdog TTL` Kommentar in `libtoob.h` Z. 89), aber das Networking-Dokument plant diesen Mechanismus nicht ein.

**Lösung:**  
Das Dokument muss einen Abschnitt definieren, wann und wie das OS `toob_accumulate_net_search()` aufruft:
- **Wann:** Während jeder Netzwerk-Suchphase (z.B. WLAN Scanning, MQTT Reconnect) akkumuliert das OS die verstrichene Such-Zeit.
- **Wie:** Das OS ruft periodisch (z.B. alle 10s) `toob_accumulate_net_search(elapsed_ms)` auf.
- **Effekt:** Der Bootloader kann bei übermäßiger Suche (z.B. > 24h ohne Verbindung) in den Exponential-Backoff-Sleep gehen, um den Akku bei "Lagerhaus-Geräten" (eingelagert ohne Netzwerk) zu schonen.

---

## GAP-7: Kein Erase des Staging-Slots nach erfolgreichem Update (Datenhygiene)

**Problem:**  
Nachdem der Bootloader das Update installiert hat und das OS per `toob_confirm_boot()` bestätigt, bleibt das alte Update-Image im Staging-Slot physisch liegen. Das ist ein Sicherheits-Problem: Ein Angreifer mit physischem Flash-Zugang kann den alten Staging-Slot auslesen und erhält den vollen Firmware-Binärcode.

**Lösung:**  
Nach einem erfolgreichen `TOOB_STATE_COMMITTED` sollte der Bootloader (oder optional das OS via `toob_os_flash_erase`) den Staging-Slot aktiv löschen. Im Bootloader kann dies als letzter Schritt nach dem Confirm-Check in `boot_state.c` STEP 2 passieren.

---

## GAP-8: Keine maximale Download-Dauer definiert

**Problem:**  
Ein Angreifer, der den Download-Server imitiert (MITM), könnte absichtlich extrem langsame Daten senden (1 Byte/Sekunde). Das OS würde im `TOOB_OTA_STATE_RECEIVING` State hängen bleiben und den Staging-Slot quasi als "Busy Lock" halten, ohne jemals zum `finalize()` zu kommen. Das blockiert das Gerät von echten Updates.

**Lösung:**  
Die Network-App muss ein `max_download_duration_ms` Timeout implementieren. Wenn die Gesamtdauer des Downloads diesen Wert überschreitet, bricht das OS den Download ab, ruft eine neue API `toob_ota_abort()` auf (die den State auf IDLE zurücksetzt und den Buffer zeroized) und loggt den Fehlschlag.

---

## GAP-9: Fehlende `toob_ota_abort()` API

**Problem:**  
Es existiert keine Möglichkeit, einen aktiven Download sauber abzubrechen. Wenn das OS einen Netzwerk-Timeout, eine ungültige Serverantwort oder einen Benutzer-Cancel erkennt, kann es den OTA Daemon nicht aufräumen. Der State bleibt auf `TOOB_OTA_STATE_RECEIVING` und der Alignment-Buffer behält potenziell sensible Firmware-Daten im RAM.

**Lösung:**  
Eine `toob_ota_abort()` Funktion hinzufügen:
```c
toob_status_t toob_ota_abort(void);
```
- Setzt `s_state` auf `TOOB_OTA_STATE_IDLE`.
- Zeroized `s_align_buf` via `toob_ota_secure_zeroize()`.
- Setzt alle Counters zurück.
- Kann aus jedem State aufgerufen werden (RECEIVING, ERROR, DONE).

---

## GAP-10: Push-to-Pull MQTT Topic-Struktur ist unsicher

**Problem:**  
Das Dokument schlägt `devices/xyz/ota_notify` als MQTT Topic vor. Wenn ein Gerät dieses Topic abonniert und der Broker keine strikte ACL hat, kann ein kompromittiertes Gerät `devices/ANDERES_GERAET/ota_notify` abonnieren und Update-Notifications anderer Geräte mitlesen oder (schlimmer) eigene Fake-Notifications publishen.

**Lösung:**  
- MQTT Topics müssen per Broker-ACL auf die jeweilige `device_id` gelockt werden.
- Das Dokument muss explizit definieren, dass die MQTT-Topic-Bindung per Client-Zertifikat (TLS Mutual Auth) oder einem Token-basierten ACL-Mechanismus abgesichert wird.
- Der Notification-Payload sollte keine URL enthalten (das wäre ein Redirect-Angriff), sondern nur ein Flag `{"update": true}`. Die URL wird erst über den authentifizierten HTTPS POST geholt.

---

## GAP-11: Keine TLS/Certificate Pinning Anforderung definiert

**Problem:**  
Das Dokument plant HTTPS für den Download, aber definiert nicht, wie der TLS-Trust hergestellt wird. Auf Embedded-Geräten mit begrenztem Flash sind vollständige CA-Stores (100+ Root-CAs, ~200 KB) oft nicht tragbar. Ohne Certificate Pinning kann ein MITM-Angriff über ein kompromittiertes CA-Zertifikat den Download-Stream komplett ersetzen.

**Lösung:**  
Definieren, dass die Network-App **Certificate Pinning** auf den Toob-Backend-Server nutzt:
- Der SHA-256 Fingerprint des Server-Zertifikats wird fest in die Firmware eingebaut.
- Alternativ: SPKI (Subject Public Key Info) Pinning, das Zertifikats-Erneuerungen überlebt.
- Der Pin wird als Teil des SUIT Manifests oder des `generated_boot_config.h` vom Manifest-Compiler injiziert.

---

## GAP-12: Fehlende Power-Aware Download-Strategie (Batterie-Geräte)

**Problem:**  
Das Dokument behandelt nur netzgebundene Geräte. Batteriebetriebene IoT-Geräte (der Hauptmarkt) dürfen nicht mitten im Download den Akkustand unterschreiten. Ein Brownout während des Flash-Writes ist zwar durch den WAL abgesichert, aber ein Download, der den Akku von 20% auf 3% zieht und dann abbricht, ist eine Verschwendung.

**Lösung:**  
Die Network-App muss einen **Pre-Flight Battery Check** implementieren:
- Vor `toob_ota_begin()` muss der Akkustand abgefragt werden.
- Definiere ein `TOOB_OTA_MIN_BATTERY_PERCENT` (z.B. 30%).
- Wenn der Akku unter dem Schwellwert liegt, wird der Download nicht gestartet und der nächste Polling-Zyklus abgewartet.
- Optional: Schätze den Energiebedarf (`total_size * energy_per_byte`) und vergleiche mit dem verbleibenden Budget.

---

## GAP-13: HTTP Response-Validierung fehlt komplett

**Problem:**  
Das Dokument beschreibt die Server-Response als JSON (`{"update_available": true, "download_url": "...", "size": 45056}`). Es wird nicht definiert, was passiert wenn:
- `size` in der Antwort nicht mit der tatsächlichen Content-Length des Downloads übereinstimmt.
- Die `download_url` auf eine andere Domain zeigt (Open Redirect Angriff).
- Die JSON-Antwort selbst malformed ist.

**Lösung:**  
- `size` aus der JSON-Antwort muss exakt mit dem HTTP `Content-Length` Header des Downloads übereinstimmen. Abweichung → Abort.
- `download_url` muss gegen eine Allowlist von Domains geprüft werden (z.B. nur `*.toob.io` oder der Server-Origin selbst).
- Der JSON-Parser muss strict sein und bei jeder Anomalie den Download-Versuch verwerfen.

---

## GAP-14: Retry-Logik bei fehlgeschlagenem Download nicht definiert

**Problem:**  
Was passiert, wenn der HTTP GET auf die `download_url` mit einem 503, Connection Timeout oder einem partiellen Body abbricht? Das Dokument definiert keine Retry-Strategie.

**Lösung:**  
Die Network-App braucht eine definierte Retry-Strategie:
- **Max Retries:** 3 Versuche pro Polling-Zyklus.
- **Backoff:** Exponentiell: 5s → 30s → 120s.
- **Unterscheidung:** Transiente Fehler (5xx, Timeout) → Retry. Permanente Fehler (404, 403) → Abort und Meldung an den Server.
- Bei 3 fehlgeschlagenen Versuchen: Download-Versuch für diesen Zyklus abbrechen, beim nächsten Polling (24h) erneut versuchen.

---

## GAP-15: Keine Staged-Rollout/Canary-Strategie auf Geräteseite dokumentiert

**Problem:**  
Das Dokument beschreibt den Update-Flow rein aus Geräte-Sicht. Professionelle OTA-Systeme (AWS IoT, Memfault) unterstützen **Staged Rollouts** (Canary-Gruppen). Das Gerät muss wissen, ob es ein "Early Adopter" ist oder ob es warten soll.

**Lösung:**  
Die Server-Response um ein optionales `rollout_delay_s` Feld erweitern:
```json
{
  "update_available": true,
  "rollout_delay_s": 3600,
  "download_url": "..."
}
```
Das Gerät wartet die angegebene Dauer ab, bevor es den Download startet. Dadurch kann der Server steuern, welche Geräte-Gruppe (Canary 1%, Main 99%) wann drankommt.
