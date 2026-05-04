# Toob-Loader OTA Networking & Rollback Architecture

Dieses Dokument definiert die Strategien für das Auslösen von OTA-Updates und die lebenswichtigen Rollback-Mechanismen für den Fall, dass ein Update die Netzwerkkonnektivität des Geräts (z.B. durch einen fehlerhaften Treiber) zerstört.

## 1. Network App Implementierung (Zephyr)
Die primäre Referenz-Applikation für das Testen des OTA-Daemons wird auf **Zephyr OS** gebaut. 
* **Warum Zephyr?** Es bietet eine stark abstrahierte, POSIX-ähnliche Socket-API, einen extrem robusten Netzwerk-Stack und native Unterstützung für IoT-Protokolle.
* **Struktur**: Die Netzwerk-App läuft als isolierter Hintergrund-Thread (`toob_ota_thread`), der den Lebenszyklus des Updates asynchron zur Hauptapplikation abwickelt.

### 1.1. Download Constraints & Security (Zero-Trust)
Um die Integrität und Stabilität des Downloads zu gewährleisten, implementiert die Network App folgende P10-Constraints:
* **TLS Certificate Pinning:** Der Download-Stream darf nicht manipuliert werden. Da ein vollständiger CA-Store auf Embedded-Geräten zu groß ist, nutzt die App **Certificate Pinning** (SHA-256 Fingerprint des Server-Zertifikats oder SPKI Pinning). Der Fingerprint ist fest in der Firmware verankert.
* **HTTP Response Validation:** Das OS prüft, ob die `size` in der Server-Response exakt mit dem HTTP `Content-Length` Header übereinstimmt. Abweichungen, malformed JSONs oder Redirects auf fremde Domains (Open Redirect) führen zum sofortigen Abbruch (`toob_ota_abort`).
* **Max Download Duration:** Ein "Slowloris"-Angriff (1 Byte/Sekunde) würde das Gerät dauerhaft im Update-Status blockieren. Die App definiert einen Timeout (z.B. 10 Minuten) für den gesamten Download-Vorgang. Bei Überschreitung wird der Download abgebrochen.
* **Power-Aware Pre-Flight:** Bei Batteriegeräten prüft die App vor dem Download, ob der Akkustand ausreichend ist (z.B. `> 30%`). Ist der Akku zu schwach, wird der Polling-Zyklus ohne Download beendet, um einen Brownout während des Flash-Writes zu verhindern.

## 2. Trigger: Wie werden Updates ausgelöst?
Um die Serverlast zu minimieren und maximale Skalierbarkeit zu gewährleisten, nutzen wir ein hybrides Modell aus Polling und Push-Benachrichtigungen.

### A. Periodisches Polling (Normalzyklus)
* Das Gerät wacht in festen Intervallen auf (z.B. alle 24 Stunden) oder nutzt einen Timer im Hintergrund.
* Es sendet einen simplen HTTPS `POST` Request an das `Toob-Update-Backend`.
* **Payload**: Beinhaltet die `device_id`, aktuelle OS-Version und Diagnose-Daten (aus `toob_handoff_t`).
* **Response**: Der Server antwortet entweder mit HTTP 204 (No Content) oder HTTP 200 mit der URL zum neuen `.toob` Manifest und einer optionalen `rollout_delay_s` Zeit (für Canary-Releases / Staged Rollouts).
* **Retry-Strategie:** Schlägt der HTTP GET fehl (z.B. 503 Timeout), wird ein exponentieller Backoff (5s → 30s → 120s) für maximal 3 Versuche angewendet. Bei 404/403 Fehlern wird der Download sofort abgebrochen.

### B. Event-Driven Polling (Push-to-Pull)
* Wenn das Gerät dauerhaft verbunden ist (z.B. per MQTT für Telemetriedaten), publiziert der Server ein leichtgewichtiges Flag.
* **Sicherheit:** Das MQTT-Topic muss per Broker-ACL auf die jeweilige `device_id` beschränkt sein (z.B. `devices/<device_id>/ota_notify`), idealerweise gekoppelt an TLS Mutual Auth (Client-Zertifikate). Der Payload enthält aus Sicherheitsgründen *keine URL*, sondern nur ein Flag. Das Gerät führt daraufhin den authentifizierten Polling-Request (Schritt A) aus.

## 3. Das "Broken Network Driver" Problem
**Das Horror-Szenario im IoT-Bereich:**
Ein neues OS-Update wird erfolgreich heruntergeladen, vom Bootloader kryptografisch verifiziert und installiert (TENTATIVE Boot). Das OS startet fehlerfrei bis zur `main()`. Allerdings enthält das Update einen Bug im WLAN- oder LTE-Treiber. Das Gerät kann sich **nie wieder** mit dem Internet verbinden.

Würde das OS nun blind `toob_confirm_boot()` aufrufen, wäre das Update offiziell COMMITTED. Das Gerät wäre aus OTA-Sicht für immer ein "Brick", da es nie wieder ein Fix-Update laden kann.

## 4. Connectivity-Based Rollback Strategie (Failsafe)
Um Netzwerk-Bricks zu 100% auszuschließen, nutzen wir einen **Post-Installation Smoke Test** in zwei Stufen (L1/L2).

### Die 4 Phasen der Bestätigung:
1. **Verzögerte Bestätigung**: Das OS darf `toob_confirm_boot()` unter keinen Umständen direkt beim Systemstart aufrufen.
2. **Der L1/L2 Smoke Test**:
   * Das OS startet (befindet sich weiterhin im `TENTATIVE` Status).
   * **L1 (Netzwerk-Check):** Das OS initialisiert den Netzwerk-Stack, bezieht eine IP (DHCP) und löst einen DNS-Namen auf. Schlägt dies fehl, ist der Treiber/Stack defekt.
   * **L2 (Server-Check):** Das OS baut eine Verbindung zum `Toob-Update-Backend` auf (Ping/HTTPS).
3. **Success Path (Erfolg)**: 
   * *Nur wenn* der Server erreicht wird (L2 Erfolg), ruft das OS `toob_confirm_boot()` in der `libtoob` auf. Das Update ist nun dauerhaft COMMITTED.
4. **Failure Path (Automatischer Rollback vs. Server-Down)**:
   * **Szenario A (Treiber defekt):** Wenn **L1** fehlschlägt (Timeout definiert durch `TOOB_SMOKE_TEST_TIMEOUT_MS`), führt das OS absichtlich einen **Hardware Reset** aus (`NVIC_SystemReset()`). Der Bootloader inkrementiert den `boot_failure_counter` und führt nach 3 Versuchen den Rollback auf `STAGE_OS_B` durch.
   * **Szenario B (Server offline):** Wenn L1 erfolgreich ist, aber **L2** fehlschlägt (z.B. Server down, DDoS), geht das Gerät in einen "Server Unreachable" Backoff-Modus, *ohne* den Rollback-Mechanismus zu triggern. Dies schützt die Flotte vor falschen Rollbacks bei reinen Backend-Ausfällen.

## 5. Anti-Lagerhaus Lockout
Für Geräte, die über Monate ohne Netzwerkunterstützung eingelagert werden, akkumuliert das OS aktiv die verstrichene Netzwerk-Suchzeit (z.B. WLAN-Scanning) per `toob_accumulate_net_search()`. Überschreitet diese Akkumulation einen Grenzwert, sendet der Bootloader das Gerät in einen tagelangen "Deep Sleep" Penalty, um den Akku vor dem Tod durch ständiges Booten/Suchen zu retten.
