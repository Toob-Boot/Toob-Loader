# Bootloader Telemetrie-Spezifikation (CBOR)

> Die standardisierte, binär kodierte Übermittlung von Health-, Crash-, und Boot-Insights an das Feature-OS (und Cloud-Backend).

Damit Fleet-Manager in IoT-Anwendungen proaktiv Anomalien erkennen können, generiert Toob-Boot nach jedem Startvorgang eine fundierte Telemetrie.

## 1. Das Transportformat (toob_telemetry_t)

Um wertvollen MCU RAM zu schonen (und keine String-Verkettungen `sprintf` vornehmen zu müssen), rendert Toob-Boot die Datenpakete als binäres CBOR (Concise Binary Object Representation) mittels `zcbor`.

Das OS-Programm (Feature-App) kann dieses Paket (als Typ `toob_boot_diag_t` in C) über die `libtoob` aus der passiven Shared-RAM Sektion extrahieren und an den Cloud-Broker per MQTT/CoAP streamen.

Die CBOR Struktur (CDDL) sieht wie folgt aus:

```cddl
toob_telemetry = {
    1: uint,     ; boot_time_ms (Gesamtdauer Start)
    2: uint,     ; verify_time_ms (Zeit für Krypto-Hashes)
    3: uint,     ; last_error_code (z.B. BOOT_ERR_WDT_TRIGGER)
    4: uint,     ; vendor_error (Spezifischer Flash-Fehler aus der SDK-Ebene)
    5: uint,     ; active_key_index (eFuse Epoch Index)
    6: uint,     ; current_svn (Version)
    7: uint,     ; boot_failure_count (Aktuelle Edge-Recovery Versuche)
    8: bstr,     ; sbom_digest (SHA-256 der letzten Stückliste)
    9: ext_health; Health & Wear Data (Optional)
}

ext_health = {
    1: uint, ; wal_erase_count (Sliding Window Pointer)
    2: uint, ; app_slot_erase_count
    3: uint, ; staging_slot_erase_count
    4: uint  ; swap_buffer_erase_count
}
```

## 2. API Referenz (libtoob)

Die Funktion dekodiert nicht blind, sondern liest den Byte-Stream sicher als C-Struct.

```c
/**
 * @brief Extrahiert die strukturierte Boot-Diagnostik ins RAM.
 * @param out_diag Pointer auf die C-Struct für die App-Verwendung.
 * @return TOOB_OK bei Erfolg.
 */
toob_status_t toob_get_boot_diag(toob_boot_diag_t *out_diag);
```

Sobald diese Daten in der Cloud ankommen, können Alarme ausgelöst werden (z.B. `swap_buffer_erase_count > 80.000` = MCU nähert sich Flash-Tod, Gerät vorzeitig autark deaktivieren).
