> **Quelle/Referenz:** Analysiert aus `wolfBoot/docs/API.md`


# 09. Application Interaction Interface (API)

Dieses Dokument spezifiziert die vertragliche API (Application Programming Interface), welche das laufende Ziel-Betriebssystem verwendet, um mit der State-Machine des Bootloaders zu kommunizieren. Es definiert die Brücke (C-Library) zwischen "Application Space" und "Bootloader Space" nach strengen Checklist-Vorgaben.

## 1. Library Integration (lib_bootloader)
- [ ] **Header Inclusion:** Die Ziel-Applikation muss sich zwingend gegen die bereitgestellte Header-Datei (z.B. `#include <toob_bootloader.h>`) linken, um Zugang zu State-Flags und IPC-Aufrufen zu erlangen.
- [ ] **State-Manipulation:** Die Library kapselt alle low-level Flash-Zugriffe (wie das Setzen der Magic-Bytes in die Partition-Trailer, siehe Item `06`) hinter hochsprachlichen C-Funktionen.

## 2. High-Level Operations (Standard Firmware API)
Um den Update-Lebenszyklus zu steuern, **MUSS** die Ziel-Firmware folgende Schnittstellen-Verträge implementieren und ansprechen:

| API Funktion / Makro | Beschreibung & State-Machine Effekt |
|----------------------|-------------------------------------|
| `bootloader_get_image_version(part)` | Gibt die 4-Byte Versionsnummer aus dem TLV-Header der angeforderten Partition (BOOT oder UPDATE) zurück. |
| `bootloader_update_trigger()` | Signalisierungs-Funktion. **When** aufgerufen, **Then** setzt der Code via Flash-Write den Trailer der UPDATE Partition auf `STATE_UPDATING (0x70)`. Instructiert den Bootloader beim nächsten regulären MCU-Reset, den Swap-Vorgang zu starten. |
| `bootloader_success()` | Bestätigungs-Funktion. **When** das aktualisierte OS erfolgreich hochfährt, **Then** muss diese Funktion aufgerufen werden, um das State-Byte der BOOT-Partition von `STATE_TESTING (0x10)` auf `STATE_SUCCESS (0x00)` umzuschreiben. Erfolgt der Aufruf nicht, triggert der nächste Power-Loss unweigerlich den Fallback (Rollback). |

*(Hinweis: Als Syntax-Sugar existieren hierfür Hilfsmakros wie `bootloader_current_firmware_version()` und `bootloader_update_firmware_version()`).*

## 3. TrustZone Non-Secure Callables (NSC API)
Spezialfall für ARM TrustZone-M (`TZEN=1`): Wenn die Ziel-Firmware in der Non-Secure Zone läuft, der Bootloader und das Flash-Subsystem aus Sicherheitsgründen aber komplett in die Secure Zone gemappt sind. 
In diesem Fall stellt die Toob-Boot Library isolierte NSC (Non-Secure Callable) Wrapper-Routinen bereit, um cross-domain Zugriffe zu autorisieren:

- [ ] **Status & Trigger Wrappers:** Alle High-Level Standard-APIs werden über gesicherte Bridges gemappt (`bootloader_nsc_success()`, `bootloader_nsc_update_trigger()`, `bootloader_nsc_get_image_version()`).
- [ ] **Flash Access Delegation:** Die Non-Secure App darf den Update-Flash auf Hardware-Basis nicht physisch beschreiben. Sie **muss** folgende sicheren Delegations-APIs nutzen, um das Payload in den UPDATE Slot zu streamen:
  - `bootloader_nsc_get_partition_state(part, *st)`: Sicherer Trailer-Read.
  - `bootloader_nsc_erase_update(address, len)`: Leitet einen Sektor-Erase im Secure-Bereich an einem gewünschten relativen Offset ein.
  - `bootloader_nsc_write_update(address, *buf, len)`: Pumpt den Buffer-Array (Firmware Payload) sicher vom Non-Secure in den Secure-UPDATE-Speicher.
