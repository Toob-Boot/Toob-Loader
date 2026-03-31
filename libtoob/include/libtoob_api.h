#ifndef LIBTOOB_API_H
#define LIBTOOB_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Feature-OS Flash Write Shim (WEAK Symbol)
 * 
 * toob_libtoob.c (z.B. der Toob-OTA Agent) benötigt die Fähigkeit, in den Flash 
 * zu schreiben (für das WAL & Confirm-Flags). Um die Library von riesigen 
 * `toob_hal` Treibern abzukapseln, MUSS das Kunden-Feature-OS (z.B. MCUboot/Zephyr)
 * dieses schwache Symbol implementieren und damit auf seinen EIGENEN Flash-Stack umleiten.
 * 
 * @param offset Der absolute Adress-Offset im SPI Flash.
 * @param data Pointer auf die zu schreibenden Daten.
 * @param len Länge der Daten in Bytes.
 * @return 0 bei Erfolg, negativ bei Fehler.
 */
__attribute__((weak)) int toob_os_flash_write(uint32_t offset, const void* data, uint32_t len);

/* ... Weitere APIs folgen im Zuge der C-Implementierung ... */

#ifdef __cplusplus
}
#endif

#endif // LIBTOOB_API_H
