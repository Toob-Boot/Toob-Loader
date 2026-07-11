#ifndef FLASH_MODEL_H
#define FLASH_MODEL_H

#include "boot_hal.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Dateibasiertes NOR-Flash-Modell für Host-Simulationen (Torn-Writes & Crashes).
 */
typedef struct {
    char     *file_path;     /**< Pfad zur Simulationsdatei */
    size_t    total_size;    /**< Gesamtgröße des simulierten Flashs */
    uint32_t  sector_size;   /**< Sektorgröße */
    uint8_t   erased_value;  /**< Standard-Wert nach dem Löschen (0xFF) */
    uint8_t   write_align;   /**< Schreib-Ausrichtung (Alignment) */

    /* Fehler- und Torn-Write-Injektions-Steuerung */
    uint32_t  fail_at_op;    /**< 0 = kein Fehler; n = simuliere Stromausfall bei der n-ten Operation */
    uint32_t  torn_prefix;   /**< Anzahl Bytes, die vor dem Abbruch noch geschrieben werden */
    uint32_t  op_counter;    /**< Interner Zähler für Schreib- und Löschoperationen */
} flash_model_t;

/**
 * @brief Initialisiert das Flash-Modell und liefert die flash_hal_t-Schnittstelle.
 * @param model Zeiger auf das zu initialisierende Modell. Die Felder müssen vorab befüllt sein.
 * @return Eine HAL-Schnittstelle, die direkt in boot_platform_t eingehängt werden kann.
 */
const flash_hal_t *flash_model_get_hal(flash_model_t *model);

#endif /* FLASH_MODEL_H */
