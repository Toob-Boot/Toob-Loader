#ifndef HAL_TAPE_H
#define HAL_TAPE_H

#include "boot_hal.h"
#include <stdbool.h>

typedef enum {
    TAPE_MODE_DISABLED,
    TAPE_MODE_RECORD,
    TAPE_MODE_REPLAY
} hal_tape_mode_t;

/**
 * @brief Initialisiert das Record/Replay-System.
 * @param tape_path Pfad zum Binärfile, auf dem gearbeitet wird.
 * @param mode Modus (RECORD, REPLAY oder DISABLED).
 * @param base_platform Die darunterliegende echte oder gemockte Plattform.
 * @return Eine gekapselte Plattform, die Aufrufe mitschreibt oder wiedergibt.
 */
const boot_platform_t *hal_tape_init(const char *tape_path, hal_tape_mode_t mode, const boot_platform_t *base_platform);

/**
 * @brief Schließt das Bandfile und beendet die Aufzeichnung/Wiedergabe.
 */
void hal_tape_deinit(void);

#endif /* HAL_TAPE_H */
