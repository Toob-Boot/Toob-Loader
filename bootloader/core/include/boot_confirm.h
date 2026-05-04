/**
 * @file boot_confirm.h
 * @brief Boot-Bestätigungs-Logik und Reset-Klassifikation
 *
 * Relevant Specs:
 * - docs/libtoob_api.md (Bestätigungs-Interaktion mit dem OS)
 * - docs/hals.md (Confirm HAL)
 * - docs/concept_fusion.md (Endless-Loop Protection & Watchdog-Ignorierung)
 */

#ifndef BOOT_CONFIRM_H
#define BOOT_CONFIRM_H

#include "boot_types.h"
#include "boot_hal.h"

/**
 * @brief Evaluiert das OS-Confirm-Flag unter Einbezug von Hardware-Resets.
 *
 * @param platform       HAL Plattform Pointer
 * @param expected_nonce Die vom System erwartete Boot-Nonce
 * @return BOOT_OK wenn das Flag gültig und das System stabil ist, BOOT_ERR_VERIFY bei nötigem Rollback.
 */
boot_status_t boot_confirm_evaluate(const boot_platform_t* platform, uint64_t expected_nonce);

/**
 * @brief Löscht das Confirm-Flag.
 * MUSS vor einem erfolgreichen Handoff aufgerufen werden.
 *
 * @param platform HAL Plattform Pointer
 * @return BOOT_OK oder BOOT_ERR_FLASH bei Hardwarefehlern.
 */
boot_status_t boot_confirm_clear(const boot_platform_t* platform);

#endif // BOOT_CONFIRM_H
