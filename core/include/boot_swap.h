#ifndef BOOT_SWAP_H
#define BOOT_SWAP_H

/*
 * Toob-Boot Core Header: boot_swap.h
 * Relevant Spec-Dateien:
 * - docs/toobfuzzer_integration.md (Fuzzing-Aware Block Tausch, Limitierungen)
 * - docs/testing_requirements.md (Brownout Recovery)
 */

#include "boot_types.h"
#include "boot_hal.h"
#include "boot_config_mock.h"


/**
 * @brief Apply a swap or copy operation from src_base to dest_base.
 *        This function safely orchestrates the in-place overwrite using a swap buffer.
 *
 * @param platform  Hardware HAL abstraction
 * @param src_base  Source address
 * @param dest_base Destination address
 * @param length    Total length to swap
 * @return boot_status_t BOOT_OK on success, error otherwise.
 */
boot_status_t boot_swap_apply(const boot_platform_t *platform, uint32_t src_base, uint32_t dest_base, uint32_t length);
 
#endif /* BOOT_SWAP_H */
