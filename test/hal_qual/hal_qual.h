#ifndef TOOB_HAL_QUAL_H
#define TOOB_HAL_QUAL_H

#include "boot_hal.h"
#include "boot_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_QUAL_OK   0
#define HAL_QUAL_FAIL (-1)

#define HAL_QUAL_FLAG_TEST_OTP_ADVANCE (1U << 0)

typedef struct {
    uint32_t tests_run;
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t tests_skipped;
    uint32_t scratch_flash_addr;
    uint32_t flags;
    const char *first_failure;
} hal_qual_report_t;

int hal_qual_crypto(const boot_platform_t *plat, hal_qual_report_t *rep);
int hal_qual_entropy(const boot_platform_t *plat, hal_qual_report_t *rep);
int hal_qual_flash(const boot_platform_t *plat, hal_qual_report_t *rep);
int hal_qual_keystore_soc(const boot_platform_t *plat, hal_qual_report_t *rep);

int toob_hal_qualify_with_report(const boot_platform_t *plat, hal_qual_report_t *report);
int toob_hal_qualify(const boot_platform_t *plat);

#ifdef __cplusplus
}
#endif

#endif /* TOOB_HAL_QUAL_H */
