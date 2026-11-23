#include "fuzz_common.h"

#include "boot_crc32.h"
#include "boot_effect.h"
#include "boot_journal.h"
#include "boot_multiimage.h"
#include "boot_verify.h"

#define FUZZ_MI_MAX_COMPS 8U

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL) {
        return 0;
    }

    fuzz_platform_reset(0x4D554C54ULL ^ (uint64_t)size);
    const boot_platform_t *plat = fuzz_platform_get();
    fuzz_keystore_set_dslc(0x01U);
    fuzz_keystore_set_monotonic(0U);
    fuzz_keystore_set_key(0U, g_fuzz_root_pk, true);

    /* 1. toob_image_header_t + TSIG trailer verification on App Slot flash image. */
    fuzz_flash_fill_erased(CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE);
    if (size >= sizeof(toob_image_header_t)) {
        size_t app_wr = (size > CHIP_APP_SLOT_SIZE) ? CHIP_APP_SLOT_SIZE : size;
        fuzz_flash_write_raw(CHIP_APP_SLOT_ABS_ADDR, data, app_wr);

        toob_image_header_t hdr;
        memcpy(&hdr, data, sizeof(hdr));
        (void)boot_verify_slot_image(plat, CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE, &hdr,
                                     crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    }

    /* 2. Multi-image descriptor + whitelist bounds + Stage 1/NetCore planning & apply. */
    g_fuzz_trap_active = 1;
    if (setjmp(g_fuzz_trap_jmp) == 0) {
        if (boot_journal_init(plat) == BOOT_OK && size >= sizeof(boot_component_t)) {
            static const boot_allowed_region_t whitelist[3] = {
                { CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE },
                { CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE },
                { CHIP_NETCORE_SLOT_ABS_ADDR, CHIP_NETCORE_SLOT_SIZE }
            };

            boot_component_t comps[FUZZ_MI_MAX_COMPS];
            memset(comps, 0, sizeof(comps));

            uint32_t count = (uint32_t)(size / sizeof(boot_component_t));
            if (count > FUZZ_MI_MAX_COMPS) {
                count = FUZZ_MI_MAX_COMPS;
            }
            memcpy(comps, data, count * sizeof(boot_component_t));

            size_t payload_off = count * sizeof(boot_component_t);
            if (payload_off < size) {
                size_t rem = size - payload_off;
                size_t wr = (rem > CHIP_STAGING_SLOT_SIZE) ? CHIP_STAGING_SLOT_SIZE : rem;
                fuzz_flash_write_raw(CHIP_STAGING_SLOT_ABS_ADDR, &data[payload_off], wr);
            }

            for (uint32_t i = 0U; i < count; i++) {
                flash_effect_t fx[2];
                size_t planned = 0U;
                (void)boot_multiimage_plan_component(plat, CHIP_STAGING_SLOT_ABS_ADDR, &comps[i],
                                                     0x12345678U, fx, 2U, &planned);
            }

            wal_entry_payload_t txn;
            memset(&txn, 0, sizeof(txn));
            txn.magic = WAL_ENTRY_MAGIC;
            txn.intent = WAL_INTENT_UPDATE_PENDING;
            (void)boot_multiimage_apply(plat, CHIP_STAGING_SLOT_ABS_ADDR, comps, count,
                                        whitelist, 3U, &txn, crypto_arena,
                                        BOOT_CRYPTO_ARENA_SIZE);
        }
    }
    g_fuzz_trap_active = 0;

    boot_journal_zeroize_secrets();
    return 0;
}

TOOB_FUZZ_DEFINE_MAIN("multiimage")
