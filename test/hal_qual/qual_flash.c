#include "hal_qual.h"
#include "boot_flash_guard.h"
#include "boot_secure_zeroize.h"
#include <string.h>

#define QUAL_FLASH_BUF_LEN 256U

static void record_check(hal_qual_report_t *rep, bool cond, const char *name) {
    rep->tests_run++;
    if (cond) {
        rep->tests_passed++;
    } else {
        rep->tests_failed++;
        if (rep->first_failure == NULL) {
            rep->first_failure = name;
        }
    }
}

int hal_qual_flash(const boot_platform_t *plat, hal_qual_report_t *rep) {
    if (plat == NULL || rep == NULL) {
        return HAL_QUAL_FAIL;
    }
    if (plat->flash == NULL || plat->flash->abi_version != TOOB_HAL_ABI_V2 ||
        plat->flash->init == NULL || plat->flash->deinit == NULL ||
        plat->flash->read == NULL || plat->flash->write == NULL ||
        plat->flash->erase_sector == NULL || plat->flash->get_sector_size == NULL ||
        plat->flash->total_size == 0U || plat->flash->max_sector_size == 0U ||
        plat->flash->write_align == 0U) {
        record_check(rep, false, "flash_abi_and_geometry");
        return HAL_QUAL_FAIL;
    }

    const flash_hal_t *fl = plat->flash;
    record_check(rep, fl->init() == BOOT_OK, "flash_init");

    uint8_t buf[QUAL_FLASH_BUF_LEN];
    memset(buf, 0xA5, sizeof(buf));

    /* 1. NULL and OOB read/write/erase checks */
    record_check(rep, fl->read(0U, NULL, 16U) != BOOT_OK, "flash_read_null_buf");
    record_check(rep, fl->write(rep->scratch_flash_addr, NULL, fl->write_align) != BOOT_OK,
                 "flash_write_null_buf");
    record_check(rep, fl->read(fl->total_size, buf, 4U) != BOOT_OK, "flash_read_oob_exact");
    record_check(rep, fl->read(fl->total_size - 2U, buf, 4U) != BOOT_OK, "flash_read_oob_cross");
    record_check(rep, fl->write(fl->total_size, buf, fl->write_align) != BOOT_OK,
                 "flash_write_oob_exact");
    record_check(rep, fl->erase_sector(fl->total_size) != BOOT_OK, "flash_erase_oob_exact");

    /* 2. uint32_t integer wraparound (0xFFFFFFF0 + 0x20) rejection */
    record_check(rep, fl->read(0xFFFFFFF0U, buf, 0x20U) != BOOT_OK, "flash_read_wrap_u32");
    record_check(rep, fl->write(0xFFFFFFF0U, buf, 0x20U) != BOOT_OK, "flash_write_wrap_u32");
    record_check(rep, fl->erase_sector(0xFFFFF000U) != BOOT_OK, "flash_erase_wrap_u32");
    record_check(rep, boot_flash_write_guarded(fl, 0xFFFFFFF0U, buf, 0x20U) == BOOT_ERR_FLASH_BOUNDS,
                 "flash_guard_write_wrap_u32");
    record_check(rep, boot_flash_erase_sector_guarded(fl, 0xFFFFFFF0U) == BOOT_ERR_FLASH_BOUNDS,
                 "flash_guard_erase_wrap_u32");

    /* 3. Stage-0 immutable boot firewall via boot_flash_guard */
    record_check(rep,
                 boot_flash_write_guarded(fl, 0x00000000U, buf, fl->write_align) ==
                     BOOT_ERR_FLASH_BOUNDS,
                 "flash_guard_blocks_stage0_write");
    record_check(rep, boot_flash_erase_sector_guarded(fl, 0x00000000U) == BOOT_ERR_FLASH_BOUNDS,
                 "flash_guard_blocks_stage0_erase");

    /* 4. Scratch sector geometry & alignment validation */
    uint32_t test_addr = rep->scratch_flash_addr;
    if (test_addr == 0U || test_addr >= fl->total_size ||
        boot_flash_range_hits_immutable_boot(test_addr, fl->max_sector_size)) {
        test_addr = fl->total_size - fl->max_sector_size;
    }

    size_t sec_sz = 0U;
    record_check(rep, fl->get_sector_size(test_addr, &sec_sz) == BOOT_OK && sec_sz > 0U,
                 "flash_get_sector_size");

    if (fl->write_align > 1U) {
        record_check(rep, fl->write(test_addr + 1U, buf, fl->write_align) != BOOT_OK,
                     "flash_write_unaligned_addr");
        record_check(rep, fl->write(test_addr, buf, 1U) != BOOT_OK,
                     "flash_write_unaligned_len");
    }
    if (sec_sz > 1U) {
        record_check(rep, fl->erase_sector(test_addr + 1U) != BOOT_OK,
                     "flash_erase_unaligned_addr");
    }

    /* 5. Erase-before-write semantics + readback verification */
    record_check(rep, boot_flash_erase_sector_guarded(fl, test_addr) == BOOT_OK,
                 "flash_scratch_erase");

    uint8_t rb[QUAL_FLASH_BUF_LEN];
    memset(rb, 0, sizeof(rb));
    record_check(rep, fl->read(test_addr, rb, sizeof(rb)) == BOOT_OK, "flash_readback_erased");
    bool erased_match = true;
    for (size_t i = 0U; i < sizeof(rb); i++) {
        if (rb[i] != fl->erased_value) {
            erased_match = false;
            break;
        }
    }
    record_check(rep, erased_match, "flash_erased_value_match");

    uint8_t pat[QUAL_FLASH_BUF_LEN];
    for (size_t i = 0U; i < sizeof(pat); i++) {
        pat[i] = (uint8_t)(0x5AU ^ (uint8_t)i);
    }
    size_t wlen = (sizeof(pat) / fl->write_align) * fl->write_align;
    record_check(rep, wlen > 0U && boot_flash_write_guarded(fl, test_addr, pat, wlen) == BOOT_OK,
                 "flash_scratch_write_pattern");

    memset(rb, 0, sizeof(rb));
    record_check(rep, fl->read(test_addr, rb, wlen) == BOOT_OK && memcmp(rb, pat, wlen) == 0,
                 "flash_readback_pattern_match");

    /* Attempting to restore erased bits without erase MUST fail on NOR flash. */
    if (fl->erased_value == 0xFFU) {
        uint8_t ones[64];
        memset(ones, 0xFF, sizeof(ones));
        size_t o_len = (sizeof(ones) / fl->write_align) * fl->write_align;
        record_check(rep, fl->write(test_addr, ones, o_len) != BOOT_OK,
                     "flash_nor_rewrite_without_erase_rejected");
    }

    record_check(rep, boot_flash_erase_sector_guarded(fl, test_addr) == BOOT_OK,
                 "flash_scratch_cleanup_erase");

    boot_secure_zeroize(buf, sizeof(buf));
    boot_secure_zeroize(rb, sizeof(rb));
    boot_secure_zeroize(pat, sizeof(pat));
    fl->deinit();
    return (rep->tests_failed == 0U) ? HAL_QUAL_OK : HAL_QUAL_FAIL;
}
