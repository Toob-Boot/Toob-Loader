/**
 * @file tbm1_cgo.c
 * @brief CGo-callable shim for the bootloader's TBM1 manifest reader.
 *
 * Source-includes the exact same C code that runs on the device. This is
 * the same inclusion pattern used by test/host/tbm1_vectors.c — zero drift
 * by construction. No second implementation, no mirror, no stale copy.
 *
 * Host-compilation overrides: TOOB_DEVICE_PRODUCT_ID is set to 0xFFFF
 * (skip HW-compat check). The HW-compat and capacity checks are performed
 * in Go with full channel/product context that the C-Reader doesn't have.
 */

/* Override device identity to skip HW-compat in the C-Reader.
 * The Go admission layer performs this check with DB-derived profile data. */
#define TOOB_DEVICE_PRODUCT_ID  0xFFFFU
#define TOOB_DEVICE_HW_REV     0U
#define TOOB_DEVICE_KEY_SLOTS   6U

/* Source-level inclusion — compiles the bootloader C code in this TU. */
#include "../../../../toobloader/core/boot_tbm1.c"
#include "../../../../toobloader/core/utils/boot_crc32.c"

/**
 * @brief CGo entry point: run tbm1_validate on a raw manifest blob.
 *
 * @param buf         Pointer to the manifest buffer (must be 4-byte aligned).
 * @param buf_len     Total length of the buffer in bytes.
 * @param staging_cap Staging area capacity of the target device class.
 * @return            tbm1_reject_t value (0 = TBM1_OK).
 */
int toob_admit_validate(const unsigned char *buf,
                        unsigned int buf_len,
                        unsigned int staging_cap) {
    unsigned int offs[4]; /* image data offsets, required by tbm1_validate */
    return (int)tbm1_validate(buf, (size_t)buf_len,
                              (size_t)staging_cap, offs);
}
