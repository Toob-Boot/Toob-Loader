/**
 * @file tbm1_fuzz.c
 * @brief libFuzzer harness for tbm1_validate() (V3)
 *
 * Feeds arbitrary byte buffers into tbm1_validate(). Must never crash,
 * never OOB-read, always return a defined tbm1_reject_t.
 *
 * Build (requires Clang with libFuzzer):
 *   clang -g -O1 -fsanitize=fuzzer,address \
 *     -I common/include -I toobloader/core/include \
 *     -I toobloader/core/utils/include -I sdk/libtoob/include \
 *     test/fuzz/tbm1_fuzz.c -o builds/build_host/tbm1_fuzz
 *
 * Run:
 *   ./builds/build_host/tbm1_fuzz -max_len=4096 -timeout=10
 *
 * Seed corpus (optional): place a valid 1024-byte TBM1 blob in corpus/
 * to give the fuzzer a head start past the magic/CRC checks.
 */

#include <stdint.h>
#include <stddef.h>

/* Use default device identity (product_id = 0xFFFF → skip HW check) */
#include "../../toobloader/core/boot_tbm1.c"
#include "../../toobloader/core/utils/boot_crc32.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Let small inputs through — they exercise early precheck rejects.
   * Only skip truly degenerate sizes that add no value. */
  if (size < 16) return 0;

  (void)tbm1_validate(data, size);
  return 0;
}
