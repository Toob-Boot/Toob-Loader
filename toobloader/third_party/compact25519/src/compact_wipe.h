/**
 * @osv
 * component: Kernel.Security.Crypto
 * library: true
 * tag_status: auto
 */
#ifndef __COMPACT_WIPE_H
#define __COMPACT_WIPE_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
    Try to wipe contents of a buffer, as best as we can.
    (memset can be ignored by the compiler)

    Use this to clear private key data if you do not need it anymore.

    returns the data pointer, makes for easier chaining
*/
void *compact_wipe(void *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
