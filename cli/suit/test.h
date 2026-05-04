/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef TEST_H__
#define TEST_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "test_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_decode_test_map(
		const uint8_t *payload, size_t payload_len,
		struct test_map *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* TEST_H__ */
