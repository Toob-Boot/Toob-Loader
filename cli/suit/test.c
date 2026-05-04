/*
 * Generated using zcbor version 0.9.1
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "test.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

#define log_result(state, result, func) do { \
	if (!result) { \
		zcbor_trace_file(state); \
		zcbor_log("%s error: %s\r\n", func, zcbor_error_str(zcbor_peek_error(state))); \
	} else { \
		zcbor_log("%s success\r\n", func); \
	} \
} while(0)

static bool decode_my_field(zcbor_state_t *state, struct my_field *result);
static bool decode_test_map(zcbor_state_t *state, struct test_map *result);


static bool decode_my_field(
		zcbor_state_t *state, struct my_field *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((((zcbor_uint32_expect(state, (100))))
	&& (zcbor_uint32_decode(state, (&(*result).my_field)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_test_map(
		zcbor_state_t *state, struct test_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_map_start_decode(state) && ((((decode_my_field(state, (&(*result).test_map_my_field_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	log_result(state, res, __func__);
	return res;
}



int cbor_decode_test_map(
		const uint8_t *payload, size_t payload_len,
		struct test_map *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_test_map, sizeof(states) / sizeof(zcbor_state_t), 1);
}
