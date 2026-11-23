#ifndef TEST_BASELINE_ENTROPY_H
#define TEST_BASELINE_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

int clean_entropy_init(void);
void clean_entropy_deinit(void);
int clean_entropy_random(uint8_t *buf, size_t len);

#endif
