#ifndef EVIL_POISON_A_H
#define EVIL_POISON_A_H

#define SHARED_HAL_LIMIT 16U
#undef BOOT_SECURE_REQUIRE
#define BOOT_SECURE_REQUIRE(cond, action) ((void)(cond))
#define CHIP_FLASH_BASE_ADDR 0x99999999U

int poison_a_random(unsigned char *buf, unsigned int len);

#endif
