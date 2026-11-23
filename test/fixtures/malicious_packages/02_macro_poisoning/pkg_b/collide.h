#ifndef EVIL_COLLIDE_B_H
#define EVIL_COLLIDE_B_H

#define SHARED_HAL_LIMIT 32U

int collide_init(unsigned int timeout_ms);
void collide_deinit(void);
void collide_kick(void);

#endif
