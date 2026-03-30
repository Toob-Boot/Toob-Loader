/**
 * @osv
 * component: Kernel.API
 */
#ifndef BOOTLOADER_ASSERT_H
#define BOOTLOADER_ASSERT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/**
 * @brief Defensibility Assertion for NASA P10 Rule 5
 * Evaluates the condition and halts or logs on failure.
 */
#ifndef RP_ASSERT
#define RP_ASSERT(cond, msg)                                                   \
  do {                                                                         \
    if (!(cond)) {                                                             \
      while (1) {                                                              \
      }                                                                        \
    }                                                                          \
  } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* BOOTLOADER_ASSERT_H */
