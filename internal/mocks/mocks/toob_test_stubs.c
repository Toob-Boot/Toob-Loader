/**
 * @file toob_test_stubs.c
 * @brief Stubs for TOOB_MOCK_TEST sandbox builds.
 * 
 * Provides the definitions for NOINIT boundary states required by libtoob 
 * logic testing when compiled with TOOB_MOCK_TEST.
 */

#include "libtoob_types.h"
#include "libtoob_config_sandbox.h"

#ifdef TOOB_MOCK_TEST

/* In a test environment, these symbols are not allocated via Linker Scripts / NOINIT.
 * We must provide them in standard BSS/DATA so the tests can link and manipulate them. */
toob_boot_diag_t toob_diag_state;
toob_handoff_t toob_handoff_state;

#endif
