/**
 * @file test_esp_mmu_remap.c
 * @brief Conformance Test Suite for esp_mmu_remap Slot Driver (REG-020)
 *
 * Verifies:
 * 1. esp_mmu_remap_slot_caps structure parameters (exec_model, slot_count, has_scratch).
 * 2. esp_mmu_get_active_slot invalid argument handling (NULL pointer check).
 * 3. Contract compliance of exported function signatures.
 */

#include "drivers/slot/esp_mmu_remap/esp_mmu_remap.h"
#include <assert.h>
#include <stdio.h>

void test_esp_mmu_remap_capabilities(void) {
    const slot_caps_t *caps = &esp_mmu_remap_slot_caps;
    assert(caps != NULL);
    assert(caps->exec_model == SLOT_EXEC_XIP_REMAP);
    assert(caps->slot_count == 2);
    assert(caps->has_scratch == false);
    assert(caps->scratch_size == 0);
    assert(caps->ops.xip_remap.xip_remap_commit == esp_mmu_remap_commit);
    assert(caps->get_active_slot == esp_mmu_get_active_slot);
    printf("test_esp_mmu_remap_capabilities: PASS\n");
}

void test_esp_mmu_get_active_slot_null(void) {
    boot_status_t status = esp_mmu_get_active_slot(NULL);
    assert(status == BOOT_ERR_INVALID_ARG);
    printf("test_esp_mmu_get_active_slot_null: PASS\n");
}

int main(void) {
    printf("--- Running esp_mmu_remap Conformance Vector Suite ---\n");
    test_esp_mmu_remap_capabilities();
    test_esp_mmu_get_active_slot_null();
    printf("--- All esp_mmu_remap Conformance Tests PASSED ---\n");
    return 0;
}
