/**
 * @file test_esp_mmu_remap.c
 * @brief Conformance Test Suite for esp_mmu_remap Slot Driver (REG-020)
 *
 * Verifies:
 * 1. esp_mmu_remap_slot_caps structure parameters (exec_model, slot_count, has_scratch).
 * 2. esp_mmu_get_active_slot invalid argument handling (NULL pointer check).
 * 3. esp_mmu_remap_commit alignment and flash bounds rejection before MMIO access.
 * 4. Contract compliance of exported function signatures.
 */

#include "drivers/slot/esp_mmu_remap/esp_mmu_remap.h"
#include "generated_boot_config.h"
#include <assert.h>
#include <stdio.h>

static void test_esp_mmu_remap_capabilities(void) {
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

static void test_esp_mmu_get_active_slot_null(void) {
    boot_status_t status = esp_mmu_get_active_slot(NULL);
    assert(status == BOOT_ERR_INVALID_ARG);
    printf("test_esp_mmu_get_active_slot_null: PASS\n");
}

static void test_esp_mmu_remap_commit_guards(void) {
    assert(esp_mmu_remap_commit(0x00001000U) == BOOT_ERR_FLASH_ALIGN);
    assert(esp_mmu_remap_commit(CHIP_FLASH_TOTAL_SIZE) == BOOT_ERR_FLASH_BOUNDS);
    assert(esp_mmu_remap_commit(CHIP_FLASH_TOTAL_SIZE - CHIP_MMU_PAGE_SIZE) == BOOT_ERR_FLASH_BOUNDS);
    printf("test_esp_mmu_remap_commit_guards: PASS\n");
}

int main(void) {
    printf("--- Running esp_mmu_remap Conformance Vector Suite ---\n");
    test_esp_mmu_remap_capabilities();
    test_esp_mmu_get_active_slot_null();
    test_esp_mmu_remap_commit_guards();
    printf("--- All esp_mmu_remap Conformance Tests PASSED ---\n");
    return 0;
}
