#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Host-Sandbox Mock für die Assembler-Zeroize Funktion.
 * 
 * Diese Datei wird exklusiv für das `sandbox` Target (`host` Arch) kompiliert,
 * da die x86_64 Host-Umgebung keine ARM Cortex oder Xtensa Assembler-Befehle
 * (.S Dateien) versteht. Sie nutzt einen volatile Pointer-Cast, um
 * Compiler Dead-Code-Elimination abzubremsen/verhindern.
 */
void boot_secure_zeroize(void* ptr, size_t len);

__attribute__((noinline)) void boot_secure_zeroize(void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
    __asm__ volatile("" : : "g"(ptr) : "memory");
}

#ifdef TOOB_MOCK_TEST
volatile int g_fault_trigger_count = 0;
volatile int g_fault_target_index = -1;

bool should_inject_fault(void) {
    int current = g_fault_trigger_count++;
    if (g_fault_target_index >= 0 && current == g_fault_target_index) {
        return true;
    }
    return false;
}
#endif
