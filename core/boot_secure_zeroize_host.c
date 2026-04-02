#include <stddef.h>
#include <stdint.h>

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
}
