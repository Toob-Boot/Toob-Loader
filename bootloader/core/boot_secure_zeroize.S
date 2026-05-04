/*
 * @file boot_secure_zeroize.S
 * @brief O(1) Memory Zeroization (Bare-Metal Assembly)
 * 
 * Verhindert, dass C-Compiler (GCC/Clang) sicherheitskritische memset(0)
 * Aufrufe am Ende von Funktionen wegoptimieren (Dead Code Elimination).
 * P10 Compliant für ARM Cortex-M und RISC-V32.
 */

#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB)

    .syntax unified
    .text
    .align 2
    .global boot_secure_zeroize
    .thumb_func
    .type boot_secure_zeroize, %function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * r0 = ptr
 * r1 = len
 */
boot_secure_zeroize:
    cbz     r1, .L_end_arm    /* Wenn len == 0, sofort beenden */
    movs    r2, #0            /* Null-Register */

.L_loop_arm:
    strb    r2, [r0]          /* 1 Byte auf 0 setzen */
    adds    r0, r0, #1        /* ptr++ */
    subs    r1, r1, #1        /* len-- */
    bne     .L_loop_arm       /* Wiederholen, bis len == 0 */

.L_end_arm:
    bx      lr                /* Return */

#elif defined(__riscv)

    .text
    .align 2
    .global boot_secure_zeroize
    .type boot_secure_zeroize, @function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * a0 = ptr
 * a1 = len
 */
boot_secure_zeroize:
    beqz    a1, .L_end_riscv  /* Wenn len == 0, sofort beenden */

.L_loop_riscv:
    sb      zero, 0(a0)       /* 1 Byte auf 0 setzen (zero-register) */
    addi    a0, a0, 1         /* ptr++ */
    addi    a1, a1, -1        /* len-- */
    bnez    a1, .L_loop_riscv /* Wiederholen, bis len == 0 */

.L_end_riscv:
    ret                       /* Return */

#endif
