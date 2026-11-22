/*
 * @file boot_secure_zeroize.S
 * @brief O(1) Memory Zeroization (Bare-Metal Assembly)
 *
 * Prevents C compilers (GCC/Clang) from dead-store eliminating security-critical
 * zeroization calls. Supports ARMv6-M/v7-M/v8-M, AArch64, RISC-V, and Xtensa.
 */

#if defined(__aarch64__)

    .text
    .align 2
    .global boot_secure_zeroize
    .type boot_secure_zeroize, %function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * x0 = ptr, x1 = len
 */
boot_secure_zeroize:
    cbz     x1, .L_end_aarch64

.L_loop_aarch64:
    strb    wzr, [x0], #1
    subs    x1, x1, #1
    b.ne    .L_loop_aarch64

.L_end_aarch64:
    ret

#elif defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB)

    .syntax unified
    .text
    .align 2
    .global boot_secure_zeroize
    .thumb_func
    .type boot_secure_zeroize, %function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * r0 = ptr, r1 = len (ARMv6-M Thumb-1 compatible: no cbz)
 */
boot_secure_zeroize:
    cmp     r1, #0
    beq     .L_end_arm
    movs    r2, #0

.L_loop_arm:
    strb    r2, [r0]
    adds    r0, r0, #1
    subs    r1, r1, #1
    bne     .L_loop_arm

.L_end_arm:
    bx      lr

#elif defined(__riscv)

    .text
    .align 2
    .global boot_secure_zeroize
    .type boot_secure_zeroize, @function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * a0 = ptr, a1 = len
 */
boot_secure_zeroize:
    beqz    a1, .L_end_riscv

.L_loop_riscv:
    sb      zero, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, -1
    bnez    a1, .L_loop_riscv

.L_end_riscv:
    ret

#elif defined(__XTENSA__)

    .text
    .align 4
    .global boot_secure_zeroize
    .type boot_secure_zeroize, @function

/*
 * void boot_secure_zeroize(void *ptr, size_t len);
 * Windowed ABI (CALL8) / Call0 ABI: a2 = ptr, a3 = len
 */
boot_secure_zeroize:
#ifdef __XTENSA_WINDOWED_ABI__
    entry   sp, 16
#endif
    beqz    a3, .L_end_xtensa
    movi    a4, 0

.L_loop_xtensa:
    s8i     a4, a2, 0
    addi    a2, a2, 1
    addi    a3, a3, -1
    bnez    a3, .L_loop_xtensa

.L_end_xtensa:
#ifdef __XTENSA_WINDOWED_ABI__
    retw
#else
    ret
#endif

#endif
