.section .text.entry
.global _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    /* Stack setup from Linker */
    la sp, _stack_top

    /* Watchdog Sterilization (AI Extracted) */

    /* Zero BSS */
    la t0, _bss_start
    la t1, _bss_end
1:
    bgeu t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:

    /* Jump to C payload */
    call main
3:  j 3b /* Infinite loop on exit */