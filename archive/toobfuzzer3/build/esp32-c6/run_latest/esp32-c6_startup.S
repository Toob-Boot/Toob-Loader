.section .text.entry
.global _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    /* Stack setup from Linker */
    la sp, _stack_top
    /* Global Pointer initialization for relaxed data segments */
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    /* Watchdog Sterilization (AI Extracted) */
    /* Disable TIMG0_WDT */
    li a0, 0x50D83AA1
    li a1, 0x60008064
    sw a0, 0(a1)
    li a0, 0x0
    li a1, 0x60008048
    sw a0, 0(a1)
    /* Disable TIMG1_WDT */
    li a0, 0x50D83AA1
    li a1, 0x60009064
    sw a0, 0(a1)
    li a0, 0x0
    li a1, 0x60009048
    sw a0, 0(a1)
    /* Disable LP_WDT */
    li a0, 0x50D83AA1
    li a1, 0x600B0414
    sw a0, 0(a1)
    li a0, 0x0
    li a1, 0x600B0400
    sw a0, 0(a1)

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