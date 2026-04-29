.section .text.entry, "ax"
.global _start
_start:
    movi a0, 0
    movi a1, _stack_top
    wsr.vecbase a0
    movi a1, _stack_top

    /* Watchdog Sterilization (AI Extracted) */
    /* Disable TIMG0_WDT */
    movi a2, 0x50D83AA1
    movi a3, 0x3FF5F064
    s32i a2, a3, 0
    movi a2, 0x0
    movi a3, 0x3FF5F048
    s32i a2, a3, 0
    /* Disable TIMG1_WDT */
    movi a2, 0x50D83AA1
    movi a3, 0x3FF60064
    s32i a2, a3, 0
    movi a2, 0x0
    movi a3, 0x3FF60048
    s32i a2, a3, 0
    /* Disable RTC_WDT */
    movi a2, 0x50D83AA1
    movi a3, 0x3FF480A4
    s32i a2, a3, 0
    movi a2, 0x0
    movi a3, 0x3FF4808C
    s32i a2, a3, 0

    /* Zero BSS */
    movi a2, _bss_start
    movi a3, _bss_end
    movi a4, 0
.L_clear_bss:
    bgeu a2, a3, .L_bss_done
    s32i a4, a2, 0
    addi a2, a2, 4
    j .L_clear_bss
.L_bss_done:

    call4 main
3:  j 3b /* Infinite loop */