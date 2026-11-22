/*
 * Bare-Metal STM32F072 (ARM Cortex-M0 ARMv6-M, No VTOR) XIP Linker Script for Toob-Boot Guest App
 *
 * Offset +0x00..+0x13 holds toob_image_header_t (20 bytes), +0x14..+0xFF is 0xFF padding,
 * and +0x100 holds the 48-entry (192-byte) ARMv6-M vector table copied by Stage 1 into
 * reserved SRAM [0x20000000..0x20000100) and remapped to 0x00000000 via SYSCFG_CFGR1.MEM_MODE=3.
 * Guest App .data/.bss/stack start at __SRAM_ORIGIN (0x20000100) so the live vector table
 * at 0x20000000 is never overwritten.
 */

INCLUDE generated_memory.ld

PROVIDE(APP_FLASH_ORIGIN = __APP_SLOT_ORIGIN);

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = APP_FLASH_ORIGIN, LENGTH = __APP_SLOT_LENGTH
    ram    (rwx) : ORIGIN = __SRAM_ORIGIN,    LENGTH = __SRAM_LENGTH
    lp_ram (rw)  : ORIGIN = __LP_RAM_ORIGIN,  LENGTH = __LP_RAM_LENGTH
}

SECTIONS
{
    /* Reserve 20 bytes (0x14) for prepended toob_image_header_t, pad to +0x100 vector table */
    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4)
    {
        FILL(0xFF);
        LONG(0xFFFFFFFF);
        . = ORIGIN(flash) + 0x100;
        KEEP(*(.isr_vector))
        KEEP(*(.app_entry))
        *(.text .text.*)
        . = ALIGN(16);
    } > flash

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.gnu.linkonce.r.*)
        . = ALIGN(16);
    } > flash

    _sidata = LOADADDR(.data);
    .data : ALIGN(16)
    {
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(16);
        _data_end = .;
    } > ram AT > flash

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } > ram

    .noinit (NOLOAD) : ALIGN(8)
    {
        _noinit_base = .;
        KEEP(*(.noinit.toob_handoff_state))
        . = MAX(., _noinit_base + 0x50);
        KEEP(*(.noinit.toob_diag_state))
        . = MAX(., _noinit_base + 0xD8);
        KEEP(*(.noinit.toob_ota_resume_state))
        . = MAX(., _noinit_base + 0x118);
        . = ALIGN(8);
        *(.noinit .noinit.*)
    } > lp_ram

    _stack_top = ORIGIN(ram) + LENGTH(ram);

    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
