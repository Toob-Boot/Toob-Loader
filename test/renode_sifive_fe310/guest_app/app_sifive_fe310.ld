/*
 * Bare-Metal SiFive FE310-G002 QSPI0 XIP Linker Script for Toob-Boot Guest App
 *
 * Stage 1 verifies and executes the active Guest App directly via XIP at
 * __APP_SLOT_ORIGIN (0x20050000). Offset 0x00..0x13 holds the 20-byte
 * toob_image_header_t; _app_start resides at 0x20050014.
 */

INCLUDE generated_memory.ld

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = __APP_SLOT_ORIGIN, LENGTH = __APP_SLOT_LENGTH
    ram    (rwx) : ORIGIN = __SRAM_ORIGIN, LENGTH = __SRAM_LENGTH
    lp_ram (rw)  : ORIGIN = __LP_RAM_ORIGIN, LENGTH = __LP_RAM_LENGTH
}

SECTIONS
{
    /* Reserve 20 bytes (0x14) for prepended toob_image_header_t */
    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4)
    {
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
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.data.ramfunc .data.ramfunc.*)
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
