/*
 * Bare-Metal Nordic nRF52840 Cortex-M4F XIP Linker Script for Toob-Boot Rust Guest App
 *
 * Stage 1 deploys the active firmware to App Slot (0x00038000), sets SCB->VTOR to
 * 0x00038100 (ORIGIN(flash) + 0x100), loads MSP from [VTOR], and branches to [VTOR + 4].
 */

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = 0x00038000, LENGTH = 0x00030000
    ram    (rwx) : ORIGIN = 0x20000000, LENGTH = 0x0003F000
    lp_ram (rw)  : ORIGIN = 0x2003F000, LENGTH = 0x00000FC0
}

SECTIONS
{
    /* Reserve 0x14 bytes for prepended toob_image_header_t and 0xFF-pad up to +0x100 VTOR */
    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4)
    {
        FILL(0xFF);
        LONG(0xFFFFFFFF);
        . = ORIGIN(flash) + 0x100;
        KEEP(*(.isr_vector))
        KEEP(*(.app_entry))
        *(.text .text.*)
        . = ALIGN(16);
    } > flash =0xFF

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
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
        *(.ARM.exidx*)
        *(.ARM.extab*)
    }
}
