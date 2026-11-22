/*
 * Bare-Metal STM32L476RG (ARM Cortex-M4F) XIP Linker Script for Toob-Boot Guest App
 *
 * APP_FLASH_ORIGIN is supplied via -Wl,--defsym,APP_FLASH_ORIGIN=0x08038000 (Slot 0)
 * or 0x08058000 (Slot 1). Offset +0x00..+0x13 holds toob_image_header_t (20 bytes),
 * +0x14..+0xFF is 0xFF padding, and +0x100 holds the 256B-aligned Cortex-M4 VTOR table.
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
    /* Reserve 20 bytes (0x14) for prepended toob_image_header_t, pad to +0x100 VTOR */
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

