/*
 * Bare-Metal ARM Corstone-300 (Cortex-M55 ARMv8.1-M Non-Secure) XIP Linker Script
 *
 * Links the Guest Application at the Non-Secure alias of the Active App Slot
 * (__APP_SLOT_ORIGIN - 0x10000000 = 0x01050000) with Non-Secure SRAM at
 * 0x20040000..0x2007BFFF and Shared .noinit at __LP_RAM_ORIGIN (0x2007C000).
 */

INCLUDE generated_memory.ld

PROVIDE(APP_FLASH_ORIGIN = (__APP_SLOT_ORIGIN - 0x10000000));

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = APP_FLASH_ORIGIN, LENGTH = __APP_SLOT_LENGTH
    ram    (rwx) : ORIGIN = 0x20040000,       LENGTH = 0x0003C000
    lp_ram (rw)  : ORIGIN = __LP_RAM_ORIGIN,  LENGTH = __LP_RAM_LENGTH
}

SECTIONS
{
    /* Reserve 20 bytes (0x14) for prepended toob_image_header_t, pad to +0x100 VTOR_NS */
    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4)
    {
        FILL(0xFF);
        LONG(0xFFFFFFFF);
        . = ORIGIN(flash) + 0x100;
        KEEP(*(.isr_vector))
        KEEP(*(.app_entry))
        *(.text .text.*)
        . = ALIGN(32);
    } > flash

    .rodata : ALIGN(32)
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.gnu.linkonce.r.*)
        . = ALIGN(32);
    } > flash

    _sidata = LOADADDR(.data);
    .data : ALIGN(32)
    {
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(32);
        _data_end = .;
    } > ram AT > flash

    .bss (NOLOAD) : ALIGN(32)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(32);
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
