/*
 * Bare-Metal ESP32-C6 Unified XIP Linker Script for Toob-Boot Guest App
 *
 * Stage 1 remaps the active App/Staging physical slot to virtual 0x42000000
 * (Unified L1 Cache for instructions + rodata). Offset 0x00..0x13 holds the
 * 20-byte toob_image_header_t. HP-SRAM ends at 0x4087C000 to preserve the
 * top 16 KB (0x4087C000..0x4087FFFF) reserved by BootROM SPI flash routines.
 */

INCLUDE generated_memory.ld

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = 0x42000000, LENGTH = __APP_SLOT_LENGTH
    sram   (rwx) : ORIGIN = 0x40820000, LENGTH = 0x5C000
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

    .iram_text : ALIGN(16)
    {
        _iram_start = .;
        *(.iram_text .iram_text.*)
        . = ALIGN(16);
        _iram_end = .;
    } > sram AT > flash
    _siiram = LOADADDR(.iram_text);

    .data : ALIGN(16)
    {
        _data_start = .;
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(16);
        _data_end = .;
    } > sram AT > flash
    _sidata = LOADADDR(.data);

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } > sram

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

    _stack_top = ORIGIN(sram) + LENGTH(sram);

    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
