/*
 * Bare-Metal ESP32-S3 Harvard XIP Linker Script for Toob-Boot Guest App
 *
 * Stage 1 remaps the active App/Staging physical slot to virtual 0x42000000 (IROM)
 * and 0x3C000000 (DROM). Offset 0x00..0x13 holds the 20-byte toob_image_header_t.
 */

INCLUDE generated_memory.ld

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = 0x42000000, LENGTH = __APP_SLOT_LENGTH
    drom   (r)   : ORIGIN = 0x3C000000, LENGTH = __APP_SLOT_LENGTH
    iram   (rwx) : ORIGIN = 0x40390000, LENGTH = 0x08000
    dram   (rw)  : ORIGIN = 0x3FCA0000, LENGTH = 0x20000
    lp_ram (rw)  : ORIGIN = __LP_RAM_ORIGIN, LENGTH = __LP_RAM_LENGTH
}

SECTIONS
{
    /* Reserve 20 bytes (0x14) for prepended toob_image_header_t */
    .text (ORIGIN(flash) + 0x14) : AT(ORIGIN(flash) + 0x14) ALIGN(4)
    {
        KEEP(*(.app_entry))
        *(.literal .literal.*)
        *(.text .text.*)
        . = ALIGN(16);
    } > flash

    _rodata_lma = ALIGN(LOADADDR(.text) + SIZEOF(.text), 16);
    .rodata (ORIGIN(drom) + (_rodata_lma - ORIGIN(flash))) : AT(_rodata_lma) ALIGN(16)
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.gnu.linkonce.r.*)
        . = ALIGN(16);
    } > drom

    _iram_lma = ALIGN(LOADADDR(.rodata) + SIZEOF(.rodata), 16);
    _siiram = ORIGIN(drom) + (_iram_lma - ORIGIN(flash));
    .iram1 : AT(_iram_lma) ALIGN(16)
    {
        . = ALIGN(1024);
        _iram_start = .;
        KEEP(*(.iram1.vectors))
        *(.iram1.literal .iram1.*.literal .iram1.text.literal)
        *(.iram1 .iram1.*)
        . = ALIGN(16);
        _iram_end = .;
    } > iram

    _data_lma = ALIGN(LOADADDR(.iram1) + SIZEOF(.iram1), 16);
    _sidata = ORIGIN(drom) + (_data_lma - ORIGIN(flash));
    .data : AT(_data_lma) ALIGN(16)
    {
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(16);
        _data_end = .;
    } > dram

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } > dram

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

    _stack_top = ORIGIN(dram) + LENGTH(dram);

    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
        *(.xt.lit*)
        *(.xt.prop*)
    }
}
