/*
 * Bare-Metal ESP32 (Xtensa LX6) Split IROM/DROM XIP Linker Script for Guest App
 *
 * Stage 1 programs DPORT_PRO_FLASH_MMU_TABLE (0x3FF10000) so the active 64 KB
 * aligned App/Staging physical slot is mapped simultaneously to:
 *   - IROM0 0x400D0000 (entries [77..82]) for .text XIP instruction fetch
 *   - DROM0 0x3F400000 (entries [0..5])   for .rodata & prepended TIMG header
 * Offset 0x00..0x13 holds the 20-byte toob_image_header_t.
 */

INCLUDE generated_memory.ld

ENTRY(_app_start)

MEMORY
{
    flash  (rx)  : ORIGIN = 0x400D0000, LENGTH = __APP_SLOT_LENGTH
    drom   (r)   : ORIGIN = 0x3F400000, LENGTH = __APP_SLOT_LENGTH
    iram   (rwx) : ORIGIN = 0x40088000, LENGTH = 0x08000
    dram   (rw)  : ORIGIN = 0x3FFB0000, LENGTH = 0x30000
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
        *(.scommon)
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
