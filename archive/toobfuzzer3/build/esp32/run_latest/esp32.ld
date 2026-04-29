/* Auto-Generated Bare-Metal Linker Script for esp32 (Xtensa (ESP32)) */
ENTRY(_start)

MEMORY
{
    irom0 (rx) : ORIGIN = 0x40000000, LENGTH = 0x60000
    drom0 (r) : ORIGIN = 0x3FF90000, LENGTH = 0x10000
    hardware_reserved_cache : ORIGIN = 0x40070000, LENGTH = 0x10000
    iram0 (rwx) : ORIGIN = 0x40080400, LENGTH = 0x1FC00
    bootrom_reserved_dram : ORIGIN = 0x3FFAE000, LENGTH = 0x2000
    dram0 (rw) : ORIGIN = 0x3FFB2000, LENGTH = 0x2E000
    dram1 (rw) : ORIGIN = 0x3FFE0000, LENGTH = 0x20000
    rtc_fast_dram (rw) : ORIGIN = 0x3FF80000, LENGTH = 0x2000
    rtc_fast_iram (rwx) : ORIGIN = 0x400C0000, LENGTH = 0x2000
    rtc_slow_dram (rw) : ORIGIN = 0x50000000, LENGTH = 0x2000
}

SECTIONS
{
    .text : ALIGN(16)
    {
        _text_start = .;
        *(.iram0.vectors) /* Architecture-specific Vector/Entry Alignment */
        *(.literal.entry)
        *(.text.entry) /* Startup assembly goes here */
        *(.literal .literal.*)
        *(.text .text.*)
        _text_end = .;
    } > iram0

    .data : ALIGN(16)
    {
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r.*)
        _data_end = .;
    } > dram0

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    } > dram0

    /* Stack calculation dynamically anchored to data segment end */
    _stack_top = ORIGIN(dram0) + LENGTH(dram0);
}
