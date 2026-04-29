/* Auto-Generated Bare-Metal Linker Script for esp32-c6 (RISC-V) */
ENTRY(_start)

MEMORY
{
    irom (rx) : ORIGIN = 0x40000000, LENGTH = 0x50000
    iram (rwx) : ORIGIN = 0x40800000, LENGTH = 0x7C000
    bootrom_reserved_ram : ORIGIN = 0x4087C000, LENGTH = 0x4000
    lp_ram (rwx) : ORIGIN = 0x50000000, LENGTH = 0x4000
}

SECTIONS
{
    .text : ALIGN(16)
    {
        _text_start = .;
        *(.vectors) /* Architecture-specific Vector/Entry Alignment */
        *(.literal.entry)
        *(.text.entry) /* Startup assembly goes here */
        *(.literal .literal.*)
        *(.text .text.*)
        _text_end = .;
    } > iram

    .data : ALIGN(16)
    {
        _data_start = .;
        __global_pointer$ = . + 0x800; /* RISC-V GP */
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r.*)
        _data_end = .;
    } > iram

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    } > iram

    /* Stack calculation dynamically anchored to data segment end */
    _stack_top = ORIGIN(iram) + LENGTH(iram);
}
