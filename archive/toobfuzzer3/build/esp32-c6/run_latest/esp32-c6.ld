/* Auto-Generated Bare-Metal Linker Script for esp32-c6 (RISC-V) */
ENTRY(_start)

MEMORY
{
    rom (rx) : ORIGIN = 0x40000000, LENGTH = 0x50000
    hp_sram (rwx) : ORIGIN = 0x40800000, LENGTH = 0x80000
    lp_sram (rwx) : ORIGIN = 0x50000000, LENGTH = 0x4000
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
    } > hp_sram

    .data : ALIGN(16)
    {
        _data_start = .;
        __global_pointer$ = . + 0x800; /* RISC-V GP */
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r.*)
        _data_end = .;
    } > hp_sram

    .bss (NOLOAD) : ALIGN(16)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    } > hp_sram

    /* Stack calculation dynamically anchored to data segment end */
    _stack_top = ORIGIN(hp_sram) + LENGTH(hp_sram);
}
