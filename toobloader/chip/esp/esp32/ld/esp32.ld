ENTRY(boot_startup_vector)

MEMORY
{
  iram_seg (RX) : ORIGIN = 0x40080000, LENGTH = 0x20000 /* 128KB IRAM */
  dram_seg (RW) : ORIGIN = 0x3FFF0000, LENGTH = 0x10000 /* 64KB DRAM */
}

SECTIONS
{
  .iram.text :
  {
    . = ALIGN(4);
    _iram_start = .;
    KEEP(*(.entry.literal))
    KEEP(*(.entry.text))
    *(.literal .text .literal.* .text.*)
    *(.rodata .rodata.*)
    _iram_end = .;
  } > iram_seg

  .dram.data :
  {
    . = ALIGN(4);
    _data_start = .;
    *(.data .data.*)
    _data_end = .;
  } > dram_seg

  .dram.bss (NOLOAD) :
  {
    . = ALIGN(4);
    _bss_start = .;
    *(.bss .bss.* COMMON)
    _bss_end = .;
  } > dram_seg
}
