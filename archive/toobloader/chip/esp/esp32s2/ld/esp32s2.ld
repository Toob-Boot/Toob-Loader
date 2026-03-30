ENTRY(boot_startup_vector)

MEMORY
{
  iram_seg (RX) : ORIGIN = 0x40020000, LENGTH = 128K
  dram_seg (RW) : ORIGIN = 0x3FFB0000, LENGTH = 64K
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
