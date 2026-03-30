ENTRY(boot_startup_vector)

MEMORY
{
  iram_seg (RX) : ORIGIN = 0x40800000, LENGTH = 0x20000 /* 128KB Code (HP SRAM) */
  dram_seg (RW) : ORIGIN = 0x40820000, LENGTH = 0x10000 /* 64KB Data (HP SRAM) */
}

SECTIONS
{
  .iram.text :
  {
    . = ALIGN(4);
    _iram_start = .;
    KEEP(*(.entry.text))
    *(.text .text.*)
    *(.rodata .rodata.*)
    _iram_end = .;
  } > iram_seg

  .dram.data :
  {
    . = ALIGN(4);
    _data_start = .;
    *(.data .data.*)
    *(.sdata .sdata.*)
    _data_end = .;
  } > dram_seg

  .dram.bss (NOLOAD) :
  {
    . = ALIGN(4);
    _bss_start = .;
    *(.sbss .sbss.*)
    *(.bss .bss.* COMMON)
    _bss_end = .;
  } > dram_seg
}
