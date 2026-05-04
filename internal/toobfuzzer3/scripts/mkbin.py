#!/usr/bin/env python3
import sys
import struct
import os

def align_to(n, align):
    return ((n + align - 1) // align) * align

def main():
    if len(sys.argv) not in (3, 4):
        print("Usage: mkbin.py <input.elf> <output.bin> [chip_name]")
        sys.exit(1)

    elf_path = sys.argv[1]
    bin_path = sys.argv[2]
    chip_name = sys.argv[3] if len(sys.argv) == 4 else "esp32"

    with open(elf_path, "rb") as f:
        elf_data = f.read()

    if len(elf_data) < 52 or elf_data[:4] != b'\x7fELF':
        print("[!] ERROR: Not a valid ELF file")
        sys.exit(1)

    # Read Elf32_Ehdr
    e_entry, e_phoff = struct.unpack_from("<II", elf_data, 0x18)
    e_phentsize, e_phnum = struct.unpack_from("<HH", elf_data, 0x2A)

    segments = []
    # Identify loadable segments
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from("<IIIIIIII", elf_data, offset)
        
        # PT_LOAD == 1
        if p_type == 1 and p_filesz > 0:
            segments.append({
                "vaddr": p_vaddr,
                "data": elf_data[p_offset : p_offset + p_filesz]
            })

    num_segments = len(segments)
    if num_segments > 16:
        print(f"[!] ERROR: Too many segments ({num_segments})")
        sys.exit(1)

    # Prepare Binary Image
    bin_data = bytearray()
    
    # Common Header: magic 0xE9, num_segments, flash_mode(2 = DIO), flash_size_freq(0x20 = 4MB, 40MHz)
    bin_data.extend(struct.pack("<BBBB", 0xE9, num_segments, 2, 0x20))
    # Entry Point (4 bytes)
    bin_data.extend(struct.pack("<I", e_entry))
    # Extended Header (16 bytes: 0xEE, ..., 0)
    CHIP_IDS = {
        "esp32": 0, "esp32s2": 2, "esp32c3": 5, "esp32s3": 9,
        "esp32c2": 12, "esp32c6": 13, "esp32h2": 16
    }
    chip_id = CHIP_IDS.get(chip_name.lower(), 0)
    
    extended_hdr = bytearray([0xEE] + [0]*14 + [0])
    struct.pack_into("<H", extended_hdr, 4, chip_id)
    bin_data.extend(extended_hdr)

    # Process Segments
    checksum = 0xEF
    for seg in segments:
        vaddr = seg["vaddr"]
        data = seg["data"]
        aligned_size = align_to(len(data), 4)
        
        # Write Segment Header
        bin_data.extend(struct.pack("<II", vaddr, aligned_size))
        
        # Write Segment Data
        bin_data.extend(data)
        
        # Pad up to 4-byte boundaries
        pad_len = aligned_size - len(data)
        if pad_len > 0:
            bin_data.extend(b'\x00' * pad_len)
            
        # Checksum calculation: XOR sum of the UNPADDED data
        for byte in data:
            checksum ^= byte

    # Checksum Padding
    # Pad to a 16 byte boundary minus 1 byte, then write the 1 byte checksum
    current_ofs = len(bin_data)
    aligned_ofs = align_to(current_ofs + 1, 16)
    pad_bytes = aligned_ofs - current_ofs - 1
    
    if pad_bytes > 0:
        bin_data.extend(b'\x00' * pad_bytes)
        
    bin_data.append(checksum & 0xFF)

    with open(bin_path, "wb") as f:
        f.write(bin_data)

    print(f"[*] mkbin.py: Generated {bin_path} with {num_segments} segments. Entry: 0x{e_entry:08X}, Checksum: 0x{checksum:02X}")

if __name__ == "__main__":
    main()
