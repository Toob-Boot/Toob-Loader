import os
import sys
from cmsis_svd.parser import SVDParser


def calculate_write_mask(register):
    """
    Calculates a safe 32-bit mask of writable bits for a register.
    Returns 0 if the register is completely read-only.
    """
    # access rights can be inherited from peripheral, but let's check register level first
    access = getattr(register, "access", None)

    if access == "read-only":
        return 0x0

    # Use get_fields() if available to automatically unroll SVDFieldArray objects
    fields = (
        register.get_fields()
        if hasattr(register, "get_fields")
        else getattr(register, "fields", [])
    )

    # If no fields are defined, assume the whole register is writable if not read-only
    if not fields:
        if access in ["write-only", "read-write", "writeOnce"]:
            size = getattr(register, "size", 32)
            if size == 32:
                return 0xFFFFFFFF
            return (1 << size) - 1
        # if access is None, we might cautiously skip or assume RW.
        # For fuzzing, let's assume it's RW to be aggressive, but rely on Keelhaul methodology.
        return 0xFFFFFFFF

    mask = 0x0
    for field in fields:
        field_access = getattr(field, "access", access)
        if field_access in [
            "write-only",
            "read-write",
            "writeOnce",
            None,
        ]:  # if None, assume writable
            field_mask = ((1 << field.bit_width) - 1) << field.bit_offset
            mask |= field_mask

    return mask


def generate_keelhaul_header(svd_path, output_c_path, chip_name):
    print(f"[*] Parsing SVD File: {svd_path}")
    parser = SVDParser.for_xml_file(svd_path)
    device = parser.get_device()

    registers_out = []
    uarts = []
    wdts = []

    for peripheral in device.peripherals:
        base_addr = peripheral.base_address
        p_name = peripheral.name.upper()

        if "UART" in p_name or "USART" in p_name:
            uarts.append((peripheral.name, base_addr))
        if "WDT" in p_name or "WDG" in p_name or "WATCHDOG" in p_name:
            wdts.append((peripheral.name, base_addr))

        # get_registers() automatically flattens SVDRegisterArray into individual SVDRegister instances
        for register in peripheral.get_registers():
            reg_addr = base_addr + register.address_offset
            reset_val = getattr(register, "reset_value", 0)
            if reset_val is None:
                reset_val = 0

            write_mask = calculate_write_mask(register)
            if write_mask > 0:
                registers_out.append((reg_addr, reset_val, write_mask))

    print(f"[*] Extracted {len(registers_out)} writable MMIO registers.")

    with open(output_c_path, "w") as f:
        f.write("/* AUTO-GENERATED KEELHAUL SVD DICTIONARY */\n")
        f.write('#include "fz_types.h"\n\n')

        f.write("/* Memory-Optimized MMIO Table (Read-Only Fields Stripped) */\n")
        f.write(f"const keelhaul_reg_t keelhaul_svd_array[{len(registers_out)}] = {{\n")

        for reg in registers_out:
            f.write(f"    {{ 0x{reg[0]:08X}, 0x{reg[1]:08X}, 0x{reg[2]:08X} }},\n")

        f.write("};\n\n")
        f.write(f"const uint32_t keelhaul_svd_count = {len(registers_out)};\n\n")

        f.write("/* Auto-Extracted Peripheral Base Addresses */\n")
        f.write(
            f"const uint32_t keelhaul_uart_bases[] = {{ {', '.join(f'0x{u[1]:08X}' for u in uarts)} }};\n"
            if uarts
            else "const uint32_t keelhaul_uart_bases[] = { 0 };\n"
        )
        f.write(f"const uint32_t keelhaul_uart_count = {len(uarts)};\n\n")

        f.write(
            f"const uint32_t keelhaul_wdt_bases[] = {{ {', '.join(f'0x{w[1]:08X}' for w in wdts)} }};\n"
            if wdts
            else "const uint32_t keelhaul_wdt_bases[] = { 0 };\n"
        )
        f.write(f"const uint32_t keelhaul_wdt_count = {len(wdts)};\n")

    print(f"[+] Generation Complete: {output_c_path}")

    # --- SVD PAC GENERATION ---
    pac_path = os.path.join(os.path.dirname(output_c_path), "keelhaul_pac.h")
    with open(pac_path, "w") as f:
        f.write(f"/* Auto-Generated Peripheral Access Crate (PAC) for {chip_name} */\n")
        f.write("#pragma once\n#include <stdint.h>\n\n")

        tx_macro = None
        rx_macro = None

        # Build UART Structs
        for u in uarts:
            p_name = u[0]
            base_addr = u[1]
            periph = next((p for p in device.peripherals if p.name == p_name), None)
            if not periph:
                continue

            regs = sorted(periph.get_registers(), key=lambda r: r.address_offset)
            struct_name = f"pac_{p_name.lower()}_t"

            f.write(f"typedef struct {{\n")
            current_offset = 0
            tx_reg_name = None
            rx_reg_name = None

            for reg in regs:
                if reg.address_offset > current_offset:
                    pad = reg.address_offset - current_offset
                    f.write(f"    uint8_t reserved_{current_offset:X}[{pad}];\n")
                    current_offset += pad

                size_bytes = getattr(reg, "size", 32) // 8
                if size_bytes == 0:
                    size_bytes = 4
                f.write(f"    volatile uint{size_bytes*8}_t {reg.name};\n")
                current_offset += size_bytes

                # Heuristic for TX register
                rn = reg.name.upper()
                if not tx_reg_name and (
                    rn == "FIFO"
                    or rn == "TDR"
                    or rn == "TXD"
                    or rn == "DR"
                    or rn == "THR"
                    or rn == "DATA"
                ):
                    tx_reg_name = reg.name

                # Heuristic for RX register
                if not rx_reg_name and (
                    rn == "FIFO"
                    or rn == "RDR"
                    or rn == "RXD"
                    or rn == "DR"
                    or rn == "RBR"
                    or rn == "DATA"
                ):
                    rx_reg_name = reg.name

            f.write(f"}} {struct_name};\n\n")
            f.write(
                f"#define PAC_{p_name.upper()} (({struct_name}*) 0x{base_addr:08X})\n\n"
            )

            if tx_reg_name and not tx_macro:
                tx_macro = (
                    f"#define PAC_UART_TX_BYTE(dev, val) (dev->{tx_reg_name} = (val))\n"
                )
            if rx_reg_name and not rx_macro:
                rx_macro = f"#define PAC_UART_RX_BYTE(dev, val_ptr) (*(val_ptr) = dev->{rx_reg_name})\n"

        if tx_macro:
            f.write("/* Heuristic Universal UART Bridging Macro */\n")
            f.write(tx_macro)
            if rx_macro:
                f.write(rx_macro)
        else:
            f.write("/* WARNING: No suitable TX register found heuristically. */\n")
            f.write("// #define PAC_UART_TX_BYTE(dev, val) (dev->UNKNOWN = (val))\n")
            f.write(
                "// #define PAC_UART_RX_BYTE(dev, val_ptr) (*(val_ptr) = dev->UNKNOWN)\n"
            )

    print(f"[+] PAC Generation Complete: {pac_path}")

    cpu_name = "Unknown"

    # CMSIS-SVD drops non-ARM CPUs (like Xtensa or RISC-V) into `SVDCPUNameType.CUSTOM`.
    # To recover the real name, we parse the raw XML natively.
    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(svd_path)
        root = tree.getroot()
        cpu_node = root.find(".//cpu/name")
        if cpu_node is not None and cpu_node.text:
            cpu_name = cpu_node.text
    except Exception:
        pass

    # If the XML parser failed to locate it, try the device enum
    if cpu_name == "Unknown" and device.cpu:
        cpu_name = str(device.cpu.name)
    return {
        "name": device.name,
        "vendor": device.vendor,
        "cpu": cpu_name,
        "uart_count": len(uarts),
        "wdt_count": len(wdts),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate Keelhaul C Header from SVD")
    parser.add_argument("svd_file", help="Path to the .svd XML file")
    parser.add_argument("output_c", help="Path to the output .c file")
    parser.add_argument("--chip", default="unknown", help="Name of the target chip")

    args = parser.parse_args()
    generate_keelhaul_header(args.svd_file, args.output_c, args.chip)
