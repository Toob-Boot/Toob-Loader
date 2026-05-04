import json
import argparse
import sys
import os

def ingest_fuzzer(scan_path, blueprint_path, out_path, chip_name):
    try:
        with open(scan_path, 'r') as f:
            scan_data = json.load(f)
        with open(blueprint_path, 'r') as f:
            fuzzer_blueprint = json.load(f)
    except Exception as e:
        print(f"Error reading input files: {e}")
        sys.exit(1)

    chip_data = fuzzer_blueprint.get(chip_name, {})
    
    # Read existing hardware.json to preserve manual registers if any
    existing_hardware = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, 'r') as f:
                existing_hardware = json.load(f)
        except Exception:
            pass

    # 1. Process Flash Regions from aggregated_scan.json
    sorted_keys = sorted([int(k) for k in scan_data.keys() if k.isdigit()])
    
    regions = []
    current_region = None
    
    total_flash_size = 0

    for k in sorted_keys:
        sector = scan_data[str(k)]
        base = sector["start_addr"]
        size = sector["size"]
        status = sector.get("run_ping", "skipped")
        total_flash_size += size
        
        rtype = "reserved" if status == "skipped" else "writable"
        
        if current_region is None:
            current_region = {"base": base, "size": size, "type": rtype, "sector_size": size, "count": 1}
        else:
            if current_region["type"] == rtype and current_region.get("sector_size") == size:
                current_region["size"] += size
                current_region["count"] += 1
            else:
                regions.append(current_region)
                current_region = {"base": base, "size": size, "type": rtype, "sector_size": size, "count": 1}

    if current_region:
        regions.append(current_region)
        
    final_regions = []
    for r in regions:
        out_r = {"base": r["base"], "type": r["type"]}
        if r["type"] == "reserved":
            out_r["size"] = r["size"]
            out_r["description"] = "Derived from scan: skipped"
        else:
            out_r["sector_size"] = r["sector_size"]
            out_r["count"] = r["count"]
        final_regions.append(out_r)
        
    # 2. Extract Data from blueprint
    flash_caps = chip_data.get("flash_capabilities", {})
    write_alignment = flash_caps.get("write_alignment_bytes", 32)
    app_alignment = flash_caps.get("app_alignment_bytes", 65536)
    
    boot_vectors = chip_data.get("boot_vectors", {})
    xip_base = boot_vectors.get("user_app_base", "0x0")
    
    crypto_caps = chip_data.get("crypto_capabilities", {})
    # Preserve arena size if already specified manually
    if "arena_size" in existing_hardware.get("crypto_capabilities", {}):
        crypto_caps["arena_size"] = existing_hardware["crypto_capabilities"]["arena_size"]
    else:
        crypto_caps["arena_size"] = 2048 # default
    
    wdt_registers = chip_data.get("watchdog_kill_registers", [])
    multi_core = chip_data.get("multi_core_topology", {})
    
    # 3. Assemble hardware.json
    hardware = {
        "chip_family": chip_name,
        "flash": {
            "size": total_flash_size,
            "write_alignment": write_alignment,
            "app_alignment": app_alignment,
            "xip_base": xip_base,
            "regions": final_regions
        },
        "crypto_capabilities": crypto_caps,
        "watchdogs": wdt_registers,
        "multi_core": multi_core,
        "registers": existing_hardware.get("registers", {
             "uart0_base": "0x60000000",
             "uart_sclk_freq": 40000000,
             "uart_tx_fifo_size": 128,
             "cpu_freq_hz": 160000000
        })
    }
    
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(hardware, f, indent=4)
    print(f"Successfully generated {out_path} from Fuzzer artifacts")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest ToobFuzzer3 artifacts into Toob-Loader hardware profile")
    parser.add_argument("--scan", required=True, help="Path to aggregated_scan.json")
    parser.add_argument("--blueprint", required=True, help="Path to fuzzer blueprint.json")
    parser.add_argument("--out", required=True, help="Path to output hardware.json")
    parser.add_argument("--chip", required=True, help="Target chip name (e.g., esp32-c6)")
    args = parser.parse_args()
    ingest_fuzzer(args.scan, args.blueprint, args.out, args.chip)
