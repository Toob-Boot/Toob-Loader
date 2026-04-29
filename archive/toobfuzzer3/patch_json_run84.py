import json
import os

path = r"C:\Users\Robin\Desktop\Toob-Loader\toobfuzzer3\blueprints\esp32\run_84\aggregated_scan.json"
with open(path, "r") as f:
    d = json.load(f)

md = {
    "ram_fuzzed_boundaries": [
        "0x400A0000",
        "0x3FFE0000"
    ],
    "scan_total_bytes": 0x3C0000
}

new_d = {"metadata": md}

for k, v in d.items():
    if k == "metadata":
        continue
    
    start_addr = int(k)
    size = v.get("size", 4096)
    
    v["start_addr"] = start_addr
    v["end_addr"] = start_addr + size - 1
    v["start_hex"] = hex(start_addr)
    v["end_hex"] = hex(v["end_addr"])
    
    if "verification_method" not in v:
        v["verification_method"] = "Physical Fuzzing (Bare-Metal)"
        
    if "fallback" not in v:
        v["fallback"] = False
        
    new_d[k] = v

with open(path, "w") as f:
    json.dump(new_d, f, indent=4)

print("JSON Patched.")
