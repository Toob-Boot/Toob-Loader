#!/usr/bin/env python3
import os
import sys
import argparse
import tomllib

def main():
    parser = argparse.ArgumentParser(description="Toob-Boot Budget Check")
    parser.add_argument("--toml", required=True, help="Path to device.toml")
    parser.add_argument("--bin", required=True, help="Path to compiled .bin")
    parser.add_argument("--stage", required=True, choices=["stage0", "stage1"], help="Which stage to check")
    
    args = parser.parse_args()

    # Load TOML
    try:
        with open(args.toml, "rb") as f:
            toml_data = tomllib.load(f)
    except Exception as e:
        print(f"BUDGET CHECK ERROR: Could not read {args.toml}: {e}")
        sys.exit(1)

    # Get budget
    partitions = toml_data.get("partitions", {})
    if args.stage == "stage0":
        budget = partitions.get("stage0_size", 16384)
    else:
        budget = partitions.get("stage1_size", 28672)

    # Get file size
    try:
        actual_size = os.path.getsize(args.bin)
    except Exception as e:
        print(f"BUDGET CHECK ERROR: Could not read binary {args.bin}: {e}")
        sys.exit(1)

    if actual_size > budget:
        print(f"FATAL [BUDGET_EXCEEDED]: {args.stage} is {actual_size} bytes, which exceeds the budget of {budget} bytes!")
        sys.exit(1)
    
    print(f"BUDGET SUCCESS: {args.stage} ({actual_size} bytes) fits into budget ({budget} bytes).")

if __name__ == "__main__":
    main()
