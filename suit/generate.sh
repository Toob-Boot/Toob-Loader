#!/usr/bin/env bash
# Dummy-Script für M-BUILD Gap-Fix. 
# Dieses Script wird später vom Manifest-Compiler gefüllt.

OUTPUT_DIR=$1

if [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <output_dir>"
    exit 1
fi

echo "[SUIT-Stub] Generiere Dummy-C-Files in: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT_DIR/boot_suit.c"
touch "$OUTPUT_DIR/toob_telemetry_decode.c"
touch "$OUTPUT_DIR/chip_config.h"
touch "$OUTPUT_DIR/stage0_layout.ld"

echo "[SUIT-Stub] Finished."
