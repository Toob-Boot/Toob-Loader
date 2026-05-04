#!/usr/bin/env bash
# ==============================================================================
# Toob-Boot Code Generator Bridge (ZCBOR + Manifest Compiler)
# ==============================================================================
# Verhindert CI Pipeline-Abbrüche durch intelligentes Fallback-Mocking.
# 
# P10 Constraint & Review Integration:
# 1. ZCBOR-Fallback erzwingt stabile Memory-Constraints (C-Stubs) anstatt CMake crashen zu lassen.
# 2. Windows-PE Linker erstickt an leeren Layout Skripten -> Safe SECTIONS Mock.
# 3. Unit-Test False Positives -> Mocks garantieren 'return false'.
# 4. Sandbox Memory Safety -> Hardware-Pointers als Safe 'extern', ODR-Resolution via .c
# ==============================================================================

set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <output_dir> <device_manifest_path> <toob_chip>"
    exit 1
fi

OUTPUT_DIR=$1
DEVICE_MANIFEST=$2
TOOB_CHIP=$3

PROJECT_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUTPUT_DIR"

echo "[SUIT CodeGen] Generating C artifacts in: $OUTPUT_DIR"

# ------------------------------------------------------------------------------
# 1. ZCBOR CODE GENERATION (CDDL -> C-Logic)
# ------------------------------------------------------------------------------
if command -v zcbor >/dev/null 2>&1; then
    echo "[SUIT CodeGen] zcbor CLI found. Generating strict parsers..."
    zcbor code -c "$PROJECT_ROOT/cli/suit/toob_suit.cddl" --decode -t toob_suit --output-c "$OUTPUT_DIR/boot_suit.c" --output-h "$OUTPUT_DIR/boot_suit.h"
    zcbor code -c "$PROJECT_ROOT/cli/suit/toob_telemetry.cddl" --decode -t toob_telemetry --output-c "$OUTPUT_DIR/toob_telemetry_decode.c" --output-h "$OUTPUT_DIR/toob_telemetry_decode.h"
    zcbor code -c "$PROJECT_ROOT/cli/suit/toob_telemetry.cddl" --encode -t toob_telemetry --output-c "$OUTPUT_DIR/toob_telemetry_encode.c" --output-h "$OUTPUT_DIR/toob_telemetry_encode.h"
elif [ -f "$OUTPUT_DIR/boot_suit.h" ] && ! grep -q "BOOT_SUIT_MOCK_H" "$OUTPUT_DIR/boot_suit.h"; then
    echo "[SUIT CodeGen] zcbor not found, but real outputs exist. Preserving them! (Idempotence Guard)"
else
    echo "[SUIT CodeGen] FATAL ERROR: Valid Python zcbor CLI not found!"
    echo "Please ensure zcbor is installed ('pip install zcbor') and available in your PATH."
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. CHIP CONFIG && MANIFEST COMPILER GENERATION
# ------------------------------------------------------------------------------

MANIFEST_CLI="$PROJECT_ROOT/cli/manifest_compiler/toob_manifest.py"

if [ -f "$MANIFEST_CLI" ]; then
    echo "[SUIT CodeGen] Executing Manifest-Compiler..."
    if ! python "$MANIFEST_CLI" --toml "$DEVICE_MANIFEST" --hardware "$PROJECT_ROOT/toobloader/hal/chips/$TOOB_CHIP/hardware.json" --outdir "$OUTPUT_DIR"; then
        echo "[SUIT CodeGen] FATAL ERROR: Manifest-Compiler crashed or failed!"
        exit 1
    fi
    # Delete the old empty mock requirement since we removed it from CMake
else
    echo "[SUIT CodeGen] FATAL ERROR: manifest_compiler not deployed. Cannot continue!"
    exit 1
fi

echo "[SUIT CodeGen] Complete."
