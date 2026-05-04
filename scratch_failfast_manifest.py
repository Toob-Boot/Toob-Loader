import os
import re

sh_file = r'c:\Users\Robin\Desktop\Toob-Loader\cli\suit\generate.sh'

with open(sh_file, 'r', encoding='utf-8') as f:
    sh_code = f.read()

start_marker = 'inject_hardware_mocks() {'
new_block = """MANIFEST_CLI="$PROJECT_ROOT/cli/manifest_compiler/toob_manifest.py"

if [ -f "$MANIFEST_CLI" ]; then
    echo "[SUIT CodeGen] Executing Manifest-Compiler..."
    if ! python "$MANIFEST_CLI" --toml "$DEVICE_MANIFEST" --hardware "$PROJECT_ROOT/bootloader/hal/chips/$TOOB_CHIP/hardware.json" --outdir "$OUTPUT_DIR"; then
        echo "[SUIT CodeGen] FATAL ERROR: Manifest-Compiler crashed or failed!"
        exit 1
    fi
    # Delete the old empty mock requirement since we removed it from CMake
else
    echo "[SUIT CodeGen] FATAL ERROR: manifest_compiler not deployed. Cannot continue!"
    exit 1
fi

echo "[SUIT CodeGen] Complete."
"""

if start_marker in sh_code:
    pre = sh_code.split(start_marker)[0]
    
    new_sh = pre + new_block
    with open(sh_file, 'w', encoding='utf-8') as f:
        f.write(new_sh)
    print("generate.sh successfully updated for manifest Fail-Fast!")
else:
    print("Marker not found in generate.sh!")
