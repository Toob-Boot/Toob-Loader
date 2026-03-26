#!/usr/bin/env python3
import json
import os
import subprocess
import sys

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    targets_json_path = os.path.join(script_dir, "targets.json")
    build_script_path = os.path.join(script_dir, "build_standalone.py")
    
    if not os.path.exists(targets_json_path):
        print(f"[ERROR] Could not find targets.json at {targets_json_path}")
        sys.exit(1)
        
    with open(targets_json_path, 'r') as f:
        targets_data = json.load(f)
        
    targets = [t for t in targets_data.get('targets', {}).keys() if not t.startswith('__')]
    
    variations = [
        {"name": "Dev", "flags": ["--dev"]},
        {"name": "Crypto", "flags": ["--encrypt", "0000000000000000000000000000000000000000000000000000000000000000"]}
    ]
    
    print(f"[*] Found {len(targets)} architectural targets: {', '.join(targets)}")
    print(f"[*] Starting universal multi-variant build matrix...")
    
    results = []
    has_failures = False
    
    for target in targets:
        for var in variations:
            print(f"\n============================================================")
            print(f"[*] Building {target} ({var['name']} Variant)")
            print(f"============================================================")
            
            # Clean first to ensure accurate build metrics without cache artifacts
            subprocess.run([sys.executable, build_script_path, "--chip", target, "--clean"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            cmd = [sys.executable, build_script_path, "--chip", target] + var['flags']
            
            # Run the build process, streaming output in real-time
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
            warnings = 0
            errors = 0
            
            for line in process.stdout:
                print(line, end="")
                line_lower = line.lower()
                # Basic diagnostic counting
                if "warning:" in line_lower:
                    warnings += 1
                if "error:" in line_lower:
                    errors += 1
                    
            process.wait()
            
            status = "PASS" if process.returncode == 0 else "FAIL"
            if status == "FAIL":
                has_failures = True
                
            # Determine size of the generated binary artifact
            project_dir = os.path.dirname(script_dir)
            build_dir = os.path.join(project_dir, "build", f"build_{target}")
            
            size = "N/A"
            if status == "PASS":
                if "--dev" in var['flags']:
                    bin_path = os.path.join(build_dir, "toobloader.bin")
                else:
                    bin_path = os.path.join(build_dir, "toobloader.bin.encrypted")
                
                if os.path.exists(bin_path):
                    size = f"{os.path.getsize(bin_path)} B"
            
            results.append({
                "target": target,
                "variant": var["name"],
                "status": status,
                "warnings": warnings,
                "errors": errors,
                "size": size
            })
            
    # Render Output Matrix
    print("\n\n" + "="*80)
    print(" " * 24 + "REPOWATT CI/CD BUILD MATRIX SUMMARY")
    print("="*80)
    print(f"{'Target':<15} | {'Variant':<10} | {'Status':<6} | {'Warnings':<8} | {'Errors':<6} | {'Size'}")
    print("-" * 80)
    
    for r in results:
        print(f"{r['target']:<15} | {r['variant']:<10} | {r['status']:<6} | {r['warnings']:<8} | {r['errors']:<6} | {r['size']}")
        
    print("="*80)
    
    if has_failures:
        print("\n[!] CI/CD Matrix failed. One or more builds exited with an error.")
        sys.exit(1)
    else:
        print("\n[*] CI/CD Matrix succeeded. All target architectures verified.")
        sys.exit(0)

if __name__ == "__main__":
    main()
