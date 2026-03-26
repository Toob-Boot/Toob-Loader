import argparse
import subprocess
import os
import sys
import json
import shutil

from toolchains import Toolchain, EspressifToolchain, GenericToolchain

# =============================================================================
# Helper Functions
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="Standalone Toobloader Builder")
    parser.add_argument("--chip", required=True, help="Target chip (e.g. esp32, stm32f4)")
    parser.add_argument("--clean", action="store_true", help="Clean the build directory before building")
    parser.add_argument("--flash", action="store_true", help="Automatically flash the bootloader after a successful build")
    parser.add_argument("--port", help="Serial port for flashing (e.g., COM3, /dev/ttyUSB0)")
    parser.add_argument("--dev", action="store_true", help="Enable Developer Mode: Mocks hardware eFuses and bypasses Ed25519 signature verification via GNU Linker wrap")
    parser.add_argument("--encrypt", metavar="KEY", help="Encrypt the generated binary using ChaCha20-256. Provide a 32-byte hex string or filepath to the FEK.")
    parser.add_argument("--rec-pin", type=int, help="Hardware GPIO Pin to use as the manual Recovery Trigger")
    parser.add_argument("--rec-level", type=int, default=0, help="Hardware active level for the Recovery Pin (0 or 1)")
    return parser.parse_args()

def load_config(script_dir: str, chip: str) -> tuple:
    targets_file = os.path.join(script_dir, "targets.json")
    if not os.path.exists(targets_file):
        print(f"[!] Target configuration file not found at {targets_file}")
        sys.exit(1)
        
    with open(targets_file, "r") as f:
        config = json.load(f)
        
    targets = config.get("targets", {})
    
    # 1. Exact Match
    if chip in targets:
        target_info = targets[chip]
        target_info["base_target"] = chip
        return config, target_info
        
    # 2. Alias Match
    for t_name, t_info in targets.items():
        if chip in t_info.get("aliases", []):
            print(f"[*] Auto-mapped alias '{chip}' to target architecture '{t_name}'")
            t_info["base_target"] = t_name
            return config, t_info
            
    # 3. Prefix Match
    for t_name, t_info in targets.items():
        if t_info.get("allow_prefix_match", False) and chip.startswith(t_name):
            print(f"[*] Auto-mapped specific chip '{chip}' to target architecture '{t_name}'")
            t_info["base_target"] = t_name
            return config, t_info
            
    print(f"[!] Unknown chip/architecture: {chip}. Please register it or its prefix in toobloader/scripts/targets.json.")
    sys.exit(1)

def validate_recovery_pin(args, target_info):
    if args.rec_pin is None:
        return
        
    rules = target_info.get("recovery_pin_rules")
    if not rules:
        print(f"[!] Target '{args.chip}' does not define recovery_pin_rules in targets.json.")
        sys.exit(1)
        
    if not rules.get("supported", False):
        print(f"[!] Target '{args.chip}' architecture does not support hardware recovery pins.")
        sys.exit(1)
        
    max_pin = rules.get("max_pin", 0)
    blacklist = rules.get("blacklist", [])
    
    if args.rec_pin < 0 or args.rec_pin > max_pin:
        print(f"[!] Invalid recovery pin {args.rec_pin}. Target '{args.chip}' only supports pins 0 to {max_pin}.")
        sys.exit(1)
        
    if args.rec_pin in blacklist:
        print(f"[!] Invalid recovery pin {args.rec_pin}. This pin is heavily restricted on '{args.chip}' (Blacklisted).")
        sys.exit(1)
        
    if args.rec_level not in [0, 1]:
        print(f"[!] Invalid recovery pin active level. Must be 0 or 1.")
        sys.exit(1)
        
    print(f"[*] Recovery Pin validated on GPIO {args.rec_pin} (Active: {args.rec_level})")

def get_toolchain_for_target(args, config, target_info) -> Toolchain:
    family = target_info.get("family", "")
    if family == "esp":
        return EspressifToolchain(target_info, args, config)
    else:
        return GenericToolchain(target_info, args, config)

def load_env_fallback():
    """Zero-dependency .env parser for secure CI/CD Key Injection."""
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            # Only set if not already in environment (e.g. from CI/CLI)
                            if k not in os.environ:
                                os.environ[k] = v.strip().strip('"').strip("'")
        except Exception as e:
            print(f"[!] Warning: Could not process .env file: {e}")

# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    args = parse_args()
    
    # 1. Load local .env (if present) for cross-platform Secrets Injection
    load_env_fallback()
    
    # 2. Key Injection Strategy (CLI Priority -> Environment Fallback)
    if not getattr(args, "encrypt", None):
        env_key = os.environ.get("TOOBLOADER_FEK")
        if env_key:
            setattr(args, "encrypt", env_key)
            print("[*] Security: Auto-Loaded Encryption Key from Environment (TOOBLOADER_FEK)")
            
    # 3. Dev Mode Test Key Auto-Injection
    if getattr(args, "dev", False) and not getattr(args, "encrypt", None):
        # This string must EXACTLY match the 32-byte dev_fek array hardcoded in `mocks/dev_keys.c`
        test_key = "42" * 32
        setattr(args, "encrypt", test_key)
        print("[*] Security: Dev Mode active. Auto-injecting test Encryption Key from mocks/dev_keys.c")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bootloader_dir = os.path.dirname(script_dir)
    build_dir = os.path.join(bootloader_dir, "build", f"build_{args.chip}")
    
    # Load and map configuration
    config, target_info = load_config(script_dir, args.chip)
    validate_recovery_pin(args, target_info)
    
    # Environment Setup
    if args.clean and os.path.exists(build_dir):
        print(f"[*] Cleaning build directory: {build_dir}")
        shutil.rmtree(build_dir, ignore_errors=True)
    os.makedirs(build_dir, exist_ok=True)
    
    # Initialize targeted Toolchain handler
    toolchain = get_toolchain_for_target(args, config, target_info)
    
    # Execute Toolchain Pipeline
    toolchain.configure(bootloader_dir, build_dir)
    toolchain.build(build_dir)
    
    if getattr(args, "encrypt", None):
        import glob
        bin_files = glob.glob(os.path.join(build_dir, f"*{toolchain.binary_extension}"))
        bin_files = [b for b in bin_files if not b.endswith(".encrypted")]
        
        if not bin_files:
            print(f"[!] Warning: No {toolchain.binary_extension} file found to encrypt in {build_dir}")
        else:
            target_bin = bin_files[0]
            enc_bin = target_bin + ".encrypted"
            crypt_script = os.path.join(script_dir, "toobcrypt.py")
            cmd = [
                sys.executable, crypt_script,
                "--in-file", target_bin,
                "--out-file", enc_bin,
                "--key", args.encrypt
            ]
            print(f"[*] Post-Build: Encrypting payload with toobcrypt.py...")
            if subprocess.call(cmd) != 0:
                print("[!] Encryption script failed.")
                sys.exit(1)
    
    print("\n" + "="*60)
    print(f"[*] SUCCESS: Standalone Toobloader Built for {args.chip}!")
    toolchain.flash(build_dir)
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
