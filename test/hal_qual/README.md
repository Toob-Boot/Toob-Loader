# Tier 3C HAL Security Qualification Suite (`test/hal_qual/`)

Vendor-agnostic C17 HAL qualification suite exporting `int toob_hal_qualify(const boot_platform_t *plat)` (and `toob_hal_qualify_with_report(...)`).

## Qualification Modules

- `qual_crypto.c`: RFC 8032 Ed25519 KATs (TV1, TV2, TV3) + 1-bit flip rejection on message, public key, and signature; FIPS 180-4 SHA-256 KATs (`""`, `"abc"`, multi-block 2-block `"abcdbcdecdefdef..."`); crypto scratch arena canary guard verification; repeated verify cycle timing sanity check.
- `qual_entropy.c`: NIST SP 800-90B Repetition Count Test (RCT) and Adaptive Proportion Test (APT); constant `0x00` / `0xFF` / repeating stride rejection; fail-closed negative error propagation checks.
- `qual_flash.c`: Bounds validation, `uint32_t` wraparound (`0xFFFFFFF0 + 0x20`) rejection, unaligned address/length checks, NOR erase-before-write (AND-mask semantics), and readback verification.
- `qual_keystore_soc.c`: Domain-separated HUK `read_device_secret` determinism, `read_pqc_pubkey_hash` length/stability checks, OTP active-key index monotonicity + blank-tail invariant, `lockdown_before_handoff` idempotence/enforcement, WDT kick, and monotonic counter advance error propagation.

## Running Host Selftest

`hal_qual_main.c` provides both the library qualification entry point (`-DTOOB_HAL_QUAL_LIBRARY_ONLY` if integrating into firmware) and a standalone host reference HAL + negative fault-injection selftest:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_security_suite.ps1 -Quick
```
