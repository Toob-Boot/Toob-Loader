# Tier 2 FIH Emulation & Negative Security E2E (`test/fih_emu/`)

## Components

1. **`fih_fault_campaign.py`**:
   - Uses `arm-none-eabi-nm` and `arm-none-eabi-objdump` to inspect compiled nRF52840 ELFs (`toob_stage0` and `toob_stage1`), extracting target compare/branch PCs, Thumb instruction widths (`2` / `4` bytes), and `BOOT_GLITCH_DELAY()` (`bf00 bf00 bf00`) DSLC/verification gates inside `stage0_verify_signature`, `stage0_try_boot_bank*`, `boot_state_run`, `boot_verify_manifest_envelope`, and `enforce_dslc_lifecycle`.
   - `--dry-run` (used by `scripts/run_security_suite.ps1 -Quick`): validates ELF symbol/PC discovery, compiles & signs `probe_app_fault_test`, builds & runs `neg_e2e_vectors` under Clang ASan+UBSan, and checks `sram_handover_audit.resc` syntax/placeholders.
   - `--full` (used by `scripts/run_security_suite.ps1 -Full`): runs headless Renode 1.17.0 on `nrf52840_toob.repl` + `Nrf52840SocOverlay.cs` to execute:
     - **Factory UART COBS provisioning baseline** (stored in `D:\ToobStorage\tmp_build\w2sec\fih_emu\`).
     - **SRAM Handover Secret Audit** via `sram_handover_audit.resc`: captures full 256 KB SRAM `[0x20000000..0x20040000)` at `jump_to_vtor_image` and verifies `crypto_arena`, `journal_key`, `journal_key_valid`, and `"toob-journal-key-v2"` domain markers are wiped (`0x00`).
     - **`probe_app_fault_test`**: boots the signed bare-metal Cortex-M4 probe app in Renode, attempts NVMC `ERASEPAGE` + `WEN` overwrites against Stage 0 (`0x00001000`), tests `BPROT->CONFIG0` sticky lock resistance, audits `MPU` & UICR/Stage-0 visibility, and checks `sysbus.powerBprot BlockedOperations`.
     - **Live Renode Negative Security E2E**: blank 0xFF UICR, deployed `DSLC=0x01` blank WAL, unsigned App image, 1-bit tampered `TSIG` rollback image, and tampered Stage 1A image.
     - **Machine-Code FIH Fault Injection Campaign**: single-instruction skips (`PC += width`), double-instruction skips, and `R0..R3` register flips (`R0 = 0x55AA55AA`, `R0 ^= 1`, `R1..R3` perturbations) against tampered Stage 1A (Stage 0 FIH) and tampered App Slot 0 (Stage 1 FIH), asserting `boot_panic` / `dead_halt` / fail-closed rejection with zero unauthorized `[APP] BOOT` or `[S0] Signature verification PASSED!`.

2. **`sram_handover_audit.resc`**:
   - Parameterized Renode Monitor script hooking `$HANDOFF_PC` (`jump_to_vtor_image`) to dump SRAM before guest `.bss` zero-initialization runs.

3. **`probe_app_fault_test/`**:
   - Minimal Cortex-M4 guest firmware (`probe_main.c`, `probe_nrf52840.ld`, `build_probe.ps1`) compiled with `arm-none-eabi-gcc` and signed via `toob.exe sign image --entry 0x100 --mock`.

4. **`neg_e2e_vectors.c` & `negative_e2e_vectors.json`**:
   - Host C17 verification suite compiled directly against `toobloader/core/` (`-DTOOB_PQC_ENABLED=1 -DTOOB_TA1_STRICT_NO_CRC_SKIP=1`) covering TA-1 zero-wear bypass, deployed blank WAL, KDM floor replay, PQC pubkey SHA-256 pinning hash mismatch, and unsigned/tampered TSIG/revoked-key rollback.

## CI/CD & Unified Runner Integration

```powershell
# Quick smoke (Tier 1 fuzzers + Tier 2 ELF/script/C negative vectors + Tier 3C HAL qual)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_security_suite.ps1 -Quick

# Full suite (adds Renode 1.17.0 headless FIH, SRAM audit, BPROT probe, and live negative E2E)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_security_suite.ps1 -Full
```
