# Toob-Loader Core MISRA C:2023, CERT C & Glitch-Hardening (FIH) Profile

This specification defines the mandatory coding, static-analysis, and Fault-Injection-Hardening (FIH) rules enforced across Toob-Loader's immutable Root-of-Trust (`toobloader/stage0/`), Stage-1 Core (`toobloader/core/`), and shared wire contracts (`common/include/`).

Verification is automated via:
1. [`.clang-format`](../.clang-format) — LLVM 2-space C17 style + mandatory compound braces (*MISRA C:2023 Rule 15.6*).
2. [`.clang-tidy`](../.clang-tidy) — MISRA C:2023 Mandatory/Required subset + SEI CERT C checks (`WarningsAsErrors: '*'`).
3. [`scripts/check_core_safety_and_fih.ps1`](../scripts/check_core_safety_and_fih.ps1) — Executes `clang-tidy`, MMIO HAL isolation, and Toob-specific Glitch/FIH & Flash-Firewall rules (`TOOB-FIH-01` .. `TOOB-FW-05`).
4. [`scripts/run_cbmc_proofs.ps1`](../scripts/run_cbmc_proofs.ps1) & [`scripts/run_rocq_proofs.ps1`](../scripts/run_rocq_proofs.ps1) — Mathematical proof of runtime-error freedom (*MISRA C:2023 Dir 4.1*) and non-brickability state invariants.

---

## 1. Enforced MISRA C:2023 & CERT C Core Rules

| Standard / Rule | Enforcement Mechanism | Security / Safety Rationale |
| :--- | :--- | :--- |
| **MISRA Dir 4.1** *(Run-time error freedom)* | CBMC (`--bounds-check`, `--pointer-check`, `--signed-overflow-check`, `--unsigned-overflow-check`, `--div-by-zero-check`) | Proves absence of buffer overflows, null dereferences, arithmetic wraparound, and division by zero. |
| **MISRA Dir 4.7 / Rule 17.7** *(Error return checking)* | `bugprone-unused-return-value` + `cert-err33-c` | Prevents silent continuation on flash, keystore, or crypto HAL failures. |
| **MISRA Dir 4.12 / Rule 21.3** *(No dynamic allocation)* | Compile-time poisoning (`malloc=MALLOC_FORBIDDEN` in `CMakeLists.txt`) | Guarantees deterministic O(1) static memory usage and zero heap fragmentation. |
| **MISRA Rule 8.7** *(Internal linkage `static`)* | `misc-use-internal-linkage` + `-Wmissing-prototypes` | Prevents unintended global symbol exposure across translation units. |
| **MISRA Rules 10.1–10.8** *(Essential type conversions)* | `-Wconversion -Werror` + `bugprone-narrowing-conversions` + `bugprone-signed-char-misuse` + `bugprone-implicit-widening-of-multiplication-result` | Eliminates signed/unsigned promotion traps across 32-bit MCU and 64-bit Host-SIL targets. |
| **MISRA Rules 13.3 / 13.4 / 13.6** *(Side-effect free conditions & `sizeof`)* | `bugprone-inc-dec-in-conditions`, `bugprone-assignment-in-if-condition`, `bugprone-sizeof-expression` | Ensures deterministic evaluation order and side-effect-free assertions/sizes. |
| **MISRA Rule 14.3 / 14.4** *(Invariant & boolean conditions)* | `misc-redundant-expression`, `bugprone-redundant-branch-condition`, `bugprone-bool-pointer-implicit-conversion` | Catches dead security gates and implicit integer/pointer boolean coercions. |
| **MISRA Rule 15.6** *(Compound `{ ... }` statements)* | `readability-braces-around-statements` + `.clang-format` `InsertBraces: true` | Eliminates dangling-else and single-line macro expansion bugs. |
| **MISRA Rule 16.4** *(Mandatory `default:` in `switch`)* | `bugprone-switch-missing-default-case` | Ensures fail-closed rejection when voltage/EMFI glitches corrupt an enum register into an out-of-range value. |
| **MISRA Rule 17.2** *(No recursion)* | `misc-no-recursion` + CBMC `--unwinding-assertions` | Guarantees statically bounded call-stack depth across all execution paths. |
| **MISRA Rule 18.8** *(No VLAs)* | `-Wvla` / static arena sizing | Prevents attacker-controlled stack pointer displacement. |
| **MISRA Rules 21.1 / 21.2 / CERT DCL37-C** *(No reserved identifiers)* | `bugprone-reserved-identifier` + `cert-dcl37-c` | Prohibits file-scope `_foo` or `__foo` identifiers reserved by the C17 implementation (except ABI-mandated SSP/CRT hooks). |
| **CERT EXP42-C** *(No `memcmp` on padded structs)* | `bugprone-suspicious-memory-comparison` + `TOOB-FIH-01` | Prevents false mismatches and stack-byte side channels on padded structures. |

---

## 2. Documented Architectural Deviations (`DEV-01` .. `DEV-04`)

Third-party cryptographic/compression sources (`monocypher`, `heatshrink`) are excluded from stylistic/lint refactoring to preserve upstream constant-time verification. Within first-party `stage0/` and `core/` code, exactly **four** deliberate deviations apply:

1. **`DEV-01` — MISRA Rule 15.5 (*Advisory: Single point of exit*):**
   - **Decision:** Early fail-closed guard returns (`if (err) { zeroize(); return BOOT_ERR_...; }`) are **permitted and preferred** (aligned with SEI CERT C).
   - **Rationale:** Deeply nested single-return pyramids obscure security preconditions and increase the surface where a single skipped branch reaches commit logic. Functions holding stack secrets must zeroize before every return or route through a single zeroizing `cleanup:` block.
2. **`DEV-02` — MISRA Rules 11.3 / 11.4 / 11.5 & Rule 19.2 (*Aligned arena/MMIO pointer casts & unions*):**
   - **Decision:** Controlled pointer casts on 8-byte-aligned `crypto_arena` sub-slices, linker section symbols (`_sdata`, `_ebss`, `.noinit`), and phase-disjoint unions (guarded by `_Static_assert` alignment/size checks) are **permitted**.
   - **Rationale:** Zero-allocation bare-metal bootloaders require deterministic static buffer reuse without heap allocators. Wire parsing (`TDR1`, `TCI1`, `TCC1`) uses explicit little-endian byte readers/writers rather than unaligned struct casts.
3. **`DEV-03` — MISRA Dir 4.9 / Rule 20.7 (*Security/FIH control-flow macros*):**
   - **Decision:** `BOOT_SECURE_REQUIRE(cond, fail_action)` and `TOOB_DOUBLE_VERIFY(...)` in `boot_fih.h` **must remain function-like macros** whose `fail_action` statement block is deliberately unparenthesized.
   - **Rationale:** Converting `BOOT_SECURE_REQUIRE` into a `bool`-returning helper would introduce a single-register return bottleneck vulnerable to single-instruction skip / register fault injection.
4. **`DEV-04` — MISRA Dir 4.3 / Rule 1.2 (*Encapsulated inline assembly & freestanding attributes*):**
   - **Decision:** Architecture startup (`_stage0_start`), payload handoff (`jump_to_payload`), compiler/glitch barriers (`BOOT_GLITCH_DELAY`), and section/alignment attributes (`TOOB_NOINIT_VAR`, `aligned(8)`, `naked`, `noreturn`) are **permitted** within dedicated headers and freestanding entry points.

---

## 3. Toob-Specific Glitch-Hardening & Firewall Rules (`TOOB-FIH-01` .. `TOOB-FW-05`)

Enforced automatically by [`scripts/check_core_safety_and_fih.ps1`](../scripts/check_core_safety_and_fih.ps1) across `toobloader/stage0/` and `toobloader/core/`:

- **`TOOB-FIH-01` (Ban Raw `memcmp` in Core & Stage 0):**
  Standard `memcmp()` short-circuits on the first differing byte (timing side channel + single-branch exit). All digest, signature, pubkey, token, UID, and flash read-back comparisons must use `constant_time_memcmp_glitch_safe()`.
- **`TOOB-FIH-02` (Ban Optimizable `memset(..., 0, ...)` on Secret Buffers):**
  Zeroing keys, digests, signatures, nonces, tokens, handoff structs, or `crypto_arena` via `memset(..., 0, ...)` violates CERT C `MSC06-C` (compiler Dead-Store Elimination). `boot_secure_zeroize()` is mandatory.
- **`TOOB-FIH-03` (Mandatory Glitch Barrier Inside Terminal Halt Loops):**
  Every infinite trap loop (`while (1)` / `while (true)` / `for (;;)`) in production `stage0/` and `core/` code must invoke `BOOT_GLITCH_DELAY()` (or delegate to `dead_halt()` / `boot_terminal_halt()` / `boot_panic()`).
- **`TOOB-FIH-04` (No Discarded Critical Security Verifiers):**
  Calls to `verify_signature`, `stage0_verify_signature`, `boot_verify_manifest_envelope`, `boot_verify_slot_image`, `boot_merkle_verify_stream`, `boot_rollback_verify_svn`, `boot_proof_verify`, `boot_random_safe`, `boot_journal_update_tmr`, and `read_dslc` must never silently ignore failures or cast errors away to bypass fail-closed gating. Stage 0 `stage0_verify_signature` returns canonical `boot_status_t` (`BOOT_OK` / `BOOT_ERR_VERIFY`), and verdict flags (`auth_verdict`, `entry_valid`) use pessimistic default initialization (`BOOT_ERR_VERIFY` / `false`) prior to `BOOT_SECURE_REQUIRE`.
- **`TOOB-FW-05` (Stage-0 Immutable-Boot Flash Firewall & MMIO Isolation):**
  Direct `flash->write(...)` and `flash->erase_sector(...)` calls inside `toobloader/core/` outside `boot_flash_guard.h` / `boot_ct_utils.c` are forbidden — all writes and erases must pass through `boot_flash_write_guarded()` / `boot_flash_erase_sector_guarded()`, and zero direct `(volatile uint32_t *)0x...` MMIO casts may appear in `stage0/` or `core/`.
- **Production Profile Hard-Blocks & ABI Invariants:**
  `TOOB_PROFILE_PRODUCTION` triggers compile-time `#error` rejection if `TOOB_ALLOW_UNSIGNED_APP_BOOT`, `TOOB_ALLOW_DEV_BYPASS`, `TOOB_STAGE0_VERIFY_MODE_HASH_ONLY`, or `TOOB_TA1_STRICT_NO_CRC_SKIP == 0` is enabled. Append-only HAL V3 extensions (`read_device_secret`, `read_pqc_pubkey_hash` on `keystore_hal_t`) and `toob_img_sig_trailer_t` (72 bytes) are enforced via `_Static_assert` ABI size/offset checks.
