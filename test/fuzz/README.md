# Tier 1 Security Fuzzers (`test/fuzz/`)

## Targets

All 8 fuzzers implement `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and compile directly against first-party `toobloader/core/`, `recovery/`, and `sdk/libtoob/` C17 sources (never mocking out the parser under test):

| Target | Entry Source | Exercised Subsystems | Corpus Directory |
| --- | --- | --- | --- |
| `fuzz_tbm1` | `fuzz_tbm1.c` | `boot_tbm1.c`, `boot_verify.c` | `corpus/tbm1/` |
| `fuzz_tcc1` | `fuzz_tcc1.c` | `boot_cloud_cmd.c`, `boot_journal.c`, `boot_rstore.c` | `corpus/tcc1/` |
| `fuzz_kdm` | `fuzz_kdm.c` | `boot_cloud_cmd.c` KDM & quorum store | `corpus/kdm/` |
| `fuzz_wal_journal` | `fuzz_wal_journal.c` | `boot_journal.c` WAL & TMR sector scan/MAC | `corpus/wal_journal/` |
| `fuzz_cobs_mailbox` | `fuzz_cobs_mailbox.c` | `boot_cobs.c`, `boot_mailbox.c` RFC-1982 seq wrap | `corpus/cobs_mailbox/` |
| `fuzz_xmodem` | `fuzz_xmodem.c` | `recovery/main.c` XMODEM + `sdk/libtoob/toob_ota.c` | `corpus/xmodem/` |
| `fuzz_decomp_delta` | `fuzz_decomp_delta.c` | `boot_decomp.c`, `boot_delta.c`, `heatshrink_decoder.c` | `corpus/decomp_delta/` |
| `fuzz_multiimage` | `fuzz_multiimage.c` | `boot_multiimage.c`, `boot_verify.c` (`toob_image_header_t` + `TSIG`) | `corpus/multiimage/` |

## Seed Corpus

Regenerate deterministic valid + adversarial binary seeds into `test/fuzz/corpus/<target>/`:

```powershell
python test/fuzz/gen_seeds.py
```

## Building & Running

### Standalone Mode (Windows Clang ASan + UBSan / GCC / CI Smoke)

Compile with `-DTOOB_FUZZ_STANDALONE=1` (via `scripts/run_security_suite.ps1` or CMake):

```powershell
cmake -S test/fuzz -B D:/ToobStorage/tmp_build/w2sec/fuzz_build -G Ninja -DCMAKE_C_COMPILER=clang
cmake --build D:/ToobStorage/tmp_build/w2sec/fuzz_build
D:/ToobStorage/tmp_build/w2sec/fuzz_build/fuzz_tbm1.exe --iters=1024
```

### libFuzzer Mode (Linux / WSL / Windows LLVM)

```bash
cmake -S test/fuzz -B /tmp/toob_fuzz_lf -G Ninja -DCMAKE_C_COMPILER=clang -DTOOB_FUZZ_LIBFUZZER=ON
cmake --build /tmp/toob_fuzz_lf
/tmp/toob_fuzz_lf/fuzz_tbm1 test/fuzz/corpus/tbm1 -max_total_time=60
```
