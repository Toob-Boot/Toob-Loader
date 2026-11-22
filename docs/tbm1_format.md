# TBM1 — Toob Boot Manifest Format v2

## Purpose

TBM1 v2 replaces the previous fixed-format v1 manifest to enhance usability, flash-friendliness, extensibility, and diagnostics. It maintains the core design goal: **the boot path does not parse grammars**, keeping the reader within ~35 lines of constant-offset bounds-checked reads, while solving layout growth issues without future breaking updates.

## Wire Format Overview

All integers are **little-endian**. All offsets are relative to the TBM1 start.

Layout in staging area:
```
+-------------------------------------------------------------+
| Fixed Header (512 Bytes)                                   |
|   - Magic, Version, Lengths                                 |
|   - HW Compatibility, Revisions, Telemetry                  |
|   - SBOM Digest (32 Bytes)                                  |
|   - Region Directory (8 Slots, 96 Bytes)                    |
|   - Image Descriptors (4 Slots, 176 Bytes)                  |
|   - Reserved Tail (148 Bytes)                               |
|   - Fixed CRC32 Pre-Check (4 Bytes)                         |
+-------------------------------------------------------------+
| Variable-length Regions                                     |
|   - Chunk Hashes                                            |
|   - PQC Signature & Public Key                              |
|   - Device Binding ID                                       |
+-------------------------------------------------------------+
| Ed25519 Signature (Last 64 Bytes)                           |
+-------------------------------------------------------------+
```

---

## 1. Fixed Header (512 Bytes)

> **Naming**: "TBM1" is the format family name, not the version number.
> The schema version within the TBM1 family is `version_major` (currently 2).

> **Hard Limits**: `TBM1_MAX_IMAGES` (4) and `TBM1_MAX_REGIONS` (8) are fixed
> arrays at fixed offsets. Exceeding either limit requires a new major version
> with a new reader — `_reserved_tail` cannot extend them.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `0x314D4254` (`'TBM1'` LE — mnemonic: "TBM1 Manifest") |
| 4 | 1 | `version_major` | Breaking changes bump. Rejects if != 2 |
| 5 | 1 | `version_minor` | Additive changes bump. Ignored if not understood |
| 6 | 2 | `fixed_len` | Must be exactly 512 bytes (verifies page alignment) |
| 8 | 4 | `total_len` | Entire manifest size (fixed + variable + signature) |
| 12 | 2 | `flags_critical` | Must-understand bitmask. Unknown bit -> reject |
| 14 | 2 | `flags_info` | May-ignore bitmask. Unknown bit -> safe |
| 16 | 2 | `vendor_id` | Manufacturer identifier |
| 18 | 2 | `product_id` | Product family identifier |
| 20 | 2 | `hw_rev_min` | Minimum compatible hardware revision |
| 22 | 2 | `hw_rev_max` | Maximum compatible hardware revision |
| 24 | 1 | `key_index` | eFuse public key index slot (0-255) |
| 25 | 1 | `image_count` | Number of active image descriptors (1-4) |
| 26 | 2 | `boot_retry_limit` | Max WAL failure error counter (ex-max_resume) |
| 28 | 2 | `min_reader_major` | Rejects if bootloader major is less than this |
| 30 | 2 | `min_reader_minor` | Rejects if major matches but minor is less than this |
| 32 | 4 | `svn` | Application Security Version Number |
| 36 | 4 | `stage1_svn` | P7a Stage-1 anti-rollback SVN (0 = n/a) |
| 40 | 4 | `key_epoch` | eFuse key revocation epoch |
| 44 | 4 | `build_number` | CI build number for version telemetries |
| 48 | 2 | `fw_ver_major` | Firmware semantic version major |
| 50 | 2 | `fw_ver_minor` | Firmware semantic version minor |
| 52 | 2 | `fw_ver_patch` | Firmware semantic version patch |
| 54 | 2 | `_rsvd0` | Alignment padding (Encoder: must be 0. Reader: tolerate non-zero) |
| 56 | 32 | `sbom_digest` | SHA-256 digest of the EU-CRA SBOM |
| 88 | 96 | `regions[8]` | Region Directory (8 slots × 12 bytes each) |
| 184 | 176 | `images[4]` | Image descriptors (4 slots × 44 bytes each) |
| 360 | 148 | `_reserved_tail` | Additive growth for future minor versions (Encoder: must zero unused. Reader: tolerate non-zero) |
| 508 | 4 | `fixed_crc32` | Fast CRC32 pre-check over bytes `[0..508)` |

---

## 2. Region Directory

Instead of scattered offset/length fields, v2 uses a unified **Region Directory**. The reader iterates over a single loop to parse and bounds-check all variable regions:

```c
typedef struct __attribute__((packed)) {
  uint16_t region_id;   /* ID of the region, 0 = empty slot */
  uint16_t _rsvd;       /* Must be 0 */
  uint32_t off;         /* Relative to TBM1 start */
  uint32_t len;         /* Byte length of the region */
} tbm1_region_t;
```

### Standard Region IDs:
* `1`: `REGION_CHUNK_HASHES` — Merkle tree chunk hash list
* `2`: `REGION_PQC_SIGNATURE` — Post-quantum hybrid signature
* `3`: `REGION_PQC_PUBKEY` — Post-quantum hybrid public key
* `4`: `REGION_DEVICE_BIND` — 32-byte device-ID binding (DSLC)
* `5`: `REGION_DELTA_SCRIPT` — Delta patch instructions
* `6`: `REGION_REVERSE_DELTA` — Reverse-delta descriptor (`tbm1_rdelta_desc_t`, 48 bytes) and patch stream
* `7..127`: Reserved for standard updates
* `128..255`: Vendor-specific extensions

### Reverse-Delta Descriptor (Region 6, 48 Bytes):
```c
typedef struct __attribute__((packed)) {
  uint8_t  target_slot;          /* Target slot ID (TBM1_SLOT_APP = 0) */
  uint8_t  delta_alg;            /* Delta algorithm (TBM1_DELTA_TDS1 = 3) */
  uint16_t _rsvd;                /* Must be 0 */
  uint32_t data_off;             /* Offset of reverse-delta stream in staging */
  uint32_t stored_size;          /* Stored byte length of delta stream */
  uint32_t restored_size;        /* Exact byte length of restored baseline I_old */
  uint8_t  restored_sha256[32];  /* Expected SHA-256 of restored I_old */
} tbm1_rdelta_desc_t;
```

---

## 3. Image Descriptor (44 Bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0 | 1 | `image_type` | Component category (0..127 standard, 128..255 vendor) |
| +1 | 1 | `target_slot` | Target slot: 0=App, 1=NetCore, 2=Recovery, 3=Stage1 |
| +2 | 1 | `compression_alg` | Compression enum: 0=None, 1=Heatshrink, 2=LZ4 |
| +3 | 1 | `delta_alg` | Delta enum: 0=None, 1=BSDiff, 2=Detools, 3=TDS1 |
| +4 | 4 | `data_off` | Offset of image bytes in staging slot (strictly ascending, non-overlapping) |
| +8 | 4 | `stored_size` | Staging size of image (compressed or delta size) |
| +12 | 4 | `installed_size` | Final size of image after decompression/patching |
| +16 | 4 | `chunk_size` | Block size for streaming Merkle tree checks |
| +20 | 4 | `num_chunks` | ceil(installed_size / chunk_size) |
| +24 | 4 | `base_svn` | Delta: version SVN this delta patch expects |
| +28 | 2 | `ver_major` | Image major version |
| +30 | 2 | `ver_minor` | Image minor version |
| +32 | 2 | `ver_patch` | Image patch version |
| +34 | 2 | `_rsvd` | Must be 0 |
| +36 | 8 | `base_fingerprint` | Delta: 8-byte truncated SHA-256 of expected base image |

---

## 4. Trailing Signature & Bounds Checks

* **Ed25519 Signature Position**: Always the final 64 bytes of the total block.
* **Signed Area**: Covers bytes `[0 .. total_len - 64)`.
* **Bounds Verification Rule**: All variable-length regions must satisfy:
  `off <= total_len` and `len <= total_len - off`.
  Additionally, they must not overlap the trailing signature:
  `off + len <= total_len - 64`.

---

## 5. Reject Error Taxonomy

Instead of generic aborts, v2 utilizes precise reject codes for telemetries:
* `BOOT_ERR_MANIFEST_CORRUPT`: `fixed_crc32` pre-check failed (staging write rot).
* `BOOT_ERR_MANIFEST_VERSION`: Major version mismatch, or critical flags/min_reader check failed.
* `BOOT_ERR_MANIFEST_PRODUCT`: Vendor, product family, or hardware revision mismatch.
* `TBM1_BAD_PAYLOAD_LAYOUT`: Payloads out of order or overlapping in staging.
* `TBM1_BAD_RDELTA`: Malformed reverse delta descriptor or region size.

---

## 6. Reserved-Field Discipline

All reserved and padding fields (`_rsvd`, `_rsvd0`, `_reserved_tail`) follow a split rule:

- **Encoder obligation**: Set all unused reserved bytes to `0x00`.
- **Reader tolerance**: Do NOT reject a manifest because reserved bytes are non-zero.

**Rationale**: Reserved fields lie within the signed area `[0 .. total_len − 64)`. Only the legitimate signer can fill them. A future minor version may place new scalar fields into `_reserved_tail` — a zero-check would reject manifests that the reader should accept (minor versions are backward-compatible by definition). Unknown bytes are semantically ignored by the reader.

---

## 7. Chunk-Hash Partitioning Rule

`REGION_CHUNK_HASHES` contains per-image SHA-256 chunk hashes **concatenated in image-descriptor order** (index 0 first). Each image contributes `num_chunks × 32` bytes.

**Reader verification**: `region.len == Σ(images[i].num_chunks) × 32` for `i ∈ [0 .. image_count)`. Mismatch → reject (`TBM1_BAD_CHUNKHASH_LEN`).

**Per-image offset computation** (prefix sum):
```
slice_off[0] = region.off
slice_off[i] = region.off + Σ(images[j].num_chunks × 32) for j < i
```

---

## 8. Supported Swap Strategies (T0–T4)

Toob-Boot supports 7 deterministic swap mechanisms derived from hardware capabilities:

| Strategy | Name | Transport Provider | Execution Model | Rollback Mechanism |
|---|---|---|---|---|
| **T0** | Dual-Bank Hardware Flip | `pointer` (ID 4) | `SLOT_EXEC_BANK_SWAP` | Register toggle back |
| **T1A** | MMU / XIP Remap | `pointer` (ID 4) | `SLOT_EXEC_XIP_REMAP` | MMU reprogram via TMR |
| **T1B** | Relocatable Vector Table | `pointer` (ID 4) | `SLOT_EXEC_RELOCATABLE`| VTOR/mtvec handoff |
| **T2A** | Reverse-Delta Oneway | `oneway` (ID 2, `REVERSE_DELTA`) | `SLOT_EXEC_FIXED` | TDS1 VM apply from Region 6 |
| **T2B** | Swap-Offset with Tail-Gap | `swapoffset` (ID 5) | `SLOT_EXEC_FIXED` | Symmetric reverse swap |
| **T3** | Swap-Scratch Ring | `swapscratch` (ID 1) | `SLOT_EXEC_FIXED` | Legacy trigger revert / ring |
| **T4** | Oneway without Backup | `oneway` (ID 2, `NONE`) | `SLOT_EXEC_FIXED` | Escalate to Recovery OS |

---

## 9. TDS1 Streaming Virtual Machine & Encoder Optimizations

TDS1 (`delta_alg = 3`) defines a Turing-incomplete, $O(1)$-RAM streaming delta engine tailored for embedded flash constraints.

### 9.1 VM Instruction Set Architecture (16-byte P10-aligned)

| Opcode | Hex Value | Length | Offset | Description |
|---|---|---|---|---|
| `COPY_BASE` | `0xC0C0C0C0` | $N$ Bytes | Base Offset | Reuses unchanged code blocks directly from the active base slot. |
| `INSERT_LIT` | `0x1A1A1A1A` | $N$ Bytes | 0 | Streams $N$ Heatshrink LZSS compressed bytes into destination flash. |
| `BZERO` | `0x5A5A5A5A` | $N$ Bytes | 0 | Emits $N$ zero bytes directly without flash reads (BSS optimization). |
| `EOF` | `0x0F0F0F0F` | 0 | 0 | Marks legitimate end of patch stream with CRC validation. |

Every 16-byte instruction contains an isolated CRC-32 against SPI transit noise and EMFI glitches.

### 9.2 Offline Mathematical Encoder Optimizations

1. **Phase-Shift Invariance**: Employs fine-grained 1-byte prefix indexing on binaries $\le 2\text{ MB}$ (scaling to 2-byte instruction alignment on larger images) so odd-byte insertions do not invalidate subsequent matches.
2. **Unified Backward/Forward Candidate Evaluation**: Evaluates candidate matches both backward into the pending literal accumulator (`litAccum`) and forward into the target, reclaiming up to $100\%$ of preceding literals into `COPY_BASE`.
3. **64-bit Accelerated Matching**: Scans 8 bytes per iteration using `binary.LittleEndian.Uint64` and bit-manipulation (`TrailingZeros64(xor) / 8`) before single-byte tail matching.
4. **Simulated Lookahead Lazy Matching**: Defers matches when lookahead position $t+1$ discovers a match exceeding the current match length by $> 4$ bytes.
5. **Peephole Instruction Coalescing**: Dynamically merges adjacent `COPY_BASE` and `BZERO` operations with overflow guards, eliminating 16-byte wire overhead per coalesced block.



