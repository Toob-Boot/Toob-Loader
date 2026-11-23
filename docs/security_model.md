# Toob-Boot Security Model

This document formalizes the security assumptions, defense lines, and
known limitations of the Toob-Boot bootloader.

---

## §1 — Threat Assumptions

| Assumption | Rationale |
|---|---|
| **TA-1** An attacker can write arbitrary data to external flash. | Otherwise Ed25519 image signatures would be unnecessary. |
| **TA-2** An attacker cannot execute arbitrary code on the MCU during boot. | Code execution implies full compromise; the bootloader's role is to prevent this state. |
| **TA-3** eFuse/OTP values are immutable once burned. | Hardware guarantee of the silicon vendor. |
| **TA-4** The TRNG produces unpredictable output (NIST SP 800-90B). | HAL contract; runtime entropy health checks are mandatory. |

---

## §2 — Two-Line Anti-Rollback Defense

The SVN (Security Version Number) floor is enforced by two **independent**
defense lines:

| Line | Root of Trust | Mechanism | Compromise Impact |
|---|---|---|---|
| **A2** (Hard Floor) | eFuse monotonic counter | Hardware-backed, irreversible | Cannot be rolled back without silicon replacement |
| **A1** (Enforced Floor) | WAL-persisted SVN | Device-bound hash chain (K4 `chain_tag`) | Manipulation is detectable as chain break |

**Independence**: Compromise of A1 (e.g., full flash rewrite with code execution)
does not weaken A2, and vice versa. The effective floor is `max(A1, A2)`.

---

## §3 — Journal Chain Mechanics (K4)

### 3.1 Device-Bound Key & Active OTP Root Resolution

On every boot, the active Root Public Key slot is discovered by double-reading all
contiguous provisioned OTP slots `0 .. TOOB_MAX_OTP_SLOTS - 1` (`boot_otp_get_active_key_index`),
enforcing a blank tail (`Stage0Chain.v all_blank_tail`) and rejecting all-zero/all-`0xFF`
keys or read-back discrepancies.

When `keystore->read_device_secret` is implemented (HAL V3 append-only extension),
the journal key `k_journal` is derived as:

```
k_journal = H(device_secret || chip_uid || active_root_pubkey || "toob-journal-key-v2")[0:16]
```

Chips without hardware fuse secrets fail closed with `BOOT_ERR_NOT_SUPPORTED` unless
compiled explicitly with the chip capability flag `TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION=1`
(which selects `"toob-journal-key-v1"` without `device_secret` and is documented as `L-2`).
All static K4 secrets (`journal_key` and cached TMR state) are zeroized via
`boot_journal_zeroize_secrets()` prior to handoff.

### 3.2 Chain Tag Computation

Only **security-bearing** WAL intents participate in the chain:
- `WAL_INTENT_DEVICE_LOCKED` (13)
- `WAL_INTENT_CONFIRM_COMMIT` (4)
- `WAL_INTENT_TXN_COMMIT` (3)

All other intents remain CRC-32 only (bounded hash cost per boot).

For each security-bearing entry `e_n` appended to the WAL:

```
tag_n = H(k_journal ‖ e_n ‖ tag_{n-1})[0:16]
```

The chain tag is stored in the TMR payload's `chain_tag[16]` field
(sector header, replicated across 3 TMR sectors).

### 3.3 Epoch Anchor

During each TMR rotation, the current eFuse epoch is bound into the chain:

```
tag_epoch = H(k_journal ‖ tmr_bytes ‖ efuse_epoch ‖ prev_tag)[0:16]
```

This ensures that a full replay of an old, internally-consistent WAL image
is detected once the eFuse epoch has advanced.

---

## §4 — Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| **L-1** Within the same eFuse epoch, a full WAL replay is undetectable. | An attacker who can write flash and knows `k_journal` can replay a complete old WAL state. | The eFuse counter is the only monotone anchor; it is intentionally burned sparingly. |
| **L-2** On chips without protected key storage (`read_device_secret == NULL`) and explicit `TOOB_ALLOW_PUBLIC_JOURNAL_KEY_DEGRADATION=1`, `k_journal` degrades. | The key binding reduces to `H(chip_uid ‖ active_root_pubkey ‖ "toob-journal-key-v1")` — no silent degradation occurs without the explicit capability flag. | Explicit chip capability gating (`BOOT_ERR_NOT_SUPPORTED` default). |
| **L-3** Chain tag is 128 bits (truncated SHA-256). | Collision resistance is 2^64 (birthday bound). | Sufficient for the embedded threat model; full 256-bit tags would exceed TMR reserved space. |

---

## §5 — Independence of Defense Lines (§5.1)

The A1 and A2 defense lines are architecturally independent:

1. **A2 (eFuse)** relies solely on silicon-level monotonic counters.
   No software can decrement them. No flash-level manipulation affects them.

2. **A1 (WAL chain)** relies on the device-bound journal key and the
   cryptographic hash chain. An attacker who can rewrite flash but cannot
   extract the eFuse secret (TA-2) cannot forge a valid chain.

3. **Combined floor**: `boot_rollback_verify_svn` checks both lines
   independently. The effective SVN floor is `max(WAL_svn, eFuse_epoch)`.
   A downgrade is rejected if *either* line fails.

---

## §6 — Fail-Closed WAL Initialization & Hardening Guarantees

- **Deployed Blank-WAL Wipe Rejection**: When no valid WAL sector exists (`highest_idx == -1`), `boot_journal_init` fails closed (`BOOT_ERR_VERIFY`) if hardware `efuse_epoch > 0` or `dslc != 0x00` (or if either hardware read fails with an unexpected error), preventing flash-wipe reset attacks on provisioned devices.
- **No Unauthenticated `chain_entry_count == 0` / Legacy Bypasses**: K4 TMR MAC verification and `WAL_INTENT_*` MAC checks run unconditionally once `boot_derive_journal_key` succeeds. Legacy V1 WAL magic (`WAL_ABI_VERSION_MAGIC_LEGACY`) is rejected (`BOOT_ERR_ABI_MISMATCH`) unless `TOOB_ALLOW_LEGACY_WAL_MIGRATION=1` is compiled explicitly.
- **Reclaimed KDM Floor (`kdm_seq_floor`)**: `wal_tmr_payload_t` (`WAL_TMR_VERSION_9`, 112B) anchors `kdm_seq_floor` inside the K4-authenticated TMR payload so `boot_cloud_cmd` rejects KDM quorum rollback below the last ratified sequence number.

---

## §7 — Authenticated Slot Execution & Rollback (`TSIG`)

- Every booted slot image (Normal App, Recovery OS) and backup/rollback source (`boot_rollback`, `swapmove`, `oneway`) is authenticated by `boot_verify_slot_image` over the 72-byte `toob_img_sig_trailer_t` (`TOOB_IMG_SIG_MAGIC = "TSIG"`, SHA-256 digest over `[0 .. image_size - 72)`, non-revoked OTP slot check, and Ed25519 signature) prior to proof sealing (`boot_proof_seal`) or slot restoration.
- `TOOB_ALLOW_UNSIGNED_APP_BOOT` is compile-time forbidden when `TOOB_PROFILE_PRODUCTION` is defined.
- Reverse-delta descriptors in `boot_transport_oneway` (`resolve_staging_rdelta`) authenticate the full TBM1 manifest via `boot_verify_manifest_envelope` (not `fixed_crc32` alone) before inspecting descriptor fields.
- `stage_apply_raw` verifies the Staging Merkle tree unconditionally unless the K4 WAL transaction explicitly records that a bidirectional chunk swap (`SWAPSCRATCH` `0xAA55AA55U` or `TOOB_PHASE_SWAPMOVE_SWAP`) has already modified Staging in-place; final slot `TSIG` verification still executes prior to handoff.

---

## §8 — PQC Public-Key Pinning & Stage 0 RAM-First Verification

- **PQC Pubkey Pinning**: When `TOOB_PQC_ENABLED` hybrid verification is active, `boot_verify_manifest_envelope` hashes the envelope-embedded `pubkey_pqc` with SHA-256 and verifies a constant-time match against `keystore->read_pqc_pubkey_hash(expected, key_index)` or compile-time `TOOB_PINNED_PQC_PUBKEY_SHA256`, failing closed if neither anchor is provisioned.
- **Stage 0 RAM-First Copy & Hardware Counter Floor**: Stage 0 validates RAM destinations against `.data`/`.bss` (`_sdata.._ebss`) and the active stack guard window, copies RAM payloads once into target SRAM prior to hashing and Ed25519 signature verification (eliminating Flash-to-RAM TOCTOU), and enforces `boot_read_monotonic_counter_safe` alongside `stage1_svn`.

---

## §9 — Runtime Entropy Health & CRC-32 Skip Policy

- `boot_random_safe` enforces stuck-at `0x00`/`0xFF`, uniform-byte, constant linear stride (`len >= 8`), and NIST SP 800-90B repetition-count (`>= 8` consecutive equal bytes on `len >= 16`) checks, zeroizing the buffer on failure. Callers propagate errors fail-closed.
- `TOOB_TA1_STRICT_NO_CRC_SKIP` defaults to `1` (and `0` is compile-time forbidden under `TOOB_PROFILE_PRODUCTION`), eliminating pre-write CRC-32 collision skips in `boot_effect`, `boot_swap`, and `boot_transport_swapmove`, while gating 3-sector chunk tearing deduction strictly on `is_resuming_this_chunk`.
