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

### 3.1 Device-Bound Key

The journal key `k_journal` is derived as:

```
k_journal = H(chip_uid ‖ root_pubkey ‖ "toob-journal-key-v1")[0:16]
```

This key is **unique per device** and deterministic (re-derivable on every boot).

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
| **L-2** On chips without protected key storage, `k_journal` degrades. | The key binding reduces to `H(chip_uid ‖ root_pubkey ‖ ...)` — detectable only by actors without code execution. | Documented degradation, not a silent failure. |
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
