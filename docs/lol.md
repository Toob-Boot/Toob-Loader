Based on a comprehensive security audit of the **Toob-Boot** codebase, it is clear that significant engineering effort has gone into building a highly resilient bootloader. The adherence to NASA P10 coding standards, the absolute zero-allocation architecture (via `crypto_arena`), the Triple Modular Redundancy (TMR) WAL, and the hardware-level EMFI glitch defenses are highly impressive.

However, beneath these heavy hardware-level mitigations, there are several **critical logical vulnerabilities** and **cryptographic integration flaws**. These bypass the Secure Boot chain, allowing for **Arbitrary Code Execution (ACE)**, information disclosure, and persistent bricking.

Here is the security audit detailing the findings and how to fix them.

---

### 🚨 1. Arbitrary Code Execution: Missing Delta Patch Verification

**Location:** `core/boot_state.c`
**Impact:** Critical (Remote / Local Code Execution)

**Description:**
When a `toob_image_delta` update is processed, the bootloader correctly authenticates the SUIT manifest. However, the raw delta patch payload residing in the staging flash is **never cryptographically verified**.

In `_handle_update_flow()`, `boot_merkle_verify_stream()` is only called for `toob_image_raw` updates. For delta updates, `boot_delta_apply()` is invoked directly:

```c
if (is_delta) {
    boot_status_t delta_stat = boot_delta_apply(...);
    if (delta_stat == BOOT_OK) {
        verify_status = BOOT_OK; // VULNERABILITY: No Merkle stream verification!
        requires_swap = true;
```

If `boot_delta_apply()` succeeds, the `verify_status` is blindly set to `BOOT_OK`. An attacker can intercept an OTA update, provide a valid (or replayed) signed manifest, but maliciously swap the `.patch` binary in flash. The Streaming Delta Virtual Machine (SDVM) will execute the malicious unauthenticated instructions (e.g., `INSERT_LIT`), granting the attacker Arbitrary Code Execution.

**Remediation:** After `boot_delta_apply()` successfully completes, you must call `boot_merkle_verify_stream()` on the reconstructed firmware in the `Recovery` slot to prove it matches the signed `chunk_hashes` from the manifest.

---

### 🚨 2. Arbitrary Flash Read via Unchecked Delta Literal Offset

**Location:** `core/boot_delta.c`
**Impact:** Critical (Information Disclosure / Exfiltration of secrets)

**Description:**
The SDVM reads the `literal_block_offset` directly from the unauthenticated `toob_tds_header_t` struct at the start of the delta patch. While the bootloader calculates and checks `expected_lit_offset`, it never validates the actual variable used for flash reads (`hdr.literal_block_offset`):

```c
uint32_t lit_read_offset = hdr.literal_block_offset; // Unchecked!
// ...
if (inst_opcode == TOOB_TDS_OP_INSERT_LIT) {
    // VULNERABILITY: Reads from arbitrary flash locations
    if (platform->flash->read(delta_addr + lit_read_offset, read_buf, chunk) != BOOT_OK)
```

An attacker can craft a malicious patch with `hdr.literal_block_offset` pointing to a sensitive memory region (e.g., internal flash containing Root Keys or eFuses). The `INSERT_LIT` instruction will decompress this out-of-bounds data and write it directly into the newly generated firmware, allowing the attacker to boot and extract the secrets.

**Remediation:** Assert that `hdr.literal_block_offset` is exactly equal to `expected_lit_offset`.

---

### 🚨 3. Secure Boot Bypass via Unauthenticated `entry_point`

**Location:** `stage0/stage0_main.c`
**Impact:** Critical (Local Arbitrary Code Execution)

**Description:**
In Stage 0, the Ed25519 signature verification strictly covers the payload but entirely omits the 20-byte `toob_image_header_t` header.

```c
  uint8_t digest[32] __attribute__((aligned(8)));
  uint32_t payload_addr = active_slot + sizeof(hdr);

  // VULNERABILITY: Hash computation starts AFTER the header.
  stage0_hash_compute(platform, payload_addr, hdr.image_size, digest);
  // ...
  // Jumps to the unauthenticated entry_point
  jump_to_payload(payload_addr + hdr.entry_point);
```

An attacker with physical SPI flash access can leave the valid payload and signature perfectly intact but modify `hdr.entry_point` to point to a ROP chain or a malicious payload appended to the flash. Stage 0 will verify the signature successfully and blindly hijack the control flow to the attacker's offset.

**Remediation:** Hash the entire slot starting from `active_slot` (Header + Payload) and update your offline signing tools to reflect this inclusion.

---

### ⚠️ 4. Out-of-Bounds Read in Stage 0 Ed25519ph (Persistent Brick)

**Location:** `stage0/stage0_main.c` -> `crypto/monocypher/monocypher-ed25519.c`
**Impact:** High (Denial of Service / Brick)

**Description:**
Stage 0 allocates a 32-byte `digest` array for the SHA-256 hash. It passes this 32-byte array to `crypto_ed25519_ph_check()`. However, Monocypher's `crypto_ed25519_ph_check` assumes Ed25519ph traditionally uses SHA-512 and is hardcoded to read a **64-byte** `msg_hash` buffer:

```c
int crypto_ed25519_ph_check(const uint8_t sig[64], const uint8_t pk[32],
                            const uint8_t msg_hash[64]) {
	u8 h_ram[32];
    // VULNERABILITY: Reads 64 bytes from the 32-byte msg_hash stack buffer
	hash_reduce(h_ram, domain, sizeof(domain), sig, 32, pk, 32, msg_hash, 64);
```

This forces an Out-of-Bounds stack read, absorbing 32 bytes of unpredictable stack memory (such as adjacent variables like `pubkey` or `sig`) into the verification hash. Valid firmware updates will deterministically fail signature verification, causing Stage 0 to enter a permanent panic loop.

**Remediation:** Either allocate a 64-byte buffer for the hash and zero-pad the SHA-256 output, or switch Monocypher to use a pure Ed25519 signature rather than the `ph` variant over a 32-byte digest.

---

### ⚠️ 5. Compiler Optimization Defeats CFI Glitch Protection

**Location:** `core/include/boot_types.h`
**Impact:** High (Total bypass of Fault Injection/EMFI mitigations)

**Description:**
Your glitch defense relies heavily on double-evaluation patterns separated by `BOOT_GLITCH_DELAY()`. However, the inline assembly lacks the `"memory"` clobber:

```c
#if defined(__GNUC__) || defined(__clang__)
  #define BOOT_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
```

Without `::: "memory"`, modern compilers (GCC/Clang) are free to cache the evaluation of boolean conditions in a CPU register across the macro. Instead of physically re-evaluating memory states for the second check, the compiler will read the previously cached result from the register. A single voltage glitch that flips the register or skips the original evaluation instruction defeats the entire double-check architecture.

**Remediation:** Add the memory clobber to act as a compiler barrier: `__asm__ volatile("nop; nop; nop;" ::: "memory");`

---

### ⚠️ 6. Serial Rescue Authentication Replay Attack

**Location:** `core/boot_panic.c`
**Impact:** Medium (Authentication Bypass)

**Description:**
The Serial Rescue (Stage 1.5) validates the token's timestamp against the hardware monotonic counter (`safe_timestamp > current_monotonic`). Upon success, it calls `advance_monotonic_counter()`, which typically increments the hardware counter by exactly `1`.

```c
              if (platform->crypto->advance_monotonic_counter) {
                platform->crypto->advance_monotonic_counter();
                current_monotonic = (uint32_t)safe_timestamp;
              }
```

If an attacker intercepts a token generated for `current_monotonic + 100` (e.g., generated offline by a technician), the token is accepted, and the hardware counter is incremented by 1. Upon reboot, the attacker can **replay the exact same token another 99 times** because its timestamp is still greater than the slowly incrementing hardware counter, entirely defeating the 2FA anti-replay protection.

**Remediation:** Require tokens to strictly equal `current_monotonic + 1` (no skipping), or force the hardware monotonic counter to advance multiple times in a loop until it catches up to the token's timestamp.
