# Toobfuzzer 3.0: Security Profiles & Mathematical Strategies

The Toobfuzzer architecture abandons chip-specific IFDEF-spaghetti in favor of **Capability-Driven Fuzzing**. We map thousands of different microcontrollers (ESP32, STM32, nRF, NXP) into exactly **7 Mathematical Profiles**.

This document explains what these profiles mean in the real world, which chips trigger them, and how the Toobfuzzer Core Algorithm adapts to guarantee stable execution without HardFaults.

---

## 1. `PROFILE_BARE_METAL_OPEN`

- **Capabilities Required:** `raw_flash_erase == true`, `raw_flash_read == true`, `raw_ram_rw == true`
- **Real-World Examples:**
  - **STM32:** Any STM32 (e.g., STM32F407, STM32H7) shipped from the factory with `RDP Level 0` (Option Bytes unlocked).
  - **ESP32:** Development boards (NodeMCU, ESP32-C3) where eFuses `FLASH_CRYPT_CNT` and `DISABLE_JTAG` are 0.
  - **nRF52:** Standard development kits where `APPROTECT` is disabled or bypassed via voltage glitching (e.g., older Rev 2 silicon).
- **The Problem it Solves:** This is the baseline. The chip trusts us completely.
- **Algorithmic Strategy (Aggressive):**
  The Core fires the `full_sector_scan()` algorithm. It iterates through memory using an exponential step search, writes a magic 32-bit pattern (`0xAA55A5A5`), issues a hardware raw-erase command mapped to the BootROM, and scans forward to find the exact byte boundary where the pattern reappears. This maps the flash physically, regardless of what any datasheet or partition table claims.

## 2. `PROFILE_BOOTLOADER_MEDIATED`

- **Capabilities Required:** `debug_access == false` (or unreliable), but `raw_flash_erase == true` via API.
- **Real-World Examples:**
  - **ESP32 w/ IDF:** The developer insists on keeping the massive ESP-IDF Bootloader intact instead of overwriting Sector 0.
  - **nRF53 w/ NSIB/MCUBoot:** The Nordic Secure Immutable Bootloader protects the vector table.
- **The Problem it Solves:** We cannot take over the reset vector (`0x0`) or Early Boot because a vendor BootROM will crash if we violate its Trust Chain.
- **Algorithmic Strategy (Cooperative):**
  The auto-linker shifts our `toobfuzzer.ld` origin to the **App Slot** (e.g., `0x10000` or `0x42000000`). The core avoids probing regions below the `user_flash_base`. Instead of raw hardware writes, the generated Shim layers inject calls to the vendor's HAL (e.g., `esp_rom_spiflash_erase_sector()` or `nrf_nvmc_page_erase()`), letting the vendor bootloader implicitly handle necessary page unlocking.

## 3. `PROFILE_LOCKED_FLASH_ENCRYPTED`

- **Capabilities Required:** `flash_encrypted == true`
- **Real-World Examples:**
  - **ESP32 (V3) / ESP32-C6:** Devices where the `FLASH_CRYPT_CNT` eFuse is burnt. On older V1 silicon, Fault Injection could bypass this (CVE-2020-15048), but V3 silicon permanently blocks Downgrade loops using RSA Secure Boot V2.
  - **nRF5340:** Network Cores enforcing `fprotect` combined with TrustZone encryption zones.
- **The Problem it Solves:** A raw SPI Flash read returns ciphertext. A raw Erase command corrupts the AES block padding, causing the hardware decryption engine to fetch garbage code instructions into the CPU cache, immediately triggering `LoadStoreError` or `InstructionAccessFault`.
- **Algorithmic Strategy (Logical Degradation):**
  The Core aborts physical boundary scanning. It falls back to `partition_table_scan()`. Since we are running _inside_ the chip, the Memory Management Unit (MMU) decrypts memory transparently for us. Thus, we parse the logical partition tables (like the IDF Partition table at `0x8000`) in Klartext via the MMU cache to build our Memory Map, completely avoiding raw physical flash commands.

## 4. `PROFILE_RDP_LEVEL1`

- **Capabilities Required:** `rdp_level == 1`, `debug_access == false`
- **Real-World Examples:**
  - **STM32:** Devices locked via `FLASH->OPTCR`. Debuggers (J-Link, ST-Link) are hard-disabled from reading Flash or RAM.
- **The Problem it Solves:** If the STM32 detects a boot attempt from SRAM or the System Bootloader (BootROM) while RDP1 is active, Flash access is hardware-blocked. Attempting to read a single byte via a bare-metal pointer will cause a HardFault.
- **Algorithmic Strategy (Origin Confinement):**
  The Core understands it _must_ boot from User Flash. It restricts all mathematical searches to exactly the region defined by `chip_get_user_flash_base()`. It strictly prohibits any boundary probes into `0x00000000` (Aliased ROM), preventing the scanner from triggering the RDP trapdoor.

## 5. `PROFILE_SECURE_BOOT_ONLY`

- **Capabilities Required:** `secure_boot == true`, `flash_encrypted == false`
- **Real-World Examples:**
  - **nRF52 / STM32 TrustZone:** Systems checking Ed25519/RSA signatures on boot, but not encrypting the payload.
- **The Problem it Solves:** Our `toobfuzzer.bin` will be rejected by the BootROM unless it is correctly signed and packaged with vendor-specific Image Headers.
- **Vendor-Specific Pre-requisites (The Packaging Phase):**
  Before the math can run, the Python `build_core.py` orchestrator must satisfy the target's Root of Trust (RoT):
  - **Nordic (nRF52/nRF53):** The binary must be processed by MCUboot's `imgtool`. It requires a 32-byte `image_header` (Magic `0x96f3b83d`) prepended to the binary, and cryptographic TLV (Type-Length-Value) records containing the SHA256 hash and RSA/ECDSA signature appended to the end.
  - **ESP32 (Secure Boot V2):** The binary must be signed using `espsecure.py sign_data` with an RSA-3072 private key, appending the Signature Block to the firmware image.
  - **STM32 (TrustZone/SFI):** The binary requires an ST-specific Image Header (often generated via STM32TrustedPackage Creator) containing versioning, hashes, and potentially configuration Option Bytes.
- **Algorithmic Strategy (Signature Padding):**
  This profile doesn't change the C math (we can still scan raw boundaries). Instead, it alters the Python Builder pipeline (`build_core.py`). The builder injects a mandatory signing step using the vendor keys (provided via the GUI/CLI) to wrap the generic `.bin` into the required signed format _before_ handing it to the flashing tool.

## 6. `PROFILE_READONLY_HARDENED`

- **Capabilities Required:** `rdp_level >= 2` (or irreversible `APPROTECT` without downgrade keys)
- **Real-World Examples:**
  - **STM32 RDP Level 2:** The final lock. Debug interface physically fused off. Flash mass-erase is hardware disabled. (Exceptions exist on bleeding-edge chips like STM32U5 using OEM2Key passwords for authorized downgrades).
  - **nRF53 Locked:** `UICR.APPROTECT` hard-burnt without TF-M bypass paths.
- **The Problem it Solves:** The device is a complete Black Box. We cannot flash it. We cannot read it.
- **Algorithmic Strategy (Total Abort):**
  The GUI and Python Pipeline gracefully halt the workflow. The system instructs the user that physical Fault Injection (Voltage Glitching/EMFI) or a full board replacement is required. It prevents the system from hanging in endless timeout loops.

## 7. `PROFILE_EMULATION_ONLY`

- **Capabilities Required:** Simulated Runtime
- **Real-World Examples:**
  - Targets executing inside QEMU, Renode, or strict POSIX environments where physical peripheral registers (`FLASH->CR`) do not exist or map to OS segfaults.
- **Algorithmic Strategy (Mocked I/O):**
  All hardware-register pointers in the Shim layer are repointed to zero-copy RAM buffers. The Fuzzer behaves as if discovering a massive continuous RAM block, testing pure control-flow logic without physical delays.

---

## 8. The Core Mathematical Algorithms

The true power of Toobfuzzer lies in its refusal to trust datasheets. It uses **Pure Mathematics and Hardware Physics** to extract 100% guaranteed measurements. The `core/` C code is completely chip-agnostic; it only relies on the `arch/` layer to catch exceptions when the math hits physical limits.

### A. Flash Sector Discovery (Erase-Boundary Binary Search)

Flash memory dictates that while single bits can be written (`1` -> `0`), they can only be cleared (`0` -> `1`) by erasing an entire sector block at once.

1.  **Tagging:** The fuzzer writes a 32-bit Magic Pattern (e.g., `0xAA55A5A5`) to the start address (e.g., `0x08000000`).
2.  **Exponential Leap:** It jumps forward exponentially (e.g., `+4096` bytes to `0x08001000`) and fires a hardware `erase` command mapped via the chip Shim.
3.  **The Lookback:** It instantly reads `0x08000000` again.
    - If the pattern remains `0xAA55A5A5`, the erase command hit a _different_ sector. The jump continues.
    - If the address suddenly reads `0xFFFFFFFF`, the physics dictate that the erase at `0x08001000` cleared the sector containing `0x08000000`.
4.  **Binary Convergence:** Upon detecting the boundary crossing, the fuzzer switches to a Binary Search, dividing the distance by 2 repeatedly until it finds the exact byte boundary where the erase stops affecting the start pattern. **This exact delta is the guaranteed sector size.**

### B. RAM Boundary Discovery (Fault & Aliasing Scans)

SRAM lacks sectors. We map it using CPU Exceptions and Address Decoders.

1.  **The Hard Limit (Fault Scan):** The fuzzer sweeps forward through logical RAM addresses. When it steps off the physical edge of the silicon memory array, the CPU throws a hardware exception. The `arch/` layer (e.g., `arm_cm` HardFault handler or `xtensa` LoadStoreError handler) gracefully catches this crash, flags the exact failing address in a register, and returns control to the loop. The failing address is mathematically the end of RAM.
2.  **The Mirror Limit (Aliasing Scan):** If a chip's address decoder "wraps around" instead of crashing, the fuzzer detects it via Mirroring. It writes `0x01` at `0x20000000`. It then writes `0x02` far ahead at `0x20080000`. If reading `0x20000000` suddenly yields `0x02`, the memory map has folded over. The alias boundary physically proves the maximum RAM size.

### C. Peripheral & eFuse Classification (Behavioral Masking)

Toobfuzzer fuses its physical math with the LLM's static analysis Blueprint (`chips.json` / `chip_caps.c`).
When scanning a region the LLM claims is "eFuse" (e.g., ESP32 `0x3FF5A000`), the fuzzer tests its physics:

- It reads `0x000000A1` from the address.
- It attempts to write `0xFFFFFFFF` to mask over it.
- If a subsequent read still yields `0x000000A1` without the `arch/` layer catching a HardFault, the memory behaves as a Read-Only Hardware Register.
- Because this physical behavior perfectly matches the LLM's classification, the Fuzzer dumps this block into the final validated JSON explicitly tagged as `"type": "efuse"`, completing the Autonomous Factory feedback loop.
