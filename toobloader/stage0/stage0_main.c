/**
 * @file stage0_main.c
 * @brief Immutable Core Entry
 *
 * Orchestrates bare-metal CRT bringup, Magic-Checks, Hashing,
 * Ed25519-Verification and the multi-architecture payload jump.
 *
 * Relevant Specs:
 * - docs/concept_fusion.md
 */

#include "boot_fih.h"
#include "boot_hal.h"
#include "boot_merkle.h"
#include "boot_platform_bringup.h"
#include "boot_proof.h"
#include "boot_secure_zeroize.h"
#include "boot_types.h"
#include "generated_boot_config.h"
#include "stage0_crypto.h"
#include <string.h>

static uint32_t g_seal_key[4];

extern uint32_t stage0_evaluate_tentative(const boot_platform_t *platform, uint32_t current_slot);
extern uint8_t stage0_get_active_otp_key_index(const boot_platform_t *platform);

/* --- STAGE 0 STUBS (To satisfy linker without pulling in core/libtoob) --- */
#include "boot_ct_utils.h"
#include "boot_panic.h"
#include "libtoob_types.h"
TOOB_NOINIT_VAR(toob_handoff_state) toob_handoff_t toob_handoff_state;

void toob_ecc_trap(void) {
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
  (void)platform;
  (void)reason;
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}

_Noreturn void boot_terminal_halt(const boot_platform_t *platform, boot_status_t reason,
                                  uint16_t site_id) {
  (void)site_id;
  boot_panic(platform, reason);
}

_Noreturn static void dead_halt(void) {
  while (1) {
    BOOT_GLITCH_DELAY(); /* Intentional starvation of WDT */
  }
}

#if !defined(TOOB_MOCK_TEST) && !defined(TOOB_HOST_FUZZING) && !defined(_WIN32) &&                 \
    !defined(__linux__) && !defined(__APPLE__) && !defined(__CPROVER__)
uintptr_t __stack_chk_guard =
    0x5A0E91C3U; /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */

void __stack_chk_fail(void); /* NOLINT(bugprone-reserved-identifier,cert-dcl37-c) */

void __stack_chk_fail(
    void) { /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */
  dead_halt();
}
#endif
/* -------------------------------------------------------------------------- */

#ifndef TOOB_ALLOW_DEV_BYPASS
#define TOOB_ALLOW_DEV_BYPASS 0
#endif
#if defined(TOOB_PROFILE_PRODUCTION) && TOOB_ALLOW_DEV_BYPASS
#error "TOOB_ALLOW_DEV_BYPASS forbidden in production!"
#endif

#ifndef BOOT_STAGE1_SVN
#define BOOT_STAGE1_SVN 0U
#endif

#if defined(__ARM_ARCH_PROFILE) && (__ARM_ARCH_PROFILE == 'M') &&                                  \
    ((defined(CHIP_HAS_VTOR) && (CHIP_HAS_VTOR != 0)) ||                                           \
     (!defined(CHIP_HAS_VTOR) &&                                                                   \
      ((defined(__ARM_ARCH) && (__ARM_ARCH >= 7)) || defined(__ARM_ARCH_8M_BASE__))))
#define TOOB_STAGE0_ENTRY_ALIGN_MASK 0x7FU
#else
#define TOOB_STAGE0_ENTRY_ALIGN_MASK 0x03U
#endif

int main(void); /* NOLINT(misc-use-internal-linkage) */

#if !defined(__linux__) && !defined(__APPLE__) && !defined(_WIN32)
extern uint32_t _sidata[];
extern uint32_t _sdata[];
extern uint32_t _edata[];
extern uint32_t _sbss[];
extern uint32_t _ebss[];
extern uint32_t _stack_top;

static void __attribute__((used, noinline, noreturn)) stage0_c_init(void);

static void __attribute__((used, noinline, noreturn)) stage0_c_init(void) {
  if (&_sdata[0] != &_sidata[0]) {
    const uint32_t *src = _sidata;
    uint32_t *dst = _sdata;
    while (dst < _edata) {
      *dst++ = *src++;
    }
  }
  uint32_t *bss = _sbss;
  while (bss < _ebss) {
    *bss++ = 0U;
  }
  (void)main();
  dead_halt();
}

#if defined(__riscv)
extern uint32_t __global_pointer$;
void __attribute__((naked, noreturn, section(".stage0_entry"))) _stage0_start(
    void) { /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */
  __asm__ volatile(".option push\n"
                   ".option norelax\n"
                   "la gp, __global_pointer$\n"
                   ".option pop\n"
                   "csrci mstatus, 8\n"
                   "la sp, _stack_top\n"
                   "j stage0_c_init\n");
}
#elif defined(__aarch64__)
void __attribute__((naked, noreturn, section(".stage0_entry"))) _stage0_start(
    void) { /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */
  __asm__ volatile("msr daifset, #0xf\n"
                   "ldr x0, =_stack_top\n"
                   "mov sp, x0\n"
                   "b stage0_c_init\n");
}
#elif defined(__arm__)
static void __attribute__((used, noreturn)) stage0_fault_trap(void) {
  dead_halt();
}
void __attribute__((naked, noreturn, section(".stage0_entry"))) _stage0_start(
    void) { /* NOLINT(misc-use-internal-linkage,bugprone-reserved-identifier,cert-dcl37-c) */
  __asm__ volatile("cpsid i\n"
                   "ldr r0, =_stack_top\n"
                   "mov sp, r0\n"
                   "b stage0_c_init\n");
}
__attribute__((used, section(".isr_vector"))) static const uintptr_t s_stage0_arm_vectors[16] = {
    (uintptr_t)&_stack_top,
    (uintptr_t)&_stage0_start,
    (uintptr_t)&stage0_fault_trap, /* NMI */
    (uintptr_t)&stage0_fault_trap, /* HardFault */
    (uintptr_t)&stage0_fault_trap, /* MemManage */
    (uintptr_t)&stage0_fault_trap, /* BusFault */
    (uintptr_t)&stage0_fault_trap, /* UsageFault */
    0U,
    0U,
    0U,
    0U,
    (uintptr_t)&stage0_fault_trap, /* SVCall */
    (uintptr_t)&stage0_fault_trap, /* DebugMon */
    0U,
    (uintptr_t)&stage0_fault_trap, /* PendSV */
    (uintptr_t)&stage0_fault_trap  /* SysTick */
};
#elif defined(__XTENSA__)
#ifdef __XTENSA_WINDOWED_ABI__
__asm__(".section .stage0_entry, \"ax\"\n"
        ".global _stage0_start\n"
        ".type _stage0_start, @function\n"
        ".align 4\n"
        "_stage0_start:\n"
        "    j .L_s0_entry_init\n"
        "    .align 4\n"
        ".L_s0_lit_ps:\n"
        "    .word 0x0004002F\n"
        ".L_s0_lit_sp:\n"
        "    .word _stack_top\n"
        ".L_s0_lit_c_init:\n"
        "    .word stage0_c_init\n"
        ".L_s0_entry_init:\n"
        "    movi a0, 0\n"
        "    wsr a0, windowbase\n"
        "    rsync\n"
        "    movi a0, 1\n"
        "    wsr a0, windowstart\n"
        "    rsync\n"
        "    l32r a0, .L_s0_lit_ps\n"
        "    wsr a0, ps\n"
        "    rsync\n"
        "    l32r a1, .L_s0_lit_sp\n"
        "    l32r a4, .L_s0_lit_c_init\n"
        "    callx4 a4\n"
        "1:  j 1b\n"
        ".size _stage0_start, . - _stage0_start\n"
        ".previous\n");
#else
__asm__(".section .stage0_entry, \"ax\"\n"
        ".global _stage0_start\n"
        ".type _stage0_start, @function\n"
        ".align 4\n"
        "_stage0_start:\n"
        "    j .L_s0_entry_init\n"
        "    .align 4\n"
        ".L_s0_lit_sp:\n"
        "    .word _stack_top\n"
        ".L_s0_lit_c_init:\n"
        "    .word stage0_c_init\n"
        ".L_s0_entry_init:\n"
        "    rsil a2, 15\n"
        "    l32r a1, .L_s0_lit_sp\n"
        "    l32r a4, .L_s0_lit_c_init\n"
        "    jx a4\n"
        ".size _stage0_start, . - _stage0_start\n"
        ".previous\n");
#endif
#endif
#endif /* Freestanding bare-metal CRT */

/* P10 Rule: O(1) Memory layout, Multi-Architecture Payload Jump */
#if defined(__XTENSA__)
static void __attribute__((noreturn)) jump_to_payload(uint32_t vector_table_addr) {
  __asm__ volatile("isync\n"
                   "jx %0\n" ::"r"(vector_table_addr)
                   : "memory");
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}
#else
static void __attribute__((noreturn)) jump_to_payload(uint32_t vector_table_addr) {
  (void)vector_table_addr;
#if defined(__GNUC__) || defined(__clang__)
#if defined(__aarch64__)
  __asm__ volatile("dsb sy\n"
                   "isb sy\n"
                   "br %0\n" ::"r"((uintptr_t)vector_table_addr)
                   : "memory");
#elif defined(__arm__)
  __asm__ volatile(
#if (defined(CHIP_HAS_VTOR) && (CHIP_HAS_VTOR != 0)) ||                                            \
    (!defined(CHIP_HAS_VTOR) &&                                                                    \
     ((defined(__ARM_ARCH) && (__ARM_ARCH >= 7)) || defined(__ARM_ARCH_8M_BASE__)))
      "ldr r2, =0xE000ED08\n" /* SCB->VTOR */
      "str %0, [r2]\n"
      "dsb sy\n"
      "isb sy\n"
#endif
      "ldr r1, [%0]\n" /* Initial MSP at offset 0 */
      "msr msp, r1\n"
      "ldr r1, [%0, #4]\n" /* Reset_Handler at offset 4 */
      "bx r1\n" ::"r"(vector_table_addr)
      : "r1", "r2", "memory");
#elif defined(__riscv)
  __asm__ volatile("fence.i\n"
                   "jr %0\n" ::"r"(vector_table_addr)
                   : "memory");
#endif
#endif
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}
#endif

static bool stage0_is_ram_entry(uint32_t addr) {
  (void)addr;
#if defined(CHIP_IRAM_BASE) && defined(CHIP_IRAM_SIZE)
  if (addr >= (uint32_t)CHIP_IRAM_BASE &&
      addr < ((uint32_t)CHIP_IRAM_BASE + (uint32_t)CHIP_IRAM_SIZE)) {
    return true;
  }
#endif
#if defined(CHIP_SRAM_BASE) && defined(CHIP_SRAM_SIZE)
  if (addr >= (uint32_t)CHIP_SRAM_BASE &&
      addr < ((uint32_t)CHIP_SRAM_BASE + (uint32_t)CHIP_SRAM_SIZE)) {
    return true;
  }
#endif
  return false;
}

static bool stage0_is_ram_range_valid(uint32_t addr, uint32_t size) {
  if ((addr & 3U) != 0U || size == 0U || UINT32_MAX - addr < size) {
    return false;
  }
#if defined(CHIP_IRAM_BASE) && defined(CHIP_IRAM_SIZE)
  if (addr >= (uint32_t)CHIP_IRAM_BASE &&
      (addr + size) <= ((uint32_t)CHIP_IRAM_BASE + (uint32_t)CHIP_IRAM_SIZE)) {
    return true;
  }
#endif
#if defined(CHIP_SRAM_BASE) && defined(CHIP_SRAM_SIZE)
  if (addr >= (uint32_t)CHIP_SRAM_BASE &&
      (addr + size) <= ((uint32_t)CHIP_SRAM_BASE + (uint32_t)CHIP_SRAM_SIZE)) {
    return true;
  }
#endif
  return false;
}

static bool stage0_ranges_overlap(uintptr_t a_start, uintptr_t a_size, uintptr_t b_start,
                                  uintptr_t b_size) {
  if (a_size == 0U || b_size == 0U) {
    return false;
  }
  if (UINTPTR_MAX - a_start < a_size || UINTPTR_MAX - b_start < b_size) {
    return true;
  }
  uintptr_t a_end = a_start + a_size;
  uintptr_t b_end = b_start + b_size;
  return (a_start < b_end) && (b_start < a_end);
}

static uint32_t stage0_ram_load_addr(uint32_t entry_point) {
  uint32_t load_addr = entry_point;
#if defined(CHIP_IRAM_BASE) && defined(CHIP_IRAM_SIZE) && defined(CHIP_IRAM_DBUS_BASE)
  if (entry_point >= (uint32_t)CHIP_IRAM_BASE &&
      entry_point < ((uint32_t)CHIP_IRAM_BASE + (uint32_t)CHIP_IRAM_SIZE)) {
    load_addr = (entry_point - (uint32_t)CHIP_IRAM_BASE) + (uint32_t)CHIP_IRAM_DBUS_BASE;
  }
#endif
  return load_addr;
}

static bool stage0_is_target_ram_safe(uint32_t target_addr, uint32_t size) {
  if (size == 0U || UINT32_MAX - target_addr < size) {
    return false;
  }
#if !defined(__linux__) && !defined(__APPLE__) && !defined(_WIN32) && !defined(__CPROVER__) &&     \
    !defined(TOOB_MOCK_TEST)
  volatile uint8_t stack_probe = 0U;
  uintptr_t sp_now = (uintptr_t)&stack_probe;
  uintptr_t sdata_start = (uintptr_t)_sdata;
  uintptr_t ebss_end = (uintptr_t)_ebss;
  if (ebss_end > sdata_start && stage0_ranges_overlap((uintptr_t)target_addr, (uintptr_t)size,
                                                      sdata_start, ebss_end - sdata_start)) {
    return false;
  }
  uintptr_t stack_top = (uintptr_t)&_stack_top;
  uintptr_t stack_lo = (sp_now > 2048U) ? (sp_now - 2048U) : 0U;
  if (stack_top >= stack_lo && stage0_ranges_overlap((uintptr_t)target_addr, (uintptr_t)size,
                                                     stack_lo, stack_top - stack_lo)) {
    return false;
  }
#else
  (void)stage0_ranges_overlap;
#endif
  return true;
}

static boot_status_t stage0_hash_ram_compute(const boot_platform_t *platform,
                                             const toob_image_header_t *hdr, const uint8_t *ram_buf,
                                             size_t ram_len, uint8_t *digest) {
  if (!platform || !platform->crypto || !platform->crypto->hash_init ||
      !platform->crypto->hash_update || !platform->crypto->hash_finish ||
      !platform->crypto->get_hash_ctx_size || !hdr || !ram_buf || ram_len == 0U || !digest) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (platform->crypto->get_hash_ctx_size() > BOOT_MERKLE_MAX_CTX_SIZE) {
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t hash_ctx[BOOT_MERKLE_MAX_CTX_SIZE] __attribute__((aligned(8)));
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  if (platform->crypto->hash_init(hash_ctx, sizeof(hash_ctx)) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_CRYPTO;
  }

  if (platform->crypto->hash_update(hash_ctx, (const uint8_t *)hdr, sizeof(*hdr)) != BOOT_OK) {
    boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_CRYPTO;
  }

  size_t offset = 0U;
  while (offset < ram_len) {
    if (platform->wdt && platform->wdt->kick) {
      platform->wdt->kick();
    }
    size_t step = (ram_len - offset > 128U) ? 128U : (ram_len - offset);
    if (platform->crypto->hash_update(hash_ctx, ram_buf + offset, step) != BOOT_OK) {
      boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));
      boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
      return BOOT_ERR_CRYPTO;
    }
    offset += step;
  }

  size_t digest_len = BOOT_MERKLE_HASH_LEN;
  boot_status_t fin_st = platform->crypto->hash_finish(hash_ctx, digest, &digest_len);
  boot_secure_zeroize(hash_ctx, sizeof(hash_ctx));

  if (fin_st != BOOT_OK || digest_len != BOOT_MERKLE_HASH_LEN) {
    boot_secure_zeroize(digest, BOOT_MERKLE_HASH_LEN);
    return BOOT_ERR_CRYPTO;
  }

  return BOOT_OK;
}

static void dbg_putc(const boot_platform_t *platform, char c) {
  if (platform && platform->console && platform->console->putchar) {
    platform->console->putchar((char)c);
  }
}

static void dbg_puts(const boot_platform_t *platform, const char *s) {
  while (*s) {
    dbg_putc(platform, *s++);
  }
}

static void dbg_hex(const boot_platform_t *platform, uint32_t val) {
  static const char hex[] = "0123456789ABCDEF";
  dbg_puts(platform, "0x");
  for (int i = 28; i >= 0; i -= 4) {
    dbg_putc(platform, hex[(val >> i) & 0xF]);
  }
}

static bool stage0_compute_xip_entry(uint32_t bank_addr, uint32_t image_size, uint32_t entry_offset,
                                     uint32_t *out_target_pc) {
  const uint32_t hdr_len = (uint32_t)sizeof(toob_image_header_t);
  if (image_size == 0U || image_size > (UINT32_MAX - hdr_len)) {
    return false;
  }
  const uint32_t payload_end_off = hdr_len + image_size;
  if (entry_offset < hdr_len || entry_offset >= payload_end_off) {
    return false;
  }

  uint32_t exec_base = bank_addr;
#if defined(CHIP_FLASH_XIP_BASE) && (CHIP_FLASH_XIP_BASE != 0U)
#if (CHIP_FLASH_BASE_ADDR != 0U)
  if (bank_addr < (uint32_t)CHIP_FLASH_BASE_ADDR) {
    return false;
  }
#endif
  uint32_t rel_bank = bank_addr - (uint32_t)CHIP_FLASH_BASE_ADDR;
  if (UINT32_MAX - (uint32_t)CHIP_FLASH_XIP_BASE < rel_bank) {
    return false;
  }
  exec_base = (uint32_t)CHIP_FLASH_XIP_BASE + rel_bank;
#endif

  if (UINT32_MAX - exec_base < entry_offset) {
    return false;
  }
  uint32_t target_pc = exec_base + entry_offset;
  if ((target_pc & TOOB_STAGE0_ENTRY_ALIGN_MASK) != 0U) {
    return false;
  }
  if (out_target_pc != NULL) {
    *out_target_pc = target_pc;
  }
  return true;
}

static bool stage0_try_boot_bank(const boot_platform_t *platform, uint32_t bank_addr,
                                 uint8_t confirmed_dslc, uint32_t svn_floor,
                                 boot_proof_t *out_proof) {
  (void)confirmed_dslc; /* Used only with TOOB_ALLOW_DEV_BYPASS */

  dbg_puts(platform, "[S0] Checking bank at ");
  dbg_hex(platform, bank_addr);
  dbg_puts(platform, "...\r\n");

  uint32_t bank_limit = CHIP_STAGE1B_SIZE;
  if (bank_addr == CHIP_STAGE1A_ABS_ADDR) {
    bank_limit = CHIP_STAGE1A_SIZE;
  }
  const uint32_t envelope_overhead = (uint32_t)sizeof(toob_image_header_t) + 64U;
  if (bank_limit <= envelope_overhead) {
    return false;
  }

  /* 1. Read and validate header against Stage 1 bank capacity */
  toob_image_header_t hdr __attribute__((aligned(8)));
  if (platform->flash->read(bank_addr, (uint8_t *)&hdr, sizeof(hdr)) != BOOT_OK) {
    dbg_puts(platform, "[S0] Flash read failed!\r\n");
    return false;
  }
  dbg_puts(platform, "[S0] Header magic: ");
  dbg_hex(platform, hdr.magic);
  dbg_puts(platform, " size: ");
  dbg_hex(platform, hdr.image_size);
  dbg_puts(platform, "\r\n");

  if (hdr.magic != TOOB_MAGIC_HEADER || hdr.image_size == 0U ||
      hdr.image_size > (bank_limit - envelope_overhead)) {
    dbg_puts(platform, "[S0] Bad magic or bank size bounds!\r\n");
    return false;
  }

  /* HIGH-26: Validate entry_point bounds & architectural alignment upfront */
  const bool ram_payload = stage0_is_ram_entry(hdr.entry_point);
  uint32_t ram_load_addr = 0U;
  if (ram_payload) {
    if (!stage0_is_ram_range_valid(hdr.entry_point, hdr.image_size)) {
      dbg_puts(platform, "[S0] Bad RAM entry bounds!\r\n");
      return false;
    }
    ram_load_addr = stage0_ram_load_addr(hdr.entry_point);
    if (!stage0_is_target_ram_safe(hdr.entry_point, hdr.image_size) ||
        !stage0_is_target_ram_safe(ram_load_addr, hdr.image_size)) {
      dbg_puts(platform, "[S0] RAM target overlaps Stage 0!\r\n");
      return false;
    }
  } else {
    uint32_t xip_probe = 0U;
    if (!stage0_compute_xip_entry(bank_addr, hdr.image_size, hdr.entry_point, &xip_probe)) {
      dbg_puts(platform, "[S0] Bad XIP entry bounds or alignment!\r\n");
      return false;
    }
  }

  /* 2. Load hardware PubKey */
  uint8_t key_idx = stage0_get_active_otp_key_index(platform);
  uint8_t pubkey[32] __attribute__((aligned(8)));
  boot_secure_zeroize(pubkey, 32);

#if TOOB_ALLOW_DEV_BYPASS
  bool is_dev_bypass = false;
#endif
  if (!platform->keystore->read_pubkey ||
      platform->keystore->read_pubkey(pubkey, 32, key_idx) != BOOT_OK ||
      verify_not_all_zeros_glitch_safe(pubkey, 32) != BOOT_OK) {
    dbg_puts(platform, "[S0] read_pubkey failed or zero key!\r\n");
#if TOOB_ALLOW_DEV_BYPASS
    if (confirmed_dslc == 0x00) {
      is_dev_bypass = true;
    } else {
      boot_secure_zeroize(pubkey, 32);
      return false;
    }
#else
    boot_secure_zeroize(pubkey, 32);
    return false;
#endif
  }

  /* 3. Hash computation (RAM payloads copied once FIRST to prevent Flash->RAM TOCTOU) */
  uint8_t digest[32] __attribute__((aligned(8)));
  uint8_t sig[64] __attribute__((aligned(8)));
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(sig, sizeof(sig));
  bool bank_ok = false;

  if (ram_payload) {
    if (platform->flash->read(bank_addr + (uint32_t)sizeof(hdr), (void *)(uintptr_t)ram_load_addr,
                              hdr.image_size) != BOOT_OK) {
      dbg_puts(platform, "[S0] RAM copy failed!\r\n");
      goto fail_cleanup;
    }
    if (stage0_hash_ram_compute(platform, &hdr, (const uint8_t *)(uintptr_t)ram_load_addr,
                                hdr.image_size, digest) != BOOT_OK) {
      dbg_puts(platform, "[S0] Hash compute failed!\r\n");
      goto fail_cleanup;
    }
  } else {
    if (stage0_hash_compute(platform, bank_addr, (uint32_t)sizeof(hdr) + hdr.image_size, digest) !=
        BOOT_OK) {
      dbg_puts(platform, "[S0] Hash compute failed!\r\n");
      goto fail_cleanup;
    }
  }

  uint32_t digest_head = 0U;
  memcpy(&digest_head, digest, sizeof(digest_head));
  dbg_puts(platform, "[S0] Digest[0..3]: ");
  dbg_hex(platform, digest_head);
  dbg_puts(platform, "\r\n");

  /* 4. Load signature */
  if (platform->flash->read(bank_addr + (uint32_t)sizeof(hdr) + hdr.image_size, sig, 64) !=
      BOOT_OK) {
    dbg_puts(platform, "[S0] Sig read failed!\r\n");
    goto fail_cleanup;
  }

  /* 5. Glitch-Resistant Ed25519 Verify */
  boot_status_t sig_ok = BOOT_ERR_VERIFY;
#if TOOB_ALLOW_DEV_BYPASS
  if (is_dev_bypass) {
    sig_ok = BOOT_OK;
  } else {
    sig_ok = stage0_verify_signature(platform, sig, pubkey, digest);
  }
#else
  sig_ok = stage0_verify_signature(platform, sig, pubkey, digest);
#endif

  if (sig_ok != BOOT_OK) {
    dbg_puts(platform, "[S0] Signature verification FAILED!\r\n");
    goto fail_cleanup;
  }

  BOOT_SECURE_REQUIRE(sig_ok == BOOT_OK && boot_secure_confirm(sig_ok) == BOOT_OK,
                      { goto fail_cleanup; });
  BOOT_GLITCH_DELAY();
  BOOT_SECURE_REQUIRE(sig_ok == BOOT_OK, { goto fail_cleanup; });
  dbg_puts(platform, "[S0] Signature verification PASSED!\r\n");

  /* 6. CRIT-29: Enforce authenticated Stage-1 Anti-Rollback floor */
  const uint32_t img_svn = (hdr.s1.svn_magic == TOOB_STAGE1_SVN_MAGIC) ? hdr.s1.stage1_svn : 0U;
  BOOT_SECURE_REQUIRE(img_svn >= svn_floor, {
    dbg_puts(platform, "[S0] Stage 1 SVN downgrade rejected!\r\n");
    goto fail_cleanup;
  });

  /* K1-T2: Populate and seal the proof handle */
  if (out_proof) {
    out_proof->image_addr = bank_addr;
    out_proof->image_size = hdr.image_size;
    out_proof->entry_point = hdr.entry_point;
    out_proof->svn = img_svn;
    boot_proof_seal(out_proof, g_seal_key);
  }
  bank_ok = true;

fail_cleanup:
  boot_secure_zeroize(pubkey, sizeof(pubkey));
  boot_secure_zeroize(digest, sizeof(digest));
  boot_secure_zeroize(sig, sizeof(sig));
  if (!bank_ok && ram_payload) {
    boot_secure_zeroize((void *)(uintptr_t)ram_load_addr, hdr.image_size);
  }
  return bank_ok;
}

int main(void) { /* NOLINT(misc-use-internal-linkage) */
  /* 1. Hardware Initialisierung (duplikatsicher falls via REG-022 bereits initialisiert) */
  const boot_platform_t *platform = boot_platform_init();
  if (!platform || !platform->flash || !platform->crypto || !platform->entropy ||
      !platform->keystore || platform->crypto->abi_version != TOOB_HAL_ABI_V3 ||
      platform->entropy->abi_version != TOOB_HAL_ABI_V3 || platform->entropy->random == NULL ||
      platform->keystore->abi_version != TOOB_HAL_ABI_V3) {
    dead_halt();
  }

  if (!boot_platform_is_brought_up(platform)) {
    dead_halt();
  }

  dbg_puts(platform, "\r\n=== TOOB STAGE 0 BOOT ===\r\n");

  /* P10 Rule: Secure Initialization of the Boot-Proof Seal Key using TRNG */
  if (boot_random_safe(platform, (uint8_t *)g_seal_key, sizeof(g_seal_key)) != BOOT_OK) {
    dead_halt();
  }

  /* 1.5 DSLC Majority Vote Gate (Phase 2) */
  uint8_t dslc_reads[5] = {0U, 0U, 0U, 0U, 0U};
  uint8_t valid_reads = 0U;
  uint8_t confirmed_dslc = 0xFFU;
  bool dslc_found = false;

  for (uint8_t round = 0U; round < 5U && !dslc_found; round++) {
    /* Anti-Sustained-Glitch: Randomized jitter between reads */
    if (round > 0U && platform->entropy && platform->entropy->random) {
      uint8_t jitter = 0U;
      if (platform->entropy->random(&jitter, 1U) == BOOT_OK) {
        for (volatile uint32_t d = 0U; d < (uint32_t)(jitter & 0x3FU); d++) {
          BOOT_GLITCH_DELAY();
        }
      }
    }
    uint8_t dslc_buf[64];
    size_t dslc_len = sizeof(dslc_buf);
    boot_secure_zeroize(dslc_buf, sizeof(dslc_buf));

    if (platform->keystore->read_dslc != NULL &&
        platform->keystore->read_dslc(dslc_buf, &dslc_len) == BOOT_OK && dslc_len > 0U) {
      dslc_reads[valid_reads] = dslc_buf[0];
      valid_reads++;
    }
    boot_secure_zeroize(dslc_buf, sizeof(dslc_buf));

    if (valid_reads >= 3U) {
      for (uint8_t i = 0U; i < valid_reads && !dslc_found; i++) {
        uint8_t matches = 0U;
        for (uint8_t j = 0U; j < valid_reads; j++) {
          if (dslc_reads[i] == dslc_reads[j]) {
            matches++;
          }
        }
        if (matches >= 3U) {
          confirmed_dslc = dslc_reads[i];
          dslc_found = true;
        }
      }
    }
  }

  BOOT_SECURE_REQUIRE(dslc_found, { dead_halt(); });
  BOOT_SECURE_REQUIRE(confirmed_dslc != 0xFFU, { dead_halt(); });

  /* 2. Single-pass 2-of-3 WAL TMR Quorum Scan + Tentative Crash Check */
  uint32_t wal_stage1_svn = 0U;
  uint32_t active_slot = stage0_read_wal_boot_meta(platform, &wal_stage1_svn);
  if (wal_stage1_svn == UINT32_MAX) {
    boot_panic(platform, BOOT_ERR_VERIFY);
  }
  active_slot = stage0_evaluate_tentative(platform, active_slot);

  /* CRIT-29 / Stage0Chain: Effective Stage-1 Anti-Rollback floor across WAL & HW monotonic counter. */
  const uint32_t cfg_stage1_svn = (uint32_t)BOOT_STAGE1_SVN;
  uint32_t svn_floor = (wal_stage1_svn > cfg_stage1_svn) ? wal_stage1_svn : cfg_stage1_svn;

  boot_proof_t proof;
  boot_secure_zeroize(&proof, sizeof(proof));

  /* 3-8. Per-Bank Verification (Signature + Bounds) */
  if (!stage0_try_boot_bank(platform, active_slot, confirmed_dslc, svn_floor, &proof)) {
    uint32_t fallback_slot =
        (active_slot == CHIP_STAGE1A_ABS_ADDR) ? CHIP_STAGE1B_ABS_ADDR : CHIP_STAGE1A_ABS_ADDR;
    if (!stage0_try_boot_bank(platform, fallback_slot, confirmed_dslc, svn_floor, &proof)) {
      boot_panic(platform, BOOT_ERR_DOWNGRADE);
    }
    active_slot = fallback_slot;
  }

  /* Glitch-hardened double seal verification immediately before handoff */
  BOOT_SECURE_REQUIRE(boot_proof_verify(&proof, g_seal_key) == BOOT_OK, {
    boot_secure_zeroize(g_seal_key, sizeof(g_seal_key));
    boot_secure_zeroize(&proof, sizeof(proof));
    dead_halt();
  });
  BOOT_GLITCH_DELAY();
  BOOT_SECURE_REQUIRE(boot_proof_verify(&proof, g_seal_key) == BOOT_OK, {
    boot_secure_zeroize(g_seal_key, sizeof(g_seal_key));
    boot_secure_zeroize(&proof, sizeof(proof));
    dead_halt();
  });
  boot_secure_zeroize(g_seal_key, sizeof(g_seal_key));

  /* RAM payload was already copied and verified in-place before Ed25519 check (zero TOCTOU). */
  const bool ram_payload = stage0_is_ram_entry(proof.entry_point);
  uint32_t final_target_pc = 0U;
  if (ram_payload) {
    uint32_t load_addr = stage0_ram_load_addr(proof.entry_point);
    if (!stage0_is_ram_range_valid(proof.entry_point, proof.image_size) ||
        !stage0_is_target_ram_safe(proof.entry_point, proof.image_size) ||
        !stage0_is_target_ram_safe(load_addr, proof.image_size)) {
      boot_secure_zeroize(&proof, sizeof(proof));
      dead_halt();
    }
    final_target_pc = proof.entry_point;
  } else {
    if (!stage0_compute_xip_entry(proof.image_addr, proof.image_size, proof.entry_point,
                                  &final_target_pc)) {
      boot_secure_zeroize(&proof, sizeof(proof));
      dead_halt();
    }
  }
  boot_secure_zeroize(&proof, sizeof(proof));

  /* Deinit Hardware (Schliesst Flash/Crypto fuer S1-Isolation) */
  if (platform->crypto && platform->crypto->deinit) {
    platform->crypto->deinit();
  }
  if (platform->entropy && platform->entropy->deinit) {
    platform->entropy->deinit();
  }
  if (platform->keystore && platform->keystore->deinit) {
    platform->keystore->deinit();
  }
  if (platform->wdt && platform->wdt->deinit) {
    platform->wdt->deinit();
  }
  if (platform->flash && platform->flash->deinit) {
    platform->flash->deinit();
  }
  if (platform->clock && platform->clock->deinit) {
    platform->clock->deinit();
  }
  boot_platform_mark_down();

  /* P10 FIX: I-Cache / Instruction Pipeline Synchronisation nach SRAM-Copy */
  if (platform->soc && platform->soc->invalidate_icache) {
    platform->soc->invalidate_icache();
  }
#if defined(__riscv) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile("fence.i" ::: "memory");
#endif

  __asm__ volatile("" ::: "memory");
  jump_to_payload(final_target_pc);

  /* Fallback: jump_to_payload should never return */
  while (1) {
    BOOT_GLITCH_DELAY();
  }
}
