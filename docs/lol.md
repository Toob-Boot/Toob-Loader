Hier ist die Überprüfung der Code-Basis. Der Fokus lag dabei auf Werten, die potenziell die Portabilität zwischen verschiedenen MCU-Architekturen brechen (z. B. unterschiedliche Flash-Geometrien, Taktfrequenzen oder Speicher-Limits).

### 🚨 Kritische Architektur-Brüche (Hardware-Annahmen im generischen Code)

Diese Werte führen bei abweichender Hardware direkt zu Fehlverhalten wie unvollständigen Erases, Write-Amplification oder unvorhersehbarem Timing.

- **`libtoob/toob_ota.c` (Zeile 131): Hardcodierte 4KB Flash-Sektoren**
  - **Ist-Zustand:** `uint32_t remainder = erase_size % 4096; /* Assumption: standard 4K sector */`
  - **Problem:** Diese Annahme bricht sofort auf NOR-Flashs mit 32 KB, 64 KB oder 128 KB Sektoren. Ein Update würde hier mitten im Sektor stoppen und nachfolgende Writes durch fehlende Löschung korrumpieren.
  - **Lösung:** Ersetzt durch das Makro `CHIP_FLASH_MAX_SECTOR_SIZE`, welches bereits über die Sandbox-/Chip-Configs an `libtoob` durchgereicht wird.
- **`core/boot_panic.c` (Zeile 276): CPU-takt-abhängiger Fallback-Timeout**
  - **Ist-Zustand:** `uint32_t hang_timeout = 10000000; while (hang_timeout > 0)...`
  - **Problem:** Eine reine Zählschleife dauert auf einem ESP32-C6 (160 MHz) nur wenige Millisekunden, auf einem STM32L0 (16 MHz) hingegen knapp eine Sekunde. Das konterkariert den Kommentar `~10 Sekunden`.
  - **Lösung:** Wenn die Clock bereits deinitialisiert ist, macht eine takt-abhängige Wartezeit als WDT-Fallback wenig Sinn. Pragmatischer ist es, direkt einen Exception-Trap auszulösen, statt unvorhersehbar lange zu loopen.

### ⚠️ Warnungen: Magic Numbers und statische Limits

Diese Punkte verursachen keine sofortigen Fehler, schränken aber die Flexibilität des Manifest-Compilers ein.

- **`core/boot_journal.c`:** `#define MAX_WAL_SECTORS 8`. Ein statisches Array-Limit tief im Core. Wenn ein Chip winzige Sektoren hat und der Manifest-Compiler `TOOB_WAL_SECTORS = 16` generiert, fängt der Sanity-Check in `boot_journal_init` den Boot zwar sauber ab (`BOOT_ERR_INVALID_ARG`), aber das Limit sollte über die `boot_config.h` überschreibbar sein (`#ifndef MAX_WAL_SECTORS`).
- **`libtoob/toob_ota.c`:** `if ((s_bytes_queued % 65536) == 0)`. Der 64-KB-Intervall für OTA-Checkpoints ist hardcodiert. Das ist ein vernünftiger Default, sollte aber zur klaren Lesbarkeit in ein Makro (z. B. `TOOB_OTA_CHECKPOINT_INTERVAL`) ausgelagert werden.
- **`core/boot_delay.c`:** `uint32_t max_sw_limit = (target_ms * 4) + 1000;`. Glitch-Toleranzen als Magic Numbers. Auf extrem ungenauen LSI-Oszillatoren (Low-Speed Internal, typischerweise +/- 50 % Abweichung bei Temperatur-Drift) könnte diese Schranke zu False-Positives führen.

---

### 🛠️ Korrigierte Code-Dateien

Um eine saubere Versionierung und strikte Trennung zu gewährleisten, findest du hier die angepassten Originaldateien in voller Länge. Die Änderungen wurden subtil integriert und über Versionierungs-Tags im Header markiert.

#### Datei: `libtoob/toob_ota.c` (V1.1 - Sector & Checkpoint Alignment Fix)

```c
/**
 * ==============================================================================
 * Toob-Boot libtoob: OTA Daemon Implementation (toob_ota.c)
 * VERSION: 1.1 (Sector-Alignment & Magic-Number Fixes)
 * ==============================================================================
 */

#include "libtoob.h"
#include "libtoob_config_sandbox.h"
#include "toob_internal.h"
#include <string.h>

#ifndef CHIP_STAGING_SLOT_ABS_ADDR
#define CHIP_STAGING_SLOT_ABS_ADDR 0x0
#endif
#ifndef CHIP_STAGING_SLOT_SIZE
#define CHIP_STAGING_SLOT_SIZE 0x0
#endif
#ifndef CHIP_FLASH_WRITE_ALIGNMENT
#define CHIP_FLASH_WRITE_ALIGNMENT CHIP_FLASH_WRITE_ALIGN
#endif

/* OTA Checkpoint Intervall: 64 KB (Konfigurierbar für stark abnutzende Flashs) */
#ifndef TOOB_OTA_CHECKPOINT_INTERVAL
#define TOOB_OTA_CHECKPOINT_INTERVAL 65536
#endif

/* ==============================================================================
 * Cross-Compiler Glitch-Delay (mirrors toob_confirm.c pattern)
 * ==============================================================================
 */
#if defined(__GNUC__) || defined(__clang__)
#define TOOB_OTA_GLITCH_DELAY() __asm__ volatile("nop; nop; nop;")
#elif defined(__ICCARM__)
#include <intrinsics.h>
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    __no_operation();                                                          \
    __no_operation();                                                          \
    __no_operation();                                                          \
  } while (0)
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    __nop();                                                                   \
    __nop();                                                                   \
    __nop();                                                                   \
  } while (0)
#else
#define TOOB_OTA_GLITCH_DELAY()                                                \
  do {                                                                         \
    volatile uint32_t _d = 0;                                                  \
    _d = 1;                                                                    \
    (void)_d;                                                                  \
  } while (0)
#endif

/* ==============================================================================
 * OS-Safe Memory Zeroization (Prevents Compiler DCE on alignment buffer)
 * ==============================================================================
 */
static inline void toob_ota_secure_zeroize(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    p[i] = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ volatile("" : : "g"(ptr) : "memory");
#endif
}

/* ==============================================================================
 * Internal State (File-Scoped, Zero-Allocation)
 * ==============================================================================
 */

typedef enum {
  TOOB_OTA_STATE_IDLE = 0x00,
  TOOB_OTA_STATE_RECEIVING = 0x5A,
  TOOB_OTA_STATE_DONE = 0xA5,
  TOOB_OTA_STATE_ERROR = 0xFF
} toob_ota_state_t;

/* P10: Alignment buffer must be an exact multiple of flash write alignment */
#define TOOB_OTA_BUF_SIZE 256U
_Static_assert(
    TOOB_OTA_BUF_SIZE % CHIP_FLASH_WRITE_ALIGNMENT == 0,
    "OTA alignment buffer must be a multiple of CHIP_FLASH_WRITE_ALIGNMENT");
_Static_assert(TOOB_OTA_BUF_SIZE > 0 && TOOB_OTA_BUF_SIZE <= 4096,
               "OTA alignment buffer must be within sane bounds [1..4096]");

static toob_ota_state_t s_state = TOOB_OTA_STATE_IDLE;
static uint32_t s_write_cursor = 0;
static uint32_t s_total_size = 0;
static uint32_t s_bytes_queued = 0;

/* 8-byte aligned buffer for DMA-safe flash writes (P10) */
static uint8_t s_align_buf[TOOB_OTA_BUF_SIZE] __attribute__((aligned(8)));
static uint32_t s_buf_len = 0;

static bool s_is_verified_stream = false;
static uint8_t s_expected_sha256[32] __attribute__((aligned(8)));
static toob_os_sha256_ctx_t s_sha_ctx __attribute__((aligned(8)));

static void _reset_state(void) {
    toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
    toob_ota_secure_zeroize(s_expected_sha256, sizeof(s_expected_sha256));
    toob_ota_secure_zeroize(&s_sha_ctx, sizeof(s_sha_ctx));
    s_state = TOOB_OTA_STATE_IDLE;
    s_buf_len = 0;
    s_bytes_queued = 0;
    s_write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
    s_is_verified_stream = false;
}

/* ==============================================================================
 * INTERNAL HELPER: Flush alignment buffer to flash with glitch-shielded verify
 * ==============================================================================
 */
static toob_status_t _flush_buffer(uint32_t write_len) {
  if (write_len == 0 || write_len > TOOB_OTA_BUF_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  toob_status_t res =
      toob_os_flash_write(s_write_cursor, s_align_buf, write_len);

  /* Glitch-Resistant Double-Check on flash result */
  volatile uint32_t shield_1 = 0, shield_2 = 0;
  if (res == TOOB_OK) {
    shield_1 = TOOB_OK;
  }
  TOOB_OTA_GLITCH_DELAY();
  if (shield_1 == TOOB_OK && res == TOOB_OK) {
    shield_2 = TOOB_OK;
  }

  if (shield_1 != TOOB_OK || shield_2 != TOOB_OK || shield_1 != shield_2) {
    return (res != TOOB_OK) ? res : TOOB_ERR_FLASH;
  }

  s_write_cursor += write_len;
  return TOOB_OK;
}

/* ==============================================================================
 * PUBLIC API
 * ==============================================================================
 */

static toob_status_t _ota_begin_core(uint32_t total_size, uint8_t image_type) {
  (void)image_type; /* Stored by the SUIT manifest, not needed by the writer */

  if (total_size == 0 || total_size > CHIP_STAGING_SLOT_SIZE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Reject re-entry while a transfer is active */
  if (s_state == TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Erase Flash before write (Erase-Before-Write Hardware Constraint) */
  /* Dynamisches Sector-Alignment über HAL-Konstante statt fix 4096 */
  uint32_t erase_size = total_size;
  uint32_t remainder = erase_size % CHIP_FLASH_MAX_SECTOR_SIZE;
  if (remainder != 0) {
      erase_size += (CHIP_FLASH_MAX_SECTOR_SIZE - remainder);
  }
  if (erase_size > CHIP_STAGING_SLOT_SIZE) {
      erase_size = CHIP_STAGING_SLOT_SIZE;
  }

  toob_status_t res = toob_os_flash_erase(CHIP_STAGING_SLOT_ABS_ADDR, erase_size);
  if (res != TOOB_OK) {
      return res;
  }

  _reset_state();

  s_write_cursor = CHIP_STAGING_SLOT_ABS_ADDR;
  s_total_size = total_size;
  s_state = TOOB_OTA_STATE_RECEIVING;

  return TOOB_OK;
}

toob_status_t toob_ota_begin(uint32_t total_size, uint8_t image_type) {
    return _ota_begin_core(total_size, image_type);
}

toob_status_t toob_ota_begin_verified(uint32_t total_size, uint8_t image_type, const uint8_t expected_sha256[32]) {
    toob_status_t res = _ota_begin_core(total_size, image_type);
    if (res != TOOB_OK) return res;

    if (toob_os_sha256_init(&s_sha_ctx) != TOOB_OK) {
        _reset_state();
        return TOOB_ERR_NOT_SUPPORTED;
    }

    memcpy(s_expected_sha256, expected_sha256, 32);
    s_is_verified_stream = true;
    return TOOB_OK;
}

toob_status_t toob_ota_abort(void) {
    _reset_state();
    return TOOB_OK;
}

toob_status_t toob_ota_resume(uint32_t* resume_offset) {
    if (!resume_offset) return TOOB_ERR_INVALID_ARG;

    if (s_state == TOOB_OTA_STATE_RECEIVING) {
        *resume_offset = s_bytes_queued;
        return TOOB_OK;
    }

    /* Lese Checkpoint aus dem OS Handoff RAM */
    if (toob_validate_handoff() == TOOB_OK) {
        if (toob_handoff_state.resume_offset > 0 && toob_handoff_state.resume_offset <= CHIP_STAGING_SLOT_SIZE) {
            /* Wir resumieren intern den State-Machine Cursor */
            s_write_cursor = CHIP_STAGING_SLOT_ABS_ADDR + toob_handoff_state.resume_offset;
            s_bytes_queued = toob_handoff_state.resume_offset;
            s_state = TOOB_OTA_STATE_RECEIVING;
            *resume_offset = s_bytes_queued;
            return TOOB_OK;
        }
    }

    return TOOB_ERR_NOT_FOUND;
}

toob_status_t toob_ota_process_chunk(const uint8_t *chunk, uint32_t len) {
  toob_status_t final_stat = TOOB_ERR_INVALID_ARG;

  if (s_state != TOOB_OTA_STATE_RECEIVING) {
    return TOOB_ERR_INVALID_ARG;
  }
  if (!chunk || len == 0) {
    return TOOB_ERR_INVALID_ARG;
  }

  if (s_is_verified_stream) {
      if (toob_os_sha256_update(&s_sha_ctx, chunk, len) != TOOB_OK) {
          s_state = TOOB_OTA_STATE_ERROR;
          return TOOB_ERR_NOT_SUPPORTED;
      }
  }

  /* Overflow guard: total bytes received must not exceed declared size */
  if (s_bytes_queued + len < s_bytes_queued) {
    s_state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }
  if (s_bytes_queued + len > s_total_size) {
    s_state = TOOB_OTA_STATE_ERROR;
    return TOOB_ERR_INVALID_ARG;
  }

  uint32_t chunk_pos = 0;

  /* P10 Bounded Loop: chunk_pos strictly advances by at least 1 each iteration */
  while (chunk_pos < len) {
    uint32_t space_left = TOOB_OTA_BUF_SIZE - s_buf_len;
    uint32_t remaining = len - chunk_pos;
    uint32_t to_copy = (remaining < space_left) ? remaining : space_left;

    memcpy(&s_align_buf[s_buf_len], &chunk[chunk_pos], to_copy);
    s_buf_len += to_copy;
    chunk_pos += to_copy;
    s_bytes_queued += to_copy;

    /* Flush when buffer is exactly full (guaranteed aligned) */
    if (s_buf_len == TOOB_OTA_BUF_SIZE) {
      toob_status_t res = _flush_buffer(TOOB_OTA_BUF_SIZE);
      if (res != TOOB_OK) {
        s_state = TOOB_OTA_STATE_ERROR;
        toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
        return res;
      }
      s_buf_len = 0;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);

      /* Write Resume Checkpoint basierend auf konfiguriertem Makro */
      if ((s_bytes_queued % TOOB_OTA_CHECKPOINT_INTERVAL) == 0) {
          toob_wal_entry_payload_t ckpt;
          toob_ota_secure_zeroize(&ckpt, sizeof(ckpt));
          ckpt.magic = TOOB_WAL_ENTRY_MAGIC;
          ckpt.intent = TOOB_WAL_INTENT_DOWNLOAD_CHECKPOINT;
          ckpt.delta_chunk_id = s_bytes_queued;
          (void)toob_wal_naive_append(&ckpt); /* Fire-and-forget, non-critical */
      }
    }
  }

  /* Transition to DONE when all declared bytes have been received */
  if (s_bytes_queued == s_total_size) {
    s_state = TOOB_OTA_STATE_DONE;
  }

  final_stat = TOOB_OK;
  return final_stat;
}

toob_status_t toob_ota_finalize(void) {
  toob_status_t final_stat = TOOB_ERR_INVALID_ARG;

  if (s_state != TOOB_OTA_STATE_DONE) {
    return TOOB_ERR_INVALID_ARG;
  }

  /* Flush residual bytes (pad to CHIP_FLASH_WRITE_ALIGNMENT) */
  if (s_buf_len > 0) {
    uint32_t aligned_len = s_buf_len;
    uint32_t remainder = aligned_len % CHIP_FLASH_WRITE_ALIGNMENT;
    if (remainder != 0) {
      aligned_len += (CHIP_FLASH_WRITE_ALIGNMENT - remainder);
    }

    /* Safety: clamped write must never exceed buffer capacity */
    if (aligned_len > TOOB_OTA_BUF_SIZE) {
      s_state = TOOB_OTA_STATE_ERROR;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
      return TOOB_ERR_INVALID_ARG;
    }

    toob_status_t res = _flush_buffer(aligned_len);
    if (res != TOOB_OK) {
      s_state = TOOB_OTA_STATE_ERROR;
      toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);
      return res;
    }
  }

  toob_ota_secure_zeroize(s_align_buf, TOOB_OTA_BUF_SIZE);

  if (s_is_verified_stream) {
      uint8_t final_hash[32];
      toob_ota_secure_zeroize(final_hash, sizeof(final_hash));
      if (toob_os_sha256_finalize(&s_sha_ctx, final_hash) != TOOB_OK) {
          _reset_state();
          return TOOB_ERR_VERIFY;
      }

      volatile uint8_t diff = 0;
      for (int i = 0; i < 32; i++) {
          diff |= final_hash[i] ^ s_expected_sha256[i];
      }

      toob_ota_secure_zeroize(final_hash, sizeof(final_hash));

      if (diff != 0) {
          _reset_state();
          return TOOB_ERR_VERIFY;
      }
  }

  _reset_state();
  final_stat = toob_set_next_update(CHIP_STAGING_SLOT_ABS_ADDR);
  return final_stat;
}
```

#### Datei: `core/boot_panic.c` (V3.1 - Hang Timeout Fix)

```c
/*
 * ==============================================================================
 * Toob-Boot Core File: boot_panic.c (Mathematical Perfection Revision v3.1)
 * VERSION: 3.1 (Takt-Unabhängige Trap-Logik)
 * ==============================================================================
 */

#include "boot_panic.h"
#include "boot_config_mock.h"
#include "boot_crc32.h"
#include "boot_delay.h"
#include "boot_secure_zeroize.h"
#include <stddef.h>
#include <string.h>

extern uint8_t crypto_arena[BOOT_CRYPTO_ARENA_SIZE];

_Static_assert(
    BOOT_CRYPTO_ARENA_SIZE >= 2048,
    "Crypto Arena muss mindestens 2KB aufweisen für Serial Rescue Puffer");
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK must be high-hamming distance for Glitch-Shielding");

#define PANIC_CHALLENGE_MAX_SIZE 128
#define PANIC_RX_MAX_SIZE 128
#define PANIC_VERIFY_MAX_SIZE 80
#define PANIC_CHUNK_MAX_SIZE                                                   \
  (BOOT_CRYPTO_ARENA_SIZE - PANIC_CHALLENGE_MAX_SIZE - PANIC_RX_MAX_SIZE -     \
   PANIC_VERIFY_MAX_SIZE)

_Static_assert(
    (PANIC_CHALLENGE_MAX_SIZE + PANIC_RX_MAX_SIZE + PANIC_VERIFY_MAX_SIZE +
     PANIC_CHUNK_MAX_SIZE) == BOOT_CRYPTO_ARENA_SIZE,
    "FATAL: Arena Partitioning exceeds total BOOT_CRYPTO_ARENA_SIZE!");

#define CFI_PANIC_INIT 0xAAAAAAAA
#define CFI_AUTH_PASSED 0x55AA55AA

static inline boot_status_t
constant_time_memcmp_32_glitch_safe(const uint8_t *a, const uint8_t *b) {
  uint32_t acc_fwd = 0;
  uint32_t acc_rev = 0;

  for (uint32_t i = 0; i < 32; i++) {
    acc_fwd |= (uint32_t)(a[i] ^ b[i]);
    acc_rev |= (uint32_t)(a[31 - i] ^ b[31 - i]);
  }

  volatile uint32_t flag1 = 0, flag2 = 0;
  if (acc_fwd == 0)
    flag1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (flag1 == BOOT_OK && acc_rev == 0)
    flag2 = BOOT_OK;

  if (flag1 != BOOT_OK || flag2 != BOOT_OK)
    return BOOT_ERR_VERIFY;
  return BOOT_OK;
}

static bool is_fully_erased_constant_time(const uint8_t *buf, size_t len,
                                          uint8_t erased_val) {
  uint32_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint32_t)(buf[i] ^ erased_val);
  }
  return diff == 0;
}

static void send_cobs_frame(const boot_platform_t *platform,
                            const uint8_t *data, size_t len) {
  if (!platform || !platform->console || !platform->console->putchar ||
      len == 0 || !data)
    return;

  platform->console->putchar((char)COBS_MARKER_START);

  size_t ptr = 0;
  while (ptr < len) {
    uint8_t code = 1;
    size_t end = ptr;

    while (end < len && data[end] != 0 && code < 0xFF) {
      end++;
      code++;
    }

    platform->console->putchar((char)code);

    for (size_t i = ptr; i < end; i++) {
      platform->console->putchar((char)data[i]);
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();
    }

    ptr = end;
    if (ptr < len && data[ptr] == 0) {
      ptr++;
    }
  }

  platform->console->putchar((char)COBS_MARKER_END);
  if (platform->console->flush) {
    platform->console->flush();
  }
}

static boot_status_t cobs_decode_in_place(uint8_t *__restrict data, size_t len,
                                          size_t *__restrict out_len) {
  if (!data || !out_len || len == 0)
    return BOOT_ERR_INVALID_ARG;

  size_t read_idx = 0;
  size_t write_idx = 0;

  while (read_idx < len) {
    uint8_t code = data[read_idx++];
    if (code == 0)
      return BOOT_ERR_INVALID_ARG;

    uint8_t copy_len = code - 1;

    volatile uint32_t bounds_shield_1 = 0;
    volatile uint32_t bounds_shield_2 = 0;
    bool is_within_bounds = (len - read_idx >= copy_len);

    if (is_within_bounds)
      bounds_shield_1 = BOOT_OK;
    BOOT_GLITCH_DELAY();
    if (bounds_shield_1 == BOOT_OK && is_within_bounds)
      bounds_shield_2 = BOOT_OK;

    if (bounds_shield_1 != BOOT_OK || bounds_shield_2 != BOOT_OK) {
      return BOOT_ERR_INVALID_ARG;
    }

    for (uint8_t i = 0; i < copy_len; i++) {
      data[write_idx++] = data[read_idx++];
    }

    if (code < 0xFF && read_idx < len) {
      if (write_idx >= len)
        return BOOT_ERR_INVALID_ARG;
      data[write_idx++] = 0x00;
    }
  }

  *out_len = write_idx;

  if (write_idx < len) {
    boot_secure_zeroize(&data[write_idx], len - write_idx);
  }

  return BOOT_OK;
}

_Noreturn static void enter_sos_loop(const boot_platform_t *platform) {
  while (1) {
    if (platform && platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    if (platform && platform->clock && platform->clock->delay_ms)
      boot_delay_with_wdt(platform, 500);
  }
}

_Noreturn void boot_panic(const boot_platform_t *platform,
                          boot_status_t reason) {
  if (!platform || !platform->wdt) {
    while (1) { }
  }

  if (!platform->console || !platform->console->putchar || !platform->crypto ||
      !platform->crypto->random || !platform->flash || !platform->flash->read ||
      !platform->flash->write || !platform->flash->erase_sector ||
      !platform->flash->get_sector_size) {
    enter_sos_loop(platform);
  }

  uint32_t failed_auth_attempts = 0;

session_reset:
  if (platform->console->putchar) {
    platform->console->putchar('P');
    platform->console->putchar('N');
    platform->console->putchar('C');
    if (platform->console->flush)
      platform->console->flush();
  }

  boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

  uint8_t *challenge_buf = crypto_arena;
  uint8_t *rx_buf = challenge_buf + PANIC_CHALLENGE_MAX_SIZE;
  uint8_t *verify_msg = rx_buf + PANIC_RX_MAX_SIZE;
  uint8_t *chunk_buf = verify_msg + PANIC_VERIFY_MAX_SIZE;

  volatile uint32_t panic_cfi = CFI_PANIC_INIT;

  size_t challenge_len = 32;

  if (platform->crypto->random(challenge_buf, 32) != BOOT_OK) {
    enter_sos_loop(platform);
  }

  uint8_t *temp_dslc = chunk_buf;
  size_t dslc_len = 64;

  if (platform->crypto->read_dslc) {
    boot_status_t d_status = platform->crypto->read_dslc(temp_dslc, &dslc_len);
    if (d_status == BOOT_OK && dslc_len > 0) {
      if (dslc_len > 64)
        dslc_len = 64;
      memcpy(challenge_buf + 32, temp_dslc, dslc_len);
    } else {
      dslc_len = 32;
      memset(challenge_buf + 32, 0, 32);
    }
  } else {
    dslc_len = 32;
    memset(challenge_buf + 32, 0, 32);
  }
  boot_secure_zeroize(temp_dslc, 64);
  challenge_len += dslc_len;

  uint32_t current_monotonic = 0;
  if (platform->crypto->read_monotonic_counter) {
    platform->crypto->read_monotonic_counter(&current_monotonic);
  }

  memcpy(challenge_buf + challenge_len, &current_monotonic, sizeof(current_monotonic));
  challenge_len += sizeof(current_monotonic);

  memcpy(challenge_buf + challenge_len, &reason, sizeof(reason));
  challenge_len += sizeof(reason);

  send_cobs_frame(platform, challenge_buf, challenge_len);

  while (1) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE);
    size_t rx_len = 0;
    bool frame_ready = false;

    while (!frame_ready) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar &&
          platform->console->getchar(&c, 100) != BOOT_OK)
        continue;

      if (c == COBS_MARKER_END) {
        if (rx_len > 0)
          frame_ready = true;
      } else {
        if (rx_len < PANIC_RX_MAX_SIZE) {
          rx_buf[rx_len++] = c;
        } else {
          boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE);
          rx_len = 0;
        }
      }
    }

    size_t decoded_len = 0;
    volatile uint32_t auth_eval = 0;

    if (cobs_decode_in_place(rx_buf, rx_len, &decoded_len) == BOOT_OK) {
      if (decoded_len == sizeof(stage15_auth_payload_t)) {

        uint32_t safe_slot_id = 0;
        uint32_t safe_sequence_id = 0;

        memcpy(&safe_slot_id,
               rx_buf + offsetof(stage15_auth_payload_t, slot_id),
               sizeof(uint32_t));
        memcpy(&safe_sequence_id,
               rx_buf + offsetof(stage15_auth_payload_t, sequence_id),
               sizeof(uint32_t));

        const uint8_t *auth_nonce =
            rx_buf + offsetof(stage15_auth_payload_t, nonce);
        const uint8_t *auth_sig =
            rx_buf + offsetof(stage15_auth_payload_t, sig);

        bool time_ok = (safe_sequence_id == current_monotonic + 1);
        bool slot_ok = (safe_slot_id == CHIP_STAGING_SLOT_ID);
        boot_status_t nonce_stat =
            constant_time_memcmp_32_glitch_safe(auth_nonce, challenge_buf);

        volatile uint32_t shield_1 = 0, shield_2 = 0;
        if (time_ok && slot_ok && nonce_stat == BOOT_OK)
          shield_1 = BOOT_OK;
        BOOT_GLITCH_DELAY();
        if (shield_1 == BOOT_OK && time_ok && slot_ok && nonce_stat == BOOT_OK)
          shield_2 = BOOT_OK;

        if (shield_1 == BOOT_OK && shield_2 == BOOT_OK) {
          boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
          memcpy(verify_msg, challenge_buf, 64);
          memcpy(verify_msg + 64, &safe_slot_id, sizeof(uint32_t));
          memcpy(verify_msg + 68, &safe_sequence_id, sizeof(uint32_t));

          uint8_t *root_pubkey = chunk_buf;
          boot_secure_zeroize(root_pubkey, 32);

          if (platform->crypto->read_pubkey &&
              platform->crypto->read_pubkey(root_pubkey, 32, 0) == BOOT_OK) {

            volatile uint32_t auth_shield_1 = 0;
            volatile uint32_t auth_shield_2 = 0;

            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();
            boot_status_t sig_stat = platform->crypto->verify_ed25519(
                verify_msg, 72, auth_sig, root_pubkey);
            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();

            if (sig_stat == BOOT_OK)
              auth_shield_1 = BOOT_OK;
            BOOT_GLITCH_DELAY();
            if (auth_shield_1 == BOOT_OK && sig_stat == BOOT_OK)
              auth_shield_2 = BOOT_OK;

            if (auth_shield_1 == BOOT_OK && auth_shield_2 == BOOT_OK) {
              auth_eval = BOOT_OK;

              if (platform->crypto->advance_monotonic_counter) {
                platform->crypto->advance_monotonic_counter();
                current_monotonic = safe_sequence_id;
              }
              panic_cfi ^= CFI_AUTH_PASSED;
            }
          }
          boot_secure_zeroize(root_pubkey, 32);
        }
        boot_secure_zeroize(verify_msg, PANIC_VERIFY_MAX_SIZE);
      }
    }

    boot_secure_zeroize(rx_buf, PANIC_RX_MAX_SIZE);

    if (auth_eval == BOOT_OK) {
      break;
    } else {
      failed_auth_attempts++;

      uint32_t shifts = (failed_auth_attempts > 10) ? 10 : failed_auth_attempts;
      uint32_t penalty_ms = (1U << shifts) * 100U;

      boot_delay_with_wdt(platform, penalty_ms);
      continue;
    }
  }

  volatile uint32_t cfi_proof_1 = 0, cfi_proof_2 = 0;
  if (panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_1 = BOOT_OK;
  BOOT_GLITCH_DELAY();
  if (cfi_proof_1 == BOOT_OK && panic_cfi == (CFI_PANIC_INIT ^ CFI_AUTH_PASSED))
    cfi_proof_2 = BOOT_OK;

  if (cfi_proof_1 != BOOT_OK || cfi_proof_2 != BOOT_OK) {
    boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);
    enter_sos_loop(platform);
  }

  uint32_t flash_offset = 0;
  uint32_t current_sector_end = CHIP_STAGING_SLOT_ABS_ADDR;
  bool staging_erased = false;

  while (1) {
    send_cobs_frame(platform, (const uint8_t *)"RDY", 3);

    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
    size_t chunk_len = 0;
    bool chunk_received = false;

    while (!chunk_received) {
      if (platform->wdt && platform->wdt->kick)
        platform->wdt->kick();

      uint8_t c;
      if (platform->console->getchar &&
          platform->console->getchar(&c, 500) != BOOT_OK)
        break;

      if (c == COBS_MARKER_END) {
        if (chunk_len > 0)
          chunk_received = true;
      } else {
        if (chunk_len < PANIC_CHUNK_MAX_SIZE) {
          chunk_buf[chunk_len++] = c;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          chunk_len = 0;
        }
      }
    }

    if (!chunk_received)
      continue;

    size_t payload_len = 0;
    if (cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK &&
        payload_len > 0) {

      volatile uint32_t eof_shield_1 = 0, eof_shield_2 = 0;
      if (payload_len == 3 && memcmp(chunk_buf, "EOF", 3) == 0)
        eof_shield_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (eof_shield_1 == BOOT_OK && payload_len == 3 &&
          memcmp(chunk_buf, "EOF", 3) == 0)
        eof_shield_2 = BOOT_OK;

      if (eof_shield_1 == BOOT_OK && eof_shield_2 == BOOT_OK) {
        send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        boot_secure_zeroize(crypto_arena, BOOT_CRYPTO_ARENA_SIZE);

        if (platform->console && platform->console->flush)
          platform->console->flush();
        if (platform->clock && platform->clock->deinit)
          platform->clock->deinit();

        /* Takt-unabhängiger Hardware Trap (Erzwingt HardFault / WDT Reset) */
        void (*trap)(void) = NULL;
        trap();
      }

      uint8_t align = platform->flash->write_align;
      if (align == 0)
        align = 1;

      size_t aligned_len = payload_len;
      uint8_t align_mod = (uint8_t)(payload_len % align);
      if (align_mod != 0) {
        size_t padding = align - align_mod;
        if (UINT32_MAX - aligned_len < padding ||
            aligned_len + padding > PANIC_CHUNK_MAX_SIZE) {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
        memset(chunk_buf + payload_len, platform->flash->erased_value, padding);
        aligned_len += padding;
      }

      volatile uint32_t bounds_flag_1 = 0, bounds_flag_2 = 0;
      bool bounds_ok =
          (aligned_len <= CHIP_APP_SLOT_SIZE) &&
          (flash_offset <= (CHIP_APP_SLOT_SIZE - aligned_len)) &&
          (CHIP_STAGING_SLOT_ABS_ADDR <= (UINT32_MAX - CHIP_APP_SLOT_SIZE));

      if (bounds_ok)
        bounds_flag_1 = BOOT_OK;
      BOOT_GLITCH_DELAY();
      if (bounds_flag_1 == BOOT_OK && bounds_ok)
        bounds_flag_2 = BOOT_OK;

      if (bounds_flag_1 != BOOT_OK || bounds_flag_2 != BOOT_OK) {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }

      uint32_t addr = CHIP_STAGING_SLOT_ABS_ADDR + flash_offset;
      size_t write_end = addr + aligned_len;

      if (write_end < addr) {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }

      while (!staging_erased || current_sector_end < write_end) {
        size_t s_size = 0;
        uint32_t erase_target = !staging_erased ? addr : current_sector_end;

        if (platform->flash->get_sector_size(erase_target, &s_size) ==
            BOOT_OK) {

          bool needs_erase = false;
          uint32_t chk_off = 0;
          uint8_t e_val = platform->flash->erased_value;
          uint8_t *e_buf = verify_msg;
          size_t e_buf_size = PANIC_VERIFY_MAX_SIZE;

          while (chk_off < s_size) {
            uint32_t read_len = (s_size - chk_off > e_buf_size)
                                    ? (uint32_t)e_buf_size
                                    : (uint32_t)(s_size - chk_off);
            if (platform->flash->read(erase_target + chk_off, e_buf,
                                      read_len) != BOOT_OK) {
              needs_erase = true;
              break;
            }
            if (!is_fully_erased_constant_time(e_buf, read_len, e_val)) {
              needs_erase = true;
              break;
            }
            chk_off += read_len;
            if (platform->wdt && platform->wdt->kick)
              platform->wdt->kick();
          }

          if (needs_erase) {
            if (platform->wdt && platform->wdt->suspend_for_critical_section) {
              platform->wdt->suspend_for_critical_section();
            } else if (platform->wdt && platform->wdt->kick) {
              platform->wdt->kick();
            }

            if (platform->flash->erase_sector(erase_target) != BOOT_OK) {
              boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
              goto session_reset;
            }

            if (platform->wdt && platform->wdt->resume) {
              platform->wdt->resume();
            }
          }

          if (UINT32_MAX - erase_target < s_size) {
            boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
            goto session_reset;
          }

          current_sector_end = erase_target + (uint32_t)s_size;
          staging_erased = true;
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
      }

      if (platform->flash->write(addr, chunk_buf, aligned_len) == BOOT_OK) {
        uint8_t *rb_buf = verify_msg;
        size_t rb_buf_size = PANIC_VERIFY_MAX_SIZE;
        uint32_t check_off = 0;
        bool write_ok = true;

        while (check_off < aligned_len) {
          if (platform->wdt && platform->wdt->kick)
            platform->wdt->kick();
          size_t step = (aligned_len - check_off > rb_buf_size)
                            ? rb_buf_size
                            : (aligned_len - check_off);

          if (platform->flash->read(addr + check_off, rb_buf, step) !=
              BOOT_OK) {
            write_ok = false;
            break;
          }

          uint32_t diff = 0;
          for (size_t i = 0; i < step; i++) {
            diff |= (rb_buf[i] ^ chunk_buf[check_off + i]);
          }

          volatile uint32_t v_shield_1 = 0, v_shield_2 = 0;
          if (diff == 0)
            v_shield_1 = BOOT_OK;
          BOOT_GLITCH_DELAY();
          if (v_shield_1 == BOOT_OK && diff == 0)
            v_shield_2 = BOOT_OK;

          if (v_shield_1 != BOOT_OK || v_shield_2 != BOOT_OK) {
            write_ok = false;
            break;
          }

          check_off += (uint32_t)step;
        }

        if (write_ok) {
          flash_offset += (uint32_t)aligned_len;
          send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
        } else {
          boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
          goto session_reset;
        }
      } else {
        boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
        goto session_reset;
      }
    }
    boot_secure_zeroize(chunk_buf, PANIC_CHUNK_MAX_SIZE);
  }
}

void __attribute__((section(".iram1.text"))) toob_ecc_trap(void) {
    while(1) {
        __asm__ volatile("nop");
    }
}

uintptr_t __stack_chk_guard = 0xDEADBEEF;

void __stack_chk_fail(void);

void __stack_chk_fail(void) {
    boot_panic(NULL, BOOT_ERR_ECC_HARDFAULT);
}
```
