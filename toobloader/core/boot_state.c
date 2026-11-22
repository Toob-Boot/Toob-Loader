/**
 * @file boot_state.c
 * @brief Core State-Machine Logic (K2: TBM1 Fixed-Format Manifest)
 *
 * Implements the lifecycle orchestration for the update state machine
 * bridging M-JOURNAL, M-VERIFY, M-SWAP, and M-ROLLBACK.
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Global CFI (Control Flow Integrity): Ein nicht-abelscher Mix-Akkumulator
 * beweist mathematisch, dass JEDER Schritt der State-Machine in exakter
 * Reihenfolge ausgeführt wurde. Verhindert PC-Glitches!
 * 2. Glitch-Resistant Auth-Gating: Nonce-Verifizierung und Handoff-Checks sind
 *    durch Double-Check Patterns gegen Voltage Faults abgesichert.
 * 3. TBM1 Fixed-Format Manifest (K2): Uses deterministic constant-offset field
 *    reads. Supports both Head-TBM1 and Zero-Copy Trailer-TBM1 layouts across
 *    all chip topologies.
 * 4. Zero-Allocation Streaming: Verzicht auf BSS-Bloat durch dynamische
 *    sichere 8-Byte-aligned Partitionierung der bestehenden crypto_arena.
 * 5. P10 Stack Security: Alle Crypto-Sub-Buffer und C-Structs werden vor dem
 *    Return via boot_secure_zeroize restlos vernichtet.
 */

#include "boot_state.h"
#include "boot_features.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_cloud_cmd.h"
#include "boot_ct_utils.h"
#include "boot_decomp.h"
#include "boot_delta.h"
#include "boot_diag.h"
#include "boot_effect.h"
#include "boot_flash_guard.h"
#include "boot_journal.h"
#include "boot_mailbox.h"
#include "boot_merkle.h"
#include "boot_multiimage.h"
#include "boot_panic.h"
#include "boot_rollback.h"
#include "boot_secure_zeroize.h"
#include "boot_swap.h"
#include "boot_tbm1.h"
#include "boot_transport.h"
#include "boot_types.h"
#include "boot_verify.h"
#include <string.h>

/* K6-T2: Events und Aktionen für die Intent-Algebra */
typedef enum {
  EV_NONE,
  EV_CONFIRM_OK,   /* Erfolgreiche OS-Bestätigung (RTC oder Nonce) */
  EV_CRASH,        /* Watchdog/Hardfault oder unresolved CONFIRM_COMMIT */
  EV_CLOUD_UNLOCK, /* TOOB_CMD_UNLOCK */
  EV_CLOUD_LOCK,   /* TOOB_CMD_KILLSWITCH */
  EV_CLOUD_UPDATE  /* TOOB_CMD_FORCE_UPDATE */
} boot_event_t;

typedef enum {
  ACT_NONE,
  ACT_HEAL_COUNTER, /* Reset failure_counter, append NONE, erase Staging Slot */
  ACT_APPEND,       /* Schreibe open_txn->intent = next in den WAL */
  ACT_PANIC_LOCKED, /* Trigger boot_panic mit BOOT_ERR_DEVICE_LOCKED */
  ACT_CRASH_ACCUM   /* Failure counter++, update TMR */
} intent_action_t;

typedef struct {
  wal_intent_t cur;
  boot_event_t ev;
  wal_intent_t next;
  intent_action_t action;
} intent_row_t;

/* Transition table mapped according to design spec */
static const intent_row_t INTENT_TABLE[] = {
    {WAL_INTENT_DEVICE_LOCKED, EV_CONFIRM_OK, WAL_INTENT_DEVICE_LOCKED, ACT_PANIC_LOCKED},
    {WAL_INTENT_DEVICE_LOCKED, EV_CLOUD_UNLOCK, WAL_INTENT_NONE, ACT_APPEND},

    {WAL_INTENT_CONFIRM_COMMIT, EV_CONFIRM_OK, WAL_INTENT_NONE, ACT_HEAL_COUNTER},
    {WAL_INTENT_CONFIRM_COMMIT, EV_CRASH, WAL_INTENT_CONFIRM_COMMIT, ACT_CRASH_ACCUM},

    {WAL_INTENT_TXN_COMMIT, EV_CONFIRM_OK, WAL_INTENT_NONE, ACT_HEAL_COUNTER},
    {WAL_INTENT_TXN_COMMIT, EV_CRASH, WAL_INTENT_TXN_COMMIT, ACT_CRASH_ACCUM},

    {WAL_INTENT_RECOVERY_RESOLVED, EV_CONFIRM_OK, WAL_INTENT_NONE, ACT_HEAL_COUNTER},
    {WAL_INTENT_RECOVERY_RESOLVED, EV_CRASH, WAL_INTENT_RECOVERY_RESOLVED, ACT_CRASH_ACCUM},

    {WAL_INTENT_NONE, EV_CLOUD_LOCK, WAL_INTENT_DEVICE_LOCKED, ACT_APPEND},
    {WAL_INTENT_NONE, EV_CLOUD_UPDATE, WAL_INTENT_UPDATE_PENDING, ACT_APPEND},
    {WAL_INTENT_NONE, EV_CRASH, WAL_INTENT_NONE, ACT_CRASH_ACCUM},
    {WAL_INTENT_TXN_ROLLBACK_PENDING, EV_CRASH, WAL_INTENT_TXN_ROLLBACK_PENDING, ACT_CRASH_ACCUM}};

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define STATE_CFI_SLOT_INIT 0U
#define STATE_CFI_SLOT_1 1U
#define STATE_CFI_SLOT_1_5 2U /* OS Mailbox Fold-In */
#define STATE_CFI_SLOT_2 3U
#define STATE_CFI_SLOT_2_5 4U /* Cloud-Command Evaluation */
#define STATE_CFI_SLOT_2_7 5U /* Lock-State Gate */
#define STATE_CFI_SLOT_3 6U
#define STATE_CFI_SLOT_4 7U
#define STATE_CFI_SLOT_5 8U
#define STATE_CFI_NUM_TOKENS 9U

/* K6-T3: Pipeline Sub-CFI slots */
#define STATE_CFI_SLOT_P1 9U
#define STATE_CFI_SLOT_P1B 10U /* CRC32 pre-check (v2) */
#define STATE_CFI_SLOT_P2 11U
#define STATE_CFI_SLOT_P3 12U
#define STATE_CFI_SLOT_P3B 13U /* Hardware compatibility check (v2) */
#define STATE_CFI_SLOT_P4 14U
#define STATE_CFI_SLOT_P5 15U
#define STATE_CFI_SLOT_P6 16U
#define STATE_CFI_SLOT_P7 17U
#define STATE_CFI_SLOT_P8 18U

/* P5: Arena is now passed explicitly through the call graph */

/* ==============================================================================
 * STATIC HELPERS (Single Responsibility & Glitch Shielded)
 * ==============================================================================
 */

#if TOOB_FEATURE_CLOUD_COMMANDS
static boot_status_t resolve_inactive_slot_bounds(const boot_platform_t *platform,
                                                  uint32_t *out_base, uint32_t *out_size);
#endif

/**
 * @brief Step 2.5: Evaluates the Cloud-Command Flash Slot.
 *
 * Reads CHIP_CLOUD_CMD_SLOT exactly once into the crypto_arena (TOCTOU-safe),
 * verifies the envelope, and dispatches the command intent into the WAL.
 * On empty/invalid slot: Skip-Pfad (no side effect, CFI token still applied).
 */
static boot_status_t handle_cloud_cmd(const boot_platform_t *platform,
                                      wal_entry_payload_t *open_txn,
                                      boot_target_config_t *target_out, boot_cfi_ctx_t *cfi_ctx,
                                      uint8_t slot, uint8_t *arena, size_t arena_len) {
#if !TOOB_FEATURE_CLOUD_COMMANDS
  (void)platform;
  (void)open_txn;
  (void)target_out;
  (void)arena;
  (void)arena_len;
  boot_cfi_step(*cfi_ctx, slot);
  return BOOT_OK;
#else
  (void)arena_len;
  toob_cloud_cmd_t cmd_intent = TOOB_CMD_NOP;

  boot_status_t eval_stat = boot_cloud_cmd_evaluate_flash(platform, arena, &cmd_intent);

  if (eval_stat != BOOT_OK) {
    /* Kein gültiger Command im Slot (leerer Slot, Parse-Error, Replay, etc.).
     * Das ist der Normalfall beim Boot ohne Cloud-Interaktion.
     * Kein Seiteneffekt. Skip-Pfad. */
    boot_cfi_step(*cfi_ctx, slot);
    return BOOT_OK;
  }

  /* Gültiger, kryptografisch verifizierter Command. Dispatch. */
  boot_status_t dispatch_stat = BOOT_OK;

  switch (cmd_intent) {
  case TOOB_CMD_KILLSWITCH: {
    wal_entry_payload_t lock_txn = *open_txn;
    lock_txn.intent = (uint32_t)WAL_INTENT_DEVICE_LOCKED;
    dispatch_stat = boot_journal_append(platform, &lock_txn);
    if (dispatch_stat == BOOT_OK) {
      open_txn->intent = (uint32_t)WAL_INTENT_DEVICE_LOCKED;
    }
    break;
  }
  case TOOB_CMD_UNLOCK: {
    wal_entry_payload_t unlock_txn = *open_txn;
    unlock_txn.intent = (uint32_t)WAL_INTENT_NONE;
    dispatch_stat = boot_journal_append(platform, &unlock_txn);
    if (dispatch_stat == BOOT_OK) {
      open_txn->intent = (uint32_t)WAL_INTENT_NONE;
    }
    break;
  }
  case TOOB_CMD_FORCE_UPDATE: {
    if (open_txn->intent == (uint32_t)WAL_INTENT_DEVICE_LOCKED) {
      break;
    }
    wal_entry_payload_t update_txn;
    boot_secure_zeroize(&update_txn, sizeof(update_txn));
    update_txn.intent = (uint32_t)WAL_INTENT_UPDATE_PENDING;
    uint32_t inactive_base = CHIP_STAGING_SLOT_ABS_ADDR;
    uint32_t inactive_size = CHIP_STAGING_SLOT_SIZE;
    (void)resolve_inactive_slot_bounds(platform, &inactive_base, &inactive_size);
    if (open_txn->intent == (uint32_t)WAL_INTENT_UPDATE_PENDING &&
        open_txn->offset >= inactive_base && (open_txn->offset - inactive_base) < inactive_size) {
      update_txn.offset = open_txn->offset;
    } else {
      update_txn.offset = inactive_base;
    }
    dispatch_stat = boot_journal_append(platform, &update_txn);
    if (dispatch_stat == BOOT_OK) {
      *open_txn = update_txn;
    }
    break;
  }
  case TOOB_CMD_REVOKE: {
    /* Irreversibel: DSLC → 0xFF. Gerät ist danach physisch tot. */
    if (!platform->keystore || !platform->keystore->write_dslc) {
      dispatch_stat = BOOT_ERR_NOT_SUPPORTED;
      break;
    }
    uint8_t revoke_val = 0xFFU;
    boot_status_t burn_stat = platform->keystore->write_dslc(&revoke_val, 1U);
    if (burn_stat != BOOT_OK) {
      dispatch_stat = burn_stat;
      break;
    }
    /* eFuse gebrannt. Gerät ist permanent revoked. dead_halt. */
    boot_terminal_halt(platform, BOOT_ERR_NOT_SUPPORTED, SITE_STATE_LOCK_FAIL);
  }
  case TOOB_CMD_WIPE: {
    wal_entry_payload_t wipe_txn = *open_txn;
    wipe_txn.intent = (uint32_t)WAL_INTENT_NONE;
    dispatch_stat = boot_journal_append(platform, &wipe_txn);
    /* Das OS liest wipe_requested aus dem Handoff und führt den Factory-Reset
     * durch */
    if (dispatch_stat == BOOT_OK) {
      open_txn->intent = (uint32_t)WAL_INTENT_NONE;
      if (target_out != NULL) {
        target_out->wipe_requested = true;
      }
    }
    break;
  }
  case TOOB_CMD_ROTATE_KEY:
  case TOOB_CMD_NOP:
  default:
    break;
  }

  if (dispatch_stat != BOOT_OK) {
    return dispatch_stat;
  }

  /* Cloud-Command Slot löschen (Fire-and-Forget), damit er beim nächsten
   * Boot nicht nochmal evaluiert wird. Fehler hier sind nicht fatal. */
#if defined(CHIP_CLOUD_CMD_SLOT_ABS_ADDR) && defined(CHIP_CLOUD_CMD_SLOT_SIZE) &&                  \
    (CHIP_CLOUD_CMD_SLOT_SIZE > 0)
  if (platform->flash->erase_sector) {
    (void)boot_flash_erase_sector_guarded(platform->flash, CHIP_CLOUD_CMD_SLOT_ABS_ADDR);
  }
#endif

  boot_cfi_step(*cfi_ctx, slot);
  return BOOT_OK;
#endif
}

typedef struct {
  bool valid;
  uint32_t build_number;
  uint16_t fw_major;
  uint16_t fw_minor;
  uint16_t fw_patch;
  uint8_t key_index;
} extracted_app_meta_t;

static void promote_pending_app_meta_on_confirm(wal_tmr_payload_t *tmr, bool *out_changed) {
  if ((tmr->pending_key_index & WAL_TMR_PENDING_META_BIT) != 0U) {
    tmr->app_build_number = tmr->pending_build_number;
    tmr->app_fw_major = tmr->pending_fw_major;
    tmr->app_fw_minor = tmr->pending_fw_minor;
    tmr->app_fw_patch = tmr->pending_fw_patch;
    tmr->active_key_index = (uint8_t)(tmr->pending_key_index & WAL_TMR_KEY_INDEX_MASK);
    tmr->pending_build_number = 0U;
    tmr->pending_fw_major = 0U;
    tmr->pending_fw_minor = 0U;
    tmr->pending_fw_patch = 0U;
    tmr->pending_key_index = 0U;
    if (out_changed != NULL) {
      *out_changed = true;
    }
  }
}

static void clear_pending_app_meta_on_rollback(wal_tmr_payload_t *tmr) {
  tmr->pending_build_number = 0U;
  tmr->pending_fw_major = 0U;
  tmr->pending_fw_minor = 0U;
  tmr->pending_fw_patch = 0U;
  tmr->pending_key_index = 0U;
}

static boot_status_t handle_rollback_flow(const boot_platform_t *platform,
                                          wal_tmr_payload_t *current_tmr,
                                          wal_entry_payload_t *open_txn, bool immediate_crash_rst,
                                          bool *healed_out, boot_target_config_t *target_out,
                                          boot_cfi_ctx_t *cfi_ctx, uint8_t slot, uint8_t *arena,
                                          size_t arena_len) {
  boot_status_t status = BOOT_OK;

  /* P10 Glitch Protection: Evaluierung des Counter-Status + Mid-Rollback WAL Resume */
  bool has_failures = false;
  if (current_tmr->boot_failure_counter > 0U) {
    BOOT_SECURE_REQUIRE(current_tmr->boot_failure_counter > 0U, { return BOOT_ERR_VERIFY; });
    has_failures = true;
  }

  bool rollback_pending = (open_txn->intent == (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING);
  bool rollback_done_unhealed = (open_txn->intent == (uint32_t)WAL_INTENT_TXN_ROLLBACK);

  if (rollback_done_unhealed) {
    target_out->boot_recovery_os = false;
    target_out->rollback_occurred = true;
    target_out->observed_failure_count =
        (current_tmr->boot_failure_counter > 0U) ? current_tmr->boot_failure_counter : 1U;
    boot_diag_set_update_result(3U /* reverted */, 0U);
    clear_pending_app_meta_on_rollback(current_tmr);
    open_txn->intent = (uint32_t)WAL_INTENT_NONE;
    open_txn->delta_chunk_id = 0U;
    boot_secure_zeroize(open_txn->transfer_bitmap, sizeof(open_txn->transfer_bitmap));
    current_tmr->boot_failure_counter = 0U;
    current_tmr->active_nonce_lo = 0U;
    current_tmr->active_nonce_hi = 0U;
    status = boot_journal_update_tmr(platform, current_tmr);
    if (status != BOOT_OK) {
      return status;
    }
    if (healed_out != NULL) {
      *healed_out = true;
    }
#ifdef TOOB_MOCK_TEST
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK) {
      return status;
    }
#endif
  } else if (has_failures || rollback_pending) {

    /* CASE A: Crash happened after TXN_COMMIT or mid-rollback. Revert to prior slot/backup!
     * Hardware watchdog/fault resets revert immediately on the 1st crash; unconfirmed
     * software/power reboots permit up to BOOT_CONFIG_MAX_RETRIES tentative boots
     * before forcing revert so abort()->SW_SYS_RST bootloops cannot brick the device. */
    if (open_txn->intent == (uint32_t)WAL_INTENT_TXN_COMMIT || rollback_pending) {
      if (immediate_crash_rst || rollback_pending ||
          (current_tmr->boot_failure_counter > (uint32_t)BOOT_CONFIG_MAX_RETRIES)) {
        BOOT_SECURE_REQUIRE(
            immediate_crash_rst || rollback_pending ||
                (current_tmr->boot_failure_counter > (uint32_t)BOOT_CONFIG_MAX_RETRIES),
            { return BOOT_ERR_VERIFY; });

        const slot_caps_t *caps = platform->slot_caps;
        if (!caps) {
          caps = boot_get_slot_caps();
        }

        uint8_t committed_slot = 0U;
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
        committed_slot = current_tmr->active_app_slot;
        if (caps != NULL && caps->exec_model != SLOT_EXEC_FIXED) {
          if (CHIP_STAGING_SLOT_SIZE > 0U && open_txn->offset >= CHIP_STAGING_SLOT_ABS_ADDR &&
              (open_txn->offset - CHIP_STAGING_SLOT_ABS_ADDR) < CHIP_STAGING_SLOT_SIZE) {
            committed_slot = 1U;
          } else if (CHIP_APP_SLOT_SIZE > 0U && open_txn->offset >= CHIP_APP_SLOT_ABS_ADDR &&
                     (open_txn->offset - CHIP_APP_SLOT_ABS_ADDR) < CHIP_APP_SLOT_SIZE) {
            committed_slot = 0U;
          }
          if (!rollback_pending) {
            wal_entry_payload_t rb_log = *open_txn;
            rb_log.intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING;
            status = boot_journal_append(platform, &rb_log);
            boot_secure_zeroize(&rb_log, sizeof(rb_log));
            if (status != BOOT_OK) {
              return status;
            }
            open_txn->intent = (uint32_t)WAL_INTENT_TXN_ROLLBACK_PENDING;
          }
        }
#endif

        toob_image_header_t backup_header;
        boot_secure_zeroize(&backup_header, sizeof(backup_header));

        const bool temp_src_used = ((open_txn->_pad_txn & TOOB_WAL_TXN_FLAG_TEMP_SRC) != 0U);
        uint32_t backup_hdr_addr = CHIP_STAGING_SLOT_ABS_ADDR;
#if (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY) &&                                          \
    (TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_FULL) && defined(CHIP_SCRATCH_SLOT_SIZE) &&     \
    (CHIP_SCRATCH_SLOT_SIZE > 0)
        backup_hdr_addr = temp_src_used ? CHIP_STAGING_SLOT_ABS_ADDR : CHIP_SCRATCH_SLOT_ABS_ADDR;
#elif ((TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE) ||                                     \
       (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPOFFSET)) &&                                  \
    defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
        backup_hdr_addr = temp_src_used ? CHIP_SCRATCH_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
#endif
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
        if (caps != NULL && caps->exec_model != SLOT_EXEC_FIXED) {
          backup_hdr_addr =
              (committed_slot == 1U) ? CHIP_APP_SLOT_ABS_ADDR : CHIP_STAGING_SLOT_ABS_ADDR;
        }
#endif

        uint8_t hdr_buf[32] __attribute__((aligned(8)));
        boot_secure_zeroize(hdr_buf, sizeof(hdr_buf));
        status = platform->flash->read(backup_hdr_addr, hdr_buf, sizeof(hdr_buf));
        if (status == BOOT_OK) {
          memcpy(&backup_header, hdr_buf, sizeof(toob_image_header_t));
        }
        boot_secure_zeroize(hdr_buf, sizeof(hdr_buf));

        if (status == BOOT_OK) {
          slot_txn_t txn;
          boot_secure_zeroize(&txn, sizeof(txn));
          txn.src_addr = CHIP_STAGING_SLOT_ABS_ADDR;
          txn.src_region_size = CHIP_STAGING_SLOT_SIZE;
          txn.dest_addr = CHIP_APP_SLOT_ABS_ADDR;
          txn.dest_region_size = CHIP_APP_SLOT_SIZE;
#if defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
#if (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY) &&                                          \
    (TOOB_ONEWAY_BACKUP_MODE == TOOB_ONEWAY_BACKUP_FULL)
          txn.backup_addr = temp_src_used ? CHIP_STAGING_SLOT_ABS_ADDR : CHIP_SCRATCH_SLOT_ABS_ADDR;
          txn.backup_region_size = temp_src_used ? CHIP_STAGING_SLOT_SIZE : CHIP_SCRATCH_SLOT_SIZE;
#elif (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPMOVE) ||                                      \
    (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_SWAPOFFSET)
          if (temp_src_used) {
            txn.src_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
            txn.src_region_size = CHIP_SCRATCH_SLOT_SIZE;
          }
          txn.backup_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
          txn.backup_region_size = CHIP_SCRATCH_SLOT_SIZE;
#else
          txn.backup_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
          txn.backup_region_size = CHIP_SCRATCH_SLOT_SIZE;
#endif
#endif
          txn.length = backup_header.image_size;
          txn.dest_slot = BOOT_DEST_SLOT_APP;
#ifdef TOOB_TMR_HAS_ACTIVE_APP_SLOT
          txn.target_slot_index = committed_slot;
#endif
          txn.src_is_delta_output = temp_src_used;
          txn.src_verified = true;

          status = boot_transport_active()->rollback(platform, caps, &txn, arena, arena_len);
        }
        if (status != BOOT_OK) {
          return status; /* FATAL: Cannot revert Staging image */
        }

        /* Reload TMR in case transport rollback updated active_app_slot in quorum */
        status = boot_journal_get_tmr(platform, current_tmr);
        if (status != BOOT_OK) {
          return status;
        }

#if defined(CHIP_STAGE1A_SIZE) && (CHIP_STAGE1A_SIZE >= 20) && defined(CHIP_STAGE1B_SIZE) &&       \
    (CHIP_STAGE1B_SIZE >= 20)
        {
          uint32_t cur_s1 = (current_tmr->active_stage1_bank == 0U) ? CHIP_STAGE1A_ABS_ADDR
                                                                    : CHIP_STAGE1B_ABS_ADDR;
          uint32_t alt_s1 = (current_tmr->active_stage1_bank == 0U) ? CHIP_STAGE1B_ABS_ADDR
                                                                    : CHIP_STAGE1A_ABS_ADDR;
          toob_image_header_t cur_hdr __attribute__((aligned(8)));
          toob_image_header_t alt_hdr __attribute__((aligned(8)));
          boot_secure_zeroize(&cur_hdr, sizeof(cur_hdr));
          boot_secure_zeroize(&alt_hdr, sizeof(alt_hdr));
          if (platform->flash->read(cur_s1, (uint8_t *)&cur_hdr, sizeof(cur_hdr)) == BOOT_OK &&
              cur_hdr.magic == TOOB_MAGIC_HEADER && cur_hdr.s1.svn_magic == TOOB_STAGE1_SVN_MAGIC &&
              cur_hdr.s1.stage1_svn > current_tmr->stage1_svn &&
              platform->flash->read(alt_s1, (uint8_t *)&alt_hdr, sizeof(alt_hdr)) == BOOT_OK &&
              alt_hdr.magic == TOOB_MAGIC_HEADER && alt_hdr.s1.svn_magic == TOOB_STAGE1_SVN_MAGIC &&
              alt_hdr.s1.stage1_svn >= current_tmr->stage1_svn) {
            current_tmr->active_stage1_bank = (current_tmr->active_stage1_bank == 0U) ? 1U : 0U;
          }
          boot_secure_zeroize(&cur_hdr, sizeof(cur_hdr));
          boot_secure_zeroize(&alt_hdr, sizeof(alt_hdr));
        }
#endif

        target_out->boot_recovery_os = false; /* We will boot the restored baseline OS instead */
        target_out->rollback_occurred = true;
        target_out->observed_failure_count = current_tmr->boot_failure_counter;
        boot_diag_set_update_result(3U /* reverted */, 0U);
        clear_pending_app_meta_on_rollback(current_tmr);
        open_txn->intent = (uint32_t)WAL_INTENT_NONE;
        open_txn->delta_chunk_id = 0U;
        boot_secure_zeroize(open_txn->transfer_bitmap, sizeof(open_txn->transfer_bitmap));

        /* Heal the system completely: Set counter to 0; Step 5 flushes TMR before NONE append */
        current_tmr->boot_failure_counter = 0U;
        current_tmr->active_nonce_lo = 0U;
        current_tmr->active_nonce_hi = 0U;
        status = boot_journal_update_tmr(platform, current_tmr);
        if (status != BOOT_OK) {
          return status;
        }

        if (healed_out != NULL) {
          *healed_out = true;
        }

#ifdef TOOB_MOCK_TEST
        status = boot_journal_append(platform, open_txn);
        if (status != BOOT_OK) {
          return status;
        }
#endif
      }

    } else {
      /* CASE B: Normal OS run with persistent crashes. Evaluate Backoff or
       * Recovery OS. */
      status = boot_rollback_evaluate_os(platform, current_tmr, &target_out->boot_recovery_os);
      if (status != BOOT_OK) {
        return status;
      }
    }
  }

  /* Logik-Bombe gefixt: Bei erfolgreicher Ausführung wird der CFI-Token exakt
   * verrechnet */
  boot_cfi_step(*cfi_ctx, slot);
  return BOOT_OK;
}

/* ==============================================================================
 * P6 UPDATE PIPELINE — Stage-Decomposition of _handle_update_flow
 *
 * Jede Stage hat EINE Aufgabe, nimmt update_ctx_t*, gibt boot_status_t.
 * KEINE Function-Pointer-Tabelle — statisch inline verkettete Sequenz.
 * CFI-Token werden vom Treiber vergeben, nicht von den Stages.
 * ==============================================================================
 */

typedef struct {
  const boot_platform_t *platform;
  uint8_t *arena;
  size_t arena_len;
  wal_entry_payload_t *open_txn;

  /* stage_parse output (TBM1 v2 fixed-format: Head-TBM1 & Zero-Copy Trailer-TBM1) */
  const tbm1_header_t *tbm1;                 /* Pointer into arena (read-only after parse) */
  uint32_t tbm1_total_len;                   /* == tbm1->total_len */
  uint32_t tbm1_flash_addr;                  /* Absolute flash address of TBM1 header */
  uint32_t payload_base_addr;                /* Base address for image[i].data_off */
  uint32_t slot_base_addr;                   /* Containing staging/inactive slot base */
  uint32_t slot_cap_size;                    /* Containing staging/inactive slot capacity */
  uint32_t chunk_hash_offs[TBM1_MAX_IMAGES]; /* Per-image chunk-hash offsets from tbm1_validate */
  bool is_trailer_tbm1;

  /* stage_check_svn & stage_check_binding candidate metadata (committed atomically in handle_update_result) */
  uint32_t extracted_svn;
  bool has_cand_meta;
  uint32_t cand_build_number;
  uint16_t cand_fw_major;
  uint16_t cand_fw_minor;
  uint16_t cand_fw_patch;
  uint8_t cand_key_index;
  uint8_t last_reject_code;
  uint8_t cand_sbom_digest[32];

  /* stage_swap output (P7a) */
  uint32_t extracted_stage1_svn;

  /* stage_route output */
  bool requires_swap;
  bool is_delta;
  bool uses_temp_output;
  uint32_t swap_src_addr;
  uint32_t stream_dest_addr;
  uint32_t stream_dest_size;
  toob_image_header_t staging_header;
  const tbm1_image_desc_t *primary_image; /* Pointer to images[0] in TBM1 */
  const uint8_t *chunk_hash_ptr;          /* Pointer into arena */
  uint32_t chunk_hash_len;
  uint32_t num_chunks;
  uint32_t chunk_size;
  boot_component_t components[3];
  uint32_t comp_count;
} update_ctx_t;

/* --------------------------------------------------------------------------
 * Stage PARSE: Flash-Read → TBM1 v2 Validation via boot_tbm1.c
 *
 * Delegates all structural validation (magic, version, CRC, bounds, regions,
 * images, chunk-hash partitioning) to tbm1_validate(). Supports both classic
 * Head-TBM1 and Zero-Copy Trailer-TBM1 layouts within verified slot bounds.
 * -------------------------------------------------------------------------- */
static boot_status_t resolve_update_slot_bounds(const boot_platform_t *platform,
                                                const wal_entry_payload_t *open_txn,
                                                uint32_t *out_base, uint32_t *out_size) {
  if (!platform || !out_base || !out_size) {
    return BOOT_ERR_INVALID_ARG;
  }

#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
  const slot_caps_t *caps = platform->slot_caps ? platform->slot_caps : boot_get_slot_caps();
  if (caps != NULL && caps->exec_model != SLOT_EXEC_FIXED) {
    if (open_txn != NULL && open_txn->transport_id == TOOB_TRANSPORT_ID_POINTER) {
      if (open_txn->offset >= CHIP_STAGING_SLOT_ABS_ADDR &&
          (open_txn->offset - CHIP_STAGING_SLOT_ABS_ADDR) < CHIP_STAGING_SLOT_SIZE) {
        *out_base = CHIP_STAGING_SLOT_ABS_ADDR;
        *out_size = CHIP_STAGING_SLOT_SIZE;
        return BOOT_OK;
      }
      if (open_txn->offset >= CHIP_APP_SLOT_ABS_ADDR &&
          (open_txn->offset - CHIP_APP_SLOT_ABS_ADDR) < CHIP_APP_SLOT_SIZE) {
        *out_base = CHIP_APP_SLOT_ABS_ADDR;
        *out_size = CHIP_APP_SLOT_SIZE;
        return BOOT_OK;
      }
      return BOOT_ERR_FLASH_BOUNDS;
    }
    uint8_t active_slot = 0U;
    uint32_t active_addr = CHIP_APP_SLOT_ABS_ADDR;
    boot_status_t st = boot_transport_resolve_active(platform, &active_slot, &active_addr);
    if (st != BOOT_OK) {
      return st;
    }
    if (active_slot == 0U) {
      *out_base = CHIP_STAGING_SLOT_ABS_ADDR;
      *out_size = CHIP_STAGING_SLOT_SIZE;
      return BOOT_OK;
    }
    if (active_slot == 1U) {
      *out_base = CHIP_APP_SLOT_ABS_ADDR;
      *out_size = CHIP_APP_SLOT_SIZE;
      return BOOT_OK;
    }
    return BOOT_ERR_INVALID_STATE;
  }
#else
  (void)open_txn;
#endif

  *out_base = CHIP_STAGING_SLOT_ABS_ADDR;
  *out_size = CHIP_STAGING_SLOT_SIZE;
  return BOOT_OK;
}

#if TOOB_FEATURE_CLOUD_COMMANDS
static boot_status_t resolve_inactive_slot_bounds(const boot_platform_t *platform,
                                                  uint32_t *out_base, uint32_t *out_size) {
  return resolve_update_slot_bounds(platform, NULL, out_base, out_size);
}
#endif

static boot_status_t stage_parse(update_ctx_t *ctx) {
#ifdef TOOB_MOCK_TEST
  ctx->tbm1 = (const tbm1_header_t *)ctx->arena;
  ctx->tbm1_total_len = 464U;
  ctx->tbm1_flash_addr = ctx->open_txn->offset;
  ctx->payload_base_addr = ctx->open_txn->offset;
  ctx->slot_base_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  ctx->slot_cap_size = CHIP_STAGING_SLOT_SIZE;
  return BOOT_OK;
#else
  uint32_t req_off = ctx->open_txn->offset;
  boot_status_t slot_st = resolve_update_slot_bounds(ctx->platform, ctx->open_txn,
                                                     &ctx->slot_base_addr, &ctx->slot_cap_size);
  if (slot_st != BOOT_OK) {
    return slot_st;
  }
  if (req_off < ctx->slot_base_addr || (req_off - ctx->slot_base_addr) >= ctx->slot_cap_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  if (UINT32_MAX - ctx->slot_base_addr < ctx->slot_cap_size) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  uint32_t slot_end = ctx->slot_base_addr + ctx->slot_cap_size;
  uint32_t tbm1_addr = req_off;
  size_t rem_in_slot = (size_t)(slot_end - tbm1_addr);
  if (rem_in_slot < (size_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }

  size_t read_len = (ctx->arena_len < rem_in_slot) ? ctx->arena_len : rem_in_slot;

  ctx->platform->wdt->kick();
  boot_status_t read_stat = ctx->platform->flash->read(tbm1_addr, ctx->arena, read_len);
  ctx->platform->wdt->kick();
  if (read_stat != BOOT_OK) {
    return read_stat;
  }

  /* Auto-discover sector-aligned Trailer-TBM1 when offset points to slot base
   * (e.g. TOOB_CMD_FORCE_UPDATE or Serial Rescue on a Zero-Copy Trailer bundle). */
  uint32_t first_magic = 0U;
  memcpy(&first_magic, ctx->arena, sizeof(first_magic));
  if (tbm1_addr == ctx->slot_base_addr && first_magic == TOOB_MAGIC_HEADER) {
    toob_image_header_t raw_hdr;
    memcpy(&raw_hdr, ctx->arena, sizeof(raw_hdr));
    uint32_t sec_mask = CHIP_FLASH_MAX_SECTOR_SIZE - 1U;
    if (raw_hdr.image_size > sizeof(toob_image_header_t) &&
        raw_hdr.image_size < ctx->slot_cap_size && UINT32_MAX - raw_hdr.image_size >= sec_mask) {
      uint32_t cand_off = (raw_hdr.image_size + sec_mask) & ~sec_mask;
      if (cand_off < ctx->slot_cap_size &&
          (ctx->slot_cap_size - cand_off) >= (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN)) {
        tbm1_addr = ctx->slot_base_addr + cand_off;
        rem_in_slot = (size_t)(slot_end - tbm1_addr);
        read_len = (ctx->arena_len < rem_in_slot) ? ctx->arena_len : rem_in_slot;
        ctx->platform->wdt->kick();
        read_stat = ctx->platform->flash->read(tbm1_addr, ctx->arena, read_len);
        ctx->platform->wdt->kick();
        if (read_stat != BOOT_OK) {
          return read_stat;
        }
      }
    }
  }

  tbm1_reject_t rc = tbm1_precheck(ctx->arena, read_len);
  if (rc != TBM1_OK) {
    ctx->last_reject_code = (uint8_t)rc;
    return tbm1_reject_to_boot_status(rc);
  }

  const tbm1_header_t *hdr = (const tbm1_header_t *)ctx->arena;
  bool is_trailer = ((hdr->flags_critical & TBM1_CRIT_TRAILER_LAYOUT) != 0U);
  size_t payload_cap = 0U;

  if (is_trailer) {
    if (tbm1_addr <= ctx->slot_base_addr) {
      ctx->last_reject_code = (uint8_t)TBM1_BAD_PAYLOAD_LAYOUT;
      return BOOT_ERR_INVALID_ARG;
    }
    payload_cap = (size_t)(tbm1_addr - ctx->slot_base_addr);
    ctx->payload_base_addr = ctx->slot_base_addr;
  } else {
    payload_cap = rem_in_slot;
    ctx->payload_base_addr = tbm1_addr;
  }

  rc = tbm1_validate(ctx->arena, read_len, payload_cap, ctx->chunk_hash_offs);
  if (rc != TBM1_OK) {
    ctx->last_reject_code = (uint8_t)rc;
    return tbm1_reject_to_boot_status(rc);
  }

  ctx->tbm1 = hdr;
  ctx->tbm1_total_len = hdr->total_len;
  ctx->tbm1_flash_addr = tbm1_addr;
  ctx->is_trailer_tbm1 = is_trailer;
  ctx->open_txn->offset = tbm1_addr;
  return BOOT_OK;
#endif
}

/* --------------------------------------------------------------------------
 * Stage VERIFY ENVELOPE: Ed25519/PQC Signaturverifikation (Glitch-gehärtet)
 * -------------------------------------------------------------------------- */
static boot_status_t stage_verify_envelope(update_ctx_t *ctx) {
#ifdef TOOB_MOCK_TEST
  boot_verify_envelope_t mock_envelope = {.manifest_flash_addr = ctx->open_txn->offset,
                                          .manifest_size = 400U,
                                          .signature_ed25519 = ctx->arena + 400U,
                                          .key_index = 0U,
#if TOOB_PQC_ENABLED
                                          .pqc_hybrid_active = false
#endif
  };
  return boot_verify_manifest_envelope(ctx->platform, &mock_envelope, ctx->arena, ctx->arena_len);
#else
  /* Ed25519 signature is located at the very end of the bounded TBM1 block */
  const uint8_t *sig_ptr = ctx->arena + ctx->tbm1_total_len - TBM1_SIG_LEN;

#if TOOB_PQC_ENABLED
  const tbm1_region_t *pqc_sig = tbm1_find_region(ctx->tbm1, TBM1_REGION_PQC_SIGNATURE);
  const tbm1_region_t *pqc_key = tbm1_find_region(ctx->tbm1, TBM1_REGION_PQC_PUBKEY);
#endif

  boot_verify_envelope_t envelope = {
      .manifest_flash_addr = ctx->tbm1_flash_addr,
      .manifest_size = tbm1_signed_len(ctx->tbm1),
      .signature_ed25519 = sig_ptr,
      .key_index = ctx->tbm1->key_index,
#if TOOB_PQC_ENABLED
      .pqc_hybrid_active = (pqc_sig != NULL && pqc_key != NULL),
      .signature_pqc = (pqc_sig != NULL) ? ctx->arena + pqc_sig->off : NULL,
      .signature_pqc_len = (pqc_sig != NULL) ? pqc_sig->len : 0,
      .pubkey_pqc = (pqc_key != NULL) ? ctx->arena + pqc_key->off : NULL,
      .pubkey_pqc_len = (pqc_key != NULL) ? pqc_key->len : 0,
#endif
  };

  boot_status_t verify_status =
      boot_verify_manifest_envelope(ctx->platform, &envelope, ctx->arena, ctx->arena_len);

  /* CFI Glitch-Guard: Krypto-Resultat doppelt absichern */
  bool envelope_ok = (verify_status == BOOT_OK);
  if (!envelope_ok) {
    return BOOT_ERR_VERIFY;
  }

  BOOT_SECURE_REQUIRE(verify_status == BOOT_OK, {
    boot_terminal_halt(ctx->platform, BOOT_ERR_VERIFY, SITE_STATE_CFI_MISMATCH);
  });

  return BOOT_OK;
#endif
}

/* --------------------------------------------------------------------------
 * Stage CHECK SVN: Anti-Rollback Verifikation gegen eFuse-Epoch
 * -------------------------------------------------------------------------- */
static boot_status_t stage_check_svn(update_ctx_t *ctx) {
  ctx->extracted_svn = ctx->tbm1->svn;
  return boot_rollback_verify_svn(ctx->platform, ctx->extracted_svn, ROLLBACK_TARGET_APP);
}

/* stage_check_compat removed — HW compatibility is now part of
 * tbm1_validate_images() in boot_tbm1.c (compile-time device identity). */

/* --------------------------------------------------------------------------
 * Stage CHECK BINDING: Device-ID DSLC Match + EU-CRA SBOM Extraction
 * -------------------------------------------------------------------------- */
static boot_status_t stage_check_binding(update_ctx_t *ctx) {
  /* Device-ID Binding (only if flag is set and binding region exists) */
  if (ctx->tbm1->flags_info & TBM1_INFO_DEVICE_BIND) {
    const tbm1_region_t *bind_reg = tbm1_find_region(ctx->tbm1, TBM1_REGION_DEVICE_BIND);
    if (!bind_reg || bind_reg->len != 32) {
      return BOOT_ERR_INVALID_ARG;
    }

    uint8_t dslc_buf[32] __attribute__((aligned(8)));
    size_t dslc_len = 32;
    if (!ctx->platform->keystore || !ctx->platform->keystore->read_dslc ||
        ctx->platform->keystore->read_dslc(dslc_buf, &dslc_len) != BOOT_OK) {
      return BOOT_ERR_NOT_SUPPORTED;
    }

    const uint8_t *bind_ptr = ctx->arena + bind_reg->off;
    boot_status_t bind_st = constant_time_memcmp_glitch_safe(bind_ptr, dslc_buf, 32);
    boot_secure_zeroize(dslc_buf, sizeof(dslc_buf));
    if (bind_st != BOOT_OK) {
      return BOOT_ERR_VERIFY;
    }
  }

  /* Snapshot candidate security metadata; committed to boot_diag strictly at
   * pipeline commit point in handle_update_result (TDR1-03). */
  ctx->has_cand_meta = true;
  ctx->cand_key_index = ctx->tbm1->key_index;
  ctx->cand_build_number = ctx->tbm1->build_number;
  ctx->cand_fw_major = ctx->tbm1->fw_ver_major;
  ctx->cand_fw_minor = ctx->tbm1->fw_ver_minor;
  ctx->cand_fw_patch = ctx->tbm1->fw_ver_patch;
  memcpy(ctx->cand_sbom_digest, ctx->tbm1->sbom_digest, sizeof(ctx->cand_sbom_digest));
  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Stage ROUTE: Staging Header → Cross-Chip Raw/Decomp/Delta Branching
 * -------------------------------------------------------------------------- */
static boot_status_t stage_route(update_ctx_t *ctx) {
  uint32_t inactive_base = 0U;
  uint32_t inactive_size = 0U;
  boot_status_t slot_st =
      resolve_update_slot_bounds(ctx->platform, ctx->open_txn, &inactive_base, &inactive_size);
  if (slot_st != BOOT_OK) {
    return slot_st;
  }

  /* HIGH-22: Enforce that open_txn->offset lies strictly within the currently inactive slot */
#ifdef TOOB_MOCK_TEST
  if (ctx->open_txn->offset != 0U)
#endif
  {
    bool off_ok = (ctx->open_txn->offset >= inactive_base) &&
                  ((ctx->open_txn->offset - inactive_base) < inactive_size);
    BOOT_SECURE_REQUIRE(off_ok, { return BOOT_ERR_FLASH_BOUNDS; });
  }

  ctx->primary_image = &ctx->tbm1->images[0];
  ctx->chunk_hash_ptr = ctx->arena + ctx->chunk_hash_offs[0];
  const tbm1_region_t *hash_reg = tbm1_find_region(ctx->tbm1, TBM1_REGION_CHUNK_HASHES);
  ctx->num_chunks = ctx->primary_image->num_chunks;
  ctx->chunk_size = ctx->primary_image->chunk_size;
#ifdef TOOB_MOCK_TEST
  ctx->chunk_hash_len = hash_reg ? hash_reg->len : 0U;
#else
  if (hash_reg == NULL || ctx->num_chunks > (hash_reg->len / BOOT_MERKLE_HASH_LEN)) {
    return BOOT_ERR_INVALID_ARG;
  }
  ctx->chunk_hash_len = ctx->num_chunks * BOOT_MERKLE_HASH_LEN;
#endif
  ctx->is_delta = (ctx->primary_image->delta_alg == TBM1_DELTA_TDS1);
  bool is_comp = (ctx->primary_image->compression_alg == TBM1_COMP_HEATSHRINK);

  /* Reject unknown compression or delta algorithms */
  if ((ctx->primary_image->compression_alg != TBM1_COMP_NONE && !is_comp) ||
      (ctx->primary_image->delta_alg != TBM1_DELTA_NONE && !ctx->is_delta)) {
    return BOOT_ERR_NOT_SUPPORTED;
  }

  if (UINT32_MAX - ctx->payload_base_addr < ctx->primary_image->data_off) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
  uint32_t img_data_addr = ctx->payload_base_addr + ctx->primary_image->data_off;
#ifndef TOOB_MOCK_TEST
  if (img_data_addr < inactive_base || (img_data_addr - inactive_base) >= inactive_size ||
      ctx->primary_image->stored_size > inactive_size - (img_data_addr - inactive_base)) {
    return BOOT_ERR_FLASH_BOUNDS;
  }
#endif

  if (ctx->is_delta || is_comp) {
#if defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
    /* Scratch-bearing topology: stream into dedicated Scratch slot, then swap/copy. */
    ctx->stream_dest_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
    ctx->stream_dest_size = CHIP_SCRATCH_SLOT_SIZE;
    ctx->uses_temp_output = true;
    ctx->requires_swap = true;
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    /* Scratch-less Zero-Copy topology (XIP_REMAP / BANK_SWAP / RELOCATABLE):
     * Stream directly into the base of the inactive bootable slot. Compressed/delta
     * source payload must reside above installed_size to prevent self-overwrite. */
    if (ctx->slot_base_addr == inactive_base) {
      if (img_data_addr < inactive_base ||
          (img_data_addr - inactive_base) < ctx->primary_image->installed_size) {
        return BOOT_ERR_INVALID_ARG;
      }
    }

    ctx->stream_dest_addr = inactive_base;
    ctx->stream_dest_size = inactive_size;
    ctx->uses_temp_output = false;
    ctx->requires_swap = true;
#elif TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY
    /* Scratch-less fixed-slot topology: reject both Delta and Heatshrink so
     * active CHIP_APP_SLOT_ABS_ADDR is never erased before Merkle + Vbat admission. */
    return BOOT_ERR_NOT_SUPPORTED;
#else
    return BOOT_ERR_NOT_SUPPORTED;
#endif

    if (ctx->primary_image->installed_size > ctx->stream_dest_size ||
        ctx->primary_image->installed_size <= sizeof(toob_image_header_t)) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    ctx->swap_src_addr = ctx->stream_dest_addr;
    ctx->staging_header.image_size = ctx->primary_image->installed_size;
  } else {
    ctx->requires_swap = true;
    ctx->uses_temp_output = false;
    ctx->swap_src_addr = img_data_addr;
    boot_secure_zeroize(&ctx->staging_header, sizeof(ctx->staging_header));

#ifdef TOOB_MOCK_TEST
    boot_status_t head_status = ctx->platform->flash->read(
        img_data_addr, (uint8_t *)&ctx->staging_header, sizeof(toob_image_header_t));

    if (head_status != BOOT_OK || ctx->staging_header.magic != TOOB_MAGIC_HEADER) {
      return BOOT_ERR_INVALID_STATE;
    }

    if (ctx->staging_header.image_size > CHIP_APP_SLOT_SIZE) {
      return BOOT_ERR_FLASH_BOUNDS;
    }

    return BOOT_OK;
#else
    if (ctx->open_txn->transport_id != 0U) {
      if (ctx->primary_image->installed_size > CHIP_APP_SLOT_SIZE) {
        return BOOT_ERR_FLASH_BOUNDS;
      }
      if (ctx->primary_image->installed_size <= sizeof(toob_image_header_t)) {
        return BOOT_ERR_INVALID_ARG;
      }
      ctx->staging_header.magic = TOOB_MAGIC_HEADER;
      ctx->staging_header.image_size = ctx->primary_image->installed_size;
    } else {
      boot_status_t head_status = ctx->platform->flash->read(
          img_data_addr, (uint8_t *)&ctx->staging_header, sizeof(toob_image_header_t));

      if (head_status != BOOT_OK || ctx->staging_header.magic != TOOB_MAGIC_HEADER) {
        return BOOT_ERR_INVALID_STATE;
      }

      if (ctx->staging_header.image_size > CHIP_APP_SLOT_SIZE) {
        return BOOT_ERR_FLASH_BOUNDS;
      }

      if (ctx->staging_header.image_size <= sizeof(toob_image_header_t) ||
          ctx->staging_header.image_size != ctx->primary_image->installed_size) {
        return BOOT_ERR_INVALID_ARG;
      }
    }
#endif
  }

  /* Extract secondary components before stage_apply_decomp/delta reuses ctx->arena */
  ctx->comp_count = 0U;
  if (ctx->tbm1 != NULL && ctx->tbm1->image_count > 1U) {
#if !TOOB_FEATURE_MULTIIMAGE
    return BOOT_ERR_NOT_SUPPORTED;
#else
    for (uint8_t i = 1U; i < ctx->tbm1->image_count && i < TBM1_MAX_IMAGES; i++) {
      const tbm1_image_desc_t *sub_img = &ctx->tbm1->images[i];
      if (sub_img->compression_alg != TBM1_COMP_NONE || sub_img->delta_alg != TBM1_DELTA_NONE) {
        return BOOT_ERR_NOT_SUPPORTED;
      }

      boot_secure_zeroize(&ctx->components[ctx->comp_count], sizeof(boot_component_t));
      ctx->components[ctx->comp_count].component_id = (uint32_t)i;
      ctx->components[ctx->comp_count].image_size = sub_img->installed_size;
      ctx->components[ctx->comp_count].staging_offset = sub_img->data_off;
      ctx->components[ctx->comp_count].chunk_hashes_flash_addr =
          ctx->tbm1_flash_addr + ctx->chunk_hash_offs[i];
      ctx->components[ctx->comp_count].chunk_size = sub_img->chunk_size;
      ctx->components[ctx->comp_count].num_chunks = sub_img->num_chunks;

      if (sub_img->target_slot == TBM1_SLOT_NETCORE) {
        ctx->components[ctx->comp_count].target_addr = CHIP_NETCORE_SLOT_ABS_ADDR;
      } else if (sub_img->target_slot == TBM1_SLOT_RECOVERY) {
        /* D0-B: Recovery OS is Immutable (Factory-Locked). Rejects any updates. */
        return BOOT_ERR_NOT_SUPPORTED;
      } else if (sub_img->target_slot == TBM1_SLOT_STAGE1) {
        /* P7a / CRIT-29: Stage-1 Anti-Rollback Gate + signed header binding */
        if (ctx->tbm1->stage1_svn == 0U) {
          return BOOT_ERR_INVALID_ARG;
        }

        boot_status_t svn_st =
            boot_rollback_verify_svn(ctx->platform, ctx->tbm1->stage1_svn, ROLLBACK_TARGET_STAGE1);
        if (svn_st != BOOT_OK) {
          return svn_st;
        }

        if (UINT32_MAX - ctx->payload_base_addr < sub_img->data_off ||
            sub_img->installed_size <= sizeof(toob_image_header_t)) {
          return BOOT_ERR_FLASH_BOUNDS;
        }
        toob_image_header_t s1_stg_hdr __attribute__((aligned(8)));
        boot_secure_zeroize(&s1_stg_hdr, sizeof(s1_stg_hdr));
        if (ctx->platform->flash->read(ctx->payload_base_addr + sub_img->data_off,
                                       (uint8_t *)&s1_stg_hdr, sizeof(s1_stg_hdr)) != BOOT_OK ||
            s1_stg_hdr.magic != TOOB_MAGIC_HEADER ||
            s1_stg_hdr.s1.svn_magic != TOOB_STAGE1_SVN_MAGIC ||
            s1_stg_hdr.s1.stage1_svn != ctx->tbm1->stage1_svn) {
          boot_secure_zeroize(&s1_stg_hdr, sizeof(s1_stg_hdr));
          return BOOT_ERR_VERIFY;
        }
        boot_secure_zeroize(&s1_stg_hdr, sizeof(s1_stg_hdr));

        ctx->extracted_stage1_svn = ctx->tbm1->stage1_svn;

        wal_tmr_payload_t temp_tmr;
        boot_secure_zeroize(&temp_tmr, sizeof(temp_tmr));
        if (boot_journal_get_tmr(ctx->platform, &temp_tmr) == BOOT_OK) {
          ctx->components[ctx->comp_count].target_addr =
              (temp_tmr.active_stage1_bank == 0U) ? CHIP_STAGE1B_ABS_ADDR : CHIP_STAGE1A_ABS_ADDR;
          boot_secure_zeroize(&temp_tmr, sizeof(temp_tmr));
        } else {
          boot_secure_zeroize(&temp_tmr, sizeof(temp_tmr));
          return BOOT_ERR_INVALID_ARG;
        }
      } else {
        return BOOT_ERR_INVALID_ARG;
      }

      ctx->comp_count++;
    }
#endif
  }

  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Stage APPLY DECOMP: Arena-Slicing + Streaming Decompress + Merkle-Verify
 * -------------------------------------------------------------------------- */
static boot_status_t stage_apply_decomp(update_ctx_t *ctx) {
#if !TOOB_FEATURE_DECOMP
  (void)ctx;
  return BOOT_ERR_NOT_SUPPORTED;
#else
  size_t hash_slice_size = (ctx->chunk_hash_len + 7U) & ~((size_t)7U);
  if (hash_slice_size >= ctx->arena_len) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Snapshot descriptor fields before memmove overwrites TBM1 in ctx->arena */
  const uint32_t data_off = ctx->primary_image->data_off;
  const uint32_t stored_size = ctx->primary_image->stored_size;
  const uint32_t installed_size = ctx->primary_image->installed_size;
  const uint32_t chunk_size = ctx->primary_image->chunk_size;
  const uint8_t *chunk_hash_src = ctx->chunk_hash_ptr;
  ctx->primary_image = NULL;
  ctx->chunk_hash_ptr = NULL;
  ctx->tbm1 = NULL;

  uint8_t *hash_arena = ctx->arena;
  uint8_t *decomp_arena = ctx->arena + hash_slice_size;
  size_t decomp_arena_len = ctx->arena_len - hash_slice_size;

  /* Safe for potentially overlapping slices inside ctx->arena */
  memmove(hash_arena, chunk_hash_src, ctx->chunk_hash_len);

  const uint32_t phase = ctx->open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE];
  bool swap_already_started =
      (ctx->open_txn->transport_id != 0U) ||
      (ctx->uses_temp_output && phase != 0U && phase != TOOB_PHASE_STREAM_WRITE);

  if (!swap_already_started) {
    uint32_t comp_src = ctx->payload_base_addr + data_off;
    boot_status_t decomp_stat = boot_decomp_apply(
        ctx->platform, comp_src, stored_size, ctx->stream_dest_addr, ctx->stream_dest_size,
        installed_size, ctx->open_txn, decomp_arena, decomp_arena_len);

    if (decomp_stat != BOOT_OK) {
      boot_secure_zeroize(hash_arena, hash_slice_size);
      return decomp_stat;
    }
  }

  boot_status_t hash_stat = boot_merkle_verify_stream(
      ctx->platform, ctx->stream_dest_addr, installed_size, chunk_size, hash_arena,
      ctx->chunk_hash_len, ctx->num_chunks, decomp_arena, decomp_arena_len);

  boot_secure_zeroize(hash_arena, hash_slice_size);

  if (hash_stat != BOOT_OK) {
    return BOOT_ERR_VERIFY;
  }

  boot_secure_zeroize(&ctx->staging_header, sizeof(ctx->staging_header));
  if (ctx->platform->flash->read(ctx->stream_dest_addr, (uint8_t *)&ctx->staging_header,
                                 sizeof(toob_image_header_t)) != BOOT_OK ||
      ctx->staging_header.magic != TOOB_MAGIC_HEADER ||
      ctx->staging_header.image_size != installed_size) {
    return BOOT_ERR_INVALID_STATE;
  }

  ctx->swap_src_addr = ctx->stream_dest_addr;
  return BOOT_OK;
#endif
}

/* --------------------------------------------------------------------------
 * Stage APPLY DELTA: Arena-Slicing + SDVM + Merkle-Verify des Outputs
 * -------------------------------------------------------------------------- */
static boot_status_t stage_apply_delta(update_ctx_t *ctx) {
#if !TOOB_FEATURE_DELTA
  (void)ctx;
  return BOOT_ERR_NOT_SUPPORTED;
#else
  const uint32_t phase = ctx->open_txn->transfer_bitmap[TOOB_TB_SLOT_PHASE];
  const bool swap_already_started =
      (ctx->open_txn->transport_id != 0U) ||
      (ctx->uses_temp_output && phase != 0U && phase != TOOB_PHASE_STREAM_WRITE);

  /* Delta SVN Gating: verify installed base SVN matches expected delta base */
  if (!swap_already_started && ctx->primary_image->base_svn > 0) {
    boot_status_t base_svn_st =
        boot_rollback_verify_svn(ctx->platform, ctx->primary_image->base_svn, ROLLBACK_TARGET_APP);
    if (base_svn_st != BOOT_OK) {
      return BOOT_ERR_INVALID_STATE; /* Base version mismatch */
    }
    wal_tmr_payload_t base_tmr;
    boot_secure_zeroize(&base_tmr, sizeof(base_tmr));
    if (boot_journal_get_tmr(ctx->platform, &base_tmr) != BOOT_OK) {
      return BOOT_ERR_STATE;
    }
    uint32_t installed_svn = base_tmr.app_svn;
    boot_secure_zeroize(&base_tmr, sizeof(base_tmr));
    if (installed_svn > 0U && ctx->primary_image->base_svn != installed_svn) {
      return BOOT_ERR_DOWNGRADE;
    }
  }

  uint8_t active_slot = 0U;
  uint32_t active_base_addr = CHIP_APP_SLOT_ABS_ADDR;
  (void)boot_transport_resolve_active(ctx->platform, &active_slot, &active_base_addr);
  uint32_t active_base_size = CHIP_APP_SLOT_SIZE;
  if (active_slot == 1U) {
    active_base_size = CHIP_STAGING_SLOT_SIZE;
  }

  /* Bind unsigned staged TDS1 header to Ed25519-signed TBM1 descriptor and
   * installed active slot bounds before any sector erase occurs. */
  uint32_t delta_src = ctx->payload_base_addr + ctx->primary_image->data_off;
  if (!swap_already_started) {
    uint8_t SignedBaseFP[8];
    memcpy(SignedBaseFP, ctx->primary_image->base_fingerprint, sizeof(SignedBaseFP));

    toob_tds_header_t tds_hdr __attribute__((aligned(8)));
    boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
    if (ctx->primary_image->stored_size < (sizeof(toob_tds_header_t) + sizeof(toob_tds_instr_t)) ||
        ctx->platform->flash->read(delta_src, (uint8_t *)&tds_hdr, sizeof(tds_hdr)) != BOOT_OK) {
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      boot_secure_zeroize(SignedBaseFP, sizeof(SignedBaseFP));
      return BOOT_ERR_VERIFY;
    }
    if (tds_hdr.magic != TOOB_TDS_MAGIC ||
        tds_hdr.expected_target_size != ctx->primary_image->installed_size) {
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      boot_secure_zeroize(SignedBaseFP, sizeof(SignedBaseFP));
      return BOOT_ERR_VERIFY;
    }
    /* MED-27: Mandatory signed base_fingerprint binding (non-zero when a base image is referenced) */
    if ((tds_hdr.base_size > 0U || ctx->primary_image->base_svn > 0U) &&
        verify_not_all_zeros_glitch_safe(SignedBaseFP, sizeof(SignedBaseFP)) != BOOT_OK) {
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      boot_secure_zeroize(SignedBaseFP, sizeof(SignedBaseFP));
      return BOOT_ERR_VERIFY;
    }
    if (constant_time_memcmp_glitch_safe(tds_hdr.base_fingerprint, SignedBaseFP,
                                         sizeof(SignedBaseFP)) != BOOT_OK) {
      boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
      boot_secure_zeroize(SignedBaseFP, sizeof(SignedBaseFP));
      return BOOT_ERR_DOWNGRADE;
    }
    boot_secure_zeroize(SignedBaseFP, sizeof(SignedBaseFP));

    if (tds_hdr.base_size > 0U) {
      toob_image_header_t active_hdr __attribute__((aligned(8)));
      boot_secure_zeroize(&active_hdr, sizeof(active_hdr));
      if (ctx->platform->flash->read(active_base_addr, (uint8_t *)&active_hdr,
                                     sizeof(active_hdr)) != BOOT_OK ||
          active_hdr.magic != TOOB_MAGIC_HEADER || active_hdr.image_size > active_base_size ||
          tds_hdr.base_size != active_hdr.image_size) {
        boot_secure_zeroize(&active_hdr, sizeof(active_hdr));
        boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
        return BOOT_ERR_INVALID_STATE;
      }
      active_base_size = active_hdr.image_size;
      boot_secure_zeroize(&active_hdr, sizeof(active_hdr));
    } else {
      active_base_size = 0U;
    }
    boot_secure_zeroize(&tds_hdr, sizeof(tds_hdr));
  }

  size_t hash_slice_size = (ctx->chunk_hash_len + 7U) & ~((size_t)7U);
  if (hash_slice_size >= ctx->arena_len) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Snapshot descriptor fields before memmove overwrites TBM1 in ctx->arena */
  const uint32_t stored_size = ctx->primary_image->stored_size;
  const uint32_t installed_size = ctx->primary_image->installed_size;
  const uint32_t chunk_size = ctx->primary_image->chunk_size;
  const uint8_t *chunk_hash_src = ctx->chunk_hash_ptr;
  ctx->primary_image = NULL;
  ctx->chunk_hash_ptr = NULL;
  ctx->tbm1 = NULL;

  uint8_t *hash_arena = ctx->arena;
  uint8_t *delta_arena = ctx->arena + hash_slice_size;
  size_t delta_arena_len = ctx->arena_len - hash_slice_size;

  memmove(hash_arena, chunk_hash_src, ctx->chunk_hash_len);

  if (!swap_already_started) {
    boot_status_t delta_stat = boot_delta_apply(
        ctx->platform, delta_src, stored_size, ctx->stream_dest_addr, ctx->stream_dest_size,
        active_base_addr, active_base_size, ctx->open_txn, delta_arena, delta_arena_len);

    if (delta_stat != BOOT_OK) {
      boot_secure_zeroize(hash_arena, hash_slice_size);
      return delta_stat;
    }
  }

  boot_status_t hash_stat = boot_merkle_verify_stream(
      ctx->platform, ctx->stream_dest_addr, installed_size, chunk_size, hash_arena,
      ctx->chunk_hash_len, ctx->num_chunks, delta_arena, delta_arena_len);

  boot_secure_zeroize(hash_arena, hash_slice_size);

  if (hash_stat != BOOT_OK) {
    return BOOT_ERR_VERIFY;
  }

  boot_secure_zeroize(&ctx->staging_header, sizeof(ctx->staging_header));
  if (ctx->platform->flash->read(ctx->stream_dest_addr, (uint8_t *)&ctx->staging_header,
                                 sizeof(toob_image_header_t)) != BOOT_OK ||
      ctx->staging_header.magic != TOOB_MAGIC_HEADER ||
      ctx->staging_header.image_size != installed_size) {
    return BOOT_ERR_INVALID_STATE;
  }

  ctx->swap_src_addr = ctx->stream_dest_addr;
  return BOOT_OK;
#endif
}

/* --------------------------------------------------------------------------
 * Stage APPLY RAW: Merkle-Verify des Staging-Slots
 * -------------------------------------------------------------------------- */
static boot_status_t stage_apply_raw(update_ctx_t *ctx) {
#ifndef TOOB_MOCK_TEST
  if (ctx->open_txn->transport_id != 0U) {
    return BOOT_OK;
  }
#endif
  size_t aligned_offset = (ctx->tbm1_total_len + 7U) & ~((size_t)7U);

  if (aligned_offset >= ctx->arena_len) {
    return BOOT_ERR_INVALID_ARG;
  }

  uint8_t *scratch = ctx->arena + aligned_offset;
  size_t scratch_size = ctx->arena_len - aligned_offset;

  if (scratch_size < BOOT_MERKLE_HASH_LEN) {
    return BOOT_ERR_INVALID_ARG;
  }

  boot_secure_zeroize(scratch, scratch_size);
  boot_status_t hash_stat = boot_merkle_verify_stream(
      ctx->platform, ctx->swap_src_addr, ctx->staging_header.image_size, ctx->chunk_size,
      ctx->chunk_hash_ptr, ctx->chunk_hash_len, ctx->num_chunks, scratch, scratch_size);
  boot_secure_zeroize(scratch, scratch_size);

  return hash_stat;
}

/* --------------------------------------------------------------------------
 * Stage SWAP: Multi-Image Deployment + boot_transport_active()->apply
 * -------------------------------------------------------------------------- */
static boot_status_t stage_swap(update_ctx_t *ctx) {
  boot_status_t swap_status = BOOT_OK;

  /* 1. Release TBM1 arena pointers before handing full arena to multiimage/transport */
  ctx->tbm1 = NULL;
  ctx->primary_image = NULL;
  ctx->chunk_hash_ptr = NULL;

  /* 2. Run the energy and wear admission verification */
  wal_tmr_payload_t current_tmr;
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));
  if (boot_journal_get_tmr(ctx->platform, &current_tmr) != BOOT_OK) {
    return BOOT_ERR_STATE;
  }

  uint32_t admit_app_bytes =
      (TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER && !ctx->uses_temp_output)
          ? 0U
          : ctx->staging_header.image_size;

  boot_status_t admit_status =
      boot_effect_admit_or_defer(ctx->platform, &current_tmr, admit_app_bytes, ctx->components,
                                 ctx->comp_count, ctx->requires_swap);
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));
  if (admit_status != BOOT_OK) {
    return admit_status; /* Defer/Counter Exhausted */
  }

  /* 3. Perform physical multi-image writes FIRST (before any volatile XIP MMU
   *    remap alters low flash pages such as Stage 1A at 0x00048000).
   *    CRIT-30: Skip once primary swap transport has started (transport_id != 0)
   *    so post-brownout swap resume never clobbers transfer_bitmap[0] (crc_src). */
  if (ctx->comp_count > 0U && ctx->open_txn->transport_id == 0U) {
#if !TOOB_FEATURE_MULTIIMAGE
    return BOOT_ERR_NOT_SUPPORTED;
#else
    boot_allowed_region_t whitelist[4] = {{CHIP_NETCORE_SLOT_ABS_ADDR, CHIP_NETCORE_SLOT_SIZE},
                                          {CHIP_RECOVERY_OS_ABS_ADDR, CHIP_RECOVERY_OS_SIZE},
                                          {CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE},
                                          {CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE}};
    swap_status = boot_multiimage_apply(ctx->platform, ctx->payload_base_addr, ctx->components,
                                        ctx->comp_count, whitelist, 4, ctx->open_txn, ctx->arena,
                                        ctx->arena_len);
    if (swap_status != BOOT_OK) {
      return swap_status;
    }
#endif
  }

  /* 4. Perform the actual physical swap, copy, or zero-copy pointer commit */
  if (ctx->requires_swap) {
    const slot_caps_t *caps = ctx->platform->slot_caps;
    if (!caps) {
      caps = boot_get_slot_caps();
    }

    uint8_t curr_slot = 0;
    uint32_t curr_addr = 0;
    (void)boot_transport_resolve_active(ctx->platform, &curr_slot, &curr_addr);

    slot_txn_t txn;
    boot_secure_zeroize(&txn, sizeof(txn));
    txn.src_addr = ctx->swap_src_addr;
    if (caps->exec_model != SLOT_EXEC_FIXED) {
      txn.target_slot_index =
          (ctx->slot_base_addr == CHIP_STAGING_SLOT_ABS_ADDR)
              ? 1u
              : ((ctx->slot_base_addr == CHIP_APP_SLOT_ABS_ADDR) ? 0u : (1u - (uint32_t)curr_slot));
    } else {
      txn.target_slot_index = 0u;
    }

    if (txn.target_slot_index == 1u) {
      txn.dest_addr = CHIP_STAGING_SLOT_ABS_ADDR;
      txn.dest_region_size = CHIP_STAGING_SLOT_SIZE;
      txn.dest_slot = BOOT_DEST_SLOT_STAGING;
    } else {
      txn.dest_addr = CHIP_APP_SLOT_ABS_ADDR;
      txn.dest_region_size = CHIP_APP_SLOT_SIZE;
      txn.dest_slot = BOOT_DEST_SLOT_APP;
    }

#if defined(CHIP_SCRATCH_SLOT_SIZE) && (CHIP_SCRATCH_SLOT_SIZE > 0)
    txn.backup_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;
    txn.backup_region_size = CHIP_SCRATCH_SLOT_SIZE;
#endif
    txn.length = ctx->staging_header.image_size;
    txn.src_is_delta_output = ctx->uses_temp_output;
    txn.src_verified = true;

    if (ctx->uses_temp_output) {
      txn.src_region_size = ctx->stream_dest_size;
      if (txn.target_slot_index == 1U) {
        txn.backup_addr = CHIP_APP_SLOT_ABS_ADDR;
        txn.backup_region_size = CHIP_APP_SLOT_SIZE;
      } else {
        txn.backup_addr = CHIP_STAGING_SLOT_ABS_ADDR;
        txn.backup_region_size = CHIP_STAGING_SLOT_SIZE;
      }
      ctx->open_txn->_pad_txn |= TOOB_WAL_TXN_FLAG_TEMP_SRC;
    } else {
      txn.src_region_size = ctx->slot_cap_size;
      ctx->open_txn->_pad_txn &= (uint8_t)~TOOB_WAL_TXN_FLAG_TEMP_SRC;
    }

    swap_status = boot_transport_active()->apply(ctx->platform, caps, &txn, ctx->open_txn,
                                                 ctx->arena, ctx->arena_len);
  }

  return swap_status;
}

/* --------------------------------------------------------------------------
 * Stage COMMIT: WAL TXN_COMMIT + SVN-Übergabe an den TMR
 * -------------------------------------------------------------------------- */
static boot_status_t stage_commit(update_ctx_t *ctx) {
#ifdef TOOB_MOCK_TEST
  wal_entry_payload_t commit_txn = *ctx->open_txn;
  commit_txn.intent = (uint32_t)WAL_INTENT_TXN_COMMIT;
  boot_status_t status = boot_journal_append(ctx->platform, &commit_txn);
  if (status != BOOT_OK) {
    return status;
  }
#endif
  /* Physical WAL_INTENT_TXN_COMMIT append occurs in Step 5 immediately after
   * boot_journal_flush_tmr() commits the updated TMR quorum (app_svn,
   * active_app_slot, active_nonce) so a brownout can never observe TXN_COMMIT
   * paired with stale pre-update TMR state. */
  ctx->open_txn->intent = (uint32_t)WAL_INTENT_TXN_COMMIT;
  return BOOT_OK;
}

static boot_status_t stage_apply_unified(update_ctx_t *ctx) {
  if (ctx->is_delta) {
    return stage_apply_delta(ctx);
  } else if (ctx->primary_image->compression_alg == TBM1_COMP_HEATSHRINK) {
    return stage_apply_decomp(ctx);
  } else {
    return stage_apply_raw(ctx);
  }
}

typedef boot_status_t (*stage_fn_t)(update_ctx_t *ctx);

typedef struct {
  stage_fn_t fn;
  uint8_t cfi_slot;
  bool skippable;
} stage_row_t;

/* K6-T3: Pipeline-Stages als statische Tabelle (R-Block v2: CRC + HW-compat
 * sind jetzt Teil von tbm1_validate in stage_parse — P1B/P3B entfallen) */
static const stage_row_t PIPELINE[] = {
    {stage_parse, STATE_CFI_SLOT_P1, false},     {stage_verify_envelope, STATE_CFI_SLOT_P2, false},
    {stage_check_svn, STATE_CFI_SLOT_P3, false}, {stage_check_binding, STATE_CFI_SLOT_P4, false},
    {stage_route, STATE_CFI_SLOT_P5, false},     {stage_apply_unified, STATE_CFI_SLOT_P6, false},
    {stage_swap, STATE_CFI_SLOT_P7, false},      {stage_commit, STATE_CFI_SLOT_P8, false}};

#define PIPELINE_SIZE (sizeof(PIPELINE) / sizeof(PIPELINE[0]))

static boot_status_t run_pipeline(update_ctx_t *ctx, boot_cfi_ctx_t *cfi) {
  /* CFI Sollmenge dynamisch initialisieren */
  for (size_t i = 0; i < PIPELINE_SIZE; i++) {
    boot_cfi_add_expected(*cfi, PIPELINE[i].cfi_slot);
  }

  for (size_t i = 0; i < PIPELINE_SIZE; i++) {
    boot_status_t status = PIPELINE[i].fn(ctx);
    if (status != BOOT_OK) {
      if (PIPELINE[i].skippable) {
        boot_cfi_step(*cfi, PIPELINE[i].cfi_slot);
        continue;
      }
      return status;
    }
    boot_cfi_step(*cfi, PIPELINE[i].cfi_slot);
  }
  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Error Handler: Smart Error Topology (Reject vs. Propagate)
 * -------------------------------------------------------------------------- */
typedef struct {
  boot_status_t in_error;   /* Eingangsfehler */
  boot_status_t out_status; /* Rückgabewert des Flows */
  wal_intent_t reject_to;   /* Folge-Intent nach Reject */
} err_row_t;

/* K6-T1: Fehlertopologie als Tabelle (erweitert für K2 v2 Fehler-Taxonomie) */
static const err_row_t ERR_TABLE[] = {{BOOT_ERR_VERIFY, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_DOWNGRADE, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_INVALID_ARG, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_FLASH_BOUNDS, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_FLASH_ALIGN, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_INVALID_STATE, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_NOT_FOUND, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_NOT_SUPPORTED, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_MANIFEST_CORRUPT, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_MANIFEST_VERSION, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_MANIFEST_PRODUCT, BOOT_OK, WAL_INTENT_NONE},
                                      {BOOT_ERR_DEFER, BOOT_OK, WAL_INTENT_SLEEP_BACKOFF}};

static boot_status_t handle_update_result(const boot_platform_t *platform,
                                          wal_entry_payload_t *open_txn, update_ctx_t *ctx,
                                          boot_status_t pipeline_status, boot_cfi_ctx_t *cfi_ctx,
                                          uint8_t slot) {

  boot_status_t flow_final_status = pipeline_status;

  if (pipeline_status == BOOT_OK) {
    /* TDR1-03: Commit candidate metadata and APPLIED outcome strictly after swap & commit succeed */
    if (ctx->has_cand_meta) {
      boot_diag_set_security_meta(ctx->extracted_svn, ctx->cand_key_index, ctx->cand_sbom_digest,
                                  ctx->cand_build_number, ctx->cand_fw_major, ctx->cand_fw_minor,
                                  ctx->cand_fw_patch);
    }
    boot_diag_set_update_result(1U /* applied */, 0U /* TBM1_OK */);
    flow_final_status = BOOT_OK;
  } else if (open_txn->transport_id != 0U && pipeline_status != BOOT_ERR_DEFER) {
    /* Once destructive in-place transport has started, never silently discard
     * the WAL resume checkpoint via ERR_TABLE. */
    boot_diag_set_update_result(2U /* rejected */, ctx->last_reject_code);
    boot_diag_set_error(pipeline_status, 0U);
    flow_final_status = pipeline_status;
  } else {
    if (pipeline_status == BOOT_ERR_DEFER) {
      boot_diag_set_update_result(4U /* deferred */, 0U);
    } else {
      boot_diag_set_update_result(2U /* rejected */, ctx->last_reject_code);
      boot_diag_set_error(pipeline_status, 0U);
    }
    /* Suche den Fehler in der ERR_TABLE */
    bool found = false;
    for (size_t i = 0; i < sizeof(ERR_TABLE) / sizeof(ERR_TABLE[0]); i++) {
      if (ERR_TABLE[i].in_error == pipeline_status) {
        /* Kontrollierte Ablehnung: Update verwerfen, kein Bootloop */
        wal_entry_payload_t reject_txn = *open_txn;
        reject_txn.intent = (uint32_t)ERR_TABLE[i].reject_to;

        boot_status_t rej_stat = boot_journal_append(platform, &reject_txn);
        if (rej_stat != BOOT_OK) {
          flow_final_status = rej_stat;
        } else {
          open_txn->intent = (uint32_t)ERR_TABLE[i].reject_to;
          flow_final_status = ERR_TABLE[i].out_status;
        }
        found = true;
        break;
      }
    }
    if (!found) {
      /* Hardware-Fehler -> Propagieren für Panic */
      flow_final_status = pipeline_status;
    }
  }

#ifdef TOOB_MOCK_TEST
  (void)ctx;
#else
  /* K2: TBM1 lives in the arena — zeroize covers all sensitive manifest data */
  if (ctx->tbm1_total_len > 0U && ctx->tbm1_total_len <= ctx->arena_len) {
    boot_secure_zeroize(ctx->arena, ctx->tbm1_total_len);
  }
  ctx->tbm1 = NULL;
#endif

  if (flow_final_status == BOOT_OK) {
    boot_cfi_step(*cfi_ctx, slot);
  }

  return flow_final_status;
}

/* --------------------------------------------------------------------------
 * Pipeline Driver: Flache Sequenz, ein Cleanup-Pfad
 * -------------------------------------------------------------------------- */
static boot_status_t handle_update_flow(const boot_platform_t *platform,
                                        wal_entry_payload_t *open_txn, uint32_t *extracted_svn,
                                        uint32_t *extracted_stage1_svn,
                                        extracted_app_meta_t *extracted_app_meta,
                                        boot_cfi_ctx_t *cfi_ctx, uint8_t slot, uint8_t *arena,
                                        size_t arena_len) {
  if (extracted_app_meta != NULL) {
    boot_secure_zeroize(extracted_app_meta, sizeof(*extracted_app_meta));
  }
  if (open_txn->intent != (uint32_t)WAL_INTENT_UPDATE_PENDING) {
    boot_cfi_step(*cfi_ctx, slot);
    return BOOT_OK;
  }

  update_ctx_t ctx;
  boot_secure_zeroize(&ctx, sizeof(ctx));
  ctx.platform = platform;
  ctx.arena = arena;
  ctx.arena_len = arena_len;
  ctx.open_txn = open_txn;
  ctx.requires_swap = true;

  boot_cfi_ctx_t pipeline_cfi_ctx;
  uint32_t pipe_cfi_seed = boot_cfi_mix_val(cfi_ctx->current_val, 0x5a5a5a5aU);
  boot_cfi_init(pipeline_cfi_ctx, pipe_cfi_seed);

  boot_status_t status = run_pipeline(&ctx, &pipeline_cfi_ctx);

  if (status == BOOT_OK) {
    boot_cfi_require(pipeline_cfi_ctx, {
      status = BOOT_ERR_INVALID_STATE; /* CFI Failure - Attack Trapped! */
    });
  }

  if (status == BOOT_OK) {
    if (extracted_svn != NULL) {
      *extracted_svn = ctx.extracted_svn;
    }
    if (extracted_stage1_svn != NULL) {
      *extracted_stage1_svn = ctx.extracted_stage1_svn;
    }
    if (extracted_app_meta != NULL && ctx.has_cand_meta) {
      extracted_app_meta->valid = true;
      extracted_app_meta->build_number = ctx.cand_build_number;
      extracted_app_meta->fw_major = ctx.cand_fw_major;
      extracted_app_meta->fw_minor = ctx.cand_fw_minor;
      extracted_app_meta->fw_patch = ctx.cand_fw_patch;
      extracted_app_meta->key_index = ctx.cand_key_index;
    }
  }

  boot_status_t res = handle_update_result(platform, open_txn, &ctx, status, cfi_ctx, slot);
  boot_secure_zeroize(&ctx, sizeof(ctx));
  return res;
}

static void ratify_stage1_svn_on_confirm(const boot_platform_t *platform, wal_tmr_payload_t *tmr,
                                         bool *out_changed) {
#if defined(CHIP_STAGE1A_SIZE) && (CHIP_STAGE1A_SIZE >= 20) && defined(CHIP_STAGE1B_SIZE) &&       \
    (CHIP_STAGE1B_SIZE >= 20)
  uint32_t s1_addr =
      (tmr->active_stage1_bank == 0U) ? CHIP_STAGE1A_ABS_ADDR : CHIP_STAGE1B_ABS_ADDR;
  toob_image_header_t s1_hdr __attribute__((aligned(8)));
  boot_secure_zeroize(&s1_hdr, sizeof(s1_hdr));
  if (platform->flash->read(s1_addr, (uint8_t *)&s1_hdr, sizeof(s1_hdr)) == BOOT_OK &&
      s1_hdr.magic == TOOB_MAGIC_HEADER && s1_hdr.s1.svn_magic == TOOB_STAGE1_SVN_MAGIC &&
      s1_hdr.s1.stage1_svn > tmr->stage1_svn) {
    tmr->stage1_svn = s1_hdr.s1.stage1_svn;
    if (out_changed != NULL) {
      *out_changed = true;
    }
  }
  boot_secure_zeroize(&s1_hdr, sizeof(s1_hdr));
#else
  (void)platform;
  (void)tmr;
  (void)out_changed;
#endif
}

static boot_status_t evaluate_transition(const boot_platform_t *platform,
                                         wal_entry_payload_t *open_txn,
                                         wal_tmr_payload_t *current_tmr, boot_event_t event,
                                         boot_target_config_t *target_cfg, uint8_t *arena,
                                         size_t arena_len) {

  (void)target_cfg;
  const intent_row_t *match = NULL;
  for (size_t i = 0; i < sizeof(INTENT_TABLE) / sizeof(INTENT_TABLE[0]); i++) {
    if ((uint32_t)INTENT_TABLE[i].cur == open_txn->intent && INTENT_TABLE[i].ev == event) {
      match = &INTENT_TABLE[i];
      break;
    }
  }

  if (!match) {
    return BOOT_OK; /* No matching transition defined: keep current state, no-op */
  }

  boot_status_t status = BOOT_OK;
  switch (match->action) {
  case ACT_NONE:
    break;
  case ACT_HEAL_COUNTER: {
    bool tmr_changed =
        (current_tmr->boot_failure_counter > 0U || current_tmr->recovery_failure_counter > 0U ||
         current_tmr->active_nonce_lo != 0U || current_tmr->active_nonce_hi != 0U);
    current_tmr->boot_failure_counter = 0U;
    current_tmr->recovery_failure_counter = 0U;
    current_tmr->active_nonce_lo = 0U;
    current_tmr->active_nonce_hi = 0U;
    ratify_stage1_svn_on_confirm(platform, current_tmr, &tmr_changed);
    promote_pending_app_meta_on_confirm(current_tmr, &tmr_changed);
    if (tmr_changed) {
      status = boot_journal_update_tmr(platform, current_tmr);
      if (status != BOOT_OK) {
        return status;
      }
    }
    bool update_still_pending = (open_txn->intent == (uint32_t)WAL_INTENT_UPDATE_PENDING);
    open_txn->intent = (uint32_t)match->next;
    status = boot_journal_append(platform, open_txn);
    if (status != BOOT_OK) {
      return status;
    }

#if TOOB_TRANSPORT_PROVIDER != TOOB_TRANSPORT_POINTER
    /* CRIT-24: Never erase staging if an update is pending or under POINTER */
    if (!update_still_pending) {
      (void)boot_swap_erase_safe(platform, CHIP_STAGING_SLOT_ABS_ADDR, CHIP_STAGING_SLOT_SIZE,
                                 arena, arena_len);
    }
#else
    (void)update_still_pending;
    (void)arena;
    (void)arena_len;
#endif
    break;
  }
  case ACT_APPEND: {
    wal_entry_payload_t next_txn = *open_txn;
    next_txn.intent = (uint32_t)match->next;
    status = boot_journal_append(platform, &next_txn);
    if (status == BOOT_OK) {
      open_txn->intent = (uint32_t)match->next;
    }
    break;
  }
  case ACT_PANIC_LOCKED: {
    (void)boot_journal_flush_tmr(platform);
    boot_journal_set_tmr_defer(false);
    boot_panic(platform, BOOT_ERR_DEVICE_LOCKED);
    return BOOT_ERR_DEVICE_LOCKED;
  }
  case ACT_CRASH_ACCUM: {
    if (current_tmr->boot_failure_counter > BOOT_CONFIG_MAX_RETRIES) {
      if (current_tmr->recovery_failure_counter < UINT32_MAX) {
        current_tmr->recovery_failure_counter++;
      }
    } else {
      if (current_tmr->boot_failure_counter < UINT32_MAX) {
        current_tmr->boot_failure_counter++;
      }
    }
    status = boot_journal_update_tmr(platform, current_tmr);
    break;
  }
  default:
    return BOOT_ERR_INVALID_STATE;
  }
  return status;
}

/* ==============================================================================
 * MAIN BOOT STATE MACHINE (CFI-ORCHESTRATOR)
 * ==============================================================================
 */

boot_status_t boot_state_run(const boot_platform_t *platform, boot_target_config_t *target_out,
                             const uint32_t seal_key[4], uint8_t *arena, size_t arena_len) {
  if (!arena || arena_len < 512) {
    return BOOT_ERR_INVALID_ARG;
  }
  /* P10 Pointer-Guard (Zero-Trust HAL Assumption) */
  if (!platform || !platform->clock || !platform->flash || !platform->crypto ||
      !platform->entropy || !platform->keystore || !platform->wdt || !target_out || !seal_key) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (!platform->clock->get_reset_reason || !platform->flash->read || !platform->entropy->random ||
      !platform->wdt->kick) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Initialize Output Struct entirely to prevent uninitialized memory attacks
   */
  boot_secure_zeroize(target_out, sizeof(boot_target_config_t));

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t state_cfi_seed = 0U;
  (void)boot_random_safe(platform, (uint8_t *)&state_cfi_seed, sizeof(state_cfi_seed));
  boot_cfi_ctx_t state_cfi_ctx;
  boot_cfi_init(state_cfi_ctx, state_cfi_seed);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_1);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_1_5);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_2);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_2_5);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_2_7);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_3);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_4);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_5);

  wal_entry_payload_t open_txn;
  wal_tmr_payload_t current_tmr;
  boot_secure_zeroize(&open_txn, sizeof(open_txn));
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));

  toob_image_header_t app_header;
  boot_secure_zeroize(&app_header, sizeof(app_header));

  boot_status_t core_status = BOOT_OK;

  /* Wurde der Failure-Counter in DIESEM Boot geheilt (Confirm/Recovery)?
   * Verhindert, dass Step 3 den bereits aufgelösten (vergangenen) Crash aus dem
   * reset_reason erneut als frischen EV_CRASH wertet. */
  bool healed_this_boot = false;

  /*
   * ==============================================================================
   * STEP 1 - Journal Initialization, TMR State Retrieval & WAL Reconstruction
   * ==============================================================================
   */
  core_status = boot_journal_init(platform);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  /* HIGH-09: Coalesce in-RAM TMR mutations into at most 1 quorum rotation per boot */
  boot_journal_set_tmr_defer(true);

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_1); /* Proof Step 1 (Journal Init) */

  /* Consume OS Mailbox requests and append folded intents to WAL before reconstruction */
  core_status = boot_mailbox_consume(platform);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  core_status = boot_journal_get_tmr(platform, &current_tmr);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  uint32_t active_net_accum = 0U;
  uint32_t resume_offset = 0U;
  core_status =
      boot_journal_reconstruct_txn(platform, &open_txn, &active_net_accum, &resume_offset);

  if (core_status != BOOT_OK && core_status != BOOT_ERR_STATE) {
    goto state_cleanup;
  }

  if (core_status == BOOT_ERR_STATE) {
    open_txn.intent = (uint32_t)WAL_INTENT_NONE;
    core_status = BOOT_OK; /* Normalize clean state */
  }

  /* Resume safety check (B3): provider validation */
  if (open_txn.intent != (uint32_t)WAL_INTENT_NONE && open_txn.transport_id != 0U) {
    if (boot_transport_by_id(open_txn.transport_id) == NULL) {
      core_status = BOOT_ERR_INVALID_STATE;
      goto state_cleanup;
    }
  }

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_1_5); /* Proof Step 1.5 (Mailbox & Reconstruction) */
  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 2 - Clean-Up / Confirmation Check (Auth Protected)
   * ==============================================================================
   */
  uint64_t combined_nonce =
      ((uint64_t)current_tmr.active_nonce_hi << 32U) | current_tmr.active_nonce_lo;
  bool rtc_confirmed = false;

  if (combined_nonce != 0ULL && platform->confirm && platform->confirm->check_ok) {
    rtc_confirmed = platform->confirm->check_ok(combined_nonce);
  }

  if (open_txn.intent == (uint32_t)WAL_INTENT_UPDATE_PENDING) {
    /* CRIT-24: Cumulative mailbox path (CONFIRM/RECOVERY_RESOLVED + UPDATE_PENDING).
     * Heal failure counters and retire old boot_nonce WITHOUT overwriting open_txn
     * or erasing the newly staged image in CHIP_STAGING_SLOT_ABS_ADDR! */
    wal_entry_payload_t aux_heal;
    bool aux_found = false;
    core_status = boot_journal_reconstruct_aux_heal(platform, &aux_heal, &aux_found);
    if (core_status != BOOT_OK) {
      boot_secure_zeroize(&aux_heal, sizeof(aux_heal));
      goto state_cleanup;
    }
    if (rtc_confirmed || aux_found) {
      bool aux_is_confirm = aux_found && (aux_heal.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT);
      bool aux_is_recovery =
          aux_found && (aux_heal.intent == (uint32_t)WAL_INTENT_RECOVERY_RESOLVED);
      bool auth_ok = (rtc_confirmed && combined_nonce != 0ULL) ||
                     (aux_is_confirm && combined_nonce != 0ULL && aux_heal.expected_nonce != 0ULL &&
                      (aux_heal.expected_nonce ^ combined_nonce) == 0ULL) ||
                     aux_is_recovery;
      if (auth_ok) {
        bool tmr_changed =
            (current_tmr.boot_failure_counter > 0U || current_tmr.recovery_failure_counter > 0U ||
             current_tmr.active_nonce_lo != 0U || current_tmr.active_nonce_hi != 0U);
        current_tmr.boot_failure_counter = 0U;
        current_tmr.recovery_failure_counter = 0U;
        current_tmr.active_nonce_lo = 0U;
        current_tmr.active_nonce_hi = 0U;
        ratify_stage1_svn_on_confirm(platform, &current_tmr, &tmr_changed);
        promote_pending_app_meta_on_confirm(&current_tmr, &tmr_changed);
        if (tmr_changed) {
          core_status = boot_journal_update_tmr(platform, &current_tmr);
          if (core_status != BOOT_OK) {
            boot_secure_zeroize(&aux_heal, sizeof(aux_heal));
            goto state_cleanup;
          }
        }
        healed_this_boot = true;
      }
    }
    boot_secure_zeroize(&aux_heal, sizeof(aux_heal));
  } else if (open_txn.intent != (uint32_t)WAL_INTENT_DEVICE_LOCKED &&
             (open_txn.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT ||
              open_txn.intent == (uint32_t)WAL_INTENT_RECOVERY_RESOLVED || rtc_confirmed)) {

    /* P10 Security: Glitch-Resistente Nonce-Autorisation */
    bool intent_is_confirm = (open_txn.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT);
    bool intent_is_recovery = (open_txn.intent == (uint32_t)WAL_INTENT_RECOVERY_RESOLVED);

    bool auth_ok =
        (rtc_confirmed && combined_nonce != 0ULL) ||
        (intent_is_confirm && combined_nonce != 0ULL && open_txn.expected_nonce != 0ULL &&
         (open_txn.expected_nonce ^ combined_nonce) == 0ULL) ||
        intent_is_recovery;

    volatile uint32_t auth_verdict = BOOT_OK;
    BOOT_SECURE_REQUIRE(auth_ok, { auth_verdict = BOOT_ERR_VERIFY; });

    if (auth_verdict != BOOT_OK) {
      /* MALICIOUS OR CORRUPT AUTHORIZATION! Preserve tentative TXN_COMMIT if an
       * unconfirmed boot nonce is active so a forged confirm never clears tentative state. */
      open_txn.intent =
          (combined_nonce != 0ULL) ? (uint32_t)WAL_INTENT_TXN_COMMIT : (uint32_t)WAL_INTENT_NONE;
    } else {
      if (rtc_confirmed && open_txn.intent == (uint32_t)WAL_INTENT_NONE) {
        open_txn.intent = (uint32_t)WAL_INTENT_CONFIRM_COMMIT;
      }
      core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CONFIRM_OK,
                                        target_out, arena, arena_len);
      if (core_status != BOOT_OK) {
        goto state_cleanup;
      }

      healed_this_boot = true;
    }
  }

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_2); /* Proof Step 2 */

  /*
   * ==============================================================================
   * STEP 2.5 - Cloud-Command Evaluation (Phase 6)
   * ==============================================================================
   * Evaluiert den CHIP_CLOUD_CMD_SLOT. Muss VOR dem Lock-Gate (Step 2.7)
   * laufen, damit ein TOOB_CMD_UNLOCK den Lock aufheben kann.
   */
  core_status = handle_cloud_cmd(platform, &open_txn, target_out, &state_cfi_ctx,
                                 STATE_CFI_SLOT_2_5, arena, arena_len);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }
  (void)boot_journal_get_tmr(platform, &current_tmr);

  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 2.7 - Lock-State Gate (Phase 6)
   * ==============================================================================
   * Wenn das Gerät im Soft-Lock (WAL_INTENT_DEVICE_LOCKED) ist, darf die
   * State-Machine NICHT weiterlaufen. Nur boot_panic mit BOOT_ERR_DEVICE_LOCKED
   * ist erlaubt. Dort wartet Block 3A auf ein UART-Unlock-Envelope.
   */
  BOOT_SECURE_REQUIRE(open_txn.intent != (uint32_t)WAL_INTENT_DEVICE_LOCKED, {
    (void)boot_journal_flush_tmr(platform);
    boot_journal_set_tmr_defer(false);
    boot_panic(platform, BOOT_ERR_DEVICE_LOCKED);
    return BOOT_ERR_DEVICE_LOCKED;
  });

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_2_7); /* Proof: Device is NOT locked */

  /*
   * ==============================================================================
   * STEP 3 - Failure Counter & Recovery Evaluation (M-ROLLBACK)
   * ==============================================================================
   */
  reset_reason_t rst_reason = platform->clock->get_reset_reason();

  /* P7b: WAL-Primary Crash Detection (counts unconfirmed tentative reboots). */
  bool wal_indicates_crash = (open_txn.intent == (uint32_t)WAL_INTENT_CONFIRM_COMMIT ||
                              open_txn.intent == (uint32_t)WAL_INTENT_TXN_COMMIT);
  bool rst_indicates_crash =
      (rst_reason == RESET_REASON_WATCHDOG || rst_reason == RESET_REASON_HARD_FAULT);

  bool is_app_crash =
      wal_indicates_crash ||
      (rst_indicates_crash && open_txn.intent != (uint32_t)WAL_INTENT_UPDATE_PENDING &&
       open_txn.intent != (uint32_t)WAL_INTENT_TXN_BEGIN);

  if (healed_this_boot) {
    is_app_crash = false;
  }

  if (is_app_crash) {
    core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CRASH, target_out,
                                      arena, arena_len);
    if (core_status != BOOT_OK) {
      goto state_cleanup;
    }
  }

  core_status = handle_rollback_flow(
      platform, &current_tmr, &open_txn, (rst_indicates_crash && !healed_this_boot),
      &healed_this_boot, target_out, &state_cfi_ctx, STATE_CFI_SLOT_3, arena, arena_len);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 4 - Update Pipeline (STAGING -> TESTING -> SWAP)
   * ==============================================================================
   */
  uint32_t extracted_svn = 0U;
  uint32_t extracted_stage1_svn = 0U;
  extracted_app_meta_t extracted_app_meta;
  boot_secure_zeroize(&extracted_app_meta, sizeof(extracted_app_meta));
  bool update_was_pending = (open_txn.intent == (uint32_t)WAL_INTENT_UPDATE_PENDING);

  core_status =
      handle_update_flow(platform, &open_txn, &extracted_svn, &extracted_stage1_svn,
                         &extracted_app_meta, &state_cfi_ctx, STATE_CFI_SLOT_4, arena, arena_len);
  if (core_status != BOOT_OK) {
    boot_secure_zeroize(&extracted_app_meta, sizeof(extracted_app_meta));
    goto state_cleanup;
  }

  /* Reload TMR in case transport commit updated active_app_slot in quorum */
  core_status = boot_journal_get_tmr(platform, &current_tmr);
  if (core_status != BOOT_OK) {
    boot_secure_zeroize(&extracted_app_meta, sizeof(extracted_app_meta));
    goto state_cleanup;
  }

  if (update_was_pending && open_txn.intent == (uint32_t)WAL_INTENT_TXN_COMMIT) {
    current_tmr.boot_failure_counter = 0U;
    target_out->observed_failure_count = 0U;
    target_out->rollback_occurred = false;
  }

  if (extracted_app_meta.valid) {
    if (open_txn.intent == (uint32_t)WAL_INTENT_TXN_COMMIT) {
      current_tmr.pending_build_number = extracted_app_meta.build_number;
      current_tmr.pending_fw_major = extracted_app_meta.fw_major;
      current_tmr.pending_fw_minor = extracted_app_meta.fw_minor;
      current_tmr.pending_fw_patch = extracted_app_meta.fw_patch;
      current_tmr.pending_key_index =
          (uint8_t)(WAL_TMR_PENDING_META_BIT |
                    (extracted_app_meta.key_index & WAL_TMR_KEY_INDEX_MASK));
    } else {
      current_tmr.app_build_number = extracted_app_meta.build_number;
      current_tmr.app_fw_major = extracted_app_meta.fw_major;
      current_tmr.app_fw_minor = extracted_app_meta.fw_minor;
      current_tmr.app_fw_patch = extracted_app_meta.fw_patch;
      current_tmr.active_key_index =
          (uint8_t)(extracted_app_meta.key_index & WAL_TMR_KEY_INDEX_MASK);
      clear_pending_app_meta_on_rollback(&current_tmr);
    }
  }
  boot_secure_zeroize(&extracted_app_meta, sizeof(extracted_app_meta));

  if (extracted_svn > current_tmr.app_svn) {
    current_tmr.app_svn = extracted_svn;
  }
  /* P7a / CRIT-29: Switch to newly deployed Stage-1 bank; ratify stage1_svn
   * only once confirmed (or non-tentative) so crashing tentative Stage-1 boots
   * can safely fall back to the previous bank. */
  if (extracted_stage1_svn > 0U) {
    current_tmr.active_stage1_bank = (current_tmr.active_stage1_bank == 0U) ? 1U : 0U;
    if (open_txn.intent != (uint32_t)WAL_INTENT_TXN_COMMIT &&
        extracted_stage1_svn > current_tmr.stage1_svn) {
      current_tmr.stage1_svn = extracted_stage1_svn;
    }
  }

  /*
   * ==============================================================================
   * STEP 5 - Handoff Preparation / Nonce Registration
   * ==============================================================================
   */

  uint8_t resolved_slot = 0U;
  uint32_t resolved_addr = CHIP_APP_SLOT_ABS_ADDR;
  core_status = boot_transport_resolve_active(platform, &resolved_slot, &resolved_addr);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  uint32_t slot_addr = target_out->boot_recovery_os ? CHIP_RECOVERY_OS_ABS_ADDR : resolved_addr;
  target_out->active_slot = resolved_slot;

  core_status =
      platform->flash->read(slot_addr, (uint8_t *)&app_header, sizeof(toob_image_header_t));
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  if (!target_out->boot_recovery_os && app_header.magic != TOOB_MAGIC_HEADER &&
      CHIP_RECOVERY_OS_SIZE > 0U &&
      current_tmr.recovery_failure_counter <= BOOT_CONFIG_MAX_RECOVERY_RETRIES) {
    toob_image_header_t rec_hdr;
    boot_secure_zeroize(&rec_hdr, sizeof(rec_hdr));
    if (platform->flash->read(CHIP_RECOVERY_OS_ABS_ADDR, (uint8_t *)&rec_hdr,
                              sizeof(toob_image_header_t)) == BOOT_OK &&
        rec_hdr.magic == TOOB_MAGIC_HEADER) {
      target_out->boot_recovery_os = true;
      slot_addr = CHIP_RECOVERY_OS_ABS_ADDR;
      app_header = rec_hdr;
    }
    boot_secure_zeroize(&rec_hdr, sizeof(rec_hdr));
  }

  /* Glitch-Proof Magic Header Boundary */
  BOOT_SECURE_REQUIRE(app_header.magic == TOOB_MAGIC_HEADER, {
    core_status = BOOT_ERR_NOT_FOUND;
    goto state_cleanup;
  });

  target_out->proof.image_addr = slot_addr;
  target_out->proof.image_size = app_header.image_size;
  target_out->proof.entry_point = app_header.entry_point;
  target_out->proof.svn = current_tmr.stage1_svn;
  boot_proof_seal(&target_out->proof, seal_key);

  /* CRIT-25: Only newly committed updates require tentative confirmation.
   * Once healed via confirm/recovery, handoff seals as TOOB_STATE_COMMITTED. */
  bool requires_confirmation = false;
  if (open_txn.intent == (uint32_t)WAL_INTENT_TXN_COMMIT) {
    BOOT_SECURE_REQUIRE(open_txn.intent == (uint32_t)WAL_INTENT_TXN_COMMIT, {
      core_status = BOOT_ERR_VERIFY;
      goto state_cleanup;
    });
    requires_confirmation = true;
  }
  target_out->is_tentative_boot = requires_confirmation;

  platform->wdt->kick();

  if (requires_confirmation) {
    core_status =
        boot_random_safe(platform, (uint8_t *)&target_out->generated_nonce, sizeof(uint64_t));
    if (core_status != BOOT_OK) {
      goto state_cleanup;
    }

    current_tmr.active_nonce_lo = (uint32_t)(target_out->generated_nonce & 0xFFFFFFFFU);
    current_tmr.active_nonce_hi = (uint32_t)(target_out->generated_nonce >> 32U);
  } else {
    target_out->generated_nonce = 0ULL;
    current_tmr.active_nonce_lo = 0U;
    current_tmr.active_nonce_hi = 0U;
  }

  core_status = boot_journal_update_tmr(platform, &current_tmr);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  /* HIGH-09: Single 3-sector TMR flush for the entire boot */
  core_status = boot_journal_flush_tmr(platform);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  /* Anchor current terminal/open intent in the head WAL sector (zero erases) */
  if (open_txn.intent != (uint32_t)WAL_INTENT_NONE || healed_this_boot || update_was_pending) {
    core_status = boot_journal_append(platform, &open_txn);
    if (core_status != BOOT_OK) {
      goto state_cleanup;
    }
  }

  target_out->net_search_accum_ms = active_net_accum;
  target_out->resume_offset = resume_offset;

  core_status = boot_transport_reassert(
      platform, target_out->boot_recovery_os ? 0U : target_out->active_slot);
  if (core_status != BOOT_OK) {
    goto state_cleanup;
  }

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_5);

state_cleanup:
  (void)boot_journal_flush_tmr(platform);
  boot_journal_set_tmr_defer(false);
  /* ==============================================================================
   * FINAL GLITCH-DEFENSE GATE (CFI VALIDATION)
   * ==============================================================================
   * Nur wenn der Status bisher legitimerweise OK war, prüfen wir, ob die
   * Pipeline physisch lückenlos bewiesen wurde! Ist sie das nicht, liegt ein
   * Fault-Injection Angriff (PC-Glitch) vor. Hardware-Fehler aus früheren
   * Schritten dürfen durch diesen Check nicht mit BOOT_ERR_INVALID_STATE
   * überschrieben werden!
   */
  if (core_status == BOOT_OK) {
    boot_cfi_require(state_cfi_ctx, {
      core_status = BOOT_ERR_INVALID_STATE; /* CFI Failure - Attack Trapped! */
    });
  }

  /* Secure Fallback: Nulle den Target Output bei Fehlern, damit niemand den PC
   * verbiegt! */
  if (core_status != BOOT_OK) {
    boot_secure_zeroize(target_out, sizeof(boot_target_config_t));
  }

  /* P10 Single-Exit: Vernichte kritische Runtime-Secrets (TMR/WAL-Payloads) vom
   * C-Stack */
  boot_secure_zeroize(&open_txn, sizeof(open_txn));
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));
  boot_secure_zeroize(&app_header, sizeof(app_header));

  return core_status;
}
