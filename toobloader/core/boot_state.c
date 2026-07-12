/**
 * @file boot_state.c
 * @brief Core State-Machine Logic (K2: TBM1 Fixed-Format Manifest)
 *
 * Implements the lifecycle orchestration for the update state machine
 * bridging M-JOURNAL, M-VERIFY, M-SWAP, and M-ROLLBACK.
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Global CFI (Control Flow Integrity): Ein XOR-Akkumulator beweist
 * mathematisch, dass JEDER Schritt der State-Machine ausgeführt wurde.
 * Verhindert PC-Glitches!
 * 2. Glitch-Resistant Auth-Gating: Nonce-Verifizierung und Handoff-Checks sind
 *    durch Double-Check Patterns gegen Voltage Faults abgesichert.
 * 3. TBM1 Fixed-Format Manifest (K2): Replaces zcbor/SUIT grammar parser with
 *    constant-offset field reads. No recursive structures, no state machine,
 *    no pointer sandboxing — all bounds checked at parse time.
 * 4. Zero-Allocation Streaming: Verzicht auf BSS-Bloat durch dynamische
 *    sichere 8-Byte-aligned Partitionierung der bestehenden crypto_arena.
 * 5. P10 Stack Security: Alle Crypto-Sub-Buffer und C-Structs werden vor dem
 *    Return via boot_secure_zeroize restlos vernichtet.
 */

#include "boot_state.h"
#include "boot_fih.h"
#include "generated_boot_config.h"

#include "boot_cloud_cmd.h"
#include "boot_ct_utils.h"
#include "boot_delta.h"
#include "boot_diag.h"
#include "boot_journal.h"
#include "boot_merkle.h"
#include "boot_multiimage.h"
#include "boot_panic.h"
#include "boot_rollback.h"
#include "boot_secure_zeroize.h"
#include "boot_tbm1.h"
#include "boot_swap.h"
#include "boot_effect.h"
#include "boot_types.h"
#include "boot_verify.h"
#include <string.h>

/* K6-T2: Events und Aktionen für die Intent-Algebra */
typedef enum {
    EV_NONE,
    EV_CONFIRM_OK,       /* Erfolgreiche OS-Bestätigung (RTC oder Nonce) */
    EV_CRASH,            /* Watchdog/Hardfault oder unresolved CONFIRM_COMMIT */
    EV_CLOUD_UNLOCK,     /* TOOB_CMD_UNLOCK */
    EV_CLOUD_LOCK,       /* TOOB_CMD_KILLSWITCH */
    EV_CLOUD_UPDATE      /* TOOB_CMD_FORCE_UPDATE */
} boot_event_t;

typedef enum {
    ACT_NONE,
    ACT_HEAL_COUNTER,    /* Reset failure_counter, append NONE, erase Staging Slot */
    ACT_APPEND,          /* Schreibe open_txn->intent = next in den WAL */
    ACT_PANIC_LOCKED,    /* Trigger boot_panic mit BOOT_ERR_DEVICE_LOCKED */
    ACT_CRASH_ACCUM      /* Failure counter++, update TMR */
} intent_action_t;

typedef struct {
    wal_intent_t    cur;
    boot_event_t    ev;
    wal_intent_t    next;
    intent_action_t action;
} intent_row_t;

/* Transition table mapped according to design spec */
static const intent_row_t INTENT_TABLE[] = {
    { WAL_INTENT_DEVICE_LOCKED, EV_CONFIRM_OK,    WAL_INTENT_DEVICE_LOCKED, ACT_PANIC_LOCKED },
    { WAL_INTENT_DEVICE_LOCKED, EV_CLOUD_UNLOCK,  WAL_INTENT_NONE,          ACT_APPEND       },
    
    { WAL_INTENT_CONFIRM_COMMIT,EV_CONFIRM_OK,    WAL_INTENT_NONE,          ACT_HEAL_COUNTER },
    { WAL_INTENT_CONFIRM_COMMIT,EV_CRASH,         WAL_INTENT_CONFIRM_COMMIT, ACT_CRASH_ACCUM  },
    
    { WAL_INTENT_RECOVERY_RESOLVED, EV_CONFIRM_OK,WAL_INTENT_NONE,          ACT_HEAL_COUNTER },
    { WAL_INTENT_RECOVERY_RESOLVED, EV_CRASH,     WAL_INTENT_RECOVERY_RESOLVED, ACT_CRASH_ACCUM},

    { WAL_INTENT_NONE,          EV_CLOUD_LOCK,    WAL_INTENT_DEVICE_LOCKED, ACT_APPEND       },
    { WAL_INTENT_NONE,          EV_CLOUD_UPDATE,  WAL_INTENT_UPDATE_PENDING,ACT_APPEND       },
    { WAL_INTENT_NONE,          EV_CRASH,         WAL_INTENT_NONE,          ACT_CRASH_ACCUM  },
    { WAL_INTENT_TXN_COMMIT,    EV_CRASH,         WAL_INTENT_TXN_COMMIT,    ACT_CRASH_ACCUM  },
    { WAL_INTENT_TXN_ROLLBACK_PENDING, EV_CRASH,  WAL_INTENT_TXN_ROLLBACK_PENDING, ACT_CRASH_ACCUM }
};

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define STATE_CFI_SLOT_INIT   0
#define STATE_CFI_SLOT_1      1
#define STATE_CFI_SLOT_2      2
#define STATE_CFI_SLOT_2_5    3 /* Cloud-Command Evaluation */
#define STATE_CFI_SLOT_2_7    4 /* Lock-State Gate */
#define STATE_CFI_SLOT_3      5
#define STATE_CFI_SLOT_4      6
#define STATE_CFI_SLOT_5      7
#define STATE_CFI_NUM_TOKENS  8

/* K6-T3: Pipeline Sub-CFI slots */
#define STATE_CFI_SLOT_P1     9
#define STATE_CFI_SLOT_P1B    10  /* CRC32 pre-check (v2) */
#define STATE_CFI_SLOT_P2     11
#define STATE_CFI_SLOT_P3     12
#define STATE_CFI_SLOT_P3B    13  /* Hardware compatibility check (v2) */
#define STATE_CFI_SLOT_P4     14
#define STATE_CFI_SLOT_P5     15
#define STATE_CFI_SLOT_P6     16
#define STATE_CFI_SLOT_P7     17
#define STATE_CFI_SLOT_P8     18

/* P5: Arena is now passed explicitly through the call graph */

/* ==============================================================================
 * STATIC HELPERS (Single Responsibility & Glitch Shielded)
 * ==============================================================================
 */



/**
 * @brief Step 2.5: Evaluates the Cloud-Command Flash Slot.
 *
 * Reads CHIP_CLOUD_CMD_SLOT exactly once into the crypto_arena (TOCTOU-safe),
 * verifies the envelope, and dispatches the command intent into the WAL.
 * On empty/invalid slot: Skip-Pfad (no side effect, CFI token still applied).
 */
static boot_status_t _handle_cloud_cmd(const boot_platform_t *platform,
                                       wal_entry_payload_t *open_txn,
                                       boot_target_config_t *target_out,
                                       boot_cfi_ctx_t *cfi_ctx,
                                       uint32_t slot,
                                       uint8_t *arena, size_t arena_len) {
  toob_cloud_cmd_t cmd_intent = TOOB_CMD_NOP;

  boot_status_t eval_stat =
      boot_cloud_cmd_evaluate_flash(platform, arena, &cmd_intent);

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
    lock_txn.intent = WAL_INTENT_DEVICE_LOCKED;
    dispatch_stat = boot_journal_append(platform, &lock_txn);
    if (dispatch_stat == BOOT_OK)
      open_txn->intent = WAL_INTENT_DEVICE_LOCKED;
    break;
  }
  case TOOB_CMD_UNLOCK: {
    wal_entry_payload_t unlock_txn = *open_txn;
    unlock_txn.intent = WAL_INTENT_NONE;
    dispatch_stat = boot_journal_append(platform, &unlock_txn);
    if (dispatch_stat == BOOT_OK)
      open_txn->intent = WAL_INTENT_NONE;
    break;
  }
  case TOOB_CMD_FORCE_UPDATE: {
    wal_entry_payload_t update_txn = *open_txn;
    update_txn.intent = WAL_INTENT_UPDATE_PENDING;
    dispatch_stat = boot_journal_append(platform, &update_txn);
    if (dispatch_stat == BOOT_OK)
      open_txn->intent = WAL_INTENT_UPDATE_PENDING;
    break;
  }
  case TOOB_CMD_REVOKE: {
    /* Irreversibel: DSLC → 0xFF. Gerät ist danach physisch tot. */
    if (!platform->crypto->write_dslc) {
      dispatch_stat = BOOT_ERR_NOT_SUPPORTED;
      break;
    }
    uint8_t revoke_val = 0xFF;
    boot_status_t burn_stat = platform->crypto->write_dslc(&revoke_val, 1);
    if (burn_stat != BOOT_OK) {
      dispatch_stat = burn_stat;
      break;
    }
    /* eFuse gebrannt. Gerät ist permanent revoked. dead_halt. */
    boot_terminal_halt(platform, BOOT_ERR_NOT_SUPPORTED, SITE_STATE_LOCK_FAIL);
  }
  case TOOB_CMD_WIPE: {
    wal_entry_payload_t wipe_txn = *open_txn;
    wipe_txn.intent = WAL_INTENT_NONE;
    dispatch_stat = boot_journal_append(platform, &wipe_txn);
    /* Das OS liest wipe_requested aus dem Handoff und führt den Factory-Reset
     * durch */
    if (dispatch_stat == BOOT_OK && target_out != NULL)
      target_out->wipe_requested = true;
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
  if (platform->flash->erase_sector) {
    (void)platform->flash->erase_sector(CHIP_CLOUD_CMD_SLOT_ABS_ADDR);
  }

  boot_cfi_step(*cfi_ctx, slot);
  return BOOT_OK;
}

static boot_status_t _handle_rollback_flow(const boot_platform_t *platform,
                                           wal_tmr_payload_t *current_tmr,
                                           wal_entry_payload_t *open_txn,
                                           boot_target_config_t *target_out,
                                           boot_cfi_ctx_t *cfi_ctx,
                                           uint32_t slot,
                                           uint8_t *arena, size_t arena_len) {
  boot_status_t status = BOOT_OK;

  /* P10 Glitch Protection: Evaluierung des Counter-Status */
  bool has_failures = false;
  if (current_tmr->boot_failure_counter > 0) {
    BOOT_SECURE_REQUIRE(current_tmr->boot_failure_counter > 0, {
      return BOOT_ERR_VERIFY;
    });
    has_failures = true;
  }

  if (has_failures) {

    /* CASE A: Crash happened exactly after TXN_COMMIT. Revert Staging! */
    if (open_txn->intent == WAL_INTENT_TXN_COMMIT ||
        open_txn->intent == WAL_INTENT_TXN_ROLLBACK_PENDING) {
      status = boot_rollback_trigger_revert(platform, arena, arena_len);
      if (status != BOOT_OK)
        return status; /* FATAL: Cannot revert Staging image */

      target_out->boot_recovery_os =
          false; /* We will boot the restored Staging OS instead */
      open_txn->intent = WAL_INTENT_NONE; /* Old firmware is stable baseline.
                                             Drop trial constraints. */

      /* Heal the system completely: Set counter to 0 and persist NONE append */
      current_tmr->boot_failure_counter = 0;
      status = boot_journal_update_tmr(platform, current_tmr);
      if (status != BOOT_OK)
        return status;

      status = boot_journal_append(platform, open_txn);
      if (status != BOOT_OK)
        return status;

    } else {
      /* CASE B: Normal OS run with persistent crashes. Evaluate Backoff or
       * Recovery OS. */
      status = boot_rollback_evaluate_os(platform, current_tmr,
                                         &target_out->boot_recovery_os);
      if (status != BOOT_OK)
        return status;
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

  /* stage_parse output (TBM1 v2 fixed-format) */
  const tbm1_header_t *tbm1;     /* Pointer into arena (read-only after parse) */
  uint32_t tbm1_total_len;       /* == tbm1->total_len */

  /* stage_check_svn output */
  uint32_t extracted_svn;

  /* stage_swap output (P7a) */
  uint32_t extracted_stage1_svn;

  /* stage_route output */
  bool requires_swap;
  bool is_delta;
  uint32_t swap_src_addr;
  toob_image_header_t staging_header;
  const tbm1_image_desc_t *primary_image; /* Pointer to images[0] in TBM1 */
  const uint8_t *chunk_hash_ptr;          /* Pointer into arena */
  uint32_t chunk_hash_len;
  uint32_t num_chunks;
  uint32_t chunk_size;
} update_ctx_t;

/* --------------------------------------------------------------------------
 * Stage PARSE: Flash-Read → TBM1 v2 Validation via boot_tbm1.c
 *
 * Delegates all structural validation (magic, version, CRC, bounds, regions,
 * images, chunk-hash partitioning) to tbm1_validate(). This stage only handles
 * flash I/O and maps reject codes to boot_status_t.
 * -------------------------------------------------------------------------- */
static boot_status_t stage_parse(update_ctx_t *ctx) {
#ifdef TOOB_MOCK_TEST
  ctx->tbm1_total_len = 600;
  return BOOT_OK;
#else
  ctx->platform->wdt->kick();
  boot_status_t read_stat = ctx->platform->flash->read(
      ctx->open_txn->offset, ctx->arena, ctx->arena_len);
  ctx->platform->wdt->kick();

  if (read_stat != BOOT_OK)
    return read_stat;

  tbm1_reject_t rc = tbm1_validate(ctx->arena, ctx->arena_len);
  if (rc != TBM1_OK)
    return tbm1_reject_to_boot_status(rc);

  ctx->tbm1 = (const tbm1_header_t *)ctx->arena;
  ctx->tbm1_total_len = ctx->tbm1->total_len;
  return BOOT_OK;
#endif
}

/* --------------------------------------------------------------------------
 * Stage VERIFY ENVELOPE: Ed25519/PQC Signaturverifikation (Glitch-gehärtet)
 * -------------------------------------------------------------------------- */
static boot_status_t stage_verify_envelope(update_ctx_t *ctx) {
#ifdef TOOB_MOCK_TEST
  boot_verify_envelope_t mock_envelope = {
      .manifest_flash_addr = ctx->open_txn->offset,
      .manifest_size = 600,
      .signature_ed25519 = (const uint8_t *)"DUMMYSIG",
      .key_index = 0,
#if TOOB_PQC_ENABLED
      .pqc_hybrid_active = false
#endif
  };
  return boot_verify_manifest_envelope(
      ctx->platform, &mock_envelope, ctx->arena, ctx->arena_len);
#else
  /* Ed25519 signature is located at the very end of the total block */
  const uint8_t *sig_ptr = ctx->arena + ctx->tbm1_total_len - TBM1_SIG_LEN;

#if TOOB_PQC_ENABLED
  const tbm1_region_t *pqc_sig = tbm1_find_region(ctx->tbm1, TBM1_REGION_PQC_SIGNATURE);
  const tbm1_region_t *pqc_key = tbm1_find_region(ctx->tbm1, TBM1_REGION_PQC_PUBKEY);
#endif

  boot_verify_envelope_t envelope = {
      .manifest_flash_addr = ctx->open_txn->offset,
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

  boot_status_t verify_status = boot_verify_manifest_envelope(
      ctx->platform, &envelope, ctx->arena, ctx->arena_len);

  /* CFI Glitch-Guard: Krypto-Resultat doppelt absichern */
  bool envelope_ok = (verify_status == BOOT_OK);
  if (!envelope_ok)
    return BOOT_ERR_VERIFY;

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
    if (!bind_reg || bind_reg->len != 32)
      return BOOT_ERR_INVALID_ARG;

    uint8_t dslc_buf[32] __attribute__((aligned(8)));
    size_t dslc_len = 32;
    if (!ctx->platform->crypto->read_dslc ||
        ctx->platform->crypto->read_dslc(dslc_buf, &dslc_len) != BOOT_OK)
      return BOOT_ERR_NOT_SUPPORTED;

    const uint8_t *bind_ptr = ctx->arena + bind_reg->off;
    if (constant_time_memcmp_glitch_safe(bind_ptr, dslc_buf, 32) != BOOT_OK)
      return BOOT_ERR_VERIFY;
  }

  /* EU-CRA SBOM Extraction (in .noinit Diagnostics Areal) */
  boot_diag_set_security_meta(
      ctx->extracted_svn,
      ctx->tbm1->key_index,
      ctx->tbm1->sbom_digest,
      ctx->tbm1->build_number,
      ctx->tbm1->fw_ver_major,
      ctx->tbm1->fw_ver_minor,
      ctx->tbm1->fw_ver_patch);

  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Stage ROUTE: Staging Header → Raw/Delta Branching → Chunk-Hash Extraction
 * -------------------------------------------------------------------------- */
static boot_status_t stage_route(update_ctx_t *ctx) {
  ctx->requires_swap = true;
  ctx->swap_src_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  boot_secure_zeroize(&ctx->staging_header, sizeof(ctx->staging_header));

  /* Double Check Gating: Redundanter Verify-Guard */
  boot_status_t head_status = ctx->platform->flash->read(
      CHIP_STAGING_SLOT_ABS_ADDR, (uint8_t *)&ctx->staging_header,
      sizeof(toob_image_header_t));

  if (head_status != BOOT_OK ||
      ctx->staging_header.magic != TOOB_MAGIC_HEADER)
    return BOOT_ERR_INVALID_STATE;

  if (ctx->staging_header.image_size > CHIP_APP_SLOT_SIZE)
    return BOOT_ERR_FLASH_BOUNDS;

#ifdef TOOB_MOCK_TEST
  return BOOT_OK;
#endif

  if (ctx->staging_header.image_size <= sizeof(toob_image_header_t))
    return BOOT_ERR_INVALID_ARG;

  ctx->primary_image = &ctx->tbm1->images[0];

  /* Chunk-hash pointer from Region Directory */
  const tbm1_region_t *hash_reg = tbm1_find_region(ctx->tbm1, TBM1_REGION_CHUNK_HASHES);
  if (!hash_reg)
    return BOOT_ERR_INVALID_ARG;

  ctx->chunk_hash_ptr = ctx->arena + hash_reg->off;
  ctx->chunk_hash_len = hash_reg->len;

  /* Primary image fields */
  ctx->num_chunks = ctx->primary_image->num_chunks;
  ctx->chunk_size = ctx->primary_image->chunk_size;
  ctx->is_delta = (ctx->primary_image->delta_alg != TBM1_DELTA_NONE);

  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Stage APPLY DELTA: Arena-Slicing + SDVM + Merkle-Verify des Outputs
 * -------------------------------------------------------------------------- */
static boot_status_t stage_apply_delta(update_ctx_t *ctx) {
  /* Delta SVN Gating: verify installed base SVN matches expected delta base */
  if (ctx->primary_image->base_svn > 0) {
    boot_status_t base_svn_st = boot_rollback_verify_svn(
        ctx->platform, ctx->primary_image->base_svn, ROLLBACK_TARGET_APP);
    if (base_svn_st != BOOT_OK) {
      return BOOT_ERR_INVALID_STATE; /* Base version mismatch */
    }
  }

  size_t hash_slice_size = (ctx->chunk_hash_len + 7) & ~((size_t)7);
  if (hash_slice_size >= ctx->arena_len)
    return BOOT_ERR_INVALID_ARG;

  uint8_t *hash_arena = ctx->arena;
  uint8_t *delta_arena = ctx->arena + hash_slice_size;
  size_t delta_arena_len = ctx->arena_len - hash_slice_size;

  memcpy(hash_arena, ctx->chunk_hash_ptr, ctx->chunk_hash_len);

  boot_status_t delta_stat = boot_delta_apply(
      ctx->platform, ctx->open_txn->offset + ctx->tbm1_total_len,
      CHIP_STAGING_SLOT_ABS_ADDR + CHIP_APP_SLOT_SIZE -
          (ctx->open_txn->offset + ctx->tbm1_total_len),
      CHIP_SCRATCH_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,
      CHIP_APP_SLOT_ABS_ADDR, CHIP_APP_SLOT_SIZE,
      ctx->open_txn, delta_arena, delta_arena_len);

  if (delta_stat != BOOT_OK) {
    boot_secure_zeroize(hash_arena, hash_slice_size);
    return delta_stat;
  }

  boot_status_t hash_stat = boot_merkle_verify_stream(
      ctx->platform, CHIP_SCRATCH_SLOT_ABS_ADDR,
      ctx->primary_image->installed_size,
      ctx->primary_image->chunk_size,
      hash_arena, ctx->chunk_hash_len, ctx->num_chunks,
      delta_arena, delta_arena_len);

  boot_secure_zeroize(hash_arena, hash_slice_size);

  if (hash_stat != BOOT_OK)
    return BOOT_ERR_VERIFY;

  /* Delta erfolgreich: Swap-Quelle ist Scratch, Image-Size ist Zielgröße */
  ctx->staging_header.image_size = ctx->primary_image->installed_size;
  ctx->swap_src_addr = CHIP_SCRATCH_SLOT_ABS_ADDR;

  return BOOT_OK;
}

/* --------------------------------------------------------------------------
 * Stage APPLY RAW: Merkle-Verify des Staging-Slots
 * -------------------------------------------------------------------------- */
static boot_status_t stage_apply_raw(update_ctx_t *ctx) {
  ctx->swap_src_addr = CHIP_STAGING_SLOT_ABS_ADDR;
  size_t aligned_offset =
      (ctx->tbm1_total_len + 7) & ~((size_t)7);

  if (aligned_offset >= ctx->arena_len)
    return BOOT_ERR_INVALID_ARG;

  uint8_t *scratch = ctx->arena + aligned_offset;
  size_t scratch_size = ctx->arena_len - aligned_offset;

  if (scratch_size < ctx->chunk_size)
    return BOOT_ERR_INVALID_ARG;

  boot_secure_zeroize(scratch, scratch_size);
  boot_status_t hash_stat = boot_merkle_verify_stream(
      ctx->platform, CHIP_STAGING_SLOT_ABS_ADDR,
      ctx->staging_header.image_size, ctx->chunk_size,
      ctx->chunk_hash_ptr, ctx->chunk_hash_len,
      ctx->num_chunks, scratch, scratch_size);
  boot_secure_zeroize(scratch, scratch_size);

  return hash_stat;
}

/* --------------------------------------------------------------------------
 * Stage SWAP: boot_swap_apply + Multi-Image Deployment
 * -------------------------------------------------------------------------- */
static boot_status_t stage_swap(update_ctx_t *ctx) {
  boot_status_t swap_status = BOOT_OK;

  /* 1. Parse components from TBM1 image descriptors */
  boot_component_t components[3];
  uint32_t comp_count = 0;
  uint32_t current_staging_offset = ctx->staging_header.image_size;

  if (ctx->tbm1->image_count > 1) {
    for (uint8_t i = 1; i < ctx->tbm1->image_count && i < TBM1_MAX_IMAGES; i++) {
      const tbm1_image_desc_t *sub_img = &ctx->tbm1->images[i];
      boot_secure_zeroize(&components[comp_count], sizeof(boot_component_t));
      components[comp_count].component_id = (uint32_t)i;
      components[comp_count].image_size = sub_img->installed_size;
      components[comp_count].staging_offset = current_staging_offset;
      current_staging_offset += sub_img->stored_size;

      if (sub_img->target_slot == TBM1_SLOT_NETCORE) {
        components[comp_count].target_addr = CHIP_NETCORE_SLOT_ABS_ADDR;
      } else if (sub_img->target_slot == TBM1_SLOT_RECOVERY) {
        components[comp_count].target_addr = CHIP_RECOVERY_OS_ABS_ADDR;
      } else if (sub_img->target_slot == TBM1_SLOT_STAGE1) {
        /* P7a: Stage-1 Anti-Rollback Gate — enforce before any flash write */
        if (ctx->tbm1->stage1_svn == 0)
          return BOOT_ERR_INVALID_ARG; /* Stage-1 manifest without stage1_svn */

        boot_status_t svn_st = boot_rollback_verify_svn(
            ctx->platform, ctx->tbm1->stage1_svn, ROLLBACK_TARGET_STAGE1);
        if (svn_st != BOOT_OK) return svn_st;
        ctx->extracted_stage1_svn = ctx->tbm1->stage1_svn;

        wal_tmr_payload_t temp_tmr;
        boot_secure_zeroize(&temp_tmr, sizeof(temp_tmr));
        if (boot_journal_get_tmr(ctx->platform, &temp_tmr) == BOOT_OK) {
          components[comp_count].target_addr =
              (temp_tmr.active_stage1_bank == 0) ? CHIP_STAGE1B_ABS_ADDR
                                                 : CHIP_STAGE1A_ABS_ADDR;
        } else {
          return BOOT_ERR_INVALID_ARG;
        }
      } else {
        return BOOT_ERR_INVALID_ARG;
      }

      comp_count++;
    }
  }

  /* 2. Run the energy and wear admission verification */
  wal_tmr_payload_t current_tmr;
  boot_secure_zeroize(&current_tmr, sizeof(current_tmr));
  if (boot_journal_get_tmr(ctx->platform, &current_tmr) != BOOT_OK) {
    return BOOT_ERR_STATE;
  }

  boot_status_t admit_status = boot_effect_admit_or_defer(
      ctx->platform, &current_tmr, ctx->staging_header.image_size,
      components, comp_count, ctx->requires_swap);
  if (admit_status != BOOT_OK) {
    return admit_status; /* Defer/Counter Exhausted */
  }

  /* 3. Perform the actual physical swap if admitted */
  if (ctx->requires_swap) {
    swap_status = boot_swap_apply(
        ctx->platform, ctx->swap_src_addr, CHIP_APP_SLOT_ABS_ADDR,
        ctx->staging_header.image_size, BOOT_DEST_SLOT_APP, ctx->open_txn,
        ctx->arena, ctx->arena_len);
  }

  /* 4. Perform the actual physical multi-image write if admitted */
  if (swap_status == BOOT_OK && comp_count > 0) {
    boot_allowed_region_t whitelist[4] = {
        {CHIP_NETCORE_SLOT_ABS_ADDR, CHIP_NETCORE_SLOT_SIZE},
        {CHIP_RECOVERY_OS_ABS_ADDR, CHIP_RECOVERY_OS_SIZE},
        {CHIP_STAGE1A_ABS_ADDR, CHIP_STAGE1A_SIZE},
        {CHIP_STAGE1B_ABS_ADDR, CHIP_STAGE1B_SIZE}};
    swap_status = boot_multiimage_apply(
        ctx->platform, CHIP_STAGING_SLOT_ABS_ADDR, components, comp_count,
        whitelist, 4, ctx->open_txn, ctx->arena, ctx->arena_len);
  }

  return swap_status;
}

/* --------------------------------------------------------------------------
 * Stage COMMIT: WAL TXN_COMMIT + SVN-Übergabe an den TMR
 * -------------------------------------------------------------------------- */
static boot_status_t stage_commit(update_ctx_t *ctx) {
  wal_entry_payload_t commit_txn = *ctx->open_txn;
  commit_txn.intent = WAL_INTENT_TXN_COMMIT;

  boot_status_t status = boot_journal_append(ctx->platform, &commit_txn);
  if (status != BOOT_OK)
    return status;

  ctx->open_txn->intent = WAL_INTENT_TXN_COMMIT;
  return BOOT_OK;
}

static boot_status_t stage_apply_unified(update_ctx_t *ctx) {
  if (ctx->is_delta) {
    return stage_apply_delta(ctx);
  } else {
    return stage_apply_raw(ctx);
  }
}

typedef boot_status_t (*stage_fn_t)(update_ctx_t *ctx);

typedef struct {
  stage_fn_t fn;
  uint8_t    cfi_slot;
  bool       skippable;
} stage_row_t;

/* K6-T3: Pipeline-Stages als statische Tabelle (R-Block v2: CRC + HW-compat
 * sind jetzt Teil von tbm1_validate in stage_parse — P1B/P3B entfallen) */
static const stage_row_t PIPELINE[] = {
  { stage_parse,            STATE_CFI_SLOT_P1,  false },
  { stage_verify_envelope,  STATE_CFI_SLOT_P2,  false },
  { stage_check_svn,        STATE_CFI_SLOT_P3,  false },
  { stage_check_binding,    STATE_CFI_SLOT_P4,  true  },
  { stage_route,            STATE_CFI_SLOT_P5,  false },
  { stage_apply_unified,    STATE_CFI_SLOT_P6,  false },
  { stage_swap,             STATE_CFI_SLOT_P7,  false },
  { stage_commit,           STATE_CFI_SLOT_P8,  false }
};

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
  boot_status_t in_error;     /* Eingangsfehler */
  boot_status_t out_status;   /* Rückgabewert des Flows */
  wal_intent_t  reject_to;    /* Folge-Intent nach Reject */
} err_row_t;

/* K6-T1: Fehlertopologie als Tabelle (erweitert für K2 v2 Fehler-Taxonomie) */
static const err_row_t ERR_TABLE[] = {
  { BOOT_ERR_VERIFY,            BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_DOWNGRADE,         BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_INVALID_ARG,       BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_FLASH_BOUNDS,      BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_INVALID_STATE,     BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_NOT_FOUND,         BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_MANIFEST_CORRUPT,  BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_MANIFEST_VERSION,  BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_MANIFEST_PRODUCT,  BOOT_OK, WAL_INTENT_NONE },
  { BOOT_ERR_DEFER,             BOOT_OK, WAL_INTENT_SLEEP_BACKOFF }
};

static boot_status_t _handle_update_result(
    const boot_platform_t *platform, wal_entry_payload_t *open_txn,
    update_ctx_t *ctx, boot_status_t pipeline_status,
    boot_cfi_ctx_t *cfi_ctx, uint32_t slot) {

  boot_status_t flow_final_status = pipeline_status;

  if (pipeline_status == BOOT_OK) {
    flow_final_status = BOOT_OK;
  } else {
    /* Suche den Fehler in der ERR_TABLE */
    bool found = false;
    for (size_t i = 0; i < sizeof(ERR_TABLE)/sizeof(ERR_TABLE[0]); i++) {
      if (ERR_TABLE[i].in_error == pipeline_status) {
        /* Kontrollierte Ablehnung: Update verwerfen, kein Bootloop */
        wal_entry_payload_t reject_txn = *open_txn;
        reject_txn.intent = ERR_TABLE[i].reject_to;

        boot_status_t rej_stat = boot_journal_append(platform, &reject_txn);
        if (rej_stat != BOOT_OK) {
          flow_final_status = rej_stat;
        } else {
          open_txn->intent = ERR_TABLE[i].reject_to;
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

#ifndef TOOB_MOCK_TEST
  /* K2: TBM1 lives in the arena — zeroize covers all sensitive manifest data */
  if (ctx->tbm1_total_len > 0 && ctx->tbm1_total_len <= ctx->arena_len) {
    boot_secure_zeroize(ctx->arena, ctx->tbm1_total_len);
  }
  ctx->tbm1 = NULL;
#endif

  if (flow_final_status == BOOT_OK)
    boot_cfi_step(*cfi_ctx, slot);

  return flow_final_status;
}

/* --------------------------------------------------------------------------
 * Pipeline Driver: Flache Sequenz, ein Cleanup-Pfad
 * -------------------------------------------------------------------------- */
static boot_status_t _handle_update_flow(const boot_platform_t *platform,
                                         wal_entry_payload_t *open_txn,
                                         uint32_t *extracted_svn,
                                         uint32_t *extracted_stage1_svn,
                                         boot_cfi_ctx_t *cfi_ctx,
                                         uint32_t slot,
                                         uint8_t *arena, size_t arena_len) {
  if (open_txn->intent != WAL_INTENT_UPDATE_PENDING) {
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
  boot_cfi_init(pipeline_cfi_ctx, 0x5a5a5a5a);

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
  }

  return _handle_update_result(platform, open_txn, &ctx, status, cfi_ctx, slot);
}

static boot_status_t evaluate_transition(
    const boot_platform_t *platform,
    wal_entry_payload_t *open_txn,
    wal_tmr_payload_t *current_tmr,
    boot_event_t event,
    boot_target_config_t *target_cfg,
    uint8_t *arena,
    size_t arena_len) {

  const intent_row_t *match = NULL;
  for (size_t i = 0; i < sizeof(INTENT_TABLE)/sizeof(INTENT_TABLE[0]); i++) {
    if (INTENT_TABLE[i].cur == open_txn->intent && INTENT_TABLE[i].ev == event) {
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
      if (current_tmr->boot_failure_counter > 0) {
        current_tmr->boot_failure_counter = 0;
        status = boot_journal_update_tmr(platform, current_tmr);
        if (status != BOOT_OK) return status;
      }
      open_txn->intent = match->next;
      status = boot_journal_append(platform, open_txn);
      if (status != BOOT_OK) return status;

      /* Datenhygiene: Erase des Staging-Slots */
      (void)boot_swap_erase_safe(platform, CHIP_STAGING_SLOT_ABS_ADDR,
                                 CHIP_STAGING_SLOT_SIZE, arena, arena_len);
      break;
    }
    case ACT_APPEND: {
      wal_entry_payload_t next_txn = *open_txn;
      next_txn.intent = match->next;
      status = boot_journal_append(platform, &next_txn);
      if (status == BOOT_OK) {
        open_txn->intent = match->next;
      }
      break;
    }
    case ACT_PANIC_LOCKED: {
      boot_panic(platform, BOOT_ERR_DEVICE_LOCKED);
      return BOOT_ERR_DEVICE_LOCKED;
    }
    case ACT_CRASH_ACCUM: {
      current_tmr->boot_failure_counter++;
      status = boot_journal_update_tmr(platform, current_tmr);
      break;
    }
  }
  return status;
}

/* ==============================================================================
 * MAIN BOOT STATE MACHINE (CFI-ORCHESTRATOR)
 * ==============================================================================
 */

boot_status_t boot_state_run(const boot_platform_t *platform,
                             boot_target_config_t *target_out,
                             const uint32_t seal_key[4],
                             uint8_t *arena, size_t arena_len) {
  if (!arena || arena_len < 512)
    return BOOT_ERR_INVALID_ARG;
  /* P10 Pointer-Guard (Zero-Trust HAL Assumption) */
  if (!platform || !platform->clock || !platform->flash || !platform->crypto ||
      !platform->wdt || !target_out || !seal_key) {
    return BOOT_ERR_INVALID_ARG;
  }

  if (!platform->clock->get_reset_reason || !platform->flash->read ||
      !platform->crypto->random || !platform->wdt->kick) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* Initialize Output Struct entirely to prevent uninitialized memory attacks
   */
  boot_secure_zeroize(target_out, sizeof(boot_target_config_t));

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t state_cfi_seed = 0;
  boot_random_safe(platform, (uint8_t *)&state_cfi_seed, sizeof(state_cfi_seed));
  boot_cfi_ctx_t state_cfi_ctx;
  boot_cfi_init(state_cfi_ctx, state_cfi_seed);
  boot_cfi_add_expected(state_cfi_ctx, STATE_CFI_SLOT_1);
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

  /*
   * ==============================================================================
   * STEP 1 - Journal Initialization, TMR State Retrieval & WAL Reconstruction
   * ==============================================================================
   */
  core_status = boot_journal_init(platform);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  core_status = boot_journal_get_tmr(platform, &current_tmr);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  uint32_t active_net_accum = 0;
  uint32_t resume_offset = 0;
  core_status = boot_journal_reconstruct_txn(platform, &open_txn,
                                             &active_net_accum, &resume_offset);

  if (core_status != BOOT_OK && core_status != BOOT_ERR_STATE) {
    goto state_cleanup;
  }

  if (core_status == BOOT_ERR_STATE) {
    open_txn.intent = WAL_INTENT_NONE;
    core_status = BOOT_OK; /* Normalize clean state */
  }

  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_1); /* Proof Step 1 */
  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 2 - Clean-Up / Confirmation Check (Auth Protected)
   * ==============================================================================
   */
  uint64_t combined_nonce = ((uint64_t)current_tmr.active_nonce_hi << 32) |
                            current_tmr.active_nonce_lo;
  bool rtc_confirmed = false;

  if (platform->confirm && platform->confirm->check_ok) {
    rtc_confirmed = platform->confirm->check_ok(combined_nonce);
  }

  /* Sticky Lock: DEVICE_LOCKED überspringt den Confirm-Check komplett.
   * Ein gelocktes Gerät darf seinen Lock-Intent niemals durch eine normale
   * OS-Confirmation aufheben. Nur TOOB_CMD_UNLOCK (Step 2.5) kann das. */
  if (open_txn.intent != WAL_INTENT_DEVICE_LOCKED &&
      (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT ||
       open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED || rtc_confirmed)) {

    /* P10 Security: Glitch-Resistente Nonce-Autorisation */
    bool intent_is_confirm = (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT);
    bool intent_is_recovery = (open_txn.intent == WAL_INTENT_RECOVERY_RESOLVED);

    /* P7b: WAL-Intent ist die Autorisierung, nicht der Reset-Reason.
     * RECOVERY_RESOLVED wird nur durch das Recovery-OS selbst in den WAL
     * geschrieben — das Vorhandensein des Intents beweist, dass Recovery lief. */
    bool auth_ok = rtc_confirmed ||
                   (intent_is_confirm && (open_txn.expected_nonce ^ combined_nonce) == 0) ||
                   intent_is_recovery;

    volatile uint32_t auth_verdict = BOOT_OK;
    BOOT_SECURE_REQUIRE(auth_ok, {
      auth_verdict = BOOT_ERR_VERIFY;
    });

    if (auth_verdict != BOOT_OK) {
      /* MALICIOUS OR CORRUPT AUTHORIZATION! Discard silently. */
      open_txn.intent = WAL_INTENT_NONE;
    } else {
      if (rtc_confirmed && open_txn.intent == WAL_INTENT_NONE) {
        open_txn.intent = WAL_INTENT_CONFIRM_COMMIT;
      }
      core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CONFIRM_OK, target_out, arena, arena_len);
      if (core_status != BOOT_OK)
        goto state_cleanup;
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
  core_status = _handle_cloud_cmd(platform, &open_txn, target_out, &state_cfi_ctx,
                                   STATE_CFI_SLOT_2_5, arena, arena_len);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 2.7 - Lock-State Gate (Phase 6)
   * ==============================================================================
   * Wenn das Gerät im Soft-Lock (WAL_INTENT_DEVICE_LOCKED) ist, darf die
   * State-Machine NICHT weiterlaufen. Nur boot_panic mit BOOT_ERR_DEVICE_LOCKED
   * ist erlaubt. Dort wartet Block 3A auf ein UART-Unlock-Envelope.
   */
  BOOT_SECURE_REQUIRE(open_txn.intent != WAL_INTENT_DEVICE_LOCKED, {
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

  /* P7b: WAL-Primary Crash Detection.
   * Ein un-aufgelöster CONFIRM_COMMIT ist das stärkste Crash-Signal:
   * Das OS hatte die Chance zu confirmen, hat aber nicht.
   * Reset-Reason korroboriert nur — Brownout ist kein Crash-Signal mehr,
   * da ein leerer Akku nach Monaten kein App-Bug ist. */
  bool wal_indicates_crash = (open_txn.intent == WAL_INTENT_CONFIRM_COMMIT);
  bool rst_indicates_crash = (rst_reason == RESET_REASON_WATCHDOG ||
                              rst_reason == RESET_REASON_HARD_FAULT);

  bool is_app_crash = wal_indicates_crash ||
                      (rst_indicates_crash &&
                       open_txn.intent != WAL_INTENT_UPDATE_PENDING &&
                       open_txn.intent != WAL_INTENT_TXN_BEGIN);

  if (is_app_crash) {
    core_status = evaluate_transition(platform, &open_txn, &current_tmr, EV_CRASH, target_out, arena, arena_len);
    if (core_status != BOOT_OK)
      goto state_cleanup;
  }

  core_status = _handle_rollback_flow(platform, &current_tmr, &open_txn,
                                      target_out, &state_cfi_ctx,
                                      STATE_CFI_SLOT_3, arena, arena_len);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  platform->wdt->kick();

  /*
   * ==============================================================================
   * STEP 4 - Update Pipeline (STAGING -> TESTING -> SWAP)
   * ==============================================================================
   */
  uint32_t extracted_svn = 0;
  uint32_t extracted_stage1_svn = 0;

  core_status =
      _handle_update_flow(platform, &open_txn, &extracted_svn,
                          &extracted_stage1_svn, &state_cfi_ctx,
                          STATE_CFI_SLOT_4, arena, arena_len);
  if (core_status != BOOT_OK)
    goto state_cleanup;

  if (extracted_svn > current_tmr.app_svn) {
    current_tmr.app_svn = extracted_svn;
  }
  /* P7a: Persist Stage-1 SVN (last-confirmed) to TMR */
  if (extracted_stage1_svn > current_tmr.stage1_svn) {
    current_tmr.stage1_svn = extracted_stage1_svn;
  }

  /*
   * ==============================================================================
   * STEP 5 - Handoff Preparation / Nonce Registration
   * ==============================================================================
   */

  uint32_t slot_addr = target_out->boot_recovery_os ? CHIP_RECOVERY_OS_ABS_ADDR
                                                    : CHIP_APP_SLOT_ABS_ADDR;

  core_status = platform->flash->read(slot_addr, (uint8_t *)&app_header,
                                      sizeof(toob_image_header_t));
  if (core_status != BOOT_OK)
    goto state_cleanup;

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

  /* Glitch-Shielded Evaluation for Nonce Generation */
  bool requires_confirmation = false;
  if (open_txn.intent == WAL_INTENT_TXN_COMMIT) {
    BOOT_SECURE_REQUIRE(open_txn.intent == WAL_INTENT_TXN_COMMIT, {
      core_status = BOOT_ERR_VERIFY;
      goto state_cleanup;
    });
    requires_confirmation = true;
  }
  target_out->is_tentative_boot = requires_confirmation;

  platform->wdt->kick();

  if (requires_confirmation) {
    core_status = boot_random_safe(
        platform, (uint8_t *)&target_out->generated_nonce, sizeof(uint64_t));
    if (core_status != BOOT_OK)
      goto state_cleanup;

    current_tmr.active_nonce_lo =
        (uint32_t)(target_out->generated_nonce & 0xFFFFFFFF);
    current_tmr.active_nonce_hi = (uint32_t)(target_out->generated_nonce >> 32);
    core_status = boot_journal_update_tmr(platform, &current_tmr);
    if (core_status != BOOT_OK)
      goto state_cleanup;

    /* Stateful Slide Abandonment Fix */
    if (open_txn.intent != WAL_INTENT_NONE) {
      core_status = boot_journal_append(platform, &open_txn);
      if (core_status != BOOT_OK)
        goto state_cleanup;
    }
  } else {
    target_out->generated_nonce = 0;
  }

  target_out->net_search_accum_ms = active_net_accum;
  target_out->resume_offset = resume_offset;
  boot_cfi_step(state_cfi_ctx, STATE_CFI_SLOT_5);

state_cleanup:
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