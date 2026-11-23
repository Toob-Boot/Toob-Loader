(* ========================================================================== *)
(* Toob-Loader Formal Verification                                            *)
(* File: BootTransitions.v                                                    *)
(*                                                                            *)
(* Exact step, reboot, and step-indexed power-cut transition semantics        *)
(* matching toobloader/core/{boot_state,boot_effect,boot_rollback,            *)
(* boot_journal,boot_confirm,boot_rstore,boot_verify,boot_mailbox,            *)
(* boot_cloud_cmd,boot_transport_oneway}.c.                                   *)
(* ========================================================================== *)

From Stdlib Require Import Bool Arith Lia List.
From ToobBoot Require Export BootModel.
Import ListNotations.

(* -------------------------------------------------------------------------- *)
(* 1. WAL Journal Reconstruction & Append (boot_journal.c)                    *)
(* -------------------------------------------------------------------------- *)

Definition wal_append_valid (w : WAL_Journal) (i : WalIntent) (exp_nonce : nat) : WAL_Journal :=
  mkWAL (RWE_Valid i exp_nonce true :: wal_entries w).

Definition wal_append_torn (w : WAL_Journal) : WAL_Journal :=
  mkWAL (RWE_TornCrcInvalid :: wal_entries w).

Inductive ReconstructResult : Type :=
  | Recon_Empty     : ReconstructResult
  | Recon_Tampered  : ReconstructResult
  | Recon_Ok        : WalIntent -> nat (* expected_nonce *) -> ReconstructResult.

Fixpoint reconstruct_entries (es : list RawWalEntry) : ReconstructResult :=
  match es with
  | [] => Recon_Empty
  | e :: rest =>
      match e with
      | RWE_Erased | RWE_TornCrcInvalid | RWE_Sideband =>
          reconstruct_entries rest
      | RWE_Valid intent exp_nonce mac_ok =>
          if wal_intent_is_security_bearing intent && negb mac_ok then
            Recon_Tampered
          else
            Recon_Ok intent exp_nonce
      end
  end.

Definition wal_reconstruct_txn (w : WAL_Journal) : option (WalIntent * nat) :=
  match reconstruct_entries (wal_entries w) with
  | Recon_Empty        => Some (WI_None, 0)
  | Recon_Tampered     => None
  | Recon_Ok i exp_n   => Some (i, exp_n)
  end.

(* CRIT-24 auxiliary heal scan past leading UPDATE_PENDING entries *)
Inductive AuxHealResult : Type :=
  | Aux_None     : AuxHealResult
  | Aux_Tampered : AuxHealResult
  | Aux_Found    : WalIntent -> nat -> AuxHealResult.

Fixpoint reconstruct_aux_entries (es : list RawWalEntry) : AuxHealResult :=
  match es with
  | [] => Aux_None
  | e :: rest =>
      match e with
      | RWE_Erased | RWE_TornCrcInvalid | RWE_Sideband =>
          reconstruct_aux_entries rest
      | RWE_Valid intent exp_nonce mac_ok =>
          if wal_intent_is_security_bearing intent && negb mac_ok then
            Aux_Tampered
          else
            match intent with
            | WI_ConfirmCommit | WI_RecoveryResolved => Aux_Found intent exp_nonce
            | WI_UpdatePending => reconstruct_aux_entries rest
            | _ => Aux_None
            end
      end
  end.

(* -------------------------------------------------------------------------- *)
(* 2. 3-Sector TMR Quorum Vote (boot_journal.c + boot_rstore.c)               *)
(* -------------------------------------------------------------------------- *)

Definition tmr_quorum_vote (q : TMR_Quorum) (fallback : TMR_Counters) : TMR_Counters :=
  match tmr_sec0 q, tmr_sec1 q, tmr_sec2 q with
  | Some a, Some b, Some c =>
      if tmr_eqb a b then a
      else if tmr_eqb a c then a
      else if tmr_eqb b c then b
      else a
  | Some a, Some b, None   => if tmr_eqb a b then a else a
  | Some a, None,   Some c => if tmr_eqb a c then a else a
  | None,   Some b, Some c => if tmr_eqb b c then b else b
  | Some a, None,   None   => a
  | None,   Some b, None   => b
  | None,   None,   Some c => c
  | None,   None,   None   => fallback
  end.

(* -------------------------------------------------------------------------- *)
(* 3. Step 1.5: OS Mailbox Fold-In (boot_mailbox.c, synced with HIGH-31)      *)
(* -------------------------------------------------------------------------- *)

Definition wal_is_device_locked (wal : WAL_Journal) : bool :=
  match wal_reconstruct_txn wal with
  | Some (WI_DeviceLocked, _) => true
  | _ => false
  end.

Inductive MailboxStepResult : Type :=
  | Mbx_Err  : BootErrCode -> MailboxStepResult
  | Mbx_Done : FlashSlots -> WAL_Journal -> TMR_Counters -> MailboxStepResult.

Definition step1_mailbox_consume
    (slots : FlashSlots) (wal : WAL_Journal) (tmr : TMR_Counters)
    : MailboxStepResult :=
  match mailbox_slot slots with
  | MBX_Empty => Mbx_Done slots wal tmr
  | MBX_Record crc_ok seq req_conf req_upd req_rec mbx_nonce =>
      if negb crc_ok then
        Mbx_Done slots wal tmr
      else if negb (req_conf || req_upd || req_rec) then
        Mbx_Done slots wal tmr
      else if req_conf && (mbx_nonce =? 0) then
        Mbx_Done slots wal tmr
      else if seq <=? last_mbx_seq tmr then
        Mbx_Done slots wal tmr
      else
        (* HIGH-31 (boot_mailbox.c:105-109): Soft-lock (WI_DeviceLocked) cannot
           be overwritten by an unauthenticated OS mailbox slot; consume/advance
           the watermark as a WAL no-op. *)
        let wal_out :=
          if wal_is_device_locked wal then
            wal
          else
            let wal1 := if req_rec then wal_append_valid wal WI_RecoveryResolved 0 else wal in
            let conf_match := (0 <? active_nonce tmr) && (mbx_nonce =? active_nonce tmr) in
            let wal2 := if req_conf && conf_match
                        then wal_append_valid wal1 WI_ConfirmCommit mbx_nonce
                        else wal1 in
            if req_upd
            then wal_append_valid wal2 WI_UpdatePending 0
            else wal2 in
        let tmr' := mkTMR
                      (tmr_app_svn tmr)
                      (tmr_stage1_svn tmr)
                      (boot_failure_counter tmr)
                      (recovery_failure_counter tmr)
                      (active_nonce tmr)
                      seq
                      (last_cloud_issued_at tmr)
                      (tmr_mac_valid tmr) in
        let slots' := mkFlashSlots
                        (app_slot slots)
                        (staging_slot slots)
                        (backup_slot slots)
                        (recovery_rom_valid slots)
                        (cloud_slot slots)
                        MBX_Empty in
        Mbx_Done slots' wal_out tmr'
  end.

(* -------------------------------------------------------------------------- *)
(* 4. Step 2: Confirmation Check (boot_state.c:1702-1792)                     *)
(* -------------------------------------------------------------------------- *)

Definition heal_tmr_counters (tmr : TMR_Counters) : TMR_Counters :=
  mkTMR
    (tmr_app_svn tmr)
    (tmr_stage1_svn tmr)
    0
    0
    0
    (last_mbx_seq tmr)
    (last_cloud_issued_at tmr)
    (tmr_mac_valid tmr).

Definition erase_staging_in_slots (slots : FlashSlots) : FlashSlots :=
  mkFlashSlots
    (app_slot slots)
    erased_slot_image
    (backup_slot slots)
    (recovery_rom_valid slots)
    (cloud_slot slots)
    (mailbox_slot slots).

Inductive Step2Result : Type :=
  | S2_Tampered : Step2Result
  | S2_Ok       : FlashSlots -> WAL_Journal -> TMR_Counters -> ConfirmStore ->
                  WalIntent -> bool (* healed_this_boot *) -> Step2Result.

Definition step2_confirm_check
    (slots : FlashSlots) (wal : WAL_Journal) (tmr : TMR_Counters)
    (conf : ConfirmStore) (open_intent : WalIntent) (open_exp_nonce : nat)
    : Step2Result :=
  let act_n := active_nonce tmr in
  let rtc_ok := (0 <? act_n) && (rtc_nonce conf =? act_n) in
  let conf' := if rtc_ok then mkConfirmStore 0 else conf in
  if wal_intent_eqb open_intent WI_UpdatePending then
    match reconstruct_aux_entries (wal_entries wal) with
    | Aux_Tampered => S2_Tampered
    | Aux_None =>
        if rtc_ok then
          S2_Ok slots wal (heal_tmr_counters tmr) conf' open_intent true
        else
          S2_Ok slots wal tmr conf' open_intent false
    | Aux_Found aux_i aux_n =>
        let aux_conf := wal_intent_eqb aux_i WI_ConfirmCommit in
        let aux_rec  := wal_intent_eqb aux_i WI_RecoveryResolved in
        let auth_ok  := rtc_ok ||
                        (aux_conf && (0 <? act_n) && (0 <? aux_n) && (aux_n =? act_n)) ||
                        aux_rec in
        if auth_ok then
          S2_Ok slots wal (heal_tmr_counters tmr) conf' open_intent true
        else
          S2_Ok slots wal tmr conf' open_intent false
    end
  else if negb (wal_intent_eqb open_intent WI_DeviceLocked) &&
          (wal_intent_eqb open_intent WI_ConfirmCommit ||
           wal_intent_eqb open_intent WI_RecoveryResolved ||
           rtc_ok) then
    let is_conf := wal_intent_eqb open_intent WI_ConfirmCommit in
    let is_rec  := wal_intent_eqb open_intent WI_RecoveryResolved in
    let auth_ok := rtc_ok ||
                   (is_conf && (0 <? act_n) && (0 <? open_exp_nonce) && (open_exp_nonce =? act_n)) ||
                   is_rec in
    if negb auth_ok then
      let next_i := if 0 <? act_n then WI_TxnCommit else WI_None in
      S2_Ok slots wal tmr conf' next_i false
    else
      let eff_i := if rtc_ok && wal_intent_eqb open_intent WI_None
                   then WI_ConfirmCommit
                   else open_intent in
      match eff_i with
      | WI_ConfirmCommit | WI_TxnCommit | WI_RecoveryResolved =>
          let tmr'   := heal_tmr_counters tmr in
          let wal'   := wal_append_valid wal WI_None 0 in
          let slots' := erase_staging_in_slots slots in
          S2_Ok slots' wal' tmr' conf' WI_None true
      | _ =>
          S2_Ok slots wal tmr conf' eff_i true
      end
  else
    S2_Ok slots wal tmr conf' open_intent false.

(* -------------------------------------------------------------------------- *)
(* 5. Step 2.5: Cloud Command Evaluation (boot_cloud_cmd.c + boot_state.c)    *)
(* -------------------------------------------------------------------------- *)

Definition toob_cmd_max_burn_steps : nat := 4.

Definition step2_5_cloud_cmd
    (slots : FlashSlots) (wal : WAL_Journal) (tmr : TMR_Counters)
    (otp : OTP_Epoch) (open_intent : WalIntent)
    : (FlashSlots * WAL_Journal * TMR_Counters * OTP_Epoch * WalIntent) :=
  match cloud_slot slots with
  | CC_Empty => (slots, wal, tmr, otp, open_intent)
  | CC_Token cmd sig_ok dev_ok ctr_min issued_at =>
      let replay_ok := (otp_min_svn otp <? ctr_min) &&
                       (last_cloud_issued_at tmr <? issued_at) &&
                       ((ctr_min - otp_min_svn otp) <=? toob_cmd_max_burn_steps) in
      if negb (sig_ok && dev_ok && replay_ok) then
        (slots, wal, tmr, otp, open_intent)
      else
        let otp' := mkOTPEpoch ctr_min (otp_active_key_index otp) in
        let tmr' := mkTMR
                      (tmr_app_svn tmr)
                      (tmr_stage1_svn tmr)
                      (boot_failure_counter tmr)
                      (recovery_failure_counter tmr)
                      (active_nonce tmr)
                      (last_mbx_seq tmr)
                      issued_at
                      (tmr_mac_valid tmr) in
        let slots' := mkFlashSlots
                        (app_slot slots)
                        (staging_slot slots)
                        (backup_slot slots)
                        (recovery_rom_valid slots)
                        CC_Empty
                        (mailbox_slot slots) in
        match cmd with
        | CCK_Killswitch =>
            (slots', wal_append_valid wal WI_DeviceLocked 0, tmr', otp', WI_DeviceLocked)
        | CCK_Unlock =>
            (slots', wal_append_valid wal WI_None 0, tmr', otp', WI_None)
        | CCK_ForceUpdate =>
            (* LOW-13 (boot_state.c:187-190): FORCE_UPDATE on WI_DeviceLocked
               consumes/erases the slot and burns OTP without clearing lock! *)
            if wal_intent_eqb open_intent WI_DeviceLocked then
              (slots', wal, tmr', otp', WI_DeviceLocked)
            else
              (slots', wal_append_valid wal WI_UpdatePending 0, tmr', otp', WI_UpdatePending)
        | CCK_Wipe =>
            (* HIGH-32 (boot_state.c:224-237): WIPE sets open_txn->intent = WI_None
               in RAM and sets target_out->wipe_requested = true on this boot. *)
            (slots', wal_append_valid wal WI_None 0, tmr', otp', WI_None)
        | CCK_RotateKey | CCK_Nop =>
            (slots', wal, tmr', otp', open_intent)
        end
  end.

(* HIGH-32 observable: target_out->wipe_requested is set iff Step 2.5 accepted
   CCK_Wipe on this boot and Stage 1 completes handoff without panicking. *)
Definition step2_5_sets_wipe_requested
    (slots : FlashSlots) (tmr : TMR_Counters) (otp : OTP_Epoch) : bool :=
  match cloud_slot slots with
  | CC_Token CCK_Wipe sig_ok dev_ok ctr_min issued_at =>
      let replay_ok := (otp_min_svn otp <? ctr_min) &&
                       (last_cloud_issued_at tmr <? issued_at) &&
                       ((ctr_min - otp_min_svn otp) <=? toob_cmd_max_burn_steps) in
      sig_ok && dev_ok && replay_ok
  | _ => false
  end.

(* -------------------------------------------------------------------------- *)
(* 6. Step 3: Failure Counter & Rollback Cascade (boot_state.c + rollback.c)  *)
(* -------------------------------------------------------------------------- *)

Definition crash_accum_applicable (i : WalIntent) : bool :=
  match i with
  | WI_ConfirmCommit | WI_TxnCommit | WI_RecoveryResolved
  | WI_None | WI_TxnRollbackPending => true
  | _ => false
  end.

Definition apply_crash_accum (cfg : BootConfig) (tmr : TMR_Counters) : TMR_Counters :=
  if cfg_max_retries cfg <? boot_failure_counter tmr then
    mkTMR
      (tmr_app_svn tmr)
      (tmr_stage1_svn tmr)
      (boot_failure_counter tmr)
      (S (recovery_failure_counter tmr))
      (active_nonce tmr)
      (last_mbx_seq tmr)
      (last_cloud_issued_at tmr)
      (tmr_mac_valid tmr)
  else
    mkTMR
      (tmr_app_svn tmr)
      (tmr_stage1_svn tmr)
      (S (boot_failure_counter tmr))
      (recovery_failure_counter tmr)
      (active_nonce tmr)
      (last_mbx_seq tmr)
      (last_cloud_issued_at tmr)
      (tmr_mac_valid tmr).

Definition clear_boot_failure_and_nonce (tmr : TMR_Counters) : TMR_Counters :=
  mkTMR
    (tmr_app_svn tmr)
    (tmr_stage1_svn tmr)
    0
    (recovery_failure_counter tmr)
    0
    (last_mbx_seq tmr)
    (last_cloud_issued_at tmr)
    (tmr_mac_valid tmr).

Inductive Step3Result : Type :=
  | S3_Panic : BootErrCode -> TMR_Counters -> Step3Result
  | S3_Ok    : FlashSlots -> WAL_Journal -> TMR_Counters ->
               WalIntent -> bool (* healed *) -> bool (* boot_recovery_os *) -> Step3Result.

Definition step3_failure_and_rollback
    (cfg : BootConfig) (slots : FlashSlots) (wal : WAL_Journal)
    (tmr : TMR_Counters) (rst : ResetReason)
    (open_intent : WalIntent) (healed_in : bool)
    : Step3Result :=
  let wal_crash := wal_intent_eqb open_intent WI_ConfirmCommit ||
                   wal_intent_eqb open_intent WI_TxnCommit in
  let rst_crash := rst_indicates_crash rst in
  let is_crash  := negb healed_in &&
                   (wal_crash || (rst_crash && negb (wal_intent_eqb open_intent WI_UpdatePending))) in
  let tmr1 := if is_crash && crash_accum_applicable open_intent
              then apply_crash_accum cfg tmr
              else tmr in
  let imm_crash := rst_crash && negb healed_in in
  if wal_intent_eqb open_intent WI_TxnRollback then
    S3_Ok slots wal (clear_boot_failure_and_nonce tmr1) WI_None true false
  else if (0 <? boot_failure_counter tmr1) ||
          wal_intent_eqb open_intent WI_TxnRollbackPending then
    if wal_intent_eqb open_intent WI_TxnCommit ||
       wal_intent_eqb open_intent WI_TxnRollbackPending then
      let must_revert := imm_crash ||
                         wal_intent_eqb open_intent WI_TxnRollbackPending ||
                         (cfg_max_retries cfg <? boot_failure_counter tmr1) in
      if must_revert then
        if negb (hdr_valid (backup_slot slots)) then
          S3_Panic Err_NotFound tmr1
        else if negb (sig_valid (backup_slot slots)) then
          S3_Panic Err_Verify tmr1
        else
          let slots' := mkFlashSlots
                          (backup_slot slots)
                          (staging_slot slots)
                          (backup_slot slots)
                          (recovery_rom_valid slots)
                          (cloud_slot slots)
                          (mailbox_slot slots) in
          let wal1 := if wal_intent_eqb open_intent WI_TxnRollbackPending
                      then wal
                      else wal_append_valid wal WI_TxnRollbackPending 0 in
          let wal2 := wal_append_valid wal1 WI_TxnRollback 0 in
          S3_Ok slots' wal2 (clear_boot_failure_and_nonce tmr1) WI_None true false
      else
        S3_Ok slots wal tmr1 open_intent healed_in false
    else
      (* Case B: boot_rollback_evaluate_os *)
      if boot_failure_counter tmr1 <=? cfg_max_retries cfg then
        S3_Ok slots wal tmr1 open_intent healed_in false
      else if recovery_failure_counter tmr1 <=? cfg_max_recovery_retries cfg then
        S3_Ok slots wal tmr1 open_intent healed_in true
      else
        S3_Panic Err_RecoveryRequested tmr1
  else
    S3_Ok slots wal tmr1 open_intent healed_in false.

(* -------------------------------------------------------------------------- *)
(* 7. Step 4: Update Pipeline (boot_state.c:542-1503 + boot_verify.c)         *)
(* -------------------------------------------------------------------------- *)

(* Key acceptance in boot_verify.c: slot k is accepted iff k == active_key_index *)
Definition key_is_accepted (k active_key : nat) : bool :=
  Nat.eqb k active_key.

Definition staging_can_apply
    (stg : SlotImage) (tmr : TMR_Counters) (otp : OTP_Epoch) : bool :=
  tbm1_valid stg &&
  key_is_accepted (key_index stg) (otp_active_key_index otp) &&
  sig_valid stg &&
  (tmr_app_svn tmr <=? image_svn stg) &&
  (otp_min_svn otp <=? image_svn stg) &&
  merkle_valid stg &&
  hdr_valid stg.

Definition step4_update_pipeline
    (slots : FlashSlots) (wal : WAL_Journal) (tmr : TMR_Counters)
    (otp : OTP_Epoch) (open_intent : WalIntent)
    : (FlashSlots * WAL_Journal * TMR_Counters * WalIntent * bool) :=
  if negb (wal_intent_eqb open_intent WI_UpdatePending) then
    (slots, wal, tmr, open_intent, false)
  else
    let stg := staging_slot slots in
    if staging_can_apply stg tmr otp then
      let slots' := mkFlashSlots
                      stg              (* DEPLOY: Staging -> App_Slot_0 *)
                      stg              (* Staging preserved until confirm *)
                      (app_slot slots) (* BACKUP: App_Slot_0 -> Backup_Slot *)
                      (recovery_rom_valid slots)
                      (cloud_slot slots)
                      (mailbox_slot slots) in
      let wal1 := wal_append_valid wal WI_UpdatePending 0 in
      let wal2 := wal_append_valid wal1 WI_TxnCommit 0 in
      let new_app_svn := Nat.max (tmr_app_svn tmr) (image_svn stg) in
      let tmr' := mkTMR
                    new_app_svn
                    (tmr_stage1_svn tmr)
                    0 (* boot_state.c:1891 zeroes boot_failure_counter on TXN_COMMIT *)
                    (recovery_failure_counter tmr)
                    (active_nonce tmr)
                    (last_mbx_seq tmr)
                    (last_cloud_issued_at tmr)
                    (tmr_mac_valid tmr) in
      (slots', wal2, tmr', WI_TxnCommit, true)
    else
      (* Controlled reject via ERR_TABLE -> append WAL_INTENT_NONE, keep slots *)
      let wal' := wal_append_valid wal WI_None 0 in
      (slots, wal', tmr, WI_None, true).

(* -------------------------------------------------------------------------- *)
(* 8. Step 5 & Complete Boot Cycle Evaluation (boot_state_run)                *)
(* -------------------------------------------------------------------------- *)

Definition set_tmr_nonce (tmr : TMR_Counters) (n : nat) : TMR_Counters :=
  mkTMR
    (tmr_app_svn tmr)
    (tmr_stage1_svn tmr)
    (boot_failure_counter tmr)
    (recovery_failure_counter tmr)
    n
    (last_mbx_seq tmr)
    (last_cloud_issued_at tmr)
    (tmr_mac_valid tmr).

(* Wave-1 CRIT-68 / CRIT-71: Explicit seal/handoff & rollback verification gates
   mirroring boot_verify_slot_image() in boot_state.c:2182 and boot_rollback.c:295. *)
Definition boot_handoff_seal_gate
    (target_is_rec rec_hdr_ok rec_tsig_ok : bool)
    (app_img : SlotImage) (active_key : nat) : option BootErrCode :=
  if target_is_rec then
    if negb rec_hdr_ok then Some Err_NotFound
    else if negb rec_tsig_ok then Some Err_Verify
    else None
  else
    if negb (hdr_valid app_img) then Some Err_NotFound
    else if negb (slot_tsig_valid app_img active_key) then Some Err_Verify
    else None.

Definition boot_rollback_verify_slot_before_copy
    (bkup : SlotImage) (active_key : nat) : option BootErrCode :=
  if negb (hdr_valid bkup) then Some Err_NotFound
  else if negb (slot_tsig_valid bkup active_key) then Some Err_Verify
  else None.

Definition eval_boot_state (cfg : BootConfig) (st : State) : (BootOutcome * State) :=
  let slots0 := st_slots st in
  let wal0   := st_wal st in
  let tmr0   := st_tmr st in
  let conf0  := st_confirm st in
  let otp0   := st_otp st in
  let rst0   := st_reset st in

  (* Step 1a: Journal Init & K4 TMR MAC authentication *)
  if negb (tmr_mac_valid tmr0) then
    (Enter_Recovery_OS (RM_SerialRescue Err_Verify), st)
  else
  (* Step 1b: Mailbox Fold-In *)
  match step1_mailbox_consume slots0 wal0 tmr0 with
  | Mbx_Err err =>
      (Enter_Recovery_OS (RM_SerialRescue err), st)
  | Mbx_Done slots1 wal1 tmr1 =>
      (* Step 1c: WAL Transaction Reconstruction *)
      match wal_reconstruct_txn wal1 with
      | None =>
          let st_tampered := mkState slots1 wal1 tmr1 conf0 otp0 rst0 in
          (Enter_Recovery_OS (RM_SerialRescue Err_Verify), st_tampered)
      | Some (open_i1, open_exp1) =>
          (* Step 2: Confirmation Check *)
          match step2_confirm_check slots1 wal1 tmr1 conf0 open_i1 open_exp1 with
          | S2_Tampered =>
              let st_s2 := mkState slots1 wal1 tmr1 conf0 otp0 rst0 in
              (Enter_Recovery_OS (RM_SerialRescue Err_Verify), st_s2)
          | S2_Ok slots2 wal2 tmr2 conf2 open_i2 healed2 =>
              (* Step 2.5: Cloud Command Slot Evaluation *)
              let '(slots25, wal25, tmr25, otp25, open_i25) :=
                step2_5_cloud_cmd slots2 wal2 tmr2 otp0 open_i2 in
              (* Step 2.7: Lock-State Gate *)
              if wal_intent_eqb open_i25 WI_DeviceLocked then
                let st_locked := mkState slots25 wal25 tmr25 conf2 otp25 rst0 in
                (Enter_Recovery_OS (RM_SerialRescue Err_DeviceLocked), st_locked)
              else
                (* Step 3: Failure Counter & Rollback Cascade *)
                match step3_failure_and_rollback cfg slots25 wal25 tmr25 rst0 open_i25 healed2 with
                | S3_Panic err tmr3p =>
                    let st_p := mkState slots25 wal25 tmr3p conf2 otp25 rst0 in
                    (Enter_Recovery_OS (RM_SerialRescue err), st_p)
                | S3_Ok slots3 wal3 tmr3 open_i3 healed3 boot_rec3 =>
                    (* Step 4: Update Pipeline *)
                    let '(slots4, wal4, tmr4, open_i4, upd_was_pending) :=
                      step4_update_pipeline slots3 wal3 tmr3 otp25 open_i3 in
                    (* Step 5: Handoff Preparation *)
                    let boot_rec4 :=
                      if upd_was_pending && wal_intent_eqb open_i4 WI_TxnCommit
                      then false else boot_rec3 in
                    let app_hdr_ok := hdr_valid (app_slot slots4) in
                    let fallback_to_rec :=
                      negb boot_rec4 &&
                      negb app_hdr_ok &&
                      recovery_rom_valid slots4 &&
                      (recovery_failure_counter tmr4 <=? cfg_max_recovery_retries cfg) in
                    let boot_rec5 := boot_rec4 || fallback_to_rec in
                    let target_hdr_ok :=
                      if boot_rec5 then recovery_rom_valid slots4 else app_hdr_ok in
                    let target_tsig_ok :=
                      if boot_rec5
                      then recovery_rom_valid slots4
                      else slot_tsig_valid (app_slot slots4) (otp_active_key_index otp25) in
                    if negb target_hdr_ok then
                      let st_nf := mkState slots4 wal4 tmr4 conf2 otp25 rst0 in
                      (Enter_Recovery_OS (RM_SerialRescue Err_NotFound), st_nf)
                    else if negb target_tsig_ok then
                      let st_ver := mkState slots4 wal4 tmr4 conf2 otp25 rst0 in
                      (Enter_Recovery_OS (RM_SerialRescue Err_Verify), st_ver)
                    else
                      let req_conf := wal_intent_eqb open_i4 WI_TxnCommit in
                      let gen_nonce := if req_conf then cfg_fresh_nonce cfg else 0 in
                      let tmr5 := set_tmr_nonce tmr4 gen_nonce in
                      let need_wal_anchor :=
                        negb (wal_intent_eqb open_i4 WI_None) ||
                        healed3 ||
                        upd_was_pending in
                      let wal5 :=
                        if need_wal_anchor
                        then wal_append_valid wal4 open_i4 0
                        else wal4 in
                      let st_final := mkState slots4 wal5 tmr5 conf2 otp25 rst0 in
                      if boot_rec5 then
                        (Enter_Recovery_OS RM_PartitionOS, st_final)
                      else
                        (Boot_App (app_slot slots4) req_conf gen_nonce, st_final)
                end
          end
      end
  end.

Definition eval_boot_wipe_requested (cfg : BootConfig) (st : State) : bool :=
  if negb (tmr_mac_valid (st_tmr st)) then false
  else
    match step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) with
    | Mbx_Err _ => false
    | Mbx_Done slots1 wal1 tmr1 =>
        match wal_reconstruct_txn wal1 with
        | None => false
        | Some (oi1, oe1) =>
            match step2_confirm_check slots1 wal1 tmr1 (st_confirm st) oi1 oe1 with
            | S2_Tampered => false
            | S2_Ok slots2 _ tmr2 _ _ _ =>
                let wipe25 := step2_5_sets_wipe_requested slots2 tmr2 (st_otp st) in
                match fst (eval_boot_state cfg st) with
                | Enter_Recovery_OS (RM_SerialRescue _) => false
                | _ => wipe25
                end
            end
        end
    end.

(* Post-confirmation OTP monotonic ratchet (only invoked after Confirm_OK) *)
Definition confirm_ratchet_otp (st : State) : State :=
  let cur_wal := wal_reconstruct_txn (st_wal st) in
  match cur_wal with
  | Some (WI_None, _) =>
      if (active_nonce (st_tmr st) =? 0) && hdr_valid (app_slot (st_slots st)) then
        let new_floor := Nat.max (otp_min_svn (st_otp st))
                                 (image_svn (app_slot (st_slots st))) in
        mkState
          (st_slots st)
          (st_wal st)
          (st_tmr st)
          (st_confirm st)
          (mkOTPEpoch new_floor (otp_active_key_index (st_otp st)))
          (st_reset st)
      else st
  | _ => st
  end.

(* -------------------------------------------------------------------------- *)
(* 9. Multi-Reboot Execution Model (for Theorem 1 Non-Brickability)           *)
(* -------------------------------------------------------------------------- *)

(* Models the runtime behavior after Stage 1 hands off execution:
   - If the booted image is cryptographically verified, it runs healthy or
     confirms;
   - If an unconfirmed tentative image fails to confirm (any reset reason
     tent_rst: SW, POR, PIN, BROWNOUT, WDT, or HardFault) or an unverified
     app triggers the hardware watchdog (RR_Watchdog), the SoC reboots into
     Stage 1 with cleared volatile RTC confirm store. *)
Definition next_unconfirmed_reboot_state
    (tentative : bool) (tent_rst : ResetReason) (st_after : State) : State :=
  let next_rst := if tentative then tent_rst else RR_Watchdog in
  mkState
    (st_slots st_after)
    (st_wal st_after)
    (st_tmr st_after)
    (mkConfirmStore 0)
    (st_otp st_after)
    next_rst.

(* Step through up to `fuel` consecutive reboots until reaching either a
   cryptographically verified non-tentative Boot_App or Enter_Recovery_OS.
   Returns `(terminal_outcome, final_state, reboots_taken)` where `0` means the
   initial boot already reached a terminal safe outcome. *)
Definition is_verified_boot_app (img : SlotImage) (otp : OTP_Epoch) : bool :=
  sig_valid img &&
  merkle_valid img &&
  hdr_valid img &&
  (otp_min_svn otp <=? image_svn img) &&
  Nat.eqb (key_index img) (otp_active_key_index otp).

Fixpoint run_until_safe
    (cfg : BootConfig) (tent_rst : ResetReason) (fuel : nat) (st : State)
    : (BootOutcome * State * nat) :=
  let '(out, st') := eval_boot_state cfg st in
  match out with
  | Enter_Recovery_OS _ => (out, st', 0)
  | Boot_App img tentative _ =>
      if is_verified_boot_app img (st_otp st') && negb tentative then
        (out, st', 0)
      else
        match fuel with
        | 0 => (out, st', 0)
        | S fuel' =>
            let st_next := next_unconfirmed_reboot_state tentative tent_rst st' in
            let '(out_f, st_f, reboots) := run_until_safe cfg tent_rst fuel' st_next in
            (out_f, st_f, S reboots)
        end
  end.

(* -------------------------------------------------------------------------- *)
(* 10. Sector-Granular Flash Effect & Power-Cut Model (for Theorem 2)         *)
(* -------------------------------------------------------------------------- *)

(* Each physical sector holds either None (erased / torn / CRC-corrupt) or
   Some sector_word (valid sector payload). *)
Definition SectorImage := list (option nat).

Definition lift_clean_sectors (words : list nat) : SectorImage :=
  map Some words.

Fixpoint replace_nth {A : Type} (n : nat) (v : A) (l : list A) : list A :=
  match l, n with
  | [], _ => []
  | _ :: xs, 0 => v :: xs
  | x :: xs, S n' => x :: replace_nth n' v xs
  end.

Definition opt_nat_eqb (a b : option nat) : bool :=
  match a, b with
  | Some x, Some y => Nat.eqb x y
  | None, None => true
  | _, _ => false
  end.

(* Models boot_effect.c zero-wear CRC check + EFF_ERASE + EFF_COPY on sector i *)
Definition copy_sector_completed (src dst : SectorImage) (i : nat) : SectorImage :=
  match nth_error src i, nth_error dst i with
  | Some s_val, Some d_val =>
      if opt_nat_eqb s_val d_val then dst else replace_nth i s_val dst
  | _, _ => dst
  end.

(* Models a power-cut / brownout interrupting EFF_ERASE or EFF_COPY on sector i *)
Definition copy_sector_torn (src dst : SectorImage) (i : nat) : SectorImage :=
  match nth_error src i, nth_error dst i with
  | Some s_val, Some d_val =>
      if opt_nat_eqb s_val d_val then dst else replace_nth i None dst
  | _, _ => dst
  end.

(* Run full resumable copy over indices [start .. start + count - 1] *)
Fixpoint copy_range_complete (src dst : SectorImage) (start count : nat) : SectorImage :=
  match count with
  | 0 => dst
  | S count' =>
      let dst1 := copy_sector_completed src dst start in
      copy_range_complete src dst1 (S start) count'
  end.

(* Run copy interrupted by a power-cut after `steps_before_cut` completed sectors,
   leaving the cut sector torn (if cut occurs before completion). *)
Fixpoint copy_range_cut
    (src dst : SectorImage) (start count cut_at : nat) : SectorImage :=
  match count with
  | 0 => dst
  | S count' =>
      match cut_at with
      | 0 => copy_sector_torn src dst start
      | S cut' =>
          let dst1 := copy_sector_completed src dst start in
          copy_range_cut src dst1 (S start) count' cut'
      end
  end.

Inductive OnewayTxnPhase : Type :=
  | OTP_Backup    : OnewayTxnPhase
  | OTP_Deploy    : OnewayTxnPhase
  | OTP_Committed : OnewayTxnPhase.

Record OnewayFlashState : Type := mkOnewayFlash {
  ow_app     : SectorImage;
  ow_staging : SectorImage;
  ow_backup  : SectorImage;
  ow_phase   : OnewayTxnPhase
}.

(* Execute ONEWAY update (n sectors) interrupted at arbitrary micro-step k:
   - k < n           : torn during Phase 1 BACKUP (App -> Backup) at sector k
   - k = n           : torn while appending WAL phase DEPLOY (Backup complete!)
   - n < k <= 2*n    : torn during Phase 2 DEPLOY (Staging -> App) at sector (k - n - 1)
   - k > 2*n         : full update + WAL TXN_COMMIT completed *)
Definition oneway_update_power_cut (st : OnewayFlashState) (n k : nat) : OnewayFlashState :=
  if k <? n then
    mkOnewayFlash
      (ow_app st)
      (ow_staging st)
      (copy_range_cut (ow_app st) (ow_backup st) 0 n k)
      OTP_Backup
  else if k =? n then
    mkOnewayFlash
      (ow_app st)
      (ow_staging st)
      (copy_range_complete (ow_app st) (ow_backup st) 0 n)
      OTP_Backup
  else if k <=? 2 * n then
    let bkup_done := copy_range_complete (ow_app st) (ow_backup st) 0 n in
    let dep_k := k - (n + 1) in
    mkOnewayFlash
      (copy_range_cut (ow_staging st) (ow_app st) 0 n dep_k)
      (ow_staging st)
      bkup_done
      OTP_Deploy
  else
    let bkup_done := copy_range_complete (ow_app st) (ow_backup st) 0 n in
    let app_done  := copy_range_complete (ow_staging st) (ow_app st) 0 n in
    mkOnewayFlash app_done (ow_staging st) bkup_done OTP_Committed.

(* Resume ONEWAY update cleanly on subsequent reboot *)
Definition oneway_update_resume (st : OnewayFlashState) (n : nat) : OnewayFlashState :=
  match ow_phase st with
  | OTP_Backup =>
      let bkup_done := copy_range_complete (ow_app st) (ow_backup st) 0 n in
      let app_done  := copy_range_complete (ow_staging st) (ow_app st) 0 n in
      mkOnewayFlash app_done (ow_staging st) bkup_done OTP_Committed
  | OTP_Deploy =>
      let app_done  := copy_range_complete (ow_staging st) (ow_app st) 0 n in
      mkOnewayFlash app_done (ow_staging st) (ow_backup st) OTP_Committed
  | OTP_Committed => st
  end.

(* Execute ONEWAY rollback (Backup -> App) interrupted at sector step k,
   followed by reboot resume *)
Definition oneway_rollback_power_cut (st : OnewayFlashState) (n k : nat) : OnewayFlashState :=
  if k <? n then
    mkOnewayFlash
      (copy_range_cut (ow_backup st) (ow_app st) 0 n k)
      (ow_staging st)
      (ow_backup st)
      OTP_Committed
  else
    mkOnewayFlash
      (copy_range_complete (ow_backup st) (ow_app st) 0 n)
      (ow_staging st)
      (ow_backup st)
      OTP_Committed.

Definition oneway_rollback_resume (st : OnewayFlashState) (n : nat) : OnewayFlashState :=
  mkOnewayFlash
    (copy_range_complete (ow_backup st) (ow_app st) 0 n)
    (ow_staging st)
    (ow_backup st)
    OTP_Committed.

(* 3-sector TMR Quorum flush interrupted at sector step k in {0, 1, 2, 3} *)
Definition tmr_flush_power_cut
    (old_tmr new_tmr : TMR_Counters) (k : nat) : TMR_Quorum :=
  match k with
  | 0 => mkTMRQuorum None         (Some old_tmr) (Some old_tmr) (* Cut erasing sec0 *)
  | 1 => mkTMRQuorum (Some new_tmr) None         (Some old_tmr) (* Cut erasing sec1 *)
  | 2 => mkTMRQuorum (Some new_tmr) (Some new_tmr) None         (* Cut erasing sec2 *)
  | _ => mkTMRQuorum (Some new_tmr) (Some new_tmr) (Some new_tmr)
  end.

(* -------------------------------------------------------------------------- *)
(* 11. In-Place Swap-Move (N+1 Shift) & Swap-Scratch Sector-Step Semantics    *)
(*     Mirrors boot_transport_swapmove.c & boot_swap.c (SWAPSCRATCH)          *)
(* -------------------------------------------------------------------------- *)

Definition sec_at (img : SectorImage) (i : nat) : option nat :=
  match nth_error img i with
  | Some v => v
  | None => None
  end.

Definition opt_sub (cut : option nat) (d : nat) : option nat :=
  match cut with
  | None => None
  | Some k => Some (k - d)
  end.

Inductive SwapMovePhase : Type :=
  | SMP_Move : SwapMovePhase
  | SMP_Swap : SwapMovePhase
  | SMP_Done : SwapMovePhase.

Record SwapMoveState : Type := mkSwapMove {
  sm_P        : SectorImage; (* Primary slot: N + 1 physical sectors [0 .. N] *)
  sm_S        : SectorImage; (* Secondary slot: N physical sectors [0 .. N-1] *)
  sm_phase    : SwapMovePhase;
  sm_idx      : nat;         (* WAL step_idx checkpoint *)
  sm_resuming : bool;        (* True iff WAL holds active SWAP checkpoint at sm_idx *)
  sm_cs       : option nat;  (* Checkpointed expected S[i] content *)
  sm_cp       : option nat   (* Checkpointed expected P[i+1] content *)
}.

Definition shift_up_completed (pri : SectorImage) (i : nat) : SectorImage :=
  let v_src := sec_at pri i in
  let v_dst := sec_at pri (S i) in
  if opt_nat_eqb v_src v_dst then pri else replace_nth (S i) v_src pri.

Definition shift_up_torn (pri : SectorImage) (i : nat) : SectorImage :=
  let v_src := sec_at pri i in
  let v_dst := sec_at pri (S i) in
  if opt_nat_eqb v_src v_dst then pri else replace_nth (S i) None pri.

(* Ascending SWAP phase (boot_transport_swapmove.c:205-249):
   For i = N - rem .. N - 1, checkpoints (SMP_Swap, i, cs, cp) and executes:
     Sub-step (a): if pri[i] != cs, copy sec[i] -> pri[i]
     Sub-step (b): if sec[i] != cp, copy pri[i+1] -> sec[i] *)
Fixpoint sm_swap_loop
    (rem N : nat) (pri sec : SectorImage)
    (resuming : bool) (cs cp : option nat) (cut : option nat)
    : SwapMoveState :=
  match rem with
  | 0 => mkSwapMove pri sec SMP_Done N false None None
  | S rem' =>
      let i := N - S rem' in
      let cs0 := if resuming then cs else sec_at sec i in
      let cp0 := if resuming then cp else sec_at pri (S i) in
      if negb resuming && match cut with Some 0 => true | _ => false end then
        mkSwapMove pri sec SMP_Swap i true cs0 cp0
      else
        let cut1 := if resuming then cut else opt_sub cut 1 in
        let p_has_s := opt_nat_eqb (sec_at pri i) cs0 in
        let s_has_p := opt_nat_eqb (sec_at sec i) cp0 in
        if p_has_s then
          if s_has_p then
            sm_swap_loop rem' N pri sec false None None cut1
          else
            match cut1 with
            | Some 0 => mkSwapMove pri (replace_nth i None sec) SMP_Swap i true cs0 cp0
            | Some 1 => mkSwapMove pri (replace_nth i (sec_at pri (S i)) sec) SMP_Swap i true cs0 cp0
            | _ =>
                sm_swap_loop rem' N pri (replace_nth i (sec_at pri (S i)) sec)
                  false None None (opt_sub cut1 2)
            end
        else
          match cut1 with
          | Some 0 => mkSwapMove (replace_nth i None pri) sec SMP_Swap i true cs0 cp0
          | Some 1 => mkSwapMove (replace_nth i (sec_at sec i) pri) sec SMP_Swap i true cs0 cp0
          | _ =>
              let pri1 := replace_nth i (sec_at sec i) pri in
              let cut2 := opt_sub cut1 2 in
              if s_has_p then
                sm_swap_loop rem' N pri1 sec false None None cut2
              else
                match cut2 with
                | Some 0 => mkSwapMove pri1 (replace_nth i None sec) SMP_Swap i true cs0 cp0
                | Some 1 => mkSwapMove pri1 (replace_nth i (sec_at pri1 (S i)) sec) SMP_Swap i true cs0 cp0
                | _ =>
                    sm_swap_loop rem' N pri1 (replace_nth i (sec_at pri1 (S i)) sec)
                      false None None (opt_sub cut2 2)
                end
          end
  end.

(* Descending MOVE phase (boot_transport_swapmove.c:174-202):
   For cnt = S i down to 1, checkpoints (SMP_Move, i) and shifts pri[i] -> pri[i+1],
   then transitions directly into sm_swap_loop over 0 .. N-1. *)
Fixpoint sm_move_loop
    (cnt N : nat) (pri sec : SectorImage) (cut : option nat) : SwapMoveState :=
  match cnt with
  | 0 => sm_swap_loop N N pri sec false None None cut
  | S i =>
      match cut with
      | Some 0 => mkSwapMove (shift_up_torn pri i) sec SMP_Move i false None None
      | Some 1 => mkSwapMove (shift_up_completed pri i) sec SMP_Move i false None None
      | _ => sm_move_loop i N (shift_up_completed pri i) sec (opt_sub cut 2)
      end
  end.

Definition swapmove_init
    (A B : SectorImage) (spare : option nat) (N : nat) : SwapMoveState :=
  mkSwapMove (A ++ [spare]) B SMP_Move (N - 1) false None None.

Definition swapmove_exec
    (st : SwapMoveState) (N : nat) (cut : option nat) : SwapMoveState :=
  match sm_phase st with
  | SMP_Move =>
      sm_move_loop (S (sm_idx st)) N (sm_P st) (sm_S st) cut
  | SMP_Swap =>
      sm_swap_loop (N - sm_idx st) N (sm_P st) (sm_S st)
                   (sm_resuming st) (sm_cs st) (sm_cp st) cut
  | SMP_Done => st
  end.

Definition swapmove_power_cut (st : SwapMoveState) (N k : nat) : SwapMoveState :=
  swapmove_exec st N (Some k).

Definition swapmove_resume (st : SwapMoveState) (N : nat) : SwapMoveState :=
  swapmove_exec st N None.

(* Swap-Move Rollback (boot_transport_swapmove.c:287-358):
   Resumable 1-way copy sec[0..N-1] -> pri[0..N-1] restoring exact A into App_Slot. *)
Definition swapmove_rollback_power_cut
    (pri sec : SectorImage) (N k : nat) : SectorImage :=
  if k <? N then copy_range_cut sec pri 0 N k
  else copy_range_complete sec pri 0 N.

Definition swapmove_rollback_resume (pri sec : SectorImage) (N : nat) : SectorImage :=
  copy_range_complete sec pri 0 N.

(* Swap-Scratch 3-Phase Ring (boot_swap.c:666-775 & boot_transport_swapscratch.c):
   Exchanges Dest[0..N-1] (App) <-> Src[0..N-1] (Staging) via 1-sector Scratch. *)
Record SwapScratchState : Type := mkSwapScratch {
  ss_dest     : SectorImage; (* App_Slot: N sectors *)
  ss_src      : SectorImage; (* Staging_Slot: N sectors *)
  ss_scratch  : option nat;  (* Dedicated 1-sector Scratch_Slot *)
  ss_done     : bool;
  ss_idx      : nat;         (* WAL step_idx checkpoint *)
  ss_resuming : bool;        (* True iff WAL holds active chunk checkpoint at ss_idx *)
  ss_cs       : option nat;  (* Expected Src[i] content *)
  ss_cd       : option nat   (* Expected Dest[i] content *)
}.

Fixpoint ss_loop
    (rem N : nat) (dest src : SectorImage) (scr : option nat)
    (resuming : bool) (cs cd : option nat) (cut : option nat)
    : SwapScratchState :=
  match rem with
  | 0 => mkSwapScratch dest src scr true N false None None
  | S rem' =>
      let i := N - S rem' in
      if negb resuming && opt_nat_eqb (sec_at dest i) (sec_at src i) then
        ss_loop rem' N dest src scr false None None cut
      else
        let cs0 := if resuming then cs else sec_at src i in
        let cd0 := if resuming then cd else sec_at dest i in
        if negb resuming && match cut with Some 0 => true | _ => false end then
          mkSwapScratch dest src scr false i true cs0 cd0
        else
          let cut1 := if resuming then cut else opt_sub cut 1 in
          let dest_has_src := opt_nat_eqb (sec_at dest i) cs0 in
          let src_has_dest := opt_nat_eqb (sec_at src i) cd0 in
          let scr_has_dest := opt_nat_eqb scr cd0 in
          if dest_has_src && src_has_dest then
            ss_loop rem' N dest src scr false None None cut1
          else if dest_has_src then
            (* Phase C only: Scratch -> Src[i] *)
            match cut1 with
            | Some 0 => mkSwapScratch dest (replace_nth i None src) scr false i true cs0 cd0
            | Some 1 => mkSwapScratch dest (replace_nth i scr src) scr false i true cs0 cd0
            | _ =>
                ss_loop rem' N dest (replace_nth i scr src) scr
                  false None None (opt_sub cut1 2)
            end
          else if scr_has_dest then
            (* Phase B (Src[i] -> Dest[i]) then Phase C (Scratch -> Src[i]) *)
            let dest1 := replace_nth i (sec_at src i) dest in
            let src1  := replace_nth i scr src in
            match cut1 with
            | Some 0 => mkSwapScratch (replace_nth i None dest) src scr false i true cs0 cd0
            | Some 1 => mkSwapScratch dest1 src scr false i true cs0 cd0
            | Some 2 => mkSwapScratch dest1 (replace_nth i None src) scr false i true cs0 cd0
            | Some 3 => mkSwapScratch dest1 src1 scr false i true cs0 cd0
            | _ =>
                ss_loop rem' N dest1 src1 scr false None None (opt_sub cut1 4)
            end
          else
            (* Phase A (Dest[i] -> Scratch), Phase B (Src[i] -> Dest[i]), Phase C (Scratch -> Src[i]) *)
            let scr1  := sec_at dest i in
            let dest1 := replace_nth i (sec_at src i) dest in
            let src1  := replace_nth i scr1 src in
            match cut1 with
            | Some 0 => mkSwapScratch dest src None false i true cs0 cd0
            | Some 1 => mkSwapScratch dest src scr1 false i true cs0 cd0
            | Some 2 => mkSwapScratch (replace_nth i None dest) src scr1 false i true cs0 cd0
            | Some 3 => mkSwapScratch dest1 src scr1 false i true cs0 cd0
            | Some 4 => mkSwapScratch dest1 (replace_nth i None src) scr1 false i true cs0 cd0
            | Some 5 => mkSwapScratch dest1 src1 scr1 false i true cs0 cd0
            | _ =>
                ss_loop rem' N dest1 src1 scr1 false None None (opt_sub cut1 6)
            end
  end.

Definition swapscratch_init
    (A B : SectorImage) (init_scr : option nat) : SwapScratchState :=
  mkSwapScratch A B init_scr false 0 false None None.

Definition swapscratch_exec
    (st : SwapScratchState) (N : nat) (cut : option nat) : SwapScratchState :=
  if ss_done st then st
  else ss_loop (N - ss_idx st) N (ss_dest st) (ss_src st) (ss_scratch st)
               (ss_resuming st) (ss_cs st) (ss_cd st) cut.

Definition swapscratch_power_cut
    (st : SwapScratchState) (N k : nat) : SwapScratchState :=
  swapscratch_exec st N (Some k).

Definition swapscratch_resume
    (st : SwapScratchState) (N : nat) : SwapScratchState :=
  swapscratch_exec st N None.

(* -------------------------------------------------------------------------- *)
(* 12. Synced Killswitch Aliases, TDR1-02/TDR1-03 Telemetry & Dual-Failure    *)
(* -------------------------------------------------------------------------- *)

(* With HIGH-31 and LOW-13 landed in production boot_mailbox.c & boot_state.c,
   the canonical step1_mailbox_consume, step2_5_cloud_cmd, and eval_boot_state
   are definitionally identical to their lock-hardened specifications. *)
Definition step1_mailbox_consume_lock_hardened := step1_mailbox_consume.
Definition step2_5_cloud_cmd_strict_lock := step2_5_cloud_cmd.
Definition eval_boot_state_lock_hardened := eval_boot_state.

(* TDR1-02 (boot_state.c:270-295, 1969, 2133-2152 & boot_main.c:540-553):
   WAL_TMR_VERSION_8 separates ratified app_* identity from tentative pending_*
   identity (WAL_TMR_PENDING_META_BIT = 0x80U). *)
Definition tmr_stage_pending_meta
    (meta : TmrAppMeta) (cand : AppIdentityMeta) : TmrAppMeta :=
  mkTmrAppMeta (tam_ratified meta) (Some cand).

Definition promote_pending_app_meta_on_confirm (meta : TmrAppMeta) : TmrAppMeta :=
  match tam_pending meta with
  | Some cand => mkTmrAppMeta cand None
  | None      => meta
  end.

Definition clear_pending_app_meta_on_rollback (meta : TmrAppMeta) : TmrAppMeta :=
  mkTmrAppMeta (tam_ratified meta) None.

Definition select_handoff_persisted_identity
    (is_tentative_boot : bool) (meta : TmrAppMeta) : AppIdentityMeta :=
  match is_tentative_boot, tam_pending meta with
  | true, Some cand => cand
  | _, _            => tam_ratified meta
  end.

(* Complete single-boot TDR1-02 metadata transition indexed by Step 2/3/4 action *)
Inductive MetaStepEvent : Type :=
  | MSE_Idle            : MetaStepEvent
  | MSE_ApplyTentative  : AppIdentityMeta -> MetaStepEvent
  | MSE_ConfirmCommit   : bool (* auth_ok *) -> MetaStepEvent
  | MSE_RollbackRevert  : MetaStepEvent
  | MSE_RejectOrDefer   : MetaStepEvent.

Definition eval_tmr_meta_step
    (ev : MetaStepEvent) (meta : TmrAppMeta) : (TmrAppMeta * bool (* is_tentative *)) :=
  match ev with
  | MSE_Idle =>
      (meta, match tam_pending meta with Some _ => true | None => false end)
  | MSE_ApplyTentative cand =>
      (tmr_stage_pending_meta meta cand, true)
  | MSE_ConfirmCommit auth_ok =>
      if auth_ok then (promote_pending_app_meta_on_confirm meta, false)
      else (meta, match tam_pending meta with Some _ => true | None => false end)
  | MSE_RollbackRevert =>
      (clear_pending_app_meta_on_rollback meta, false)
  | MSE_RejectOrDefer =>
      (meta, false)
  end.

(* TDR1-03 (boot_state.c:325-330, 475-481, 1569-1620 & boot_main.c:527-566):
   Commit-point discipline for candidate security metadata, update outcome
   {0=None, 1=Applied, 2=Rejected, 3=Reverted, 4=Deferred}, and pre-heal
   observed_failure_count preservation across rollback. *)
Inductive TelemetryNextWal : Type :=
  | TNW_KeepResume   : TelemetryNextWal (* transport_id != 0 on fatal error *)
  | TNW_None         : TelemetryNextWal
  | TNW_TxnCommit    : TelemetryNextWal
  | TNW_SleepBackoff : TelemetryNextWal.

Definition eval_update_commit_point
    (inp : PipelineCommitInput) (transport_started : bool)
    (meta : TmrAppMeta) (tmr_bf : nat)
    : (TmrAppMeta * DiagTelemetrySnapshot * TelemetryNextWal * bool (* flow_ok *)) :=
  match inp with
  | PCI_Ok svn cand =>
      let meta' := tmr_stage_pending_meta meta cand in
      let snap  := mkDiagSnapshot UDO_Applied (Some (svn, cand))
                     (select_handoff_persisted_identity true meta') 0 in
      (meta', snap, TNW_TxnCommit, true)
  | PCI_Defer _ =>
      let snap := mkDiagSnapshot UDO_Deferred None
                    (select_handoff_persisted_identity false meta) tmr_bf in
      (meta, snap, TNW_SleepBackoff, true)
  | PCI_Reject _ _ =>
      let snap := mkDiagSnapshot UDO_Rejected None
                    (select_handoff_persisted_identity false meta) tmr_bf in
      if transport_started then
        (meta, snap, TNW_KeepResume, false)
      else
        (meta, snap, TNW_None, true)
  | PCI_FatalHw _ _ =>
      let snap := mkDiagSnapshot UDO_Rejected None
                    (select_handoff_persisted_identity false meta) tmr_bf in
      (meta, snap, if transport_started then TNW_KeepResume else TNW_KeepResume, false)
  end.

Definition eval_rollback_telemetry
    (rollback_done_unhealed : bool) (pre_heal_bf : nat) (meta : TmrAppMeta)
    : (TmrAppMeta * DiagTelemetrySnapshot * nat (* post_tmr_bf *)) :=
  let obs_cnt :=
    if rollback_done_unhealed then
      if 0 <? pre_heal_bf then pre_heal_bf else 1
    else
      pre_heal_bf in
  let meta' := clear_pending_app_meta_on_rollback meta in
  let post_bf := 0 in
  let eff_fail_cnt := Nat.max obs_cnt post_bf in
  let snap := mkDiagSnapshot UDO_Reverted None
                (select_handoff_persisted_identity false meta') eff_fail_cnt in
  (meta', snap, post_bf).

(* Dual-Failure Escalation Loop (for Extension Theorem 4b):
   Models repeated crashes/faults of BOTH App_Slot_0 AND Recovery_OS
   (RM_PartitionOS) until Stage 1 escalates to terminal Enter_Serial_Rescue. *)
Definition is_serial_rescue_outcome (out : BootOutcome) : bool :=
  match out with
  | Enter_Recovery_OS (RM_SerialRescue _) => true
  | _ => false
  end.

Definition next_dual_fault_reboot_state
    (fault_rst : ResetReason) (st_after : State) : State :=
  mkState
    (st_slots st_after)
    (st_wal st_after)
    (st_tmr st_after)
    (mkConfirmStore 0)
    (st_otp st_after)
    fault_rst.

Fixpoint run_dual_fault_until_serial_rescue
    (cfg : BootConfig) (fault_rst : ResetReason) (fuel : nat) (st : State)
    : (BootOutcome * State * nat) :=
  let '(out, st') := eval_boot_state cfg st in
  if is_serial_rescue_outcome out then
    (out, st', 0)
  else
    match fuel with
    | 0 => (out, st', 0)
    | S fuel' =>
        let st_next := next_dual_fault_reboot_state fault_rst st' in
        let '(out_f, st_f, reboots) :=
          run_dual_fault_until_serial_rescue cfg fault_rst fuel' st_next in
        (out_f, st_f, S reboots)
    end.
