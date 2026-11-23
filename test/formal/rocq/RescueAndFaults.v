(* ========================================================================== *)
(* Toob-Loader Formal Verification — Stage 1.5 Rescue, Recovery & FIH/CFI    *)
(* File: test/formal/rocq/RescueAndFaults.v                                   *)
(* Covers:                                                                    *)
(*   FV-15 (P1): stage15_2fa_rescue_replay_free                               *)
(*               recovery_os_heals_to_boot_app                                *)
(*   FV-16 (P2): fih_single_fault_soundness                                   *)
(*               non_abelian_cfi_order_soundness                              *)
(* Zero Admitted, Zero Axioms.                                                *)
(* ========================================================================== *)

From Stdlib Require Import List Arith Bool PeanoNat ZArith Lia.
Import ListNotations.

From ToobBoot Require Import BootModel BootTransitions BootTheorems.

(* ========================================================================== *)
(* SECTION 1: FV-15 — Stage 1.5 2FA Ed25519 Serial Rescue & Recovery-OS Heal  *)
(*            Mirrors boot_panic.c, recovery/, boot_mailbox.c, boot_state.c   *)
(* ========================================================================== *)

Inductive RescueCommand : Type :=
  | RCmd_FlashStaging : SlotImage -> RescueCommand
  | RCmd_LockDevice   : RescueCommand (* LCK *)
  | RCmd_UnlockDevice : RescueCommand (* ULK *)
  | RCmd_DiagQuery    : RescueCommand.

Record RescueToken2FA : Type := mkRescueToken {
  rt2_cmd              : RescueCommand;
  rt2_seq_id           : nat;  (* Must equal otp_rescue_seq + 1 *)
  rt2_bound_challenge  : nat;  (* TRNG session challenge inside signed transcript *)
  rt2_ed25519_sig_ok   : bool  (* 2FA rescue authority Ed25519 signature valid *)
}.

Record Stage15RescueState : Type := mkRescueState {
  s15_otp_seq        : nat;  (* Hardware OTP monotonic rescue fuse counter *)
  s15_challenge      : nat;  (* Ephemeral TRNG challenge (> 0) *)
  s15_device_locked  : bool; (* Soft-lock state enforced by Stage 1.5 *)
  s15_backoff_exp    : nat;  (* RTC backup exponential backoff exponent *)
  s15_staged_slot    : SlotImage
}.

Inductive Stage15RescueResult : Type :=
  | S15_Accepted       : Stage15RescueState -> Stage15RescueResult
  | S15_CooldownActive : Stage15RescueState -> Stage15RescueResult
  | S15_AuthRejected   : Stage15RescueState -> Stage15RescueResult
  | S15_LockedRejected : Stage15RescueState -> Stage15RescueResult.

Definition s15_max_backoff_exp : nat := 10.

Definition extract_s15_state (r : Stage15RescueResult) : Stage15RescueState :=
  match r with
  | S15_Accepted s       => s
  | S15_CooldownActive s => s
  | S15_AuthRejected s   => s
  | S15_LockedRejected s => s
  end.

(* Stage 1.5 2FA Serial Rescue Evaluator (boot_panic.c):
   1. Enforces RTC exponential backoff cooldown (2 ^ s15_backoff_exp seconds).
   2. Requires valid 2FA Ed25519 signature, exact match with current TRNG
      challenge (> 0), and strict sequence_id == s15_otp_seq + 1.
      On auth failure: increments RTC backoff exponent (up to cap) and rotates
      TRNG challenge without burning OTP or mutating flash/lock state.
   3. Enforces LCK/ULK gate: RCmd_FlashStaging is blocked while s15_device_locked
      is true until an authenticated RCmd_UnlockDevice succeeds.
   4. On acceptance: atomically burns OTP sequence to s15_otp_seq + 1, resets
      backoff to 0, rotates TRNG challenge, and applies the command. *)
Definition eval_stage15_2fa_rescue
    (st : Stage15RescueState)
    (tok : RescueToken2FA)
    (elapsed_sec : nat)
    (next_trng_challenge : nat)
    : Stage15RescueResult :=
  if elapsed_sec <? Nat.pow 2 (s15_backoff_exp st) then
    S15_CooldownActive st
  else
    let auth_ok :=
      rt2_ed25519_sig_ok tok &&
      (0 <? s15_challenge st) &&
      (rt2_bound_challenge tok =? s15_challenge st) &&
      (rt2_seq_id tok =? S (s15_otp_seq st)) in
    if negb auth_ok then
      let next_exp := Nat.min s15_max_backoff_exp (S (s15_backoff_exp st)) in
      S15_AuthRejected
        (mkRescueState (s15_otp_seq st) next_trng_challenge
                       (s15_device_locked st) next_exp (s15_staged_slot st))
    else
      match rt2_cmd tok with
      | RCmd_FlashStaging img =>
          if s15_device_locked st then
            S15_LockedRejected
              (mkRescueState (s15_otp_seq st) next_trng_challenge
                             true (s15_backoff_exp st) (s15_staged_slot st))
          else
            S15_Accepted
              (mkRescueState (S (s15_otp_seq st)) next_trng_challenge
                             false 0 img)
      | RCmd_LockDevice =>
          S15_Accepted
            (mkRescueState (S (s15_otp_seq st)) next_trng_challenge
                           true 0 (s15_staged_slot st))
      | RCmd_UnlockDevice =>
          S15_Accepted
            (mkRescueState (S (s15_otp_seq st)) next_trng_challenge
                           false 0 (s15_staged_slot st))
      | RCmd_DiagQuery =>
          S15_Accepted
            (mkRescueState (S (s15_otp_seq st)) next_trng_challenge
                           (s15_device_locked st) 0 (s15_staged_slot st))
      end.

(* Theorem FV-15a: Stage 1.5 2FA Serial Rescue Anti-Replay, Lock Gate & Backoff *)
Theorem stage15_2fa_rescue_replay_free :
  forall st tok elapsed next_ch,
    let res := eval_stage15_2fa_rescue st tok elapsed next_ch in
    let st' := extract_s15_state res in
    (* 1. Monotonic OTP rescue sequence counter across all outcomes *)
    s15_otp_seq st <= s15_otp_seq st' /\
    (* 2. Unauthenticated, wrong-challenge, or wrong-sequence tokens never mutate
          OTP, lock state, or flash, and strictly ratchet RTC backoff toward cap *)
    ((rt2_ed25519_sig_ok tok = false \/
      rt2_bound_challenge tok <> s15_challenge st \/
      rt2_seq_id tok <> S (s15_otp_seq st)) ->
     (forall s_acc, res <> S15_Accepted s_acc) /\
     s15_otp_seq st' = s15_otp_seq st /\
     s15_device_locked st' = s15_device_locked st /\
     s15_staged_slot st' = s15_staged_slot st /\
     (Nat.pow 2 (s15_backoff_exp st) <= elapsed ->
      s15_backoff_exp st' = Nat.min s15_max_backoff_exp (S (s15_backoff_exp st)))) /\
    (* 3. Lock enforcement: locked device rejects RCmd_FlashStaging *)
    (forall img s_acc,
       s15_device_locked st = true ->
       rt2_cmd tok = RCmd_FlashStaging img ->
       res <> S15_Accepted s_acc /\
       s15_staged_slot st' = s15_staged_slot st) /\
    (* 4. Replay immunity: once tok is accepted, replaying tok on ANY subsequent
          state st_later with s15_otp_seq st' <= s15_otp_seq st_later is rejected *)
    (forall s_acc st_later elapsed2 next_ch2 s_acc2,
       res = S15_Accepted s_acc ->
       s15_otp_seq s_acc <= s15_otp_seq st_later ->
       eval_stage15_2fa_rescue st_later tok elapsed2 next_ch2 <> S15_Accepted s_acc2).
Proof.
  intros st tok elapsed next_ch.
  remember (eval_stage15_2fa_rescue st tok elapsed next_ch) as res eqn:Eres.
  cbv zeta.
  unfold eval_stage15_2fa_rescue in Eres; cbv zeta in Eres.
  subst res.
  set (auth_ok := rt2_ed25519_sig_ok tok &&
                  (0 <? s15_challenge st) &&
                  (rt2_bound_challenge tok =? s15_challenge st) &&
                  (rt2_seq_id tok =? S (s15_otp_seq st))) in *.
  destruct (elapsed <? Nat.pow 2 (s15_backoff_exp st)) eqn:Ecool.
  - apply Nat.ltb_lt in Ecool.
    simpl; split; [lia|].
    split.
    + intros _; repeat split; try reflexivity; [intros; discriminate | lia].
    + split.
      * intros; split; [discriminate | reflexivity].
      * intros; discriminate.
  - apply Nat.ltb_ge in Ecool.
    destruct (negb auth_ok) eqn:Enauth.
    + simpl; split; [lia|].
      split.
      * intros _; repeat split; try reflexivity; intros; discriminate.
      * split.
        -- intros; split; [discriminate | reflexivity].
        -- intros; discriminate.
    + apply Bool.negb_false_iff in Enauth.
      assert (Hauth_parts :
        rt2_ed25519_sig_ok tok = true /\
        rt2_bound_challenge tok = s15_challenge st /\
        rt2_seq_id tok = S (s15_otp_seq st)).
      { unfold auth_ok in Enauth; rewrite !Bool.andb_true_iff in Enauth.
        destruct Enauth as [[[Hs _] Hch] Hsq].
        apply Nat.eqb_eq in Hch; apply Nat.eqb_eq in Hsq; auto. }
      destruct Hauth_parts as [Hsig [Hch Hsq]].
      assert (Hno_bad :
        rt2_ed25519_sig_ok tok = false \/
        rt2_bound_challenge tok <> s15_challenge st \/
        rt2_seq_id tok <> S (s15_otp_seq st) -> False)
        by (intros [A|[B|C]]; congruence).
      assert (Hreplay_impossible :
        forall st_later elapsed2 next_ch2 s_acc2,
          S (s15_otp_seq st) <= s15_otp_seq st_later ->
          eval_stage15_2fa_rescue st_later tok elapsed2 next_ch2 <> S15_Accepted s_acc2).
      { intros st_later elapsed2 next_ch2 s_acc2 Hge.
        unfold eval_stage15_2fa_rescue; cbv zeta.
        destruct (elapsed2 <? Nat.pow 2 (s15_backoff_exp st_later)); [discriminate|].
        assert (Eseq_f : (rt2_seq_id tok =? S (s15_otp_seq st_later)) = false)
          by (apply Nat.eqb_neq; lia).
        rewrite Eseq_f, Bool.andb_false_r; simpl; discriminate. }
      destruct (rt2_cmd tok) as [img | | | ] eqn:Ecmd.
      * destruct (s15_device_locked st) eqn:Elock; simpl.
        -- split; [lia | split; [intro Hb; exfalso; exact (Hno_bad Hb)|]].
           split; [intros; split; [discriminate | reflexivity] | intros; discriminate].
        -- split; [lia | split; [intro Hb; exfalso; exact (Hno_bad Hb)|]].
           split; [intros ? ? Hl; congruence|].
           intros s_acc st_later elapsed2 next_ch2 s_acc2 Hacc Hle.
           inversion Hacc; subst s_acc; simpl in Hle.
           exact (Hreplay_impossible st_later elapsed2 next_ch2 s_acc2 Hle).
      * simpl; split; [lia | split; [intro Hb; exfalso; exact (Hno_bad Hb)|]].
        split; [intros ? ? _ Hc; discriminate Hc|].
        intros s_acc st_later elapsed2 next_ch2 s_acc2 Hacc Hle.
        inversion Hacc; subst s_acc; simpl in Hle.
        exact (Hreplay_impossible st_later elapsed2 next_ch2 s_acc2 Hle).
      * simpl; split; [lia | split; [intro Hb; exfalso; exact (Hno_bad Hb)|]].
        split; [intros ? ? _ Hc; discriminate Hc|].
        intros s_acc st_later elapsed2 next_ch2 s_acc2 Hacc Hle.
        inversion Hacc; subst s_acc; simpl in Hle.
        exact (Hreplay_impossible st_later elapsed2 next_ch2 s_acc2 Hle).
      * simpl; split; [lia | split; [intro Hb; exfalso; exact (Hno_bad Hb)|]].
        split; [intros ? ? _ Hc; discriminate Hc|].
        intros s_acc st_later elapsed2 next_ch2 s_acc2 Hacc Hle.
        inversion Hacc; subst s_acc; simpl in Hle.
        exact (Hreplay_impossible st_later elapsed2 next_ch2 s_acc2 Hle).
Qed.

(* FV-15b: Recovery-OS XMODEM Signed Bundle -> Cumulative Mailbox -> Boot_App
   Models Recovery-OS writing a verified image into staging_slot and posting
   the cumulative mailbox request TOOB_REQ_RECOVERY_RESOLVED | TOOB_REQ_UPDATE_PENDING
   with seq = last_mbx_seq + 1, followed by Stage 1 rebooting via eval_boot_state. *)
Definition recovery_os_post_xmodem_bundle
    (st_after_rec_entry : State) (healed_img : SlotImage) (reboot_rst : ResetReason)
    : State :=
  let s0 := st_slots st_after_rec_entry in
  let t0 := st_tmr st_after_rec_entry in
  let mbx := MBX_Record true (S (last_mbx_seq t0)) false true true 0 in
  let slots' := mkFlashSlots (app_slot s0) healed_img (backup_slot s0)
                             (recovery_rom_valid s0) CC_Empty mbx in
  mkState slots' (st_wal st_after_rec_entry) t0 (mkConfirmStore 0)
          (st_otp st_after_rec_entry) reboot_rst.

(* Theorem FV-15b: Degraded State Enters Recovery OS and Heals to Boot_App in
   1 Reboot After XMODEM Signed Bundle + Cumulative Mailbox Submission *)
Theorem recovery_os_heals_to_boot_app :
  forall cfg st_deg healed_img reboot_rst,
    tmr_mac_valid (st_tmr st_deg) = true ->
    mailbox_slot (st_slots st_deg) = MBX_Empty ->
    cloud_slot (st_slots st_deg) = CC_Empty ->
    wal_reconstruct_txn (st_wal st_deg) = Some (WI_None, 0) ->
    active_nonce (st_tmr st_deg) = 0 ->
    cfg_max_retries cfg < boot_failure_counter (st_tmr st_deg) ->
    recovery_failure_counter (st_tmr st_deg) < cfg_max_recovery_retries cfg ->
    recovery_rom_valid (st_slots st_deg) = true ->
    staging_can_apply healed_img (heal_tmr_counters (st_tmr st_deg)) (st_otp st_deg) = true ->
    (* 1. Degraded boot enters Enter_Recovery_OS RM_PartitionOS *)
    let '(out1, st_rec) := eval_boot_state cfg st_deg in
    out1 = Enter_Recovery_OS RM_PartitionOS /\
    (* 2. After Recovery OS stages verified XMODEM bundle & posts cumulative
          mailbox, the very next boot heals counters and boots Boot_App! *)
    let st_xmodem := recovery_os_post_xmodem_bundle st_rec healed_img reboot_rst in
    let '(out2, st_healed) := eval_boot_state cfg st_xmodem in
    out2 = Boot_App healed_img true (cfg_fresh_nonce cfg) /\
    boot_failure_counter (st_tmr st_healed) = 0 /\
    recovery_failure_counter (st_tmr st_healed) = 0.
Proof.
  intros cfg st_deg healed_img reboot_rst
         Hmac Hmbx0 Hcld0 Hwal0 Han0 Hbf_gt Hrf_lt Hrom Hcan.
  destruct (eval_boot_state cfg st_deg) as [out1 st_rec] eqn:Eboot1.
  cbv zeta.
  (* Step through Boot 1: st_deg -> Enter_Recovery_OS RM_PartitionOS *)
  unfold eval_boot_state in Eboot1; cbv zeta in Eboot1.
  rewrite Hmac in Eboot1; simpl in Eboot1.
  unfold step1_mailbox_consume in Eboot1; rewrite Hmbx0, Hwal0 in Eboot1; simpl in Eboot1.
  unfold step2_confirm_check in Eboot1; cbv zeta in Eboot1.
  rewrite Han0 in Eboot1; simpl in Eboot1.
  unfold step2_5_cloud_cmd in Eboot1; rewrite Hcld0 in Eboot1; simpl in Eboot1.
  unfold step3_failure_and_rollback in Eboot1; cbv zeta in Eboot1; simpl in Eboot1.
  rewrite !Bool.andb_true_r in Eboot1.
  set (t_acc := if rst_indicates_crash (st_reset st_deg)
                then apply_crash_accum cfg (st_tmr st_deg)
                else st_tmr st_deg) in *.
  assert (Htacc_props :
    tmr_mac_valid t_acc = true /\
    tmr_app_svn t_acc = tmr_app_svn (st_tmr st_deg) /\
    tmr_stage1_svn t_acc = tmr_stage1_svn (st_tmr st_deg) /\
    last_mbx_seq t_acc = last_mbx_seq (st_tmr st_deg) /\
    last_cloud_issued_at t_acc = last_cloud_issued_at (st_tmr st_deg) /\
    cfg_max_retries cfg < boot_failure_counter t_acc /\
    recovery_failure_counter t_acc <= cfg_max_recovery_retries cfg).
  { unfold t_acc, apply_crash_accum.
    destruct (rst_indicates_crash (st_reset st_deg)); [|repeat split; assumption || lia].
    assert (Egt : (cfg_max_retries cfg <? boot_failure_counter (st_tmr st_deg)) = true)
      by (apply Nat.ltb_lt; exact Hbf_gt).
    rewrite Egt; simpl; repeat split; assumption || lia. }
  destruct Htacc_props as [Htm [Htsvn [Hs1svn [Htmseq [Htmiss [Htbf Htrf]]]]]].
  assert (Ebf_pos : (0 <? boot_failure_counter t_acc) = true)
    by (apply Nat.ltb_lt; lia).
  assert (Ebf_le : (boot_failure_counter t_acc <=? cfg_max_retries cfg) = false)
    by (apply Nat.leb_gt; exact Htbf).
  assert (Erf_le : (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg) = true)
    by (apply Nat.leb_le; exact Htrf).
  change (match boot_failure_counter t_acc with 0 => false | S _ => true end)
    with (0 <? boot_failure_counter t_acc) in Eboot1.
  rewrite Ebf_pos, Ebf_le, Erf_le in Eboot1; simpl in Eboot1.
  unfold step4_update_pipeline in Eboot1; simpl in Eboot1.
  rewrite Hrom in Eboot1; simpl in Eboot1.
  inversion Eboot1; subst out1 st_rec; clear Eboot1.
  split; [reflexivity|].
  (* Step through Boot 2: recovery_os_post_xmodem_bundle -> Boot_App healed_img *)
  destruct (eval_boot_state cfg (recovery_os_post_xmodem_bundle
              (mkState (st_slots st_deg) (st_wal st_deg) (set_tmr_nonce t_acc 0)
                       (st_confirm st_deg) (st_otp st_deg) (st_reset st_deg))
              healed_img reboot_rst)) as [out2 st_healed] eqn:Eboot2.
  unfold recovery_os_post_xmodem_bundle in Eboot2; simpl in Eboot2.
  unfold eval_boot_state in Eboot2; cbv zeta in Eboot2; simpl in Eboot2.
  rewrite Htm in Eboot2; simpl in Eboot2.
  assert (Eseq_not_le : (S (last_mbx_seq t_acc) <=? last_mbx_seq t_acc) = false)
    by (apply Nat.leb_gt; lia).
  unfold step1_mailbox_consume in Eboot2;
    cbn [mailbox_slot last_mbx_seq set_tmr_nonce] in Eboot2.
  rewrite Eseq_not_le in Eboot2; simpl in Eboot2.
  unfold wal_is_device_locked in Eboot2; rewrite Hwal0 in Eboot2; simpl in Eboot2.
  unfold wal_reconstruct_txn in Eboot2; simpl in Eboot2.
  unfold step2_confirm_check, heal_tmr_counters in Eboot2; cbv zeta in Eboot2; simpl in Eboot2.
  unfold step2_5_cloud_cmd in Eboot2; simpl in Eboot2.
  unfold step3_failure_and_rollback in Eboot2; cbv zeta in Eboot2; simpl in Eboot2.
  unfold step4_update_pipeline in Eboot2; cbv zeta in Eboot2;
    cbn [wal_intent_eqb negb staging_slot] in Eboot2; cbv iota in Eboot2.
  assert (Hcan2 :
    staging_can_apply healed_img
      (mkTMR (tmr_app_svn t_acc) (tmr_stage1_svn t_acc) 0 0 0 (S (last_mbx_seq t_acc))
             (last_cloud_issued_at t_acc) (tmr_mac_valid t_acc))
      (st_otp st_deg) = true).
  { unfold staging_can_apply, heal_tmr_counters in Hcan |- *; simpl in Hcan |- *.
    rewrite Htsvn; exact Hcan. }
  rewrite Htm in Hcan2; rewrite ?Htm in Eboot2.
  rewrite Hcan2 in Eboot2; simpl in Eboot2.
  pose proof (staging_can_apply_verified _ _ _ Hcan2) as [[Hhdr_h [Hsig_h [_ [_ Hkey_h]]]] _].
  assert (Htsig_h : slot_tsig_valid healed_img (otp_active_key_index (st_otp st_deg)) = true)
    by (unfold slot_tsig_valid; rewrite Hhdr_h, Hsig_h, Hkey_h, Nat.eqb_refl; reflexivity).
  rewrite Hhdr_h, Htsig_h in Eboot2; simpl in Eboot2.
  inversion Eboot2; subst out2 st_healed; simpl; repeat split; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 2: FV-16 — Single-Glitch FIH Soundness & 32-Bit Non-Abelian CFI    *)
(*            Mirrors boot_fih.h and boot_proof.h                             *)
(* ========================================================================== *)

Inductive FihGateId : Type :=
  | FG_Signature : FihGateId
  | FG_SvnFloor  : FihGateId
  | FG_Merkle    : FihGateId
  | FG_BootProof : FihGateId.

Definition fih_gate_eqb (a b : FihGateId) : bool :=
  match a, b with
  | FG_Signature, FG_Signature => true
  | FG_SvnFloor,  FG_SvnFloor  => true
  | FG_Merkle,    FG_Merkle    => true
  | FG_BootProof, FG_BootProof => true
  | _, _                       => false
  end.

(* Explicit single-fault adversary model (AtMostOneFault):
   - FI_None: 0 faults injected
   - FI_SkipPrimary g: 1 instruction/branch skip on primary check of gate g
   - FI_SkipRedundant g: 1 instruction/branch skip on TOOB_DOUBLE_VERIFY shadow check of g
   - FI_CorruptStatusWord v: 1 register glitch forging status register to v *)
Inductive SingleFaultBudget : Type :=
  | FI_None              : SingleFaultBudget
  | FI_SkipPrimary       : FihGateId -> SingleFaultBudget
  | FI_SkipRedundant     : FihGateId -> SingleFaultBudget
  | FI_CorruptStatusWord : Z -> SingleFaultBudget.

Record FihSecurityInputs : Type := mkFihInputs {
  fsi_sig_ok    : bool;
  fsi_svn_ok    : bool;
  fsi_merkle_ok : bool;
  fsi_proof_ok  : bool
}.

Inductive FihHandoffDecision : Type :=
  | FIH_AllowHandoff : FihHandoffDecision
  | FIH_TrapPanic    : FihHandoffDecision.

Definition fih_success_word : Z := 1437226410%Z. (* 0x55AA55AA *)
Definition fih_fail_word    : Z := 2857740885%Z. (* 0xAA55AA55 *)

Definition eval_primary_gate
    (g : FihGateId) (actual : bool) (flt : SingleFaultBudget) : bool :=
  match flt with
  | FI_SkipPrimary g_f => if fih_gate_eqb g g_f then true else actual
  | _                  => actual
  end.

Definition eval_redundant_gate
    (g : FihGateId) (actual : bool) (flt : SingleFaultBudget) : bool :=
  match flt with
  | FI_SkipRedundant g_f => if fih_gate_eqb g g_f then true else actual
  | _                    => actual
  end.

(* Hardened Stage-1 handoff gate combining BOOT_SECURE_REQUIRE + TOOB_DOUBLE_VERIFY
   with an independent shadow proof accumulator so a single skipped branch OR a
   single corrupted status register always traps into boot_panic(). *)
Definition eval_fih_hardened_handoff
    (inp : FihSecurityInputs) (flt : SingleFaultBudget) : FihHandoffDecision :=
  let p_sig := eval_primary_gate FG_Signature (fsi_sig_ok inp) flt in
  let r_sig := eval_redundant_gate FG_Signature (fsi_sig_ok inp) flt in
  let p_svn := eval_primary_gate FG_SvnFloor (fsi_svn_ok inp) flt in
  let r_svn := eval_redundant_gate FG_SvnFloor (fsi_svn_ok inp) flt in
  let p_mrk := eval_primary_gate FG_Merkle (fsi_merkle_ok inp) flt in
  let r_mrk := eval_redundant_gate FG_Merkle (fsi_merkle_ok inp) flt in
  let p_prf := eval_primary_gate FG_BootProof (fsi_proof_ok inp) flt in
  let r_prf := eval_redundant_gate FG_BootProof (fsi_proof_ok inp) flt in
  let pri_all := p_sig && p_svn && p_mrk && p_prf in
  let red_all := r_sig && r_svn && r_mrk && r_prf in
  let status_reg :=
    match flt with
    | FI_CorruptStatusWord forged => forged
    | _ => if pri_all then fih_success_word else fih_fail_word
    end in
  let shadow_reg := if red_all then fih_success_word else fih_fail_word in
  if pri_all && red_all &&
     Z.eqb status_reg fih_success_word &&
     Z.eqb shadow_reg fih_success_word then
    FIH_AllowHandoff
  else
    FIH_TrapPanic.

(* Theorem FV-16a: Single-Glitch FIH Soundness & Zero-Fault Completeness.
   1. Under ANY SingleFaultBudget (0 faults, 1 skipped primary branch, 1 skipped
      redundant branch, or 1 forged status word), an invalid candidate (violating
      sig, SVN, Merkle, or BootProof) NEVER reaches FIH_AllowHandoff!
   2. With 0 faults, a fully valid candidate deterministically reaches FIH_AllowHandoff. *)
Theorem fih_single_fault_soundness :
  forall inp flt,
    ((fsi_sig_ok inp = false \/
      fsi_svn_ok inp = false \/
      fsi_merkle_ok inp = false \/
      fsi_proof_ok inp = false) ->
     eval_fih_hardened_handoff inp flt = FIH_TrapPanic) /\
    (fsi_sig_ok inp = true ->
     fsi_svn_ok inp = true ->
     fsi_merkle_ok inp = true ->
     fsi_proof_ok inp = true ->
     eval_fih_hardened_handoff inp FI_None = FIH_AllowHandoff).
Proof.
  intros [sig svn mrk prf] flt; split.
  - intros Hbad.
    destruct flt as [ | [| | |] | [| | |] | forged];
      destruct sig, svn, mrk, prf;
      try (exfalso; simpl in Hbad; intuition discriminate);
      unfold eval_fih_hardened_handoff; simpl;
      rewrite ?Bool.andb_false_r; simpl; reflexivity.
  - simpl; intros -> -> -> ->; vm_compute; reflexivity.
Qed.

(* FV-16b: Exact 32-Bit Non-Abelian Rotate-XOR Control-Flow Integrity (CFI)
   Mirrors boot_cfi_mix_val in toobloader/core/boot_proof.h:
     ((acc << 7) | (acc >> 25)) ^ token   (over uint32_t) *)
Open Scope Z_scope.

Definition cfi_mask32 : Z := Z.ones 32.

Definition is_u32 (x : Z) : Prop :=
  0 <= x < 2 ^ 32.

Definition rotl32_7 (x : Z) : Z :=
  let x32 := Z.land x cfi_mask32 in
  Z.land (Z.lor (Z.shiftl x32 7) (Z.shiftr x32 25)) cfi_mask32.

Definition rotr32_7 (x : Z) : Z :=
  let x32 := Z.land x cfi_mask32 in
  Z.land (Z.lor (Z.shiftr x32 7) (Z.shiftl x32 25)) cfi_mask32.

Definition boot_cfi_mix32 (acc tok : Z) : Z :=
  Z.lxor (rotl32_7 acc) (Z.land tok cfi_mask32).

Fixpoint run_cfi_stages (acc : Z) (tokens : list Z) : Z :=
  match tokens with
  | [] => Z.land acc cfi_mask32
  | tok :: rest => run_cfi_stages (boot_cfi_mix32 acc tok) rest
  end.

Lemma land_mask32_u32 :
  forall x, is_u32 x -> Z.land x cfi_mask32 = x.
Proof.
  intros x [Hge Hlt].
  unfold cfi_mask32; rewrite Z.land_ones by lia.
  apply Z.mod_small; lia.
Qed.

Lemma testbit_cfi_mask32 :
  forall j, 0 <= j -> Z.testbit cfi_mask32 j = (j <? 32).
Proof.
  intros j Hj; unfold cfi_mask32; apply Z.testbit_ones_nonneg; lia.
Qed.

Lemma rotl32_7_testbit :
  forall x j,
    0 <= j < 32 ->
    Z.testbit (rotl32_7 x) j =
      (if j <? 7 then Z.testbit x (j + 25) else Z.testbit x (j - 7)).
Proof.
  intros x j [Hj0 Hj32].
  unfold rotl32_7.
  rewrite Z.land_spec, Z.lor_spec, testbit_cfi_mask32 by lia.
  assert (Ej32 : (j <? 32) = true) by (apply Z.ltb_lt; lia).
  rewrite Ej32, Bool.andb_true_r.
  rewrite Z.shiftl_spec, Z.shiftr_spec by lia.
  destruct (j <? 7) eqn:Ej7.
  - apply Z.ltb_lt in Ej7.
    rewrite Z.testbit_neg_r by lia.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    assert (E25 : (j + 25 <? 32) = true) by (apply Z.ltb_lt; lia).
    rewrite E25, Bool.andb_true_r, Bool.orb_false_l; reflexivity.
  - apply Z.ltb_ge in Ej7.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    assert (Em7 : (j - 7 <? 32) = true) by (apply Z.ltb_lt; lia).
    assert (Ep25 : (j + 25 <? 32) = false) by (apply Z.ltb_ge; lia).
    rewrite Em7, Ep25, Bool.andb_true_r, Bool.andb_false_r, Bool.orb_false_r.
    reflexivity.
Qed.

Lemma rotr32_7_rotl32_7 :
  forall x, rotr32_7 (rotl32_7 x) = Z.land x cfi_mask32.
Proof.
  intros x; apply Z.bits_inj'; intros j Hj.
  unfold rotr32_7.
  rewrite !Z.land_spec, Z.lor_spec, testbit_cfi_mask32 by lia.
  destruct (j <? 32) eqn:Ej32; [|rewrite !Bool.andb_false_r; reflexivity].
  apply Z.ltb_lt in Ej32.
  rewrite !Bool.andb_true_r.
  rewrite Z.shiftr_spec, Z.shiftl_spec by lia.
  destruct (j <? 25) eqn:Ej25.
  - apply Z.ltb_lt in Ej25.
    rewrite (Z.testbit_neg_r _ (j - 25)) by lia.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    assert (Ep7 : (j + 7 <? 32) = true) by (apply Z.ltb_lt; lia).
    rewrite Ep7, Bool.andb_true_r, Bool.orb_false_r.
    rewrite rotl32_7_testbit by lia.
    assert (En7 : (j + 7 <? 7) = false) by (apply Z.ltb_ge; lia).
    rewrite En7; f_equal; lia.
  - apply Z.ltb_ge in Ej25.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    assert (Ep7 : (j + 7 <? 32) = false) by (apply Z.ltb_ge; lia).
    rewrite Ep7, Bool.andb_false_r, Bool.orb_false_l.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    assert (Em25 : (j - 25 <? 32) = true) by (apply Z.ltb_lt; lia).
    rewrite Em25, Bool.andb_true_r.
    rewrite rotl32_7_testbit by lia.
    assert (Elt7 : (j - 25 <? 7) = true) by (apply Z.ltb_lt; lia).
    rewrite Elt7; f_equal; lia.
Qed.

Lemma boot_cfi_mix32_u32 :
  forall acc tok, is_u32 (boot_cfi_mix32 acc tok).
Proof.
  intros acc tok.
  assert (Heq_y : forall y, Z.land y cfi_mask32 = y mod 2 ^ 32)
    by (intro y; unfold cfi_mask32; apply Z.land_ones; lia).
  assert (Heq : Z.land (boot_cfi_mix32 acc tok) cfi_mask32 = boot_cfi_mix32 acc tok).
  { apply Z.bits_inj'; intros j Hj.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    unfold boot_cfi_mix32, rotl32_7.
    rewrite Z.lxor_spec, !Z.land_spec, testbit_cfi_mask32 by lia.
    destruct (j <? 32); rewrite ?Bool.andb_true_r, ?Bool.andb_false_r; reflexivity. }
  rewrite <- Heq, Heq_y; apply Z.mod_pos_bound; lia.
Qed.

Lemma boot_cfi_mix32_inj_acc :
  forall acc1 acc2 tok,
    is_u32 acc1 ->
    is_u32 acc2 ->
    boot_cfi_mix32 acc1 tok = boot_cfi_mix32 acc2 tok ->
    acc1 = acc2.
Proof.
  intros acc1 acc2 tok Hu1 Hu2 Hmix.
  unfold boot_cfi_mix32 in Hmix.
  assert (Hrot : rotl32_7 acc1 = rotl32_7 acc2).
  { apply (f_equal (fun v => Z.lxor v (Z.land tok cfi_mask32))) in Hmix.
    rewrite !Z.lxor_assoc, Z.lxor_nilpotent, !Z.lxor_0_r in Hmix.
    exact Hmix. }
  apply (f_equal rotr32_7) in Hrot.
  rewrite !rotr32_7_rotl32_7, !land_mask32_u32 in Hrot by assumption.
  exact Hrot.
Qed.

Lemma boot_cfi_mix32_inj_tok :
  forall acc tok1 tok2,
    is_u32 tok1 ->
    is_u32 tok2 ->
    boot_cfi_mix32 acc tok1 = boot_cfi_mix32 acc tok2 ->
    tok1 = tok2.
Proof.
  intros acc tok1 tok2 Ht1 Ht2 Hmix.
  unfold boot_cfi_mix32 in Hmix.
  apply (f_equal (fun v => Z.lxor (rotl32_7 acc) v)) in Hmix.
  rewrite <- !Z.lxor_assoc, Z.lxor_nilpotent, !Z.lxor_0_l in Hmix.
  rewrite !land_mask32_u32 in Hmix by assumption.
  exact Hmix.
Qed.

Lemma run_cfi_stages_inj_acc :
  forall suffix acc1 acc2,
    is_u32 acc1 ->
    is_u32 acc2 ->
    run_cfi_stages acc1 suffix = run_cfi_stages acc2 suffix ->
    acc1 = acc2.
Proof.
  induction suffix as [|tok rest IH]; intros acc1 acc2 Hu1 Hu2 Heq; simpl in Heq.
  - rewrite !land_mask32_u32 in Heq by assumption; exact Heq.
  - apply IH in Heq; [|apply boot_cfi_mix32_u32 | apply boot_cfi_mix32_u32].
    exact (boot_cfi_mix32_inj_acc acc1 acc2 tok Hu1 Hu2 Heq).
Qed.

(* Number-theoretic fixed-point characterization of rotl32_7:
   Since gcd(7, 32) = 1 (7 * 23 = 161 = 5 * 32 + 1), if rotl32_7 d = d for
   a 32-bit word d, then every bit j in 0..31 equals bit 0 of d, so d is
   either 0x00000000 or 0xFFFFFFFF! *)
Lemma rotl32_7_fixed_step :
  forall d (k : nat),
    rotl32_7 d = d ->
    Z.testbit d ((7 * Z.of_nat k) mod 32) = Z.testbit d 0.
Proof.
  intros d k Hfix; induction k as [|k' IH].
  - simpl; reflexivity.
  - set (m := (7 * Z.of_nat k') mod 32).
    assert (Hm_bounds : 0 <= m < 32) by (unfold m; apply Z.mod_pos_bound; lia).
    assert (Hnext : ((7 * Z.of_nat (S k')) mod 32) =
                    (if m <? 25 then m + 7 else m - 25)).
    { replace (7 * Z.of_nat (S k')) with (7 * Z.of_nat k' + 7) by lia.
      rewrite <- Z.add_mod_idemp_l by lia.
      fold m.
      destruct (m <? 25) eqn:Em25.
      - apply Z.ltb_lt in Em25; apply Z.mod_small; lia.
      - apply Z.ltb_ge in Em25.
        replace (m + 7) with ((m - 25) + 1 * 32) by lia.
        rewrite Z.mod_add by lia; apply Z.mod_small; lia. }
    rewrite Hnext.
    destruct (m <? 25) eqn:Em25.
    + apply Z.ltb_lt in Em25.
      rewrite <- Hfix at 1.
      rewrite rotl32_7_testbit by lia.
      assert (En7 : (m + 7 <? 7) = false) by (apply Z.ltb_ge; lia).
      rewrite En7; replace (m + 7 - 7) with m by lia; exact IH.
    + apply Z.ltb_ge in Em25.
      rewrite <- Hfix at 1.
      rewrite rotl32_7_testbit by lia.
      assert (El7 : (m - 25 <? 7) = true) by (apply Z.ltb_lt; lia).
      rewrite El7; replace (m - 25 + 25) with m by lia; exact IH.
Qed.

Lemma rotl32_7_fixpoint_characterization :
  forall d,
    is_u32 d ->
    rotl32_7 d = d ->
    d = 0 \/ d = cfi_mask32.
Proof.
  intros d Hd Hfix.
  assert (Hall_bits : forall j, 0 <= j < 32 -> Z.testbit d j = Z.testbit d 0).
  { intros j [Hj0 Hj32].
    set (k := Z.to_nat ((23 * j) mod 32)).
    assert (Hk_eq : (7 * Z.of_nat k) mod 32 = j).
    { unfold k; rewrite Z2Nat.id by (apply Z.mod_pos_bound; lia).
      rewrite Z.mul_mod_idemp_r by lia.
      replace (7 * (23 * j)) with (j + (5 * j) * 32) by lia.
      rewrite Z.mod_add by lia; apply Z.mod_small; lia. }
    rewrite <- Hk_eq; exact (rotl32_7_fixed_step d k Hfix). }
  destruct (Z.testbit d 0) eqn:Eb0.
  - right; rewrite <- (land_mask32_u32 d Hd).
    apply Z.bits_inj'; intros j Hj.
    rewrite Z.land_spec, testbit_cfi_mask32 by lia.
    destruct (j <? 32) eqn:Ej32.
    + apply Z.ltb_lt in Ej32; rewrite Bool.andb_true_r; rewrite Hall_bits by lia; reflexivity.
    + rewrite Bool.andb_false_r; reflexivity.
  - left; rewrite <- (land_mask32_u32 d Hd).
    apply Z.bits_inj'; intros j Hj.
    rewrite Z.land_spec, testbit_cfi_mask32, Z.bits_0 by lia.
    destruct (j <? 32) eqn:Ej32.
    + apply Z.ltb_lt in Ej32; rewrite Bool.andb_true_r; rewrite Hall_bits by lia; reflexivity.
    + rewrite Bool.andb_false_r; reflexivity.
Qed.

Lemma rotl32_7_distributes_lxor :
  forall a b,
    rotl32_7 (Z.lxor a b) = Z.lxor (rotl32_7 a) (rotl32_7 b).
Proof.
  intros a b; apply Z.bits_inj'; intros j Hj.
  destruct (j <? 32) eqn:Ej32.
  - apply Z.ltb_lt in Ej32.
    rewrite Z.lxor_spec, !rotl32_7_testbit by lia.
    destruct (j <? 7); rewrite Z.lxor_spec; reflexivity.
  - unfold rotl32_7.
    rewrite Z.lxor_spec, !Z.land_spec, testbit_cfi_mask32 by lia.
    rewrite Ej32, !Bool.andb_false_r; reflexivity.
Qed.

Lemma cfi_two_step_swap_ne :
  forall acc tok1 tok2,
    is_u32 tok1 ->
    is_u32 tok2 ->
    tok1 <> tok2 ->
    Z.lxor tok1 tok2 <> cfi_mask32 ->
    boot_cfi_mix32 (boot_cfi_mix32 acc tok1) tok2 <>
    boot_cfi_mix32 (boot_cfi_mix32 acc tok2) tok1.
Proof.
  intros acc tok1 tok2 Ht1 Ht2 Hne Hncomp Heq.
  unfold boot_cfi_mix32 in Heq.
  rewrite !rotl32_7_distributes_lxor in Heq.
  rewrite !land_mask32_u32 in Heq by assumption.
  assert (Hrot_eq :
    Z.lxor (rotl32_7 tok1) tok2 = Z.lxor (rotl32_7 tok2) tok1).
  { apply (f_equal (fun v => Z.lxor (rotl32_7 (rotl32_7 acc)) v)) in Heq.
    rewrite <- !Z.lxor_assoc, Z.lxor_nilpotent, !Z.lxor_0_l in Heq.
    exact Heq. }
  assert (Hfix : rotl32_7 (Z.lxor tok1 tok2) = Z.lxor tok1 tok2).
  { rewrite rotl32_7_distributes_lxor.
    apply Z.bits_inj'; intros j Hj.
    apply (f_equal (fun v => Z.testbit v j)) in Hrot_eq.
    rewrite !Z.lxor_spec in Hrot_eq |- *.
    destruct (Z.testbit (rotl32_7 tok1) j),
             (Z.testbit (rotl32_7 tok2) j),
             (Z.testbit tok1 j),
             (Z.testbit tok2 j); simpl in *; congruence. }
  assert (Hu_xor : is_u32 (Z.lxor tok1 tok2)).
  { assert (Hland : Z.land (Z.lxor tok1 tok2) cfi_mask32 = Z.lxor tok1 tok2).
    { apply Z.bits_inj'; intros j Hj.
      rewrite Z.land_spec, !Z.lxor_spec, testbit_cfi_mask32 by lia.
      destruct (j <? 32) eqn:Ej32; [rewrite Bool.andb_true_r; reflexivity|].
      rewrite Bool.andb_false_r.
      rewrite <- (land_mask32_u32 tok1 Ht1), <- (land_mask32_u32 tok2 Ht2).
      rewrite !Z.land_spec, testbit_cfi_mask32, Ej32, !Bool.andb_false_r by lia.
      reflexivity. }
    rewrite <- Hland; unfold cfi_mask32; rewrite Z.land_ones by lia; apply Z.mod_pos_bound; lia. }
  destruct (rotl32_7_fixpoint_characterization (Z.lxor tok1 tok2) Hu_xor Hfix) as [Hz | Hmask].
  - apply Hne; apply Z.lxor_eq_0_iff; exact Hz.
  - exact (Hncomp Hmask).
Qed.

Lemma run_cfi_stages_app :
  forall l1 l2 acc,
    is_u32 acc ->
    run_cfi_stages acc (l1 ++ l2) = run_cfi_stages (run_cfi_stages acc l1) l2.
Proof.
  induction l1 as [|t rest IH]; intros l2 acc Hu; simpl.
  - rewrite land_mask32_u32 by exact Hu; reflexivity.
  - apply IH; apply boot_cfi_mix32_u32.
Qed.

Lemma run_cfi_stages_u32 :
  forall l acc, is_u32 (run_cfi_stages acc l).
Proof.
  induction l as [|t rest IH]; intros acc; simpl.
  - unfold cfi_mask32; rewrite Z.land_ones by lia; apply Z.mod_pos_bound; lia.
  - apply IH.
Qed.

(* Concrete 8-stage pipeline CFI domain tokens (P1..P8) *)
Definition cfi_p1_p8_tokens : list Z :=
  [ 270544961; (* 0x10203041 P1: Read Envelope *)
    589505314; (* 0x23232322 P2: Verify Envelope *)
    909522483; (* 0x36363633 P3: Route Stream *)
   1212696644; (* 0x48484844 P4: Init Decrypt *)
   1515870805; (* 0x5A5A5A55 P5: MultiImage Check *)
   1819044966; (* 0x6C6C6C66 P6: Stream + Merkle *)
   2122219127; (* 0x7E7E7E77 P7: Energy Admit + Swap *)
   2408583576  (* 0x8F8F8F98 P8: Finalize Commit *)
  ].

Definition cfi_init_seed : Z := 16909060. (* 0x01020304 *)

Definition remove_idx {A : Type} (idx : nat) (l : list A) : list A :=
  firstn idx l ++ skipn (S idx) l.

(* Theorem FV-16b: 32-Bit Non-Abelian Rotate-XOR CFI Order & Tamper Soundness.
   1. Universal Single-Stage Substitution Detection: Changing ANY stage token
      `tok -> tok'` at ANY position `(prefix ++ [tok] ++ suffix)` strictly alters
      the final 32-bit CFI accumulator!
   2. Universal Non-Abelian Adjacent-Transposition Detection: Swapping ANY two
      consecutive stage tokens `(tok1, tok2) -> (tok2, tok1)` (for any distinct,
      non-complementary 32-bit tokens) at ANY position `(prefix ++ [tok1; tok2] ++ suffix)`
      strictly alters the final 32-bit CFI accumulator!
   3. Concrete P1..P8 Pipeline Skip & Truncation Soundness: Every single-stage
      omission (`k in 0..7`) and every prefix truncation (`len in 0..7`) of
      `cfi_p1_p8_tokens` fails the final CFI tag check! *)
Theorem non_abelian_cfi_order_soundness :
  (* 1. Universal single-stage substitution detection *)
  (forall seed prefix suffix tok tok',
     is_u32 seed ->
     is_u32 tok ->
     is_u32 tok' ->
     tok <> tok' ->
     run_cfi_stages seed (prefix ++ [tok] ++ suffix) <>
     run_cfi_stages seed (prefix ++ [tok'] ++ suffix)) /\
  (* 2. Universal non-abelian out-of-order swap detection *)
  (forall seed prefix suffix tok1 tok2,
     is_u32 seed ->
     is_u32 tok1 ->
     is_u32 tok2 ->
     tok1 <> tok2 ->
     Z.lxor tok1 tok2 <> cfi_mask32 ->
     run_cfi_stages seed (prefix ++ [tok1; tok2] ++ suffix) <>
     run_cfi_stages seed (prefix ++ [tok2; tok1] ++ suffix)) /\
  (* 3. Concrete P1..P8 stage-skip and prefix-truncation rejection *)
  (forall k : nat,
     (k < 8)%nat ->
     run_cfi_stages cfi_init_seed (remove_idx k cfi_p1_p8_tokens) <>
       run_cfi_stages cfi_init_seed cfi_p1_p8_tokens /\
     run_cfi_stages cfi_init_seed (firstn k cfi_p1_p8_tokens) <>
       run_cfi_stages cfi_init_seed cfi_p1_p8_tokens).
Proof.
  split.
  - intros seed prefix suffix tok tok' Hseed Ht Ht' Hne Heq.
    rewrite (run_cfi_stages_app prefix ([tok] ++ suffix) seed Hseed),
            (run_cfi_stages_app prefix ([tok'] ++ suffix) seed Hseed) in Heq.
    set (acc_p := run_cfi_stages seed prefix) in *.
    simpl in Heq.
    apply run_cfi_stages_inj_acc in Heq;
      [|apply boot_cfi_mix32_u32 | apply boot_cfi_mix32_u32].
    exact (Hne (boot_cfi_mix32_inj_tok acc_p tok tok' Ht Ht' Heq)).
  - split.
    + intros seed prefix suffix tok1 tok2 Hseed Ht1 Ht2 Hne Hncomp Heq.
      rewrite (run_cfi_stages_app prefix ([tok1; tok2] ++ suffix) seed Hseed),
              (run_cfi_stages_app prefix ([tok2; tok1] ++ suffix) seed Hseed) in Heq.
      set (acc_p := run_cfi_stages seed prefix) in *.
      simpl in Heq.
      apply run_cfi_stages_inj_acc in Heq;
        [|apply boot_cfi_mix32_u32 | apply boot_cfi_mix32_u32].
      exact (cfi_two_step_swap_ne acc_p tok1 tok2 Ht1 Ht2 Hne Hncomp Heq).
    + intros [|[|[|[|[|[|[|[|k8]]]]]]]] Hlt; try lia;
        (split; intro Hc; vm_compute in Hc; discriminate Hc).
Qed.

Close Scope Z_scope.
