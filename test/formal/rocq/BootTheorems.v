(* ========================================================================== *)
(* Toob-Loader Formal Verification                                            *)
(* File: BootTheorems.v                                                       *)
(*                                                                            *)
(* Machine-checked constructive proofs (0 Admitted, 0 admit, 0 Axiom) of:     *)
(*   - Theorem 1: bounded_boot_termination (Non-Brickability)                 *)
(*   - Theorem 2: torn_write_power_loss_idempotence                           *)
(*   - Theorem 3: monotonic_anti_rollback_safety                              *)
(*   - Theorem 4: auth_before_mutate                                          *)
(*   - Theorem 5: swapscratch_sector_conservation_and_resume &                *)
(*                swapmove_sector_conservation_and_resume (Arbitrary N >= 1)  *)
(*   - Theorem 6: tcc1_killswitch_non_bypassable,                             *)
(*                tcc1_killswitch_non_bypassable_hardened &                   *)
(*                tcc1_otp_depletion_cap_and_replay_immunity                  *)
(*   - Theorem 7: mailbox_replay_and_zero_nonce_immunity,                     *)
(*                confirm_nonce_mismatch_cannot_heal &                        *)
(*                cross_epoch_trial_boot_isolation                            *)
(*   - Theorem 8: k4_spi_tamper_fail_closed &                                 *)
(*                dual_failure_escalation_to_serial_rescue                    *)
(* ========================================================================== *)

From Stdlib Require Import Bool Arith Lia List.
From ToobBoot Require Import BootModel BootTransitions.
Import ListNotations.

(* ========================================================================== *)
(* SECTION 1: Step-Level Structural Lemmas                                    *)
(* ========================================================================== *)

Lemma is_verified_boot_app_spec :
  forall img otp,
    is_verified_boot_app img otp = true <->
    image_is_verified img (otp_min_svn otp) (otp_active_key_index otp).
Proof.
  intros img otp.
  unfold is_verified_boot_app, image_is_verified.
  rewrite !Bool.andb_true_iff, Nat.leb_le, Nat.eqb_eq.
  split.
  - intros [[[[Hs Hm] Hh] Hsvn] Hkey].
    repeat split; assumption || lia.
  - intros [Hh [Hs [Hm [Hsvn Hkey]]]].
    repeat split; assumption || lia.
Qed.

Lemma step1_mailbox_preserves_slots_and_svn :
  forall slots wal tmr slots' wal' tmr',
    step1_mailbox_consume slots wal tmr = Mbx_Done slots' wal' tmr' ->
    app_slot slots' = app_slot slots /\
    staging_slot slots' = staging_slot slots /\
    backup_slot slots' = backup_slot slots /\
    recovery_rom_valid slots' = recovery_rom_valid slots /\
    cloud_slot slots' = cloud_slot slots /\
    tmr_app_svn tmr' = tmr_app_svn tmr /\
    boot_failure_counter tmr' = boot_failure_counter tmr /\
    recovery_failure_counter tmr' = recovery_failure_counter tmr /\
    active_nonce tmr' = active_nonce tmr /\
    last_cloud_issued_at tmr' = last_cloud_issued_at tmr /\
    tmr_mac_valid tmr' = tmr_mac_valid tmr /\
    last_mbx_seq tmr <= last_mbx_seq tmr'.
Proof.
  intros slots wal tmr slots' wal' tmr' H.
  unfold step1_mailbox_consume in H.
  destruct (mailbox_slot slots) as [|crc seq rc ru rr mn] eqn:Hmbx.
  - inversion H; subst; repeat split; lia.
  - destruct (negb crc); [inversion H; subst; repeat split; lia|].
    destruct (negb (rc || ru || rr)); [inversion H; subst; repeat split; lia|].
    destruct (rc && (mn =? 0)); [inversion H; subst; repeat split; lia|].
    destruct (seq <=? last_mbx_seq tmr) eqn:Hseq; [inversion H; subst; repeat split; lia|].
    apply Nat.leb_gt in Hseq.
    inversion H; subst; simpl; repeat split; lia.
Qed.

Lemma step1_mailbox_idempotent_after_run :
  forall slots wal tmr slots' wal' tmr' s2 w2 t2,
    step1_mailbox_consume slots wal tmr = Mbx_Done slots' wal' tmr' ->
    last_mbx_seq tmr' <= last_mbx_seq t2 ->
    mailbox_slot s2 = mailbox_slot slots' ->
    step1_mailbox_consume s2 w2 t2 = Mbx_Done s2 w2 t2.
Proof.
  intros slots wal tmr slots' wal' tmr' s2 w2 t2 H Hle Hms.
  unfold step1_mailbox_consume in H |- *.
  destruct (mailbox_slot slots) as [|crc seq rc ru rr mn] eqn:Hmbx.
  - inversion H; subst; rewrite Hms, Hmbx; reflexivity.
  - destruct (negb crc) eqn:Hcrc.
    + inversion H; subst; rewrite Hms, Hmbx, Hcrc; reflexivity.
    + destruct (negb (rc || ru || rr)) eqn:Hreq.
      * inversion H; subst; rewrite Hms, Hmbx, Hcrc, Hreq; reflexivity.
      * destruct (rc && (mn =? 0)) eqn:Hrc0.
        -- inversion H; subst; rewrite Hms, Hmbx, Hcrc, Hreq, Hrc0; reflexivity.
        -- destruct (seq <=? last_mbx_seq tmr) eqn:Hseq.
           ++ inversion H; subst.
              rewrite Hms, Hmbx, Hcrc, Hreq, Hrc0.
              apply Nat.leb_le in Hseq.
              assert (Hseq2 : (seq <=? last_mbx_seq t2) = true)
                by (apply Nat.leb_le; lia).
              rewrite Hseq2; reflexivity.
           ++ inversion H; subst; simpl in Hms; rewrite Hms; reflexivity.
Qed.

Lemma step2_confirm_preserves_app_bkup_svn :
  forall slots wal tmr conf oi oe slots' wal' tmr' conf' oi' healed',
    step2_confirm_check slots wal tmr conf oi oe =
      S2_Ok slots' wal' tmr' conf' oi' healed' ->
    app_slot slots' = app_slot slots /\
    backup_slot slots' = backup_slot slots /\
    recovery_rom_valid slots' = recovery_rom_valid slots /\
    cloud_slot slots' = cloud_slot slots /\
    mailbox_slot slots' = mailbox_slot slots /\
    tmr_app_svn tmr' = tmr_app_svn tmr /\
    last_mbx_seq tmr' = last_mbx_seq tmr /\
    last_cloud_issued_at tmr' = last_cloud_issued_at tmr /\
    tmr_mac_valid tmr' = tmr_mac_valid tmr.
Proof.
  intros slots wal tmr conf oi oe slots' wal' tmr' conf' oi' healed' H.
  unfold step2_confirm_check in H.
  destruct (wal_intent_eqb oi WI_UpdatePending).
  - destruct (reconstruct_aux_entries (wal_entries wal)) as [| |ai an].
    + destruct ((0 <? active_nonce tmr) && (rtc_nonce conf =? active_nonce tmr));
        inversion H; subst; simpl; repeat split.
    + discriminate.
    + destruct (((0 <? active_nonce tmr) && (rtc_nonce conf =? active_nonce tmr)) ||
                (wal_intent_eqb ai WI_ConfirmCommit && (0 <? active_nonce tmr) &&
                 (0 <? an) && (an =? active_nonce tmr)) ||
                wal_intent_eqb ai WI_RecoveryResolved);
        inversion H; subst; simpl; repeat split.
  - destruct (negb (wal_intent_eqb oi WI_DeviceLocked) &&
              (wal_intent_eqb oi WI_ConfirmCommit ||
               wal_intent_eqb oi WI_RecoveryResolved ||
               ((0 <? active_nonce tmr) && (rtc_nonce conf =? active_nonce tmr)))).
    + destruct (negb (((0 <? active_nonce tmr) && (rtc_nonce conf =? active_nonce tmr)) ||
                      (wal_intent_eqb oi WI_ConfirmCommit && (0 <? active_nonce tmr) &&
                       (0 <? oe) && (oe =? active_nonce tmr)) ||
                      wal_intent_eqb oi WI_RecoveryResolved)).
      * inversion H; subst; simpl; repeat split.
      * destruct (if ((0 <? active_nonce tmr) && (rtc_nonce conf =? active_nonce tmr)) &&
                     wal_intent_eqb oi WI_None
                  then WI_ConfirmCommit else oi);
          inversion H; subst; simpl; repeat split.
    + inversion H; subst; simpl; repeat split.
Qed.

Lemma step2_5_cloud_preserves_images :
  forall slots wal tmr otp oi slots' wal' tmr' otp' oi',
    step2_5_cloud_cmd slots wal tmr otp oi = (slots', wal', tmr', otp', oi') ->
    app_slot slots' = app_slot slots /\
    staging_slot slots' = staging_slot slots /\
    backup_slot slots' = backup_slot slots /\
    recovery_rom_valid slots' = recovery_rom_valid slots /\
    mailbox_slot slots' = mailbox_slot slots /\
    otp_min_svn otp <= otp_min_svn otp' /\
    otp_active_key_index otp' = otp_active_key_index otp /\
    tmr_app_svn tmr' = tmr_app_svn tmr /\
    boot_failure_counter tmr' = boot_failure_counter tmr /\
    recovery_failure_counter tmr' = recovery_failure_counter tmr /\
    active_nonce tmr' = active_nonce tmr /\
    last_mbx_seq tmr' = last_mbx_seq tmr /\
    tmr_mac_valid tmr' = tmr_mac_valid tmr.
Proof.
  intros slots wal tmr otp oi slots' wal' tmr' otp' oi' H.
  unfold step2_5_cloud_cmd in H.
  destruct (cloud_slot slots) as [|cmd sig_ok dev_ok ctr iss] eqn:Hc.
  - inversion H; subst; repeat split; lia.
  - destruct (negb (sig_ok && dev_ok &&
                    ((otp_min_svn otp <? ctr) &&
                     (last_cloud_issued_at tmr <? iss) &&
                     (ctr - otp_min_svn otp <=? toob_cmd_max_burn_steps)))) eqn:Hgate.
    + inversion H; subst; simpl; repeat split; try reflexivity; try lia.
    + apply Bool.negb_false_iff in Hgate.
      rewrite !Bool.andb_true_iff in Hgate.
      destruct Hgate as [[_ _] [[Hctr _] _]].
      apply Nat.ltb_lt in Hctr.
      destruct cmd; try destruct (wal_intent_eqb oi WI_DeviceLocked);
        inversion H; subst; simpl; repeat split; lia.
Qed.

Lemma step2_5_cloud_idempotent_after_run :
  forall slots wal tmr otp oi slots' wal' tmr' otp' oi' s2 w2 t2 i2,
    step2_5_cloud_cmd slots wal tmr otp oi = (slots', wal', tmr', otp', oi') ->
    last_cloud_issued_at t2 = last_cloud_issued_at tmr' ->
    cloud_slot s2 = cloud_slot slots' ->
    step2_5_cloud_cmd s2 w2 t2 otp' i2 = (s2, w2, t2, otp', i2).
Proof.
  intros slots wal tmr otp oi slots' wal' tmr' otp' oi' s2 w2 t2 i2 H Ht Hcs.
  unfold step2_5_cloud_cmd in H |- *.
  destruct (cloud_slot slots) as [|cmd sig_ok dev_ok ctr iss] eqn:Hc.
  - inversion H; subst; rewrite Hcs, Hc; reflexivity.
  - destruct (negb (sig_ok && dev_ok &&
                    ((otp_min_svn otp <? ctr) &&
                     (last_cloud_issued_at tmr <? iss) &&
                     (ctr - otp_min_svn otp <=? toob_cmd_max_burn_steps)))) eqn:Hgate.
    + inversion H; subst.
      rewrite Hcs, Hc, Ht, Hgate; reflexivity.
    + destruct cmd; try destruct (wal_intent_eqb oi WI_DeviceLocked);
        inversion H; subst; simpl in Hcs; rewrite Hcs; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 2: Theorem 4 — Auth-Before-Mutate                                  *)
(* ========================================================================== *)

Lemma unauth_staging_cannot_apply :
  forall stg tmr otp,
    (sig_valid stg = false \/
     key_index stg <> otp_active_key_index otp \/
     tbm1_valid stg = false \/
     merkle_valid stg = false \/
     hdr_valid stg = false \/
     image_svn stg < otp_min_svn otp) ->
    staging_can_apply stg tmr otp = false.
Proof.
  intros stg tmr otp Hbad.
  unfold staging_can_apply, key_is_accepted.
  destruct Hbad as [Hsig | [Hkey | [Htbm | [Hmrk | [Hhdr | Hsvn]]]]].
  - rewrite Hsig; repeat rewrite Bool.andb_false_r; simpl;
    destruct (tbm1_valid stg), (key_index stg =? otp_active_key_index otp); reflexivity.
  - apply Nat.eqb_neq in Hkey; rewrite Hkey;
    destruct (tbm1_valid stg); reflexivity.
  - rewrite Htbm; reflexivity.
  - rewrite Hmrk; repeat rewrite Bool.andb_false_r;
    destruct (tbm1_valid stg && (key_index stg =? otp_active_key_index otp) &&
              sig_valid stg && (tmr_app_svn tmr <=? image_svn stg) &&
              (otp_min_svn otp <=? image_svn stg)); reflexivity.
  - rewrite Hhdr, Bool.andb_false_r; reflexivity.
  - assert (Hleb : (otp_min_svn otp <=? image_svn stg) = false)
      by (apply Nat.leb_gt; lia).
    rewrite Hleb;
    destruct (tbm1_valid stg && (key_index stg =? otp_active_key_index otp) &&
              sig_valid stg && (tmr_app_svn tmr <=? image_svn stg)); reflexivity.
Qed.

Theorem unauth_cloud_never_mutates :
  forall slots wal tmr otp oi,
    (cloud_slot slots = CC_Empty \/
     exists cmd dev_ok ctr iss,
       cloud_slot slots = CC_Token cmd false dev_ok ctr iss) ->
    step2_5_cloud_cmd slots wal tmr otp oi = (slots, wal, tmr, otp, oi).
Proof.
  intros slots wal tmr otp oi H.
  unfold step2_5_cloud_cmd.
  destruct H as [Hemp | [cmd [dev_ok [ctr [iss Htok]]]]].
  - rewrite Hemp; reflexivity.
  - rewrite Htok; simpl; reflexivity.
Qed.

Theorem unauth_mailbox_confirm_never_commits :
  forall slots wal tmr crc seq ru rr mn,
    mailbox_slot slots = MBX_Record crc seq true ru rr mn ->
    (active_nonce tmr = 0 \/ mn <> active_nonce tmr) ->
    (exists err, step1_mailbox_consume slots wal tmr = Mbx_Err err) \/
    (exists slots' wal' tmr',
       step1_mailbox_consume slots wal tmr = Mbx_Done slots' wal' tmr' /\
       (wal' = wal \/
        wal' = (let w1 := if rr then wal_append_valid wal WI_RecoveryResolved 0 else wal in
                if ru then wal_append_valid w1 WI_UpdatePending 0 else w1))) \/
    step1_mailbox_consume slots wal tmr = Mbx_Done slots wal tmr.
Proof.
  intros slots wal tmr crc seq ru rr mn Hmbx Hbad.
  unfold step1_mailbox_consume; rewrite Hmbx.
  destruct (negb crc); [right; right; reflexivity|].
  simpl.
  destruct (mn =? 0) eqn:Hmn0; [right; right; reflexivity|].
  destruct (seq <=? last_mbx_seq tmr); [right; right; reflexivity|].
  right; left.
  destruct (wal_is_device_locked wal).
  - eexists _, _, _; split; [reflexivity | left; reflexivity].
  - assert (Hmatch : ((0 <? active_nonce tmr) && (mn =? active_nonce tmr)) = false).
    { destruct Hbad as [Hz | Hneq].
      - rewrite Hz; reflexivity.
      - apply Nat.eqb_neq in Hneq; rewrite Hneq, Bool.andb_false_r; reflexivity. }
    rewrite Hmatch; simpl.
    eexists _, _, _; split; [reflexivity | right; reflexivity].
Qed.

(* Core Theorem 4: Auth-Before-Mutate across the complete Stage 1 pipeline *)
Theorem auth_before_mutate :
  forall cfg st out st',
    eval_boot_state cfg st = (out, st') ->
    (* 1. Staging image is unauthenticated (or corrupt / revoked) *)
    (sig_valid (staging_slot (st_slots st)) = false \/
     key_index (staging_slot (st_slots st)) <> otp_active_key_index (st_otp st) \/
     tbm1_valid (staging_slot (st_slots st)) = false \/
     merkle_valid (staging_slot (st_slots st)) = false) ->
    (* 2. Cloud command slot is empty or unauthenticated *)
    (cloud_slot (st_slots st) = CC_Empty \/
     exists cmd dev_ok ctr iss,
       cloud_slot (st_slots st) = CC_Token cmd false dev_ok ctr iss) ->
    (* 3. No prior authenticated tentative rollback is actively reverting *)
    active_nonce (st_tmr st) = 0 ->
    (forall exp_n,
       wal_reconstruct_txn (st_wal st) <> Some (WI_TxnCommit, exp_n) /\
       wal_reconstruct_txn (st_wal st) <> Some (WI_TxnRollbackPending, exp_n)) ->
    (* Post-conditions: App_Slot_0 and all security epoch counters are untouched *)
    app_slot (st_slots st') = app_slot (st_slots st) /\
    st_otp st' = st_otp st /\
    tmr_app_svn (st_tmr st') = tmr_app_svn (st_tmr st).
Proof.
  intros cfg st out st' Heval Hstg Hcloud Hnonce0 Hnorb.
  unfold eval_boot_state in Heval.
  destruct (negb (tmr_mac_valid (st_tmr st))).
  { inversion Heval; subst; repeat split. }
  destruct (step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st))
    as [err | slots1 wal1 tmr1] eqn:Hmbx.
  { inversion Heval; subst; repeat split. }
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx)
    as [Happ1 [Hstg1 [Hbk1 [Hrec1 [Hcld1 [Hsvn1 [Hbf1 [Hrf1 [Han1 [Hiss1 [Hmac1 _]]]]]]]]]]].
  (* Observe that mailbox fold-in with active_nonce = 0 can only keep wal or
     append WI_RecoveryResolved / WI_UpdatePending, never WI_TxnCommit or
     WI_TxnRollbackPending. *)
  assert (Hwal1_norb :
    forall exp_n,
      wal_reconstruct_txn wal1 <> Some (WI_TxnCommit, exp_n) /\
      wal_reconstruct_txn wal1 <> Some (WI_TxnRollbackPending, exp_n)).
  { intros exp_n.
    unfold step1_mailbox_consume in Hmbx.
    destruct (mailbox_slot (st_slots st)) as [|crc seq rc ru rr mn].
    - inversion Hmbx; subst; apply Hnorb.
    - destruct (negb crc); [inversion Hmbx; subst; apply Hnorb|].
      destruct (negb (rc || ru || rr)); [inversion Hmbx; subst; apply Hnorb|].
      destruct (rc && (mn =? 0)); [inversion Hmbx; subst; apply Hnorb|].
      destruct (seq <=? last_mbx_seq (st_tmr st)); [inversion Hmbx; subst; apply Hnorb|].
      destruct (wal_is_device_locked (st_wal st)).
      + inversion Hmbx; subst; apply Hnorb.
      + rewrite Hnonce0 in Hmbx; simpl in Hmbx.
        rewrite Bool.andb_false_r in Hmbx.
        inversion Hmbx; subst.
        destruct ru, rr; simpl; unfold wal_reconstruct_txn; simpl;
          try (split; discriminate);
          apply Hnorb. }
  destruct (wal_reconstruct_txn wal1) as [[oi1 oe1]|] eqn:Hrec_txn.
  2: { inversion Heval; subst; simpl; repeat split; congruence. }
  destruct (step2_confirm_check slots1 wal1 tmr1 (st_confirm st) oi1 oe1)
    as [|slots2 wal2 tmr2 conf2 oi2 healed2] eqn:Hs2.
  { inversion Heval; subst; simpl; repeat split; congruence. }
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Hs2)
    as [Happ2 [Hbk2 [Hrec2 [Hcld2 [_ [Hsvn2 _]]]]]].
  assert (Hoi2_norb : oi2 <> WI_TxnCommit /\ oi2 <> WI_TxnRollbackPending).
  { unfold step2_confirm_check in Hs2.
    rewrite Han1, Hnonce0 in Hs2; simpl in Hs2.
    rewrite !Bool.andb_false_r, !Bool.andb_false_l, !Bool.orb_false_l, !Bool.orb_false_r in Hs2.
    destruct (wal_intent_eqb oi1 WI_UpdatePending) eqn:Hup1.
    - apply wal_intent_eqb_eq in Hup1; subst oi1.
      destruct (reconstruct_aux_entries (wal_entries wal1)) as [| |ai an];
        try discriminate.
      + inversion Hs2; subst; split; discriminate.
      + rewrite !Bool.andb_false_r, !Bool.andb_false_l, !Bool.orb_false_l in Hs2.
        destruct (wal_intent_eqb ai WI_RecoveryResolved);
          inversion Hs2; subst; split; discriminate.
    - destruct (negb (wal_intent_eqb oi1 WI_DeviceLocked) &&
                (wal_intent_eqb oi1 WI_ConfirmCommit ||
                 wal_intent_eqb oi1 WI_RecoveryResolved)).
      + specialize (Hwal1_norb oe1) as [Hnc Hnr].
        destruct (negb (wal_intent_eqb oi1 WI_RecoveryResolved)).
        * inversion Hs2; subst; split; discriminate.
        * destruct oi1; try contradiction; inversion Hs2; subst; split; discriminate.
      + inversion Hs2; subst.
        specialize (Hwal1_norb oe1) as [Hnc Hnr].
        split; intro Heq; subst; contradiction. }
  assert (Hcloud2 :
    cloud_slot slots2 = CC_Empty \/
    exists cmd dev_ok ctr iss,
      cloud_slot slots2 = CC_Token cmd false dev_ok ctr iss).
  { rewrite Hcld2, Hcld1; exact Hcloud. }
  pose proof (unauth_cloud_never_mutates slots2 wal2 tmr2 (st_otp st) oi2 Hcloud2)
    as Hc_eq.
  rewrite Hc_eq in Heval.
  destruct (wal_intent_eqb oi2 WI_DeviceLocked).
  { inversion Heval; subst; simpl; repeat split; congruence. }
  (* Step 3: Since oi2 <> WI_TxnCommit and oi2 <> WI_TxnRollbackPending,
     Step 3 cannot enter Case A rollback, so slots3 = slots2! *)
  assert (Hs3_slots :
    forall err t3p,
      step3_failure_and_rollback cfg slots2 wal2 tmr2 (st_reset st) oi2 healed2 =
      S3_Panic err t3p -> tmr_app_svn t3p = tmr_app_svn tmr2).
  { intros err t3p Hs3p.
    unfold step3_failure_and_rollback in Hs3p.
    destruct Hoi2_norb as [Hnc Hnr].
    assert (Hc1 : wal_intent_eqb oi2 WI_TxnCommit = false)
      by (destruct oi2; simpl; try reflexivity; contradiction).
    assert (Hc2 : wal_intent_eqb oi2 WI_TxnRollbackPending = false)
      by (destruct oi2; simpl; try reflexivity; contradiction).
    rewrite Hc1, Hc2, !Bool.orb_false_r in Hs3p; simpl in Hs3p.
    destruct (wal_intent_eqb oi2 WI_TxnRollback); [discriminate|].
    set (t_acc := if negb healed2 &&
                     (wal_intent_eqb oi2 WI_ConfirmCommit ||
                      (rst_indicates_crash (st_reset st) &&
                       negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                     crash_accum_applicable oi2
                  then apply_crash_accum cfg tmr2 else tmr2) in *.
    assert (Htacc_svn : tmr_app_svn t_acc = tmr_app_svn tmr2).
    { unfold t_acc, apply_crash_accum.
      destruct (negb healed2 &&
                (wal_intent_eqb oi2 WI_ConfirmCommit ||
                 (rst_indicates_crash (st_reset st) &&
                  negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                crash_accum_applicable oi2); [|reflexivity].
      destruct (cfg_max_retries cfg <? boot_failure_counter tmr2); reflexivity. }
    destruct (0 <? boot_failure_counter t_acc); [|discriminate].
    destruct (boot_failure_counter t_acc <=? cfg_max_retries cfg); [discriminate|].
    destruct (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg); [discriminate|].
    inversion Hs3p; subst; exact Htacc_svn. }
  destruct (step3_failure_and_rollback cfg slots2 wal2 tmr2 (st_reset st) oi2 healed2)
    as [err t3p | slots3 wal3 tmr3 oi3 healed3 rec3] eqn:Hs3.
  { specialize (Hs3_slots _ _ eq_refl).
    inversion Heval; subst; simpl; repeat split; congruence. }
  assert (Hs3_ok :
    slots3 = slots2 /\ tmr_app_svn tmr3 = tmr_app_svn tmr2).
  { unfold step3_failure_and_rollback in Hs3.
    destruct Hoi2_norb as [Hnc Hnr].
    assert (Hc1 : wal_intent_eqb oi2 WI_TxnCommit = false)
      by (destruct oi2; simpl; try reflexivity; contradiction).
    assert (Hc2 : wal_intent_eqb oi2 WI_TxnRollbackPending = false)
      by (destruct oi2; simpl; try reflexivity; contradiction).
    rewrite Hc1, Hc2, !Bool.orb_false_r in Hs3; simpl in Hs3.
    set (t_acc := if negb healed2 &&
                     (wal_intent_eqb oi2 WI_ConfirmCommit ||
                      (rst_indicates_crash (st_reset st) &&
                       negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                     crash_accum_applicable oi2
                  then apply_crash_accum cfg tmr2 else tmr2) in *.
    assert (Htacc_svn : tmr_app_svn t_acc = tmr_app_svn tmr2).
    { unfold t_acc, apply_crash_accum.
      destruct (negb healed2 &&
                (wal_intent_eqb oi2 WI_ConfirmCommit ||
                 (rst_indicates_crash (st_reset st) &&
                  negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                crash_accum_applicable oi2); [|reflexivity].
      destruct (cfg_max_retries cfg <? boot_failure_counter tmr2); reflexivity. }
    destruct (wal_intent_eqb oi2 WI_TxnRollback).
    - inversion Hs3; subst; simpl; split; [reflexivity | exact Htacc_svn].
    - destruct (0 <? boot_failure_counter t_acc).
      + destruct (boot_failure_counter t_acc <=? cfg_max_retries cfg).
        * inversion Hs3; subst; split; [reflexivity | exact Htacc_svn].
        * destruct (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg);
            [inversion Hs3; subst; split; [reflexivity | exact Htacc_svn] | discriminate].
      + inversion Hs3; subst; split; [reflexivity | exact Htacc_svn]. }
  destruct Hs3_ok as [Hslots3 Hsvn3]; subst slots3.
  (* Step 4: staging_slot slots2 is either erased_slot_image (from ACT_HEAL_COUNTER)
     or staging_slot (st_slots st), both of which have staging_can_apply = false! *)
  assert (Hstg2_bad : staging_can_apply (staging_slot slots2) tmr3 (st_otp st) = false).
  { unfold step2_confirm_check in Hs2.
    assert (Hstg_cases : staging_slot slots2 = staging_slot slots1 \/
                         staging_slot slots2 = erased_slot_image).
    { destruct (wal_intent_eqb oi1 WI_UpdatePending).
      - destruct (reconstruct_aux_entries (wal_entries wal1)); try discriminate.
        + destruct ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st) =? active_nonce tmr1));
            inversion Hs2; left; reflexivity.
        + destruct (((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st) =? active_nonce tmr1)) ||
                    (wal_intent_eqb w WI_ConfirmCommit && (0 <? active_nonce tmr1) &&
                     (0 <? n) && (n =? active_nonce tmr1)) ||
                    wal_intent_eqb w WI_RecoveryResolved);
            inversion Hs2; left; reflexivity.
      - destruct (negb (wal_intent_eqb oi1 WI_DeviceLocked) &&
                  (wal_intent_eqb oi1 WI_ConfirmCommit ||
                   wal_intent_eqb oi1 WI_RecoveryResolved ||
                   ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st) =? active_nonce tmr1)))).
        + destruct (negb (((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st) =? active_nonce tmr1)) ||
                          (wal_intent_eqb oi1 WI_ConfirmCommit && (0 <? active_nonce tmr1) &&
                           (0 <? oe1) && (oe1 =? active_nonce tmr1)) ||
                          wal_intent_eqb oi1 WI_RecoveryResolved)).
          * inversion Hs2; left; reflexivity.
          * destruct (if ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st) =? active_nonce tmr1)) &&
                         wal_intent_eqb oi1 WI_None then WI_ConfirmCommit else oi1);
              inversion Hs2; try (left; reflexivity); right; reflexivity.
        + inversion Hs2; left; reflexivity. }
    destruct Hstg_cases as [Hsame | Herased].
    - rewrite Hsame, Hstg1.
      apply unauth_staging_cannot_apply.
      destruct Hstg as [A|[B|[C|D]]]; auto.
    - rewrite Herased; reflexivity. }
  unfold step4_update_pipeline in Heval.
  destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)).
  - destruct (negb (if rec3 || (negb rec3 && negb (hdr_valid (app_slot slots2)) &&
                                recovery_rom_valid slots2 &&
                                (recovery_failure_counter tmr3 <=? cfg_max_recovery_retries cfg))
                    then recovery_rom_valid slots2 else hdr_valid (app_slot slots2))).
    + inversion Heval; subst; simpl; repeat split; congruence.
    + destruct (rec3 || (negb rec3 && negb (hdr_valid (app_slot slots2)) &&
                         recovery_rom_valid slots2 &&
                         (recovery_failure_counter tmr3 <=? cfg_max_recovery_retries cfg)));
        inversion Heval; subst; simpl; repeat split; congruence.
  - rewrite Hstg2_bad in Heval.
    destruct (negb (if rec3 || (negb rec3 && negb (hdr_valid (app_slot slots2)) &&
                                recovery_rom_valid slots2 &&
                                (recovery_failure_counter tmr3 <=? cfg_max_recovery_retries cfg))
                    then recovery_rom_valid slots2 else hdr_valid (app_slot slots2))).
    + inversion Heval; subst; simpl; repeat split; congruence.
    + destruct (rec3 || (negb rec3 && negb (hdr_valid (app_slot slots2)) &&
                         recovery_rom_valid slots2 &&
                         (recovery_failure_counter tmr3 <=? cfg_max_recovery_retries cfg)));
        inversion Heval; subst; simpl; repeat split; congruence.
Qed.

(* ========================================================================== *)
(* SECTION 3: Theorem 3 — Monotonic Anti-Rollback Safety                      *)
(* ========================================================================== *)

Definition ValidInstalledSlots (slots : FlashSlots) (otp : OTP_Epoch) : Prop :=
  (hdr_valid (app_slot slots) = true ->
   image_is_verified (app_slot slots) (otp_min_svn otp) (otp_active_key_index otp)) /\
  (hdr_valid (backup_slot slots) = true ->
   image_is_verified (backup_slot slots) (otp_min_svn otp) (otp_active_key_index otp)).

Lemma staging_can_apply_verified :
  forall stg tmr otp,
    staging_can_apply stg tmr otp = true ->
    image_is_verified stg (otp_min_svn otp) (otp_active_key_index otp) /\
    tmr_app_svn tmr <= image_svn stg.
Proof.
  intros stg tmr otp H.
  unfold staging_can_apply, key_is_accepted in H.
  rewrite !Bool.andb_true_iff in H.
  destruct H as [[[[[[Htbm Hkey] Hsig] Htmr] Hotp] Hmrk] Hhdr].
  apply Nat.eqb_eq in Hkey.
  apply Nat.leb_le in Htmr.
  apply Nat.leb_le in Hotp.
  unfold image_is_verified.
  split; [repeat split; assumption || lia | exact Htmr].
Qed.

(* Core Theorem 3:
   1. No transition from ValidInstalledSlots ever hands off execution (Boot_App)
      to an image with image_svn < otp_min_svn or a revoked key_index, and
      ValidInstalledSlots is preserved across every transition;
   2. Stage 1 never ratchets otp_min_svn upward prior to confirmed boot
      (Confirm_OK), preventing transient-update rollback-lockout bricks;
   3. Explicit confirm_ratchet_otp only ratchets monotonically on confirmed
      non-tentative state while preserving ValidInstalledSlots. *)
Theorem monotonic_anti_rollback_safety :
  forall cfg st out st',
    ValidInstalledSlots (st_slots st) (st_otp st) ->
    cloud_slot (st_slots st) = CC_Empty ->
    eval_boot_state cfg st = (out, st') ->
    ValidInstalledSlots (st_slots st') (st_otp st') /\
    otp_min_svn (st_otp st') = otp_min_svn (st_otp st) /\
    otp_active_key_index (st_otp st') = otp_active_key_index (st_otp st) /\
    tmr_app_svn (st_tmr st) <= tmr_app_svn (st_tmr st') /\
    (forall img tentative nonce,
       out = Boot_App img tentative nonce ->
       image_svn img >= otp_min_svn (st_otp st') /\
       key_index img = otp_active_key_index (st_otp st') /\
       key_index img >= otp_active_key_index (st_otp st') /\
       sig_valid img = true /\
       merkle_valid img = true /\
       hdr_valid img = true).
Proof.
  intros cfg st out st' Hinv Hcld Heval.
  pose proof Hinv as [Happ_ok Hbk_ok].
  unfold eval_boot_state in Heval.
  destruct (negb (tmr_mac_valid (st_tmr st))).
  { inversion Heval; subst; split; [exact Hinv | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  destruct (step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st))
    as [err | slots1 wal1 tmr1] eqn:Hmbx.
  { inversion Heval; subst; split; [exact Hinv | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx)
    as [Happ1 [Hstg1 [Hbk1 [_ [Hcld1 [Hsvn1 _]]]]]].
  assert (Hinv1 : ValidInstalledSlots slots1 (st_otp st))
    by (split; [rewrite Happ1; exact Happ_ok | rewrite Hbk1; exact Hbk_ok]).
  destruct (wal_reconstruct_txn wal1) as [[oi1 oe1]|].
  2: { inversion Heval; subst; simpl;
       split; [exact Hinv1 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  destruct (step2_confirm_check slots1 wal1 tmr1 (st_confirm st) oi1 oe1)
    as [|slots2 wal2 tmr2 conf2 oi2 healed2] eqn:Hs2.
  { inversion Heval; subst; simpl;
    split; [exact Hinv1 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Hs2)
    as [Happ2 [Hbk2 [_ [Hcld2 [_ [Hsvn2 _]]]]]].
  assert (Hc2 : cloud_slot slots2 = CC_Empty) by congruence.
  unfold step2_5_cloud_cmd in Heval; rewrite Hc2 in Heval.
  assert (Hinv2 : ValidInstalledSlots slots2 (st_otp st))
    by (split; [rewrite Happ2, Happ1; exact Happ_ok | rewrite Hbk2, Hbk1; exact Hbk_ok]).
  destruct (wal_intent_eqb oi2 WI_DeviceLocked).
  { inversion Heval; subst; simpl;
    split; [exact Hinv2 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  (* Analyze Step 3 *)
  destruct (step3_failure_and_rollback cfg slots2 wal2 tmr2 (st_reset st) oi2 healed2)
    as [err t3p | slots3 wal3 tmr3 oi3 healed3 rec3] eqn:Hs3.
  { unfold step3_failure_and_rollback in Hs3.
    set (t_acc := if negb healed2 &&
                     ((wal_intent_eqb oi2 WI_ConfirmCommit || wal_intent_eqb oi2 WI_TxnCommit) ||
                      (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                     crash_accum_applicable oi2
                  then apply_crash_accum cfg tmr2 else tmr2) in *.
    assert (Htacc_svn : tmr_app_svn t_acc = tmr_app_svn tmr2).
    { unfold t_acc, apply_crash_accum.
      destruct (negb healed2 &&
                ((wal_intent_eqb oi2 WI_ConfirmCommit || wal_intent_eqb oi2 WI_TxnCommit) ||
                 (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                crash_accum_applicable oi2); [|reflexivity].
      destruct (cfg_max_retries cfg <? boot_failure_counter tmr2); reflexivity. }
    assert (Hp_svn : tmr_app_svn t3p = tmr_app_svn tmr2).
    { destruct (wal_intent_eqb oi2 WI_TxnRollback); [discriminate|].
      destruct ((0 <? boot_failure_counter t_acc) || wal_intent_eqb oi2 WI_TxnRollbackPending); [|discriminate].
      destruct (wal_intent_eqb oi2 WI_TxnCommit || wal_intent_eqb oi2 WI_TxnRollbackPending).
      - destruct (rst_indicates_crash (st_reset st) && negb healed2 ||
                  wal_intent_eqb oi2 WI_TxnRollbackPending ||
                  (cfg_max_retries cfg <? boot_failure_counter t_acc)); [|discriminate].
        destruct (negb (hdr_valid (backup_slot slots2))); [inversion Hs3; subst; exact Htacc_svn | discriminate].
      - destruct (boot_failure_counter t_acc <=? cfg_max_retries cfg); [discriminate|].
        destruct (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg); [discriminate|].
        inversion Hs3; subst; exact Htacc_svn. }
    inversion Heval; subst; simpl;
      split; [exact Hinv2 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  assert (Hs3_inv : ValidInstalledSlots slots3 (st_otp st) /\ tmr_app_svn tmr3 = tmr_app_svn tmr2).
  { unfold step3_failure_and_rollback in Hs3.
    set (t_acc := if negb healed2 &&
                     ((wal_intent_eqb oi2 WI_ConfirmCommit || wal_intent_eqb oi2 WI_TxnCommit) ||
                      (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                     crash_accum_applicable oi2
                  then apply_crash_accum cfg tmr2 else tmr2) in *.
    assert (Htacc_svn : tmr_app_svn t_acc = tmr_app_svn tmr2).
    { unfold t_acc, apply_crash_accum.
      destruct (negb healed2 &&
                ((wal_intent_eqb oi2 WI_ConfirmCommit || wal_intent_eqb oi2 WI_TxnCommit) ||
                 (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi2 WI_UpdatePending))) &&
                crash_accum_applicable oi2); [|reflexivity].
      destruct (cfg_max_retries cfg <? boot_failure_counter tmr2); reflexivity. }
    destruct (wal_intent_eqb oi2 WI_TxnRollback).
    - inversion Hs3; subst; simpl; split; [exact Hinv2 | exact Htacc_svn].
    - destruct ((0 <? boot_failure_counter t_acc) || wal_intent_eqb oi2 WI_TxnRollbackPending).
      + destruct (wal_intent_eqb oi2 WI_TxnCommit || wal_intent_eqb oi2 WI_TxnRollbackPending).
        * destruct (rst_indicates_crash (st_reset st) && negb healed2 ||
                    wal_intent_eqb oi2 WI_TxnRollbackPending ||
                    (cfg_max_retries cfg <? boot_failure_counter t_acc)).
          -- destruct (negb (hdr_valid (backup_slot slots2))) eqn:Hbhdr; [discriminate|].
             inversion Hs3; subst; simpl.
             destruct Hinv2 as [_ Hbk2_ok].
             split; [split; exact Hbk2_ok | exact Htacc_svn].
          -- inversion Hs3; subst; split; [exact Hinv2 | exact Htacc_svn].
        * destruct (boot_failure_counter t_acc <=? cfg_max_retries cfg).
          -- inversion Hs3; subst; split; [exact Hinv2 | exact Htacc_svn].
          -- destruct (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg);
               [inversion Hs3; subst; split; [exact Hinv2 | exact Htacc_svn] | discriminate].
      + inversion Hs3; subst; split; [exact Hinv2 | exact Htacc_svn]. }
  destruct Hs3_inv as [Hinv3 Hsvn3].
  (* Analyze Step 4 *)
  destruct (step4_update_pipeline slots3 wal3 tmr3 (st_otp st) oi3)
    as [[[[slots4 wal4] tmr4] oi4] upd_pend] eqn:Hs4.
  assert (Hs4_inv : ValidInstalledSlots slots4 (st_otp st) /\ tmr_app_svn tmr3 <= tmr_app_svn tmr4).
  { unfold step4_update_pipeline in Hs4.
    destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)).
    - inversion Hs4; subst; split; [exact Hinv3 | lia].
    - destruct (staging_can_apply (staging_slot slots3) tmr3 (st_otp st)) eqn:Hcan.
      + apply staging_can_apply_verified in Hcan as [Hstg_ver Hstg_svn].
        inversion Hs4; subst; simpl.
        destruct Hinv3 as [Happ3_ok _].
        split.
        * split; [intros _; exact Hstg_ver | exact Happ3_ok].
        * lia.
      + inversion Hs4; subst; split; [exact Hinv3 | lia]. }
  destruct Hs4_inv as [Hinv4 Hsvn4].
  pose proof Hinv4 as [Happ4_ok Hbk4_ok].
  (* Analyze Step 5 *)
  set (fb := negb rec3 && negb (hdr_valid (app_slot slots4)) &&
             recovery_rom_valid slots4 &&
             (recovery_failure_counter tmr4 <=? cfg_max_recovery_retries cfg)) in *.
  destruct (negb (if rec3 || fb then recovery_rom_valid slots4 else hdr_valid (app_slot slots4))) eqn:Htarg.
  { inversion Heval; subst; simpl;
    split; [exact Hinv4 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]]. }
  destruct (rec3 || fb) eqn:Hrec5.
  - inversion Heval; subst; simpl;
    split; [exact Hinv4 | split; [lia | split; [lia | split; [lia | intros; discriminate]]]].
  - simpl in Htarg.
    apply Bool.negb_false_iff in Htarg.
    inversion Heval; subst; simpl.
    specialize (Happ4_ok Htarg) as [Hh [Hs [Hm [Hsvn_ge Hkey_eq]]]].
    split; [exact Hinv4 | split; [lia | split; [lia | split; [lia|]]]].
    intros img tentative nonce Hout.
    inversion Hout; subst.
    repeat split; assumption || lia.
Qed.

Theorem confirm_ratchet_monotonic_and_safe :
  forall st,
    ValidInstalledSlots (st_slots st) (st_otp st) ->
    let st' := confirm_ratchet_otp st in
    otp_min_svn (st_otp st) <= otp_min_svn (st_otp st') /\
    (active_nonce (st_tmr st) <> 0 -> otp_min_svn (st_otp st') = otp_min_svn (st_otp st)) /\
    (hdr_valid (app_slot (st_slots st')) = true ->
     image_is_verified (app_slot (st_slots st'))
                       (otp_min_svn (st_otp st'))
                       (otp_active_key_index (st_otp st'))).
Proof.
  intros st [Happ_ok _]; cbv zeta.
  unfold confirm_ratchet_otp.
  destruct (wal_reconstruct_txn (st_wal st)) as [[wi wn]|];
    try (split; [lia | split; [intros; reflexivity | exact Happ_ok]]).
  destruct wi;
    try (split; [lia | split; [intros; reflexivity | exact Happ_ok]]).
  destruct ((active_nonce (st_tmr st) =? 0) && hdr_valid (app_slot (st_slots st))) eqn:Hcond.
  - rewrite Bool.andb_true_iff, Nat.eqb_eq in Hcond.
    destruct Hcond as [Hn0 Hhdr].
    specialize (Happ_ok Hhdr) as [Hh [Hs [Hm [Hsvn Hkey]]]].
    simpl; split; [lia | split].
    + intros Hneq; contradiction.
    + intros _; unfold image_is_verified; simpl; repeat split; assumption || lia.
  - split; [lia | split; [intros; reflexivity | exact Happ_ok]].
Qed.

(* ========================================================================== *)
(* SECTION 4: Theorem 2 — Torn-Write & Power-Loss Idempotence                 *)
(* ========================================================================== *)

Lemma replace_nth_length :
  forall {A : Type} n (v : A) l,
    length (replace_nth n v l) = length l.
Proof.
  intros A n v l; revert n.
  induction l as [|x xs IH]; intros [|n]; simpl; auto.
Qed.

Lemma nth_error_replace_nth_eq :
  forall {A : Type} n (v : A) l,
    n < length l ->
    nth_error (replace_nth n v l) n = Some v.
Proof.
  intros A n v l; revert n.
  induction l as [|x xs IH]; intros [|n] Hlt; simpl in *; try lia; auto.
  apply IH; lia.
Qed.

Lemma nth_error_replace_nth_neq :
  forall {A : Type} n m (v : A) l,
    n <> m ->
    nth_error (replace_nth n v l) m = nth_error l m.
Proof.
  intros A n m v l; revert n m.
  induction l as [|x xs IH]; intros [|n] [|m] Hneq; simpl; auto; try congruence.
Qed.

Lemma opt_nat_eqb_eq :
  forall a b, opt_nat_eqb a b = true <-> a = b.
Proof.
  intros [x|] [y|]; simpl; split; intro H;
    try reflexivity; try discriminate.
  - apply Nat.eqb_eq in H; subst; reflexivity.
  - inversion H; subst; apply Nat.eqb_refl.
Qed.

Lemma copy_sector_completed_length :
  forall src dst i,
    length (copy_sector_completed src dst i) = length dst.
Proof.
  intros src dst i; unfold copy_sector_completed.
  destruct (nth_error src i), (nth_error dst i); auto.
  destruct (opt_nat_eqb o o0); [reflexivity | apply replace_nth_length].
Qed.

Lemma copy_sector_torn_length :
  forall src dst i,
    length (copy_sector_torn src dst i) = length dst.
Proof.
  intros src dst i; unfold copy_sector_torn.
  destruct (nth_error src i), (nth_error dst i); auto.
  destruct (opt_nat_eqb o o0); [reflexivity | apply replace_nth_length].
Qed.

Lemma copy_sector_completed_nth_eq :
  forall src dst i,
    length src = length dst ->
    i < length src ->
    nth_error (copy_sector_completed src dst i) i = nth_error src i.
Proof.
  intros src dst i Hlen Hi.
  unfold copy_sector_completed.
  assert (Hsrc : exists sv, nth_error src i = Some sv).
  { destruct (nth_error src i) as [sv|] eqn:E; [exists sv; reflexivity|].
    apply nth_error_None in E; lia. }
  assert (Hdst : exists dv, nth_error dst i = Some dv).
  { destruct (nth_error dst i) as [dv|] eqn:E; [exists dv; reflexivity|].
    apply nth_error_None in E; lia. }
  destruct Hsrc as [sv Esrc], Hdst as [dv Edst].
  rewrite Esrc, Edst.
  destruct (opt_nat_eqb sv dv) eqn:Heqb.
  - apply opt_nat_eqb_eq in Heqb; subst; exact Edst.
  - apply nth_error_replace_nth_eq; lia.
Qed.

Lemma copy_sector_completed_nth_neq :
  forall src dst i j,
    i <> j ->
    nth_error (copy_sector_completed src dst i) j = nth_error dst j.
Proof.
  intros src dst i j Hneq.
  unfold copy_sector_completed.
  destruct (nth_error src i), (nth_error dst i); auto.
  destruct (opt_nat_eqb o o0); [reflexivity | apply nth_error_replace_nth_neq; exact Hneq].
Qed.

Lemma nth_error_ext_eq :
  forall {A : Type} (l1 l2 : list A),
    length l1 = length l2 ->
    (forall i, i < length l1 -> nth_error l1 i = nth_error l2 i) ->
    l1 = l2.
Proof.
  intros A l1; induction l1 as [|x xs IH]; intros [|y ys] Hlen Hnth;
    simpl in *; try discriminate; auto.
  assert (Hx : Some x = Some y) by ( exact (Hnth 0 ltac:(lia)) ).
  inversion Hx; subst.
  f_equal; apply IH; [lia|].
  intros i Hi; exact (Hnth (S i) ltac:(lia)).
Qed.

Lemma copy_range_complete_invariants :
  forall count start src dst,
    length src = start + count ->
    length dst = start + count ->
    (forall j, j < start -> nth_error dst j = nth_error src j) ->
    copy_range_complete src dst start count = src.
Proof.
  induction count as [|count' IH]; intros start src dst Hls Hld Hpre.
  - simpl.
    apply nth_error_ext_eq; [lia|].
    intros i Hi; apply Hpre; lia.
  - simpl.
    apply IH.
    + lia.
    + rewrite copy_sector_completed_length; lia.
    + intros j Hj.
      destruct (Nat.eq_dec start j) as [Heq | Hneq].
      * subst j; apply copy_sector_completed_nth_eq; lia.
      * rewrite copy_sector_completed_nth_neq by exact Hneq.
        apply Hpre; lia.
Qed.

Lemma copy_range_complete_all :
  forall src dst n,
    length src = n ->
    length dst = n ->
    copy_range_complete src dst 0 n = src.
Proof.
  intros src dst n Hls Hld.
  apply copy_range_complete_invariants; lia.
Qed.

Lemma copy_range_cut_length :
  forall count start src dst cut_at,
    length (copy_range_cut src dst start count cut_at) = length dst.
Proof.
  induction count as [|count' IH]; intros start src dst cut_at; simpl; [reflexivity|].
  destruct cut_at as [|cut'].
  - apply copy_sector_torn_length.
  - rewrite IH, copy_sector_completed_length; reflexivity.
Qed.

(* WAL torn-entry idempotence *)
Theorem wal_torn_append_idempotent :
  forall w,
    wal_reconstruct_txn (wal_append_torn w) = wal_reconstruct_txn w.
Proof.
  intro w; reflexivity.
Qed.

(* 3-sector TMR Quorum exact recovery across single sector cut k *)
Theorem tmr_quorum_power_cut_safe :
  forall old_tmr new_tmr fallback k,
    let q := tmr_flush_power_cut old_tmr new_tmr k in
    (k = 0 /\ tmr_quorum_vote q fallback = old_tmr) \/
    (k >= 1 /\ tmr_quorum_vote q fallback = new_tmr).
Proof.
  intros old_tmr new_tmr fallback [|[|[|k]]];
    cbv zeta; unfold tmr_quorum_vote, tmr_flush_power_cut; simpl.
  - left; split; [reflexivity | destruct (tmr_eqb old_tmr old_tmr); reflexivity].
  - right; split; [lia | destruct (tmr_eqb new_tmr old_tmr); reflexivity].
  - right; split; [lia | destruct (tmr_eqb new_tmr new_tmr); reflexivity].
  - right; split; [lia | rewrite tmr_eqb_refl; reflexivity].
Qed.

(* Core Theorem 2: Torn-Write & Power-Loss Idempotence
   1. At EVERY power-cut step k during ONEWAY update, both old_img and new_img
      remain 100% intact across the slots (never losing both slots);
   2. Resuming after ANY power-cut step k (and even nested cuts k1, k2)
      deterministically converges to the exact post-update state
      `mkOnewayFlash new_img new_img old_img OTP_Committed`;
   3. Resuming after ANY power-cut step k during ONEWAY rollback deterministically
      converges to the exact pre-update active image `old_img`. *)
Theorem torn_write_power_loss_idempotence :
  forall (old_img new_img init_bkup : SectorImage) (n k k2 : nat),
    length old_img = n ->
    length new_img = n ->
    length init_bkup = n ->
    let st0 := mkOnewayFlash old_img new_img init_bkup OTP_Backup in
    let st_cut := oneway_update_power_cut st0 n k in
    (* (a) Zero dual-slot loss at arbitrary power-cut step k *)
    ((ow_app st_cut = old_img /\ ow_staging st_cut = new_img) \/
     (ow_backup st_cut = old_img /\ ow_staging st_cut = new_img)) /\
    (* (b) Deterministic convergence of update resume to exact post-update state *)
    oneway_update_resume st_cut n =
      mkOnewayFlash new_img new_img old_img OTP_Committed /\
    (* (c) Rollback power-cut at arbitrary step k2 preserves backup & converges
           deterministically to exact pre-update active image old_img *)
    let st_post := mkOnewayFlash new_img new_img old_img OTP_Committed in
    let st_rb_cut := oneway_rollback_power_cut st_post n k2 in
    ow_backup st_rb_cut = old_img /\
    ow_app (oneway_rollback_resume st_rb_cut n) = old_img.
Proof.
  intros old_img new_img init_bkup n k k2 Hold Hnew Hbk; cbv zeta.
  unfold oneway_update_power_cut; cbn [ow_app ow_staging ow_backup ow_phase].
  assert (Hbk_done : copy_range_complete old_img init_bkup 0 n = old_img)
    by (apply copy_range_complete_all; assumption).
  assert (Happ_done : copy_range_complete new_img old_img 0 n = new_img)
    by (apply copy_range_complete_all; assumption).
  split; [|split; [|split]].
  - (* (a) Slot preservation at cut k *)
    destruct (k <? n); [left; simpl; split; reflexivity|].
    destruct (k =? n); [left; simpl; split; reflexivity|].
    destruct (k <=? 2 * n); right; simpl; rewrite Hbk_done; split; reflexivity.
  - (* (b) Deterministic convergence of update resume *)
    destruct (k <? n); [|destruct (k =? n); [|destruct (k <=? 2 * n)]];
    unfold oneway_update_resume; simpl;
    rewrite ?Hbk_done;
    rewrite !copy_range_complete_all
      by (rewrite ?copy_range_cut_length; assumption);
    reflexivity.
  - (* (c1) Rollback cut preserves backup = old_img *)
    unfold oneway_rollback_power_cut; destruct (k2 <? n); reflexivity.
  - (* (c2) Rollback resume converges to old_img *)
    unfold oneway_rollback_power_cut, oneway_rollback_resume; simpl.
    destruct (k2 <? n); simpl.
    + apply copy_range_complete_all; [exact Hold | rewrite copy_range_cut_length; exact Hnew].
    + rewrite (copy_range_complete_all old_img new_img n Hold Hnew).
      apply copy_range_complete_all; exact Hold.
Qed.

(* ========================================================================== *)
(* SECTION 5: Theorem 1 — Bounded Boot Termination (Non-Brickability)         *)
(* ========================================================================== *)

Local Arguments Nat.leb : simpl never.
Local Arguments Nat.ltb : simpl never.

Definition is_safe_terminal_outcome (out : BootOutcome) (otp : OTP_Epoch) : Prop :=
  match out with
  | Enter_Recovery_OS _ => True
  | Boot_App img tentative _ =>
      tentative = false /\
      image_is_verified img (otp_min_svn otp) (otp_active_key_index otp)
  end.

(* Stabilized post-Boot-0 environment: mailbox & cloud slots no longer trigger
   mutations, TMR MAC is valid, RTC confirm store is 0, Recovery ROM is intact. *)
Definition IdleInputs (st : State) : Prop :=
  recovery_rom_valid (st_slots st) = true /\
  tmr_mac_valid (st_tmr st) = true /\
  rtc_nonce (st_confirm st) = 0 /\
  step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) =
    Mbx_Done (st_slots st) (st_wal st) (st_tmr st) /\
  (forall w t i,
     last_cloud_issued_at t = last_cloud_issued_at (st_tmr st) ->
     step2_5_cloud_cmd (st_slots st) w t (st_otp st) i =
       (st_slots st, w, t, st_otp st, i)).

(* Helper 5.1: Non-tentative WDT loop converges to Enter_Recovery_OS (or verified
   Boot_App) in <= (M - c) reboots! *)
Lemma non_tentative_wdt_converges :
  forall rem cfg tent_rst fuel st,
    IdleInputs st ->
    st_reset st = RR_Watchdog ->
    active_nonce (st_tmr st) = 0 ->
    ((exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_None, exp_n)) \/
     exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_ConfirmCommit, exp_n)) ->
    cfg_max_retries cfg - boot_failure_counter (st_tmr st) <= rem ->
    rem <= fuel ->
    let '(out, st_f, reboots) := run_until_safe cfg tent_rst fuel st in
    reboots <= rem /\ is_safe_terminal_outcome out (st_otp st_f).
Proof.
  induction rem as [|rem' IH]; intros cfg tent_rst fuel st Hidle Hrst Han0 Hwal Hrem Hfuel.
  - (* rem = 0 => boot_failure_counter >= M => after +1 in Step 3, S c > M => immediate Enter_Recovery_OS! *)
    assert (Hge : cfg_max_retries cfg <= boot_failure_counter (st_tmr st)) by lia.
    destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    assert (Heval_rec : exists rm st', eval_boot_state cfg st = (Enter_Recovery_OS rm, st')).
    { unfold eval_boot_state; cbv zeta.
      rewrite Hmac; simpl; rewrite Hmbx.
      assert (Hs2_eq :
        exists oi1 oe1,
          wal_reconstruct_txn (st_wal st) = Some (oi1, oe1) /\
          step2_confirm_check (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) oi1 oe1 =
            S2_Ok (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) WI_None false).
      { destruct Hwal as [[en Hnone] | [en Hcc]].
        - exists WI_None, en; split; [exact Hnone|].
          unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity.
        - exists WI_ConfirmCommit, en; split; [exact Hcc|].
          unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity. }
      destruct Hs2_eq as [oi1 [oe1 [Hwrec Hs2]]].
      rewrite Hwrec, Hs2, Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; rewrite Hrst; simpl.
      unfold apply_crash_accum.
      destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:Hltb; simpl.
      - apply Nat.ltb_lt in Hltb.
        assert (Hpos : (0 <? boot_failure_counter (st_tmr st)) = true) by (apply Nat.ltb_lt; lia).
        assert (Hleb_f : (boot_failure_counter (st_tmr st) <=? cfg_max_retries cfg) = false)
          by (apply Nat.leb_gt; lia).
        rewrite Hpos, Hleb_f; simpl.
        destruct (S (recovery_failure_counter (st_tmr st)) <=? cfg_max_recovery_retries cfg); simpl.
        + unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hrec_rom; simpl; eexists _, _; reflexivity.
        + eexists _, _; reflexivity.
      - assert (Hleb_f : (S (boot_failure_counter (st_tmr st)) <=? cfg_max_retries cfg) = false)
          by (apply Nat.leb_gt; lia).
        rewrite Hleb_f; simpl.
        destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg); simpl.
        + unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hrec_rom; simpl; eexists _, _; reflexivity.
        + eexists _, _; reflexivity. }
    destruct Heval_rec as [rm [st' Hev]].
    destruct fuel as [|fuel']; simpl; rewrite Hev; (split; [lia | exact I]).
  - (* Inductive step rem = S rem' *)
    destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    destruct (cfg_max_retries cfg <=? boot_failure_counter (st_tmr st)) eqn:Hreach.
    + (* Already >= M: after +1 in Step 3, counter = S c > M => immediate Enter_Recovery_OS! *)
      apply Nat.leb_le in Hreach.
      assert (Heval_rec : exists rm st', eval_boot_state cfg st = (Enter_Recovery_OS rm, st')).
      { unfold eval_boot_state; cbv zeta.
        rewrite Hmac; simpl; rewrite Hmbx.
        assert (Hs2_eq :
          exists oi1 oe1,
            wal_reconstruct_txn (st_wal st) = Some (oi1, oe1) /\
            step2_confirm_check (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) oi1 oe1 =
              S2_Ok (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) WI_None false).
        { destruct Hwal as [[en Hnone] | [en Hcc]].
          - exists WI_None, en; split; [exact Hnone|].
            unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity.
          - exists WI_ConfirmCommit, en; split; [exact Hcc|].
            unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity. }
        destruct Hs2_eq as [oi1 [oe1 [Hwrec Hs2]]].
        rewrite Hwrec, Hs2, Hcld by reflexivity; simpl.
        unfold step3_failure_and_rollback; cbv zeta; rewrite Hrst; simpl.
        unfold apply_crash_accum.
        destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:Hltb; simpl.
        - apply Nat.ltb_lt in Hltb.
          assert (Hpos : (0 <? boot_failure_counter (st_tmr st)) = true) by (apply Nat.ltb_lt; lia).
          assert (Hleb_f : (boot_failure_counter (st_tmr st) <=? cfg_max_retries cfg) = false)
            by (apply Nat.leb_gt; lia).
          rewrite Hpos, Hleb_f; simpl.
          destruct (S (recovery_failure_counter (st_tmr st)) <=? cfg_max_recovery_retries cfg); simpl.
          + unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hrec_rom; simpl; eexists _, _; reflexivity.
          + eexists _, _; reflexivity.
        - assert (Hleb_f : (S (boot_failure_counter (st_tmr st)) <=? cfg_max_retries cfg) = false)
            by (apply Nat.leb_gt; lia).
          rewrite Hleb_f; simpl.
          destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg); simpl.
          + unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hrec_rom; simpl; eexists _, _; reflexivity.
          + eexists _, _; reflexivity. }
      destruct Heval_rec as [rm [st' Hev]].
      destruct fuel as [|fuel']; simpl; rewrite Hev; (split; [lia | exact I]).
    + (* boot_failure_counter < M: increments to S c <= M *)
      apply Nat.leb_gt in Hreach.
      assert (Hfuel_pos : exists fuel', fuel = S fuel').
      { destruct fuel as [|f']; [lia | exists f'; reflexivity]. }
      destruct Hfuel_pos as [fuel' Hfeq]; subst fuel.
      simpl.
      unfold eval_boot_state; cbv zeta.
      rewrite Hmac; simpl; rewrite Hmbx.
      assert (Hs2_eq :
        exists oi1 oe1,
          wal_reconstruct_txn (st_wal st) = Some (oi1, oe1) /\
          step2_confirm_check (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) oi1 oe1 =
            S2_Ok (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) WI_None false).
      { destruct Hwal as [[en Hnone] | [en Hcc]].
        - exists WI_None, en; split; [exact Hnone|].
          unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity.
        - exists WI_ConfirmCommit, en; split; [exact Hcc|].
          unfold step2_confirm_check; cbv zeta; rewrite Han0; simpl; reflexivity. }
      destruct Hs2_eq as [oi1 [oe1 [Hwrec Hs2]]].
      rewrite Hwrec, Hs2, Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; rewrite Hrst; simpl.
      unfold apply_crash_accum.
      assert (Hltb_f : (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) = false)
        by (apply Nat.ltb_ge; lia).
      rewrite Hltb_f; simpl.
      assert (Hleb_t : (S (boot_failure_counter (st_tmr st)) <=? cfg_max_retries cfg) = true)
        by (apply Nat.leb_le; lia).
      rewrite Hleb_t; simpl.
      unfold step4_update_pipeline; simpl; cbv zeta.
      destruct (hdr_valid (app_slot (st_slots st))) eqn:Happ_hdr; simpl; cbv zeta.
      * (* App header valid: either verified Boot_App (done in 0!) or unverified -> recurse *)
        destruct (is_verified_boot_app (app_slot (st_slots st)) (st_otp st)) eqn:Hver; simpl.
        -- apply is_verified_boot_app_spec in Hver.
           split; [lia | split; [reflexivity | exact Hver]].
        -- set (st_next := next_unconfirmed_reboot_state false tent_rst
                  (mkState (st_slots st) (st_wal st)
                    (set_tmr_nonce
                      (mkTMR (tmr_app_svn (st_tmr st)) (tmr_stage1_svn (st_tmr st))
                             (S (boot_failure_counter (st_tmr st)))
                             (recovery_failure_counter (st_tmr st))
                             (active_nonce (st_tmr st)) (last_mbx_seq (st_tmr st))
                             (last_cloud_issued_at (st_tmr st)) (tmr_mac_valid (st_tmr st))) 0)
                    (st_confirm st) (st_otp st) RR_Watchdog)).
           assert (Hidle_next : IdleInputs st_next).
           { unfold IdleInputs, st_next, next_unconfirmed_reboot_state; simpl.
             repeat split; try assumption; try reflexivity.
             eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | reflexivity]. }
           specialize (IH cfg tent_rst fuel' st_next Hidle_next eq_refl eq_refl Hwal
                         ltac:(simpl; lia) ltac:(lia)).
           destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb].
           destruct IH as [Hreb Hsafe].
           split; [lia | exact Hsafe].
      * (* App header invalid: falls back to Recovery OS or Serial Rescue in 0 reboots! *)
        rewrite Hrec_rom; simpl.
        destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg);
          simpl; (split; [lia | exact I]).
Qed.

(* Helper 5.2: Tentative TXN_COMMIT loop under ANY reset reason tent_rst:
   - Under ValidBackup: reaches verified Boot_App or Enter_Recovery_OS in
     <= (M + 1 - c) reboots!
   - Unconditionally (even forged backup): reaches safe terminal outcome in
     <= (M + 1 - c) + (M + 1) reboots! *)
Lemma tentative_txn_commit_converges :
  forall rem cfg tent_rst fuel st,
    IdleInputs st ->
    wal_reconstruct_txn (st_wal st) = Some (WI_TxnCommit, 0) ->
    cfg_max_retries cfg - boot_failure_counter (st_tmr st) <= rem ->
    (hdr_valid (backup_slot (st_slots st)) = true ->
     image_is_verified (backup_slot (st_slots st))
                       (otp_min_svn (st_otp st))
                       (otp_active_key_index (st_otp st))) ->
    rem <= fuel ->
    let '(out, st_f, reboots) := run_until_safe cfg tent_rst fuel st in
    reboots <= rem /\ is_safe_terminal_outcome out (st_otp st_f).
Proof.
  induction rem as [|rem' IH]; intros cfg tent_rst fuel st Hidle Hwal Hrem Hbk_ver Hfuel.
  - (* rem = 0 => c >= M => after +1 in Step 3, t1 > M => immediate revert! *)
    assert (Hge : cfg_max_retries cfg <= boot_failure_counter (st_tmr st)) by lia.
    destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    assert (Heval_done :
      exists out1 st1,
        eval_boot_state cfg st = (out1, st1) /\
        is_safe_terminal_outcome out1 (st_otp st1) /\
        match out1 with
        | Enter_Recovery_OS _ => True
        | Boot_App img tent _ =>
            is_verified_boot_app img (st_otp st1) && negb tent = true
        end).
    { unfold eval_boot_state; cbv zeta.
      rewrite Hmac; simpl; rewrite Hmbx, Hwal.
      unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
      assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
        by (destruct (active_nonce (st_tmr st)); reflexivity).
      rewrite Hrtc_f; simpl.
      rewrite Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; simpl.
      rewrite ?Bool.orb_true_l; simpl.
      set (t1 := apply_crash_accum cfg (st_tmr st)).
      assert (Hpos : (0 <? boot_failure_counter t1) = true).
      { unfold t1, apply_crash_accum.
        destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
          apply Nat.ltb_lt; [apply Nat.ltb_lt in E; lia | lia]. }
      assert (Hmust : (rst_indicates_crash (st_reset st) && true || false ||
                       (cfg_max_retries cfg <? boot_failure_counter t1)) = true).
      { assert (Hgt1 : (cfg_max_retries cfg <? boot_failure_counter t1) = true).
        { unfold t1, apply_crash_accum.
          destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
            [exact E | apply Nat.ltb_lt; lia]. }
        rewrite Hgt1, Bool.orb_true_r; reflexivity. }
      rewrite Hpos, Hmust; simpl.
      destruct (hdr_valid (backup_slot (st_slots st))) eqn:Hbhdr; simpl.
      - unfold step4_update_pipeline; simpl; cbv zeta.
        rewrite Hbhdr; simpl.
        specialize (Hbk_ver eq_refl).
        eexists _, _; split; [reflexivity | split;
          [split; [reflexivity | exact Hbk_ver]
          | rewrite Bool.andb_true_r; apply is_verified_boot_app_spec; exact Hbk_ver]].
      - eexists _, _; repeat split; exact I. }
    destruct Heval_done as [out1 [st1 [Hev [Hsafe Hchk]]]].
    destruct out1 as [img tent n | rm];
      destruct fuel as [|fuel']; simpl; rewrite Hev; rewrite ?Hchk; (split; [lia | exact Hsafe]).
  - (* rem = S rem' *)
    destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    destruct (rst_indicates_crash (st_reset st) ||
              (cfg_max_retries cfg <=? boot_failure_counter (st_tmr st))) eqn:Hrev_now.
    + (* Immediate revert on this boot! *)
      assert (Heval_done :
        exists out1 st1,
          eval_boot_state cfg st = (out1, st1) /\
          is_safe_terminal_outcome out1 (st_otp st1) /\
          match out1 with
          | Enter_Recovery_OS _ => True
          | Boot_App img tent _ =>
              is_verified_boot_app img (st_otp st1) && negb tent = true
          end).
      { unfold eval_boot_state; cbv zeta.
        rewrite Hmac; simpl; rewrite Hmbx, Hwal.
        unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
        assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
          by (destruct (active_nonce (st_tmr st)); reflexivity).
        rewrite Hrtc_f; simpl; rewrite Hcld by reflexivity; simpl.
        unfold step3_failure_and_rollback; cbv zeta; simpl.
        rewrite ?Bool.orb_true_l; simpl.
        set (t1 := apply_crash_accum cfg (st_tmr st)).
        assert (Hpos : (0 <? boot_failure_counter t1) = true).
        { unfold t1, apply_crash_accum.
          destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
            apply Nat.ltb_lt; [apply Nat.ltb_lt in E; lia | lia]. }
        assert (Hmust : (rst_indicates_crash (st_reset st) && true || false ||
                         (cfg_max_retries cfg <? boot_failure_counter t1)) = true).
        { apply Bool.orb_true_iff in Hrev_now.
          destruct Hrev_now as [Hrc | Hge].
          - rewrite Hrc; reflexivity.
          - apply Nat.leb_le in Hge.
            assert (Hgt1 : (cfg_max_retries cfg <? boot_failure_counter t1) = true).
            { unfold t1, apply_crash_accum.
              destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
                [exact E | apply Nat.ltb_lt; lia]. }
            rewrite Hgt1, Bool.orb_true_r; reflexivity. }
        rewrite Hpos, Hmust; simpl.
        destruct (hdr_valid (backup_slot (st_slots st))) eqn:Hbhdr; simpl.
        - unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hbhdr; simpl.
          specialize (Hbk_ver eq_refl).
          eexists _, _; split; [reflexivity | split;
            [split; [reflexivity | exact Hbk_ver]
            | rewrite Bool.andb_true_r; apply is_verified_boot_app_spec; exact Hbk_ver]].
        - eexists _, _; repeat split; exact I. }
      destruct Heval_done as [out1 [st1 [Hev [Hsafe Hchk]]]].
      destruct out1 as [img tent n | rm];
        destruct fuel as [|fuel']; simpl; rewrite Hev; rewrite ?Hchk; (split; [lia | exact Hsafe]).
    + (* Non-immediate reset and boot_failure_counter < M: increments c -> S c <= M *)
      apply Bool.orb_false_iff in Hrev_now as [Hrc_f Hlt_m].
      apply Nat.leb_gt in Hlt_m.
      assert (Hfuel_pos : exists fuel', fuel = S fuel').
      { destruct fuel as [|f']; [lia | exists f'; reflexivity]. }
      destruct Hfuel_pos as [fuel' Hfeq]; subst fuel.
      simpl.
      unfold eval_boot_state; cbv zeta.
      rewrite Hmac; simpl; rewrite Hmbx, Hwal.
      unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
      assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
        by (destruct (active_nonce (st_tmr st)); reflexivity).
      rewrite Hrtc_f; simpl; rewrite Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; simpl.
      rewrite ?Hrc_f, ?Bool.orb_true_l; simpl.
      unfold apply_crash_accum.
      assert (Hltb_f : (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) = false)
        by (apply Nat.ltb_ge; lia).
      rewrite Hltb_f; simpl.
      assert (Hltb_f2 : (cfg_max_retries cfg <? S (boot_failure_counter (st_tmr st))) = false)
        by (apply Nat.ltb_ge; lia).
      rewrite Hltb_f2; simpl.
      unfold step4_update_pipeline; simpl; cbv zeta.
      destruct (hdr_valid (app_slot (st_slots st))) eqn:Happ_hdr; simpl; cbv zeta.
      * (* Tentative boot continues to next reboot (`negb true = false`) *)
        rewrite Bool.andb_false_r.
        set (st_next := next_unconfirmed_reboot_state true tent_rst
               (mkState (st_slots st)
                 (wal_append_valid (st_wal st) WI_TxnCommit 0)
                 (set_tmr_nonce
                   (mkTMR (tmr_app_svn (st_tmr st)) (tmr_stage1_svn (st_tmr st))
                          (S (boot_failure_counter (st_tmr st)))
                          (recovery_failure_counter (st_tmr st))
                          (active_nonce (st_tmr st)) (last_mbx_seq (st_tmr st))
                          (last_cloud_issued_at (st_tmr st)) (tmr_mac_valid (st_tmr st)))
                   (cfg_fresh_nonce cfg))
                 (st_confirm st) (st_otp st) (st_reset st))).
        assert (Hidle_next : IdleInputs st_next).
        { unfold IdleInputs, st_next, next_unconfirmed_reboot_state; simpl.
          repeat split; try assumption; try reflexivity.
          eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | reflexivity]. }
        specialize (IH cfg tent_rst fuel' st_next Hidle_next eq_refl ltac:(simpl; lia)
                       Hbk_ver ltac:(lia)).
        destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb].
        destruct IH as [Hreb Hsafe].
        split; [lia | exact Hsafe].
      * (* App header invalid: falls back to Recovery OS or Rescue in 0 reboots! *)
        rewrite Hrec_rom; simpl.
        destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg);
          simpl; (split; [lia | exact I]).
Qed.

(* Unconditional variant of Helper 5.2 (even if backup_slot has a forged unverified
   header, rollback drops into non_tentative_wdt_converges within <= M + 1 more reboots!) *)
Lemma tentative_txn_commit_converges_unconditional :
  forall rem cfg tent_rst fuel st,
    IdleInputs st ->
    wal_reconstruct_txn (st_wal st) = Some (WI_TxnCommit, 0) ->
    cfg_max_retries cfg - boot_failure_counter (st_tmr st) <= rem ->
    rem + (cfg_max_retries cfg + 1) <= fuel ->
    let '(out, st_f, reboots) := run_until_safe cfg tent_rst fuel st in
    reboots <= rem + (cfg_max_retries cfg + 1) /\
    is_safe_terminal_outcome out (st_otp st_f).
Proof.
  induction rem as [|rem' IH]; intros cfg tent_rst fuel st Hidle Hwal Hrem Hfuel.
  - assert (Hge : cfg_max_retries cfg <= boot_failure_counter (st_tmr st)) by lia.
    destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    assert (Hfuel_pos : exists fuel', fuel = S fuel').
    { destruct fuel as [|f']; [lia | exists f'; reflexivity]. }
    destruct Hfuel_pos as [fuel' Hfeq]; subst fuel; simpl.
    unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl; rewrite Hmbx, Hwal.
    unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
    assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
      by (destruct (active_nonce (st_tmr st)); reflexivity).
    rewrite Hrtc_f; simpl; rewrite Hcld by reflexivity; simpl.
    unfold step3_failure_and_rollback; cbv zeta; simpl; rewrite ?Bool.orb_true_l; simpl.
    set (t1 := apply_crash_accum cfg (st_tmr st)).
    assert (Hpos : (0 <? boot_failure_counter t1) = true).
    { unfold t1, apply_crash_accum.
      destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
        apply Nat.ltb_lt; [apply Nat.ltb_lt in E; lia | lia]. }
    assert (Hmust : (rst_indicates_crash (st_reset st) && true || false ||
                     (cfg_max_retries cfg <? boot_failure_counter t1)) = true).
    { assert (Hgt1 : (cfg_max_retries cfg <? boot_failure_counter t1) = true).
      { unfold t1, apply_crash_accum.
        destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
          [exact E | apply Nat.ltb_lt; lia]. }
      rewrite Hgt1, Bool.orb_true_r; reflexivity. }
    rewrite Hpos, Hmust; simpl.
    destruct (hdr_valid (backup_slot (st_slots st))) eqn:Hbhdr; simpl.
    + unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hbhdr; simpl.
      destruct (is_verified_boot_app (backup_slot (st_slots st)) (st_otp st)) eqn:Hver; simpl.
      * apply is_verified_boot_app_spec in Hver; split; [lia | split; [reflexivity | exact Hver]].
      * set (st_next := next_unconfirmed_reboot_state false tent_rst _).
        assert (Ht1_meta : tmr_mac_valid t1 = tmr_mac_valid (st_tmr st) /\
                           last_mbx_seq t1 = last_mbx_seq (st_tmr st) /\
                           last_cloud_issued_at t1 = last_cloud_issued_at (st_tmr st)).
        { unfold t1, apply_crash_accum;
          destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)); simpl; auto. }
        destruct Ht1_meta as [Ht1_mac [Ht1_seq Ht1_iss]].
        assert (Hidle_n : IdleInputs st_next).
        { unfold IdleInputs, st_next, next_unconfirmed_reboot_state, set_tmr_nonce, clear_boot_failure_and_nonce; simpl.
          rewrite Ht1_mac, ?Ht1_seq, Ht1_iss.
          repeat split; try assumption; try reflexivity.
          - eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; rewrite ?Ht1_seq; lia | reflexivity].
          - intros w t i Ht.
            eapply step2_5_cloud_idempotent_after_run; [exact (Hcld w t i Ht) | reflexivity | reflexivity]. }
        pose proof (non_tentative_wdt_converges
                      (cfg_max_retries cfg) cfg tent_rst fuel' st_next
                      Hidle_n eq_refl eq_refl (or_introl (ex_intro _ 0 eq_refl))
                      ltac:(simpl; lia) ltac:(lia)) as Hconv.
        destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb].
        destruct Hconv as [Hreb Hsafe]; split; [lia | exact Hsafe].
    + split; [lia | exact I].
  - destruct Hidle as [Hrec_rom [Hmac [Hrtc0 [Hmbx Hcld]]]].
    assert (Hfuel_pos : exists fuel', fuel = S fuel').
    { destruct fuel as [|f']; [lia | exists f'; reflexivity]. }
    destruct Hfuel_pos as [fuel' Hfeq]; subst fuel; simpl.
    destruct (rst_indicates_crash (st_reset st) ||
              (cfg_max_retries cfg <=? boot_failure_counter (st_tmr st))) eqn:Hrev_now.
    + unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl; rewrite Hmbx, Hwal.
      unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
      assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
        by (destruct (active_nonce (st_tmr st)); reflexivity).
      rewrite Hrtc_f; simpl; rewrite Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; simpl; rewrite ?Bool.orb_true_l; simpl.
      set (t1 := apply_crash_accum cfg (st_tmr st)).
      assert (Hpos : (0 <? boot_failure_counter t1) = true).
      { unfold t1, apply_crash_accum.
        destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
          apply Nat.ltb_lt; [apply Nat.ltb_lt in E; lia | lia]. }
      assert (Hmust : (rst_indicates_crash (st_reset st) && true || false ||
                       (cfg_max_retries cfg <? boot_failure_counter t1)) = true).
      { apply Bool.orb_true_iff in Hrev_now.
        destruct Hrev_now as [Hrc | Hge]; [rewrite Hrc; reflexivity|].
        apply Nat.leb_le in Hge.
        assert (Hgt1 : (cfg_max_retries cfg <? boot_failure_counter t1) = true).
        { unfold t1, apply_crash_accum.
          destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:E; simpl;
            [exact E | apply Nat.ltb_lt; lia]. }
        rewrite Hgt1, Bool.orb_true_r; reflexivity. }
      rewrite Hpos, Hmust; simpl.
      destruct (hdr_valid (backup_slot (st_slots st))) eqn:Hbhdr; simpl.
      * unfold step4_update_pipeline; simpl; cbv zeta; rewrite Hbhdr; simpl.
        destruct (is_verified_boot_app (backup_slot (st_slots st)) (st_otp st)) eqn:Hver; simpl.
        -- apply is_verified_boot_app_spec in Hver; split; [lia | split; [reflexivity | exact Hver]].
        -- set (st_next := next_unconfirmed_reboot_state false tent_rst _).
           assert (Ht1_meta : tmr_mac_valid t1 = tmr_mac_valid (st_tmr st) /\
                              last_mbx_seq t1 = last_mbx_seq (st_tmr st) /\
                              last_cloud_issued_at t1 = last_cloud_issued_at (st_tmr st)).
           { unfold t1, apply_crash_accum;
             destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)); simpl; auto. }
           destruct Ht1_meta as [Ht1_mac [Ht1_seq Ht1_iss]].
           assert (Hidle_n : IdleInputs st_next).
           { unfold IdleInputs, st_next, next_unconfirmed_reboot_state, set_tmr_nonce, clear_boot_failure_and_nonce; simpl.
             rewrite Ht1_mac, ?Ht1_seq, Ht1_iss.
             repeat split; try assumption; try reflexivity.
             - eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; rewrite ?Ht1_seq; lia | reflexivity].
             - intros w t i Ht.
               eapply step2_5_cloud_idempotent_after_run; [exact (Hcld w t i Ht) | reflexivity | reflexivity]. }
           pose proof (non_tentative_wdt_converges
                         (cfg_max_retries cfg) cfg tent_rst fuel' st_next
                         Hidle_n eq_refl eq_refl (or_introl (ex_intro _ 0 eq_refl))
                         ltac:(simpl; lia) ltac:(lia)) as Hconv.
           destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb].
           destruct Hconv as [Hreb Hsafe]; split; [lia | exact Hsafe].
      * split; [lia | exact I].
    + apply Bool.orb_false_iff in Hrev_now as [Hrc_f Hlt_m].
      apply Nat.leb_gt in Hlt_m.
      unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl; rewrite Hmbx, Hwal.
      unfold step2_confirm_check; cbv zeta; rewrite Hrtc0.
      assert (Hrtc_f : ((0 <? active_nonce (st_tmr st)) && (0 =? active_nonce (st_tmr st))) = false)
        by (destruct (active_nonce (st_tmr st)); reflexivity).
      rewrite Hrtc_f; simpl; rewrite Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; simpl; rewrite ?Hrc_f, ?Bool.orb_true_l; simpl.
      unfold apply_crash_accum.
      assert (Hltb_f : (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) = false)
        by (apply Nat.ltb_ge; lia).
      assert (Hltb_f2 : (cfg_max_retries cfg <? S (boot_failure_counter (st_tmr st))) = false)
        by (apply Nat.ltb_ge; lia).
      rewrite Hltb_f; simpl; rewrite Hltb_f2; simpl.
      unfold step4_update_pipeline; simpl; cbv zeta.
      destruct (hdr_valid (app_slot (st_slots st))) eqn:Happ_hdr; simpl; cbv zeta.
      * rewrite Bool.andb_false_r.
        set (st_next := next_unconfirmed_reboot_state true tent_rst _).
        assert (Hidle_n : IdleInputs st_next).
        { unfold IdleInputs, st_next, next_unconfirmed_reboot_state; simpl.
          repeat split; try assumption; try reflexivity.
          eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | reflexivity]. }
        specialize (IH cfg tent_rst fuel' st_next Hidle_n eq_refl ltac:(simpl; lia) ltac:(lia)).
        destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb].
        destruct IH as [Hreb Hsafe]; split; [lia | exact Hsafe].
      * rewrite Hrec_rom; simpl.
        destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg);
          simpl; (split; [lia | exact I]).
Qed.

(* Characterization of any Boot_App state produced by eval_boot_state *)
Lemma post_boot_app_characterization :
  forall cfg tent_rst st0 img tent nonce st1,
    recovery_rom_valid (st_slots st0) = true ->
    eval_boot_state cfg st0 = (Boot_App img tent nonce, st1) ->
    let st_next := next_unconfirmed_reboot_state tent tent_rst st1 in
    IdleInputs st_next /\
    boot_failure_counter (st_tmr st_next) <= cfg_max_retries cfg /\
    (tent = true ->
       wal_reconstruct_txn (st_wal st_next) = Some (WI_TxnCommit, 0) /\
       (backup_slot (st_slots st_next) = backup_slot (st_slots st0) \/
        backup_slot (st_slots st_next) = app_slot (st_slots st0))) /\
    (tent = false ->
       st_reset st_next = RR_Watchdog /\
       active_nonce (st_tmr st_next) = 0 /\
       ((exists exp_n, wal_reconstruct_txn (st_wal st_next) = Some (WI_None, exp_n)) \/
        exists exp_n, wal_reconstruct_txn (st_wal st_next) = Some (WI_ConfirmCommit, exp_n))).
Proof.
  intros cfg tent_rst st0 img tent nonce st1 Hrec0 Heval st_next.
  unfold eval_boot_state in Heval; cbv zeta in Heval.
  destruct (negb (tmr_mac_valid (st_tmr st0))) eqn:Hmac0; [discriminate|].
  apply Bool.negb_false_iff in Hmac0.
  destruct (step1_mailbox_consume (st_slots st0) (st_wal st0) (st_tmr st0))
    as [err | slots1 wal1 tmr1] eqn:Hmbx; [discriminate|].
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx)
    as [Happ1 [Hstg1 [Hbk1 [Hrec1 [Hcld1 [Hsvn1 [Hbf1 [Hrf1 [Han1 [Hiss1 [Hmac1 Hseq_le]]]]]]]]]]].
  destruct (wal_reconstruct_txn wal1) as [[oi1 oe1]|] eqn:Hwrec1; [|discriminate].
  destruct (step2_confirm_check slots1 wal1 tmr1 (st_confirm st0) oi1 oe1)
    as [|slots2 wal2 tmr2 conf2 oi2 healed2] eqn:Hs2; [discriminate|].
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Hs2)
    as [Happ2 [Hbk2 [Hrec2 [Hcld2 [Hmbx2 [Hsvn2 [Hseq2 [Hiss2 Hmac2]]]]]]]].
  destruct (step2_5_cloud_cmd slots2 wal2 tmr2 (st_otp st0) oi2)
    as [[[[slots25 wal25] tmr25] otp25] oi25] eqn:Hs25.
  pose proof (step2_5_cloud_preserves_images _ _ _ _ _ _ _ _ _ _ Hs25)
    as [Happ25 [Hstg25 [Hbk25 [Hrec25 [Hmbx25 [Hotp_le [Hkey25 [Hsvn25 [Hbf25 [Hrf25 [Han25 [Hseq25 Hmac25]]]]]]]]]]]].
  destruct (wal_intent_eqb oi25 WI_DeviceLocked) eqn:Hlock; [discriminate|].
  destruct (step3_failure_and_rollback cfg slots25 wal25 tmr25 (st_reset st0) oi25 healed2)
    as [err3 t3p | slots3 wal3 tmr3 oi3 healed3 rec3] eqn:Hs3; [discriminate|].
  (* Extract properties of Step 3 when rec3 must eventually be false *)
  destruct (step4_update_pipeline slots3 wal3 tmr3 otp25 oi3)
    as [[[[slots4 wal4] tmr4] oi4] upd_pend] eqn:Hs4.
  cbv zeta in Heval.
  set (fb := negb rec3 && negb (hdr_valid (app_slot slots4)) &&
             recovery_rom_valid slots4 &&
             (recovery_failure_counter tmr4 <=? cfg_max_recovery_retries cfg)) in *.
  destruct (negb (if rec3 || fb then recovery_rom_valid slots4 else hdr_valid (app_slot slots4))) eqn:Htarg;
    [discriminate|].
  destruct (rec3 || fb) eqn:Hrec5; [discriminate|].
  apply Bool.orb_false_iff in Hrec5 as [Hrec3_f Hfb_f].
  subst rec3.
  inversion Heval; subst img tent nonce st1.
  assert (Hs3_full :
    recovery_rom_valid slots3 = true /\
    cloud_slot slots3 = cloud_slot slots25 /\
    mailbox_slot slots3 = mailbox_slot slots25 /\
    backup_slot slots3 = backup_slot (st_slots st0) /\
    (app_slot slots3 = app_slot (st_slots st0) \/ app_slot slots3 = backup_slot (st_slots st0)) /\
    tmr_mac_valid tmr3 = true /\
    last_mbx_seq tmr3 = last_mbx_seq tmr1 /\
    last_cloud_issued_at tmr3 = last_cloud_issued_at tmr25 /\
    boot_failure_counter tmr3 <= cfg_max_retries cfg /\
    oi3 <> WI_DeviceLocked /\ oi3 <> WI_TxnRollback /\ oi3 <> WI_TxnRollbackPending /\
    (oi3 = WI_ConfirmCommit -> False) /\
    (oi3 = WI_RecoveryResolved -> False) /\
    (oi3 = WI_None /\ healed3 = false ->
       (exists exp_n, wal_reconstruct_txn wal3 = Some (WI_None, exp_n)) \/
       exists exp_n, wal_reconstruct_txn wal3 = Some (WI_ConfirmCommit, exp_n))).
  { (* Step 2 & 2.5 trace for oi25 and wal25 *)
    assert (Hs2_oi :
      (oi2 = WI_UpdatePending) \/
      (oi2 = WI_TxnCommit) \/
      (oi2 = WI_TxnRollback) \/
      (oi2 = WI_TxnRollbackPending) \/
      (oi2 = WI_DeviceLocked) \/
      (oi2 = WI_None /\ healed2 = true) \/
      (oi2 = WI_None /\ healed2 = false /\ wal2 = wal1 /\
       (oi1 = WI_None \/ oi1 = WI_ConfirmCommit))).
    { unfold step2_confirm_check in Hs2; cbv zeta in Hs2.
      destruct (wal_intent_eqb oi1 WI_UpdatePending) eqn:Eup.
      - apply wal_intent_eqb_eq in Eup; subst oi1.
        destruct (reconstruct_aux_entries (wal_entries wal1)); try discriminate.
        + destruct ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st0) =? active_nonce tmr1));
            inversion Hs2; subst; left; reflexivity.
        + destruct (((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st0) =? active_nonce tmr1)) ||
                    (wal_intent_eqb w WI_ConfirmCommit && (0 <? active_nonce tmr1) &&
                     (0 <? n) && (n =? active_nonce tmr1)) ||
                    wal_intent_eqb w WI_RecoveryResolved);
            inversion Hs2; subst; left; reflexivity.
      - destruct (negb (wal_intent_eqb oi1 WI_DeviceLocked) &&
                  (wal_intent_eqb oi1 WI_ConfirmCommit ||
                   wal_intent_eqb oi1 WI_RecoveryResolved ||
                   ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st0) =? active_nonce tmr1)))) eqn:Ec2.
        + destruct (negb (((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st0) =? active_nonce tmr1)) ||
                          (wal_intent_eqb oi1 WI_ConfirmCommit && (0 <? active_nonce tmr1) &&
                           (0 <? oe1) && (oe1 =? active_nonce tmr1)) ||
                          wal_intent_eqb oi1 WI_RecoveryResolved)) eqn:Eauth.
          * destruct (0 <? active_nonce tmr1) eqn:Ean.
            -- inversion Hs2; subst; right; left; reflexivity.
            -- inversion Hs2; subst.
               (* Since auth_ok = false and 0 <? active_nonce = false, rtc_ok = false and oi1 <> RecoveryResolved, so oi1 = ConfirmCommit! *)
               assert (Hoi1_cc : oi1 = WI_ConfirmCommit)
                 by (destruct oi1; simpl in *; try discriminate; reflexivity).
               subst oi1.
               right; right; right; right; right; right.
               repeat split; auto.
          * destruct (if ((0 <? active_nonce tmr1) && (rtc_nonce (st_confirm st0) =? active_nonce tmr1)) &&
                         wal_intent_eqb oi1 WI_None then WI_ConfirmCommit else oi1) eqn:Eeff;
              inversion Hs2; subst; auto 8.
        + inversion Hs2; subst.
          destruct oi2; simpl in *; try discriminate; auto 8.
          right; right; right; right; right; right; repeat split; auto. }
    assert (Hs25_oi :
      (oi25 = oi2 /\ wal25 = wal2) \/
      (oi25 = WI_None /\ wal_reconstruct_txn wal25 = Some (WI_None, 0)) \/
      (oi25 = WI_UpdatePending) \/
      (oi25 = WI_DeviceLocked)).
    { unfold step2_5_cloud_cmd in Hs25; cbv zeta in Hs25.
      destruct (cloud_slot slots2) as [|cmd sig_ok dev_ok ctr iss].
      - inversion Hs25; subst; left; split; reflexivity.
      - destruct (negb (sig_ok && dev_ok &&
                        ((otp_min_svn (st_otp st0) <? ctr) &&
                         (last_cloud_issued_at tmr2 <? iss) &&
                         (ctr - otp_min_svn (st_otp st0) <=? toob_cmd_max_burn_steps)))).
        + inversion Hs25; subst; left; split; reflexivity.
        + destruct cmd; try destruct (wal_intent_eqb oi2 WI_DeviceLocked);
            inversion Hs25; subst; auto. }
    assert (Hoi25_clean :
      oi25 <> WI_DeviceLocked /\ oi25 <> WI_ConfirmCommit /\ oi25 <> WI_RecoveryResolved /\
      (oi25 = WI_None /\ healed2 = false ->
         (exists exp_n, wal_reconstruct_txn wal25 = Some (WI_None, exp_n)) \/
         exists exp_n, wal_reconstruct_txn wal25 = Some (WI_ConfirmCommit, exp_n))).
    { assert (Hnd : oi25 <> WI_DeviceLocked)
        by (intro H; subst; discriminate).
      destruct Hs25_oi as [[Heq_i Heq_w] | [[Hn25 Hwn25] | [Hup25 | Hdl25]]].
      - subst oi25 wal25.
        repeat split; try exact Hnd.
        + intro Hc; subst oi2; intuition discriminate.
        + intro Hr; subst oi2; intuition discriminate.
        + intros [Hn2 Hh2]; subst oi2 healed2.
          destruct Hs2_oi as [?|[?|[?|[?|[?|[[_ ?]|[_ [_ [Hw2 H1]]]]]]]]];
            try discriminate.
          subst wal2.
          destruct H1 as [Ho1 | Ho1]; subst oi1.
          * left; exists oe1; exact Hwrec1.
          * right; exists oe1; exact Hwrec1.
      - subst oi25; repeat split; try discriminate.
        intros _; left; exists 0; exact Hwn25.
      - subst oi25; repeat split; try discriminate.
        intros [? _]; discriminate.
      - contradiction. }
    destruct Hoi25_clean as [Hnd25 [Hncc25 [Hnrr25 Hnone25]]].
    unfold step3_failure_and_rollback in Hs3; cbv zeta in Hs3.
    set (t_acc := if negb healed2 &&
                     ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                      (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending))) &&
                     crash_accum_applicable oi25
                  then apply_crash_accum cfg tmr25 else tmr25) in *.
    assert (Htacc_props :
      tmr_mac_valid t_acc = true /\
      last_mbx_seq t_acc = last_mbx_seq tmr1 /\
      last_cloud_issued_at t_acc = last_cloud_issued_at tmr25).
    { unfold t_acc, apply_crash_accum.
      destruct (negb healed2 &&
                ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                 (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending))) &&
                crash_accum_applicable oi25).
      - destruct (cfg_max_retries cfg <? boot_failure_counter tmr25); simpl;
          repeat split; congruence.
      - repeat split; congruence. }
    destruct Htacc_props as [Ht_mac [Ht_seq Ht_iss]].
    destruct (wal_intent_eqb oi25 WI_TxnRollback) eqn:Etrb.
    - inversion Hs3; subst; simpl.
      repeat split; try congruence; try lia; try discriminate.
      left; congruence.
    - destruct ((0 <? boot_failure_counter t_acc) || wal_intent_eqb oi25 WI_TxnRollbackPending) eqn:Ehasf.
      + destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending) eqn:Ecasea.
        * destruct (rst_indicates_crash (st_reset st0) && negb healed2 ||
                    wal_intent_eqb oi25 WI_TxnRollbackPending ||
                    (cfg_max_retries cfg <? boot_failure_counter t_acc)) eqn:Emust.
          -- destruct (negb (hdr_valid (backup_slot slots25))); [discriminate|].
             inversion Hs3; subst; simpl.
             repeat split; try congruence; try lia; try discriminate.
             right; congruence.
          -- (* must_revert = false => oi25 = WI_TxnCommit AND boot_failure_counter t_acc <= M *)
             assert (Hoi_tc : oi25 = WI_TxnCommit).
             { destruct oi25; simpl in *; rewrite ?Bool.orb_true_r in Emust; simpl in Emust; try discriminate; reflexivity. }
             subst oi25.
             assert (Hle_m : boot_failure_counter t_acc <= cfg_max_retries cfg).
             { apply Bool.orb_false_iff in Emust as [_ Hltf].
               apply Nat.ltb_ge in Hltf; exact Hltf. }
             inversion Hs3; subst; simpl.
             repeat split; try congruence; try lia; try discriminate.
             ++ left; congruence.
             ++ intros [? _]; discriminate.
        * destruct (boot_failure_counter t_acc <=? cfg_max_retries cfg) eqn:Ele_m;
            [|destruct (recovery_failure_counter t_acc <=? cfg_max_recovery_retries cfg); discriminate].
          apply Nat.leb_le in Ele_m.
          inversion Hs3; subst.
          repeat split; try congruence; try lia.
          -- left; congruence.
          -- intro H; subst; simpl in Etrb; discriminate.
          -- intro H; subst; simpl in Ecasea; rewrite ?Bool.orb_true_r in Ecasea; discriminate.
          -- exact Hnone25.
      + apply Bool.orb_false_iff in Ehasf as [Hbf0 Hnrp].
        apply Nat.ltb_ge in Hbf0.
        inversion Hs3; subst.
        repeat split; try congruence; try lia.
        * left; congruence.
        * intro H; subst; simpl in Etrb; discriminate.
        * intro H; subst; simpl in Hnrp; discriminate.
        * exact Hnone25. }
  destruct Hs3_full as [Hrec3 [Hcld3 [Hmbx3 [Hbk3 [Happ3 [Hmac3 [Hseq3 [Hiss3 [Hbf3 [Hnd3 [Hnrb3 [Hnrp3 [Hncc3 [Hnrr3 Hnone3]]]]]]]]]]]]]].
  (* Now analyze Step 4 *)
  unfold step4_update_pipeline in Hs4; cbv zeta in Hs4.
  destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)) eqn:Enot_up.
  - (* oi3 <> WI_UpdatePending *)
    assert (Hoi3_cases : oi3 = WI_None \/ oi3 = WI_TxnCommit).
    { destruct oi3; simpl in *; try contradiction; try discriminate; auto. }
    inversion Hs4; subst slots4 wal4 tmr4 oi4 upd_pend.
    assert (Hidle_out : IdleInputs st_next).
    { unfold st_next, IdleInputs, next_unconfirmed_reboot_state; simpl.
      repeat split; try assumption; try reflexivity.
      - eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | congruence].
      - intros w t i Ht.
        pose proof (step2_5_cloud_idempotent_after_run _ _ _ _ _ _ _ _ _ _ slots3 w t i Hs25) as Hcid.
        apply Hcid; [simpl in Ht; congruence | congruence]. }
    split; [exact Hidle_out | split; [unfold st_next, next_unconfirmed_reboot_state; simpl; exact Hbf3 | split]].
    + intro Htent; unfold st_next, next_unconfirmed_reboot_state; simpl.
      destruct Hoi3_cases as [Hn | Htc]; subst oi3; [discriminate|].
      simpl; split; [reflexivity | left; exact Hbk3].
    + intro Hntent; unfold st_next, next_unconfirmed_reboot_state; simpl.
      destruct Hoi3_cases as [Hn | Htc]; subst oi3; [|discriminate].
      simpl; repeat split.
      destruct healed3 eqn:Hh3; simpl.
      * left; exists 0; reflexivity.
      * apply Hnone3; split; reflexivity.
  - (* oi3 = WI_UpdatePending *)
    destruct (staging_can_apply (staging_slot slots3) tmr3 otp25) eqn:Hcan.
    + inversion Hs4; subst slots4 wal4 tmr4 oi4 upd_pend; simpl.
      unfold st_next, IdleInputs, next_unconfirmed_reboot_state; simpl.
      repeat split; try reflexivity; try lia; try discriminate.
      * exact Hrec3.
      * exact Hmac3.
      * eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | simpl; congruence].
      * intros w t i Ht.
        eapply step2_5_cloud_idempotent_after_run; [exact Hs25 | simpl in Ht; congruence | simpl; congruence].
      * destruct Happ3 as [Ha | Hb]; [right; exact Ha | left; exact Hb].
    + inversion Hs4; subst slots4 wal4 tmr4 oi4 upd_pend; simpl.
      unfold st_next, IdleInputs, next_unconfirmed_reboot_state; simpl.
      repeat split; try reflexivity; try lia; try discriminate.
      * exact Hrec3.
      * exact Hmac3.
      * eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | congruence].
      * intros w t i Ht.
        eapply step2_5_cloud_idempotent_after_run; [exact Hs25 | simpl in Ht; congruence | congruence].
      * rewrite Bool.orb_true_r; left; exists 0; reflexivity.
Qed.

(* Core Theorem 1A: Bounded Boot Termination (<= BOOT_CONFIG_MAX_RETRIES + 1
   consecutive reboots across ALL corrupted WAL / TMR / Confirm / Staging /
   ResetReason states with intact Stage 0 + Stage 1/Recovery ROM and valid
   installed slot invariant). *)
Theorem bounded_boot_termination :
  forall cfg tent_rst st0,
    recovery_rom_valid (st_slots st0) = true ->
    ValidInstalledSlots (st_slots st0) (st_otp st0) ->
    cloud_slot (st_slots st0) = CC_Empty ->
    let '(out, st_final, reboots) :=
      run_until_safe cfg tent_rst (cfg_max_retries cfg + 1) st0 in
    reboots <= cfg_max_retries cfg + 1 /\
    is_safe_terminal_outcome out (st_otp st_final).
Proof.
  intros cfg tent_rst st0 Hrec0 Hvalid0 Hcld0.
  rewrite Nat.add_1_r; simpl.
  destruct (eval_boot_state cfg st0) as [out0 st1] eqn:Heval0.
  pose proof (monotonic_anti_rollback_safety cfg st0 out0 st1 Hvalid0 Hcld0 Heval0)
    as [Hvalid1 [Hotp_eq [Hkey_eq [_ Happ_safe]]]].
  destruct out0 as [img0 tent0 nonce0 | rm0]; simpl.
  - destruct (is_verified_boot_app img0 (st_otp st1) && negb tent0) eqn:Hdone; simpl.
    + rewrite Bool.andb_true_iff, Bool.negb_true_iff in Hdone.
      destruct Hdone as [Hver Ht0].
      apply is_verified_boot_app_spec in Hver.
      split; [lia | split; [exact Ht0 | exact Hver]].
    + pose proof (post_boot_app_characterization cfg tent_rst st0 img0 tent0 nonce0 st1 Hrec0 Heval0)
        as [Hidle_next [Hbf_le [Htent_t Htent_f]]].
      set (st_next := next_unconfirmed_reboot_state tent0 tent_rst st1) in *.
      destruct tent0.
      * destruct (Htent_t eq_refl) as [Hwal_tc _].
        destruct Hvalid1 as [_ Hbk1_ok].
        assert (Hbk_next :
          hdr_valid (backup_slot (st_slots st_next)) = true ->
          image_is_verified (backup_slot (st_slots st_next))
                            (otp_min_svn (st_otp st_next))
                            (otp_active_key_index (st_otp st_next)))
          by exact Hbk1_ok.
        pose proof (tentative_txn_commit_converges
                      (cfg_max_retries cfg - boot_failure_counter (st_tmr st_next))
                      cfg tent_rst (cfg_max_retries cfg) st_next
                      Hidle_next Hwal_tc ltac:(lia) Hbk_next ltac:(lia)) as Hconv.
        destruct (run_until_safe cfg tent_rst (cfg_max_retries cfg) st_next) as [[out_f st_f] reb]; simpl.
        destruct Hconv as [Hreb Hsafe].
        split; [lia | exact Hsafe].
      * (* Wait: if tent0 = false, ValidInstalledSlots ALREADY proves img0 IS verified,
           so Hdone cannot be false! *)
        exfalso.
        specialize (Happ_safe img0 false nonce0 eq_refl)
          as [Hsvn_ge [Hk_eq [_ [Hs [Hm Hh]]]]].
        assert (Hver_true : is_verified_boot_app img0 (st_otp st1) = true).
        { apply is_verified_boot_app_spec.
          unfold image_is_verified; repeat split; assumption. }
        rewrite Hver_true in Hdone; discriminate.
  - split; [lia | exact I].
Qed.

(* Core Theorem 1B: Unconditional Non-Brickability from EVERY arbitrary /
   adversarially corrupted initial State (zero assumptions on app_slot,
   backup_slot, cloud_slot, mailbox_slot, WAL_Journal, TMR_Counters,
   ConfirmStore, OTP_Epoch, or ResetReason — assuming only immutable
   Stage 0 + Stage 1/Recovery ROM intact!). *)
Theorem bounded_boot_termination_unconditional :
  forall cfg tent_rst st0,
    recovery_rom_valid (st_slots st0) = true ->
    let bound := 2 * (cfg_max_retries cfg + 1) in
    let '(out, st_final, reboots) :=
      run_until_safe cfg tent_rst bound st0 in
    reboots <= bound /\
    is_safe_terminal_outcome out (st_otp st_final).
Proof.
  intros cfg tent_rst st0 Hrec0 bound.
  assert (Hbound_pos : exists fuel', bound = S fuel').
  { unfold bound; exists (2 * cfg_max_retries cfg + 1); lia. }
  destruct Hbound_pos as [fuel' Hbeq]; rewrite Hbeq; simpl.
  destruct (eval_boot_state cfg st0) as [out0 st1] eqn:Heval0.
  destruct out0 as [img0 tent0 nonce0 | rm0]; simpl.
  - destruct (is_verified_boot_app img0 (st_otp st1) && negb tent0) eqn:Hdone; simpl.
    + rewrite Bool.andb_true_iff, Bool.negb_true_iff in Hdone.
      destruct Hdone as [Hver Ht0].
      apply is_verified_boot_app_spec in Hver.
      split; [lia | split; [exact Ht0 | exact Hver]].
    + pose proof (post_boot_app_characterization cfg tent_rst st0 img0 tent0 nonce0 st1 Hrec0 Heval0)
        as [Hidle_next [Hbf_le [Htent_t Htent_f]]].
      set (st_next := next_unconfirmed_reboot_state tent0 tent_rst st1) in *.
      destruct tent0.
      * destruct (Htent_t eq_refl) as [Hwal_tc _].
        pose proof (tentative_txn_commit_converges_unconditional
                      (cfg_max_retries cfg - boot_failure_counter (st_tmr st_next))
                      cfg tent_rst fuel' st_next
                      Hidle_next Hwal_tc ltac:(lia) ltac:(unfold bound in Hbeq; lia)) as Hconv.
        destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb]; simpl.
        destruct Hconv as [Hreb Hsafe].
        split; [unfold bound in Hbeq; lia | exact Hsafe].
      * destruct (Htent_f eq_refl) as [Hrst_w [Han_0 Hwal_n]].
        pose proof (non_tentative_wdt_converges
                      (cfg_max_retries cfg - boot_failure_counter (st_tmr st_next))
                      cfg tent_rst fuel' st_next
                      Hidle_next Hrst_w Han_0 Hwal_n ltac:(lia) ltac:(unfold bound in Hbeq; lia)) as Hconv.
        destruct (run_until_safe cfg tent_rst fuel' st_next) as [[out_f st_f] reb]; simpl.
        destruct Hconv as [Hreb Hsafe].
        split; [unfold bound in Hbeq; lia | exact Hsafe].
  - split; [lia | exact I].
Qed.

(* Corollary 1C: Even with corrupted / unverified App_Slot_0 header (and NO
   tentative rollback chain), WDT crashes reach Enter_Recovery_OS in
   <= BOOT_CONFIG_MAX_RETRIES + 1 consecutive reboots! *)
Corollary bounded_boot_termination_corrupt_app :
  forall cfg tent_rst st0,
    recovery_rom_valid (st_slots st0) = true ->
    (hdr_valid (backup_slot (st_slots st0)) = true ->
     image_is_verified (backup_slot (st_slots st0))
                       (otp_min_svn (st_otp st0))
                       (otp_active_key_index (st_otp st0))) ->
    cloud_slot (st_slots st0) = CC_Empty ->
    (forall exp_n, wal_reconstruct_txn (st_wal st0) <> Some (WI_UpdatePending, exp_n)) ->
    mailbox_slot (st_slots st0) = MBX_Empty ->
    let '(out, st_final, reboots) :=
      run_until_safe cfg tent_rst (cfg_max_retries cfg + 1) st0 in
    reboots <= cfg_max_retries cfg + 1 /\
    is_safe_terminal_outcome out (st_otp st_final).
Proof.
  intros cfg tent_rst st0 Hrec0 Hbk0 Hcld0 Hnoup Hmbx0.
  rewrite Nat.add_1_r; simpl.
  destruct (eval_boot_state cfg st0) as [out0 st1] eqn:Heval0.
  destruct out0 as [img0 tent0 nonce0 | rm0]; simpl; [|split; [lia | exact I]].
  destruct (is_verified_boot_app img0 (st_otp st1) && negb tent0) eqn:Hdone; simpl.
  - rewrite Bool.andb_true_iff, Bool.negb_true_iff in Hdone.
    destruct Hdone as [Hver Ht0].
    apply is_verified_boot_app_spec in Hver.
    split; [lia | split; [exact Ht0 | exact Hver]].
  - pose proof (post_boot_app_characterization cfg tent_rst st0 img0 tent0 nonce0 st1 Hrec0 Heval0)
      as [Hidle_next [Hbf_le [Htent_t Htent_f]]].
    set (st_next := next_unconfirmed_reboot_state tent0 tent_rst st1) in *.
    (* Since mailbox_slot = MBX_Empty, cloud_slot = CC_Empty, and WAL != UpdatePending,
       Step 4 never overwrote backup_slot with an unverified app_slot! *)
    assert (Hbk_kept : backup_slot (st_slots st1) = backup_slot (st_slots st0) /\
                       st_otp st1 = st_otp st0).
    { unfold eval_boot_state in Heval0; cbv zeta in Heval0.
      destruct (negb (tmr_mac_valid (st_tmr st0))); [discriminate|].
      unfold step1_mailbox_consume in Heval0; rewrite Hmbx0 in Heval0; simpl in Heval0.
      destruct (wal_reconstruct_txn (st_wal st0)) as [[oi1 oe1]|] eqn:Ewr; [|discriminate].
      assert (Hoi1_noup : oi1 <> WI_UpdatePending)
        by (intro H; subst; exact (Hnoup oe1 eq_refl)).
      destruct (step2_confirm_check (st_slots st0) (st_wal st0) (st_tmr st0)
                  (st_confirm st0) oi1 oe1)
        as [|s2 w2 t2 c2 oi2 h2] eqn:Es2; [discriminate|].
      pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Es2)
        as [_ [Hbk2 [_ [Hcld2 _]]]].
      assert (Hoi2_noup : oi2 <> WI_UpdatePending).
      { unfold step2_confirm_check in Es2; cbv zeta in Es2.
        set (rtc_ok := (0 <? active_nonce (st_tmr st0)) &&
                       (rtc_nonce (st_confirm st0) =? active_nonce (st_tmr st0))) in *.
        assert (Hup_f : wal_intent_eqb oi1 WI_UpdatePending = false)
          by (destruct oi1; simpl; try reflexivity; contradiction).
        rewrite Hup_f in Es2.
        destruct (negb (wal_intent_eqb oi1 WI_DeviceLocked) &&
                  (wal_intent_eqb oi1 WI_ConfirmCommit ||
                   wal_intent_eqb oi1 WI_RecoveryResolved || rtc_ok)).
        - set (auth_ok := rtc_ok ||
                          (wal_intent_eqb oi1 WI_ConfirmCommit &&
                           (0 <? active_nonce (st_tmr st0)) &&
                           (0 <? oe1) && (oe1 =? active_nonce (st_tmr st0))) ||
                          wal_intent_eqb oi1 WI_RecoveryResolved) in *.
          destruct (negb auth_ok).
          + destruct (0 <? active_nonce (st_tmr st0)); inversion Es2; discriminate.
          + destruct (if rtc_ok && wal_intent_eqb oi1 WI_None then WI_ConfirmCommit else oi1) eqn:Eeff;
              inversion Es2; subst; try discriminate.
            destruct (rtc_ok && wal_intent_eqb oi1 WI_None); [discriminate | contradiction].
        - inversion Es2; subst; exact Hoi1_noup. }
      unfold step2_5_cloud_cmd in Heval0; rewrite Hcld2, Hcld0 in Heval0; simpl in Heval0; cbv zeta in Heval0.
      destruct (wal_intent_eqb oi2 WI_DeviceLocked); [discriminate|].
      destruct (step3_failure_and_rollback cfg s2 w2 t2 (st_reset st0) oi2 h2)
        as [e3 t3p | s3 w3 t3 oi3 h3 r3] eqn:Es3; [discriminate|].
      assert (Hs3_bk : backup_slot s3 = backup_slot s2 /\ oi3 <> WI_UpdatePending).
      { unfold step3_failure_and_rollback in Es3; cbv zeta in Es3.
        set (wc := wal_intent_eqb oi2 WI_ConfirmCommit || wal_intent_eqb oi2 WI_TxnCommit) in *.
        set (rc := rst_indicates_crash (st_reset st0)) in *.
        set (ic := negb h2 && (wc || (rc && negb (wal_intent_eqb oi2 WI_UpdatePending)))) in *.
        set (ta := if ic && crash_accum_applicable oi2 then apply_crash_accum cfg t2 else t2) in *.
        set (im := rc && negb h2) in *.
        destruct (wal_intent_eqb oi2 WI_TxnRollback); [inversion Es3; subst; split; [reflexivity | discriminate]|].
        destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi2 WI_TxnRollbackPending).
        - destruct (wal_intent_eqb oi2 WI_TxnCommit || wal_intent_eqb oi2 WI_TxnRollbackPending).
          + destruct (im || wal_intent_eqb oi2 WI_TxnRollbackPending || (cfg_max_retries cfg <? boot_failure_counter ta)).
            * destruct (negb (hdr_valid (backup_slot s2))); [discriminate|].
              inversion Es3; subst; simpl; split; [reflexivity | discriminate].
            * inversion Es3; subst; split; [reflexivity | exact Hoi2_noup].
          + destruct (boot_failure_counter ta <=? cfg_max_retries cfg); [|
              destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg);
                [inversion Es3; subst; split; [reflexivity | exact Hoi2_noup] | discriminate]].
            inversion Es3; subst; split; [reflexivity | exact Hoi2_noup].
        - inversion Es3; subst; split; [reflexivity | exact Hoi2_noup]. }
      destruct Hs3_bk as [Hbk3 Hoi3_noup].
      unfold step4_update_pipeline in Heval0.
      assert (Hup3_f : negb (wal_intent_eqb oi3 WI_UpdatePending) = true)
        by (destruct oi3; simpl; try reflexivity; contradiction).
      rewrite Hup3_f in Heval0; simpl in Heval0; cbv zeta in Heval0.
      set (fb := negb r3 && negb (hdr_valid (app_slot s3)) && recovery_rom_valid s3 &&
                 (recovery_failure_counter t3 <=? cfg_max_recovery_retries cfg)) in *.
      destruct (negb (if r3 || fb then recovery_rom_valid s3 else hdr_valid (app_slot s3))); [discriminate|].
      destruct (r3 || fb); [discriminate|].
      inversion Heval0; subst; simpl; split; congruence. }
    destruct Hbk_kept as [Hbk1 Hotp1].
    destruct tent0.
    + destruct (Htent_t eq_refl) as [Hwal_tc _].
      assert (Hbk_next :
        hdr_valid (backup_slot (st_slots st_next)) = true ->
        image_is_verified (backup_slot (st_slots st_next))
                          (otp_min_svn (st_otp st_next))
                          (otp_active_key_index (st_otp st_next))).
      { unfold st_next, next_unconfirmed_reboot_state; simpl.
        rewrite Hbk1, Hotp1; exact Hbk0. }
      pose proof (tentative_txn_commit_converges
                    (cfg_max_retries cfg - boot_failure_counter (st_tmr st_next))
                    cfg tent_rst (cfg_max_retries cfg) st_next
                    Hidle_next Hwal_tc ltac:(lia) Hbk_next ltac:(lia)) as Hconv.
      destruct (run_until_safe cfg tent_rst (cfg_max_retries cfg) st_next) as [[out_f st_f] reb]; simpl.
      destruct Hconv as [Hreb Hsafe]; split; [lia | exact Hsafe].
    + destruct (Htent_f eq_refl) as [Hrst_w [Han_0 Hwal_n]].
      pose proof (non_tentative_wdt_converges
                    (cfg_max_retries cfg - boot_failure_counter (st_tmr st_next))
                    cfg tent_rst (cfg_max_retries cfg) st_next
                    Hidle_next Hrst_w Han_0 Hwal_n ltac:(lia) ltac:(lia)) as Hconv.
      destruct (run_until_safe cfg tent_rst (cfg_max_retries cfg) st_next) as [[out_f st_f] reb]; simpl.
      destruct Hconv as [Hreb Hsafe]; split; [lia | exact Hsafe].
Qed.


Local Arguments Nat.leb : simpl never.
Local Arguments Nat.ltb : simpl never.

Ltac split_conj := repeat match goal with |- _ /\ _ => split end.

(* ========================================================================== *)
(* SECTION 6: Extension Theorem 1 — Swap-Move & Swap-Scratch Conservation     *)
(*            and Power-Cut Resume Idempotence for Arbitrary N >= 1           *)
(* ========================================================================== *)

Lemma sec_at_nth_error :
  forall img i v,
    nth_error img i = Some v ->
    sec_at img i = v.
Proof.
  intros img i v H; unfold sec_at; rewrite H; reflexivity.
Qed.

Lemma nth_error_sec_at :
  forall img i,
    i < length img ->
    nth_error img i = Some (sec_at img i).
Proof.
  intros img i Hi; unfold sec_at.
  destruct (nth_error img i) as [v|] eqn:E; [reflexivity|].
  apply nth_error_None in E; lia.
Qed.

Lemma sec_at_replace_nth_eq :
  forall img i v,
    i < length img ->
    sec_at (replace_nth i v img) i = v.
Proof.
  intros img i v Hi; unfold sec_at.
  rewrite nth_error_replace_nth_eq by exact Hi; reflexivity.
Qed.

Lemma sec_at_replace_nth_neq :
  forall img i j v,
    i <> j ->
    sec_at (replace_nth i v img) j = sec_at img j.
Proof.
  intros img i j v Hneq; unfold sec_at.
  rewrite nth_error_replace_nth_neq by exact Hneq; reflexivity.
Qed.

Lemma sec_at_ext_eq :
  forall img1 img2,
    length img1 = length img2 ->
    (forall j, j < length img1 -> sec_at img1 j = sec_at img2 j) ->
    img1 = img2.
Proof.
  intros img1 img2 Hlen Hsec.
  apply nth_error_ext_eq; [exact Hlen|].
  intros j Hj; rewrite !nth_error_sec_at by lia.
  f_equal; apply Hsec; exact Hj.
Qed.

Lemma firstn_sec_at_eq :
  forall n pri img,
    n <= length pri ->
    length img = n ->
    (forall j, j < n -> sec_at pri j = sec_at img j) ->
    firstn n pri = img.
Proof.
  induction n as [|n' IH]; intros pri img Hlp Hli Hsec.
  - destruct img; simpl in *; [reflexivity | lia].
  - destruct pri as [|x xs]; simpl in *; [lia|].
    destruct img as [|y ys]; simpl in *; [lia|].
    assert (Hxy : x = y) by (exact (Hsec 0 ltac:(lia))).
    subst y; f_equal.
    apply IH; [lia | lia |].
    intros j Hj; exact (Hsec (S j) ltac:(lia)).
Qed.

Definition CleanImage (N : nat) (img : SectorImage) : Prop :=
  length img = N /\ forall j, j < N -> sec_at img j <> None.

Lemma lift_clean_sectors_clean :
  forall words N,
    length words = N ->
    CleanImage N (lift_clean_sectors words).
Proof.
  intros words N Hlen; subst N; unfold CleanImage, lift_clean_sectors.
  split.
  - induction words as [|w ws IH]; simpl; auto.
  - intros j Hj; unfold sec_at.
    destruct (nth_error words j) as [w|] eqn:Ew; [|apply nth_error_None in Ew; lia].
    rewrite nth_error_map, Ew; simpl; discriminate.
Qed.

Lemma opt_nat_eqb_neq :
  forall a b, opt_nat_eqb a b = false <-> a <> b.
Proof.
  intros a b; split; intro H.
  - intro Heq; subst; destruct b as [x|]; simpl in H;
      [rewrite Nat.eqb_refl in H | ]; discriminate.
  - destruct (opt_nat_eqb a b) eqn:E; [apply opt_nat_eqb_eq in E; contradiction | reflexivity].
Qed.

(* -------------------------------------------------------------------------- *)
(* 6A. Swap-Scratch Sector-Conservation & Power-Cut Resume                    *)
(* -------------------------------------------------------------------------- *)

Definition SwapScratchConserved
    (A B : SectorImage) (N : nat) (st : SwapScratchState) : Prop :=
  forall j, j < N ->
    (sec_at (ss_dest st) j = sec_at A j \/
     sec_at (ss_src st) j = sec_at A j \/
     ss_scratch st = sec_at A j) /\
    (sec_at (ss_src st) j = sec_at B j \/
     sec_at (ss_dest st) j = sec_at B j).

Definition SwapScratchValid
    (A B : SectorImage) (N : nat) (st : SwapScratchState) : Prop :=
  length (ss_dest st) = N /\
  length (ss_src st) = N /\
  if ss_done st then
    ss_dest st = B /\ ss_src st = A
  else if ss_resuming st then
    ss_idx st < N /\
    ss_cs st = sec_at B (ss_idx st) /\
    ss_cd st = sec_at A (ss_idx st) /\
    sec_at A (ss_idx st) <> sec_at B (ss_idx st) /\
    (forall j, j < ss_idx st ->
       sec_at (ss_dest st) j = sec_at B j /\ sec_at (ss_src st) j = sec_at A j) /\
    (forall j, ss_idx st < j -> j < N ->
       sec_at (ss_dest st) j = sec_at A j /\ sec_at (ss_src st) j = sec_at B j) /\
    let i := ss_idx st in
    ((sec_at (ss_dest st) i = sec_at B i /\ sec_at (ss_src st) i = sec_at A i) \/
     (sec_at (ss_dest st) i = sec_at B i /\ sec_at (ss_src st) i <> sec_at A i /\ ss_scratch st = sec_at A i) \/
     (sec_at (ss_dest st) i <> sec_at B i /\ sec_at (ss_src st) i = sec_at B i /\ ss_scratch st = sec_at A i) \/
     (sec_at (ss_dest st) i = sec_at A i /\ sec_at (ss_src st) i = sec_at B i /\ ss_scratch st <> sec_at A i))
  else
    ss_idx st <= N /\
    (forall j, j < ss_idx st ->
       sec_at (ss_dest st) j = sec_at B j /\ sec_at (ss_src st) j = sec_at A j) /\
    (forall j, ss_idx st <= j -> j < N ->
       sec_at (ss_dest st) j = sec_at A j /\ sec_at (ss_src st) j = sec_at B j).

Lemma swapscratch_valid_implies_conserved :
  forall A B N st,
    SwapScratchValid A B N st ->
    SwapScratchConserved A B N st.
Proof.
  intros A B N st [Hld [Hls Hbody]] j Hj.
  destruct (ss_done st).
  - destruct Hbody as [Hd Hs]; subst; split; [ right; left; reflexivity | right; reflexivity ].
  - destruct (ss_resuming st).
    + destruct Hbody as [Hi [Hcs [Hcd [Hneq [Hpre [Hpost Hmid]]]]]].
      destruct (Nat.lt_trichotomy j (ss_idx st)) as [Hlt | [Heq | Hgt]].
      * destruct (Hpre j Hlt) as [Hd Hs]; split; [right; left; exact Hs | right; exact Hd].
      * subst j; cbv zeta in Hmid.
        destruct Hmid as [[Hd Hs] | [[Hd [_ Hsc]] | [[_ [Hs Hsc]] | [Hd [Hs _]]]]].
        -- split; [right; left; exact Hs | right; exact Hd].
        -- split; [right; right; exact Hsc | right; exact Hd].
        -- split; [right; right; exact Hsc | left; exact Hs].
        -- split; [left; exact Hd | left; exact Hs].
      * destruct (Hpost j Hgt Hj) as [Hd Hs]; split; [left; exact Hd | left; exact Hs].
    + destruct Hbody as [Hi [Hpre Hpost]].
      destruct (Nat.lt_ge_cases j (ss_idx st)) as [Hlt | Hge].
      * destruct (Hpre j Hlt) as [Hd Hs]; split; [right; left; exact Hs | right; exact Hd].
      * destruct (Hpost j Hge Hj) as [Hd Hs]; split; [left; exact Hd | left; exact Hs].
Qed.

Lemma ss_loop_invariant_and_complete :
  forall rem N A B dest src scr resuming cs cd cut,
    CleanImage N A ->
    CleanImage N B ->
    rem <= N ->
    SwapScratchValid A B N (mkSwapScratch dest src scr false (N - rem) resuming cs cd) ->
    let out := ss_loop rem N dest src scr resuming cs cd cut in
    SwapScratchValid A B N out /\
    (cut = None -> ss_done out = true /\ ss_dest out = B /\ ss_src out = A).
Proof.
  induction rem as [|rem' IH];
    intros N A B dest src scr resuming cs cd cut [HlA HnA] [HlB HnB] Hrem Hval;
    cbv zeta.
  - simpl.
    destruct Hval as [Hld [Hls Hbody]]; simpl in *.
    destruct resuming; [lia|].
    replace (N - 0) with N in Hbody by lia.
    destruct Hbody as [_ [Hpre _]].
    assert (HdestB : dest = B)
      by (apply sec_at_ext_eq; [lia | intros j Hj; apply (Hpre j); lia]).
    assert (HsrcA : src = A)
      by (apply sec_at_ext_eq; [lia | intros j Hj; apply (Hpre j); lia]).
    subst dest src.
    split; [unfold SwapScratchValid; simpl; repeat split; auto | intros _; repeat split; reflexivity].
  - simpl.
    set (i := N - S rem') in *.
    assert (Hi_lt : i < N) by lia.
    assert (HAi_some : sec_at A i <> None) by (apply HnA; exact Hi_lt).
    assert (HBi_some : sec_at B i <> None) by (apply HnB; exact Hi_lt).
    assert (Hnext_idx : S i = N - rem') by lia.
    destruct Hval as [Hld [Hls Hbody]]; simpl in Hld, Hls, Hbody.
    destruct (negb resuming && opt_nat_eqb (sec_at dest i) (sec_at src i)) eqn:Eskip.
    + apply Bool.andb_true_iff in Eskip as [Hnr Heqb].
      apply Bool.negb_true_iff in Hnr; subst resuming.
      apply opt_nat_eqb_eq in Heqb.
      destruct Hbody as [_ [Hpre Hpost]].
      destruct (Hpost i ltac:(lia) Hi_lt) as [Hdi Hsi].
      assert (HAB_eq : sec_at A i = sec_at B i) by congruence.
      apply IH; [split; assumption | split; assumption | lia |].
      unfold SwapScratchValid; simpl; split_conj; try assumption; try lia.
      * intros j Hj.
        destruct (Nat.eq_dec j i) as [Heq | Hneq].
        -- subst j; split; congruence.
        -- apply Hpre; lia.
      * intros j Hge Hj; apply Hpost; lia.
    + set (cs0 := if resuming then cs else sec_at src i).
      set (cd0 := if resuming then cd else sec_at dest i).
      assert (Hchk :
        cs0 = sec_at B i /\
        cd0 = sec_at A i /\
        sec_at A i <> sec_at B i /\
        (forall j, j < i -> sec_at dest j = sec_at B j /\ sec_at src j = sec_at A j) /\
        (forall j, i < j -> j < N -> sec_at dest j = sec_at A j /\ sec_at src j = sec_at B j) /\
        ((sec_at dest i = sec_at B i /\ sec_at src i = sec_at A i) \/
         (sec_at dest i = sec_at B i /\ sec_at src i <> sec_at A i /\ scr = sec_at A i) \/
         (sec_at dest i <> sec_at B i /\ sec_at src i = sec_at B i /\ scr = sec_at A i) \/
         (sec_at dest i = sec_at A i /\ sec_at src i = sec_at B i /\ scr <> sec_at A i))).
      { destruct resuming.
        - unfold cs0, cd0; destruct Hbody as [_ [Hcs [Hcd [Hneq [Hpre [Hpost Hmid]]]]]].
          split_conj; assumption.
        - simpl in Eskip; apply opt_nat_eqb_neq in Eskip.
          destruct Hbody as [_ [Hpre Hpost]].
          destruct (Hpost i ltac:(lia) Hi_lt) as [Hdi Hsi].
          unfold cs0, cd0.
          assert (Hneq : sec_at A i <> sec_at B i) by congruence.
          split_conj; try congruence.
          + intros j Hj; apply Hpre; lia.
          + intros j Hgt Hj; apply Hpost; lia.
          + destruct (opt_nat_eqb scr (sec_at A i)) eqn:Escr.
            * apply opt_nat_eqb_eq in Escr.
              right; right; left; split_conj; congruence.
            * apply opt_nat_eqb_neq in Escr.
              right; right; right; split_conj; congruence. }
      destruct Hchk as [Hcs0 [Hcd0 [Hneq [Hpre [Hpost Hmid]]]]].
      destruct (negb resuming && match cut with Some 0 => true | _ => false end) eqn:Ecut0.
      * split.
        -- unfold SwapScratchValid; simpl; split_conj; assumption.
        -- intro Hnone; subst cut; rewrite Bool.andb_false_r in Ecut0; discriminate.
      * set (cut1 := if resuming then cut else opt_sub cut 1).
        assert (Hcut1_none : cut = None -> cut1 = None)
          by (intro Hn; subst cut; unfold cut1; destruct resuming; reflexivity).
        assert (Hadvance :
          forall dest' src' scr' cut_n,
            length dest' = N ->
            length src' = N ->
            sec_at dest' i = sec_at B i ->
            sec_at src' i = sec_at A i ->
            (forall j, j <> i -> sec_at dest' j = sec_at dest j /\ sec_at src' j = sec_at src j) ->
            (cut = None -> cut_n = None) ->
            let out_n := ss_loop rem' N dest' src' scr' false None None cut_n in
            SwapScratchValid A B N out_n /\
            (cut = None -> ss_done out_n = true /\ ss_dest out_n = B /\ ss_src out_n = A)).
        { intros dest' src' scr' cut_n Hld' Hls' Hdi' Hsi' H frame_c.
          pose proof (IH N A B dest' src' scr' false None None cut_n
                         (conj HlA HnA) (conj HlB HnB) ltac:(lia)) as Hih.
          destruct Hih as [Hv_out Hc_out].
          - unfold SwapScratchValid; simpl; split_conj; try assumption; try lia.
            + intros j Hj.
              destruct (Nat.eq_dec j i) as [Heq | Hne].
              * subst j; split; assumption.
              * destruct (H j Hne) as [Ed Es]; rewrite Ed, Es; apply Hpre; lia.
            + intros j Hge Hj.
              assert (Hne : j <> i) by lia.
              destruct (H j Hne) as [Ed Es]; rewrite Ed, Es; apply Hpost; lia.
          - split; [exact Hv_out | intro Hn; apply Hc_out, frame_c, Hn]. }
        assert (Hpause :
          forall dest' src' scr' c_sub,
            cut1 = Some c_sub ->
            length dest' = N ->
            length src' = N ->
            (forall j, j <> i -> sec_at dest' j = sec_at dest j /\ sec_at src' j = sec_at src j) ->
            ((sec_at dest' i = sec_at B i /\ sec_at src' i = sec_at A i) \/
             (sec_at dest' i = sec_at B i /\ sec_at src' i <> sec_at A i /\ scr' = sec_at A i) \/
             (sec_at dest' i <> sec_at B i /\ sec_at src' i = sec_at B i /\ scr' = sec_at A i) \/
             (sec_at dest' i = sec_at A i /\ sec_at src' i = sec_at B i /\ scr' <> sec_at A i)) ->
            let out_p := mkSwapScratch dest' src' scr' false i true cs0 cd0 in
            SwapScratchValid A B N out_p /\
            (cut = None -> ss_done out_p = true /\ ss_dest out_p = B /\ ss_src out_p = A)).
        { intros dest' src' scr' c_sub Hc1 Hld' Hls' Hfr Hdisj.
          split.
          - unfold SwapScratchValid; simpl; split_conj; try assumption.
            + intros j Hj; destruct (Hfr j ltac:(lia)) as [Ed Es]; rewrite Ed, Es; apply Hpre; exact Hj.
            + intros j Hgt Hj; destruct (Hfr j ltac:(lia)) as [Ed Es]; rewrite Ed, Es; apply Hpost; assumption.
          - intro Hn; specialize (Hcut1_none Hn); congruence. }
        destruct Hmid as [[Hdi Hsi] | [[Hdi [Hsi Hsc]] | [[Hdi [Hsi Hsc]] | [Hdi [Hsi Hsc]]]]].
        -- assert (Edhs : opt_nat_eqb (sec_at dest i) cs0 = true)
             by (apply opt_nat_eqb_eq; congruence).
           assert (Eshd : opt_nat_eqb (sec_at src i) cd0 = true)
             by (apply opt_nat_eqb_eq; congruence).
           rewrite Edhs, Eshd; simpl.
           apply Hadvance; auto.
        -- assert (Edhs : opt_nat_eqb (sec_at dest i) cs0 = true)
             by (apply opt_nat_eqb_eq; congruence).
           assert (Eshd : opt_nat_eqb (sec_at src i) cd0 = false)
             by (apply opt_nat_eqb_neq; congruence).
           rewrite Edhs, Eshd; simpl.
           destruct cut1 as [[|[|k']]|] eqn:Ec1.
           ++ eapply Hpause; [reflexivity | exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; [reflexivity | apply sec_at_replace_nth_neq; lia].
              ** right; left; rewrite sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; [reflexivity | apply sec_at_replace_nth_neq; lia].
              ** left; rewrite sec_at_replace_nth_eq by lia; split; congruence.
           ++ apply Hadvance; [exact Hld | rewrite replace_nth_length; exact Hls | exact Hdi |
                rewrite sec_at_replace_nth_eq by lia; exact Hsc |
                intros j Hne; split; [reflexivity | apply sec_at_replace_nth_neq; lia] |
                intro Hn; specialize (Hcut1_none Hn); discriminate].
           ++ apply Hadvance; [exact Hld | rewrite replace_nth_length; exact Hls | exact Hdi |
                rewrite sec_at_replace_nth_eq by lia; exact Hsc |
                intros j Hne; split; [reflexivity | apply sec_at_replace_nth_neq; lia] |
                reflexivity].
        -- assert (Edhs : opt_nat_eqb (sec_at dest i) cs0 = false)
             by (apply opt_nat_eqb_neq; congruence).
           assert (Escd : opt_nat_eqb scr cd0 = true)
             by (apply opt_nat_eqb_eq; congruence).
           rewrite Edhs, Escd; simpl.
           destruct cut1 as [[|[|[|[|k']]]]|] eqn:Ec1.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | exact Hls | |].
              ** intros j Hne; split; [apply sec_at_replace_nth_neq; lia | reflexivity].
              ** right; right; left; rewrite sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | exact Hls | |].
              ** intros j Hne; split; [apply sec_at_replace_nth_neq; lia | reflexivity].
              ** right; left; rewrite sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; apply sec_at_replace_nth_neq; lia.
              ** right; left; rewrite !sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; apply sec_at_replace_nth_neq; lia.
              ** left; rewrite !sec_at_replace_nth_eq by lia; split; congruence.
           ++ apply Hadvance; [rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls |
                rewrite sec_at_replace_nth_eq by lia; exact Hsi |
                rewrite sec_at_replace_nth_eq by lia; exact Hsc |
                intros j Hne; split; apply sec_at_replace_nth_neq; lia |
                intro Hn; specialize (Hcut1_none Hn); discriminate].
           ++ apply Hadvance; [rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls |
                rewrite sec_at_replace_nth_eq by lia; exact Hsi |
                rewrite sec_at_replace_nth_eq by lia; exact Hsc |
                intros j Hne; split; apply sec_at_replace_nth_neq; lia |
                reflexivity].
        -- assert (Edhs : opt_nat_eqb (sec_at dest i) cs0 = false)
             by (apply opt_nat_eqb_neq; congruence).
           assert (Escd : opt_nat_eqb scr cd0 = false)
             by (apply opt_nat_eqb_neq; congruence).
           rewrite Edhs, Escd; simpl.
           destruct cut1 as [[|[|[|[|[|[|k']]]]]]|] eqn:Ec1.
           ++ eapply Hpause; [reflexivity | exact Hld | exact Hls | auto |].
              right; right; right; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | exact Hld | exact Hls | auto |].
              right; right; left; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | exact Hls | |].
              ** intros j Hne; split; [apply sec_at_replace_nth_neq; lia | reflexivity].
              ** right; right; left; rewrite sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | exact Hls | |].
              ** intros j Hne; split; [apply sec_at_replace_nth_neq; lia | reflexivity].
              ** right; left; rewrite sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; apply sec_at_replace_nth_neq; lia.
              ** right; left; rewrite !sec_at_replace_nth_eq by lia; repeat split; congruence.
           ++ eapply Hpause; [reflexivity | rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls | |].
              ** intros j Hne; split; apply sec_at_replace_nth_neq; lia.
              ** left; rewrite !sec_at_replace_nth_eq by lia; split; congruence.
           ++ apply Hadvance; [rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls |
                rewrite sec_at_replace_nth_eq by lia; exact Hsi |
                rewrite sec_at_replace_nth_eq by lia; exact Hdi |
                intros j Hne; split; apply sec_at_replace_nth_neq; lia |
                intro Hn; specialize (Hcut1_none Hn); discriminate].
           ++ apply Hadvance; [rewrite replace_nth_length; exact Hld | rewrite replace_nth_length; exact Hls |
                rewrite sec_at_replace_nth_eq by lia; exact Hsi |
                rewrite sec_at_replace_nth_eq by lia; exact Hdi |
                intros j Hne; split; apply sec_at_replace_nth_neq; lia |
                reflexivity].
Qed.

Lemma swapscratch_init_valid :
  forall A B init_scr N,
    CleanImage N A ->
    CleanImage N B ->
    SwapScratchValid A B N (swapscratch_init A B init_scr).
Proof.
  intros A B init_scr N [HlA _] [HlB _].
  unfold SwapScratchValid, swapscratch_init; simpl.
  repeat split; try assumption; try lia; reflexivity.
Qed.

Lemma swapscratch_exec_valid_and_complete :
  forall A B N st cut,
    CleanImage N A ->
    CleanImage N B ->
    SwapScratchValid A B N st ->
    let out := swapscratch_exec st N cut in
    SwapScratchValid A B N out /\
    (cut = None -> ss_done out = true /\ ss_dest out = B /\ ss_src out = A).
Proof.
  intros A B N st cut HcA HcB Hval; cbv zeta; unfold swapscratch_exec.
  destruct st as [dest src scr done idx res cs cd]; simpl in *.
  destruct done.
  - pose proof Hval as [Hld [Hls [Hd Hs]]].
    split; [exact Hval | intros _; auto].
  - assert (Hidx_le : idx <= N).
    { destruct Hval as [_ [_ Hbody]]; simpl in Hbody.
      destruct res; destruct Hbody; lia. }
    pose proof (ss_loop_invariant_and_complete
                  (N - idx) N A B dest src scr res cs cd cut HcA HcB ltac:(lia)) as Hloop.
    apply Hloop.
    replace (N - (N - idx)) with idx by lia.
    exact Hval.
Qed.

Theorem swapscratch_sector_conservation_and_resume :
  forall (a_words b_words : list nat) (init_scr : option nat) (N k1 k2 k_rb : nat),
    1 <= N ->
    length a_words = N ->
    length b_words = N ->
    let A := lift_clean_sectors a_words in
    let B := lift_clean_sectors b_words in
    let st0 := swapscratch_init A B init_scr in
    let st_cut1 := swapscratch_power_cut st0 N k1 in
    let st_cut2 := swapscratch_power_cut st_cut1 N k2 in
    let st_fin1 := swapscratch_resume st_cut1 N in
    let st_fin2 := swapscratch_resume st_cut2 N in
    SwapScratchConserved A B N st_cut1 /\
    SwapScratchConserved A B N st_cut2 /\
    ss_done st_fin1 = true /\ ss_dest st_fin1 = B /\ ss_src st_fin1 = A /\
    ss_done st_fin2 = true /\ ss_dest st_fin2 = B /\ ss_src st_fin2 = A /\
    let st_rb0 := swapscratch_init (ss_dest st_fin2) (ss_src st_fin2) (ss_scratch st_fin2) in
    let st_rb_cut := swapscratch_power_cut st_rb0 N k_rb in
    let st_rb_fin := swapscratch_resume st_rb_cut N in
    SwapScratchConserved B A N st_rb_cut /\
    ss_dest st_rb_fin = A /\ ss_src st_rb_fin = B.
Proof.
  intros a_words b_words init_scr N k1 k2 k_rb HN Hla Hlb; cbv zeta.
  set (A := lift_clean_sectors a_words).
  set (B := lift_clean_sectors b_words).
  assert (HcA : CleanImage N A) by (apply lift_clean_sectors_clean; exact Hla).
  assert (HcB : CleanImage N B) by (apply lift_clean_sectors_clean; exact Hlb).
  assert (Hv0 : SwapScratchValid A B N (swapscratch_init A B init_scr))
    by (apply swapscratch_init_valid; assumption).
  unfold swapscratch_power_cut, swapscratch_resume.
  destruct (swapscratch_exec_valid_and_complete A B N _ (Some k1) HcA HcB Hv0) as [Hv1 _].
  destruct (swapscratch_exec_valid_and_complete A B N _ (Some k2) HcA HcB Hv1) as [Hv2 _].
  destruct (swapscratch_exec_valid_and_complete A B N _ None HcA HcB Hv1) as [_ Hfin1].
  destruct (Hfin1 eq_refl) as [Hd1 [Hdest1 Hsrc1]].
  destruct (swapscratch_exec_valid_and_complete A B N _ None HcA HcB Hv2) as [_ Hfin2].
  destruct (Hfin2 eq_refl) as [Hd2 [Hdest2 Hsrc2]].
  set (st_fin2 := swapscratch_exec (swapscratch_exec (swapscratch_init A B init_scr) N (Some k1)) N (Some k2)) in *.
  set (st_done2 := swapscratch_exec st_fin2 N None) in *.
  rewrite Hdest2, Hsrc2.
  assert (Hv_rb0 : SwapScratchValid B A N (swapscratch_init B A (ss_scratch st_done2)))
    by (apply swapscratch_init_valid; assumption).
  destruct (swapscratch_exec_valid_and_complete B A N _ (Some k_rb) HcB HcA Hv_rb0) as [Hv_rb1 _].
  destruct (swapscratch_exec_valid_and_complete B A N _ None HcB HcA Hv_rb1) as [_ Hrb_fin].
  destruct (Hrb_fin eq_refl) as [_ [Hrb_d Hrb_s]].
  split_conj; try reflexivity; try assumption.
  - apply swapscratch_valid_implies_conserved; exact Hv1.
  - apply swapscratch_valid_implies_conserved; exact Hv2.
  - apply swapscratch_valid_implies_conserved; exact Hv_rb1.
Qed.

(* -------------------------------------------------------------------------- *)
(* 6B. Swap-Move (N+1 Shift) Sector-Conservation & Power-Cut Resume           *)
(* -------------------------------------------------------------------------- *)

Definition SwapMoveConserved
    (A B : SectorImage) (N : nat) (st : SwapMoveState) : Prop :=
  forall j, j < N ->
    (exists idx_a, idx_a < S N /\
       (sec_at (sm_P st) idx_a = sec_at A j \/
        (idx_a < N /\ sec_at (sm_S st) idx_a = sec_at A j))) /\
    (sec_at (sm_S st) j = sec_at B j \/ sec_at (sm_P st) j = sec_at B j).

Definition SwapMoveValid
    (A B : SectorImage) (N : nat) (st : SwapMoveState) : Prop :=
  length (sm_P st) = S N /\
  length (sm_S st) = N /\
  match sm_phase st with
  | SMP_Move =>
      sm_idx st < N /\
      sm_S st = B /\
      (forall j, j <= sm_idx st -> sec_at (sm_P st) j = sec_at A j) /\
      (forall j, sm_idx st < j -> j < N -> sec_at (sm_P st) (S j) = sec_at A j)
  | SMP_Swap =>
      if sm_resuming st then
        sm_idx st < N /\
        sm_cs st = sec_at B (sm_idx st) /\
        sm_cp st = sec_at A (sm_idx st) /\
        (forall j, j < sm_idx st ->
           sec_at (sm_P st) j = sec_at B j /\ sec_at (sm_S st) j = sec_at A j) /\
        (forall j, sm_idx st <= j -> j < N ->
           sec_at (sm_P st) (S j) = sec_at A j) /\
        (forall j, sm_idx st < j -> j < N ->
           sec_at (sm_S st) j = sec_at B j) /\
        let i := sm_idx st in
        (sec_at (sm_P st) i = sec_at B i \/
         (sec_at (sm_P st) i <> sec_at B i /\ sec_at (sm_S st) i = sec_at B i))
      else
        sm_idx st <= N /\
        (forall j, j < sm_idx st ->
           sec_at (sm_P st) j = sec_at B j /\ sec_at (sm_S st) j = sec_at A j) /\
        (forall j, sm_idx st <= j -> j < N ->
           sec_at (sm_P st) (S j) = sec_at A j /\ sec_at (sm_S st) j = sec_at B j)
  | SMP_Done =>
      firstn N (sm_P st) = B /\ sm_S st = A
  end.

Lemma firstn_nth_sec_at :
  forall n pri img j,
    n <= length pri ->
    firstn n pri = img ->
    j < n ->
    sec_at pri j = sec_at img j.
Proof.
  induction n as [|n' IH]; intros pri img j Hlen Hfn Hj; [lia|].
  destruct pri as [|x xs]; simpl in *; [lia|].
  subst img; destruct j as [|j']; [reflexivity|].
  change (sec_at xs j' = sec_at (firstn n' xs) j').
  apply IH with (img := firstn n' xs); [lia | reflexivity | lia].
Qed.

Lemma swapmove_valid_implies_conserved :
  forall A B N st,
    SwapMoveValid A B N st ->
    SwapMoveConserved A B N st.
Proof.
  intros A B N st [Hlp [Hls Hbody]] j Hj.
  destruct (sm_phase st).
  - destruct Hbody as [Hi [Hs [Hle Hgt]]].
    split.
    + destruct (Nat.le_gt_cases j (sm_idx st)) as [Hj_le | Hj_gt].
      * exists j; split; [lia | left; apply Hle; exact Hj_le].
      * exists (S j); split; [lia | left; apply Hgt; assumption].
    + left; rewrite Hs; reflexivity.
  - destruct (sm_resuming st).
    + destruct Hbody as [Hi [Hcs [Hcp [Hpre [Hps [Hs_post Hmid]]]]]].
      destruct (Nat.lt_trichotomy j (sm_idx st)) as [Hlt | [Heq | Hgt]].
      * destruct (Hpre j Hlt) as [Hp Hs].
        split; [exists j; split; [lia | right; split; [exact Hj | exact Hs]] | right; exact Hp].
      * subst j; cbv zeta in Hmid.
        split.
        -- exists (S (sm_idx st)); split; [lia | left; apply Hps; lia].
        -- destruct Hmid as [Hp | [_ Hs]]; [right; exact Hp | left; exact Hs].
      * split.
        -- exists (S j); split; [lia | left; apply Hps; lia].
        -- left; apply Hs_post; assumption.
    + destruct Hbody as [Hi [Hpre Hpost]].
      destruct (Nat.lt_ge_cases j (sm_idx st)) as [Hlt | Hge].
      * destruct (Hpre j Hlt) as [Hp Hs].
        split; [exists j; split; [lia | right; split; [exact Hj | exact Hs]] | right; exact Hp].
      * destruct (Hpost j Hge Hj) as [Hp Hs].
        split; [exists (S j); split; [lia | left; exact Hp] | left; exact Hs].
  - destruct Hbody as [Hfn Hs].
    split.
    + exists j; split; [lia | right; split; [exact Hj | rewrite Hs; reflexivity]].
    + right; apply (firstn_nth_sec_at N); [lia | exact Hfn | exact Hj].
Qed.

Lemma sm_swap_loop_invariant_and_complete :
  forall rem N A B pri sec resuming cs cp cut,
    CleanImage N A ->
    CleanImage N B ->
    rem <= N ->
    SwapMoveValid A B N (mkSwapMove pri sec SMP_Swap (N - rem) resuming cs cp) ->
    let out := sm_swap_loop rem N pri sec resuming cs cp cut in
    SwapMoveValid A B N out /\
    (cut = None ->
     sm_phase out = SMP_Done /\ firstn N (sm_P out) = B /\ sm_S out = A).
Proof.
  induction rem as [|rem' IH];
    intros N A B pri sec resuming cs cp cut [HlA HnA] [HlB HnB] Hrem Hval;
    cbv zeta.
  - simpl.
    destruct Hval as [Hlp [Hls Hbody]]; simpl in *.
    destruct resuming; [lia|].
    replace (N - 0) with N in Hbody by lia.
    destruct Hbody as [_ [Hpre _]].
    assert (Hfn : firstn N pri = B).
    { apply firstn_sec_at_eq; [lia | exact HlB | intros j Hj; apply (Hpre j); lia]. }
    assert (Hsec : sec = A).
    { apply sec_at_ext_eq; [lia | intros j Hj; apply (Hpre j); lia]. }
    subst sec.
    split; [unfold SwapMoveValid; simpl; repeat split; auto | intros _; repeat split; auto].
  - simpl.
    set (i := N - S rem') in *.
    assert (Hi_lt : i < N) by lia.
    assert (HBi_some : sec_at B i <> None) by (apply HnB; exact Hi_lt).
    destruct Hval as [Hlp [Hls Hbody]]; simpl in Hlp, Hls, Hbody.
    set (cs0 := if resuming then cs else sec_at sec i).
    set (cp0 := if resuming then cp else sec_at pri (S i)).
    assert (Hchk :
      cs0 = sec_at B i /\
      cp0 = sec_at A i /\
      (forall j, j < i -> sec_at pri j = sec_at B j /\ sec_at sec j = sec_at A j) /\
      (forall j, i <= j -> j < N -> sec_at pri (S j) = sec_at A j) /\
      (forall j, i < j -> j < N -> sec_at sec j = sec_at B j) /\
      (sec_at pri i = sec_at B i \/
       (sec_at pri i <> sec_at B i /\ sec_at sec i = sec_at B i))).
    { destruct resuming.
      - unfold cs0, cp0; destruct Hbody as [_ Hrest]; exact Hrest.
      - destruct Hbody as [_ [Hpre Hpost]].
        destruct (Hpost i ltac:(lia) Hi_lt) as [Hpi_s Hsi].
        unfold cs0, cp0; split_conj; try congruence.
        + intros j Hj; apply Hpre; lia.
        + intros j Hge Hj; apply Hpost; lia.
        + intros j Hgt Hj; apply Hpost; lia.
        + destruct (opt_nat_eqb (sec_at pri i) (sec_at B i)) eqn:Ep.
          * apply opt_nat_eqb_eq in Ep; left; exact Ep.
          * apply opt_nat_eqb_neq in Ep; right; split; [exact Ep | exact Hsi]. }
    destruct Hchk as [Hcs0 [Hcp0 [Hpre [Hps [Hs_post Hmid]]]]].
    destruct (negb resuming && match cut with Some 0 => true | _ => false end) eqn:Ecut0.
    + split.
      * unfold SwapMoveValid; simpl; split_conj; assumption.
      * intro Hn; subst cut; rewrite Bool.andb_false_r in Ecut0; discriminate.
    + set (cut1 := if resuming then cut else opt_sub cut 1).
      assert (Hcut1_none : cut = None -> cut1 = None)
        by (intro Hn; subst cut; unfold cut1; destruct resuming; reflexivity).
      assert (Hpi_s_eq : sec_at pri (S i) = sec_at A i) by (apply Hps; lia).
      assert (Hadv :
        forall pri' sec' cut_n,
          length pri' = S N ->
          length sec' = N ->
          sec_at pri' i = sec_at B i ->
          sec_at sec' i = sec_at A i ->
          (forall j, j <> i -> sec_at pri' j = sec_at pri j) ->
          (forall j, j <> i -> sec_at sec' j = sec_at sec j) ->
          (cut = None -> cut_n = None) ->
          let out_n := sm_swap_loop rem' N pri' sec' false None None cut_n in
          SwapMoveValid A B N out_n /\
          (cut = None -> sm_phase out_n = SMP_Done /\ firstn N (sm_P out_n) = B /\ sm_S out_n = A)).
      { intros pri' sec' cut_n Hlp' Hls' Hpi' Hsi' Hfp Hfs Hfc.
        pose proof (IH N A B pri' sec' false None None cut_n
                       (conj HlA HnA) (conj HlB HnB) ltac:(lia)) as Hih.
        destruct Hih as [Hv Hc].
        - unfold SwapMoveValid; simpl; split_conj; try assumption; try lia.
          + intros j Hj.
            destruct (Nat.eq_dec j i) as [Heq | Hne].
            * subst j; split; assumption.
            * rewrite Hfp, Hfs by exact Hne; apply Hpre; lia.
          + intros j Hge Hj.
            rewrite Hfp by lia; rewrite Hfs by lia.
            split; [apply Hps; lia | apply Hs_post; lia].
        - split; [exact Hv | intro Hn; apply Hc, Hfc, Hn]. }
      assert (Hpause :
        forall pri' sec',
          (cut = None -> False) ->
          length pri' = S N ->
          length sec' = N ->
          (forall j, j <> i -> sec_at pri' j = sec_at pri j) ->
          (forall j, j <> i -> sec_at sec' j = sec_at sec j) ->
          (sec_at pri' i = sec_at B i \/
           (sec_at pri' i <> sec_at B i /\ sec_at sec' i = sec_at B i)) ->
          let out_p := mkSwapMove pri' sec' SMP_Swap i true cs0 cp0 in
          SwapMoveValid A B N out_p /\
          (cut = None -> sm_phase out_p = SMP_Done /\ firstn N (sm_P out_p) = B /\ sm_S out_p = A)).
      { intros pri' sec' Hnotn Hlp' Hls' Hfp Hfs Hdisj.
        split.
        - unfold SwapMoveValid; simpl; split_conj; try assumption.
          + intros j Hj; rewrite Hfp, Hfs by lia; apply Hpre; exact Hj.
          + intros j Hge Hj; rewrite Hfp by lia; apply Hps; assumption.
          + intros j Hgt Hj; rewrite Hfs by lia; apply Hs_post; assumption.
        - intro Hn; exfalso; apply (Hnotn Hn). }
      destruct (opt_nat_eqb (sec_at pri i) cs0) eqn:Ephs.
      * apply opt_nat_eqb_eq in Ephs.
        assert (Hpi_b : sec_at pri i = sec_at B i) by congruence.
        destruct (opt_nat_eqb (sec_at sec i) cp0) eqn:Eshp.
        -- apply opt_nat_eqb_eq in Eshp.
           apply Hadv; try assumption; try congruence; auto.
        -- destruct cut1 as [[|[|k']]|] eqn:Ec1.
           ++ apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
                exact Hlp | rewrite replace_nth_length; exact Hls | auto |
                intros j Hne; apply sec_at_replace_nth_neq; lia | left; exact Hpi_b].
           ++ apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
                exact Hlp | rewrite replace_nth_length; exact Hls | auto |
                intros j Hne; apply sec_at_replace_nth_neq; lia | left; exact Hpi_b].
           ++ apply Hadv; [exact Hlp | rewrite replace_nth_length; exact Hls | exact Hpi_b |
                rewrite sec_at_replace_nth_eq by lia; exact Hpi_s_eq | auto |
                intros j Hne; apply sec_at_replace_nth_neq; lia |
                intro Hn; specialize (Hcut1_none Hn); discriminate].
           ++ apply Hadv; [exact Hlp | rewrite replace_nth_length; exact Hls | exact Hpi_b |
                rewrite sec_at_replace_nth_eq by lia; exact Hpi_s_eq | auto |
                intros j Hne; apply sec_at_replace_nth_neq; lia | reflexivity].
      * apply opt_nat_eqb_neq in Ephs.
        assert (Hsi_b : sec_at sec i = sec_at B i)
          by (destruct Hmid as [Hp | [_ Hs]]; [congruence | exact Hs]).
        destruct cut1 as [[|k1]|] eqn:Ec1.
        -- apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
             rewrite replace_nth_length; exact Hlp | exact Hls |
             intros j Hne; apply sec_at_replace_nth_neq; lia | auto |
             right; rewrite sec_at_replace_nth_eq by lia; split; congruence].
        -- destruct k1 as [|k2].
           ++ apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
                rewrite replace_nth_length; exact Hlp | exact Hls |
                intros j Hne; apply sec_at_replace_nth_neq; lia | auto |
                left; rewrite sec_at_replace_nth_eq by lia; exact Hsi_b].
           ++ simpl.
              set (pri1 := replace_nth i (sec_at sec i) pri).
              assert (Hlp1 : length pri1 = S N) by (unfold pri1; rewrite replace_nth_length; exact Hlp).
              assert (Hpi1_b : sec_at pri1 i = sec_at B i)
                by (unfold pri1; rewrite sec_at_replace_nth_eq by lia; exact Hsi_b).
              assert (Hpi1_s : sec_at pri1 (S i) = sec_at A i)
                by (unfold pri1; rewrite sec_at_replace_nth_neq by lia; exact Hpi_s_eq).
              destruct (opt_nat_eqb (sec_at sec i) cp0) eqn:Eshp.
              ** apply opt_nat_eqb_eq in Eshp.
                 apply Hadv; [exact Hlp1 | exact Hls | exact Hpi1_b | congruence |
                   intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia | auto |
                   intro Hn; specialize (Hcut1_none Hn); discriminate].
              ** destruct k2 as [|[|k3]].
                 --- apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
                       exact Hlp1 | rewrite replace_nth_length; exact Hls |
                       intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia |
                       intros j Hne; apply sec_at_replace_nth_neq; lia | left; exact Hpi1_b].
                 --- apply Hpause; [intro Hn; specialize (Hcut1_none Hn); discriminate |
                       exact Hlp1 | rewrite replace_nth_length; exact Hls |
                       intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia |
                       intros j Hne; apply sec_at_replace_nth_neq; lia | left; exact Hpi1_b].
                 --- apply Hadv; [exact Hlp1 | rewrite replace_nth_length; exact Hls | exact Hpi1_b |
                       rewrite sec_at_replace_nth_eq by lia; exact Hpi1_s |
                       intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia |
                       intros j Hne; apply sec_at_replace_nth_neq; lia |
                       intro Hn; specialize (Hcut1_none Hn); discriminate].
        -- simpl.
           set (pri1 := replace_nth i (sec_at sec i) pri).
           assert (Hlp1 : length pri1 = S N) by (unfold pri1; rewrite replace_nth_length; exact Hlp).
           assert (Hpi1_b : sec_at pri1 i = sec_at B i)
             by (unfold pri1; rewrite sec_at_replace_nth_eq by lia; exact Hsi_b).
           assert (Hpi1_s : sec_at pri1 (S i) = sec_at A i)
             by (unfold pri1; rewrite sec_at_replace_nth_neq by lia; exact Hpi_s_eq).
           destruct (opt_nat_eqb (sec_at sec i) cp0) eqn:Eshp.
           ++ apply opt_nat_eqb_eq in Eshp.
              apply Hadv; [exact Hlp1 | exact Hls | exact Hpi1_b | congruence |
                intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia | auto | reflexivity].
           ++ apply Hadv; [exact Hlp1 | rewrite replace_nth_length; exact Hls | exact Hpi1_b |
                rewrite sec_at_replace_nth_eq by lia; exact Hpi1_s |
                intros j Hne; unfold pri1; apply sec_at_replace_nth_neq; lia |
                intros j Hne; apply sec_at_replace_nth_neq; lia | reflexivity].
Qed.

Lemma shift_up_completed_props :
  forall pri i N,
    length pri = S N ->
    i < N ->
    length (shift_up_completed pri i) = S N /\
    sec_at (shift_up_completed pri i) (S i) = sec_at pri i /\
    (forall j, j <> S i -> sec_at (shift_up_completed pri i) j = sec_at pri j).
Proof.
  intros pri i N Hlp Hi; unfold shift_up_completed; cbv zeta.
  destruct (opt_nat_eqb (sec_at pri i) (sec_at pri (S i))) eqn:E.
  - apply opt_nat_eqb_eq in E; split_conj; [exact Hlp | congruence | auto].
  - split_conj.
    + rewrite replace_nth_length; exact Hlp.
    + apply sec_at_replace_nth_eq; lia.
    + intros j Hne; apply sec_at_replace_nth_neq; lia.
Qed.

Lemma shift_up_torn_props :
  forall pri i N,
    length pri = S N ->
    i < N ->
    length (shift_up_torn pri i) = S N /\
    (forall j, j <> S i -> sec_at (shift_up_torn pri i) j = sec_at pri j).
Proof.
  intros pri i N Hlp Hi; unfold shift_up_torn; cbv zeta.
  destruct (opt_nat_eqb (sec_at pri i) (sec_at pri (S i))).
  - split; [exact Hlp | auto].
  - split; [rewrite replace_nth_length; exact Hlp | intros j Hne; apply sec_at_replace_nth_neq; lia].
Qed.

Lemma sm_move_loop_invariant_and_complete :
  forall cnt N A B pri sec cut,
    CleanImage N A ->
    CleanImage N B ->
    cnt <= N ->
    length pri = S N ->
    sec = B ->
    (forall j, j < cnt -> sec_at pri j = sec_at A j) ->
    (forall j, cnt <= j -> j < N -> sec_at pri (S j) = sec_at A j) ->
    let out := sm_move_loop cnt N pri sec cut in
    SwapMoveValid A B N out /\
    (cut = None ->
     sm_phase out = SMP_Done /\ firstn N (sm_P out) = B /\ sm_S out = A).
Proof.
  induction cnt as [|i IH];
    intros N A B pri sec cut HcA HcB Hcnt Hlp Hsec Hle Hgt; cbv zeta; simpl.
  - apply sm_swap_loop_invariant_and_complete; try assumption; [lia|].
    destruct HcB as [HlB _]; subst sec.
    unfold SwapMoveValid; simpl; split_conj.
    + exact Hlp.
    + exact HlB.
    + lia.
    + intros j Hj; lia.
    + intros j _ Hj; split; [apply Hgt; lia | reflexivity].
  - destruct (shift_up_completed_props pri i N Hlp ltac:(lia)) as [Hl_c [Hsi_c Hfr_c]].
    destruct (shift_up_torn_props pri i N Hlp ltac:(lia)) as [Hl_t Hfr_t].
    destruct HcB as [HlB HnB].
    destruct cut as [[|[|k']]|].
    + split; [|discriminate].
      unfold SwapMoveValid; simpl; subst sec; split_conj; try reflexivity; try assumption; try lia.
      * intros j Hj; rewrite Hfr_t by lia; apply Hle; lia.
      * intros j Hgt_i Hj; rewrite Hfr_t by lia; apply Hgt; lia.
    + split; [|discriminate].
      unfold SwapMoveValid; simpl; subst sec; split_conj; try reflexivity; try assumption; try lia.
      * intros j Hj; rewrite Hfr_c by lia; apply Hle; lia.
      * intros j Hgt_i Hj; rewrite Hfr_c by lia; apply Hgt; lia.
    + destruct (IH N A B (shift_up_completed pri i) sec (opt_sub (Some (S (S k'))) 2)
                   HcA (conj HlB HnB) ltac:(lia) Hl_c Hsec) as [Hv _].
      * intros j Hj; rewrite Hfr_c by lia; apply Hle; lia.
      * intros j Hge Hj.
        destruct (Nat.eq_dec j i) as [Heq | Hne].
        -- subst j; rewrite Hsi_c; apply Hle; lia.
        -- rewrite Hfr_c by lia; apply Hgt; lia.
      * split; [exact Hv | discriminate].
    + apply (IH N A B (shift_up_completed pri i) sec None
                HcA (conj HlB HnB) ltac:(lia) Hl_c Hsec).
      * intros j Hj; rewrite Hfr_c by lia; apply Hle; lia.
      * intros j Hge Hj.
        destruct (Nat.eq_dec j i) as [Heq | Hne].
        -- subst j; rewrite Hsi_c; apply Hle; lia.
        -- rewrite Hfr_c by lia; apply Hgt; lia.
Qed.

Lemma swapmove_init_valid :
  forall A B spare N,
    1 <= N ->
    CleanImage N A ->
    CleanImage N B ->
    SwapMoveValid A B N (swapmove_init A B spare N).
Proof.
  intros A B spare N HN [HlA _] [HlB _].
  unfold SwapMoveValid, swapmove_init; simpl.
  assert (Hl_app : length (A ++ [spare]) = S N).
  { rewrite length_app; simpl; lia. }
  split_conj; try reflexivity; try assumption; try lia.
  intros j Hj; unfold sec_at.
  rewrite nth_error_app1 by lia; reflexivity.
Qed.

Lemma swapmove_exec_valid_and_complete :
  forall A B N st cut,
    CleanImage N A ->
    CleanImage N B ->
    SwapMoveValid A B N st ->
    let out := swapmove_exec st N cut in
    SwapMoveValid A B N out /\
    (cut = None ->
     sm_phase out = SMP_Done /\ firstn N (sm_P out) = B /\ sm_S out = A).
Proof.
  intros A B N st cut HcA HcB Hval; cbv zeta; unfold swapmove_exec.
  unfold SwapMoveValid in Hval.
  destruct st as [pri sec phase idx res cs cp];
    cbn [sm_phase sm_idx sm_P sm_S sm_resuming sm_cs sm_cp] in *.
  destruct phase.
  - destruct Hval as [Hlp [Hls [Hi [Hs [Hle Hgt]]]]].
    apply (sm_move_loop_invariant_and_complete (S idx) N A B pri sec cut);
      try assumption; try lia.
    intros j Hj; apply Hle; lia.
  - assert (Hidx_le : idx <= N).
    { destruct Hval as [_ [_ Hb]]; simpl in Hb.
      destruct res; destruct Hb; lia. }
    pose proof (sm_swap_loop_invariant_and_complete
                  (N - idx) N A B pri sec res cs cp cut HcA HcB ltac:(lia)) as Hsw.
    apply Hsw.
    replace (N - (N - idx)) with idx by lia.
    exact Hval.
  - destruct Hval as [Hlp [Hls [Hfn Hs]]]; simpl in *.
    split; [unfold SwapMoveValid; simpl; auto | intros _; auto].
Qed.

Lemma copy_range_complete_prefix :
  forall count start src dst,
    start + count <= length src ->
    start + count <= length dst ->
    (forall j, j < start -> sec_at dst j = sec_at src j) ->
    forall j, j < start + count ->
      sec_at (copy_range_complete src dst start count) j = sec_at src j.
Proof.
  induction count as [|count' IH]; intros start src dst Hls Hld Hpre j Hj; simpl.
  - apply Hpre; lia.
  - assert (Hc_len : length (copy_sector_completed src dst start) = length dst)
      by apply copy_sector_completed_length.
    replace (start + S count') with (S start + count') in * by lia.
    apply IH; [lia | lia | | exact Hj].
    intros m Hm.
    destruct (Nat.eq_dec start m) as [Heq | Hne].
    + subst m; unfold copy_sector_completed.
      rewrite !nth_error_sec_at by lia.
      destruct (opt_nat_eqb (sec_at src start) (sec_at dst start)) eqn:E.
      * apply opt_nat_eqb_eq in E; symmetry; exact E.
      * apply sec_at_replace_nth_eq; lia.
    + unfold sec_at; rewrite copy_sector_completed_nth_neq by exact Hne.
      fold (sec_at dst m); apply Hpre; lia.
Qed.

Lemma swapmove_rollback_converges :
  forall pri A N k,
    N <= length pri ->
    length A = N ->
    let pri_cut := swapmove_rollback_power_cut pri A N k in
    firstn N (swapmove_rollback_resume pri_cut A N) = A.
Proof.
  intros pri A N k Hlp HlA; cbv zeta.
  assert (Hres_len : forall c st dst, length (copy_range_complete A dst st c) = length dst).
  { induction c as [|c' IHc]; intros st dst; simpl; [reflexivity|].
    rewrite IHc, copy_sector_completed_length; reflexivity. }
  set (pri_cut := swapmove_rollback_power_cut pri A N k).
  assert (Hcut_len : length pri_cut = length pri).
  { unfold pri_cut, swapmove_rollback_power_cut.
    destruct (k <? N); [apply copy_range_cut_length | apply Hres_len]. }
  unfold swapmove_rollback_resume.
  apply firstn_sec_at_eq.
  - rewrite Hres_len, Hcut_len; exact Hlp.
  - exact HlA.
  - intros j Hj.
    apply (copy_range_complete_prefix N 0 A pri_cut ltac:(lia) ltac:(lia)
             (fun m Hm => ltac:(lia)) j ltac:(lia)).
Qed.

Theorem swapmove_sector_conservation_and_resume :
  forall (a_words b_words : list nat) (spare : option nat) (N k1 k2 k_rb : nat),
    1 <= N ->
    length a_words = N ->
    length b_words = N ->
    let A := lift_clean_sectors a_words in
    let B := lift_clean_sectors b_words in
    let st0 := swapmove_init A B spare N in
    let st_cut1 := swapmove_power_cut st0 N k1 in
    let st_cut2 := swapmove_power_cut st_cut1 N k2 in
    let st_fin1 := swapmove_resume st_cut1 N in
    let st_fin2 := swapmove_resume st_cut2 N in
    SwapMoveConserved A B N st_cut1 /\
    SwapMoveConserved A B N st_cut2 /\
    sm_phase st_fin1 = SMP_Done /\
    firstn N (sm_P st_fin1) = B /\
    sm_S st_fin1 = A /\
    sm_phase st_fin2 = SMP_Done /\
    firstn N (sm_P st_fin2) = B /\
    sm_S st_fin2 = A /\
    let pri_rb_cut := swapmove_rollback_power_cut (sm_P st_fin2) (sm_S st_fin2) N k_rb in
    firstn N (swapmove_rollback_resume pri_rb_cut (sm_S st_fin2) N) = A.
Proof.
  intros a_words b_words spare N k1 k2 k_rb HN Hla Hlb; cbv zeta.
  set (A := lift_clean_sectors a_words).
  set (B := lift_clean_sectors b_words).
  assert (HcA : CleanImage N A) by (apply lift_clean_sectors_clean; exact Hla).
  assert (HcB : CleanImage N B) by (apply lift_clean_sectors_clean; exact Hlb).
  assert (Hv0 : SwapMoveValid A B N (swapmove_init A B spare N))
    by (apply swapmove_init_valid; assumption).
  unfold swapmove_power_cut, swapmove_resume.
  destruct (swapmove_exec_valid_and_complete A B N _ (Some k1) HcA HcB Hv0) as [Hv1 _].
  destruct (swapmove_exec_valid_and_complete A B N _ (Some k2) HcA HcB Hv1) as [Hv2 _].
  destruct (swapmove_exec_valid_and_complete A B N _ None HcA HcB Hv1) as [_ Hfin1].
  destruct (Hfin1 eq_refl) as [Hp1 [Hfn1 Hs1]].
  destruct (swapmove_exec_valid_and_complete A B N _ None HcA HcB Hv2) as [Hv_done2 Hfin2].
  destruct (Hfin2 eq_refl) as [Hp2 [Hfn2 Hs2]].
  destruct Hv_done2 as [Hlp_done2 _].
  destruct HcA as [HlA _].
  split_conj; try reflexivity; try assumption.
  - apply swapmove_valid_implies_conserved; exact Hv1.
  - apply swapmove_valid_implies_conserved; exact Hv2.
  - rewrite Hs2; apply swapmove_rollback_converges; lia.
Qed.

(* ========================================================================== *)
(* SECTION 7: Extension Theorem 2 — TCC1 Killswitch Non-Bypassability         *)
(*            & Anti-OTP-Depletion Cap                                        *)
(* ========================================================================== *)

Definition cloud_token_auth_fresh
    (sig_ok dev_ok : bool) (ctr_min issued_at : nat)
    (tmr : TMR_Counters) (otp : OTP_Epoch) : bool :=
  sig_ok && dev_ok &&
  ((otp_min_svn otp <? ctr_min) &&
   (last_cloud_issued_at tmr <? issued_at) &&
   ((ctr_min - otp_min_svn otp) <=? toob_cmd_max_burn_steps)).

Definition cloud_clears_lock_c
    (cld : CloudCmdSlot) (tmr : TMR_Counters) (otp : OTP_Epoch) : bool :=
  match cld with
  | CC_Token CCK_Unlock sig_ok dev_ok ctr iss =>
      cloud_token_auth_fresh sig_ok dev_ok ctr iss tmr otp
  | CC_Token CCK_Wipe sig_ok dev_ok ctr iss =>
      cloud_token_auth_fresh sig_ok dev_ok ctr iss tmr otp
  | CC_Token CCK_ForceUpdate sig_ok dev_ok ctr iss =>
      cloud_token_auth_fresh sig_ok dev_ok ctr iss tmr otp
  | _ => false
  end.

Definition cloud_clears_lock_strict
    (cld : CloudCmdSlot) (tmr : TMR_Counters) (otp : OTP_Epoch) : bool :=
  match cld with
  | CC_Token CCK_Unlock sig_ok dev_ok ctr iss =>
      cloud_token_auth_fresh sig_ok dev_ok ctr iss tmr otp
  | CC_Token CCK_Wipe sig_ok dev_ok ctr iss =>
      cloud_token_auth_fresh sig_ok dev_ok ctr iss tmr otp
  | _ => false
  end.

(* Helper: HIGH-31 guarantees Step 1 mailbox consumption preserves WI_DeviceLocked
   for ALL possible mailbox records (empty, corrupt, replayed, or fresh). *)
Lemma step1_mailbox_preserves_device_lock :
  forall slots wal tmr exp_n,
    wal_reconstruct_txn wal = Some (WI_DeviceLocked, exp_n) ->
    exists slots' tmr',
      step1_mailbox_consume slots wal tmr = Mbx_Done slots' wal tmr' /\
      cloud_slot slots' = cloud_slot slots /\
      last_cloud_issued_at tmr' = last_cloud_issued_at tmr.
Proof.
  intros slots wal tmr exp_n Hwal.
  unfold step1_mailbox_consume, wal_is_device_locked; rewrite Hwal.
  destruct (mailbox_slot slots) as [|crc seq rc ru rr mn].
  - exists slots, tmr; repeat split; reflexivity.
  - destruct (negb crc); [exists slots, tmr; repeat split; reflexivity|].
    destruct (negb (rc || ru || rr)); [exists slots, tmr; repeat split; reflexivity|].
    destruct (rc && (mn =? 0)); [exists slots, tmr; repeat split; reflexivity|].
    destruct (seq <=? last_mbx_seq tmr); [exists slots, tmr; repeat split; reflexivity|].
    eexists; eexists; repeat split; reflexivity.
Qed.

(* Theorem 7.1: Unconditional TCC1 Killswitch Non-Bypassability on 1:1 C
   eval_boot_state (synced with HIGH-31 + LOW-13) across ALL mailbox_slot
   states (including fresh OS mailbox records), ALL staging_slot, ConfirmStore,
   CCK_ForceUpdate tokens, ResetReason, and failure counters whenever no valid
   CCK_Unlock / CCK_Wipe cloud override token is present. *)
Theorem tcc1_killswitch_non_bypassable :
  forall cfg st exp_n,
    wal_reconstruct_txn (st_wal st) = Some (WI_DeviceLocked, exp_n) ->
    cloud_clears_lock_strict (cloud_slot (st_slots st)) (st_tmr st) (st_otp st) = false ->
    let '(out, _) := eval_boot_state cfg st in
    (forall img tent nonce, out <> Boot_App img tent nonce) /\
    (out = Enter_Recovery_OS (RM_SerialRescue Err_DeviceLocked) \/
     out = Enter_Recovery_OS (RM_SerialRescue Err_Verify)).
Proof.
  intros cfg st exp_n Hwal Hcld; cbv zeta.
  unfold eval_boot_state; cbv zeta.
  destruct (negb (tmr_mac_valid (st_tmr st))).
  - split; [intros; discriminate | right; reflexivity].
  - destruct (step1_mailbox_preserves_device_lock
                (st_slots st) (st_wal st) (st_tmr st) exp_n Hwal)
      as [slots1 [tmr1 [Hmbx [Hcld1 Hiss1]]]].
    rewrite Hmbx, Hwal.
    unfold step2_confirm_check; cbv zeta; simpl.
    unfold step2_5_cloud_cmd, cloud_clears_lock_strict, cloud_token_auth_fresh in *; cbv zeta in *.
    rewrite Hcld1, Hiss1; simpl.
    destruct (cloud_slot (st_slots st)) as [|cmd sig_ok dev_ok ctr iss].
    + simpl; split; [intros; discriminate | left; reflexivity].
    + set (ok := sig_ok && dev_ok &&
                 ((otp_min_svn (st_otp st) <? ctr) &&
                  (last_cloud_issued_at (st_tmr st) <? iss) &&
                  (ctr - otp_min_svn (st_otp st) <=? toob_cmd_max_burn_steps))) in *.
      destruct cmd; destruct ok; try discriminate; simpl;
        (split; [intros; discriminate | left; reflexivity]).
Qed.

(* Corollary 7.2: Alias compatibility with eval_boot_state_lock_hardened *)
Theorem tcc1_killswitch_non_bypassable_hardened :
  forall cfg st exp_n,
    wal_reconstruct_txn (st_wal st) = Some (WI_DeviceLocked, exp_n) ->
    cloud_clears_lock_strict (cloud_slot (st_slots st)) (st_tmr st) (st_otp st) = false ->
    let '(out, _) := eval_boot_state_lock_hardened cfg st in
    (forall img tent nonce, out <> Boot_App img tent nonce) /\
    exists err, out = Enter_Recovery_OS (RM_SerialRescue err).
Proof.
  intros cfg st exp_n Hwal Hcld; cbv zeta.
  unfold eval_boot_state_lock_hardened.
  pose proof (tcc1_killswitch_non_bypassable cfg st exp_n Hwal Hcld) as H.
  destruct (eval_boot_state cfg st) as [out st']; destruct H as [Hno Hresc].
  split; [exact Hno | destruct Hresc as [-> | ->]; eexists; reflexivity].
Qed.

(* Theorem 7.2b (HIGH-31 + LOW-13 Persistence): Neither arbitrary OS mailbox
   records nor signed fresh CCK_ForceUpdate tokens can clear WI_DeviceLocked in
   WAL; the post-boot state remains locked at Err_DeviceLocked. *)
Theorem tcc1_mailbox_and_force_update_cannot_bypass_lock :
  forall cfg st exp_n,
    tmr_mac_valid (st_tmr st) = true ->
    wal_reconstruct_txn (st_wal st) = Some (WI_DeviceLocked, exp_n) ->
    (cloud_slot (st_slots st) = CC_Empty \/
     exists sig_ok dev_ok ctr iss,
       cloud_slot (st_slots st) = CC_Token CCK_ForceUpdate sig_ok dev_ok ctr iss) ->
    let '(out, st') := eval_boot_state cfg st in
    out = Enter_Recovery_OS (RM_SerialRescue Err_DeviceLocked) /\
    wal_reconstruct_txn (st_wal st') = Some (WI_DeviceLocked, exp_n).
Proof.
  intros cfg st exp_n Hmac Hwal Hforce; cbv zeta.
  unfold eval_boot_state; cbv zeta.
  rewrite Hmac; simpl.
  destruct (step1_mailbox_preserves_device_lock
              (st_slots st) (st_wal st) (st_tmr st) exp_n Hwal)
    as [slots1 [tmr1 [Hmbx [Hcld1 Hiss1]]]].
  rewrite Hmbx, Hwal.
  unfold step2_confirm_check; cbv zeta; simpl.
  unfold step2_5_cloud_cmd; cbv zeta.
  rewrite Hcld1, Hiss1.
  destruct Hforce as [Hemp | [sig_ok [dev_ok [ctr [iss Htok]]]]].
  - rewrite Hemp; simpl; split; [reflexivity | exact Hwal].
  - rewrite Htok.
    destruct (negb (sig_ok && dev_ok &&
                    ((otp_min_svn (st_otp st) <? ctr) &&
                     (last_cloud_issued_at (st_tmr st) <? iss) &&
                     (ctr - otp_min_svn (st_otp st) <=? toob_cmd_max_burn_steps))));
      simpl; split; [reflexivity | exact Hwal | reflexivity | exact Hwal].
Qed.

(* Theorem 7.2c (HIGH-32): Valid CCK_Wipe on a WI_DeviceLocked device unlocks
   open_txn->intent to WI_None in RAM on that same boot and preserves
   wipe_requested = true across handoff. *)
Theorem tcc1_wipe_unlocks_and_preserves_wipe_flag :
  forall cfg st exp_n sig_ok dev_ok ctr iss,
    tmr_mac_valid (st_tmr st) = true ->
    wal_reconstruct_txn (st_wal st) = Some (WI_DeviceLocked, exp_n) ->
    cloud_slot (st_slots st) = CC_Token CCK_Wipe sig_ok dev_ok ctr iss ->
    cloud_token_auth_fresh sig_ok dev_ok ctr iss (st_tmr st) (st_otp st) = true ->
    boot_failure_counter (st_tmr st) = 0 ->
    rst_indicates_crash (st_reset st) = false ->
    hdr_valid (app_slot (st_slots st)) = true ->
    let '(out, st') := eval_boot_state cfg st in
    out = Boot_App (app_slot (st_slots st)) false 0 /\
    eval_boot_wipe_requested cfg st = true /\
    wal_reconstruct_txn (st_wal st') = Some (WI_None, 0).
Proof.
  intros cfg st exp_n sig_ok dev_ok ctr iss Hmac Hwal Htok Hok Hbf0 Hrst Hhdr.
  cbv zeta.
  destruct (step1_mailbox_preserves_device_lock
              (st_slots st) (st_wal st) (st_tmr st) exp_n Hwal)
    as [slots1 [tmr1 [Hmbx [Hcld1 Hiss1]]]].
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx)
    as [Happ1 [_ [_ [_ [_ [_ [Hbf1 [_ [_ [_ _]]]]]]]]]].
  unfold eval_boot_wipe_requested, eval_boot_state; cbv zeta.
  rewrite Hmac; simpl.
  rewrite Hmbx, Hwal.
  unfold step2_confirm_check; cbv zeta; simpl.
  unfold step2_5_sets_wipe_requested, step2_5_cloud_cmd; cbv zeta.
  rewrite Hcld1, Hiss1, Htok.
  unfold cloud_token_auth_fresh in Hok.
  rewrite Hok; simpl.
  unfold step3_failure_and_rollback; cbv zeta.
  rewrite Hrst, Hbf1, Hbf0; simpl.
  unfold step4_update_pipeline; cbv zeta; simpl.
  rewrite Happ1, Hhdr; simpl.
  repeat split; reflexivity.
Qed.

(* Theorem 7.2d (MED-28): When Step 2.5 accepts a fresh cloud token with
   timestamp issued_at, boot_state_run reloads current_tmr so post-boot TMR
   preserves last_cloud_issued_at = issued_at across Steps 2.7, 3, 4, and 5. *)
Theorem med28_cloud_issued_at_preserved_across_boot :
  forall cfg st slots1 wal1 tmr1 oi1 oe1 slots2 wal2 tmr2 conf2 oi2 healed2
         cmd sig_ok dev_ok ctr issued_at,
    tmr_mac_valid (st_tmr st) = true ->
    step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) =
      Mbx_Done slots1 wal1 tmr1 ->
    wal_reconstruct_txn wal1 = Some (oi1, oe1) ->
    step2_confirm_check slots1 wal1 tmr1 (st_confirm st) oi1 oe1 =
      S2_Ok slots2 wal2 tmr2 conf2 oi2 healed2 ->
    cloud_slot slots2 = CC_Token cmd sig_ok dev_ok ctr issued_at ->
    cloud_token_auth_fresh sig_ok dev_ok ctr issued_at tmr2 (st_otp st) = true ->
    last_cloud_issued_at (st_tmr (snd (eval_boot_state cfg st))) = issued_at.
Proof.
  intros cfg st slots1 wal1 tmr1 oi1 oe1 slots2 wal2 tmr2 conf2 oi2 healed2
         cmd sig_ok dev_ok ctr issued_at Hmac Hmbx Hwal Hs2 Hcld Hok.
  unfold eval_boot_state; cbv zeta.
  rewrite Hmac; simpl; rewrite Hmbx, Hwal, Hs2.
  destruct (step2_5_cloud_cmd slots2 wal2 tmr2 (st_otp st) oi2)
    as [[[[slots25 wal25] tmr25] otp25] oi25] eqn:Hs25.
  assert (Hiss25 : last_cloud_issued_at tmr25 = issued_at).
  { unfold step2_5_cloud_cmd in Hs25; cbv zeta in Hs25.
    rewrite Hcld in Hs25; unfold cloud_token_auth_fresh in Hok; rewrite Hok in Hs25; simpl in Hs25.
    destruct cmd; try destruct (wal_intent_eqb oi2 WI_DeviceLocked);
      inversion Hs25; subst; reflexivity. }
  destruct (wal_intent_eqb oi25 WI_DeviceLocked); [simpl; exact Hiss25|].
  destruct (step3_failure_and_rollback cfg slots25 wal25 tmr25 (st_reset st) oi25 healed2)
    as [err3 tmr3p | slots3 wal3 tmr3 oi3 healed3 boot_rec3] eqn:Hs3.
  - simpl.
    unfold step3_failure_and_rollback in Hs3; cbv zeta in Hs3.
    set (ta := if (negb healed2 &&
                   ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                    (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                  crash_accum_applicable oi25
               then apply_crash_accum cfg tmr25 else tmr25) in *.
    assert (Hta : last_cloud_issued_at ta = issued_at).
    { unfold ta, apply_crash_accum.
      destruct ((negb healed2 &&
                 ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                  (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                crash_accum_applicable oi25);
        [destruct (cfg_max_retries cfg <? boot_failure_counter tmr25); simpl; exact Hiss25
        | exact Hiss25]. }
    destruct (wal_intent_eqb oi25 WI_TxnRollback); [discriminate|].
    destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi25 WI_TxnRollbackPending); [|discriminate].
    destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending).
    + destruct (rst_indicates_crash (st_reset st) && negb healed2 ||
                wal_intent_eqb oi25 WI_TxnRollbackPending ||
                (cfg_max_retries cfg <? boot_failure_counter ta)); [|discriminate].
      destruct (negb (hdr_valid (backup_slot slots25))); inversion Hs3; subst; exact Hta.
    + destruct (boot_failure_counter ta <=? cfg_max_retries cfg); [discriminate|].
      destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg);
        inversion Hs3; subst; exact Hta.
  - assert (Hiss3 : last_cloud_issued_at tmr3 = issued_at).
    { unfold step3_failure_and_rollback in Hs3; cbv zeta in Hs3.
      set (ta := if (negb healed2 &&
                     ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                      (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                    crash_accum_applicable oi25
                 then apply_crash_accum cfg tmr25 else tmr25) in *.
      assert (Hta : last_cloud_issued_at ta = issued_at).
      { unfold ta, apply_crash_accum.
        destruct ((negb healed2 &&
                   ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                    (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                  crash_accum_applicable oi25);
          [destruct (cfg_max_retries cfg <? boot_failure_counter tmr25); simpl; exact Hiss25
          | exact Hiss25]. }
      destruct (wal_intent_eqb oi25 WI_TxnRollback); [inversion Hs3; subst; simpl; exact Hta|].
      destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi25 WI_TxnRollbackPending);
        [|inversion Hs3; subst; exact Hta].
      destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending).
      - destruct (rst_indicates_crash (st_reset st) && negb healed2 ||
                  wal_intent_eqb oi25 WI_TxnRollbackPending ||
                  (cfg_max_retries cfg <? boot_failure_counter ta));
          [|inversion Hs3; subst; exact Hta].
        destruct (negb (hdr_valid (backup_slot slots25))); inversion Hs3; subst; simpl; exact Hta.
      - destruct (boot_failure_counter ta <=? cfg_max_retries cfg);
          [inversion Hs3; subst; exact Hta|].
        destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg);
          inversion Hs3; subst; exact Hta. }
    destruct (step4_update_pipeline slots3 wal3 tmr3 otp25 oi3)
      as [[[[slots4 wal4] tmr4] oi4] upd_p] eqn:Hs4.
    assert (Hiss4 : last_cloud_issued_at tmr4 = issued_at).
    { unfold step4_update_pipeline in Hs4; cbv zeta in Hs4.
      destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)); [inversion Hs4; subst; exact Hiss3|].
      destruct (staging_can_apply (staging_slot slots3) tmr3 otp25);
        inversion Hs4; subst; simpl; exact Hiss3. }
    set (app_hdr_ok := hdr_valid (app_slot slots4)).
    set (fb := negb boot_rec3 && negb app_hdr_ok && recovery_rom_valid slots4 &&
               (recovery_failure_counter tmr4 <=? cfg_max_recovery_retries cfg)).
    set (br5 := boot_rec3 || fb).
    destruct (negb (if br5 then recovery_rom_valid slots4 else app_hdr_ok));
      [simpl; exact Hiss4 | destruct br5; simpl; exact Hiss4].
Qed.

(* Theorem 7.3: TCC1 OTP Fuse-Depletion Cap (<= +4) & Cloud Anti-Replay *)
Theorem tcc1_otp_depletion_cap_and_replay_immunity :
  forall slots wal tmr otp oi,
    let '(slots', wal', tmr', otp', oi') :=
      step2_5_cloud_cmd slots wal tmr otp oi in
    otp_min_svn otp <= otp_min_svn otp' /\
    otp_min_svn otp' <= otp_min_svn otp + toob_cmd_max_burn_steps /\
    toob_cmd_max_burn_steps = 4 /\
    last_cloud_issued_at tmr <= last_cloud_issued_at tmr' /\
    (forall cmd sig_ok dev_ok ctr_min issued_at,
       cloud_slot slots = CC_Token cmd sig_ok dev_ok ctr_min issued_at ->
       cloud_token_auth_fresh sig_ok dev_ok ctr_min issued_at tmr otp = true ->
       otp_min_svn otp < otp_min_svn otp' /\
       otp_min_svn otp' = ctr_min /\
       last_cloud_issued_at tmr < last_cloud_issued_at tmr' /\
       last_cloud_issued_at tmr' = issued_at /\
       cloud_slot slots' = CC_Empty) /\
    (forall cmd sig_ok dev_ok ctr_min issued_at,
       cloud_slot slots = CC_Token cmd sig_ok dev_ok ctr_min issued_at ->
       (sig_ok = false \/ dev_ok = false \/
        ctr_min <= otp_min_svn otp \/
        issued_at <= last_cloud_issued_at tmr \/
        toob_cmd_max_burn_steps < ctr_min - otp_min_svn otp) ->
       (slots', wal', tmr', otp', oi') = (slots, wal, tmr, otp, oi)) /\
    (forall slots_r wal_r oi_r,
       cloud_slot slots_r = cloud_slot slots ->
       step2_5_cloud_cmd slots_r wal_r tmr' otp' oi_r =
         (slots_r, wal_r, tmr', otp', oi_r)).
Proof.
  intros slots wal tmr otp oi.
  destruct (step2_5_cloud_cmd slots wal tmr otp oi)
    as [[[[slots' wal'] tmr'] otp'] oi'] eqn:Hs25.
  pose proof Hs25 as Hs25_orig.
  unfold step2_5_cloud_cmd in Hs25; cbv zeta in Hs25.
  destruct (cloud_slot slots) as [|cmd0 sig0 dev0 ctr0 iss0] eqn:Hcs.
  - inversion Hs25; subst.
    split_conj; unfold toob_cmd_max_burn_steps; try lia.
    + intros; discriminate.
    + intros; discriminate.
    + intros slots_r wal_r oi_r Hcr; unfold step2_5_cloud_cmd; rewrite Hcr; reflexivity.
  - set (ok := sig0 && dev0 &&
               ((otp_min_svn otp <? ctr0) &&
                (last_cloud_issued_at tmr <? iss0) &&
                (ctr0 - otp_min_svn otp <=? toob_cmd_max_burn_steps))) in *.
    destruct (negb ok) eqn:Enok.
    + apply Bool.negb_true_iff in Enok.
      inversion Hs25; subst.
      split_conj; unfold toob_cmd_max_burn_steps; try lia.
      * intros cmd sig_ok dev_ok ctr_min issued_at Htok Hok.
        inversion Htok; subst; unfold ok in Enok; unfold cloud_token_auth_fresh in Hok; congruence.
      * intros; reflexivity.
      * intros slots_r wal_r oi_r Hcr.
        unfold step2_5_cloud_cmd; cbv zeta; rewrite Hcr.
        fold ok; rewrite Enok; simpl; reflexivity.
    + apply Bool.negb_false_iff in Enok.
      assert (Hbounds : sig0 = true /\ dev0 = true /\
                        otp_min_svn otp < ctr0 /\
                        last_cloud_issued_at tmr < iss0 /\
                        ctr0 - otp_min_svn otp <= toob_cmd_max_burn_steps).
      { unfold ok in Enok.
        repeat rewrite Bool.andb_true_iff in Enok.
        destruct Enok as [[Hs Hd] [[Hc Hi] Hb]].
        apply Nat.ltb_lt in Hc; apply Nat.ltb_lt in Hi; apply Nat.leb_le in Hb.
        split_conj; assumption. }
      destruct Hbounds as [Hs0 [Hd0 [Hctr_lt [Hiss_lt Hburn_le]]]].
      assert (Hout :
        otp_min_svn otp' = ctr0 /\
        last_cloud_issued_at tmr' = iss0 /\
        cloud_slot slots' = CC_Empty).
      { destruct cmd0; try destruct (wal_intent_eqb oi WI_DeviceLocked);
          inversion Hs25; subst; simpl; split_conj; reflexivity. }
      destruct Hout as [Hotp' [Hiss' Hce]].
      split_conj; unfold toob_cmd_max_burn_steps in *; try lia.
      * intros cmd sig_ok dev_ok ctr_min issued_at Htok _.
        inversion Htok; subst; split_conj; try lia; exact Hce.
      * intros cmd sig_ok dev_ok ctr_min issued_at Htok Hbad.
        inversion Htok; subst.
        exfalso; unfold toob_cmd_max_burn_steps in *; intuition (congruence || lia).
      * intros slots_r wal_r oi_r Hcr.
        unfold step2_5_cloud_cmd; cbv zeta; rewrite Hcr, Hotp', Hiss'.
        rewrite Nat.ltb_irrefl; destruct sig0, dev0; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 8: Extension Theorem 3 — Cross-Epoch Trial-Boot Isolation          *)
(*            & Nonce / OS Mailbox Replay Immunity                            *)
(* ========================================================================== *)

Theorem mailbox_replay_and_zero_nonce_immunity :
  forall slots wal tmr,
    (forall crc_ok seq rc ru rr n,
       mailbox_slot slots = MBX_Record crc_ok seq rc ru rr n ->
       seq <= last_mbx_seq tmr ->
       step1_mailbox_consume slots wal tmr = Mbx_Done slots wal tmr) /\
    (forall crc_ok seq ru rr,
       mailbox_slot slots = MBX_Record crc_ok seq true ru rr 0 ->
       step1_mailbox_consume slots wal tmr = Mbx_Done slots wal tmr) /\
    (forall slots' wal' tmr' slots_r wal_r crc_ok seq rc ru rr n,
       step1_mailbox_consume slots wal tmr = Mbx_Done slots' wal' tmr' ->
       (mailbox_slot slots = MBX_Record crc_ok seq rc ru rr n ->
        crc_ok = true -> (rc || ru || rr) = true ->
        (rc = true -> 0 < n) ->
        seq <= last_mbx_seq tmr') /\
       (mailbox_slot slots_r = MBX_Record crc_ok seq rc ru rr n ->
        seq <= last_mbx_seq tmr' ->
        step1_mailbox_consume slots_r wal_r tmr' = Mbx_Done slots_r wal_r tmr')).
Proof.
  intros slots wal tmr; split_conj.
  - intros crc_ok seq rc ru rr n Hmbx Hle.
    unfold step1_mailbox_consume; rewrite Hmbx.
    destruct (negb crc_ok); [reflexivity|].
    destruct (negb (rc || ru || rr)); [reflexivity|].
    destruct (rc && (n =? 0)); [reflexivity|].
    assert (Hleb : (seq <=? last_mbx_seq tmr) = true) by (apply Nat.leb_le; exact Hle).
    rewrite Hleb; reflexivity.
  - intros crc_ok seq ru rr Hmbx.
    unfold step1_mailbox_consume; rewrite Hmbx.
    destruct (negb crc_ok); [reflexivity|].
    destruct (negb (true || ru || rr)); reflexivity.
  - intros slots' wal' tmr' slots_r wal_r crc_ok seq rc ru rr n Hstep; split.
    + intros Hmbx Hcrc Hreq Hnz.
      unfold step1_mailbox_consume in Hstep; rewrite Hmbx, Hcrc, Hreq in Hstep; simpl in Hstep.
      assert (Hrc0 : (rc && (n =? 0)) = false).
      { destruct rc; [simpl; apply Nat.eqb_neq; specialize (Hnz eq_refl); lia | reflexivity]. }
      rewrite Hrc0 in Hstep.
      destruct (seq <=? last_mbx_seq tmr) eqn:Ele.
      * apply Nat.leb_le in Ele; inversion Hstep; subst; exact Ele.
      * inversion Hstep; subst; simpl; lia.
    + intros Hmr Hle.
      unfold step1_mailbox_consume; rewrite Hmr.
      destruct (negb crc_ok); [reflexivity|].
      destruct (negb (rc || ru || rr)); [reflexivity|].
      destruct (rc && (n =? 0)); [reflexivity|].
      assert (Hleb : (seq <=? last_mbx_seq tmr') = true) by (apply Nat.leb_le; exact Hle).
      rewrite Hleb; reflexivity.
Qed.

Theorem confirm_nonce_mismatch_cannot_heal :
  forall slots wal tmr conf open_intent open_exp,
    (active_nonce tmr = 0 ->
     (open_intent = WI_TxnCommit \/
      open_intent = WI_ConfirmCommit \/
      open_intent = WI_None) ->
     forall slots' wal' tmr' conf' oi' healed',
       step2_confirm_check slots wal tmr conf open_intent open_exp =
         S2_Ok slots' wal' tmr' conf' oi' healed' ->
       healed' = false /\ wal' = wal /\ tmr' = tmr /\ conf' = conf /\
       (open_intent = WI_TxnCommit -> oi' = WI_TxnCommit)) /\
    (0 < active_nonce tmr ->
     rtc_nonce conf <> active_nonce tmr ->
     (open_intent = WI_TxnCommit \/
      (open_intent = WI_ConfirmCommit /\ (open_exp <> active_nonce tmr \/ open_exp = 0))) ->
     forall slots' wal' tmr' conf' oi' healed',
       step2_confirm_check slots wal tmr conf open_intent open_exp =
         S2_Ok slots' wal' tmr' conf' oi' healed' ->
       healed' = false /\ oi' = WI_TxnCommit /\ wal' = wal /\ tmr' = tmr /\ conf' = conf).
Proof.
  intros slots wal tmr conf open_intent open_exp; split.
  - intros Han0 Hoi slots' wal' tmr' conf' oi' healed' Hs2.
    unfold step2_confirm_check in Hs2; cbv zeta in Hs2.
    assert (Hlt0 : (0 <? active_nonce tmr) = false) by (rewrite Han0; reflexivity).
    rewrite Hlt0 in Hs2; simpl in Hs2.
    destruct Hoi as [Htc | [Hcc | Hn]]; subst open_intent; simpl in Hs2;
      inversion Hs2; subst; split_conj; try reflexivity; intro; discriminate || reflexivity.
  - intros Han_pos Hrtc_ne Hoi slots' wal' tmr' conf' oi' healed' Hs2.
    unfold step2_confirm_check in Hs2; cbv zeta in Hs2.
    assert (Hlt_t : (0 <? active_nonce tmr) = true) by (apply Nat.ltb_lt; exact Han_pos).
    assert (Heq_f : (rtc_nonce conf =? active_nonce tmr) = false)
      by (apply Nat.eqb_neq; exact Hrtc_ne).
    rewrite Hlt_t, Heq_f in Hs2; simpl in Hs2.
    destruct Hoi as [Htc | [Hcc Hbad]]; subst open_intent; simpl in Hs2.
    + inversion Hs2; subst; split_conj; reflexivity.
    + assert (Hexp_f : ((0 <? open_exp) && (open_exp =? active_nonce tmr)) = false).
      { destruct Hbad as [Hne | Hz].
        - apply Nat.eqb_neq in Hne; rewrite Hne, Bool.andb_false_r; reflexivity.
        - subst open_exp; reflexivity. }
      rewrite Hexp_f in Hs2; simpl in Hs2.
      inversion Hs2; subst; split_conj; reflexivity.
Qed.

Theorem cross_epoch_trial_boot_isolation :
  forall cfg st0 img gen_nonce st1,
    0 < cfg_fresh_nonce cfg ->
    eval_boot_state cfg st0 = (Boot_App img true gen_nonce, st1) ->
    gen_nonce = cfg_fresh_nonce cfg /\
    0 < active_nonce (st_tmr st1) /\
    active_nonce (st_tmr st1) = cfg_fresh_nonce cfg /\
    wal_reconstruct_txn (st_wal st1) = Some (WI_TxnCommit, 0) /\
    (0 < active_nonce (st_tmr st0) ->
     rtc_nonce (st_confirm st0) = active_nonce (st_tmr st0) ->
     st_confirm st1 = mkConfirmStore 0) /\
    (forall old_n rst_next,
       old_n <> cfg_fresh_nonce cfg ->
       let st_next_epoch :=
         mkState (st_slots st1) (st_wal st1) (st_tmr st1)
                 (mkConfirmStore old_n) (st_otp st1) rst_next in
       let '(out2, st2) := eval_boot_state cfg st_next_epoch in
       (forall img2 n2,
          out2 = Boot_App img2 false n2 ->
          img2 = backup_slot (st_slots st1) /\
          wal_reconstruct_txn (st_wal st2) = Some (WI_None, 0)) /\
       (forall img2 n2,
          out2 = Boot_App img2 true n2 ->
          img2 = app_slot (st_slots st1) /\
          wal_reconstruct_txn (st_wal st2) = Some (WI_TxnCommit, 0))).
Proof.
  intros cfg st0 img gen_nonce st1 Hfresh Heval.
  unfold eval_boot_state in Heval; cbv zeta in Heval.
  destruct (negb (tmr_mac_valid (st_tmr st0))) eqn:Emac0; [discriminate|].
  apply Bool.negb_false_iff in Emac0.
  destruct (step1_mailbox_consume (st_slots st0) (st_wal st0) (st_tmr st0))
    as [err | s1 w1 t1] eqn:Embx; [discriminate|].
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Embx)
    as [_ [_ [_ [_ [_ [_ [_ [_ [Han1 [_ [Hmac1 Hseq1]]]]]]]]]]].
  destruct (wal_reconstruct_txn w1) as [[oi1 oe1]|] eqn:Ew1; [|discriminate].
  destruct (step2_confirm_check s1 w1 t1 (st_confirm st0) oi1 oe1)
    as [|s2 w2 t2 c2 oi2 h2] eqn:Es2; [discriminate|].
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Es2)
    as [_ [_ [_ [_ [Hmbx2 [_ [Hseq2 [Hiss2 Hmac2]]]]]]]].
  destruct (step2_5_cloud_cmd s2 w2 t2 (st_otp st0) oi2)
    as [[[[s25 w25] t25] otp25] oi25] eqn:Es25.
  pose proof (step2_5_cloud_preserves_images _ _ _ _ _ _ _ _ _ _ Es25)
    as [_ [_ [_ [_ [Hmbx25 [_ [_ [_ [_ [_ [_ [Hseq25 Hmac25]]]]]]]]]]]].
  destruct (wal_intent_eqb oi25 WI_DeviceLocked) eqn:Elock; [discriminate|].
  destruct (step3_failure_and_rollback cfg s25 w25 t25 (st_reset st0) oi25 h2)
    as [e3 t3p | s3 w3 t3 oi3 h3 r3] eqn:Es3; [discriminate|].
  destruct (step4_update_pipeline s3 w3 t3 otp25 oi3)
    as [[[[s4 w4] t4] oi4] upd4] eqn:Es4.
  cbv zeta in Heval.
  set (fb := negb r3 && negb (hdr_valid (app_slot s4)) && recovery_rom_valid s4 &&
             (recovery_failure_counter t4 <=? cfg_max_recovery_retries cfg)) in *.
  destruct (negb (if r3 || fb then recovery_rom_valid s4 else hdr_valid (app_slot s4))); [discriminate|].
  destruct (r3 || fb); [discriminate|].
  assert (Htent : wal_intent_eqb oi4 WI_TxnCommit = true) by (inversion Heval; reflexivity).
  apply wal_intent_eqb_eq in Htent; subst oi4.
  inversion Heval; subst img gen_nonce st1; clear Heval; simpl in *.
  assert (Hs3_meta :
    tmr_mac_valid t3 = true /\
    last_mbx_seq t3 = last_mbx_seq t1 /\
    last_cloud_issued_at t3 = last_cloud_issued_at t25 /\
    mailbox_slot s3 = mailbox_slot s25 /\
    cloud_slot s3 = cloud_slot s25).
  { unfold step3_failure_and_rollback in Es3; cbv zeta in Es3.
    set (ta := if (negb h2 &&
                   ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                    (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                  crash_accum_applicable oi25
               then apply_crash_accum cfg t25 else t25) in *.
    assert (Hta : tmr_mac_valid ta = true /\ last_mbx_seq ta = last_mbx_seq t1 /\
                  last_cloud_issued_at ta = last_cloud_issued_at t25).
    { unfold ta, apply_crash_accum.
      destruct ((negb h2 &&
                 ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                  (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                crash_accum_applicable oi25);
        [destruct (cfg_max_retries cfg <? boot_failure_counter t25); simpl; repeat split; congruence
        | repeat split; congruence]. }
    destruct (wal_intent_eqb oi25 WI_TxnRollback); [inversion Es3; subst; simpl; intuition congruence|].
    destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi25 WI_TxnRollbackPending).
    - destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending).
      + destruct (rst_indicates_crash (st_reset st0) && negb h2 ||
                  wal_intent_eqb oi25 WI_TxnRollbackPending ||
                  (cfg_max_retries cfg <? boot_failure_counter ta)).
        * destruct (negb (hdr_valid (backup_slot s25))); [discriminate | inversion Es3; subst; simpl; intuition congruence].
        * inversion Es3; subst; intuition congruence.
      + destruct (boot_failure_counter ta <=? cfg_max_retries cfg);
          [inversion Es3; subst; intuition congruence|].
        destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg);
          [inversion Es3; subst; intuition congruence | discriminate].
    - inversion Es3; subst; intuition congruence. }
  destruct Hs3_meta as [Hmac3 [Hseq3 [Hiss3 [Hmbx3 Hcld3]]]].
  assert (Hs4_meta :
    tmr_mac_valid t4 = true /\
    last_mbx_seq t4 = last_mbx_seq t1 /\
    last_cloud_issued_at t4 = last_cloud_issued_at t25 /\
    mailbox_slot s4 = mailbox_slot s25 /\
    cloud_slot s4 = cloud_slot s25).
  { unfold step4_update_pipeline in Es4; cbv zeta in Es4.
    destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)).
    - inversion Es4; subst; repeat split; assumption.
    - destruct (staging_can_apply (staging_slot s3) t3 otp25);
        [inversion Es4; subst; simpl; repeat split; assumption | discriminate]. }
  destruct Hs4_meta as [Hmac4 [Hseq4 [Hiss4 [Hmbx4 Hcld4]]]].
  assert (Hc2_zero :
    0 < active_nonce (st_tmr st0) ->
    rtc_nonce (st_confirm st0) = active_nonce (st_tmr st0) ->
    c2 = mkConfirmStore 0).
  { intros Hpos Heq_rtc.
    unfold step2_confirm_check in Es2; cbv zeta in Es2.
    rewrite Han1 in Es2.
    assert (Hlt : (0 <? active_nonce (st_tmr st0)) = true) by (apply Nat.ltb_lt; exact Hpos).
    assert (Heqb : (rtc_nonce (st_confirm st0) =? active_nonce (st_tmr st0)) = true)
      by (apply Nat.eqb_eq; exact Heq_rtc).
    rewrite Hlt, Heqb in Es2; simpl in Es2.
    destruct (wal_intent_eqb oi1 WI_UpdatePending).
    - destruct (reconstruct_aux_entries (wal_entries w1)); try discriminate;
        inversion Es2; reflexivity.
    - destruct (negb (wal_intent_eqb oi1 WI_DeviceLocked) &&
                (wal_intent_eqb oi1 WI_ConfirmCommit || wal_intent_eqb oi1 WI_RecoveryResolved || true)).
      + simpl in Es2.
        destruct (if wal_intent_eqb oi1 WI_None then WI_ConfirmCommit else oi1);
          inversion Es2; reflexivity.
      + inversion Es2; reflexivity. }
  split_conj; try reflexivity; try exact Hfresh; try exact Hc2_zero.
  intros old_n rst_next Hold_ne; cbv zeta.
  set (tmr_b1 := set_tmr_nonce t4 (cfg_fresh_nonce cfg)).
  set (wal_b1 := wal_append_valid w4 WI_TxnCommit 0).
  assert (Hmbx_next :
    step1_mailbox_consume s4 wal_b1 tmr_b1 = Mbx_Done s4 wal_b1 tmr_b1).
  { eapply step1_mailbox_idempotent_after_run; [exact Embx | simpl; lia | congruence]. }
  assert (Hcld_next :
    step2_5_cloud_cmd s4 wal_b1 tmr_b1 otp25 WI_TxnCommit =
      (s4, wal_b1, tmr_b1, otp25, WI_TxnCommit)).
  { eapply step2_5_cloud_idempotent_after_run; [exact Es25 | simpl; congruence | congruence]. }
  unfold eval_boot_state; cbv zeta; simpl.
  rewrite Hmac4; simpl; rewrite Hmbx_next; simpl.
  unfold step2_confirm_check; cbv zeta; simpl.
  assert (Hlt_fn : (0 <? cfg_fresh_nonce cfg) = true) by (apply Nat.ltb_lt; exact Hfresh).
  assert (Heq_old : (old_n =? cfg_fresh_nonce cfg) = false) by (apply Nat.eqb_neq; exact Hold_ne).
  rewrite Hlt_fn, Heq_old; simpl.
  rewrite Hcld_next; simpl.
  unfold step3_failure_and_rollback; cbv zeta; simpl.
  set (ta2 := apply_crash_accum cfg tmr_b1).
  assert (Hpos_ta2 : (0 <? boot_failure_counter ta2) = true).
  { unfold ta2, apply_crash_accum.
    destruct (cfg_max_retries cfg <? boot_failure_counter tmr_b1) eqn:E; cbn [boot_failure_counter].
    - apply Nat.ltb_lt in E; apply Nat.ltb_lt; lia.
    - reflexivity. }
  rewrite Hpos_ta2; simpl.
  rewrite ?Bool.andb_true_r, ?Bool.orb_false_r.
  destruct (rst_indicates_crash rst_next || (cfg_max_retries cfg <? boot_failure_counter ta2)); simpl.
  - destruct (negb (hdr_valid (backup_slot s4))); simpl.
    + split; intros; discriminate.
    + unfold step4_update_pipeline; simpl; cbv zeta.
      set (fb2 := negb (hdr_valid (backup_slot s4)) && recovery_rom_valid s4 &&
                  (recovery_failure_counter ta2 <=? cfg_max_recovery_retries cfg)).
      destruct (negb (if fb2 then recovery_rom_valid s4 else hdr_valid (backup_slot s4)));
        [split; intros; discriminate|].
      destruct fb2; [split; intros; discriminate|].
      split; intros img2 n2 Hout2; inversion Hout2; subst; simpl; split; reflexivity.
  - unfold step4_update_pipeline; simpl; cbv zeta.
    set (fb2 := negb (hdr_valid (app_slot s4)) && recovery_rom_valid s4 &&
                (recovery_failure_counter ta2 <=? cfg_max_recovery_retries cfg)).
    destruct (negb (if fb2 then recovery_rom_valid s4 else hdr_valid (app_slot s4)));
      [split; intros; discriminate|].
    destruct fb2; [split; intros; discriminate|].
    split; intros img2 n2 Hout2; inversion Hout2; subst; simpl; split; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 9: Extension Theorem 4 — Offline SPI-Flash Tamper (K4 MAC          *)
(*            Fail-Closed) & Dual-Failure Escalation to Enter_Serial_Rescue   *)
(* ========================================================================== *)

Theorem k4_spi_tamper_fail_closed :
  forall cfg st,
    let '(out, st') := eval_boot_state cfg st in
    otp_min_svn (st_otp st) <= otp_min_svn (st_otp st') /\
    (tmr_mac_valid (st_tmr st) = false ->
       out = Enter_Recovery_OS (RM_SerialRescue Err_Verify) /\
       st' = st /\
       (forall img tent n, out <> Boot_App img tent n)) /\
    (forall s1 w1 t1,
       tmr_mac_valid (st_tmr st) = true ->
       step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) = Mbx_Done s1 w1 t1 ->
       wal_reconstruct_txn w1 = None ->
       out = Enter_Recovery_OS (RM_SerialRescue Err_Verify) /\
       app_slot (st_slots st') = app_slot (st_slots st) /\
       otp_min_svn (st_otp st') = otp_min_svn (st_otp st) /\
       wal_reconstruct_txn (st_wal st') = None /\
       (forall img tent n, out <> Boot_App img tent n)) /\
    (forall s1 w1 t1 exp1,
       tmr_mac_valid (st_tmr st) = true ->
       step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) = Mbx_Done s1 w1 t1 ->
       wal_reconstruct_txn w1 = Some (WI_UpdatePending, exp1) ->
       reconstruct_aux_entries (wal_entries w1) = Aux_Tampered ->
       out = Enter_Recovery_OS (RM_SerialRescue Err_Verify) /\
       app_slot (st_slots st') = app_slot (st_slots st) /\
       otp_min_svn (st_otp st') = otp_min_svn (st_otp st) /\
       active_nonce (st_tmr st') = active_nonce (st_tmr st) /\
       (forall img tent n, out <> Boot_App img tent n)).
Proof.
  intros cfg st.
  destruct (eval_boot_state cfg st) as [out st'] eqn:Hev.
  split; [|split; [|split]].
  - unfold eval_boot_state in Hev; cbv zeta in Hev.
    destruct (negb (tmr_mac_valid (st_tmr st))); [inversion Hev; subst; lia|].
    destruct (step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st)) as [? | s1 w1 t1];
      [inversion Hev; subst; lia|].
    destruct (wal_reconstruct_txn w1) as [[oi1 oe1]|]; [|inversion Hev; subst; simpl; lia].
    destruct (step2_confirm_check s1 w1 t1 (st_confirm st) oi1 oe1) as [|s2 w2 t2 c2 oi2 h2];
      [inversion Hev; subst; simpl; lia|].
    destruct (step2_5_cloud_cmd s2 w2 t2 (st_otp st) oi2)
      as [[[[s25 w25] t25] otp25] oi25] eqn:Es25.
    pose proof (step2_5_cloud_preserves_images _ _ _ _ _ _ _ _ _ _ Es25)
      as [_ [_ [_ [_ [_ [Hotp_le _]]]]]].
    destruct (wal_intent_eqb oi25 WI_DeviceLocked); [inversion Hev; subst; simpl; exact Hotp_le|].
    destruct (step3_failure_and_rollback cfg s25 w25 t25 (st_reset st) oi25 h2)
      as [? ? | s3 w3 t3 oi3 h3 r3];
      [inversion Hev; subst; simpl; exact Hotp_le|].
    destruct (step4_update_pipeline s3 w3 t3 otp25 oi3) as [[[[s4 w4] t4] oi4] upd4].
    cbv zeta in Hev.
    destruct (negb (if r3 || (negb r3 && negb (hdr_valid (app_slot s4)) &&
                              recovery_rom_valid s4 &&
                              (recovery_failure_counter t4 <=? cfg_max_recovery_retries cfg))
                    then recovery_rom_valid s4 else hdr_valid (app_slot s4)));
      [inversion Hev; subst; simpl; exact Hotp_le|].
    destruct (r3 || (negb r3 && negb (hdr_valid (app_slot s4)) &&
                     recovery_rom_valid s4 &&
                     (recovery_failure_counter t4 <=? cfg_max_recovery_retries cfg)));
      inversion Hev; subst; simpl; exact Hotp_le.
  - intro Hmac_f; unfold eval_boot_state in Hev; rewrite Hmac_f in Hev; simpl in Hev.
    inversion Hev; subst; split_conj; try reflexivity; intros; discriminate.
  - intros s1 w1 t1 Hmac_t Hmbx Hwnone.
    pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx) as [Happ1 _].
    unfold eval_boot_state in Hev; rewrite Hmac_t in Hev; simpl in Hev.
    rewrite Hmbx, Hwnone in Hev.
    inversion Hev; subst; simpl; split_conj; try reflexivity; try assumption; intros; discriminate.
  - intros s1 w1 t1 exp1 Hmac_t Hmbx Hwup Haux.
    pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hmbx)
      as [Happ1 [_ [_ [_ [_ [_ [_ [_ [Han1 _]]]]]]]]].
    unfold eval_boot_state in Hev; rewrite Hmac_t in Hev; simpl in Hev.
    rewrite Hmbx, Hwup in Hev.
    unfold step2_confirm_check in Hev; cbv zeta in Hev; simpl in Hev.
    rewrite Haux in Hev.
    inversion Hev; subst; simpl; split_conj; try reflexivity; try assumption; intros; discriminate.
Qed.

(* -------------------------------------------------------------------------- *)
(* 9B. Dual-Failure Escalation Liveness to Enter_Serial_Rescue                *)
(* -------------------------------------------------------------------------- *)

Definition StabilizedPostBoot (st : State) : Prop :=
  tmr_mac_valid (st_tmr st) = true /\
  rtc_nonce (st_confirm st) = 0 /\
  step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st) =
    Mbx_Done (st_slots st) (st_wal st) (st_tmr st) /\
  (forall w t i,
     last_cloud_issued_at t = last_cloud_issued_at (st_tmr st) ->
     step2_5_cloud_cmd (st_slots st) w t (st_otp st) i =
       (st_slots st, w, t, st_otp st, i)).

Lemma dual_fault_non_tentative_escalates :
  forall rem cfg fault_rst fuel st,
    StabilizedPostBoot st ->
    st_reset st = fault_rst ->
    rst_indicates_crash fault_rst = true ->
    active_nonce (st_tmr st) = 0 ->
    ((exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_None, exp_n)) \/
     exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_ConfirmCommit, exp_n)) ->
    (cfg_max_retries cfg + 1 - boot_failure_counter (st_tmr st)) +
    (cfg_max_recovery_retries cfg + 1 - recovery_failure_counter (st_tmr st)) <= rem ->
    rem <= fuel ->
    let '(out, _, reboots) :=
      run_dual_fault_until_serial_rescue cfg fault_rst fuel st in
    reboots <= rem /\ is_serial_rescue_outcome out = true.
Proof.
  induction rem as [|rem' IH];
    intros cfg fault_rst fuel st Hstab Hrst Hcrash Han0 Hwal Hmu Hfuel.
  - assert (Hbf_gt : cfg_max_retries cfg < boot_failure_counter (st_tmr st)) by lia.
    assert (Hrf_gt : cfg_max_recovery_retries cfg < recovery_failure_counter (st_tmr st)) by lia.
    destruct Hstab as [Hmac [Hrtc0 [Hmbx Hcld]]].
    assert (Hs2_eq :
      exists oi1 oe1,
        wal_reconstruct_txn (st_wal st) = Some (oi1, oe1) /\
        step2_confirm_check (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) oi1 oe1 =
          S2_Ok (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) WI_None false).
    { destruct Hwal as [[en Hn] | [en Hcc]].
      - exists WI_None, en; split; [exact Hn | unfold step2_confirm_check; cbv zeta; rewrite Han0; reflexivity].
      - exists WI_ConfirmCommit, en; split; [exact Hcc | unfold step2_confirm_check; cbv zeta; rewrite Han0; reflexivity]. }
    destruct Hs2_eq as [oi1 [oe1 [Hwrec Hs2]]].
    assert (Hev : exists st_p,
      eval_boot_state cfg st = (Enter_Recovery_OS (RM_SerialRescue Err_RecoveryRequested), st_p)).
    { unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl; rewrite Hmbx, Hwrec, Hs2, Hcld by reflexivity; simpl.
      unfold step3_failure_and_rollback; cbv zeta; rewrite Hrst, Hcrash; simpl.
      unfold apply_crash_accum.
      assert (Eltb : (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) = true)
        by (apply Nat.ltb_lt; exact Hbf_gt).
      assert (Epos : (0 <? boot_failure_counter (st_tmr st)) = true)
        by (apply Nat.ltb_lt; lia).
      assert (Ele_b : (boot_failure_counter (st_tmr st) <=? cfg_max_retries cfg) = false)
        by (apply Nat.leb_gt; exact Hbf_gt).
      assert (Ele_r : (S (recovery_failure_counter (st_tmr st)) <=? cfg_max_recovery_retries cfg) = false)
        by (apply Nat.leb_gt; lia).
      rewrite Eltb; simpl; rewrite Epos, Ele_b, Ele_r; simpl; eexists; reflexivity. }
    destruct Hev as [st_p Hev].
    destruct fuel as [|fuel']; (simpl; rewrite Hev; simpl; split; [lia | reflexivity]).
  - assert (Hfuel_pos : exists fuel', fuel = S fuel').
    { destruct fuel as [|f']; [lia | exists f'; reflexivity]. }
    destruct Hfuel_pos as [fuel' Hfeq]; subst fuel; simpl.
    destruct Hstab as [Hmac [Hrtc0 [Hmbx Hcld]]].
    assert (Hs2_eq :
      exists oi1 oe1,
        wal_reconstruct_txn (st_wal st) = Some (oi1, oe1) /\
        step2_confirm_check (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) oi1 oe1 =
          S2_Ok (st_slots st) (st_wal st) (st_tmr st) (st_confirm st) WI_None false).
    { destruct Hwal as [[en Hn] | [en Hcc]].
      - exists WI_None, en; split; [exact Hn | unfold step2_confirm_check; cbv zeta; rewrite Han0; reflexivity].
      - exists WI_ConfirmCommit, en; split; [exact Hcc | unfold step2_confirm_check; cbv zeta; rewrite Han0; reflexivity]. }
    destruct Hs2_eq as [oi1 [oe1 [Hwrec Hs2]]].
    assert (Hs3_cases :
      (exists err t_p,
         step3_failure_and_rollback cfg (st_slots st) (st_wal st) (st_tmr st)
           (st_reset st) WI_None false = S3_Panic err t_p) \/
      (exists bf_n rf_n rec3,
         (cfg_max_retries cfg + 1 - bf_n) +
         (cfg_max_recovery_retries cfg + 1 - rf_n) <= rem' /\
         step3_failure_and_rollback cfg (st_slots st) (st_wal st) (st_tmr st)
           (st_reset st) WI_None false =
           S3_Ok (st_slots st) (st_wal st)
             (mkTMR (tmr_app_svn (st_tmr st)) (tmr_stage1_svn (st_tmr st))
                    bf_n rf_n (active_nonce (st_tmr st))
                    (last_mbx_seq (st_tmr st)) (last_cloud_issued_at (st_tmr st))
                    (tmr_mac_valid (st_tmr st)))
             WI_None false rec3)).
    { unfold step3_failure_and_rollback; cbv zeta; rewrite Hrst, Hcrash; simpl.
      unfold apply_crash_accum.
      destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st)) eqn:Eltb; simpl.
      - apply Nat.ltb_lt in Eltb.
        assert (Epos : (0 <? boot_failure_counter (st_tmr st)) = true) by (apply Nat.ltb_lt; lia).
        assert (Ele_b : (boot_failure_counter (st_tmr st) <=? cfg_max_retries cfg) = false)
          by (apply Nat.leb_gt; exact Eltb).
        rewrite Epos, Ele_b; simpl.
        destruct (S (recovery_failure_counter (st_tmr st)) <=? cfg_max_recovery_retries cfg) eqn:Ele_r.
        + apply Nat.leb_le in Ele_r; right.
          exists (boot_failure_counter (st_tmr st)), (S (recovery_failure_counter (st_tmr st))), true.
          split; [lia | reflexivity].
        + left; eexists _, _; reflexivity.
      - apply Nat.ltb_ge in Eltb.
        destruct (S (boot_failure_counter (st_tmr st)) <=? cfg_max_retries cfg) eqn:Ele_b; simpl.
        + apply Nat.leb_le in Ele_b; right.
          exists (S (boot_failure_counter (st_tmr st))), (recovery_failure_counter (st_tmr st)), false.
          split; [lia | reflexivity].
        + destruct (recovery_failure_counter (st_tmr st) <=? cfg_max_recovery_retries cfg) eqn:Ele_r.
          * right.
            exists (S (boot_failure_counter (st_tmr st))), (recovery_failure_counter (st_tmr st)), true.
            split; [apply Nat.leb_gt in Ele_b; lia | reflexivity].
          * left; eexists _, _; reflexivity. }
    destruct Hs3_cases as [[err [t_p Hs3]] | [bf_n [rf_n [rec3 [Hmu_n Hs3]]]]].
    + unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl.
      rewrite Hmbx, Hwrec, Hs2, Hcld, Hs3 by reflexivity; simpl.
      split; [lia | reflexivity].
    + unfold eval_boot_state; cbv zeta; rewrite Hmac; simpl.
      rewrite Hmbx, Hwrec, Hs2, Hcld, Hs3 by reflexivity; simpl.
      unfold step4_update_pipeline, set_tmr_nonce; simpl; cbv iota zeta.
      set (fb := negb rec3 && negb (hdr_valid (app_slot (st_slots st))) &&
                 recovery_rom_valid (st_slots st) && (rf_n <=? cfg_max_recovery_retries cfg)).
      destruct (negb (if rec3 || fb then recovery_rom_valid (st_slots st)
                      else hdr_valid (app_slot (st_slots st)))).
      * simpl; split; [lia | reflexivity].
      * set (st1 := mkState (st_slots st) (st_wal st)
                      (mkTMR (tmr_app_svn (st_tmr st)) (tmr_stage1_svn (st_tmr st))
                             bf_n rf_n 0 (last_mbx_seq (st_tmr st))
                             (last_cloud_issued_at (st_tmr st)) (tmr_mac_valid (st_tmr st)))
                      (st_confirm st) (st_otp st) (st_reset st)).
        destruct (rec3 || fb); cbv iota zeta; cbn [is_serial_rescue_outcome]; cbv iota zeta;
        (set (st_next := next_dual_fault_reboot_state fault_rst st1);
         assert (Hstab_n : StabilizedPostBoot st_next) by
           (unfold StabilizedPostBoot, st_next, next_dual_fault_reboot_state, st1; simpl;
            split_conj; [exact Hmac | reflexivity
                        | eapply step1_mailbox_idempotent_after_run; [exact Hmbx | simpl; lia | reflexivity]
                        | intros w t i Ht; apply Hcld; exact Ht]);
         specialize (IH cfg fault_rst fuel' st_next Hstab_n eq_refl Hcrash eq_refl Hwal
                       ltac:(unfold st_next, st1; simpl; lia) ltac:(lia));
         destruct (run_dual_fault_until_serial_rescue cfg fault_rst fuel' st_next) as [[of sf] rb];
         cbv iota zeta; destruct IH as [Hrb Hsr]; split; [lia | exact Hsr]).
Qed.

Lemma post_non_rescue_stabilizes :
  forall cfg fault_rst st0 out0 st1,
    rst_indicates_crash fault_rst = true ->
    eval_boot_state cfg st0 = (out0, st1) ->
    is_serial_rescue_outcome out0 = false ->
    let st_next := next_dual_fault_reboot_state fault_rst st1 in
    StabilizedPostBoot st_next /\
    st_reset st_next = fault_rst /\
    (wal_reconstruct_txn (st_wal st_next) = Some (WI_TxnCommit, 0) \/
     (active_nonce (st_tmr st_next) = 0 /\
      ((exists exp_n, wal_reconstruct_txn (st_wal st_next) = Some (WI_None, exp_n)) \/
       exists exp_n, wal_reconstruct_txn (st_wal st_next) = Some (WI_ConfirmCommit, exp_n)))).
Proof.
  intros cfg fault_rst st0 out0 st1 Hcrash Hev Hnr st_next.
  unfold eval_boot_state in Hev; cbv zeta in Hev.
  destruct (negb (tmr_mac_valid (st_tmr st0))) eqn:Emac; [inversion Hev; subst; discriminate|].
  apply Bool.negb_false_iff in Emac.
  destruct (step1_mailbox_consume (st_slots st0) (st_wal st0) (st_tmr st0))
    as [e1 | s1 w1 t1] eqn:Embx; [inversion Hev; subst; discriminate|].
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Embx)
    as [_ [_ [_ [_ [_ [_ [_ [_ [_ [_ [Hmac1 _]]]]]]]]]]].
  destruct (wal_reconstruct_txn w1) as [[oi1 oe1]|] eqn:Ew1;
    [|inversion Hev; subst; discriminate].
  destruct (step2_confirm_check s1 w1 t1 (st_confirm st0) oi1 oe1)
    as [|s2 w2 t2 c2 oi2 h2] eqn:Es2; [inversion Hev; subst; discriminate|].
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Es2)
    as [_ [_ [_ [_ [Hmbx2 [_ [Hseq2 [_ Hmac2]]]]]]]].
  destruct (step2_5_cloud_cmd s2 w2 t2 (st_otp st0) oi2)
    as [[[[s25 w25] t25] otp25] oi25] eqn:Es25.
  pose proof (step2_5_cloud_preserves_images _ _ _ _ _ _ _ _ _ _ Es25)
    as [_ [_ [_ [_ [Hmbx25 [_ [_ [_ [_ [_ [_ [Hseq25 Hmac25]]]]]]]]]]]].
  destruct (wal_intent_eqb oi25 WI_DeviceLocked) eqn:Elock;
    [inversion Hev; subst; discriminate|].
  destruct (step3_failure_and_rollback cfg s25 w25 t25 (st_reset st0) oi25 h2)
    as [e3 t3p | s3 w3 t3 oi3 h3 r3] eqn:Es3;
    [inversion Hev; subst; discriminate|].
  destruct (step4_update_pipeline s3 w3 t3 otp25 oi3)
    as [[[[s4 w4] t4] oi4] upd4] eqn:Es4.
  cbv zeta in Hev.
  set (fb := negb r3 && negb (hdr_valid (app_slot s4)) && recovery_rom_valid s4 &&
             (recovery_failure_counter t4 <=? cfg_max_recovery_retries cfg)) in *.
  destruct (negb (if r3 || fb then recovery_rom_valid s4 else hdr_valid (app_slot s4)));
    [inversion Hev; subst; discriminate|].
  assert (Hs2_oi :
    oi2 = WI_UpdatePending \/ oi2 = WI_TxnCommit \/ oi2 = WI_TxnRollback \/
    oi2 = WI_TxnRollbackPending \/ oi2 = WI_DeviceLocked \/
    (oi2 = WI_None /\ h2 = true) \/
    (oi2 = WI_None /\ h2 = false /\ w2 = w1 /\ (oi1 = WI_None \/ oi1 = WI_ConfirmCommit))).
  { unfold step2_confirm_check in Es2; cbv zeta in Es2.
    destruct (wal_intent_eqb oi1 WI_UpdatePending) eqn:Eup.
    - apply wal_intent_eqb_eq in Eup; subst oi1.
      destruct (reconstruct_aux_entries (wal_entries w1)); try discriminate.
      + destruct ((0 <? active_nonce t1) && (rtc_nonce (st_confirm st0) =? active_nonce t1));
          inversion Es2; left; reflexivity.
      + destruct (((0 <? active_nonce t1) && (rtc_nonce (st_confirm st0) =? active_nonce t1)) ||
                  (wal_intent_eqb w WI_ConfirmCommit && (0 <? active_nonce t1) &&
                   (0 <? n) && (n =? active_nonce t1)) ||
                  wal_intent_eqb w WI_RecoveryResolved);
          inversion Es2; left; reflexivity.
    - destruct (0 <? active_nonce t1),
               (rtc_nonce (st_confirm st0) =? active_nonce t1),
               (0 <? oe1),
               (oe1 =? active_nonce t1),
               oi1;
        try discriminate Eup; simpl in Es2; inversion Es2; subst; intuition auto 15. }
  assert (Hs25_oi :
    (oi25 = oi2 /\ w25 = w2) \/
    (oi25 = WI_None /\ wal_reconstruct_txn w25 = Some (WI_None, 0)) \/
    oi25 = WI_UpdatePending \/ oi25 = WI_DeviceLocked).
  { unfold step2_5_cloud_cmd in Es25; cbv zeta in Es25.
    destruct (cloud_slot s2) as [|cmd sig_ok dev_ok ctr iss]; [inversion Es25; auto|].
    destruct (negb (sig_ok && dev_ok &&
                    ((otp_min_svn (st_otp st0) <? ctr) &&
                     (last_cloud_issued_at t2 <? iss) &&
                     (ctr - otp_min_svn (st_otp st0) <=? toob_cmd_max_burn_steps))));
      [inversion Es25; auto
      | destruct cmd; try destruct (wal_intent_eqb oi2 WI_DeviceLocked); inversion Es25; auto]. }
  assert (Hs3_out :
    tmr_mac_valid t3 = true /\
    last_mbx_seq t3 = last_mbx_seq t1 /\
    last_cloud_issued_at t3 = last_cloud_issued_at t25 /\
    mailbox_slot s3 = mailbox_slot s25 /\
    cloud_slot s3 = cloud_slot s25 /\
    (oi3 = WI_UpdatePending \/ oi3 = WI_TxnCommit \/
     (oi3 = WI_None /\
      (h3 = true \/
       ((exists en, wal_reconstruct_txn w3 = Some (WI_None, en)) \/
        exists en, wal_reconstruct_txn w3 = Some (WI_ConfirmCommit, en)))))).
  { assert (H25_clean :
      oi25 <> WI_DeviceLocked /\ oi25 <> WI_ConfirmCommit /\ oi25 <> WI_RecoveryResolved /\
      (oi25 = WI_None /\ h2 = false ->
         (exists en, wal_reconstruct_txn w25 = Some (WI_None, en)) \/
         exists en, wal_reconstruct_txn w25 = Some (WI_ConfirmCommit, en))).
    { assert (Hnd : oi25 <> WI_DeviceLocked) by (intro H; subst; discriminate).
      destruct Hs25_oi as [[Ei Ew] | [[En Ewn] | [Eup | Edl]]].
      - subst oi25 w25; repeat split; try exact Hnd;
          [intro Hc; subst oi2; intuition discriminate
          |intro Hr; subst oi2; intuition discriminate|].
        intros [Hn Hh]; subst oi2 h2.
        destruct Hs2_oi as [?|[?|[?|[?|[?|[[_ ?]|[_ [_ [Ew2 Eo1]]]]]]]]]; try discriminate.
        subst w2; destruct Eo1 as [Eo1|Eo1]; subst oi1;
          [left; exists oe1; exact Ew1 | right; exists oe1; exact Ew1].
      - subst oi25; repeat split; try discriminate; intros _; left; exists 0; exact Ewn.
      - subst oi25; repeat split; try discriminate; intros [? _]; discriminate.
      - contradiction. }
    destruct H25_clean as [Hnd [Hncc [Hnrr Hn25]]].
    unfold step3_failure_and_rollback in Es3; cbv zeta in Es3.
    set (ta := if (negb h2 &&
                   ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                    (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                  crash_accum_applicable oi25
               then apply_crash_accum cfg t25 else t25) in *.
    assert (Hta : tmr_mac_valid ta = true /\ last_mbx_seq ta = last_mbx_seq t1 /\
                  last_cloud_issued_at ta = last_cloud_issued_at t25).
    { unfold ta, apply_crash_accum.
      destruct ((negb h2 &&
                 ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                  (rst_indicates_crash (st_reset st0) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                crash_accum_applicable oi25);
        [destruct (cfg_max_retries cfg <? boot_failure_counter t25); simpl; split_conj; congruence
        | split_conj; congruence]. }
    destruct Hta as [Hta_m [Hta_s Hta_i]].
    destruct (wal_intent_eqb oi25 WI_TxnRollback) eqn:Etrb.
    - inversion Es3; subst; simpl; split_conj;
        try exact Hta_m; try exact Hta_s; try exact Hta_i; try reflexivity.
      right; right; split; [reflexivity | left; reflexivity].
    - destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi25 WI_TxnRollbackPending) eqn:Ehf.
      + destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending) eqn:Eca.
        * destruct (rst_indicates_crash (st_reset st0) && negb h2 ||
                    wal_intent_eqb oi25 WI_TxnRollbackPending ||
                    (cfg_max_retries cfg <? boot_failure_counter ta)) eqn:Emr.
          -- destruct (negb (hdr_valid (backup_slot s25))); [discriminate|].
             inversion Es3; subst; simpl; split_conj;
               try exact Hta_m; try exact Hta_s; try exact Hta_i; try reflexivity.
             right; right; split; [reflexivity | left; reflexivity].
          -- assert (Htc : oi25 = WI_TxnCommit)
               by (destruct oi25; simpl in *; rewrite ?Bool.orb_true_r in Emr; simpl in Emr; try discriminate; reflexivity).
             subst oi25; inversion Es3; subst; split_conj;
               try exact Hta_m; try exact Hta_s; try exact Hta_i; try reflexivity.
             right; left; reflexivity.
        * assert (Hcases25 : oi25 = WI_UpdatePending \/ oi25 = WI_None).
          { destruct oi25; simpl in *; try contradiction; try discriminate; auto. }
          destruct (boot_failure_counter ta <=? cfg_max_retries cfg);
            [|destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg); [|discriminate]];
            (inversion Es3; subst; split_conj;
             [exact Hta_m | exact Hta_s | exact Hta_i | reflexivity | reflexivity |
              destruct Hcases25 as [Hu | Hn]; [left; exact Hu | right; right; split; [exact Hn|];
                destruct h3; [left; reflexivity | right; apply Hn25; auto]]]).
      + apply Bool.orb_false_iff in Ehf as [_ Enrp].
        assert (Hcases25 : oi25 = WI_UpdatePending \/ oi25 = WI_TxnCommit \/ oi25 = WI_None).
        { destruct oi25; simpl in *; try contradiction; try discriminate; auto. }
        inversion Es3; subst; split_conj;
          [exact Hta_m | exact Hta_s | exact Hta_i | reflexivity | reflexivity |].
        destruct Hcases25 as [Hu | [Htc | Hn]]; [left; exact Hu | right; left; exact Htc |].
        right; right; split; [exact Hn | destruct h3; [left; reflexivity | right; apply Hn25; auto]]. }
  destruct Hs3_out as [Hmac3 [Hseq3 [Hiss3 [Hmbx3 [Hcld3 Hoi3]]]]].
  assert (Hs4_out :
    tmr_mac_valid t4 = true /\
    last_mbx_seq t4 = last_mbx_seq t1 /\
    last_cloud_issued_at t4 = last_cloud_issued_at t25 /\
    mailbox_slot s4 = mailbox_slot s25 /\
    cloud_slot s4 = cloud_slot s25 /\
    (oi4 = WI_TxnCommit \/
     (oi4 = WI_None /\
      (h3 = true \/ upd4 = true \/
       ((exists en, wal_reconstruct_txn w4 = Some (WI_None, en)) \/
        exists en, wal_reconstruct_txn w4 = Some (WI_ConfirmCommit, en)))))).
  { unfold step4_update_pipeline in Es4; cbv zeta in Es4.
    destruct Hoi3 as [Hup | [Htc | [Hn Hw3]]]; subst oi3; simpl in Es4.
    - destruct (staging_can_apply (staging_slot s3) t3 otp25);
        inversion Es4; subst; simpl; repeat split; try assumption; auto.
    - inversion Es4; subst; repeat split; try assumption; left; reflexivity.
    - inversion Es4; subst; repeat split; try assumption.
      right; split; [reflexivity | destruct Hw3 as [Hh | Hw]; [left; exact Hh | right; right; exact Hw]]. }
  destruct Hs4_out as [Hmac4 [Hseq4 [Hiss4 [Hmbx4 [Hcld4 Hoi4]]]]].
  assert (Hst1_eq :
    st1 = mkState s4
            (if negb (wal_intent_eqb oi4 WI_None) || h3 || upd4
             then wal_append_valid w4 oi4 0 else w4)
            (set_tmr_nonce t4 (if wal_intent_eqb oi4 WI_TxnCommit then cfg_fresh_nonce cfg else 0))
            c2 otp25 (st_reset st0)).
  { destruct (r3 || fb); inversion Hev; reflexivity. }
  subst st1.
  assert (Hstab_out : StabilizedPostBoot st_next).
  { unfold StabilizedPostBoot, st_next, next_dual_fault_reboot_state; simpl.
    split_conj; [exact Hmac4 | reflexivity | |].
    - eapply step1_mailbox_idempotent_after_run; [exact Embx | simpl; lia | congruence].
    - intros w t i Ht; eapply step2_5_cloud_idempotent_after_run;
        [exact Es25 | simpl in Ht; congruence | congruence]. }
  split; [exact Hstab_out | split; [reflexivity |]].
  destruct Hoi4 as [Htc | [Hn Hrest]]; subst oi4; simpl.
  - left; reflexivity.
  - right; split; [reflexivity |].
    destruct (h3 || upd4) eqn:Ehu; simpl.
    + left; exists 0; reflexivity.
    + apply Bool.orb_false_iff in Ehu as [Eh3 Eupd4]; subst h3 upd4.
      destruct Hrest as [?|[?|Hw4]]; try discriminate; exact Hw4.
Qed.

(* Tight Dual-Failure Escalation Bound from broken App + broken Recovery OS *)
Theorem dual_failure_escalation_tight :
  forall cfg fault_rst st,
    StabilizedPostBoot st ->
    st_reset st = fault_rst ->
    rst_indicates_crash fault_rst = true ->
    active_nonce (st_tmr st) = 0 ->
    ((exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_None, exp_n)) \/
     exists exp_n, wal_reconstruct_txn (st_wal st) = Some (WI_ConfirmCommit, exp_n)) ->
    let bound :=
      (cfg_max_retries cfg + 1 - boot_failure_counter (st_tmr st)) +
      (cfg_max_recovery_retries cfg + 1 - recovery_failure_counter (st_tmr st)) in
    let '(out, _, reboots) :=
      run_dual_fault_until_serial_rescue cfg fault_rst bound st in
    reboots <= bound /\ is_serial_rescue_outcome out = true.
Proof.
  intros cfg fault_rst st Hstab Hrst Hcrash Han0 Hwal bound.
  apply (dual_fault_non_tentative_escalates bound cfg fault_rst bound st
           Hstab Hrst Hcrash Han0 Hwal ltac:(lia) ltac:(lia)).
Qed.

(* Unconditional Dual-Failure Escalation Liveness from EVERY initial State:
   Whenever both App_Slot_0 and Recovery_OS repeatedly fault/reset without
   confirming or resolving, Stage 1 deterministically escalates to
   Enter_Recovery_OS (RM_SerialRescue err) in <= M + R + 4 reboots. *)
Theorem dual_failure_escalation_to_serial_rescue :
  forall cfg fault_rst st0,
    rst_indicates_crash fault_rst = true ->
    let bound := cfg_max_retries cfg + cfg_max_recovery_retries cfg + 4 in
    let '(out, _, reboots) :=
      run_dual_fault_until_serial_rescue cfg fault_rst bound st0 in
    reboots <= bound /\
    exists err, out = Enter_Recovery_OS (RM_SerialRescue err).
Proof.
  intros cfg fault_rst st0 Hcrash bound.
  assert (Hb_split : exists f2 f1, bound = S f2 /\ f2 = S f1 /\
                     (cfg_max_retries cfg + 1) + (cfg_max_recovery_retries cfg + 1) <= f1).
  { unfold bound; exists (cfg_max_retries cfg + cfg_max_recovery_retries cfg + 3),
                         (cfg_max_retries cfg + cfg_max_recovery_retries cfg + 2); lia. }
  destruct Hb_split as [f2 [f1 [Hbeq [Hf2eq Hf1]]]].
  rewrite Hbeq; cbn [run_dual_fault_until_serial_rescue]; cbv iota zeta.
  destruct (eval_boot_state cfg st0) as [out0 st1] eqn:Hev0; cbv iota zeta.
  destruct (is_serial_rescue_outcome out0) eqn:Esr0; cbv iota zeta.
  - destruct out0 as [|[|e0]]; try discriminate.
    split; [lia | exists e0; reflexivity].
  - pose proof (post_non_rescue_stabilizes cfg fault_rst st0 out0 st1 Hcrash Hev0 Esr0) as Hpost1.
    cbv zeta in Hpost1; destruct Hpost1 as [Hstab1 [Hrst1 Hcases1]].
    remember (next_dual_fault_reboot_state fault_rst st1) as st_n1 eqn:Est_n1; clear Est_n1.
    destruct Hcases1 as [Htc1 | [Han1 Hwal1]].
    + rewrite Hf2eq; cbn [run_dual_fault_until_serial_rescue]; cbv iota zeta.
      destruct (eval_boot_state cfg st_n1) as [out1 st2] eqn:Hev1; cbv iota zeta.
      destruct (is_serial_rescue_outcome out1) eqn:Esr1; cbv iota zeta.
      * destruct out1 as [|[|e1]]; try discriminate.
        split; [lia | exists e1; reflexivity].
      * assert (Hrev1 :
          let st_n2 := next_dual_fault_reboot_state fault_rst st2 in
          StabilizedPostBoot st_n2 /\
          st_reset st_n2 = fault_rst /\
          active_nonce (st_tmr st_n2) = 0 /\
          wal_reconstruct_txn (st_wal st_n2) = Some (WI_None, 0)).
        { destruct Hstab1 as [Hm1 [Hrtc1 [Hmb1 Hcl1]]].
          unfold eval_boot_state in Hev1; cbv zeta in Hev1.
          rewrite Hm1 in Hev1; simpl in Hev1; rewrite Hmb1, Htc1 in Hev1.
          unfold step2_confirm_check in Hev1; cbv zeta in Hev1; rewrite Hrtc1 in Hev1.
          assert (Hrf_f : ((0 <? active_nonce (st_tmr st_n1)) && (0 =? active_nonce (st_tmr st_n1))) = false)
            by (destruct (active_nonce (st_tmr st_n1)); reflexivity).
          rewrite Hrf_f in Hev1; simpl in Hev1; rewrite Hcl1 in Hev1 by reflexivity; simpl in Hev1.
          unfold step3_failure_and_rollback in Hev1; cbv zeta in Hev1; rewrite Hrst1, Hcrash in Hev1; simpl in Hev1.
          set (ta := apply_crash_accum cfg (st_tmr st_n1)) in *.
          assert (Epos : (0 <? boot_failure_counter ta) = true).
          { unfold ta, apply_crash_accum.
            destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st_n1)) eqn:E; cbn [boot_failure_counter].
            - apply Nat.ltb_lt in E; apply Nat.ltb_lt; lia.
            - reflexivity. }
          rewrite Epos in Hev1; simpl in Hev1.
          destruct (negb (hdr_valid (backup_slot (st_slots st_n1)))) eqn:Ebh;
            [inversion Hev1; subst; discriminate|].
          unfold step4_update_pipeline in Hev1; simpl in Hev1; cbv zeta in Hev1.
          set (fb2 := negb (hdr_valid (backup_slot (st_slots st_n1))) &&
                      recovery_rom_valid (st_slots st_n1) &&
                      (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg)) in *.
          destruct (negb (if fb2 then recovery_rom_valid (st_slots st_n1)
                          else hdr_valid (backup_slot (st_slots st_n1))));
            [inversion Hev1; subst; discriminate|].
          assert (Hst2 :
            st2 = mkState
                    (mkFlashSlots (backup_slot (st_slots st_n1)) (staging_slot (st_slots st_n1))
                                  (backup_slot (st_slots st_n1)) (recovery_rom_valid (st_slots st_n1))
                                  (cloud_slot (st_slots st_n1)) (mailbox_slot (st_slots st_n1)))
                    (wal_append_valid (wal_append_valid (wal_append_valid (st_wal st_n1) WI_TxnRollbackPending 0)
                                                        WI_TxnRollback 0) WI_None 0)
                    (set_tmr_nonce (clear_boot_failure_and_nonce ta) 0)
                    (st_confirm st_n1) (st_otp st_n1) fault_rst)
            by (destruct fb2; inversion Hev1; reflexivity).
          subst st2; cbv zeta.
          assert (Hta_m : tmr_mac_valid ta = true /\
                          last_mbx_seq ta = last_mbx_seq (st_tmr st_n1) /\
                          last_cloud_issued_at ta = last_cloud_issued_at (st_tmr st_n1)).
          { unfold ta, apply_crash_accum;
              destruct (cfg_max_retries cfg <? boot_failure_counter (st_tmr st_n1));
              simpl; split_conj; assumption || reflexivity. }
          destruct Hta_m as [Htm [Hts Hti]].
          unfold StabilizedPostBoot, next_dual_fault_reboot_state; simpl.
          split_conj; try reflexivity; [exact Htm | | ].
          - eapply step1_mailbox_idempotent_after_run; [exact Hmb1 | simpl; lia | reflexivity].
          - intros w t i Ht; simpl in Ht; rewrite Hti in Ht.
            eapply step2_5_cloud_idempotent_after_run; [exact (Hcl1 w (st_tmr st_n1) i eq_refl) | exact Ht | reflexivity]. }
        cbv zeta in Hrev1.
        remember (next_dual_fault_reboot_state fault_rst st2) as st_n2 eqn:Est_n2; clear Est_n2.
        destruct Hrev1 as [Hstab2 [Hrst2 [Han2 Hwn2]]].
        pose proof (dual_fault_non_tentative_escalates
                      f1 cfg fault_rst f1 st_n2
                      Hstab2 Hrst2 Hcrash Han2 (or_introl (ex_intro _ 0 Hwn2))
                      ltac:(lia) ltac:(lia)) as Hfin.
        destruct (run_dual_fault_until_serial_rescue cfg fault_rst f1 st_n2) as [[of sf] rb]; cbv iota zeta.
        destruct Hfin as [Hrb Hsr].
        destruct of as [|[|ef]]; try discriminate.
        split; [unfold bound in Hbeq; lia | exists ef; reflexivity].
    + pose proof (dual_fault_non_tentative_escalates
                    f2 cfg fault_rst f2 st_n1
                    Hstab1 Hrst1 Hcrash Han1 Hwal1 ltac:(lia) ltac:(lia)) as Hfin.
      destruct (run_dual_fault_until_serial_rescue cfg fault_rst f2 st_n1) as [[of sf] rb]; cbv iota zeta.
      destruct Hfin as [Hrb Hsr].
      destruct of as [|[|ef]]; try discriminate.
      split; [unfold bound in Hbeq; lia | exists ef; reflexivity].
Qed.

(* ========================================================================== *)
(* SECTION 10: Landed Core Synchronization — TDR1-02 & TDR1-03                *)
(*             Pending Metadata Ratification & Telemetry Commit-Point         *)
(* ========================================================================== *)

Fixpoint run_meta_trace (evs : list MetaStepEvent) (meta : TmrAppMeta) : TmrAppMeta :=
  match evs with
  | [] => meta
  | ev :: rest => run_meta_trace rest (fst (eval_tmr_meta_step ev meta))
  end.

Definition has_authenticated_confirm (evs : list MetaStepEvent) : bool :=
  existsb (fun ev => match ev with MSE_ConfirmCommit true => true | _ => false end) evs.

(* Theorem 10.1 (TDR1-02): Ratified vs Pending App Identity Atomicity.
   1. Applying a tentative candidate stages pending_* without mutating ratified app_*.
   2. Unauthenticated confirm, idle, rejection/deferral, and rollback NEVER
      promote pending_* into ratified app_*; rollback explicitly clears pending_*.
   3. Authenticated CONFIRM_COMMIT atomically promotes pending_* -> ratified app_*
      and clears pending_*.
   4. Across any multi-boot trace without an authenticated CONFIRM_COMMIT,
      ratified app_* identity is invariant. *)
Theorem tdr1_02_pending_meta_ratification_atomicity :
  (forall meta cand,
     let '(meta', tent) := eval_tmr_meta_step (MSE_ApplyTentative cand) meta in
     tent = true /\
     tam_ratified meta' = tam_ratified meta /\
     tam_pending meta' = Some cand /\
     select_handoff_persisted_identity true meta' = cand /\
     select_handoff_persisted_identity false meta' = tam_ratified meta) /\
  (forall meta,
     let '(meta', tent) := eval_tmr_meta_step MSE_RollbackRevert meta in
     tent = false /\
     tam_ratified meta' = tam_ratified meta /\
     tam_pending meta' = None /\
     select_handoff_persisted_identity false meta' = tam_ratified meta /\
     select_handoff_persisted_identity true meta' = tam_ratified meta) /\
  (forall rat cand,
     let '(meta', tent) :=
       eval_tmr_meta_step (MSE_ConfirmCommit true) (mkTmrAppMeta rat (Some cand)) in
     tent = false /\
     tam_ratified meta' = cand /\
     tam_pending meta' = None /\
     select_handoff_persisted_identity false meta' = cand) /\
  (forall evs meta,
     has_authenticated_confirm evs = false ->
     tam_ratified (run_meta_trace evs meta) = tam_ratified meta).
Proof.
  split_conj.
  - intros meta cand; simpl; repeat split; reflexivity.
  - intros meta; simpl; repeat split; reflexivity.
  - intros rat cand; simpl; repeat split; reflexivity.
  - induction evs as [|ev rest IH]; intros meta Hno; [reflexivity|].
    simpl in Hno; apply Bool.orb_false_iff in Hno as [Hev Hrest].
    simpl; rewrite (IH _ Hrest).
    destruct ev as [|cand|auth_ok| |]; simpl; try reflexivity.
    destruct auth_ok; [discriminate Hev | reflexivity].
Qed.

(* Theorem 10.2 (TDR1-03): Telemetry Commit-Point Discipline & Pre-Heal Failure
   Preservation.
   1. Outcome UDO_Applied and candidate security metadata Some (svn, cand) are
      recorded IF AND ONLY IF pipeline_status == BOOT_OK (PCI_Ok svn cand).
   2. Low-Vbat deferral (PCI_Defer) records UDO_Deferred, TNW_SleepBackoff,
      None for candidate metadata, and preserves ratified app_* identity.
   3. Controlled/fatal pipeline rejections record UDO_Rejected, None for
      candidate metadata, and never contaminate ratified app_* identity.
   4. Rollback records UDO_Reverted, clears pending_*, heals post-boot TMR
      boot_failure_counter to 0, and preserves pre-heal observed_failure_count
      (>= 1 on unhealed crash-triggered rollback). *)
Theorem tdr1_03_telemetry_commit_point_discipline :
  (forall inp ts meta bf meta' snap nwal fok,
     eval_update_commit_point inp ts meta bf = (meta', snap, nwal, fok) ->
     (dts_outcome snap = UDO_Applied <-> exists svn cand, inp = PCI_Ok svn cand) /\
     (forall svn cand,
        dts_cand_security_meta snap = Some (svn, cand) <-> inp = PCI_Ok svn cand) /\
     (forall opt_c,
        inp = PCI_Defer opt_c ->
        dts_outcome snap = UDO_Deferred /\
        dts_cand_security_meta snap = None /\
        nwal = TNW_SleepBackoff /\
        meta' = meta /\
        dts_handoff_identity snap = tam_ratified meta) /\
     (forall err opt_c,
        (inp = PCI_Reject err opt_c \/ inp = PCI_FatalHw err opt_c) ->
        dts_outcome snap = UDO_Rejected /\
        dts_cand_security_meta snap = None /\
        meta' = meta /\
        dts_handoff_identity snap = tam_ratified meta)) /\
  (forall unhealed pre_bf meta meta' snap post_bf,
     eval_rollback_telemetry unhealed pre_bf meta = (meta', snap, post_bf) ->
     dts_outcome snap = UDO_Reverted /\
     dts_cand_security_meta snap = None /\
     post_bf = 0 /\
     tam_pending meta' = None /\
     tam_ratified meta' = tam_ratified meta /\
     dts_handoff_identity snap = tam_ratified meta /\
     pre_bf <= dts_observed_failures snap /\
     (unhealed = true -> 1 <= dts_observed_failures snap)).
Proof.
  split.
  - intros inp ts meta bf meta' snap nwal fok Heval.
    unfold eval_update_commit_point in Heval.
    destruct inp as [svn0 cand0 | opt_d | err_r opt_r | err_f opt_f].
    + inversion Heval; subst; simpl; split_conj.
      * split; [intros _; exists svn0, cand0; reflexivity | intros _; reflexivity].
      * intros svn cand; split; intros H; inversion H; subst; reflexivity.
      * intros; discriminate.
      * intros err opt_c [H|H]; discriminate H.
    + inversion Heval; subst; simpl; split_conj.
      * split; [discriminate | intros [? [? H]]; discriminate H].
      * intros svn cand; split; discriminate.
      * intros opt_c H; inversion H; repeat split; reflexivity.
      * intros err opt_c [H|H]; discriminate H.
    + destruct ts; inversion Heval; subst; simpl; split_conj;
        try (split; [discriminate | intros [? [? H]]; discriminate H]);
        try (intros svn cand; split; discriminate);
        try (intros; discriminate);
        (intros err opt_c [H|H]; inversion H; repeat split; reflexivity).
    + inversion Heval; subst; simpl; split_conj.
      * split; [discriminate | intros [? [? H]]; discriminate H].
      * intros svn cand; split; discriminate.
      * intros; discriminate.
      * intros err opt_c [H|H]; inversion H; repeat split; reflexivity.
  - intros unhealed pre_bf meta meta' snap post_bf Hrb.
    unfold eval_rollback_telemetry in Hrb.
    inversion Hrb; subst; simpl.
    destruct unhealed; [destruct (0 <? pre_bf) eqn:Epos|].
    + apply Nat.ltb_lt in Epos; repeat split; lia.
    + apply Nat.ltb_ge in Epos; repeat split; lia.
    + repeat split; [lia | intro H; discriminate H].
Qed.
