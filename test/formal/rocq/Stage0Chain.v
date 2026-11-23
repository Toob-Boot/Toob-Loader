(* ========================================================================== *)
(* Toob-Loader Formal Verification — Stage 0 -> Stage 1 Chain & Lifecycle    *)
(* File: test/formal/rocq/Stage0Chain.v                                       *)
(* Covers:                                                                    *)
(*   FV-10 (P0): stage0_to_stage1_chain_of_trust                              *)
(*               stage1_self_update_non_brick                                 *)
(*   FV-11 (P0): dslc_irreversible_progression                                *)
(*               no_unprovisioned_or_revoked_app_boot                         *)
(*               unprovisioned_without_uart_halts_in_stage1 (CRIT-31a)        *)
(*               stage1_independent_dslc_gate_blocks_faulted_stage0 (CRIT-31b)*)
(*               (+ dslc_revoked_post_reboot_bypass_witness for Finding E)    *)
(* Zero Admitted, Zero Axioms.                                                *)
(* ========================================================================== *)

From Stdlib Require Import List Arith Bool PeanoNat Lia.
Import ListNotations.

From ToobBoot Require Import BootModel BootTransitions BootTheorems.

(* ========================================================================== *)
(* SECTION 1: Stage 0 Hardware & Flash Abstractions                           *)
(*            Mirrors stage0_otp.c, stage0_boot_pointer.c, stage0_tentative.c *)
(*            stage0_verify.c, stage0_main.c, and boot_proof.h                *)
(* ========================================================================== *)

Inductive Stage1Bank : Type :=
  | Bank_A : Stage1Bank
  | Bank_B : Stage1Bank.

Definition bank_eqb (a b : Stage1Bank) : bool :=
  match a, b with
  | Bank_A, Bank_A => true
  | Bank_B, Bank_B => true
  | _, _           => false
  end.

Definition flip_bank (b : Stage1Bank) : Stage1Bank :=
  match b with
  | Bank_A => Bank_B
  | Bank_B => Bank_A
  end.

Lemma flip_bank_involutive : forall b, flip_bank (flip_bank b) = b.
Proof. destruct b; reflexivity. Qed.

(* OTP root-key slot state (stage0_otp.c: contiguous scan over K0[0..255]) *)
Inductive OtpKeySlot : Type :=
  | OKS_Valid     : nat (* pubkey_id > 0 *) -> OtpKeySlot
  | OKS_Blank     : OtpKeySlot
  | OKS_AllZero   : OtpKeySlot (* Fault/tamper: occupied slot with zero key *)
  | OKS_ReadFault : OtpKeySlot.

Inductive OtpScanResult : Type :=
  | OS_Ok        : nat (* active_key_idx *) -> nat (* pubkey_id *) -> OtpScanResult
  | OS_FaultHalt : OtpScanResult.

Fixpoint all_blank_tail (xs : list OtpKeySlot) : bool :=
  match xs with
  | [] => true
  | OKS_Blank :: rest => all_blank_tail rest
  | _ :: _ => false
  end.

Fixpoint scan_otp_keys_aux
    (xs : list OtpKeySlot) (cur_idx : nat) (last_valid : option (nat * nat))
    : OtpScanResult :=
  match xs with
  | [] =>
      match last_valid with
      | Some (idx, pk) => OS_Ok idx pk
      | None           => OS_FaultHalt
      end
  | OKS_Valid pk :: rest =>
      if pk =? 0 then OS_FaultHalt
      else scan_otp_keys_aux rest (S cur_idx) (Some (cur_idx, pk))
  | OKS_Blank :: rest =>
      if all_blank_tail rest then
        match last_valid with
        | Some (idx, pk) => OS_Ok idx pk
        | None           => OS_FaultHalt
        end
      else
        OS_FaultHalt
  | OKS_AllZero :: _   => OS_FaultHalt
  | OKS_ReadFault :: _ => OS_FaultHalt
  end.

Definition scan_otp_keys (xs : list OtpKeySlot) : OtpScanResult :=
  scan_otp_keys_aux xs 0 None.

(* Stage 0 WAL Boot-Pointer TMR Quorum & Split-Brain SVN Floor
   (stage0_boot_pointer.c) *)
Record Stage0WalSector : Type := mkS0WalSec {
  s0w_active_bank : Stage1Bank;
  s0w_stage1_svn  : nat
}.

Record Stage0WalQuorum : Type := mkS0WalQuorum {
  s0q_sec0 : option Stage0WalSector;
  s0q_sec1 : option Stage0WalSector;
  s0q_sec2 : option Stage0WalSector
}.

Definition opt_s0_svn (o : option Stage0WalSector) : nat :=
  match o with
  | Some s => s0w_stage1_svn s
  | None   => 0
  end.

(* Split-brain defense: floor is max stage1_svn across ALL valid TMR sectors *)
Definition s0_wal_max_stage1_svn (q : Stage0WalQuorum) : nat :=
  Nat.max (opt_s0_svn (s0q_sec0 q))
          (Nat.max (opt_s0_svn (s0q_sec1 q)) (opt_s0_svn (s0q_sec2 q))).

(* 2-of-3 bank quorum vote (defaults to Bank_A on split/erased WAL) *)
Definition s0_wal_vote_bank (q : Stage0WalQuorum) : Stage1Bank :=
  match s0q_sec0 q, s0q_sec1 q, s0q_sec2 q with
  | Some a, Some b, Some c =>
      if bank_eqb (s0w_active_bank a) (s0w_active_bank b) then s0w_active_bank a
      else if bank_eqb (s0w_active_bank a) (s0w_active_bank c) then s0w_active_bank a
      else if bank_eqb (s0w_active_bank b) (s0w_active_bank c) then s0w_active_bank b
      else Bank_A
  | Some a, Some b, None =>
      if bank_eqb (s0w_active_bank a) (s0w_active_bank b) then s0w_active_bank a else Bank_A
  | Some a, None, Some c =>
      if bank_eqb (s0w_active_bank a) (s0w_active_bank c) then s0w_active_bank a else Bank_A
  | None, Some b, Some c =>
      if bank_eqb (s0w_active_bank b) (s0w_active_bank c) then s0w_active_bank b else Bank_A
  | _, _, _ => Bank_A
  end.

(* Stage 0 .noinit Tentative Crash-Flip State (stage0_tentative.c) *)
Inductive Stage0TentativeTag : Type :=
  | S0T_Idle      : Stage0TentativeTag
  | S0T_Tentative : Stage0TentativeTag
  | S0T_Reverted  : Stage0TentativeTag.

Record Stage0NoinitRam : Type := mkS0Noinit {
  s0n_crc_valid : bool;
  s0n_tag       : Stage0TentativeTag
}.

Definition s0_resolve_tentative_bank
    (ptr_bank : Stage1Bank) (noinit : Stage0NoinitRam) (rst : ResetReason)
    : (Stage1Bank * Stage0NoinitRam) :=
  match s0n_crc_valid noinit, s0n_tag noinit with
  | true, S0T_Tentative =>
      if rst_indicates_crash rst then
        (flip_bank ptr_bank, mkS0Noinit true S0T_Reverted)
      else
        (ptr_bank, noinit)
  | _, _ => (ptr_bank, noinit)
  end.

(* 5-Round 3-of-5 DSLC Majority Vote (stage0_main.c:535-582) *)
Definition count_opt_eq (v : nat) (samples : list (option nat)) : nat :=
  length (filter (fun s => match s with Some x => x =? v | None => false end) samples).

Fixpoint dslc_quorum_find (cands samples : list (option nat)) : option nat :=
  match cands with
  | [] => None
  | None :: rest => dslc_quorum_find rest samples
  | Some v :: rest =>
      if 3 <=? count_opt_eq v samples then Some v
      else dslc_quorum_find rest samples
  end.

Definition dslc_quorum_5 (samples : list (option nat)) : option nat :=
  if length samples =? 5 then dslc_quorum_find samples samples
  else None.

(* Stage 1 Bank Image Descriptor (stage0_main.c:364-480 & stage0_verify.c) *)
Record Stage1BankImage : Type := mkStage1Bank {
  s1b_present        : bool; (* Header magic + header CRC32 valid *)
  s1b_sig_valid      : bool; (* Ed25519 signature over Stage-1 image valid *)
  s1b_exec_bounds_ok : bool; (* Entry & load window strictly in XIP/Stage1 SRAM *)
  s1b_key_idx        : nat;  (* Root key index in Stage-1 header *)
  s1b_svn            : nat   (* Stage-1 image SVN *)
}.

Definition erased_stage1_bank : Stage1BankImage :=
  mkStage1Bank false false false 0 0.

Record Stage1DualBanks : Type := mkStage1DualBanks {
  s1_bank_a : Stage1BankImage;
  s1_bank_b : Stage1BankImage
}.

Definition get_stage1_bank (banks : Stage1DualBanks) (b : Stage1Bank) : Stage1BankImage :=
  match b with
  | Bank_A => s1_bank_a banks
  | Bank_B => s1_bank_b banks
  end.

Definition put_stage1_bank
    (banks : Stage1DualBanks) (b : Stage1Bank) (img : Stage1BankImage) : Stage1DualBanks :=
  match b with
  | Bank_A => mkStage1DualBanks img (s1_bank_b banks)
  | Bank_B => mkStage1DualBanks (s1_bank_a banks) img
  end.

Definition stage0_verify_bank
    (img : Stage1BankImage) (active_key_idx : nat) (min_stage1_svn : nat) : bool :=
  s1b_present img &&
  (s1b_key_idx img =? active_key_idx) &&
  s1b_sig_valid img &&
  (min_stage1_svn <=? s1b_svn img) &&
  s1b_exec_bounds_ok img.

(* Stage 0 -> Stage 1 Boot-Proof Handoff Seal (boot_proof.h) *)
Record BootProofToken : Type := mkBootProof {
  bp_sealed_ok  : bool;
  bp_bank       : Stage1Bank;
  bp_stage1_svn : nat;
  bp_key_idx    : nat;
  bp_dslc       : nat
}.

Definition dslc_blank_byte : nat := 0.
Definition dslc_decommissioned_byte : nat := 255.

Inductive Stage0Outcome : Type :=
  | S0_BootStage1 : Stage1Bank -> Stage1BankImage -> BootProofToken ->
                    Stage0NoinitRam -> Stage0Outcome
  | S0_DeadHalt   : Stage0Outcome.

(* Stage 0 top-level execution (stage0_main.c).
   enforce_decomm_gate = true enforces the specification requirement that
   DSLC == 0xFF (255) halts before Stage 1; enforce_decomm_gate = false mirrors
   current stage0_main.c:370 where confirmed_dslc is cast to (void). *)
Definition eval_stage0
    (enforce_decomm_gate : bool)
    (cfg_stage1_svn : nat)
    (otp_keys : list OtpKeySlot)
    (dslc_samples : list (option nat))
    (wal_q : Stage0WalQuorum)
    (noinit : Stage0NoinitRam)
    (rst : ResetReason)
    (banks : Stage1DualBanks)
    : Stage0Outcome :=
  match scan_otp_keys otp_keys with
  | OS_FaultHalt => S0_DeadHalt
  | OS_Ok active_key_idx _ =>
      match dslc_quorum_5 dslc_samples with
      | None => S0_DeadHalt
      | Some confirmed_dslc =>
          if enforce_decomm_gate && (confirmed_dslc =? dslc_decommissioned_byte) then
            S0_DeadHalt
          else
            let min_s1_svn := Nat.max cfg_stage1_svn (s0_wal_max_stage1_svn wal_q) in
            let ptr_bank := s0_wal_vote_bank wal_q in
            let '(pri_bank, noinit') := s0_resolve_tentative_bank ptr_bank noinit rst in
            let pri_img := get_stage1_bank banks pri_bank in
            if stage0_verify_bank pri_img active_key_idx min_s1_svn then
              let proof := mkBootProof true pri_bank (s1b_svn pri_img) active_key_idx confirmed_dslc in
              S0_BootStage1 pri_bank pri_img proof noinit'
            else
              let alt_bank := flip_bank pri_bank in
              let alt_img := get_stage1_bank banks alt_bank in
              if stage0_verify_bank alt_img active_key_idx min_s1_svn then
                let proof := mkBootProof true alt_bank (s1b_svn alt_img) active_key_idx confirmed_dslc in
                S0_BootStage1 alt_bank alt_img proof noinit'
              else
                S0_DeadHalt
      end
  end.

(* ========================================================================== *)
(* SECTION 2: Stage 0 + Stage 1 Sequential Chain Composition & DSLC Lifecycle *)
(* ========================================================================== *)

Inductive ChainOutcome : Type :=
  | Chain_Boot_App        : Stage1Bank -> Stage1BankImage -> BootProofToken ->
                            SlotImage -> bool -> nat -> State -> ChainOutcome
  | Chain_Provisioning    : Stage1Bank -> Stage1BankImage -> ChainOutcome
  | Chain_Recovery        : Stage1Bank -> Stage1BankImage -> RecoveryMode -> State -> ChainOutcome
  | Chain_Stage0_Halt     : ChainOutcome
  | Chain_Stage1_Halt     : ChainOutcome.

Definition dslc_is_active_provisioned (d : nat) : bool :=
  (dslc_blank_byte <? d) && (d <? dslc_decommissioned_byte).

(* Stage 1 Block 2.6 DSLC Gate (boot_main.c:426-445, CRIT-31 fix):
   - When enforce_stage1_gate = true (post-CRIT-31):
     Stage 1 UNCONDITIONALLY invokes read_dslc (s1_dslc_opt), even when
     TOOB_FEATURE_UART_PROVISIONING == 0 (prov_uart_wired = false):
       * None (read failure) -> Chain_Stage1_Halt
       * 0x00 (unprovisioned) -> Chain_Provisioning iff prov_uart_wired = true,
                                 else Chain_Stage1_Halt!
       * 0x01..0xFE (active)  -> proceed to eval_boot_state
       * >= 0xFF (revoked)    -> Chain_Stage1_Halt
   - When enforce_stage1_gate = false (pre-CRIT-31 Finding E bug model):
     Block 2.6 only runs when prov_uart_wired = true and only checks == 0x00. *)
Definition eval_stage1_dslc_gate
    (enforce_stage1_gate : bool)
    (prov_uart_wired : bool)
    (s1_dslc_opt : option nat)
    (b_exec : Stage1Bank)
    (s1_img : Stage1BankImage)
    (proof : BootProofToken)
    (cfg1 : BootConfig)
    (st1 : State)
    : ChainOutcome :=
  let st_synced :=
    mkState (st_slots st1) (st_wal st1) (st_tmr st1) (st_confirm st1)
            (mkOTPEpoch (otp_min_svn (st_otp st1)) (bp_key_idx proof))
            (st_reset st1) in
  let run_normal :=
    match eval_boot_state cfg1 st_synced with
    | (Boot_App app_img tent nonce, st_out) =>
        Chain_Boot_App b_exec s1_img proof app_img tent nonce st_out
    | (Enter_Recovery_OS mode, st_out) =>
        Chain_Recovery b_exec s1_img mode st_out
    end in
  if enforce_stage1_gate then
    match s1_dslc_opt with
    | None => Chain_Stage1_Halt
    | Some s1_d =>
        if s1_d =? dslc_blank_byte then
          if prov_uart_wired then Chain_Provisioning b_exec s1_img
          else Chain_Stage1_Halt
        else if dslc_is_active_provisioned s1_d then
          run_normal
        else
          Chain_Stage1_Halt
    end
  else
    if prov_uart_wired then
      match s1_dslc_opt with
      | None => Chain_Stage1_Halt
      | Some s1_d =>
          if s1_d =? dslc_blank_byte then Chain_Provisioning b_exec s1_img
          else run_normal
      end
    else
      run_normal.

(* Two-Gate Defense-in-Depth Stage 0 -> Stage 1 Composition (CRIT-31):
   Allows independent control over Stage 0's 0xFF gate (enforce_stage0_gate)
   and Stage 1's unconditional read_dslc gate (enforce_stage1_gate), as well
   as Stage 1's independent OTP read result s1_dslc_opt. *)
Definition eval_stage0_then_stage1_did
    (enforce_stage0_gate : bool)
    (enforce_stage1_gate : bool)
    (prov_uart_wired : bool)
    (cfg_stage1_svn : nat)
    (otp_keys : list OtpKeySlot)
    (dslc_samples : list (option nat))
    (s1_dslc_opt : option nat)
    (wal_q : Stage0WalQuorum)
    (noinit : Stage0NoinitRam)
    (banks : Stage1DualBanks)
    (cfg1 : BootConfig)
    (st1 : State)
    : ChainOutcome :=
  match eval_stage0 enforce_stage0_gate cfg_stage1_svn otp_keys dslc_samples
                    wal_q noinit (st_reset st1) banks with
  | S0_DeadHalt => Chain_Stage0_Halt
  | S0_BootStage1 b_exec s1_img proof _ =>
      if negb (bp_sealed_ok proof) then
        Chain_Stage1_Halt
      else
        eval_stage1_dslc_gate enforce_stage1_gate prov_uart_wired s1_dslc_opt
                              b_exec s1_img proof cfg1 st1
  end.

(* Standard sequential Stage 0 -> Stage 1 composition where Stage 1 reads the
   same physical OTP DSLC fuse state confirmed by the hardware fuse bank. *)
Definition eval_stage0_then_stage1
    (enforce_dslc_gate : bool)
    (prov_uart_wired : bool)
    (cfg_stage1_svn : nat)
    (otp_keys : list OtpKeySlot)
    (dslc_samples : list (option nat))
    (wal_q : Stage0WalQuorum)
    (noinit : Stage0NoinitRam)
    (banks : Stage1DualBanks)
    (cfg1 : BootConfig)
    (st1 : State)
    : ChainOutcome :=
  eval_stage0_then_stage1_did enforce_dslc_gate enforce_dslc_gate prov_uart_wired
    cfg_stage1_svn otp_keys dslc_samples (dslc_quorum_5 dslc_samples)
    wal_q noinit banks cfg1 st1.

(* ========================================================================== *)
(* SECTION 3: FV-10 Proofs — Chain of Trust & Stage-1 Self-Update Non-Brick   *)
(* ========================================================================== *)

Lemma scan_otp_keys_aux_sound :
  forall xs cur last idx pk,
    scan_otp_keys_aux xs cur last = OS_Ok idx pk ->
    (last = Some (idx, pk) \/
     (cur <= idx /\ nth_error xs (idx - cur) = Some (OKS_Valid pk) /\ 0 < pk)).
Proof.
  induction xs as [|slot rest IH]; intros cur last idx pk Hscan; simpl in Hscan.
  - destruct last as [[i p]|]; [inversion Hscan; subst; left; reflexivity | discriminate].
  - destruct slot as [pk0 | | |]; try discriminate.
    + destruct (pk0 =? 0) eqn:Ez; [discriminate|].
      apply Nat.eqb_neq in Ez.
      destruct (IH (S cur) (Some (cur, pk0)) idx pk Hscan) as [Heq | [Hle [Hnth Hpos]]].
      * inversion Heq; subst.
        right; split; [lia | rewrite Nat.sub_diag; simpl; split; [reflexivity | lia]].
      * right; split; [lia|].
        replace (idx - cur) with (S (idx - S cur)) by lia.
        simpl; exact (conj Hnth Hpos).
    + destruct (all_blank_tail rest); [|discriminate].
      destruct last as [[i p]|]; [inversion Hscan; subst; left; reflexivity | discriminate].
Qed.

Lemma scan_otp_keys_sound :
  forall otp_keys idx pk,
    scan_otp_keys otp_keys = OS_Ok idx pk ->
    nth_error otp_keys idx = Some (OKS_Valid pk) /\ 0 < pk.
Proof.
  intros otp_keys idx pk H.
  unfold scan_otp_keys in H.
  destruct (scan_otp_keys_aux_sound otp_keys 0 None idx pk H) as [Hnone | [_ [Hnth Hpos]]].
  - discriminate Hnone.
  - rewrite Nat.sub_0_r in Hnth; exact (conj Hnth Hpos).
Qed.

Lemma stage0_verify_bank_spec :
  forall img k_idx min_svn,
    stage0_verify_bank img k_idx min_svn = true <->
    (s1b_present img = true /\
     s1b_key_idx img = k_idx /\
     s1b_sig_valid img = true /\
     min_svn <= s1b_svn img /\
     s1b_exec_bounds_ok img = true).
Proof.
  intros img k_idx min_svn.
  unfold stage0_verify_bank.
  rewrite !Bool.andb_true_iff, Nat.eqb_eq, Nat.leb_le.
  tauto.
Qed.

Lemma dslc_quorum_find_spec :
  forall cands samples d,
    dslc_quorum_find cands samples = Some d ->
    3 <= count_opt_eq d samples.
Proof.
  induction cands as [|[v|] rest IH]; intros samples d H; cbn [dslc_quorum_find] in H.
  - discriminate.
  - destruct (3 <=? count_opt_eq v samples) eqn:E.
    + inversion H; subst; apply Nat.leb_le; exact E.
    + exact (IH samples d H).
  - exact (IH samples d H).
Qed.

Lemma dslc_quorum_5_spec :
  forall samples d,
    dslc_quorum_5 samples = Some d ->
    length samples = 5 /\ 3 <= count_opt_eq d samples.
Proof.
  intros samples d H.
  unfold dslc_quorum_5 in H.
  destruct (length samples =? 5) eqn:Elen; [|discriminate].
  apply Nat.eqb_eq in Elen.
  split; [exact Elen | exact (dslc_quorum_find_spec samples samples d H)].
Qed.

Lemma eval_boot_state_boot_app_verified :
  forall cfg st app_img tent nonce st_out,
    ValidInstalledSlots (st_slots st) (st_otp st) ->
    eval_boot_state cfg st = (Boot_App app_img tent nonce, st_out) ->
    image_is_verified app_img (otp_min_svn (st_otp st)) (otp_active_key_index (st_otp st)) /\
    otp_min_svn (st_otp st) <= otp_min_svn (st_otp st_out).
Proof.
  intros cfg st app_img tent nonce st_out [Happ0 Hbk0] Heval.
  unfold eval_boot_state in Heval; cbv zeta in Heval.
  destruct (negb (tmr_mac_valid (st_tmr st))); [discriminate|].
  destruct (step1_mailbox_consume (st_slots st) (st_wal st) (st_tmr st))
    as [|s1 w1 t1] eqn:Hm1; [discriminate|].
  pose proof (step1_mailbox_preserves_slots_and_svn _ _ _ _ _ _ Hm1)
    as [Ha1 [_ [Hb1 _]]].
  destruct (wal_reconstruct_txn w1) as [[oi1 oe1]|]; [|discriminate].
  destruct (step2_confirm_check s1 w1 t1 (st_confirm st) oi1 oe1)
    as [|s2 w2 t2 c2 oi2 h2] eqn:Hs2; [discriminate|].
  pose proof (step2_confirm_preserves_app_bkup_svn _ _ _ _ _ _ _ _ _ _ _ _ Hs2)
    as [Ha2 [Hb2 _]].
  destruct (step2_5_cloud_cmd s2 w2 t2 (st_otp st) oi2)
    as [[[[s25 w25] t25] otp25] oi25] eqn:Hs25.
  pose proof (step2_5_cloud_preserves_images _ _ _ _ _ _ _ _ _ _ Hs25)
    as [Ha25 [_ [Hb25 [_ [_ [Hotp_le [Hkey25 _]]]]]]].
  destruct (wal_intent_eqb oi25 WI_DeviceLocked); [discriminate|].
  destruct (step3_failure_and_rollback cfg s25 w25 t25 (st_reset st) oi25 h2)
    as [|s3 w3 t3 oi3 h3 br3] eqn:Hs3; [discriminate|].
  assert (Hs3_app : app_slot s3 = app_slot (st_slots st) \/
                    app_slot s3 = backup_slot (st_slots st)).
  { unfold step3_failure_and_rollback in Hs3; cbv zeta in Hs3.
    destruct (wal_intent_eqb oi25 WI_TxnRollback); [inversion Hs3; subst; left; congruence|].
    set (ta := if (negb h2 &&
                   ((wal_intent_eqb oi25 WI_ConfirmCommit || wal_intent_eqb oi25 WI_TxnCommit) ||
                    (rst_indicates_crash (st_reset st) && negb (wal_intent_eqb oi25 WI_UpdatePending)))) &&
                  crash_accum_applicable oi25
               then apply_crash_accum cfg t25 else t25) in *.
    destruct ((0 <? boot_failure_counter ta) || wal_intent_eqb oi25 WI_TxnRollbackPending);
      [|inversion Hs3; subst; left; congruence].
    destruct (wal_intent_eqb oi25 WI_TxnCommit || wal_intent_eqb oi25 WI_TxnRollbackPending).
    - destruct (rst_indicates_crash (st_reset st) && negb h2 ||
                wal_intent_eqb oi25 WI_TxnRollbackPending ||
                (cfg_max_retries cfg <? boot_failure_counter ta));
        [|inversion Hs3; subst; left; congruence].
      destruct (negb (hdr_valid (backup_slot s25))); [discriminate|].
      destruct (negb (sig_valid (backup_slot s25))); [discriminate|].
      inversion Hs3; subst; simpl; right; congruence.
    - destruct (boot_failure_counter ta <=? cfg_max_retries cfg);
        [inversion Hs3; subst; left; congruence|].
      destruct (recovery_failure_counter ta <=? cfg_max_recovery_retries cfg);
        [inversion Hs3; subst; left; congruence | discriminate]. }
  destruct (step4_update_pipeline s3 w3 t3 otp25 oi3)
    as [[[[s4 w4] t4] oi4] upd_p] eqn:Hs4.
  set (br4 := if upd_p && wal_intent_eqb oi4 WI_TxnCommit then false else br3) in *.
  set (app_hdr_ok := hdr_valid (app_slot s4)) in *.
  set (fb := negb br4 && negb app_hdr_ok && recovery_rom_valid s4 &&
             (recovery_failure_counter t4 <=? cfg_max_recovery_retries cfg)) in *.
  set (br5 := br4 || fb) in *.
  destruct (negb (if br5 then recovery_rom_valid s4 else app_hdr_ok)) eqn:Eth; [discriminate|].
  destruct (negb (if br5
                  then recovery_rom_valid s4
                  else slot_tsig_valid (app_slot s4) (otp_active_key_index otp25))) eqn:Etsig; [discriminate|].
  destruct br5 eqn:Ebr5; [discriminate|].
  inversion Heval; subst app_img st_out; simpl.
  apply Bool.negb_false_iff in Eth; unfold app_hdr_ok in Eth.
  unfold step4_update_pipeline in Hs4; cbv zeta in Hs4.
  destruct (negb (wal_intent_eqb oi3 WI_UpdatePending)).
  - inversion Hs4; subst s4.
    destruct Hs3_app as [Heq | Heq]; rewrite Heq in Eth |- *;
      split; [exact (Happ0 Eth) | exact Hotp_le | exact (Hbk0 Eth) | exact Hotp_le].
  - destruct (staging_can_apply (staging_slot s3) t3 otp25) eqn:Ecan.
    + inversion Hs4; subst s4; simpl.
      apply staging_can_apply_verified in Ecan as [[Hh [Hs [Hm [Hsvn Hk]]]] _].
      rewrite Hkey25 in Hk.
      split; [unfold image_is_verified; repeat split; try assumption; lia | exact Hotp_le].
    + inversion Hs4; subst s4.
      destruct Hs3_app as [Heq | Heq]; rewrite Heq in Eth |- *;
        split; [exact (Happ0 Eth) | exact Hotp_le | exact (Hbk0 Eth) | exact Hotp_le].
Qed.

(* Theorem FV-10a: End-to-End Stage 0 -> Stage 1 -> App Chain of Trust *)
Theorem stage0_to_stage1_chain_of_trust :
  forall prov_wired cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1
         b_exec s1_img proof app_img tent nonce st_out,
    ValidInstalledSlots (st_slots st1)
      (mkOTPEpoch (otp_min_svn (st_otp st1)) (bp_key_idx proof)) ->
    eval_stage0_then_stage1 true prov_wired cfg_s1_svn otp_keys dslc_samples
                            wal_q noinit banks cfg1 st1 =
      Chain_Boot_App b_exec s1_img proof app_img tent nonce st_out ->
    exists pk,
      (* 1. OTP root-key scan resolved an occupied, non-zero active root key *)
      scan_otp_keys otp_keys = OS_Ok (bp_key_idx proof) pk /\
      nth_error otp_keys (bp_key_idx proof) = Some (OKS_Valid pk) /\
      0 < pk /\
      (* 2. Stage-1 bank passed Ed25519 sig, latest-key bind, split-brain SVN floor, and bounds *)
      get_stage1_bank banks b_exec = s1_img /\
      s1b_present s1_img = true /\
      s1b_sig_valid s1_img = true /\
      s1b_exec_bounds_ok s1_img = true /\
      s1b_key_idx s1_img = bp_key_idx proof /\
      Nat.max cfg_s1_svn (s0_wal_max_stage1_svn wal_q) <= s1b_svn s1_img /\
      (* 3. Stage 1 verified an authentic BootProofToken sealed by Stage 0 *)
      bp_sealed_ok proof = true /\
      bp_bank proof = b_exec /\
      bp_stage1_svn proof = s1b_svn s1_img /\
      (* 4. 3-of-5 DSLC quorum succeeded and device is provisioned & non-revoked *)
      length dslc_samples = 5 /\
      3 <= count_opt_eq (bp_dslc proof) dslc_samples /\
      dslc_blank_byte < bp_dslc proof /\
      bp_dslc proof < dslc_decommissioned_byte /\
      (* 5. Booted application image is authenticated & anti-rollback verified *)
      image_is_verified app_img (otp_min_svn (st_otp st1)) (bp_key_idx proof) /\
      otp_min_svn (st_otp st1) <= otp_min_svn (st_otp st_out).
Proof.
  intros prov_wired cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1
         b_exec s1_img proof app_img tent nonce st_out Hslots Hchain.
  unfold eval_stage0_then_stage1, eval_stage0_then_stage1_did in Hchain.
  destruct (eval_stage0 true cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks)
    as [b0 s1_0 proof0 noinit0 | ] eqn:Es0; [|discriminate].
  destruct (negb (bp_sealed_ok proof0)) eqn:Ebp; [discriminate|].
  unfold eval_stage1_dslc_gate in Hchain; cbv zeta in Hchain.
  destruct (dslc_quorum_5 dslc_samples) as [s1_d | ] eqn:Edslc; [|discriminate].
  destruct (s1_d =? dslc_blank_byte) eqn:Eblank;
    [destruct prov_wired; discriminate|].
  destruct (dslc_is_active_provisioned s1_d) eqn:Eact; [|discriminate].
  set (st_synced := mkState (st_slots st1) (st_wal st1) (st_tmr st1) (st_confirm st1)
                            (mkOTPEpoch (otp_min_svn (st_otp st1)) (bp_key_idx proof0))
                            (st_reset st1)) in *.
  destruct (eval_boot_state cfg1 st_synced) as [[app0 tent0 nonce0 | rmode] st_f] eqn:Eboot;
    [|discriminate].
  inversion Hchain; subst b0 s1_0 proof0 app0 tent0 nonce0 st_f; clear Hchain.
  unfold dslc_is_active_provisioned in Eact.
  apply Bool.andb_true_iff in Eact as [Hgt0 Hlt255].
  apply Nat.ltb_lt in Hgt0; apply Nat.ltb_lt in Hlt255.
  unfold eval_stage0 in Es0.
  destruct (scan_otp_keys otp_keys) as [k_idx pk | ] eqn:Escan; [|discriminate].
  rewrite Edslc in Es0.
  destruct (s1_d =? dslc_decommissioned_byte) eqn:Edec; [simpl in Es0; discriminate|].
  simpl in Es0.
  set (min_svn := Nat.max cfg_s1_svn (s0_wal_max_stage1_svn wal_q)) in *.
  destruct (s0_resolve_tentative_bank (s0_wal_vote_bank wal_q) noinit (st_reset st1))
    as [pri_b noinit1] eqn:Etent.
  assert (Hs0_inv :
    k_idx = bp_key_idx proof /\
    s1_d = bp_dslc proof /\
    bp_sealed_ok proof = true /\
    bp_bank proof = b_exec /\
    bp_stage1_svn proof = s1b_svn s1_img /\
    get_stage1_bank banks b_exec = s1_img /\
    stage0_verify_bank s1_img k_idx min_svn = true).
  { destruct (stage0_verify_bank (get_stage1_bank banks pri_b) k_idx min_svn) eqn:Ev1.
    - inversion Es0; subst; simpl; repeat split; try reflexivity; exact Ev1.
    - destruct (stage0_verify_bank (get_stage1_bank banks (flip_bank pri_b)) k_idx min_svn) eqn:Ev2;
        [|discriminate].
      inversion Es0; subst; simpl; repeat split; try reflexivity; exact Ev2. }
  destruct Hs0_inv as [Hk [Hd [Hseal [Hbb [Hbsvn [Hget Hver]]]]]].
  subst k_idx s1_d.
  apply stage0_verify_bank_spec in Hver as [Hpres [Hki [Hsig [Hsvn Hbnds]]]].
  pose proof (scan_otp_keys_sound otp_keys (bp_key_idx proof) pk Escan) as [Hnth Hpk_pos].
  pose proof (dslc_quorum_5_spec dslc_samples (bp_dslc proof) Edslc) as [Hlen5 Hq3].
  pose proof (eval_boot_state_boot_app_verified cfg1 st_synced app_img tent nonce st_out Hslots Eboot)
    as [[Hih [His [Him [Hisvn Hikey]]]] Hotp_le].
  simpl in Hisvn, Hikey, Hotp_le.
  exists pk; repeat split; assumption.
Qed.

(* Stage 1 Self-Update State & Transition Model (FV-10b):
   Stage 1 writes a candidate Stage-1 image exclusively to flip_bank(active_bank),
   arms .noinit S0T_Tentative while pointing WAL active_bank at flip_bank(active_bank)
   WITHOUT advancing wal_stage1_svn until explicit post-boot confirmation! *)
Record Stage1SelfUpdateState : Type := mkS1SelfUpd {
  s1u_banks       : Stage1DualBanks;
  s1u_active_bank : Stage1Bank;
  s1u_wal_svn     : nat;
  s1u_noinit      : Stage0NoinitRam
}.

Definition make_uniform_s0_wal (b : Stage1Bank) (svn : nat) : Stage0WalQuorum :=
  let sec := Some (mkS0WalSec b svn) in
  mkS0WalQuorum sec sec sec.

Lemma uniform_s0_wal_props :
  forall b svn,
    s0_wal_vote_bank (make_uniform_s0_wal b svn) = b /\
    s0_wal_max_stage1_svn (make_uniform_s0_wal b svn) = svn.
Proof.
  intros [|] svn; unfold make_uniform_s0_wal, s0_wal_vote_bank, s0_wal_max_stage1_svn;
    simpl; split; [reflexivity | lia | reflexivity | lia].
Qed.

(* Staging a Stage-1 self-update writes ONLY to flip_bank(s1u_active_bank)
   (possibly torn/corrupted on mid-write power-cut) and arms S0T_Tentative
   while keeping s1u_wal_svn unchanged (deferred SVN ratification). *)
Definition stage1_stage_self_update
    (st : Stage1SelfUpdateState)
    (cand_written : Stage1BankImage)
    (pointer_switched : bool)
    : Stage1SelfUpdateState :=
  let target_bank := flip_bank (s1u_active_bank st) in
  let banks' := put_stage1_bank (s1u_banks st) target_bank cand_written in
  if pointer_switched then
    mkS1SelfUpd banks' target_bank (s1u_wal_svn st) (mkS0Noinit true S0T_Tentative)
  else
    mkS1SelfUpd banks' (s1u_active_bank st) (s1u_wal_svn st) (mkS0Noinit false S0T_Idle).

Definition stage1_confirm_self_update
    (st : Stage1SelfUpdateState) (confirmed_img : Stage1BankImage)
    : Stage1SelfUpdateState :=
  mkS1SelfUpd
    (s1u_banks st)
    (s1u_active_bank st)
    (Nat.max (s1u_wal_svn st) (s1b_svn confirmed_img))
    (mkS0Noinit false S0T_Idle).

Lemma put_get_other_bank :
  forall banks b img,
    get_stage1_bank (put_stage1_bank banks (flip_bank b) img) b =
    get_stage1_bank banks b.
Proof.
  intros [ba bb] [|] img; reflexivity.
Qed.

(* Theorem FV-10b: Stage-1 Dual-Bank Self-Update Non-Brickability & Deferred
   SVN Ratification.
   1. Staging any candidate (valid, corrupted, or mid-write torn) into
      flip_bank(active_bank) preserves the known-good active bank bit-identically
      and keeps wal_stage1_svn unratcheted.
   2. On ANY subsequent boot (power-cut before pointer switch, power-cut/corrupt
      candidate after pointer switch, OR tentative boot followed by WDT/HardFault
      crash reset), eval_stage0 NEVER dead-halts: it deterministically boots a
      verified Stage-1 bank (recovering to the intact old bank whenever the
      candidate fails verification or crashes during its tentative trial!).
   3. Confirming a verified candidate ratchets wal_stage1_svn monotonically. *)
Theorem stage1_self_update_non_brick :
  forall st cand ptr_switched cfg_s1_svn otp_keys pk active_key_idx dslc_samples d rst,
    scan_otp_keys otp_keys = OS_Ok active_key_idx pk ->
    dslc_quorum_5 dslc_samples = Some d ->
    d < dslc_decommissioned_byte ->
    stage0_verify_bank
      (get_stage1_bank (s1u_banks st) (s1u_active_bank st))
      active_key_idx
      (Nat.max cfg_s1_svn (s1u_wal_svn st)) = true ->
    let st_staged := stage1_stage_self_update st cand ptr_switched in
    let wal_q := make_uniform_s0_wal (s1u_active_bank st_staged) (s1u_wal_svn st_staged) in
    (* 1. Known-good bank & unratcheted SVN floor preserved *)
    get_stage1_bank (s1u_banks st_staged) (s1u_active_bank st) =
      get_stage1_bank (s1u_banks st) (s1u_active_bank st) /\
    s1u_wal_svn st_staged = s1u_wal_svn st /\
    (* 2. Stage 0 never bricks (always boots a verified bank) *)
    (exists b_boot img_boot proof_boot noinit_boot,
       eval_stage0 true cfg_s1_svn otp_keys dslc_samples wal_q
                   (s1u_noinit st_staged) rst (s1u_banks st_staged) =
         S0_BootStage1 b_boot img_boot proof_boot noinit_boot /\
       stage0_verify_bank img_boot active_key_idx (Nat.max cfg_s1_svn (s1u_wal_svn st)) = true /\
       (* Crash during tentative trial flips straight back to the intact bank *)
       (ptr_switched = true -> rst_indicates_crash rst = true ->
        b_boot = s1u_active_bank st /\
        img_boot = get_stage1_bank (s1u_banks st) (s1u_active_bank st) /\
        s0n_tag noinit_boot = S0T_Reverted)) /\
    (* 3. Post-confirmation monotonic Stage-1 SVN ratchet *)
    s1u_wal_svn st <= s1u_wal_svn (stage1_confirm_self_update st_staged cand).
Proof.
  intros st cand ptr_switched cfg_s1_svn otp_keys pk active_key_idx dslc_samples d rst
         Hscan Hdslc Hd_lt Hgood_ok.
  cbv zeta.
  assert (Hpres_old :
    get_stage1_bank (s1u_banks (stage1_stage_self_update st cand ptr_switched))
                    (s1u_active_bank st) =
    get_stage1_bank (s1u_banks st) (s1u_active_bank st)).
  { unfold stage1_stage_self_update.
    destruct ptr_switched; simpl; apply put_get_other_bank. }
  assert (Hsvn_eq :
    s1u_wal_svn (stage1_stage_self_update st cand ptr_switched) = s1u_wal_svn st).
  { unfold stage1_stage_self_update; destruct ptr_switched; reflexivity. }
  split; [exact Hpres_old|].
  split; [exact Hsvn_eq|].
  split.
  - unfold eval_stage0.
    rewrite Hscan, Hdslc.
    assert (Ed_neq : (d =? dslc_decommissioned_byte) = false)
      by (apply Nat.eqb_neq; unfold dslc_decommissioned_byte in *; lia).
    rewrite Ed_neq; simpl.
    pose proof (uniform_s0_wal_props
                  (s1u_active_bank (stage1_stage_self_update st cand ptr_switched))
                  (s1u_wal_svn (stage1_stage_self_update st cand ptr_switched)))
      as [Hvote Hmax].
    rewrite Hvote, Hmax, Hsvn_eq.
    set (min_svn := Nat.max cfg_s1_svn (s1u_wal_svn st)) in *.
    unfold s0_resolve_tentative_bank, stage1_stage_self_update in *.
    destruct (s1u_banks st) as [ba bb]; simpl in *.
    destruct (s1u_active_bank st); destruct ptr_switched; simpl in *.
    + destruct (rst_indicates_crash rst) eqn:Ecrash; simpl.
      * rewrite Hgood_ok; do 4 eexists; repeat split; reflexivity || exact Hgood_ok.
      * destruct (stage0_verify_bank cand active_key_idx min_svn) eqn:Ecand.
        -- do 4 eexists; split; [reflexivity | split; [exact Ecand | intros _ Hc; congruence]].
        -- rewrite Hgood_ok; do 4 eexists; split; [reflexivity | split; [exact Hgood_ok | intros _ Hc; congruence]].
    + rewrite Hgood_ok; do 4 eexists; split; [reflexivity | split; [exact Hgood_ok | intros Hp _; discriminate Hp]].
    + destruct (rst_indicates_crash rst) eqn:Ecrash; simpl.
      * rewrite Hgood_ok; do 4 eexists; repeat split; reflexivity || exact Hgood_ok.
      * destruct (stage0_verify_bank cand active_key_idx min_svn) eqn:Ecand.
        -- do 4 eexists; split; [reflexivity | split; [exact Ecand | intros _ Hc; congruence]].
        -- rewrite Hgood_ok; do 4 eexists; split; [reflexivity | split; [exact Hgood_ok | intros _ Hc; congruence]].
    + rewrite Hgood_ok; do 4 eexists; split; [reflexivity | split; [exact Hgood_ok | intros Hp _; discriminate Hp]].
  - unfold stage1_confirm_self_update; simpl; lia.
Qed.

(* ========================================================================== *)
(* SECTION 4: FV-11 Proofs — DSLC Irreversible Progression & Revoke Gate      *)
(* ========================================================================== *)

Inductive DslcTransitionEvent : Type :=
  | DTE_ProvSetDslc : nat (* requested_dslc *) -> DslcTransitionEvent
  | DTE_FuseRatchet : nat (* next_dslc *) -> DslcTransitionEvent
  | DTE_CloudRevoke : bool (* token_authenticated *) -> DslcTransitionEvent
  | DTE_Reboot      : DslcTransitionEvent.

(* Hardware + firmware DSLC state transition:
   - UART PROV_CMD_SET_DSLC is ONLY accepted when current DSLC == 0x00 (Blank)
     and requested value is in 1..254 (rejecting 0x00 no-op / 0xFF brick via prov).
   - Fuse ratchet transitions monotonically upward within 1..254 (OTP 0->1 fuses
     cannot clear 1->0).
   - Authenticated TOOB_CMD_REVOKE burns all 8 bits to 0xFF (255), permanently
     decommissioning the device.
   - Hardware reboots preserve the non-volatile OTP DSLC byte. *)
Definition step_dslc_lifecycle (cur : nat) (ev : DslcTransitionEvent) : nat :=
  match ev with
  | DTE_ProvSetDslc req =>
      if (cur =? dslc_blank_byte) && dslc_is_active_provisioned req then req
      else cur
  | DTE_FuseRatchet nxt =>
      if dslc_is_active_provisioned cur && (cur <=? nxt) && (nxt <? dslc_decommissioned_byte)
      then nxt
      else cur
  | DTE_CloudRevoke auth_ok =>
      if auth_ok && (cur <=? dslc_decommissioned_byte) then dslc_decommissioned_byte
      else cur
  | DTE_Reboot => cur
  end.

Fixpoint run_dslc_trace (cur : nat) (evs : list DslcTransitionEvent) : nat :=
  match evs with
  | [] => cur
  | ev :: rest => run_dslc_trace (step_dslc_lifecycle cur ev) rest
  end.

Lemma step_dslc_monotonic :
  forall cur ev,
    cur <= dslc_decommissioned_byte ->
    cur <= step_dslc_lifecycle cur ev /\
    step_dslc_lifecycle cur ev <= dslc_decommissioned_byte /\
    (cur = dslc_decommissioned_byte -> step_dslc_lifecycle cur ev = dslc_decommissioned_byte).
Proof.
  intros cur ev Hle.
  unfold step_dslc_lifecycle, dslc_is_active_provisioned,
         dslc_blank_byte, dslc_decommissioned_byte in *.
  destruct ev as [req | nxt | auth_ok | ].
  - destruct ((cur =? 0) && ((0 <? req) && (req <? 255))) eqn:E.
    + rewrite !Bool.andb_true_iff in E; destruct E as [Ec [Er1 Er2]].
      apply Nat.eqb_eq in Ec; apply Nat.ltb_lt in Er1; apply Nat.ltb_lt in Er2.
      repeat split; lia.
    + repeat split; lia.
  - destruct (((0 <? cur) && (cur <? 255)) && (cur <=? nxt) && (nxt <? 255)) eqn:E.
    + rewrite !Bool.andb_true_iff in E; destruct E as [[[Ec1 Ec2] Hcn] Hn].
      apply Nat.leb_le in Hcn; apply Nat.ltb_lt in Hn.
      repeat split; lia.
    + repeat split; lia.
  - destruct (auth_ok && (cur <=? 255)) eqn:E.
    + repeat split; lia.
    + repeat split; lia.
  - repeat split; lia.
Qed.

(* Theorem FV-11a: DSLC Irreversible Monotonic Lifecycle Progression *)
Theorem dslc_irreversible_progression :
  forall evs cur,
    cur <= dslc_decommissioned_byte ->
    let final := run_dslc_trace cur evs in
    (* 1. Monotonic non-decreasing progression bounded by 0xFF *)
    cur <= final /\
    final <= dslc_decommissioned_byte /\
    (* 2. Provisioned devices (cur > 0) can NEVER revert to Blank (0x00) *)
    (dslc_blank_byte < cur -> dslc_blank_byte < final) /\
    (* 3. Decommissioned devices (0xFF) remain 0xFF across ALL future events/reboots *)
    (cur = dslc_decommissioned_byte -> final = dslc_decommissioned_byte) /\
    (* 4. PROV_CMD_SET_DSLC is permanently ignored once cur > 0 *)
    (forall req, dslc_blank_byte < cur -> step_dslc_lifecycle cur (DTE_ProvSetDslc req) = cur).
Proof.
  induction evs as [|ev rest IH]; intros cur Hle; cbv zeta.
  - simpl; split_conj; try lia.
    intros req Hgt.
    unfold step_dslc_lifecycle, dslc_blank_byte in *.
    assert (Ez : (cur =? 0) = false) by (apply Nat.eqb_neq; lia).
    rewrite Ez; reflexivity.
  - simpl.
    pose proof (step_dslc_monotonic cur ev Hle) as [Hstep_ge [Hstep_ub Hstep_dec]].
    pose proof (IH (step_dslc_lifecycle cur ev) Hstep_ub)
      as [Htr_ge [Htr_ub [Htr_pos [Htr_dec _]]]].
    split_conj; try lia.
    intros req Hgt.
    unfold step_dslc_lifecycle, dslc_blank_byte in *.
    assert (Ez : (cur =? 0) = false) by (apply Nat.eqb_neq; lia).
    rewrite Ez; reflexivity.
Qed.

(* Theorem FV-11b: No Unprovisioned (0x00) or Decommissioned (0xFF) App Boot,
   including permanent post-TOOB_CMD_REVOKE non-bootability across reboots *)
Theorem no_unprovisioned_or_revoked_app_boot :
  forall prov_wired cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1,
    (dslc_quorum_5 dslc_samples = None \/
     dslc_quorum_5 dslc_samples = Some dslc_blank_byte \/
     dslc_quorum_5 dslc_samples = Some dslc_decommissioned_byte) ->
    forall b_exec s1_img proof app_img tent nonce st_out,
      eval_stage0_then_stage1 true prov_wired cfg_s1_svn otp_keys dslc_samples
                              wal_q noinit banks cfg1 st1 <>
      Chain_Boot_App b_exec s1_img proof app_img tent nonce st_out.
Proof.
  intros prov_wired cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1
         Hdslc b_exec s1_img proof app_img tent nonce st_out Hcontra.
  unfold eval_stage0_then_stage1, eval_stage0_then_stage1_did in Hcontra.
  destruct (eval_stage0 true cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks)
    as [b0 s1_0 proof0 noinit0 | ] eqn:Es0; [|discriminate Hcontra].
  destruct (negb (bp_sealed_ok proof0)); [discriminate Hcontra|].
  unfold eval_stage1_dslc_gate in Hcontra; cbv zeta in Hcontra.
  destruct Hdslc as [Hnone | [Hblank | Hdec]].
  - rewrite Hnone in Hcontra; discriminate Hcontra.
  - rewrite Hblank in Hcontra; simpl in Hcontra.
    destruct prov_wired; discriminate Hcontra.
  - rewrite Hdec in Hcontra; simpl in Hcontra; discriminate Hcontra.
Qed.

(* Theorem FV-11c (CRIT-31a): Unprovisioned Device (DSLC == 0x00) with UART
   Provisioning Disabled / Unwired (prov_uart_wired = false) Halts in Stage 1.
   - Stage 0 allows DSLC == 0x00 into verified Stage 1;
   - Stage 1's unconditional read_dslc gate halts at Chain_Stage1_Halt when
     prov_uart_wired = false (never entering Chain_Provisioning, Chain_Recovery,
     or Chain_Boot_App), and enters Chain_Provisioning iff prov_uart_wired = true! *)
Theorem unprovisioned_without_uart_halts_in_stage1 :
  forall cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1,
    dslc_quorum_5 dslc_samples = Some dslc_blank_byte ->
    (* 1. Whenever Stage 0 boots Stage 1, prov_uart_wired = false yields Chain_Stage1_Halt
          and prov_uart_wired = true yields Chain_Provisioning *)
    (forall b_exec s1_img proof noinit',
       eval_stage0 true cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks =
         S0_BootStage1 b_exec s1_img proof noinit' ->
       eval_stage0_then_stage1 true false cfg_s1_svn otp_keys dslc_samples
                               wal_q noinit banks cfg1 st1 = Chain_Stage1_Halt /\
       (bp_sealed_ok proof = true ->
        eval_stage0_then_stage1 true true cfg_s1_svn otp_keys dslc_samples
                                wal_q noinit banks cfg1 st1 = Chain_Provisioning b_exec s1_img)) /\
    (* 2. Across ALL Stage 0 outcomes, prov_uart_wired = false always halts *)
    (eval_stage0_then_stage1 true false cfg_s1_svn otp_keys dslc_samples
                             wal_q noinit banks cfg1 st1 = Chain_Stage0_Halt \/
     eval_stage0_then_stage1 true false cfg_s1_svn otp_keys dslc_samples
                             wal_q noinit banks cfg1 st1 = Chain_Stage1_Halt).
Proof.
  intros cfg_s1_svn otp_keys dslc_samples wal_q noinit banks cfg1 st1 Hblank.
  unfold eval_stage0_then_stage1, eval_stage0_then_stage1_did.
  rewrite Hblank.
  split.
  - intros b_exec s1_img proof noinit' Hs0.
    rewrite Hs0.
    destruct (bp_sealed_ok proof); simpl; split; try reflexivity; intro Hfalse; discriminate Hfalse.
  - destruct (eval_stage0 true cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks)
      as [b0 s1_0 proof0 noinit0 | ].
    + right; destruct (negb (bp_sealed_ok proof0)); reflexivity.
    + left; reflexivity.
Qed.

(* Theorem FV-11d (CRIT-31b): Single-Fault Defense-in-Depth — Stage 1's
   Unconditional read_dslc Gate Blocks Faulted Stage 0.
   Even if a hardware glitch skipped Stage 0's 0xFF decommission gate
   (enforce_stage0_gate = false), Stage 1's independent unconditional read_dslc
   gate (enforce_stage1_gate = true) STILL prevents s1_dslc_opt = None,
   s1_dslc_opt = Some 0x00, or s1_dslc_opt = Some (>= 0xFF) from ever reaching
   Chain_Boot_App or Chain_Recovery! *)
Theorem stage1_independent_dslc_gate_blocks_faulted_stage0 :
  forall prov_wired cfg_s1_svn otp_keys dslc_samples s1_dslc_opt
         wal_q noinit banks cfg1 st1,
    (s1_dslc_opt = None \/
     s1_dslc_opt = Some dslc_blank_byte \/
     exists d, s1_dslc_opt = Some d /\ dslc_decommissioned_byte <= d) ->
    let out := eval_stage0_then_stage1_did false true prov_wired cfg_s1_svn
                 otp_keys dslc_samples s1_dslc_opt wal_q noinit banks cfg1 st1 in
    (* 1. Never boots App or Recovery OS regardless of Stage 0 fault *)
    (forall b_exec s1_img proof app_img tent nonce st_out,
       out <> Chain_Boot_App b_exec s1_img proof app_img tent nonce st_out) /\
    (forall b_exec s1_img rmode st_out,
       out <> Chain_Recovery b_exec s1_img rmode st_out) /\
    (* 2. Deterministic Stage 1 halt on None, >= 0xFF, or (0x00 with prov_wired = false) *)
    (forall b_exec s1_img proof noinit',
       eval_stage0 false cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks =
         S0_BootStage1 b_exec s1_img proof noinit' ->
       (s1_dslc_opt = None \/
        (prov_wired = false /\ s1_dslc_opt = Some dslc_blank_byte) \/
        (exists d, s1_dslc_opt = Some d /\ dslc_decommissioned_byte <= d)) ->
       out = Chain_Stage1_Halt).
Proof.
  intros prov_wired cfg_s1_svn otp_keys dslc_samples s1_dslc_opt
         wal_q noinit banks cfg1 st1 Hbad; cbv zeta.
  unfold eval_stage0_then_stage1_did.
  assert (Hgate :
    forall b0 s1_0 proof0,
      let g := eval_stage1_dslc_gate true prov_wired s1_dslc_opt b0 s1_0 proof0 cfg1 st1 in
      (g = Chain_Stage1_Halt \/ g = Chain_Provisioning b0 s1_0) /\
      ((s1_dslc_opt = None \/
        (prov_wired = false /\ s1_dslc_opt = Some dslc_blank_byte) \/
        (exists d, s1_dslc_opt = Some d /\ dslc_decommissioned_byte <= d)) ->
       g = Chain_Stage1_Halt)).
  { intros b0 s1_0 proof0; cbv zeta; unfold eval_stage1_dslc_gate; cbv zeta.
    destruct Hbad as [-> | [-> | [d [-> Hd]]]].
    - split; [left; reflexivity | intros _; reflexivity].
    - simpl; split.
      + destruct prov_wired; [right | left]; reflexivity.
      + intros [Hnone | [[-> _] | [d [Hsome Hd]]]];
          [discriminate Hnone | reflexivity | inversion Hsome; unfold dslc_blank_byte, dslc_decommissioned_byte in *; lia].
    - assert (Enz : (d =? dslc_blank_byte) = false)
        by (apply Nat.eqb_neq; unfold dslc_blank_byte, dslc_decommissioned_byte in *; lia).
      assert (Enact : dslc_is_active_provisioned d = false).
      { unfold dslc_is_active_provisioned, dslc_decommissioned_byte in *.
        assert (Elt : (d <? 255) = false) by (apply Nat.ltb_ge; lia).
        rewrite Elt, Bool.andb_false_r; reflexivity. }
      rewrite Enz, Enact; split; [left; reflexivity | intros _; reflexivity]. }
  destruct (eval_stage0 false cfg_s1_svn otp_keys dslc_samples wal_q noinit (st_reset st1) banks)
    as [b0 s1_0 proof0 noinit0 | ].
  - destruct (negb (bp_sealed_ok proof0)).
    + repeat split; try (intros; discriminate); reflexivity.
    + destruct (Hgate b0 s1_0 proof0) as [[Hg | Hg] Hhalt].
      * rewrite Hg; repeat split; try (intros; discriminate); reflexivity.
      * rewrite Hg; repeat split; try (intros; discriminate).
        intros _ _ _ _ _ Hsub; rewrite <- Hg; exact (Hhalt Hsub).
  - repeat split; intros; discriminate.
Qed.

(* Formal Bug-Discovery Witness for Finding E / CRIT-31:
   In pre-fix stage0_main.c:370 ((void)confirmed_dslc;) and boot_main.c:426-438
   (enforce_dslc_gate = false), BOTH:
     1. A revoked device (DSLC = 0xFF) boots Chain_Boot_App after reset; and
     2. An unprovisioned device (DSLC = 0x00) with prov_uart_wired = false boots
        Chain_Boot_App instead of halting at Chain_Stage1_Halt! *)
Lemma dslc_revoked_post_reboot_bypass_witness :
  let otp_keys := [OKS_Valid 42; OKS_Blank] in
  let revoked_samples := [Some 255; Some 255; Some 255; Some 255; Some 255] in
  let blank_samples := [Some 0; Some 0; Some 0; Some 0; Some 0] in
  let wal_q := make_uniform_s0_wal Bank_A 1 in
  let noinit := mkS0Noinit false S0T_Idle in
  let s1_ok := mkStage1Bank true true true 0 1 in
  let banks := mkStage1DualBanks s1_ok erased_stage1_bank in
  let app_ok := mkSlotImage true true true true 2 0 20 in
  let slots := mkFlashSlots app_ok erased_slot_image app_ok true CC_Empty MBX_Empty in
  let wal := mkWAL [RWE_Valid WI_None 0 true] in
  let tmr := mkTMR 2 1 0 0 0 0 0 true in
  let st1 := mkState slots wal tmr (mkConfirmStore 0) (mkOTPEpoch 1 0) RR_Watchdog in
  eval_stage0_then_stage1 true true 1 otp_keys revoked_samples wal_q noinit banks
                          default_boot_config st1 = Chain_Stage0_Halt /\
  eval_stage0_then_stage1 true false 1 otp_keys blank_samples wal_q noinit banks
                          default_boot_config st1 = Chain_Stage1_Halt /\
  (exists proof st_out,
     eval_stage0_then_stage1 false true 1 otp_keys revoked_samples wal_q noinit banks
                             default_boot_config st1 =
       Chain_Boot_App Bank_A s1_ok proof app_ok false 0 st_out) /\
  (exists proof st_out,
     eval_stage0_then_stage1 false false 1 otp_keys blank_samples wal_q noinit banks
                             default_boot_config st1 =
       Chain_Boot_App Bank_A s1_ok proof app_ok false 0 st_out).
Proof.
  vm_compute; repeat split; try reflexivity; do 2 eexists; reflexivity.
Qed.
