(* ========================================================================== *)
(* Toob-Loader Formal Verification                                            *)
(* File: BootOracleGen.v                                                      *)
(*                                                                            *)
(* Verified exhaustive Cartesian-product test-vector generator and OCaml      *)
(* extraction coupling BootTransitions.eval_boot_state 1:1 to Host-SIL        *)
(* production C (test/host/test_rocq_oracle.c).                               *)
(* ========================================================================== *)

From Stdlib Require Import Bool Arith Lia List Extraction.
From ToobBoot Require Import BootModel BootTransitions.
Import ListNotations.

(* -------------------------------------------------------------------------- *)
(* 1. Compact Integer Encodings Shared 1:1 with test_rocq_oracle.c            *)
(* -------------------------------------------------------------------------- *)

Record OracleInput : Type := mkOracleInput {
  oi_suite           : nat; (* 0=MainCartesian, 1=RecExhausted, 2=Mailbox, 3=Cloud, 4=Tamper *)
  oi_slot_cfg        : nat; (* 0=AppOkBkupOk, 1=AppOkBkupBad, 2=AppBadBkupOk, 3=BothBad *)
  oi_stg_cfg         : nat; (* 0=CorruptTBM1, 1..8 = 2x2x2 cube (sig_ok, svn_ok, key_ok) *)
  oi_wal_intent      : nat; (* 0..7 canonical WAL intents *)
  oi_confirm_cfg     : nat; (* 0=None, 1=ActiveUnconf, 2=WalMatch, 3=RtcMatch *)
  oi_retry_count     : nat; (* 0..5 (0 .. BOOT_CONFIG_MAX_RETRIES + 2) *)
  oi_rec_retry_count : nat; (* 0, 5, or 6 (boundary around BOOT_CONFIG_MAX_RECOVERY_RETRIES) *)
  oi_reset_reason    : nat; (* 0=POR, 1=PIN, 2=SW, 3=WDT, 4=BROWNOUT, 5=HARD_FAULT *)
  oi_mbx_cfg         : nat; (* 0=Empty, 1..7 mailbox scenarios *)
  oi_cloud_cfg       : nat; (* 0=Empty, 1..11 cloud command scenarios *)
  oi_tamper_cfg      : nat  (* 0=Clean, 1=TmrMacBad, 2=WalSecMacBad, 3=AuxHealMacBad *)
}.

Record OracleRow : Type := mkOracleRow {
  or_in              : OracleInput;
  or_out_kind        : nat; (* 0=Boot_App, 1=Enter_Recovery_PartitionOS, 2=SerialRescuePanic *)
  or_out_err         : nat; (* 0=OK, 1=Verify, 2=InvalidArg, 3=NotFound, 4=Locked, 5=RecReq *)
  or_out_tentative   : nat; (* 0 or 1 *)
  or_out_app_id      : nat; (* post-boot app_slot payload_id: 0=corrupt, 10=bkup_v1, 20=app_v2, 30=stg_v3 *)
  or_out_bf          : nat; (* post-boot tmr.boot_failure_counter *)
  or_out_rf          : nat; (* post-boot tmr.recovery_failure_counter *)
  or_out_nonce_act   : nat; (* 1 iff post-boot active_nonce > 0 else 0 *)
  or_out_wal_intent  : nat; (* 0..7 reconstructed post-boot WAL intent *)
  or_out_tmr_svn     : nat; (* post-boot tmr.app_svn *)
  or_out_otp_svn     : nat; (* post-boot otp.otp_min_svn *)
  or_out_issued_at   : nat; (* post-boot tmr.last_cloud_issued_at (MED-28) *)
  or_out_wipe        : nat  (* post-boot handoff.wipe_requested (HIGH-32) *)
}.

(* -------------------------------------------------------------------------- *)
(* 2. Bijective Encoders / Decoders                                           *)
(* -------------------------------------------------------------------------- *)

Definition decode_wal_intent (code : nat) : WalIntent :=
  match code with
  | 0 => WI_None
  | 1 => WI_UpdatePending
  | 2 => WI_TxnCommit
  | 3 => WI_ConfirmCommit
  | 4 => WI_RecoveryResolved
  | 5 => WI_TxnRollback
  | 6 => WI_TxnRollbackPending
  | _ => WI_DeviceLocked
  end.

Definition encode_wal_intent (i : WalIntent) : nat :=
  match i with
  | WI_None               => 0
  | WI_UpdatePending      => 1
  | WI_TxnCommit          => 2
  | WI_ConfirmCommit      => 3
  | WI_RecoveryResolved   => 4
  | WI_TxnRollback        => 5
  | WI_TxnRollbackPending => 6
  | WI_DeviceLocked       => 7
  end.

Definition decode_reset_reason (code : nat) : ResetReason :=
  match code with
  | 0 => RR_PowerOn
  | 1 => RR_PinReset
  | 2 => RR_Software
  | 3 => RR_Watchdog
  | 4 => RR_Brownout
  | _ => RR_HardFault
  end.

Definition encode_err_code (e : BootErrCode) : nat :=
  match e with
  | Err_Verify            => 1
  | Err_InvalidArg        => 2
  | Err_NotFound          => 3
  | Err_DeviceLocked      => 4
  | Err_RecoveryRequested => 5
  | Err_NotSupported      => 6
  end.

(* Baseline OTP: otp_min_svn = 1, otp_active_key_index = 1 (key 0 is revoked!) *)
Definition baseline_otp : OTP_Epoch := mkOTPEpoch 1 1.

Definition img_corrupt : SlotImage :=
  mkSlotImage false false false false 0 0 0.

Definition img_bkup_v1 : SlotImage :=
  mkSlotImage true true true true 1 1 10.

Definition img_app_v2 : SlotImage :=
  mkSlotImage true true true true 2 1 20.

(* 9 Staging configurations:
   0: Corrupt / erased TBM1
   1..8: 2x2x2 cube over (sig_ok, svn_ok: 0 vs 3, key_ok: 0=revoked vs 1=active) *)
Definition decode_stg_image (cfg : nat) : SlotImage :=
  match cfg with
  | 0 => img_corrupt
  | 1 => mkSlotImage true true false true 0 0 30 (* bad sig, downgrade svn=0, revoked key=0 *)
  | 2 => mkSlotImage true true false true 0 1 30 (* bad sig, downgrade svn=0, active key=1 *)
  | 3 => mkSlotImage true true false true 3 0 30 (* bad sig, valid svn=3,     revoked key=0 *)
  | 4 => mkSlotImage true true false true 3 1 30 (* bad sig, valid svn=3,     active key=1 *)
  | 5 => mkSlotImage true true true  true 0 0 30 (* ok sig,  downgrade svn=0, revoked key=0 *)
  | 6 => mkSlotImage true true true  true 0 1 30 (* ok sig,  downgrade svn=0, active key=1 *)
  | 7 => mkSlotImage true true true  true 3 0 30 (* ok sig,  valid svn=3,     revoked key=0 *)
  | _ => mkSlotImage true true true  true 3 1 30 (* ok sig,  valid svn=3,     active key=1 -> APPLIES! *)
  end.

Definition decode_app_bkup (cfg : nat) : (SlotImage * SlotImage) :=
  match cfg with
  | 0 => (img_app_v2,  img_bkup_v1)
  | 1 => (img_app_v2,  img_corrupt)
  | 2 => (img_corrupt, img_bkup_v1)
  | _ => (img_corrupt, img_corrupt)
  end.

(* Confirm/Nonce configurations (active tentative nonce = 7):
   0: active_nonce = 0, wal_exp = 0, rtc = 0
   1: active_nonce = 7, wal_exp = 5 (mismatch), rtc = 0
   2: active_nonce = 7, wal_exp = 7 (match),    rtc = 0
   3: active_nonce = 7, wal_exp = 5,            rtc = 7 (RTC match) *)
Definition decode_confirm_quad (cfg : nat) : (nat * nat * nat) :=
  match cfg with
  | 0 => (0, 0, 0)
  | 1 => (7, 5, 0)
  | 2 => (7, 7, 0)
  | _ => (7, 5, 7)
  end.

(* Mailbox scenarios (last_mbx_seq initialized to 1):
   0: Empty
   1: seq=2, TOOB_REQ_CONFIRM with matching nonce 7
   2: seq=2, TOOB_REQ_CONFIRM with mismatched nonce 5
   3: seq=2, TOOB_REQ_CONFIRM with zero nonce 0 (-> rejected by mbx_read_valid, no-op)
   4: seq=2, TOOB_REQ_UPDATE_PENDING
   5: seq=2, CRIT-24 cumulative TOOB_REQ_CONFIRM(7) | TOOB_REQ_UPDATE_PENDING
   6: seq=2, CRIT-24 cumulative TOOB_REQ_RECOVERY_RESOLVED | TOOB_REQ_UPDATE_PENDING
   7: seq=1 (stale seq <= last_mbx_seq), TOOB_REQ_UPDATE_PENDING (ignored!) *)
Definition decode_mailbox (cfg : nat) : MailboxSlot :=
  match cfg with
  | 0 => MBX_Empty
  | 1 => MBX_Record true 2 true  false false 7
  | 2 => MBX_Record true 2 true  false false 5
  | 3 => MBX_Record true 2 true  false false 0
  | 4 => MBX_Record true 2 false true  false 0
  | 5 => MBX_Record true 2 true  true  false 7
  | 6 => MBX_Record true 2 false true  true  0
  | _ => MBX_Record true 1 false true  false 0
  end.

(* Cloud Command scenarios (baseline otp_min_svn=1, last_cloud_issued_at=10):
   0:  Empty
   1:  Valid KILLSWITCH (counter_min=2, issued_at=20)
   2:  Valid UNLOCK     (counter_min=2, issued_at=20)
   3:  Valid FORCE_UPDATE (counter_min=2, issued_at=20)
   4:  Unauthenticated KILLSWITCH (sig_valid=false, counter_min=2, issued_at=20)
   5:  Counter-replay KILLSWITCH (sig_valid=true, counter_min=1 <= otp_min_svn, issued_at=20)
   6:  Max-burn-cap UNLOCK (counter_min=5, delta=4 == toob_cmd_max_burn_steps, issued_at=20)
   7:  Over-burn-cap UNLOCK (counter_min=6, delta=5 > toob_cmd_max_burn_steps, rejected)
   8:  Timestamp-replay UNLOCK (counter_min=2, issued_at=10 <= last_cloud_issued_at, rejected)
   9:  Device-ID-mismatch UNLOCK (sig_valid=true, device_match=false, counter_min=2, rejected)
   10: Valid NOP (counter_min=3, issued_at=20, burns fuses without unlocking WI_DeviceLocked)
   11: Valid WIPE (counter_min=2, issued_at=20, HIGH-32 unlocks WI_DeviceLocked + sets wipe_requested) *)
Definition decode_cloud (cfg : nat) : CloudCmdSlot :=
  match cfg with
  | 0  => CC_Empty
  | 1  => CC_Token CCK_Killswitch  true  true  2 20
  | 2  => CC_Token CCK_Unlock      true  true  2 20
  | 3  => CC_Token CCK_ForceUpdate true  true  2 20
  | 4  => CC_Token CCK_Killswitch  false true  2 20
  | 5  => CC_Token CCK_Killswitch  true  true  1 20
  | 6  => CC_Token CCK_Unlock      true  true  5 20
  | 7  => CC_Token CCK_Unlock      true  true  6 20
  | 8  => CC_Token CCK_Unlock      true  true  2 10
  | 9  => CC_Token CCK_Unlock      true  false 2 20
  | 10 => CC_Token CCK_Nop         true  true  3 20
  | _  => CC_Token CCK_Wipe        true  true  2 20
  end.

Definition decode_oracle_input (inp : OracleInput) : State :=
  let '(app_i, bkup_i) := decode_app_bkup (oi_slot_cfg inp) in
  let stg_i := decode_stg_image (oi_stg_cfg inp) in
  let mbx_i := decode_mailbox (oi_mbx_cfg inp) in
  let cld_i := decode_cloud (oi_cloud_cfg inp) in
  let slots := mkFlashSlots app_i stg_i bkup_i true cld_i mbx_i in
  let '(act_n, wal_exp, rtc_n) := decode_confirm_quad (oi_confirm_cfg inp) in
  let wi := decode_wal_intent (oi_wal_intent inp) in
  let wal_mac_ok := negb (oi_tamper_cfg inp =? 2) in
  let tmr_mac_ok := negb (oi_tamper_cfg inp =? 1) in
  let wal :=
    if oi_tamper_cfg inp =? 3 then
      mkWAL [RWE_Valid wi wal_exp true;
             RWE_Sideband;
             RWE_Sideband;
             RWE_Valid WI_ConfirmCommit 7 false]
    else
      mkWAL [RWE_Valid wi wal_exp wal_mac_ok] in
  let tmr := mkTMR 1 0 (oi_retry_count inp) (oi_rec_retry_count inp)
                   act_n 1 10 tmr_mac_ok in
  let conf := mkConfirmStore rtc_n in
  let rst := decode_reset_reason (oi_reset_reason inp) in
  mkState slots wal tmr conf baseline_otp rst.

Definition eval_oracle_row (inp : OracleInput) : OracleRow :=
  let st0 := decode_oracle_input inp in
  let '(out, st1) := eval_boot_state default_boot_config st0 in
  let post_wal :=
    match wal_reconstruct_txn (st_wal st1) with
    | Some (wi, _) => encode_wal_intent wi
    | None => 0
    end in
  let post_nonce := if 0 <? active_nonce (st_tmr st1) then 1 else 0 in
  let post_app_id := payload_id (app_slot (st_slots st1)) in
  let post_bf := boot_failure_counter (st_tmr st1) in
  let post_rf := recovery_failure_counter (st_tmr st1) in
  let post_tmr_svn := tmr_app_svn (st_tmr st1) in
  let post_otp_svn := otp_min_svn (st_otp st1) in
  let post_issued := last_cloud_issued_at (st_tmr st1) in
  let post_wipe := if eval_boot_wipe_requested default_boot_config st0 then 1 else 0 in
  match out with
  | Boot_App img tent _ =>
      mkOracleRow inp 0 0 (if tent then 1 else 0)
                  (payload_id img) post_bf post_rf post_nonce
                  post_wal post_tmr_svn post_otp_svn post_issued post_wipe
  | Enter_Recovery_OS RM_PartitionOS =>
      mkOracleRow inp 1 0 0
                  post_app_id post_bf post_rf post_nonce
                  post_wal post_tmr_svn post_otp_svn post_issued post_wipe
  | Enter_Recovery_OS (RM_SerialRescue err) =>
      mkOracleRow inp 2 (encode_err_code err) 0
                  post_app_id post_bf post_rf post_nonce
                  post_wal post_tmr_svn post_otp_svn post_issued post_wipe
  end.

(* -------------------------------------------------------------------------- *)
(* 3. Exhaustive Cartesian-Product Vector Suites                              *)
(* -------------------------------------------------------------------------- *)

(* Suite 0a: Non-Update WAL Intents {0,2,3,4,5,6,7} x Slots(0..3) x Stg({0,8})
             x Confirm(0..3) x Retries(0..5) x Resets(0..5) = 8,064 vectors *)
Definition non_update_wal_codes : list nat := [0; 2; 3; 4; 5; 6; 7].

Definition gen_suite0_non_update : list OracleInput :=
  flat_map (fun sl =>
  flat_map (fun stg =>
  flat_map (fun wi =>
  flat_map (fun cf =>
  flat_map (fun bf =>
  map (fun rst => mkOracleInput 0 sl stg wi cf bf 0 rst 0 0 0)
      (seq 0 6))
      (seq 0 6))
      (seq 0 4))
      non_update_wal_codes)
      [0; 8])
      (seq 0 4).

(* Suite 0b: UpdatePending WAL Intent {1} x Slots(0..3) x Full 9-State Staging
             Cube (Corrupt + 2x2x2 Sig x SVN x KeyRevocation) x Confirm(0..3)
             x Retries(0..5) x Resets(0..5) = 5,184 vectors *)
Definition gen_suite0_update_cube : list OracleInput :=
  flat_map (fun sl =>
  flat_map (fun stg =>
  flat_map (fun cf =>
  flat_map (fun bf =>
  map (fun rst => mkOracleInput 0 sl stg 1 cf bf 0 rst 0 0 0)
      (seq 0 6))
      (seq 0 6))
      (seq 0 4))
      (seq 0 9))
      (seq 0 4).

(* Suite 1: Recovery-OS Escalation Boundary (rec_retry in {5, 6} around MAX_RECOVERY_RETRIES=5)
            x Slots(0..3) x WAL(0..7) x Retries({3, 4}) x Resets({0, 3}) = 256 vectors *)
Definition gen_suite1_rec_exhausted : list OracleInput :=
  flat_map (fun sl =>
  flat_map (fun wi =>
  flat_map (fun bf =>
  flat_map (fun rf =>
  map (fun rst => mkOracleInput 1 sl 0 wi 0 bf rf rst 0 0 0)
      [0; 3])
      [5; 6])
      [3; 4])
      (seq 0 8))
      (seq 0 4).

(* Suite 2: OS Mailbox v2 Fold-In, Replay/Zero-Nonce & Lock Interaction
            Mailbox(1..7) x Staging({4=BadSig, 8=Valid}) x WAL({0=None, 2=TxnCommit, 7=Locked})
            x Confirm({0=NoNonce, 1=Active7}) x Retries({0, 4}) = 168 vectors *)
Definition gen_suite2_mailbox : list OracleInput :=
  flat_map (fun mbx =>
  flat_map (fun stg =>
  flat_map (fun wi =>
  flat_map (fun cf =>
  map (fun bf => mkOracleInput 2 0 stg wi cf bf 0 2 mbx 0 0)
      [0; 4])
      [0; 1])
      [0; 2; 7])
      [4; 8])
      (seq 1 7).

(* Suite 3: Pre-Auth TCC1 Cloud Command Pipeline (Auth, Replay, Fuse-Cap, DevID, Nop, Unlock, Wipe)
            Cloud(1..11) x Staging({4=BadSig, 8=Valid}) x WAL({0=None, 2=TxnCommit, 7=Locked})
            x Reset({0=POR, 3=WDT}) = 132 vectors *)
Definition gen_suite3_cloud : list OracleInput :=
  flat_map (fun cld =>
  flat_map (fun stg =>
  flat_map (fun wi =>
  map (fun rst => mkOracleInput 3 0 stg wi 0 0 0 rst 0 cld 0)
      [0; 3])
      [0; 2; 7])
      [4; 8])
      (seq 1 11).

(* Suite 4: K4 MAC Tamper Detection (TMR MAC + Security-Bearing WAL Entry + Aux-Heal Entry)
            Tamper({1, 2, 3}) x WAL({0, 1, 2, 3, 7}) x Reset({0, 3}) = 30 vectors *)
Definition gen_suite4_tamper : list OracleInput :=
  flat_map (fun tmp =>
  flat_map (fun wi =>
  map (fun rst => mkOracleInput 4 0 0 wi 1 0 0 rst 0 0 tmp)
      [0; 3])
      [0; 1; 2; 3; 7])
      [1; 2; 3].

Definition all_oracle_inputs : list OracleInput :=
  gen_suite0_non_update ++
  gen_suite0_update_cube ++
  gen_suite1_rec_exhausted ++
  gen_suite2_mailbox ++
  gen_suite3_cloud ++
  gen_suite4_tamper.

Definition all_oracle_vectors : list OracleRow :=
  map eval_oracle_row all_oracle_inputs.

(* -------------------------------------------------------------------------- *)
(* 4. Machine-Checked Oracle Soundness Proof                                  *)
(* -------------------------------------------------------------------------- *)

Theorem all_oracle_vectors_sound :
  forall row,
    In row all_oracle_vectors ->
    row = eval_oracle_row (or_in row) /\
    let st0 := decode_oracle_input (or_in row) in
    let '(out, st1) := eval_boot_state default_boot_config st0 in
    match out with
    | Boot_App img tent _ =>
        or_out_kind row = 0 /\
        or_out_err row = 0 /\
        or_out_tentative row = (if tent then 1 else 0) /\
        or_out_app_id row = payload_id img
    | Enter_Recovery_OS RM_PartitionOS =>
        or_out_kind row = 1 /\
        or_out_err row = 0 /\
        or_out_tentative row = 0
    | Enter_Recovery_OS (RM_SerialRescue err) =>
        or_out_kind row = 2 /\
        or_out_err row = encode_err_code err /\
        or_out_tentative row = 0
    end /\
    or_out_bf row = boot_failure_counter (st_tmr st1) /\
    or_out_rf row = recovery_failure_counter (st_tmr st1) /\
    or_out_tmr_svn row = tmr_app_svn (st_tmr st1) /\
    or_out_otp_svn row = otp_min_svn (st_otp st1) /\
    or_out_issued_at row = last_cloud_issued_at (st_tmr st1) /\
    or_out_wipe row = (if eval_boot_wipe_requested default_boot_config st0 then 1 else 0).
Proof.
  intros row Hin.
  unfold all_oracle_vectors in Hin.
  apply in_map_iff in Hin as [inp [Hrow _]].
  subst row.
  assert (Hin_eq : or_in (eval_oracle_row inp) = inp).
  { unfold eval_oracle_row.
    destruct (eval_boot_state default_boot_config (decode_oracle_input inp)) as [out st1].
    destruct out as [img tent n | [|err]]; reflexivity. }
  rewrite Hin_eq.
  split; [reflexivity|].
  cbv zeta.
  unfold eval_oracle_row.
  destruct (eval_boot_state default_boot_config (decode_oracle_input inp)) as [out st1].
  destruct out as [img tent n | [|err]]; simpl; repeat split; reflexivity.
Qed.

(* Flat 23-field list representation for deterministic C header emission *)
Definition row_to_flat_list (r : OracleRow) : list nat :=
  let i := or_in r in
  [ oi_suite i; oi_slot_cfg i; oi_stg_cfg i; oi_wal_intent i;
    oi_confirm_cfg i; oi_retry_count i; oi_rec_retry_count i;
    oi_reset_reason i; oi_mbx_cfg i; oi_cloud_cfg i; oi_tamper_cfg i;
    or_out_kind r; or_out_err r; or_out_tentative r; or_out_app_id r;
    or_out_bf r; or_out_rf r; or_out_nonce_act r; or_out_wal_intent r;
    or_out_tmr_svn r; or_out_otp_svn r; or_out_issued_at r; or_out_wipe r ].

Definition all_oracle_flat_rows : list (list nat) :=
  map row_to_flat_list all_oracle_vectors.

(* Verified OCaml Extraction of both transition semantics & oracle generator *)
Extraction "D:/ToobStorage/tmp_build/f2_rocq/BootOracleExtracted.ml"
  eval_boot_state all_oracle_vectors all_oracle_flat_rows.

(* Verified Rocq VM evaluation dump for 1:1 C header generation *)
Redirect "D:/ToobStorage/tmp_build/f2_rocq/rocq_oracle_flat"
  Eval vm_compute in all_oracle_flat_rows.
