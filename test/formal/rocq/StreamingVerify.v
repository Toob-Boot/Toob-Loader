(* ========================================================================== *)
(* Toob-Loader Formal Verification — Streaming Pipeline, Multi-Image & RDelta *)
(* File: test/formal/rocq/StreamingVerify.v                                   *)
(* Covers:                                                                    *)
(*   FV-12 (P0): verify_before_active_slot_mutation                           *)
(*               scratchless_oneway_streaming_modes_rejected_cleanly (HIGH-33)*)
(*               multiimage_swap_bitmap_non_collision (CRIT-30)               *)
(*               (+ scratchless_oneway_heatshrink_premature_overwrite_witness *)
(*                  for Finding F)                                            *)
(*   FV-17 (P2): oneway_reverse_delta_lossless_rollback                       *)
(*               low_energy_deferral_counter_neutral_liveness                 *)
(* Zero Admitted, Zero Axioms.                                                *)
(* ========================================================================== *)

From Stdlib Require Import List Arith Bool PeanoNat Lia.
Import ListNotations.

From ToobBoot Require Import BootModel BootTransitions BootTheorems.

(* ========================================================================== *)
(* SECTION 1: 8-Stage Update Pipeline (P1..P8) Across Modes & Transports      *)
(*            Mirrors boot_state.c, boot_decomp.c, boot_merkle.c,             *)
(*            boot_effect.c, and boot_multiimage.c                            *)
(* ========================================================================== *)

Inductive PayloadMode : Type :=
  | PM_Raw          : PayloadMode (* TBM1_COMP_NONE *)
  | PM_Heatshrink   : PayloadMode (* TBM1_COMP_HEATSHRINK *)
  | PM_DeltaTDS1    : PayloadMode (* Forward patch TDS1 *)
  | PM_MultiImage   : PayloadMode (* Multi-component bundle *)
  | PM_ReverseDelta : PayloadMode (* OneWay + Region-6 Reverse-Delta *).

Inductive TransportKind : Type :=
  | TP_SwapScratch : TransportKind
  | TP_SwapMove    : TransportKind
  | TP_OneWay      : TransportKind
  | TP_Pointer     : TransportKind.

Inductive StreamDest : Type :=
  | Dest_VerifyInPlace  : StreamDest (* Raw payload already in pf_inactive_buf; no P6a write *)
  | Dest_InactiveBuffer : StreamDest (* Stream P6a into Scratch / Inactive Bank *)
  | Dest_ActiveApp      : StreamDest (* Pre-fix Finding F: stream directly to Active App *).

Inductive P3RouteResult : Type :=
  | Route_Ok           : StreamDest -> bool (* requires_swap *) -> P3RouteResult
  | Route_NotSupported : P3RouteResult.

Record CandidateBundle : Type := mkCandBundle {
  cb_mode               : PayloadMode;
  cb_transport          : TransportKind;
  cb_tbm1_ok            : bool;
  cb_key_idx            : nat;
  cb_sig_ok             : bool;
  cb_svn                : nat;
  cb_base_svn           : nat;  (* MED-27 delta base_svn *)
  cb_base_fp            : nat;  (* MED-27 delta base_fingerprint (> 0) *)
  cb_multiimage_hdr_ok  : bool; (* P5 sub-image bounds & header check *)
  cb_stream_output      : SectorImage; (* Output bytes written by P6a stream *)
  cb_merkle_ok          : bool; (* P6b 4KB chunked Merkle root verification *)
  cb_inner_tim1_ok      : bool; (* P6b inner TIM1 header check *)
  cb_required_energy_mv : nat   (* P7a worst-case flash energy threshold *)
}.

Record PipelineFlashState : Type := mkPipeFlash {
  pf_active_app      : SectorImage;
  pf_inactive_buf    : SectorImage;
  pf_backup_buf      : SectorImage;
  pf_active_app_fp   : nat;
  pf_has_scratch     : bool
}.

Inductive PipelineRunResult : Type :=
  | Pipe_Applied  : PipelineFlashState -> nat (* new_tmr_svn *) -> PipelineRunResult
  | Pipe_Deferred : PipelineFlashState -> PipelineRunResult
  | Pipe_Rejected : BootErrCode -> PipelineFlashState -> PipelineRunResult.

Definition mode_uses_delta_base (pm : PayloadMode) : bool :=
  match pm with
  | PM_DeltaTDS1 | PM_ReverseDelta => true
  | _ => false
  end.

(* MED-27: Delta payloads must match exact running tmr_app_svn and a non-zero
   active base image fingerprint before streaming reconstruction begins. *)
Definition check_med27_delta_base
    (cb : CandidateBundle) (tmr_svn active_fp : nat) : bool :=
  if mode_uses_delta_base (cb_mode cb) then
    (cb_base_svn cb =? tmr_svn) &&
    (0 <? cb_base_fp cb) &&
    (cb_base_fp cb =? active_fp)
  else
    true.

Definition mode_requires_out_of_place_stream (pm : PayloadMode) : bool :=
  match pm with
  | PM_Heatshrink | PM_DeltaTDS1 | PM_ReverseDelta => true
  | PM_Raw | PM_MultiImage                         => false
  end.

(* P3 Route Selection (boot_state.c:910-965, HIGH-33 fix):
   - On physical hardware with TOOB_TRANSPORT_ONEWAY and CHIP_SCRATCH_SLOT_SIZE == 0
     (pf_has_scratch = false), the candidate TBM1 bundle ALREADY sits in
     CHIP_STAGING_SLOT_ABS_ADDR (pf_inactive_buf), so Stage 1 cannot stream-decompress
     or delta-reconstruct from CHIP_STAGING_SLOT into CHIP_STAGING_SLOT in-place.
   - When safe_routing = true (post-HIGH-33 C fix):
     * (TP_OneWay, has_scratch = false) rejects out-of-place streaming modes
       (PM_Heatshrink, PM_DeltaTDS1, PM_ReverseDelta) right at P3 with
       Route_NotSupported (BOOT_ERR_NOT_SUPPORTED) BEFORE P6a ever executes;
     * PM_Raw / PM_MultiImage verifies in-place in pf_inactive_buf (Dest_VerifyInPlace)
       during P6b and copies to pf_active_app in P7b (requires_swap = true).
   - When safe_routing = false (pre-fix bug model for Finding F), (TP_OneWay,
     has_scratch = false, PM_Heatshrink) sets Dest_ActiveApp and requires_swap = false. *)
Definition route_stream_dest
    (safe_routing has_scratch : bool) (tp : TransportKind) (pm : PayloadMode)
    : P3RouteResult :=
  match tp, has_scratch with
  | TP_OneWay, false =>
      if safe_routing then
        if mode_requires_out_of_place_stream pm then
          Route_NotSupported
        else
          Route_Ok Dest_VerifyInPlace true
      else
        match pm with
        | PM_Heatshrink => Route_Ok Dest_ActiveApp false
        | _             => Route_Ok Dest_InactiveBuffer true
        end
  | _, _ =>
      if mode_requires_out_of_place_stream pm then
        Route_Ok Dest_InactiveBuffer true
      else
        Route_Ok Dest_VerifyInPlace true
  end.

Definition apply_stream_write
    (fl : PipelineFlashState) (dest : StreamDest) (bytes : SectorImage)
    : PipelineFlashState :=
  match dest with
  | Dest_VerifyInPlace =>
      fl
  | Dest_InactiveBuffer =>
      mkPipeFlash (pf_active_app fl) bytes (pf_backup_buf fl)
                  (pf_active_app_fp fl) (pf_has_scratch fl)
  | Dest_ActiveApp =>
      mkPipeFlash bytes (pf_inactive_buf fl) (pf_backup_buf fl)
                  (pf_active_app_fp fl) (pf_has_scratch fl)
  end.

(* Complete P1..P8 8-stage update pipeline execution *)
Definition eval_8stage_pipeline
    (safe_routing : bool)
    (fl : PipelineFlashState)
    (cb : CandidateBundle)
    (tmr : TMR_Counters)
    (otp : OTP_Epoch)
    (vbat_mv : nat)
    : PipelineRunResult :=
  (* P1: Envelope structure & CRC *)
  if negb (cb_tbm1_ok cb) then
    Pipe_Rejected Err_Verify fl
  else
  (* P2: Root-key index, Ed25519 signature, anti-rollback SVN, and MED-27 base *)
  let auth_svn_ok :=
    (cb_key_idx cb =? otp_active_key_index otp) &&
    cb_sig_ok cb &&
    (tmr_app_svn tmr <=? cb_svn cb) &&
    (otp_min_svn otp <=? cb_svn cb) &&
    check_med27_delta_base cb (tmr_app_svn tmr) (pf_active_app_fp fl) in
  if negb auth_svn_ok then
    Pipe_Rejected Err_Verify fl
  else
  (* P3..P5: Route destination & check multi-image sub-headers *)
  match route_stream_dest safe_routing (pf_has_scratch fl) (cb_transport cb) (cb_mode cb) with
  | Route_NotSupported =>
      Pipe_Rejected Err_NotSupported fl
  | Route_Ok dest req_swap =>
      let mi_ok :=
        match cb_mode cb with
        | PM_MultiImage => cb_multiimage_hdr_ok cb
        | _             => true
        end in
      if negb mi_ok then
        Pipe_Rejected Err_InvalidArg fl
      else
      (* P6a: Stream decompression / delta reconstruction to routed destination *)
      let fl_p6 := apply_stream_write fl dest (cb_stream_output cb) in
      (* P6b: Verify 4KB chunked Merkle root & inner TIM1 header *)
      if negb (cb_merkle_ok cb && cb_inner_tim1_ok cb) then
        Pipe_Rejected Err_Verify fl_p6
      else
      (* P7a: Low-Vbat energy admission check (boot_effect_admit_or_defer) *)
      if vbat_mv <? cb_required_energy_mv cb then
        Pipe_Deferred fl_p6
      else
      (* P7b & P8: Commit verified image to Active App & preserve prior App in Backup *)
      let fl_p7 :=
        if req_swap then
          mkPipeFlash (pf_inactive_buf fl_p6) (pf_inactive_buf fl_p6) (pf_active_app fl_p6)
                      (pf_active_app_fp fl_p6) (pf_has_scratch fl_p6)
        else
          fl_p6 in
      Pipe_Applied fl_p7 (Nat.max (tmr_app_svn tmr) (cb_svn cb))
  end.

Definition extract_pipeline_flash (res : PipelineRunResult) : PipelineFlashState :=
  match res with
  | Pipe_Applied fl' _  => fl'
  | Pipe_Deferred fl'   => fl'
  | Pipe_Rejected _ fl' => fl'
  end.

(* ========================================================================== *)
(* SECTION 2: FV-12 Proofs — Verify-Before-Mutate, HIGH-33 & CRIT-30          *)
(* ========================================================================== *)

Lemma safe_route_never_streams_to_active_app :
  forall has_scratch tp pm dest req_swap,
    route_stream_dest true has_scratch tp pm = Route_Ok dest req_swap ->
    forall fl bytes, pf_active_app (apply_stream_write fl dest bytes) = pf_active_app fl.
Proof.
  intros [|] [| | |] [| | | | ] dest req_swap H fl bytes;
    simpl in H; try discriminate H; inversion H; subst; reflexivity.
Qed.

(* Theorem FV-12a: Verify-Before-Active-Slot-Mutation Across All Payload Modes
   and All Transports.
   1. Any failure in P1 (TBM1), P2 (key, Ed25519 sig, SVN floor, MED-27 base),
      P3 (HIGH-33 unsupported scratch-less OneWay streaming mode), P5 (multi-image
      bounds), P6b (chunked Merkle or inner TIM1 header), or P7a (low-Vbat deferral)
      leaves pf_active_app 100% UNMODIFIED!
   2. Whenever pf_active_app changes, ALL cryptographic, anti-rollback, MED-27,
      P3 route, Merkle, TIM1, and energy-admission gates MUST have passed beforehand. *)
Theorem verify_before_active_slot_mutation :
  forall fl cb tmr otp vbat_mv,
    let res := eval_8stage_pipeline true fl cb tmr otp vbat_mv in
    let fl' := extract_pipeline_flash res in
    (* Part 1: Rejection or deferral never mutates pf_active_app *)
    ((forall fl_ok svn', res <> Pipe_Applied fl_ok svn') ->
     pf_active_app fl' = pf_active_app fl) /\
    (* Part 2: Mutating pf_active_app implies every P1..P7a gate succeeded *)
    (pf_active_app fl' <> pf_active_app fl ->
     cb_tbm1_ok cb = true /\
     cb_key_idx cb = otp_active_key_index otp /\
     cb_sig_ok cb = true /\
     tmr_app_svn tmr <= cb_svn cb /\
     otp_min_svn otp <= cb_svn cb /\
     check_med27_delta_base cb (tmr_app_svn tmr) (pf_active_app_fp fl) = true /\
     cb_merkle_ok cb = true /\
     cb_inner_tim1_ok cb = true /\
     cb_required_energy_mv cb <= vbat_mv).
Proof.
  intros fl cb tmr otp vbat_mv; cbv zeta.
  unfold eval_8stage_pipeline; cbv zeta.
  destruct (negb (cb_tbm1_ok cb)) eqn:Etbm.
  - simpl; split; [intros _; reflexivity | intros Hne; exfalso; apply Hne; reflexivity].
  - apply Bool.negb_false_iff in Etbm.
    set (auth_ok := (cb_key_idx cb =? otp_active_key_index otp) &&
                    cb_sig_ok cb &&
                    (tmr_app_svn tmr <=? cb_svn cb) &&
                    (otp_min_svn otp <=? cb_svn cb) &&
                    check_med27_delta_base cb (tmr_app_svn tmr) (pf_active_app_fp fl)) in *.
    destruct (negb auth_ok) eqn:Eauth.
    + simpl; split; [intros _; reflexivity | intros Hne; exfalso; apply Hne; reflexivity].
    + apply Bool.negb_false_iff in Eauth.
      destruct (route_stream_dest true (pf_has_scratch fl) (cb_transport cb) (cb_mode cb))
        as [dest req_swap | ] eqn:Eroute.
      * pose proof (safe_route_never_streams_to_active_app
                      (pf_has_scratch fl) (cb_transport cb) (cb_mode cb)
                      dest req_swap Eroute fl (cb_stream_output cb)) as Hp6_pres.
        set (mi_ok := match cb_mode cb with PM_MultiImage => cb_multiimage_hdr_ok cb | _ => true end) in *.
        destruct (negb mi_ok) eqn:Emi.
        -- simpl; split; [intros _; reflexivity | intros Hne; exfalso; apply Hne; reflexivity].
        -- destruct (negb (cb_merkle_ok cb && cb_inner_tim1_ok cb)) eqn:Emrk.
           ++ simpl; split; [intros _; exact Hp6_pres | intros Hne; exfalso; exact (Hne Hp6_pres)].
           ++ apply Bool.negb_false_iff in Emrk.
              apply Bool.andb_true_iff in Emrk as [Hmrk Htim].
              destruct (vbat_mv <? cb_required_energy_mv cb) eqn:Evbat.
              ** simpl; split; [intros _; exact Hp6_pres | intros Hne; exfalso; exact (Hne Hp6_pres)].
              ** apply Nat.ltb_ge in Evbat.
                 simpl; split.
                 --- intros Hnot; exfalso; eapply Hnot; reflexivity.
                 --- intros _.
                     unfold auth_ok in Eauth.
                     rewrite !Bool.andb_true_iff in Eauth.
                     destruct Eauth as [[[[Hki Hsig] Htsvn] Hosvn] Hmed27].
                     apply Nat.eqb_eq in Hki; apply Nat.leb_le in Htsvn; apply Nat.leb_le in Hosvn.
                     repeat split; assumption.
      * simpl; split; [intros _; reflexivity | intros Hne; exfalso; apply Hne; reflexivity].
Qed.

(* Theorem HIGH-33: Physical Scratch-less OneWay Out-of-Place Streaming Rejection.
   When pf_has_scratch fl = false and cb_transport cb = TP_OneWay, out-of-place
   streaming modes (PM_Heatshrink, PM_DeltaTDS1, PM_ReverseDelta) are rejected
   before P6a executes, leaving pf_active_app, pf_inactive_buf, and pf_backup_buf
   100% unmodified (with Err_NotSupported whenever P1/P2 envelope & sig checks pass). *)
Theorem scratchless_oneway_streaming_modes_rejected_cleanly :
  forall fl cb tmr otp vbat_mv,
    pf_has_scratch fl = false ->
    cb_transport cb = TP_OneWay ->
    (cb_mode cb = PM_Heatshrink \/
     cb_mode cb = PM_DeltaTDS1 \/
     cb_mode cb = PM_ReverseDelta) ->
    let res := eval_8stage_pipeline true fl cb tmr otp vbat_mv in
    (exists err, res = Pipe_Rejected err fl) /\
    pf_active_app (extract_pipeline_flash res) = pf_active_app fl /\
    pf_inactive_buf (extract_pipeline_flash res) = pf_inactive_buf fl /\
    pf_backup_buf (extract_pipeline_flash res) = pf_backup_buf fl /\
    (cb_tbm1_ok cb = true ->
     cb_key_idx cb = otp_active_key_index otp ->
     cb_sig_ok cb = true ->
     tmr_app_svn tmr <= cb_svn cb ->
     otp_min_svn otp <= cb_svn cb ->
     check_med27_delta_base cb (tmr_app_svn tmr) (pf_active_app_fp fl) = true ->
     res = Pipe_Rejected Err_NotSupported fl).
Proof.
  intros fl cb tmr otp vbat_mv Hscr Htp Hmode; cbv zeta.
  unfold eval_8stage_pipeline; cbv zeta.
  rewrite Hscr, Htp.
  assert (Hroute : route_stream_dest true false TP_OneWay (cb_mode cb) = Route_NotSupported).
  { destruct Hmode as [-> | [-> | ->]]; reflexivity. }
  rewrite Hroute.
  destruct (negb (cb_tbm1_ok cb)) eqn:Etbm.
  - simpl; split; [exists Err_Verify; reflexivity|].
    repeat split; try reflexivity.
    intro Htbm; rewrite Htbm in Etbm; discriminate Etbm.
  - set (auth_ok := (cb_key_idx cb =? otp_active_key_index otp) &&
                    cb_sig_ok cb &&
                    (tmr_app_svn tmr <=? cb_svn cb) &&
                    (otp_min_svn otp <=? cb_svn cb) &&
                    check_med27_delta_base cb (tmr_app_svn tmr) (pf_active_app_fp fl)) in *.
    destruct (negb auth_ok) eqn:Eauth.
    + simpl; split; [exists Err_Verify; reflexivity|].
      repeat split; try reflexivity.
      intros _ Hki Hsig Htsvn Hosvn Hmed.
      unfold auth_ok in Eauth.
      apply Nat.eqb_eq in Hki; apply Nat.leb_le in Htsvn; apply Nat.leb_le in Hosvn.
      rewrite Hki, Hsig, Htsvn, Hosvn, Hmed in Eauth; simpl in Eauth; discriminate Eauth.
    + simpl; split; [exists Err_NotSupported; reflexivity|].
      repeat split; reflexivity.
Qed.

(* Formal Bug-Discovery Witness for Finding F / HIGH-33:
   In pre-fix boot_state.c:933-951 (safe_routing = false), when CHIP_SCRATCH_SLOT_SIZE == 0
   and TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_ONEWAY with TBM1_COMP_HEATSHRINK,
   stage_route sets stream_dest_addr = CHIP_APP_SLOT_ABS_ADDR. If compressed chunks
   fail P6b Merkle verification OR P7a low-Vbat admission, pf_active_app has ALREADY
   been overwritten with unverified/corrupt stream bytes, whereas safe_routing = true
   rejects at P3 with Pipe_Rejected Err_NotSupported fl0 leaving good_app intact! *)
Lemma scratchless_oneway_heatshrink_premature_overwrite_witness :
  let good_app := [Some 10; Some 20] in
  let bad_stream := [Some 99; Some 99] in
  let fl0 := mkPipeFlash good_app [] good_app 77 false in
  let cb_corrupt_merkle :=
    mkCandBundle PM_Heatshrink TP_OneWay true 0 true 3 0 0 true bad_stream false true 3600 in
  let tmr0 := mkTMR 2 1 0 0 0 0 0 true in
  let otp0 := mkOTPEpoch 1 0 in
  (* Post-HIGH-33 safe routing rejects at P3 with Err_NotSupported and preserves fl0 *)
  eval_8stage_pipeline true fl0 cb_corrupt_merkle tmr0 otp0 3800
    = Pipe_Rejected Err_NotSupported fl0 /\
  pf_active_app (extract_pipeline_flash (eval_8stage_pipeline true fl0 cb_corrupt_merkle tmr0 otp0 3800))
    = good_app /\
  (* Pre-fix scratch-less OneWay+Heatshrink overwrites good_app BEFORE Merkle rejects! *)
  eval_8stage_pipeline false fl0 cb_corrupt_merkle tmr0 otp0 3800
    = Pipe_Rejected Err_Verify (mkPipeFlash bad_stream [] good_app 77 false).
Proof.
  vm_compute; repeat split; reflexivity.
Qed.

(* CRIT-30: Multi-Image vs Swap WAL transfer_bitmap[0..7] Isolation
   (boot_multiimage.c & boot_swap.c):
   - Word 0 (bits 0..31) is reserved exclusively for sector swap checkpoints
     when transport_id > 0.
   - Words 1..7 (7 * 32 = 224 component bits) are reserved exclusively for
     multi-image sub-component completion tracking when transport_id == 0. *)
Record WalTransferBitmap : Type := mkWalBitmap {
  wtb_transport_id : nat;       (* 0 = MULTIIMAGE, 1..4 = Swap Transports *)
  wtb_words        : list nat   (* 8 words: index 0 = swap, indices 1..7 = multiimage *)
}.

Definition init_wal_bitmap (tid : nat) : WalTransferBitmap :=
  mkWalBitmap tid [0; 0; 0; 0; 0; 0; 0; 0].

Definition swap_bitmap_word_idx : nat := 0.
Definition multiimage_bitmap_word_idx (comp_idx : nat) : nat :=
  1 + (comp_idx / 32).

Definition update_word_at (words : list nat) (w_idx new_val : nat) : list nat :=
  firstn w_idx words ++ [new_val] ++ skipn (S w_idx) words.

Definition swap_record_sector_checkpoint
    (bm : WalTransferBitmap) (new_word0 : nat) : WalTransferBitmap :=
  if 0 <? wtb_transport_id bm then
    mkWalBitmap (wtb_transport_id bm)
                (update_word_at (wtb_words bm) swap_bitmap_word_idx new_word0)
  else
    bm.

Definition multiimage_record_component
    (bm : WalTransferBitmap) (comp_idx new_word_val : nat) : WalTransferBitmap :=
  if (wtb_transport_id bm =? 0) && (comp_idx <? 224) then
    mkWalBitmap (wtb_transport_id bm)
                (update_word_at (wtb_words bm) (multiimage_bitmap_word_idx comp_idx) new_word_val)
  else
    bm.

Definition swap_read_checkpoint (bm : WalTransferBitmap) : nat :=
  if 0 <? wtb_transport_id bm then nth swap_bitmap_word_idx (wtb_words bm) 0
  else 0.

Definition multiimage_read_word (bm : WalTransferBitmap) (comp_idx : nat) : nat :=
  if (wtb_transport_id bm =? 0) && (comp_idx <? 224) then
    nth (multiimage_bitmap_word_idx comp_idx) (wtb_words bm) 0
  else 0.

Lemma nth_update_word_disjoint :
  forall (words : list nat) (i j v : nat),
    i < length words ->
    j < length words ->
    i <> j ->
    nth i (update_word_at words j v) 0 = nth i words 0.
Proof.
  induction words as [|w rest IH]; intros i j v Hi Hj Hne; simpl in *.
  - lia.
  - destruct j as [|j'].
    + destruct i as [|i']; [lia | simpl; reflexivity].
    + destruct i as [|i']; [simpl; reflexivity|].
      simpl; apply IH; lia.
Qed.

Lemma length_update_word_at :
  forall words j v,
    j < length words ->
    length (update_word_at words j v) = length words.
Proof.
  induction words as [|w rest IH]; intros j v Hj; simpl in *.
  - lia.
  - destruct j as [|j']; simpl; [reflexivity | f_equal; apply IH; lia].
Qed.

(* Theorem FV-12b (CRIT-30): Multi-Image & Swap WAL Bitmap Non-Collision *)
Theorem multiimage_swap_bitmap_non_collision :
  forall (bm : WalTransferBitmap) (comp_idx : nat) (w_swap w_mi : nat),
    length (wtb_words bm) = 8 ->
    comp_idx < 224 ->
    (* 1. Physical word coordinates are strictly disjoint (0 vs 1..7) *)
    multiimage_bitmap_word_idx comp_idx <> swap_bitmap_word_idx /\
    1 <= multiimage_bitmap_word_idx comp_idx /\
    multiimage_bitmap_word_idx comp_idx < 8 /\
    (* 2. Any swap checkpoint update leaves all multi-image words [1..7] untouched *)
    nth (multiimage_bitmap_word_idx comp_idx)
        (wtb_words (swap_record_sector_checkpoint bm w_swap)) 0 =
      nth (multiimage_bitmap_word_idx comp_idx) (wtb_words bm) 0 /\
    (* 3. Any multi-image component update leaves swap word [0] untouched *)
    nth swap_bitmap_word_idx
        (wtb_words (multiimage_record_component bm comp_idx w_mi)) 0 =
      nth swap_bitmap_word_idx (wtb_words bm) 0 /\
    (* 4. transport_id gating prevents cross-mode resume misinterpretation *)
    (wtb_transport_id bm = 0 -> swap_read_checkpoint bm = 0) /\
    (0 < wtb_transport_id bm -> multiimage_read_word bm comp_idx = 0).
Proof.
  intros bm comp_idx w_swap w_mi Hlen Hcomp.
  assert (Hmi_bounds : 1 <= multiimage_bitmap_word_idx comp_idx /\
                       multiimage_bitmap_word_idx comp_idx < 8).
  { unfold multiimage_bitmap_word_idx.
    assert (Hdiv : comp_idx / 32 < 7)
      by (apply Nat.Div0.div_lt_upper_bound; lia).
    lia. }
  destruct Hmi_bounds as [Hge1 Hlt8].
  assert (Hneq : multiimage_bitmap_word_idx comp_idx <> swap_bitmap_word_idx)
    by (unfold swap_bitmap_word_idx; lia).
  split; [exact Hneq|].
  split; [exact Hge1|].
  split; [exact Hlt8|].
  split.
  - unfold swap_record_sector_checkpoint.
    destruct (0 <? wtb_transport_id bm); [cbn [wtb_words]|reflexivity].
    apply nth_update_word_disjoint; unfold swap_bitmap_word_idx in *; lia.
  - split.
    + unfold multiimage_record_component.
      destruct ((wtb_transport_id bm =? 0) && (comp_idx <? 224)); [cbn [wtb_words]|reflexivity].
      apply nth_update_word_disjoint; unfold swap_bitmap_word_idx in *; lia.
    + split.
      * intro Hz; unfold swap_read_checkpoint; rewrite Hz; reflexivity.
      * intro Hpos; unfold multiimage_read_word.
        assert (Ez : (wtb_transport_id bm =? 0) = false) by (apply Nat.eqb_neq; lia).
        rewrite Ez; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 3: FV-17 Proofs — OneWay + Reverse-Delta Lossless Rollback         *)
(*            & Low-Energy Deferral Counter-Neutral Liveness                  *)
(* ========================================================================== *)

(* Sector-level reversible delta encoding stored in dedicated Region 6 before
   OneWay overwrites App with B (boot_transport_oneway.c). *)
Inductive RDeltaSector : Type :=
  | RDS_Unchanged : RDeltaSector
  | RDS_Diff      : option nat (* exact original A[i] reconstruction *) -> RDeltaSector.

Definition encode_rdelta_sector (a_sec b_sec : option nat) : RDeltaSector :=
  if opt_nat_eqb a_sec b_sec then RDS_Unchanged
  else RDS_Diff a_sec.

Definition apply_rdelta_sector (b_sec : option nat) (rd : RDeltaSector) : option nat :=
  match rd with
  | RDS_Unchanged  => b_sec
  | RDS_Diff a_orig => a_orig
  end.

Lemma apply_encode_rdelta_sector_id :
  forall a_sec b_sec,
    apply_rdelta_sector b_sec (encode_rdelta_sector a_sec b_sec) = a_sec.
Proof.
  intros [va|] [vb|]; unfold apply_rdelta_sector, encode_rdelta_sector, opt_nat_eqb.
  - destruct (va =? vb) eqn:E; [apply Nat.eqb_eq in E; congruence | reflexivity].
  - reflexivity.
  - reflexivity.
  - reflexivity.
Qed.

Fixpoint encode_rdelta_image (A B : SectorImage) : list RDeltaSector :=
  match A, B with
  | a :: restA, b :: restB => encode_rdelta_sector a b :: encode_rdelta_image restA restB
  | _, _ => []
  end.

Record OnewayRDeltaState : Type := mkOnewayRDelta {
  owrd_app      : SectorImage;       (* Active App_Slot_0 (mutated during rollback) *)
  owrd_staging  : SectorImage;       (* Intact B in Staging/Scratch (read-only) *)
  owrd_region6  : list RDeltaSector; (* Intact Reverse-Delta in Region 6 (read-only) *)
  owrd_step_idx : nat                (* Persisted WAL rollback sector checkpoint *)
}.

(* Reconstruct sectors [idx .. N-1] from read-only (staging, region6) into app,
   with optional mid-erase/mid-write power-cut at step budget `cut`. *)
Fixpoint rdelta_rollback_loop
    (rem N : nat) (app stg : SectorImage) (r6 : list RDeltaSector)
    (cut : option nat) : OnewayRDeltaState :=
  match rem with
  | 0 => mkOnewayRDelta app stg r6 N
  | S rem' =>
      let i := N - S rem' in
      let b_i := sec_at stg i in
      let d_i := nth i r6 RDS_Unchanged in
      let a_i := apply_rdelta_sector b_i d_i in
      match cut with
      | Some 0 =>
          (* Power-cut mid-erase of App[i] BEFORE WAL step_idx advances *)
          mkOnewayRDelta (replace_nth i None app) stg r6 i
      | Some 1 =>
          (* Power-cut after writing App[i] BEFORE WAL step_idx advances *)
          mkOnewayRDelta (replace_nth i a_i app) stg r6 i
      | _ =>
          rdelta_rollback_loop rem' N (replace_nth i a_i app) stg r6 (opt_sub cut 2)
      end
  end.

Definition oneway_rdelta_init_deployed (A B : SectorImage) : OnewayRDeltaState :=
  mkOnewayRDelta B B (encode_rdelta_image A B) 0.

Definition oneway_rdelta_rollback_cut
    (st : OnewayRDeltaState) (N k : nat) : OnewayRDeltaState :=
  rdelta_rollback_loop (N - owrd_step_idx st) N
    (owrd_app st) (owrd_staging st) (owrd_region6 st) (Some k).

Definition oneway_rdelta_rollback_resume
    (st : OnewayRDeltaState) (N : nat) : OnewayRDeltaState :=
  rdelta_rollback_loop (N - owrd_step_idx st) N
    (owrd_app st) (owrd_staging st) (owrd_region6 st) None.

Lemma nth_encode_rdelta_image :
  forall A B i,
    length A = length B ->
    i < length A ->
    nth i (encode_rdelta_image A B) RDS_Unchanged =
      encode_rdelta_sector (sec_at A i) (sec_at B i).
Proof.
  induction A as [|a restA IH]; intros [|b restB] i Hlen Hi; simpl in *; try lia.
  destruct i as [|i']; unfold sec_at; simpl.
  - reflexivity.
  - apply IH; lia.
Qed.

Lemma length_replace_nth_eq :
  forall (A : Type) n (x : A) l, length (replace_nth n x l) = length l.
Proof.
  intros A n x l; revert n; induction l as [|h t IH]; intros [|n']; simpl; auto.
Qed.

Lemma sec_at_replace_nth_same :
  forall n v img,
    n < length img ->
    sec_at (replace_nth n v img) n = v.
Proof.
  intros n v img; revert n; induction img as [|h t IH]; intros [|n'] Hlt;
    unfold sec_at; simpl in *; try lia.
  - reflexivity.
  - apply IH; lia.
Qed.

Lemma sec_at_replace_nth_other :
  forall n m v img,
    n <> m ->
    sec_at (replace_nth n v img) m = sec_at img m.
Proof.
  intros n m v img; revert n m; induction img as [|h t IH]; intros [|n'] [|m'] Hne;
    unfold sec_at in *; simpl in *; try lia; try reflexivity.
  apply IH; lia.
Qed.

Lemma sector_image_ext :
  forall img1 img2,
    length img1 = length img2 ->
    (forall j, j < length img1 -> sec_at img1 j = sec_at img2 j) ->
    img1 = img2.
Proof.
  induction img1 as [|x1 r1 IH]; intros [|x2 r2] Hlen Hext; simpl in *; try lia; [reflexivity|].
  assert (Hx : x1 = x2) by (specialize (Hext 0 ltac:(lia)); unfold sec_at in Hext; simpl in Hext; exact Hext).
  subst x2; f_equal; apply IH; [lia|].
  intros j Hj; specialize (Hext (S j) ltac:(lia)); unfold sec_at in *; simpl in *; exact Hext.
Qed.

Lemma rdelta_rollback_loop_cut_inv :
  forall rem N app A B cut,
    rem <= N ->
    length app = N ->
    length A = N ->
    length B = N ->
    (forall j, j < N - rem -> sec_at app j = sec_at A j) ->
    let st' := rdelta_rollback_loop rem N app B (encode_rdelta_image A B) cut in
    owrd_staging st' = B /\
    owrd_region6 st' = encode_rdelta_image A B /\
    owrd_step_idx st' <= N /\
    length (owrd_app st') = N /\
    (forall j, j < owrd_step_idx st' -> sec_at (owrd_app st') j = sec_at A j) /\
    (cut = None -> owrd_step_idx st' = N /\ owrd_app st' = A).
Proof.
  induction rem as [|rem' IH]; intros N app A B cut Hrem Hla HlA HlB Hpre; cbv zeta; simpl.
  - assert (HappA : app = A).
    { apply sector_image_ext; [lia|].
      intros j Hj; apply Hpre; lia. }
    subst app.
    repeat (split || intros _); try lia; reflexivity.
  - set (i := N - S rem').
    assert (Hi_lt : i < N) by (unfold i; lia).
    assert (Ha_eq :
      apply_rdelta_sector (sec_at B i) (nth i (encode_rdelta_image A B) RDS_Unchanged) =
      sec_at A i).
    { rewrite nth_encode_rdelta_image by lia.
      apply apply_encode_rdelta_sector_id. }
    rewrite Ha_eq.
    destruct cut as [[|[|k]]|].
    + simpl; split_conj; try reflexivity; try (unfold i; lia).
      * rewrite length_replace_nth_eq; exact Hla.
      * intros j Hj; rewrite sec_at_replace_nth_other by lia; apply Hpre; unfold i in *; lia.
      * intro Hc; discriminate Hc.
    + simpl; split_conj; try reflexivity; try (unfold i; lia).
      * rewrite length_replace_nth_eq; exact Hla.
      * intros j Hj; rewrite sec_at_replace_nth_other by lia; apply Hpre; unfold i in *; lia.
      * intro Hc; discriminate Hc.
    + assert (Hla' : length (replace_nth i (sec_at A i) app) = N)
        by (rewrite length_replace_nth_eq; exact Hla).
      assert (Hpre' : forall j, j < N - rem' -> sec_at (replace_nth i (sec_at A i) app) j = sec_at A j).
      { intros j Hj; destruct (Nat.eq_dec j i) as [-> | Hne].
        - rewrite sec_at_replace_nth_same by lia; reflexivity.
        - rewrite sec_at_replace_nth_other by (intro; apply Hne; symmetry; assumption).
          apply Hpre; unfold i in *; lia. }
      pose proof (IH N (replace_nth i (sec_at A i) app) A B (Some (k - 0))
                    ltac:(lia) Hla' HlA HlB Hpre')
        as [Hs' [Hr' [Hi' [Hl' [Hp' _]]]]].
      split_conj; try assumption; intro Hc; discriminate Hc.
    + simpl opt_sub; apply IH; try lia.
      * rewrite length_replace_nth_eq; exact Hla.
      * intros j Hj; destruct (Nat.eq_dec j i) as [-> | Hne].
        -- rewrite sec_at_replace_nth_same by lia; reflexivity.
        -- rewrite sec_at_replace_nth_other by (intro; apply Hne; symmetry; assumption).
           apply Hpre; unfold i in *; lia.
Qed.

(* Theorem FV-17a: OneWay + Region-6 Reverse-Delta Lossless Rollback Across
   Arbitrary N and Single or Nested Mid-Rollback Power-Cuts (k1, k2) *)
Theorem oneway_reverse_delta_lossless_rollback :
  forall N (A B : SectorImage) (k1 k2 : nat),
    length A = N ->
    length B = N ->
    let st0 := oneway_rdelta_init_deployed A B in
    let st1 := oneway_rdelta_rollback_cut st0 N k1 in
    let st2 := oneway_rdelta_rollback_cut st1 N k2 in
    let st_res1 := oneway_rdelta_rollback_resume st1 N in
    let st_res2 := oneway_rdelta_rollback_resume st2 N in
    (* 1. Staging (B) and Region-6 (rdelta) remain intact across every power-cut *)
    owrd_staging st1 = B /\
    owrd_region6 st1 = encode_rdelta_image A B /\
    owrd_staging st2 = B /\
    owrd_region6 st2 = encode_rdelta_image A B /\
    (* 2. Resuming after single power-cut k1 restores bit-exact A *)
    owrd_app st_res1 = A /\
    owrd_step_idx st_res1 = N /\
    (* 3. Resuming after nested power-cuts (k1, k2) restores bit-exact A *)
    owrd_app st_res2 = A /\
    owrd_step_idx st_res2 = N.
Proof.
  intros N A B k1 k2 HlA HlB; cbv zeta.
  unfold oneway_rdelta_init_deployed, oneway_rdelta_rollback_cut, oneway_rdelta_rollback_resume;
    simpl.
  replace (N - 0) with N by lia.
  pose proof (rdelta_rollback_loop_cut_inv N N B A B (Some k1)
                ltac:(lia) HlB HlA HlB ltac:(intros j Hj; lia))
    as [Hs1 [Hr1 [Hi1 [Hla1 [Hpre1 _]]]]].
  set (st1 := rdelta_rollback_loop N N B B (encode_rdelta_image A B) (Some k1)) in *.
  rewrite Hs1, Hr1.
  pose proof (rdelta_rollback_loop_cut_inv (N - owrd_step_idx st1) N (owrd_app st1) A B None
                ltac:(lia) Hla1 HlA HlB
                ltac:(intros j Hj; apply Hpre1; lia))
    as [_ [_ [_ [_ [_ Hdone1]]]]].
  destruct (Hdone1 eq_refl) as [Hidx_r1 Happ_r1].
  pose proof (rdelta_rollback_loop_cut_inv (N - owrd_step_idx st1) N (owrd_app st1) A B (Some k2)
                ltac:(lia) Hla1 HlA HlB
                ltac:(intros j Hj; apply Hpre1; lia))
    as [Hs2 [Hr2 [Hi2 [Hla2 [Hpre2 _]]]]].
  set (st2 := rdelta_rollback_loop (N - owrd_step_idx st1) N (owrd_app st1) B
                (encode_rdelta_image A B) (Some k2)) in *.
  rewrite Hs2, Hr2.
  pose proof (rdelta_rollback_loop_cut_inv (N - owrd_step_idx st2) N (owrd_app st2) A B None
                ltac:(lia) Hla2 HlA HlB
                ltac:(intros j Hj; apply Hpre2; lia))
    as [_ [_ [_ [_ [_ Hdone2]]]]].
  destruct (Hdone2 eq_refl) as [Hidx_r2 Happ_r2].
  repeat split; assumption.
Qed.

(* FV-17b: Low-Energy Deferral Counter-Neutrality & Post-Recovery Liveness
   (boot_effect.c: boot_effect_admit_or_defer + boot_state.c: BOOT_ERR_DEFER) *)
Inductive EnergyWalIntent : Type :=
  | EWI_None          : EnergyWalIntent
  | EWI_UpdatePending : EnergyWalIntent
  | EWI_SleepBackoff  : EnergyWalIntent (* WAL_INTENT_SLEEP_BACKOFF = 6 *)
  | EWI_TxnCommit     : EnergyWalIntent.

Record EnergyBootState : Type := mkEnergyState {
  ebs_app       : SlotImage;
  ebs_staging   : SlotImage;
  ebs_backup    : SlotImage;
  ebs_tmr       : TMR_Counters;
  ebs_otp       : OTP_Epoch;
  ebs_intent    : EnergyWalIntent
}.

Definition step_update_with_vbat
    (est : EnergyBootState) (vbat_mv vbat_min_mv : nat) : EnergyBootState :=
  match ebs_intent est with
  | EWI_UpdatePending | EWI_SleepBackoff =>
      if staging_can_apply (ebs_staging est) (ebs_tmr est) (ebs_otp est) then
        if vbat_mv <? vbat_min_mv then
          (* BOOT_ERR_DEFER: counter-neutral sleep backoff, staging preserved! *)
          mkEnergyState (ebs_app est) (ebs_staging est) (ebs_backup est)
                        (ebs_tmr est) (ebs_otp est) EWI_SleepBackoff
        else
          let new_svn := Nat.max (tmr_app_svn (ebs_tmr est)) (image_svn (ebs_staging est)) in
          let tmr' := mkTMR new_svn (tmr_stage1_svn (ebs_tmr est))
                            0 (recovery_failure_counter (ebs_tmr est))
                            (active_nonce (ebs_tmr est))
                            (last_mbx_seq (ebs_tmr est))
                            (last_cloud_issued_at (ebs_tmr est))
                            (tmr_mac_valid (ebs_tmr est)) in
          mkEnergyState (ebs_staging est) (ebs_staging est) (ebs_app est)
                        tmr' (ebs_otp est) EWI_TxnCommit
      else
        mkEnergyState (ebs_app est) (ebs_staging est) (ebs_backup est)
                      (ebs_tmr est) (ebs_otp est) EWI_None
  | _ => est
  end.

Fixpoint run_low_vbat_deferrals
    (k : nat) (est : EnergyBootState) (low_vbat vbat_min_mv : nat) : EnergyBootState :=
  match k with
  | 0 => est
  | S k' =>
      run_low_vbat_deferrals k'
        (step_update_with_vbat est low_vbat vbat_min_mv) low_vbat vbat_min_mv
  end.

Lemma run_low_vbat_deferrals_inv :
  forall k est low_vbat vbat_min_mv,
    (ebs_intent est = EWI_UpdatePending \/ ebs_intent est = EWI_SleepBackoff) ->
    staging_can_apply (ebs_staging est) (ebs_tmr est) (ebs_otp est) = true ->
    low_vbat < vbat_min_mv ->
    let est_k := run_low_vbat_deferrals k est low_vbat vbat_min_mv in
    ebs_app est_k = ebs_app est /\
    ebs_staging est_k = ebs_staging est /\
    ebs_backup est_k = ebs_backup est /\
    ebs_tmr est_k = ebs_tmr est /\
    ebs_otp est_k = ebs_otp est /\
    (ebs_intent est_k = EWI_UpdatePending \/ ebs_intent est_k = EWI_SleepBackoff).
Proof.
  induction k as [|k' IH]; intros est low_vbat vbat_min_mv Hint Hcan Hlow; cbv zeta; simpl.
  - repeat split; assumption || reflexivity.
  - assert (Hstep :
      step_update_with_vbat est low_vbat vbat_min_mv =
      mkEnergyState (ebs_app est) (ebs_staging est) (ebs_backup est)
                    (ebs_tmr est) (ebs_otp est) EWI_SleepBackoff).
    { unfold step_update_with_vbat.
      destruct Hint as [-> | ->]; rewrite Hcan;
        assert (E : (low_vbat <? vbat_min_mv) = true) by (apply Nat.ltb_lt; exact Hlow);
        rewrite E; reflexivity. }
    rewrite Hstep.
    pose proof (IH (mkEnergyState (ebs_app est) (ebs_staging est) (ebs_backup est)
                                  (ebs_tmr est) (ebs_otp est) EWI_SleepBackoff)
                   low_vbat vbat_min_mv (or_intror eq_refl) Hcan Hlow)
      as [Ha [Hs [Hb [Ht [Ho Hi]]]]].
    simpl in Ha, Hs, Hb, Ht, Ho.
    repeat split; assumption.
Qed.

(* Theorem FV-17b: Low-Energy Deferral Counter-Neutrality & Liveness.
   1. Across ANY number k of consecutive low-Vbat boots (low_vbat < vbat_min_mv),
      boot_failure_counter and recovery_failure_counter remain strictly UNCHANGED
      (zero false rollback or recovery escalation!), pf_active_app and staging_slot
      remain intact, and intent transitions cleanly to EWI_SleepBackoff.
   2. On the very first boot where Vbat recovers (high_vbat >= vbat_min_mv), the
      preserved candidate in staging_slot applies cleanly to ebs_app in 1 boot! *)
Theorem low_energy_deferral_counter_neutral_liveness :
  forall k est low_vbat high_vbat vbat_min_mv,
    ebs_intent est = EWI_UpdatePending ->
    staging_can_apply (ebs_staging est) (ebs_tmr est) (ebs_otp est) = true ->
    low_vbat < vbat_min_mv ->
    vbat_min_mv <= high_vbat ->
    let est_deferred := run_low_vbat_deferrals k est low_vbat vbat_min_mv in
    let est_recovered := step_update_with_vbat est_deferred high_vbat vbat_min_mv in
    (* 1. Counter-neutral across arbitrary k brownout deferrals *)
    boot_failure_counter (ebs_tmr est_deferred) = boot_failure_counter (ebs_tmr est) /\
    recovery_failure_counter (ebs_tmr est_deferred) = recovery_failure_counter (ebs_tmr est) /\
    ebs_app est_deferred = ebs_app est /\
    ebs_staging est_deferred = ebs_staging est /\
    (0 < k -> ebs_intent est_deferred = EWI_SleepBackoff) /\
    (* 2. Immediate 1-boot liveness once Vbat >= vbat_min_mv *)
    ebs_app est_recovered = ebs_staging est /\
    ebs_backup est_recovered = ebs_app est /\
    ebs_intent est_recovered = EWI_TxnCommit.
Proof.
  intros k est low_vbat high_vbat vbat_min_mv Hint Hcan Hlow Hhigh; cbv zeta.
  pose proof (run_low_vbat_deferrals_inv k est low_vbat vbat_min_mv
                (or_introl Hint) Hcan Hlow)
    as [Ha [Hs [Hb [Ht [Ho Hi]]]]].
  set (est_d := run_low_vbat_deferrals k est low_vbat vbat_min_mv) in *.
  assert (Hpos_sb : 0 < k -> ebs_intent est_d = EWI_SleepBackoff).
  { destruct k as [|k']; [lia|].
    intros _; unfold est_d; simpl.
    unfold step_update_with_vbat; rewrite Hint, Hcan.
    assert (El : (low_vbat <? vbat_min_mv) = true) by (apply Nat.ltb_lt; exact Hlow).
    rewrite El.
    clear est_d Ha Hs Hb Ht Ho Hi.
    remember (mkEnergyState (ebs_app est) (ebs_staging est) (ebs_backup est)
                            (ebs_tmr est) (ebs_otp est) EWI_SleepBackoff) as sb eqn:Esb.
    assert (Hsb : ebs_intent sb = EWI_SleepBackoff /\
                  staging_can_apply (ebs_staging sb) (ebs_tmr sb) (ebs_otp sb) = true)
      by (subst sb; simpl; auto).
    clear Esb; revert sb Hsb.
    induction k' as [|k'' IHk]; intros sb [Hisb Hcsb]; simpl; [exact Hisb|].
    unfold step_update_with_vbat; rewrite Hisb, Hcsb, El.
    apply IHk; simpl; auto. }
  assert (Hrec :
    ebs_app (step_update_with_vbat est_d high_vbat vbat_min_mv) = ebs_staging est /\
    ebs_backup (step_update_with_vbat est_d high_vbat vbat_min_mv) = ebs_app est /\
    ebs_intent (step_update_with_vbat est_d high_vbat vbat_min_mv) = EWI_TxnCommit).
  { unfold step_update_with_vbat.
    assert (Hcan_d : staging_can_apply (ebs_staging est_d) (ebs_tmr est_d) (ebs_otp est_d) = true)
      by congruence.
    assert (Eh : (high_vbat <? vbat_min_mv) = false) by (apply Nat.ltb_ge; exact Hhigh).
    destruct Hi as [Hid | Hid]; rewrite Hid, Hcan_d, Eh; simpl; repeat split; congruence. }
  destruct Hrec as [Hra [Hrb Hri]].
  repeat split; try congruence; exact Hpos_sb.
Qed.
