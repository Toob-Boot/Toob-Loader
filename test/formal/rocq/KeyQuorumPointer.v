(* ========================================================================== *)
(* Toob-Loader Formal Verification — Key Quorum, Root Rotation & Pointer MMU *)
(* File: test/formal/rocq/KeyQuorumPointer.v                                  *)
(* Covers:                                                                    *)
(*   FV-13 (P1): kdm_quorum_brownout_monotonic                                *)
(*               root_key_rotation_invalidates_prior_k0                       *)
(*   FV-14 (P1): pointer_mmu_reassert_consistency                             *)
(*               pointer_o1_rollback_safety                                   *)
(* Zero Admitted, Zero Axioms.                                                *)
(* ========================================================================== *)

From Stdlib Require Import List Arith Bool PeanoNat Lia.
Import ListNotations.

From ToobBoot Require Import BootModel BootTransitions BootTheorems Stage0Chain.

(* ========================================================================== *)
(* SECTION 1: FV-13 — 3-Slot KDM Quorum Store & Root-Key Rotation             *)
(*            Mirrors boot_rstore.c, stage0_otp.c, and boot_verify.c          *)
(* ========================================================================== *)

Record KdmRecord : Type := mkKdmRecord {
  kr_epoch     : nat; (* Monotonic KDM generation counter *)
  kr_k1_id     : nat; (* Operational manifest signing key fingerprint *)
  kr_k2_id     : nat; (* Operational payload encryption key fingerprint *)
  kr_k0_anchor : nat  (* Bound OTP root key index *)
}.

Definition kdm_eqb (a b : KdmRecord) : bool :=
  (kr_epoch a =? kr_epoch b) &&
  (kr_k1_id a =? kr_k1_id b) &&
  (kr_k2_id a =? kr_k2_id b) &&
  (kr_k0_anchor a =? kr_k0_anchor b).

Lemma kdm_eqb_refl : forall r, kdm_eqb r r = true.
Proof.
  intros [e k1 k2 k0]; unfold kdm_eqb; simpl;
    rewrite !Nat.eqb_refl; reflexivity.
Qed.

Lemma kdm_eqb_eq : forall a b, kdm_eqb a b = true <-> a = b.
Proof.
  intros [e1 a1 b1 c1] [e2 a2 b2 c2]; unfold kdm_eqb; simpl.
  rewrite !Bool.andb_true_iff, !Nat.eqb_eq.
  split.
  - intros [[[-> ->] ->] ->]; reflexivity.
  - intros H; inversion H; repeat split; reflexivity.
Qed.

Record KdmQuorumStore : Type := mkKdmQuorum {
  kq_slot0 : option KdmRecord;
  kq_slot1 : option KdmRecord;
  kq_slot2 : option KdmRecord
}.

Definition kdm_pick_higher_epoch (a b : KdmRecord) : KdmRecord :=
  if kr_epoch b <=? kr_epoch a then a else b.

(* boot_rstore.c 3-slot KDM resolution:
   1. 2-of-3 identical valid slots win immediately by majority quorum.
   2. When a mid-rotation brownout leaves 2 valid slots with distinct epochs
      (1 new, 1 old, 1 torn/erased), selects the authenticated slot with the
      higher monotonic epoch counter. *)
Definition kdm_quorum_read (q : KdmQuorumStore) : option KdmRecord :=
  match kq_slot0 q, kq_slot1 q, kq_slot2 q with
  | Some a, Some b, Some c =>
      if kdm_eqb a b then Some a
      else if kdm_eqb a c then Some a
      else if kdm_eqb b c then Some b
      else Some (kdm_pick_higher_epoch a (kdm_pick_higher_epoch b c))
  | Some a, Some b, None   => Some (if kdm_eqb a b then a else kdm_pick_higher_epoch a b)
  | Some a, None,   Some c => Some (if kdm_eqb a c then a else kdm_pick_higher_epoch a c)
  | None,   Some b, Some c => Some (if kdm_eqb b c then b else kdm_pick_higher_epoch b c)
  | Some a, None,   None   => Some a
  | None,   Some b, None   => Some b
  | None,   None,   Some c => Some c
  | None,   None,   None   => None
  end.

(* Bounded 1-pass self-heal (boot_rstore_heal): rewrites any torn/stale slot
   to match the quorum-resolved record. *)
Definition kdm_heal_store (q : KdmQuorumStore) : KdmQuorumStore :=
  match kdm_quorum_read q with
  | Some winner => mkKdmQuorum (Some winner) (Some winner) (Some winner)
  | None        => q
  end.

(* Sequential 3-slot KDM rotation interrupted by brownout at step `cut`:
     cut = 0: brownout mid-erase/write of slot 0 -> (None, Some old, Some old)
     cut = 1: brownout mid-erase/write of slot 1 -> (Some new, None, Some old)
     cut = 2: brownout mid-erase/write of slot 2 -> (Some new, Some new, None)
     cut >= 3: all 3 slots committed             -> (Some new, Some new, Some new) *)
Definition kdm_write_with_brownout
    (old_rec new_rec : KdmRecord) (cut : nat) : KdmQuorumStore :=
  match cut with
  | 0 => mkKdmQuorum None           (Some old_rec) (Some old_rec)
  | 1 => mkKdmQuorum (Some new_rec) None           (Some old_rec)
  | 2 => mkKdmQuorum (Some new_rec) (Some new_rec) None
  | _ => mkKdmQuorum (Some new_rec) (Some new_rec) (Some new_rec)
  end.

(* Single-slot bit-rot / brownout fault on an already-healed 3-slot store *)
Definition kdm_corrupt_single_slot (q : KdmQuorumStore) (slot_idx : nat) : KdmQuorumStore :=
  match slot_idx with
  | 0 => mkKdmQuorum None         (kq_slot1 q) (kq_slot2 q)
  | 1 => mkKdmQuorum (kq_slot0 q) None         (kq_slot2 q)
  | _ => mkKdmQuorum (kq_slot0 q) (kq_slot1 q) None
  end.

(* Theorem FV-13a: 3-Slot KDM Quorum Monotonicity & 1-Pass Self-Heal Across
   Single-Slot Mid-Write / Mid-Erase Brownouts *)
Theorem kdm_quorum_brownout_monotonic :
  forall old_rec new_rec cut next_fault_slot,
    kr_epoch old_rec <= kr_epoch new_rec ->
    let q_cut := kdm_write_with_brownout old_rec new_rec cut in
    (* 1. KDM read NEVER loses state (Some resolved) and is strictly monotonic *)
    exists resolved,
      kdm_quorum_read q_cut = Some resolved /\
      (resolved = old_rec \/ resolved = new_rec) /\
      kr_epoch old_rec <= kr_epoch resolved /\
      kr_epoch resolved <= kr_epoch new_rec /\
      (1 <= cut -> kr_epoch resolved = kr_epoch new_rec) /\
      (* 2. 1-pass heal restores full 3-of-3 redundancy *)
      let q_healed := kdm_heal_store q_cut in
      q_healed = mkKdmQuorum (Some resolved) (Some resolved) (Some resolved) /\
      (* 3. Healed store survives any subsequent single-slot brownout/corruption *)
      kdm_quorum_read (kdm_corrupt_single_slot q_healed next_fault_slot) = Some resolved.
Proof.
  intros old_rec new_rec cut next_fault_slot Hle; cbv zeta.
  destruct cut as [|[|[|c']]];
    unfold kdm_write_with_brownout, kdm_heal_store, kdm_corrupt_single_slot, kdm_quorum_read;
    cbn [kq_slot0 kq_slot1 kq_slot2].
  - rewrite kdm_eqb_refl.
    exists old_rec; repeat split; try reflexivity; try lia;
      [left; reflexivity
      | destruct next_fault_slot as [|[|s']]; cbn [kq_slot0 kq_slot1 kq_slot2];
        rewrite kdm_eqb_refl; reflexivity].
  - destruct (kdm_eqb new_rec old_rec) eqn:Eeq.
    + apply kdm_eqb_eq in Eeq; subst new_rec.
      exists old_rec; repeat split; try reflexivity; try lia;
        [left; reflexivity
        | destruct next_fault_slot as [|[|s']]; cbn [kq_slot0 kq_slot1 kq_slot2];
          rewrite kdm_eqb_refl; reflexivity].
    + unfold kdm_pick_higher_epoch.
      assert (Ege : (kr_epoch old_rec <=? kr_epoch new_rec) = true)
        by (apply Nat.leb_le; exact Hle).
      rewrite Ege.
      exists new_rec; repeat split; try reflexivity; try lia;
        [right; reflexivity
        | destruct next_fault_slot as [|[|s']]; cbn [kq_slot0 kq_slot1 kq_slot2];
          rewrite kdm_eqb_refl; reflexivity].
  - rewrite kdm_eqb_refl.
    exists new_rec; repeat split; try reflexivity; try lia;
      [right; reflexivity
      | destruct next_fault_slot as [|[|s']]; cbn [kq_slot0 kq_slot1 kq_slot2];
        rewrite kdm_eqb_refl; reflexivity].
  - rewrite kdm_eqb_refl.
    exists new_rec; repeat split; try reflexivity; try lia;
      [right; reflexivity
      | destruct next_fault_slot as [|[|s']]; cbn [kq_slot0 kq_slot1 kq_slot2];
        rewrite kdm_eqb_refl; reflexivity].
Qed.

(* FV-13b: Append-Only OTP K0[0..255] Root-Key Rotation & Epoch-Derived K4 MAC *)

(* Program a fresh non-zero root key into the first OKS_Blank slot of OTP *)
Fixpoint otp_append_root_key (xs : list OtpKeySlot) (new_pk : nat) : list OtpKeySlot :=
  match xs with
  | [] => []
  | OKS_Valid pk :: rest => OKS_Valid pk :: otp_append_root_key rest new_pk
  | OKS_Blank :: rest => OKS_Valid new_pk :: rest
  | other :: rest => other :: rest
  end.

(* Epoch-bound K4 WAL MAC tag check: K4 is derived from (device_secret, active_k0_idx) *)
Record K4AuthenticatedTmr : Type := mkK4Tmr {
  k4t_counters   : TMR_Counters;
  k4t_mac_epoch  : nat; (* Root key epoch under which K4 MAC was computed *)
  k4t_tag_intact : bool
}.

Definition verify_k4_tmr_epoch (rec : K4AuthenticatedTmr) (active_k0_idx : nat) : bool :=
  k4t_tag_intact rec && (k4t_mac_epoch rec =? active_k0_idx).

(* Clean constructive representation of an OTP root-key array with (k + 1)
   provisioned valid keys followed by `rem_slots` blank fuse slots. *)
Definition make_otp_key_table
    (provisioned_pks : list nat) (blank_slots : nat) : list OtpKeySlot :=
  map OKS_Valid provisioned_pks ++ repeat OKS_Blank blank_slots.

Lemma all_blank_tail_repeat :
  forall n, all_blank_tail (repeat OKS_Blank n) = true.
Proof.
  induction n as [|n' IH]; simpl; [reflexivity | exact IH].
Qed.

Lemma scan_make_otp_key_table_aux :
  forall pks blanks cur last_idx last_pk,
    Forall (fun pk => 0 < pk) pks ->
    match pks with
    | [] =>
        scan_otp_keys_aux (make_otp_key_table [] blanks) cur (Some (last_idx, last_pk)) =
          OS_Ok last_idx last_pk
    | _ =>
        exists final_pk,
          scan_otp_keys_aux (make_otp_key_table pks blanks) cur (Some (last_idx, last_pk)) =
            OS_Ok (cur + length pks - 1) final_pk
    end.
Proof.
  induction pks as [|pk rest IH]; intros blanks cur last_idx last_pk Hall;
    unfold make_otp_key_table in *; simpl in *.
  - destruct blanks as [|b']; simpl; [reflexivity|].
    rewrite all_blank_tail_repeat; reflexivity.
  - inversion Hall as [|? ? Hpos Hrest]; subst.
    assert (Ez : (pk =? 0) = false) by (apply Nat.eqb_neq; lia).
    rewrite Ez.
    destruct rest as [|pk2 rest2].
    + pose proof (IH blanks (S cur) cur pk Hrest) as Hbase.
      simpl in Hbase |- *.
      exists pk; replace (cur + 1 - 1) with cur by lia; exact Hbase.
    + destruct (IH blanks (S cur) cur pk Hrest) as [fpk Hrec].
      simpl in Hrec |- *.
      exists fpk; replace (cur + S (S (length rest2)) - 1)
                    with (S (cur + S (length rest2) - 1)) by lia.
      replace (S (cur + S (length rest2) - 1))
        with (S cur + S (length rest2) - 1) by lia.
      exact Hrec.
Qed.

Lemma scan_make_otp_key_table :
  forall pk0 more_pks blanks,
    0 < pk0 ->
    Forall (fun pk => 0 < pk) more_pks ->
    exists active_pk,
      scan_otp_keys (make_otp_key_table (pk0 :: more_pks) blanks) =
        OS_Ok (length more_pks) active_pk.
Proof.
  intros pk0 more_pks blanks Hpk0 Hmore.
  unfold scan_otp_keys, make_otp_key_table; simpl.
  assert (Ez : (pk0 =? 0) = false) by (apply Nat.eqb_neq; lia).
  rewrite Ez.
  destruct more_pks as [|pk1 rest].
  - pose proof (scan_make_otp_key_table_aux [] blanks 1 0 pk0 (Forall_nil _)) as Hb.
    unfold make_otp_key_table in Hb; simpl in Hb.
    exists pk0; exact Hb.
  - destruct (scan_make_otp_key_table_aux (pk1 :: rest) blanks 1 0 pk0 Hmore) as [fpk Hrec].
    unfold make_otp_key_table in Hrec; simpl in Hrec |- *.
    exists fpk; replace (1 + S (length rest) - 1) with (S (length rest)) in Hrec by lia.
    exact Hrec.
Qed.

(* Rotate OTP root key by burning `new_pk` into the next blank OTP slot *)
Definition rotate_otp_key_table
    (pk0 : nat) (more_pks : list nat) (blanks : nat) (new_pk : nat)
    : list OtpKeySlot :=
  match blanks with
  | 0 => make_otp_key_table (pk0 :: more_pks) 0
  | S blanks' => make_otp_key_table (pk0 :: more_pks ++ [new_pk]) blanks'
  end.

(* Theorem FV-13b: Root-Key Rotation Strictly Invalidates All Prior K0 Keys
   Across Stage 0, Stage 1, and Epoch-Derived K4 WAL MACs *)
Theorem root_key_rotation_invalidates_prior_k0 :
  forall pk0 more_pks blanks_rem new_pk,
    0 < pk0 ->
    Forall (fun pk => 0 < pk) more_pks ->
    0 < new_pk ->
    let old_idx := length more_pks in
    let rotated_table := rotate_otp_key_table pk0 more_pks (S blanks_rem) new_pk in
    let new_idx := S old_idx in
    (* 1. OTP key scan advances active root key index from old_idx to S old_idx *)
    (exists active_pk,
       scan_otp_keys rotated_table = OS_Ok new_idx active_pk) /\
    (* 2. Every Stage-1 image signed by ANY prior root key k_prior <= old_idx is rejected by Stage 0 *)
    (forall s1_img min_svn,
       s1b_key_idx s1_img <= old_idx ->
       stage0_verify_bank s1_img new_idx min_svn = false) /\
    (* 3. Every App/Update image signed by ANY prior root key k_prior <= old_idx is rejected by Stage 1 *)
    (forall img tmr min_svn,
       key_index img <= old_idx ->
       let otp_rot := mkOTPEpoch min_svn new_idx in
       staging_can_apply img tmr otp_rot = false /\
       is_verified_boot_app img otp_rot = false) /\
    (* 4. WAL TMR records MACed under any prior K4(k_prior) fail epoch MAC verification *)
    (forall tmr_rec,
       k4t_mac_epoch tmr_rec <= old_idx ->
       verify_k4_tmr_epoch tmr_rec new_idx = false).
Proof.
  intros pk0 more_pks blanks_rem new_pk Hpk0 Hmore Hnew; cbv zeta.
  set (old_idx := length more_pks).
  split.
  - unfold rotate_otp_key_table.
    assert (Hall' : Forall (fun pk => 0 < pk) (more_pks ++ [new_pk])).
    { apply Forall_app; split; [exact Hmore | constructor; [exact Hnew | constructor]]. }
    destruct (scan_make_otp_key_table pk0 (more_pks ++ [new_pk]) blanks_rem Hpk0 Hall')
      as [apk Hscan].
    rewrite length_app in Hscan; simpl in Hscan.
    replace (length more_pks + 1) with (S old_idx) in Hscan by (unfold old_idx; lia).
    exists apk; exact Hscan.
  - split.
    + intros s1_img min_svn Hk_le.
      unfold stage0_verify_bank.
      assert (Eneq : (s1b_key_idx s1_img =? S old_idx) = false)
        by (apply Nat.eqb_neq; lia).
      rewrite Eneq, Bool.andb_false_r; simpl; reflexivity.
    + split.
      * intros img tmr min_svn Hk_le; simpl.
        assert (Eneq : (key_index img =? S old_idx) = false)
          by (apply Nat.eqb_neq; lia).
        split.
        -- unfold staging_can_apply, key_is_accepted; simpl.
           rewrite Eneq, Bool.andb_false_r; simpl; reflexivity.
        -- unfold is_verified_boot_app; simpl.
           rewrite Eneq, Bool.andb_false_r; reflexivity.
      * intros tmr_rec Hk_le.
        unfold verify_k4_tmr_epoch.
        assert (Eneq : (k4t_mac_epoch tmr_rec =? S old_idx) = false)
          by (apply Nat.eqb_neq; lia).
        rewrite Eneq, Bool.andb_false_r; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 2: FV-14 — Pointer Transport MMU Reassert & O(1) Rollback Safety   *)
(*            Mirrors toobloader/core/boot_transport_pointer.c                *)
(* ========================================================================== *)

Inductive PointerSlot : Type :=
  | PSlot_0 : PointerSlot
  | PSlot_1 : PointerSlot.

Definition flip_pslot (p : PointerSlot) : PointerSlot :=
  match p with
  | PSlot_0 => PSlot_1
  | PSlot_1 => PSlot_0
  end.

Lemma flip_pslot_involutive : forall p, flip_pslot (flip_pslot p) = p.
Proof. destruct p; reflexivity. Qed.

Record PointerSystemState : Type := mkPointerSys {
  ps_slot0              : SectorImage; (* Physical XIP Slot 0 *)
  ps_slot1              : SectorImage; (* Physical XIP Slot 1 *)
  ps_persisted_active   : PointerSlot; (* Persisted in WAL TMR active_app_slot *)
  ps_hw_mmu_mapped      : PointerSlot; (* Volatile MCU XIP MMU alias register *)
  ps_tentative          : bool;
  ps_slot0_erase_writes : nat;
  ps_slot1_erase_writes : nat
}.

Definition get_pslot_image (st : PointerSystemState) (p : PointerSlot) : SectorImage :=
  match p with
  | PSlot_0 => ps_slot0 st
  | PSlot_1 => ps_slot1 st
  end.

Definition put_pslot_image
    (st : PointerSystemState) (p : PointerSlot) (img : SectorImage) : PointerSystemState :=
  match p with
  | PSlot_0 =>
      mkPointerSys img (ps_slot1 st) (ps_persisted_active st) (ps_hw_mmu_mapped st)
                   (ps_tentative st) (S (ps_slot0_erase_writes st)) (ps_slot1_erase_writes st)
  | PSlot_1 =>
      mkPointerSys (ps_slot0 st) img (ps_persisted_active st) (ps_hw_mmu_mapped st)
                   (ps_tentative st) (ps_slot0_erase_writes st) (S (ps_slot1_erase_writes st))
  end.

Definition get_pslot_wear (st : PointerSystemState) (p : PointerSlot) : nat :=
  match p with
  | PSlot_0 => ps_slot0_erase_writes st
  | PSlot_1 => ps_slot1_erase_writes st
  end.

(* Image fetched by CPU when jumping to the XIP virtual alias base address *)
Definition xip_fetch_mapped_app (st : PointerSystemState) : SectorImage :=
  get_pslot_image st (ps_hw_mmu_mapped st).

(* Hardware reset: volatile XIP MMU register ALWAYS resets to PSlot_0,
   whereas flash slots and persisted WAL TMR active_app_slot survive! *)
Definition pointer_hw_reset (st : PointerSystemState) : PointerSystemState :=
  mkPointerSys (ps_slot0 st) (ps_slot1 st) (ps_persisted_active st)
               PSlot_0 (ps_tentative st)
               (ps_slot0_erase_writes st) (ps_slot1_erase_writes st).

Fixpoint pointer_run_resets (k : nat) (st : PointerSystemState) : PointerSystemState :=
  match k with
  | 0 => st
  | S k' => pointer_run_resets k' (pointer_hw_reset st)
  end.

(* boot_transport_reassert (boot_transport_pointer.c):
   Synchronizes volatile hardware XIP MMU alias register with persisted
   active_app_slot strictly prior to Stage-1 -> App handoff! *)
Definition pointer_reassert (st : PointerSystemState) : PointerSystemState :=
  mkPointerSys (ps_slot0 st) (ps_slot1 st) (ps_persisted_active st)
               (ps_persisted_active st) (ps_tentative st)
               (ps_slot0_erase_writes st) (ps_slot1_erase_writes st).

(* O(1) Pointer Update Apply:
   Stages candidate `B` into flip_pslot(active), flips persisted_active to
   flip_pslot(active), marks tentative = true, and reasserts MMU — ZERO erases
   or writes on the known-good active slot! *)
Definition pointer_stage_and_apply_o1
    (st : PointerSystemState) (cand_B : SectorImage) : PointerSystemState :=
  let target := flip_pslot (ps_persisted_active st) in
  let st_staged := put_pslot_image st target cand_B in
  pointer_reassert
    (mkPointerSys (ps_slot0 st_staged) (ps_slot1 st_staged)
                  target (ps_hw_mmu_mapped st_staged) true
                  (ps_slot0_erase_writes st_staged) (ps_slot1_erase_writes st_staged)).

(* O(1) Pointer Rollback (with optional pre-flush power-cut `cut_before_tmr`):
   If `cut_before_tmr = true`, power fails before WAL TMR persists the flipped
   slot so `ps_tentative` remains `true` for resume on the next reboot;
   once resumed (`cut_before_tmr = false`), flips persisted_active back to the
   untouched prior slot, clears tentative, and reasserts MMU in O(1) with ZERO
   flash slot erases/writes! *)
Definition pointer_rollback_o1
    (st : PointerSystemState) (cut_before_tmr : bool) : PointerSystemState :=
  if negb (ps_tentative st) then
    pointer_reassert st
  else if cut_before_tmr then
    pointer_hw_reset st
  else
    let prev_slot := flip_pslot (ps_persisted_active st) in
    pointer_reassert
      (mkPointerSys (ps_slot0 st) (ps_slot1 st)
                    prev_slot (ps_hw_mmu_mapped st) false
                    (ps_slot0_erase_writes st) (ps_slot1_erase_writes st)).

Lemma pointer_run_resets_preserves_persisted :
  forall k st,
    let st_r := pointer_run_resets k st in
    ps_slot0 st_r = ps_slot0 st /\
    ps_slot1 st_r = ps_slot1 st /\
    ps_persisted_active st_r = ps_persisted_active st /\
    ps_tentative st_r = ps_tentative st /\
    ps_slot0_erase_writes st_r = ps_slot0_erase_writes st /\
    ps_slot1_erase_writes st_r = ps_slot1_erase_writes st /\
    (0 < k -> ps_hw_mmu_mapped st_r = PSlot_0).
Proof.
  induction k as [|k' IH]; intros st; cbv zeta; simpl.
  - repeat split; try reflexivity; lia.
  - pose proof (IH (pointer_hw_reset st))
      as [Hs0 [Hs1 [Hp [Ht [Hw0 [Hw1 Hk]]]]]].
    simpl in Hs0, Hs1, Hp, Ht, Hw0, Hw1.
    repeat split; try assumption.
    intros _.
    destruct k' as [|k'']; [simpl; reflexivity | apply Hk; lia].
Qed.

(* Theorem FV-14a: Pointer Transport Hardware MMU Reassert Consistency.
   Across ANY persisted active slot (PSlot_0 or PSlot_1) and ANY number `k` of
   hardware resets (each resetting volatile hw_mmu_mapped to PSlot_0, creating a
   desynchronized hardware mapping whenever persisted_active = PSlot_1), running
   pointer_reassert before handoff guarantees hw_mmu_mapped == persisted_active
   and xip_fetch_mapped_app == get_pslot_image st persisted_active! *)
Theorem pointer_mmu_reassert_consistency :
  forall k st,
    let st_after_resets := pointer_run_resets k st in
    let st_handoff := pointer_reassert st_after_resets in
    (* Desynchronization witness on reset when persisted_active = PSlot_1 *)
    (0 < k -> ps_persisted_active st = PSlot_1 ->
     ps_hw_mmu_mapped st_after_resets <> ps_persisted_active st_after_resets) /\
    (* Reassert restores exact MMU <-> persisted slot equivalence *)
    ps_hw_mmu_mapped st_handoff = ps_persisted_active st /\
    ps_persisted_active st_handoff = ps_persisted_active st /\
    xip_fetch_mapped_app st_handoff = get_pslot_image st (ps_persisted_active st).
Proof.
  intros k st; cbv zeta.
  pose proof (pointer_run_resets_preserves_persisted k st)
    as [Hs0 [Hs1 [Hp [Ht [Hw0 [Hw1 Hk]]]]]].
  set (st_r := pointer_run_resets k st) in *.
  split.
  - intros Hpos Hp1.
    rewrite (Hk Hpos), Hp, Hp1; discriminate.
  - unfold pointer_reassert, xip_fetch_mapped_app; simpl.
    rewrite Hp.
    split; [reflexivity | split; [reflexivity|]].
    destruct (ps_persisted_active st); simpl; assumption.
Qed.

(* Theorem FV-14b: Pointer Transport O(1) Update & Rollback Safety.
   Starting from ANY active slot (PSlot_0 or PSlot_1) holding known-good image A:
   1. Applying candidate B maps XIP execution to B while keeping A bit-identical
      in the original slot with ZERO flash erases/writes to A's slot.
   2. Following a crash reset (resetting volatile MMU to PSlot_0) and even a
      mid-rollback power-cut (`cut_before_tmr = true`), resuming `pointer_rollback_o1`
      restores XIP execution to exact A in O(1) with ZERO flash erases/writes to
      either slot during rollback! *)
Theorem pointer_o1_rollback_safety :
  forall st cand_B,
    let orig_slot := ps_persisted_active st in
    let orig_A    := get_pslot_image st orig_slot in
    let orig_wear := get_pslot_wear st orig_slot in
    let st_applied := pointer_stage_and_apply_o1 st cand_B in
    let st_crashed := pointer_hw_reset st_applied in
    let st_rb_cut  := pointer_rollback_o1 st_crashed true in
    let st_healed  := pointer_rollback_o1 st_rb_cut false in
    (* 1. Apply maps XIP to cand_B with 0 erases/writes on orig_slot *)
    xip_fetch_mapped_app st_applied = cand_B /\
    get_pslot_image st_applied orig_slot = orig_A /\
    get_pslot_wear st_applied orig_slot = orig_wear /\
    (* 2. Rollback after crash + interrupted attempt restores exact orig_A in O(1) *)
    ps_persisted_active st_healed = orig_slot /\
    ps_hw_mmu_mapped st_healed = orig_slot /\
    ps_tentative st_healed = false /\
    xip_fetch_mapped_app st_healed = orig_A /\
    ps_slot0_erase_writes st_healed = ps_slot0_erase_writes st_applied /\
    ps_slot1_erase_writes st_healed = ps_slot1_erase_writes st_applied.
Proof.
  intros [s0 s1 act mmu tent w0 w1] cand_B; cbv zeta.
  destruct act; vm_compute; repeat split; reflexivity.
Qed.

(* ========================================================================== *)
(* SECTION 3: Wave-1 HIGH-104 — KDM Sequence Floor & Anti-Rollback in TMR     *)
(*            Mirrors toobloader/core/boot_cloud_cmd.c & boot_journal.c       *)
(* ========================================================================== *)

Record KdmCloudState : Type := mkKdmCloudState {
  kcs_tmr_kdm_floor : nat;
  kcs_quorum        : KdmQuorumStore;
  kcs_dslc          : nat
}.

Inductive KdmLoadResult : Type :=
  | KLR_Record        : KdmRecord -> KdmLoadResult
  | KLR_EfuseFallback : nat -> KdmLoadResult
  | KLR_Rejected      : BootErrCode -> KdmLoadResult.

Definition eval_load_active_cloud_key
    (st : KdmCloudState) (root_sig_ok : KdmRecord -> bool)
    (efuse_key1_valid : bool) : KdmLoadResult :=
  match kdm_quorum_read (kcs_quorum st) with
  | Some rec =>
      if (kcs_tmr_kdm_floor st <=? kr_epoch rec) && root_sig_ok rec then
        KLR_Record rec
      else if (kcs_tmr_kdm_floor st =? 0) && (kcs_dslc st =? 0) && efuse_key1_valid then
        KLR_EfuseFallback 0
      else
        KLR_Rejected Err_NotFound
  | None =>
      if (kcs_tmr_kdm_floor st =? 0) && (kcs_dslc st =? 0) && efuse_key1_valid then
        KLR_EfuseFallback 0
      else
        KLR_Rejected Err_NotFound
  end.

Definition eval_kdm_rotate
    (st : KdmCloudState) (root_sig_ok : KdmRecord -> bool)
    (efuse_key1_valid : bool) (new_rec : KdmRecord) (cmd_root_ok : bool)
    : (bool * KdmCloudState) :=
  let loaded := eval_load_active_cloud_key st root_sig_ok efuse_key1_valid in
  match loaded with
  | KLR_Rejected _ => (false, st)
  | KLR_Record cur_rec =>
      if cmd_root_ok && (kr_epoch cur_rec <? kr_epoch new_rec) then
        let new_floor := Nat.max (kcs_tmr_kdm_floor st) (kr_epoch new_rec) in
        let q' := kdm_write_with_brownout cur_rec new_rec 3 in
        (true, mkKdmCloudState new_floor q' (kcs_dslc st))
      else
        (false, st)
  | KLR_EfuseFallback cur_seq =>
      if cmd_root_ok && (cur_seq <? kr_epoch new_rec) then
        let new_floor := Nat.max (kcs_tmr_kdm_floor st) (kr_epoch new_rec) in
        let q' := mkKdmQuorum (Some new_rec) (Some new_rec) (Some new_rec) in
        (true, mkKdmCloudState new_floor q' (kcs_dslc st))
      else
        (false, st)
  end.

Theorem high104_kdm_seq_floor_strictly_monotone :
  forall st root_sig_ok efuse_ok new_rec cmd_ok accepted st',
    eval_kdm_rotate st root_sig_ok efuse_ok new_rec cmd_ok = (accepted, st') ->
    (* 1. Floor never decreases across ANY rotation attempt *)
    kcs_tmr_kdm_floor st <= kcs_tmr_kdm_floor st' /\
    (* 2. Any accepted rotation strictly advances tmr.kdm_seq_floor and matches new_rec *)
    (accepted = true ->
       kcs_tmr_kdm_floor st < kcs_tmr_kdm_floor st' /\
       kcs_tmr_kdm_floor st' = kr_epoch new_rec /\
       kdm_quorum_read (kcs_quorum st') = Some new_rec) /\
    (* 3. Deployed or floor > 0 devices never use eFuse fallback *)
    ((0 < kcs_tmr_kdm_floor st \/ kcs_dslc st <> 0) ->
       eval_load_active_cloud_key st root_sig_ok efuse_ok <> KLR_EfuseFallback 0) /\
    (* 4. Any quorum record below tmr.kdm_seq_floor is rejected *)
    (forall rec,
       kdm_quorum_read (kcs_quorum st) = Some rec ->
       kr_epoch rec < kcs_tmr_kdm_floor st ->
       (exists err, eval_load_active_cloud_key st root_sig_ok efuse_ok = KLR_Rejected err)).
Proof.
  intros st root_sig_ok efuse_ok new_rec cmd_ok accepted st' Hrot.
  assert (Hload_ge : forall r,
    eval_load_active_cloud_key st root_sig_ok efuse_ok = KLR_Record r ->
    kcs_tmr_kdm_floor st <= kr_epoch r).
  { intros r Hld; unfold eval_load_active_cloud_key in Hld.
    destruct (kdm_quorum_read (kcs_quorum st)) as [rec|].
    - destruct ((kcs_tmr_kdm_floor st <=? kr_epoch rec) && root_sig_ok rec) eqn:Echk.
      + apply Bool.andb_true_iff in Echk as [Hle _].
        apply Nat.leb_le in Hle; inversion Hld; subst; exact Hle.
      + destruct ((kcs_tmr_kdm_floor st =? 0) && (kcs_dslc st =? 0) && efuse_ok); discriminate.
    - destruct ((kcs_tmr_kdm_floor st =? 0) && (kcs_dslc st =? 0) && efuse_ok); discriminate. }
  assert (Hfallback_gate :
    (0 < kcs_tmr_kdm_floor st \/ kcs_dslc st <> 0) ->
    eval_load_active_cloud_key st root_sig_ok efuse_ok <> KLR_EfuseFallback 0).
  { intros [Hf_pos | Hdslc_nz] Hfb; unfold eval_load_active_cloud_key in Hfb.
    - assert (Ez : (kcs_tmr_kdm_floor st =? 0) = false) by (apply Nat.eqb_neq; lia).
      rewrite Ez in Hfb; simpl in Hfb.
      destruct (kdm_quorum_read (kcs_quorum st)) as [rec|];
        [destruct ((kcs_tmr_kdm_floor st <=? kr_epoch rec) && root_sig_ok rec)|]; discriminate Hfb.
    - assert (Ez : (kcs_dslc st =? 0) = false) by (apply Nat.eqb_neq; lia).
      rewrite Ez, Bool.andb_false_r, Bool.andb_false_l in Hfb.
      destruct (kdm_quorum_read (kcs_quorum st)) as [rec|];
        [destruct ((kcs_tmr_kdm_floor st <=? kr_epoch rec) && root_sig_ok rec)|]; discriminate Hfb. }
  assert (Hlow_rej :
    forall rec,
      kdm_quorum_read (kcs_quorum st) = Some rec ->
      kr_epoch rec < kcs_tmr_kdm_floor st ->
      exists err, eval_load_active_cloud_key st root_sig_ok efuse_ok = KLR_Rejected err).
  { intros rec Hq Hlt.
    unfold eval_load_active_cloud_key; rewrite Hq.
    assert (Ele : (kcs_tmr_kdm_floor st <=? kr_epoch rec) = false) by (apply Nat.leb_gt; lia).
    assert (Ez : (kcs_tmr_kdm_floor st =? 0) = false) by (apply Nat.eqb_neq; lia).
    rewrite Ele, Ez; simpl; exists Err_NotFound; reflexivity. }
  split; [|split; [|split; [exact Hfallback_gate | exact Hlow_rej]]].
  - unfold eval_kdm_rotate in Hrot.
    destruct (eval_load_active_cloud_key st root_sig_ok efuse_ok) as [cur | cseq | err] eqn:Hld.
    + destruct (cmd_ok && (kr_epoch cur <? kr_epoch new_rec));
        inversion Hrot; subst; simpl; lia.
    + destruct (cmd_ok && (cseq <? kr_epoch new_rec));
        inversion Hrot; subst; simpl; lia.
    + inversion Hrot; subst; lia.
  - intros Hacc; subst accepted.
    unfold eval_kdm_rotate in Hrot.
    destruct (eval_load_active_cloud_key st root_sig_ok efuse_ok) as [cur | cseq | err] eqn:Hld.
    + destruct (cmd_ok && (kr_epoch cur <? kr_epoch new_rec)) eqn:Erot; [|discriminate].
      apply Bool.andb_true_iff in Erot as [_ Hlt].
      apply Nat.ltb_lt in Hlt.
      pose proof (Hload_ge cur eq_refl) as Hcur_ge.
      inversion Hrot; subst; simpl; clear Hrot.
      split; [lia | split; [lia|]].
      unfold kdm_write_with_brownout, kdm_quorum_read; simpl; rewrite kdm_eqb_refl; reflexivity.
    + destruct (cmd_ok && (cseq <? kr_epoch new_rec)) eqn:Erot; [|discriminate].
      apply Bool.andb_true_iff in Erot as [_ Hlt].
      apply Nat.ltb_lt in Hlt.
      assert (Hfb0 : kcs_tmr_kdm_floor st = 0 /\ cseq = 0).
      { clear Hrot Hlt. unfold eval_load_active_cloud_key in Hld.
        destruct (kdm_quorum_read (kcs_quorum st)) as [rec|];
          [destruct ((kcs_tmr_kdm_floor st <=? kr_epoch rec) && root_sig_ok rec); [discriminate|]|];
          destruct ((kcs_tmr_kdm_floor st =? 0) && (kcs_dslc st =? 0) && efuse_ok) eqn:Ef; try discriminate;
          apply Bool.andb_true_iff in Ef as [Ef _]; apply Bool.andb_true_iff in Ef as [Ez _];
          apply Nat.eqb_eq in Ez; inversion Hld; split; assumption || reflexivity. }
      destruct Hfb0 as [Hfl0 Hcs0].
      inversion Hrot; subst; simpl; clear Hrot.
      split; [lia | split; [lia|]].
      unfold kdm_quorum_read; simpl; rewrite kdm_eqb_refl; reflexivity.
    + discriminate.
Qed.
