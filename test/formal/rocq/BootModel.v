(* ========================================================================== *)
(* Toob-Loader Formal Verification                                            *)
(* File: BootModel.v                                                          *)
(*                                                                            *)
(* Inductive hardware, flash, journal, TMR, confirm, and OTP state model      *)
(* matching toobloader/core/{boot_state,boot_effect,boot_rollback,            *)
(* boot_journal,boot_confirm,boot_rstore,boot_verify,boot_mailbox,            *)
(* boot_cloud_cmd,boot_transport_oneway}.c.                                   *)
(* ========================================================================== *)

From Stdlib Require Import Bool Arith Lia List.
Import ListNotations.

(* -------------------------------------------------------------------------- *)
(* 1. Hardware Reset Reasons (common/include/boot_types.h)                    *)
(* -------------------------------------------------------------------------- *)

Inductive ResetReason : Type :=
  | RR_Unknown   : ResetReason
  | RR_PowerOn   : ResetReason
  | RR_PinReset  : ResetReason
  | RR_Watchdog  : ResetReason
  | RR_Brownout  : ResetReason
  | RR_Software  : ResetReason
  | RR_HardFault : ResetReason.

Definition reset_reason_eqb (a b : ResetReason) : bool :=
  match a, b with
  | RR_Unknown,   RR_Unknown   => true
  | RR_PowerOn,   RR_PowerOn   => true
  | RR_PinReset,  RR_PinReset  => true
  | RR_Watchdog,  RR_Watchdog  => true
  | RR_Brownout,  RR_Brownout  => true
  | RR_Software,  RR_Software  => true
  | RR_HardFault, RR_HardFault => true
  | _, _ => false
  end.

Definition rst_indicates_crash (r : ResetReason) : bool :=
  match r with
  | RR_Watchdog | RR_HardFault => true
  | _ => false
  end.

(* -------------------------------------------------------------------------- *)
(* 2. Canonical & Raw Flash WAL Intents (common/include/toob_wal_wire.h)      *)
(* -------------------------------------------------------------------------- *)

Inductive WalIntent : Type :=
  | WI_None               : WalIntent (* WAL_INTENT_NONE = 0 *)
  | WI_TxnCommit          : WalIntent (* WAL_INTENT_TXN_COMMIT = 2 *)
  | WI_TxnRollback        : WalIntent (* WAL_INTENT_TXN_ROLLBACK = 3 *)
  | WI_UpdatePending      : WalIntent (* WAL_INTENT_UPDATE_PENDING = 5 *)
  | WI_ConfirmCommit      : WalIntent (* WAL_INTENT_CONFIRM_COMMIT = 7 *)
  | WI_TxnRollbackPending : WalIntent (* WAL_INTENT_TXN_ROLLBACK_PENDING = 10 *)
  | WI_RecoveryResolved   : WalIntent (* WAL_INTENT_RECOVERY_RESOLVED = 11 *)
  | WI_DeviceLocked       : WalIntent (* WAL_INTENT_DEVICE_LOCKED = 13 *).

Definition wal_intent_eqb (a b : WalIntent) : bool :=
  match a, b with
  | WI_None,               WI_None               => true
  | WI_TxnCommit,          WI_TxnCommit          => true
  | WI_TxnRollback,        WI_TxnRollback        => true
  | WI_UpdatePending,      WI_UpdatePending      => true
  | WI_ConfirmCommit,      WI_ConfirmCommit      => true
  | WI_TxnRollbackPending, WI_TxnRollbackPending => true
  | WI_RecoveryResolved,   WI_RecoveryResolved   => true
  | WI_DeviceLocked,       WI_DeviceLocked       => true
  | _, _ => false
  end.

Lemma wal_intent_eqb_eq : forall a b, wal_intent_eqb a b = true <-> a = b.
Proof.
  destruct a, b; simpl; split; intro H; try reflexivity; try discriminate.
Qed.

(* K4 MAC-authenticated security-bearing intents (toob_wal_wire.h) *)
Definition wal_intent_is_security_bearing (i : WalIntent) : bool :=
  match i with
  | WI_DeviceLocked | WI_ConfirmCommit | WI_TxnCommit => true
  | _ => false
  end.

(* Raw 64B flash entry in a WAL sector (newest entry at list head) *)
Inductive RawWalEntry : Type :=
  | RWE_Erased         : RawWalEntry
  | RWE_TornCrcInvalid : RawWalEntry
  | RWE_Sideband       : RawWalEntry (* NET_SEARCH / CHECKPOINT / SLEEP_BACKOFF *)
  | RWE_Valid          : WalIntent -> nat (* expected_nonce *) -> bool (* k4_mac_ok *) -> RawWalEntry.

Record WAL_Journal : Type := mkWAL {
  wal_entries : list RawWalEntry
}.

Definition mk_clean_wal (i : WalIntent) (exp_nonce : nat) : WAL_Journal :=
  mkWAL [RWE_Valid i exp_nonce true].

(* -------------------------------------------------------------------------- *)
(* 3. Flash Slots, Mailbox & Cloud Command Envelope                           *)
(* -------------------------------------------------------------------------- *)

Record SlotImage : Type := mkSlotImage {
  hdr_valid    : bool; (* magic == TOOB_MAGIC_HEADER && valid size bounds *)
  tbm1_valid   : bool; (* TBM1 v2 magic + CRC32 + layout bounds valid *)
  sig_valid    : bool; (* Ed25519 signature over signed manifest valid *)
  merkle_valid : bool; (* SHA-256 chunk hashes match payload bytes *)
  image_svn    : nat;  (* Manifest / image Security Version Number *)
  key_index    : nat;  (* Signing root key slot index (0..255) *)
  payload_id   : nat   (* Abstract content fingerprint for identity proofs *)
}.

Definition erased_slot_image : SlotImage :=
  mkSlotImage false false false false 0 0 0.

Definition slot_image_eqb (a b : SlotImage) : bool :=
  Bool.eqb (hdr_valid a) (hdr_valid b) &&
  Bool.eqb (tbm1_valid a) (tbm1_valid b) &&
  Bool.eqb (sig_valid a) (sig_valid b) &&
  Bool.eqb (merkle_valid a) (merkle_valid b) &&
  Nat.eqb (image_svn a) (image_svn b) &&
  Nat.eqb (key_index a) (key_index b) &&
  Nat.eqb (payload_id a) (payload_id b).

Lemma slot_image_eqb_eq : forall a b, slot_image_eqb a b = true <-> a = b.
Proof.
  intros [h1 t1 s1 m1 v1 k1 p1] [h2 t2 s2 m2 v2 k2 p2].
  unfold slot_image_eqb; simpl.
  rewrite !Bool.andb_true_iff, !Bool.eqb_true_iff, !Nat.eqb_eq.
  split.
  - intros [[[[[[-> ->] ->] ->] ->] ->] ->]; reflexivity.
  - intros H; inversion H; subst; repeat split; reflexivity.
Qed.

(* Cryptographically verified bootable image predicate *)
Definition image_is_verified (img : SlotImage) (min_svn active_key : nat) : Prop :=
  hdr_valid img = true /\
  sig_valid img = true /\
  merkle_valid img = true /\
  image_svn img >= min_svn /\
  key_index img = active_key.

Inductive CloudCmdKind : Type :=
  | CCK_Nop         : CloudCmdKind
  | CCK_ForceUpdate : CloudCmdKind
  | CCK_Killswitch  : CloudCmdKind
  | CCK_Unlock      : CloudCmdKind
  | CCK_RotateKey   : CloudCmdKind
  | CCK_Wipe        : CloudCmdKind.

Inductive CloudCmdSlot : Type :=
  | CC_Empty : CloudCmdSlot
  | CC_Token : CloudCmdKind -> bool (* sig_valid *) -> bool (* device_match *) ->
               nat (* counter_min *) -> nat (* issued_at *) -> CloudCmdSlot.

Inductive MailboxSlot : Type :=
  | MBX_Empty  : MailboxSlot
  | MBX_Record : bool (* crc_valid *) ->
                 nat  (* seq *) ->
                 bool (* req_confirm *) ->
                 bool (* req_update *) ->
                 bool (* req_recovery_resolved *) ->
                 nat  (* mbx_nonce *) ->
                 MailboxSlot.

Record FlashSlots : Type := mkFlashSlots {
  app_slot           : SlotImage;   (* Active execution slot: App_Slot_0 *)
  staging_slot       : SlotImage;   (* Inactive staging slot: Staging_Slot *)
  backup_slot        : SlotImage;   (* One-way full backup slot: Scratch_Slot *)
  recovery_rom_valid : bool;        (* Immutable Recovery OS / Stage 1.5 intact *)
  cloud_slot         : CloudCmdSlot;
  mailbox_slot       : MailboxSlot
}.

(* -------------------------------------------------------------------------- *)
(* 4. TMR Counters, RTC Confirm Store & Hardware OTP Epoch                    *)
(* -------------------------------------------------------------------------- *)

Record TMR_Counters : Type := mkTMR {
  tmr_app_svn              : nat;
  tmr_stage1_svn           : nat;
  boot_failure_counter     : nat;
  recovery_failure_counter : nat;
  active_nonce             : nat; (* 0 = none; > 0 = tentative 64-bit nonce *)
  last_mbx_seq             : nat;
  last_cloud_issued_at     : nat;
  tmr_mac_valid            : bool (* K4 TMR MAC tag valid *)
}.

Definition tmr_eqb (a b : TMR_Counters) : bool :=
  Nat.eqb (tmr_app_svn a) (tmr_app_svn b) &&
  Nat.eqb (tmr_stage1_svn a) (tmr_stage1_svn b) &&
  Nat.eqb (boot_failure_counter a) (boot_failure_counter b) &&
  Nat.eqb (recovery_failure_counter a) (recovery_failure_counter b) &&
  Nat.eqb (active_nonce a) (active_nonce b) &&
  Nat.eqb (last_mbx_seq a) (last_mbx_seq b) &&
  Nat.eqb (last_cloud_issued_at a) (last_cloud_issued_at b) &&
  Bool.eqb (tmr_mac_valid a) (tmr_mac_valid b).

Lemma tmr_eqb_refl : forall t, tmr_eqb t t = true.
Proof.
  intros [? ? ? ? ? ? ? ?]; unfold tmr_eqb; simpl.
  rewrite !Nat.eqb_refl, Bool.eqb_reflx; reflexivity.
Qed.

Lemma tmr_eqb_eq : forall a b, tmr_eqb a b = true <-> a = b.
Proof.
  intros [a1 a2 a3 a4 a5 a6 a7 a8] [b1 b2 b3 b4 b5 b6 b7 b8].
  unfold tmr_eqb; simpl.
  rewrite !Bool.andb_true_iff, !Nat.eqb_eq, !Bool.eqb_true_iff.
  split.
  - intros [[[[[[[-> ->] ->] ->] ->] ->] ->] ->]; reflexivity.
  - intros H; inversion H; subst; repeat split; reflexivity.
Qed.

(* Physical 3-sector TMR Quorum for Theorem 2 torn-write recovery *)
Record TMR_Quorum : Type := mkTMRQuorum {
  tmr_sec0 : option TMR_Counters;
  tmr_sec1 : option TMR_Counters;
  tmr_sec2 : option TMR_Counters
}.

Record ConfirmStore : Type := mkConfirmStore {
  rtc_nonce : nat (* Non-zero RTC confirm token written by libtoob confirm *)
}.

Record OTP_Epoch : Type := mkOTPEpoch {
  otp_min_svn          : nat; (* Hardware monotonic anti-rollback floor *)
  otp_active_key_index : nat  (* Highest contiguous provisioned root key slot *)
}.

(* -------------------------------------------------------------------------- *)
(* 5. Composite Machine State & Terminal Handoff Outcomes                     *)
(* -------------------------------------------------------------------------- *)

Record State : Type := mkState {
  st_slots   : FlashSlots;
  st_wal     : WAL_Journal;
  st_tmr     : TMR_Counters;
  st_confirm : ConfirmStore;
  st_otp     : OTP_Epoch;
  st_reset   : ResetReason
}.

Record BootConfig : Type := mkBootConfig {
  cfg_max_retries          : nat; (* BOOT_CONFIG_MAX_RETRIES = 3 *)
  cfg_max_recovery_retries : nat; (* BOOT_CONFIG_MAX_RECOVERY_RETRIES = 5 *)
  cfg_fresh_nonce          : nat  (* Non-zero TRNG nonce (> 0) *)
}.

Definition default_boot_config : BootConfig :=
  mkBootConfig 3 5 7.

Inductive BootErrCode : Type :=
  | Err_Verify            : BootErrCode (* BOOT_ERR_VERIFY *)
  | Err_InvalidArg        : BootErrCode (* BOOT_ERR_INVALID_ARG *)
  | Err_NotFound          : BootErrCode (* BOOT_ERR_NOT_FOUND *)
  | Err_DeviceLocked      : BootErrCode (* BOOT_ERR_DEVICE_LOCKED *)
  | Err_RecoveryRequested : BootErrCode (* BOOT_RECOVERY_REQUESTED *)
  | Err_NotSupported      : BootErrCode (* BOOT_ERR_NOT_SUPPORTED *).

Definition boot_err_eqb (a b : BootErrCode) : bool :=
  match a, b with
  | Err_Verify,            Err_Verify            => true
  | Err_InvalidArg,        Err_InvalidArg        => true
  | Err_NotFound,          Err_NotFound          => true
  | Err_DeviceLocked,      Err_DeviceLocked      => true
  | Err_RecoveryRequested, Err_RecoveryRequested => true
  | Err_NotSupported,      Err_NotSupported      => true
  | _, _ => false
  end.

Inductive RecoveryMode : Type :=
  | RM_PartitionOS  : RecoveryMode             (* boot_recovery_os == true, BOOT_OK *)
  | RM_SerialRescue : BootErrCode -> RecoveryMode (* Stage 1.5 ROM boot_panic(err) *).

Inductive BootOutcome : Type :=
  | Boot_App          : SlotImage -> bool (* is_tentative *) -> nat (* nonce *) -> BootOutcome
  | Enter_Recovery_OS : RecoveryMode -> BootOutcome.

(* -------------------------------------------------------------------------- *)
(* 6. WAL TMR v8 Ratified vs Pending Identity & Telemetry (TDR1-02 / TDR1-03) *)
(* -------------------------------------------------------------------------- *)

Record AppIdentityMeta : Type := mkAppMeta {
  am_build_number : nat;
  am_fw_major     : nat;
  am_fw_minor     : nat;
  am_fw_patch     : nat;
  am_key_index    : nat; (* Masked 7-bit key index 0..127 *)
  am_sbom_digest  : nat
}.

Definition zero_app_meta : AppIdentityMeta :=
  mkAppMeta 0 0 0 0 0 0.

Definition app_meta_eqb (a b : AppIdentityMeta) : bool :=
  Nat.eqb (am_build_number a) (am_build_number b) &&
  Nat.eqb (am_fw_major a) (am_fw_major b) &&
  Nat.eqb (am_fw_minor a) (am_fw_minor b) &&
  Nat.eqb (am_fw_patch a) (am_fw_patch b) &&
  Nat.eqb (am_key_index a) (am_key_index b) &&
  Nat.eqb (am_sbom_digest a) (am_sbom_digest b).

Lemma app_meta_eqb_eq : forall a b, app_meta_eqb a b = true <-> a = b.
Proof.
  intros [a1 a2 a3 a4 a5 a6] [b1 b2 b3 b4 b5 b6].
  unfold app_meta_eqb; simpl.
  rewrite !Bool.andb_true_iff, !Nat.eqb_eq.
  split.
  - intros [[[[[-> ->] ->] ->] ->] ->]; reflexivity.
  - intros H; inversion H; subst; repeat split; reflexivity.
Qed.

(* WAL_TMR_VERSION_8 (112B ABI-locked) separates ratified app_* fields from
   tentative pending_* fields gated by WAL_TMR_PENDING_META_BIT (0x80U). *)
Record TmrAppMeta : Type := mkTmrAppMeta {
  tam_ratified : AppIdentityMeta;
  tam_pending  : option AppIdentityMeta
}.

Inductive UpdateDiagOutcome : Type :=
  | UDO_None     : UpdateDiagOutcome (* 0: no update action this boot *)
  | UDO_Applied  : UpdateDiagOutcome (* 1: pipeline_status == BOOT_OK *)
  | UDO_Rejected : UpdateDiagOutcome (* 2: controlled or fatal pipeline reject *)
  | UDO_Reverted : UpdateDiagOutcome (* 3: handle_rollback_flow reverted trial *)
  | UDO_Deferred : UpdateDiagOutcome (* 4: BOOT_ERR_DEFER low-Vbat deferral *).

Inductive PipelineCommitInput : Type :=
  | PCI_Ok       : nat (* svn *) -> AppIdentityMeta -> PipelineCommitInput
  | PCI_Defer    : option (nat * AppIdentityMeta) (* snapshotted cand_meta *) -> PipelineCommitInput
  | PCI_Reject   : BootErrCode -> option (nat * AppIdentityMeta) -> PipelineCommitInput
  | PCI_FatalHw  : BootErrCode -> option (nat * AppIdentityMeta) -> PipelineCommitInput.

Record DiagTelemetrySnapshot : Type := mkDiagSnapshot {
  dts_outcome            : UpdateDiagOutcome;
  dts_cand_security_meta : option (nat * AppIdentityMeta);
  dts_handoff_identity   : AppIdentityMeta;
  dts_observed_failures  : nat
}.
