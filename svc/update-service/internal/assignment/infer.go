// Package assignment implements the Confirm-Inferenz Engine (§6 in plan7.md, UPD-026 in plan8.md).
package assignment

import (
	"context"
	"fmt"

	"github.com/toob-boot/update-service/internal/resolver"
)

// InferenceOutcome represents the result of boot telemetry confirm-inference.
type InferenceOutcome string

const (
	OutcomeConfirmed          InferenceOutcome = "CONFIRMED"
	OutcomeRolledBack         InferenceOutcome = "ROLLED_BACK"
	OutcomeRetrying           InferenceOutcome = "RETRYING"
	OutcomeFailedMaxAttempts InferenceOutcome = "FAILED_MAX_ATTEMPTS"
	OutcomeIncomplete         InferenceOutcome = "INCOMPLETE" // In progress, attempts NOT incremented
)

func (o InferenceOutcome) String() string {
	return string(o)
}

// Partition Slot Constants
const (
	SlotApp      uint8 = 0
	SlotRecovery uint8 = 2
)

// InferAssignmentOutcome evaluates device boot telemetry against an open assignment (§6 in plan7.md, UPD-026 in plan8.md).
//
// Inference Rules:
//  1. Successful Boot: obs.ReportedBuild == want.BuildNumber && obs.BootedPartition == SlotApp (0)
//     -> Transitions state to 'confirmed'.
//  2. Recovery Boot: obs.BootedPartition == SlotRecovery (2)
//     -> Transitions state to 'rolled_back' AND sets device.health = 'degraded'.
//  3. Install Failure: a.State == StateInstalling && obs.ReportedBuild != want.BuildNumber
//     -> Reboot occurred, but device booted running the old build.
//     -> Increments attempts counter.
//     -> If attempts >= maxAttempts -> transitions state to 'failed'.
//     -> Else -> transitions state back to 'offered' for retry.
//  4. Download Continuation: a.State IN ('offered', 'downloading', 'staged')
//     -> Device is resuming download/staging across check-ins.
//     -> attempts STAYS UNCHANGED (attempts == 0)!
func InferAssignmentOutcome(
	ctx context.Context,
	db DatabaseOps,
	dev resolver.Device,
	obs resolver.ObservedState,
	a *AssignmentRecord,
	want *resolver.Artifact,
	maxAttempts int16,
) (InferenceOutcome, error) {
	if a == nil || want == nil {
		return OutcomeIncomplete, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	// 1. Case 1: Successful Update Confirmation (Device booted into desired build on SlotApp)
	if obs.ReportedBuild == want.BuildNumber && obs.BootedPartition == SlotApp {
		if err := TransitionState(ctx, db, a, StateConfirmed, "telemetry_boot_matched_desired_build_slot_app"); err != nil {
			return OutcomeIncomplete, fmt.Errorf("infer: transition confirmed: %w", err)
		}
		return OutcomeConfirmed, nil
	}

	// 2. Case 2: Recovery Boot -> Rollback & Degraded Device Health
	if obs.BootedPartition == SlotRecovery {
		if err := TransitionState(ctx, db, a, StateRolledBack, "telemetry_booted_into_recovery"); err != nil {
			return OutcomeIncomplete, fmt.Errorf("infer: transition rolled_back: %w", err)
		}
		// Set device.health = 'degraded' in DB
		if err := db.UpdateDeviceHealth(ctx, dev.ID, "degraded"); err != nil {
			_ = err // Non-fatal, state change succeeded
		}
		_ = db.LogDeviceEvent(ctx, dev.ID, "device_health_changed", map[string]interface{}{
			"health": "degraded",
			"reason": "recovery_boot_detected",
		})
		return OutcomeRolledBack, nil
	}

	// 3. Case 3: Failed Installation Attempt (Rebooted into Old Build after 'installing' state)
	if a.State == StateInstalling && obs.ReportedBuild != want.BuildNumber {
		attempts, err := db.IncrementAssignmentAttempts(ctx, a.ID)
		if err != nil {
			attempts = a.Attempts + 1
		}
		a.Attempts = attempts

		if attempts >= maxAttempts {
			if err := TransitionState(ctx, db, a, StateFailed, fmt.Sprintf("max_attempts_exceeded_%d", attempts)); err != nil {
				return OutcomeIncomplete, fmt.Errorf("infer: transition failed: %w", err)
			}
			return OutcomeFailedMaxAttempts, nil
		}

		// Revert to 'offered' state for retry
		if err := TransitionState(ctx, db, a, StateOffered, fmt.Sprintf("install_failed_reverted_for_retry_attempt_%d", attempts)); err != nil {
			return OutcomeIncomplete, fmt.Errorf("infer: transition retry: %w", err)
		}
		return OutcomeRetrying, nil
	}

	// 4. Case 4: Download / Staging Continuation Across Checkins
	// Device is downloading/staging -> attempts stays unchanged (attempts == 0)!
	return OutcomeIncomplete, nil
}
