package assignment_test

import (
	"context"
	"testing"

	"github.com/toob-boot/update-service/internal/assignment"
	"github.com/toob-boot/update-service/internal/resolver"
)

func TestInferOutcome_DownloadContinuationKeepsZeroAttempts(t *testing.T) {
	db := newMockDB()
	dev := makeDev()
	obs := makeObs() // dev.ReportedBuild = 100

	wantArt := makeArt("art-101", 101, 11) // Target build is 101

	// Create assignment in state 'offered'
	asgn, _ := db.InsertAssignment(context.Background(), dev.ID, wantArt.ID, assignment.StateOffered, "resolver")

	ctx := context.Background()

	// 1st Check-in during download: state moves to downloading
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateDownloading, "downloading")
	outcome1, err1 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err1 != nil || outcome1 != assignment.OutcomeIncomplete {
		t.Fatalf("checkin 1: expected OutcomeIncomplete, got %v, err %v", outcome1, err1)
	}
	if asgn.Attempts != 0 {
		t.Errorf("INVARIANT VIOLATION: attempts should be 0 during download, got %d", asgn.Attempts)
	}

	// 2nd Check-in during download: state remains downloading
	outcome2, err2 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err2 != nil || outcome2 != assignment.OutcomeIncomplete {
		t.Fatalf("checkin 2: expected OutcomeIncomplete, got %v, err %v", outcome2, err2)
	}
	if asgn.Attempts != 0 {
		t.Errorf("INVARIANT VIOLATION: attempts should be 0 during 2nd download check-in, got %d", asgn.Attempts)
	}

	// 3rd Check-in: state moves to staged
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateStaged, "staged")
	outcome3, err3 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err3 != nil || outcome3 != assignment.OutcomeIncomplete {
		t.Fatalf("checkin 3: expected OutcomeIncomplete, got %v, err %v", outcome3, err3)
	}
	if asgn.Attempts != 0 {
		t.Errorf("INVARIANT VIOLATION: attempts should be 0 in staged state, got %d", asgn.Attempts)
	}
}

func TestInferOutcome_SuccessfulConfirmation(t *testing.T) {
	db := newMockDB()
	dev := makeDev()

	wantArt := makeArt("art-101", 101, 11)
	asgn, _ := db.InsertAssignment(context.Background(), dev.ID, wantArt.ID, assignment.StateInstalling, "resolver")

	// Device telemetry: ReportedBuild = 101 (matched!), BootedPartition = SlotApp (0)
	obs := resolver.ObservedState{
		ReportedBuild:   101,
		ReportedSVN:     11,
		BootedPartition: assignment.SlotApp,
	}

	ctx := context.Background()
	outcome, err := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if outcome != assignment.OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed, got %s", outcome)
	}

	if asgn.State != assignment.StateConfirmed {
		t.Errorf("expected assignment state 'confirmed', got %s", asgn.State)
	}
}

func TestInferOutcome_RecoveryBootDegradesHealth(t *testing.T) {
	db := newMockDB()
	dev := makeDev()

	wantArt := makeArt("art-101", 101, 11)
	asgn, _ := db.InsertAssignment(context.Background(), dev.ID, wantArt.ID, assignment.StateInstalling, "resolver")

	// Device telemetry: BootedPartition = SlotRecovery (2)
	obs := resolver.ObservedState{
		ReportedBuild:   100,
		ReportedSVN:     10,
		BootedPartition: assignment.SlotRecovery,
	}

	ctx := context.Background()
	outcome, err := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if outcome != assignment.OutcomeRolledBack {
		t.Errorf("expected OutcomeRolledBack, got %s", outcome)
	}

	if asgn.State != assignment.StateRolledBack {
		t.Errorf("expected assignment state 'rolled_back', got %s", asgn.State)
	}

	// Verify device_events received health change event
	hasHealthEvent := false
	for _, ev := range db.events {
		if ev["event_type"] == "device_health_changed" {
			hasHealthEvent = true
			payload := ev["payload"].(map[string]interface{})
			if payload["health"] != "degraded" {
				t.Errorf("expected health degraded, got %v", payload["health"])
			}
		}
	}
	if !hasHealthEvent {
		t.Error("expected device_health_changed event in log, none found")
	}
}

func TestInferOutcome_InstallFailureRetryAndMaxAttempts(t *testing.T) {
	db := newMockDB()
	dev := makeDev()

	wantArt := makeArt("art-101", 101, 11)
	asgn, _ := db.InsertAssignment(context.Background(), dev.ID, wantArt.ID, assignment.StateInstalling, "resolver")

	// Device telemetry: rebooted, but back on old build 100
	obs := resolver.ObservedState{
		ReportedBuild:   100,
		ReportedSVN:     10,
		BootedPartition: assignment.SlotApp,
	}

	ctx := context.Background()

	// Attempt 1: Failed install -> Revert to offered for retry
	outcome1, err1 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err1 != nil || outcome1 != assignment.OutcomeRetrying {
		t.Fatalf("attempt 1: expected OutcomeRetrying, got %v, err %v", outcome1, err1)
	}
	if asgn.Attempts != 1 {
		t.Errorf("expected attempts == 1, got %d", asgn.Attempts)
	}
	if asgn.State != assignment.StateOffered {
		t.Errorf("expected assignment state reverted to 'offered', got %s", asgn.State)
	}

	// Attempt 2: Re-enter installing, fail again
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateInstalling, "reinstall_attempt")
	outcome2, err2 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err2 != nil || outcome2 != assignment.OutcomeRetrying {
		t.Fatalf("attempt 2: expected OutcomeRetrying, got %v, err %v", outcome2, err2)
	}
	if asgn.Attempts != 2 {
		t.Errorf("expected attempts == 2, got %d", asgn.Attempts)
	}

	// Attempt 3: Re-enter installing, fail 3rd time -> Reaches MAX_ATTEMPTS -> FAILED!
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateInstalling, "reinstall_attempt_3")
	outcome3, err3 := assignment.InferAssignmentOutcome(ctx, db, dev, obs, asgn, &wantArt, 3)
	if err3 != nil || outcome3 != assignment.OutcomeFailedMaxAttempts {
		t.Fatalf("attempt 3: expected OutcomeFailedMaxAttempts, got %v, err %v", outcome3, err3)
	}
	if asgn.Attempts != 3 {
		t.Errorf("expected attempts == 3, got %d", asgn.Attempts)
	}
	if asgn.State != assignment.StateFailed {
		t.Errorf("expected assignment state 'failed', got %s", asgn.State)
	}
}
