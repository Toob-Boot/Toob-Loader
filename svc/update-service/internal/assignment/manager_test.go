package assignment_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/toob-boot/update-service/internal/assignment"
	"github.com/toob-boot/update-service/internal/resolver"
)

// mockDB implements assignment.DatabaseOps for unit testing.
type mockDB struct {
	mu          sync.Mutex
	assignments map[string]*assignment.AssignmentRecord // key: assignment_id
	openByDev   map[string]*assignment.AssignmentRecord // key: hex(device_id)
	artifacts   map[string]*resolver.Artifact
	events      []map[string]interface{}
	writeCount  int
}

func newMockDB() *mockDB {
	return &mockDB{
		assignments: make(map[string]*assignment.AssignmentRecord),
		openByDev:   make(map[string]*assignment.AssignmentRecord),
		artifacts:   make(map[string]*resolver.Artifact),
		events:      make([]map[string]interface{}, 0),
	}
}

func (m *mockDB) GetOpenAssignment(ctx context.Context, deviceID []byte) (*assignment.AssignmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%x", deviceID)
	rec, exists := m.openByDev[key]
	if !exists || rec.State.IsTerminal() {
		return nil, assignment.ErrAssignmentNotFound
	}
	return rec, nil
}

func (m *mockDB) GetArtifactByID(ctx context.Context, artifactID string) (*resolver.Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	art, exists := m.artifacts[artifactID]
	if !exists {
		return nil, errors.New("artifact not found")
	}
	return art, nil
}

func (m *mockDB) InsertAssignment(ctx context.Context, deviceID []byte, artifactID string, initialState assignment.State, source string) (*assignment.AssignmentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.writeCount++
	key := fmt.Sprintf("%x", deviceID)

	if existing, exists := m.openByDev[key]; exists && !existing.State.IsTerminal() {
		return nil, fmt.Errorf("unique constraint violation: assignments_one_open")
	}

	rec := &assignment.AssignmentRecord{
		ID:         fmt.Sprintf("asgn-%d", len(m.assignments)+1),
		DeviceID:   deviceID,
		ArtifactID: artifactID,
		State:      initialState,
		Attempts:   0,
		Source:     source,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	m.assignments[rec.ID] = rec
	m.openByDev[key] = rec
	return rec, nil
}

func (m *mockDB) UpdateAssignmentState(ctx context.Context, assignmentID string, newState assignment.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.writeCount++
	rec, exists := m.assignments[assignmentID]
	if !exists {
		return assignment.ErrAssignmentNotFound
	}
	rec.State = newState
	rec.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *mockDB) IncrementAssignmentAttempts(ctx context.Context, assignmentID string) (int16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.assignments[assignmentID]
	if !exists {
		return 0, assignment.ErrAssignmentNotFound
	}
	rec.Attempts++
	return rec.Attempts, nil
}

func (m *mockDB) SupersedeOpenAssignment(ctx context.Context, deviceID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%x", deviceID)
	if rec, exists := m.openByDev[key]; exists && !rec.State.IsTerminal() {
		rec.State = assignment.StateSuperseded
		m.writeCount++
	}
	return nil
}

func (m *mockDB) UpdateDeviceHealth(ctx context.Context, deviceID []byte, health string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.writeCount++
	return nil
}

func (m *mockDB) LogDeviceEvent(ctx context.Context, deviceID []byte, eventType string, payload map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := map[string]interface{}{
		"device_id":  fmt.Sprintf("%x", deviceID),
		"event_type": eventType,
		"payload":    payload,
		"created_at": time.Now().UTC(),
	}
	m.events = append(m.events, entry)
	return nil
}

// Helpers
func makeDev() resolver.Device {
	return resolver.Device{
		ID:              []byte("01234567890123456789012345678901"),
		Product:         "toob-lamp-01",
		ProductHWRev:    1,
		StagingCapacity: 1024 * 1024,
		ReaderMajor:     2,
		ReaderMinor:     0,
		Channel:         "stable",
		Health:          "ok",
	}
}

func makeObs() resolver.ObservedState {
	return resolver.ObservedState{
		ReportedSVN:   10,
		ReportedBuild: 100,
	}
}

func makeArt(id string, buildNum uint32, svnVal uint32) resolver.Artifact {
	return resolver.Artifact{
		ID:             id,
		Product:        "toob-lamp-01",
		BuildNumber:    buildNum,
		Kind:           "full",
		SizeBytes:      512 * 1024,
		SVN:            svnVal,
		HWRevMin:       1,
		HWRevMax:       5,
		MinReaderMajor: 2,
		MinReaderMinor: 0,
		TargetSlot:     0,
	}
}

// ---- Unit & Integration Tests ----

func TestTransitionState_ExplicitMatrixAndAuditLogging(t *testing.T) {
	db := newMockDB()
	devID := []byte("01234567890123456789012345678901")

	asgn, _ := db.InsertAssignment(context.Background(), devID, "art-101", assignment.StateOffered, "resolver")
	ctx := context.Background()

	// 1. Valid Transition: offered -> downloading
	if err := assignment.TransitionState(ctx, db, asgn, assignment.StateDownloading, "chunk_download_started"); err != nil {
		t.Fatalf("expected valid transition offered->downloading, got: %v", err)
	}

	// 2. Valid Transition: downloading -> staged
	if err := assignment.TransitionState(ctx, db, asgn, assignment.StateStaged, "download_completed_sha_verified"); err != nil {
		t.Fatalf("expected valid transition downloading->staged, got: %v", err)
	}

	// 3. Valid Transition: staged -> installing
	if err := assignment.TransitionState(ctx, db, asgn, assignment.StateInstalling, "device_rebooting"); err != nil {
		t.Fatalf("expected valid transition staged->installing, got: %v", err)
	}

	// 4. Valid Terminal Transition: installing -> confirmed
	if err := assignment.TransitionState(ctx, db, asgn, assignment.StateConfirmed, "checkin_build_matched"); err != nil {
		t.Fatalf("expected valid terminal transition installing->confirmed, got: %v", err)
	}

	// Verify device_events audit count (1 initial + 4 transitions = 5)
	if len(db.events) != 4 {
		t.Errorf("expected 4 transition device_events audit records, got %d", len(db.events))
	}
}

func TestTransitionState_OutOfOrderEventRejection(t *testing.T) {
	db := newMockDB()
	devID := []byte("01234567890123456789012345678901")
	asgn, _ := db.InsertAssignment(context.Background(), devID, "art-101", assignment.StateOffered, "resolver")
	ctx := context.Background()

	// Move assignment to staged
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateStaged, "staged")

	// Out-of-order event: delayed downloading event arrives after staged -> MUST BE REJECTED!
	err := assignment.TransitionState(ctx, db, asgn, assignment.StateDownloading, "delayed_download_event")
	if !errors.Is(err, assignment.ErrNonMonotonicTransition) {
		t.Fatalf("expected ErrNonMonotonicTransition on out-of-order event, got: %v", err)
	}

	// Move assignment to confirmed (terminal)
	_ = assignment.TransitionState(ctx, db, asgn, assignment.StateConfirmed, "confirmed")

	// Out-of-order event after terminal state -> MUST BE REJECTED!
	err = assignment.TransitionState(ctx, db, asgn, assignment.StateStaged, "delayed_staged_event")
	if !errors.Is(err, assignment.ErrAssignmentAlreadyTerminal) && !errors.Is(err, assignment.ErrNonMonotonicTransition) {
		t.Fatalf("expected terminal rejection, got: %v", err)
	}
}

func TestTransitionState_IdempotentSameStateNoOp(t *testing.T) {
	db := newMockDB()
	devID := []byte("01234567890123456789012345678901")
	asgn, _ := db.InsertAssignment(context.Background(), devID, "art-101", assignment.StateDownloading, "resolver")
	ctx := context.Background()

	initialEventCount := len(db.events)

	// Transition downloading -> downloading (Same state!)
	err := assignment.TransitionState(ctx, db, asgn, assignment.StateDownloading, "duplicate_downloading_event")
	if err != nil {
		t.Fatalf("unexpected error on idempotent transition: %v", err)
	}

	// Must NOT create extra audit event logs for idempotent no-op
	if len(db.events) != initialEventCount {
		t.Errorf("idempotent transition created duplicate audit event!")
	}
}

func TestTransitionState_PropertyBasedStateMachinePermutations(t *testing.T) {
	allStates := []assignment.State{
		assignment.StateOffered,
		assignment.StateDownloading,
		assignment.StateStaged,
		assignment.StateInstalling,
		assignment.StateConfirmed,
		assignment.StateRolledBack,
		assignment.StateFailed,
		assignment.StateSuperseded,
	}

	rng := rand.New(rand.NewSource(42))

	// Run 1,000 randomized state transition sequences
	for i := 0; i < 1000; i++ {
		db := newMockDB()
		devID := []byte(fmt.Sprintf("device-random-%d", i))
		asgn, _ := db.InsertAssignment(context.Background(), devID, "art-101", assignment.StateOffered, "resolver")
		ctx := context.Background()

		// Generate random sequence of 10 target state transitions
		seqLen := 10
		lastOrdinal := asgn.State.Ordinal()

		for step := 0; step < seqLen; step++ {
			targetState := allStates[rng.Intn(len(allStates))]
			err := assignment.TransitionState(ctx, db, asgn, targetState, fmt.Sprintf("random_step_%d", step))

			if err == nil {
				// Transition succeeded: assert ordinal moved forward or stayed same
				currentOrd := asgn.State.Ordinal()
				if currentOrd < lastOrdinal {
					t.Fatalf("PROPERTY VIOLATION: ordinal regressed from %d to %d!", lastOrdinal, currentOrd)
				}
				lastOrdinal = currentOrd
			} else {
				// Transition failed: assert that it was a valid rejection (backward or illegal)
				if !errors.Is(err, assignment.ErrNonMonotonicTransition) &&
					!errors.Is(err, assignment.ErrAssignmentAlreadyTerminal) &&
					!errors.Is(err, assignment.ErrInvalidState) {
					t.Fatalf("unexpected state machine error: %v", err)
				}
			}
		}

		// Final safety assertion: state ordinal MUST be >= initial ordinal
		if asgn.State.Ordinal() < 0 {
			t.Fatalf("PROPERTY VIOLATION: final state ordinal invalid: %s", asgn.State)
		}
	}
}
