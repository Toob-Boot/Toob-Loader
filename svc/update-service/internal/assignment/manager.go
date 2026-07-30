// Package assignment implements the Lazy Materialization engine and Assignment State Machine
// with strict monotonicity enforcement and audit event logging (§5.1, §5.2, §5.3 in plan7.md, UPD-022, UPD-025 in plan8.md).
package assignment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/toob-boot/update-service/internal/resolver"
)

// State represents the lifecycle state of an assignment.
type State string

const (
	StateOffered     State = "offered"     // Ordinal 0: initial offer
	StateAssigned    State = "assigned"    // Alias for offered
	StateDownloading State = "downloading" // Ordinal 1: device downloading blob
	StateStaged      State = "staged"      // Ordinal 2: download finished & transport SHA verified
	StateInstalling  State = "installing"  // Ordinal 3: device rebooting/installing build
	StateConfirmed   State = "confirmed"   // Ordinal 4: Terminal success
	StateRolledBack  State = "rolled_back" // Ordinal 4: Terminal rollback
	StateFailed      State = "failed"      // Ordinal 4: Terminal failure
	StateSuperseded  State = "superseded"  // Ordinal 4: Terminal superseded
)

// Ordinal returns the monotonic ordinal number of a state.
// State transitions can only move to equal or higher ordinals.
func (s State) Ordinal() int {
	switch s {
	case StateOffered, StateAssigned:
		return 0
	case StateDownloading:
		return 1
	case StateStaged:
		return 2
	case StateInstalling:
		return 3
	case StateConfirmed, StateRolledBack, StateFailed, StateSuperseded:
		return 4
	default:
		return -1
	}
}

// IsTerminal returns true if the assignment has reached a final state.
func (s State) IsTerminal() bool {
	return s.Ordinal() == 4
}

func (s State) String() string {
	return string(s)
}

// CanTransition evaluates whether moving from currentState to targetState is allowed
// according to the explicit state transition permission matrix (§5.1 in plan7.md).
func CanTransition(from, to State) bool {
	if from.Ordinal() < 0 || to.Ordinal() < 0 {
		return false
	}
	// Terminal states cannot transition anywhere (even to other terminal states)
	if from.IsTerminal() {
		return false
	}
	// Ordinal cannot decrease (monotonic rule)
	if to.Ordinal() < from.Ordinal() {
		return false
	}
	// Explicit Matrix:
	switch from {
	case StateOffered, StateAssigned:
		return to == StateDownloading || to == StateStaged || to == StateInstalling || to == StateFailed || to == StateSuperseded
	case StateDownloading:
		return to == StateStaged || to == StateInstalling || to == StateFailed || to == StateSuperseded
	case StateStaged:
		return to == StateInstalling || to == StateConfirmed || to == StateRolledBack || to == StateFailed || to == StateSuperseded
	case StateInstalling:
		return to == StateConfirmed || to == StateRolledBack || to == StateFailed || to == StateSuperseded
	default:
		return false
	}
}

// Sentinel error definitions.
var (
	ErrAssignmentNotFound        = errors.New("assignment: assignment not found")
	ErrNonMonotonicTransition    = errors.New("assignment: non-monotonic state transition prohibited")
	ErrInvalidState              = errors.New("assignment: invalid state value")
	ErrAssignmentAlreadyTerminal = errors.New("assignment: assignment is in a terminal state")
)

// AssignmentRecord represents a materialized assignment row from DB.
type AssignmentRecord struct {
	ID         string    `json:"id"`
	DeviceID   []byte    `json:"device_id"`
	ArtifactID string    `json:"artifact_id"`
	State      State     `json:"state"`
	Attempts   int16     `json:"attempts"`
	Source     string    `json:"source"` // "resolver" or "pin"
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DatabaseOps abstracts database queries for assignment operations and device audit logging.
type DatabaseOps interface {
	GetOpenAssignment(ctx context.Context, deviceID []byte) (*AssignmentRecord, error)
	GetArtifactByID(ctx context.Context, artifactID string) (*resolver.Artifact, error)
	InsertAssignment(ctx context.Context, deviceID []byte, artifactID string, initialState State, source string) (*AssignmentRecord, error)
	UpdateAssignmentState(ctx context.Context, assignmentID string, newState State) error
	IncrementAssignmentAttempts(ctx context.Context, assignmentID string) (int16, error)
	SupersedeOpenAssignment(ctx context.Context, deviceID []byte) error
	UpdateDeviceHealth(ctx context.Context, deviceID []byte, health string) error
	LogDeviceEvent(ctx context.Context, deviceID []byte, eventType string, payload map[string]interface{}) error
}

// Reconcile performs lazy materialization of desired state assignments (§5.2 in plan7.md).
func Reconcile(
	ctx context.Context,
	db DatabaseOps,
	dev resolver.Device,
	obs resolver.ObservedState,
	candidates []resolver.Artifact,
	opts resolver.Options,
) (*AssignmentRecord, *resolver.Artifact, bool, error) {
	if len(dev.ID) == 0 {
		return nil, nil, false, errors.New("assignment.Reconcile: device_id cannot be empty")
	}

	// 1. Check for existing open assignment (WHERE state IN ('offered', 'downloading', 'staged'))
	openAssignment, err := db.GetOpenAssignment(ctx, dev.ID)
	if err != nil && !errors.Is(err, ErrAssignmentNotFound) {
		return nil, nil, false, fmt.Errorf("assignment.Reconcile: check open assignment: %w", err)
	}

	if openAssignment != nil {
		// Open assignment exists — STABLE! No re-resolution, NO DB WRITES!
		art, artErr := db.GetArtifactByID(ctx, openAssignment.ArtifactID)
		if artErr != nil {
			return nil, nil, false, fmt.Errorf("assignment.Reconcile: fetch assigned artifact %s: %w", openAssignment.ArtifactID, artErr)
		}
		return openAssignment, art, false, nil
	}

	// 2. No open assignment exists — run pure deterministic Resolver
	selectedArt, reason, resErr := resolver.Resolve(dev, obs, candidates, opts)
	if resErr != nil {
		return nil, nil, false, fmt.Errorf("assignment.Reconcile: resolver error: %w", resErr)
	}

	if selectedArt == nil {
		// Resolver returned no update (e.g. up-to-date, excluded by ramp) → HTTP 204 (NO DB WRITES!)
		_ = reason
		return nil, nil, false, nil
	}

	// 3. Materialize Assignment Exactly Now (Lazy Materialization)
	source := "resolver"
	if opts.PinnedArtifactID != "" && opts.PinnedArtifactID == selectedArt.ID {
		source = "pin"
	}

	newAssignment, insErr := db.InsertAssignment(ctx, dev.ID, selectedArt.ID, StateOffered, source)
	if insErr != nil {
		// Handle potential race condition: concurrent check-in inserted open assignment first
		if strings.Contains(insErr.Error(), "assignments_one_open") || strings.Contains(insErr.Error(), "unique") {
			existing, getErr := db.GetOpenAssignment(ctx, dev.ID)
			if getErr == nil && existing != nil {
				art, _ := db.GetArtifactByID(ctx, existing.ArtifactID)
				return existing, art, false, nil
			}
		}
		return nil, nil, false, fmt.Errorf("assignment.Reconcile: insert assignment: %w", insErr)
	}

	// Synchronously record initial materialization in device_events
	_ = db.LogDeviceEvent(ctx, dev.ID, "assignment_created", map[string]interface{}{
		"assignment_id": newAssignment.ID,
		"artifact_id":   selectedArt.ID,
		"source":        source,
	})

	return newAssignment, selectedArt, true, nil
}

// TransitionState enforces monotonic forward state transitions and writes a device_events audit record (§5.1, UPD-025).
func TransitionState(
	ctx context.Context,
	db DatabaseOps,
	currentAssignment *AssignmentRecord,
	targetState State,
	reason string,
) error {
	if currentAssignment == nil {
		return ErrAssignmentNotFound
	}
	if targetState.Ordinal() < 0 {
		return ErrInvalidState
	}

	fromState := currentAssignment.State

	// 1. Idempotent Same-State Transition -> No-op
	if fromState == targetState {
		return nil
	}

	// 2. Terminal State Guard
	if fromState.IsTerminal() {
		return fmt.Errorf("%w: assignment %s is already terminal (%s)", ErrAssignmentAlreadyTerminal, currentAssignment.ID, fromState)
	}

	// 3. Explicit Transition Matrix & Monotonicity Guard
	if !CanTransition(fromState, targetState) {
		return fmt.Errorf("%w: illegal transition from %s (ord %d) to %s (ord %d)",
			ErrNonMonotonicTransition, fromState, fromState.Ordinal(), targetState, targetState.Ordinal())
	}

	// 4. Update state in Database
	if err := db.UpdateAssignmentState(ctx, currentAssignment.ID, targetState); err != nil {
		return fmt.Errorf("assignment.TransitionState: update state failed: %w", err)
	}

	// Update in-memory struct
	currentAssignment.State = targetState
	currentAssignment.UpdatedAt = time.Now().UTC()

	// 5. Synchronous Audit Logging: Write exactly ONE device_events row
	payload := map[string]interface{}{
		"assignment_id": currentAssignment.ID,
		"artifact_id":   currentAssignment.ArtifactID,
		"from_state":    string(fromState),
		"to_state":      string(targetState),
		"reason":        reason,
	}
	if err := db.LogDeviceEvent(ctx, currentAssignment.DeviceID, "assignment_state_changed", payload); err != nil {
		// Log warning, but state change succeeded
		_ = err
	}

	return nil
}
