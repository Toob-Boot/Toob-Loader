package svn_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/toob-boot/update-service/internal/svn"
)

// mockRow implements svn.RowScanner for unit testing.
type mockRow struct {
	val uint32
	err error
}

func (m *mockRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	if len(dest) > 0 {
		if ptr, ok := dest[0].(*uint32); ok {
			*ptr = m.val
		}
	}
	return nil
}

// mockDB implements svn.ExecQueryRow for unit testing.
type mockDB struct {
	floors      map[string]uint32 // key: "product:slot"
	auditEvents []string
	queryErr    error
}

func newMockDB() *mockDB {
	return &mockDB{
		floors: make(map[string]uint32),
	}
}

func (m *mockDB) QueryRow(ctx context.Context, query string, args ...any) svn.RowScanner {
	if m.queryErr != nil {
		return &mockRow{err: m.queryErr}
	}
	product := args[0].(string)
	slot := args[1].(uint8)
	key := fmt.Sprintf("%s:%d", product, slot)

	val, exists := m.floors[key]
	if !exists {
		return &mockRow{err: errors.New("no rows in result set")}
	}
	return &mockRow{val: val}
}

func (m *mockDB) Exec(ctx context.Context, query string, args ...any) (any, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if len(args) >= 3 && query != "" {
		// Insert or Update floor
		product := args[0].(string)
		slot := args[1].(uint8)
		val := args[2].(uint32)
		key := fmt.Sprintf("%s:%d", product, slot)
		m.floors[key] = val
	}
	return nil, nil
}

func TestEnforceFloor_InitialPublish(t *testing.T) {
	db := newMockDB()
	ctx := context.Background()

	// Initial publish with SVN = 10 for App slot (0)
	err := svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 10, false, "")
	if err != nil {
		t.Fatalf("expected success on initial publish, got: %v", err)
	}

	if db.floors["toob-lamp-01:0"] != 10 {
		t.Errorf("expected floor to be 10, got %d", db.floors["toob-lamp-01:0"])
	}
}

func TestEnforceFloor_MonotonicIncrease(t *testing.T) {
	db := newMockDB()
	ctx := context.Background()

	_ = svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 10, false, "")

	// Inkrementeller Publish mit SVN = 15
	err := svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 15, false, "")
	if err != nil {
		t.Fatalf("expected success on higher SVN, got: %v", err)
	}

	if db.floors["toob-lamp-01:0"] != 15 {
		t.Errorf("expected floor to be 15, got %d", db.floors["toob-lamp-01:0"])
	}
}

func TestEnforceFloor_RejectLowerSVN(t *testing.T) {
	db := newMockDB()
	ctx := context.Background()

	_ = svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 10, false, "")

	// Versuche Veröffentlichung mit SVN = 5 (niedriger als 10) ohne Force
	err := svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 5, false, "")
	if err == nil {
		t.Fatal("expected ErrSVNTooLow error, got nil")
	}

	var svnErr *svn.ErrSVNTooLow
	if !errors.As(err, &svnErr) {
		t.Fatalf("expected ErrSVNTooLow error type, got: %T (%v)", err, err)
	}

	if svnErr.CurrentFloor != 10 || svnErr.AttemptedSVN != 5 {
		t.Errorf("unexpected error details: %+v", svnErr)
	}
}

func TestEnforceFloor_TargetSlotSeparation(t *testing.T) {
	db := newMockDB()
	ctx := context.Background()

	// App Slot (0) hat SVN = 20
	_ = svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 20, false, "")

	// Stage1 Slot (3) wird mit SVN = 2 initialisiert — muss unabhängig von App Slot (20) klappen!
	err := svn.EnforceFloor(ctx, db, "toob-lamp-01", 3, 2, false, "")
	if err != nil {
		t.Fatalf("expected Stage1 slot (3) to be independent of App slot (0), got error: %v", err)
	}

	if db.floors["toob-lamp-01:0"] != 20 {
		t.Errorf("App slot floor changed unexpectedly: %d", db.floors["toob-lamp-01:0"])
	}
	if db.floors["toob-lamp-01:3"] != 2 {
		t.Errorf("Stage1 slot floor expected 2, got: %d", db.floors["toob-lamp-01:3"])
	}
}

func TestEnforceFloor_ForceBypass(t *testing.T) {
	db := newMockDB()
	ctx := context.Background()

	_ = svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 10, false, "")

	// Force bypass ohne Audit-Begründung muss abgelehnt werden
	err := svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 5, true, "")
	if !errors.Is(err, svn.ErrForceRequiresAuditReason) {
		t.Fatalf("expected ErrForceRequiresAuditReason, got: %v", err)
	}

	// Force bypass mit gültiger Audit-Begründung muss erlaubt sein
	err = svn.EnforceFloor(ctx, db, "toob-lamp-01", 0, 5, true, "Security emergency hotfix rollback")
	if err != nil {
		t.Fatalf("expected force bypass with reason to succeed, got: %v", err)
	}
}
