// Package svn enforces per-product, per-target-slot SVN (Security Version Number)
// monotonicity invariants at the database level (§7.3 in plan7.md, UPD-012 in plan8.md).
package svn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Standard error sentinel errors.
var (
	ErrForceRequiresAuditReason = errors.New("svn: force bypass requires a non-empty audit reason")
	ErrProductNotFound          = errors.New("svn: product not found in database")
)

// ErrSVNTooLow indicates that the proposed SVN is lower than the highest published SVN
// for the given product and target slot.
type ErrSVNTooLow struct {
	Product      string
	TargetSlot   uint8
	CurrentFloor uint32
	AttemptedSVN uint32
}

func (e *ErrSVNTooLow) Error() string {
	return fmt.Sprintf(
		"svn: proposed SVN %d for product %q (slot %d) is lower than max published floor %d",
		e.AttemptedSVN, e.Product, e.TargetSlot, e.CurrentFloor,
	)
}

// ExecQueryRow matches the subset of pgx.Tx or pgxpool.Pool needed to execute queries.
type ExecQueryRow interface {
	QueryRow(ctx context.Context, sql string, args ...any) RowScanner
	Exec(ctx context.Context, sql string, args ...any) (any, error)
}

// RowScanner abstracts pgx.Row / sql.Row scanning.
type RowScanner interface {
	Scan(dest ...any) error
}

// NilDeviceID is a 32-byte zero buffer used for system-level audit events in device_events.
var NilDeviceID = make([]byte, 32)

// EnforceFloor verifies and updates the SVN floor for a product and target slot.
// Must be called within a database transaction to maintain serializability.
//
// Arguments:
//   - ctx: execution context
//   - db: database transaction (must support SELECT FOR UPDATE)
//   - productID: product identifier (e.g. "toob-lamp-01")
//   - targetSlot: target slot (0 = SlotApp, 3 = SlotStage1)
//   - newSVN: the SVN of the new artifact being published
//   - force: if true, allows publishing an SVN < current floor
//   - auditReason: mandatory justification when force is true
//
// Returns nil on success, ErrSVNTooLow if SVN is lower than floor and force=false,
// or ErrForceRequiresAuditReason if force=true but auditReason is empty.
func EnforceFloor(
	ctx context.Context,
	db ExecQueryRow,
	productID string,
	targetSlot uint8,
	newSVN uint32,
	force bool,
	auditReason string,
) error {
	productID = strings.TrimSpace(productID)
	if productID == "" {
		return errors.New("svn: productID cannot be empty")
	}

	// 1. SELECT FOR UPDATE to lock the SVN floor row for this product & slot
	queryLock := `
		SELECT max_published_svn
		FROM product_svn_floor
		WHERE product = $1 AND target_slot = $2
		FOR UPDATE;
	`

	var currentFloor uint32
	err := db.QueryRow(ctx, queryLock, productID, targetSlot).Scan(&currentFloor)

	rowExists := true
	if err != nil {
		// Row does not exist yet for this (product, target_slot)
		if strings.Contains(err.Error(), "no rows") {
			rowExists = false
			currentFloor = 0
		} else {
			return fmt.Errorf("svn.EnforceFloor: select lock failed: %w", err)
		}
	}

	// 2. Check SVN monotonicity
	if newSVN < currentFloor {
		if !force {
			return &ErrSVNTooLow{
				Product:      productID,
				TargetSlot:   targetSlot,
				CurrentFloor: currentFloor,
				AttemptedSVN: newSVN,
			}
		}

		// Force bypass requested — audit reason is mandatory
		reason := strings.TrimSpace(auditReason)
		if reason == "" {
			return ErrForceRequiresAuditReason
		}

		// Write audit event to device_events within the same transaction
		payload, jsonErr := json.Marshal(map[string]any{
			"product":       productID,
			"target_slot":   targetSlot,
			"current_floor": currentFloor,
			"attempted_svn": newSVN,
			"reason":        reason,
		})
		if jsonErr != nil {
			return fmt.Errorf("svn.EnforceFloor: marshal audit payload: %w", jsonErr)
		}

		auditQuery := `
			INSERT INTO device_events (device_id, event_type, payload)
			VALUES ($1, 'svn_floor_force_bypass', $2);
		`
		if _, execErr := db.Exec(ctx, auditQuery, NilDeviceID, payload); execErr != nil {
			return fmt.Errorf("svn.EnforceFloor: log audit event: %w", execErr)
		}
	}

	// 3. Upsert floor in product_svn_floor
	if !rowExists {
		insertQuery := `
			INSERT INTO product_svn_floor (product, target_slot, max_published_svn)
			VALUES ($1, $2, $3);
		`
		if _, execErr := db.Exec(ctx, insertQuery, productID, targetSlot, newSVN); execErr != nil {
			return fmt.Errorf("svn.EnforceFloor: insert initial floor: %w", execErr)
		}
	} else if newSVN > currentFloor {
		updateQuery := `
			UPDATE product_svn_floor
			SET max_published_svn = GREATEST(max_published_svn, $3)
			WHERE product = $1 AND target_slot = $2;
		`
		if _, execErr := db.Exec(ctx, updateQuery, productID, targetSlot, newSVN); execErr != nil {
			return fmt.Errorf("svn.EnforceFloor: update floor: %w", execErr)
		}
	}

	return nil
}
