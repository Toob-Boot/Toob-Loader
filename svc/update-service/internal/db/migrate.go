// Package db provides database migration management for the update service.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/toob-boot/update-service/migrations"
)

// Migrate runs all pending database migrations against the given DSN.
// It uses goose with embedded SQL files — no external migration binary needed.
//
// The migration runner is idempotent: re-running on an up-to-date database
// is a no-op. Goose tracks applied migrations in a `goose_db_version` table.
func Migrate(ctx context.Context, dsn string) error {
	db, err := stdlib.Open(dsn)
	if err != nil {
		return fmt.Errorf("db.Migrate: open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("db.Migrate: ping: %w", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("db.Migrate: set dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("db.Migrate: apply migrations: %w", err)
	}

	return nil
}
