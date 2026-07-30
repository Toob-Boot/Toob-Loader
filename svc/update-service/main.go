// Package main is the entry point for the Toob Update Service.
//
// The service manages firmware artifact ingestion, release assignment,
// and device check-in for OTA updates. See plan7.md for the full
// architecture specification.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/toob-boot/update-service/internal/db"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	if err := db.Migrate(ctx, dsn); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	fmt.Println("toob-update-service: migrations applied, ready.")

	// Service initialization will be added by subsequent UPD tickets.
	// Block until shutdown signal.
	<-ctx.Done()
	fmt.Println("toob-update-service: shutting down.")
}
