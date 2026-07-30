// Package migrations embeds the SQL migration files for the update service.
package migrations

import "embed"

// FS contains all SQL migration files, embedded at compile time.
// Used by the db package to run goose migrations without external files.
//
//go:embed *.sql
var FS embed.FS
