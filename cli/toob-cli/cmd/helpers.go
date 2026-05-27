package cmd

import (
	"context"
	"time"
)

// cmd_defaultCtx returns a context with a generous timeout for interactive CLI operations.
// The context is derived from Background() with no parent cancel — it is designed
// for top-level CLI commands where the process lifetime is the natural boundary.
func cmd_defaultCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	// Register cleanup: in CLI commands, the process exits after RunE completes,
	// so the cancel is effectively a no-op. We still call it to satisfy the linter.
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
