package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/buildrunner"
	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

const (
	defaultCmdTimeout = 60 * time.Second
	stepUpCmdTimeout  = 5 * time.Minute
)

// commandContext returns a signal-aware context bounded by timeout (when > 0).
// Callers must always invoke the returned cancel function via defer.
func commandContext(cmd *cobra.Command, timeout time.Duration) (context.Context, context.CancelFunc) {
	base := context.Background()
	if cmd != nil && cmd.Context() != nil {
		base = cmd.Context()
	}
	sigCtx, stop := signal.NotifyContext(base, os.Interrupt, syscall.SIGTERM)
	if timeout <= 0 {
		return sigCtx, stop
	}
	ctx, cancel := context.WithTimeout(sigCtx, timeout)
	return ctx, func() {
		cancel()
		stop()
	}
}

// withStepUp executes fn with a standard command timeout and automatically performs
// interactive Step-Up MFA verification before retrying once when required.
func withStepUp(cmd *cobra.Command, client *apiclient.Client, fn func(context.Context) error) error {
	ctx, cancel := commandContext(cmd, defaultCmdTimeout)
	defer cancel()

	err := fn(ctx)
	if err == nil {
		return nil
	}

	var stepUp *apiclient.StepUpRequired
	if !errors.As(err, &stepUp) {
		return err
	}

	ui.Warn("Step-Up MFA verification required: %s", sanitizeDisplay(stepUp.Detail))
	if _, authErr := authenticateInteractive(cmd, client, stepUpCmdTimeout, authFlowOptions{
		stepUp:     true,
		stepUpACR:  stepUp.ACRValues,
		stepMaxAge: stepUp.MaxAge,
	}); authErr != nil {
		return fmt.Errorf("step-up verification failed: %w", authErr)
	}

	retryCtx, retryCancel := commandContext(cmd, defaultCmdTimeout)
	defer retryCancel()
	return fn(retryCtx)
}

// openBrowserSafe validates rawURL as HTTPS or loopback HTTP, launches the OS browser
// detached from cancellation, and reaps the child process in a background goroutine.
func openBrowserSafe(ctx context.Context, rawURL string) error {
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(rawURL); err != nil {
		return fmt.Errorf("refusing unsafe browser URL: %w", err)
	}

	procCtx := context.WithoutCancel(ctx)
	var proc *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		proc = exec.CommandContext(procCtx, "rundll32", "url.dll,FileProtocolHandler", rawURL)
	case "darwin":
		proc = exec.CommandContext(procCtx, "open", rawURL)
	default:
		proc = exec.CommandContext(procCtx, "xdg-open", rawURL)
	}

	if err := proc.Start(); err != nil {
		return fmt.Errorf("start browser: %w", err)
	}
	go func() {
		_ = proc.Wait()
	}()
	return nil
}

// openProjectInstaller resolves the strict Toob workspace, opens the project registry
// cache, and constructs an Installer ready for package operations.
func openProjectInstaller(devMode bool) (*installer.Installer, error) {
	root, err := paths.FindProjectRootStrict(".")
	if err != nil {
		return nil, fmt.Errorf("not inside a Toob project: %w", err)
	}
	cache, err := registry.OpenForProject(root, devMode || paths.IsDevMode())
	if err != nil {
		return nil, fmt.Errorf("open registry: %w", err)
	}
	inst, err := installer.New(root, cache)
	if err != nil {
		return nil, fmt.Errorf("initialize installer: %w", err)
	}
	return inst, nil
}

// confirmIrreversible requires interactive user confirmation unless assumeYes is true.
func confirmIrreversible(assumeYes bool, prompt string) error {
	if assumeYes {
		return nil
	}
	if !ui.IsInteractive() {
		return errors.New("refusing irreversible operation in non-interactive mode (pass --yes to confirm)")
	}
	ok, err := ui.Confirm(prompt, false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("operation cancelled by user")
	}
	return nil
}

func formatTierBadge(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "official", "verified":
		return "[" + strings.ToUpper(strings.TrimSpace(tier)) + "]"
	case "community":
		return "[COMMUNITY]"
	case "deprecated":
		return "[DEPRECATED]"
	case "revoked":
		return "[REVOKED]"
	default:
		if strings.TrimSpace(tier) == "" {
			return "[UNVERIFIED]"
		}
		return "[" + strings.ToUpper(strings.TrimSpace(tier)) + "]"
	}
}

func sanitizeDisplay(s string) string {
	return buildrunner.SanitizeTerminalOutput(s)
}

func shortID(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func truncateRunes(s string, maxRunes int) string {
	s = sanitizeDisplay(s)
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return string([]rune(s)[:maxRunes])
	}
	return string([]rune(s)[:maxRunes-3]) + "..."
}

func isValidToobToken(tok string) bool {
	var rest string
	switch {
	case strings.HasPrefix(tok, "toob_pat_"):
		rest = strings.TrimPrefix(tok, "toob_pat_")
	case strings.HasPrefix(tok, "toob_svc_"):
		rest = strings.TrimPrefix(tok, "toob_svc_")
	case strings.HasPrefix(tok, "toob_fed_"):
		rest = strings.TrimPrefix(tok, "toob_fed_")
	default:
		return false
	}
	if rest == "" {
		return false
	}
	for i := range len(rest) {
		c := rest[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		if !isAlphaNum {
			return false
		}
	}
	return true
}
