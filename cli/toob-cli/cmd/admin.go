package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

func newAdminCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "admin",
		Short: "Registry administrator review, release, revocation, and cache controls",
	}

	c.AddCommand(
		newAdminStatusCmd(),
		newAdminStagingCmd(),
		newAdminAcceptCmd(),
		newAdminRejectCmd(),
		newAdminReleaseCmd(),
		newAdminRevokeCmd(),
		newAdminArchiveCmd(),
		newAdminCachePurgeCmd(),
		newAdminMockWebhookCmd(),
	)
	return c
}

func newAdminStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show registry administration queue and release index status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			st, err := client.AdminStatus(ctx)
			if err != nil {
				return fmt.Errorf("admin status: %w", err)
			}
			ui.Info("Staging queue: %d | Pending PRs: %d | Validation jobs: %d/%d running=%d failed=%d | Publish jobs: %d/%d failed=%d",
				len(st.StagingPackages),
				len(st.PendingPRs),
				st.ValidationJobsStats.Passed,
				st.ValidationJobsStats.Total,
				st.ValidationJobsStats.Running,
				st.ValidationJobsStats.Failed,
				st.PublishJobsStats.Passed,
				st.PublishJobsStats.Total,
				st.PublishJobsStats.Failed)
			return nil
		},
	}
}

func newAdminStagingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "staging",
		Short: "List staged packages awaiting administrator review",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			resp, err := client.AdminStaging(ctx)
			if err != nil {
				return fmt.Errorf("admin staging: %w", err)
			}
			if resp == nil || len(resp.Packages) == 0 {
				ui.Info("Staging queue is empty.")
				return nil
			}
			for i := range resp.Packages {
				item := &resp.Packages[i]
				ui.Info("%-10s %-24s %-12s status=%s",
					shortID(sanitizeDisplay(item.ID), 10),
					sanitizeDisplay(item.Name),
					sanitizeDisplay(item.Version),
					sanitizeDisplay(item.StagingStatus))
			}
			return nil
		},
	}
}

func newAdminAcceptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "accept <name> <version>",
		Short: "Approve a staged package version for release",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := apiclient.New()
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				return client.AdminAccept(ctx, args[0], args[1])
			}); err != nil {
				return fmt.Errorf("accept staged package: %w", err)
			}
			ui.Success("Accepted %s@%s", sanitizeDisplay(args[0]), sanitizeDisplay(args[1]))
			return nil
		},
	}
}

func newAdminRejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <name> <version> <reason>",
		Short: "Reject a staged package version with a reason",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := apiclient.New()
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				return client.AdminReject(ctx, args[0], args[1], args[2])
			}); err != nil {
				return fmt.Errorf("reject staged package: %w", err)
			}
			ui.Success("Rejected %s@%s", sanitizeDisplay(args[0]), sanitizeDisplay(args[1]))
			return nil
		},
	}
}

func newAdminReleaseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "release",
		Short: "Publish and Ed25519-sign a new registry index release snapshot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := apiclient.New()
			var rel *apiclient.AdminReleaseResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var relErr error
				rel, relErr = client.AdminRelease(ctx)
				return relErr
			}); err != nil {
				return fmt.Errorf("release index snapshot: %w", err)
			}
			ui.Success("Published signed registry index release (revision=%d, count=%d, status=%s)",
				rel.RevisionID, rel.Count, sanitizeDisplay(rel.Status))
			return nil
		},
	}
}

func newAdminRevokeCmd() *cobra.Command {
	var (
		severity    string
		title       string
		description string
	)

	c := &cobra.Command{
		Use:   "revoke <name> <version>",
		Short: "Security-revoke a released package version (emits HTTP 410 / revoked stage)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(title) == "" {
				return errors.New("--title (advisory reason) is required when revoking a package")
			}

			client := apiclient.New()
			var revResp *apiclient.AdminRevokeResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var revErr error
				revResp, revErr = client.AdminRevoke(ctx, apiclient.AdminRevokeRequest{
					Name:        args[0],
					Version:     args[1],
					Severity:    severity,
					Title:       title,
					Description: description,
				})
				return revErr
			}); err != nil {
				return fmt.Errorf("revoke package: %w", err)
			}
			ui.Success("Revoked %s@%s (advisory=%d, affected_revisions=%d)",
				sanitizeDisplay(args[0]), sanitizeDisplay(args[1]), revResp.AdvisoryID, revResp.AffectedRevisions)
			return nil
		},
	}

	c.Flags().StringVar(&severity, "severity", "high", "Security advisory severity (critical, high, medium, low)")
	c.Flags().StringVar(&title, "title", "", "Security advisory summary title (required)")
	c.Flags().StringVar(&title, "reason", "", "Alias for --title")
	c.Flags().StringVar(&description, "description", "", "Optional detailed revocation notes")
	return c
}

func newAdminArchiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "archive <name> <version>",
		Short: "Archive an older package version from active distribution",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := apiclient.New()
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				return client.AdminArchive(ctx, args[0], args[1])
			}); err != nil {
				return fmt.Errorf("archive package: %w", err)
			}
			ui.Success("Archived %s@%s", sanitizeDisplay(args[0]), sanitizeDisplay(args[1]))
			return nil
		},
	}
}

func newAdminCachePurgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cache-purge",
		Short: "Purge edge CDN and metadata caches on the registry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := apiclient.New()
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				return client.AdminCachePurge(ctx)
			}); err != nil {
				return fmt.Errorf("purge registry caches: %w", err)
			}
			ui.Success("Purged registry caches.")
			return nil
		},
	}
}

func newAdminMockWebhookCmd() *cobra.Command {
	var (
		action       string
		prNumber     int
		repo         string
		headSHA      string
		githubUserID int64
		files        []string
	)

	c := &cobra.Command{
		Use:    "mock-webhook",
		Short:  "Simulate a GitHub PR webhook callback (dev/test only)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := apiclient.New()
			var resp *apiclient.AdminMockWebhookResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var hookErr error
				resp, hookErr = client.AdminMockWebhook(ctx, apiclient.AdminMockWebhookRequest{
					Action:       action,
					PRNumber:     prNumber,
					Repo:         repo,
					HeadSHA:      headSHA,
					GitHubUserID: githubUserID,
					Files:        files,
				})
				return hookErr
			}); err != nil {
				return fmt.Errorf("mock webhook failed: %w", err)
			}
			ui.Success("Dispatched mock webhook: status=%s job_id=%d", sanitizeDisplay(resp.Status), resp.JobID)
			return nil
		},
	}

	c.Flags().StringVar(&action, "action", "opened", "PR webhook action")
	c.Flags().IntVar(&prNumber, "pr", 1, "Pull request number")
	c.Flags().StringVar(&repo, "repo", "toob-boot/toob-registry", "Repository slug")
	c.Flags().StringVar(&headSHA, "sha", "", "Git head commit SHA")
	c.Flags().Int64Var(&githubUserID, "user-id", 1, "GitHub user ID")
	c.Flags().StringSliceVar(&files, "files", nil, "Changed file paths")
	return c
}
