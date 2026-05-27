package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Core-team administration commands",
	Long:  `Administrative commands for Toob core team members (requires 'core' role).`,
}

// --- admin staging ---

var adminStagingCmd = &cobra.Command{
	Use:   "staging",
	Short: "List all packages in staging review",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		body, err := adminGET(client, "/api/v1/admin/staging")
		if err != nil {
			return fmt.Errorf("failed to fetch staging packages: %w", err)
		}

		var resp struct {
			Packages []struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Version string `json:"version"`
				Status  string `json:"staging_status"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if len(resp.Packages) == 0 {
			ui.Info("No packages in staging.")
			return nil
		}

		ui.Header("Staging Review")
		headers := []string{"ID", "NAME", "VERSION", "STATUS"}
		var rows [][]string
		for _, p := range resp.Packages {
			rows = append(rows, []string{p.ID[:8], p.Name, p.Version, p.Status})
		}
		ui.Table(headers, rows)
		return nil
	},
}

// --- admin accept ---

var adminAcceptCmd = &cobra.Command{
	Use:   "accept <name>@<version>",
	Short: "Accept a staging package for release",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		name, version, err := parseNameVersion(args[0])
		if err != nil {
			return err
		}

		ui.Step("Accepting %s@%s...", name, version)
		_, err = adminPOST(client, "/api/v1/admin/accept", map[string]string{
			"name":    name,
			"version": version,
		})
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}

		ui.Success("Accepted %s@%s for release.", name, version)
		return nil
	},
}

// --- admin reject ---

var adminRejectCmd = &cobra.Command{
	Use:   "reject <name>@<version>",
	Short: "Reject a staging package with feedback",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		name, version, err := parseNameVersion(args[0])
		if err != nil {
			return err
		}

		reason, _ := cmd.Flags().GetString("reason")
		if reason == "" {
			return fmt.Errorf("--reason is required when rejecting a package")
		}

		ui.Step("Rejecting %s@%s...", name, version)
		_, err = adminPOST(client, "/api/v1/admin/reject", map[string]string{
			"name":    name,
			"version": version,
			"reason":  reason,
		})
		if err != nil {
			return fmt.Errorf("reject failed: %w", err)
		}

		ui.Success("Rejected %s@%s with feedback.", name, version)
		return nil
	},
}

// --- admin release ---

var adminReleaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Trigger a batch release of all accepted staging packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		confirmed, err := ui.Confirm("Release all accepted staging packages to stable?", false)
		if err != nil || !confirmed {
			ui.Info("Aborted.")
			return nil
		}

		ui.Step("Triggering batch release...")
		body, err := adminPOST(client, "/api/v1/admin/release", nil)
		if err != nil {
			return fmt.Errorf("release failed: %w", err)
		}

		var resp struct {
			Released int `json:"released"`
		}
		json.Unmarshal(body, &resp)

		ui.Success("Released %d package(s) to stable.", resp.Released)
		return nil
	},
}

// --- Admin HTTP Helpers ---

func adminGET(client *apiclient.Client, path string) ([]byte, error) {
	ctx := cmd_defaultCtx()
	url := client.BaseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+client.Token)
	req.Header.Set("User-Agent", "Toob-CLI")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAdminError(resp)
	}
	return io.ReadAll(resp.Body)
}

func adminPOST(client *apiclient.Client, path string, payload any) ([]byte, error) {
	ctx := cmd_defaultCtx()
	url := client.BaseURL + path

	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+client.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Toob-CLI")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readAdminError(resp)
	}
	return io.ReadAll(resp.Body)
}

func readAdminError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}

// --- admin status ---

var adminStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the staging and compile validation status dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		body, err := adminGET(client, "/api/v1/admin/status")
		if err != nil {
			return fmt.Errorf("failed to fetch dashboard status: %w", err)
		}

		var resp struct {
			StagingPackages []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Version   string `json:"version"`
				Category  string `json:"category"`
				Publisher string `json:"publisher"`
				CreatedAt string `json:"created_at"`
			} `json:"staging_packages"`
			PendingPRs []struct {
				ID        int64  `json:"id"`
				PRNumber  int    `json:"pr_number"`
				Repo      string `json:"repo"`
				HeadSHA   string `json:"head_sha"`
				Status    string `json:"status"`
				CreatedAt string `json:"created_at"`
			} `json:"pending_prs"`
			ValidationJobsStats struct {
				Queued      int     `json:"queued"`
				Running     int     `json:"running"`
				Passed      int     `json:"passed"`
				Failed      int     `json:"failed"`
				Total       int     `json:"total"`
				FailureRate float64 `json:"failure_rate"`
			} `json:"validation_jobs_stats"`
			PublishJobsStats struct {
				Queued      int     `json:"queued"`
				Running     int     `json:"running"`
				Passed      int     `json:"passed"`
				Failed      int     `json:"failed"`
				Total       int     `json:"total"`
				FailureRate float64 `json:"failure_rate"`
			} `json:"publish_jobs_stats"`
		}

		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to parse dashboard status: %w", err)
		}

		ui.Header("Staging & Compile Validation Dashboard")

		// 1. Publish Jobs Stats
		ui.Step("Publish Jobs (dev -> testing)")
		ui.KeyValue("Queued/Running", fmt.Sprintf("%d / %d", resp.PublishJobsStats.Queued, resp.PublishJobsStats.Running))
		ui.KeyValue("Passed/Failed", fmt.Sprintf("%d / %d", resp.PublishJobsStats.Passed, resp.PublishJobsStats.Failed))
		ui.KeyValue("Failure Rate", fmt.Sprintf("%.1f%%", resp.PublishJobsStats.FailureRate*100))

		// 2. PR Validation Jobs Stats
		ui.Step("VCS PR Validation Jobs (community)")
		ui.KeyValue("Queued/Running", fmt.Sprintf("%d / %d", resp.ValidationJobsStats.Queued, resp.ValidationJobsStats.Running))
		ui.KeyValue("Passed/Failed", fmt.Sprintf("%d / %d", resp.ValidationJobsStats.Passed, resp.ValidationJobsStats.Failed))
		ui.KeyValue("Failure Rate", fmt.Sprintf("%.1f%%", resp.ValidationJobsStats.FailureRate*100))

		// 3. Pending PRs Table
		ui.Step("Pending Pull Requests")
		if len(resp.PendingPRs) == 0 {
			ui.Muted("  No active PR jobs.")
		} else {
			headers := []string{"PR", "REPO", "HEAD SHA", "STATUS"}
			var rows [][]string
			for _, pr := range resp.PendingPRs {
				sha := pr.HeadSHA
				if len(sha) > 8 {
					sha = sha[:8]
				}
				rows = append(rows, []string{fmt.Sprintf("#%d", pr.PRNumber), pr.Repo, sha, pr.Status})
			}
			ui.Table(headers, rows)
		}

		// 4. Staging Packages Table
		ui.Step("Packages Awaiting Release Review (Staging)")
		if len(resp.StagingPackages) == 0 {
			ui.Muted("  No packages in staging.")
		} else {
			headers := []string{"ID", "NAME", "VERSION", "CATEGORY", "PUBLISHER"}
			var rows [][]string
			for _, p := range resp.StagingPackages {
				rows = append(rows, []string{p.ID[:8], p.Name, p.Version, p.Category, p.Publisher})
			}
			ui.Table(headers, rows)
		}

		return nil
	},
}

// --- admin mock-webhook ---

var adminMockWebhookCmd = &cobra.Command{
	Use:   "mock-webhook",
	Short: "Send a mock pull request webhook event to the registry",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()
		if !client.HasToken() {
			return fmt.Errorf("not logged in — run 'toob login' first")
		}

		action, _ := cmd.Flags().GetString("action")
		pr, _ := cmd.Flags().GetInt("pr")
		repo, _ := cmd.Flags().GetString("repo")
		sha, _ := cmd.Flags().GetString("sha")
		userId, _ := cmd.Flags().GetInt64("user-id")
		files, _ := cmd.Flags().GetStringSlice("files")

		if pr <= 0 {
			return fmt.Errorf("--pr is required and must be positive")
		}
		if sha == "" && action != "closed" {
			return fmt.Errorf("--sha is required unless action is closed")
		}

		payload := map[string]any{
			"action":         action,
			"pr_number":      pr,
			"repo":           repo,
			"head_sha":       sha,
			"github_user_id": userId,
			"files":          files,
		}

		ui.Step("Sending mock pull_request webhook (%s)...", action)
		body, err := adminPOST(client, "/api/v1/admin/mock-webhook", payload)
		if err != nil {
			return fmt.Errorf("mock webhook failed: %w", err)
		}

		var resp struct {
			Status string `json:"status"`
			Reason string `json:"reason,omitempty"`
			JobID  string `json:"job_id,omitempty"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			ui.Info("Response: %s", string(body))
			return nil
		}

		switch resp.Status {
		case "queued":
			ui.Success("Webhook processed: PR job enqueued with Job ID %s.", resp.JobID)
		case "rejected":
			ui.Warn("Webhook processed but REJECTED: %s", resp.Reason)
		default:
			ui.Success("Webhook processed: status=%s reason=%s", resp.Status, resp.Reason)
		}

		return nil
	},
}

func init() {
	adminRejectCmd.Flags().String("reason", "", "Reason for rejection (required)")

	adminMockWebhookCmd.Flags().String("action", "opened", "PR action (opened, synchronize, closed)")
	adminMockWebhookCmd.Flags().Int("pr", 0, "PR number")
	adminMockWebhookCmd.Flags().String("repo", "Toob-Boot/Toob-Loader", "Repository name")
	adminMockWebhookCmd.Flags().String("sha", "", "PR Head SHA")
	adminMockWebhookCmd.Flags().Int64("user-id", 1, "VCS Github User ID")
	adminMockWebhookCmd.Flags().StringSlice("files", []string{}, "Comma-separated list of modified files")

	adminCmd.AddCommand(adminStagingCmd)
	adminCmd.AddCommand(adminAcceptCmd)
	adminCmd.AddCommand(adminRejectCmd)
	adminCmd.AddCommand(adminReleaseCmd)
	adminCmd.AddCommand(adminStatusCmd)
	adminCmd.AddCommand(adminMockWebhookCmd)

	rootCmd.AddCommand(adminCmd)
}
