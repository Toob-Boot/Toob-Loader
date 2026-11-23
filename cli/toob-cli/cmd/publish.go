package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/conformance"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/literallint"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/registry"
	"github.com/toob-boot/toob/internal/ui"
)

func newPublishCmd() *cobra.Command {
	var notes string

	c := &cobra.Command{
		Use:   "publish [package-dir]",
		Short: "Validate, package, and publish a Toob package to the registry",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("resolve package directory %q: %w", dir, err)
			}

			cat, tgzBytes, fileCount, err := buildAndValidatePackageTarball(absDir)
			if err != nil {
				return fmt.Errorf("package validation failed: %w", err)
			}

			report, err := conformance.AuditPackage(absDir)
			if err != nil {
				return fmt.Errorf("conformance audit failed: %w", err)
			}
			if !report.Passed {
				return fmt.Errorf("conformance audit failed with %d failed check(s)", countFailedConformanceChecks(report))
			}

			if isHALSourceCategory(cat) {
				lintReport, lintErr := literallint.RunLint(literallint.DefaultConfig(absDir))
				if lintErr != nil {
					return fmt.Errorf("literallint check failed: %w", lintErr)
				}
				if !lintReport.Passed || len(lintReport.Violations) > 0 {
					return fmt.Errorf("literallint rejected HAL package: %d violation(s)", len(lintReport.Violations))
				}
			}

			if depErr := checkManifestDependencies(absDir, cat); depErr != nil {
				return depErr
			}

			mpBody, contentType, err := buildPublishMultipart(absDir, cat, tgzBytes, notes)
			if err != nil {
				return fmt.Errorf("encode upload body: %w", err)
			}

			client := apiclient.New()
			var pubResp *apiclient.PublishResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var pubErr error
				pubResp, pubErr = client.Publish(ctx, bytes.NewReader(mpBody), contentType)
				return pubErr
			}); err != nil {
				return fmt.Errorf("publish package: %w", err)
			}

			ui.Success("Published %s@%s (%s: %d files, %d bytes) [id=%s stage=%s]",
				sanitizeDisplay(pubResp.Name),
				sanitizeDisplay(pubResp.Version),
				cat,
				fileCount,
				len(tgzBytes),
				shortID(sanitizeDisplay(pubResp.ID), 12),
				sanitizeDisplay(pubResp.Stage))
			for _, w := range pubResp.IngestionWarnings {
				ui.Warn("Ingestion notice: %s", sanitizeDisplay(w))
			}
			return nil
		},
	}

	c.Flags().StringVar(&notes, "notes", "", "Optional release notes")

	c.AddCommand(
		newPublishStatusCmd(),
		newPublishSearchCmd(),
		newPublishPromoteCmd(),
		newPublishUnpublishCmd(),
	)
	return c
}

func buildPublishMultipart(absDir, cat string, tgzBytes []byte, notes string) ([]byte, string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	part, err := mw.CreateFormFile("tarball", filepath.Base(absDir)+".tar.gz")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(tgzBytes); err != nil {
		return nil, "", err
	}
	if cat != "" {
		if err := mw.WriteField("category", cat); err != nil {
			return nil, "", err
		}
	}
	if strings.TrimSpace(notes) != "" {
		if err := mw.WriteField("notes", notes); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), mw.FormDataContentType(), nil
}

func isHALSourceCategory(cat string) bool {
	switch cat {
	case "chip", "arch", "driver", "crypto":
		return true
	default:
		return false
	}
}

func checkManifestDependencies(pkgDir, cat string) error {
	raw, err := os.ReadFile(filepath.Join(pkgDir, cat+".toml"))
	if err != nil {
		return fmt.Errorf("read %s.toml: %w", cat, err)
	}

	var parsed struct {
		Arch         string            `toml:"arch"`
		Chip         string            `toml:"chip"`
		Drivers      []string          `toml:"drivers"`
		Crypto       []string          `toml:"crypto"`
		Dependencies map[string]string `toml:"dependencies"`
	}
	if decErr := toml.Unmarshal(raw, &parsed); decErr != nil {
		return fmt.Errorf("parse %s.toml dependencies: %w", cat, decErr)
	}

	cache, err := registry.OpenForProject(pkgDir, paths.IsDevMode())
	if err != nil {
		return fmt.Errorf("open registry for dependency check: %w", err)
	}
	if !cache.IsInitialized() {
		return nil
	}
	idx, err := cache.LoadIndex()
	if err != nil {
		return fmt.Errorf("load registry index for dependency check: %w", err)
	}
	if idx == nil {
		return nil
	}

	var refs []struct {
		cat string
		ref string
	}
	if parsed.Arch != "" {
		refs = append(refs, struct{ cat, ref string }{"arch", parsed.Arch})
	}
	if parsed.Chip != "" {
		refs = append(refs, struct{ cat, ref string }{"chip", parsed.Chip})
	}
	for _, d := range parsed.Drivers {
		refs = append(refs, struct{ cat, ref string }{"driver", d})
	}
	for _, cr := range parsed.Crypto {
		refs = append(refs, struct{ cat, ref string }{"crypto", cr})
	}
	for depName, depVer := range parsed.Dependencies {
		full := depName
		if depVer != "" && depVer != "*" {
			full = depName + "@" + depVer
		}
		refs = append(refs, struct{ cat, ref string }{"driver", full})
	}

	for _, item := range refs {
		name, _, parseErr := installer.ParsePackageRef(item.ref)
		if parseErr != nil {
			return fmt.Errorf("invalid manifest dependency reference %q: %w", item.ref, parseErr)
		}
		if _, found := findIndexEntry(idx, item.cat, name); !found {
			ui.Warn("Dependency %s/%s not present in synchronized local index", item.cat, sanitizeDisplay(name))
		}
	}
	return nil
}

func newPublishStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <job-id>",
		Short: "Check the ingestion status of a package validation job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
			if err != nil || jobID <= 0 {
				return fmt.Errorf("invalid job ID %q: expected positive integer", args[0])
			}

			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			job, err := client.GetPublishJob(ctx, jobID)
			if err != nil {
				return fmt.Errorf("get publish job %d: %w", jobID, err)
			}

			printPublishJob(job)
			return nil
		},
	}
}

func printPublishJob(job *apiclient.PublishJob) {
	if job == nil {
		return
	}
	ui.Info("Job %d: status=%s package=%s@%s",
		job.ID,
		sanitizeDisplay(job.Status),
		sanitizeDisplay(job.PackageName),
		sanitizeDisplay(job.PackageVersion))
	if job.ErrorSummary != nil && *job.ErrorSummary != "" {
		ui.Warn("Summary: %s", sanitizeDisplay(*job.ErrorSummary))
	}
	if job.ErrorMessage != nil && *job.ErrorMessage != "" {
		ui.Warn("Error:   %s", sanitizeDisplay(*job.ErrorMessage))
	}
}

func newPublishSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search published packages in the remote Toob Registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := commandContext(cmd, defaultCmdTimeout)
			defer cancel()

			client := apiclient.New()
			resp, err := client.Search(ctx, args[0])
			if err != nil {
				return fmt.Errorf("search registry: %w", err)
			}

			if resp == nil || len(resp.Results) == 0 {
				ui.Info("No matching packages found.")
				return nil
			}

			for _, p := range resp.Results {
				ui.Info("%-12s %-28s %-12s %-16s %s",
					sanitizeDisplay(p.Category),
					sanitizeDisplay(p.Name),
					sanitizeDisplay(p.Version),
					sanitizeDisplay(p.Author),
					truncateRunes(p.Description, 47))
			}
			return nil
		},
	}
}

func newPublishPromoteCmd() *cobra.Command {
	var wait bool

	c := &cobra.Command{
		Use:   "promote <pkg>@<version>",
		Short: "Promote a dev-stage package version into Firecracker staging validation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, ver, err := installer.ParsePackageRef(args[0])
			if err != nil {
				return err
			}
			if ver == "" {
				return errors.New("version is required (<pkg>@<version>)")
			}

			client := apiclient.New()
			var promResp *apiclient.PromoteResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var promErr error
				promResp, promErr = client.Promote(ctx, name, ver)
				return promErr
			}); err != nil {
				return fmt.Errorf("promote package: %w", err)
			}

			ui.Success("Submitted %s@%s for promotion (job=%d, status=%s)",
				sanitizeDisplay(name), sanitizeDisplay(ver), promResp.JobID, sanitizeDisplay(promResp.Status))

			if wait && promResp.JobID > 0 {
				waitCtx, waitCancel := commandContext(cmd, 5*defaultCmdTimeout)
				defer waitCancel()
				finalJob, streamErr := client.StreamPublishJob(waitCtx, promResp.JobID, func(j *apiclient.PublishJob) error {
					ui.Step("Job %d: %s", j.ID, sanitizeDisplay(j.Status))
					return nil
				})
				if streamErr != nil {
					return fmt.Errorf("stream validation job %d: %w", promResp.JobID, streamErr)
				}
				printPublishJob(finalJob)
				if finalJob != nil && strings.EqualFold(finalJob.Status, "failed") {
					return fmt.Errorf("promotion validation job %d failed", finalJob.ID)
				}
			}
			return nil
		},
	}

	c.Flags().BoolVar(&wait, "wait", false, "Wait for Firecracker validation job completion via SSE stream")
	return c
}

func newPublishUnpublishCmd() *cobra.Command {
	var yes bool

	c := &cobra.Command{
		Use:   "unpublish <pkg>@<version>",
		Short: "Unpublish (yank) a dev-stage package version from the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, ver, err := installer.ParsePackageRef(args[0])
			if err != nil {
				return err
			}
			if ver == "" {
				return errors.New("version is required (<pkg>@<version>)")
			}

			if err := confirmIrreversible(yes, fmt.Sprintf("Unpublish %s@%s from the registry?", name, ver)); err != nil {
				return err
			}

			client := apiclient.New()
			var res *apiclient.UnpublishResponse
			if err := withStepUp(cmd, client, func(ctx context.Context) error {
				var unpubErr error
				res, unpubErr = client.Unpublish(ctx, name, ver)
				return unpubErr
			}); err != nil {
				return fmt.Errorf("unpublish package: %w", err)
			}

			ui.Success("Unpublished %s@%s (status=%s)", sanitizeDisplay(res.Name), sanitizeDisplay(res.Version), sanitizeDisplay(res.Status))
			return nil
		},
	}

	c.Flags().BoolVarP(&yes, "yes", "y", false, "Confirm without interactive prompt")
	return c
}
