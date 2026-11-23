package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/installer"
	"github.com/toob-boot/toob/internal/lockfile"
	"github.com/toob-boot/toob/internal/paths"
	"github.com/toob-boot/toob/internal/ui"
)

type auditFinding struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

func newAuditCmd() *cobra.Command {
	var (
		lockPath string
		strict   bool
		jsonOut  bool
	)

	c := &cobra.Command{
		Use:   "audit",
		Short: "Audit locked project dependencies and toolchains against the registry for revocations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, 2*defaultCmdTimeout)
			defer cancel()

			if lockPath == "" {
				root, err := paths.FindProjectRootStrict(".")
				if err != nil {
					return fmt.Errorf("find project root: %w", err)
				}
				lockPath = paths.LockfilePath(root)
			}

			lf, err := lockfile.Load(filepath.Clean(lockPath))
			if err != nil {
				return fmt.Errorf("load lockfile %s: %w", lockPath, err)
			}
			if valErr := lf.Validate(); valErr != nil {
				return fmt.Errorf("invalid lockfile %s: %w", lockPath, valErr)
			}

			entries := collectAuditEntries(lf)
			if len(entries) == 0 {
				ui.Info("Lockfile contains no external packages to audit.")
				return nil
			}

			client := apiclient.New()
			findings := make([]auditFinding, 0, len(entries))
			issues := 0

			for _, entry := range entries {
				finding, failed := auditLockEntry(ctx, client, entry, strict)
				if failed {
					issues++
				}
				findings = append(findings, finding)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(map[string]any{
					"issues":   issues,
					"findings": findings,
				}); encErr != nil {
					return fmt.Errorf("encode audit report: %w", encErr)
				}
			} else {
				for _, f := range findings {
					ui.Info("[%s] %s/%s@%s %s",
						f.Status,
						sanitizeDisplay(f.Category),
						sanitizeDisplay(f.Name),
						sanitizeDisplay(f.Version),
						sanitizeDisplay(f.Detail))
				}
			}

			if issues > 0 {
				return fmt.Errorf("security audit failed: %d issue(s) detected across %d locked entries", issues, len(entries))
			}

			ui.Success("Security audit passed (%d locked package/toolchain entries verified).", len(entries))
			return nil
		},
	}

	c.Flags().StringVar(&lockPath, "lockfile", "", "Path to toob.lock")
	c.Flags().BoolVar(&strict, "strict", false, "Treat deprecated packages and warnings as audit failures")
	c.Flags().BoolVar(&jsonOut, "json", false, "Output audit results as JSON")
	return c
}

type auditTarget struct {
	category string
	name     string
	version  string
	sha256   string
}

func collectAuditEntries(lf *lockfile.Lockfile) []auditTarget {
	seen := make(map[string]struct{})
	versioned := make(map[string]string)
	var out []auditTarget

	add := func(cat, name, ver, sha string) {
		name = strings.TrimSpace(name)
		if name == "" || strings.EqualFold(name, "none") {
			return
		}
		key := cat + "\x00" + name + "\x00" + ver
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		if ver != "" {
			versioned[cat+"\x00"+name] = ver
		}
		out = append(out, auditTarget{
			category: cat,
			name:     name,
			version:  ver,
			sha256:   sha,
		})
	}

	addRef := func(cat, ref string) {
		if ref == "" || strings.EqualFold(ref, "none") {
			return
		}
		name, ver, err := installer.ParsePackageRef(ref)
		if err != nil {
			add(cat, ref, "", "")
			return
		}
		if ver == "" {
			if existingVer, ok := versioned[cat+"\x00"+name]; ok && existingVer != "" {
				return
			}
		}
		add(cat, name, ver, "")
	}

	for i := range lf.Packages {
		pkg := &lf.Packages[i]
		if pkg.Source == "spawned" || pkg.Source == "local" {
			continue
		}
		add(pkg.Category, pkg.Name, pkg.Version, pkg.SHA256)
	}

	tcKeys := make([]string, 0, len(lf.Toolchains))
	for k := range lf.Toolchains {
		tcKeys = append(tcKeys, k)
	}
	slices.Sort(tcKeys)
	for _, k := range tcKeys {
		tc := lf.Toolchains[k]
		add("toolchain", k, tc.Version, "")
	}

	targetKeys := make([]string, 0, len(lf.Targets))
	for k := range lf.Targets {
		targetKeys = append(targetKeys, k)
	}
	slices.Sort(targetKeys)
	for _, tk := range targetKeys {
		tgt := lf.Targets[tk]
		addRef("chip", tgt.Chip)
		addRef("arch", tgt.Arch)
		addRef("toolchain", tgt.Toolchain)
		addRef("soc", tgt.SoC)
		addRef("integration", tgt.Integration)
		for _, ref := range sortedMapValues(tgt.Drivers) {
			addRef("driver", ref)
		}
		for _, ref := range sortedMapValues(tgt.Crypto) {
			addRef("crypto", ref)
		}
		for _, ref := range sortedMapValues(tgt.RecoveryDrivers) {
			addRef("driver", ref)
		}
		for _, ref := range sortedMapValues(tgt.RecoveryCrypto) {
			addRef("crypto", ref)
		}
	}

	return out
}

func sortedMapValues(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	vals := make([]string, 0, len(keys))
	for _, k := range keys {
		vals = append(vals, m[k])
	}
	return vals
}

func auditLockEntry(ctx context.Context, client *apiclient.Client, entry auditTarget, strict bool) (auditFinding, bool) {
	pkg, err := client.GetPackage(ctx, entry.name, entry.version)
	if err != nil {
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusGone {
			return auditFinding{
				Category: entry.category,
				Name:     entry.name,
				Version:  entry.version,
				Status:   "REVOKED (410)",
				Detail:   "registry returned 410 Gone (package removed/revoked)",
			}, true
		}
		return auditFinding{
			Category: entry.category,
			Name:     entry.name,
			Version:  entry.version,
			Status:   "ERROR",
			Detail:   err.Error(),
		}, true
	}

	if strings.EqualFold(pkg.Stage, "revoked") {
		return auditFinding{
			Category: entry.category,
			Name:     entry.name,
			Version:  entry.version,
			Status:   "REVOKED",
			Detail:   "package stage is revoked",
		}, true
	}

	if entry.sha256 != "" && len(pkg.Manifest) > 0 {
		var mf struct {
			SHA256     string `json:"sha256"`
			TarballSHA string `json:"tarball_sha"`
		}
		if json.Unmarshal(pkg.Manifest, &mf) == nil {
			regSHA := mf.TarballSHA
			if regSHA == "" {
				regSHA = mf.SHA256
			}
			if regSHA != "" && !strings.EqualFold(entry.sha256, regSHA) {
				return auditFinding{
					Category: entry.category,
					Name:     entry.name,
					Version:  entry.version,
					Status:   "DIGEST MISMATCH",
					Detail:   fmt.Sprintf("lock=%s registry=%s", shortID(entry.sha256, 12), shortID(regSHA, 12)),
				}, true
			}
		}
	}

	if strings.EqualFold(pkg.Stage, "deprecated") {
		return auditFinding{
			Category: entry.category,
			Name:     entry.name,
			Version:  entry.version,
			Status:   "DEPRECATED",
			Detail:   "package marked deprecated upstream",
		}, strict
	}

	return auditFinding{
		Category: entry.category,
		Name:     entry.name,
		Version:  entry.version,
		Status:   "OK",
		Detail:   pkg.Stage,
	}, false
}
