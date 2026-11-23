package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"

	"github.com/toob-boot/toob/internal/httputil"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
)

const (
	maxUpdateArchiveBytes = 64 << 20
	maxUpdateSigBytes     = 64 << 10
)

func newUpdateCmd() *cobra.Command {
	var (
		checkOnly     bool
		targetVersion string
		yes           bool
	)

	c := &cobra.Command{
		Use:   "update",
		Short: "Check for and install Ed25519-verified Toob CLI updates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, 2*defaultCmdTimeout)
			defer cancel()

			if Version == "dev" && strings.TrimSpace(targetVersion) == "" {
				return fmt.Errorf("development builds (%s) do not auto-update; pass --version <tag> to install a signed release", Version)
			}

			var rel *updater.CheckResult
			var err error
			if strings.TrimSpace(targetVersion) != "" {
				rel, err = updater.FetchReleaseByTag(targetVersion, false)
			} else {
				rel, err = updater.CheckForUpdate(Version, true, false)
				if err == nil && rel != nil && !rel.Available && !checkOnly {
					ui.Success("toob %s is already up to date.", Version)
					return nil
				}
			}
			if err != nil {
				return fmt.Errorf("check for CLI update: %w", err)
			}
			if rel == nil || !rel.Available {
				ui.Info("No newer CLI release found.")
				return nil
			}

			ui.Info("Latest release: %s (current: %s)", sanitizeDisplay(rel.Version), Version)
			if checkOnly {
				return nil
			}

			if err := confirmIrreversible(yes, fmt.Sprintf("Download and replace toob binary with %s?", rel.Version)); err != nil {
				return err
			}

			return downloadVerifyAndApplyUpdate(ctx, rel)
		},
	}

	c.Flags().BoolVar(&checkOnly, "check", false, "Only check for available updates without installing")
	c.Flags().StringVar(&targetVersion, "version", "", "Install a specific signed CLI release version/tag")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "Apply update without interactive confirmation")
	return c
}

func downloadVerifyAndApplyUpdate(ctx context.Context, rel *updater.CheckResult) error {
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(rel.DownloadURL); err != nil {
		return fmt.Errorf("unsafe release download URL: %w", err)
	}
	if _, err := httputil.ValidateHTTPSOrLoopbackURL(rel.SigURL); err != nil {
		return fmt.Errorf("unsafe signature URL: %w", err)
	}

	httpClient, err := httputil.NewClient(defaultCmdTimeout)
	if err != nil {
		return fmt.Errorf("initialize HTTP client: %w", err)
	}

	sigBytes, err := fetchUpdateAsset(ctx, httpClient, rel.SigURL, maxUpdateSigBytes)
	if err != nil {
		return fmt.Errorf("download release signature: %w", err)
	}
	archiveBytes, err := fetchUpdateAsset(ctx, httpClient, rel.DownloadURL, maxUpdateArchiveBytes)
	if err != nil {
		return fmt.Errorf("download release archive: %w", err)
	}

	if _, keyErr := updater.GetUpdatePublicKey(); keyErr != nil {
		return fmt.Errorf("load update public key: %w", keyErr)
	}

	rawSig := strings.TrimSpace(string(sigBytes))
	digest := sha256.Sum256(archiveBytes)
	if sigErr := updater.VerifyHashSignature(digest[:], rawSig); sigErr != nil {
		if rawErr := updater.VerifySignature(archiveBytes, rawSig); rawErr != nil {
			return fmt.Errorf("Ed25519 signature verification failed: %w", sigErr)
		}
	}

	binBytes, err := extractVerifiedBinary(rel.DownloadURL, archiveBytes)
	if err != nil {
		return fmt.Errorf("extract update binary: %w", err)
	}

	if err := selfupdate.Apply(bytes.NewReader(binBytes), selfupdate.Options{}); err != nil {
		return fmt.Errorf("apply binary update: %w", err)
	}

	ui.Success("Updated toob to %s", sanitizeDisplay(rel.Version))
	return nil
}

func fetchUpdateAsset(ctx context.Context, client *http.Client, urlStr string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if warn := resp.Header.Get("X-Toob-Warning"); warn != "" {
		ui.Warn("Registry update notice: %s", sanitizeDisplay(warn))
	}

	data, readErr := httputil.ReadBounded(resp.Body, limit)
	if resp.StatusCode == http.StatusGone {
		return nil, fmt.Errorf("release endpoint returned 410 Gone (version revoked/recalled): %s", sanitizeDisplay(string(data)))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, sanitizeDisplay(urlStr), sanitizeDisplay(string(data)))
	}
	if readErr != nil {
		return nil, readErr
	}
	return data, nil
}

func extractVerifiedBinary(downloadURL string, archive []byte) ([]byte, error) {
	lower := strings.ToLower(downloadURL)
	targetName := "toob"
	if runtime.GOOS == "windows" {
		targetName = "toob.exe"
	}

	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractTarGzBinary(archive, targetName)
	case strings.HasSuffix(lower, ".zip"):
		return extractZipBinary(archive, targetName)
	default:
		return nil, fmt.Errorf("unsupported update archive format in %q (only .tar.gz, .tgz, or .zip accepted)", downloadURL)
	}
}

func extractTarGzBinary(archive []byte, targetName string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(io.LimitReader(gzr, maxUpdateArchiveBytes))
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if strings.EqualFold(baseName(hdr.Name), targetName) {
			return io.ReadAll(io.LimitReader(tr, maxUpdateArchiveBytes))
		}
	}
	return nil, fmt.Errorf("binary %q not found in tar.gz archive", targetName)
}

func extractZipBinary(archive []byte, targetName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if !f.Mode().IsRegular() {
			continue
		}
		if strings.EqualFold(baseName(f.Name), targetName) {
			rc, openErr := f.Open()
			if openErr != nil {
				return nil, openErr
			}
			data, readErr := io.ReadAll(io.LimitReader(rc, maxUpdateArchiveBytes))
			_ = rc.Close()
			if readErr != nil {
				return nil, readErr
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("binary %q not found in zip archive", targetName)
}

func baseName(p string) string {
	idx := strings.LastIndexAny(p, "/\\")
	if idx >= 0 {
		return p[idx+1:]
	}
	return p
}
