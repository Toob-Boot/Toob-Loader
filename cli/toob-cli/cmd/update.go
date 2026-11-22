package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
	"golang.org/x/mod/semver"
)

const (
	maxSignatureBytes     = 64 << 10  // 64 KiB
	maxUpdateArchiveBytes = 256 << 20 // 256 MiB
)

var (
	targetVersion string
	insecure      bool
)

type progressReader struct {
	io.Reader
	total   int64
	current int64
	lastPct int
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.Reader.Read(p)
	pr.current += int64(n)
	if pr.total > 0 {
		pct := int(float64(pr.current) / float64(pr.total) * 100)
		if pct != pr.lastPct && pct%5 == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "\r  %s Downloading: %d%% (%.2f MB / %.2f MB)",
				ui.Brand("▸"), pct, float64(pr.current)/1024/1024, float64(pr.total)/1024/1024)
			pr.lastPct = pct
		}
	}
	return
}

func fetchSignature(sigURL string, insecureTLS bool) (string, error) {
	if insecureTLS {
		return "", updater.ErrInsecureTLS
	}
	client := &http.Client{
		Transport:     apiclient.BuildTransport(),
		CheckRedirect: apiclient.SafeCheckRedirect,
	}

	resp, err := client.Get(sigURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSignatureBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxSignatureBytes {
		return "", fmt.Errorf("signature response exceeds %d bytes", maxSignatureBytes)
	}
	return string(body), nil
}

func readBoundedExecutable(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxUpdateArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxUpdateArchiveBytes {
		return nil, fmt.Errorf("extracted update binary exceeds %d bytes", maxUpdateArchiveBytes)
	}
	return out, nil
}

func decompressArchive(archiveBytes []byte, filename string) ([]byte, error) {
	if strings.HasSuffix(filename, ".zip") {
		r, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if err != nil {
			return nil, err
		}
		for _, f := range r.File {
			if f.Name == "toob" || f.Name == "toob.exe" {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				data, readErr := readBoundedExecutable(rc)
				closeErr := rc.Close()
				if readErr != nil {
					return nil, readErr
				}
				if closeErr != nil {
					return nil, closeErr
				}
				return data, nil
			}
		}
		return nil, fmt.Errorf("toob executable not found in zip archive")
	} else if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
		if err != nil {
			return nil, err
		}
		defer func() { _ = gr.Close() }()
		tr := tar.NewReader(gr)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if hdr.Name == "toob" || hdr.Name == "toob.exe" {
				return readBoundedExecutable(tr)
			}
		}
		return nil, fmt.Errorf("toob executable not found in tar.gz archive")
	}
	return archiveBytes, nil
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Toob CLI to the latest version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if insecure {
			return updater.ErrInsecureTLS
		}

		var res *updater.CheckResult
		var err error

		if targetVersion != "" {
			ui.Step("Fetching specific release: %s", targetVersion)
			res, err = updater.FetchReleaseByTag(targetVersion, false)
		} else {
			ui.Step("Checking for updates (current: %s)", ui.Bold(Version))
			res, err = updater.CheckForUpdate(Version, true, false)
		}

		if err != nil {
			if errors.Is(err, updater.ErrUnsupportedArch) {
				return fmt.Errorf("an update exists on Registry, but no compiled binary was found for your architecture (%s)", err.Error())
			}
			return fmt.Errorf("failed to check for updates: %w", err)
		}

		if !res.Available {
			ui.Success("Already on the target version!")
			return nil
		}

		ui.Step("Downloading %s ...", ui.Bold(res.Version))

		client := &http.Client{
			Transport:     apiclient.BuildTransport(),
			CheckRedirect: apiclient.SafeCheckRedirect,
		}

		resp, err := client.Get(res.DownloadURL)
		if err != nil {
			return fmt.Errorf("failed to download update: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
		}

		pr := &progressReader{
			Reader: io.LimitReader(resp.Body, maxUpdateArchiveBytes+1),
			total:  resp.ContentLength,
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, pr); err != nil {
			return fmt.Errorf("failed during download: %w", err)
		}
		_, _ = fmt.Fprintln(os.Stderr)
		if buf.Len() > maxUpdateArchiveBytes {
			return fmt.Errorf("update archive exceeds %d bytes", maxUpdateArchiveBytes)
		}

		if res.SigURL != "" {
			ui.Step("Verifying Ed25519 signature (Supply Chain Security)")
			sigStr, err := fetchSignature(res.SigURL, false)
			if err != nil {
				return fmt.Errorf("failed to fetch release signature: %w", err)
			}

			pubKey, err := updater.GetUpdatePublicKey()
			if err != nil {
				return fmt.Errorf("FATAL: hardcoded public key is invalid: %w", err)
			}

			sigBytes, err := hex.DecodeString(strings.TrimSpace(sigStr))
			if err != nil {
				return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: signature hex decoding failed: %w", err)
			}

			hash := sha256.Sum256(buf.Bytes())
			if !ed25519.Verify(pubKey, hash[:], sigBytes) {
				return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: Ed25519 signature invalid or binary was tampered with")
			}
			ui.Success("Signature OK. Binary is authentic.")
		} else {
			return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: no signature found in release; downgrade attack prevented")
		}

		// Downgrade guard: reject signed-but-older binaries unless user explicitly
		// requested a specific version with --version (intentional rollback).
		if targetVersion == "" {
			releaseVer := res.Version
			currentVer := Version
			if !strings.HasPrefix(releaseVer, "v") {
				releaseVer = "v" + releaseVer
			}
			if !strings.HasPrefix(currentVer, "v") {
				currentVer = "v" + currentVer
			}
			if semver.IsValid(releaseVer) && semver.IsValid(currentVer) {
				if semver.Compare(releaseVer, currentVer) < 0 {
					return fmt.Errorf("FATAL [DOWNGRADE_BLOCKED]: Server offered v%s but current is v%s. Possible supply-chain attack", releaseVer, currentVer)
				}
			}
		}

		ui.Step("Decompressing update archive...")
		filename := filepath.Base(res.DownloadURL)
		decompressedBytes, err := decompressArchive(buf.Bytes(), filename)
		if err != nil {
			return fmt.Errorf("failed to decompress update: %w", err)
		}

		ui.Step("Applying update...")
		err = selfupdate.Apply(bytes.NewReader(decompressedBytes), selfupdate.Options{})
		if err != nil {
			return fmt.Errorf("failed to apply update: %w", err)
		}

		ui.Success("Updated to %s!", ui.Bold(res.Version))
		return nil
	},
}

func init() {
	updateCmd.Flags().StringVar(&targetVersion, "version", "", "Target a specific release version (e.g. v1.0.0) to rollback or upgrade")
	updateCmd.Flags().BoolVar(&insecure, "insecure", false, "Bypass TLS proxy verification (for strict corporate networks)")
	rootCmd.AddCommand(updateCmd)
}
