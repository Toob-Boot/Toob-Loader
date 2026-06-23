package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/ui"
	"github.com/toob-boot/toob/internal/updater"
	"golang.org/x/mod/semver"
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
			fmt.Fprintf(os.Stderr, "\r  %s Downloading: %d%% (%.2f MB / %.2f MB)",
				ui.Brand("▸"), pct, float64(pr.current)/1024/1024, float64(pr.total)/1024/1024)
			pr.lastPct = pct
		}
	}
	return
}

func fetchSignature(url string, insecure bool) (string, error) {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
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
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("toob executable not found in zip archive")
	} else if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".tgz") {
		gr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		tr := tar.NewReader(gr)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if hdr.Name == "toob" || hdr.Name == "toob.exe" {
				return io.ReadAll(tr)
			}
		}
		return nil, fmt.Errorf("toob executable not found in tar.gz archive")
	}
	return archiveBytes, nil
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Toob CLI to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		var res *updater.CheckResult
		var err error

		if targetVersion != "" {
			ui.Step("Fetching specific release: %s", targetVersion)
			res, err = updater.FetchReleaseByTag(targetVersion, insecure)
		} else {
			ui.Step("Checking for updates (current: %s)", ui.Bold(Version))
			res, err = updater.CheckForUpdate(Version, true, insecure)
		}

		if err != nil {
			if err == updater.ErrUnsupportedArch {
				return fmt.Errorf("an update exists on Registry, but no compiled binary was found for your architecture (%s)", err.Error())
			}
			return fmt.Errorf("failed to check for updates: %w", err)
		}

		if !res.Available {
			ui.Success("Already on the target version!")
			return nil
		}

		ui.Step("Downloading %s ...", ui.Bold(res.Version))

		transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
		if insecure {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client := &http.Client{Transport: transport}

		resp, err := client.Get(res.DownloadURL)
		if err != nil {
			return fmt.Errorf("failed to download update: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
		}

		pr := &progressReader{
			Reader: resp.Body,
			total:  resp.ContentLength,
		}

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, pr); err != nil {
			return fmt.Errorf("\nfailed during download: %w", err)
		}
		fmt.Fprintln(os.Stderr)

		if res.SigURL != "" {
			ui.Step("Verifying Ed25519 signature (Supply Chain Security)")
			sigStr, err := fetchSignature(res.SigURL, insecure)
			if err != nil {
				return fmt.Errorf("failed to fetch release signature: %w", err)
			}

			pubKey, err := updater.GetUpdatePublicKey()
			if err != nil {
				return fmt.Errorf("FATAL: Hardcoded public key is corrupted: %w", err)
			}

			sigBytes, err := hex.DecodeString(strings.TrimSpace(sigStr))
			if err != nil {
				return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: Signature hex decoding failed: %w", err)
			}

			hash := sha256.Sum256(buf.Bytes())
			if !ed25519.Verify(pubKey, hash[:], sigBytes) {
				return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: Ed25519 signature invalid or binary was tampered with!")
			}
			ui.Success("Signature OK. Binary is authentic.")
		} else {
			return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: No signature found in release. Downgrade attack prevented.")
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
