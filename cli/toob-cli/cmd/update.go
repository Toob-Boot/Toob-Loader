package cmd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/minio/selfupdate"
	"github.com/spf13/cobra"
	"aead.dev/minisign"
	"github.com/toob-boot/toob/internal/updater"
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
			fmt.Printf("\r[toob] Downloading update: %d%% (%.2f MB / %.2f MB)", pct, float64(pr.current)/1024/1024, float64(pr.total)/1024/1024)
			pr.lastPct = pct
		}
	}
	return
}

func fetchMinisig(url string, insecure bool) (string, error) {
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

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Toob CLI to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		var res *updater.CheckResult
		var err error

		if targetVersion != "" {
			fmt.Printf("[toob] Fetching specific release: %s...\n", targetVersion)
			res, err = updater.FetchReleaseByTag(targetVersion, insecure)
		} else {
			fmt.Printf("[toob] Checking for updates (current version: %s)...\n", Version)
			res, err = updater.CheckForUpdate(Version, true, insecure)
		}

		if err != nil {
			if err == updater.ErrUnsupportedArch {
				return fmt.Errorf("an update exists on GitHub, but no compiled binary was found for your architecture (%s)", err.Error())
			}
			return fmt.Errorf("failed to check for updates: %w", err)
		}

		if !res.Available {
			fmt.Println("[toob] You are already on the target version!")
			return nil
		}

		fmt.Printf("[toob] Downloading update %s ...\n", res.Version)
		
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
		fmt.Println()

		if res.MinisigURL != "" {
			fmt.Println("[toob] Verifying Minisign signature (Supply Chain Security)...")
			sigStr, err := fetchMinisig(res.MinisigURL, insecure)
			if err != nil {
				return fmt.Errorf("failed to fetch minisign signature: %w", err)
			}
			
			pubKey, err := updater.GetPublicKey()
			if err != nil {
				return fmt.Errorf("FATAL: Hardcoded public key is corrupted: %w", err)
			}
			
			if !minisign.Verify(pubKey, buf.Bytes(), []byte(sigStr)) {
				return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: Minisign signature invalid or binary was tampered with!")
			}
			fmt.Println("[toob] Signature OK. Binary is authentic.")
		} else {
			return fmt.Errorf("FATAL [INTEGRITY_COMPROMISED]: No .minisig signature found in release. Downgrade attack prevented.")
		}

		fmt.Println("[toob] Applying update...")
		err = selfupdate.Apply(bytes.NewReader(buf.Bytes()), selfupdate.Options{})
		if err != nil {
			return fmt.Errorf("failed to apply update: %w", err)
		}

		fmt.Printf("[toob] Successfully updated to %s!\n", res.Version)
		return nil
	},
}

func init() {
	updateCmd.Flags().StringVar(&targetVersion, "version", "", "Target a specific release version (e.g. v1.0.0) to rollback or upgrade")
	updateCmd.Flags().BoolVar(&insecure, "insecure", false, "Bypass TLS proxy verification (for strict corporate networks)")
	rootCmd.AddCommand(updateCmd)
}
