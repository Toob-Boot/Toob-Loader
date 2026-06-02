package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/toob-boot/toob/internal/apiclient"
	"github.com/toob-boot/toob/internal/ui"
)

//go:embed assets/success.html
var successAssets embed.FS

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Toob Registry via GitHub",
	Long: `Authenticates your CLI with the Toob Registry API using GitHub OAuth.

After authentication, your API key is stored in ~/.toob/credentials.json
and automatically used for package publishing and download tracking.

Use --rotate to invalidate your current key and generate a new one.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := apiclient.New()

		rotate, _ := cmd.Flags().GetBool("rotate")
		force, _ := cmd.Flags().GetBool("force")
		noBrowser, _ := cmd.Flags().GetBool("no-browser")

		if client.HasToken() && !force && !rotate {
			ui.Info("Already authenticated. Use --force to re-authenticate or --rotate to get a new key.")
			return nil
		}

		ui.Header("GitHub Authentication")

		// Generate PKCE credentials and state
		verifier, challenge, err := generatePKCE()
		if err != nil {
			return fmt.Errorf("failed to generate PKCE credentials: %w", err)
		}

		state, err := generateState()
		if err != nil {
			return fmt.Errorf("failed to generate security state: %w", err)
		}

		var code string
		var useLocalServer bool

		// Start local server to receive loopback callback
		if !noBrowser {
			srvCtx, srvCancel := context.WithTimeout(cmd_defaultCtx(), 5*time.Minute)
			defer srvCancel()

			listener, port, codeChan, errChan := startLocalServer(srvCtx, state)
			if listener != nil {
				defer listener.Close()
				useLocalServer = true

				authURL := fmt.Sprintf("%s/api/v1/auth/github?state=%s&code_challenge=%s&redirect_uri=http://127.0.0.1:%d/callback", client.BaseURL, state, challenge, port)
				if rotate {
					authURL += "&rotate=true"
				}

				ui.Step("Opening your browser to authenticate...")
				ui.KeyValue("URL", ui.Bold(authURL))

				if err := openBrowser(authURL); err != nil {
					ui.Warn("Failed to open browser automatically: %v", err)
					ui.Step("Please visit the URL manually to complete login.")
				}

				// Wait for code or server error/timeout
				select {
				case c := <-codeChan:
					code = c
				case err := <-errChan:
					ui.Warn("Local loopback server error: %v", err)
					useLocalServer = false
				case <-srvCtx.Done():
					ui.Warn("Authentication timed out waiting for browser callback.")
					useLocalServer = false
				}
			} else {
				ui.Warn("Could not start local callback server: %v", <-errChan)
			}
		}

		// Fallback to manual flow
		if !useLocalServer {
			authURL := fmt.Sprintf("%s/api/v1/auth/github?state=%s&code_challenge=%s&redirect_uri=urn:ietf:wg:oauth:2.0:oob", client.BaseURL, state, challenge)
			if rotate {
				authURL += "&rotate=true"
			}

			ui.Step("Please visit the following URL in your browser:")
			ui.KeyValue("URL", ui.Bold(authURL))
			ui.Divider()

			ui.Step("Enter the authorization code shown in your browser:")
			fmt.Scanln(&code)

			if code == "" {
				return fmt.Errorf("no authorization code provided")
			}
		}

		return handleTokenExchange(client, code, verifier, rotate)
	},
}

func handleTokenExchange(client *apiclient.Client, code, verifier string, rotate bool) error {
	loginResp, err := client.TokenExchange(cmd_defaultCtx(), code, verifier)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if loginResp.APIKey != "" {
		if err := apiclient.SaveCredentials(loginResp.APIKey, loginResp.Login); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}
		if rotate {
			ui.Success("API key rotated for @%s", loginResp.Login)
			ui.Tip("Your new key has been stored. The old key is now invalid.")
		} else {
			ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
			ui.Tip("Your API key has been stored in ~/.toob/credentials.json")
		}
	} else if loginResp.HasAPIKey {
		ui.Success("Authenticated as @%s (Role: %s)", loginResp.Login, loginResp.Role)
		ui.Info("You already have an API key. Use 'toob login --rotate' to generate a new one.")
	}

	return nil
}

func generatePKCE() (verifier string, challenge string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(bytes)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

func generateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

func startLocalServer(ctx context.Context, state string) (net.Listener, int, chan string, chan error) {
	// Buffered to prevent goroutine leaks if the calling select exits early
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	var listener net.Listener
	var err error
	var port int

	for p := 54321; p <= 54330; p++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			port = p
			break
		}
	}

	if listener == nil {
		errChan <- fmt.Errorf("no free ports in range 54321-54330: %w", err)
		return nil, 0, nil, errChan
	}

	mux := http.NewServeMux()
	server := &http.Server{
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    10 * time.Second,
		MaxHeaderBytes: 1 << 10, // Limit request header to 1KB (mitigates DoS)
	}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Enforce strict HTTP method and path
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("<h1>Error</h1><p>Method Not Allowed</p>"))
			return
		}

		if r.URL.Path != "/callback" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<h1>Error</h1><p>Not Found</p>"))
			return
		}

		// Enforce Host header validation (mitigates DNS rebinding attacks)
		host, portStr, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
			portStr = ""
		}

		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		if host != "127.0.0.1" && host != "localhost" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("<h1>Error</h1><p>Invalid Host Header</p>"))
			return
		}

		if portStr != "" && portStr != fmt.Sprintf("%d", port) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("<h1>Error</h1><p>Invalid Host Port</p>"))
			return
		}

		retState := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")

		if retState != state {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("<h1>Error</h1><p>CSRF State mismatch</p>"))
			return
		}

		if code == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("<h1>Error</h1><p>Missing auth code</p>"))
			return
		}

		htmlBytes, err := successAssets.ReadFile("assets/success.html")
		if err != nil {
			htmlBytes = []byte("<h1>Login Successful</h1><p>You can close this tab now.</p>")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(htmlBytes)

		select {
		case codeChan <- code:
		default:
		}

		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(context.Background())
		}()
	})

	// Background worker to gracefully shut down the server when command context terminates
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	return listener, port, codeChan, errChan
}

func init() {
	loginCmd.Flags().Bool("force", false, "Re-authenticate even if already logged in")
	loginCmd.Flags().Bool("rotate", false, "Generate a new API key, invalidating the old one")
	loginCmd.Flags().Bool("no-browser", false, "Do not attempt to open the browser automatically; fallback to manual code entry")
	rootCmd.AddCommand(loginCmd)
}
