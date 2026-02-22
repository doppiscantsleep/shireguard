package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
	"github.com/shireguard/shireguard/internal/daemon"
	"github.com/shireguard/shireguard/internal/wg"
)

var (
	cfg     *config.Config
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	root := &cobra.Command{
		Use:     "shireguard",
		Short:   "Shireguard — WireGuard P2P connectivity",
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
	}

	root.PersistentFlags().StringVar(&cfg.APIURL, "api-url", cfg.APIURL, "Control plane API URL")

	root.AddCommand(loginCmd(), registerDeviceCmd(), upCmd(), downCmd(), statusCmd(), devicesCmd(), logoutCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newClient() *api.Client {
	return api.New(cfg.APIURL, cfg.AccessToken, cfg.RefreshToken, func(access, refresh string) {
		cfg.AccessToken = access
		cfg.RefreshToken = refresh
		_ = cfg.Save()
	})
}

func loginCmd() *cobra.Command {
	var useApple, useGoogle, useGitHub bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in via Apple, Google, or GitHub (opens browser)",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case useGoogle:
				return loginWith("google", "Google")
			case useGitHub:
				return loginWith("github", "GitHub")
			default:
				return loginWith("apple", "Apple")
			}
		},
	}
	cmd.Flags().BoolVar(&useApple, "apple", false, "Sign in with Apple")
	cmd.Flags().BoolVar(&useGoogle, "google", false, "Sign in with Google")
	cmd.Flags().BoolVar(&useGitHub, "github", false, "Sign in with GitHub")
	return cmd
}

func loginWithApple() error { return loginWith("apple", "Apple") }

func loginWith(provider, label string) error {
	// Generate a random 16-byte session ID
	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return fmt.Errorf("generating session ID: %w", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	authURL := fmt.Sprintf("%s/v1/auth/%s?cli_session=%s", cfg.APIURL, provider, sessionID)

	fmt.Printf("Opening browser for %s Sign-In...\n", label)
	fmt.Printf("If your browser doesn't open automatically, visit:\n  %s\n\n", authURL)

	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", authURL).Start()
	case "linux":
		exec.Command("xdg-open", authURL).Start()
	}

	fmt.Print("Waiting for authentication")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pollURL := fmt.Sprintf("%s/v1/auth/poll?session_id=%s", cfg.APIURL, sessionID)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return fmt.Errorf("timed out waiting for %s Sign-In (5 minutes)", label)
		case <-ticker.C:
			fmt.Print(".")

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
			if err != nil {
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode == http.StatusAccepted {
				continue
			}
			if resp.StatusCode == http.StatusOK {
				var result struct {
					Status       string `json:"status"`
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
					Email        string `json:"email"`
				}
				if err := json.Unmarshal(body, &result); err != nil {
					fmt.Println()
					return fmt.Errorf("parsing poll response: %w", err)
				}
				if result.AccessToken == "" || result.RefreshToken == "" {
					fmt.Println()
					return fmt.Errorf("sign-in succeeded but no tokens received")
				}
				cfg.AccessToken = result.AccessToken
				cfg.RefreshToken = result.RefreshToken
				cfg.Email = result.Email
				if err := cfg.Save(); err != nil {
					return err
				}
				fmt.Printf("\nLogged in as %s\n", result.Email)
				return nil
			}
			fmt.Println()
			return fmt.Errorf("poll request failed (status %d): %s", resp.StatusCode, string(body))
		}
	}
}

func registerDeviceCmd() *cobra.Command {
	var deviceName string
	cmd := &cobra.Command{
		Use:   "register-device",
		Short: "Register this device with your account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.IsLoggedIn() {
				return fmt.Errorf("not logged in — run 'shireguard login' first")
			}

			client := newClient()

			// Fetch default network
			nets, err := client.ListNetworks()
			if err != nil {
				return fmt.Errorf("listing networks: %w", err)
			}
			if len(nets) == 0 {
				return fmt.Errorf("no networks found")
			}
			networkID := nets[0].ID

			// Generate WireGuard keys
			privKey, pubKey, err := wg.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generating keys: %w", err)
			}

			platform := runtime.GOOS
			if platform == "darwin" {
				platform = "macos"
			}

			if deviceName == "" {
				hostname, _ := os.Hostname()
				deviceName = hostname
			}

			dev, err := client.RegisterDevice(&api.RegisterDeviceRequest{
				Name:      deviceName,
				Platform:  platform,
				PublicKey: pubKey,
				NetworkID: networkID,
			})
			if err != nil {
				return fmt.Errorf("registering device: %w", err)
			}

			cfg.DeviceID = dev.ID
			cfg.DeviceName = dev.Name
			cfg.NetworkID = dev.NetworkID
			cfg.PrivateKey = privKey
			cfg.PublicKey = pubKey
			cfg.AssignedIP = dev.AssignedIP

			if err := cfg.Save(); err != nil {
				return err
			}

			fmt.Printf("Device registered: %s (%s)\n", dev.Name, dev.AssignedIP)
			fmt.Println("Run 'shireguard up' to start the tunnel")
			return nil
		},
	}
	cmd.Flags().StringVar(&deviceName, "name", "", "Device name (defaults to hostname)")
	return cmd
}

func upCmd() *cobra.Command {
	var foreground bool
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start the WireGuard tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.IsLoggedIn() {
				return fmt.Errorf("not logged in — run 'shireguard login' first")
			}
			if !cfg.IsRegistered() {
				return fmt.Errorf("device not registered — run 'shireguard register-device' first")
			}

			if !foreground {
				return startDaemon()
			}

			// Foreground mode: write pidfile and run the tunnel directly.
			// Used by service managers (launchd, systemd) and by startDaemon().
			if pidPath, err := config.PidFile(); err == nil {
				_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600)
				defer os.Remove(pidPath)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				cancel()
			}()

			d := daemon.New(cfg)
			return d.Run(ctx)
		},
	}
	// --foreground is for service managers; hidden from normal help output.
	cmd.Flags().BoolVar(&foreground, "foreground", false, "Run in the foreground (for launchd/systemd)")
	_ = cmd.Flags().MarkHidden("foreground")
	return cmd
}

// startDaemon re-execs the current binary with --foreground, detaches it from
// the terminal, and returns immediately so the shell is free.
func startDaemon() error {
	// Refuse to start a second instance.
	if pidPath, err := config.PidFile(); err == nil {
		if data, err := os.ReadFile(pidPath); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				if proc, err := os.FindProcess(pid); err == nil {
					if proc.Signal(syscall.Signal(0)) == nil {
						return fmt.Errorf("shireguard is already running (pid %d) — run 'shireguard down' first", pid)
					}
				}
			}
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	logPath := "/var/log/shireguard.log"
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	child := exec.Command(exePath, "up", "--foreground")
	child.Stdout = logFile
	child.Stderr = logFile
	child.Stdin = nil
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from terminal

	if err := child.Start(); err != nil {
		return fmt.Errorf("starting daemon: %w", err)
	}

	fmt.Printf("Shireguard started (pid %d)\n", child.Process.Pid)
	fmt.Printf("Logs:  sudo tail -f %s\n", logPath)
	fmt.Println("Stop:  sudo shireguard down")
	return nil
}

func downCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Stop the WireGuard tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath, err := config.PidFile()
			if err != nil {
				return err
			}

			data, err := os.ReadFile(pidPath)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("shireguard is not running")
				}
				return err
			}

			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				return fmt.Errorf("invalid pidfile: %v", err)
			}

			proc, err := os.FindProcess(pid)
			if err != nil {
				_ = os.Remove(pidPath)
				return fmt.Errorf("process not found: %v", err)
			}

			// Check the process is actually alive before signalling
			if err := proc.Signal(syscall.Signal(0)); err != nil {
				_ = os.Remove(pidPath)
				return fmt.Errorf("shireguard is not running (stale pidfile removed)")
			}

			if err := proc.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("failed to stop process: %v", err)
			}

			fmt.Printf("Stopping shireguard (pid %d)...", pid)

			// Wait up to 10s for the process to exit
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
				if err := proc.Signal(syscall.Signal(0)); err != nil {
					fmt.Println(" done")
					return nil
				}
				fmt.Print(".")
			}

			return fmt.Errorf("timed out waiting for shireguard to stop")
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.IsLoggedIn() {
				fmt.Println("Status: not logged in")
				return nil
			}
			if !cfg.IsRegistered() {
				fmt.Printf("Logged in as: %s\n", cfg.Email)
				fmt.Println("Status: device not registered")
				return nil
			}

			fmt.Printf("Account:  %s\n", cfg.Email)
			fmt.Printf("Device:   %s (%s)\n", cfg.DeviceName, cfg.DeviceID[:8]+"...")
			fmt.Printf("IP:       %s\n", cfg.AssignedIP)
			fmt.Printf("Network:  %s\n", cfg.NetworkID[:8]+"...")
			fmt.Printf("API:      %s\n", cfg.APIURL)

			// Try to list peers
			client := newClient()
			peers, err := client.GetPeers(cfg.NetworkID)
			if err != nil {
				fmt.Printf("Peers:    (error: %v)\n", err)
				return nil
			}

			fmt.Printf("Peers:    %d\n", len(peers)-1) // Exclude self
			for _, p := range peers {
				if p.ID == cfg.DeviceID {
					continue
				}
				status := "offline"
				if p.Online {
					status = "online"
				}
				endpoint := "—"
				if p.Endpoint != nil {
					endpoint = *p.Endpoint
				}
				fmt.Printf("  %-15s %-15s %-8s %s\n", p.Name, p.AssignedIP, status, endpoint)
			}

			return nil
		},
	}
}

func devicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "List registered devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.IsLoggedIn() {
				return fmt.Errorf("not logged in")
			}
			client := newClient()
			devices, err := client.ListDevices()
			if err != nil {
				return err
			}
			if len(devices) == 0 {
				fmt.Println("No devices registered")
				return nil
			}
			fmt.Printf("%-20s %-12s %-15s %-8s\n", "NAME", "PLATFORM", "IP", "STATUS")
			for _, d := range devices {
				status := "offline"
				if d.Online {
					status = "online"
				}
				fmt.Printf("%-20s %-12s %-15s %-8s\n", d.Name, d.Platform, d.AssignedIP, status)
			}
			return nil
		},
	}
	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and clear credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Clear()
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Println("Logged out")
			return nil
		},
	}
}
