package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	root.AddCommand(loginCmd(), registerCmd(), upCmd(), downCmd(), statusCmd(), devicesCmd(), logoutCmd())

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
	var email, password string
	var useApple bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to your Shireguard account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if useApple {
				return loginWithApple()
			}
			if email == "" || password == "" {
				return fmt.Errorf("--email and --password are required (or use --apple)")
			}
			client := api.New(cfg.APIURL, "", "", nil)
			resp, err := client.Login(email, password)
			if err != nil {
				return err
			}
			cfg.AccessToken = resp.AccessToken
			cfg.RefreshToken = resp.RefreshToken
			cfg.Email = resp.User.Email
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Printf("Logged in as %s\n", resp.User.Email)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Account email")
	cmd.Flags().StringVar(&password, "password", "", "Account password")
	cmd.Flags().BoolVar(&useApple, "apple", false, "Sign in with Apple (opens browser)")
	return cmd
}

func loginWithApple() error {
	// Bind to a random free port on localhost
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("could not start local callback server: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	type result struct {
		accessToken  string
		refreshToken string
		email        string
		err          error
	}
	done := make(chan result, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errMsg := q.Get("error"); errMsg != "" {
			fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h2>Sign in failed</h2><p>%s</p><p>You can close this tab.</p>
</body></html>`, errMsg)
			done <- result{err: fmt.Errorf("apple sign-in failed: %s", errMsg)}
			return
		}
		fmt.Fprint(w, `<!DOCTYPE html><html><body>
<h2>✓ Signed in successfully</h2><p>You can close this tab and return to the terminal.</p>
</body></html>`)
		done <- result{
			accessToken:  q.Get("access_token"),
			refreshToken: q.Get("refresh_token"),
			email:        q.Get("email"),
		}
	})

	go srv.Serve(ln)
	defer srv.Close()

	authURL := fmt.Sprintf("%s/v1/auth/apple?cli_redirect=%s",
		cfg.APIURL,
		url.QueryEscape(callbackURL),
	)

	fmt.Println("Opening browser for Apple Sign-In...")
	fmt.Printf("If your browser doesn't open automatically, visit:\n  %s\n\n", authURL)

	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", authURL).Start()
	case "linux":
		exec.Command("xdg-open", authURL).Start()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	select {
	case res := <-done:
		if res.err != nil {
			return res.err
		}
		if res.accessToken == "" || res.refreshToken == "" {
			return fmt.Errorf("sign-in succeeded but no tokens received")
		}
		cfg.AccessToken = res.accessToken
		cfg.RefreshToken = res.refreshToken
		cfg.Email = res.email
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Printf("Logged in as %s\n", res.email)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for Apple Sign-In (5 minutes)")
	}
}

func registerCmd() *cobra.Command {
	var email, password, deviceName string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create account and register this device",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := api.New(cfg.APIURL, "", "", nil)

			// Register account
			resp, err := client.Register(email, password)
			if err != nil {
				return err
			}
			cfg.AccessToken = resp.AccessToken
			cfg.RefreshToken = resp.RefreshToken
			cfg.Email = resp.User.Email

			// Update client with tokens
			client = newClient()

			// Generate WireGuard keys
			privKey, pubKey, err := wg.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generating keys: %w", err)
			}

			// Determine platform
			platform := runtime.GOOS
			if platform == "darwin" {
				platform = "macos"
			}

			// Register device
			networkID := ""
			if resp.Network != nil {
				networkID = resp.Network.ID
			} else {
				// Fetch default network
				nets, err := client.ListNetworks()
				if err != nil {
					return fmt.Errorf("listing networks: %w", err)
				}
				if len(nets) == 0 {
					return fmt.Errorf("no networks found")
				}
				networkID = nets[0].ID
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

			fmt.Printf("Account created: %s\n", resp.User.Email)
			fmt.Printf("Device registered: %s (%s)\n", dev.Name, dev.AssignedIP)
			fmt.Println("Run 'shireguard up' to start the tunnel")
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Account email")
	cmd.Flags().StringVar(&password, "password", "", "Account password")
	cmd.Flags().StringVar(&deviceName, "name", "", "Device name (defaults to hostname)")
	cmd.MarkFlagRequired("email")
	cmd.MarkFlagRequired("password")
	return cmd
}

func upCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Start the WireGuard tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cfg.IsLoggedIn() {
				return fmt.Errorf("not logged in — run 'shireguard login' first")
			}
			if !cfg.IsRegistered() {
				return fmt.Errorf("device not registered — run 'shireguard register' first")
			}

			// Write pidfile so 'shireguard down' can signal this process
			if pidPath, err := config.PidFile(); err == nil {
				_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600)
				defer os.Remove(pidPath)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle signals
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				fmt.Println("\nShutting down...")
				cancel()
			}()

			d := daemon.New(cfg)
			return d.Run(ctx)
		},
	}
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
