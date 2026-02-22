package tray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/shireguard/shireguard/internal/config"
)

// State holds the current observable state of the Shireguard daemon.
type State struct {
	Email        string
	Connected    bool
	LoggedIn     bool
	AssignedIP   string
	LaunchAtLogin bool
}

// CurrentState reads config and pidfile to determine current state.
func CurrentState() State {
	cfg, err := config.Load()
	if err != nil {
		return State{LaunchAtLogin: IsLaunchAtLoginEnabled()}
	}

	s := State{
		Email:        cfg.Email,
		LoggedIn:     cfg.IsLoggedIn(),
		AssignedIP:   cfg.AssignedIP,
		LaunchAtLogin: IsLaunchAtLoginEnabled(),
	}

	s.Connected = daemonRunning()
	return s
}

// daemonRunning returns true if shireguard.pid exists and the process is alive.
func daemonRunning() bool {
	pidFile, err := config.PidFile()
	if err != nil {
		return false
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return false
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// kill -0 checks if the process exists without sending a signal.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// shireguardBinary returns the path to the shireguard binary.
// It looks next to the current executable first, then falls back to $PATH.
func shireguardBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return "shireguard"
	}

	// The menubar binary lives in MacOS/shireguard-menubar inside an .app
	// bundle, or alongside shireguard in a plain install.
	dir := exe[:strings.LastIndex(exe, "/")]
	candidate := dir + "/shireguard"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	// Check well-known Homebrew paths (PATH is minimal inside an .app bundle).
	for _, p := range []string{"/opt/homebrew/bin/shireguard", "/usr/local/bin/shireguard"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "shireguard"
}

func (s State) StatusLabel() string {
	if !s.LoggedIn {
		return "Not logged in"
	}
	if s.Connected {
		if s.AssignedIP != "" {
			return "● Connected · " + s.AssignedIP
		}
		return "● Connected"
	}
	return "○ Not connected"
}

func (s State) EmailLabel() string {
	if s.Email == "" {
		return "Not logged in"
	}
	return s.Email
}

// launchAgentPath returns the path to the LaunchAgent plist.
func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", "com.shireguard.menubar.plist"), nil
}

// IsLaunchAtLoginEnabled returns true if the LaunchAgent plist exists.
func IsLaunchAtLoginEnabled() bool {
	p, err := launchAgentPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// SetLaunchAtLogin installs or removes the LaunchAgent plist.
func SetLaunchAtLogin(enabled bool) error {
	p, err := launchAgentPath()
	if err != nil {
		return err
	}

	if !enabled {
		exec.Command("launchctl", "unload", p).Run()
		return os.Remove(p)
	}

	// Get the path to this executable.
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.shireguard.menubar</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
`, exe)

	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(plist), 0644); err != nil {
		return err
	}

	exec.Command("launchctl", "load", p).Run()
	return nil
}
