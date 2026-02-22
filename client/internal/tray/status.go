package tray

import (
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/shireguard/shireguard/internal/config"
)

// State holds the current observable state of the Shireguard daemon.
type State struct {
	Email     string
	Connected bool
	LoggedIn  bool
}

// CurrentState reads config and pidfile to determine current state.
func CurrentState() State {
	cfg, err := config.Load()
	if err != nil {
		return State{}
	}

	s := State{
		Email:    cfg.Email,
		LoggedIn: cfg.IsLoggedIn(),
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

	// App bundle: .../Contents/MacOS/shireguard-menubar → try ../../Resources
	// But shireguard is typically installed in /usr/local/bin or brew prefix.
	return "shireguard"
}

func (s State) StatusLabel() string {
	if !s.LoggedIn {
		return "Not logged in"
	}
	if s.Connected {
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
