//go:build darwin

package tray

import (
	_ "embed"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"fyne.io/systray"
)

//go:embed icons/connected.png
var iconConnected []byte

//go:embed icons/disconnected.png
var iconDisconnected []byte

// Run starts the menu bar app. It blocks until Quit is selected.
func Run() {
	systray.Run(onReady, nil)
}

func onReady() {
	systray.SetIcon(iconDisconnected)
	systray.SetTooltip("Shireguard")

	// Menu items
	emailItem := systray.AddMenuItem("Not logged in", "")
	emailItem.Disable()

	systray.AddSeparator()

	statusItem := systray.AddMenuItem("○ Not connected", "")
	statusItem.Disable()

	systray.AddSeparator()

	connectItem := systray.AddMenuItem("Connect", "Start the Shireguard daemon")
	disconnectItem := systray.AddMenuItem("Disconnect", "Stop the Shireguard daemon")

	systray.AddSeparator()

	launchAtLoginItem := systray.AddMenuItem("  Launch at Login", "Start automatically at login")

	systray.AddSeparator()

	quitItem := systray.AddMenuItem("Quit", "Quit Shireguard Menu Bar")

	// Apply initial state and capture it as previous for change detection.
	prev := CurrentState()
	applyState(prev, emailItem, statusItem, connectItem, disconnectItem, launchAtLoginItem)

	// Polling goroutine — detects state changes and fires notifications.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			curr := CurrentState()
			if curr.Connected != prev.Connected {
				if curr.Connected {
					notify("Connected")
				} else {
					notify("Disconnected")
				}
			}
			prev = curr
			applyState(curr, emailItem, statusItem, connectItem, disconnectItem, launchAtLoginItem)
		}
	}()

	// Event loop
	go func() {
		for {
			select {
			case <-connectItem.ClickedCh:
				connectItem.Disable()
				disconnectItem.Disable()
				statusItem.SetTitle("Connecting…")
				go func() {
					if out, err := exec.Command(shireguardBinary(), "up").CombinedOutput(); err != nil {
						msg := strings.TrimSpace(string(out))
						if msg == "" {
							msg = "Connect failed"
						}
						notify(msg)
					}
					// Give daemon a moment to start
					time.Sleep(2 * time.Second)
					curr := CurrentState()
					applyState(curr, emailItem, statusItem, connectItem, disconnectItem, launchAtLoginItem)
				}()

			case <-disconnectItem.ClickedCh:
				connectItem.Disable()
				disconnectItem.Disable()
				statusItem.SetTitle("Disconnecting…")
				go func() {
					if out, err := exec.Command(shireguardBinary(), "down").CombinedOutput(); err != nil {
						msg := strings.TrimSpace(string(out))
						if msg == "" {
							msg = "Disconnect failed"
						}
						notify(msg)
					}
					time.Sleep(2 * time.Second)
					curr := CurrentState()
					applyState(curr, emailItem, statusItem, connectItem, disconnectItem, launchAtLoginItem)
				}()

			case <-launchAtLoginItem.ClickedCh:
				s := CurrentState()
				SetLaunchAtLogin(!s.LaunchAtLogin)
				if IsLaunchAtLoginEnabled() {
					launchAtLoginItem.SetTitle("✓ Launch at Login")
				} else {
					launchAtLoginItem.SetTitle("  Launch at Login")
				}

			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func applyState(s State, email, status, connect, disconnect, launchAtLogin *systray.MenuItem) {
	// Update email label
	email.SetTitle(s.EmailLabel())

	// Update status label and icon
	status.SetTitle(s.StatusLabel())
	if s.Connected {
		systray.SetIcon(iconConnected)
	} else {
		systray.SetIcon(iconDisconnected)
	}

	// Update launch at login label
	if s.LaunchAtLogin {
		launchAtLogin.SetTitle("✓ Launch at Login")
	} else {
		launchAtLogin.SetTitle("  Launch at Login")
	}

	// Update connect/disconnect enabled state
	if !s.LoggedIn {
		connect.Disable()
		disconnect.Disable()
		return
	}

	if s.Connected {
		connect.Disable()
		disconnect.Enable()
	} else {
		connect.Enable()
		disconnect.Disable()
	}
}

// notify sends a macOS notification via osascript (no entitlements required).
func notify(subtitle string) {
	exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification %q with title "Shireguard"`, subtitle),
	).Run()
}
