//go:build darwin

package tray

import (
	_ "embed"
	"os/exec"
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

	quitItem := systray.AddMenuItem("Quit", "Quit Shireguard Menu Bar")

	// Apply initial state immediately
	applyState(CurrentState(), emailItem, statusItem, connectItem, disconnectItem)

	// Polling goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			applyState(CurrentState(), emailItem, statusItem, connectItem, disconnectItem)
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
					exec.Command(shireguardBinary(), "up").Run()
					// Give daemon a moment to start
					time.Sleep(2 * time.Second)
					applyState(CurrentState(), emailItem, statusItem, connectItem, disconnectItem)
				}()

			case <-disconnectItem.ClickedCh:
				connectItem.Disable()
				disconnectItem.Disable()
				statusItem.SetTitle("Disconnecting…")
				go func() {
					exec.Command(shireguardBinary(), "down").Run()
					time.Sleep(2 * time.Second)
					applyState(CurrentState(), emailItem, statusItem, connectItem, disconnectItem)
				}()

			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func applyState(s State, email, status, connect, disconnect *systray.MenuItem) {
	// Update email label
	email.SetTitle(s.EmailLabel())

	// Update status label and icon
	status.SetTitle(s.StatusLabel())
	if s.Connected {
		systray.SetIcon(iconConnected)
	} else {
		systray.SetIcon(iconDisconnected)
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
