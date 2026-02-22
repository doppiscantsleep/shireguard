//go:build darwin

package tray

import (
	_ "embed"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
)

//go:embed icons/connected.png
var iconConnected []byte

//go:embed icons/disconnected.png
var iconDisconnected []byte

const maxPeerSlots = 8

// peerSlot holds the pre-allocated menu items for one peer entry.
type peerSlot struct {
	mu          sync.Mutex
	item        *systray.MenuItem
	copyIPItem  *systray.MenuItem
	copyEndItem *systray.MenuItem
	ip          string
	endpoint    string
}

// Run starts the menu bar app. It blocks until Quit is selected.
func Run() {
	systray.Run(onReady, nil)
}

func onReady() {
	systray.SetIcon(iconDisconnected)
	systray.SetTooltip("Shireguard")

	// — Account —
	emailItem := systray.AddMenuItem("Not logged in", "")
	emailItem.Disable()

	systray.AddSeparator()

	// — Status —
	statusItem := systray.AddMenuItem("○ Not connected", "")
	statusItem.Disable()
	copyMyIPItem := systray.AddMenuItem("", "Copy this device's WireGuard IP to clipboard")
	copyMyIPItem.Hide()

	systray.AddSeparator()

	// — Connect / Disconnect —
	connectItem := systray.AddMenuItem("Connect", "Start the Shireguard daemon")
	disconnectItem := systray.AddMenuItem("Disconnect", "Stop the Shireguard daemon")

	systray.AddSeparator()

	// — Peers —
	peersLabelItem := systray.AddMenuItem("Peers", "")
	peersLabelItem.Disable()
	peersLabelItem.Hide()

	slots := make([]*peerSlot, maxPeerSlots)
	for i := range slots {
		s := &peerSlot{
			item: systray.AddMenuItem("", ""),
		}
		s.copyIPItem = s.item.AddSubMenuItem("Copy WireGuard IP", "")
		s.copyEndItem = s.item.AddSubMenuItem("Copy Public Endpoint", "")
		s.item.Hide()
		slots[i] = s

		// One goroutine per slot handles copy-click events.
		go func(slot *peerSlot) {
			for {
				select {
				case <-slot.copyIPItem.ClickedCh:
					slot.mu.Lock()
					ip := slot.ip
					slot.mu.Unlock()
					if ip != "" {
						copyToClipboard(ip)
					}
				case <-slot.copyEndItem.ClickedCh:
					slot.mu.Lock()
					ep := slot.endpoint
					slot.mu.Unlock()
					if ep != "" {
						copyToClipboard(ep)
					}
				}
			}
		}(s)
	}

	systray.AddSeparator()

	// — Settings —
	launchAtLoginItem := systray.AddMenuItem("  Launch at Login", "Start automatically at login")

	systray.AddSeparator()

	quitItem := systray.AddMenuItem("Quit", "Quit Shireguard Menu Bar")

	// Apply initial state.
	prev := CurrentState()
	applyState(prev, emailItem, statusItem, copyMyIPItem, connectItem, disconnectItem, launchAtLoginItem)

	// Polling goroutine: refreshes state every 5 s, fires notifications on transitions.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastPeers []api.Peer
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

			// Fetch peer list directly from the API (works regardless of daemon state).
			if curr.LoggedIn {
				if cfg, err := config.Load(); err == nil {
					if peers, err := FetchPeers(cfg); err == nil {
						lastPeers = peers
					}
				}
			} else {
				lastPeers = nil
			}

			applyState(curr, emailItem, statusItem, copyMyIPItem, connectItem, disconnectItem, launchAtLoginItem)
			applyPeers(lastPeers, slots, peersLabelItem)
		}
	}()

	// Event loop.
	go func() {
		for {
			select {
			case <-copyMyIPItem.ClickedCh:
				s := CurrentState()
				if s.AssignedIP != "" {
					copyToClipboard(s.AssignedIP)
				}

			case <-connectItem.ClickedCh:
				connectItem.Disable()
				disconnectItem.Disable()
				statusItem.SetTitle("Connecting…")
				go func() {
					if out, err := exec.Command("sudo", "-n", "-E", shireguardBinary(), "up").CombinedOutput(); err != nil {
						msg := strings.TrimSpace(string(out))
						if msg == "" {
							msg = "Connect failed"
						}
						notify(msg)
					}
					time.Sleep(2 * time.Second)
					curr := CurrentState()
					applyState(curr, emailItem, statusItem, copyMyIPItem, connectItem, disconnectItem, launchAtLoginItem)
				}()

			case <-disconnectItem.ClickedCh:
				connectItem.Disable()
				disconnectItem.Disable()
				statusItem.SetTitle("Disconnecting…")
				go func() {
					if out, err := exec.Command("sudo", "-n", "-E", shireguardBinary(), "down").CombinedOutput(); err != nil {
						msg := strings.TrimSpace(string(out))
						if msg == "" {
							msg = "Disconnect failed"
						}
						notify(msg)
					}
					time.Sleep(2 * time.Second)
					curr := CurrentState()
					applyState(curr, emailItem, statusItem, copyMyIPItem, connectItem, disconnectItem, launchAtLoginItem)
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

func applyState(s State, email, status, copyMyIP, connect, disconnect, launchAtLogin *systray.MenuItem) {
	email.SetTitle(s.EmailLabel())
	status.SetTitle(s.StatusLabel())

	if s.Connected && s.AssignedIP != "" {
		systray.SetIcon(iconConnected)
		copyMyIP.SetTitle("Copy " + s.AssignedIP)
		copyMyIP.Show()
	} else {
		systray.SetIcon(iconDisconnected)
		copyMyIP.Hide()
	}

	if s.LaunchAtLogin {
		launchAtLogin.SetTitle("✓ Launch at Login")
	} else {
		launchAtLogin.SetTitle("  Launch at Login")
	}

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

// applyPeers updates the pre-allocated peer slots with the current peer list.
func applyPeers(peers []api.Peer, slots []*peerSlot, label *systray.MenuItem) {
	if len(peers) == 0 {
		label.Hide()
		for _, s := range slots {
			s.item.Hide()
		}
		return
	}
	label.Show()

	for i, slot := range slots {
		if i >= len(peers) {
			slot.item.Hide()
			slot.mu.Lock()
			slot.ip = ""
			slot.endpoint = ""
			slot.mu.Unlock()
			continue
		}

		p := peers[i]

		dot := "○"
		if p.Online {
			dot = "●"
		}
		slot.item.SetTitle(fmt.Sprintf("%s %s · %s · %s", dot, p.Name, platformLabel(p.Platform), p.AssignedIP))

		slot.copyIPItem.SetTitle("Copy WireGuard IP: " + p.AssignedIP)

		ep := ""
		if p.Endpoint != nil {
			ep = *p.Endpoint
		}
		if ep != "" {
			slot.copyEndItem.SetTitle("Copy Public Endpoint: " + ep)
			slot.copyEndItem.Show()
		} else {
			slot.copyEndItem.Hide()
		}

		slot.mu.Lock()
		slot.ip = p.AssignedIP
		slot.endpoint = ep
		slot.mu.Unlock()

		slot.item.Show()
	}
}

// platformLabel returns a human-readable OS name.
func platformLabel(p string) string {
	switch p {
	case "macos":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	default:
		if p == "" {
			return "unknown"
		}
		return p
	}
}

// copyToClipboard copies text to the macOS clipboard and fires a notification.
func copyToClipboard(text string) {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err == nil {
		notify("Copied: " + text)
	}
}

// notify sends a macOS notification via osascript (no entitlements required).
func notify(subtitle string) {
	exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification %q with title "Shireguard"`, subtitle),
	).Run()
}
