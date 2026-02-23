package wg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func interfaceName() string {
	if runtime.GOOS == "darwin" {
		return "utun" // macOS auto-assigns the number (utun0, utun1, …)
	}
	return "sg0"
}

type PeerConfig struct {
	PublicKey  string
	Endpoint  string   // ip:port
	AllowedIPs []string // e.g. ["100.65.0.2/32"]
}

type TunnelConfig struct {
	PrivateKey string
	Address    string // e.g. "100.65.0.1/16"
	ListenPort int
	Peers      []PeerConfig
}

type Tunnel struct {
	device *device.Device
	tunDev tun.Device
	mu     sync.Mutex
	up     bool
	ifName string
}

func NewTunnel() *Tunnel {
	return &Tunnel{}
}

func (t *Tunnel) Up(cfg *TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.up {
		return fmt.Errorf("tunnel already up")
	}

	// Create TUN device
	tunDevice, err := tun.CreateTUN(interfaceName(), device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("creating TUN device: %w", err)
	}

	// Get the actual interface name assigned by the OS (important on macOS utun)
	ifName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return fmt.Errorf("getting interface name: %w", err)
	}

	// Create WireGuard device
	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Build IPC config
	ipc := buildIPC(cfg)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		tunDevice.Close()
		return fmt.Errorf("configuring WireGuard: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		tunDevice.Close()
		return fmt.Errorf("bringing up device: %w", err)
	}

	// Configure IP address on the interface
	if err := configureInterface(ifName, cfg.Address); err != nil {
		dev.Close()
		tunDevice.Close()
		return fmt.Errorf("configuring interface: %w", err)
	}

	t.device = dev
	t.tunDev = tunDevice
	t.ifName = ifName
	t.up = true

	return nil
}

func (t *Tunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.up {
		return nil
	}

	if t.device != nil {
		t.device.Close()
	}
	if t.tunDev != nil {
		t.tunDev.Close()
	}

	t.up = false
	return nil
}

func (t *Tunnel) IsUp() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

// Name returns the OS-assigned interface name (e.g. "utun8"), or empty string
// if the tunnel is not up.
func (t *Tunnel) Name() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ifName
}

func (t *Tunnel) UpdatePeers(peers []PeerConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.up || t.device == nil {
		return fmt.Errorf("tunnel not up")
	}

	// Build desired peer set (keyed by base64 public key).
	desired := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		desired[peer.PublicKey] = struct{}{}
	}

	// Remove peers no longer in the desired set.
	var buf strings.Builder
	if err := t.device.IpcGetOperation(&buf); err == nil {
		current := parsePeerStats(buf.String())
		var removals strings.Builder
		for b64Key := range current {
			if _, ok := desired[b64Key]; !ok {
				fmt.Fprintf(&removals, "public_key=%s\nremove=true\n", hexKey(b64Key))
			}
		}
		if removals.Len() > 0 {
			_ = t.device.IpcSet(removals.String())
		}
	}

	// Update/add desired peers, re-setting keepalive on every sync so it is
	// never silently dropped by wireguard-go on peer reconfiguration.
	var ipc strings.Builder
	for _, peer := range peers {
		fmt.Fprintf(&ipc, "public_key=%s\n", hexKey(peer.PublicKey))
		if peer.Endpoint != "" {
			fmt.Fprintf(&ipc, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprint(&ipc, "replace_allowed_ips=true\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&ipc, "allowed_ip=%s\n", ip)
		}
		fmt.Fprint(&ipc, "persistent_keepalive_interval=25\n")
	}

	return t.device.IpcSet(ipc.String())
}

func buildIPC(cfg *TunnelConfig) string {
	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\n", hexKey(cfg.PrivateKey))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&ipc, "listen_port=%d\n", cfg.ListenPort)
	}

	for _, peer := range cfg.Peers {
		fmt.Fprintf(&ipc, "public_key=%s\n", hexKey(peer.PublicKey))
		if peer.Endpoint != "" {
			fmt.Fprintf(&ipc, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprintf(&ipc, "persistent_keepalive_interval=25\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&ipc, "allowed_ip=%s\n", ip)
		}
	}

	return ipc.String()
}

// hexKey converts a base64 WireGuard key to hex (as expected by IPC).
func hexKey(b64Key string) string {
	// wireguard IPC expects hex-encoded keys
	data, err := base64Decode(b64Key)
	if err != nil || len(data) != 32 {
		return ""
	}
	return fmt.Sprintf("%x", data)
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func configureInterface(ifName, address string) error {
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", address, err)
	}

	switch runtime.GOOS {
	case "darwin":
		// macOS: ifconfig utunN inet <ip> <ip> netmask <mask>
		mask := fmt.Sprintf("%d.%d.%d.%d",
			ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
		if err := run("ifconfig", ifName, "inet", ip.String(), ip.String(), "netmask", mask); err != nil {
			return err
		}
		// Add route for the subnet
		return run("route", "-n", "add", "-net", ipNet.String(), "-interface", ifName)

	case "linux":
		// Linux: ip addr add <address> dev sg0 && ip link set sg0 up
		if err := run("ip", "addr", "add", address, "dev", ifName); err != nil {
			return err
		}
		return run("ip", "link", "set", ifName, "up")

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, string(out), err)
	}
	return nil
}

// PeerStat holds per-peer statistics read from the WireGuard IPC.
type PeerStat struct {
	LastHandshakeTime time.Time
	Endpoint          string
	TxBytes           int64
	RxBytes           int64
}

// GetPeerStats returns a map of base64 public key → PeerStat by reading
// the WireGuard UAPI state. Returns an error if the tunnel is not up.
func (t *Tunnel) GetPeerStats() (map[string]PeerStat, error) {
	t.mu.Lock()
	dev := t.device
	up := t.up
	t.mu.Unlock()

	if !up || dev == nil {
		return nil, fmt.Errorf("tunnel not up")
	}

	var buf strings.Builder
	if err := dev.IpcGetOperation(&buf); err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}

	return parsePeerStats(buf.String()), nil
}

// UpdatePeerEndpoint updates the endpoint for a single peer identified by
// its base64 public key without affecting other peer settings.
func (t *Tunnel) UpdatePeerEndpoint(pubKey, endpoint string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.up || t.device == nil {
		return fmt.Errorf("tunnel not up")
	}

	ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", hexKey(pubKey), endpoint)
	return t.device.IpcSet(ipc)
}

// parsePeerStats parses WireGuard UAPI GET output into a map keyed by
// base64-encoded public key.
func parsePeerStats(ipcOutput string) map[string]PeerStat {
	stats := make(map[string]PeerStat)

	var currentHex string
	var currentStat PeerStat
	inPeer := false

	for _, line := range strings.Split(ipcOutput, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "public_key":
			if inPeer && currentHex != "" {
				if b64 := hexToBase64(currentHex); b64 != "" {
					stats[b64] = currentStat
				}
			}
			currentHex = val
			currentStat = PeerStat{}
			inPeer = true

		case "endpoint":
			if inPeer {
				currentStat.Endpoint = val
			}

		case "last_handshake_time_sec":
			if inPeer {
				sec, err := strconv.ParseInt(val, 10, 64)
				if err == nil && sec > 0 {
					currentStat.LastHandshakeTime = time.Unix(sec, 0)
				}
			}

		case "tx_bytes":
			if inPeer {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					currentStat.TxBytes = n
				}
			}

		case "rx_bytes":
			if inPeer {
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					currentStat.RxBytes = n
				}
			}
		}
	}

	// Save the final peer
	if inPeer && currentHex != "" {
		if b64 := hexToBase64(currentHex); b64 != "" {
			stats[b64] = currentStat
		}
	}

	return stats
}

// hexToBase64 converts a 64-char hex WireGuard key to base64.
func hexToBase64(hexKey string) string {
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 32 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
