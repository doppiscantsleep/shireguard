package wg

import (
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const InterfaceName = "sg0"

type PeerConfig struct {
	PublicKey  string
	Endpoint  string   // ip:port
	AllowedIPs []string // e.g. ["10.100.0.2/32"]
}

type TunnelConfig struct {
	PrivateKey string
	Address    string // e.g. "10.100.0.1/24"
	ListenPort int
	Peers      []PeerConfig
}

type Tunnel struct {
	device *device.Device
	tunDev tun.Device
	mu     sync.Mutex
	up     bool
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
	tunDevice, err := tun.CreateTUN(InterfaceName, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("creating TUN device: %w", err)
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
	if err := configureInterface(cfg.Address); err != nil {
		dev.Close()
		tunDevice.Close()
		return fmt.Errorf("configuring interface: %w", err)
	}

	t.device = dev
	t.tunDev = tunDevice
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

func (t *Tunnel) UpdatePeers(peers []PeerConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.up || t.device == nil {
		return fmt.Errorf("tunnel not up")
	}

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

func configureInterface(address string) error {
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", address, err)
	}

	switch runtime.GOOS {
	case "darwin":
		// macOS: ifconfig sg0 inet 10.100.0.1 10.100.0.1 netmask 255.255.255.0
		mask := fmt.Sprintf("%d.%d.%d.%d",
			ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
		if err := run("ifconfig", InterfaceName, "inet", ip.String(), ip.String(), "netmask", mask); err != nil {
			return err
		}
		// Add route for the subnet
		return run("route", "-n", "add", "-net", ipNet.String(), "-interface", InterfaceName)

	case "linux":
		// Linux: ip addr add 10.100.0.1/24 dev sg0 && ip link set sg0 up
		if err := run("ip", "addr", "add", address, "dev", InterfaceName); err != nil {
			return err
		}
		return run("ip", "link", "set", InterfaceName, "up")

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
