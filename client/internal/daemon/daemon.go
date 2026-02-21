package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
	"github.com/shireguard/shireguard/internal/nat"
	"github.com/shireguard/shireguard/internal/wg"
)

const (
	heartbeatInterval    = 30 * time.Second
	peerSyncInterval     = 15 * time.Second
	connectivityInterval = 30 * time.Second
	relayKeepaliveInterval = 25 * time.Second
	handshakeTimeout     = 90 * time.Second
	relayBackoffDuration = 5 * time.Minute
)

type Daemon struct {
	cfg    *config.Config
	client *api.Client
	tunnel *wg.Tunnel

	// Relay registration for this device
	relayHost  string
	relayPort  int
	relayToken []byte // 16 raw bytes

	// Peer state (keyed by base64 public key)
	mu             sync.RWMutex
	peersByKey     map[string]api.Peer // pubKey → peer (includes relay info)
	usingRelay     map[string]bool     // pubKey → true when relay is active
	switchedToRelay map[string]time.Time // pubKey → when we switched to relay
}

func New(cfg *config.Config) *Daemon {
	client := api.New(cfg.APIURL, cfg.AccessToken, cfg.RefreshToken, func(access, refresh string) {
		cfg.AccessToken = access
		cfg.RefreshToken = refresh
		_ = cfg.Save()
	})

	return &Daemon{
		cfg:             cfg,
		client:          client,
		tunnel:          wg.NewTunnel(),
		peersByKey:      make(map[string]api.Peer),
		usingRelay:      make(map[string]bool),
		switchedToRelay: make(map[string]time.Time),
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	if !d.cfg.IsLoggedIn() {
		return fmt.Errorf("not logged in — run 'shireguard login' first")
	}
	if !d.cfg.IsRegistered() {
		return fmt.Errorf("device not registered — run 'shireguard register' first")
	}

	// 1. Discover public endpoint via STUN
	stunEndpoint := nat.DiscoverEndpoint()
	if stunEndpoint != "" {
		log.Printf("STUN discovered endpoint: %s", stunEndpoint)
	} else {
		log.Println("STUN discovery failed, proceeding without public endpoint")
	}

	// 2. Fetch initial peer list
	peers, err := d.client.GetPeers(d.cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("fetching peers: %w", err)
	}
	d.storePeers(peers)

	// 3. Bring up the tunnel
	tunnelCfg := d.buildTunnelConfig(peers)
	if err := d.tunnel.Up(tunnelCfg); err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}
	defer d.tunnel.Down()

	log.Printf("tunnel up with IP %s", d.cfg.AssignedIP)
	log.Printf("connected to %d peer(s)", len(tunnelCfg.Peers))

	// 4. Send initial heartbeat with discovered endpoint
	if err := d.client.Heartbeat(d.cfg.DeviceID, stunEndpoint); err != nil {
		log.Printf("initial heartbeat failed: %v", err)
	}

	// 5. Register with relay (best-effort)
	d.setupRelay(ctx)

	// 6. Run background loops
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	peerSyncTicker := time.NewTicker(peerSyncInterval)
	checkConnTicker := time.NewTicker(connectivityInterval)
	defer heartbeatTicker.Stop()
	defer peerSyncTicker.Stop()
	defer checkConnTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down tunnel")
			return nil

		case <-heartbeatTicker.C:
			if err := d.client.Heartbeat(d.cfg.DeviceID, stunEndpoint); err != nil {
				log.Printf("heartbeat failed: %v", err)
			}

		case <-peerSyncTicker.C:
			d.syncPeers()

		case <-checkConnTicker.C:
			d.checkConnectivity()
		}
	}
}

// setupRelay fetches relay info from the control plane, registers this device
// with the relay server, stores the result, and starts the keepalive goroutine.
func (d *Daemon) setupRelay(ctx context.Context) {
	relays, err := d.client.GetRelays()
	if err != nil || len(relays) == 0 {
		log.Printf("no relays available: %v", err)
		return
	}

	relay := relays[0]
	relayPort, relayTokenHex, err := d.client.RegisterWithRelay(relay, d.cfg.DeviceID)
	if err != nil {
		log.Printf("relay registration failed: %v", err)
		return
	}

	tokenBytes, err := hex.DecodeString(relayTokenHex)
	if err != nil || len(tokenBytes) != 16 {
		log.Printf("invalid relay token: %v", err)
		return
	}

	d.relayHost = relay.Host
	d.relayPort = relayPort
	d.relayToken = tokenBytes

	log.Printf("registered with relay %s on port %d", relay.Host, relayPort)

	// Store relay endpoint in control plane so peers can discover us
	if err := d.client.StoreRelayEndpoint(d.cfg.DeviceID, relay.Host, relayPort); err != nil {
		log.Printf("storing relay endpoint failed: %v", err)
	}

	go d.runRelayKeepalive(ctx)
}

// runRelayKeepalive sends UDP keepalives to the relay every 25 seconds so the
// relay can track this device's real address and port.
func (d *Daemon) runRelayKeepalive(ctx context.Context) {
	addr := fmt.Sprintf("%s:%d", d.relayHost, d.relayPort)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		log.Printf("relay keepalive: dial %s: %v", addr, err)
		return
	}
	defer conn.Close()

	// Keepalive packet: [0xFF] + 16 token bytes = 17 bytes
	pkt := make([]byte, 17)
	pkt[0] = 0xFF
	copy(pkt[1:], d.relayToken)

	// Send immediately on startup
	if _, err := conn.Write(pkt); err != nil {
		log.Printf("relay keepalive: initial write: %v", err)
	}

	ticker := time.NewTicker(relayKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := conn.Write(pkt); err != nil {
				log.Printf("relay keepalive: write: %v", err)
			}
		}
	}
}

// checkConnectivity inspects WireGuard handshake times and switches peers
// between direct and relay endpoints as needed.
func (d *Daemon) checkConnectivity() {
	stats, err := d.tunnel.GetPeerStats()
	if err != nil {
		log.Printf("connectivity check: %v", err)
		return
	}

	d.mu.RLock()
	peers := make(map[string]api.Peer, len(d.peersByKey))
	for k, v := range d.peersByKey {
		peers[k] = v
	}
	d.mu.RUnlock()

	for pubKey, peer := range peers {
		stat := stats[pubKey]
		noHandshake := stat.LastHandshakeTime.IsZero() ||
			time.Since(stat.LastHandshakeTime) > handshakeTimeout

		d.mu.RLock()
		usingRelay := d.usingRelay[pubKey]
		switchedAt := d.switchedToRelay[pubKey]
		d.mu.RUnlock()

		if noHandshake && !usingRelay && d.relayHost != "" {
			// No recent handshake → switch to relay
			if peer.RelayHost == "" || peer.RelayPort == 0 {
				continue // peer has no relay endpoint registered yet
			}
			relayEndpoint := peer.RelayHost + ":" + strconv.Itoa(peer.RelayPort)
			if err := d.tunnel.UpdatePeerEndpoint(pubKey, relayEndpoint); err != nil {
				log.Printf("switch to relay for %s: %v", pubKey[:8], err)
				continue
			}
			log.Printf("switching peer %s... to relay (%s)", pubKey[:8], relayEndpoint)
			d.mu.Lock()
			d.usingRelay[pubKey] = true
			d.switchedToRelay[pubKey] = time.Now()
			d.mu.Unlock()

		} else if !noHandshake && usingRelay {
			// Handshake is working and we've been on relay for at least 5 min;
			// attempt to return to direct.
			if time.Since(switchedAt) < relayBackoffDuration {
				continue
			}
			directEndpoint := ""
			if peer.Endpoint != nil {
				directEndpoint = *peer.Endpoint
			}
			if directEndpoint == "" {
				continue
			}
			if err := d.tunnel.UpdatePeerEndpoint(pubKey, directEndpoint); err != nil {
				log.Printf("switch to direct for %s: %v", pubKey[:8], err)
				continue
			}
			log.Printf("switching peer %s... back to direct (%s)", pubKey[:8], directEndpoint)
			d.mu.Lock()
			d.usingRelay[pubKey] = false
			delete(d.switchedToRelay, pubKey)
			d.mu.Unlock()
		}
	}
}

func (d *Daemon) syncPeers() {
	peers, err := d.client.GetPeers(d.cfg.NetworkID)
	if err != nil {
		log.Printf("peer sync failed: %v", err)
		return
	}

	d.storePeers(peers)

	d.mu.RLock()
	usingRelaySnapshot := make(map[string]bool, len(d.usingRelay))
	for k, v := range d.usingRelay {
		usingRelaySnapshot[k] = v
	}
	d.mu.RUnlock()

	var peerConfigs []wg.PeerConfig
	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		pc := wg.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{p.AssignedIP + "/32"},
		}
		// Preserve relay endpoint if currently active for this peer
		if usingRelaySnapshot[p.PublicKey] && p.RelayHost != "" && p.RelayPort != 0 {
			pc.Endpoint = p.RelayHost + ":" + strconv.Itoa(p.RelayPort)
		} else if p.Endpoint != nil {
			pc.Endpoint = *p.Endpoint
		}
		peerConfigs = append(peerConfigs, pc)
	}

	if err := d.tunnel.UpdatePeers(peerConfigs); err != nil {
		log.Printf("updating peers: %v", err)
	}
}

func (d *Daemon) storePeers(peers []api.Peer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		d.peersByKey[p.PublicKey] = p
	}
}

func (d *Daemon) buildTunnelConfig(peers []api.Peer) *wg.TunnelConfig {
	cfg := &wg.TunnelConfig{
		PrivateKey: d.cfg.PrivateKey,
		Address:    d.cfg.AssignedIP + "/24",
		ListenPort: 51820,
	}

	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		pc := wg.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{p.AssignedIP + "/32"},
		}
		if p.Endpoint != nil {
			pc.Endpoint = *p.Endpoint
		}
		cfg.Peers = append(cfg.Peers, pc)
	}

	return cfg
}

