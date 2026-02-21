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

	// Local relay proxy: a UDP proxy on localhost that bridges WireGuard
	// traffic and keepalives through a single socket to the relay server.
	// This ensures the keepalive and data packets share one NAT mapping.
	relayProxyAddr string // "127.0.0.1:<port>" — set when proxy is running

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

	// 1. Discover public endpoint via STUN, binding to WireGuard's port (51820)
	// so the discovered external port matches what WireGuard will actually use.
	stunEndpoint := nat.DiscoverEndpoint(51820)
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
// with the relay server, stores the result, and starts the local relay proxy.
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

	// Start a local UDP proxy that bridges WireGuard and the relay through
	// a single outbound socket. This ensures keepalives and data share one
	// NAT mapping, so the relay can forward return traffic correctly.
	proxyAddr, err := d.startRelayProxy(ctx)
	if err != nil {
		log.Printf("relay proxy failed to start: %v", err)
		return
	}
	d.relayProxyAddr = proxyAddr
	log.Printf("relay proxy listening on %s", proxyAddr)
}

// startRelayProxy creates a local UDP proxy that:
//  1. Listens on a random localhost port for WireGuard data from the local
//     wireguard-go device.
//  2. Connects to the relay server from a single outbound socket.
//  3. Sends periodic keepalive packets to the relay through that socket.
//  4. Forwards WireGuard packets from localhost to the relay and back.
//
// Because keepalives and WireGuard data share the same outbound socket,
// they share the same NAT mapping. The relay sets homeAddr to this socket's
// public address, and all forwarded packets return through the same NAT hole.
//
// Returns the "127.0.0.1:<port>" address that WireGuard should use as the
// peer endpoint when relaying through this device's slot.
func (d *Daemon) startRelayProxy(ctx context.Context) (string, error) {
	// Outbound socket to relay server (single NAT mapping for keepalive + data)
	relayAddr := fmt.Sprintf("%s:%d", d.relayHost, d.relayPort)
	remoteAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return "", fmt.Errorf("resolving relay address %s: %w", relayAddr, err)
	}
	outbound, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return "", fmt.Errorf("dialing relay %s: %w", relayAddr, err)
	}

	// Local listener for WireGuard traffic
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		outbound.Close()
		return "", fmt.Errorf("listening on localhost: %w", err)
	}

	localAddr := local.LocalAddr().String()

	// Build keepalive packet: [0xFF][0x00][0x00][token 16 bytes] = 19 bytes
	// The two reserved bytes after 0xFF are no longer used for port embedding.
	keepalive := make([]byte, 19)
	keepalive[0] = 0xFF
	keepalive[1] = 0x00
	keepalive[2] = 0x00
	copy(keepalive[3:], d.relayToken)

	// Send initial keepalive
	if _, err := outbound.Write(keepalive); err != nil {
		log.Printf("relay proxy: initial keepalive: %v", err)
	}

	// Track the WireGuard device's local address (set on first packet from it)
	var wgAddr *net.UDPAddr
	var wgAddrMu sync.Mutex

	// Goroutine: relay -> local WireGuard
	go func() {
		defer local.Close()
		defer outbound.Close()
		buf := make([]byte, 1500)
		for {
			n, err := outbound.Read(buf)
			if err != nil {
				return
			}
			wgAddrMu.Lock()
			dst := wgAddr
			wgAddrMu.Unlock()
			if dst != nil {
				local.WriteTo(buf[:n], dst)
			}
		}
	}()

	// Goroutine: local WireGuard -> relay + periodic keepalives
	go func() {
		ticker := time.NewTicker(relayKeepaliveInterval)
		defer ticker.Stop()

		// Set a read deadline so we can check ctx and send keepalives
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				local.Close()
				outbound.Close()
				return
			case <-ticker.C:
				if _, err := outbound.Write(keepalive); err != nil {
					log.Printf("relay proxy: keepalive: %v", err)
				}
			default:
				local.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, addr, err := local.ReadFrom(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				// Remember the WireGuard device's address for return traffic
				if udpAddr, ok := addr.(*net.UDPAddr); ok {
					wgAddrMu.Lock()
					wgAddr = udpAddr
					wgAddrMu.Unlock()
				}
				// Forward to relay
				if _, err := outbound.Write(buf[:n]); err != nil {
					log.Printf("relay proxy: forward to relay: %v", err)
				}
			}
		}
	}()

	return localAddr, nil
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
			// No recent handshake → switch to relay.
			// Both devices must use the same relay port so each has a NAT hole
			// for it. Use the relay port of whichever device has the lower IP.
			if peer.RelayHost == "" || peer.RelayPort == 0 {
				continue // peer hasn't registered with relay yet
			}
			relayEndpoint := d.sharedRelayEndpoint(peer)
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
		if usingRelaySnapshot[p.PublicKey] && d.relayHost != "" && d.relayPort != 0 {
			pc.Endpoint = d.sharedRelayEndpoint(p)
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

// sharedRelayEndpoint returns the endpoint that WireGuard should use to reach
// the given peer via relay. Both devices converge on the same relay port
// (belonging to the device with the lower WireGuard IP).
//
// If this device is the "home" device for the chosen relay slot (i.e., our IP
// is lower), WireGuard sends to the local relay proxy instead of directly to
// the relay. The proxy bridges traffic through a single outbound socket that
// also handles keepalives, ensuring they share one NAT mapping.
//
// If this device is the "peer" for the slot (our IP is higher), WireGuard
// sends directly to the relay. The relay learns our address from the data
// packets and the NAT mapping is maintained by WireGuard's own packets.
func (d *Daemon) sharedRelayEndpoint(peer api.Peer) string {
	myIP := net.ParseIP(d.cfg.AssignedIP)
	peerIP := net.ParseIP(peer.AssignedIP)
	if netIPLess(myIP, peerIP) {
		// My IP is lower — use my relay port. Route through local proxy
		// so keepalives and data share the same NAT mapping.
		if d.relayProxyAddr != "" {
			return d.relayProxyAddr
		}
		return d.relayHost + ":" + strconv.Itoa(d.relayPort)
	}
	// Peer's IP is lower — use peer's relay port directly.
	// We are the "peer" for this slot; the relay will learn our address
	// from our WireGuard packets.
	return peer.RelayHost + ":" + strconv.Itoa(peer.RelayPort)
}

// netIPLess returns true if a < b (IPv4 comparison).
func netIPLess(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}
	return false
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

