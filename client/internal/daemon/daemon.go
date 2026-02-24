package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
	"github.com/shireguard/shireguard/internal/nat"
	"github.com/shireguard/shireguard/internal/wg"
)

const (
	heartbeatInterval      = 30 * time.Second
	peerSyncInterval       = 15 * time.Second
	connectivityInterval   = 10 * time.Second
	relayKeepaliveInterval = 25 * time.Second
	handshakeTimeout       = 90 * time.Second
	relayBackoffDuration   = 5 * time.Minute
	relayReconnectBackoff  = 5 * time.Second
	relayReconnectAttempts = 3
)

type Daemon struct {
	cfg      *config.Config
	client   *api.Client
	tunnel   *wg.Tunnel
	startedAt time.Time
	Version   string

	// Relay registration for this device
	relayHost  string
	relayPort  int
	relayToken []byte // 16 raw bytes

	// Local relay proxy address ("127.0.0.1:<port>") — set when proxy is running.
	relayProxyAddr string

	// STUN-discovered public endpoint, refreshed every 5 minutes.
	stunMu       sync.RWMutex
	stunEndpoint string

	// Peer state (keyed by base64 public key)
	mu              sync.RWMutex
	peersByKey      map[string]api.Peer // pubKey → peer (includes relay info)
	usingRelay      map[string]bool     // pubKey → true when relay is active
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
		startedAt:       time.Now(),
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
	// Called before tunnel.Up() so port 51820 is still free to bind.
	initialEndpoint := nat.DiscoverEndpoint(51820)
	if initialEndpoint != "" {
		slog.Info("STUN discovered endpoint", "endpoint", initialEndpoint)
	} else {
		slog.Warn("STUN discovery failed, proceeding without public endpoint")
	}
	d.stunMu.Lock()
	d.stunEndpoint = initialEndpoint
	d.stunMu.Unlock()

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

	slog.Info("tunnel up", "ip", d.cfg.AssignedIP, "peers", len(tunnelCfg.Peers))

	go d.startSocketServer(ctx)

	// Probe each peer immediately so WireGuard initiates handshakes now
	// rather than waiting up to 25 s for the first periodic keepalive.
	for _, p := range tunnelCfg.Peers {
		go triggerHandshake(strings.SplitN(p.AllowedIPs[0], "/", 2)[0])
	}

	// 4. Send initial heartbeat with discovered endpoint
	if err := d.client.Heartbeat(d.cfg.DeviceID, d.stunEndpoint); err != nil {
		slog.Error("initial heartbeat failed", "err", err)
	}

	// 4b. Sync advertised routes and enable IP forwarding if needed
	if len(d.cfg.AdvertiseRoutes) > 0 {
		if err := wg.EnableForwarding(); err != nil {
			slog.Error("failed to enable IP forwarding", "err", err)
		} else {
			slog.Info("IP forwarding enabled for subnet routing")
		}
		d.syncAdvertisedRoutes()
	}

	// 5. Register with relay and watch for failures (best-effort)
	go d.relayManager(ctx)

	// 6. Run background loops
	go d.stunRefreshLoop(ctx)

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	peerSyncTicker := time.NewTicker(peerSyncInterval)
	checkConnTicker := time.NewTicker(connectivityInterval)
	defer heartbeatTicker.Stop()
	defer peerSyncTicker.Stop()
	defer checkConnTicker.Stop()

	heartbeatFailures := 0
	peerSyncFailures := 0

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down tunnel")
			return nil

		case <-heartbeatTicker.C:
			d.stunMu.RLock()
			endpoint := d.stunEndpoint
			d.stunMu.RUnlock()
			if err := d.client.Heartbeat(d.cfg.DeviceID, endpoint); err != nil {
				heartbeatFailures++
				slog.Error("heartbeat failed", "attempts", heartbeatFailures, "err", err)
				heartbeatTicker.Reset(backoffDuration(heartbeatInterval, heartbeatFailures))
			} else if heartbeatFailures > 0 {
				heartbeatFailures = 0
				heartbeatTicker.Reset(heartbeatInterval)
			}

		case <-peerSyncTicker.C:
			if err := d.syncPeers(); err != nil {
				peerSyncFailures++
				slog.Error("peer sync failed", "attempts", peerSyncFailures, "err", err)
				peerSyncTicker.Reset(backoffDuration(peerSyncInterval, peerSyncFailures))
			} else if peerSyncFailures > 0 {
				peerSyncFailures = 0
				peerSyncTicker.Reset(peerSyncInterval)
			}

		case <-checkConnTicker.C:
			d.checkConnectivity()
		}
	}
}

// triggerHandshake sends a single probe packet to the peer's WireGuard IP,
// causing wireguard-go to initiate a handshake immediately rather than waiting
// for the next periodic keepalive (up to 25 s away). The packet is discarded
// by the peer — we only care that WireGuard starts the handshake exchange.
func triggerHandshake(peerWGIP string) {
	conn, err := net.DialTimeout("udp", peerWGIP+":1", time.Second)
	if err != nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	conn.Write([]byte{0})
	conn.Close()
}

// backoffDuration returns base * 2^failures, capped at 5 minutes.
func backoffDuration(base time.Duration, failures int) time.Duration {
	d := base
	for i := 0; i < failures; i++ {
		d *= 2
		if d > 5*time.Minute {
			return 5 * time.Minute
		}
	}
	return d
}

// relayManager registers this device with the relay, then watches for proxy
// failure and reconnects with exponential backoff (up to 3 attempts).
// If all reconnect attempts fail, relay is disabled for this daemon session.
func (d *Daemon) relayManager(ctx context.Context) {
	died := d.setupRelayOnce(ctx)
	if died == nil {
		return // initial setup failed; relay unavailable
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-died:
		}

		if ctx.Err() != nil {
			return
		}

		slog.Warn("relay proxy died, attempting reconnection")

		backoff := relayReconnectBackoff
		var newDied <-chan struct{}
		for attempt := 1; attempt <= relayReconnectAttempts; attempt++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			newDied = d.setupRelayOnce(ctx)
			if newDied != nil {
				slog.Info("relay reconnected", "attempt", attempt)
				d.updateRelayEndpoints()
				break
			}
			slog.Error("relay reconnect attempt failed", "attempt", attempt, "of", relayReconnectAttempts)
			backoff *= 2
		}

		if newDied == nil {
			slog.Error("relay reconnection exhausted, relay unavailable until daemon restart")
			d.clearRelayFallback()
			return
		}

		died = newDied
	}
}

// setupRelayOnce registers this device with the relay, stores the result, and
// starts the local relay proxy. Returns the proxy's done channel (closed when
// the proxy exits), or nil if any step fails.
func (d *Daemon) setupRelayOnce(ctx context.Context) <-chan struct{} {
	reg, err := d.client.RegisterDeviceWithRelay(d.cfg.DeviceID)
	if err != nil {
		slog.Error("relay registration failed", "err", err)
		return nil
	}

	tokenBytes, err := hex.DecodeString(reg.RelayToken)
	if err != nil || len(tokenBytes) != 16 {
		slog.Error("invalid relay token", "err", err)
		return nil
	}

	d.relayHost = reg.RelayHost
	d.relayPort = reg.RelayPort
	d.relayToken = tokenBytes

	slog.Info("registered with relay", "host", reg.RelayHost, "port", reg.RelayPort)

	// Store relay endpoint in control plane so peers can discover us
	if err := d.client.StoreRelayEndpoint(d.cfg.DeviceID, reg.RelayHost, reg.RelayPort); err != nil {
		slog.Error("storing relay endpoint failed", "err", err)
	}

	// Start a local UDP proxy that bridges WireGuard and the relay through
	// a single outbound socket.
	proxyAddr, died, err := d.startRelayProxy(ctx)
	if err != nil {
		slog.Error("relay proxy failed to start", "err", err)
		return nil
	}
	d.relayProxyAddr = proxyAddr
	slog.Info("relay proxy listening", "addr", proxyAddr)

	return died
}

// updateRelayEndpoints re-applies relay WireGuard endpoints for all peers
// currently using relay. Called after the relay proxy reconnects with a new
// proxy address.
func (d *Daemon) updateRelayEndpoints() {
	d.mu.RLock()
	peers := make(map[string]api.Peer, len(d.peersByKey))
	for k, v := range d.peersByKey {
		peers[k] = v
	}
	usingRelaySnap := make(map[string]bool, len(d.usingRelay))
	for k, v := range d.usingRelay {
		usingRelaySnap[k] = v
	}
	d.mu.RUnlock()

	for pubKey, peer := range peers {
		if !usingRelaySnap[pubKey] {
			continue
		}
		newEndpoint := d.sharedRelayEndpoint(peer)
		if err := d.tunnel.UpdatePeerEndpoint(pubKey, newEndpoint); err != nil {
			slog.Error("updating relay endpoint after reconnect", "peer", pubKey[:8], "err", err)
		} else {
			slog.Info("updated relay endpoint after reconnect", "peer", pubKey[:8], "endpoint", newEndpoint)
			go triggerHandshake(peer.AssignedIP)
		}
	}
}

// clearRelayFallback clears all relay state so peers fall back to direct
// connection. Called when relay reconnection is exhausted.
func (d *Daemon) clearRelayFallback() {
	d.mu.Lock()
	d.relayHost = ""
	d.relayPort = 0
	d.relayToken = nil
	d.relayProxyAddr = ""
	for k := range d.usingRelay {
		d.usingRelay[k] = false
	}
	d.mu.Unlock()
}

// stunRefreshLoop periodically re-discovers the public endpoint via STUN and
// sends a heartbeat immediately if the endpoint has changed. After tunnel.Up()
// port 51820 is owned by wireguard-go, so we use an ephemeral port for STUN
// and replace the discovered port with WireGuard's fixed listen port (51820).
func (d *Daemon) stunRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Use ephemeral port (0) since WireGuard owns 51820.
			raw := nat.DiscoverEndpoint(0)
			if raw == "" {
				continue
			}
			// Replace the STUN-assigned port with WireGuard's listen port.
			host, _, err := net.SplitHostPort(raw)
			if err != nil {
				continue
			}
			endpoint := net.JoinHostPort(host, "51820")

			d.stunMu.Lock()
			changed := endpoint != d.stunEndpoint
			d.stunEndpoint = endpoint
			d.stunMu.Unlock()

			if changed {
				slog.Info("STUN endpoint changed, sending heartbeat", "endpoint", endpoint)
				if err := d.client.Heartbeat(d.cfg.DeviceID, endpoint); err != nil {
					slog.Error("heartbeat after STUN change failed", "err", err)
				}
			}
		}
	}
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
// peer endpoint when relaying through this device's slot, and a channel that
// is closed when the forwarding goroutine (G2) has exited.
func (d *Daemon) startRelayProxy(ctx context.Context) (string, <-chan struct{}, error) {
	// Outbound socket to relay server (single NAT mapping for keepalive + data)
	relayAddr := fmt.Sprintf("%s:%d", d.relayHost, d.relayPort)
	remoteAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return "", nil, fmt.Errorf("resolving relay address %s: %w", relayAddr, err)
	}
	outbound, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return "", nil, fmt.Errorf("dialing relay %s: %w", relayAddr, err)
	}

	// Local listener for WireGuard traffic
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		outbound.Close()
		return "", nil, fmt.Errorf("listening on localhost: %w", err)
	}

	localAddr := local.LocalAddr().String()

	// Build keepalive packet: [0xFF][0x00][0x00][token 16 bytes] = 19 bytes
	keepalive := make([]byte, 19)
	keepalive[0] = 0xFF
	keepalive[1] = 0x00
	keepalive[2] = 0x00
	copy(keepalive[3:], d.relayToken)

	// Send initial keepalive
	if _, err := outbound.Write(keepalive); err != nil {
		slog.Error("relay proxy: initial keepalive failed", "err", err)
	}

	// Track the WireGuard device's local address (set on first packet from it)
	var wgAddr *net.UDPAddr
	var wgAddrMu sync.Mutex

	// Shared cancellation: any goroutine exiting cancels the others.
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	done := make(chan struct{})

	// Context watcher: close sockets when the proxy context is cancelled so
	// that G1 (blocked on outbound.Read) and G2 (blocked on local.ReadFrom)
	// both unblock and exit promptly.
	go func() {
		<-proxyCtx.Done()
		outbound.Close()
		local.Close()
	}()

	// G1: relay → local WireGuard
	go func() {
		defer proxyCancel()
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

	// G2: local WireGuard → relay (pure blocking read; no keepalive logic here)
	go func() {
		defer proxyCancel()
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := local.ReadFrom(buf)
			if err != nil {
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
				return
			}
		}
	}()

	// G3: keepalive sender — fires independently of data forwarding so the
	// keepalive interval is always honoured regardless of traffic volume.
	go func() {
		ticker := time.NewTicker(relayKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-proxyCtx.Done():
				return
			case <-ticker.C:
				if _, err := outbound.Write(keepalive); err != nil {
					proxyCancel() // trigger socket cleanup
					return
				}
			}
		}
	}()

	return localAddr, done, nil
}

// checkConnectivity inspects WireGuard handshake times and switches peers
// between direct and relay endpoints as needed.
func (d *Daemon) checkConnectivity() {
	stats, err := d.tunnel.GetPeerStats()
	if err != nil {
		slog.Error("connectivity check failed", "err", err)
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
			if peer.RelayHost == "" || peer.RelayPort == 0 {
				continue // peer hasn't registered with relay yet
			}
			relayEndpoint := d.sharedRelayEndpoint(peer)
			if err := d.tunnel.UpdatePeerEndpoint(pubKey, relayEndpoint); err != nil {
				slog.Error("switch to relay failed", "peer", pubKey[:8], "err", err)
				continue
			}
			slog.Info("switching peer to relay", "peer", pubKey[:8], "endpoint", relayEndpoint)
			d.mu.Lock()
			d.usingRelay[pubKey] = true
			d.switchedToRelay[pubKey] = time.Now()
			d.mu.Unlock()
			go triggerHandshake(peer.AssignedIP)

		} else if !noHandshake && usingRelay {
			// Handshake is working; attempt to return to direct after backoff.
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
				slog.Error("switch to direct failed", "peer", pubKey[:8], "err", err)
				continue
			}
			slog.Info("switching peer back to direct", "peer", pubKey[:8], "endpoint", directEndpoint)
			d.mu.Lock()
			d.usingRelay[pubKey] = false
			delete(d.switchedToRelay, pubKey)
			d.mu.Unlock()
			go triggerHandshake(peer.AssignedIP)
		}
	}
}

func (d *Daemon) syncPeers() error {
	peers, err := d.client.GetPeers(d.cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("getting peers: %w", err)
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
		// If this device accepts routes, append approved subnet routes for this peer
		// (skip 0.0.0.0/0 — exit node support is not yet implemented).
		if d.cfg.AcceptRoutes {
			for _, route := range p.AdvertisedRoutes {
				if route != "0.0.0.0/0" {
					pc.AllowedIPs = append(pc.AllowedIPs, route)
				}
			}
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
		return fmt.Errorf("updating peers in tunnel: %w", err)
	}
	return nil
}

// syncAdvertisedRoutes ensures all locally-configured routes are advertised to
// the control plane. Idempotent — 409 (already exists) is silently ignored.
func (d *Daemon) syncAdvertisedRoutes() {
	if len(d.cfg.AdvertiseRoutes) == 0 {
		return
	}
	for _, cidr := range d.cfg.AdvertiseRoutes {
		_, err := d.client.AdvertiseRoute(d.cfg.NetworkID, d.cfg.DeviceID, cidr, "")
		if err != nil {
			if apiErr, ok := err.(*api.APIError); ok && apiErr.Status == 409 {
				slog.Debug("route already advertised", "cidr", cidr)
				continue
			}
			slog.Error("failed to advertise route", "cidr", cidr, "err", err)
		} else {
			slog.Info("advertised route (pending approval)", "cidr", cidr)
		}
	}
}

func (d *Daemon) storePeers(peers []api.Peer) {
	newPeers := make(map[string]api.Peer, len(peers))
	for _, p := range peers {
		if p.ID == d.cfg.DeviceID {
			continue
		}
		newPeers[p.PublicKey] = p
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Clean up relay state for peers that no longer exist
	for pubKey := range d.peersByKey {
		if _, stillPresent := newPeers[pubKey]; !stillPresent {
			delete(d.usingRelay, pubKey)
			delete(d.switchedToRelay, pubKey)
		}
	}
	d.peersByKey = newPeers
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
		Address:    d.cfg.AssignedIP + "/16",
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
		if d.cfg.AcceptRoutes {
			for _, route := range p.AdvertisedRoutes {
				if route != "0.0.0.0/0" {
					pc.AllowedIPs = append(pc.AllowedIPs, route)
				}
			}
		}
		if p.Endpoint != nil {
			pc.Endpoint = *p.Endpoint
		}
		cfg.Peers = append(cfg.Peers, pc)
	}

	return cfg
}
