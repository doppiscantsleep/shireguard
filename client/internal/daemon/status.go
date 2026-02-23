package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/shireguard/shireguard/internal/api"
	"github.com/shireguard/shireguard/internal/config"
	"github.com/shireguard/shireguard/internal/wg"
)

// DaemonStatus is the JSON response for GET /status on the Unix socket.
type DaemonStatus struct {
	Version       string       `json:"version"`
	UptimeSeconds int64        `json:"uptime_seconds"`
	AssignedIP    string       `json:"assigned_ip"`
	Interface     string       `json:"interface"`
	StunEndpoint  string       `json:"stun_endpoint"`
	Relay         *RelayStatus `json:"relay,omitempty"`
	Peers         []PeerStatus `json:"peers"`
}

// RelayStatus describes the current relay connection.
type RelayStatus struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	ProxyAddr string `json:"proxy_addr"`
	Connected bool   `json:"connected"`
}

// PeerStatus describes the live state of a single peer.
type PeerStatus struct {
	Name                string     `json:"name"`
	Platform            string     `json:"platform"`
	AssignedIP          string     `json:"assigned_ip"`
	PublicKey           string     `json:"public_key"`
	ConnectionType      string     `json:"connection_type"` // "direct" or "relay"
	Endpoint            string     `json:"endpoint"`
	LastHandshake       *time.Time `json:"last_handshake,omitempty"`
	HandshakeAgeSeconds int64      `json:"handshake_age_seconds"`
	TxBytes             int64      `json:"tx_bytes"`
	RxBytes             int64      `json:"rx_bytes"`
}

type peerSnapshot struct {
	peer       api.Peer
	usingRelay bool
}

func (d *Daemon) statusHandler(w http.ResponseWriter, r *http.Request) {
	// Get live peer stats — not an error if tunnel isn't up yet.
	peerStats, _ := d.tunnel.GetPeerStats()
	if peerStats == nil {
		peerStats = make(map[string]wg.PeerStat)
	}

	d.stunMu.RLock()
	stunEndpoint := d.stunEndpoint
	d.stunMu.RUnlock()

	d.mu.RLock()
	relayHost := d.relayHost
	relayPort := d.relayPort
	relayProxyAddr := d.relayProxyAddr
	snapshots := make([]peerSnapshot, 0, len(d.peersByKey))
	for _, p := range d.peersByKey {
		snapshots = append(snapshots, peerSnapshot{
			peer:       p,
			usingRelay: d.usingRelay[p.PublicKey],
		})
	}
	d.mu.RUnlock()

	peerStatuses := make([]PeerStatus, 0, len(snapshots))
	for _, snap := range snapshots {
		stat := peerStats[snap.peer.PublicKey]
		ps := PeerStatus{
			Name:       snap.peer.Name,
			Platform:   snap.peer.Platform,
			AssignedIP: snap.peer.AssignedIP,
			PublicKey:  snap.peer.PublicKey,
			Endpoint:   stat.Endpoint,
			TxBytes:    stat.TxBytes,
			RxBytes:    stat.RxBytes,
		}
		if snap.usingRelay {
			ps.ConnectionType = "relay"
		} else {
			ps.ConnectionType = "direct"
		}
		if !stat.LastHandshakeTime.IsZero() {
			t := stat.LastHandshakeTime
			ps.LastHandshake = &t
			ps.HandshakeAgeSeconds = int64(time.Since(stat.LastHandshakeTime).Seconds())
		}
		peerStatuses = append(peerStatuses, ps)
	}

	var relay *RelayStatus
	if relayHost != "" {
		relay = &RelayStatus{
			Host:      relayHost,
			Port:      relayPort,
			ProxyAddr: relayProxyAddr,
			Connected: relayProxyAddr != "",
		}
	}

	status := DaemonStatus{
		Version:       d.Version,
		UptimeSeconds: int64(time.Since(d.startedAt).Seconds()),
		AssignedIP:    d.cfg.AssignedIP,
		Interface:     d.tunnel.Name(),
		StunEndpoint:  stunEndpoint,
		Relay:         relay,
		Peers:         peerStatuses,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

// startSocketServer starts an HTTP server over a Unix domain socket at the
// path returned by config.SocketFile(). It exposes a single route:
//
//	GET /status → DaemonStatus JSON
//
// The server shuts down when ctx is cancelled.
func (d *Daemon) startSocketServer(ctx context.Context) {
	sockPath, err := config.SocketFile()
	if err != nil {
		return
	}

	// Remove stale socket from a previous run.
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", d.statusHandler)
	srv := &http.Server{Handler: mux}

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background()) //nolint:errcheck
		os.Remove(sockPath)                //nolint:errcheck
	}()

	srv.Serve(ln) //nolint:errcheck
}
