package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RelaySlot represents one registered device's relay allocation.
// homeAddr is the registered device (set by keepalive).
// peerAddr is whoever else is sending to this slot (set dynamically).
// Packets from homeAddr are forwarded to peerAddr and vice versa.
type RelaySlot struct {
	mu       sync.Mutex
	token    [16]byte
	homeAddr *net.UDPAddr
	peerAddr *net.UDPAddr
	lastSeen time.Time
	metrics  *relayMetrics
}

type relayMetrics struct {
	slotsRegistered  prometheus.Counter
	slotsEvicted     prometheus.Counter
	keepalives       prometheus.Counter
	packetsForwarded prometheus.Counter
	bytesForwarded   prometheus.Counter
}

// RelayServer manages relay slots and HTTP registration.
type RelayServer struct {
	mu          sync.RWMutex
	slots       map[int]*RelaySlot // relay_port → slot
	tokenToPort map[string]int     // hex(token) → relay_port
	nextPort    int
	authToken   string // shared secret from --token flag
	host        string // public hostname/IP of this server
	metrics     *relayMetrics
}

// NewServer creates a RelayServer with the given public host, base UDP port, and auth token.
func NewServer(host string, udpBase int, authToken string, version, commit string) *RelayServer {
	m := &relayMetrics{
		slotsRegistered: promauto.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_slots_registered_total",
			Help: "Total relay slots registered since startup.",
		}),
		slotsEvicted: promauto.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_slots_evicted_total",
			Help: "Total relay slots evicted due to inactivity.",
		}),
		keepalives: promauto.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_keepalives_total",
			Help: "Total keepalive packets received.",
		}),
		packetsForwarded: promauto.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_packets_forwarded_total",
			Help: "Total UDP packets forwarded between peers.",
		}),
		bytesForwarded: promauto.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_bytes_forwarded_total",
			Help: "Total bytes forwarded between peers.",
		}),
	}

	// Build info — version/commit as labels, value always 1.
	promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "shireguard_relay_build_info",
		Help: "Relay build information.",
	}, []string{"version", "commit"}).With(prometheus.Labels{
		"version": version,
		"commit":  commit,
	}).Set(1)

	s := &RelayServer{
		slots:       make(map[int]*RelaySlot),
		tokenToPort: make(map[string]int),
		nextPort:    udpBase,
		authToken:   authToken,
		host:        host,
		metrics:     m,
	}

	// GaugeFuncs read live state at every Prometheus scrape.
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "shireguard_relay_active_slots",
			Help: "Current number of registered relay slots.",
		},
		func() float64 {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return float64(len(s.slots))
		},
	))
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "shireguard_relay_active_pairs",
			Help: "Relay slots where both the home and peer endpoints are established.",
		},
		func() float64 {
			s.mu.RLock()
			snapshot := make([]*RelaySlot, 0, len(s.slots))
			for _, sl := range s.slots {
				snapshot = append(snapshot, sl)
			}
			s.mu.RUnlock()
			var n int
			for _, sl := range snapshot {
				sl.mu.Lock()
				if sl.homeAddr != nil && sl.peerAddr != nil {
					n++
				}
				sl.mu.Unlock()
			}
			return float64(n)
		},
	))

	go s.cleanupLoop()
	return s
}

// ListenAndServe starts the HTTP server on the given address (e.g. ":8080").
func (s *RelayServer) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.Handle("GET /metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}

func (s *RelayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *RelayServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Validate auth token
	authHeader := r.Header.Get("Authorization")
	expected := "Bearer " + s.authToken
	if authHeader != expected {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var body struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeviceID == "" {
		http.Error(w, `{"error":"device_id required"}`, http.StatusBadRequest)
		return
	}

	// Generate 16-byte random token
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	tokenHex := hex.EncodeToString(token[:])

	// Allocate next port
	s.mu.Lock()
	port := s.nextPort
	s.nextPort++
	slot := &RelaySlot{token: token, metrics: s.metrics}
	s.slots[port] = slot
	s.tokenToPort[tokenHex] = port
	s.mu.Unlock()

	s.metrics.slotsRegistered.Inc()

	// Open UDP socket for this slot
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		s.mu.Lock()
		delete(s.slots, port)
		delete(s.tokenToPort, tokenHex)
		s.mu.Unlock()
		s.metrics.slotsRegistered.Add(-1) // undo
		http.Error(w, `{"error":"could not bind port"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("registered device %s on relay port %d", body.DeviceID, port)
	go slot.serve(conn)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"relay_host":  s.host,
		"relay_port":  port,
		"relay_token": tokenHex,
	})
}

// serve runs the per-device UDP relay loop.
//
// The slot owner ("home" device) maintains a local UDP proxy that sends both
// keepalive packets and WireGuard data through a single socket to this relay
// port. This ensures a single NAT mapping for both control and data traffic.
//
// Keepalive packets (0xFF prefix + 16-byte token) authenticate the home device
// and update homeAddr to the actual source address of the keepalive packet.
//
// All other packets are forwarded bidirectionally:
//   - Packets from homeAddr -> peerAddr
//   - Packets from anyone else -> homeAddr (sender becomes peerAddr)
func (slot *RelaySlot) serve(conn net.PacketConn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		if n == 19 && buf[0] == 0xFF && bytes.Equal(buf[3:19], slot.token[:]) {
			// Keepalive: [0xFF][2 reserved bytes][token 16 bytes]
			// Set homeAddr to the actual source address of the keepalive.
			// Since the client sends keepalives and WireGuard data through
			// the same local proxy socket, this address matches where data
			// packets from the home device will arrive from.
			slot.metrics.keepalives.Inc()
			slot.mu.Lock()
			prev := slot.homeAddr
			slot.homeAddr = &net.UDPAddr{IP: udpAddr.IP, Port: udpAddr.Port}
			slot.lastSeen = time.Now()
			slot.mu.Unlock()
			if prev == nil || !prev.IP.Equal(udpAddr.IP) || prev.Port != udpAddr.Port {
				log.Printf("relay port %s: homeAddr set to %s (from keepalive)", conn.LocalAddr(), udpAddr)
			}
		} else {
			// Data packet: bidirectional forwarding.
			// Packets from homeAddr -> peerAddr; packets from anyone else -> homeAddr.
			slot.mu.Lock()
			home := slot.homeAddr
			peer := slot.peerAddr
			fromHome := home != nil && udpAddr.IP.Equal(home.IP) && udpAddr.Port == home.Port
			var dst *net.UDPAddr
			if fromHome {
				dst = peer
			} else {
				slot.peerAddr = udpAddr
				dst = home
			}
			slot.mu.Unlock()
			log.Printf("relay port %s: pkt from %s fromHome=%v dst=%v len=%d", conn.LocalAddr(), udpAddr, fromHome, dst, n)
			if dst != nil {
				conn.WriteTo(buf[:n], dst)
				slot.metrics.packetsForwarded.Inc()
				slot.metrics.bytesForwarded.Add(float64(n))
			}
		}
	}
}

// cleanupLoop evicts slots that have not received a keepalive in 30 minutes.
func (s *RelayServer) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-30 * time.Minute)
		s.mu.Lock()
		for port, slot := range s.slots {
			slot.mu.Lock()
			stale := slot.lastSeen.Before(cutoff)
			slot.mu.Unlock()
			if stale {
				log.Printf("evicting stale relay slot on port %d", port)
				delete(s.slots, port)
				// Remove from token map
				tokenHex := hex.EncodeToString(slot.token[:])
				delete(s.tokenToPort, tokenHex)
				s.metrics.slotsEvicted.Inc()
			}
		}
		s.mu.Unlock()
	}
}
