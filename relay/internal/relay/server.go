package relay

import (
	"crypto/rand"
	"crypto/subtle"
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
	conn     net.PacketConn // owned UDP socket; closed by cleanupLoop on eviction
	token    [16]byte
	deviceID string
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
	mu           sync.RWMutex
	slots        map[int]*RelaySlot // relay_port → slot
	tokenToPort  map[string]int     // hex(token) → relay_port
	deviceToPort map[string]int     // device_id → relay_port (prevents slot leak on reconnect)
	udpBase      int                // first UDP port in the relay range
	nextPort     int
	freePorts    []int  // evicted ports available for reuse
	authToken    string // shared secret from --token flag
	host         string // public hostname/IP of this server
	metrics      *relayMetrics
	registry     *prometheus.Registry // per-server registry (avoids global conflicts in tests)
}

// NewServer creates a RelayServer with the given public host, base UDP port, and auth token.
func NewServer(host string, udpBase int, authToken string, version, commit string) *RelayServer {
	// Use a per-server registry so multiple servers can be created in tests
	// without triggering "duplicate metrics collector" panics on the global registry.
	reg := prometheus.NewRegistry()
	factory := promauto.With(reg)

	m := &relayMetrics{
		slotsRegistered: factory.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_slots_registered_total",
			Help: "Total relay slots registered since startup.",
		}),
		slotsEvicted: factory.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_slots_evicted_total",
			Help: "Total relay slots evicted due to inactivity.",
		}),
		keepalives: factory.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_keepalives_total",
			Help: "Total keepalive packets received.",
		}),
		packetsForwarded: factory.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_packets_forwarded_total",
			Help: "Total UDP packets forwarded between peers.",
		}),
		bytesForwarded: factory.NewCounter(prometheus.CounterOpts{
			Name: "shireguard_relay_bytes_forwarded_total",
			Help: "Total bytes forwarded between peers.",
		}),
	}

	// Build info — version/commit as labels, value always 1.
	factory.NewGaugeVec(prometheus.GaugeOpts{
		Name: "shireguard_relay_build_info",
		Help: "Relay build information.",
	}, []string{"version", "commit"}).With(prometheus.Labels{
		"version": version,
		"commit":  commit,
	}).Set(1)

	s := &RelayServer{
		slots:        make(map[int]*RelaySlot),
		tokenToPort:  make(map[string]int),
		deviceToPort: make(map[string]int),
		udpBase:      udpBase,
		nextPort:     udpBase,
		authToken:    authToken,
		host:         host,
		metrics:      m,
		registry:     reg,
	}

	// GaugeFuncs read live state at every Prometheus scrape.
	reg.MustRegister(prometheus.NewGaugeFunc(
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
	reg.MustRegister(prometheus.NewGaugeFunc(
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
// If certFile and keyFile are non-empty, it starts a TLS server instead.
func (s *RelayServer) ListenAndServe(addr, certFile, keyFile string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /metrics", s.requireAuth(promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}).ServeHTTP))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if certFile != "" && keyFile != "" {
		log.Printf("TLS enabled: cert=%s key=%s", certFile, keyFile)
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

func (s *RelayServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := []byte("Bearer " + s.authToken)
		actual := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(actual, expected) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *RelayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

// statusResponse is the JSON body returned by GET /status.
type statusResponse struct {
	ActiveSlots    int     `json:"active_slots"`
	RecycledFree   int     `json:"recycled_free"`
	Capacity       int     `json:"capacity"`
	UtilizationPct float64 `json:"utilization_pct"`
	Warning        string  `json:"warning,omitempty"`
}

const slotCapacity = 1000 // firewall allows 1000 UDP ports (udpBase through udpBase+999)

func (s *RelayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	active := len(s.slots)
	recycled := len(s.freePorts)
	s.mu.RUnlock()

	utilPct := float64(active) / float64(slotCapacity) * 100

	resp := statusResponse{
		ActiveSlots:    active,
		RecycledFree:   recycled,
		Capacity:       slotCapacity,
		UtilizationPct: utilPct,
	}
	if utilPct > 80 {
		resp.Warning = fmt.Sprintf("relay at %.0f%% capacity — %d/%d slots in use", utilPct, active, slotCapacity)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *RelayServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Validate auth token
	authHeader := r.Header.Get("Authorization")
	expected := "Bearer " + s.authToken
	if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expected)) != 1 {
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

	// Allocate port — prefer recycled ports to prevent unbounded growth.
	// If this device already has a slot, evict it first so we don't leak ports.
	s.mu.Lock()
	if oldPort, exists := s.deviceToPort[body.DeviceID]; exists {
		if oldSlot, ok := s.slots[oldPort]; ok {
			if oldSlot.conn != nil {
				oldSlot.conn.Close() // unblocks the serve() goroutine
			}
			oldTokenHex := hex.EncodeToString(oldSlot.token[:])
			delete(s.tokenToPort, oldTokenHex)
			delete(s.slots, oldPort)
			s.freePorts = append(s.freePorts, oldPort)
			log.Printf("evicted previous slot for device %s on port %d (re-registration)", body.DeviceID, oldPort)
		}
		delete(s.deviceToPort, body.DeviceID)
	}
	var port int
	if len(s.freePorts) > 0 {
		port = s.freePorts[len(s.freePorts)-1]
		s.freePorts = s.freePorts[:len(s.freePorts)-1]
	} else {
		port = s.nextPort
		s.nextPort++
	}
	slot := &RelaySlot{token: token, deviceID: body.DeviceID, metrics: s.metrics}
	s.slots[port] = slot
	s.tokenToPort[tokenHex] = port
	s.deviceToPort[body.DeviceID] = port
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
	slot.conn = conn // store so cleanupLoop can close it on eviction

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

		if n == 19 && buf[0] == 0xFF && subtle.ConstantTimeCompare(buf[3:19], slot.token[:]) == 1 {
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
		s.evictStale(time.Now().Add(-30 * time.Minute))
	}
}

// evictStale removes all slots whose lastSeen is before cutoff.
// Separated from cleanupLoop so it can be called directly in tests.
func (s *RelayServer) evictStale(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for port, slot := range s.slots {
		slot.mu.Lock()
		stale := slot.lastSeen.Before(cutoff)
		slot.mu.Unlock()
		if stale {
			log.Printf("evicting stale relay slot on port %d (recycling)", port)
			// Close the socket — unblocks serve()'s ReadFrom so the
			// goroutine exits cleanly. The deferred conn.Close() in
			// serve() is a no-op on an already-closed conn.
			if slot.conn != nil {
				slot.conn.Close()
			}
			delete(s.slots, port)
			tokenHex := hex.EncodeToString(slot.token[:])
			delete(s.tokenToPort, tokenHex)
			if slot.deviceID != "" {
				delete(s.deviceToPort, slot.deviceID)
			}
			s.freePorts = append(s.freePorts, port) // recycle for reuse
			s.metrics.slotsEvicted.Inc()
		}
	}
}
