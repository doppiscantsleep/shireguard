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
)

// RelaySlot represents one registered device's relay allocation.
type RelaySlot struct {
	mu       sync.Mutex
	token    [16]byte
	realAddr *net.UDPAddr
	lastSeen time.Time
}

// RelayServer manages relay slots and HTTP registration.
type RelayServer struct {
	mu          sync.RWMutex
	slots       map[int]*RelaySlot // relay_port → slot
	tokenToPort map[string]int     // hex(token) → relay_port
	nextPort    int
	authToken   string // shared secret from --token flag
	host        string // public hostname/IP of this server
}

// NewServer creates a RelayServer with the given public host, base UDP port, and auth token.
func NewServer(host string, udpBase int, authToken string) *RelayServer {
	s := &RelayServer{
		slots:       make(map[int]*RelaySlot),
		tokenToPort: make(map[string]int),
		nextPort:    udpBase,
		authToken:   authToken,
		host:        host,
	}
	go s.cleanupLoop()
	return s
}

// ListenAndServe starts the HTTP server on the given address (e.g. ":8080").
func (s *RelayServer) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /register", s.handleRegister)
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
	slot := &RelaySlot{token: token}
	s.slots[port] = slot
	s.tokenToPort[tokenHex] = port
	s.mu.Unlock()

	// Open UDP socket for this slot
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		s.mu.Lock()
		delete(s.slots, port)
		delete(s.tokenToPort, tokenHex)
		s.mu.Unlock()
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
// Keepalive packets (0xFF prefix + 16-byte token) update the device's real address.
// All other packets are forwarded to the device's last-known real address.
func (slot *RelaySlot) serve(conn net.PacketConn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}

		if n == 17 && buf[0] == 0xFF && bytes.Equal(buf[1:17], slot.token[:]) {
			// Keepalive: update the device's real address
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			slot.mu.Lock()
			slot.realAddr = udpAddr
			slot.lastSeen = time.Now()
			slot.mu.Unlock()
		} else {
			// Data packet: forward to the device's registered address
			slot.mu.Lock()
			dst := slot.realAddr
			slot.mu.Unlock()
			if dst != nil {
				conn.WriteTo(buf[:n], dst)
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
			}
		}
		s.mu.Unlock()
	}
}
