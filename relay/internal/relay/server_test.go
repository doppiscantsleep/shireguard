package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer creates a RelayServer using a unique UDP base port for the test.
// Using distinct base ports per test avoids port conflicts when tests run in parallel.
func newTestServer(t *testing.T, udpBase int) *RelayServer {
	t.Helper()
	return NewServer("127.0.0.1", udpBase, "testtoken", "test", "none")
}

// registerDevice calls handleRegister and returns the allocated relay_port and relay_token.
func registerDevice(t *testing.T, srv *RelayServer, deviceID string) (port int, tokenHex string) {
	t.Helper()
	body := fmt.Sprintf(`{"device_id":%q}`, deviceID)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer testtoken")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleRegister(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("register: decode response: %v", err)
	}
	port = int(resp["relay_port"].(float64))
	tokenHex = resp["relay_token"].(string)
	return
}

func TestRegistration_ReturnsValidResponse(t *testing.T) {
	srv := newTestServer(t, 55000)

	port, tokenHex := registerDevice(t, srv, "device-001")

	if port != 55000 {
		t.Errorf("expected port 55000, got %d", port)
	}
	if len(tokenHex) != 32 {
		t.Errorf("expected 32-char hex token, got len %d: %q", len(tokenHex), tokenHex)
	}
	// Token must be valid hex
	if _, err := hex.DecodeString(tokenHex); err != nil {
		t.Errorf("token is not valid hex: %v", err)
	}
}

func TestRegistration_RejectsWrongAuthToken(t *testing.T) {
	srv := newTestServer(t, 55010)

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"device_id":"x"}`))
	req.Header.Set("Authorization", "Bearer wrongtoken")
	w := httptest.NewRecorder()
	srv.handleRegister(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestRegistration_RejectsMissingDeviceID(t *testing.T) {
	srv := newTestServer(t, 55020)

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	srv.handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRegistration_AllocatesSequentialPorts(t *testing.T) {
	srv := newTestServer(t, 55030)

	port1, _ := registerDevice(t, srv, "device-A")
	port2, _ := registerDevice(t, srv, "device-B")

	if port1 != 55030 {
		t.Errorf("expected first port 55030, got %d", port1)
	}
	if port2 != 55031 {
		t.Errorf("expected second port 55031, got %d", port2)
	}
}

func TestForwarding_KeepaliveSetshomeAddr(t *testing.T) {
	srv := newTestServer(t, 55040)
	port, tokenHex := registerDevice(t, srv, "device-home")

	tokenBytes, _ := hex.DecodeString(tokenHex)
	relayAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))

	// Send keepalive from a home socket
	homeConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer homeConn.Close()

	keepalive := make([]byte, 19)
	keepalive[0] = 0xFF
	copy(keepalive[3:], tokenBytes)
	homeConn.WriteTo(keepalive, relayAddr)

	time.Sleep(50 * time.Millisecond)

	// Verify homeAddr was set on the slot
	srv.mu.RLock()
	slot := srv.slots[port]
	srv.mu.RUnlock()
	if slot == nil {
		t.Fatal("slot not found after keepalive")
	}

	slot.mu.Lock()
	home := slot.homeAddr
	slot.mu.Unlock()

	if home == nil {
		t.Fatal("homeAddr not set after keepalive")
	}
	homePort := homeConn.LocalAddr().(*net.UDPAddr).Port
	if home.Port != homePort {
		t.Errorf("homeAddr port = %d, want %d", home.Port, homePort)
	}
}

func TestForwarding_BidirectionalPackets(t *testing.T) {
	srv := newTestServer(t, 55060)
	port, tokenHex := registerDevice(t, srv, "device-bidi")

	tokenBytes, _ := hex.DecodeString(tokenHex)
	relayAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))

	homeConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer homeConn.Close()
	peerConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer peerConn.Close()

	// 1. Home sends keepalive so relay learns homeAddr
	keepalive := make([]byte, 19)
	keepalive[0] = 0xFF
	copy(keepalive[3:], tokenBytes)
	homeConn.WriteTo(keepalive, relayAddr)
	time.Sleep(50 * time.Millisecond)

	// 2. Peer sends a data packet → relay forwards to home
	msg := []byte("hello from peer")
	peerConn.WriteTo(msg, relayAddr)

	homeConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, _, err := homeConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("home did not receive peer's packet: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("home received %q, want %q", buf[:n], msg)
	}

	// 3. Home sends a data packet → relay forwards to peer
	reply := []byte("hello from home")
	homeConn.WriteTo(reply, relayAddr)

	peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err = peerConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("peer did not receive home's packet: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("peer received %q, want %q", buf[:n], reply)
	}
}

func TestEviction_StaleSlotIsRecycled(t *testing.T) {
	srv := newTestServer(t, 55080)
	port, _ := registerDevice(t, srv, "device-stale")

	// Backdate lastSeen so the slot appears stale
	srv.mu.RLock()
	slot := srv.slots[port]
	srv.mu.RUnlock()

	slot.mu.Lock()
	slot.lastSeen = time.Now().Add(-31 * time.Minute)
	slot.mu.Unlock()

	srv.evictStale(time.Now().Add(-30 * time.Minute))

	srv.mu.RLock()
	_, still := srv.slots[port]
	freeLen := len(srv.freePorts)
	srv.mu.RUnlock()

	if still {
		t.Error("stale slot was not evicted")
	}
	if freeLen == 0 {
		t.Error("evicted port was not added to freePorts for recycling")
	}
}

func TestEviction_PortIsReusedAfterEviction(t *testing.T) {
	srv := newTestServer(t, 55090)

	// Register and evict first device
	port1, _ := registerDevice(t, srv, "device-evicted")

	srv.mu.RLock()
	slot := srv.slots[port1]
	srv.mu.RUnlock()
	slot.mu.Lock()
	slot.lastSeen = time.Now().Add(-31 * time.Minute)
	slot.mu.Unlock()

	srv.evictStale(time.Now().Add(-30 * time.Minute))

	// Second registration should reuse the evicted port
	port2, _ := registerDevice(t, srv, "device-new")
	if port2 != port1 {
		t.Errorf("expected recycled port %d, got %d", port1, port2)
	}
}

func TestStatus_ReportsActiveSlots(t *testing.T) {
	srv := newTestServer(t, 55100)
	registerDevice(t, srv, "device-status-1")
	registerDevice(t, srv, "device-status-2")

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	srv.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp statusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /status: %v", err)
	}

	if resp.ActiveSlots != 2 {
		t.Errorf("active_slots = %d, want 2", resp.ActiveSlots)
	}
	if resp.Capacity != slotCapacity {
		t.Errorf("capacity = %d, want %d", resp.Capacity, slotCapacity)
	}
	if resp.UtilizationPct <= 0 {
		t.Error("utilization_pct should be > 0")
	}
}
