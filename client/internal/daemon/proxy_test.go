package daemon

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/shireguard/shireguard/internal/config"
)

// newProxyDaemon returns a minimal Daemon configured to proxy through fakeRelayAddr.
func newProxyDaemon(t *testing.T, fakeRelayAddr *net.UDPAddr) *Daemon {
	t.Helper()
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return &Daemon{
		cfg:        &config.Config{},
		relayHost:  "127.0.0.1",
		relayPort:  fakeRelayAddr.Port,
		relayToken: token[:],
	}
}

// startFakeRelay starts a UDP listener acting as the relay server.
// Returns the listener and its address.
func startFakeRelay(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startFakeRelay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestRelayProxy_SendsInitialKeepalive(t *testing.T) {
	fakeRelay := startFakeRelay(t)
	relayAddr := fakeRelay.LocalAddr().(*net.UDPAddr)

	d := newProxyDaemon(t, relayAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, _, err := d.startRelayProxy(ctx)
	if err != nil {
		t.Fatalf("startRelayProxy: %v", err)
	}

	// Relay should immediately receive a keepalive
	fakeRelay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	n, _, err := fakeRelay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay did not receive initial keepalive: %v", err)
	}
	if n != 19 {
		t.Errorf("keepalive length = %d, want 19", n)
	}
	if buf[0] != 0xFF {
		t.Errorf("keepalive[0] = 0x%02x, want 0xFF", buf[0])
	}
	expectedToken := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if !bytes.Equal(buf[3:19], expectedToken[:]) {
		t.Error("keepalive token mismatch")
	}
}

func TestRelayProxy_ForwardsWireGuardPacketsToRelay(t *testing.T) {
	fakeRelay := startFakeRelay(t)
	relayAddr := fakeRelay.LocalAddr().(*net.UDPAddr)

	d := newProxyDaemon(t, relayAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddrStr, _, err := d.startRelayProxy(ctx)
	if err != nil {
		t.Fatalf("startRelayProxy: %v", err)
	}

	// Drain the initial keepalive
	fakeRelay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	fakeRelay.ReadFrom(make([]byte, 64))

	// Simulate WireGuard sending a packet to the proxy
	proxyAddr, _ := net.ResolveUDPAddr("udp", proxyAddrStr)
	wgConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer wgConn.Close()

	testPkt := []byte("wireguard data packet")
	wgConn.WriteTo(testPkt, proxyAddr)

	// Relay should receive the forwarded packet
	fakeRelay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, _, err := fakeRelay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay did not receive forwarded packet: %v", err)
	}
	if !bytes.Equal(buf[:n], testPkt) {
		t.Errorf("relay received %q, want %q", buf[:n], testPkt)
	}
}

func TestRelayProxy_DeliverRelayPacketsToWireGuard(t *testing.T) {
	fakeRelay := startFakeRelay(t)
	relayAddr := fakeRelay.LocalAddr().(*net.UDPAddr)

	d := newProxyDaemon(t, relayAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddrStr, _, err := d.startRelayProxy(ctx)
	if err != nil {
		t.Fatalf("startRelayProxy: %v", err)
	}

	// Drain initial keepalive and learn proxy's outbound address
	fakeRelay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	fakeRelay.ReadFrom(buf)

	// WireGuard sends a packet through the proxy (establishes wgAddr on the proxy)
	proxyAddr, _ := net.ResolveUDPAddr("udp", proxyAddrStr)
	wgConn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer wgConn.Close()

	wgConn.WriteTo([]byte("wg out"), proxyAddr)

	// Drain the forwarded packet at relay and note the proxy's source address
	fakeRelay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, proxyOutboundAddr, err := fakeRelay.ReadFrom(buf)
	if err != nil || n == 0 {
		t.Fatalf("relay did not receive forwarded wg packet: %v", err)
	}

	// Relay sends a response back to the proxy
	reply := []byte("relay response data")
	fakeRelay.WriteTo(reply, proxyOutboundAddr)

	// WireGuard conn should receive the reply
	wgConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err = wgConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("wgConn did not receive relay response: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Errorf("wgConn received %q, want %q", buf[:n], reply)
	}
}

func TestRelayProxy_CancelledContextShutsDown(t *testing.T) {
	fakeRelay := startFakeRelay(t)
	relayAddr := fakeRelay.LocalAddr().(*net.UDPAddr)

	d := newProxyDaemon(t, relayAddr)
	ctx, cancel := context.WithCancel(context.Background())

	_, done, err := d.startRelayProxy(ctx)
	if err != nil {
		t.Fatalf("startRelayProxy: %v", err)
	}

	cancel()

	select {
	case <-done:
		// proxy goroutines exited cleanly
	case <-time.After(2 * time.Second):
		t.Error("proxy goroutines did not exit within 2s after context cancel")
	}
}
