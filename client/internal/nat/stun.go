package nat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	stunServer     = "stun.l.google.com:19302"
	stunMagicCookie = uint32(0x2112A442)
	stunBindingRequest = uint16(0x0001)
	stunAttrXORMappedAddress = uint16(0x0020)
)

// DiscoverEndpoint sends a STUN binding request to stun.l.google.com:19302
// and returns the observed public "IP:port" string, or "" on failure.
// It first tries to bind to localPort (e.g. 51820) so the discovered external
// address matches WireGuard's actual UDP socket. Falls back to ephemeral port.
func DiscoverEndpoint(localPort int) string {
	// Try binding to the requested local port first
	if localPort > 0 {
		local := &net.UDPAddr{Port: localPort}
		conn, err := net.ListenUDP("udp", local)
		if err == nil {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			remote, err := net.ResolveUDPAddr("udp", stunServer)
			if err != nil {
				return ""
			}
			req := makeSTUNRequest()
			if _, err := conn.WriteTo(req, remote); err == nil {
				resp := make([]byte, 512)
				if n, _, err := conn.ReadFrom(resp); err == nil {
					if ep := parseXORMappedAddress(resp[:n], req[8:20]); ep != "" {
						return ep
					}
				}
			}
		}
	}

	// Fall back to ephemeral port
	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := makeSTUNRequest()
	if _, err := conn.Write(req); err != nil {
		return ""
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 20 {
		return ""
	}

	return parseXORMappedAddress(resp[:n], req[8:20])
}

// makeSTUNRequest builds a minimal 20-byte STUN binding request.
func makeSTUNRequest() []byte {
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // length
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	rand.Read(req[8:20]) // transaction ID
	return req
}

// parseXORMappedAddress extracts the XOR-MAPPED-ADDRESS from a STUN response.
func parseXORMappedAddress(resp, txID []byte) string {
	if len(resp) < 20 {
		return ""
	}

	// Skip 20-byte header, iterate attributes
	pos := 20
	for pos+4 <= len(resp) {
		attrType := binary.BigEndian.Uint16(resp[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(resp[pos+2 : pos+4]))
		pos += 4

		if pos+attrLen > len(resp) {
			break
		}

		if attrType == stunAttrXORMappedAddress && attrLen >= 8 {
			// Byte 0: reserved, Byte 1: family (0x01=IPv4)
			family := resp[pos+1]
			if family != 0x01 {
				// IPv6 not handled
				return ""
			}

			// XOR port with upper 2 bytes of magic cookie
			xorPort := binary.BigEndian.Uint16(resp[pos+2 : pos+4])
			port := xorPort ^ uint16(stunMagicCookie>>16)

			// XOR IP with magic cookie
			xorIP := resp[pos+4 : pos+8]
			magic := make([]byte, 4)
			binary.BigEndian.PutUint32(magic, stunMagicCookie)
			ip := net.IP{
				xorIP[0] ^ magic[0],
				xorIP[1] ^ magic[1],
				xorIP[2] ^ magic[2],
				xorIP[3] ^ magic[3],
			}

			return fmt.Sprintf("%s:%d", ip.String(), port)
		}

		// Attributes are padded to 4-byte boundaries
		pos += attrLen
		if attrLen%4 != 0 {
			pos += 4 - (attrLen % 4)
		}
	}

	return ""
}
