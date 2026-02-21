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
func DiscoverEndpoint() string {
	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build minimal STUN binding request (20-byte header)
	// Message Type: 0x0001 (Binding Request)
	// Message Length: 0x0000 (no attributes)
	// Magic Cookie: 0x2112A442
	// Transaction ID: 12 random bytes
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // length
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	rand.Read(req[8:20]) // transaction ID

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
