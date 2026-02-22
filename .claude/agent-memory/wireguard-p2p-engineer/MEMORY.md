# ShireGuard - WireGuard P2P Engineer Memory

## Project Structure
- `client/` - Go client daemon (wireguard-go userspace TUN)
- `relay/` - Go UDP relay server (AWS Lightsail)
- `control-plane/` - Cloudflare Workers (IP assignment, relay discovery)

## Key Files
- `relay/internal/relay/server.go` - Relay slot management, UDP forwarding
- `client/internal/daemon/daemon.go` - Daemon lifecycle, relay proxy, connectivity checks
- `client/internal/wg/tunnel.go` - wireguard-go TUN wrapper (uses `conn.NewDefaultBind()`)
- `client/internal/nat/stun.go` - STUN endpoint discovery

## Architecture Decisions
- Relay uses per-device UDP slots (one port per registered device)
- Two peers converge on the relay port of the lower-IP device (sharedRelayEndpoint)
- The "home" device (slot owner) runs a local UDP proxy on localhost to bridge keepalive and WireGuard data through ONE outbound socket, ensuring a single NAT mapping
- The "peer" device sends WireGuard directly to the relay (no proxy needed)
- wireguard-go owns port 51820 exclusively; cannot share that socket

## Critical Bug Pattern: Separate Sockets = Separate NAT Mappings
If keepalives and WireGuard data go through different sockets, they get different NAT mappings. The relay cannot match them. Solution: local UDP proxy that multiplexes both through one outbound socket.

## Relay Protocol
- Keepalive: `[0xFF][2 reserved bytes][16-byte token]` = 19 bytes
- homeAddr set from actual keepalive source address (NOT embedded port)
- Data forwarding: homeAddr <-> peerAddr, bidirectional
