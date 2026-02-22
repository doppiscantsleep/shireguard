# ShireGuard - WireGuard P2P Engineer Memory

## Project Structure
- `client/` - Go client daemon (wireguard-go userspace TUN)
- `relay/` - Go UDP relay server (AWS Lightsail)
- `control-plane/` - Cloudflare Workers (IP assignment, relay discovery)

## Key Files
- `relay/internal/relay/server.go` - Relay slot management, UDP forwarding, port recycling
- `client/internal/daemon/daemon.go` - Daemon lifecycle, relay proxy, connectivity checks, STUN refresh
- `client/internal/wg/tunnel.go` - wireguard-go TUN wrapper (uses `conn.NewDefaultBind()`)
- `client/internal/nat/stun.go` - STUN endpoint discovery
- `client/cmd/shireguard/main.go` - CLI commands, daemonization (startDaemon)

## Architecture Decisions
- Relay uses per-device UDP slots (one port per registered device) with port recycling via freePorts
- Two peers converge on the relay port of the lower-IP device (sharedRelayEndpoint)
- "home" device runs local UDP proxy; "peer" device sends WireGuard directly to relay
- wireguard-go owns port 51820 exclusively; cannot share that socket
- `shireguard up` daemonizes by default (re-execs with --foreground, logs to /var/log/shireguard.log)
- STUN refresh every 5 min; uses ephemeral port + replaces port with 51820
- Subnet mask /16 matching 100.65.0.0/16 network CIDR

## Critical Bug Pattern: Separate Sockets = Separate NAT Mappings
Solution: local UDP proxy that multiplexes keepalive + WG data through one outbound socket.

## Relay Protocol
- Keepalive: `[0xFF][2 reserved bytes][16-byte token]` = 19 bytes
- homeAddr set from actual keepalive source address (NOT embedded port)
- Data forwarding: homeAddr <-> peerAddr, bidirectional
- Slot cleanup: 30 min inactivity, closes socket to unblock serve() goroutine
- Port recycling: evicted ports reused before incrementing nextPort

## Latest Release: v0.1.17
