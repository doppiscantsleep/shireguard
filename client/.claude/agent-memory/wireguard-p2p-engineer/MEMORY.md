# ShireGuard Client - WireGuard P2P Engineer Memory

## Key Architecture
- wireguard-go with `conn.NewDefaultBind()` on port 51820 (exclusive bind)
- Local relay proxy bridges keepalive + WireGuard data through single outbound UDP socket
- Proxy listens on `127.0.0.1:0` (random port), WireGuard endpoint set to proxy addr when home device

## Relay Proxy Design (daemon.go: startRelayProxy)
- Two goroutines: relay->local and local->relay+keepalive
- Uses 1s read deadline on local socket for select-based multiplexing
- Tracks WireGuard device local addr from first received packet

## Same-Public-IP Scenario
Both peers behind same NAT need relay. Relay distinguishes them by full IP:port.
Home device uses local proxy; peer device sends directly to relay.
