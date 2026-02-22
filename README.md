# Shireguard

Shireguard is a peer-to-peer WireGuard VPN. Devices on your account connect directly to each other — no traffic is routed through a central server. When a direct connection isn't possible (e.g. both peers are behind NAT), Shireguard falls back to an encrypted relay automatically.

## Install

**macOS**

```sh
brew install doppiscantsleep/shireguard/shireguard
```

**Linux**

```sh
curl -sSL https://shireguard.com/install.sh | bash
```

## Get started

**1. Log in**

```sh
shireguard login
```

This opens your browser for Sign-In. The CLI waits and picks up the session automatically.

**2. Register this device**

```sh
shireguard register-device
```

Generates a WireGuard key pair, registers the device with your account, and assigns it a private IP on your network.

**3. Start the tunnel**

```sh
shireguard up
```

Brings up the WireGuard interface and connects to your peers. Runs as a background daemon.

**4. Check status**

```sh
shireguard status
```

Shows your assigned IP, connected peers, and their online/offline state.

**5. Stop the tunnel**

```sh
shireguard down
```

## macOS menu bar app

After installing via Homebrew, a menu bar app is available at:

```
/opt/homebrew/opt/shireguard/ShireguardMenuBar.app
```

It shows connection status in the menu bar, lets you connect/disconnect with one click, and sends a notification when the tunnel state changes. Drag it to your Applications folder to keep it handy.

## Commands

| Command | Description |
|---|---|
| `shireguard login` | Sign in (Apple, Google, or GitHub) |
| `shireguard register-device` | Register this machine on your network |
| `shireguard up` | Start the tunnel |
| `shireguard down` | Stop the tunnel |
| `shireguard status` | Show connection status and peers |
| `shireguard devices` | List all your registered devices |
| `shireguard logout` | Sign out and clear credentials |

## How it works

1. The control plane (hosted on Cloudflare Workers) handles authentication, device registration, and peer discovery.
2. Each device discovers its public endpoint via STUN and registers it with the control plane.
3. WireGuard attempts a direct peer-to-peer connection using those endpoints.
4. If the direct connection stalls (no handshake within 90 seconds), the client automatically switches to a relay server and punches through NAT. It switches back to direct when connectivity recovers.

Config and keys are stored in `~/.shireguard/config.json`.
