#!/usr/bin/env bash
# relay-setup.sh — run once on a fresh Ubuntu VPS (Lightsail, Hetzner, etc.)
# Usage: bash relay-setup.sh <public-ip-or-hostname> <relay-token>
#
# Example:
#   bash relay-setup.sh 1.2.3.4 $(openssl rand -hex 24)
#
# Can be run as root or as a sudo-capable user (e.g. ubuntu on Lightsail).

set -euo pipefail

RELAY_HOST="${1:-}"
RELAY_TOKEN="${2:-}"

if [[ -z "$RELAY_HOST" || -z "$RELAY_TOKEN" ]]; then
  echo "Usage: $0 <public-ip-or-hostname> <relay-token>" >&2
  exit 1
fi

RELAY_HTTP_PORT="${RELAY_HTTP_PORT:-8080}"
RELAY_UDP_BASE="${RELAY_UDP_BASE:-51821}"
RELAY_UDP_END="${RELAY_UDP_END:-52820}"   # 1000 device slots
SERVICE_FILE="/etc/systemd/system/shireguard-relay.service"
CONFIG_FILE="/etc/shireguard-relay"

# Use sudo when not already root
SUDO=""
if [[ "$EUID" -ne 0 ]]; then
  SUDO="sudo"
fi

echo "==> Setting up shireguard relay on $RELAY_HOST"

# 1. Create system user (idempotent)
if ! id shireguard-relay &>/dev/null; then
  $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin shireguard-relay
  echo "    Created user: shireguard-relay"
else
  echo "    User shireguard-relay already exists"
fi

# 2. Write config file (mode 640, owned by root:shireguard-relay)
$SUDO tee "$CONFIG_FILE" > /dev/null <<EOF
RELAY_HOST=$RELAY_HOST
RELAY_TOKEN=$RELAY_TOKEN
RELAY_HTTP_PORT=$RELAY_HTTP_PORT
RELAY_UDP_BASE=$RELAY_UDP_BASE
EOF
$SUDO chmod 640 "$CONFIG_FILE"
$SUDO chown root:shireguard-relay "$CONFIG_FILE"
echo "    Wrote $CONFIG_FILE"

# 3. Install systemd service (binary is deployed separately via 'make relay-deploy')
$SUDO cp /tmp/shireguard-relay.service "$SERVICE_FILE"
$SUDO systemctl daemon-reload
$SUDO systemctl enable shireguard-relay
echo "    Installed and enabled systemd service"

# 4. OS-level firewall (ufw)
# Note: on Lightsail you also need to open ports in the Lightsail console
# or with: make relay-lightsail-firewall LIGHTSAIL_INSTANCE=<name>
if command -v ufw &>/dev/null; then
  $SUDO ufw allow "${RELAY_HTTP_PORT}/tcp"  comment "shireguard relay HTTP"
  $SUDO ufw allow "${RELAY_UDP_BASE}:${RELAY_UDP_END}/udp" comment "shireguard relay UDP"
  echo "    Opened ports $RELAY_HTTP_PORT/tcp and $RELAY_UDP_BASE-$RELAY_UDP_END/udp in ufw"
else
  echo "    ufw not found — open these ports manually:"
  echo "      TCP $RELAY_HTTP_PORT"
  echo "      UDP $RELAY_UDP_BASE-$RELAY_UDP_END"
fi

echo ""
echo "==> Setup complete."
echo ""
echo "    Next steps:"
echo "    1. make relay-deploy          RELAY_HOST=ubuntu@$RELAY_HOST"
echo "    2. make relay-lightsail-firewall LIGHTSAIL_INSTANCE=<name>   # Lightsail only"
echo "    3. make relay-register        RELAY_HOST=$RELAY_HOST RELAY_TOKEN=<token>"
echo "    4. make cp-migrate && make cp-deploy"
echo ""
echo "    Monitor: ssh ubuntu@$RELAY_HOST sudo journalctl -u shireguard-relay -f"
