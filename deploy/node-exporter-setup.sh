#!/usr/bin/env bash
# node-exporter-setup.sh — install Prometheus node_exporter on the relay server.
# Exposes system metrics (CPU, memory, network I/O, disk) on port 9100.
# Run via: make relay-node-exporter RELAY_HOST=ubuntu@<ip>

set -euo pipefail

VERSION="1.8.2"
ARCH="linux-amd64"
TARBALL="node_exporter-${VERSION}.${ARCH}.tar.gz"
URL="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/${TARBALL}"

SUDO=""
if [[ "$EUID" -ne 0 ]]; then
  SUDO="sudo"
fi

echo "==> Installing node_exporter ${VERSION}"

cd /tmp
wget -q --show-progress "$URL"
tar xzf "$TARBALL"
$SUDO install -m 755 "node_exporter-${VERSION}.${ARCH}/node_exporter" /usr/local/bin/node_exporter
rm -rf "node_exporter-${VERSION}.${ARCH}" "$TARBALL"
echo "    Binary installed: $(node_exporter --version 2>&1 | head -1)"

echo "==> Installing systemd service"
$SUDO tee /etc/systemd/system/node_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/node_exporter
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable --now node_exporter
echo "    Service started"

echo "==> Opening port 9100 in ufw"
if command -v ufw &>/dev/null; then
  $SUDO ufw allow 9100/tcp comment "Prometheus node_exporter"
  echo "    ufw: opened 9100/tcp"
else
  echo "    ufw not found — open port 9100/tcp manually"
fi

echo ""
echo "==> Done. Metrics available at http://$(hostname -I | awk '{print $1}'):9100/metrics"
echo ""
echo "    Add to your Prometheus config (prometheus.yml):"
echo ""
echo "    scrape_configs:"
echo "      - job_name: shireguard-relay"
echo "        static_configs:"
echo "          - targets: ['$(curl -s ifconfig.me):8080']  # relay app metrics"
echo "            labels: { instance: relay }"
echo "          - targets: ['$(curl -s ifconfig.me):9100']  # system metrics"
echo "            labels: { instance: relay }"
