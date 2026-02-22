#!/bin/sh
set -e

REPO="doppiscantsleep/shireguard"
INSTALL_DIR="/usr/local/bin"
BINARY="shireguard"

# ── Checks ──────────────────────────────────────────────────────────────────

if [ "$(uname -s)" != "Linux" ]; then
  echo "This installer is for Linux only."
  echo "On macOS, install via Homebrew:"
  echo "  brew install doppiscantsleep/shireguard/shireguard"
  exit 1
fi

if ! command -v curl > /dev/null 2>&1; then
  echo "Error: curl is required. Install it with: sudo apt install curl"
  exit 1
fi

if ! command -v tar > /dev/null 2>&1; then
  echo "Error: tar is required. Install it with: sudo apt install tar"
  exit 1
fi

# ── Architecture ─────────────────────────────────────────────────────────────

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Shireguard supports linux/amd64 and linux/arm64."
    exit 1
    ;;
esac

# ── Latest version ───────────────────────────────────────────────────────────

echo "Fetching latest release..."
VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')"

if [ -z "$VERSION" ]; then
  echo "Error: could not determine latest version. Check your internet connection."
  exit 1
fi

echo "Latest version: $VERSION"

# ── Download ─────────────────────────────────────────────────────────────────

TARBALL="shireguard_linux_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $TARBALL..."
curl -fsSL "$URL" -o "$TMP/$TARBALL"

tar -xf "$TMP/$TARBALL" -C "$TMP"

# ── Install ───────────────────────────────────────────────────────────────────

echo "Installing to $INSTALL_DIR/$BINARY (requires sudo)..."
sudo install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"

# setcap allows shireguard to create TUN devices without running as root.
if command -v setcap > /dev/null 2>&1; then
  sudo setcap cap_net_admin+ep "$INSTALL_DIR/$BINARY"
else
  echo ""
  echo "Warning: setcap not found. Install libcap2-bin so shireguard can create TUN devices:"
  echo "  sudo apt install libcap2-bin"
  echo "  sudo setcap cap_net_admin+ep $INSTALL_DIR/$BINARY"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "Shireguard $VERSION installed successfully."
echo ""
echo "Next steps:"
echo "  shireguard login           # Sign in via browser"
echo "  shireguard register-device # Register this machine"
echo "  shireguard up              # Start the tunnel"
echo ""
echo "To start automatically on boot:"
echo "  sudo shireguard install-service"
