#!/usr/bin/env bash
# build-menubar-app.sh — builds shireguard-menubar and wraps it into
# ShireguardMenuBar.app for macOS.
#
# Usage:
#   bash scripts/build-menubar-app.sh [output-dir]
#
# The .app bundle is written to output-dir (default: dist/).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/client"

OUTPUT_DIR="${1:-$REPO_ROOT/dist}"
APP_NAME="ShireguardMenuBar"
BUNDLE="$OUTPUT_DIR/$APP_NAME.app"
BINARY_NAME="shireguard-menubar"

echo "Building $BINARY_NAME binary..."
cd "$CLIENT_DIR"
CGO_ENABLED=1 go build -o "$OUTPUT_DIR/$BINARY_NAME" ./cmd/shireguard-menubar/

echo "Creating app bundle at $BUNDLE..."
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS"
mkdir -p "$BUNDLE/Contents/Resources"

# Copy binary
cp "$OUTPUT_DIR/$BINARY_NAME" "$BUNDLE/Contents/MacOS/$BINARY_NAME"

# Write Info.plist
# LSUIElement=1 suppresses the Dock icon (agent app).
cat > "$BUNDLE/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>ShireguardMenuBar</string>
    <key>CFBundleDisplayName</key>
    <string>Shireguard</string>
    <key>CFBundleIdentifier</key>
    <string>com.shireguard.menubar</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>shireguard-menubar</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# Copy .icns if present
ICNS="$REPO_ROOT/assets/AppIcon.icns"
if [[ -f "$ICNS" ]]; then
    cp "$ICNS" "$BUNDLE/Contents/Resources/AppIcon.icns"
    # Reference it in the plist
    /usr/libexec/PlistBuddy -c \
        "Add :CFBundleIconFile string AppIcon" \
        "$BUNDLE/Contents/Info.plist" 2>/dev/null || true
fi

echo "Done: $BUNDLE"
echo "Run with: open \"$BUNDLE\""
