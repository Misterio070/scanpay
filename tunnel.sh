#!/usr/bin/env bash
# ScanPay Cloudflare tunnel setup and run script.
# Creates a STABLE named tunnel (not a Quick Tunnel).
#
# Prerequisites:
#   - cloudflared installed
#   - cloudflared login completed
#   - ScanPay running locally (./start.sh)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL_NAME="scanpay"
CONFIG_FILE="$SCRIPT_DIR/cloudflared.yml"
CREDS_DIR="$HOME/.cloudflared"

echo "ScanPay Cloudflare Tunnel Setup"
echo "================================"

# Check cloudflared
if ! command -v cloudflared &> /dev/null; then
    echo "ERROR: cloudflared not installed."
    echo "Install: winget install --id Cloudflare.cloudflared"
    echo "  or:    brew install cloudflared"
    exit 1
fi

# Check if tunnel already exists
TUNNEL_ID=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}' || echo "")

if [ -z "$TUNNEL_ID" ]; then
    echo "Creating tunnel '$TUNNEL_NAME'..."
    TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1 | grep -oP 'Created [^\s]+ tunnels' || echo "")
    if [ -z "$TUNNEL_ID" ]; then
        echo "ERROR: Failed to create tunnel. Is cloudflared logged in?"
        echo "Run: cloudflared tunnel login"
        exit 1
    fi
fi

echo "Tunnel ID: $TUNNEL_ID"
echo "Config: $CONFIG_FILE"
echo ""
echo "Next steps:"
echo "  1. Route DNS: cloudflared tunnel route dns $TUNNEL_NAME scanpay.yourdomain.com"
echo "  2. Update $CONFIG_FILE with the tunnel UUID and hostname"
echo "  3. Run: cloudflared tunnel run --config $CONFIG_FILE $TUNNEL_NAME"
echo ""
echo "This is a STABLE named tunnel — the hostname persists across restarts."
echo "A Quick Tunnel (cloudflared tunnel --url) is NOT suitable for production."