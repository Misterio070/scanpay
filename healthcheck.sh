#!/usr/bin/env bash
# ScanPay health check script.
set -euo pipefail

PORT="${1:-${SCANPAY_PORT:-8484}}"
HEALTH_URL="http://127.0.0.1:${PORT}/api/v1/health"

if curl -sf "$HEALTH_URL" 2>/dev/null; then
    exit 0
else
    echo "ScanPay health check FAILED at $HEALTH_URL"
    exit 1
fi