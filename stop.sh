#!/usr/bin/env bash
# ScanPay graceful stop script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.run/scanpay.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No PID file found. ScanPay may not be running."
    exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping ScanPay (PID $PID)..."
    kill "$PID"
    # Wait up to 10 seconds for graceful shutdown
    for i in $(seq 1 10); do
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "ScanPay stopped."
            rm -f "$PID_FILE"
            exit 0
        fi
        sleep 1
    done
    echo "Force stopping (PID $PID)..."
    kill -9 "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "ScanPay force-stopped."
else
    echo "PID $PID not alive. Removing stale PID file."
    rm -f "$PID_FILE"
fi