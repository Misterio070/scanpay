#!/usr/bin/env bash
# ScanPay local startup script with PID management and health checks.
# Usage: ./start.sh [port]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-${SCANPAY_PORT:-8484}}"
PID_FILE="$SCRIPT_DIR/.run/scanpay.pid"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/scanpay.log"
HEALTH_URL="http://127.0.0.1:${PORT}/api/v1/health"

mkdir -p "$LOG_DIR" .run

# Check if already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "ScanPay already running (PID $PID) on port $PORT"
        echo "Health: $HEALTH_URL"
        exit 0
    else
        echo "Stale PID file found (PID $PID not alive). Removing."
        rm -f "$PID_FILE"
    fi
fi

# Default to disabled payment mode if not set
export SCANPAY_PAYMENT_MODE="${SCANPAY_PAYMENT_MODE:-disabled}"
export SCANPAY_PORT="$PORT"

echo "Starting ScanPay on port $PORT (payment_mode=$SCANPAY_PAYMENT_MODE)"
echo "Log: $LOG_FILE"

# Start uvicorn in background
python -m uvicorn main:app --host 0.0.0.0 --port "$PORT" >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

# Wait for health check (max 15 seconds)
echo "Waiting for health check..."
for i in $(seq 1 15); do
    if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        echo "ScanPay is healthy (PID $SERVER_PID) on port $PORT"
        echo "Health: $HEALTH_URL"
        echo "PID file: $PID_FILE"
        exit 0
    fi
    sleep 1
done

echo "ERROR: ScanPay did not become healthy within 15 seconds."
echo "Last 20 lines of log:"
tail -20 "$LOG_FILE"
kill "$SERVER_PID" 2>/dev/null || true
rm -f "$PID_FILE"
exit 1