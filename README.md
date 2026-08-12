# ScanPay — Paid Code Security Scanner with x402 v2 Payment

## What it is

ScanPay is an independent code security scanning API that uses deterministic
static analysis (no AI inference) to detect vulnerability patterns in Python
and JavaScript/TypeScript source code. Payment is discovered via the x402 v2
protocol (Solana devnet, payment-disabled by default).

## Status

- **Payment mode:** disabled (fail-closed default)
- **Products:** 2 (python-scan, js-scan) — both marked unavailable until payment path is verified
- **Revenue:** USD 0 (zero verified revenue)
- **Free trial:** disabled
- **Engine:** deterministic AST analysis, no code execution
- **Tests:** 75 passing (payment replay, network/amount/recipient binding, free-trial boundaries, request limits, scanner isolation, restart recovery)
- **Public endpoint:** live via Cloudflare Quick Tunnel (temporary URL; stable named tunnel requires Cloudflare account login — owner-only gate)

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the service (defaults to port 8484, payment disabled)
bash start.sh

# Health check
curl http://localhost:8484/api/v1/health

# Products
curl http://localhost:8484/api/v1/products

# Scan (will return 402 — payment required)
curl -X POST http://localhost:8484/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"source_code":"eval(\"x\")","language":"python"}'
```

## Public tunnel

```bash
# Quick Tunnel (temporary URL, no account needed)
~/cloudflared.exe tunnel --url http://localhost:8484

# Stable named tunnel (requires cloudflared login + Cloudflare domain)
# See cloudflared.yml and tunnel.sh for setup instructions
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Service health and configuration |
| GET | /api/v1/products | Available products (marked unavailable in disabled mode) |
| POST | /api/v1/scan | Scan code (x402 payment required) |
| GET | /api/v1/verify-payment/{tx_sig} | Verify a Solana payment (testnet/mainnet only) |

## Configuration

Copy `.env.example` to `.env` and configure. Key settings:

- `SCANPAY_PAYMENT_MODE`: disabled (default), testnet, or mainnet
- `SCANPAY_MERCHANT_WALLET`: Solana wallet address for receiving payments
- `SCANPAY_PRICE_LAMPORTS`: Price per scan in lamports (default: 10_000_000 = 0.01 SOL)
- `SCANPAY_PORT`: API server port (default: 8484)

## Owner-only gates

- Mainnet payment activation requires explicit owner authorization
- Stable Cloudflare named tunnel requires Cloudflare account login
- No real-value transfers without owner approval of network, asset, recipient, price, and caps