# ScanPay — Code Security Scanner with x402 v2 Micropayments

> Deterministic AST-based security scanning for Python and JavaScript/TypeScript.
> No code execution. No AI inference. Just fast, reliable vulnerability detection.

## Features

- **45+ vulnerability patterns** across Python and JS/TS/TSX
- **Deterministic analysis** — same input always produces same output
- **x402 v2 payment protocol** — pay per scan with SOL on Solana
- **Dual language support** — Python (`ast` module) and JS/TS (tree-sitter)
- **No false AI hallucinations** — pure rule-based detection
- **FastAPI-powered** — sub-100ms scan latency

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the service (port 8484, payment disabled by default)
python main.py

# Health check
curl http://localhost:8484/api/v1/health

# List products
curl http://localhost:8484/api/v1/products

# Scan code (payment required in testnet/mainnet mode)
curl -X POST http://localhost:8484/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"source_code":"eval(userInput)","language":"python"}'
```

## Payment Flow (x402 v2)

1. Client requests scan → receives `402 Payment Required`
2. Client pays 0.0007 SOL (~$0.10) to merchant wallet via Solana
3. Client retries with `X-PAYMENT` header containing payment proof
4. Server verifies payment, runs scan, returns results

## Configuration

```bash
cp .env.example .env
# Edit .env to set payment mode, wallet, price
```

| Env Var | Default | Description |
|---|---|---|
| `SCANPAY_PAYMENT_MODE` | `disabled` | `disabled`, `testnet`, or `mainnet` |
| `SCANPAY_MERCHANT_WALLET` | (empty) | Solana wallet to receive payments |
| `SCANPAY_PRICE_LAMPORTS` | `700000` | Price in lamports (0.0007 SOL) |
| `SCANPAY_PORT` | `8484` | API server port |
| `SCANPAY_FREE_TRIAL_ENABLED` | `false` | Enable free trial scans |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service health check |
| `GET` | `/api/v1/products` | List available scan products |
| `POST` | `/api/v1/scan` | Scan code (payment required) |
| `GET` | `/api/v1/verify-payment/{tx}` | Verify Solana payment |

## Detected Vulnerabilities

### Python (22 rules)
`eval()`, `exec()`, `os.system()`, `subprocess`, `pickle.loads()`, `yaml.load()`, hardcoded secrets, SQL injection, command injection, path traversal, and more.

### JavaScript/TypeScript (23 rules)
`eval()`, `Function()`, `child_process`, `prototype pollution`, `vm` module, ReDoS, dynamic imports, deserialization, filesystem writes, network requests, and more.

## Testing

```bash
python -m pytest tests/ -q
# 75 tests, all passing
```

## Docker

```bash
docker-compose up
```

## License

MIT