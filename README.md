# ScanPay — Code Security Scanner with x402 v2 Micropayments

![npm version](https://img.shields.io/npm/v/scanpay-cli.svg)
![npm downloads](https://img.shields.io/npm/dm/scanpay-cli.svg)
![GitHub](https://img.shields.io/github/stars/Misterio070/scanpay.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> Deterministic AST-based security scanning for Python and JavaScript/TypeScript.
> No code execution. No AI inference. Just fast, reliable vulnerability detection.
> Pay per scan with Solana micropayments — $0.10/scan.

## 🎯 What It Does

ScanPay analyzes source code for security vulnerabilities using deterministic AST parsing. No AI, no code execution — just fast, reliable pattern matching that catches 45+ vulnerability classes before code runs.

Built for **AI agents** that generate code: scan before execution, block dangerous patterns, log audit trails.

## ✨ Features

- **45+ vulnerability patterns** across Python and JS/TS/TSX
- **Deterministic analysis** — same input always produces same output
- **x402 v2 payment protocol** — pay per scan with SOL on Solana
- **Dual language support** — Python (`ast` module) and JS/TS (tree-sitter)
- **No false AI hallucinations** — pure rule-based detection
- **FastAPI-powered** — sub-100ms scan latency
- **SARIF output** — industry-standard vulnerability report format
- **Batch scanning** — scan multiple files in one request

## 🚀 Quick Start

### Using the Live API (testnet)

```bash
# Health check
curl https://repository-nil-camcorder-divx.trycloudflare.com/api/v1/health

# List available products
curl https://repository-nil-camcorder-divx.trycloudflare.com/api/v1/products

# Scan code (requires payment)
curl -X POST https://repository-nil-camcorder-divx.trycloudflare.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"source_code":"eval(userInput)","language":"python"}'
# → 402 Payment Required (0.0007 SOL)
```

### Self-Host

```bash
git clone https://github.com/Misterio070/scanpay.git
cd scanpay
pip install -r requirements.txt
python main.py
# → http://localhost:8484
```

## 💳 Payment Flow (x402 v2)

1. Client requests scan → receives `402 Payment Required`
2. Client pays **0.0007 SOL** (~$0.10) to merchant wallet via Solana
3. Client retries with `X-PAYMENT` header containing payment proof
4. Server verifies payment on-chain, runs scan, returns results

**Merchant wallet:** `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`

## 🤖 For AI Agents (MCP Server)

ScanPay includes an MCP server for AI agents to scan code before execution:

```json
{
  "mcpServers": {
    "scanpay": {
      "command": "npx",
      "args": ["-y", "scanpay-cli", "scanpay-mcp"],
      "env": { "SCANPAY_URL": "https://repository-nil-camcorder-divx.trycloudflare.com" }
    }
  }
}
```

Agents call `scan_code` to check code for vulnerabilities before running it.
**Network:** Solana testnet (mainnet coming soon)

## 📋 Configuration

```bash
cp .env.example .env
```

| Env Var | Default | Description |
|---------|---------|-------------|
| `SCANPAY_PAYMENT_MODE` | `disabled` | `disabled`, `testnet`, or `mainnet` |
| `SCANPAY_MERCHANT_WALLET` | — | Solana wallet address |
| `SCANPAY_PRICE_LAMPORTS` | `700000` | Price in lamports (0.0007 SOL) |
| `SCANPAY_RPC_URL` | `https://api.devnet.solana.com` | Solana RPC endpoint |
| `SCANPAY_PORT` | `8484` | Server port |

## 🧪 Detected Vulnerabilities

### Python
- `eval()` / `exec()` — code injection
- `subprocess` with `shell=True` — command injection
- `pickle.loads()` — deserialization attacks
- `os.system()` — command injection
- SQL injection patterns
- Path traversal (`../`)
- Hardcoded credentials
- And more...

### JavaScript/TypeScript
- `eval()` — code injection
- `innerHTML` — XSS
- `document.write()` — XSS
- `new Function()` — code injection
- SQL injection patterns
- Prototype pollution
- And more...

## 📊 API Reference

### `GET /api/v1/health`
Returns service status and configuration.

### `GET /api/v1/products`
Returns available scan products and pricing.

### `POST /api/v1/scan`
Scans source code for vulnerabilities. Requires payment in testnet/mainnet mode.

**Request:**
```json
{
  "source_code": "eval(userInput)",
  "language": "python"
}
```

**Response (200):**
```json
{
  "status": "ok",
  "findings": [
    {
      "rule": "PY001",
      "severity": "critical",
      "message": "Use of eval() detected — code injection risk",
      "line": 1
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## 🤝 Built For

- **AI Agents** — scan generated code before execution
- **CI/CD Pipelines** — pre-deployment security gate
- **IDE Extensions** — real-time vulnerability detection
- **Code Review** — automated security audit

## 📄 License

MIT

## 🔗 Links

- [GitHub](https://github.com/Misterio070/scanpay)
- [x402 Protocol](https://x402.org)
- [Solana](https://solana.com)