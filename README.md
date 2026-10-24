# ScanPay — Code Security Scanner & Guardrail Oracle for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Engine Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://scanpay-ob3w.onrender.com/api/v1/health)
[![x402 Conformance](https://img.shields.io/badge/x402-v2_Compliant-green.svg)](https://scanpay-ob3w.onrender.com/.well-known/x402)
[![Solana](https://img.shields.io/badge/Solana-Mainnet-purple.svg)](https://explorer.solana.com/address/JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4)

ScanPay is a deterministic AST-based code security scanner and execution gatekeeper designed specifically for the **Agent-to-Agent (A2A)** economy with x402 Solana micropayments.

- **Production API:** `https://scanpay-ob3w.onrender.com`
- **Remote Streamable MCP:** `https://scanpay-ob3w.onrender.com/mcp` (HTTP) / `https://scanpay-ob3w.onrender.com/sse` (SSE)
- **Solana Merchant Wallet:** `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`
- **Pricing:** `0.0007 SOL` (~$0.10) per single scan | `0.006 SOL` for 10 prepaid session scans

---

## 🎯 Machine Experience (MX) & A2A Capabilities

Traditional security scanners output verbose human prose. ScanPay produces structured **Machine Responses**:
1. **Execution Gate Verdict:** `PASS`, `WARN`, or `BLOCK` with explicit `allow_execution` boolean and 0-100 `risk_score`.
2. **Deterministic Auto-Remediation:** Generates instant `remediated_code` and `unified_diff` patches (e.g. `eval` $\to$ `ast.literal_eval`, `shell=True` $\to$ `shell=False`, `innerHTML` $\to$ `textContent`).
3. **Agent-Specific AST Rules:** Detects wallet private key theft, unauthorized Solana RPC routing, prompt-injected tool chaining, infinite x402 spend loops, and hallucinated packages.
4. **Session Vouchers:** Prepaid micro-vouchers (`0.006 SOL` for 10 scans) delivering **sub-millisecond latency** with zero per-call gas fees and zero RPC polling.

---

## 🌐 Live Discovery Endpoints

Autonomous agent frameworks discover ScanPay automatically via spec-compliant endpoints:

| Endpoint | Standard / Protocol | Purpose |
| :--- | :--- | :--- |
| `GET /.well-known/x402` | x402 v2 Spec | Protocol discovery, CAIP-2 network, pricing & endpoints |
| `GET /bazaar.json` | Coinbase CDP / Onyx Bazaar | Registry catalog with `extensions.bazaar.discoverable: true` |
| `GET /.well-known/mcp.json` | Model Context Protocol | Remote MCP manifest for Protogrid, Smithery, Glama |
| `GET /.well-known/agent-card.json` | ERC-8004 / ERC-8183 | Agent identity card declaring Oracle capabilities |
| `GET /SKILL.md` | Agent Skills | Native instructions for Claude Code, Hermes, and Codex |
| `GET /PAY.md` | Solana Pay.sh | Settlement routes, recipient wallet, and spend caps |
| `POST /mcp` & `GET /sse` | MCP Remote Transports | Stateless JSON-RPC tool invocation over HTTP & SSE |

---

## ⚡ Quick Start

### 1. Per-Scan Micropayment (x402 v2)
```bash
# 1. Probe scan endpoint (returns 402 Payment Required)
curl -s -i -X POST https://scanpay-ob3w.onrender.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"language":"python","source_code":"eval(user_input)"}'

# 2. Transfer 0.0007 SOL (700,000 lamports) to merchant wallet on Solana
# 3. Retry with X-PAYMENT header containing transaction signature:
curl -s -X POST https://scanpay-ob3w.onrender.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-PAYMENT: <tx_signature>" \
  -d '{"language":"python","source_code":"eval(user_input)"}'
```

### 2. High-Frequency Session Voucher (0ms Latency)
Prepay 0.006 SOL for 10 instant scans:
```bash
# 1. Deposit on-chain & activate voucher
curl -s -X POST https://scanpay-ob3w.onrender.com/api/v1/session/deposit \
  -H "Content-Type: application/json" \
  -d '{"deposit_tx": "<tx_signature_for_0.006_SOL>"}'

# 2. Pass session token on all subsequent scans
curl -s -X POST https://scanpay-ob3w.onrender.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-SCANPAY-SESSION: <session_token>" \
  -d '{"language":"python","source_code":"import ast; ast.literal_eval(user_input)"}'
```

---

## 🤖 Remote Model Context Protocol (MCP)

ScanPay runs as a native remote streamable MCP server. No local Node.js or Python runtime required.

### Add to Claude Desktop / Cursor / Windsurf
```json
{
  "mcpServers": {
    "scanpay": {
      "url": "https://scanpay-ob3w.onrender.com/sse"
    }
  }
}
```

Or connect via stdio using `npx`:
```bash
npx scanpay-mcp-server
```

---

## 📦 Agent Framework Integrations

- **Solana Agent Kit v2:** `packages/plugin-solana-agent-kit` (`@scanpay/plugin-solana-agent-kit`)
- **ElizaOS:** `packages/plugin-elizaos` (`@elizaos/plugin-scanpay`)
- **Universal Guardrail Hook:** `packages/scanpay-guardrail/scanpay-hook.py` (Claude Code `PreToolUse` hook, OpenCode, Codex, LangGraph)

---

## 🧪 Testing & Verification

```bash
# Run 104+ unit and integration tests
python3 -m pytest
```

---

## 📄 License
MIT © Alex Taghiashvili
