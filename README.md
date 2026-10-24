# ScanPay — Security Oracle & Agent Infrastructure Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Engine Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://scanpay-ob3w.onrender.com/api/v1/health)
[![x402 Conformance](https://img.shields.io/badge/x402-v2_Compliant-green.svg)](https://scanpay-ob3w.onrender.com/.well-known/x402)
[![Multi-Chain](https://img.shields.io/badge/Chains-Solana_%2B_Base-purple.svg)](https://scanpay-ob3w.onrender.com/PAY.md)
[![Glama MCP](https://glama.ai/mcp/servers/Misterio070/scanpay/badges/score.svg)](https://glama.ai/mcp/servers/Misterio070/scanpay)

ScanPay is an autonomous security guardrail and oracle infrastructure suite designed specifically for the **Agent-to-Agent (A2A)** and **Machine-to-Machine (M2M)** economy with x402 v2 micropayments.

- **Production API:** `https://scanpay-ob3w.onrender.com`
- **Remote Streamable MCP:** `https://scanpay-ob3w.onrender.com/mcp` (HTTP) / `https://scanpay-ob3w.onrender.com/sse` (SSE)
- **Solana Merchant Wallet:** `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`
- **Base (EVM) Merchant Wallet:** `0xb295E606F38C363b476FC546c27226B5fBcAAEFA` (USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)

---

## 🛠️ The 3 Core Agent Services

| Service | Endpoint | MCP Tool | Pricing (Base USDC / SOL) | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **1. Code Security Scanner** | `POST /v2/scan` | `scan_code` | **$0.10 USDC** (0.0007 SOL) | AST vulnerability analysis, deterministic patches, and execution gating (PASS/WARN/BLOCK). |
| **2. Pre-Flight Tx Shield** | `POST /v2/preflight/simulate` | `simulate_tx` | **$0.05 USDC** (0.00035 SOL) | Simulates EVM/Solana transactions before broadcast, detecting honeypots, drainers, and MEV slippage traps. |
| **3. Anti-Bot Scraper Oracle** | `POST /v2/oracle/scrape` | `scrape_url` | **$0.02 USDC** (0.00015 SOL) | Stealth browser scraping bypassing Cloudflare Turnstile/WAF, returning clean LLM Markdown. |
| **4. 10-Operation Session** | `POST /v2/session/deposit` | `create_session_deposit` | **$0.85 USDC** (0.006 SOL) | Prepaid micro-voucher valid across all tools with **sub-millisecond latency** and 0ms RPC bypass. |

---

## 🎯 Machine Experience (MX) & A2A Capabilities

Traditional developer tools output verbose human prose. ScanPay produces structured **Machine Responses**:
1. **Execution Gate Verdicts:** Unambiguous `ALLOW` or `BLOCK` booleans with 0-100 `risk_score` and cryptographic Ed25519 oracle attestations.
2. **Deterministic Auto-Remediation:** Generates instant `remediated_code` and `unified_diff` patches ready for `git apply`.
3. **Tx Pre-Flight Simulation:** Decodes ERC-20 approvals, detects unlimited allowances to untrusted spenders, honeypot functions (`setTrading`, `blacklist`), and Solana `SetAuthority` account takeovers.
4. **Anti-Bot Scraper Oracle:** Strips navigation, ads, cookies, and scripts, saving **up to 90% of LLM context window tokens**.

---

## 🌐 Live Discovery Endpoints

Autonomous agent frameworks discover ScanPay automatically via spec-compliant endpoints:

| Endpoint | Standard / Protocol | Purpose |
| :--- | :--- | :--- |
| `GET /llms.txt` | LLMs Discovery Standard | Machine documentation for LLMs, agents, and Cursor |
| `GET /robots.txt` | AI Crawler Standard | Explicit index permissions for GPTBot, Claude-Web, PerplexityBot |
| `GET /.well-known/x402` | x402 v2 Spec | Protocol discovery, CAIP-2 network, multi-chain pricing & endpoints |
| `GET /bazaar.json` | Coinbase CDP / Onyx Bazaar | Registry catalog with `extensions.bazaar.discoverable: true` |
| `GET /.well-known/mcp.json` | Model Context Protocol | Remote MCP manifest with 5 registered tools |
| `GET /.well-known/agent-card.json` | ERC-8004 / ERC-8183 | Agent identity card declaring Oracle capabilities |
| `GET /.well-known/ai-plugin.json` | OpenAI Plugin Standard | OpenAPI integration manifest for autonomous function callers |
| `GET /SKILL.md` | Agent Skills | Native instructions for Claude Code, Hermes, and Codex |
| `GET /PAY.md` | Multi-Chain Settlement | Settlement routes, recipient wallets, and spend caps |
| `POST /mcp` & `GET /sse` | MCP Remote Transports | Stateless JSON-RPC tool invocation over HTTP & SSE |

---

## 🤖 Remote Model Context Protocol (MCP)

ScanPay runs as a native remote streamable MCP server.

### Zero-Install stdio (CLI)
```bash
npx github:Misterio070/scanpay
```

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

---

## 📦 Agent Framework Integrations

- **Solana Agent Kit v2:** `packages/plugin-solana-agent-kit` (`@scanpay/plugin-solana-agent-kit`)
- **ElizaOS:** `packages/plugin-elizaos` (`@elizaos/plugin-scanpay`)
- **Universal Guardrail Hook:** `packages/scanpay-guardrail/scanpay-hook.py` (Claude Code `PreToolUse` hook, OpenCode, Codex, LangGraph)
- **ERC-8183 Commerce Evaluator:** `contracts/ScanPayEvaluator.sol`

---

## 🧪 Testing & Verification

```bash
# Run 125+ automated unit and integration tests
python3 -m pytest
```

---

## 📄 License
MIT © Alex Taghiashvili
