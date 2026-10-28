# @scanpay/agentkit-action

Official **Coinbase AgentKit** Action Provider for ScanPay Autonomous Security & Pre-Flight Drainer Shield on Base.

Allows any AI agent running with Coinbase AgentKit to automatically audit generated code, simulate EVM transactions before broadcasting to protect against honeypots & drainers, and scrape web pages with native **Base USDC micropayments via x402 v2**.

---

## 🛠️ Actions Provided

| Action | Cost (Base USDC) | Description |
| :--- | :--- | :--- |
| `scan_code` | **$0.10 USDC** | AST security scanner with 65 vulnerability rules, deterministic patches, and unified diffs. |
| `simulate_tx` | **$0.05 USDC** | Pre-flight transaction shield detecting honeypots, drainers, and MEV slippage traps on Base. |
| `scrape_url` | **$0.02 USDC** | Anti-bot web scraper oracle bypassing Cloudflare Turnstile/WAF, returning clean LLM Markdown. |

---

## 📦 Installation

```bash
npm install @scanpay/agentkit-action
```

---

## 🚀 Usage with Coinbase AgentKit

```typescript
import { AgentKit, EvmWalletProvider } from "@coinbase/agentkit";
import { scanCodeAction, simulateTxAction, scrapeUrlAction } from "@scanpay/agentkit-action";

// In your agent setup:
// 1. Audit code before executing:
const auditReport = await scanCodeAction(walletProvider, {
  code: "import os; os.system('rm -rf /')",
  language: "python"
});
console.log("Audit Verdict:", JSON.parse(auditReport).execution_gate.verdict);

// 2. Simulate raw transaction before sending to mempool:
const simulation = await simulateTxAction(walletProvider, {
  tx: { to: "0x1234...", data: "0x...", value: "0" },
  chain: "base"
});
console.log("Drainer Shield Verdict:", JSON.parse(simulation).verdict);
```

---

## 💳 Settlement Details

- **Chain:** Base (`eip155:8453`)
- **Asset:** Native USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
- **Merchant Wallet:** `0xb295E606F38C363b476FC546c27226B5fBcAAEFA`
- **Protocol:** x402 v2 Autonomous Micropayments
