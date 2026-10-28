# @scanpay/plugin-solana-agent-kit

Deterministic code security guardrail tool for **Solana Agent Kit v2** with x402 micropayments.

## Features
- **Deterministic AST Audits:** Scans code for 65 vulnerability patterns (injection, wallet key theft, SSRF, prompt-injected tool chaining).
- **Autonomous Micropayments:** Automatically handles x402 HTTP 402 challenge, signs 0.0007 SOL transfer, and verifies results.
- **Auto-Remediation:** Generates unified diffs and replacement code ready for autonomous application.
- **Session Vouchers:** Supports `X-SCANPAY-SESSION` for 0ms latency high-frequency coding loops.

## Installation
```bash
npm install @scanpay/plugin-solana-agent-kit
```

## Usage
```typescript
import { SolanaAgentKit } from 'solana-agent-kit';
import { scanPayTool, scanCode } from '@scanpay/plugin-solana-agent-kit';

// Register tool with agent
agent.registerTool(scanPayTool);

// Or call directly
const result = await scanCode(agent, codeToAudit, 'python');
if (!result.allowed) {
  console.log('Blocked unsafe code. Suggested patch:', result.autoRemediation?.unifiedDiff);
}
```
