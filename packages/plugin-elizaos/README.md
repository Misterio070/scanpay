# @elizaos/plugin-scanpay

Deterministic code security guardrail plugin for **ElizaOS** autonomous agents.

## Features
- **SCAN_CODE_SECURITY Action:** Intercepts code generation and audits AST patterns for security flaws.
- **Auto-Remediation Support:** Ingests unified diffs for self-healing code loops.
- **Provider Context:** Injects active security oracle state into Eliza's runtime context.

## Installation
```bash
npm install @elizaos/plugin-scanpay
```

## Setup
In your `character.json`:
```json
{
  "plugins": ["@elizaos/plugin-scanpay"],
  "settings": {
    "SCANPAY_SESSION_VOUCHER": "scanpay_sess_your_token_here"
  }
}
```
