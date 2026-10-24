# ScanPay A2A State

- **Milestone**: Milestone 2: Agent Infrastructure Expansion (Tx Shield & Anti-Bot Scraper Oracle)
- **Status**: Milestone 1 & 2 fully completed and tested locally (125/125 tests passing).
- **Backend URL**: `https://scanpay-ob3w.onrender.com`
- **Merchant Wallet (Solana)**: `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`
- **Merchant Wallet (Base EVM)**: `0xb295E606F38C363b476FC546c27226B5fBcAAEFA`
- **Total Test Count**: 125 passed (0 skipped, 0 failed)
- **Active MCP Tools (Remote & Stdio)**:
  - `scan_code`: Deterministic AST analysis and auto-remediation patches.
  - `simulate_tx`: Pre-flight transaction & drainer shield for EVM and Solana.
  - `scrape_url`: Anti-bot web scraper oracle bypassing Cloudflare Turnstile/WAF into clean Markdown.
  - `create_session_deposit`: 10-operation prepaid voucher with 0ms RPC bypass.
  - `health_check`: Engine health and rule inspection.
- **Settlement Matrix**:
  - Scan: $0.10 Base USDC / 0.0007 SOL
  - Preflight: $0.05 Base USDC / 0.00035 SOL
  - Scrape: $0.02 Base USDC / 0.00015 SOL
  - Session Voucher: $0.85 Base USDC / 0.006 SOL
