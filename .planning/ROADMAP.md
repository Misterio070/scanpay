# ScanPay A2A Autonomous Roadmap

## Milestone 1: Autonomous Agent-to-Agent Commercialization (Argon Blueprint) [COMPLETED]

### Phase 1: Machine Response, AST Depth, and Auto-Remediation [COMPLETED]
- [x] Add 12 agent-specific AST rules (6 in Python `src/engine.py`, 6 in JS/TS `src/engine_js.py`)
- [x] Build deterministic AST Auto-Remediation engine (`src/remediator.py`)
- [x] Implement ScanPay v2 Machine-Readable Response Schema (`execution_gate`, `auto_remediation`, `source_integrity`, `attestation`)
- [x] Wire v2 MX response into `main.py` `/api/v1/scan` and `/v2/scan`
- [x] Write pytest test suites (`tests/test_agent_rules.py`, `tests/test_remediator.py`). All passing.

### Phase 2: Remote Streamable MCP & Discovery Graph [COMPLETED]
- [x] Implement stateless remote Streamable HTTP / SSE MCP server at `/mcp` and `/sse` (`src/mcp_remote.py`)
- [x] Mount live discovery routes on FastAPI (`src/discovery.py`): `/.well-known/x402`, `/bazaar.json`, `/.well-known/mcp.json`, `/.well-known/agent-card.json`, `/SKILL.md`, `/PAY.md`, `/llms.txt`
- [x] Implement Session Voucher endpoint `POST /api/v1/session/deposit` (0.006 SOL / 0.85 USDC = 10 instant scans) (`src/session.py`)
- [x] Add session authentication & verification via `X-SCANPAY-SESSION` with 0ms RPC bypass
- [x] Write pytest test suites. All passing.

### Phase 3: Agent Integration Pack & Framework Plugins [COMPLETED]
- [x] Create `@scanpay/plugin-solana-agent-kit` (`packages/plugin-solana-agent-kit/`)
- [x] Create `@elizaos/plugin-scanpay` (`packages/plugin-elizaos/`)
- [x] Create Universal Pre-Execution Guardrail Hook (`packages/scanpay-guardrail/scanpay-hook.py`)
- [x] Deploy to production on Render (`scanpay-ob3w.onrender.com`)

## Milestone 2: Agent Infrastructure Expansion (Tx Shield & Anti-Bot Scraper Oracle) [COMPLETED]

### Phase 4: Pre-Flight Transaction & Drainer Shield [COMPLETED]
- [x] Build core simulation engine (`src/preflight.py`):
  - EVM calldata decoding & honeypot/drainer analysis (`approve` unlimited check, suspicious spender addresses, transfer blacklists, high buy/sell tax heuristics).
  - Solana instruction preflight inspection (unauthorized token freeze/burn/setAuthority, fake mints, unbounded slippage).
  - Deterministic simulation verdict: `verdict` (ALLOW, BLOCK, WARN), `risk_score` (0-100), `simulated_deltas`, `remediation_advice`.
  - Cryptographic oracle attestation generation (Ed25519 oracle signature).
- [x] Implement API routes in `main.py`: `POST /api/v1/preflight/simulate` and `POST /v2/preflight/simulate` with x402 402 challenge ($0.05 Base USDC / 0.00035 SOL) or `X-SCANPAY-SESSION` bypass.
- [x] Unit & integration test suite (`tests/test_preflight.py`). 100% passing.

### Phase 5: Anti-Bot Web Access & Scraper Oracle [COMPLETED]
- [x] Build anti-bot scraper oracle engine (`src/scraper_oracle.py`):
  - Stealth headers & browser fingerprinting (User-Agents, Sec-Ch-Ua, Accept-Language, Sec-Fetch-Dest).
  - WAF / Cloudflare Turnstile / anti-bot challenge detection and fallback recovery.
  - HTML content purification: strip scripts, styles, cookies, ads, trackers; convert HTML to clean, token-efficient Markdown for LLMs.
  - Metadata extraction (title, canonical_url, word_count, token_estimate).
- [x] Implement API routes in `main.py`: `POST /api/v1/oracle/scrape` and `POST /v2/oracle/scrape` with x402 402 challenge ($0.02 Base USDC / 0.00015 SOL) or `X-SCANPAY-SESSION` bypass.
- [x] Unit & integration test suite (`tests/test_scraper_oracle.py`). 100% passing.

### Phase 6: Remote MCP Multi-Tooling & Discovery Unification [COMPLETED]
- [x] Register `simulate_tx` and `scrape_url` in remote MCP server (`src/mcp_remote.py`) and stdio server (`npm/scanpay/bin/mcp-server.js` & `npm/scanpay-mcp/index.js`).
- [x] Update `/.well-known/x402` with multi-service price matrix (scan, preflight, scrape).
- [x] Update `/bazaar.json`, `/.well-known/mcp.json`, `SKILL.md`, `PAY.md`, `llms.txt`, and `openapi.json` to reflect all 3 services.
- [x] Test MCP streamable SSE and JSON-RPC execution for all tools (`tests/test_mcp_remote.py`). 100% passing.

### Phase 7: Automated Verification & Production Deployment [COMPLETED]
- [x] Run full test suite covering all modules (125/125 tests passing).
- [x] Commit with clean git history and push to `origin/main`.
- [x] Verified live on production.
