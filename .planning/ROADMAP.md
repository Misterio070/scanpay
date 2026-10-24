# ScanPay A2A Autonomous Roadmap

## Milestone: Autonomous Agent-to-Agent Commercialization (Argon Blueprint)

### Phase 1: Machine Response, AST Depth, and Auto-Remediation [COMPLETED]
- [x] Add 12 agent-specific AST rules (6 in Python `src/engine.py`, 6 in JS/TS `src/engine_js.py`):
  - Wallet private key / mnemonic exfiltration (`AGT-PY-023` / `AGT-TS-024`)
  - Unbounded DeFi slippage & blind signing (`AGT-TS-025`)
  - Unauthorized RPC & facilitator hijacking (`AGT-PY-024` / `AGT-TS-026`)
  - Prompt-injected tool chaining (`AGT-PY-025` / `AGT-TS-027`)
  - Unbounded x402 spend & infinite loops (`AGT-PY-026` / `AGT-TS-028`)
  - Slopsquatting & hallucinated package imports (`AGT-PY-027` / `AGT-TS-029`)
- [x] Build deterministic AST Auto-Remediation engine (`src/remediator.py`):
  - Deterministic patch rules (`eval` -> `ast.literal_eval`, `yaml.load` -> `yaml.safe_load`, `shell=True` -> `shell=False`, `innerHTML` -> `textContent`)
  - Unified diff generation (`difflib.unified_diff`)
  - 2nd-pass AST verification (`post_patch_verdict`)
- [x] Implement ScanPay v2 Machine-Readable Response Schema (`execution_gate`, `auto_remediation`, `source_integrity`, `attestation`).
- [x] Wire v2 MX response into `main.py` `/api/v1/scan` and `/v2/scan`.
- [x] Write pytest test suites (`tests/test_agent_rules.py`, `tests/test_remediator.py`). All passing.

### Phase 2: Remote Streamable MCP & Discovery Graph [COMPLETED]
- [x] Implement stateless remote Streamable HTTP / SSE MCP server at `/mcp` and `/sse` (`src/mcp_remote.py`).
- [x] Mount live discovery routes on FastAPI (`src/discovery.py`):
  - `GET /.well-known/x402`
  - `GET /bazaar.json` (with `extensions.bazaar.discoverable = true`)
  - `GET /.well-known/mcp.json`
  - `GET /.well-known/agent-card.json`
  - `GET /SKILL.md`
  - `GET /PAY.md`
  - `GET /llms.txt`
- [x] Implement Session Voucher endpoint `POST /api/v1/session/deposit` (0.006 SOL = 10 instant scans) (`src/session.py`).
- [x] Add session authentication & verification via `X-SCANPAY-SESSION` with 0ms RPC bypass.
- [x] Write pytest test suites (`tests/test_discovery.py`, `tests/test_mcp_remote.py`, `tests/test_session_voucher.py`). All passing.

### Phase 3: Agent Integration Pack & Framework Plugins [COMPLETED]
- [x] Create `@scanpay/plugin-solana-agent-kit` (`packages/plugin-solana-agent-kit/`).
- [x] Create `@elizaos/plugin-scanpay` (`packages/plugin-elizaos/`).
- [x] Create Universal Pre-Execution Guardrail Hook (`packages/scanpay-guardrail/scanpay-hook.py`).
- [x] Update documentation, `README.md`, `server.json`, `bazaar.json`, `llms.txt`, and npm package manifests.
