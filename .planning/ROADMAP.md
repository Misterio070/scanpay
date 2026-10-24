# ScanPay Roadmap

## Phases

### Phase 1: Engine & Security Verification [COMPLETED]
- [x] Fix test runner base directory (.tmp).
- [x] Run full pytest suite: 75/75 passing.
- [x] Verify AST security scanner rules (Python 22+ rules, JS 23+ rules).
- [x] Verify x402 402 challenge & replay attack defense.

### Phase 2: Client & MCP Transport Hardening [COMPLETED]
- [x] Upgrade `npm/scanpay-mcp/index.js` to support HTTPS endpoints via dynamic protocol routing.
- [x] Update JSON-RPC error handling for malformed payment responses.
- [x] Fix `start.sh` python3 detection and `.env` loading.

### Phase 3: 24/7 Zero-Cost Deployment Setup [IN PROGRESS]
- [x] Test local daemon and live x402 challenge generation.
- [ ] Add `render.yaml` for 1-click free cloud hosting (Render/Koyeb).
- [ ] Update `provider.json` and `bazaar.json` with mainnet parameters.

### Phase 4: Production Public Wiring & Marketplace Sync [PENDING]
- [ ] Configure live public endpoint URL in MCP package and docs.
- [ ] Update README with accurate Claude Desktop & Cursor MCP config snippet.
- [ ] Update mcprush listing description with live discovery details.
