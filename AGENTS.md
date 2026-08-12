# ScanPay autonomous-work contract

## Exclusive mission

Work only on the independent ScanPay service in this directory. The mission is
to turn it into a secure, tested, durable code-scanning API with truthful x402
discovery and a stable Cloudflare public endpoint.

`E:\ALEX_AGENT_OS\13_APPLICATIONS\agent-preflight` is frozen. Never read it as
a work target, edit it, run migrations against it, start or stop its containers,
or reuse its live state. Historical documentation may be consulted read-only
only when necessary to understand a protocol, and every new artifact must remain
inside this ScanPay project or the matching Agent OS project/session records.

## Autonomous operating rules

- Continue taking concrete implementation, test, documentation, packaging,
  local runtime, and public-demo steps without asking routine questions.
- Do not try to consume the entire mission in one agent turn. Complete one
  meaningful, verified milestone, persist its state, and deliberately return a
  concise handoff before 60 tool/API iterations. The Kanban goal judge will
  continue with the next milestone. Reaching the configured iteration ceiling
  is a failure, not evidence of persistence.
- Never use broad process termination such as `taskkill /IM python.exe`,
  `taskkill /IM cloudflared.exe`, or equivalent name-wide kills. Track and stop
  only PIDs created by this project, after verifying their command/path.
- Preserve unrelated files and all pre-existing user changes.
- Keep source and durable state on `E:`. Do not make `C:\Users\TMGU\scanpay`
  authoritative and do not download or execute replacement binaries without
  verified provenance.
- Do not store secrets, wallet keys, recovery phrases, cookies, or unrestricted
  tokens in source, logs, prompts, Git, Markdown, or SQLite.
- Never claim a listing, sale, settlement, revenue, uptime, or test result
  without direct evidence.

## Owner-only gates

Stop and report the smallest exact blocked step before any wallet signature,
real-value transfer, mainnet activation, purchase, KYC/legal acceptance, secret
entry, or irreversible external action. Public deployment of a payment-disabled
or testnet-only ScanPay demo is allowed; accepting real funds is not allowed
until the owner explicitly approves the exact network, asset, recipient, price,
caps, and rollback/kill-switch policy.

## Required path to completion

1. Audit the imported prototype and replace unsafe assumptions with explicit,
   environment-driven configuration and fail-closed defaults.
2. Add tests for payment replay, amount/recipient/network binding, free-trial
   abuse boundaries, request limits, scanner isolation, and restart recovery.
3. Implement official x402 v2 discovery/payment flow in testnet or disabled
   mode; a custom Solana transaction check must not be described as x402.
4. Add reproducible local startup, scoped PID files, health checks, durable
   logs/data, and restart-safe service management.
5. Create a stable Cloudflare deployment path and verify the live public
   health/catalog/payment-disabled behavior. A temporary Quick Tunnel is not a
   stable production endpoint.
6. Prepare truthful Bazaar metadata and complete every no-owner step. Pause only
   at an owner-only gate, with exact evidence and one minimal requested action.
7. Keep Agent OS project, session, current-state, handoff, and validation records
   current after meaningful milestones.

The task is complete only when the service and its public evidence satisfy the
contract above, or when progress is genuinely blocked at an owner-only gate.
