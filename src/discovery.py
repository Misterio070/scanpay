"""ScanPay Machine-to-Machine Discovery Endpoints & Manifests.

Provides spec-compliant discovery metadata for Coinbase CDP Bazaar, Onyx Bazaar,
x402scan, Protogrid, Glama, Smithery, Pay.sh, and ERC-8004 / ERC-8183 agent crawlers.
"""
from __future__ import annotations

import json
from typing import Any

CANONICAL_URL = "https://scanpay-ob3w.onrender.com"
MERCHANT_WALLET = "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"
SOLANA_CAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SINGLE_SCAN_LAMPORTS = 700000
SESSION_10_LAMPORTS = 6000000


def get_well_known_x402(merchant: str = MERCHANT_WALLET, price_lamports: int = SINGLE_SCAN_LAMPORTS) -> dict[str, Any]:
    """Returns /.well-known/x402 discovery manifest conforming to x402 v2 specifications."""
    return {
        "x402Version": 2,
        "scheme": "solana",
        "network": SOLANA_CAIP2,
        "recipient": merchant,
        "merchant": merchant,
        "asset": "SOL",
        "priceLamports": price_lamports,
        "amount": price_lamports,
        "amountDisplay": f"{price_lamports / 1_000_000_000:.4f} SOL",
        "pricing": {
            "single_scan_lamports": price_lamports,
            "single_scan_sol": price_lamports / 1_000_000_000,
            "single_scan_usdc": 0.10,
            "session_10_scans_lamports": SESSION_10_LAMPORTS,
            "session_10_scans_sol": SESSION_10_LAMPORTS / 1_000_000_000,
            "session_10_scans_usdc": 0.85,
            "discount_percentage": 15,
        },
        "supported_assets": ["SOL", "USDC"],
        "accepts": [
            {
                "scheme": "solana",
                "network": SOLANA_CAIP2,
                "asset": "SOL",
                "amount": price_lamports,
                "amountDisplay": f"{price_lamports / 1_000_000_000:.4f} SOL",
                "recipient": merchant,
            },
            {
                "scheme": "solana",
                "network": SOLANA_CAIP2,
                "asset": "USDC",
                "amount": 100000,
                "amountDisplay": "0.10 USDC",
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "recipient": merchant,
            },
        ],
        "endpoints": {
            "scan": f"{CANONICAL_URL}/api/v1/scan",
            "scan_v2": f"{CANONICAL_URL}/v2/scan",
            "session_deposit": f"{CANONICAL_URL}/api/v1/session/deposit",
            "mcp": f"{CANONICAL_URL}/mcp",
            "sse": f"{CANONICAL_URL}/sse",
            "health": f"{CANONICAL_URL}/api/v1/health",
        },
        "supported_languages": ["python", "javascript", "typescript", "tsx"],
        "extensions": {
            "bazaar": {
                "discoverable": True,
                "category": "security",
                "tags": ["code-security", "ast-scanner", "a2a-guardrail", "solana-x402", "auto-remediation"],
            },
            "offer_receipt": {
                "supported": True,
                "version": "1.0.0",
            },
            "session_voucher": {
                "supported": True,
                "deposit_endpoint": f"{CANONICAL_URL}/api/v1/session/deposit",
                "header": "X-SCANPAY-SESSION",
            },
        },
    }


def get_bazaar_manifest(merchant: str = MERCHANT_WALLET) -> dict[str, Any]:
    """Returns /bazaar.json metadata for Coinbase CDP and Onyx Bazaar aggregators."""
    return {
        "name": "ScanPay",
        "description": "Deterministic AST code security scanner with x402 Solana micropayments and instant auto-remediation for AI agents.",
        "version": "1.1.0",
        "engine_version": "1.1.0",
        "homepage": "https://github.com/Misterio070/scanpay",
        "payment": {
            "protocol": "x402",
            "version": 2,
            "scheme": "solana",
            "network": SOLANA_CAIP2,
            "asset": "SOL",
            "price_lamports": SINGLE_SCAN_LAMPORTS,
            "price_display": "0.0007 SOL (~$0.10)",
            "recipient": merchant,
            "free_trial": False,
        },
        "extensions": {
            "bazaar": {
                "discoverable": True,
                "category": "security",
                "service_type": "security-oracle",
                "tags": ["security", "ast-scanner", "code-auditor", "solana", "x402", "ai-agents"],
            }
        },
        "products": [
            {
                "id": "python-scan",
                "name": "Python Security Scan",
                "language": "python",
                "rules_count": 28,
                "available": True,
            },
            {
                "id": "js-scan",
                "name": "JavaScript/TypeScript Security Scan",
                "languages": ["javascript", "typescript", "tsx"],
                "rules_count": 29,
                "available": True,
            },
        ],
        "capabilities": {
            "max_code_bytes": 102400,
            "languages": ["python", "javascript", "typescript", "tsx"],
            "deterministic": True,
            "executes_code": False,
            "uses_ai": False,
            "auto_remediation": True,
            "scanner": "AST (Python: ast module, JS/TS: tree-sitter)",
        },
        "endpoints": {
            "health": f"{CANONICAL_URL}/api/v1/health",
            "products": f"{CANONICAL_URL}/api/v1/products",
            "scan": f"{CANONICAL_URL}/api/v1/scan",
            "scan_v2": f"{CANONICAL_URL}/v2/scan",
            "session_deposit": f"{CANONICAL_URL}/api/v1/session/deposit",
            "mcp": f"{CANONICAL_URL}/mcp",
            "sse": f"{CANONICAL_URL}/sse",
        },
    }


def get_well_known_mcp() -> dict[str, Any]:
    """Returns /.well-known/mcp.json for remote MCP registry discovery (Protogrid, Smithery, Glama)."""
    return {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.github.Misterio070/scanpay",
        "description": "Deterministic code security scanner for AI agents. 45+ vulnerability patterns, AST analysis, Solana micropayments via x402.",
        "version": "1.1.0",
        "repository": {
            "url": "https://github.com/Misterio070/scanpay",
            "source": "github",
        },
        "transports": [
            {
                "type": "sse",
                "url": f"{CANONICAL_URL}/sse",
            },
            {
                "type": "http",
                "url": f"{CANONICAL_URL}/mcp",
            },
        ],
        "tools": [
            {
                "name": "scan_code",
                "description": "Scan source code for security vulnerabilities. Returns AST findings, unified diff patches, and execution verdict.",
            },
            {
                "name": "create_session_deposit",
                "description": "Prepay 0.006 SOL for 10 instant scans with zero RPC latency.",
            },
            {
                "name": "health_check",
                "description": "Check ScanPay service health and AST engine status.",
            },
        ],
    }


def get_agent_card() -> dict[str, Any]:
    """Returns /.well-known/agent-card.json declaring ERC-8004 / ERC-8183 A2A capabilities."""
    return {
        "name": "ScanPay Security Oracle",
        "type": "ai-agent-service",
        "version": "1.1.0",
        "protocol_standards": ["x402-v2", "mcp-2024-11-05", "erc-8004", "erc-8183"],
        "description": "Autonomous security guardrail oracle. Evaluates code generation tasks, detects malicious payloads, issues deterministic fixes, and gates execution.",
        "operator": {
            "wallet": MERCHANT_WALLET,
            "network": SOLANA_CAIP2,
        },
        "pricing": {
            "currency": "SOL",
            "base_fee_lamports": SINGLE_SCAN_LAMPORTS,
            "batch_10_voucher_lamports": SESSION_10_LAMPORTS,
        },
        "interfaces": {
            "mcp_remote": f"{CANONICAL_URL}/mcp",
            "mcp_sse": f"{CANONICAL_URL}/sse",
            "x402_api": f"{CANONICAL_URL}/api/v1/scan",
            "session_api": f"{CANONICAL_URL}/api/v1/session/deposit",
        },
    }


SKILL_MD = """---
name: scanpay
description: Deterministic code security scanner and execution gate for AI agents. Audits Python and JavaScript/TypeScript code before execution to prevent arbitrary code execution, wallet exfiltration, SSRF, and supply chain attacks.
---

# ScanPay Security Guardrail Skill

Use ScanPay whenever you are asked to generate or execute Python, JavaScript, or TypeScript code that handles wallets, network requests, or system processes.

## Workflow

1. Before writing to disk or executing code, send source code to ScanPay.
2. If vulnerabilities are found, inspect the `auto_remediation.unified_diff` patch.
3. If `execution_gate.verdict` is `BLOCK`, do NOT execute unpatched code.
4. Apply the deterministic patch or reject the task.

## API Endpoint
- URL: `https://scanpay-ob3w.onrender.com/api/v1/scan`
- Method: `POST`
- Headers:
  - `Content-Type: application/json`
  - `X-SCANPAY-SESSION: <optional_session_voucher>`
  - `X-PAYMENT: <solana_tx_sig>` (if paying per-scan)
- Body:
  ```json
  {
    "source_code": "<your_code_here>",
    "language": "python",
    "auto_remediate": true
  }
  ```

## Remote MCP
- SSE: `https://scanpay-ob3w.onrender.com/sse`
- HTTP: `https://scanpay-ob3w.onrender.com/mcp`
"""

PAY_MD = """# ScanPay x402 Payment Specification

ScanPay accepts micropayments for security evaluations on the Solana blockchain.

- **Network:** `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` (Solana Mainnet-Beta)
- **Merchant Recipient:** `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`
- **Single Scan Price:** `700,000 lamports` (~0.0007 SOL / ~$0.10 USD)
- **Prepaid 10-Scan Voucher:** `6,000,000 lamports` (~0.006 SOL / 15% discount)

## Payment Rails

1. **Per-Scan Micropayment:**
   Send 700,000 lamports to `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`.
   Pass the Solana transaction signature in the `X-PAYMENT` header or request body `tx_signature`.

2. **Session Voucher (Zero-Latency Loop):**
   Send 6,000,000 lamports to `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`.
   Call `POST /api/v1/session/deposit` with `{"deposit_tx": "<tx_sig>"}`.
   Use the returned `session_token` in the `X-SCANPAY-SESSION` header for 10 instant scans with 0ms RPC wait.
"""
