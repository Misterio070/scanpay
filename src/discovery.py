"""ScanPay Machine-to-Machine Discovery Endpoints & Manifests.

Provides spec-compliant discovery metadata for Coinbase CDP Bazaar, Onyx Bazaar,
x402scan, Protogrid, Glama, Smithery, Pay.sh, and ERC-8004 / ERC-8183 agent crawlers.
"""
from __future__ import annotations

import json
from typing import Any

CANONICAL_URL = "https://scanpay-ob3w.onrender.com"
MERCHANT_WALLET = "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"
MERCHANT_EVM_WALLET = "0xb295E606F38C363b476FC546c27226B5fBcAAEFA"
SOLANA_CAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
BASE_CAIP2 = "eip155:8453"
BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SINGLE_SCAN_LAMPORTS = 700000
SESSION_10_LAMPORTS = 6000000


def get_well_known_x402(merchant: str = MERCHANT_WALLET, evm_merchant: str = MERCHANT_EVM_WALLET, price_lamports: int = SINGLE_SCAN_LAMPORTS) -> dict[str, Any]:
    """Returns /.well-known/x402 discovery manifest conforming to x402 v2 specifications."""
    return {
        "x402Version": 2,
        "scheme": "solana",
        "network": SOLANA_CAIP2,
        "recipient": merchant,
        "merchant": merchant,
        "merchant_evm": evm_merchant,
        "asset": "SOL",
        "priceLamports": price_lamports,
        "amount": price_lamports,
        "amountDisplay": f"{price_lamports / 1_000_000_000:.4f} SOL",
        "pricing": {
            "single_scan_lamports": price_lamports,
            "single_scan_sol": price_lamports / 1_000_000_000,
            "single_scan_usdc": 0.10,
            "preflight_simulate_lamports": 350000,
            "preflight_simulate_sol": 0.00035,
            "preflight_simulate_usdc": 0.05,
            "token_audit_lamports": 350000,
            "token_audit_sol": 0.00035,
            "token_audit_usdc": 0.05,
            "scraper_oracle_lamports": 150000,
            "scraper_oracle_sol": 0.00015,
            "scraper_oracle_usdc": 0.02,
            "session_10_scans_lamports": SESSION_10_LAMPORTS,
            "session_10_scans_sol": SESSION_10_LAMPORTS / 1_000_000_000,
            "session_10_scans_usdc": 0.85,
            "discount_percentage": 15,
        },
        "supported_chains": [
            {"name": "Solana", "caip2": SOLANA_CAIP2, "assets": ["SOL", "USDC"]},
            {"name": "Base", "caip2": BASE_CAIP2, "assets": ["USDC", "ETH"]},
        ],
        "accepts": [
            {
                "scheme": "exact",
                "network": BASE_CAIP2,
                "asset": BASE_USDC_CONTRACT,
                "tokenContract": BASE_USDC_CONTRACT,
                "amount": "100000",
                "maxAmountRequired": "100000",
                "amountDisplay": "0.10 USDC",
                "payTo": evm_merchant,
                "recipient": evm_merchant,
                "maxTimeoutSeconds": 600,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                },
            },
            {
                "scheme": "exact",
                "network": SOLANA_CAIP2,
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "amount": "100000",
                "maxAmountRequired": "100000",
                "amountDisplay": "0.10 USDC",
                "payTo": merchant,
                "recipient": merchant,
                "maxTimeoutSeconds": 600,
                "extra": {
                    "feePayer": "CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww",
                },
            },
        ],
        "endpoints": {
            "scan": f"{CANONICAL_URL}/api/v1/scan",
            "scan_v2": f"{CANONICAL_URL}/v2/scan",
            "preflight": f"{CANONICAL_URL}/api/v1/preflight/simulate",
            "preflight_v2": f"{CANONICAL_URL}/v2/preflight/simulate",
            "token_audit": f"{CANONICAL_URL}/api/v1/token/audit",
            "token_audit_v2": f"{CANONICAL_URL}/v2/token/audit",
            "scrape": f"{CANONICAL_URL}/api/v1/oracle/scrape",
            "scrape_v2": f"{CANONICAL_URL}/v2/oracle/scrape",
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
                "tags": ["code-security", "ast-scanner", "tx-simulation", "scraper-oracle", "solana-x402", "auto-remediation"],
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


def get_bazaar_manifest(merchant: str = MERCHANT_WALLET, evm_merchant: str = MERCHANT_EVM_WALLET) -> dict[str, Any]:
    """Returns /bazaar.json metadata for Coinbase CDP and Onyx Bazaar aggregators."""
    return {
        "name": "ScanPay",
        "description": "Deterministic AST code security scanner, pre-flight Tx shield, and anti-bot scraper oracle with multi-chain x402 micropayments (Solana + Base) for AI agents.",
        "version": "1.2.0",
        "engine_version": "1.2.0",
        "homepage": "https://github.com/Misterio070/scanpay",
        "payment": {
            "protocol": "x402",
            "version": 2,
            "chains": [
                {
                    "name": "Solana",
                    "caip2": SOLANA_CAIP2,
                    "assets": [
                        {"symbol": "SOL", "amount": SINGLE_SCAN_LAMPORTS, "recipient": merchant},
                        {"symbol": "USDC", "amount": 100000, "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "recipient": merchant},
                    ],
                },
                {
                    "name": "Base",
                    "caip2": BASE_CAIP2,
                    "assets": [
                        {"symbol": "USDC", "amount": 100000, "contract": BASE_USDC_CONTRACT, "recipient": evm_merchant},
                    ],
                },
            ],
            "price_usd_approx": 0.10,
            "free_trial": False,
        },
        "extensions": {
            "bazaar": {
                "discoverable": True,
                "category": "security",
                "service_type": "security-oracle",
                "tags": ["security", "ast-scanner", "code-auditor", "tx-simulation", "scraper-oracle", "solana", "base", "x402", "ai-agents"],
            }
        },
        "products": [
            {
                "id": "python-scan",
                "name": "Python Security Scan",
                "language": "python",
                "rules_count": 28,
                "price_usd": 0.10,
                "available": True,
            },
            {
                "id": "js-scan",
                "name": "JavaScript/TypeScript Security Scan",
                "languages": ["javascript", "typescript", "tsx"],
                "rules_count": 29,
                "price_usd": 0.10,
                "available": True,
            },
            {
                "id": "preflight-simulation",
                "name": "Pre-Flight Transaction & Drainer Shield",
                "chains": ["base", "solana", "ethereum"],
                "price_usd": 0.05,
                "available": True,
            },
            {
                "id": "token-audit",
                "name": "Live On-Chain Token Rug & Honeypot Auditor",
                "chains": ["base", "solana", "ethereum"],
                "price_usd": 0.05,
                "available": True,
            },
            {
                "id": "scraper-oracle",
                "name": "Anti-Bot Web Access & Scraper Oracle",
                "price_usd": 0.02,
                "available": True,
            },
            {
                "id": "session-voucher-10",
                "name": "Prepaid Session Voucher (10 Credits)",
                "price_usd": 0.85,
                "credits": 10,
                "discount_percentage": 15,
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
            "tx_simulation": True,
            "anti_bot_scraping": True,
            "scanner": "AST (Python: ast module, JS/TS: tree-sitter)",
        },
        "endpoints": {
            "health": f"{CANONICAL_URL}/api/v1/health",
            "products": f"{CANONICAL_URL}/api/v1/products",
            "scan": f"{CANONICAL_URL}/api/v1/scan",
            "scan_v2": f"{CANONICAL_URL}/v2/scan",
            "preflight": f"{CANONICAL_URL}/api/v1/preflight/simulate",
            "token_audit": f"{CANONICAL_URL}/api/v1/token/audit",
            "scrape": f"{CANONICAL_URL}/api/v1/oracle/scrape",
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
        "description": "Deterministic code security scanner, Tx Preflight & Anti-Bot Scraper Oracle for AI agents with x402 micropayments.",
        "version": "1.2.0",
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
                "name": "simulate_tx",
                "description": "Pre-flight transaction & drainer shield for EVM and Solana before signing/broadcasting.",
            },
            {
                "name": "audit_token",
                "description": "Live on-chain token contract & SPL/Token-2022 rug/honeypot audit on Base, Ethereum, and Solana.",
            },
            {
                "name": "scrape_url",
                "description": "Stealth anti-bot web scraper oracle bypassing Cloudflare Turnstile/WAF, returning clean LLM Markdown.",
            },
            {
                "name": "create_session_deposit",
                "description": "Prepay 0.006 SOL or 0.85 Base USDC for 10 instant operations with zero RPC latency.",
            },
            {
                "name": "health_check",
                "description": "Check ScanPay service health and active tools status.",
            },
        ],
    }


def get_agent_card() -> dict[str, Any]:
    """Returns /.well-known/agent-card.json declaring ERC-8004 / ERC-8183 A2A capabilities."""
    return {
        "name": "ScanPay Security Oracle",
        "type": "ai-agent-service",
        "version": "1.2.0",
        "protocol_standards": ["x402-v2", "mcp-2024-11-05", "erc-8004", "erc-8183"],
        "description": "Autonomous security guardrail oracle. Evaluates code generation tasks, simulates raw transactions, bypasses anti-bot WAFs, and gates execution.",
        "operator": {
            "wallet": MERCHANT_WALLET,
            "evm_wallet": MERCHANT_EVM_WALLET,
            "network": SOLANA_CAIP2,
        },
        "pricing": {
            "currency": "SOL",
            "base_fee_lamports": SINGLE_SCAN_LAMPORTS,
            "preflight_lamports": 350000,
            "scrape_lamports": 150000,
            "batch_10_voucher_lamports": SESSION_10_LAMPORTS,
        },
        "interfaces": {
            "mcp_remote": f"{CANONICAL_URL}/mcp",
            "mcp_sse": f"{CANONICAL_URL}/sse",
            "x402_api": f"{CANONICAL_URL}/api/v1/scan",
            "preflight_api": f"{CANONICAL_URL}/api/v1/preflight/simulate",
            "token_audit_api": f"{CANONICAL_URL}/api/v1/token/audit",
            "scraper_api": f"{CANONICAL_URL}/api/v1/oracle/scrape",
            "session_api": f"{CANONICAL_URL}/api/v1/session/deposit",
        },
    }


SKILL_MD = """---
name: scanpay
description: Deterministic code security scanner, Pre-flight Tx Shield, and Anti-Bot Scraper Oracle for AI agents. Audits code with deterministic auto_remediation, simulates blockchain transactions, and extracts clean web content via x402 micropayments.
---

# ScanPay Security Guardrail & Agent Oracle Skill

Use ScanPay whenever you need to:
1. **Audit generated code** before execution with deterministic `auto_remediation` (`scan_code`).
2. **Simulate a blockchain transaction** on Base or Solana before broadcasting (`simulate_tx`).
3. **Scrape anti-bot protected web pages** or documentation into clean Markdown (`scrape_url`).

## Available Tools

### 1. `scan_code`
Scan Python or JS/TS code for 45+ vulnerability patterns.
```json
{
  "source_code": "import ast\\n...",
  "language": "python",
  "auto_remediate": true
}
```

### 2. `simulate_tx`
Inspect an EVM or Solana transaction for drainer signatures, honeypots, or unbounded slippage.
```json
{
  "chain": "base",
  "tx": {
    "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "data": "0x095ea7b3..."
  }
}
```

### 3. `scrape_url`
Bypass Cloudflare Turnstile, extract clean Markdown from any web page.
```json
{
  "url": "https://docs.solana.com",
  "extract_mode": "markdown",
  "strip_media": true
}
```

## Remote MCP Access
- **JSON-RPC endpoint:** `POST https://scanpay-ob3w.onrender.com/mcp`
- **SSE Stream:** `GET https://scanpay-ob3w.onrender.com/sse`
"""

PAY_MD = """# ScanPay Multi-Chain Settlement Rules (x402 v2)

ScanPay accepts micropayments on both Solana and Base (EVM).

## Accepted Currencies & Pricing Matrix

| Service | Solana (SOL) | Solana (USDC) | Base (USDC) |
|---|---|---|---|
| **Code Scan** | 0.0007 SOL (700,000 lamports) | 0.10 USDC (100,000 units) | 0.10 USDC (100,000 units) |
| **Tx Simulation** | 0.00035 SOL (350,000 lamports) | 0.05 USDC (50,000 units) | 0.05 USDC (50,000 units) |
| **Token Rug Audit** | 0.00035 SOL (350,000 lamports) | 0.05 USDC (50,000 units) | 0.05 USDC (50,000 units) |
| **Scraper Oracle** | 0.00015 SOL (150,000 lamports) | 0.02 USDC (20,000 units) | 0.02 USDC (20,000 units) |
| **10-Credit Voucher** | 0.006 SOL (6,000,000 lamports) | 0.85 USDC (850,000 units) | 0.85 USDC (850,000 units) |

## Merchant Addresses
- **Solana Merchant Wallet:** `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`
- **Base (EVM) Merchant Wallet:** `0xb295E606F38C363b476FC546c27226B5fBcAAEFA`
- **Base USDC Contract:** `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
"""
