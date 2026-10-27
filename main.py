"""ScanPay — Paid code security scanner with x402 v2 payment discovery.

POST /api/v1/scan        — scan code (x402 payment required, disabled by default)
POST /v2/scan            — alias for A2A v2 scan endpoint
POST /api/v1/session/deposit — prepay 0.006 SOL for 10 instant scans
GET  /api/v1/products    — list available products
GET  /api/v1/health      — health check
GET  /api/v1/verify-payment/{tx_sig} — verify a Solana payment
GET  /.well-known/x402   — x402 v2 discovery manifest
GET  /bazaar.json        — Coinbase CDP Bazaar / Onyx Bazaar metadata
GET  /.well-known/mcp.json — MCP registry manifest
GET  /.well-known/agent-card.json — ERC-8004 A2A card
GET  /SKILL.md           — Agent Skill markdown
GET  /PAY.md             — Payment specification
POST /mcp                — Streamable HTTP MCP JSON-RPC
GET  /sse                — Streamable SSE MCP endpoint

x402 v2 payment flow:
1. Client requests a scan without payment → 402 with WWW-Authenticate: x402
   and a JSON body describing payment requirements.
2. Client pays via Solana transfer and receives a tx signature or uses a session voucher.
3. Client retries with X-PAYMENT or X-SCANPAY-SESSION header.
4. Server verifies the proof/voucher, runs the scan, returns MX v2 results.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import logging
import os
import sqlite3
import sys
import time
from typing import Any, Dict, Literal, Optional

from dotenv import load_dotenv
load_dotenv()

import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- Local Modules -----------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.discovery import (
    CANONICAL_URL,
    PAY_MD,
    SKILL_MD,
    get_agent_card,
    get_bazaar_manifest,
    get_well_known_mcp,
    get_well_known_x402,
)
from src.engine import RULES as PY_RULES, scan as scan_python, sha256_hex
from src.mcp_remote import build_diagnostic_preview, handle_mcp_jsonrpc
from src.preflight import simulate_transaction
from src.remediator import build_a2a_response
from src.scraper_oracle import scrape_url
from src.token_auditor import audit_token_contract
from src.session import (
    SESSION_BATCH_PRICE_LAMPORTS,
    consume_session_credit,
    create_session_voucher,
    get_session_voucher,
    init_session_table,
)

try:
    from src.engine_js import RULES as JS_RULES, scan as scan_javascript
    JS_AVAILABLE = True
except Exception:
    JS_AVAILABLE = False
    JS_RULES = []

# --- Logging -----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scanpay")

# --- Config ------------------------------------------------------------------
PaymentMode = Literal["disabled", "testnet", "mainnet"]

PAYMENT_MODE: PaymentMode = os.getenv("SCANPAY_PAYMENT_MODE", "mainnet")

_RPC_ENDPOINTS = {
    "disabled": "https://api.devnet.solana.com",
    "testnet": "https://api.devnet.solana.com",
    "mainnet": "https://api.mainnet-beta.solana.com",
}
SOLANA_RPC = os.getenv("SCANPAY_RPC_URL", os.getenv("SOLANA_RPC", _RPC_ENDPOINTS[PAYMENT_MODE]))

MERCHANT_WALLET = (os.getenv("SCANPAY_MERCHANT_WALLET") or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4").strip()
MERCHANT_EVM_WALLET = (os.getenv("SCANPAY_MERCHANT_EVM_WALLET") or "0xb295E606F38C363b476FC546c27226B5fBcAAEFA").strip()
BASE_RPC = os.getenv("SCANPAY_BASE_RPC", "https://mainnet.base.org")
BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_MINT_SOLANA = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

PRICE_LAMPORTS = int(os.getenv("SCANPAY_PRICE_LAMPORTS") or "700000")
PRICE_SOL = PRICE_LAMPORTS / 1_000_000_000

PAYMENT_TIMEOUT_S = 600
FREE_TRIAL_ENABLED = False
X402_VERSION = 2

PAYMENT_PROXY_URL = os.getenv("SCANPAY_PAYMENT_PROXY_URL", "")

DB_PATH = os.getenv("SCANPAY_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanpay.db"))

ENGINE_VERSION = "1.2.0"


# --- Database ----------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            tx_signature TEXT PRIMARY KEY,
            payer TEXT NOT NULL,
            amount_lamports INTEGER NOT NULL,
            network TEXT NOT NULL,
            created_at REAL NOT NULL,
            used INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_signature TEXT,
            language TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            findings_count INTEGER NOT NULL,
            max_severity TEXT,
            created_at REAL NOT NULL
        )
    """)
    init_session_table(conn)
    conn.commit()
    conn.close()


def check_payment(tx_sig: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT used, network FROM payments WHERE tx_signature = ?", (tx_sig,)
    ).fetchone()
    conn.close()
    if row is None:
        return False
    used, network = row
    if PAYMENT_MODE == "disabled":
        return False
    if PAYMENT_MODE == "testnet" and network != "testnet":
        return False
    return used == 0


def store_payment(tx_sig: str, payer: str, lamports: int, network: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO payments (tx_signature, payer, amount_lamports, network, created_at, used) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (tx_sig, payer, lamports, network, time.time())
    )
    conn.commit()
    conn.close()


def mark_payment_used(tx_sig: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "UPDATE payments SET used = 1 WHERE tx_signature = ? AND used = 0",
        (tx_sig,)
    )
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0


def record_scan(tx_sig: str, language: str, source_hash: str, findings_count: int, max_sev: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (tx_signature, language, source_sha256, findings_count, max_severity, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (tx_sig, language, source_hash, findings_count, max_sev, time.time())
    )
    conn.commit()
    conn.close()


# --- x402 v2 payment requirements & facilitator settlement -------------------

FACILITATOR_URLS = [
    os.getenv("SCANPAY_FACILITATOR_URL", "https://facilitator.payai.network").rstrip("/"),
    "https://x402.org/facilitator",
]
SOLANA_MAINNET_FEE_PAYER = "CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww"
SOLANA_DEVNET_FEE_PAYER = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"


def _decode_json_or_b64(raw_proof: str) -> Optional[dict]:
    """Attempt to parse a JSON or base64-encoded JSON x402 header."""
    cleaned = raw_proof.strip()
    if not cleaned:
        return None
    if cleaned.startswith("{"):
        try:
            obj = json.loads(cleaned)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    try:
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        if decoded.strip().startswith("{"):
            obj = json.loads(decoded)
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None
    return None


def is_facilitator_payload(parsed_json: Optional[dict]) -> bool:
    """Detect whether a parsed x402 JSON object is an off-chain signed facilitator payload."""
    if not isinstance(parsed_json, dict):
        return False
    payload_obj = parsed_json.get("payload")
    if not isinstance(payload_obj, dict):
        return False
    if "authorization" in payload_obj or "permit2Authorization" in payload_obj:
        return True
    tx_wire = payload_obj.get("transaction")
    if isinstance(tx_wire, str) and len(tx_wire) > 95:
        return True
    return False


def extract_payment_proof(raw_proof: Optional[str]) -> Optional[str]:
    """Decode raw or base64-encoded x402 v1/v2 payment headers into a tx hash/signature or facilitator payload."""
    if not raw_proof:
        return None
    cleaned = raw_proof.strip()
    if not cleaned:
        return None
    if cleaned.startswith("0x") and len(cleaned) == 66:
        return cleaned

    parsed_json = _decode_json_or_b64(cleaned)
    if isinstance(parsed_json, dict):
        if is_facilitator_payload(parsed_json):
            return cleaned
        payload_obj = parsed_json.get("payload") if isinstance(parsed_json.get("payload"), dict) else {}
        extracted = (
            parsed_json.get("tx_signature")
            or parsed_json.get("signature")
            or parsed_json.get("txHash")
            or parsed_json.get("hash")
            or parsed_json.get("tx")
            or payload_obj.get("tx_signature")
            or payload_obj.get("signature")
            or payload_obj.get("txHash")
            or payload_obj.get("hash")
            or payload_obj.get("transaction")
        )
        if extracted and isinstance(extracted, str):
            return extracted.strip()
    return cleaned


def build_x402_requirements(service: str = "scan") -> dict:
    if service == "preflight":
        lamports = 350000
        sol_display = "0.00035 SOL"
        usdc_units = 50000
        usdc_display = "0.05 USDC"
        eth_wei = 15000000000000
        eth_display = "0.000015 ETH"
        resource_path = f"{CANONICAL_URL}/api/v1/preflight/simulate"
        desc = "ScanPay: pre-flight transaction & drainer simulation"
        tags = ["tx-simulation", "drainer-shield", "mev-protection", "solana-x402", "base-x402"]
        body_fields = {
            "chain": {"type": "string", "description": "Target chain: 'base', 'ethereum', or 'solana'", "required": True},
            "tx": {"type": "object", "description": "Transaction object ({to, data, value} or {instructions})", "required": True},
        }
        output_example = {
            "execution_gate": {"verdict": "ALLOW", "risk_score": 0, "allow_broadcast": True},
            "findings": [],
        }
    elif service == "token":
        lamports = 350000
        sol_display = "0.00035 SOL"
        usdc_units = 50000
        usdc_display = "0.05 USDC"
        eth_wei = 15000000000000
        eth_display = "0.000015 ETH"
        resource_path = f"{CANONICAL_URL}/api/v1/token/audit"
        desc = "ScanPay: live on-chain token rug & honeypot audit"
        tags = ["token-auditor", "rug-detector", "honeypot-shield", "solana-x402", "base-x402"]
        body_fields = {
            "chain": {"type": "string", "description": "Target chain: 'base', 'ethereum', or 'solana'", "required": True},
            "token_address": {"type": "string", "description": "ERC-20 contract (0x...) or Solana SPL mint address", "required": True},
        }
        output_example = {
            "execution_gate": {"verdict": "SAFE", "risk_score": 0, "allow_trade": True},
            "findings": [],
        }
    elif service == "scrape":
        lamports = 150000
        sol_display = "0.00015 SOL"
        usdc_units = 20000
        usdc_display = "0.02 USDC"
        eth_wei = 6000000000000
        eth_display = "0.000006 ETH"
        resource_path = f"{CANONICAL_URL}/api/v1/oracle/scrape"
        desc = "ScanPay: anti-bot web scraping & LLM markdown extraction"
        tags = ["scraper-oracle", "anti-bot", "cloudflare-bypass", "markdown-extraction"]
        body_fields = {
            "url": {"type": "string", "description": "Target HTTPS URL to scrape into clean LLM Markdown", "required": True},
            "extract_mode": {"type": "string", "description": "'markdown' or 'text'", "required": False},
        }
        output_example = {
            "content": {"markdown": "# Clean Extracted Content", "estimated_tokens": 120},
            "bot_protection": {"waf_detected": False},
        }
    else:
        lamports = PRICE_LAMPORTS
        sol_display = f"{PRICE_SOL} SOL"
        usdc_units = 100000
        usdc_display = "0.10 USDC"
        eth_wei = 30000000000000
        eth_display = "0.00003 ETH"
        resource_path = f"{CANONICAL_URL}/api/v1/scan"
        desc = "ScanPay: deterministic AST code security scan & auto-remediation"
        tags = ["code-security", "ast-scanner", "a2a-guardrail", "solana-x402", "base-x402"]
        body_fields = {
            "source_code": {"type": "string", "description": "Source code to scan for vulnerabilities & drainers", "required": True},
            "language": {"type": "string", "description": "'python', 'javascript', 'typescript', or 'tsx'", "required": False},
        }
        output_example = {
            "execution_gate": {"verdict": "PASS", "risk_score": 0, "allow_execution": True},
            "findings_count": 0,
            "findings": [],
        }

    sol_net = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" if PAYMENT_MODE == "mainnet" else ("solana-" + PAYMENT_MODE if PAYMENT_MODE != "disabled" else "solana-devnet")
    sol_accept_net = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" if PAYMENT_MODE == "mainnet" else "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    sol_fee_payer = SOLANA_MAINNET_FEE_PAYER if PAYMENT_MODE == "mainnet" else SOLANA_DEVNET_FEE_PAYER
    sol_usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" if PAYMENT_MODE == "mainnet" else "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    sol_recipient = MERCHANT_WALLET or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"

    reqs = {
        "x402Version": X402_VERSION,
        "scheme": "solana",
        "network": sol_net,
        "amount": lamports,
        "maxAmountRequired": str(lamports),
        "amount_display": sol_display,
        "asset": "SOL",
        "recipient": sol_recipient,
        "payTo": sol_recipient,
        "resource": resource_path,
        "description": desc,
        "mimeType": "application/json",
        "maxTimeoutSeconds": PAYMENT_TIMEOUT_S,
        "extensions": {
            "bazaar": {
                "discoverable": True,
                "category": "security",
                "tags": tags,
                "info": {
                    "input": {
                        "type": "http",
                        "method": "POST",
                        "bodyType": "json",
                        "bodyFields": body_fields,
                    },
                    "output": {
                        "type": "json",
                        "example": output_example,
                    },
                },
            },
            "session_voucher": {
                "supported": True,
                "deposit_endpoint": f"{CANONICAL_URL}/api/v1/session/deposit",
                "batch_price_lamports": SESSION_BATCH_PRICE_LAMPORTS,
                "credits": 10
            }
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": BASE_USDC_CONTRACT,
                "tokenContract": BASE_USDC_CONTRACT,
                "amount": str(usdc_units),
                "maxAmountRequired": str(usdc_units),
                "amount_display": usdc_display,
                "recipient": MERCHANT_EVM_WALLET,
                "payTo": MERCHANT_EVM_WALLET,
                "resource": resource_path,
                "description": desc,
                "mimeType": "application/json",
                "maxTimeoutSeconds": PAYMENT_TIMEOUT_S,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                },
            },
            {
                "scheme": "exact",
                "network": sol_accept_net,
                "asset": sol_usdc_mint,
                "mint": sol_usdc_mint,
                "amount": str(usdc_units),
                "maxAmountRequired": str(usdc_units),
                "amount_display": usdc_display,
                "recipient": sol_recipient,
                "payTo": sol_recipient,
                "resource": resource_path,
                "description": desc,
                "mimeType": "application/json",
                "maxTimeoutSeconds": PAYMENT_TIMEOUT_S,
                "extra": {
                    "feePayer": sol_fee_payer,
                },
            },
        ],
        "nativeAccepts": [
            {
                "scheme": "solana",
                "network": sol_accept_net,
                "asset": "SOL",
                "amount": str(lamports),
                "maxAmountRequired": str(lamports),
                "amount_display": sol_display,
                "recipient": sol_recipient,
                "payTo": sol_recipient,
            },
            {
                "scheme": "evm",
                "network": "eip155:8453",
                "asset": "ETH",
                "amount": str(eth_wei),
                "maxAmountRequired": str(eth_wei),
                "amount_display": eth_display,
                "recipient": MERCHANT_EVM_WALLET,
                "payTo": MERCHANT_EVM_WALLET,
            },
        ],
    }
    if PAYMENT_PROXY_URL:
        reqs["paymentProxyUrl"] = PAYMENT_PROXY_URL
    return reqs


def x402_response(
    message: str = "Payment required",
    service: str = "scan",
    diagnostic_preview: Optional[dict] = None,
) -> JSONResponse:
    reqs = build_x402_requirements(service=service)
    reqs_json = json.dumps(reqs)

    # Strict @x402/core PaymentRequiredV2Schema + @boltzpay/protocols V2 header structure
    v2_header_payload = {
        "x402Version": X402_VERSION,
        "error": message,
        "resource": {
            "url": reqs["resource"],
            "description": reqs["description"],
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": a["scheme"],
                "network": a["network"],
                "amount": str(a["amount"]),
                "asset": a["asset"],
                "payTo": a["payTo"],
                "maxTimeoutSeconds": a["maxTimeoutSeconds"],
                "extra": a.get("extra", {}),
            }
            for a in reqs["accepts"]
        ],
        "extensions": reqs["extensions"],
    }
    reqs_b64 = base64.b64encode(json.dumps(v2_header_payload).encode("utf-8")).decode("utf-8")

    body: Dict[str, Any] = {
        "error": "payment_required",
        "message": message,
        "x402Version": X402_VERSION,
        "resource": v2_header_payload["resource"],
        "accepts": reqs["accepts"],
        "extensions": reqs["extensions"],
        "paymentRequirements": reqs,
    }
    if diagnostic_preview is not None:
        body["diagnostic_preview"] = diagnostic_preview
    return JSONResponse(
        status_code=402,
        content=body,
        headers={
            "WWW-Authenticate": "x402",
            "PAYMENT-REQUIRED": reqs_b64,
            "X-PAYMENT-REQUIREMENTS": reqs_json,
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-REQUIREMENTS, WWW-Authenticate",
        }
    )


async def settle_x402_facilitator_payload(raw_proof: str, service: str = "scan") -> Optional[dict]:
    """Settle an off-chain signed x402 V1/V2 payload (EIP-3009 on Base or partially signed tx on Solana) via x402 Facilitator."""
    parsed = _decode_json_or_b64(raw_proof)
    if not is_facilitator_payload(parsed):
        return None
    assert isinstance(parsed, dict)

    reqs = build_x402_requirements(service=service)
    accepted_from_client = parsed.get("accepted") if isinstance(parsed.get("accepted"), dict) else {}
    target_network = str(accepted_from_client.get("network") or parsed.get("network") or "")

    # Match against our canonical server-side payment requirements (never trust client-supplied payTo/amount)
    matched_req = None
    for candidate in reqs["accepts"]:
        if target_network and candidate["network"] == target_network:
            matched_req = candidate
            break
    if matched_req is None:
        payload_obj = parsed.get("payload", {})
        if "authorization" in payload_obj or "permit2Authorization" in payload_obj:
            matched_req = reqs["accepts"][0]  # Base USDC
        else:
            matched_req = reqs["accepts"][1]  # Solana USDC

    strict_requirement = {
        "scheme": matched_req["scheme"],
        "network": matched_req["network"],
        "amount": str(matched_req["amount"]),
        "asset": matched_req["asset"],
        "payTo": matched_req["payTo"],
        "maxTimeoutSeconds": matched_req["maxTimeoutSeconds"],
        "extra": matched_req.get("extra", {}),
    }

    last_err = "Unknown facilitator settlement error"
    async with httpx.AsyncClient(timeout=25) as client:
        for fac_url in FACILITATOR_URLS:
            try:
                resp = await client.post(
                    f"{fac_url}/settle",
                    json={
                        "x402Version": parsed.get("x402Version", 2),
                        "paymentPayload": parsed,
                        "paymentRequirements": strict_requirement,
                    },
                )
                data = resp.json()
                if resp.status_code == 200 and data.get("success") is True and data.get("transaction"):
                    net_str = str(data.get("network", strict_requirement["network"]))
                    net_label = "base" if "eip155" in net_str else ("mainnet" if PAYMENT_MODE == "mainnet" else PAYMENT_MODE)
                    return {
                        "valid": True,
                        "tx_signature": str(data["transaction"]),
                        "payer": str(data.get("payer") or "x402_agent"),
                        "amount_lamports": int(strict_requirement["amount"]),
                        "asset": "USDC",
                        "network": net_label,
                    }
                reason = data.get("errorReason") or data.get("errorMessage") or data.get("invalidReason") or resp.text[:200]
                last_err = f"{reason}"
                # If signature/authorization is explicitly invalid, don't retry secondary facilitator
                if "invalid" in str(reason).lower() or "insufficient" in str(reason).lower():
                    break
            except Exception as e:
                last_err = str(e)

    raise ValueError(f"x402 facilitator settlement failed: {last_err}")


# --- Solana & Base payment verification --------------------------------------

async def verify_solana_tx(tx_sig: str, min_lamports: int = PRICE_LAMPORTS, min_usdc: int = 100000) -> dict:
    if PAYMENT_MODE == "disabled":
        raise ValueError("Payment verification disabled (PAYMENT_MODE=disabled)")
    if not MERCHANT_WALLET:
        raise ValueError("No merchant wallet configured (SCANPAY_MERCHANT_WALLET empty)")

    network = PAYMENT_MODE if PAYMENT_MODE != "disabled" else "testnet"

    async with httpx.AsyncClient(timeout=30) as client:
        data: Dict[str, Any] = {}
        for attempt in range(3):
            resp = await client.post(SOLANA_RPC, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [tx_sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]
            })
            data = resp.json()
            if data.get("result"):
                break
            if attempt < 2:
                await asyncio.sleep(0.4)

        if not data.get("result"):
            raise ValueError("Transaction not found")

        tx = data["result"]
        if tx.get("meta", {}).get("err"):
            raise ValueError("Transaction failed on-chain")

        instructions = tx.get("transaction", {}).get("message", {}).get("instructions", [])
        for inst in instructions:
            parsed = inst.get("parsed", {})
            itype = parsed.get("type")
            info = parsed.get("info", {})

            # 1. Native SOL transfer
            if itype == "transfer" and "lamports" in info:
                dest = info.get("destination", "")
                lamports = int(info.get("lamports", 0))
                if dest == MERCHANT_WALLET and lamports >= min_lamports:
                    return {
                        "valid": True,
                        "payer": info.get("source", ""),
                        "amount_lamports": lamports,
                        "asset": "SOL",
                        "network": network,
                        "slot": tx.get("slot"),
                    }

            # 2. SPL Token transfer — must be real USDC into a merchant-owned account
            if itype in ("transfer", "transferChecked"):
                amount_str = info.get("amount") or (info.get("tokenAmount", {}).get("amount"))
                if not amount_str:
                    continue
                amt = int(amount_str)
                if amt < min_usdc:
                    continue

                dest_acct = info.get("destination") or ""
                mint = info.get("mint")
                owner = None

                # Resolve the destination token account: proves both the asset and
                # that the merchant actually owns it. A plain SPL `transfer` carries
                # no mint in its parsed form, so this lookup is the only honest way
                # to know what was sent — without it any minted token passes.
                if dest_acct:
                    try:
                        acc = await client.post(SOLANA_RPC, json={
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "getAccountInfo",
                            "params": [dest_acct, {"encoding": "jsonParsed"}],
                        })
                        parsed_info = (
                            acc.json().get("result", {})
                            .get("value", {})
                            .get("data", {})
                            .get("parsed", {})
                            .get("info", {})
                        )
                        owner = parsed_info.get("owner")
                        mint = parsed_info.get("mint") or mint
                    except Exception:
                        owner = None

                if mint != USDC_MINT_SOLANA:
                    continue
                if owner is not None and owner != MERCHANT_WALLET:
                    continue
                if owner is None:
                    # Could not prove the destination belongs to the merchant.
                    continue

                return {
                    "valid": True,
                    "payer": info.get("source", "") or info.get("authority", ""),
                    "amount_lamports": amt,
                    "asset": "USDC",
                    "network": network,
                    "slot": tx.get("slot"),
                }
        raise ValueError(f"No valid transfer to {MERCHANT_WALLET} of >= {min_lamports} lamports or >= {min_usdc / 1_000_000:.2f} USDC")


async def verify_evm_tx(tx_hash: str, min_usdc: int = 100000) -> dict:
    """Verify an EVM transaction on Base mainnet (USDC or native ETH)."""
    if PAYMENT_MODE == "disabled":
        raise ValueError("Payment verification disabled (PAYMENT_MODE=disabled)")

    recipient_padded = "0x" + MERCHANT_EVM_WALLET.lower().replace("0x", "").rjust(64, "0")
    net_label = "base" if PAYMENT_MODE == "mainnet" else PAYMENT_MODE

    async with httpx.AsyncClient(timeout=30) as client:
        receipt = None
        for attempt in range(3):
            resp = await client.post(BASE_RPC, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash]
            })
            data = resp.json()
            receipt = data.get("result")
            if receipt:
                break
            if attempt < 2:
                await asyncio.sleep(0.4)

        if not receipt:
            raise ValueError(f"Transaction receipt not found on Base ({tx_hash})")

        if receipt.get("status") != "0x1":
            raise ValueError("Transaction failed on Base")

        # 1. Parse event logs for ERC-20 USDC Transfer to merchant EVM wallet
        for log in receipt.get("logs", []):
            log_addr = log.get("address", "").lower()
            if log_addr and log_addr != BASE_USDC_CONTRACT.lower():
                continue
            topics = log.get("topics", [])
            if len(topics) >= 3 and topics[0].lower() == TRANSFER_EVENT_TOPIC:
                to_addr = topics[2].lower()
                if to_addr == recipient_padded:
                    value_hex = log.get("data", "0x0")
                    value = int(value_hex, 16)
                    if value >= min_usdc:
                        payer_addr = "0x" + topics[1][-40:]
                        return {
                            "valid": True,
                            "payer": payer_addr,
                            "amount_lamports": value,
                            "asset": "USDC",
                            "network": net_label,
                            "slot": int(receipt.get("blockNumber", "0x0"), 16),
                        }

        # 2. Fallback: Check Native Base ETH Transfer via eth_getTransactionByHash
        min_eth_wei = int(min_usdc) * 300_000_000  # e.g. 50,000 micro-USDC ($0.05) -> 1.5e13 wei (0.000015 ETH)
        try:
            tx_resp = await client.post(BASE_RPC, json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_getTransactionByHash",
                "params": [tx_hash]
            })
            tx_obj = tx_resp.json().get("result") or {}
            to_native = (tx_obj.get("to") or "").lower()
            val_wei = int(tx_obj.get("value", "0x0"), 16)
            if to_native == MERCHANT_EVM_WALLET.lower() and val_wei >= min_eth_wei:
                return {
                    "valid": True,
                    "payer": tx_obj.get("from", "unknown"),
                    "amount_lamports": val_wei,
                    "asset": "ETH",
                    "network": net_label,
                    "slot": int(receipt.get("blockNumber", "0x0"), 16),
                }
        except Exception:
            pass

        raise ValueError(f"No valid transfer to {MERCHANT_EVM_WALLET} of >= {min_usdc / 1_000_000:.2f} USDC or >= {min_eth_wei / 1e18:.6f} ETH found in receipt")


async def verify_mcp_payment(payment_proof: str, min_lamports: int = PRICE_LAMPORTS, min_usdc: int = 100000) -> str:
    """Verify and consume a single-call payment proof for Remote MCP JSON-RPC tools."""
    proof = extract_payment_proof(payment_proof) or payment_proof.strip()
    svc = "scrape" if min_usdc <= 20000 else ("token" if min_usdc <= 50000 else "scan")

    facilitator_res = await settle_x402_facilitator_payload(proof, service=svc)
    if facilitator_res:
        proof = facilitator_res["tx_signature"]
        store_payment(proof, facilitator_res["payer"], facilitator_res["amount_lamports"], facilitator_res["network"])
    elif not check_payment(proof):
        if proof.startswith("0x") and len(proof) == 66:
            result = await verify_evm_tx(proof, min_usdc=min_usdc)
        else:
            result = await verify_solana_tx(proof, min_lamports=min_lamports, min_usdc=min_usdc)
        store_payment(proof, result["payer"], result["amount_lamports"], result["network"])

    if not check_payment(proof) or not mark_payment_used(proof):
        raise ValueError("Payment proof already used. Each call requires a fresh payment or session voucher.")
    return proof


# --- Models ------------------------------------------------------------------

class ScanRequest(BaseModel):
    source_code: Optional[str] = Field(default=None, max_length=102400)
    code: Optional[str] = Field(default=None, max_length=102400)
    language: str = Field(default="python", pattern="^(python|javascript|typescript|tsx)$")
    tx_signature: Optional[str] = None
    auto_remediate: bool = True

    @model_validator(mode="after")
    def validate_code_presence(self):
        src = self.source_code if self.source_code is not None else self.code
        if src is None or len(src) == 0:
            raise ValueError("Either 'source_code' or 'code' must be non-empty")
        return self


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    language: str
    source_sha256: str
    syntax_ok: bool
    findings: list
    findings_count: int
    max_severity: str | None
    scan_duration_ms: float
    engine_version: str
    payment_mode: str
    charged: bool


class SessionDepositRequest(BaseModel):
    deposit_tx: str = Field(..., min_length=10)
    payer_wallet: Optional[str] = None


class PreflightRequest(BaseModel):
    chain: str = Field(default="base")
    tx: Dict[str, Any] = Field(...)
    tx_signature: Optional[str] = None


class TokenAuditRequest(BaseModel):
    chain: str = Field(default="base", pattern="^(base|ethereum|solana)$")
    token_address: str = Field(..., min_length=10, max_length=128)
    tx_signature: Optional[str] = None


class ScrapeRequest(BaseModel):
    url: str = Field(..., min_length=3)
    extract_mode: str = Field(default="markdown")
    strip_media: bool = Field(default=True)
    tx_signature: Optional[str] = None


class ProductInfo(BaseModel):
    id: str
    name: str
    price_sol: float
    price_usd_approx: float
    description: str
    available: bool


# --- App Lifespan ------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info(f"ScanPay starting — payment_mode={PAYMENT_MODE}, "
                f"js_engine={JS_AVAILABLE}, db={DB_PATH}")
    yield


app = FastAPI(
    title="ScanPay",
    description="Paid deterministic code security scanner. x402 v2 payment discovery, remote MCP, and session vouchers.",
    version=ENGINE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# --- Core Routes -------------------------------------------------------------

@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "js_engine_available": JS_AVAILABLE,
        "payment_mode": PAYMENT_MODE,
        "merchant_wallet": MERCHANT_WALLET if MERCHANT_WALLET else "<not configured>",
        "price_sol": PRICE_SOL,
        "x402_version": X402_VERSION,
        "free_trial_enabled": FREE_TRIAL_ENABLED,
    }


@app.get("/api/v1/products")
async def products():
    prods = [
        ProductInfo(
            id="python-scan",
            name="Python Security Scan",
            price_sol=PRICE_SOL,
            price_usd_approx=round(PRICE_SOL * 150, 2),
            description="Deterministic static AST analysis of Python code. Detects eval, exec, "
                        "os.system, pickle, secrets, wallet exfiltration, SSRF, and 28 vulnerability patterns.",
            available=PAYMENT_MODE != "disabled",
        ),
    ]
    if JS_AVAILABLE:
        prods.append(ProductInfo(
            id="js-scan",
            name="JavaScript/TypeScript Security Scan",
            price_sol=PRICE_SOL,
            price_usd_approx=round(PRICE_SOL * 150, 2),
            description="Tree-sitter AST analysis of JS/TS/TSX code. Detects eval, Function(), "
                        "child_process, prototype pollution, ReDoS, wallet exfiltration, and 29 vulnerability patterns.",
            available=PAYMENT_MODE != "disabled",
        ))
    prods.append(ProductInfo(
        id="preflight-simulation",
        name="Pre-Flight Transaction & Drainer Shield",
        price_sol=0.00035,
        price_usd_approx=0.05,
        description="Simulates EVM and Solana transactions before broadcast. Detects honeypots, unlimited token approvals, known drainers, and sandwich slippage traps.",
        available=PAYMENT_MODE != "disabled",
    ))
    prods.append(ProductInfo(
        id="token-audit",
        name="Live On-Chain Token Rug & Honeypot Auditor",
        price_sol=0.00035,
        price_usd_approx=0.05,
        description="Live on-chain token contract & SPL/Token-2022 audit on Base, Ethereum, and Solana. Detects freeze/mint authorities, Token-2022 Permanent Delegate wallet seizure, bytecode blacklists, mutable tax fees, and DEX honeypot liquidity.",
        available=PAYMENT_MODE != "disabled",
    ))
    prods.append(ProductInfo(
        id="scraper-oracle",
        name="Anti-Bot Web Access & Scraper Oracle",
        price_sol=0.00015,
        price_usd_approx=0.02,
        description="Stealth anti-bot web scraping bypassing Cloudflare Turnstile/WAF, returning clean LLM Markdown with cryptographic oracle attestation.",
        available=PAYMENT_MODE != "disabled",
    ))
    prods.append(ProductInfo(
        id="session-voucher-10",
        name="Prepaid Session Voucher (10 Credits)",
        price_sol=0.006,
        price_usd_approx=0.85,
        description="Prepaid batch of 10 operations valid across code scans, tx preflight simulations, and scraper requests. 15% discount with 0ms RPC latency bypass.",
        available=PAYMENT_MODE != "disabled",
    ))
    return prods


@app.get("/api/v1/scan")
@app.get("/v2/scan")
async def scan_code_quote():
    """x402 / BoltzPay / Bazaar GET quote & discovery endpoint for code scanning."""
    return x402_response(
        f"Payment required. Send {PRICE_SOL} SOL to {MERCHANT_WALLET} or 0.10 Base USDC to {MERCHANT_EVM_WALLET} "
        f"and call POST /api/v1/scan with X-PAYMENT or X-SCANPAY-SESSION header.",
        service="scan",
    )


@app.post("/api/v1/scan")
@app.post("/v2/scan")
async def scan_code(
    req: ScanRequest,
    request: Request,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
    payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE"),
    x_scanpay_session: Optional[str] = Header(None, alias="X-SCANPAY-SESSION"),
    x_payment_session: Optional[str] = Header(None, alias="X-PAYMENT-SESSION"),
):
    # 1. Session Voucher check (0ms RPC bypass)
    session_token = x_scanpay_session or x_payment_session
    payment_is_session = False
    payment_proof = None

    if session_token:
        claimed, remaining, msg = consume_session_credit(DB_PATH, session_token)
        if not claimed:
            raise HTTPException(status_code=402, detail=f"Session voucher invalid: {msg}")
        payment_proof = session_token
        payment_is_session = True

    # 2. Single-scan payment proof check
    if not payment_is_session:
        payment_proof = extract_payment_proof(x_payment or payment_signature or req.tx_signature)

        if not payment_proof:
            src_preview = req.source_code if req.source_code is not None else (req.code or "")
            preview = await build_diagnostic_preview("scan_code", {"code": src_preview, "language": req.language})
            return x402_response(
                f"Payment required. Send {PRICE_SOL} SOL to {MERCHANT_WALLET} or 0.10 Base USDC to {MERCHANT_EVM_WALLET} "
                f"and retry with X-PAYMENT or X-SCANPAY-SESSION header.",
                service="scan",
                diagnostic_preview=preview,
            )

        if PAYMENT_MODE == "disabled":
            return x402_response(
                "Payment verification disabled. Set SCANPAY_PAYMENT_MODE=testnet "
                "or mainnet to accept payments."
            )

        if not check_payment(payment_proof):
            try:
                facilitator_res = await settle_x402_facilitator_payload(payment_proof, service="scan")
                if facilitator_res:
                    payment_proof = facilitator_res["tx_signature"]
                    result = facilitator_res
                elif payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof)
                else:
                    result = await verify_solana_tx(payment_proof)
                store_payment(payment_proof, result["payer"],
                              result["amount_lamports"], result["network"])
            except ValueError as e:
                raise HTTPException(status_code=402, detail=f"Payment verification failed: {e}")
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"RPC error: {e}")

        if not check_payment(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used. Each scan requires a new payment.")

        if not mark_payment_used(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used. Each scan requires a new payment.")

    # --- Run AST Scan ---
    source = req.source_code if req.source_code is not None else req.code
    source_hash = sha256_hex(source)

    if req.language == "python":
        r = scan_python(source)
        findings = [f.model_dump() for f in r.findings]
        findings_objs = r.findings
        rules_cnt = len(PY_RULES)
    elif req.language in ("javascript", "typescript", "tsx") and JS_AVAILABLE:
        r = scan_javascript(source, language=req.language)
        findings = [f.model_dump() for f in r.findings]
        findings_objs = r.findings
        rules_cnt = len(JS_RULES)
    elif req.language in ("javascript", "typescript", "tsx") and not JS_AVAILABLE:
        raise HTTPException(status_code=503, detail="JS engine not available (tree-sitter not installed)")
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {req.language}")

    # Determine max severity
    max_sev = None
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for f in findings:
        sev = f.get("severity", "low")
        if max_sev is None or sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
            max_sev = sev

    # Record scan in database
    record_scan(payment_proof or "session", req.language, source_hash, len(findings), max_sev or "none")

    # Build A2A MX v2 Response
    a2a_dict = build_a2a_response(
        source=source,
        language=req.language,
        findings=findings_objs,
        execution_time_ms=r.scan_duration_ms,
        rules_evaluated=rules_cnt,
        merchant_wallet=MERCHANT_WALLET,
        payment_receipt=payment_proof,
    )

    verdict = a2a_dict.get("execution_gate", {}).get("verdict", "WARN")

    response_payload = {
        "language": req.language,
        "source_sha256": source_hash,
        "syntax_ok": r.syntax_ok,
        "findings": findings,
        "findings_count": len(findings),
        "max_severity": max_sev,
        "scan_duration_ms": r.scan_duration_ms,
        "engine_version": ENGINE_VERSION,
        "payment_mode": PAYMENT_MODE,
        "charged": PAYMENT_MODE != "disabled",
        **a2a_dict,
    }

    settled_net = "eip155:8453" if (payment_proof or "").startswith("0x") else "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    receipt_header = base64.b64encode(json.dumps({
        "success": True,
        "transaction": payment_proof or "session",
        "network": settled_net,
        "receipt": payment_proof,
        "status": "settled",
        "verdict": verdict,
    }).encode("utf-8")).decode("utf-8")

    return JSONResponse(
        content=response_payload,
        headers={
            "X-SCANPAY-VERDICT": verdict,
            "PAYMENT-RESPONSE": receipt_header,
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.post("/api/v1/session/deposit")
@app.post("/v2/session/deposit")
async def session_deposit(req: SessionDepositRequest):
    if PAYMENT_MODE == "disabled":
        return x402_response("Session deposits disabled in disabled mode.")

    deposit_proof = extract_payment_proof(req.deposit_tx) or req.deposit_tx.strip()

    try:
        if not check_payment(deposit_proof):
            if deposit_proof.startswith("0x") and len(deposit_proof) == 66:
                res = await verify_evm_tx(deposit_proof, min_usdc=850000)
            else:
                res = await verify_solana_tx(deposit_proof, min_lamports=SESSION_BATCH_PRICE_LAMPORTS, min_usdc=850000)
            store_payment(deposit_proof, res.get("payer", "unknown_agent"), res["amount_lamports"], res["network"])
            payer = req.payer_wallet or res.get("payer", "unknown_agent")
        else:
            payer = req.payer_wallet or "unknown_agent"

        if not check_payment(deposit_proof) or not mark_payment_used(deposit_proof):
            raise ValueError("Deposit transaction proof already used.")

        voucher = create_session_voucher(
            db_path=DB_PATH,
            deposit_tx=deposit_proof,
            payer=payer,
            credits=10,
        )
    except ValueError as e:
        raise HTTPException(status_code=402, detail=f"Deposit verification failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"RPC error: {e}")

    return JSONResponse(
        content={
            "status": "active",
            "message": "Prepaid session voucher activated. 10 instant scans available.",
            **voucher,
        },
        headers={
            "X-SCANPAY-SESSION": voucher["session_token"],
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.get("/api/v1/session/status")
@app.get("/v2/session/status")
async def session_status(
    session_token: Optional[str] = None,
    x_scanpay_session: Optional[str] = Header(None, alias="X-SCANPAY-SESSION"),
    x_payment_session: Optional[str] = Header(None, alias="X-PAYMENT-SESSION"),
):
    token = session_token or x_scanpay_session or x_payment_session
    if not token:
        raise HTTPException(status_code=400, detail="Provide session_token query param or X-SCANPAY-SESSION header.")
    voucher = get_session_voucher(DB_PATH, token.strip())
    if not voucher:
        raise HTTPException(status_code=404, detail="Session voucher not found.")
    now = time.time()
    return {
        "voucher_id": voucher["voucher_id"],
        "remaining_credits": voucher["remaining_credits"],
        "total_credits": voucher["total_credits"],
        "is_active": voucher["is_active"] and voucher["remaining_credits"] > 0 and voucher["expires_at"] > now,
        "expires_at": voucher["expires_at"],
    }


@app.get("/api/v1/stats")
async def service_stats():
    conn = sqlite3.connect(DB_PATH)
    try:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_payments = conn.execute("SELECT COUNT(*) FROM payments WHERE used = 1").fetchone()[0]
        active_vouchers = conn.execute("SELECT COUNT(*) FROM session_vouchers WHERE remaining_credits > 0").fetchone()[0]
    except Exception:
        total_scans, total_payments, active_vouchers = 0, 0, 0
    finally:
        conn.close()
    return {
        "status": "operational",
        "engine_version": ENGINE_VERSION,
        "payment_mode": PAYMENT_MODE,
        "rules_count": {"python": len(PY_RULES), "javascript_typescript": len(JS_RULES)},
        "supported_chains": ["solana", "base", "ethereum"],
        "accepted_assets": ["SOL", "USDC (Base)", "ETH (Base)", "USDC (Solana)"],
        "telemetry": {
            "total_scans_processed": total_scans,
            "settled_x402_payments": total_payments,
            "active_session_vouchers": active_vouchers,
        },
    }


# --- Pre-Flight Transaction & Drainer Shield ---------------------------------

@app.get("/api/v1/preflight/simulate")
@app.get("/v2/preflight/simulate")
async def preflight_simulate_quote():
    """x402 / BoltzPay GET quote & discovery endpoint for pre-flight simulation."""
    return x402_response("Payment required. Pre-flight simulation requires 0.05 USDC or 0.00035 SOL.", service="preflight")


@app.post("/api/v1/preflight/simulate")
@app.post("/v2/preflight/simulate")
async def preflight_simulate(
    req: PreflightRequest,
    request: Request,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
    payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE"),
    x_scanpay_session: Optional[str] = Header(None, alias="X-SCANPAY-SESSION"),
    x_payment_session: Optional[str] = Header(None, alias="X-PAYMENT-SESSION"),
):
    session_token = x_scanpay_session or x_payment_session
    payment_is_session = False
    payment_proof = None

    if session_token:
        claimed, remaining, msg = consume_session_credit(DB_PATH, session_token)
        if not claimed:
            raise HTTPException(status_code=402, detail=f"Session voucher invalid: {msg}")
        payment_proof = session_token
        payment_is_session = True

    if not payment_is_session:
        payment_proof = extract_payment_proof(x_payment or payment_signature or req.tx_signature)

        if not payment_proof:
            preview = await build_diagnostic_preview("simulate_tx", {"chain": req.chain, "tx": req.tx})
            return x402_response(
                "Payment required. Pre-flight simulation requires 0.05 USDC or 0.00035 SOL.",
                service="preflight",
                diagnostic_preview=preview,
            )

        if PAYMENT_MODE == "disabled":
            return x402_response("Payment verification disabled.", service="preflight")

        if not check_payment(payment_proof):
            try:
                facilitator_res = await settle_x402_facilitator_payload(payment_proof, service="preflight")
                if facilitator_res:
                    payment_proof = facilitator_res["tx_signature"]
                    result = facilitator_res
                elif payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof, min_usdc=50000)
                else:
                    result = await verify_solana_tx(payment_proof, min_lamports=350000, min_usdc=50000)
                store_payment(payment_proof, result["payer"], result["amount_lamports"], result["network"])
            except ValueError as e:
                raise HTTPException(status_code=402, detail=f"Payment verification failed: {e}")
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"RPC error: {e}")

        if not check_payment(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")
        if not mark_payment_used(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")

    res = simulate_transaction(
        chain=req.chain,
        tx_data=req.tx,
        merchant_wallet=MERCHANT_WALLET,
        payment_receipt=payment_proof,
    )

    verdict = res.get("execution_gate", {}).get("verdict", "WARN")
    status_header = "ALLOWED" if verdict == "ALLOW" else ("WARNED" if verdict == "WARN" else "BLOCKED")
    settled_net = "eip155:8453" if (payment_proof or "").startswith("0x") else "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

    receipt_header = base64.b64encode(json.dumps({
        "success": True,
        "transaction": payment_proof or "session",
        "network": settled_net,
        "receipt": payment_proof or "session",
        "service": "preflight",
        "timestamp": time.time(),
    }).encode("utf-8")).decode("utf-8")

    return JSONResponse(
        content=res,
        headers={
            "X-SCANPAY-SIMULATION-VERDICT": status_header,
            "PAYMENT-RESPONSE": receipt_header,
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-SCANPAY-SIMULATION-VERDICT",
        }
    )


# --- Live On-Chain Token Rug & Honeypot Auditor -------------------------------

@app.get("/api/v1/token/audit")
@app.get("/v2/token/audit")
async def token_audit_quote():
    """x402 / BoltzPay GET quote & discovery endpoint for live token auditing."""
    return x402_response("Payment required. Live token rug & honeypot audit requires 0.05 USDC or 0.00035 SOL.", service="token")


@app.post("/api/v1/token/audit")
@app.post("/v2/token/audit")
async def token_audit(
    req: TokenAuditRequest,
    request: Request,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
    payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE"),
    x_scanpay_session: Optional[str] = Header(None, alias="X-SCANPAY-SESSION"),
    x_payment_session: Optional[str] = Header(None, alias="X-PAYMENT-SESSION"),
):
    session_token = x_scanpay_session or x_payment_session
    payment_is_session = False
    payment_proof = None

    if session_token:
        claimed, remaining, msg = consume_session_credit(DB_PATH, session_token)
        if not claimed:
            raise HTTPException(status_code=402, detail=f"Session voucher invalid: {msg}")
        payment_proof = session_token
        payment_is_session = True

    if not payment_is_session:
        payment_proof = extract_payment_proof(x_payment or payment_signature or req.tx_signature)

        if not payment_proof:
            preview = await build_diagnostic_preview("audit_token", {"chain": req.chain, "token_address": req.token_address})
            return x402_response(
                "Payment required. Live token rug & honeypot audit requires 0.05 USDC or 0.00035 SOL.",
                service="token",
                diagnostic_preview=preview,
            )

        if PAYMENT_MODE == "disabled":
            return x402_response("Payment verification disabled.", service="token")

        if not check_payment(payment_proof):
            try:
                facilitator_res = await settle_x402_facilitator_payload(payment_proof, service="token")
                if facilitator_res:
                    payment_proof = facilitator_res["tx_signature"]
                    result = facilitator_res
                elif payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof, min_usdc=50000)
                else:
                    result = await verify_solana_tx(payment_proof, min_lamports=350000, min_usdc=50000)
                store_payment(payment_proof, result["payer"], result["amount_lamports"], result["network"])
            except ValueError as e:
                raise HTTPException(status_code=402, detail=f"Payment verification failed: {e}")
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"RPC error: {e}")

        if not check_payment(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")
        if not mark_payment_used(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")

    res = await audit_token_contract(
        chain=req.chain,
        token_address=req.token_address,
        merchant_wallet=MERCHANT_WALLET,
        payment_receipt=payment_proof,
    )

    verdict = res.get("execution_gate", {}).get("verdict", "WARN")
    settled_net = "eip155:8453" if (payment_proof or "").startswith("0x") else "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    receipt_header = base64.b64encode(json.dumps({
        "success": True,
        "transaction": payment_proof or "session",
        "network": settled_net,
        "receipt": payment_proof or "session",
        "service": "token",
        "verdict": verdict,
        "timestamp": time.time(),
    }).encode("utf-8")).decode("utf-8")

    return JSONResponse(
        content=res,
        headers={
            "X-SCANPAY-TOKEN-VERDICT": verdict,
            "PAYMENT-RESPONSE": receipt_header,
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-SCANPAY-TOKEN-VERDICT",
        }
    )


# --- Anti-Bot Web Access & Scraper Oracle ------------------------------------

@app.get("/api/v1/oracle/scrape")
@app.get("/v2/oracle/scrape")
async def oracle_scrape_quote():
    """x402 / BoltzPay GET quote & discovery endpoint for anti-bot scraper oracle."""
    return x402_response("Payment required. Anti-bot scraper oracle requires 0.02 USDC or 0.00015 SOL.", service="scrape")


@app.post("/api/v1/oracle/scrape")
@app.post("/v2/oracle/scrape")
async def oracle_scrape(
    req: ScrapeRequest,
    request: Request,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
    payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE"),
    x_scanpay_session: Optional[str] = Header(None, alias="X-SCANPAY-SESSION"),
    x_payment_session: Optional[str] = Header(None, alias="X-PAYMENT-SESSION"),
):
    session_token = x_scanpay_session or x_payment_session
    payment_is_session = False
    payment_proof = None

    if session_token:
        claimed, remaining, msg = consume_session_credit(DB_PATH, session_token)
        if not claimed:
            raise HTTPException(status_code=402, detail=f"Session voucher invalid: {msg}")
        payment_proof = session_token
        payment_is_session = True

    if not payment_is_session:
        payment_proof = extract_payment_proof(x_payment or payment_signature or req.tx_signature)

        if not payment_proof:
            return x402_response("Payment required. Anti-bot scraper oracle requires 0.02 USDC or 0.00015 SOL.", service="scrape")

        if PAYMENT_MODE == "disabled":
            return x402_response("Payment verification disabled.", service="scrape")

        if not check_payment(payment_proof):
            try:
                facilitator_res = await settle_x402_facilitator_payload(payment_proof, service="scrape")
                if facilitator_res:
                    payment_proof = facilitator_res["tx_signature"]
                    result = facilitator_res
                elif payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof, min_usdc=20000)
                else:
                    result = await verify_solana_tx(payment_proof, min_lamports=150000, min_usdc=20000)
                store_payment(payment_proof, result["payer"], result["amount_lamports"], result["network"])
            except ValueError as e:
                raise HTTPException(status_code=402, detail=f"Payment verification failed: {e}")
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"RPC error: {e}")

        if not check_payment(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")
        if not mark_payment_used(payment_proof):
            raise HTTPException(status_code=402, detail="Payment proof already used.")

    res = await scrape_url(
        url=req.url,
        extract_mode=req.extract_mode,
        strip_media=req.strip_media,
        merchant_wallet=MERCHANT_WALLET,
        payment_receipt=payment_proof,
    )

    settled_net = "eip155:8453" if (payment_proof or "").startswith("0x") else "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    receipt_header = base64.b64encode(json.dumps({
        "success": True,
        "transaction": payment_proof or "session",
        "network": settled_net,
        "receipt": payment_proof or "session",
        "service": "scrape",
        "timestamp": time.time(),
    }).encode("utf-8")).decode("utf-8")

    return JSONResponse(
        content=res,
        headers={
            "X-SCANPAY-WAF-DETECTED": str(res["bot_protection"]["waf_detected"]).lower(),
            "PAYMENT-RESPONSE": receipt_header,
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-SCANPAY-WAF-DETECTED",
        }
    )


@app.get("/api/v1/verify-payment/{tx_sig}")
async def verify_payment(tx_sig: str):
    if PAYMENT_MODE == "disabled":
        return {"valid": False, "error": "Payment verification disabled"}
    try:
        if tx_sig.startswith("0x") and len(tx_sig) == 66:
            result = await verify_evm_tx(tx_sig, min_usdc=20000)
        else:
            result = await verify_solana_tx(tx_sig, min_lamports=150000, min_usdc=20000)
        return {"valid": True, **result}
    except ValueError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": False, "error": f"RPC error: {e}"}


# --- Discovery Endpoints -----------------------------------------------------

@app.get("/.well-known/x402")
async def well_known_x402():
    return JSONResponse(
        content=get_well_known_x402(merchant=MERCHANT_WALLET, evm_merchant=MERCHANT_EVM_WALLET, price_lamports=PRICE_LAMPORTS),
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/bazaar.json")
async def bazaar_route():
    return JSONResponse(
        content=get_bazaar_manifest(MERCHANT_WALLET),
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/.well-known/mcp.json")
async def well_known_mcp():
    return JSONResponse(
        content=get_well_known_mcp(),
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/.well-known/agent-card.json")
async def well_known_agent_card():
    return JSONResponse(
        content=get_agent_card(),
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/SKILL.md")
async def skill_route():
    return Response(
        content=SKILL_MD,
        media_type="text/markdown",
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/PAY.md")
async def pay_route():
    return Response(
        content=PAY_MD,
        media_type="text/markdown",
        headers={"Access-Control-Allow-Origin": "*"}
    )


LLMS_TXT_CONTENT = """# ScanPay A2A Security Oracle & Infrastructure Suite

ScanPay is an autonomous security guardrail and oracle suite for AI agents with x402 v2 micropayments on Solana and Base.

- Production URL: https://scanpay-ob3w.onrender.com
- Remote MCP SSE: https://scanpay-ob3w.onrender.com/sse
- Remote MCP HTTP: https://scanpay-ob3w.onrender.com/mcp
- Multi-Chain Settlement:
  - Solana: Native SOL & SPL USDC (Merchant: `JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4`)
  - Base: Native USDC (Merchant: `0xb295E606F38C363b476FC546c27226B5fBcAAEFA`, USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)

## Core Capabilities & Services:

1. Code Security Scanner & Auto-Remediator (`scan_code`)
   - Endpoints: `POST /api/v1/scan`, `POST /v2/scan`
   - Pricing: 0.10 USDC or 0.0007 SOL
   - 45+ AST vulnerability patterns, deterministic patches, unified diffs, execution verdicts (PASS, WARN, BLOCK).

2. Pre-Flight Transaction & Drainer Shield (`simulate_tx`)
   - Endpoints: `POST /api/v1/preflight/simulate`, `POST /v2/preflight/simulate`
   - Pricing: 0.05 USDC or 0.00035 SOL
   - Preflight inspection for Base/Ethereum and Solana transactions. Detects honeypots, unlimited token approvals, known drainer contracts, and MEV sandwich traps.

3. Live On-Chain Token Rug & Honeypot Auditor (`audit_token`)
   - Endpoints: `POST /api/v1/token/audit`, `POST /v2/token/audit`
   - Pricing: 0.05 USDC or 0.00035 SOL
   - Live on-chain bytecode & token mint inspection on Base, Ethereum, and Solana. Detects freeze/mint authorities, Token-2022 Permanent Delegate wallet seizure, bytecode blacklists, mutable tax fees, and DEX honeypot liquidity.

4. Anti-Bot Web Access & Scraper Oracle (`scrape_url`)
   - Endpoints: `POST /api/v1/oracle/scrape`, `POST /v2/oracle/scrape`
   - Pricing: 0.02 USDC or 0.00015 SOL
   - Stealth browser headers, Cloudflare Turnstile/WAF bypass, HTML-to-clean-Markdown extraction saving ~90% LLM context tokens.

5. Prepaid Session Micro-Vouchers (`create_session_deposit`)
   - Endpoint: `POST /api/v1/session/deposit`
   - Pricing: 0.85 USDC or 0.006 SOL (10 credits valid across all tools with 0ms RPC bypass).
   - Authenticated via `X-SCANPAY-SESSION` header.

- GitHub: https://github.com/Misterio070/scanpay
"""

ROBOTS_TXT_CONTENT = """User-agent: *
Allow: /
Allow: /llms.txt
Allow: /.well-known/
Allow: /bazaar.json
Allow: /api/v1/products
Allow: /mcp
Allow: /sse

# Explicit Allow for Autonomous AI Crawlers
User-agent: GPTBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: Anthropic-AI
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: CCBot
Allow: /

User-agent: Bytespider
Allow: /

Sitemap: https://scanpay-ob3w.onrender.com/sitemap.xml
"""

SITEMAP_XML_CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://scanpay-ob3w.onrender.com/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/llms.txt</loc><changefreq>daily</changefreq><priority>0.9</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/bazaar.json</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/.well-known/x402</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/.well-known/mcp.json</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/.well-known/agent-card.json</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/api/v1/products</loc><changefreq>daily</changefreq><priority>0.8</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/SKILL.md</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/PAY.md</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://scanpay-ob3w.onrender.com/docs</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>
</urlset>
"""


@app.get("/llms.txt")
async def llms_txt_route():
    llms_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llms.txt")
    if os.path.exists(llms_path):
        with open(llms_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = LLMS_TXT_CONTENT
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/robots.txt")
async def robots_txt_route():
    return Response(
        content=ROBOTS_TXT_CONTENT,
        media_type="text/plain",
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/sitemap.xml")
async def sitemap_xml_route():
    return Response(
        content=SITEMAP_XML_CONTENT,
        media_type="application/xml",
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin_route():
    return JSONResponse(
        content={
            "schema_version": "v1",
            "name_for_model": "scanpay_security",
            "name_for_human": "ScanPay Security Suite",
            "description_for_model": "Scan code for vulnerabilities with AST analysis, simulate transactions before execution to block drainers/honeypots, and scrape protected web URLs bypassing WAFs. Supports x402 micropayments on Solana and Base.",
            "description_for_human": "Autonomous code security, transaction simulation, and scraping oracle for AI agents.",
            "auth": {"type": "none"},
            "api": {"type": "openapi", "url": "https://scanpay-ob3w.onrender.com/openapi.json"},
            "logo_url": "https://scanpay-ob3w.onrender.com/social-preview.svg",
            "contact_email": "alextaghiashvili@gmail.com",
            "legal_info_url": "https://github.com/Misterio070/scanpay"
        },
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/schemas/v2/scan-response.schema.json")
async def scan_response_schema():
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas", "v2", "scan-response.schema.json")
    if os.path.exists(schema_path):
        with open(schema_path, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f), headers={"Access-Control-Allow-Origin": "*"})
    raise HTTPException(status_code=404, detail="Schema not found")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="ScanPay A2A Security Oracle",
        version=ENGINE_VERSION,
        description="Deterministic AST code security scanner with x402 Solana micropayments, remote MCP, and ERC-8183 Evaluator oracle.",
        routes=app.routes,
    )
    openapi_schema["info"]["x-payment-protocol"] = "x402"
    openapi_schema["info"]["x-payment-version"] = 2
    openapi_schema["info"]["x-chain"] = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    openapi_schema["info"]["x-merchant-wallet"] = MERCHANT_WALLET
    openapi_schema["info"]["x-price-lamports"] = PRICE_LAMPORTS
    openapi_schema["info"]["x-price-sol"] = PRICE_SOL
    openapi_schema["info"]["x-bazaar-discoverable"] = True

    paths = openapi_schema.get("paths", {})
    for path in ["/api/v1/scan", "/v2/scan"]:
        if path in paths and "post" in paths[path]:
            paths[path]["post"]["x-upgrade-meta"] = {
                "protocol": "x402",
                "version": 2,
                "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "recipient": MERCHANT_WALLET,
                "amount": PRICE_LAMPORTS
            }
            if "responses" in paths[path]["post"]:
                paths[path]["post"]["responses"]["402"] = {
                    "description": "Payment Required — x402 v2 challenge",
                    "headers": {
                        "WWW-Authenticate": {
                            "description": "x402",
                            "schema": {"type": "string", "example": "x402"}
                        },
                        "X-PAYMENT-REQUIREMENTS": {
                            "description": "JSON payment requirement specification",
                            "schema": {"type": "string"}
                        }
                    }
                }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# --- Remote MCP Endpoints ----------------------------------------------------

@app.post("/mcp")
async def mcp_post(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    # Propagate HTTP-level x402 / session headers into JSON-RPC params._meta
    if isinstance(body, dict) and isinstance(body.get("params"), dict):
        hdr_session = request.headers.get("X-SCANPAY-SESSION") or request.headers.get("X-PAYMENT-SESSION")
        hdr_payment = extract_payment_proof(request.headers.get("X-PAYMENT") or request.headers.get("PAYMENT-SIGNATURE"))
        if hdr_session or hdr_payment:
            meta = dict(body["params"].get("_meta") or {})
            if hdr_session and "session_token" not in meta:
                meta["session_token"] = hdr_session
            if hdr_payment and "payment" not in meta:
                meta["payment"] = hdr_payment
            body["params"]["_meta"] = meta

    result = await handle_mcp_jsonrpc(
        request_data=body,
        merchant_wallet=MERCHANT_WALLET,
        payment_mode=PAYMENT_MODE,
        db_path=DB_PATH,
        verify_payment_callback=verify_mcp_payment,
    )
    return JSONResponse(content=result, headers={"Access-Control-Allow-Origin": "*"})


@app.get("/mcp")
async def mcp_get():
    return JSONResponse(
        content={
            "name": "ScanPay MCP Server",
            "version": ENGINE_VERSION,
            "status": "ready",
            "transports": ["http", "sse"],
            "endpoints": {
                "http": f"{CANONICAL_URL}/mcp",
                "sse": f"{CANONICAL_URL}/sse",
            },
        },
        headers={"Access-Control-Allow-Origin": "*"}
    )


@app.get("/sse")
async def sse_endpoint(request: Request):
    async def event_generator():
        yield "event: endpoint\ndata: /mcp\n\n"
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(15)
            yield ": ping\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


# --- Root Landing ------------------------------------------------------------

@app.get("/")
async def root():
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ScanPay v{ENGINE_VERSION} — Autonomous A2A Security Oracle</title>
  <style>
    :root {{
      --bg: #090a0f;
      --card-bg: #12151e;
      --border: #23283a;
      --primary: #00f2fe;
      --secondary: #4facfe;
      --text: #f0f3f8;
      --text-muted: #8b949e;
      --green: #10b981;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.6;
      padding: 40px 20px;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
    .logo {{ font-size: 26px; font-weight: 800; background: linear-gradient(135deg, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
    .badge {{ display: inline-flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.1); border: 1px solid var(--green); color: var(--green); padding: 4px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; font-family: var(--font-mono); }}
    .badge::before {{ content: ""; width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 10px var(--green); }}
    h1 {{ font-size: 36px; font-weight: 800; line-height: 1.2; margin-bottom: 16px; letter-spacing: -0.02em; }}
    p.lead {{ font-size: 18px; color: var(--text-muted); margin-bottom: 32px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 40px; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }}
    .card h3 {{ font-size: 18px; margin-bottom: 8px; }}
    .card .price {{ font-family: var(--font-mono); font-size: 15px; color: var(--primary); margin-bottom: 12px; }}
    .card p {{ font-size: 14px; color: var(--text-muted); }}
    .section-title {{ font-size: 22px; font-weight: 700; margin-bottom: 16px; margin-top: 32px; }}
    pre {{ background: #000; border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-x: auto; font-family: var(--font-mono); font-size: 13px; color: #a5d6ff; margin-bottom: 24px; }}
    .btn-group {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 24px; }}
    .btn {{ display: inline-block; background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 14px; transition: border-color 0.2s; }}
    .btn:hover {{ border-color: var(--primary); }}
    .btn.primary {{ background: linear-gradient(135deg, var(--secondary), var(--primary)); color: #000; font-weight: 600; border: none; }}
    footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; color: var(--text-muted); font-size: 13px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">⚡ ScanPay</div>
      <div class="badge">● LIVE ({PAYMENT_MODE.upper()} v{ENGINE_VERSION})</div>
    </header>

    <h1>Autonomous Security Oracle for AI Agents</h1>
    <p class="lead">Deterministic static AST code vulnerability scanner, live on-chain token rug/honeypot shield, pre-flight drainer shield, and anti-bot scraper oracle powered by x402 v2 micropayments on Solana & Base.</p>

    <div class="grid">
      <div class="card">
        <h3>🔍 AST Code Scanner</h3>
        <div class="price">0.0007 SOL / 0.10 Base USDC</div>
        <p>Deterministic AST inspection for Python, JS/TS/TSX. Detects code injection, wallet exfiltration, SSRF, prototype pollution with automated unified diffs.</p>
      </div>
      <div class="card">
        <h3>🪙 Live Token Rug & Honeypot Shield</h3>
        <div class="price">0.00035 SOL / 0.05 Base USDC</div>
        <p>Live on-chain bytecode & SPL/Token-2022 audit on Base, Ethereum & Solana. Detects Permanent Delegate wallet seizure, freeze/mint authorities, and DEX honeypot liquidity.</p>
      </div>
      <div class="card">
        <h3>🛡️ Pre-Flight Drainer Shield</h3>
        <div class="price">0.00035 SOL / 0.05 Base USDC</div>
        <p>Simulates EVM (Base Flashblocks 200ms) and Solana transactions before broadcast. Detects honeypots, unlimited token approvals, and sandwich traps.</p>
      </div>
      <div class="card">
        <h3>🎟️ Prepaid Session Voucher</h3>
        <div class="price">0.006 SOL / 0.85 Base USDC</div>
        <p>Prepaid 10-credit batch valid across all tools with 0ms RPC confirmation bypass. 15% discount for high-throughput autonomous agent loops.</p>
      </div>
    </div>

    <div class="card" style="margin-bottom: 40px; border-color: var(--primary);">
      <h3 style="margin-bottom: 12px;">⚡ Live Interactive Security Diagnostic & 1-Click x402 Unlock</h3>
      <p style="margin-bottom: 16px;">Test any code snippet or token contract below. Unpaid calls run our real-time threat engine and return a live <strong>402 Threat Diagnostic Preview</strong> — unlock full findings, auto-remediated patches, and cryptographic oracle attestations with a Base USDC / Solana tx signature or Session Voucher.</p>
      <div style="display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap;">
        <button onclick="setMode('token')" id="tab-token" class="btn primary" style="cursor:pointer;">🪙 Audit Token Rug/Honeypot ($0.05)</button>
        <button onclick="setMode('scan')" id="tab-scan" class="btn" style="cursor:pointer;">🔍 Scan Code AST ($0.10)</button>
      </div>
      <div id="input-token" style="display: block; margin-bottom: 12px;">
        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
          <select id="token-chain" style="background:#000; color:var(--text); border:1px solid var(--border); padding:10px; border-radius:6px; font-family:var(--font-mono);">
            <option value="base">Base Mainnet</option>
            <option value="solana">Solana Mainnet</option>
            <option value="ethereum">Ethereum Mainnet</option>
          </select>
          <input id="token-addr" type="text" value="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" placeholder="Token Contract or Mint Address (0x... or Solana Mint)" style="flex:1; min-width:260px; background:#000; color:var(--text); border:1px solid var(--border); padding:10px; border-radius:6px; font-family:var(--font-mono);" />
        </div>
      </div>
      <div id="input-scan" style="display: none; margin-bottom: 12px;">
        <textarea id="scan-code-input" rows="4" style="width:100%; background:#000; color:var(--text); border:1px solid var(--border); padding:10px; border-radius:6px; font-family:var(--font-mono);">import os, subprocess
API_KEY = "sk-live-9876543210abcdef9876543210abcdef"
eval(user_input)
subprocess.Popen(cmd, shell=True)</textarea>
      </div>
      <div style="display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap;">
        <input id="payment-proof" type="text" placeholder="Optional: Base/Solana Tx Hash (0x... / 5x...) or Session Token (sp_sess_...)" style="flex:1; min-width:260px; background:#000; color:var(--text); border:1px solid var(--border); padding:10px; border-radius:6px; font-family:var(--font-mono);" />
        <button onclick="runLiveDiagnostic()" class="btn primary" style="cursor:pointer; padding:10px 20px;">🚀 Run Security Check</button>
        <button onclick="payWithBaseWallet()" class="btn" style="cursor:pointer; border-color:var(--green); color:var(--green);">💳 1-Click Pay Base USDC (MetaMask/Coinbase)</button>
      </div>
      <pre id="live-output" style="margin-bottom:0; max-height:360px; overflow-y:auto;">Click "Run Security Check" to inspect a token or code snippet...</pre>
    </div>

    <script>
      let currentMode = 'token';
      function setMode(m) {{
        currentMode = m;
        document.getElementById('input-token').style.display = m === 'token' ? 'block' : 'none';
        document.getElementById('input-scan').style.display = m === 'scan' ? 'block' : 'none';
        document.getElementById('tab-token').className = m === 'token' ? 'btn primary' : 'btn';
        document.getElementById('tab-scan').className = m === 'scan' ? 'btn primary' : 'btn';
      }}
      async function runLiveDiagnostic() {{
        const out = document.getElementById('live-output');
        out.textContent = '⏳ Running live deterministic inspection...';
        const proof = document.getElementById('payment-proof').value.trim();
        const headers = {{ 'Content-Type': 'application/json' }};
        if (proof.startsWith('sp_sess_')) headers['X-SCANPAY-SESSION'] = proof;
        else if (proof) headers['X-PAYMENT'] = proof;
        try {{
          let url = '/api/v1/token/audit';
          let body = {{ chain: document.getElementById('token-chain').value, token_address: document.getElementById('token-addr').value.trim() }};
          if (currentMode === 'scan') {{
            url = '/api/v1/scan';
            body = {{ language: 'python', code: document.getElementById('scan-code-input').value }};
          }}
          const resp = await fetch(url, {{ method: 'POST', headers, body: JSON.stringify(body) }});
          const data = await resp.json();
          out.textContent = JSON.stringify(data, null, 2);
        }} catch (e) {{
          out.textContent = 'Error: ' + e.message;
        }}
      }}
      async function payWithBaseWallet() {{
        const out = document.getElementById('live-output');
        if (!window.ethereum) {{
          out.textContent = '⚠️ No injected Web3 wallet detected (MetaMask / Coinbase Wallet / Rabby). Send USDC on Base to {MERCHANT_EVM_WALLET} or SOL to {MERCHANT_WALLET} and paste the transaction hash above.';
          return;
        }}
        try {{
          const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
          await window.ethereum.request({{
            method: 'wallet_switchEthereumChain',
            params: [{{ chainId: '0x2105' }}]
          }});
          const usdcUnits = currentMode === 'scan' ? 100000 : 50000;
          const recipientClean = '{MERCHANT_EVM_WALLET}'.toLowerCase().replace('0x', '').padStart(64, '0');
          const amountHex = usdcUnits.toString(16).padStart(64, '0');
          const data = '0xa9059cbb' + recipientClean + amountHex;
          const txHash = await window.ethereum.request({{
            method: 'eth_sendTransaction',
            params: [{{
              from: accounts[0],
              to: '{BASE_USDC_CONTRACT}',
              data: data
            }}]
          }});
          document.getElementById('payment-proof').value = txHash;
          out.textContent = '✅ Base USDC Payment broadcasted! Tx: ' + txHash + '\\nWaiting 3 seconds for Base Flashblock confirmation before unlocking full report...';
          setTimeout(runLiveDiagnostic, 3500);
        }} catch (err) {{
          out.textContent = 'Wallet transaction cancelled or failed: ' + (err.message || err);
        }}
      }}
    </script>

    <div class="section-title">Zero-Install Agent Integration (MCP)</div>
    <pre><code>npx github:Misterio070/scanpay</code></pre>

    <div class="section-title">Remote MCP SSE Configuration (Claude Desktop / Cursor)</div>
    <pre><code>{{
  "mcpServers": {{
    "scanpay": {{
      "url": "https://scanpay-ob3w.onrender.com/sse"
    }}
  }}
}}</code></pre>

    <div class="section-title">Machine Discovery & Protocols</div>
    <div class="btn-group">
      <a href="/llms.txt" class="btn primary">📄 llms.txt</a>
      <a href="/docs" class="btn">⚡ OpenAPI Interactive Docs</a>
      <a href="/.well-known/x402" class="btn">💳 x402 Manifest</a>
      <a href="/bazaar.json" class="btn">🏪 Bazaar Manifest</a>
      <a href="/.well-known/mcp.json" class="btn">🤖 MCP Manifest</a>
      <a href="/.well-known/agent-card.json" class="btn">🪪 ERC-8004 Agent Card</a>
      <a href="/api/v1/products" class="btn">📦 Live Products</a>
      <a href="https://glama.ai/mcp/servers/Misterio070/scanpay" class="btn" target="_blank">⭐ Glama Index (Grade A)</a>
      <a href="https://github.com/Misterio070/scanpay" class="btn" target="_blank">🐙 GitHub Repository</a>
    </div>

    <footer>
      Settlement Wallets — Solana: <code style="font-family: var(--font-mono); color: var(--primary);">{MERCHANT_WALLET}</code> | Base EVM: <code style="font-family: var(--font-mono); color: var(--primary);">{MERCHANT_EVM_WALLET}</code><br>
      ScanPay v{ENGINE_VERSION} • ERC-8004 / ERC-8183 Compliant
    </footer>
  </div>
</body>
</html>""")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SCANPAY_PORT", "8484"))
    host = os.getenv("SCANPAY_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
