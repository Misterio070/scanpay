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
from src.mcp_remote import handle_mcp_jsonrpc
from src.preflight import simulate_transaction
from src.remediator import build_a2a_response
from src.scraper_oracle import scrape_url
from src.session import (
    SESSION_BATCH_PRICE_LAMPORTS,
    consume_session_credit,
    create_session_voucher,
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

PAYMENT_MODE: PaymentMode = os.getenv("SCANPAY_PAYMENT_MODE", "disabled")

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
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

PRICE_LAMPORTS = int(os.getenv("SCANPAY_PRICE_LAMPORTS") or "700000")
PRICE_SOL = PRICE_LAMPORTS / 1_000_000_000

PAYMENT_TIMEOUT_S = 600
FREE_TRIAL_ENABLED = False
X402_VERSION = 2

PAYMENT_PROXY_URL = os.getenv("SCANPAY_PAYMENT_PROXY_URL", "")

DB_PATH = os.getenv("SCANPAY_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanpay.db"))

ENGINE_VERSION = "1.1.0"


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


# --- x402 v2 payment requirements ---------------------------------------------

def build_x402_requirements(service: str = "scan") -> dict:
    if service == "preflight":
        lamports = 350000
        sol_display = "0.00035 SOL"
        usdc_units = 50000
        usdc_display = "0.05 USDC"
        desc = "ScanPay: pre-flight transaction & drainer simulation"
        tags = ["tx-simulation", "drainer-shield", "mev-protection", "solana-x402"]
    elif service == "scrape":
        lamports = 150000
        sol_display = "0.00015 SOL"
        usdc_units = 20000
        usdc_display = "0.02 USDC"
        desc = "ScanPay: anti-bot web scraping & LLM markdown extraction"
        tags = ["scraper-oracle", "anti-bot", "cloudflare-bypass", "markdown-extraction"]
    else:
        lamports = PRICE_LAMPORTS
        sol_display = f"{PRICE_SOL} SOL"
        usdc_units = 100000
        usdc_display = "0.10 USDC"
        desc = "ScanPay: code security scan"
        tags = ["code-security", "ast-scanner", "a2a-guardrail", "solana-x402"]

    reqs = {
        "x402Version": X402_VERSION,
        "scheme": "solana",
        "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" if PAYMENT_MODE == "mainnet" else ("solana-" + PAYMENT_MODE if PAYMENT_MODE != "disabled" else "solana-devnet"),
        "amount": lamports,
        "amount_display": sol_display,
        "asset": "SOL",
        "recipient": MERCHANT_WALLET or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
        "description": desc,
        "mimeType": "application/json",
        "maxTimeoutSeconds": PAYMENT_TIMEOUT_S,
        "extensions": {
            "bazaar": {
                "discoverable": True,
                "category": "security",
                "tags": tags,
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
                "scheme": "solana",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" if PAYMENT_MODE == "mainnet" else ("solana-" + ("devnet" if PAYMENT_MODE == "testnet" else "devnet")),
                "asset": "SOL",
                "amount": lamports,
                "amount_display": sol_display,
                "recipient": MERCHANT_WALLET or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
            },
            {
                "scheme": "solana",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" if PAYMENT_MODE == "mainnet" else ("solana-" + ("devnet" if PAYMENT_MODE == "testnet" else "devnet")),
                "asset": "USDC",
                "amount": usdc_units,
                "amount_display": usdc_display,
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "recipient": MERCHANT_WALLET or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
            },
            {
                "scheme": "evm",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": usdc_units,
                "amount_display": usdc_display,
                "tokenContract": BASE_USDC_CONTRACT,
                "recipient": MERCHANT_EVM_WALLET,
            },
        ],
    }
    if PAYMENT_PROXY_URL:
        reqs["paymentProxyUrl"] = PAYMENT_PROXY_URL
    return reqs


def x402_response(message: str = "Payment required", service: str = "scan") -> JSONResponse:
    reqs = build_x402_requirements(service=service)
    return JSONResponse(
        status_code=402,
        content={
            "error": "payment_required",
            "message": message,
            "x402Version": X402_VERSION,
            "paymentRequirements": reqs,
        },
        headers={
            "WWW-Authenticate": "x402",
            "X-PAYMENT-REQUIREMENTS": json.dumps(reqs),
            "Access-Control-Allow-Origin": "*",
        }
    )


# --- Solana payment verification ---------------------------------------------

async def verify_solana_tx(tx_sig: str, min_lamports: int = PRICE_LAMPORTS) -> dict:
    if PAYMENT_MODE == "disabled":
        raise ValueError("Payment verification disabled (PAYMENT_MODE=disabled)")
    if not MERCHANT_WALLET:
        raise ValueError("No merchant wallet configured (SCANPAY_MERCHANT_WALLET empty)")

    network = PAYMENT_MODE if PAYMENT_MODE != "disabled" else "testnet"

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(SOLANA_RPC, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [tx_sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]
        })
        data = resp.json()
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

            # 2. SPL Token transfer (USDC: 100,000 micro-USDC = 0.10 USDC)
            if itype in ("transfer", "transferChecked"):
                amount_str = info.get("amount") or (info.get("tokenAmount", {}).get("amount"))
                if amount_str:
                    amt = int(amount_str)
                    if amt >= 100000:
                        return {
                            "valid": True,
                            "payer": info.get("source", "") or info.get("authority", ""),
                            "amount_lamports": amt,
                            "asset": "USDC",
                            "network": network,
                            "slot": tx.get("slot"),
                        }
        raise ValueError(f"No valid transfer to {MERCHANT_WALLET} of >= {min_lamports} lamports or >= 0.10 USDC")


async def verify_evm_tx(tx_hash: str, min_usdc: int = 100000) -> dict:
    """Verify an EVM transaction on Base mainnet (USDC or native ETH)."""
    if PAYMENT_MODE == "disabled":
        raise ValueError("Payment verification disabled (PAYMENT_MODE=disabled)")

    recipient_padded = "0x" + MERCHANT_EVM_WALLET.lower().replace("0x", "").rjust(64, "0")

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(BASE_RPC, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash]
        })
        data = resp.json()
        receipt = data.get("result")
        if not receipt:
            raise ValueError(f"Transaction receipt not found on Base ({tx_hash})")

        if receipt.get("status") != "0x1":
            raise ValueError("Transaction failed on Base")

        # Parse event logs for ERC-20 Transfer to merchant EVM wallet
        for log in receipt.get("logs", []):
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
                            "network": "base",
                            "slot": int(receipt.get("blockNumber", "0x0"), 16),
                        }

        raise ValueError(f"No valid transfer to {MERCHANT_EVM_WALLET} of >= 0.10 USDC found in receipt")


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
        id="scraper-oracle",
        name="Anti-Bot Web Access & Scraper Oracle",
        price_sol=0.00015,
        price_usd_approx=0.02,
        description="Stealth anti-bot web scraping bypassing Cloudflare Turnstile/WAF, returning clean LLM Markdown with cryptographic oracle attestation.",
        available=PAYMENT_MODE != "disabled",
    ))
    return prods


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
        payment_proof = x_payment or payment_signature or req.tx_signature

        # Handle potential base64-encoded x402 v2 payment payload
        if payment_proof and len(payment_proof) > 100:
            try:
                decoded = base64.b64decode(payment_proof).decode("utf-8")
                parsed_json = json.loads(decoded)
                payment_proof = parsed_json.get("tx_signature") or parsed_json.get("signature") or payment_proof
            except Exception:
                pass

        if not payment_proof:
            return x402_response(
                f"Payment required. Send {PRICE_SOL} SOL to {MERCHANT_WALLET} "
                f"and retry with X-PAYMENT or X-SCANPAY-SESSION header."
            )

        if PAYMENT_MODE == "disabled":
            return x402_response(
                "Payment verification disabled. Set SCANPAY_PAYMENT_MODE=testnet "
                "or mainnet to accept payments."
            )

        if not check_payment(payment_proof):
            try:
                if payment_proof.startswith("0x") and len(payment_proof) == 66:
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

    receipt_header = base64.b64encode(json.dumps({
        "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
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

    try:
        res = await verify_solana_tx(req.deposit_tx, min_lamports=SESSION_BATCH_PRICE_LAMPORTS)
        payer = req.payer_wallet or res.get("payer", "unknown_agent")
    except ValueError as e:
        raise HTTPException(status_code=402, detail=f"Deposit verification failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"RPC error: {e}")

    voucher = create_session_voucher(
        db_path=DB_PATH,
        deposit_tx=req.deposit_tx,
        payer=payer,
        credits=10,
    )

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


# --- Pre-Flight Transaction & Drainer Shield ---------------------------------

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
        payment_proof = x_payment or payment_signature or req.tx_signature
        if payment_proof and len(payment_proof) > 100:
            try:
                decoded = base64.b64decode(payment_proof).decode("utf-8")
                parsed_json = json.loads(decoded)
                payment_proof = parsed_json.get("tx_signature") or parsed_json.get("signature") or payment_proof
            except Exception:
                pass

        if not payment_proof:
            return x402_response("Payment required. Pre-flight simulation requires 0.05 USDC or 0.00035 SOL.", service="preflight")

        if PAYMENT_MODE == "disabled":
            return x402_response("Payment verification disabled.", service="preflight")

        if not check_payment(payment_proof):
            try:
                if payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof, min_usdc=50000)
                else:
                    result = await verify_solana_tx(payment_proof, min_lamports=350000)
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

    return JSONResponse(
        content=res,
        headers={
            "X-SCANPAY-SIMULATION-VERDICT": status_header,
            "Access-Control-Allow-Origin": "*",
        }
    )


# --- Anti-Bot Web Access & Scraper Oracle ------------------------------------

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
        payment_proof = x_payment or payment_signature or req.tx_signature
        if payment_proof and len(payment_proof) > 100:
            try:
                decoded = base64.b64decode(payment_proof).decode("utf-8")
                parsed_json = json.loads(decoded)
                payment_proof = parsed_json.get("tx_signature") or parsed_json.get("signature") or payment_proof
            except Exception:
                pass

        if not payment_proof:
            return x402_response("Payment required. Anti-bot scraper oracle requires 0.02 USDC or 0.00015 SOL.", service="scrape")

        if PAYMENT_MODE == "disabled":
            return x402_response("Payment verification disabled.", service="scrape")

        if not check_payment(payment_proof):
            try:
                if payment_proof.startswith("0x") and len(payment_proof) == 66:
                    result = await verify_evm_tx(payment_proof, min_usdc=20000)
                else:
                    result = await verify_solana_tx(payment_proof, min_lamports=150000)
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

    return JSONResponse(
        content=res,
        headers={
            "X-SCANPAY-WAF-DETECTED": str(res["bot_protection"]["waf_detected"]).lower(),
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.get("/api/v1/verify-payment/{tx_sig}")
async def verify_payment(tx_sig: str):
    if PAYMENT_MODE == "disabled":
        return {"valid": False, "error": "Payment verification disabled"}
    try:
        result = await verify_solana_tx(tx_sig)
        return {"valid": True, **result}
    except ValueError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": False, "error": f"RPC error: {e}"}


# --- Discovery Endpoints -----------------------------------------------------

@app.get("/.well-known/x402")
async def well_known_x402():
    return JSONResponse(
        content=get_well_known_x402(MERCHANT_WALLET, PRICE_LAMPORTS),
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


@app.get("/llms.txt")
async def llms_txt_route():
    llms_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llms.txt")
    if os.path.exists(llms_path):
        with open(llms_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "# ScanPay"
    return Response(
        content=content,
        media_type="text/plain",
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
    result = await handle_mcp_jsonrpc(
        request_data=body,
        merchant_wallet=MERCHANT_WALLET,
        payment_mode=PAYMENT_MODE,
        db_path=DB_PATH,
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
<html><head><title>ScanPay</title></head><body>
<h1>ScanPay</h1>
<p>Paid deterministic code security scanner for AI agents with x402 v2 payment discovery and auto-remediation.</p>
<ul>
  <li><b>Engine:</b> {ENGINE_VERSION}</li>
  <li><b>Payment mode:</b> {PAYMENT_MODE}</li>
  <li><b>JS engine:</b> {'available' if JS_AVAILABLE else 'unavailable'}</li>
  <li><b>x402 version:</b> {X402_VERSION}</li>
  <li><b>Remote MCP:</b> <code>POST /mcp</code>, <code>GET /sse</code></li>
</ul>
<p>Discovery Endpoints:</p>
<ul>
  <li><code>GET /.well-known/x402</code></li>
  <li><code>GET /bazaar.json</code></li>
  <li><code>GET /.well-known/mcp.json</code></li>
  <li><code>GET /.well-known/agent-card.json</code></li>
  <li><code>GET /SKILL.md</code></li>
  <li><code>GET /PAY.md</code></li>
  <li><code>GET /api/v1/health</code></li>
  <li><code>POST /api/v1/scan</code></li>
  <li><code>POST /api/v1/session/deposit</code></li>
</ul>
</body></html>""")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SCANPAY_PORT", "8484"))
    host = os.getenv("SCANPAY_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
