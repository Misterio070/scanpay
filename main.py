"""ScanPay — Paid code security scanner with x402 v2 payment discovery.

POST /api/v1/scan        — scan code (x402 payment required, disabled by default)
GET  /api/v1/products    — list available products
GET  /api/v1/health      — health check
GET  /api/v1/verify-payment/{tx_sig} — verify a Solana payment (testnet only)

x402 v2 payment flow:
1. Client requests a scan without payment → 402 with WWW-Authenticate: x402
   and a JSON body describing payment requirements (chain, token, amount,
   recipient, payment-proxy URL).
2. Client pays via the x402 payment proxy and receives a payment proof.
3. Client retries with X-PAYMENT header containing the base64-encoded proof.
4. Server verifies the proof, runs the scan, returns results.

Payment modes (env SCANPAY_PAYMENT_MODE):
  disabled  — default; 402 returned with instructions, no verification (safe demo)
  testnet   — Solana devnet verification (no real value)
  mainnet   — Solana mainnet verification (OWNER-ONLY GATE, never default)

Revenue, if ever enabled, goes to the owner's SOL wallet (env-configured).
"""
from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
import time
import hashlib
import json
import sqlite3
import base64
import logging
from typing import Optional, Literal
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# --- Scanner engines ---------------------------------------------------------
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.engine import scan as scan_python, RULES as PY_RULES, sha256_hex

try:
    from src.engine_js import scan as scan_javascript
    JS_AVAILABLE = True
except Exception:
    JS_AVAILABLE = False

# --- Logging -----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scanpay")

# --- Config (fail-closed defaults) -------------------------------------------

PaymentMode = Literal["disabled", "testnet", "mainnet"]

PAYMENT_MODE: PaymentMode = os.getenv("SCANPAY_PAYMENT_MODE", "disabled")

# RPC endpoints per mode
_RPC_ENDPOINTS = {
    "disabled": "https://api.devnet.solana.com",  # never called, but valid URL
    "testnet": "https://api.devnet.solana.com",
    "mainnet": "https://api.mainnet-beta.solana.com",
}
SOLANA_RPC = os.getenv("SCANPAY_RPC_URL", os.getenv("SOLANA_RPC", _RPC_ENDPOINTS[PAYMENT_MODE]))

# Merchant wallet — env-driven, empty by default (fail-closed)
MERCHANT_WALLET = os.getenv("SCANPAY_MERCHANT_WALLET", "")

# Price in lamports (0.01 SOL = 10_000_000 lamports)
PRICE_LAMPORTS = int(os.getenv("SCANPAY_PRICE_LAMPORTS", "10000000"))
PRICE_SOL = PRICE_LAMPORTS / 1_000_000_000

# Payment window: 10 minutes
PAYMENT_TIMEOUT_S = 600

# Free trial is OFF by contract. This is non-negotiable.
FREE_TRIAL_ENABLED = False

# x402 version
X402_VERSION = 2

# Payment proxy URL (env-configured, for x402 discovery)
PAYMENT_PROXY_URL = os.getenv("SCANPAY_PAYMENT_PROXY_URL", "")

# Database path — keep on E: drive
DB_PATH = os.getenv("SCANPAY_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanpay.db"))

# Allow CORS from env (comma-separated), default localhost only
CORS_ORIGINS = [o.strip() for o in os.getenv("SCANPAY_CORS_ORIGINS",
    "http://localhost:8484,http://127.0.0.1:8484").split(",") if o.strip()]

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
    # In disabled mode, no payment is ever valid
    if PAYMENT_MODE == "disabled":
        return False
    # In testnet mode, only testnet payments are valid
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
    """Atomically mark a payment as used. Returns True if the payment was
    successfully claimed (was unused), False if it was already used or doesn't
    exist. This prevents TOCTOU race conditions under concurrent requests."""
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

def build_x402_requirements() -> dict:
    """Build x402 v2 payment requirements for the 402 response."""
    reqs = {
        "x402Version": X402_VERSION,
        "scheme": "solana",
        "network": "solana-" + PAYMENT_MODE if PAYMENT_MODE != "disabled" else "solana-devnet",
        "amount": PRICE_LAMPORTS,
        "amount_display": f"{PRICE_SOL} SOL",
        "asset": "SOL",
        "recipient": MERCHANT_WALLET,
        "description": "ScanPay: code security scan",
        "mimeType": "application/json",
        "maxTimeoutSeconds": PAYMENT_TIMEOUT_S,
        "accepts": [
            {
                "scheme": "solana",
                "network": "solana-" + ("devnet" if PAYMENT_MODE == "testnet" else
                                        "mainnet-beta" if PAYMENT_MODE == "mainnet" else "devnet"),
                "asset": "SOL",
                "amount": PRICE_LAMPORTS,
                "recipient": MERCHANT_WALLET or "<set SCANPAY_MERCHANT_WALLET>",
            }
        ],
    }
    if PAYMENT_PROXY_URL:
        reqs["paymentProxyUrl"] = PAYMENT_PROXY_URL
    return reqs

def x402_response(message: str = "Payment required") -> JSONResponse:
    """Return a proper x402 v2 402 response."""
    return JSONResponse(
        status_code=402,
        content={
            "error": "payment_required",
            "message": message,
            "x402Version": X402_VERSION,
            "paymentRequirements": build_x402_requirements(),
        },
        headers={
            "WWW-Authenticate": f"x402",
            "X-PAYMENT-REQUIREMENTS": json.dumps(build_x402_requirements()),
        }
    )

# --- Solana payment verification (testnet/mainnet only) -----------------------

async def verify_solana_tx(tx_sig: str) -> dict:
    """Verify a Solana transaction on-chain via RPC.

    Only called in testnet or mainnet mode. In disabled mode, this is never
    invoked — the 402 response simply tells the client how to pay, but no
    proof is ever accepted.
    """
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
            if parsed.get("type") == "transfer":
                info = parsed.get("info", {})
                dest = info.get("destination", "")
                lamports = int(info.get("lamports", 0))
                if dest == MERCHANT_WALLET and lamports >= PRICE_LAMPORTS:
                    return {
                        "valid": True,
                        "payer": info.get("source", ""),
                        "amount_lamports": lamports,
                        "network": network,
                        "slot": tx.get("slot"),
                    }
        raise ValueError(f"No valid transfer to {MERCHANT_WALLET} of >= {PRICE_LAMPORTS} lamports")

# --- Models ------------------------------------------------------------------

class ScanRequest(BaseModel):
    source_code: str = Field(..., min_length=1, max_length=102400)
    language: str = Field(default="python", pattern="^(python|javascript|typescript|tsx)$")
    tx_signature: Optional[str] = None  # Solana tx signature as payment proof

class ScanResponse(BaseModel):
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

class ProductInfo(BaseModel):
    id: str
    name: str
    price_sol: float
    price_usd_approx: float
    description: str
    available: bool

# --- App ---------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info(f"ScanPay starting — payment_mode={PAYMENT_MODE}, "
                f"js_engine={JS_AVAILABLE}, db={DB_PATH}")
    yield

app = FastAPI(
    title="ScanPay",
    description="Paid code security scanner. x402 v2 payment discovery.",
    version=ENGINE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- Routes ------------------------------------------------------------------

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
            description="Deterministic static analysis of Python code. Detects eval, exec, "
                        "os.system, pickle.loads, hardcoded secrets, and 30+ vulnerability patterns.",
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
                        "child_process, prototype pollution, ReDoS, and 23 vulnerability patterns.",
            available=PAYMENT_MODE != "disabled",
        ))
    return prods

@app.post("/api/v1/scan")
async def scan_code(
    req: ScanRequest,
    request: Request,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
):
    # --- Payment gate (x402 v2) ---
    payment_proof = x_payment or req.tx_signature

    if not payment_proof:
        # No payment proof → return x402 v2 402
        return x402_response(
            f"Payment required. Send {PRICE_SOL} SOL to "
            f"{MERCHANT_WALLET or '<set SCANPAY_MERCHANT_WALLET>'} "
            f"and retry with X-PAYMENT header."
        )

    # Payment proof provided — verify it
    if PAYMENT_MODE == "disabled":
        # In disabled mode, no proof is ever accepted
        return x402_response(
            "Payment verification disabled. Set SCANPAY_PAYMENT_MODE=testnet "
            "or mainnet to accept payments."
        )

    # Check if already verified and unused
    if not check_payment(payment_proof):
        try:
            result = await verify_solana_tx(payment_proof)
            store_payment(payment_proof, result["payer"],
                         result["amount_lamports"], result["network"])
        except ValueError as e:
            raise HTTPException(status_code=402, detail=f"Payment verification failed: {e}")
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"RPC error: {e}")

    # Replay prevention: reject if payment was already used
    if not check_payment(payment_proof):
        raise HTTPException(status_code=402, detail="Payment proof already used. Each scan requires a new payment.")

    # --- Run scan ---
    source = req.source_code
    source_hash = sha256_hex(source)

    if req.language == "python":
        r = scan_python(source)
        findings = [f.model_dump() for f in r.findings]
    elif req.language in ("javascript", "typescript", "tsx") and JS_AVAILABLE:
        r = scan_javascript(source, language=req.language)
        findings = [f.model_dump() for f in r.findings]
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

    # Atomically claim the payment — prevents TOCTOU race under concurrent requests
    if not mark_payment_used(payment_proof):
        raise HTTPException(status_code=402, detail="Payment proof already used. Each scan requires a new payment.")

    # Record scan
    record_scan(payment_proof, req.language, source_hash, len(findings), max_sev or "none")

    return ScanResponse(
        language=req.language,
        source_sha256=source_hash,
        syntax_ok=r.syntax_ok,
        findings=findings,
        findings_count=len(findings),
        max_severity=max_sev,
        scan_duration_ms=r.scan_duration_ms,
        engine_version=ENGINE_VERSION,
        payment_mode=PAYMENT_MODE,
        charged=PAYMENT_MODE != "disabled",
    )

@app.get("/api/v1/verify-payment/{tx_sig}")
async def verify_payment(tx_sig: str):
    """Verify a Solana payment transaction (testnet/mainnet only)."""
    if PAYMENT_MODE == "disabled":
        return {"valid": False, "error": "Payment verification disabled"}
    try:
        result = await verify_solana_tx(tx_sig)
        return {"valid": True, **result}
    except ValueError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": False, "error": f"RPC error: {e}"}

@app.get("/")
async def root():
    """Landing page with service info."""
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>ScanPay</title></head><body>
<h1>ScanPay</h1>
<p>Paid code security scanner with x402 v2 payment discovery.</p>
<ul>
  <li><b>Engine:</b> {ENGINE_VERSION}</li>
  <li><b>Payment mode:</b> {PAYMENT_MODE}</li>
  <li><b>JS engine:</b> {'available' if JS_AVAILABLE else 'unavailable'}</li>
  <li><b>x402 version:</b> {X402_VERSION}</li>
</ul>
<p>Endpoints:</p>
<ul>
  <li><code>GET /api/v1/health</code></li>
  <li><code>GET /api/v1/products</code></li>
  <li><code>POST /api/v1/scan</code> (payment required)</li>
  <li><code>GET /api/v1/verify-payment/{{tx_sig}}</code></li>
</ul>
</body></html>""")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SCANPAY_PORT", "8484"))
    host = os.getenv("SCANPAY_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)