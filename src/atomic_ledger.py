import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Dict, Optional
from fastapi import HTTPException

# მუდმივი დისკის ბილიკი Render-ზე ეფემერული წაშლის თავიდან ასაცილებლად
DB_PATH = os.getenv("SCANPAY_DB_PATH", "/var/data/scanpay.db")
SESSION_HMAC_SECRET = os.getenv("SCANPAY_SESSION_SECRET", secrets.token_hex(32)).encode()

# წონითი კრედიტების ტარიფები (100 კრედიტი = $0.85 USDC / 0.006 SOL)
SERVICE_CREDIT_COST = {
    "scan_code": 10,       # ეფექტური ფასი: $0.085 (სტანდარტული $0.10)
    "simulate_tx": 5,      # ეფექტური ფასი: $0.0425 (სტანდარტული $0.05)
    "scrape_url": 2,       # ეფექტური ფასი: $0.017 (სტანდარტული $0.02)
}


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
        # WAL რეჟიმი და სინქრონიზაცია მაღალი კონკურენტულობის A2A ნაკადებისთვის
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")

        # 3-მდგომარეობიანი ტრანზაქციების ცხრილი (coinbase/x402#1062 და Replay დაცვა)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS payment_settlements (
                tx_signature TEXT PRIMARY KEY,
                action_ref TEXT UNIQUE NOT NULL,
                chain_caip2 TEXT NOT NULL,
                payer_address TEXT NOT NULL,
                amount_units INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('held', 'settled', 'ambiguous')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        """)

        # წინასწარ გადახდილი სესიის ვაუჩერების ცხრილი
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_vouchers (
                session_token_hash TEXT PRIMARY KEY,
                deposit_tx_signature TEXT UNIQUE NOT NULL,
                credits_remaining INTEGER NOT NULL CHECK(credits_remaining >= 0),
                last_nonce INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
        """)
        conn.commit()


@contextmanager
def atomic_immediate_tx():
    """ხსნის BEGIN IMMEDIATE ტრანზაქციას, რაც გამორიცხავს TOCTOU Race Condition-ს."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000;")
    try:
        conn.execute("BEGIN IMMEDIATE;")
        yield conn
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    finally:
        conn.close()


def _hash_token(raw_token: str) -> str:
    return hmac.new(SESSION_HMAC_SECRET, raw_token.encode(), hashlib.sha256).hexdigest()


def issue_session_voucher(deposit_tx_sig: str, ttl_seconds: int = 86400 * 7) -> Dict[str, any]:
    """ქმნის 100-კრედიტიან ვაუჩერს დეპოზიტის დადასტურების შემდეგ."""
    raw_token = f"sp_live_{secrets.token_urlsafe(32)}"
    token_hash = _hash_token(raw_token)
    now = int(time.time())
    expires_at = now + ttl_seconds

    with atomic_immediate_tx() as conn:
        conn.execute(
            """
            INSERT INTO session_vouchers (
                session_token_hash, deposit_tx_signature, credits_remaining, last_nonce, expires_at, created_at
            ) VALUES (?, ?, 100, 0, ?, ?)
            """,
            (token_hash, deposit_tx_sig, expires_at, now),
        )
    return {
        "session_token": raw_token,
        "credits_granted": 100,
        "expires_at": expires_at,
    }


def consume_session_credit_atomic(
    raw_token: str, service_name: str, request_nonce: Optional[int] = None
) -> Dict[str, int]:
    """
    ატომურად ჭრის კრედიტს 0ms RPC დაყოვნებით.
    იყენებს ერთიან UPDATE ... RETURNING კონსტრუქციას ორმაგი ხარჯვის გამოსარიცხად.
    """
    cost = SERVICE_CREDIT_COST.get(service_name, 10)
    token_hash = _hash_token(raw_token)
    now = int(time.time())

    with atomic_immediate_tx() as conn:
        if request_nonce is not None:
            row = conn.execute(
                """
                UPDATE session_vouchers
                SET credits_remaining = credits_remaining - ?,
                    last_nonce = ?
                WHERE session_token_hash = ?
                  AND credits_remaining >= ?
                  AND expires_at > ?
                  AND last_nonce < ?
                RETURNING credits_remaining, last_nonce;
                """,
                (cost, request_nonce, token_hash, cost, now, request_nonce),
            ).fetchone()
        else:
            row = conn.execute(
                """
                UPDATE session_vouchers
                SET credits_remaining = credits_remaining - ?,
                    last_nonce = last_nonce + 1
                WHERE session_token_hash = ?
                  AND credits_remaining >= ?
                  AND expires_at > ?
                RETURNING credits_remaining, last_nonce;
                """,
                (cost, token_hash, cost, now),
            ).fetchone()

        if not row:
            raise HTTPException(
                status_code=402,
                detail="Session voucher invalid, expired, nonce replayed, or insufficient credits.",
            )

        return {"credits_remaining": row[0], "nonce": row[1], "cost_deducted": cost}


def reserve_or_reconcile_x402_tx(
    tx_signature: str, action_ref: str, chain_caip2: str, payer: str, amount_units: int
) -> str:
    """
    coinbase/x402#1062 და #808 დაცვა:
    თუ RPC კვანძი აგვიანებს, ტრანზაქცია ინახება 'ambiguous' სტატუსში,
    რათა აგენტის ხელახალმა მოთხოვნამ (Retry) იგივე action_ref-ით არ გამოიწვიოს ორმაგი ჩამოჭრა.
    """
    now = int(time.time())
    with atomic_immediate_tx() as conn:
        existing = conn.execute(
            "SELECT status, action_ref FROM payment_settlements WHERE tx_signature = ?",
            (tx_signature,),
        ).fetchone()

        if existing:
            status, saved_ref = existing
            if status == "settled" and saved_ref != action_ref:
                raise HTTPException(status_code=409, detail="Replay attack blocked: tx_signature already consumed.")
            return status

        conn.execute(
            """
            INSERT INTO payment_settlements (
                tx_signature, action_ref, chain_caip2, payer_address, amount_units, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'held', ?, ?)
            """,
            (tx_signature, action_ref, chain_caip2, payer, amount_units, now, now),
        )
        return "held"


def build_x402_v2_challenge_headers(
    resource_path: str, usdc_units: int, lamports: int, description: str
) -> Dict[str, str]:
    """აგენერირებს x402 v2 სტანდარტის Base64 PAYMENT-REQUIRED ჰედერს."""
    payload = {
        "x402Version": 2,
        "resource": resource_path,
        "description": description,
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "maxAmountRequired": str(usdc_units),
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xb295E606F38C363b476FC546c27226B5fBcAAEFA",
            },
            {
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "maxAmountRequired": str(lamports),
                "asset": "native",
                "payTo": "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
            },
        ],
        "extensions": {
            "bazaar": {"discoverable": True, "category": "security-oracle"}
        },
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return {"PAYMENT-REQUIRED": encoded}