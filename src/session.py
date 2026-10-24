"""ScanPay Session Voucher Engine.

Prepaid x402 session tokens (ephemeral micro-vouchers) for high-frequency
autonomous agent coding loops (e.g. 0.85 USDC / 0.006 SOL for 10 instant operations).
Eliminates on-chain transaction settlement latency during iterative code generation.
Includes thread-safe atomic WAL transactions and race-condition immunity.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
import uuid
from typing import Any, Optional


SESSION_SECRET = os.getenv("SCANPAY_SESSION_SECRET", "scanpay_sess_sec_402_deterministic_key")
SESSION_BATCH_PRICE_LAMPORTS = int(os.getenv("SCANPAY_SESSION_LAMPORTS", "6000000"))  # 0.006 SOL for 10 scans
SESSION_BATCH_CREDITS = 10


def init_session_table(conn: sqlite3.Connection):
    """Ensure session_vouchers table exists with WAL mode enabled for high concurrency."""
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session_vouchers (
            voucher_id TEXT PRIMARY KEY,
            session_token TEXT UNIQUE NOT NULL,
            payer TEXT NOT NULL,
            deposit_tx TEXT NOT NULL,
            total_credits INTEGER NOT NULL,
            remaining_credits INTEGER NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.commit()


def generate_session_token(voucher_id: str, payer: str) -> str:
    """Generate tamper-proof HMAC-signed session token."""
    raw = f"{voucher_id}:{payer}:{time.time()}"
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"scanpay_sess_{voucher_id}_{sig}"


def create_session_voucher(
    db_path: str,
    deposit_tx: str,
    payer: str,
    credits: int = SESSION_BATCH_CREDITS,
    expiry_days: int = 30,
) -> dict[str, Any]:
    """Create a new prepaid session voucher in the database atomically."""
    voucher_id = str(uuid.uuid4())[:12]
    session_token = generate_session_token(voucher_id, payer)
    now = time.time()
    expires_at = now + (expiry_days * 86400)

    conn = sqlite3.connect(db_path, timeout=10.0)
    init_session_table(conn)
    conn.execute(
        """
        INSERT INTO session_vouchers 
        (voucher_id, session_token, payer, deposit_tx, total_credits, remaining_credits, created_at, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (voucher_id, session_token, payer, deposit_tx, credits, credits, now, expires_at),
    )
    conn.commit()
    conn.close()

    return {
        "voucher_id": voucher_id,
        "session_token": session_token,
        "payer": payer,
        "deposit_tx": deposit_tx,
        "total_credits": credits,
        "remaining_credits": credits,
        "created_at": now,
        "expires_at": expires_at,
        "status": "active",
    }


def get_session_voucher(db_path: str, session_token: str) -> Optional[dict[str, Any]]:
    """Retrieve session voucher by token."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    init_session_table(conn)
    cursor = conn.execute(
        """
        SELECT voucher_id, session_token, payer, deposit_tx, total_credits, remaining_credits, created_at, expires_at, is_active
        FROM session_vouchers
        WHERE session_token = ?
        """,
        (session_token,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "voucher_id": row[0],
        "session_token": row[1],
        "payer": row[2],
        "deposit_tx": row[3],
        "total_credits": row[4],
        "remaining_credits": row[5],
        "created_at": row[6],
        "expires_at": row[7],
        "is_active": bool(row[8]),
    }


def consume_session_credit(db_path: str, session_token: str) -> tuple[bool, int, str]:
    """Atomically consume 1 credit from the session voucher using SQLite UPDATE ... RETURNING.
    
    Immune to TOCTOU (Time-of-Check to Time-of-Use) race conditions under high concurrency.
    Returns (success, remaining_credits, message).
    """
    conn = sqlite3.connect(db_path, timeout=10.0)
    init_session_table(conn)
    now = time.time()

    # Single atomic query to check validity, decrement credit, and return updated balance
    cursor = conn.execute(
        """
        UPDATE session_vouchers
        SET remaining_credits = remaining_credits - 1
        WHERE session_token = ? 
          AND remaining_credits > 0 
          AND expires_at > ? 
          AND is_active = 1
        RETURNING remaining_credits;
        """,
        (session_token, now),
    )
    row = cursor.fetchone()
    conn.commit()
    conn.close()

    if row is not None:
        new_remaining = row[0]
        return True, new_remaining, f"Credit consumed. {new_remaining} credits remaining."

    # If atomic update returned nothing, inspect reason for diagnostic message
    existing = get_session_voucher(db_path, session_token)
    if not existing:
        return False, 0, "Session voucher not found"
    if not existing["is_active"]:
        return False, existing["remaining_credits"], "Session voucher is inactive"
    if now > existing["expires_at"]:
        return False, existing["remaining_credits"], "Session voucher has expired"
    if existing["remaining_credits"] <= 0:
        return False, 0, "Session voucher depleted (0 credits remaining)"

    return False, 0, "Failed to consume credit (concurrent depletion)"
