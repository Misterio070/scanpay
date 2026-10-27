"""Free-trial quota for agent self-onboarding.

Measured problem: every prospective buyer stopped at the 402 gate because there
was no way to check detection quality before paying. This module grants a small
number of real scans per client per UTC day, then returns the paywall.

Identity is a hash of (client IP, User-Agent). There is no account system by
design — an autonomous agent has no e-mail to sign up with. The quota lives in
the same SQLite file as the payment ledger so a restart does not reset it.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trial_usage (
    identity TEXT NOT NULL,
    day      TEXT NOT NULL,
    used     INTEGER NOT NULL DEFAULT 0,
    updated  REAL NOT NULL,
    PRIMARY KEY (identity, day)
);
"""


def init_trial_table(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def client_identity(ip: str, user_agent: str) -> str:
    """Stable per-client key. Not a security boundary — a rate-limit key."""
    raw = f"{(ip or '').strip()}|{(user_agent or '').strip()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _utc_day(now: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(now if now is not None else time.time()))


def consume_trial(db_path: str, identity: str, limit: int,
                  now: Optional[float] = None) -> dict:
    """Atomically claim one free scan.

    Returns {"allowed": bool, "used": int, "limit": int, "remaining": int,
             "resets_in": seconds_until_utc_midnight}
    """
    ts = now if now is not None else time.time()
    day = _utc_day(ts)
    midnight = (int(ts) // 86400 + 1) * 86400
    resets_in = max(0, midnight - int(ts))

    if limit <= 0:
        return {"allowed": False, "used": 0, "limit": 0,
                "remaining": 0, "resets_in": resets_in}

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT used FROM trial_usage WHERE identity = ? AND day = ?",
            (identity, day),
        ).fetchone()
        used = row[0] if row else 0
        if used >= limit:
            conn.rollback()
            return {"allowed": False, "used": used, "limit": limit,
                    "remaining": 0, "resets_in": resets_in}
        conn.execute(
            "INSERT INTO trial_usage (identity, day, used, updated) VALUES (?, ?, 1, ?) "
            "ON CONFLICT(identity, day) DO UPDATE SET used = used + 1, updated = excluded.updated",
            (identity, day, ts),
        )
        conn.commit()
        used += 1
        return {"allowed": True, "used": used, "limit": limit,
                "remaining": max(0, limit - used), "resets_in": resets_in}
    finally:
        conn.close()
