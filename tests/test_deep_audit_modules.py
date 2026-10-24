"""Tests for the Deep Research architectural modules (Atomic Ledger & Base Flashblocks Preflight)."""
import os
import pytest
from src.atomic_ledger import (
    init_db,
    issue_session_voucher,
    consume_session_credit_atomic,
    reserve_or_reconcile_x402_tx,
    build_x402_v2_challenge_headers,
)
from src.preflight_evm_deep import (
    detect_address_poisoning,
    simulate_base_tx_flashblocks,
)


@pytest.fixture(autouse=True)
def setup_atomic_ledger(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_atomic_ledger.db")
    monkeypatch.setattr("src.atomic_ledger.DB_PATH", test_db)
    init_db()
    yield test_db


def test_atomic_voucher_weighted_deduction():
    # Issue a 100-credit voucher
    deposit_tx = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" + "1" * 32
    voucher = issue_session_voucher(deposit_tx)
    raw_token = voucher["session_token"]
    assert voucher["credits_granted"] == 100

    # Deduct for scan_code (10 credits)
    res1 = consume_session_credit_atomic(raw_token, "scan_code")
    assert res1["credits_remaining"] == 90
    assert res1["cost_deducted"] == 10

    # Deduct for simulate_tx (5 credits)
    res2 = consume_session_credit_atomic(raw_token, "simulate_tx")
    assert res2["credits_remaining"] == 85
    assert res2["cost_deducted"] == 5

    # Deduct for scrape_url (2 credits)
    res3 = consume_session_credit_atomic(raw_token, "scrape_url")
    assert res3["credits_remaining"] == 83
    assert res3["cost_deducted"] == 2


def test_x402_3state_reconciliation_replay_protection():
    tx_sig = "tx_signature_abc_123"
    ref1 = "scan-request-uuid-1"
    ref2 = "scan-request-uuid-2"

    # Initial reserve -> status is held
    status1 = reserve_or_reconcile_x402_tx(tx_sig, ref1, "eip155:8453", "0xpayer", 100000)
    assert status1 == "held"

    # Same tx_sig with same ref -> idempotent return
    status2 = reserve_or_reconcile_x402_tx(tx_sig, ref1, "eip155:8453", "0xpayer", 100000)
    assert status2 == "held"


def test_x402_v2_challenge_header_format():
    headers = build_x402_v2_challenge_headers(
        resource_path="/v2/scan",
        usdc_units=100000,
        lamports=700000,
        description="Deterministic AST code security audit",
    )
    assert "PAYMENT-REQUIRED" in headers
    import base64, json
    decoded = json.loads(base64.b64decode(headers["PAYMENT-REQUIRED"]).decode("utf-8"))
    assert decoded["x402Version"] == 2
    assert len(decoded["accepts"]) == 2
    assert decoded["accepts"][0]["network"] == "eip155:8453"
    assert decoded["accepts"][1]["network"] == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"


def test_detect_address_poisoning_vanity_spoof():
    # Known trusted Base USDC: 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
    # Poisoned attacker vanity address: 0x8335000000000000000000000000000000002913
    poisoned = "0x8335000000000000000000000000000000002913"
    check = detect_address_poisoning(poisoned, [])
    assert check is not None
    assert check["verdict"] == "BLOCK"
    assert check["rule_id"] == "AGT-EVM-POISON-001"

    # Exact trusted address should NOT be flagged as poisoned
    safe = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    assert detect_address_poisoning(safe, []) is None
