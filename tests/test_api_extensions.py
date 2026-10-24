"""Tests for new API routes: Pre-flight Simulation & Scraper Oracle."""
import pytest


def test_preflight_simulate_402_challenge(client):
    # In disabled/unpaid mode without payment proof, expect 402 with x402 requirements
    payload = {
        "chain": "base",
        "tx": {
            "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "data": "0x",
            "value": 0,
        }
    }
    r = client.post("/api/v1/preflight/simulate", json=payload)
    assert r.status_code == 402
    assert "WWW-Authenticate" in r.headers
    data = r.json()
    assert data["error"] == "payment_required"
    assert data["paymentRequirements"]["amount"] == 350000  # 0.00035 SOL / 0.05 USDC


def test_preflight_simulate_with_session_voucher(client):
    # First create a mock session voucher in SQLite
    from src.session import create_session_voucher
    from main import DB_PATH

    v = create_session_voucher(DB_PATH, "mock_tx_sig_for_preflight_test_123", "payer_agent_1", credits=5)
    token = v["session_token"]

    payload = {
        "chain": "base",
        "tx": {
            "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "data": "0x",
            "value": 0,
        }
    }
    r = client.post("/v2/preflight/simulate", json=payload, headers={"X-SCANPAY-SESSION": token})
    assert r.status_code == 200
    data = r.json()
    assert data["schema_version"] == "2.0.0"
    assert data["chain"] == "base"
    assert data["execution_gate"]["verdict"] == "ALLOW"
    assert data["execution_gate"]["allow_broadcast"] is True
    assert "attestation" in data
    assert "X-SCANPAY-SIMULATION-VERDICT" in r.headers


def test_scraper_oracle_402_challenge(client):
    payload = {
        "url": "https://example.com/docs",
        "extract_mode": "markdown"
    }
    r = client.post("/api/v1/oracle/scrape", json=payload)
    assert r.status_code == 402
    data = r.json()
    assert data["error"] == "payment_required"
    assert data["paymentRequirements"]["amount"] == 150000  # 0.00015 SOL / 0.02 USDC


def test_scraper_oracle_with_session_voucher(client):
    from src.session import create_session_voucher
    from main import DB_PATH

    v = create_session_voucher(DB_PATH, "mock_tx_sig_for_scraper_test_456", "payer_agent_2", credits=5)
    token = v["session_token"]

    payload = {
        "url": "https://example.com",
        "extract_mode": "markdown",
        "strip_media": True,
    }
    r = client.post("/v2/oracle/scrape", json=payload, headers={"X-SCANPAY-SESSION": token})
    assert r.status_code == 200
    data = r.json()
    assert data["schema_version"] == "2.0.0"
    assert "metadata" in data
    assert "content" in data
    assert "bot_protection" in data
    assert "X-SCANPAY-WAF-DETECTED" in r.headers
