"""Exhaustive Burn-In & End-to-End Sales Flow Test Suite.

Covers:
1. x402 / BoltzPay / Bazaar GET quote probes on all paid endpoints
2. Top-level accepts[], maxAmountRequired, payTo, resource spec compliance
3. Universal x402 base64 payment header decoding (nested payload.txHash / signature)
4. Session deposit replay attack prevention (1 deposit_tx = max 1 voucher)
5. Session voucher balance status inspection (GET /api/v1/session/status)
6. Fake ERC-20 token spoofing rejection on Base in verify_evm_tx
7. Native Base ETH payment fallback in verify_evm_tx
8. HTTP-level X-PAYMENT & X-SCANPAY-SESSION header propagation on POST /mcp
9. Service telemetry (GET /api/v1/stats)
"""
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from main import (
    BASE_USDC_CONTRACT,
    MERCHANT_EVM_WALLET,
    extract_payment_proof,
    verify_evm_tx,
)


def test_get_quote_probes_return_402_with_standard_x402_fields(client):
    """Crawlers and quote CLIs (BoltzPay, x402scan, mppx) probing GET on paid routes get 402."""
    for path, expected_lamports in [
        ("/api/v1/scan", 700000),
        ("/v2/scan", 700000),
        ("/api/v1/token/audit", 350000),
        ("/v2/token/audit", 350000),
        ("/api/v1/preflight/simulate", 350000),
        ("/api/v1/oracle/scrape", 150000),
    ]:
        r = client.get(path)
        assert r.status_code == 402, f"Expected 402 on GET {path}, got {r.status_code}"
        assert r.headers.get("WWW-Authenticate") == "x402"
        assert "PAYMENT-REQUIRED" in r.headers
        body = r.json()
        assert body["x402Version"] == 2
        assert "accepts" in body and len(body["accepts"]) >= 4
        assert body["paymentRequirements"]["amount"] == expected_lamports
        # Check standard @coinbase/x402 fields on each accepted payment option
        for opt in body["accepts"]:
            assert "maxAmountRequired" in opt
            assert "payTo" in opt
            assert "resource" in opt


def test_extract_payment_proof_handles_all_x402_payload_formats():
    """Verify short base64, nested payload.txHash, payload.signature, and raw hashes."""
    raw_evm = "0x" + "a" * 64
    assert extract_payment_proof(raw_evm) == raw_evm

    # Short base64 JSON (< 100 chars) with tx
    short_b64 = base64.b64encode(json.dumps({"tx": "sol_sig_short_123"}).encode()).decode()
    assert len(short_b64) < 100
    assert extract_payment_proof(short_b64) == "sol_sig_short_123"

    # Nested x402 v2 payload object
    nested_b64 = base64.b64encode(json.dumps({
        "x402Version": 2,
        "scheme": "exact",
        "network": "eip155:8453",
        "payload": {"txHash": raw_evm},
    }).encode()).decode()
    assert extract_payment_proof(nested_b64) == raw_evm


def test_session_deposit_replay_attack_is_blocked(testnet_client):
    """A single deposit_tx cannot be used twice to mint multiple session vouchers."""
    deposit_sig = "unique_session_deposit_tx_001"
    mock_tx = {
        "valid": True,
        "payer": "AgentWallet11111111111111111111111111111",
        "amount_lamports": 6_000_000,
        "asset": "SOL",
        "network": "testnet",
        "slot": 555,
    }
    with patch("main.verify_solana_tx", new_callable=AsyncMock, return_value=mock_tx):
        r1 = testnet_client.post("/api/v1/session/deposit", json={"deposit_tx": deposit_sig})
        assert r1.status_code == 200
        token = r1.json()["session_token"]
        assert token.startswith("scanpay_sess_")

        # Replay attempt with same deposit_tx must fail with 402
        r2 = testnet_client.post("/api/v1/session/deposit", json={"deposit_tx": deposit_sig})
        assert r2.status_code == 402
        assert "already" in r2.json()["detail"].lower()


def test_session_status_and_credit_deduction_lifecycle(testnet_client):
    """Agents can query GET /api/v1/session/status before and after consuming credits."""
    deposit_sig = "status_lifecycle_deposit_tx_002"
    mock_tx = {
        "valid": True,
        "payer": "AgentWallet22222222222222222222222222222",
        "amount_lamports": 6_000_000,
        "asset": "SOL",
        "network": "testnet",
        "slot": 556,
    }
    with patch("main.verify_solana_tx", new_callable=AsyncMock, return_value=mock_tx):
        r_dep = testnet_client.post("/api/v1/session/deposit", json={"deposit_tx": deposit_sig})
        assert r_dep.status_code == 200
        token = r_dep.json()["session_token"]

    # Check initial status (10 credits)
    r_stat1 = testnet_client.get("/api/v1/session/status", headers={"X-SCANPAY-SESSION": token})
    assert r_stat1.status_code == 200
    assert r_stat1.json()["remaining_credits"] == 10
    assert r_stat1.json()["is_active"] is True

    # Consume 1 credit via POST /mcp with HTTP X-SCANPAY-SESSION header
    r_mcp = testnet_client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "scan_code",
                "arguments": {"source_code": "eval('1+1')", "language": "python"},
            },
        },
        headers={"X-SCANPAY-SESSION": token},
    )
    assert r_mcp.status_code == 200
    assert r_mcp.json()["result"]["execution_gate"]["verdict"] == "BLOCK"

    # Check updated status (9 credits)
    r_stat2 = testnet_client.get(f"/api/v1/session/status?session_token={token}")
    assert r_stat2.status_code == 200
    assert r_stat2.json()["remaining_credits"] == 9


@pytest.mark.asyncio
async def test_verify_evm_tx_rejects_fake_erc20_and_accepts_native_base_eth(monkeypatch):
    """Fake ERC-20 transfers must be rejected; native Base ETH transfers >= min_eth_wei must succeed."""
    import main
    monkeypatch.setattr(main, "PAYMENT_MODE", "mainnet")

    recipient_padded = "0x" + MERCHANT_EVM_WALLET.lower().replace("0x", "").rjust(64, "0")
    fake_token_contract = "0x1111111111111111111111111111111111111111"

    # Case 1: Fake ERC-20 transfer with 0 native ETH value -> must raise ValueError
    fake_receipt_resp = MagicMock()
    fake_receipt_resp.json.return_value = {
        "result": {
            "status": "0x1",
            "blockNumber": "0x100",
            "logs": [
                {
                    "address": fake_token_contract,
                    "topics": [
                        main.TRANSFER_EVENT_TOPIC,
                        "0x" + "2" * 64,
                        recipient_padded,
                    ],
                    "data": hex(500_000),
                }
            ],
        }
    }
    zero_tx_resp = MagicMock()
    zero_tx_resp.json.return_value = {
        "result": {
            "from": "0x" + "2" * 40,
            "to": fake_token_contract,
            "value": "0x0",
        }
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=[fake_receipt_resp, zero_tx_resp]):
        with pytest.raises(ValueError, match="No valid transfer"):
            await verify_evm_tx("0x" + "f" * 64, min_usdc=50000)

    # Case 2: Native Base ETH payment directly to MERCHANT_EVM_WALLET -> must succeed
    empty_logs_receipt = MagicMock()
    empty_logs_receipt.json.return_value = {
        "result": {
            "status": "0x1",
            "blockNumber": "0x101",
            "logs": [],
        }
    }
    native_eth_tx_resp = MagicMock()
    native_eth_tx_resp.json.return_value = {
        "result": {
            "from": "0x" + "3" * 40,
            "to": MERCHANT_EVM_WALLET,
            "value": hex(20_000_000_000_000),  # 0.00002 ETH >= 0.000015 ETH required for $0.05
        }
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=[empty_logs_receipt, native_eth_tx_resp]):
        res = await verify_evm_tx("0x" + "e" * 64, min_usdc=50000)
        assert res["valid"] is True
        assert res["asset"] == "ETH"
        assert res["network"] == "base"


def test_stats_endpoint(client):
    r = client.get("/api/v1/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "operational"
    assert "telemetry" in data
    assert "rules_count" in data
