"""Test x402 payment gate: 402 response shape, replay prevention, network/amount/recipient binding.

These tests verify the payment gate logic without hitting the actual Solana RPC.
We mock verify_solana_tx to simulate on-chain verification results.
"""
import json
import time
import pytest
from unittest.mock import AsyncMock, patch


class TestX402Discovery:
    """x402 v2 discovery: 402 response shape and headers."""

    def test_no_payment_returns_402(self, client):
        """Scan without payment proof returns 402 with x402 headers."""
        r = client.post("/api/v1/scan", json={
            "source_code": "x = 1",
            "language": "python",
        })
        assert r.status_code == 402
        assert r.headers["WWW-Authenticate"] == "x402"
        body = r.json()
        assert body["error"] == "payment_required"
        assert body["x402Version"] == 2
        reqs = body["paymentRequirements"]
        assert reqs["scheme"] == "solana"
        assert reqs["asset"] == "SOL"
        assert "amount" in reqs
        assert "accepts" in reqs
        assert len(reqs["accepts"]) >= 1

    def test_402_has_payment_requirements_header(self, client):
        """402 response includes X-PAYMENT-REQUIREMENTS header with JSON."""
        r = client.post("/api/v1/scan", json={
            "source_code": "x = 1",
            "language": "python",
        })
        assert r.status_code == 402
        header_reqs = json.loads(r.headers["X-PAYMENT-REQUIREMENTS"])
        assert header_reqs["x402Version"] == 2
        assert header_reqs["scheme"] == "solana"

    def test_disabled_mode_rejects_all_payment_proofs(self, client):
        """In disabled mode, even with payment proof, 402 is returned."""
        r = client.post("/api/v1/scan", json={
            "source_code": "x = 1",
            "language": "python",
        }, headers={"X-PAYMENT": "faketx123"})
        assert r.status_code == 402
        assert "disabled" in r.json()["message"].lower()

    def test_disabled_mode_products_unavailable(self, client):
        """Products show available=False in disabled mode."""
        r = client.get("/api/v1/products")
        assert r.status_code == 200
        for p in r.json():
            assert p["available"] is False


class TestPaymentReplayPrevention:
    """A payment proof must only be usable once (replay prevention)."""

    def test_payment_cannot_be_reused(self, testnet_client):
        """After a successful scan, the same tx_signature cannot be used again."""
        fake_tx = "replay_test_tx_001"
        mock_result = {
            "valid": True,
            "payer": "FakePayer111111111111111111111111111111111",
            "amount_lamports": 10_000_000,
            "network": "testnet",
            "slot": 12345,
        }
        with patch("main.verify_solana_tx", new_callable=AsyncMock, return_value=mock_result):
            # First scan — should succeed
            r1 = testnet_client.post("/api/v1/scan", json={
                "source_code": "x = 1",
                "language": "python",
            }, headers={"X-PAYMENT": fake_tx})
            assert r1.status_code == 200
            assert r1.json()["charged"] is True

            # Second scan with same tx — should fail (replay prevention)
            r2 = testnet_client.post("/api/v1/scan", json={
                "source_code": "y = 2",
                "language": "python",
            }, headers={"X-PAYMENT": fake_tx})
            # After the replay-prevention fix, the second scan must be rejected
            assert r2.status_code == 402
            assert "already used" in r2.json().get("detail", "").lower()


class TestPaymentNetworkBinding:
    """Payments must be network-bound: testnet mode rejects mainnet payments."""

    def test_testnet_rejects_mainnet_payment(self, testnet_client):
        """In testnet mode, a mainnet payment should be rejected."""
        fake_tx = "mainnet_tx_on_testnet_001"
        # Simulate a mainnet payment verification result
        mock_result = {
            "valid": True,
            "payer": "FakePayer111111111111111111111111111111111",
            "amount_lamports": 10_000_000,
            "network": "mainnet",  # Wrong network!
            "slot": 99999,
        }
        with patch("main.verify_solana_tx", new_callable=AsyncMock, return_value=mock_result):
            r = testnet_client.post("/api/v1/scan", json={
                "source_code": "x = 1",
                "language": "python",
            }, headers={"X-PAYMENT": fake_tx})
            # The payment is stored with network=mainnet, then check_payment
            # in testnet mode checks: network != "testnet" → return False
            # So the scan is rejected with 402.
            assert r.status_code == 402, (
                f"Expected 402 for mainnet payment in testnet mode, got {r.status_code}: {r.text}"
            )

    def test_disabled_mode_never_verifies(self, client):
        """In disabled mode, verify_solana_tx should never be called."""
        with patch("main.verify_solana_tx", new_callable=AsyncMock) as mock_verify:
            r = client.post("/api/v1/scan", json={
                "source_code": "x = 1",
                "language": "python",
            }, headers={"X-PAYMENT": "anyproof"})
            assert r.status_code == 402
            mock_verify.assert_not_awaited()


class TestPaymentAmountBinding:
    """Payments must meet the minimum amount threshold."""

    def test_insufficient_amount_rejected(self, testnet_client):
        """A payment below PRICE_LAMPORTS should be rejected by verify_solana_tx."""
        fake_tx = "low_amount_tx_001"
        # verify_solana_tx raises ValueError if no transfer >= PRICE_LAMPORTS
        with patch("main.verify_solana_tx", new_callable=AsyncMock,
                   side_effect=ValueError("No valid transfer of >= 10000000 lamports")):
            r = testnet_client.post("/api/v1/scan", json={
                "source_code": "x = 1",
                "language": "python",
            }, headers={"X-PAYMENT": fake_tx})
            assert r.status_code == 402
            assert "verification failed" in r.json()["detail"].lower()


class TestPaymentRecipientBinding:
    """Payments must go to the configured merchant wallet."""

    def test_wrong_recipient_rejected(self, testnet_client):
        """A payment to the wrong wallet should be rejected."""
        fake_tx = "wrong_recipient_tx_001"
        with patch("main.verify_solana_tx", new_callable=AsyncMock,
                   side_effect=ValueError("No valid transfer to merchant wallet")):
            r = testnet_client.post("/api/v1/scan", json={
                "source_code": "x = 1",
                "language": "python",
            }, headers={"X-PAYMENT": fake_tx})
            assert r.status_code == 402
            assert "verification failed" in r.json()["detail"].lower()


class TestFreeTrialBoundaries:
    """Free trial is OFF by contract — no scan should ever be free."""

    def test_no_free_scan_in_disabled_mode(self, client):
        """In disabled mode, no scan returns results without payment."""
        r = client.post("/api/v1/scan", json={
            "source_code": "eval('x')",
            "language": "python",
        })
        assert r.status_code == 402
        assert "charged" not in r.json()

    def test_no_free_scan_with_fake_proof(self, client):
        """Fake payment proof in disabled mode still gets 402."""
        r = client.post("/api/v1/scan", json={
            "source_code": "eval('x')",
            "language": "python",
        }, headers={"X-PAYMENT": "completely_fake_tx"})
        assert r.status_code == 402

    def test_health_shows_free_trial_disabled(self, client):
        """Health endpoint reports free_trial_enabled=False."""
        r = client.get("/api/v1/health")
        assert r.json()["free_trial_enabled"] is False