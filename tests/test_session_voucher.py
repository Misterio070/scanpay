"""Test prepaid session vouchers (ephemeral micro-vouchers for high-frequency A2A coding)."""
import os
import pytest
from src.session import (
    create_session_voucher,
    consume_session_credit,
    get_session_voucher,
    init_session_table,
)
import sqlite3


@pytest.fixture
def temp_db(tmp_path):
    db_file = str(tmp_path / "test_session.db")
    conn = sqlite3.connect(db_file)
    init_session_table(conn)
    conn.close()
    return db_file


class TestSessionVoucher:
    def test_create_and_consume_voucher(self, temp_db):
        voucher = create_session_voucher(
            db_path=temp_db,
            deposit_tx="test_deposit_tx_12345",
            payer="TestPayerWalletPubkey1111111111111111111111",
            credits=10,
        )
        assert voucher["total_credits"] == 10
        assert voucher["remaining_credits"] == 10
        assert voucher["status"] == "active"
        token = voucher["session_token"]
        assert token.startswith("scanpay_sess_")

        # Consume 1 credit
        success, remaining, msg = consume_session_credit(temp_db, token)
        assert success is True
        assert remaining == 9

        # Consume remaining 9 credits
        for expected in range(8, -1, -1):
            s, rem, m = consume_session_credit(temp_db, token)
            assert s is True
            assert rem == expected

        # Next consume must fail (depleted)
        s, rem, m = consume_session_credit(temp_db, token)
        assert s is False
        assert rem == 0
        assert "depleted" in m.lower()

    def test_invalid_session_token_rejected(self, temp_db):
        success, remaining, msg = consume_session_credit(temp_db, "invalid_nonexistent_token")
        assert success is False
        assert "not found" in msg.lower()


class TestSessionAPIFlow:
    def test_session_header_authorizes_scan(self, testnet_client, tmp_path):
        import main
        voucher = create_session_voucher(
            db_path=main.DB_PATH,
            deposit_tx="session_api_tx_999",
            payer="AgentWallet111111111111111111111111111111",
            credits=5,
        )
        token = voucher["session_token"]

        # Scan code with X-SCANPAY-SESSION header — succeeds with 0ms RPC
        r = testnet_client.post(
            "/api/v1/scan",
            json={"source_code": "eval('2+2')", "language": "python"},
            headers={"X-SCANPAY-SESSION": token},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["charged"] is True
        assert "execution_gate" in data
        assert "auto_remediation" in data
        assert data["auto_remediation"]["patches_available"] is True
        assert data["execution_gate"]["verdict"] == "BLOCK"
        assert r.headers["X-SCANPAY-VERDICT"] == "BLOCK"
