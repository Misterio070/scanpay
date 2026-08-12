"""Test restart recovery: DB state persists across restarts, payments are tracked."""
import os
import sys
import time
import sqlite3
import importlib
import pytest
from fastapi.testclient import TestClient


class TestRestartRecovery:
    """The service must recover its state after a restart — DB is durable."""

    def test_db_created_on_startup(self, tmp_path):
        """init_db() creates the payments and scans tables."""
        db_path = str(tmp_path / "restart_test.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "disabled"
        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        conn = sqlite3.connect(db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        table_names = [t[0] for t in tables]
        assert "payments" in table_names
        assert "scans" in table_names

    def test_payment_persists_across_restart(self, tmp_path):
        """A stored payment survives a module reload (simulated restart)."""
        db_path = str(tmp_path / "persist_test.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        # Store a payment
        main_mod.store_payment("persist_tx_001", "Payer123", 10_000_000, "testnet")

        # Simulate restart by reloading
        importlib.reload(main_mod)

        # Check the payment still exists
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT payer, amount_lamports, network, used FROM payments WHERE tx_signature = ?",
            ("persist_tx_001",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "Payer123"
        assert row[1] == 10_000_000
        assert row[2] == "testnet"
        assert row[3] == 0  # unused

    def test_payment_marked_used_persists(self, tmp_path):
        """A used payment stays marked as used across restart."""
        db_path = str(tmp_path / "used_test.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        main_mod.store_payment("used_tx_001", "Payer456", 10_000_000, "testnet")
        main_mod.mark_payment_used("used_tx_001")

        # Simulate restart
        importlib.reload(main_mod)

        # The payment should still be marked as used
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT used FROM payments WHERE tx_signature = ?",
            ("used_tx_001",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 1  # still used

    def test_scan_records_persist(self, tmp_path):
        """Scan records survive a restart."""
        db_path = str(tmp_path / "scan_persist.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        main_mod.record_scan("scan_tx_001", "python", "abc123hash", 5, "critical")

        # Simulate restart
        importlib.reload(main_mod)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT language, source_sha256, findings_count, max_severity FROM scans WHERE tx_signature = ?",
            ("scan_tx_001",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "python"
        assert row[1] == "abc123hash"
        assert row[2] == 5
        assert row[3] == "critical"

    def test_check_payment_after_restart(self, tmp_path):
        """check_payment correctly reads state after restart."""
        db_path = str(tmp_path / "check_test.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        # Store and mark used
        main_mod.store_payment("check_tx_001", "Payer", 10_000_000, "testnet")
        main_mod.mark_payment_used("check_tx_001")

        # Simulate restart
        importlib.reload(main_mod)

        # check_payment should return False for used payment
        result = main_mod.check_payment("check_tx_001")
        assert result is False

    def test_check_payment_nonexistent(self, tmp_path):
        """check_payment returns False for non-existent payment."""
        db_path = str(tmp_path / "nonexist_test.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        result = main_mod.check_payment("does_not_exist_tx")
        assert result is False

    def test_mark_payment_used_returns_false_for_nonexistent(self, tmp_path):
        """mark_payment_used returns False for a non-existent payment."""
        db_path = str(tmp_path / "mark_nonexist.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        result = main_mod.mark_payment_used("nonexistent_tx_001")
        assert result is False

    def test_mark_payment_used_atomic_claim(self, tmp_path):
        """mark_payment_used returns True on first claim, False on second (atomic)."""
        db_path = str(tmp_path / "atomic_claim.db")
        os.environ["SCANPAY_DB_PATH"] = db_path
        os.environ["SCANPAY_PAYMENT_MODE"] = "testnet"
        os.environ["SCANPAY_MERCHANT_WALLET"] = "TestWallet111111111111111111111111111111111"

        import main as main_mod
        importlib.reload(main_mod)
        main_mod.init_db()

        main_mod.store_payment("atomic_tx_001", "Payer", 10_000_000, "testnet")

        # First claim succeeds
        assert main_mod.mark_payment_used("atomic_tx_001") is True
        # Second claim fails (already used)
        assert main_mod.mark_payment_used("atomic_tx_001") is False