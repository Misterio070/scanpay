"""Shared fixtures for ScanPay tests."""
import os
import sys
import tempfile
import pytest

# Ensure project root is on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temporary SQLite DB path for each test."""
    db_path = tmp_path / "test_scanpay.db"
    return str(db_path)


@pytest.fixture
def client(tmp_db, monkeypatch):
    """FastAPI TestClient with disabled payment mode and temp DB."""
    monkeypatch.setenv("SCANPAY_PAYMENT_MODE", "disabled")
    monkeypatch.setenv("SCANPAY_DB_PATH", tmp_db)
    # Reimport to pick up env
    import importlib
    import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient
    with TestClient(main_mod.app) as c:
        yield c


@pytest.fixture
def testnet_client(tmp_db, monkeypatch):
    """FastAPI TestClient with testnet payment mode and temp DB."""
    monkeypatch.setenv("SCANPAY_PAYMENT_MODE", "testnet")
    monkeypatch.setenv("SCANPAY_DB_PATH", tmp_db)
    monkeypatch.setenv("SCANPAY_MERCHANT_WALLET", "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4")
    import importlib
    import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient
    with TestClient(main_mod.app) as c:
        yield c