"""Direct tests for Solana payment verification.

Existing API tests mock `verify_solana_tx` wholesale, so the SPL branch had no
coverage — which is exactly how a "any SPL token counts as USDC" hole survived.
These tests drive the real function against a fake RPC.
"""
import asyncio

import pytest

import main as app_main

USDC = app_main.USDC_MINT_SOLANA
MERCHANT = app_main.MERCHANT_WALLET
FOREIGN = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeRpc:
    """Minimal stand-in for httpx.AsyncClient that answers by JSON-RPC method."""

    tx: dict | None = None
    account: dict | None = None
    fail_account = False

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, **kwargs):
        method = (json or {}).get("method")
        if method == "getTransaction":
            return _Resp({"result": self.tx})
        if method == "getAccountInfo":
            if self.fail_account:
                return _Resp({"result": {"value": None}})
            return _Resp({"result": {"value": {"data": {"parsed": {"info": self.account}}}}})
        return _Resp({"result": None})


def _tx(instruction: dict) -> dict:
    return {
        "slot": 123,
        "meta": {"err": None},
        "transaction": {"message": {"instructions": [instruction]}},
    }


def _transfer_checked(mint: str, amount: int, destination: str) -> dict:
    return {"parsed": {"type": "transferChecked", "info": {
        "mint": mint, "amount": str(amount), "destination": destination,
        "authority": "PayerAuthority111111111111111111111111111111",
    }}}


def _plain_transfer(amount: int, destination: str) -> dict:
    return {"parsed": {"type": "transfer", "info": {
        "amount": str(amount), "destination": destination,
        "source": "Source111111111111111111111111111111111111111",
        "authority": "PayerAuthority111111111111111111111111111111",
    }}}


@pytest.fixture(autouse=True)
def _patch_rpc(monkeypatch):
    monkeypatch.setattr(app_main, "PAYMENT_MODE", "mainnet")
    monkeypatch.setattr(app_main.httpx, "AsyncClient", _FakeRpc)
    _FakeRpc.fail_account = False
    _FakeRpc.account = {"owner": MERCHANT, "mint": USDC}
    yield


def _verify(**kwargs):
    return asyncio.run(app_main.verify_solana_tx("sig", **kwargs))


def test_real_usdc_to_merchant_account_is_accepted():
    _FakeRpc.tx = _tx(_transfer_checked(USDC, 100_000, "MerchantAta"))
    res = _verify()
    assert res["valid"] is True
    assert res["asset"] == "USDC"
    assert res["amount_lamports"] == 100_000


def test_plain_transfer_resolved_through_account_lookup():
    # parsed `transfer` carries no mint; the fix resolves it from the account.
    _FakeRpc.tx = _tx(_plain_transfer(100_000, "MerchantAta"))
    res = _verify()
    assert res["asset"] == "USDC"


def test_fake_token_is_rejected():
    bogus = "FakeMint1111111111111111111111111111111111111"
    _FakeRpc.tx = _tx(_transfer_checked(bogus, 100_000, "MerchantAta"))
    _FakeRpc.account = {"owner": MERCHANT, "mint": bogus}
    with pytest.raises(ValueError):
        _verify()


def test_plain_transfer_of_fake_token_is_rejected():
    bogus = "FakeMint2222222222222222222222222222222222222"
    _FakeRpc.tx = _tx(_plain_transfer(100_000, "AttackerAta"))
    _FakeRpc.account = {"owner": FOREIGN, "mint": bogus}
    with pytest.raises(ValueError):
        _verify()


def test_usdc_sent_to_foreign_account_is_rejected():
    _FakeRpc.tx = _tx(_transfer_checked(USDC, 100_000, "ForeignAta"))
    _FakeRpc.account = {"owner": FOREIGN, "mint": USDC}
    with pytest.raises(ValueError):
        _verify()


def test_unresolvable_destination_fails_closed():
    _FakeRpc.tx = _tx(_plain_transfer(100_000, "UnknownAta"))
    _FakeRpc.fail_account = True
    with pytest.raises(ValueError):
        _verify()


def test_underpayment_is_rejected():
    _FakeRpc.tx = _tx(_transfer_checked(USDC, 50_000, "MerchantAta"))
    with pytest.raises(ValueError):
        _verify()


def test_native_sol_transfer_to_merchant_is_accepted():
    _FakeRpc.tx = _tx({"parsed": {"type": "transfer", "info": {
        "lamports": app_main.PRICE_LAMPORTS, "destination": MERCHANT,
        "source": "Payer111111111111111111111111111111111111111",
    }}})
    res = _verify()
    assert res["asset"] == "SOL"
    assert res["amount_lamports"] == app_main.PRICE_LAMPORTS


def test_native_sol_to_wrong_destination_is_rejected():
    _FakeRpc.tx = _tx({"parsed": {"type": "transfer", "info": {
        "lamports": app_main.PRICE_LAMPORTS, "destination": FOREIGN,
        "source": "Payer111111111111111111111111111111111111111",
    }}})
    with pytest.raises(ValueError):
        _verify()
