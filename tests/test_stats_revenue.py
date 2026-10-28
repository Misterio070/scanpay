"""Stats endpoint must report revenue that survives a restart.

The free hosting tier uses an ephemeral SQLite file, so scan counters reset to
zero on every restart. Revenue lives on-chain, so the public stats endpoint
reads the merchant USDC balance instead of trusting the local counters.
"""
import asyncio

import pytest

import main


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    def __init__(self, payload=None, exc=None):
        self._payload = payload
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, *args, **kwargs):
        if self._exc:
            raise self._exc
        return _Resp(self._payload)


def _balance(value_wei: int) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "result": hex(value_wei)}


@pytest.fixture(autouse=True)
def _clear_cache():
    main._REVENUE_CACHE.update({"at": 0.0, "usdc": None})
    yield
    main._REVENUE_CACHE.update({"at": 0.0, "usdc": None})


def test_revenue_is_read_from_merchant_balance(monkeypatch):
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: _Client(_balance(140_000)))
    assert asyncio.run(main.onchain_revenue()) == 0.14


def test_empty_result_returns_none_not_zero(monkeypatch):
    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kw: _Client({"result": "0x"}))
    assert asyncio.run(main.onchain_revenue()) is None


def test_rpc_failure_returns_none(monkeypatch):
    monkeypatch.setattr(
        main.httpx, "AsyncClient", lambda **kw: _Client(exc=RuntimeError("rpc down"))
    )
    assert asyncio.run(main.onchain_revenue()) is None


def test_cached_value_skips_second_call(monkeypatch):
    calls = []

    def _factory(**kw):
        calls.append(1)
        return _Client(_balance(50_000))

    monkeypatch.setattr(main.httpx, "AsyncClient", _factory)
    assert asyncio.run(main.onchain_revenue()) == 0.05
    assert asyncio.run(main.onchain_revenue()) == 0.05
    assert len(calls) == 1
