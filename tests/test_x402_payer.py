"""Proof that the payer can actually produce a signed, payable transaction.

Uses a throwaway private key and a fake RPC: no network, no funds, no real
transfer. The assertion that matters is that the broadcast payload recovers to
the payer's own address — i.e. the agent really signed it.
"""
import sys
from pathlib import Path

from eth_account import Account

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from examples.x402_payer import BasePayer, encode_transfer

TEST_KEY = "0x" + "11" * 32
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
MERCHANT = "0xb295E606F38C363b476FC546c27226B5fBcAAEFA"


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeRpc:
    sent: list = []

    def __init__(self, *a, **k):
        pass

    def post(self, url, json=None, **kwargs):
        method = json["method"]
        if method == "eth_getTransactionCount":
            return _Resp({"result": "0x0"})
        if method == "eth_gasPrice":
            return _Resp({"result": hex(10_000_000)})
        if method == "eth_sendRawTransaction":
            self.sent.append(json["params"][0])
            return _Resp({"result": "0x" + "ab" * 32})
        return _Resp({"result": None})


def test_transfer_calldata_matches_abi_layout():
    data = encode_transfer(MERCHANT, 100_000)
    assert data.startswith("0xa9059cbb")
    assert len(data) == 2 + 8 + 64 + 64
    assert data[10:74] == MERCHANT.lower().replace("0x", "").rjust(64, "0")
    assert int(data[74:], 16) == 100_000


def test_pay_usdc_broadcasts_a_transaction_signed_by_the_payer():
    payer = BasePayer(TEST_KEY, client=_FakeRpc())
    tx_hash = payer.pay_usdc(MERCHANT, 100_000)
    assert tx_hash == "0x" + "ab" * 32

    raw = bytes.fromhex(_FakeRpc.sent[-1][2:])
    assert raw[0] == 0x02, "expected an EIP-1559 transaction"
    assert Account.recover_transaction(raw).lower() == payer.address.lower()
    assert payer.address == Account.from_key(TEST_KEY).address


def test_payer_refuses_to_start_without_a_key():
    try:
        BasePayer("")
    except ValueError:
        return
    raise AssertionError("an empty private key must not construct a payer")
