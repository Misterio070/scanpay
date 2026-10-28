"""Regression tests for the facilitator payer and the resource passthrough.

Two bugs made every facilitator payment fail while looking like a schema
problem:

* `eth_account` versions disagree about whether `HexBytes.hex()` keeps the `0x`
  prefix. A bare signature is rejected by the facilitator as
  "unrecognized EVM payment payload".
* the settlement request dropped `resource`, so a payment could succeed while
  the endpoint stayed invisible to Bazaar discovery.
"""
from __future__ import annotations

import base64
import json

from eth_account import Account

from examples.x402_facilitator_payer import build_authorization, payment_header, sign_authorization
import main


REQUIREMENT = {
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "20000",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0xb295E606F38C363b476FC546c27226B5fBcAAEFA",
    "maxTimeoutSeconds": 600,
    "resource": "https://scanpay-ob3w.onrender.com/api/v1/oracle/scrape",
    "extra": {"name": "USD Coin", "version": "2"},
}


def test_signature_always_has_0x_prefix():
    account = Account.create()
    auth = build_authorization(account.address, REQUIREMENT["payTo"], 20000)

    sig = sign_authorization(account, auth)

    assert sig.startswith("0x"), "a bare signature is rejected as an unrecognized payload"
    assert len(sig) == 132


def test_payment_header_round_trips_to_signed_authorization():
    account = Account.create()
    header = payment_header(account, REQUIREMENT)

    decoded = json.loads(base64.b64decode(header))

    assert decoded["x402Version"] == 2
    assert decoded["scheme"] == "exact"
    assert decoded["network"] == "eip155:8453"
    payload = decoded["payload"]
    assert payload["signature"].startswith("0x")
    assert payload["authorization"]["to"] == REQUIREMENT["payTo"]
    assert payload["authorization"]["value"] == REQUIREMENT["amount"]
    assert payload["authorization"]["from"] == account.address


def test_authorization_values_are_strings():
    """The facilitator's schema wants JSON strings, not numbers."""
    account = Account.create()
    header = payment_header(account, REQUIREMENT)
    auth = json.loads(base64.b64decode(header))["payload"]["authorization"]

    assert all(isinstance(auth[k], str) for k in ("value", "validAfter", "validBefore", "nonce"))


def test_every_payment_requirement_carries_a_resource_url():
    for service in ("scan", "token", "preflight", "scrape", "session"):
        reqs = main.build_x402_requirements(service=service)
        for accept in reqs["accepts"]:
            assert accept.get("resource", "").startswith("https://"), service
