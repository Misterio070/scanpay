"""Agents guess request field names; a 422 is a dead end they never retry.

These tests pin the tolerance contract on the two paid endpoints whose field
name is not obvious from the service description.
"""

import pytest

from main import PreflightRequest, TokenAuditRequest

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


@pytest.mark.parametrize(
    "field",
    ["token_address", "tokenAddress", "address", "contract", "contract_address", "mint", "token", "token_mint"],
)
def test_token_audit_accepts_every_common_spelling(field):
    req = TokenAuditRequest(**{field: USDC})
    assert req.token_address == USDC
    assert req.chain == "base"


def test_token_audit_still_rejects_a_missing_address():
    with pytest.raises(Exception):
        TokenAuditRequest(chain="base")


def test_token_audit_rejects_a_short_address():
    with pytest.raises(Exception):
        TokenAuditRequest(address="0x123")


@pytest.mark.parametrize("field", ["tx", "transaction", "raw_tx", "payload", "transaction_data"])
def test_preflight_accepts_every_common_spelling(field):
    body = {"to": USDC, "data": "0x", "value": "0"}
    req = PreflightRequest(**{field: body})
    assert req.tx == body


def test_preflight_still_rejects_a_missing_tx():
    with pytest.raises(Exception):
        PreflightRequest(chain="base")
