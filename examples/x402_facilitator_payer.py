"""Pay ScanPay through the x402 facilitator (exact / EIP-3009), not a direct transfer.

Why this exists
---------------
`examples/x402_payer.py` broadcasts a plain USDC `transfer` and hands the tx
hash to the server. That settles, but the payment never passes through the
facilitator, so the resource is invisible to facilitator-backed catalogs
(PayAI Bazaar, CDP discovery). Those catalogs are where autonomous agents
look for services, so a merchant that only accepts direct transfers is
effectively unlisted.

This payer signs an EIP-3009 `TransferWithAuthorization` off-chain and lets
the merchant's facilitator submit it. The facilitator records the resource
URL, which is what makes the endpoint discoverable.

Usage:
    set -a; . ~/.hermes/secrets/scanpay_payer.env; set +a
    python examples/x402_facilitator_payer.py [url] [--amount-units N]

Nothing here fabricates a settlement: if the facilitator rejects the
authorization, the script exits non-zero with the server's reason.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from typing import Any, Optional

import httpx
from eth_account import Account

BASE_CHAIN_ID = 8453
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CANONICAL_URL = "https://scanpay-ob3w.onrender.com"

EIP712_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def build_authorization(payer: str, pay_to: str, amount_units: int,
                        lifetime: int = 3600) -> dict[str, Any]:
    now = int(time.time())
    return {
        "from": payer,
        "to": pay_to,
        "value": str(amount_units),
        "validAfter": str(now - 600),
        "validBefore": str(now + lifetime),
        "nonce": "0x" + secrets.token_hex(32),
    }


def sign_authorization(account: Account, auth: dict[str, Any]) -> str:
    domain = {
        "name": "USD Coin",
        "version": "2",
        "chainId": BASE_CHAIN_ID,
        "verifyingContract": BASE_USDC,
    }
    message = {
        "from": auth["from"],
        "to": auth["to"],
        "value": int(auth["value"]),
        "validAfter": int(auth["validAfter"]),
        "validBefore": int(auth["validBefore"]),
        "nonce": bytes.fromhex(auth["nonce"][2:]),
    }
    signed = Account.sign_typed_data(
        account.key, full_message={
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                **EIP712_TYPES,
            },
            "domain": domain,
            "primaryType": "TransferWithAuthorization",
            "message": message,
        },
    )
    sig = signed.signature.hex()
    # eth_account <0.13 hex() strips the 0x prefix; the facilitator rejects a bare signature
    # as "unrecognized EVM payment payload", which reads like a schema error and is not one.
    return sig if sig.startswith("0x") else "0x" + sig


def payment_header(account: Account, requirement: dict[str, Any]) -> str:
    pay_to = requirement.get("payTo") or requirement.get("recipient")
    amount = int(requirement.get("amount") or requirement.get("maxAmountRequired") or 0)
    if not pay_to or amount <= 0:
        raise RuntimeError(f"Malformed payment requirement: {requirement}")

    auth = build_authorization(account.address, pay_to, amount)
    sig = sign_authorization(account, auth)
    payload = {
        "x402Version": 2,
        "scheme": requirement.get("scheme", "exact"),
        "network": requirement.get("network", "eip155:8453"),
        "payload": {"signature": sig, "authorization": auth},
        "accepted": requirement,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode()


def pay(url: str, body: dict[str, Any], account: Account,
        timeout: float = 90.0) -> dict[str, Any]:
    with httpx.Client(timeout=timeout) as client:
        first = client.post(url, json=body)
        if first.status_code != 402:
            raise RuntimeError(f"expected 402, got {first.status_code}: {first.text[:300]}")

        challenge = first.json()
        accepts = challenge.get("accepts") or []
        evm = next((a for a in accepts if str(a.get("network", "")).startswith("eip155")), None)
        if not evm:
            raise RuntimeError(f"no EVM option in challenge: {accepts}")

        header = payment_header(account, evm)
        second = client.post(url, json=body, headers={
            "PAYMENT-SIGNATURE": header,
            "X-PAYMENT": header,
        })
        if second.status_code == 402:
            raise RuntimeError(f"payment rejected: {second.text[:500]}")
        second.raise_for_status()
        return second.json()


def main() -> int:
    key = os.getenv("SCANPAY_PAYER_PRIVATE_KEY", "")
    if not key:
        print("SCANPAY_PAYER_PRIVATE_KEY is not set", file=sys.stderr)
        return 2
    account = Account.from_key(key)

    url = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else f"{CANONICAL_URL}/v2/oracle/scrape"
    body = {"url": "https://example.com", "extract_mode": "markdown", "strip_media": True}

    print(f"payer: {account.address}")
    print(f"target: {url}")
    result = pay(url, body, account)
    receipt = result.get("payment_receipt") or result.get("payment") or {}
    print(json.dumps({
        "ok": True,
        "verdict": (result.get("execution_gate") or {}).get("verdict"),
        "receipt": receipt,
    }, indent=2)[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
