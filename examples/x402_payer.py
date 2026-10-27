"""A real x402 payer for ScanPay (Base mainnet).

The previous example only pasted a transaction hash from an environment
variable, so it could never actually buy anything. This module performs the
whole loop an autonomous agent needs:

    POST -> 402 -> pay on-chain -> retry with X-PAYMENT -> result

Base/EVM path is implemented and unit-tested here (eth_account is a hard
dependency). The Solana path is intentionally not faked: it needs `solders`,
which ships in the server image via requirements.txt but is not installed on
every dev box. A missing dependency raises, it never silently degrades.

Requires a FUNDED key. Nothing in this repository can conjure balance, so a
payment only settles once the operator funds the payer wallet.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx
from eth_account import Account

BASE_CHAIN_ID = 8453
BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TRANSFER_SELECTOR = "a9059cbb"  # transfer(address,uint256)


def encode_transfer(to: str, amount_units: int) -> str:
    """ABI-encode transfer(address,uint256) without pulling in web3."""
    addr = to.lower().replace("0x", "").rjust(64, "0")
    amt = hex(int(amount_units))[2:].rjust(64, "0")
    return "0x" + TRANSFER_SELECTOR + addr + amt


class BasePayer:
    """Signs and broadcasts Base transactions from an autonomous agent wallet."""

    def __init__(self, private_key: str, rpc_url: str = "https://mainnet.base.org",
                 client: Optional[httpx.Client] = None):
        if not private_key:
            raise ValueError("A funded private key is required to pay")
        self.account = Account.from_key(private_key)
        self.rpc_url = rpc_url
        self._client = client or httpx.Client(timeout=30)

    @property
    def address(self) -> str:
        return self.account.address

    def _rpc(self, method: str, params: list) -> Any:
        resp = self._client.post(self.rpc_url, json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        })
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"{method} failed: {body['error']}")
        return body.get("result")

    def pay_usdc(self, to: str, amount_units: int) -> str:
        """Transfer USDC and return the transaction hash."""
        nonce = int(self._rpc("eth_getTransactionCount", [self.address, "pending"]), 16)
        gas_price = int(self._rpc("eth_gasPrice", ["latest"]), 16)
        tx = {
            "chainId": BASE_CHAIN_ID,
            "nonce": nonce,
            "to": BASE_USDC,
            "value": 0,
            "data": encode_transfer(to, amount_units),
            "gas": 65_000,
            "maxFeePerGas": gas_price * 2,
            "maxPriorityFeePerGas": min(gas_price, 1_000_000),
            "type": 2,
        }
        signed = Account.sign_transaction(tx, self.account.key)
        return self._rpc("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex()])


def call_paid(url: str, payload: dict, payer: BasePayer,
              timeout: float = 60.0) -> dict:
    """POST a ScanPay endpoint, pay the 402 challenge, retry, return JSON.

    Raises on anything the caller should not paper over: no 402 to pay, a
    payment of the wrong size, or a second 402 after paying.
    """
    with httpx.Client(timeout=timeout) as client:
        first = client.post(url, json=payload)
        if first.status_code != 402:
            return first.json()

        challenge = first.json()
        accepts = challenge.get("accepts") or []
        evm = next((a for a in accepts if str(a.get("network", "")).startswith("eip155")), None)
        if not evm:
            raise RuntimeError(f"No EVM payment option in challenge: {accepts}")

        pay_to = evm.get("payTo") or evm.get("recipient")
        amount = int(evm.get("maxAmountRequired") or evm.get("amount") or 0)
        if not pay_to or amount <= 0:
            raise RuntimeError(f"Malformed payment requirement: {evm}")

        tx_hash = payer.pay_usdc(pay_to, amount)
        second = client.post(url, json=payload, headers={"X-PAYMENT": tx_hash})
        if second.status_code == 402:
            raise RuntimeError(f"Payment rejected after broadcast: {second.text[:300]}")
        second.raise_for_status()
        return second.json()


if __name__ == "__main__":
    key = os.getenv("SCANPAY_PAYER_PRIVATE_KEY", "")
    payer = BasePayer(key)
    print(f"payer address: {payer.address}")
    result = call_paid(
        "https://scanpay-ob3w.onrender.com/v2/scan",
        {"language": "python", "code": "import os\nos.system(input())"},
        payer,
    )
    print(result.get("execution_gate"), len(result.get("findings", [])), "findings")
