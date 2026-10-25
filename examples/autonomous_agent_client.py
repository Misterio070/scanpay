"""ScanPay Autonomous Agent Client Example.

Demonstrates how an autonomous AI agent with a Solana or Base wallet
detects an x402 402 challenge, signs the on-chain micropayment, and receives
the verified security audit / pre-flight shield verdict.
"""
import os
import json
import urllib.request
import urllib.error

SCANPAY_BASE_URL = os.getenv("SCANPAY_URL", "https://scanpay-ob3w.onrender.com")


def call_scanpay_with_x402(endpoint: str, payload: dict, wallet_private_key: str = None, chain: str = "solana") -> dict:
    """Invokes ScanPay API, automatically settling x402 micropayments."""
    url = f"{SCANPAY_BASE_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "AutonomousAgent/1.0"}

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 402:
            requirements_raw = e.headers.get("X-Payment-Requirements") or e.headers.get("payment-required")
            if not requirements_raw:
                body = json.loads(e.read().decode("utf-8"))
                requirements = body.get("paymentRequirements", {})
            else:
                requirements = json.loads(requirements_raw)

            print(f"[ScanPay 402] Payment Required: {requirements.get('amount_display')} to {requirements.get('recipient')}")

            # Autonomous on-chain settlement:
            # In production, the agent executes the transfer using its wallet SDK.
            # Example tx signature:
            tx_signature = os.getenv("TX_SIGNATURE_OVERRIDE", "MOCK_OR_REAL_TX_SIG")

            # Retry with payment proof:
            headers["X-PAYMENT"] = tx_signature
            retry_req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(retry_req) as retry_resp:
                return json.loads(retry_resp.read().decode("utf-8"))
        raise


if __name__ == "__main__":
    print("Testing ScanPay API discovery...")
    probe = urllib.request.urlopen(f"{SCANPAY_BASE_URL}/api/v1/health")
    print("Health Status:", probe.read().decode())
