"""How an autonomous agent buys a ScanPay scan on Base.

    export SCANPAY_PAYER_PRIVATE_KEY=0x...   # a FUNDED agent wallet
    python examples/autonomous_agent_client.py

The agent needs no account, API key or human: it receives the 402 challenge,
reads the price and recipient from `accepts[]`, signs a USDC transfer with its
own key, and retries with the resulting transaction hash in `X-PAYMENT`.
"""
import os

from examples.x402_payer import BasePayer, call_paid

SCAN_URL = "https://scanpay-ob3w.onrender.com/v2/scan"

SAMPLE = '''
import os
import subprocess

def run(cmd):
    return subprocess.call(cmd, shell=True)

def fetch(user_url):
    return os.system("curl " + user_url)
'''


def main() -> None:
    key = os.getenv("SCANPAY_PAYER_PRIVATE_KEY", "")
    if not key:
        raise SystemExit(
            "Set SCANPAY_PAYER_PRIVATE_KEY to a funded Base wallet key. "
            "ScanPay cannot pay on your behalf."
        )

    payer = BasePayer(key)
    print(f"payer: {payer.address}")

    result = call_paid(
        SCAN_URL,
        {"language": "python", "source_code": SAMPLE},
        payer,
    )
    gate = result.get("execution_gate", {})
    print(f"verdict: {gate.get('verdict')}  risk: {gate.get('risk_score')}")
    print(f"findings: {len(result.get('findings', []))}")
    patch = (result.get("auto_remediation") or {}).get("unified_diff", "")
    print(patch[:600] if patch else "no deterministic patch available")


if __name__ == "__main__":
    main()
