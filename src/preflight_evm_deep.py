import os
from typing import Any, Dict, List, Optional
import httpx

BASE_RPC_URL = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

# ცნობილი უსაფრთხო კონტრაქტები და მიმღებები Base-ზე (Whitelist ბაზა)
KNOWN_TRUSTED_ADDRESSES = {
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": "Base Native USDC",
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 SwapRouter02",
    "0xb295e606f38c363b476fc546c27226b5fbcaaefa": "ScanPay Merchant Wallet",
}

ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
MAX_UINT256_THRESHOLD = (1 << 255) - 1


def detect_address_poisoning(
    target_address: str, recent_counterparties: List[str]
) -> Optional[Dict[str, Any]]:
    """
    ამოწმებს, ხომ არ არის target_address Vanity გენერატორით შექმნილი სატყუარა (Address Poisoning),
    რომელიც იმეორებს ცნობილი კონტრაგენტის პირველ და ბოლო 4-6 ჰექს-სიმბოლოს.
    """
    cand = target_address.lower().strip()
    if not cand.startswith("0x") or len(cand) != 42:
        return None

    reference_pool = set(KNOWN_TRUSTED_ADDRESSES.keys()) | {
        addr.lower().strip() for addr in recent_counterparties if len(addr) == 42
    }

    if cand in reference_pool:
        return None  # ზუსტი დამთხვევა სანდო მისამართთან

    cand_body = cand[2:]
    for ref in reference_pool:
        ref_body = ref[2:]
        prefix_match = cand_body[:4] == ref_body[:4]
        suffix_match = cand_body[-4:] == ref_body[-4:]
        if prefix_match and suffix_match:
            return {
                "rule_id": "AGT-EVM-POISON-001",
                "severity": "CRITICAL",
                "verdict": "BLOCK",
                "reason": (
                    f"Address Poisoning detected: Target {target_address} mimics prefix/suffix "
                    f"of known counterparty {ref}."
                ),
            }
    return None


async def simulate_base_tx_flashblocks(
    from_addr: str,
    to_addr: str,
    calldata: str,
    value_hex: str = "0x0",
    recent_counterparties: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    ასრულებს ღრმა Pre-Flight სიმულაციას Base Flashblocks ('pending') მდგომარეობაზე
    eth_simulateV1-ის მეშვეობით. იჭერს Multicall3-ში დამალულ approve/transfer დრეინერებს.
    """
    findings: List[Dict[str, Any]] = []

    # 1. Address Poisoning შემოწმება
    poison_check = detect_address_poisoning(to_addr, recent_counterparties or [])
    if poison_check:
        findings.append(poison_check)

    # 2. eth_simulateV1 payload Base Flashblocks-ისთვის
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_simulateV1",
        "params": [
            {
                "blockStateCalls": [
                    {
                        "calls": [
                            {
                                "from": from_addr,
                                "to": to_addr,
                                "data": calldata,
                                "value": value_hex,
                            }
                        ]
                    }
                ],
                "traceTransfers": True,
                "validation": True,
            },
            "pending",  # იყენებს Base-ის ~200ms Flashblocks preconfirmation სტატუსს
        ],
    }

    async with httpx.AsyncClient(timeout=3.5) as client:
        resp = await client.post(BASE_RPC_URL, json=rpc_payload)
        data = resp.json()

    if "error" in data:
        return {
            "gate": "BLOCK",
            "risk_score": 90,
            "findings": findings + [{
                "rule_id": "AGT-EVM-SIM-ERR",
                "severity": "HIGH",
                "reason": f"Simulation reverted or failed at RPC level: {data['error']}",
            }],
        }

    blocks = data.get("result", [])
    if not blocks or not blocks[0].get("calls"):
        return {"gate": "WARN", "risk_score": 50, "findings": findings}

    call_result = blocks[0]["calls"][0]
    if call_result.get("status") != "0x1":
        findings.append({
            "rule_id": "AGT-EVM-REVERT-HNY",
            "severity": "HIGH",
            "reason": f"Transaction execution reverted during pre-flight (potential Honeypot): {call_result.get('error')}",
        })

    # 3. შიდა ივენთ-ლოგებისა და ფარული ტრანსფერების ანალიზი (Nested Multicall3 / Delegatecall)
    for log in call_result.get("logs", []):
        topics = [t.lower() for t in log.get("topics", [])]
        if len(topics) >= 3 and topics[0] == ERC20_APPROVAL_TOPIC:
            spender = "0x" + topics[2][-40:]
            raw_amount = int(log.get("data", "0x0"), 16)
            if raw_amount >= MAX_UINT256_THRESHOLD and spender not in KNOWN_TRUSTED_ADDRESSES:
                findings.append({
                    "rule_id": "AGT-EVM-UNLIMITED-APPROVE",
                    "severity": "CRITICAL",
                    "reason": f"Nested unlimited ERC-20 approval detected to untrusted spender {spender}.",
                })

    risk_score = min(100, len(findings) * 45)
    gate = "BLOCK" if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else "ALLOW"

    return {
        "gate": gate,
        "risk_score": risk_score,
        "findings": findings,
        "flashblocks_verified": True,
    }