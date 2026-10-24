"""Tests for ScanPay Pre-Flight Transaction & Drainer Shield."""
import pytest
from src.preflight import (
    simulate_transaction,
    analyze_evm_transaction,
    analyze_solana_transaction,
    calculate_simulation_score,
    decode_evm_uint256,
    decode_evm_address,
)


def test_decode_evm_helpers():
    # Test address decoding
    hex_addr = "000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    assert decode_evm_address(hex_addr) == "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"

    # Test uint256 decoding
    hex_val = "00000000000000000000000000000000000000000000000000000000000000ff"
    assert decode_evm_uint256(hex_val) == 255


def test_evm_unlimited_approval_untrusted_blocked():
    # Unlimited approval (2^256-1) to an unverified address
    untrusted_spender = "0x9999999999999999999999999999999999999999"
    spender_hex = untrusted_spender[2:].zfill(64)
    amount_hex = "f" * 64
    calldata = f"0x095ea7b3{spender_hex}{amount_hex}"

    tx = {
        "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC
        "data": calldata,
        "value": 0,
    }

    res = simulate_transaction("base", tx)
    assert res["execution_gate"]["verdict"] == "BLOCK"
    assert res["execution_gate"]["allow_broadcast"] is False
    assert res["execution_gate"]["risk_score"] >= 80

    finding_rules = [f["rule_id"] for f in res["findings"]]
    assert "PRE-EVM-001" in finding_rules
    assert res["chain"] == "base"
    assert "attestation" in res
    assert len(res["attestation"]["oracle_signature"]) == 64


def test_evm_unlimited_approval_verified_router_warned():
    # Unlimited approval to verified Uniswap router on Base
    verified_spender = "0x2626664c2603336e57b271c5c0b26f421741e481"
    spender_hex = verified_spender[2:].zfill(64)
    amount_hex = "f" * 64
    calldata = f"0x095ea7b3{spender_hex}{amount_hex}"

    tx = {
        "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "data": calldata,
    }

    res = simulate_transaction("base", tx)
    # Warn instead of block because it's a verified router
    assert res["execution_gate"]["verdict"] in ("WARN", "ALLOW")
    finding_rules = [f["rule_id"] for f in res["findings"]]
    assert "PRE-EVM-006" in finding_rules


def test_evm_known_drainer_blocked():
    tx = {
        "to": "0xbad00000000000000000000000000000000bad00",
        "data": "0x",
        "value": 100000000000000000,
    }

    res = simulate_transaction("ethereum", tx)
    assert res["execution_gate"]["verdict"] == "BLOCK"
    assert res["execution_gate"]["allow_broadcast"] is False
    assert any(f["rule_id"] == "PRE-EVM-002" for f in res["findings"])


def test_evm_zero_slippage_sandwich_trap():
    # Swap function with min_amount_out = 0
    calldata = "0x38ed1739" + "0000000000000000000000000000000000000000000000000000000000000000" * 4
    tx = {
        "to": "0x2626664c2603336e57b271c5c0b26f421741e481",
        "data": calldata,
    }

    res = simulate_transaction("base", tx)
    assert res["execution_gate"]["verdict"] in ("WARN", "BLOCK")
    assert any(f["rule_id"] == "PRE-EVM-004" for f in res["findings"])


def test_solana_set_authority_theft_blocked():
    tx = {
        "instructions": [
            {
                "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "data": "0600000011111111111111111111111111111111",
                "accounts": ["Account1", "Account2"],
            }
        ]
    }

    res = simulate_transaction("solana", tx)
    assert res["execution_gate"]["verdict"] == "BLOCK"
    assert res["execution_gate"]["allow_broadcast"] is False
    assert res["chain"] == "solana"
    assert any(f["rule_id"] == "PRE-SOL-001" for f in res["findings"])


def test_clean_transaction_allowed():
    # Safe 10 USDC transfer
    safe_recipient = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    recip_hex = safe_recipient[2:].zfill(64)
    amount_hex = hex(10_000_000)[2:].zfill(64)  # 10 USDC (6 decimals)
    calldata = f"0xa9059cbb{recip_hex}{amount_hex}"

    tx = {
        "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "data": calldata,
        "value": 0,
    }

    res = simulate_transaction("base", tx)
    assert res["execution_gate"]["verdict"] == "ALLOW"
    assert res["execution_gate"]["allow_broadcast"] is True
    assert res["execution_gate"]["risk_score"] == 0
    assert len(res["findings"]) == 0


def test_evm_address_poisoning_detected():
    # Poisoned Base USDC vanity address
    poisoned_addr = "0x8335000000000000000000000000000000002913"
    tx = {
        "to": poisoned_addr,
        "data": "0x",
        "value": 1000000000000000,
    }
    res = simulate_transaction("base", tx)
    assert res["execution_gate"]["verdict"] == "BLOCK"
    assert res["execution_gate"]["allow_broadcast"] is False
    assert any(f["rule_id"] == "PRE-EVM-007" for f in res["findings"])


def test_evm_multicall3_nested_approval_detected():
    nested_calldata = "0xac9650d8" + "00" * 32 + "095ea7b3" + "f" * 64
    tx = {
        "to": "0xca11bde05977b3631167028862be2a173976ca11",
        "data": nested_calldata,
    }
    res = simulate_transaction("base", tx)
    assert res["execution_gate"]["verdict"] == "BLOCK"
    assert res["execution_gate"]["allow_broadcast"] is False
    assert any(f["rule_id"] == "PRE-EVM-008" for f in res["findings"])
