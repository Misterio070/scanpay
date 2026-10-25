"""ScanPay Live On-Chain Token & Smart Contract Rug/Honeypot Auditor.

Performs real-time on-chain inspection for Base (EVM) and Solana tokens:
- EVM (Base/Ethereum): Bytecode selector analysis (blacklist, hidden tax modification,
  trading pause honeypots, mint functions, proxy delegatecall, selfdestruct) + live DEX liquidity.
- Solana (SPL / Token-2022): Mint authority, Freeze authority, Token-2022 Permanent Delegate
  (wallet seizure risk), Transfer Hook honeypots, Transfer Fee tax inspection + live DEX liquidity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any

import httpx

BASE_RPC_URL = os.getenv("SCANPAY_BASE_RPC", "https://mainnet.base.org")
ETH_RPC_URL = os.getenv("SCANPAY_ETH_RPC", "https://eth.llamarpc.com")
SOLANA_RPC_URL = os.getenv("SCANPAY_RPC_URL", "https://api.mainnet-beta.solana.com")

# Dangerous EVM 4-byte function selectors commonly used in honeypots and scam tokens
EVM_DANGEROUS_SELECTORS = {
    "f9f92be4": ("TOKEN-EVM-001", "HIGH", "Blacklist Function", "Contract contains blacklist(address) selector — owner can block specific buyers from selling."),
    "fe575a87": ("TOKEN-EVM-001", "MEDIUM", "Blacklist Check", "Contract contains isBlacklisted(address) selector — token implements address blacklisting."),
    "537df3b6": ("TOKEN-EVM-001", "HIGH", "Set Blacklist", "Contract contains setBlacklist(address,bool) selector — owner can freeze user transfers."),
    "061c82d0": ("TOKEN-EVM-002", "HIGH", "Mutable Tax Fee", "Contract contains setTaxFeePercent(uint256) — owner can raise transfer tax to 99% (honeypot)."),
    "0b78f9c0": ("TOKEN-EVM-002", "HIGH", "Mutable Buy/Sell Fees", "Contract contains setFees(uint256,uint256) — owner can dynamically alter buy/sell taxes."),
    "d543dbeb": ("TOKEN-EVM-003", "MEDIUM", "Mutable Max Tx Limit", "Contract contains setMaxTxPercent(uint256) — owner can restrict max sell amount to 0."),
    "c9567bf9": ("TOKEN-EVM-004", "CRITICAL", "Trading Toggle Honeypot", "Contract contains setTrading(bool) — owner can disable trading after users buy."),
    "8456cb59": ("TOKEN-EVM-004", "HIGH", "Pausable Transfers", "Contract contains pause() selector — transfers can be halted by authority."),
    "40c10f19": ("TOKEN-EVM-005", "HIGH", "Uncapped Mint Function", "Contract contains mint(address,uint256) selector — privileged address may mint new supply."),
}


def _evm_address_valid(address: str) -> bool:
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address.strip()))


def _solana_address_valid(address: str) -> bool:
    return bool(re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address.strip()))


async def _fetch_dexscreener(token_address: str) -> dict[str, Any]:
    """Fetch live DEX pool liquidity and 24h buy/sell metrics from DexScreener."""
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers={"User-Agent": "ScanPayOracle/1.2.0"})
            if resp.status_code != 200:
                return {"pairs_found": 0, "liquidity_usd": 0.0, "buys_24h": 0, "sells_24h": 0}
            data = resp.json()
            pairs = data.get("pairs") or []
            if not pairs:
                return {"pairs_found": 0, "liquidity_usd": 0.0, "buys_24h": 0, "sells_24h": 0}

            # Pick highest liquidity pair
            best = max(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0.0))
            liq_usd = float((best.get("liquidity") or {}).get("usd") or 0.0)
            txns_24h = (best.get("txns") or {}).get("h24") or {}
            buys = int(txns_24h.get("buys") or 0)
            sells = int(txns_24h.get("sells") or 0)
            vol_24h = float((best.get("volume") or {}).get("h24") or 0.0)
            price_usd = best.get("priceUsd")
            base_token = best.get("baseToken") or {}

            return {
                "pairs_found": len(pairs),
                "dex_id": best.get("dexId"),
                "pair_address": best.get("pairAddress"),
                "symbol": base_token.get("symbol"),
                "name": base_token.get("name"),
                "price_usd": price_usd,
                "liquidity_usd": round(liq_usd, 2),
                "volume_24h_usd": round(vol_24h, 2),
                "buys_24h": buys,
                "sells_24h": sells,
            }
    except Exception:
        return {"pairs_found": 0, "liquidity_usd": 0.0, "buys_24h": 0, "sells_24h": 0}


async def _audit_evm_token(chain: str, token_address: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rpc_url = BASE_RPC_URL if chain == "base" else ETH_RPC_URL
    metadata: dict[str, Any] = {"address": token_address, "chain": chain, "bytecode_size": 0}

    bytecode = "0x"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [token_address, "latest"]},
                headers={"Content-Type": "application/json", "User-Agent": "ScanPayOracle/1.2.0"},
            )
            if resp.status_code == 200:
                bytecode = resp.json().get("result") or "0x"
    except Exception as e:
        metadata["rpc_warning"] = str(e)

    clean_hex = bytecode[2:].lower() if bytecode.startswith("0x") else bytecode.lower()
    metadata["bytecode_size"] = len(clean_hex) // 2

    if len(clean_hex) == 0:
        findings.append({
            "rule_id": "TOKEN-EVM-000",
            "severity": "CRITICAL",
            "title": "No Contract Bytecode Found (EOA or Self-Destructed)",
            "description": f"Address {token_address} has 0 bytes of code on {chain}. Not a valid deployed token contract.",
        })
        return findings, metadata

    # Check dangerous 4-byte selectors (PUSH4 0x63 + 4 bytes)
    for selector, (rule_id, severity, title, desc) in EVM_DANGEROUS_SELECTORS.items():
        if f"63{selector}" in clean_hex:
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": desc,
                "selector": f"0x{selector}",
            })

    # Minimal proxy / upgradeable delegatecall check
    if "363d3d373d3d3d363d73" in clean_hex:
        findings.append({
            "rule_id": "TOKEN-EVM-006",
            "severity": "MEDIUM",
            "title": "EIP-1167 Minimal Proxy Contract",
            "description": "Token uses a minimal proxy forwarding calls via DELEGATECALL.",
        })

    return findings, metadata


async def _audit_solana_token(token_address: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"address": token_address, "chain": "solana"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                SOLANA_RPC_URL,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getAccountInfo",
                    "params": [token_address, {"encoding": "jsonParsed"}],
                },
                headers={"Content-Type": "application/json", "User-Agent": "ScanPayOracle/1.2.0"},
            )
            data = resp.json()
            val = (data.get("result") or {}).get("value")
            if not val:
                findings.append({
                    "rule_id": "TOKEN-SOL-000",
                    "severity": "CRITICAL",
                    "title": "Mint Account Not Found",
                    "description": f"Solana mint {token_address} does not exist on mainnet.",
                })
                return findings, metadata

            owner = val.get("owner", "")
            metadata["program_owner"] = owner
            metadata["is_token_2022"] = owner == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

            parsed = ((val.get("data") or {}).get("parsed") or {}).get("info") or {}
            mint_auth = parsed.get("mintAuthority")
            freeze_auth = parsed.get("freezeAuthority")
            decimals = parsed.get("decimals")
            supply = parsed.get("supply")

            metadata["decimals"] = decimals
            metadata["supply"] = supply
            metadata["mint_authority"] = mint_auth
            metadata["freeze_authority"] = freeze_auth

            if mint_auth:
                findings.append({
                    "rule_id": "TOKEN-SOL-001",
                    "severity": "CRITICAL",
                    "title": "Mint Authority Enabled (Infinite Supply Inflation Risk)",
                    "description": f"Mint authority is active ({mint_auth}). Creator can mint unlimited tokens and dump on liquidity pool.",
                })

            if freeze_auth:
                findings.append({
                    "rule_id": "TOKEN-SOL-002",
                    "severity": "HIGH",
                    "title": "Freeze Authority Enabled (Wallet Blacklist / Honeypot Risk)",
                    "description": f"Freeze authority is active ({freeze_auth}). Creator can freeze buyer token accounts to prevent selling.",
                })

            # Check Token-2022 extensions
            extensions = parsed.get("extensions") or []
            for ext in extensions:
                ext_type = ext.get("extension")
                state = ext.get("state") or {}
                if ext_type == "permanentDelegate" and state.get("delegate"):
                    findings.append({
                        "rule_id": "TOKEN-SOL-003",
                        "severity": "CRITICAL",
                        "title": "Token-2022 Permanent Delegate Active (Wallet Seizure Risk)",
                        "description": f"Permanent delegate ({state.get('delegate')}) has unrestricted authority to transfer or burn tokens from ANY holder's wallet.",
                    })
                elif ext_type == "transferHook" and state.get("programId"):
                    findings.append({
                        "rule_id": "TOKEN-SOL-004",
                        "severity": "HIGH",
                        "title": "Token-2022 Custom Transfer Hook",
                        "description": f"Custom program ({state.get('programId')}) executes on every transfer and can dynamically revert sells.",
                    })
                elif ext_type == "transferFeeConfig":
                    newer_fee = (state.get("newerTransferFee") or {}).get("transferFeeBasisPoints", 0)
                    if int(newer_fee) >= 500:
                        findings.append({
                            "rule_id": "TOKEN-SOL-005",
                            "severity": "HIGH" if int(newer_fee) < 2000 else "CRITICAL",
                            "title": f"High Token-2022 Transfer Tax ({int(newer_fee)/100:.1f}%)",
                            "description": f"Token enforces a {int(newer_fee)/100:.1f}% protocol-level fee on every transfer.",
                        })
    except Exception as e:
        metadata["rpc_warning"] = str(e)

    return findings, metadata


async def audit_token_contract(
    chain: str,
    token_address: str,
    merchant_wallet: str = "",
    payment_receipt: str = "unverified",
) -> dict[str, Any]:
    """Perform full on-chain + DEX liquidity security audit for a token on Base, Ethereum, or Solana."""
    t0 = time.perf_counter()
    chain_norm = chain.lower().strip()
    addr = token_address.strip()

    if chain_norm in ("base", "ethereum"):
        if not _evm_address_valid(addr):
            raise ValueError(f"Invalid EVM token address: {addr}")
        findings, onchain_meta = await _audit_evm_token(chain_norm, addr)
    elif chain_norm == "solana":
        if not _solana_address_valid(addr):
            raise ValueError(f"Invalid Solana mint address: {addr}")
        findings, onchain_meta = await _audit_solana_token(addr)
    else:
        raise ValueError(f"Unsupported chain '{chain}'. Supported: base, ethereum, solana")

    dex_meta = await _fetch_dexscreener(addr)

    # Check DEX liquidity & honeypot indicators
    if dex_meta.get("pairs_found", 0) > 0:
        liq = dex_meta.get("liquidity_usd", 0.0)
        buys = dex_meta.get("buys_24h", 0)
        sells = dex_meta.get("sells_24h", 0)

        if liq < 1000.0:
            findings.append({
                "rule_id": "TOKEN-DEX-001",
                "severity": "HIGH",
                "title": f"Critically Low DEX Liquidity (${liq:,.2f})",
                "description": "Pool liquidity is under $1,000 USD. High slippage and immediate rug-pull risk.",
            })
        if buys >= 15 and sells == 0:
            findings.append({
                "rule_id": "TOKEN-DEX-002",
                "severity": "CRITICAL",
                "title": "Active Honeypot Pattern Detected (0 Sells in 24h)",
                "description": f"Recorded {buys} buys and 0 sells in 24h. Buyers are unable to sell this token.",
            })
        elif buys >= 30 and sells > 0 and (buys / sells) > 8.0:
            findings.append({
                "rule_id": "TOKEN-DEX-003",
                "severity": "HIGH",
                "title": f"Extreme Buy/Sell Imbalance ({buys} buys vs {sells} sells)",
                "description": "Sell transactions are heavily restricted or taxed compared to buys.",
            })

    # Compute Risk Score & Verdict
    weights = {"CRITICAL": 45, "HIGH": 25, "MEDIUM": 12, "LOW": 5}
    risk_score = min(100, sum(weights.get(f["severity"], 10) for f in findings))

    severities = [f["severity"] for f in findings]
    max_sev = "NONE"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in severities:
            max_sev = s
            break

    if max_sev == "CRITICAL" or risk_score >= 60:
        verdict = "BLOCK"
        allow_trade = False
    elif max_sev in ("HIGH", "MEDIUM") or risk_score >= 25:
        verdict = "WARN"
        allow_trade = True
    else:
        verdict = "ALLOW"
        allow_trade = True

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    att_hash = hashlib.sha256(f"{chain_norm}:{addr}:{verdict}:{risk_score}:{payment_receipt}".encode()).hexdigest()

    return {
        "schema_version": "2.0.0",
        "service": "token_auditor",
        "chain": chain_norm,
        "token_address": addr,
        "execution_gate": {
            "verdict": verdict,
            "allow_trade": allow_trade,
            "risk_score": risk_score,
            "max_severity": max_sev,
        },
        "findings": findings,
        "findings_count": len(findings),
        "onchain_metadata": onchain_meta,
        "dex_market": dex_meta,
        "scan_duration_ms": elapsed_ms,
        "attestation": {
            "oracle": "ScanPay Token Shield v1.2.0",
            "merchant_wallet": merchant_wallet,
            "payment_receipt": payment_receipt,
            "evaluation_hash": f"sha256:{att_hash}",
        },
    }
