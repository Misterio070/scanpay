"""ScanPay Remote Streamable MCP Server.

Stateless remote HTTP and SSE Model Context Protocol endpoints.
Enables autonomous agent platforms (Protogrid, Glama, Smithery, Claude Desktop, Cursor)
to discover tools remotely and interact with ScanPay over HTTP/SSE.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Coroutine, Optional

from .engine import scan as scan_python, RULES as PY_RULES, sha256_hex
from .remediator import build_a2a_response
from .preflight import simulate_transaction
from .scraper_oracle import scrape_url
from .token_auditor import audit_token_contract

try:
    from .engine_js import scan as scan_javascript, RULES as JS_RULES
    JS_AVAILABLE = True
except Exception:
    JS_AVAILABLE = False
    JS_RULES = []

logger = logging.getLogger("scanpay.mcp_remote")

BASE_EVM_WALLET = "0xb295E606F38C363b476FC546c27226B5fBcAAEFA"
BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

_PAYMENT_PROPS = {
    "payment_tx": {
        "type": "string",
        "description": (
            "Optional x402 payment transaction proof: Base EVM tx hash (0x...) transferring USDC to "
            f"{BASE_EVM_WALLET}, or Solana tx signature transferring SOL/USDC."
        ),
    },
    "session_token": {
        "type": "string",
        "description": "Optional prepaid session voucher token (scanpay_sess_...) for 0ms instant execution.",
    },
}

MCP_TOOLS = [
    {
        "name": "scan_code",
        "description": (
            "Use before shipping or executing agent-generated code. Deterministic AST scan for Python, "
            "JavaScript and TypeScript with 65 rules (36 Python, 29 JS/TS) covering injection, hardcoded "
            "secrets, wallet key exfiltration, SSRF, infinite x402 payment loops and unsimulated Solana "
            "transactions. Returns findings with severity, deterministic patches, unified diffs and an "
            "execution verdict (PASS, WARN, BLOCK). Pay per call: 0.10 Base USDC or 0.0007 SOL over x402, "
            "no signup or API key."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Source code to scan (Python or JS/TS)",
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "javascript", "typescript", "tsx"],
                    "default": "python",
                    "description": "Source code programming language",
                },
                "auto_remediate": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to generate deterministic patches and unified diffs",
                },
                **_PAYMENT_PROPS,
            },
            "required": ["source_code"],
        },
    },
    {
        "name": "simulate_tx",
        "description": (
            "Pre-flight transaction & drainer shield for AI agents. Simulates and inspects EVM (Base/Ethereum) "
            "and Solana transactions before signing or broadcasting. Detects unlimited approvals, known drainers, "
            "honeypots, MEV sandwich exposure (min_output=0), and unauthorized Solana authority takeovers. "
            "Returns execution verdict (ALLOW, WARN, BLOCK) and cryptographic oracle attestation. Price: $0.05 Base USDC or 0.00035 SOL."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {
                    "type": "string",
                    "enum": ["base", "ethereum", "solana"],
                    "default": "base",
                    "description": "Target blockchain network",
                },
                "tx": {
                    "type": "object",
                    "description": "Transaction payload (EVM: to, data, value; Solana: instructions)",
                },
                **_PAYMENT_PROPS,
            },
            "required": ["chain", "tx"],
        },
    },
    {
        "name": "audit_token",
        "description": (
            "Live on-chain token & smart contract rug-pull / honeypot shield for Base, Ethereum, and Solana. "
            "Inspects live EVM bytecode (blacklist selectors, mutable tax fees, pause toggles, unverified proxies) "
            "and Solana SPL / Token-2022 mint accounts (active mint authority, freeze authority, Permanent Delegate wallet seizure, "
            "Transfer Hook honeypots) plus live DexScreener liquidity and 24h buy/sell ratios. Price: $0.05 Base USDC or 0.00035 SOL."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {
                    "type": "string",
                    "enum": ["base", "ethereum", "solana"],
                    "default": "base",
                    "description": "Blockchain network where the token is deployed",
                },
                "token_address": {
                    "type": "string",
                    "description": "Token contract address (0x... for Base/Ethereum or Base58 mint address for Solana)",
                },
                **_PAYMENT_PROPS,
            },
            "required": ["chain", "token_address"],
        },
    },
    {
        "name": "scrape_url",
        "description": (
            "Anti-bot web access & scraper oracle for AI agents. Fetches web pages with stealth headers "
            "to bypass Cloudflare Turnstile, WAFs, and anti-bot challenges. Purifies HTML by removing scripts, "
            "stylesheets, tracking pixels, ads, and navigation boilerplate, returning clean, token-efficient "
            "Markdown ready for LLM consumption with cryptographic oracle attestation. Price: $0.02 Base USDC or 0.00015 SOL."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to scrape",
                },
                "extract_mode": {
                    "type": "string",
                    "enum": ["markdown", "text", "raw_html"],
                    "default": "markdown",
                    "description": "Extracted content format",
                },
                "strip_media": {
                    "type": "boolean",
                    "default": True,
                    "description": "Strip image tags and heavy media to conserve LLM context tokens",
                },
                **_PAYMENT_PROPS,
            },
            "required": ["url"],
        },
    },
    {
        "name": "create_session_deposit",
        "description": (
            "Activate a prepaid session voucher (0.006 SOL or 0.85 Base USDC for 10 operations). "
            "Eliminates per-request payment prompts and RPC latency in autonomous agent loops."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "deposit_tx": {
                    "type": "string",
                    "description": "Transaction signature/hash transferring 0.006 SOL or 0.85 Base USDC to merchant wallet",
                },
                "payer_wallet": {
                    "type": "string",
                    "description": "Public key / address of the payer",
                },
            },
            "required": ["deposit_tx"],
        },
    },
    {
        "name": "health_check",
        "description": "Check ScanPay engine health, available AST rules, and x402 payment configurations.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]

TOOL_PRICING = {
    "scan_code": {"usd": "0.10 USDC", "usdc_units": 100000, "sol": "0.0007 SOL", "lamports": 700000},
    "simulate_tx": {"usd": "0.05 USDC", "usdc_units": 50000, "sol": "0.00035 SOL", "lamports": 350000},
    "audit_token": {"usd": "0.05 USDC", "usdc_units": 50000, "sol": "0.00035 SOL", "lamports": 350000},
    "scrape_url": {"usd": "0.02 USDC", "usdc_units": 20000, "sol": "0.00015 SOL", "lamports": 150000},
}


async def build_diagnostic_preview(
    tool_name: str,
    args: dict[str, Any],
    merchant_wallet: str = "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
) -> dict[str, Any]:
    """Run a fast pre-check on the caller's input to prove value before unlocking full details."""
    try:
        if tool_name == "scan_code":
            source = args.get("source_code") or args.get("code") or ""
            language = args.get("language", "python")
            if not source:
                return {}
            if language == "python":
                scan_res = scan_python(source)
                rules_cnt = len(PY_RULES)
            elif language in ("javascript", "typescript", "tsx") and JS_AVAILABLE:
                scan_res = scan_javascript(source, language=language)
                rules_cnt = len(JS_RULES)
            else:
                return {}
            a2a_res = build_a2a_response(
                source=source,
                language=language,
                findings=scan_res.findings,
                execution_time_ms=scan_res.scan_duration_ms,
                rules_evaluated=rules_cnt,
                merchant_wallet=merchant_wallet,
                payment_receipt="preview-locked",
            )
            gate = a2a_res["execution_gate"]
            rule_ids = list({f["rule_id"] for f in a2a_res["findings"]})
            return {
                "preview_status": "THREATS_DETECTED_LOCKED" if a2a_res["findings"] else "CLEAN_VERIFICATION_LOCKED",
                "verdict_preview": gate["verdict"],
                "risk_score": gate["risk_score"],
                "max_severity": gate["max_severity"],
                "findings_count": len(a2a_res["findings"]),
                "detected_rule_ids": rule_ids[:5],
                "patches_ready_to_unlock": a2a_res["auto_remediation"]["patches_available"],
                "locked_fields": [
                    "findings.line_number",
                    "findings.description",
                    "auto_remediation.remediated_code",
                    "auto_remediation.unified_diff",
                    "attestation.signature",
                ],
            }
        elif tool_name == "simulate_tx":
            chain = args.get("chain", "base")
            tx = args.get("tx")
            if isinstance(tx, dict):
                sim_res = simulate_transaction(chain=chain, tx_data=tx, merchant_wallet=merchant_wallet, payment_receipt="preview-locked")
                gate = sim_res["execution_gate"]
                return {
                    "preview_status": "THREATS_DETECTED_LOCKED" if sim_res["findings"] else "CLEAN_VERIFICATION_LOCKED",
                    "verdict_preview": gate["verdict"],
                    "risk_score": gate["risk_score"],
                    "max_severity": gate["max_severity"],
                    "findings_count": len(sim_res["findings"]),
                    "locked_fields": ["findings_details", "simulated_deltas", "attestation"],
                }
        elif tool_name == "audit_token":
            chain = args.get("chain", "base")
            token_address = args.get("token_address", "")
            if token_address:
                aud_res = await audit_token_contract(chain=chain, token_address=token_address, merchant_wallet=merchant_wallet, payment_receipt="preview-locked")
                gate = aud_res["execution_gate"]
                return {
                    "preview_status": "THREATS_DETECTED_LOCKED" if aud_res["findings"] else "CLEAN_VERIFICATION_LOCKED",
                    "verdict_preview": gate["verdict"],
                    "risk_score": gate["risk_score"],
                    "max_severity": gate["max_severity"],
                    "findings_count": len(aud_res["findings"]),
                    "token_symbol": aud_res.get("dex_market", {}).get("symbol"),
                    "locked_fields": ["findings_details", "onchain_metadata", "dex_market_breakdown", "attestation"],
                }
    except Exception:
        pass
    return {}


async def handle_mcp_jsonrpc(
    request_data: dict[str, Any],
    merchant_wallet: str,
    payment_mode: str,
    db_path: str,
    verify_payment_callback: Optional[Callable[[str, int, int], Coroutine[Any, Any, str]]] = None,
) -> dict[str, Any]:
    """Process a Model Context Protocol JSON-RPC request asynchronously."""
    req_id = request_data.get("id")
    method = request_data.get("method")
    params = request_data.get("params") or {}

    if not method:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request: missing method"},
        }

    if method == "initialize":
        # Echo the client's version when it is one we speak; clients that ask
        # for a newer revision get the newest supported one instead of a
        # downgrade that makes them drop features.
        requested = (params or {}).get("protocolVersion")
        supported = ("2025-06-18", "2025-03-26", "2024-11-05")
        negotiated = requested if requested in supported else supported[0]
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    },
                },
                "serverInfo": {
                    "name": "scanpay",
                    "version": "1.2.0",
                    "description": "Deterministic AST code security scanner, Token Rug/Honeypot Shield, Tx Preflight & Scraper Oracle with x402 micropayments",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": MCP_TOOLS,
            },
        }

    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}

        if tool_name == "health_check":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "status": "ok",
                                "engine_version": "1.2.0",
                                "payment_mode": payment_mode,
                                "merchant_wallet": merchant_wallet,
                                "merchant_evm_wallet": BASE_EVM_WALLET,
                                "tools_active": [t["name"] for t in MCP_TOOLS],
                                "python_rules": len(PY_RULES),
                                "js_rules": len(JS_RULES),
                                "js_available": JS_AVAILABLE,
                            }, indent=2),
                        }
                    ]
                },
            }

        if tool_name == "create_session_deposit":
            deposit_tx = str(args.get("deposit_tx") or "").strip()
            payer = args.get("payer_wallet", "unknown_agent")
            if not deposit_tx:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing required argument 'deposit_tx'"},
                }
            if payment_mode in ("mainnet", "testnet") and verify_payment_callback is not None:
                try:
                    await verify_payment_callback(deposit_tx, 6_000_000, 850_000)
                except ValueError as e:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -40200, "message": f"Session deposit verification failed: {e}"},
                    }
            from .session import create_session_voucher
            voucher = create_session_voucher(db_path, deposit_tx, payer)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"Prepaid session voucher activated!\n"
                                f"Session Token: {voucher['session_token']}\n"
                                f"Credits: {voucher['remaining_credits']}\n"
                                f"Expires: {voucher['expires_at']}"
                            ),
                        }
                    ],
                    "session": voucher,
                },
            }

        # Payment enforcement for paid tools in live modes
        payment_receipt = "mcp-free"
        if tool_name in TOOL_PRICING and payment_mode in ("mainnet", "testnet"):
            meta = params.get("_meta") or {}
            session_token = args.get("session_token") or meta.get("session_token")
            payment_tx = args.get("payment_tx") or meta.get("payment")
            pricing = TOOL_PRICING[tool_name]

            paid_ok = False
            if session_token:
                from .session import consume_session_credit
                res_tuple = consume_session_credit(db_path, str(session_token))
                ok = res_tuple[0] if isinstance(res_tuple, tuple) else bool(res_tuple)
                if ok:
                    paid_ok = True
                    payment_receipt = f"voucher-{str(session_token)[:12]}"

            if not paid_ok and payment_tx and verify_payment_callback is not None:
                try:
                    verified_sig = await verify_payment_callback(
                        str(payment_tx).strip(),
                        pricing["lamports"],
                        pricing["usdc_units"],
                    )
                    paid_ok = True
                    payment_receipt = verified_sig
                except ValueError:
                    paid_ok = False

            if not paid_ok:
                preview = await build_diagnostic_preview(tool_name, args, merchant_wallet)
                alert_msg = "Payment Required (x402 v2)"
                if preview.get("findings_count", 0) > 0:
                    alert_msg = (
                        f"⚠️ ScanPay Diagnostic Alert: Detected {preview['findings_count']} security threat(s) "
                        f"(Max Severity: {preview['max_severity']}, Risk Score: {preview['risk_score']}/100, "
                        f"Verdict: {preview['verdict_preview']}). Full report, line numbers & auto-remediation patch locked — "
                        f"settle {pricing['usd']} on Base or {pricing['sol']} on Solana to unlock."
                    )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -40200,
                        "message": alert_msg,
                        "data": {
                            "x402Version": 2,
                            "tool": tool_name,
                            "price_usd": pricing["usd"],
                            "price_sol": pricing["sol"],
                            "diagnostic_preview": preview,
                            "accepted_tokens": [
                                {
                                    "chain": "base",
                                    "network": "eip155:8453",
                                    "token": "USDC",
                                    "contract": BASE_USDC_CONTRACT,
                                    "amount": pricing["usdc_units"],
                                    "amount_display": pricing["usd"],
                                    "recipient": BASE_EVM_WALLET,
                                },
                                {
                                    "chain": "solana",
                                    "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                                    "token": "SOL",
                                    "amount": pricing["lamports"],
                                    "amount_display": pricing["sol"],
                                    "recipient": merchant_wallet,
                                },
                            ],
                            "voucher_activation_tool": "create_session_deposit",
                            "instructions": (
                                f"Send {pricing['usd']} (Base USDC) to {BASE_EVM_WALLET} or {pricing['sol']} (Solana) "
                                f"to {merchant_wallet} and pass the transaction hash in 'payment_tx', OR call "
                                "'create_session_deposit' with 0.85 USDC / 0.006 SOL for 10 instant credits and pass 'session_token'."
                            ),
                        },
                    },
                }

        if tool_name == "scan_code":
            source = args.get("source_code") or args.get("code") or ""
            language = args.get("language", "python")

            if not source:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing required argument 'source_code'"},
                }

            if language == "python":
                scan_res = scan_python(source)
                rules_cnt = len(PY_RULES)
            elif language in ("javascript", "typescript", "tsx") and JS_AVAILABLE:
                scan_res = scan_javascript(source, language=language)
                rules_cnt = len(JS_RULES)
            elif language in ("javascript", "typescript", "tsx") and not JS_AVAILABLE:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": "JavaScript engine unavailable on this runtime"},
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unsupported language: {language}"},
                }

            a2a_res = build_a2a_response(
                source=source,
                language=language,
                findings=scan_res.findings,
                execution_time_ms=scan_res.scan_duration_ms,
                rules_evaluated=rules_cnt,
                merchant_wallet=merchant_wallet,
                payment_receipt=payment_receipt,
            )

            gate = a2a_res["execution_gate"]
            remediation = a2a_res["auto_remediation"]
            summary_lines = [
                f"Scan Verdict: {gate['verdict']} (Risk Score: {gate['risk_score']}/100, Max Severity: {gate['max_severity']})",
                f"Allow Execution: {gate['allow_execution']}",
                f"Findings: {len(a2a_res['findings'])} vulnerability patterns detected.",
            ]
            if remediation["patches_available"]:
                summary_lines.append("\nDeterministic Security Patch Available:")
                summary_lines.append(f"Post-patch verdict: {remediation['post_patch_verdict']}")
                summary_lines.append("```diff\n" + remediation["unified_diff"] + "\n```")

            content = [
                {"type": "text", "text": "\n".join(summary_lines)},
                {"type": "text", "text": json.dumps(a2a_res, indent=2)},
            ]

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": content,
                    "execution_gate": gate,
                    "auto_remediation": remediation,
                },
            }

        if tool_name == "simulate_tx":
            chain = args.get("chain", "base")
            tx = args.get("tx")
            if not isinstance(tx, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing required argument 'tx' (dict)"},
                }

            sim_res = simulate_transaction(
                chain=chain,
                tx_data=tx,
                merchant_wallet=merchant_wallet,
                payment_receipt=payment_receipt,
            )

            gate = sim_res["execution_gate"]
            summary_lines = [
                f"Simulation Verdict: {gate['verdict']} (Risk Score: {gate['risk_score']}/100, Max Severity: {gate['max_severity']})",
                f"Allow Broadcast: {gate['allow_broadcast']}",
                f"Chain: {sim_res['chain']}",
                f"Findings: {len(sim_res['findings'])} threat indicators detected.",
            ]
            for f in sim_res["findings"]:
                summary_lines.append(f"- [{f['severity']}] {f['title']}: {f['description']}")

            content = [
                {"type": "text", "text": "\n".join(summary_lines)},
                {"type": "text", "text": json.dumps(sim_res, indent=2)},
            ]

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": content,
                    "execution_gate": gate,
                    "simulated_deltas": sim_res["simulated_deltas"],
                    "attestation": sim_res["attestation"],
                },
            }

        if tool_name == "audit_token":
            chain = args.get("chain", "base")
            token_address = str(args.get("token_address") or "").strip()
            if not token_address:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing required argument 'token_address'"},
                }
            try:
                aud_res = await audit_token_contract(
                    chain=chain,
                    token_address=token_address,
                    merchant_wallet=merchant_wallet,
                    payment_receipt=payment_receipt,
                )
            except ValueError as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(e)},
                }

            gate = aud_res["execution_gate"]
            dex = aud_res["dex_market"]
            summary_lines = [
                f"Token Audit Verdict: {gate['verdict']} (Risk Score: {gate['risk_score']}/100, Max Severity: {gate['max_severity']})",
                f"Allow Trade: {gate['allow_trade']}",
                f"Token: {dex.get('symbol') or token_address} on {aud_res['chain']} (DEX Liquidity: ${dex.get('liquidity_usd', 0):,.2f})",
                f"Findings: {aud_res['findings_count']} rug/honeypot indicators detected.",
            ]
            for f in aud_res["findings"]:
                summary_lines.append(f"- [{f['severity']}] {f['title']}: {f['description']}")

            content = [
                {"type": "text", "text": "\n".join(summary_lines)},
                {"type": "text", "text": json.dumps(aud_res, indent=2)},
            ]

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": content,
                    "execution_gate": gate,
                    "findings": aud_res["findings"],
                    "onchain_metadata": aud_res["onchain_metadata"],
                    "dex_market": dex,
                    "attestation": aud_res["attestation"],
                },
            }

        if tool_name == "scrape_url":
            url = args.get("url")
            if not url:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing required argument 'url'"},
                }

            extract_mode = args.get("extract_mode", "markdown")
            strip_media = bool(args.get("strip_media", True))

            scrape_res = await scrape_url(
                url=url,
                extract_mode=extract_mode,
                strip_media=strip_media,
                merchant_wallet=merchant_wallet,
                payment_receipt=payment_receipt,
            )

            meta = scrape_res["metadata"]
            summary_lines = [
                f"Scraped: {scrape_res['request']['target_url']} (HTTP {scrape_res['request']['status_code']})",
                f"Title: {meta['title']}",
                f"WAF Detected: {scrape_res['bot_protection']['waf_detected']} ({scrape_res['bot_protection']['challenge_type']})",
                f"Words: {meta['word_count']} (~{meta['token_estimate']} tokens)",
            ]

            content = [
                {"type": "text", "text": "\n".join(summary_lines)},
                {"type": "text", "text": scrape_res["content"]},
            ]

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": content,
                    "metadata": meta,
                    "bot_protection": scrape_res["bot_protection"],
                    "attestation": scrape_res["attestation"],
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not supported: {method}"},
    }
