"""ScanPay Remote Streamable MCP Server.

Stateless remote HTTP and SSE Model Context Protocol endpoints.
Enables autonomous agent platforms (Protogrid, Glama, Smithery, Claude Desktop, Cursor)
to discover tools remotely and interact with ScanPay over HTTP/SSE.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from .engine import scan as scan_python, RULES as PY_RULES, sha256_hex
from .remediator import build_a2a_response
from .preflight import simulate_transaction
from .scraper_oracle import scrape_url

try:
    from .engine_js import scan as scan_javascript, RULES as JS_RULES
    JS_AVAILABLE = True
except Exception:
    JS_AVAILABLE = False
    JS_RULES = []

logger = logging.getLogger("scanpay.mcp_remote")

MCP_TOOLS = [
    {
        "name": "scan_code",
        "description": (
            "Deterministic code security scanner for AI agents. Analyzes Python, JavaScript, and TypeScript "
            "code for 45+ vulnerability patterns (injection, hardcoded secrets, wallet key exfiltration, SSRF, "
            "infinite x402 loops, unsimulated Solana transactions). Returns deterministic AST patches, "
            "unified diffs, and execution verdicts (PASS, WARN, BLOCK)."
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
            "Returns execution verdict (ALLOW, WARN, BLOCK) and cryptographic oracle attestation."
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
            },
            "required": ["chain", "tx"],
        },
    },
    {
        "name": "scrape_url",
        "description": (
            "Anti-bot web access & scraper oracle for AI agents. Fetches web pages with stealth headers "
            "to bypass Cloudflare Turnstile, WAFs, and anti-bot challenges. Purifies HTML by removing scripts, "
            "stylesheets, tracking pixels, ads, and navigation boilerplate, returning clean, token-efficient "
            "Markdown ready for LLM consumption with cryptographic oracle attestation."
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
                    "description": "Transaction signature/hash transferring payment to merchant wallet",
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


async def handle_mcp_jsonrpc(
    request_data: dict[str, Any],
    merchant_wallet: str,
    payment_mode: str,
    db_path: str,
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
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    },
                },
                "serverInfo": {
                    "name": "scanpay",
                    "version": "1.2.0",
                    "description": "Deterministic AST code security scanner, Tx Preflight & Scraper Oracle with x402 micropayments",
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
            deposit_tx = args.get("deposit_tx")
            payer = args.get("payer_wallet", "unknown_agent")
            from .session import create_session_voucher
            voucher = create_session_voucher(db_path, deposit_tx, payer)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Prepaid session voucher activated!\nSession Token: {voucher['session_token']}\nCredits: {voucher['remaining_credits']}\nExpires: {voucher['expires_at']}",
                        }
                    ],
                    "session": voucher,
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
                payment_receipt="mcp-session",
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
                payment_receipt="mcp-session",
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
                payment_receipt="mcp-session",
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
