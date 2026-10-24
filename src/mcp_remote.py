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
        "name": "create_session_deposit",
        "description": (
            "Activate a prepaid session voucher (0.006 SOL for 10 scans). "
            "Eliminates per-scan payment prompts and RPC latency in autonomous coding loops."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "deposit_tx": {
                    "type": "string",
                    "description": "Solana transaction signature transferring >= 0.006 SOL to merchant wallet",
                },
                "payer_wallet": {
                    "type": "string",
                    "description": "Solana public key of the payer",
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


def handle_mcp_jsonrpc(
    request_data: dict[str, Any],
    merchant_wallet: str,
    payment_mode: str,
    db_path: str,
) -> dict[str, Any]:
    """Process a Model Context Protocol JSON-RPC request."""
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
                    "version": "1.1.0",
                    "description": "Deterministic AST code security scanner with x402 Solana micropayments",
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
                                "engine_version": "1.1.0",
                                "payment_mode": payment_mode,
                                "merchant_wallet": merchant_wallet,
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

            # Build human & machine friendly response
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
