#!/usr/bin/env python3
"""ScanPay Universal Pre-Execution Runtime Hook.

Deterministic interceptor for Claude Code PreToolUse, OpenCode, Codex, and LangGraph.
Intercepts tool commands before execution, evaluates AST security via ScanPay API,
and blocks malicious payloads (exit code 1) or passes verified code (exit code 0).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SCANPAY_URL = os.getenv("SCANPAY_URL", "https://scanpay-ob3w.onrender.com/v2/scan")
SESSION_VOUCHER = os.getenv("SCANPAY_SESSION_VOUCHER", "")
CACHE_DIR = Path.home() / ".scanpay"
CACHE_FILE = CACHE_DIR / "verified_cache.json"


def load_cache() -> dict[str, str]:
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def extract_code_from_command(command: str) -> tuple[str, str]:
    """Extract source code and detect language from execution command."""
    # python -c "..." or python script.py
    if "python" in command:
        if "-c" in command:
            parts = command.split("-c", 1)
            code = parts[1].strip().strip('"').strip("'")
            return code, "python"
        for token in command.split():
            if token.endswith(".py") and os.path.exists(token):
                try:
                    with open(token, "r", encoding="utf-8") as f:
                        return f.read(), "python"
                except Exception:
                    pass
        return command, "python"

    # node -e "..." or node script.js
    if "node" in command or "deno" in command or "bun" in command:
        if "-e" in command:
            parts = command.split("-e", 1)
            code = parts[1].strip().strip('"').strip("'")
            return code, "javascript"
        for token in command.split():
            if token.endswith((".js", ".ts", ".tsx")) and os.path.exists(token):
                try:
                    with open(token, "r", encoding="utf-8") as f:
                        return f.read(), "javascript"
                except Exception:
                    pass
        return command, "javascript"

    return "", "python"


def main() -> int:
    # Read input from argv or stdin
    command = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read().strip()
    if not command:
        return 0

    code, lang = extract_code_from_command(command)
    if not code or len(code.strip()) == 0:
        return 0

    code_hash = "sha256:" + hashlib.sha256(code.encode("utf-8")).hexdigest()
    cache = load_cache()

    # Fast 0ms cache pass-through
    if cache.get(code_hash) == "PASS":
        return 0

    headers = {"Content-Type": "application/json"}
    if SESSION_VOUCHER:
        headers["X-SCANPAY-SESSION"] = SESSION_VOUCHER

    req_body = json.dumps({
        "source_code": code,
        "language": lang,
        "auto_remediate": True,
    }).encode("utf-8")

    req = urllib.request.Request(SCANPAY_URL, data=req_body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 402:
            sys.stderr.write("[ScanPay Guardrail] 402 Payment Required: provide SCANPAY_SESSION_VOUCHER or micropayment proof.\n")
            return 1
        sys.stderr.write(f"[ScanPay Guardrail] API HTTP error {e.code}: {e.reason}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[ScanPay Guardrail] Fail-closed: scan verification failed ({exc})\n")
        return 1

    gate = data.get("execution_gate", {})
    verdict = gate.get("verdict", "WARN")
    remediation = data.get("auto_remediation", {})

    if verdict == "BLOCK":
        sys.stderr.write("\n🚨 [ScanPay Guardrail] CRITICAL SECURITY VULNERABILITY DETECTED — EXECUTION BLOCKED!\n")
        sys.stderr.write(f"Risk Score: {gate.get('risk_score')}/100 | Max Severity: {gate.get('max_severity')}\n")
        sys.stderr.write(f"Findings: {data.get('findings_count')} issue(s) flagged.\n")
        if remediation.get("patches_available"):
            sys.stderr.write("\n✨ Deterministic Auto-Remediation Available:\n")
            sys.stderr.write(remediation.get("unified_diff", "") + "\n")
            sys.stderr.write(f"Post-patch verdict: {remediation.get('post_patch_verdict')}\n")
        return 1

    # PASS or acceptable WARN
    cache[code_hash] = verdict
    save_cache(cache)
    return 0


if __name__ == "__main__":
    sys.exit(main())
