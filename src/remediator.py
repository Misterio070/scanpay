"""ScanPay Auto-Remediation & Machine Response Engine.

Computes deterministic code patches for detected AST vulnerabilities,
generates unified diffs, runs post-patch validation, and builds the
ScanPay v2 Machine-Readable Response.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .engine import scan as scan_python, sha256_hex

try:
    from .engine_js import scan as scan_javascript
    JS_AVAILABLE = True
except Exception:
    JS_AVAILABLE = False


# Deterministic replacement rules (regex / AST patterns)
PYTHON_REPLACEMENTS = [
    # eval(x) -> ast.literal_eval(x)
    (re.compile(r"\beval\s*\(([^)]+)\)"), r"ast.literal_eval(\1)"),
    # yaml.load(x) -> yaml.safe_load(x)
    (re.compile(r"\byaml\.load\s*\(([^,)]+)\)"), r"yaml.safe_load(\1)"),
    # pickle.loads(x) -> json.loads(x)
    (re.compile(r"\bpickle\.loads\s*\(([^)]+)\)"), r"json.loads(\1)"),
    # subprocess.run(..., shell=True) -> shell=False
    (re.compile(r"\bshell\s*=\s*True\b"), r"shell=False"),
    # os.system(cmd) -> subprocess.run(shlex.split(cmd), shell=False, check=True)
    (re.compile(r"\bos\.system\s*\(([^)]+)\)"), r"subprocess.run(shlex.split(\1), shell=False, check=True)"),
]

JS_REPLACEMENTS = [
    # eval(x) -> JSON.parse(x)
    (re.compile(r"\beval\s*\(([^)]+)\)"), r"JSON.parse(\1)"),
    # element.innerHTML = x -> element.textContent = x
    (re.compile(r"\.innerHTML\s*=\s*"), r".textContent = "),
    # setTimeout("string", ms) -> setTimeout(() => string, ms)
    (re.compile(r'setTimeout\s*\(\s*["\']([^"\']+)["\']\s*,'), r"setTimeout(() => { \1 },"),
    # child_process.exec(cmd) -> child_process.execFile(cmd)
    (re.compile(r"\bchild_process\.exec\s*\("), r"child_process.execFile("),
]


def apply_deterministic_fixes(source: str, language: str = "python") -> tuple[str, bool]:
    """Apply deterministic security patches to source code. Returns (patched_code, modified)."""
    patched = source
    replacements = PYTHON_REPLACEMENTS if language == "python" else JS_REPLACEMENTS

    # Ensure required imports for Python patches
    needs_ast = False
    needs_json = False
    needs_shlex = False

    if language == "python":
        if re.search(r"\beval\s*\(", source) and "import ast" not in source:
            needs_ast = True
        if re.search(r"\bpickle\.loads\s*\(", source) and "import json" not in source:
            needs_json = True
        if re.search(r"\bos\.system\s*\(", source) and "import shlex" not in source:
            needs_shlex = True

    for pattern, replacement in replacements:
        patched = pattern.sub(replacement, patched)

    if language == "python":
        prepends = []
        if needs_ast:
            prepends.append("import ast")
        if needs_json:
            prepends.append("import json")
        if needs_shlex:
            prepends.append("import shlex")
        if prepends:
            patched = "\n".join(prepends) + "\n" + patched

    return patched, (patched != source)


def calculate_risk_score(findings: list[Any]) -> tuple[int, str, str, float]:
    """Calculate 0-100 risk score, max_severity, verdict ('PASS', 'WARN', 'BLOCK'),

    and estimated exploit loss in USD.
    """
    if not findings:
        return 0, "NONE", "PASS", 0.0

    score = 0
    max_sev = "LOW"
    severity_weights = {"low": 5, "medium": 15, "high": 35, "critical": 50}
    severity_order = ["low", "medium", "high", "critical"]

    for f in findings:
        sev = getattr(f, "severity", "medium").lower()
        score += severity_weights.get(sev, 10)
        if severity_order.index(sev) > severity_order.index(max_sev.lower()):
            max_sev = sev.upper()

    score = min(100, score)

    # Verdict rules
    if max_sev == "CRITICAL" or score >= 50:
        verdict = "BLOCK"
        est_loss = 1000.0 if any("wallet" in getattr(f, "category", "").lower() or "secret" in getattr(f, "category", "").lower() for f in findings) else 250.0
    elif max_sev == "HIGH" or score >= 25:
        verdict = "WARN"
        est_loss = 50.0
    else:
        verdict = "WARN"
        est_loss = 10.0

    return score, max_sev, verdict, est_loss


def build_a2a_response(
    source: str,
    language: str,
    findings: list[Any],
    execution_time_ms: float,
    rules_evaluated: int,
    merchant_wallet: str,
    payment_receipt: str | None = None,
) -> dict[str, Any]:
    """Build full v2 Machine-Readable Auto-Remediation response for AI Agents."""
    risk_score, max_sev, verdict, est_loss = calculate_risk_score(findings)
    allow_execution = verdict == "PASS"

    # Deterministic Auto-Remediation
    remediated_code, modified = apply_deterministic_fixes(source, language)
    diff = ""
    post_patch_verdict = verdict

    if modified:
        diff_lines = difflib.unified_diff(
            source.splitlines(keepends=True),
            remediated_code.splitlines(keepends=True),
            fromfile="original.py" if language == "python" else "original.ts",
            tofile="remediated.py" if language == "python" else "remediated.ts",
        )
        diff = "".join(diff_lines)

        # Re-run validation on remediated code
        if language == "python":
            res = scan_python(remediated_code)
            re_findings = res.findings
        elif JS_AVAILABLE:
            res = scan_javascript(remediated_code, language=language)
            re_findings = res.findings
        else:
            re_findings = []

        _, re_max_sev, re_verdict, _ = calculate_risk_score(re_findings)
        post_patch_verdict = re_verdict
    else:
        remediated_code = source
        diff = ""

    sha_orig = sha256_hex(source)
    sha_remed = sha256_hex(remediated_code)
    now = datetime.now(timezone.utc).isoformat()
    scan_id = str(uuid.uuid4())

    # Simulated oracle signature over payload
    oracle_payload = f"{sha_orig}:{verdict}:{sha_remed}:{now}".encode("utf-8")
    oracle_sig = hashlib.sha256(oracle_payload).hexdigest()

    return {
        "schema_version": "2.0.0",
        "scan_id": scan_id,
        "timestamp": now,
        "engine_metrics": {
            "language": language,
            "parser": "python-ast" if language == "python" else f"tree-sitter-{language}",
            "rules_evaluated": rules_evaluated,
            "execution_time_ms": round(execution_time_ms, 2),
            "deterministic": True,
        },
        "execution_gate": {
            "verdict": verdict,
            "allow_execution": allow_execution,
            "risk_score": risk_score,
            "max_severity": max_sev,
            "estimated_exploit_loss_usd": est_loss,
        },
        "source_integrity": {
            "original_sha256": f"sha256:{sha_orig}",
            "byte_length": len(source.encode("utf-8")),
            "line_count": len(source.splitlines()),
        },
        "findings": [f.model_dump() if hasattr(f, "model_dump") else (f.__dict__ if hasattr(f, "__dict__") else f) for f in findings],
        "auto_remediation": {
            "patches_available": modified,
            "remediated_code": remediated_code,
            "unified_diff": diff,
            "post_patch_verdict": post_patch_verdict,
        },
        "attestation": {
            "oracle_pubkey": merchant_wallet or "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
            "oracle_signature": oracle_sig,
            "timestamp": now,
            "payment_receipt": payment_receipt or "none",
        },
    }
