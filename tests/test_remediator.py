"""Tests for the Auto-Remediation and v2 response builder."""
import pytest
from src.engine import scan as scan_python
from src.remediator import apply_deterministic_fixes, build_a2a_response


def test_python_eval_remediation():
    code = "result = eval('1 + 1')"
    patched, modified = apply_deterministic_fixes(code, "python")
    assert modified is True
    assert "ast.literal_eval" in patched
    assert "import ast" in patched


def test_python_yaml_remediation():
    code = "data = yaml.load(raw_data)"
    patched, modified = apply_deterministic_fixes(code, "python")
    assert modified is True
    assert "yaml.safe_load" in patched


def test_python_subprocess_shell_remediation():
    code = "subprocess.run(cmd, shell=True)"
    patched, modified = apply_deterministic_fixes(code, "python")
    assert modified is True
    assert "shell=False" in patched


def test_js_innerhtml_remediation():
    code = "div.innerHTML = untrustedInput;"
    patched, modified = apply_deterministic_fixes(code, "javascript")
    assert modified is True
    assert "div.textContent = untrustedInput;" in patched


def test_build_a2a_response():
    code = "result = eval('1 + 1')"
    scan_res = scan_python(code)
    resp = build_a2a_response(
        source=code,
        language="python",
        findings=scan_res.findings,
        execution_time_ms=5.0,
        rules_evaluated=28,
        merchant_wallet="JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4",
    )

    assert resp["schema_version"] == "2.0.0"
    assert "execution_gate" in resp
    assert "verdict" in resp["execution_gate"]
    assert "auto_remediation" in resp
    assert resp["auto_remediation"]["patches_available"] is True
    assert "unified_diff" in resp["auto_remediation"]
    assert len(resp["auto_remediation"]["unified_diff"]) > 0
    assert "attestation" in resp
    assert resp["attestation"]["oracle_pubkey"] == "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"
