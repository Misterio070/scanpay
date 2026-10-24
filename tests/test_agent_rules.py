"""Tests for Agent-Specific AST Rules (AGT-PY-023 through AGT-PY-028, AGT-TS-024 through AGT-TS-029)."""
import pytest
from src.engine import scan as scan_python
from src.engine_js import scan as scan_js, JS_AVAILABLE
from src.remediator import apply_deterministic_fixes, build_a2a_response


def test_agent_py_wallet_exfiltration():
    code = """
import os
key = os.environ["SOLANA_PRIVATE_KEY"]
print(f"My key is: {key}")
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-023" in rule_ids


def test_agent_py_rpc_hijacking():
    code = """
client = Client("http://unencrypted-rpc.com")
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-024" in rule_ids


def test_agent_py_tool_chaining():
    code = """
import subprocess
tool_output = get_external_data()
subprocess.run(tool_output)
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-025" in rule_ids


def test_agent_py_infinite_loop():
    code = """
import requests
while True:
    res = requests.get("https://example.com/api")
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-026" in rule_ids


def test_agent_py_hallucinated_package():
    code = """
import solana_web3
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-027" in rule_ids


def test_agent_py_unsimulated_tx():
    code = """
send_transaction(signed_tx)
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-028" in rule_ids


def test_agent_py_dynamic_reflection():
    code = """
func = getattr(__builtins__, dynamic_func_name)
func("malicious_code")
"""
    result = scan_python(code)
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-PY-029" in rule_ids or "PY-SCANNER-BYPASS" in rule_ids


@pytest.mark.skipif(not JS_AVAILABLE, reason="tree-sitter required")
def test_agent_ts_wallet_exfiltration():
    code = """
const key = process.env.SOLANA_PRIVATE_KEY;
console.log("Wallet key is", key);
"""
    result = scan_js(code, language="typescript")
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-TS-024" in rule_ids


@pytest.mark.skipif(not JS_AVAILABLE, reason="tree-sitter required")
def test_agent_ts_unbounded_slippage():
    code = """
const res = await agent.trade({ slippageBps: 800 });
"""
    result = scan_js(code, language="typescript")
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-TS-025" in rule_ids


@pytest.mark.skipif(not JS_AVAILABLE, reason="tree-sitter required")
def test_agent_ts_rpc_hijacking():
    code = """
const connection = new Connection("http://insecure-rpc.solana.com");
"""
    result = scan_js(code, language="typescript")
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-TS-026" in rule_ids


@pytest.mark.skipif(not JS_AVAILABLE, reason="tree-sitter required")
def test_agent_ts_hallucinated_package():
    code = """
import { Agent } from "@solana/web3.js-agent";
"""
    result = scan_js(code, language="typescript")
    rule_ids = [f.rule_id for f in result.findings]
    assert "AGT-TS-029" in rule_ids
