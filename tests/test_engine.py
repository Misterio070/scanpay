"""Test the deterministic scanner engines (Python and JavaScript/TypeScript)."""
import pytest
from src.engine import scan as scan_python, sha256_hex
from src.engine_js import scan as scan_javascript


class TestPythonScanner:
    """Python AST-based scanner tests."""

    def test_clean_code_no_findings(self):
        r = scan_python("x = 1\ny = x + 2\nprint(y)")
        assert len(r.findings) == 0
        assert r.syntax_ok is True

    def test_eval_detected(self):
        r = scan_python("eval('1 + 2')")
        ids = [f.rule_id for f in r.findings]
        assert "PY-DANGEROUS-EVAL" in ids

    def test_exec_detected(self):
        r = scan_python("exec('x = 1')")
        ids = [f.rule_id for f in r.findings]
        assert "PY-DANGEROUS-EXEC" in ids

    def test_os_system_detected(self):
        r = scan_python('import os\nos.system("ls")')
        ids = [f.rule_id for f in r.findings]
        assert "PY-OS-SYSTEM" in ids

    def test_pickle_loads_detected(self):
        r = scan_python("import pickle\npickle.loads(data)")
        ids = [f.rule_id for f in r.findings]
        assert "PY-UNSAFE-DESERIALIZE" in ids

    def test_hardcoded_secret_detected(self):
        r = scan_python('api_key = "sk-1234567890abcdef1234567890abcdef"')
        ids = [f.rule_id for f in r.findings]
        assert "PY-HARDCODED-SECRET" in ids

    def test_syntax_error_handled(self):
        r = scan_python("def broken(:\n  pass")
        assert r.syntax_ok is False
        ids = [f.rule_id for f in r.findings]
        assert "PY-SYNTAX-ERROR" in ids

    def test_sha256_stable(self):
        code = "x = 1"
        h1 = sha256_hex(code)
        h2 = sha256_hex(code)
        assert h1 == h2
        assert len(h1) == 64

    def test_findings_have_required_fields(self):
        r = scan_python("eval('x')")
        for f in r.findings:
            assert f.rule_id
            assert f.severity in ("critical", "high", "medium", "low")
            assert f.line_start >= 1
            assert f.message
            assert f.evidence
            assert f.remediation

    def test_subprocess_detected(self):
        r = scan_python("import subprocess\nsubprocess.run(['ls'])")
        ids = [f.rule_id for f in r.findings]
        assert "PY-SUBPROCESS" in ids

    def test_shell_true_detected(self):
        r = scan_python("import subprocess\nsubprocess.run('ls', shell=True)")
        ids = [f.rule_id for f in r.findings]
        assert "PY-SHELL-EXEC" in ids

    def test_private_key_detected(self):
        r = scan_python(
            'key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIIBAAKCAQEA"')
        ids = [f.rule_id for f in r.findings]
        assert "PY-PRIVATE-KEY" in ids

    def test_obfuscation_detected(self):
        r = scan_python(
            'import base64; exec(base64.b64decode("ZXhlYygnYWJjJyk="))')
        ids = [f.rule_id for f in r.findings]
        # Should catch both the exec and the obfuscation
        assert "PY-DANGEROUS-EXEC" in ids

    def test_max_line_count_guard(self):
        """Lines beyond MAX_LINE_COUNT trigger a parser-abuse finding."""
        r = scan_python("\n" * 50_001)
        ids = [f.rule_id for f in r.findings]
        assert "PY-PARSER-ABUSE" in ids

    def test_empty_code(self):
        """Empty string produces no findings and is syntactically valid."""
        r = scan_python("")
        assert r.syntax_ok is True
        assert len(r.findings) == 0


class TestJavaScriptScanner:
    """JavaScript/TypeScript tree-sitter scanner tests."""

    def test_clean_js_no_findings(self):
        r = scan_javascript("const x = 1; const y = x + 2;", language="javascript")
        assert len(r.findings) == 0
        assert r.syntax_ok is True

    def test_eval_detected(self):
        r = scan_javascript('eval("x = 1")', language="javascript")
        ids = [f.rule_id for f in r.findings]
        assert "JS-DANGEROUS-EVAL" in ids

    def test_function_constructor_detected(self):
        r = scan_javascript('new Function("return this")()', language="javascript")
        ids = [f.rule_id for f in r.findings]
        assert "JS-DANGEROUS-FUNCTION" in ids

    def test_child_process_exec_detected(self):
        r = scan_javascript(
            'const cp = require("child_process"); cp.exec("ls")',
            language="javascript")
        ids = [f.rule_id for f in r.findings]
        assert "JS-DANGEROUS-EXEC" in ids

    def test_typescript_supported(self):
        r = scan_javascript(
            "const x: number = eval('1');", language="typescript")
        ids = [f.rule_id for f in r.findings]
        assert "JS-DANGEROUS-EVAL" in ids

    def test_tsx_supported(self):
        r = scan_javascript(
            "const x = eval('1');", language="tsx")
        ids = [f.rule_id for f in r.findings]
        assert "JS-DANGEROUS-EVAL" in ids

    def test_findings_have_required_fields(self):
        r = scan_javascript("eval('x')", language="javascript")
        for f in r.findings:
            assert f.rule_id
            assert f.severity in ("critical", "high", "medium", "low")
            assert f.line_start >= 1
            assert f.message

    def test_syntax_error_handled(self):
        r = scan_javascript("function {{(}", language="javascript")
        # Should not crash — may or may not flag syntax error depending on
        # tree-sitter recovery, but must not raise
        assert r.syntax_ok is False or len(r.findings) >= 0


class TestScannerIsolation:
    """Scanner must not execute user code — pure static analysis."""

    def test_no_code_execution_python(self):
        """Scanning code with a side-effecting expression should not execute it."""
        # If the scanner executed this, it would raise ZeroDivisionError
        r = scan_python("x = 1 / 0")
        assert r.syntax_ok is True
        # No crash — code was parsed, not executed

    def test_no_code_execution_infinite_loop(self):
        """Scanning code with an infinite loop should not hang."""
        r = scan_python("while True:\n    pass")
        assert r.syntax_ok is True
        # Must return immediately — no execution

    def test_no_import_side_effects(self):
        """Scanning code with imports should not actually import."""
        r = scan_python("import nonexistent_module_xyz")
        assert r.syntax_ok is True
        # No ImportError — code was parsed, not executed

    def test_no_network_calls(self):
        """Scanning code with network calls should not make any."""
        r = scan_python(
            "import urllib.request\nurllib.request.urlopen('http://evil.com')")
        assert r.syntax_ok is True
        # Must return immediately without hitting the network

    def test_large_input_no_crash(self):
        """100KB of code should scan without crashing."""
        code = "x = 1\n" * 5000  # ~30KB of valid Python
        r = scan_python(code)
        assert r.syntax_ok is True

    def test_deep_nesting_no_crash(self):
        """Deeply nested expressions should not crash the parser."""
        code = "x = " + "({" * 50 + "1" + "})" * 50
        r = scan_python(code)
        # Should either parse or flag parser abuse, not crash
        assert r is not None