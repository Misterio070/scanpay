"""Deterministic Python code scanner.

Source is analyzed with the `ast` module and line/regex heuristics.
It is NEVER executed, imported, or compiled to a code object.
`ast.parse` builds a syntax tree only — it runs no user code.
"""
from __future__ import annotations

import ast
import hashlib
import re
import time
from dataclasses import dataclass
from typing import ClassVar

from .schema import Confidence, Finding, Severity

# Guard against parser-abuse / deep-recursion inputs.
MAX_BRACKET_NESTING = 120   # pre-parse guard (deep nested literals blow the C stack)
MAX_AST_DEPTH = 200         # post-parse guard (deep ASTs blow the recursive visitor)
MAX_LINE_COUNT = 50_000


def sha256_hex(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _evidence(source: str, node: ast.AST) -> str:
    try:
        seg = ast.get_source_segment(source, node)
    except (IndexError, TypeError, ValueError):
        seg = None
    if not seg:
        lineno = getattr(node, "lineno", 0)
        lines = source.splitlines()
        seg = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    seg = seg.strip().replace("\n", " ")
    return seg[:160]


@dataclass
class _Rule:
    rule_id: str
    severity: Severity
    category: str
    message: str
    remediation: str


# --- Rule catalog (stable IDs; ruleset_version bumps if these change) --------
RULES: dict[str, _Rule] = {
    "PY-SYNTAX-ERROR": _Rule("PY-SYNTAX-ERROR", "high", "syntax",
        "Source is not valid Python; deterministic AST analysis is incomplete.",
        "Fix the syntax error and resubmit so the code can be fully analyzed."),
    "PY-DANGEROUS-EVAL": _Rule("PY-DANGEROUS-EVAL", "critical", "dynamic_execution",
        "Dynamic eval() invocation detected.",
        "Replace eval() with an explicit allowlisted operation or literal parsing (ast.literal_eval)."),
    "PY-DANGEROUS-EXEC": _Rule("PY-DANGEROUS-EXEC", "critical", "dynamic_execution",
        "Dynamic exec() invocation detected.",
        "Replace dynamic execution with an explicit allowlisted operation."),
    "PY-DANGEROUS-COMPILE": _Rule("PY-DANGEROUS-COMPILE", "high", "dynamic_execution",
        "compile() into exec/eval mode detected.",
        "Avoid compiling code from runtime data; use static functions."),
    "PY-OS-SYSTEM": _Rule("PY-OS-SYSTEM", "critical", "shell_execution",
        "os.system() shell invocation detected.",
        "Use subprocess with an argument list and shell=False, validating inputs."),
    "PY-SHELL-EXEC": _Rule("PY-SHELL-EXEC", "critical", "shell_execution",
        "Shell execution via shell=True or os.popen detected.",
        "Pass an argument list with shell=False and never interpolate untrusted input."),
    "PY-SUBPROCESS": _Rule("PY-SUBPROCESS", "medium", "process_spawn",
        "subprocess invocation detected.",
        "Ensure arguments are an explicit list, shell=False, and inputs are validated."),
    "PY-UNSAFE-DESERIALIZE": _Rule("PY-UNSAFE-DESERIALIZE", "critical", "deserialization",
        "Unsafe deserialization (pickle/marshal/shelve) detected.",
        "Use a safe format (JSON) or validate/authenticate serialized data before loading."),
    "PY-UNSAFE-YAML": _Rule("PY-UNSAFE-YAML", "high", "deserialization",
        "yaml.load without SafeLoader detected.",
        "Use yaml.safe_load() or Loader=yaml.SafeLoader."),
    "PY-HARDCODED-SECRET": _Rule("PY-HARDCODED-SECRET", "high", "secret",
        "Likely hardcoded credential/secret detected.",
        "Move secrets to environment variables or a secret manager."),
    "PY-PRIVATE-KEY": _Rule("PY-PRIVATE-KEY", "critical", "secret",
        "Private key material detected in source.",
        "Never embed private keys; load from a secure secret store at runtime."),
    "PY-SEED-PHRASE": _Rule("PY-SEED-PHRASE", "critical", "secret",
        "Likely BIP39 seed phrase / mnemonic detected.",
        "Never embed seed phrases; load from a secure secret store."),
    "PY-DYNAMIC-IMPORT": _Rule("PY-DYNAMIC-IMPORT", "medium", "dynamic_import",
        "Dynamic import (__import__/importlib) detected.",
        "Import modules statically where possible; validate any dynamic module name against an allowlist."),
    "PY-OBFUSCATION": _Rule("PY-OBFUSCATION", "high", "obfuscation",
        "Encoded/obfuscated payload detected.",
        "Do not decode-and-execute payloads; keep logic in plain source."),
    "PY-FS-WRITE": _Rule("PY-FS-WRITE", "medium", "filesystem",
        "Filesystem write detected.",
        "Restrict writes to a sandboxed path and validate the target."),
    "PY-FS-DESTRUCTIVE": _Rule("PY-FS-DESTRUCTIVE", "high", "filesystem",
        "Destructive filesystem operation (rmtree/remove/unlink) detected.",
        "Guard destructive operations behind explicit, validated paths."),
    "PY-NETWORK": _Rule("PY-NETWORK", "medium", "network",
        "Outbound network request detected.",
        "Validate destinations against an allowlist; avoid exfiltration channels."),
    "PY-TEMPFILE": _Rule("PY-TEMPFILE", "medium", "tempfile",
        "Insecure temporary-file handling detected.",
        "Use tempfile.NamedTemporaryFile/mkstemp instead of mktemp or hardcoded /tmp paths."),
    "PY-SENSITIVE-MODULE": _Rule("PY-SENSITIVE-MODULE", "medium", "sensitive_module",
        "Security-sensitive module import detected.",
        "Confirm this low-level module is required; prefer higher-level safe APIs."),
    "PY-SCANNER-BYPASS": _Rule("PY-SCANNER-BYPASS", "high", "scanner_bypass",
        "Attempt to disable/bypass a scanner or tamper with builtins detected.",
        "Remove scanner-suppression directives and builtin tampering."),
    "PY-DYNAMIC-ATTRIBUTE": _Rule("PY-DYNAMIC-ATTRIBUTE", "high", "dynamic_attribute",
        "A callable attribute name is resolved dynamically and cannot be proven safe.",
        "Replace dynamic getattr()/attribute dispatch with an explicit allowlisted mapping."),
    "PY-PARSER-ABUSE": _Rule("PY-PARSER-ABUSE", "high", "parser_abuse",
        "Excessive nesting / parser-stress input detected.",
        "Simplify deeply nested structures; reject machine-generated abuse input."),
}


def _mk(rule_id: str, source: str, node: ast.AST | None,
        confidence: Confidence = "high", evidence: str | None = None,
        line: int | None = None, col: int | None = None) -> Finding:
    r = RULES[rule_id]
    if node is not None:
        line_start = getattr(node, "lineno", line or 0)
        line_end = getattr(node, "end_lineno", None) or line_start
        col_start = getattr(node, "col_offset", col or 0)
        ev = evidence if evidence is not None else _evidence(source, node)
    else:
        line_start = line or 0
        line_end = line or 0
        col_start = col or 0
        ev = (evidence or "")[:160]
    return Finding(
        rule_id=r.rule_id, severity=r.severity, category=r.category,
        line_start=line_start, line_end=line_end, column_start=col_start,
        message=r.message, evidence=ev, confidence=confidence,
        remediation=r.remediation,
    )


# --- Name resolution helpers -------------------------------------------------
def _func_name(node: ast.Call) -> str:
    """Return dotted call name, e.g. 'os.system', 'subprocess.run', 'eval'."""
    f = node.func
    parts: list[str] = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.findings: list[Finding] = []
        self._import_aliases: dict[str, str] = {}  # alias -> real module
        self._from_sinks: dict[str, str] = {}      # local name -> dotted sink (from-imports)
        self._constant_strings: dict[str, str] = {}
        self._dynamic_modules: dict[str, str] = {}
        self._callable_aliases: dict[str, str] = {}

    # functions that are dangerous even when imported bare via `from x import y`
    _FROM_SINKS: ClassVar[set[str]] = {
        "os.system", "os.popen", "subprocess.run", "subprocess.call",
        "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
        "subprocess.getoutput", "subprocess.getstatusoutput",
        "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
        "yaml.load", "shutil.rmtree",
    }

    def add(self, rule_id, node, confidence="high", evidence=None):
        self.findings.append(_mk(rule_id, self.source, node, confidence, evidence))

    # track `import x as y` / `from a import b` for alias-aware module checks
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self._import_aliases[a.asname or a.name] = a.name
            self._check_module(a.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._check_module(node.module, node)
            for a in node.names:
                dotted = f"{node.module}.{a.name}"
                if dotted in self._FROM_SINKS:
                    self._from_sinks[a.asname or a.name] = dotted
        self.generic_visit(node)

    _SENSITIVE_MODULES: ClassVar[set[str]] = {
        "ctypes",
        "socket",
        "pty",
        "telnetlib",
        "marshal",
        "multiprocessing",
        "resource",
        "fcntl",
        "mmap",
    }

    def _check_module(self, module: str, node: ast.AST):
        top = module.split(".")[0]
        if top in self._SENSITIVE_MODULES:
            self.add("PY-SENSITIVE-MODULE", node, "medium", evidence=f"import {module}")

    def _resolve_string(self, node: ast.AST) -> str | None:
        """Resolve only side-effect-free string literals, names, and addition."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self._constant_strings.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_string(node.left)
            right = self._resolve_string(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def _resolve_getattr(self, node: ast.Call) -> str | None:
        name = _func_name(node)
        if name not in ("getattr", "builtins.getattr") or len(node.args) < 2:
            return None
        attr = self._resolve_string(node.args[1])
        if attr is None:
            return None
        target = node.args[0]
        if isinstance(target, ast.Name):
            if target.id in ("__builtins__", "builtins"):
                return attr
            module = (
                self._dynamic_modules.get(target.id)
                or self._import_aliases.get(target.id)
                or target.id
            )
            return f"{module}.{attr}"
        return attr

    def _resolved_func_name(self, node: ast.Call) -> str:
        """Resolve direct calls plus bounded static indirection patterns."""
        f = node.func
        if isinstance(f, ast.Name) and f.id in self._callable_aliases:
            return self._callable_aliases[f.id]
        if isinstance(f, ast.Call):
            resolved = self._resolve_getattr(f)
            if resolved:
                return resolved
        if isinstance(f, ast.Subscript) and isinstance(f.value, ast.Call):
            namespace = _func_name(f.value)
            if namespace in ("globals", "locals"):
                key = self._resolve_string(f.slice)
                if key:
                    return key

        name = _func_name(node)
        head, dot, tail = name.partition(".")
        if dot and head in self._dynamic_modules:
            return self._dynamic_modules[head] + "." + tail
        return name

    def visit_Assign(self, node: ast.Assign):
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        value = self._resolve_string(node.value)
        for name in names:
            if value is not None:
                self._constant_strings[name] = value
            else:
                self._constant_strings.pop(name, None)

        if isinstance(node.value, ast.Call):
            called = _func_name(node.value)
            if called in ("__import__", "importlib.import_module"):
                module = (
                    self._resolve_string(node.value.args[0])
                    if node.value.args else None
                )
                if module:
                    for name in names:
                        self._dynamic_modules[name] = module
            callable_name = self._resolve_getattr(node.value)
            if callable_name:
                for name in names:
                    self._callable_aliases[name] = callable_name
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.target, ast.Name) and node.value is not None:
            value = self._resolve_string(node.value)
            if value is not None:
                self._constant_strings[node.target.id] = value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._resolved_func_name(node)
        # resolve bare from-imported sinks: `from os import system; system(x)`
        if isinstance(node.func, ast.Name) and node.func.id in self._from_sinks:
            name = self._from_sinks[node.func.id]
        # resolve module aliases: `import os as o; o.system(x)` -> os.system
        head, dot, tail = name.partition(".")
        if dot and head in self._import_aliases:
            name = self._import_aliases[head] + "." + tail
        base = name.split(".")[-1]
        via_builtins = name.startswith(("__builtins__.", "builtins."))

        # eval(...) or builtins.eval(...) — the dotted-via-object form is caught too
        if name == "eval" or (base == "eval" and via_builtins):
            self.add("PY-DANGEROUS-EVAL", node)
        if name == "exec" or (base == "exec" and via_builtins):
            self.add("PY-DANGEROUS-EXEC", node)

        if name == "compile":
            # compile(..., mode) where mode is 'exec'/'eval' → dangerous
            mode = None
            if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                mode = node.args[2].value
            if mode in ("exec", "eval", "single") or mode is None:
                self.add("PY-DANGEROUS-COMPILE", node, "medium")

        if name == "os.system":
            self.add("PY-OS-SYSTEM", node)
        if name == "os.popen":
            self.add("PY-SHELL-EXEC", node)

        if name.startswith("subprocess.") and base in ("run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"):
            self.add("PY-SUBPROCESS", node, "medium")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add("PY-SHELL-EXEC", node)

        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads",
                    "marshal.load", "shelve.open", "dill.loads"):
            self.add("PY-UNSAFE-DESERIALIZE", node)

        if name in ("yaml.load",):
            safe = any(
                (kw.arg == "Loader" and isinstance(kw.value, ast.Attribute)
                 and kw.value.attr in ("SafeLoader", "CSafeLoader"))
                for kw in node.keywords
            )
            if not safe:
                self.add("PY-UNSAFE-YAML", node)

        if name == "__import__" or name in ("importlib.import_module", "importlib.__import__"):
            self.add("PY-DYNAMIC-IMPORT", node, "medium")

        if name in ("base64.b64decode", "base64.b64encode", "base64.b85decode",
                    "codecs.decode", "bytes.fromhex", "binascii.unhexlify", "binascii.a2b_base64"):
            self.add("PY-OBFUSCATION", node, "medium")

        if name in ("shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "pathlib.Path.unlink"):
            self.add("PY-FS-DESTRUCTIVE", node, "medium")

        if name in ("requests.get", "requests.post", "requests.put", "requests.delete",
                    "requests.request", "urllib.request.urlopen", "urlopen",
                    "httpx.get", "httpx.post", "socket.socket", "socket.create_connection"):
            self.add("PY-NETWORK", node, "medium")

        if name in ("tempfile.mktemp",):
            self.add("PY-TEMPFILE", node, "high")

        # getattr(x, 'exec'/'eval'/'system') — indirection to a dangerous attr
        if base == "getattr" and len(node.args) >= 2:
            attr = self._resolve_string(node.args[1])
            if attr == "exec":
                self.add("PY-DANGEROUS-EXEC", node, "medium")
            elif attr == "eval":
                self.add("PY-DANGEROUS-EVAL", node, "medium")
            elif attr in ("system", "popen"):
                self.add("PY-OS-SYSTEM", node, "medium")
            elif attr is None:
                self.add("PY-DYNAMIC-ATTRIBUTE", node, "medium")

        # setattr(__builtins__, ...) / builtins tampering
        if base == "setattr" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Name) and first.id in ("__builtins__", "builtins"):
                self.add("PY-SCANNER-BYPASS", node)

        self.generic_visit(node)


def _scan_open_writes(source: str, tree: ast.AST, findings: list[Finding]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _func_name(node) in ("open", "io.open"):
            mode = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if isinstance(mode, str) and any(c in mode for c in ("w", "a", "x", "+")):
                findings.append(_mk("PY-FS-WRITE", source, node, "medium"))


# --- Line/regex based detectors (also run when AST parse fails) --------------
_SECRET_PATTERNS: list[tuple[str, re.Pattern, Confidence]] = [
    ("PY-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "high"),
    ("PY-PRIVATE-KEY", re.compile(r"\b0x[a-fA-F0-9]{64}\b"), "medium"),
    ("PY-HARDCODED-SECRET", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("PY-HARDCODED-SECRET", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "high"),
    ("PY-HARDCODED-SECRET", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "medium"),
    ("PY-HARDCODED-SECRET", re.compile(
        r"(?i)['\"]?(api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "medium"),
]

_BIP39_LINE = re.compile(r"(?i)['\"]((?:[a-z]+\s+){11,23}[a-z]+)['\"]")
_LONG_B64 = re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]")
_SUPPRESS = re.compile(r"#\s*(nosec|noqa|type:\s*ignore|preflight:\s*ignore|skipcq)")


def redact_sensitive_text(text: str) -> str:
    """Remove every recognized credential/mnemonic span from arbitrary evidence."""
    redacted = text
    for _, pattern, _ in _SECRET_PATTERNS:
        redacted = pattern.sub("<redacted secret-like literal>", redacted)
    redacted = _BIP39_LINE.sub('"<redacted mnemonic-like string>"', redacted)
    return redacted


def _line_scans(source: str, findings: list[Finding]) -> None:
    seen: set[tuple[str, int]] = set()
    for i, line in enumerate(source.splitlines(), start=1):
        for rule_id, pat, conf in _SECRET_PATTERNS:
            m = pat.search(line)
            if m and (rule_id, i) not in seen:
                seen.add((rule_id, i))
                findings.append(_mk(rule_id, source, None, conf,
                                    evidence="<redacted secret-like literal>",
                                    line=i, col=m.start()))
        m = _BIP39_LINE.search(line)
        if m and len(m.group(1).split()) >= 12:
            findings.append(_mk("PY-SEED-PHRASE", source, None, "medium",
                                evidence="<redacted mnemonic-like string>", line=i, col=m.start()))
        m = _LONG_B64.search(line)
        if m:
            findings.append(_mk("PY-OBFUSCATION", source, None, "high",
                                evidence="<long base64-like literal>", line=i, col=m.start()))
        m = _SUPPRESS.search(line)
        if m:
            findings.append(_mk("PY-SCANNER-BYPASS", source, None, "medium",
                                evidence=m.group(0)[:160], line=i, col=m.start()))


def _ast_depth(tree: ast.AST) -> int:
    """Max node depth, computed iteratively (never recurses)."""
    stack = [(tree, 1)]
    peak = 0
    while stack:
        node, d = stack.pop()
        peak = max(peak, d)
        if d > MAX_AST_DEPTH:      # early exit; no need to measure exact depth
            return d
        for child in ast.iter_child_nodes(node):
            stack.append((child, d + 1))
    return peak


def _max_bracket_nesting(source: str) -> int:
    depth = 0
    peak = 0
    for ch in source:
        if ch in "([{":
            depth += 1
            peak = max(peak, depth)
        elif ch in ")]}":
            depth = max(0, depth - 1)
    return peak


@dataclass
class ScanResult:
    findings: list[Finding]
    source_sha256: str
    scan_duration_ms: int
    syntax_ok: bool


def scan(source: str) -> ScanResult:
    """Run all deterministic detectors. Never executes `source`."""
    t0 = time.perf_counter()
    findings: list[Finding] = []
    sha = sha256_hex(source)

    # parser-abuse guard BEFORE ast.parse (deep nesting can blow the C stack)
    nesting = _max_bracket_nesting(source)
    line_count = source.count("\n") + 1
    abuse = nesting > MAX_BRACKET_NESTING or line_count > MAX_LINE_COUNT
    if abuse:
        findings.append(_mk("PY-PARSER-ABUSE", source, None, "high",
                            evidence=f"bracket_nesting={nesting}, lines={line_count}", line=1, col=0))

    syntax_ok = False
    tree = None
    if not abuse:
        try:
            tree = ast.parse(source)
            syntax_ok = True
        except SyntaxError as e:
            findings.append(_mk("PY-SYNTAX-ERROR", source, None, "high",
                                evidence=str(e.msg)[:160], line=e.lineno or 1, col=(e.offset or 1) - 1))
        except (ValueError, RecursionError, MemoryError):
            findings.append(_mk("PY-PARSER-ABUSE", source, None, "high",
                                evidence="parser rejected input", line=1, col=0))

    if tree is not None:
        if _ast_depth(tree) > MAX_AST_DEPTH:
            findings.append(_mk("PY-PARSER-ABUSE", source, None, "high",
                                evidence=f"ast_depth>{MAX_AST_DEPTH}", line=1, col=0))
        else:
            v = _Visitor(source)
            v.visit(tree)
            findings.extend(v.findings)
            _scan_open_writes(source, tree, findings)

    # line/regex scans always run (catch secrets even in unparseable code)
    _line_scans(source, findings)

    # de-duplicate identical (rule_id, line, col)
    unique: dict[tuple, Finding] = {}
    for f in findings:
        f.evidence = redact_sensitive_text(f.evidence)
        unique.setdefault((f.rule_id, f.line_start, f.column_start), f)
    result = sorted(unique.values(), key=lambda f: (f.line_start, f.column_start, f.rule_id))

    dur = int((time.perf_counter() - t0) * 1000)
    return ScanResult(findings=result, source_sha256=sha, scan_duration_ms=dur, syntax_ok=syntax_ok)
