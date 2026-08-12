"""Deterministic JavaScript/TypeScript code scanner.

Uses tree-sitter for AST parsing. Source is NEVER executed.
Mirrors the architecture of engine.py for Python.

tree-sitter grammars:
  - tree-sitter-javascript (JS, JSX)
  - tree-sitter-typescript (TS, TSX)

Language is auto-detected from source content (type annotations, TS syntax)
or can be explicitly specified.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import ClassVar

from tree_sitter import Language, Node, Parser

from .schema import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# tree-sitter language setup (lazy-loaded)
# ---------------------------------------------------------------------------
_JS_LANGUAGE: Language | None = None
_TS_LANGUAGE: Language | None = None
_TSX_LANGUAGE: Language | None = None


def _get_js_language() -> Language:
    global _JS_LANGUAGE
    if _JS_LANGUAGE is None:
        import tree_sitter_javascript as tsjs
        _JS_LANGUAGE = Language(tsjs.language())
    return _JS_LANGUAGE


def _get_ts_language() -> Language:
    global _TS_LANGUAGE
    if _TS_LANGUAGE is None:
        import tree_sitter_typescript as tsts
        _TS_LANGUAGE = Language(tsts.language_typescript())
    return _TS_LANGUAGE


def _get_tsx_language() -> Language:
    global _TSX_LANGUAGE
    if _TSX_LANGUAGE is None:
        import tree_sitter_typescript as tsts
        _TSX_LANGUAGE = Language(tsts.language_tsx())
    return _TSX_LANGUAGE


# ---------------------------------------------------------------------------
# Parser-abuse guards (mirrors engine.py)
# ---------------------------------------------------------------------------
MAX_BRACKET_NESTING = 120
MAX_AST_DEPTH = 200
MAX_LINE_COUNT = 50_000


def sha256_hex(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
_TS_PATTERNS: list[re.Pattern] = [
    re.compile(r":\s*(string|number|boolean|void|any|never|unknown|bigint|symbol)\b"),
    re.compile(r"interface\s+\w+\s*\{"),
    re.compile(r"type\s+\w+\s*="),
    re.compile(r"<[A-Z]\w*(?:<[^>]+>)?>"),  # generic type params
    re.compile(r"\w+\s*:\s*\w+\s*=>\s*\w+"),  # type annotations in arrow functions
    re.compile(r"as\s+(string|number|boolean|const)\b"),  # `as` type assertions
    re.compile(r"enum\s+\w+\s*\{"),
    re.compile(r"namespace\s+\w+\s*\{"),
    re.compile(r"declare\s+(class|function|module|namespace|var|let|const)\b"),
    re.compile(r"implements\s+\w+"),
    re.compile(r"readonly\s+\w+"),
    re.compile(r"abstract\s+class\b"),
]

# TSX detection: JSX syntax patterns
_TSX_PATTERNS: list[re.Pattern] = [
    re.compile(r"<\w+\s+[^>]*/>"),   # self-closing JSX tag
    re.compile(r"<[A-Z]\w*[^>]*>"),  # capitalized component tag
    re.compile(r"<\/\w+>"),          # closing JSX tag
    re.compile(r"className="),       # JSX className attribute
    re.compile(r"React\.(createElement|Fragment|Component)"),
]


def detect_language(source: str) -> str:
    """Heuristic language detection. Returns 'javascript', 'typescript', or 'tsx'."""
    # Check for TSX first (it's a superset of TS)
    for pat in _TSX_PATTERNS:
        if pat.search(source):
            # If it has JSX AND type annotations, it's TSX
            for ts_pat in _TS_PATTERNS:
                if ts_pat.search(source):
                    return "tsx"
            # JSX without type annotations could be JSX or TSX; default to TSX
            return "tsx"
    for pat in _TS_PATTERNS:
        if pat.search(source):
            return "typescript"
    return "javascript"


# ---------------------------------------------------------------------------
# Rule catalog (stable IDs; ruleset_version bumps if these change)
# ---------------------------------------------------------------------------
@dataclass
class _Rule:
    rule_id: str
    severity: Severity
    category: str
    message: str
    remediation: str


RULES: dict[str, _Rule] = {
    "JS-SYNTAX-ERROR": _Rule("JS-SYNTAX-ERROR", "high", "syntax",
        "Source is not valid JavaScript/TypeScript; deterministic AST analysis is incomplete.",
        "Fix the syntax error and resubmit so the code can be fully analyzed."),
    "JS-DANGEROUS-EVAL": _Rule("JS-DANGEROUS-EVAL", "critical", "dynamic_execution",
        "Dynamic eval() invocation detected.",
        "Replace eval() with an explicit allowlisted operation or JSON.parse for data."),
    "JS-DANGEROUS-FUNCTION": _Rule("JS-DANGEROUS-FUNCTION", "critical", "dynamic_execution",
        "new Function() constructor detected — equivalent to eval().",
        "Never construct functions from runtime strings; use static functions."),
    "JS-DANGEROUS-EXEC": _Rule("JS-DANGEROUS-EXEC", "critical", "shell_execution",
        "Shell command execution via child_process.exec() detected.",
        "Use child_process.execFile() with an explicit argument list, validating all inputs."),
    "JS-DANGEROUS-SPAWN": _Rule("JS-DANGEROUS-SPAWN", "critical", "shell_execution",
        "Process spawning via child_process.spawn() detected.",
        "Ensure arguments are an explicit list, shell option is false, and inputs are validated."),
    "JS-DANGEROUS-EXEC-SYNC": _Rule("JS-DANGEROUS-EXEC-SYNC", "critical", "shell_execution",
        "Synchronous shell execution via execSync()/spawnSync() detected.",
        "Use async execFile() with validated arguments instead."),
    "JS-UNSAFE-DESERIALIZE": _Rule("JS-UNSAFE-DESERIALIZE", "high", "deserialization",
        "Potentially unsafe deserialization pattern detected.",
        "Use JSON.parse with schema validation; never eval() or new Function() on untrusted data."),
    "JS-HARDCODED-SECRET": _Rule("JS-HARDCODED-SECRET", "high", "secret",
        "Likely hardcoded credential/secret detected.",
        "Move secrets to environment variables (process.env) or a secret manager."),
    "JS-PRIVATE-KEY": _Rule("JS-PRIVATE-KEY", "critical", "secret",
        "Private key material detected in source.",
        "Never embed private keys; load from a secure secret store at runtime."),
    "JS-SEED-PHRASE": _Rule("JS-SEED-PHRASE", "critical", "secret",
        "Likely BIP39 seed phrase / mnemonic detected.",
        "Never embed seed phrases; load from a secure secret store."),
    "JS-DYNAMIC-IMPORT": _Rule("JS-DYNAMIC-IMPORT", "medium", "dynamic_import",
        "Dynamic import() with a non-literal argument detected.",
        "Import modules statically where possible; validate dynamic module names against an allowlist."),
    "JS-DYNAMIC-REQUIRE": _Rule("JS-DYNAMIC-REQUIRE", "medium", "dynamic_import",
        "require() with a non-literal argument detected.",
        "Use static import statements; validate any dynamic require against an allowlist."),
    "JS-OBFUSCATION": _Rule("JS-OBFUSCATION", "high", "obfuscation",
        "Encoded/obfuscated payload detected (atob, btoa, Buffer.from base64).",
        "Do not decode-and-execute payloads; keep logic in plain source."),
    "JS-FS-WRITE": _Rule("JS-FS-WRITE", "medium", "filesystem",
        "Filesystem write detected.",
        "Restrict writes to a sandboxed path and validate the target."),
    "JS-FS-DESTRUCTIVE": _Rule("JS-FS-DESTRUCTIVE", "high", "filesystem",
        "Destructive filesystem operation (rm/rmSync/unlink/unlinkSync) detected.",
        "Guard destructive operations behind explicit, validated paths."),
    "JS-NETWORK": _Rule("JS-NETWORK", "medium", "network",
        "Outbound network request detected.",
        "Validate destinations against an allowlist; avoid exfiltration channels."),
    "JS-SENSITIVE-MODULE": _Rule("JS-SENSITIVE-MODULE", "medium", "sensitive_module",
        "Security-sensitive module import detected.",
        "Confirm this module is required; prefer higher-level safe APIs."),
    "JS-SCANNER-BYPASS": _Rule("JS-SCANNER-BYPASS", "high", "scanner_bypass",
        "Attempt to disable/bypass a scanner or linter detected.",
        "Remove scanner-suppression directives."),
    "JS-DANGEROUS-SETTIMEOUT": _Rule("JS-DANGEROUS-SETTIMEOUT", "high", "dynamic_execution",
        "setTimeout/setInterval with a string argument detected — equivalent to eval().",
        "Pass a function reference, not a string, to setTimeout/setInterval."),
    "JS-PROTOTYPE-POLLUTION": _Rule("JS-PROTOTYPE-POLLUTION", "high", "prototype",
        "Potential prototype pollution via __proto__ or constructor.prototype assignment.",
        "Use Object.create(null) for user-controlled keys; freeze Object.prototype."),
    "JS-PARSER-ABUSE": _Rule("JS-PARSER-ABUSE", "high", "parser_abuse",
        "Excessive nesting / parser-stress input detected.",
        "Simplify deeply nested structures; reject machine-generated abuse input."),
    "JS-VM-EXECUTION": _Rule("JS-VM-EXECUTION", "critical", "dynamic_execution",
        "vm.runInNewContext() or similar VM execution detected.",
        "Avoid running untrusted code in VM contexts; use sandboxed Web Workers if needed."),
    "JS-DANGEROUS-REGEX": _Rule("JS-DANGEROUS-REGEX", "medium", "regex",
        "Regular expression constructed from a variable — potential ReDoS vector.",
        "Use static regex literals where possible; validate and limit dynamic patterns."),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mk(rule_id: str, source: str, node: Node | None,
        confidence: Confidence = "high", evidence: str | None = None,
        line: int | None = None, col: int | None = None) -> Finding:
    r = RULES[rule_id]
    if node is not None:
        line_start = node.start_point[0] + 1
        line_end = node.end_point[0] + 1
        col_start = node.start_point[1]
        ev = evidence if evidence is not None else (node.text.decode("utf-8", errors="replace")[:160])
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


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _child_text(node: Node, index: int) -> str | None:
    """Get the text of the nth named child, or None."""
    named = [c for c in node.children if c.is_named]
    if index < len(named):
        return _node_text(named[index])
    return None


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------
class _JSVisitor:
    """Walks the tree-sitter CST and emits Findings.

    Tracks:
      - require() aliases: const x = require('y')
      - import aliases: import * as x from 'y'
      - string constant assignments: const KEY = 'value'
      - callable aliases: const fn = child_process.exec
    """

    # Functions that are dangerous even when destructured/aliased
    _DANGEROUS_CALLS: ClassVar[set[str]] = {
        "eval",
        "exec",
        "Function",
        "setTimeout",
        "setInterval",
    }

    # Member expression sinks: obj.method() patterns
    _MEMBER_SINKS: ClassVar[dict[str, tuple[str, str]]] = {
        # (object, method) -> (rule_id, confidence)
        ("child_process", "exec"): ("JS-DANGEROUS-EXEC", "high"),
        ("child_process", "execSync"): ("JS-DANGEROUS-EXEC-SYNC", "high"),
        ("child_process", "spawn"): ("JS-DANGEROUS-SPAWN", "high"),
        ("child_process", "spawnSync"): ("JS-DANGEROUS-EXEC-SYNC", "high"),
        ("child_process", "fork"): ("JS-DANGEROUS-SPAWN", "medium"),
        ("fs", "writeFile"): ("JS-FS-WRITE", "medium"),
        ("fs", "writeFileSync"): ("JS-FS-WRITE", "medium"),
        ("fs", "createWriteStream"): ("JS-FS-WRITE", "medium"),
        ("fs", "appendFile"): ("JS-FS-WRITE", "medium"),
        ("fs", "appendFileSync"): ("JS-FS-WRITE", "medium"),
        ("fs", "rm"): ("JS-FS-DESTRUCTIVE", "high"),
        ("fs", "rmSync"): ("JS-FS-DESTRUCTIVE", "high"),
        ("fs", "unlink"): ("JS-FS-DESTRUCTIVE", "high"),
        ("fs", "unlinkSync"): ("JS-FS-DESTRUCTIVE", "high"),
        ("fs", "rmdir"): ("JS-FS-DESTRUCTIVE", "medium"),
        ("fs", "rmdirSync"): ("JS-FS-DESTRUCTIVE", "medium"),
        ("vm", "runInNewContext"): ("JS-VM-EXECUTION", "high"),
        ("vm", "runInThisContext"): ("JS-VM-EXECUTION", "high"),
        ("vm", "runInContext"): ("JS-VM-EXECUTION", "high"),
        ("vm", "compileFunction"): ("JS-VM-EXECUTION", "high"),
        ("vm", "Script"): ("JS-VM-EXECUTION", "high"),
    }

    # Network-related member expression sinks
    _NETWORK_SINKS: ClassVar[set[tuple[str, str]]] = {
        ("http", "request"),
        ("http", "get"),
        ("https", "request"),
        ("https", "get"),
        ("net", "connect"),
        ("net", "createConnection"),
        ("dgram", "createSocket"),
        ("axios", "get"),
        ("axios", "post"),
        ("axios", "put"),
        ("axios", "delete"),
        ("axios", "request"),
        ("got", "get"),
        ("got", "post"),
        ("node-fetch", "default"),
    }

    # Sensitive modules to flag on import/require
    _SENSITIVE_MODULES: ClassVar[set[str]] = {
        "child_process",
        "vm",
        "worker_threads",
        "cluster",
        "process",
        "net",
        "dgram",
        "tls",
        "repl",
        "inspector",
    }

    # Obfuscation-related calls
    _OBFUSCATION_CALLS: ClassVar[set[str]] = {
        "atob",
        "btoa",
    }

    # Obfuscation member calls
    _OBFUSCATION_MEMBERS: ClassVar[set[tuple[str, str]]] = {
        ("Buffer", "from"),
    }

    def __init__(self, source: str):
        self.source = source
        self.findings: list[Finding] = []
        self._require_aliases: dict[str, str] = {}   # local_name -> module_name
        self._import_aliases: dict[str, str] = {}     # local_name -> module_name
        self._constant_strings: dict[str, str] = {}   # var_name -> string_value
        self._callable_aliases: dict[str, str] = {}   # var_name -> resolved_callable

    def add(self, rule_id: str, node: Node, confidence: str = "high",
            evidence: str | None = None):
        self.findings.append(_mk(rule_id, self.source, node, confidence, evidence))

    # ------------------------------------------------------------------
    # Name resolution
    # ------------------------------------------------------------------
    def _resolve_member_call(self, node: Node) -> tuple[str, str] | None:
        """Resolve obj.method() to (object_name, method_name)."""
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return None
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        obj_name = _node_text(obj)
        prop_name = _node_text(prop)
        # Resolve aliases
        obj_name = self._require_aliases.get(obj_name, obj_name)
        obj_name = self._import_aliases.get(obj_name, obj_name)
        return (obj_name, prop_name)

    def _resolve_call_name(self, node: Node) -> str:
        """Get the resolved name of a call expression."""
        func = node.child_by_field_name("function")
        if func is None:
            return ""
        if func.type == "identifier":
            name = _node_text(func)
            # Resolve aliases
            name = self._callable_aliases.get(name, name)
            name = self._require_aliases.get(name, name)
            name = self._import_aliases.get(name, name)
            return name
        if func.type == "member_expression":
            resolved = self._resolve_member_call(node)
            if resolved:
                return f"{resolved[0]}.{resolved[1]}"
            return _node_text(func)
        return _node_text(func)

    def _is_string_arg(self, node: Node, arg_index: int = 0) -> bool:
        """Check if the nth argument is a string literal."""
        args = node.child_by_field_name("arguments")
        if args is None:
            return False
        named = [c for c in args.children if c.is_named]
        if arg_index >= len(named):
            return False
        return named[arg_index].type in ("string", "template_string")

    def _get_string_arg(self, node: Node, arg_index: int = 0) -> str | None:
        """Get the string value of the nth argument if it's a literal."""
        args = node.child_by_field_name("arguments")
        if args is None:
            return None
        named = [c for c in args.children if c.is_named]
        if arg_index >= len(named):
            return None
        arg = named[arg_index]
        if arg.type == "string":
            # Extract string content (strip quotes)
            text = _node_text(arg)
            if len(text) >= 2 and text[0] in ('"', "'", "`") and text[-1] == text[0]:
                return text[1:-1]
            return text
        return None

    # ------------------------------------------------------------------
    # Node visitors
    # ------------------------------------------------------------------
    def visit(self, node: Node):
        """Recursively walk the tree."""
        self._visit_node(node)
        for child in node.children:
            self.visit(child)

    def _visit_node(self, node: Node):
        """Dispatch to type-specific handlers."""
        handlers = {
            "call_expression": self._visit_call,
            "new_expression": self._visit_new,
            "variable_declaration": self._visit_variable_declaration,
            "lexical_declaration": self._visit_variable_declaration,
            "import_statement": self._visit_import_statement,
            "assignment_expression": self._visit_assignment,
            "subscript_expression": self._visit_subscript,
            "comment": self._visit_comment,
        }
        handler = handlers.get(node.type)
        if handler:
            handler(node)

    def _visit_call(self, node: Node):
        name = self._resolve_call_name(node)

        # Handle import() expressions — the function is the 'import' keyword
        func = node.child_by_field_name("function")
        if func is not None and func.type == "import":
            # import('module') is fine; import(variable) is not
            if not self._is_string_arg(node, 0):
                self.add("JS-DYNAMIC-IMPORT", node, "medium")
            return

        # Direct dangerous calls
        if name == "eval":
            self.add("JS-DANGEROUS-EVAL", node)
        elif name == "Function":
            self.add("JS-DANGEROUS-FUNCTION", node)
        elif name in ("setTimeout", "setInterval"):
            # Dangerous only when first arg is a string
            if self._is_string_arg(node, 0):
                self.add("JS-DANGEROUS-SETTIMEOUT", node)
        elif name == "require":
            # Dynamic require if arg is not a string literal
            if not self._is_string_arg(node, 0):
                self.add("JS-DYNAMIC-REQUIRE", node, "medium")
        elif name in self._OBFUSCATION_CALLS:
            self.add("JS-OBFUSCATION", node, "medium")

        # Member expression sinks
        member = self._resolve_member_call(node)
        if member:
            if member in self._MEMBER_SINKS:
                rule_id, conf = self._MEMBER_SINKS[member]
                self.add(rule_id, node, conf)
            elif member in self._NETWORK_SINKS:
                self.add("JS-NETWORK", node, "medium")
            elif member in self._OBFUSCATION_MEMBERS:
                # Buffer.from(x, 'base64') or Buffer.from(x, 'hex')
                args = node.child_by_field_name("arguments")
                if args:
                    named = [c for c in args.children if c.is_named]
                    if len(named) >= 2:
                        encoding = _node_text(named[1]).strip("'\"")
                        if encoding in ("base64", "hex", "utf-8"):
                            self.add("JS-OBFUSCATION", node, "medium")

        # fetch() — network
        if name == "fetch":
            self.add("JS-NETWORK", node, "medium")

        # RegExp with variable arg
        if name == "RegExp":
            if not self._is_string_arg(node, 0):
                self.add("JS-DANGEROUS-REGEX", node, "medium")

    def _visit_new(self, node: Node):
        """Handle new X() expressions."""
        constructor = node.child_by_field_name("constructor")
        if constructor is None:
            return
        name = _node_text(constructor)
        if name == "Function":
            self.add("JS-DANGEROUS-FUNCTION", node)
        elif name == "RegExp":
            # new RegExp(variable) — dynamic regex
            args = node.child_by_field_name("arguments")
            if args:
                named = [c for c in args.children if c.is_named]
                if named and named[0].type not in ("string", "template_string"):
                    self.add("JS-DANGEROUS-REGEX", node, "medium")

    def _visit_variable_declaration(self, node: Node):
        """Track variable assignments for alias resolution."""
        # Find the declarator
        for child in node.children:
            if child.type in ("variable_declarator",):
                self._process_declarator(child)

    def _process_declarator(self, node: Node):
        """Process a single variable declarator: name = value."""
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        name = _node_text(name_node)

        # String constant: const KEY = 'value'
        if value_node.type in ("string", "template_string"):
            text = _node_text(value_node)
            if len(text) >= 2 and text[0] in ('"', "'", "`") and text[-1] == text[0]:
                self._constant_strings[name] = text[1:-1]
            else:
                self._constant_strings[name] = text
            return

        # require() alias: const fs = require('fs')
        if value_node.type == "call_expression":
            call_name = self._resolve_call_name(value_node)
            if call_name == "require":
                module = self._get_string_arg(value_node, 0)
                if module:
                    self._require_aliases[name] = module
                    # Flag sensitive modules
                    top = module.split("/")[0]
                    if top.startswith("@"):
                        parts = module.split("/")
                        top = parts[1] if len(parts) > 1 else top
                    if top in self._SENSITIVE_MODULES:
                        self.add("JS-SENSITIVE-MODULE", value_node, "medium",
                                 evidence=f"require('{module}')")
            else:
                # Callable alias: const exec = child_process.exec
                self._callable_aliases[name] = call_name

        # Destructured require: const { exec } = require('child_process')
        if name_node.type == "object_pattern" and value_node.type == "call_expression":
            call_name = self._resolve_call_name(value_node)
            if call_name == "require":
                module = self._get_string_arg(value_node, 0)
                if module:
                    for child in name_node.children:
                        if child.type in ("shorthand_property_identifier",):
                            local = _node_text(child)
                            self._require_aliases[local] = module

    def _visit_import_statement(self, node: Node):
        """Track ES import statements."""
        source_node = node.child_by_field_name("source")
        if source_node is None:
            return
        module = _node_text(source_node).strip("'\"")

        # Flag sensitive modules
        top = module.split("/")[0]
        if top.startswith("@"):
            parts = module.split("/")
            top = parts[1] if len(parts) > 1 else top
        if top in self._SENSITIVE_MODULES:
            self.add("JS-SENSITIVE-MODULE", node, "medium",
                     evidence=f"import '{module}'")

        # Track named imports for alias resolution
        for child in node.children:
            if child.type == "import_clause":
                for sub in child.children:
                    if sub.type == "named_imports":
                        for spec in sub.children:
                            if spec.type == "import_specifier":
                                name_node = spec.child_by_field_name("name")
                                alias_node = spec.child_by_field_name("alias")
                                if name_node:
                                    local = _node_text(alias_node) if alias_node else _node_text(name_node)
                                    self._import_aliases[local] = module
                    elif sub.type == "namespace_import":
                        name_node = sub.child_by_field_name("name")
                        if name_node:
                            self._import_aliases[_node_text(name_node)] = module

    def _visit_assignment(self, node: Node):
        """Handle assignments for prototype pollution detection."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            return

        # Detect __proto__ assignment
        if left.type == "member_expression":
            prop = left.child_by_field_name("property")
            if prop and _node_text(prop) == "__proto__":
                self.add("JS-PROTOTYPE-POLLUTION", node, "medium")

        # Detect obj[var] = val where var could be __proto__
        if left.type == "subscript_expression":
            index = left.child_by_field_name("index")
            if index and index.type not in ("string", "number"):
                # Dynamic key access — potential prototype pollution
                # Only flag if the value is user-controlled (heuristic)
                pass  # Too many false positives; handled by regex instead

    def _visit_subscript(self, node: Node):
        """Handle obj[key] access for prototype pollution."""
        index = node.child_by_field_name("index")
        if index and index.type == "string":
            text = _node_text(index).strip("'\"")
            if text in ("__proto__", "constructor", "prototype"):
                self.add("JS-PROTOTYPE-POLLUTION", node, "medium")

    def _visit_comment(self, node: Node):
        """Detect scanner bypass directives in comments."""
        text = _node_text(node)
        bypass_patterns = [
            "eslint-disable", "eslint-disable-next-line",
            "nosec", "noqa", "preflight: ignore", "skipcq",
            "tslint:disable",
        ]
        for pat in bypass_patterns:
            if pat in text.lower():
                self.add("JS-SCANNER-BYPASS", node, "medium",
                         evidence=text[:160])
                return


# ---------------------------------------------------------------------------
# Regex-based line scans (shared with engine.py patterns)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, re.Pattern, Confidence]] = [
    ("JS-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "high"),
    ("JS-PRIVATE-KEY", re.compile(r"\b0x[a-fA-F0-9]{64}\b"), "medium"),
    ("JS-HARDCODED-SECRET", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("JS-HARDCODED-SECRET", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "high"),
    ("JS-HARDCODED-SECRET", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "medium"),
    ("JS-HARDCODED-SECRET", re.compile(
        r"(?i)['\"]?(api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "medium"),
    # JS-specific: process.env.SECRET = '...' (hardcoded in source)
    ("JS-HARDCODED-SECRET", re.compile(
        r"process\.env\.\w+\s*=\s*['\"][^'\"]{8,}['\"]"), "medium"),
]

_BIP39_LINE = re.compile(r"(?i)['\"]((?:[a-z]+\s+){11,23}[a-z]+)['\"]")
_LONG_B64 = re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]")
_SUPPRESS = re.compile(r"//\s*(?:eslint-disable|nosec|noqa|preflight:\s*ignore|skipcq|tslint:disable)")
_PROTO_POLLUTION = re.compile(r"\.__proto__\s*=")


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
            findings.append(_mk("JS-SEED-PHRASE", source, None, "medium",
                                evidence="<redacted mnemonic-like string>", line=i, col=m.start()))
        m = _LONG_B64.search(line)
        if m:
            findings.append(_mk("JS-OBFUSCATION", source, None, "high",
                                evidence="<long base64-like literal>", line=i, col=m.start()))
        m = _SUPPRESS.search(line)
        if m:
            findings.append(_mk("JS-SCANNER-BYPASS", source, None, "medium",
                                evidence=m.group(0)[:160], line=i, col=m.start()))
        m = _PROTO_POLLUTION.search(line)
        if m:
            findings.append(_mk("JS-PROTOTYPE-POLLUTION", source, None, "medium",
                                evidence=m.group(0)[:160], line=i, col=m.start()))


# ---------------------------------------------------------------------------
# Parser-abuse guards
# ---------------------------------------------------------------------------
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


def _ast_depth(node: Node) -> int:
    """Max node depth, computed iteratively."""
    stack = [(node, 1)]
    peak = 0
    while stack:
        n, d = stack.pop()
        peak = max(peak, d)
        if d > MAX_AST_DEPTH:
            return d
        for child in n.children:
            stack.append((child, d + 1))
    return peak


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    findings: list[Finding]
    source_sha256: str
    scan_duration_ms: int
    syntax_ok: bool
    detected_language: str


def scan(source: str, *, language: str | None = None) -> ScanResult:
    """Run all deterministic JS/TS detectors. Never executes `source`.

    Args:
        source: JavaScript or TypeScript source code.
        language: 'javascript' or 'typescript'. Auto-detected if None.

    Returns:
        ScanResult with findings, hash, timing, and syntax status.
    """
    t0 = time.perf_counter()
    findings: list[Finding] = []
    sha = sha256_hex(source)

    if language is None:
        language = detect_language(source)

    # Parser-abuse guard BEFORE parsing
    nesting = _max_bracket_nesting(source)
    line_count = source.count("\n") + 1
    abuse = nesting > MAX_BRACKET_NESTING or line_count > MAX_LINE_COUNT
    if abuse:
        findings.append(_mk("JS-PARSER-ABUSE", source, None, "high",
                            evidence=f"bracket_nesting={nesting}, lines={line_count}", line=1, col=0))

    syntax_ok = False
    tree = None

    if not abuse:
        try:
            if language == "tsx":
                tsx_lang = _get_tsx_language()
                parser = Parser(tsx_lang)
            elif language == "typescript":
                ts_lang = _get_ts_language()
                parser = Parser(ts_lang)
            else:
                js_lang = _get_js_language()
                parser = Parser(js_lang)

            tree = parser.parse(source.encode("utf-8"))
            # Check for syntax errors in the tree
            has_error = False
            for node in tree.root_node.children:
                if node.type == "ERROR" or node.has_error:
                    has_error = True
                    break
            if not has_error and not tree.root_node.has_error:
                syntax_ok = True
            else:
                # Find the error node for evidence
                error_msg = "syntax error"
                for node in tree.root_node.children:
                    if node.type == "ERROR":
                        error_msg = _node_text(node)[:160]
                        break
                findings.append(_mk("JS-SYNTAX-ERROR", source, None, "high",
                                    evidence=error_msg,
                                    line=tree.root_node.start_point[0] + 1,
                                    col=tree.root_node.start_point[1]))
        except Exception as e:
            findings.append(_mk("JS-PARSER-ABUSE", source, None, "high",
                                evidence=f"parser rejected input: {str(e)[:120]}", line=1, col=0))

    if tree is not None and syntax_ok:
        if _ast_depth(tree.root_node) > MAX_AST_DEPTH:
            findings.append(_mk("JS-PARSER-ABUSE", source, None, "high",
                                evidence=f"ast_depth>{MAX_AST_DEPTH}", line=1, col=0))
        else:
            v = _JSVisitor(source)
            v.visit(tree.root_node)
            findings.extend(v.findings)

    # Line/regex scans always run (catch secrets even in unparseable code)
    _line_scans(source, findings)

    # De-duplicate identical (rule_id, line, col)
    unique: dict[tuple, Finding] = {}
    for f in findings:
        f.evidence = redact_sensitive_text(f.evidence)
        unique.setdefault((f.rule_id, f.line_start, f.column_start), f)
    result = sorted(unique.values(), key=lambda f: (f.line_start, f.column_start, f.rule_id))

    dur = int((time.perf_counter() - t0) * 1000)
    return ScanResult(
        findings=result,
        source_sha256=sha,
        scan_duration_ms=dur,
        syntax_ok=syntax_ok,
        detected_language=language,
    )
