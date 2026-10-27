"""Regression tests for the injection / crypto / transport rule pack.

Each case asserts a specific rule fires on a realistic vulnerable snippet and
that the safe counterpart stays clean. These are the classes AI coding agents
produce most often and that a paying buyer tests first.
"""
import pytest

from src.engine import scan


def ids(source: str) -> set[str]:
    return {f.rule_id for f in scan(source).findings}


# --- SQL injection -----------------------------------------------------------
@pytest.mark.parametrize("source", [
    'import sqlite3\nc = sqlite3.connect("x")\ni = 1\nc.execute(f"SELECT * FROM t WHERE id={i}")',
    'c.execute("SELECT * FROM t WHERE id=%s" % user_id)',
    'c.execute("SELECT * FROM t WHERE id={}".format(user_id))',
    'c.execute("SELECT * FROM t WHERE id=" + user_id)',
    'q = f"SELECT * FROM t WHERE id={i}"\nc.execute(q)',
    'def f(cur, rows):\n    cur.executemany(f"INSERT INTO t VALUES ({rows})", [])',
])
def test_sql_injection_detected(source):
    assert "PY-SQL-INJECTION" in ids(source)


@pytest.mark.parametrize("source", [
    'c.execute("SELECT * FROM t WHERE id=?", (i,))',
    'c.execute("SELECT * FROM t")',
    'c.execute("SELECT * FROM t WHERE id=:id", {"id": i})',
])
def test_parameterized_sql_is_clean(source):
    assert "PY-SQL-INJECTION" not in ids(source)


# --- Weak crypto -------------------------------------------------------------
@pytest.mark.parametrize("source", [
    'import hashlib\nh = hashlib.md5(b"x")',
    'import hashlib\nh = hashlib.sha1(b"x")',
    'import hashlib\nh = hashlib.new("md5")',
])
def test_weak_crypto_detected(source):
    assert "PY-WEAK-CRYPTO" in ids(source)


def test_strong_hash_is_clean():
    assert "PY-WEAK-CRYPTO" not in ids('import hashlib\nh = hashlib.sha256(b"x")')


# --- Weak randomness ---------------------------------------------------------
def test_weak_random_for_token_detected():
    assert "PY-WEAK-RANDOM" in ids('import random\ntoken = random.random()')


def test_weak_random_for_password_detected():
    assert "PY-WEAK-RANDOM" in ids('import random\npassword = str(random.randint(0, 999999))')


def test_random_for_non_security_use_is_clean():
    assert "PY-WEAK-RANDOM" not in ids('import random\nroll = random.randint(1, 6)')


def test_secrets_module_is_clean():
    assert "PY-WEAK-RANDOM" not in ids("import secrets\ntoken = secrets.token_hex(32)")


# --- JWT ---------------------------------------------------------------------
@pytest.mark.parametrize("source", [
    'import jwt\njwt.decode(t, k, algorithms=["none"])',
    'import jwt\njwt.decode(t, k, options={"verify_signature": False})',
    'import jwt\njwt.decode(t, k, verify=False)',
])
def test_jwt_verification_disabled(source):
    assert "PY-JWT-NONE" in ids(source)


def test_jwt_with_explicit_alg_is_clean():
    assert "PY-JWT-NONE" not in ids('import jwt\njwt.decode(t, k, algorithms=["RS256"])')


# --- TLS ---------------------------------------------------------------------
def test_tls_verify_disabled():
    assert "PY-TLS-VERIFY-OFF" in ids("import requests\nrequests.get(u, verify=False)")


def test_tls_verified_by_default_is_clean():
    assert "PY-TLS-VERIFY-OFF" not in ids("import requests\nrequests.get(u)")


# --- Archive extraction ------------------------------------------------------
def test_zip_extractall_flagged():
    assert "PY-ARCHIVE-SLIP" in ids('import zipfile\nzipfile.ZipFile(p).extractall("/tmp")')


# --- XXE ---------------------------------------------------------------------
def test_xxe_detected():
    assert "PY-XXE" in ids("import lxml.etree as etree\netree.parse(f)")


def test_defusedxml_is_clean():
    assert "PY-XXE" not in ids(
        "from defusedxml import ElementTree as ET\nET.parse(f)"
    )


# --- rule catalog integrity --------------------------------------------------
def test_rule_catalog_has_no_orphans():
    from src.engine import RULES
    for rule_id, rule in RULES.items():
        assert rule.rule_id == rule_id
        assert rule.severity in ("low", "medium", "high", "critical")
        assert rule.category and rule.message and rule.remediation
