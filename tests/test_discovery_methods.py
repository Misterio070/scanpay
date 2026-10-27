"""x402 directories probe with HEAD and OPTIONS before they ever send a POST.

A 405 on those verbs made x402scan, agent402 and the Bazaar crawler record every
paid route as unreachable, so the listing never verified even though the endpoint
answered 402 on GET and settled real payments on POST. These tests pin the verbs.
"""

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

PAID = ["/api/v1/scan", "/api/v1/token/audit", "/api/v1/preflight/simulate", "/api/v1/oracle/scrape"]
FREE = ["/", "/robots.txt", "/llms.txt", "/.well-known/x402", "/bazaar.json"]


@pytest.mark.parametrize("path", PAID)
def test_head_on_paid_route_returns_payment_challenge(path):
    r = client.head(path)
    assert r.status_code == 402, f"HEAD {path} returned {r.status_code}"
    assert r.headers.get("WWW-Authenticate") == "x402"
    assert "PAYMENT-REQUIRED" in r.headers
    assert r.content == b""


@pytest.mark.parametrize("path", FREE)
def test_head_on_free_route_succeeds(path):
    r = client.head(path)
    assert r.status_code == 200, f"HEAD {path} returned {r.status_code}"


@pytest.mark.parametrize("path", PAID + FREE)
def test_bare_options_is_not_method_not_allowed(path):
    r = client.options(path)
    assert r.status_code != 405, f"OPTIONS {path} returned 405"
    assert r.status_code in (200, 204)


def test_get_on_paid_route_still_carries_two_networks():
    body = client.get("/api/v1/scan").json()
    networks = {a["network"] for a in body["accepts"]}
    assert any(n.startswith("eip155:") for n in networks), networks
    assert any(n.startswith("solana:") for n in networks), networks


def test_favicon_is_served_for_catalog_listings():
    r = client.get("/favicon.ico")
    assert r.status_code == 200
    assert "svg" in r.headers.get("content-type", "")


def test_openapi_carries_a_contact_for_ownership_verification():
    contact = client.get("/openapi.json").json()["info"]["contact"]
    assert contact["email"], contact
