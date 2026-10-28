"""Quick tier: a two-cent entry offer for agents.

The full scan costs 0.10 USDC and returns patches; this tier exists so an
agent can buy a cheap answer first. The price must be visible in discovery
(it is what an agent compares across servers) and the tier must never be
free.
"""
import json


def _requirements(response):
    return response.json()["accepts"]


def test_quote_advertises_the_cheap_tier(client):
    r = client.get("/api/v1/scan/quick")
    assert r.status_code == 402
    amounts = {a["network"]: str(a["amount"]) for a in _requirements(r)}
    assert amounts["eip155:8453"] == "20000"
    # The Solana network id follows payment_mode (devnet under test), so pin
    # the price without pinning the cluster.
    solana = [v for k, v in amounts.items() if k.startswith("solana:")]
    assert solana == ["20000"]


def test_quote_resource_points_at_the_quick_endpoint(client):
    body = client.get("/api/v1/scan/quick").json()
    assert body["resource"]["url"].endswith("/api/v1/scan/quick")


def test_quick_scan_without_payment_is_rejected(client):
    r = client.post("/api/v1/scan/quick", json={"source_code": "eval(x)", "language": "python"})
    assert r.status_code == 402
    assert r.json()["error"] == "payment_required"


def test_products_list_quick_tier_first(client):
    products = client.get("/api/v1/products").json()
    assert products[0]["id"] == "quick-scan"
    assert products[0]["price_usd_approx"] == 0.02


def test_mcp_advertises_scan_quick_at_tier_price(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = {t["name"]: t for t in r.json()["result"]["tools"]}
    assert "scan_quick" in tools
    description = tools["scan_quick"]["description"]
    assert "0.02" in description
    assert "65 rules" in description


def test_full_scan_description_is_not_stale(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = {t["name"]: t for t in r.json()["result"]["tools"]}
    assert "65 rules" in tools["scan_code"]["description"]
    assert "45+" not in json.dumps(tools)
