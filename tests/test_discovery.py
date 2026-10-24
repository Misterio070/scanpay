"""Test M2M Discovery Endpoints (x402, Bazaar, MCP, Agent Card, Skill)."""
import pytest


class TestDiscoveryEndpoints:
    def test_well_known_x402(self, client):
        r = client.get("/.well-known/x402")
        assert r.status_code == 200
        data = r.json()
        assert data["x402Version"] == 2
        assert data["scheme"] == "solana"
        assert "solana:" in data["network"]
        assert "pricing" in data
        assert "endpoints" in data
        assert data["extensions"]["bazaar"]["discoverable"] is True
        assert r.headers.get("access-control-allow-origin") == "*"

    def test_bazaar_json(self, client):
        r = client.get("/bazaar.json")
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "ScanPay"
        assert data["extensions"]["bazaar"]["discoverable"] is True
        assert "security" in data["extensions"]["bazaar"]["category"]
        assert len(data["products"]) >= 1

    def test_well_known_mcp(self, client):
        r = client.get("/.well-known/mcp.json")
        assert r.status_code == 200
        data = r.json()
        assert "transports" in data
        transports = {t["type"]: t["url"] for t in data["transports"]}
        assert "sse" in transports
        assert "http" in transports
        assert len(data["tools"]) >= 3

    def test_well_known_agent_card(self, client):
        r = client.get("/.well-known/agent-card.json")
        assert r.status_code == 200
        data = r.json()
        assert "protocol_standards" in data
        assert "x402-v2" in data["protocol_standards"]
        assert "interfaces" in data

    def test_skill_md(self, client):
        r = client.get("/SKILL.md")
        assert r.status_code == 200
        assert "---" in r.text
        assert "name: scanpay" in r.text
        assert "auto_remediation" in r.text

    def test_pay_md(self, client):
        r = client.get("/PAY.md")
        assert r.status_code == 200
        assert "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4" in r.text
        assert "700,000 lamports" in r.text

    def test_openapi_x402_extensions(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        data = r.json()
        assert data["info"]["x-payment-protocol"] == "x402"
        assert "x-merchant-wallet" in data["info"]
        assert data["info"]["x-bazaar-discoverable"] is True
        paths = data["paths"]
        assert "/api/v1/scan" in paths
        scan_post = paths["/api/v1/scan"]["post"]
        assert "x-upgrade-meta" in scan_post
        assert scan_post["x-upgrade-meta"]["protocol"] == "x402"

    def test_scan_response_schema_json(self, client):
        r = client.get("/schemas/v2/scan-response.schema.json")
        assert r.status_code == 200
        data = r.json()
        assert "$schema" in data
        assert "2020-12" in data["$schema"]
        assert "ScanPayA2AScanResponse" in data["title"]
        assert "execution_gate" in data["properties"]
