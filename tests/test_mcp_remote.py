"""Test Remote Streamable Model Context Protocol (MCP) server endpoints."""
import pytest


class TestRemoteMCP:
    def test_mcp_initialize(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["jsonrpc"] == "2.0"
        assert data["id"] == 1
        assert "serverInfo" in data["result"]
        assert data["result"]["serverInfo"]["name"] == "scanpay"

    def test_mcp_tools_list(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        tools = data["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "scan_code" in tool_names
        assert "simulate_tx" in tool_names
        assert "scrape_url" in tool_names
        assert "create_session_deposit" in tool_names
        assert "health_check" in tool_names

    def test_mcp_scan_code_tool_call(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_code",
                "arguments": {
                    "source_code": "eval('1+1')",
                    "language": "python"
                }
            }
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        res = data["result"]
        assert res["execution_gate"]["verdict"] == "BLOCK"
        assert res["auto_remediation"]["patches_available"] is True
        assert "ast.literal_eval" in res["auto_remediation"]["remediated_code"]

    def test_mcp_simulate_tx_tool_call(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "simulate_tx",
                "arguments": {
                    "chain": "base",
                    "tx": {
                        "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                        "data": "0x095ea7b3" + "f" * 128
                    }
                }
            }
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        res = data["result"]
        assert res["execution_gate"]["verdict"] == "BLOCK"
        assert res["execution_gate"]["allow_broadcast"] is False
        assert "attestation" in res

    def test_mcp_scrape_url_tool_call(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "scrape_url",
                "arguments": {
                    "url": "https://example.com",
                    "extract_mode": "markdown"
                }
            }
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "result" in data
        assert "metadata" in data["result"]
        assert "content" in data["result"]

    def test_mcp_ping(self, client):
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "ping",
            "params": {}
        }
        r = client.post("/mcp", json=payload)
        assert r.status_code == 200
        assert r.json()["result"] == {}

    def test_mcp_get_status(self, client):
        r = client.get("/mcp")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ready"
        assert "endpoints" in data

    def test_mcp_payment_required_error_code_40200(self, testnet_client):
        payload = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "scan_code",
                "arguments": {
                    "source_code": "eval('1+1')",
                    "language": "python"
                }
            }
        }
        r = testnet_client.post("/mcp", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "error" in data
        assert data["error"]["code"] == -40200
        assert data["error"]["data"]["x402Version"] == 2
        assert "accepted_tokens" in data["error"]["data"]
