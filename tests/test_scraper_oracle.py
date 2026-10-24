"""Tests for ScanPay Anti-Bot Web Access & Scraper Oracle."""
import pytest
import httpx
from src.scraper_oracle import (
    clean_html_to_markdown,
    detect_waf_challenge,
    scrape_url,
)


def test_clean_html_to_markdown_structure():
    raw_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Developer Docs | Quickstart</title>
        <meta name="description" content="Quickstart guide for autonomous agents">
        <script>console.log("tracking snippet");</script>
        <style>.ad-banner { display: block; }</style>
    </head>
    <body>
        <nav><a href="/home">Home</a> | <a href="/about">About</a></nav>
        <h1>Autonomous Agent Guide</h1>
        <p>This is a paragraph detailing <a href="https://example.com/api">the API</a>.</p>
        <h2>Installation</h2>
        <pre><code>pip install scanpay-cli</code></pre>
        <ul>
            <li>Feature 1: AST Analysis</li>
            <li>Feature 2: Auto-remediation</li>
        </ul>
        <footer>Copyright 2026</footer>
    </body>
    </html>
    """

    md, title, desc = clean_html_to_markdown(raw_html)
    assert title == "Developer Docs | Quickstart"
    assert desc == "Quickstart guide for autonomous agents"

    # Verify navigation, scripts, and footer were removed
    assert "tracking snippet" not in md
    assert ".ad-banner" not in md
    assert "Copyright 2026" not in md

    # Verify Markdown formatting
    assert "# Autonomous Agent Guide" in md
    assert "## Installation" in md
    assert "[the API](https://example.com/api)" in md
    assert "```\npip install scanpay-cli\n```" in md
    assert "* Feature 1: AST Analysis" in md


def test_detect_waf_challenge():
    # Cloudflare turnstile signature
    cf_html = "<html><body><script src='https://challenges.cloudflare.com/turnstile/v0/api.js'></script><p>Just a moment...</p></body></html>"
    detected, name = detect_waf_challenge(403, cf_html)
    assert detected is True
    assert "Cloudflare" in name

    # Standard clean HTML
    clean_html = "<html><body><h1>Hello World</h1><p>Documentation content</p></body></html>"
    detected, name = detect_waf_challenge(200, clean_html)
    assert detected is False
    assert name == "None"


@pytest.mark.asyncio
async def test_scrape_url_mocked_success():
    mock_html = """
    <html>
        <head><title>Agent Tokenomics</title></head>
        <body>
            <h1>A2A Micropayments</h1>
            <p>Using x402 on Base and Solana.</p>
        </body>
    </html>
    """

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, text=mock_html, request=request)

    client = httpx.AsyncClient(transport=MockTransport())

    res = await scrape_url("https://example.com/tokenomics", client=client)
    await client.aclose()

    assert res["schema_version"] == "2.0.0"
    assert res["request"]["status_code"] == 200
    assert res["bot_protection"]["waf_detected"] is False
    assert res["metadata"]["title"] == "Agent Tokenomics"
    assert "# A2A Micropayments" in res["content"]
    assert "attestation" in res
    assert len(res["attestation"]["oracle_signature"]) == 64


@pytest.mark.asyncio
async def test_scrape_url_mocked_waf_detected():
    mock_cf_html = "<html><body>Just a moment... Attention Required! | Cloudflare</body></html>"

    class MockWafTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(403, text=mock_cf_html, request=request)

    client = httpx.AsyncClient(transport=MockWafTransport())

    res = await scrape_url("https://protected-site.com", client=client)
    await client.aclose()

    assert res["request"]["status_code"] == 403
    assert res["bot_protection"]["waf_detected"] is True
    assert "Cloudflare" in res["bot_protection"]["challenge_type"]
