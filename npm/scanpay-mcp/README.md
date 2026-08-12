# scanpay-mcp-server

> MCP (Model Context Protocol) server for AI agents to scan code for security vulnerabilities before execution.

## Install

```bash
npm install -g scanpay-mcp-server
```

## Use with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scanpay": {
      "command": "scanpay-mcp",
      "env": {
        "SCANPAY_URL": "https://repository-nil-camcorder-divx.trycloudflare.com"
      }
    }
  }
}
```

## How It Works

1. AI agent generates code
2. Agent calls `scan_code` tool via MCP
3. ScanPay scans for 45+ vulnerability patterns (Python + JS/TS)
4. Agent receives results before executing code
5. Payment via x402 v2 micropayments (0.0007 SOL ~$0.10/scan)

## Supported Languages

- Python (ast module) — 30+ vulnerability patterns
- JavaScript/TypeScript (tree-sitter) — 23+ vulnerability patterns

## Links

- [GitHub](https://github.com/Misterio070/scanpay)
- [npm CLI](https://www.npmjs.com/package/scanpay-cli)
- [x402 Protocol](https://x402.org)
