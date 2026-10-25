#!/usr/bin/env node
/**
 * ScanPay MCP Server — Exposes code scanning, live token rug/honeypot auditing,
 * pre-flight transaction simulation, and anti-bot scraping as MCP tools for AI agents.
 *
 * Usage:
 *   SCANPAY_URL=https://scanpay-ob3w.onrender.com npx scanpay-mcp
 *
 * Protocol: MCP over stdio (JSON-RPC 2.0)
 */

const https = require("https");
const http = require("http");
const readline = require("readline");

const SCANPAY_URL = (process.env.SCANPAY_URL || "https://scanpay-ob3w.onrender.com").replace(/\/+$/, "");

function httpRequest(method, path, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(SCANPAY_URL + path);
    const mod = url.protocol === "https:" ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": "application/json",
        ...extraHeaders,
      },
      timeout: 30000,
    };

    const req = mod.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        }
      });
    });

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function buildAuthHeaders(args = {}) {
  const headers = {};
  const sessionToken = args.session_token || process.env.SCANPAY_SESSION_TOKEN;
  const paymentTx = args.payment_tx || process.env.SCANPAY_PAYMENT_TX;
  if (sessionToken) headers["X-SCANPAY-SESSION"] = sessionToken;
  if (paymentTx) headers["X-PAYMENT"] = paymentTx;
  return headers;
}

function format402Message(serviceLabel, body) {
  const reqs = (body && body.paymentRequirements) || {};
  const preview = (body && body.diagnostic_preview) || null;
  let out = `💳 Payment Required (HTTP 402 — x402 v2): ${serviceLabel}\n\n`;

  if (preview) {
    out += `🚨 LIVE THREAT DIAGNOSTIC PREVIEW (Unpaid Pre-Check):\n`;
    if (preview.verdict_preview) out += `  • Verdict Preview: ${preview.verdict_preview}\n`;
    if (preview.findings_detected !== undefined) out += `  • Vulnerabilities Detected: ${preview.findings_detected}\n`;
    if (preview.threats_detected !== undefined) out += `  • On-Chain Threats Detected: ${preview.threats_detected}\n`;
    if (preview.risk_score !== undefined) out += `  • Risk Score: ${preview.risk_score}/100\n`;
    if (preview.max_severity) out += `  • Max Severity: ${String(preview.max_severity).toUpperCase()}\n`;
    if (preview.notice) out += `  • Notice: ${preview.notice}\n`;
    out += `\n`;
  }

  out += `Settlement Options:\n`;
  out += `  1. Base USDC: Send ${reqs.accepts?.[2]?.amount_display || "0.05-0.10 USDC"} to ${reqs.accepts?.[2]?.recipient || "0xb295E606F38C363b476FC546c27226B5fBcAAEFA"} (Contract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)\n`;
  out += `  2. Solana SOL: Send ${reqs.amount_display || "0.0007 SOL"} to ${reqs.recipient || "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"}\n`;
  out += `  3. Session Voucher (10 credits, 0ms latency): Deposit 0.85 Base USDC or 0.006 SOL via create_session_deposit\n\n`;
  out += `To unlock the full report, pass payment_tx="<tx_hash>" or session_token="<sp_sess_...>" in your tool call.`;
  return out;
}

const SERVER_INFO = {
  name: "scanpay",
  version: "1.2.0",
};

const TOOLS = [
  {
    name: "scan_code",
    description:
      "Scan source code for security vulnerabilities using deterministic AST analysis. " +
      "Detects 57 vulnerability patterns across Python (28 rules) and JavaScript/TypeScript/TSX (29 rules). " +
      "Unpaid calls return a live Threat Diagnostic Preview with vulnerability count & severity.",
    inputSchema: {
      type: "object",
      properties: {
        source_code: {
          type: "string",
          description: "The source code to scan for security vulnerabilities (max 100KB)",
        },
        language: {
          type: "string",
          enum: ["python", "javascript", "typescript", "tsx"],
          default: "python",
          description: "Programming language of the source code",
        },
        payment_tx: {
          type: "string",
          description: "Solana signature or Base 0x transaction hash for x402 payment (0.0007 SOL or 0.10 Base USDC)",
        },
        session_token: {
          type: "string",
          description: "Prepaid ScanPay session voucher token (sp_sess_...)",
        },
      },
      required: ["source_code"],
    },
  },
  {
    name: "audit_token",
    description:
      "Live on-chain token & smart contract rug/honeypot shield for Base, Ethereum, and Solana. " +
      "Inspects live EVM bytecode (hidden blacklists, mutable 99% tax fees, pause switches), " +
      "Solana SPL / Token-2022 mint accounts (active Mint Authority, Freeze Authority, Permanent Delegate wallet seizure), " +
      "and live DexScreener liquidity & buy/sell honeypot telemetry. Cost: $0.05 USDC or 0.00035 SOL.",
    inputSchema: {
      type: "object",
      properties: {
        chain: {
          type: "string",
          enum: ["base", "ethereum", "solana"],
          default: "base",
        },
        token_address: {
          type: "string",
          description: "Token contract address (0x...) or Solana Mint address",
        },
        payment_tx: {
          type: "string",
          description: "Solana signature or Base 0x transaction hash for x402 payment",
        },
        session_token: {
          type: "string",
          description: "Prepaid ScanPay session voucher token (sp_sess_...)",
        },
      },
      required: ["chain", "token_address"],
    },
  },
  {
    name: "simulate_tx",
    description:
      "Pre-flight Transaction & Drainer Shield for Base, Ethereum, and Solana. Cost: $0.05 USDC or 0.00035 SOL.",
    inputSchema: {
      type: "object",
      properties: {
        chain: {
          type: "string",
          enum: ["base", "solana", "ethereum"],
          default: "base",
        },
        tx: {
          type: "object",
          description: "Transaction payload to simulate",
        },
        payment_tx: {
          type: "string",
          description: "Solana signature or Base 0x transaction hash for x402 payment",
        },
        session_token: {
          type: "string",
          description: "Prepaid ScanPay session voucher token (sp_sess_...)",
        },
      },
      required: ["chain", "tx"],
    },
  },
  {
    name: "scrape_url",
    description:
      "Anti-Bot Web Access & Scraper Oracle bypassing Cloudflare Turnstile/WAF. Cost: $0.02 USDC or 0.00015 SOL.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
        extract_mode: { type: "string", enum: ["markdown", "text", "raw"], default: "markdown" },
        strip_media: { type: "boolean", default: true },
        payment_tx: { type: "string" },
        session_token: { type: "string" },
      },
      required: ["url"],
    },
  },
  {
    name: "create_session_deposit",
    description:
      "Prepay 0.006 SOL or 0.85 Base USDC once for 10 instant credits across all ScanPay tools.",
    inputSchema: {
      type: "object",
      properties: {
        deposit_tx: { type: "string" },
        payer_wallet: { type: "string" },
      },
      required: ["deposit_tx"],
    },
  },
  {
    name: "scanpay_health",
    description: "Check ScanPay server health, available engines, and payment configuration.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "scanpay_products",
    description: "List available ScanPay security products and their pricing.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

async function handleToolCall(name, args = {}) {
  const authHeaders = buildAuthHeaders(args);

  if (name === "scan_code") {
    const resp = await httpRequest(
      "POST",
      "/api/v1/scan",
      {
        source_code: args.source_code,
        language: args.language || "python",
        tx_signature: args.payment_tx || undefined,
      },
      authHeaders
    );

    if (resp.status === 402) {
      return {
        content: [{ type: "text", text: format402Message("AST Code Security Scan", resp.body) }],
      };
    }
    if (resp.status !== 200) {
      return {
        content: [{ type: "text", text: `Error (${resp.status}): ${JSON.stringify(resp.body)}` }],
        isError: true,
      };
    }

    const r = resp.body;
    let summary = `Scan Complete (${r.language}) — Verdict: ${r.execution_gate?.verdict || "DONE"}\n`;
    summary += `SHA256: ${r.source_sha256}\n`;
    summary += `Findings: ${r.findings_count} (max severity: ${r.max_severity || "none"})\n\n`;

    if (r.findings_count === 0) {
      summary += "✅ No security issues found.";
    } else {
      for (const f of r.findings) {
        summary += `[${String(f.severity).toUpperCase()}] ${f.rule_id} (line ${f.line}:${f.col})\n`;
        summary += `  ${f.message}\n`;
        summary += `  Fix: ${f.recommendation}\n\n`;
      }
      if (r.remediation?.unified_diff) {
        summary += `--- Auto-Remediation Patch ---\n${r.remediation.unified_diff}\n`;
      }
    }
    return { content: [{ type: "text", text: summary }] };
  }

  if (name === "audit_token") {
    const resp = await httpRequest(
      "POST",
      "/api/v1/token/audit",
      {
        chain: args.chain || "base",
        token_address: args.token_address,
        tx_signature: args.payment_tx || undefined,
      },
      authHeaders
    );
    if (resp.status === 402) {
      return {
        content: [{ type: "text", text: format402Message(`Token Rug & Honeypot Audit (${args.chain}:${args.token_address})`, resp.body) }],
      };
    }
    return { content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }], isError: resp.status !== 200 };
  }

  if (name === "simulate_tx") {
    const resp = await httpRequest(
      "POST",
      "/api/v1/preflight/simulate",
      {
        chain: args.chain || "base",
        tx: args.tx || {},
        tx_signature: args.payment_tx || undefined,
      },
      authHeaders
    );
    if (resp.status === 402) {
      return {
        content: [{ type: "text", text: format402Message("Pre-Flight Transaction & Drainer Simulation", resp.body) }],
      };
    }
    return { content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }], isError: resp.status !== 200 };
  }

  if (name === "scrape_url") {
    const resp = await httpRequest(
      "POST",
      "/api/v1/oracle/scrape",
      {
        url: args.url,
        extract_mode: args.extract_mode || "markdown",
        strip_media: args.strip_media !== false,
        tx_signature: args.payment_tx || undefined,
      },
      authHeaders
    );
    if (resp.status === 402) {
      return {
        content: [{ type: "text", text: format402Message(`Anti-Bot Scraper Oracle (${args.url})`, resp.body) }],
      };
    }
    return { content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }], isError: resp.status !== 200 };
  }

  if (name === "create_session_deposit") {
    const resp = await httpRequest("POST", "/api/v1/session/deposit", {
      deposit_tx: args.deposit_tx,
      payer_wallet: args.payer_wallet,
    });
    return { content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }], isError: resp.status !== 200 };
  }

  if (name === "scanpay_health") {
    const resp = await httpRequest("GET", "/api/v1/health");
    return {
      content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }],
    };
  }

  if (name === "scanpay_products") {
    const resp = await httpRequest("GET", "/api/v1/products");
    return {
      content: [{ type: "text", text: JSON.stringify(resp.body, null, 2) }],
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
}

function sendResponse(id, result) {
  const msg = JSON.stringify({ jsonrpc: "2.0", id, result });
  process.stdout.write(msg + "\n");
}

function sendError(id, code, message) {
  const msg = JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
  process.stdout.write(msg + "\n");
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on("line", async (line) => {
  let req;
  try {
    req = JSON.parse(line.trim());
  } catch {
    return;
  }

  const { id, method, params } = req;

  switch (method) {
    case "initialize":
      sendResponse(id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
      break;

    case "notifications/initialized":
      break;

    case "tools/list":
      sendResponse(id, { tools: TOOLS });
      break;

    case "tools/call":
      try {
        const result = await handleToolCall(params.name, params.arguments || {});
        sendResponse(id, result);
      } catch (err) {
        sendResponse(id, {
          content: [{ type: "text", text: `ScanPay error: ${err.message}` }],
          isError: true,
        });
      }
      break;

    default:
      if (id !== undefined) {
        sendError(id, -32601, `Method not found: ${method}`);
      }
  }
});
