#!/usr/bin/env node
/**
 * ScanPay CLI — Scan code and audit tokens for security vulnerabilities from the command line.
 *
 * Usage:
 *   scanpay scan <file> [--lang python|javascript|typescript|tsx] [--payment <tx>] [--session <token>]
 *   scanpay token <address> [--chain base|solana|ethereum] [--payment <tx>] [--session <token>]
 *   scanpay health [--url https://scanpay-ob3w.onrender.com]
 *   scanpay products [--url https://scanpay-ob3w.onrender.com]
 */

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name, defaultVal) {
  const idx = args.indexOf(name);
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
  return defaultVal;
}

const baseUrl = (getFlag("--url", process.env.SCANPAY_URL || "https://scanpay-ob3w.onrender.com")).replace(/\/+$/, "");
const paymentTx = getFlag("--payment", process.env.SCANPAY_PAYMENT_TX || "");
const sessionToken = getFlag("--session", process.env.SCANPAY_SESSION_TOKEN || "");

function request(method, urlPath, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl + urlPath);
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
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function getAuthHeaders() {
  const headers = {};
  if (sessionToken) headers["X-SCANPAY-SESSION"] = sessionToken;
  if (paymentTx) headers["X-PAYMENT"] = paymentTx;
  return headers;
}

function print402(body) {
  const reqs = (body && body.paymentRequirements) || body || {};
  const preview = body && body.diagnostic_preview;
  console.error("\n💳 Payment Required (HTTP 402 — x402 v2)");
  if (preview) {
    console.error("\n🚨 LIVE THREAT DIAGNOSTIC PREVIEW:");
    if (preview.verdict_preview) console.error(`  Verdict Preview:  ${preview.verdict_preview}`);
    if (preview.findings_detected !== undefined) console.error(`  Findings Count:   ${preview.findings_detected}`);
    if (preview.threats_detected !== undefined) console.error(`  Threats Count:    ${preview.threats_detected}`);
    if (preview.risk_score !== undefined) console.error(`  Risk Score:       ${preview.risk_score}/100`);
    if (preview.max_severity) console.error(`  Max Severity:     ${String(preview.max_severity).toUpperCase()}`);
    if (preview.notice) console.error(`  Notice:           ${preview.notice}`);
  }
  console.error("\nSettlement Options:");
  console.error(`  • Base USDC:  ${reqs.accepts?.[2]?.amount_display || "0.05-0.10 USDC"} -> ${reqs.accepts?.[2]?.recipient || "0xb295E606F38C363b476FC546c27226B5fBcAAEFA"}`);
  console.error(`  • Solana SOL: ${reqs.amount_display || "0.0007 SOL"} (${reqs.amount || 700000} lamports) -> ${reqs.recipient || "JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"}`);
  console.error(`\nRe-run with: --payment <tx_hash_or_sig> or --session <sp_sess_...>`);
}

function detectLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".jsx": "javascript",
  };
  return map[ext] || "python";
}

async function main() {
  if (!command || command === "--help" || command === "-h") {
    console.log(`ScanPay CLI v1.2.0 — Autonomous Code & Token Security Oracle

Usage:
  scanpay scan <file> [--lang python|javascript|typescript|tsx] [--payment <tx>] [--session <token>]
  scanpay token <address> [--chain base|solana|ethereum] [--payment <tx>] [--session <token>]
  scanpay health [--url <server>]
  scanpay products [--url <server>]`);
    process.exit(0);
  }

  if (command === "health") {
    const resp = await request("GET", "/api/v1/health");
    console.log(JSON.stringify(resp.body, null, 2));
    process.exit(resp.status === 200 ? 0 : 1);
  }

  if (command === "products") {
    const resp = await request("GET", "/api/v1/products");
    console.log(JSON.stringify(resp.body, null, 2));
    process.exit(resp.status === 200 ? 0 : 1);
  }

  if (command === "token") {
    const tokenAddr = args[1] || getFlag("--address", "");
    const chain = getFlag("--chain", "base");
    if (!tokenAddr) {
      console.error("Error: specify a token address: scanpay token <address> [--chain base|solana|ethereum]");
      process.exit(1);
    }
    const resp = await request(
      "POST",
      "/api/v1/token/audit",
      { chain, token_address: tokenAddr, tx_signature: paymentTx || undefined },
      getAuthHeaders()
    );
    if (resp.status === 402) {
      print402(resp.body);
      process.exit(2);
    }
    console.log(JSON.stringify(resp.body, null, 2));
    process.exit(resp.status === 200 ? 0 : 1);
  }

  if (command === "scan") {
    const filePath = args[1];
    if (!filePath) {
      console.error("Error: specify a file to scan");
      process.exit(1);
    }

    if (!fs.existsSync(filePath)) {
      console.error(`Error: file not found: ${filePath}`);
      process.exit(1);
    }

    const code = fs.readFileSync(filePath, "utf-8");
    const lang = getFlag("--lang", detectLanguage(filePath));

    const resp = await request(
      "POST",
      "/api/v1/scan",
      { source_code: code, language: lang, tx_signature: paymentTx || undefined },
      getAuthHeaders()
    );

    if (resp.status === 402) {
      print402(resp.body);
      process.exit(2);
    }

    if (resp.status !== 200) {
      console.error(`Error (${resp.status}):`, resp.body);
      process.exit(1);
    }

    const r = resp.body;
    console.log(`\nScanPay v${r.engine_version} — ${r.language} scan (${r.scan_duration_ms}ms)`);
    console.log(`SHA256: ${r.source_sha256}`);
    console.log(`Syntax OK: ${r.syntax_ok}`);
    console.log(`Findings: ${r.findings_count} (max severity: ${r.max_severity || "none"})\n`);

    if (r.findings_count === 0) {
      console.log("✅ No security issues found.");
      process.exit(0);
    }

    const sevColors = {
      critical: "\x1b[31m",
      high: "\x1b[33m",
      medium: "\x1b[36m",
      low: "\x1b[37m",
    };
    const reset = "\x1b[0m";

    for (const f of r.findings) {
      const color = sevColors[f.severity] || "";
      console.log(`${color}[${f.severity.toUpperCase()}]${reset} ${f.rule_id} — line ${f.line}:${f.col}`);
      console.log(`  ${f.message}`);
      console.log(`  Snippet: ${f.snippet}`);
      console.log(`  Fix: ${f.recommendation}\n`);
    }

    process.exit(r.max_severity === "critical" || r.max_severity === "high" ? 1 : 0);
  }

  console.error(`Unknown command: ${command}. Run 'scanpay --help' for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
