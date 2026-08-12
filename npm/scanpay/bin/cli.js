#!/usr/bin/env node

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const DEFAULT_URL = 'https://repository-nil-camcorder-divx.trycloudflare.com';
const SCAN_ENDPOINT = '/api/v1/scan';
const HEALTH_ENDPOINT = '/api/v1/health';
const PRODUCTS_ENDPOINT = '/api/v1/products';

function fetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function scan(code, lang, baseUrl) {
  const url = baseUrl || DEFAULT_URL;
  const payload = JSON.stringify({ source_code: code, language: lang });
  
  // First request — expect 402
  const res1 = await fetch(`${url}${SCAN_ENDPOINT}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
  });
  
  if (res1.status === 200) {
    // Free mode — no payment needed
    return JSON.parse(res1.body);
  }
  
  if (res1.status !== 402) {
    console.error(`Unexpected status: ${res1.status}`);
    console.error(res1.body);
    process.exit(1);
  }
  
  const paymentReq = JSON.parse(res1.body);
  console.error(`\n💳 Payment required: ${paymentReq.amount} lamports (${paymentReq.amount / 1000000000} SOL)`);
  console.error(`   Recipient: ${paymentReq.recipient}`);
  console.error(`   Network: ${paymentReq.network}`);
  console.error(`\n   Pay with: solana transfer ${paymentReq.recipient} ${paymentReq.amount / 1000000000} --url https://api.devnet.solana.com`);
  console.error(`   Then retry with: scanpay scan --code <code> --lang <lang> --payment <tx-sig>`);
  process.exit(2);
}

async function health(baseUrl) {
  const url = baseUrl || DEFAULT_URL;
  const res = await fetch(`${url}${HEALTH_ENDPOINT}`);
  const data = JSON.parse(res.body);
  console.log(JSON.stringify(data, null, 2));
}

async function products(baseUrl) {
  const url = baseUrl || DEFAULT_URL;
  const res = await fetch(`${url}${PRODUCTS_ENDPOINT}`);
  const data = JSON.parse(res.body);
  console.log(JSON.stringify(data, null, 2));
}

async function scanFile(filePath, lang, baseUrl) {
  const code = fs.readFileSync(filePath, 'utf-8');
  const ext = path.extname(filePath).slice(1);
  const language = lang || (['py'].includes(ext) ? 'python' : 'javascript');
  await scan(code, language, baseUrl);
}

// CLI
const args = process.argv.slice(2);
const cmd = args[0];

if (cmd === 'scan') {
  const fileIdx = args.indexOf('--file');
  const codeIdx = args.indexOf('--code');
  const langIdx = args.indexOf('--lang');
  const urlIdx = args.indexOf('--url');
  
  const lang = langIdx >= 0 ? args[langIdx + 1] : null;
  const baseUrl = urlIdx >= 0 ? args[urlIdx + 1] : null;
  
  if (fileIdx >= 0) {
    scanFile(args[fileIdx + 1], lang, baseUrl);
  } else if (codeIdx >= 0) {
    scan(args[codeIdx + 1], lang, baseUrl);
  } else {
    // Read from stdin
    let code = '';
    process.stdin.on('data', (chunk) => code += chunk);
    process.stdin.on('end', () => scan(code, lang, baseUrl));
  }
} else if (cmd === 'health') {
  const urlIdx = args.indexOf('--url');
  const baseUrl = urlIdx >= 0 ? args[urlIdx + 1] : null;
  health(baseUrl);
} else if (cmd === 'products') {
  const urlIdx = args.indexOf('--url');
  const baseUrl = urlIdx >= 0 ? args[urlIdx + 1] : null;
  products(baseUrl);
} else {
  console.log(`
ScanPay — Code Security Scanner with x402 v2 Micropayments

Usage:
  scanpay scan --file <path> [--lang python|javascript] [--url <api-url>]
  scanpay scan --code "eval(x)" --lang python
  cat file.py | scanpay scan --lang python
  scanpay health [--url <api-url>]
  scanpay products [--url <api-url>]

Options:
  --file <path>     File to scan
  --code <string>   Code string to scan
  --lang <lang>      python or javascript (default: auto-detect)
  --url <url>        API base URL (default: live testnet)
  --help             Show this help

Examples:
  scanpay scan --file dangerous.py --lang python
  echo "eval(userInput)" | scanpay scan --lang python
  scanpay health
`);
}