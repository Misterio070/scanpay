/**
 * ScanPay Programmatic SDK for Autonomous AI Agents & Node.js Applications.
 *
 * Supports:
 * - AST Code Security Scanning (`scanCode`)
 * - Live On-Chain Token Rug & Honeypot Auditing (`auditToken`)
 * - Pre-Flight Transaction & Drainer Simulation (`simulateTx`)
 * - Anti-Bot Web Access & Scraper Oracle (`scrapeUrl`)
 * - Prepaid Session Vouchers (`createSessionDeposit`, `getSessionStatus`)
 * - Automatic 402 Payment Callback (`onPaymentRequired`)
 */

const https = require("https");
const http = require("http");

class ScanPayClient {
  /**
   * @param {Object} options
   * @param {string} [options.baseUrl] - ScanPay server URL
   * @param {string} [options.sessionToken] - Prepaid session voucher token
   * @param {Function} [options.onPaymentRequired] - Async callback `(challenge) => txHashOrSignature`
   */
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || process.env.SCANPAY_URL || "https://scanpay-ob3w.onrender.com").replace(/\/+$/, "");
    this.sessionToken = options.sessionToken || process.env.SCANPAY_SESSION_TOKEN || null;
    this.onPaymentRequired = options.onPaymentRequired || null;
  }

  _request(method, path, body = null, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(this.baseUrl + path);
      const mod = url.protocol === "https:" ? https : http;
      const headers = {
        "Content-Type": "application/json",
        ...extraHeaders,
      };
      if (this.sessionToken && !headers["X-SCANPAY-SESSION"]) {
        headers["X-SCANPAY-SESSION"] = this.sessionToken;
      }

      const req = mod.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === "https:" ? 443 : 80),
          path: url.pathname + url.search,
          method,
          headers,
          timeout: 30000,
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
            } catch {
              resolve({ status: res.statusCode, headers: res.headers, body: data });
            }
          });
        }
      );

      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Request timeout"));
      });
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }

  async _callWithAutoPay(path, payload, paymentTx = null) {
    const headers = {};
    if (paymentTx) headers["X-PAYMENT"] = paymentTx;

    let resp = await this._request("POST", path, payload, headers);
    if (resp.status === 402 && !paymentTx && typeof this.onPaymentRequired === "function") {
      const txProof = await this.onPaymentRequired(resp.body);
      if (txProof) {
        if (String(txProof).startsWith("scanpay_sess_")) {
          this.sessionToken = txProof;
          resp = await this._request("POST", path, payload, { "X-SCANPAY-SESSION": txProof });
        } else {
          resp = await this._request("POST", path, payload, { "X-PAYMENT": String(txProof) });
        }
      }
    }
    return resp;
  }

  async scanCode(sourceCode, language = "python", paymentTx = null) {
    return this._callWithAutoPay("/api/v1/scan", { source_code: sourceCode, language }, paymentTx);
  }

  async auditToken(tokenAddress, chain = "base", paymentTx = null) {
    return this._callWithAutoPay("/api/v1/token/audit", { chain, token_address: tokenAddress }, paymentTx);
  }

  async simulateTx(tx, chain = "base", paymentTx = null) {
    return this._callWithAutoPay("/api/v1/preflight/simulate", { chain, tx }, paymentTx);
  }

  async scrapeUrl(url, extractMode = "markdown", paymentTx = null) {
    return this._callWithAutoPay("/api/v1/oracle/scrape", { url, extract_mode: extractMode, strip_media: true }, paymentTx);
  }

  async createSessionDeposit(depositTx, payerWallet = null) {
    const resp = await this._request("POST", "/api/v1/session/deposit", {
      deposit_tx: depositTx,
      payer_wallet: payerWallet,
    });
    if (resp.status === 200 && resp.body && resp.body.session_token) {
      this.sessionToken = resp.body.session_token;
    }
    return resp;
  }

  async getSessionStatus(sessionToken = null) {
    const token = sessionToken || this.sessionToken;
    return this._request("GET", `/api/v1/session/status?session_token=${encodeURIComponent(token || "")}`);
  }

  async getHealth() {
    return this._request("GET", "/api/v1/health");
  }

  async getStats() {
    return this._request("GET", "/api/v1/stats");
  }
}

module.exports = { ScanPayClient };
