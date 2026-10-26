const assert = require("assert");
const { ScanPayClient } = require("../index.js");

const client = new ScanPayClient({ baseUrl: "http://localhost:8484" });
assert.strictEqual(typeof client.scanCode, "function");
assert.strictEqual(typeof client.auditToken, "function");
assert.strictEqual(typeof client.simulateTx, "function");
assert.strictEqual(typeof client.scrapeUrl, "function");
assert.strictEqual(typeof client.createSessionDeposit, "function");
console.log("✅ ScanPay SDK smoke tests passed.");
