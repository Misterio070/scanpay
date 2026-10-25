/**
 * @scanpay/agentkit-action
 * Official Coinbase AgentKit Action Provider for ScanPay Autonomous Security & Pre-Flight Drainer Shield.
 * Settles micropayments natively in Base USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913).
 */
import { z } from 'zod';

export const MERCHANT_BASE_EVM_WALLET = '0xb295E606F38C363b476FC546c27226B5fBcAAEFA';
export const BASE_USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const DEFAULT_SCANPAY_URL = 'https://scanpay-ob3w.onrender.com';

export const ScanCodeSchema = z.object({
  code: z.string().describe('The Python or JS/TS source code to audit for security vulnerabilities'),
  language: z.enum(['python', 'javascript', 'typescript']).default('python').describe('Programming language of the code'),
  autoRemediate: z.boolean().default(true).describe('Whether to generate deterministic patches and unified diffs'),
});

export const SimulateTxSchema = z.object({
  tx: z.record(z.any()).describe('The EVM transaction payload (to, data, value) to simulate before broadcast'),
  chain: z.enum(['base', 'ethereum']).default('base').describe('Target EVM chain'),
});

export const ScrapeUrlSchema = z.object({
  url: z.string().url().describe('The target URL to scrape, bypassing Cloudflare Turnstile and anti-bot WAFs'),
  extractMode: z.enum(['markdown', 'text', 'raw_html']).default('markdown').describe('Output extraction format'),
});

/**
 * Scan source code for security vulnerabilities.
 * Automatically handles x402 402 challenge with 0.10 Base USDC settlement.
 */
export async function scanCodeAction(
  walletProvider: any,
  args: z.infer<typeof ScanCodeSchema>,
  baseUrl: string = DEFAULT_SCANPAY_URL
): Promise<string> {
  const endpoint = `${baseUrl}/v2/scan`;
  const body = JSON.stringify({
    source_code: args.code,
    language: args.language,
    auto_remediate: args.autoRemediate,
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  let res = await fetch(endpoint, { method: 'POST', headers, body });

  if (res.status === 402) {
    if (!walletProvider || typeof walletProvider.sendTransaction !== 'function') {
      throw new Error('ScanPay x402 Payment Required: EvmWalletProvider required to settle 0.10 Base USDC.');
    }

    // Settle 0.10 Base USDC (100,000 units with 6 decimals)
    // ERC-20 transfer(address,uint256) signature: 0xa9059cbb
    const recipientClean = MERCHANT_BASE_EVM_WALLET.toLowerCase().replace('0x', '').padStart(64, '0');
    const amountHex = BigInt(100000).toString(16).padStart(64, '0');
    const transferCalldata = `0xa9059cbb${recipientClean}${amountHex}`;

    const txHash = await walletProvider.sendTransaction({
      to: BASE_USDC_CONTRACT,
      data: transferCalldata,
    });

    headers['X-PAYMENT'] = txHash;
    res = await fetch(endpoint, { method: 'POST', headers, body });
  }

  if (!res.ok) {
    throw new Error(`ScanPay scan failed [HTTP ${res.status}]: ${await res.text()}`);
  }

  const result = await res.json();
  return JSON.stringify(result, null, 2);
}

/**
 * Simulate an EVM transaction before broadcast to detect honeypots, drainers, and sandwich traps.
 * Automatically handles x402 402 challenge with 0.05 Base USDC settlement.
 */
export async function simulateTxAction(
  walletProvider: any,
  args: z.infer<typeof SimulateTxSchema>,
  baseUrl: string = DEFAULT_SCANPAY_URL
): Promise<string> {
  const endpoint = `${baseUrl}/v2/preflight/simulate`;
  const body = JSON.stringify({
    tx: args.tx,
    chain: args.chain,
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  let res = await fetch(endpoint, { method: 'POST', headers, body });

  if (res.status === 402) {
    if (!walletProvider || typeof walletProvider.sendTransaction !== 'function') {
      throw new Error('ScanPay x402 Payment Required: EvmWalletProvider required to settle 0.05 Base USDC.');
    }

    // Settle 0.05 Base USDC (50,000 units with 6 decimals)
    const recipientClean = MERCHANT_BASE_EVM_WALLET.toLowerCase().replace('0x', '').padStart(64, '0');
    const amountHex = BigInt(50000).toString(16).padStart(64, '0');
    const transferCalldata = `0xa9059cbb${recipientClean}${amountHex}`;

    const txHash = await walletProvider.sendTransaction({
      to: BASE_USDC_CONTRACT,
      data: transferCalldata,
    });

    headers['X-PAYMENT'] = txHash;
    res = await fetch(endpoint, { method: 'POST', headers, body });
  }

  if (!res.ok) {
    throw new Error(`ScanPay simulate failed [HTTP ${res.status}]: ${await res.text()}`);
  }

  const result = await res.json();
  return JSON.stringify(result, null, 2);
}

/**
 * Scrape a protected web URL bypassing Cloudflare Turnstile and anti-bot WAFs.
 * Automatically handles x402 402 challenge with 0.02 Base USDC settlement.
 */
export async function scrapeUrlAction(
  walletProvider: any,
  args: z.infer<typeof ScrapeUrlSchema>,
  baseUrl: string = DEFAULT_SCANPAY_URL
): Promise<string> {
  const endpoint = `${baseUrl}/v2/oracle/scrape`;
  const body = JSON.stringify({
    url: args.url,
    extract_mode: args.extractMode,
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  let res = await fetch(endpoint, { method: 'POST', headers, body });

  if (res.status === 402) {
    if (!walletProvider || typeof walletProvider.sendTransaction !== 'function') {
      throw new Error('ScanPay x402 Payment Required: EvmWalletProvider required to settle 0.02 Base USDC.');
    }

    // Settle 0.02 Base USDC (20,000 units with 6 decimals)
    const recipientClean = MERCHANT_BASE_EVM_WALLET.toLowerCase().replace('0x', '').padStart(64, '0');
    const amountHex = BigInt(20000).toString(16).padStart(64, '0');
    const transferCalldata = `0xa9059cbb${recipientClean}${amountHex}`;

    const txHash = await walletProvider.sendTransaction({
      to: BASE_USDC_CONTRACT,
      data: transferCalldata,
    });

    headers['X-PAYMENT'] = txHash;
    res = await fetch(endpoint, { method: 'POST', headers, body });
  }

  if (!res.ok) {
    throw new Error(`ScanPay scrape failed [HTTP ${res.status}]: ${await res.text()}`);
  }

  const result = await res.json();
  return JSON.stringify(result, null, 2);
}
