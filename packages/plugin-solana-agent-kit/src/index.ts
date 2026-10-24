/**
 * @scanpay/plugin-solana-agent-kit
 * ScanPay deterministic code security guardrail tool for Solana Agent Kit v2.
 */

export interface ScanPayOptions {
  endpoint?: string;
  sessionToken?: string;
  autoRemediate?: boolean;
}

export interface ScanPayResult {
  allowed: boolean;
  verdict: 'PASS' | 'WARN' | 'BLOCK';
  riskScore: number;
  maxSeverity: string;
  findings: Array<{
    rule_id: string;
    category: string;
    severity: string;
    message: string;
    line_number: number;
  }>;
  autoRemediation?: {
    patchesAvailable: boolean;
    remediatedCode?: string;
    unifiedDiff?: string;
    postPatchVerdict?: string;
  };
  raw: any;
}

const DEFAULT_ENDPOINT = 'https://scanpay-ob3w.onrender.com/v2/scan';
const MERCHANT_WALLET = 'JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4';
const PRICE_LAMPORTS = 700000;

/**
 * Scan source code with ScanPay before execution.
 * Handles x402 Solana micropayments or uses an active session voucher.
 */
export async function scanCode(
  agent: any,
  code: string,
  language: 'python' | 'javascript' | 'typescript' | 'tsx' = 'python',
  options: ScanPayOptions = {}
): Promise<ScanPayResult> {
  const endpoint = options.endpoint || DEFAULT_ENDPOINT;
  const autoRemediate = options.autoRemediate ?? true;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (options.sessionToken) {
    headers['X-SCANPAY-SESSION'] = options.sessionToken;
  }

  const payload = JSON.stringify({
    source_code: code,
    language,
    auto_remediate: autoRemediate,
  });

  // Step 1: Probe request
  let response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: payload,
  });

  // Step 2: Handle x402 challenge if payment required
  if (response.status === 402 && !options.sessionToken) {
    if (!agent || typeof agent.transfer !== 'function') {
      throw new Error(
        'ScanPay 402 Payment Required: SolanaAgentKit instance required to sign SOL micropayment.'
      );
    }

    // Settle 0.0007 SOL micropayment to merchant wallet
    const txSig = await agent.transfer(
      MERCHANT_WALLET,
      PRICE_LAMPORTS / 1_000_000_000
    );

    // Step 3: Retry with payment signature
    headers['X-PAYMENT'] = txSig;
    response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: payload,
    });
  }

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`ScanPay scan failed [HTTP ${response.status}]: ${errText}`);
  }

  const data = await response.json();
  const gate = data.execution_gate || {};
  const remediation = data.auto_remediation || {};

  return {
    allowed: gate.allow_execution ?? (data.findings_count === 0),
    verdict: gate.verdict || 'WARN',
    riskScore: gate.risk_score || 0,
    maxSeverity: gate.max_severity || 'LOW',
    findings: data.findings || [],
    autoRemediation: {
      patchesAvailable: remediation.patches_available ?? false,
      remediatedCode: remediation.remediated_code,
      unifiedDiff: remediation.unified_diff,
      postPatchVerdict: remediation.post_patch_verdict,
    },
    raw: data,
  };
}

/**
 * Solana Agent Kit v2 Tool Definition for ScanPay.
 */
export const scanPayTool = {
  name: 'scan_code_security',
  description:
    'Audit generated code for security vulnerabilities (eval, injection, wallet key exfiltration, SSRF) before execution. Returns execution gate verdict and deterministic fixes.',
  parameters: {
    type: 'object',
    properties: {
      code: {
        type: 'string',
        description: 'Source code to scan (Python, JavaScript, or TypeScript)',
      },
      language: {
        type: 'string',
        enum: ['python', 'javascript', 'typescript', 'tsx'],
        default: 'python',
        description: 'Programming language of the code',
      },
      autoRemediate: {
        type: 'boolean',
        default: true,
        description: 'Whether to compute deterministic patch diff',
      },
    },
    required: ['code'],
  },
  execute: async (agent: any, params: any) => {
    return await scanCode(agent, params.code, params.language, {
      autoRemediate: params.autoRemediate,
    });
  },
};
