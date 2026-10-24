/**
 * @elizaos/plugin-scanpay
 * ElizaOS security plugin providing deterministic code audits and execution gatekeeper actions.
 */

export const SCAN_CODE_ACTION = {
  name: 'SCAN_CODE_SECURITY',
  similes: ['AUDIT_CODE', 'VERIFY_CODE_SAFETY', 'CHECK_VULNERABILITIES'],
  description: 'Audits source code using ScanPay deterministic AST analysis and returns execution gate decision.',
  validate: async (runtime: any, message: any) => {
    return true;
  },
  handler: async (runtime: any, message: any, state: any, options: any, callback: any) => {
    const code = options?.code || message?.content?.text;
    const language = options?.language || 'python';
    const endpoint = process.env.SCANPAY_URL || 'https://scanpay-ob3w.onrender.com/v2/scan';
    const sessionToken = process.env.SCANPAY_SESSION_VOUCHER;

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (sessionToken) headers['X-SCANPAY-SESSION'] = sessionToken;

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ source_code: code, language, auto_remediate: true }),
      });

      const data = await resp.json();
      const verdict = data?.execution_gate?.verdict || 'WARN';

      if (callback) {
        callback({
          text: `ScanPay Verdict: ${verdict}\nFindings: ${data.findings_count}\nAuto-Remediation Available: ${data.auto_remediation?.patches_available}`,
          content: data,
        });
      }
      return data;
    } catch (err: any) {
      if (callback) {
        callback({ text: `ScanPay audit failed: ${err.message}` });
      }
      return null;
    }
  },
  examples: [
    [
      {
        user: 'user',
        content: { text: 'Audit this script before running: eval(user_input)' },
      },
      {
        user: 'assistant',
        content: { text: 'Scanning with ScanPay...', action: 'SCAN_CODE_SECURITY' },
      },
    ],
  ],
};

export const scanPayProvider = {
  get: async (runtime: any, message: any, state: any) => {
    return {
      service: 'ScanPay Security Guardrail',
      status: 'active',
      supportedLanguages: ['python', 'javascript', 'typescript'],
      endpoint: 'https://scanpay-ob3w.onrender.com/v2/scan',
    };
  },
};

export const scanPayPlugin = {
  name: 'scanpay',
  description: 'Deterministic code security audits and execution gatekeeping with x402 micropayments.',
  actions: [SCAN_CODE_ACTION],
  providers: [scanPayProvider],
};

export default scanPayPlugin;
