#!/usr/bin/env node

/**
 * ScanPay MCP Server
 * Model Context Protocol server for AI agents to scan code for security vulnerabilities.
 * Agents discover this via MCP registry and use it to scan code before execution.
 */

const http = require('http');
const readline = require('readline');

const DEFAULT_URL = process.env.SCANPAY_URL || 'http://localhost:8484';

// MCP protocol implementation
class ScanPayMCP {
  constructor() {
    this.tools = [
      {
        name: 'scan_code',
        description: 'Scan source code for security vulnerabilities. Returns list of findings with severity, line numbers, and descriptions. Supports Python and JavaScript/TypeScript.',
        inputSchema: {
          type: 'object',
          properties: {
            source_code: { type: 'string', description: 'The source code to scan' },
            language: { type: 'string', enum: ['python', 'javascript', 'typescript'], description: 'Programming language' }
          },
          required: ['source_code', 'language']
        }
      },
      {
        name: 'list_products',
        description: 'List available ScanPay products and their prices.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'health_check',
        description: 'Check ScanPay service health and payment mode.',
        inputSchema: { type: 'object', properties: {} }
      }
    ];
  }

  async handleRequest(method, params, id) {
    try {
      switch (method) {
        case 'initialize':
          return { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'scanpay', version: '0.1.0' } };
        
        case 'tools/list':
          return { tools: this.tools };
        
        case 'tools/call':
          return await this.callTool(params);
        
        default:
          return { error: { code: -32601, message: `Unknown method: ${method}` } };
      }
    } catch (e) {
      return { error: { code: -32603, message: e.message } };
    }
  }

  async callTool(params) {
    const { name, arguments: args } = params;
    
    switch (name) {
      case 'scan_code':
        return await this.scanCode(args.source_code, args.language);
      case 'list_products':
        return await this.listProducts();
      case 'health_check':
        return await this.healthCheck();
      default:
        return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }
  }

  async scanCode(sourceCode, language) {
    return new Promise((resolve) => {
      const data = JSON.stringify({ source_code: sourceCode, language });
      const url = new URL('/api/v1/scan', DEFAULT_URL);
      
      const options = {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
      };

      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => {
          if (res.statusCode === 402) {
            const payment = JSON.parse(body);
            resolve({
              content: [{ 
                type: 'text', 
                text: `Payment required: ${payment.paymentRequirements.amount_display} to ${payment.paymentRequirements.recipient}. Send payment and retry with X-PAYMENT header.` 
              }],
              isError: false
            });
          } else {
            resolve({ content: [{ type: 'text', text: body }], isError: false });
          }
        });
      });
      req.on('error', (e) => resolve({ content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }));
      req.write(data);
      req.end();
    });
  }

  async listProducts() {
    return new Promise((resolve) => {
      http.get(`${DEFAULT_URL}/api/v1/products`, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => resolve({ content: [{ type: 'text', text: body }], isError: false }));
      }).on('error', (e) => resolve({ content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }));
    });
  }

  async healthCheck() {
    return new Promise((resolve) => {
      http.get(`${DEFAULT_URL}/api/v1/health`, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => resolve({ content: [{ type: 'text', text: body }], isError: false }));
      }).on('error', (e) => resolve({ content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }));
    });
  }
}

// JSON-RPC over stdio
const mcp = new ScanPayMCP();
const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    mcp.handleRequest(msg.method, msg.params, msg.id).then((result) => {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }) + '\n');
    });
  } catch (e) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
  }
});