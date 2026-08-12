# scanpay

> Code security scanner with x402 v2 micropayments — scan Python/JS/TS for vulnerabilities before execution.

## Install

```bash
npm install -g scanpay
```

## Usage

```bash
# Scan a file
scanpay scan --file dangerous.py --lang python

# Scan inline code
scanpay scan --code "eval(userInput)" --lang python

# Scan from stdin
echo "eval(userInput)" | scanpay scan --lang python

# Check API health
scanpay health

# List available products
scanpay products
```

## How It Works

1. ScanPay sends your code to the ScanPay API
2. API returns `402 Payment Required` with Solana payment details
3. Pay 0.0007 SOL (~$0.10) to the merchant wallet
4. Retry with payment proof → get vulnerability report

## Detected Vulnerabilities

### Python
- `eval()` / `exec()` — code injection
- `subprocess(shell=True)` — command injection  
- `pickle.loads()` — deserialization
- `os.system()` — command injection
- SQL injection, path traversal, hardcoded credentials

### JavaScript/TypeScript
- `eval()` — code injection
- `innerHTML` — XSS
- `document.write()` — XSS
- `new Function()` — code injection
- Prototype pollution, SQL injection

## License

MIT