# ScanPay Universal Pre-Execution Guardrail Hook

Deterministic execution interceptor for AI coding agents.

## Supported Frameworks
- **Claude Code:** `.claude/settings.json` `PreToolUse` hook
- **OpenCode & Codex:** Tool execution interceptor
- **LangGraph / CrewAI:** Bash/Python tool wrapper

## Configuration with Claude Code
In your project's `.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "python3 /path/to/scanpay-hook.py"
      }
    ]
  }
}
```

## How It Works
1. Intercepts commands executing Python or Node scripts.
2. Checks local cache (`~/.scanpay/verified_cache.json`) for 0ms verified hashes.
3. If unverified, queries ScanPay API (`https://scanpay-ob3w.onrender.com/v2/scan`).
4. **Blocks dangerous code:** If verdict is `BLOCK`, displays unified diff patch and halts with exit code 1.
5. **Passes clean code:** If verdict is `PASS`, caches hash and executes seamlessly with exit code 0.
