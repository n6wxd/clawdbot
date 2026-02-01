---
summary: "CLI reference for `openclaw security` (audit and fix common security footguns)"
read_when:
  - You want to run a quick security audit on config/state
  - You want to apply safe “fix” suggestions (chmod, tighten defaults)
title: "security"
---

# `openclaw security`

Security tools (audit + optional fixes).

Related:

- Security guide: [Security](/gateway/security)

## Audit

```bash
openclaw security audit
openclaw security audit --deep
openclaw security audit --fix
```

The audit warns when multiple DM senders share the main session and recommends `session.dmScope="per-channel-peer"` (or `per-account-channel-peer` for multi-account channels) for shared inboxes.
It also warns when small models (`<=300B`) are used without sandboxing and with web/browser tools enabled.

## Plugin Security (skill-guardian)

OpenClaw includes a security verification module for plugins that detects malicious patterns, verifies content hashes, and validates signatures.

### Configuration

```json5
{
  plugins: {
    security: {
      mode: "permissive",      // "strict" | "permissive" | "off"
      trustBundled: true,      // Trust bundled plugins implicitly
      enableScanning: true,    // Enable static analysis
      audit: {
        enabled: true,         // Enable audit logging
        retention: 90,         // Days to retain logs
      },
    },
  },
}
```

Security modes:

- `strict`: Block unsigned plugins (except bundled). Recommended for production.
- `permissive` (default): Warn but allow unsigned plugins.
- `off`: No verification (not recommended).

### What it detects

The scanner checks for malicious patterns including:

- **Credential exfiltration**: Access to `.env`, `.ssh`, `.aws/credentials`, `process.env`
- **Code execution**: `eval()`, `new Function()`, `child_process`, dynamic imports
- **Network exfiltration**: Requests to webhook.site, requestbin, pipedream
- **Obfuscation**: Base64 encoding, computed property access, Unicode escapes
- **Persistence**: Modifications to `.bashrc`, `.zshrc`, crontab
- **Prompt injection**: Attempts to override system instructions

### Audit logs

Security events are logged to `~/.openclaw/audit/plugins.jsonl` (JSON Lines format).

View recent events:

```bash
tail -n 50 ~/.openclaw/audit/plugins.jsonl | jq .
```

### Trust levels

Plugins are assigned trust levels based on verification:

1. `unsigned`: No security metadata
2. `hashed`: Content hash verified
3. `signed`: Signature verified with trusted key
4. `verified`: Full verification chain passed

See [Plugins](/plugin#plugin-security-skill-guardian) for full documentation.
