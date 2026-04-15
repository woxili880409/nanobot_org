# Security Features — Implementation Guide

> This document describes the security hardening features implemented in this branch (`my_dev`).

**Last Updated**: 2026-04-13

---

## Overview

This implementation adds five security layers to `nanobot_org`, closing the gaps identified against the reference project:

| Feature | Status | File |
|---------|--------|------|
| SSRF Protection | ✅ Pre-existing | `nanobot/security/network.py` |
| Log Sanitization | ✅ New | `nanobot/security/logging.py` |
| Session Encryption (AES-256-GCM) | ✅ New | `nanobot/security/encryption.py` |
| Transport Encryption (MessageBus) | ✅ New | `nanobot/security/encryption.py` |
| File Permission Control | ✅ New | `nanobot/security/file_permissions.py` |
| API Server Bearer Token Auth | ✅ New | `nanobot/api/server.py` |
| SecurityConfig Schema | ✅ New | `nanobot/config/schema.py` |

---

## 1. Log Sanitization (`nanobot/security/logging.py`)

**Purpose**: Strip sensitive data (API keys, tokens, PII) from log output before it reaches loguru sinks.

### Patterns Redacted

| Pattern | Replacement |
|---------|-------------|
| `api_key=sk-xxxxx`, `token=ghp_xxxxx`, `password=xxx` | `***REDACTED***` |
| Email addresses | `***@***.***` |
| Chinese mobile (+86 13800138000) | `***-****-****` |
| North American phone (NXX-NXX-XXXX) | `***-****-****` |
| IPv4 addresses | `*.*.*.*` |
| Bank card / ID card numbers (15–19 digits) | `****-****-****-****` |
| Telegram Bot Tokens (`123456789:AABBcc...`) | `***TELEGRAM_TOKEN***` |

### Usage

```python
from nanobot.security.logging import LogSanitizer

# Standalone sanitization
sanitized = LogSanitizer.sanitize("api_key=sk-abcdef1234567890")
# → "api_key=***REDACTED***"

# Loguru filter (in-place modification)
from loguru import logger
logger.remove()
logger.add(sys.stderr, filter=LogSanitizer.loguru_filter)
```

### Configuration

```json
{
  "security": {
    "enable_log_sanitization": true
  }
}
```

Default: **enabled** (`true`).

---

## 2. Session Encryption (`nanobot/security/encryption.py` + `session/manager.py`)

**Purpose**: Encrypt conversation history at rest in JSONL session files using AES-256-GCM.

### How It Works

- **Algorithm**: AES-256-GCM (authenticated encryption — detects tampering)
- **Key**: 32-byte random key, base64-encoded. Set via `NANOBOT_ENCRYPTION_KEY` env var or `security.encryption_key` config field.
- **Encrypted roles**: `user` and `assistant` messages are encrypted; `system` and `tool` messages remain plaintext (they contain instructions and are needed for session loading context).
- **Format**: Each encrypted message is stored as a dict with `_encrypted: true`, `_encryption_version: "1.0"`, and a `content` field containing `base64(nonce + ciphertext + tag)`.

### Generating a Key

```bash
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

### Configuration

```json
{
  "security": {
    "enable_session_encryption": true,
    "encryption_key": ""        // Leave empty to use NANOBOT_ENCRYPTION_KEY env var
  }
}
```

Default: **disabled** (`false`). Key should be set via environment variable in production.

### Integration Points

- `SessionManager.save()` encrypts messages before writing to disk
- `SessionManager._load()` decrypts messages after reading from disk
- Original message dicts are never mutated

---

## 3. Transport Encryption (`nanobot/security/encryption.py` + `bus/queue.py`)

**Purpose**: Encrypt messages passing through the in-process `MessageBus` queue so that they are opaque in memory.

### How It Works

- **Algorithm**: AES-256-GCM
- **Key**: Set via `NANOBOT_TRANSPORT_KEY` env var or `security.transport_key` config field.
- **Scope**: Encrypts only `InboundMessage.content`; channel/sender_id metadata remains plaintext for routing.
- **Storage**: Encrypted content + GCM tag stored as base64; IV/nonce stored in message `metadata` dict.

### Configuration

```json
{
  "security": {
    "enable_transport_encryption": true,
    "transport_key": ""         // Leave empty to use NANOBOT_TRANSPORT_KEY env var
  }
}
```

Default: **disabled** (`false`).

### Integration Points

- `MessageBus.publish_inbound()` encrypts before enqueuing
- `MessageBus.consume_inbound()` decrypts after dequeued
- The `transport_encryption` parameter is passed at construction time

---

## 4. File Permission Control (`nanobot/security/file_permissions.py`)

**Purpose**: Restrict file permissions on sensitive workspace files (configs, keys, session data).

### Protected Patterns

**File extensions**: `*.json`, `*.key`, `*.pem`, `*.env`, `*.txt`, `*.log`
**Directories**: `.nanobot`, `secret`, `sessions`, `workspace`

### Behavior

| Platform | Action |
|----------|--------|
| Unix/Linux/macOS | Files → `0o600` (owner read-write only), Directories → `0o700` |
| Windows | Skipped (no-op, logs debug message) |

### Usage

```python
from nanobot.security.file_permissions import FilePermissionManager

mgr = FilePermissionManager()
count = mgr.protect_workspace(Path("/path/to/workspace"))
# Returns number of files protected
```

### Configuration

```json
{
  "security": {
    "secure_file_permissions": true
  }
}
```

Default: **enabled** (`true`). Automatically called during gateway startup on the workspace directory.

---

## 5. API Server Bearer Token Authentication (`nanobot/api/server.py`)

**Purpose**: Protect the OpenAI-compatible `/v1/chat/completions` and `/v1/models` endpoints with HTTP Bearer token authentication.

### Behavior

- When `security.api_bearer_token` is **empty** (default): endpoints are **unauthenticated** (no protection)
- When `security.api_bearer_token` is **set**: all `/v1/*` requests must include `Authorization: Bearer <token>`
- `/health` endpoint is always unauthenticated
- Failed auth returns `401 Unauthorized` with JSON error body

### Configuration

```json
{
  "security": {
    "api_bearer_token": "your-secret-token-here"
  }
}
```

Or via environment variable:
```bash
export NANOBOT_SECURITY__API_BEARER_TOKEN="your-secret-token-here"
```

### Usage

```bash
# Without token → 401
curl http://localhost:8900/v1/models

# With token → 200
curl -H "Authorization: Bearer your-secret-token-here" http://localhost:8900/v1/models
```

### Endpoint Summary

| Endpoint | Auth Required |
|----------|---------------|
| `GET /health` | No |
| `GET /v1/models` | Only if `api_bearer_token` set |
| `POST /v1/chat/completions` | Only if `api_bearer_token` set |

---

## 6. SecurityConfig Schema (`nanobot/config/schema.py`)

All security features are configured under the `security` key in the config:

```python
class SecurityConfig(Base):
    enable_log_sanitization: bool = True
    sanitization_patterns: list[str] = Field(default_factory=list)
    enable_session_encryption: bool = False
    encryption_key: str = ""
    enable_transport_encryption: bool = False
    transport_key: str = ""
    secure_file_permissions: bool = True
    api_bearer_token: str = ""
```

Priority for encryption keys: **Environment variable > Config file value**

| Feature | Env Var |
|---------|---------|
| Session encryption key | `NANOBOT_ENCRYPTION_KEY` |
| Transport encryption key | `NANOBOT_TRANSPORT_KEY` |
| API Bearer token | `NANOBOT_SECURITY__API_BEARER_TOKEN` |

---

## 7. CLI Startup Integration (`nanobot/cli/commands.py`)

Security features are initialized in this order during `gateway` startup:

1. **Log Sanitization** — Applied to all log output immediately after config load
2. **File Permission Protection** — Scans and secures workspace files
3. **Transport Encryption** — Passed to `MessageBus` constructor
4. **Session Encryption** — Passed to `SessionManager` constructor

---

## File Summary

| Action | File |
|--------|------|
| New | `nanobot/security/encryption.py` |
| New | `nanobot/security/logging.py` |
| New | `nanobot/security/file_permissions.py` |
| Modified | `nanobot/security/__init__.py` |
| Modified | `nanobot/config/schema.py` |
| Modified | `nanobot/session/manager.py` |
| Modified | `nanobot/bus/queue.py` |
| Modified | `nanobot/cli/commands.py` |
| Modified | `nanobot/api/server.py` |
| Modified | `pyproject.toml` (+ `cryptography>=44.0.0`) |
| New | `tests/security/test_security_encryption.py` |

---

## PowerShell Setup Scripts (`secret/`)

All scripts require **PowerShell 5.0+** (Windows PowerShell 5.1 or PowerShell 7).

> **Important**: The `secret/` directory is excluded from version control (via `.gitignore`). Never commit real keys or tokens.

---

### 1. `generate_keys.ps1` — Quick Key Generation

**Purpose**: Generate a random AES-256 key pair (session + transport) and print them to stdout.

```powershell
.\secret\generate_keys.ps1
```

Output:
```
NANOBOT_ENCRYPTION_KEY = <base64 44-char key>
NANOBOT_TRANSPORT_KEY  = <base64 44-char key>
```

No environment variables are set — keys are only displayed. Use the printed commands to set them manually.

---

### 2. `setup_encryption.ps1` — Interactive Encryption Setup Wizard

**Purpose**: Full-featured wizard for key generation, environment variable setup, and backup.

```powershell
.\secret\setup_encryption.ps1           # Interactive (default)
.\secret\setup_encryption.ps1 -GenerateOnly  # Keys only, no env set
.\secret\setup_encryption.ps1 -Backup        # Backup current keys to file
.\secret\setup_encryption.ps1 -Status        # Show key status (masked)
```

**Interactive mode flow**:
1. Detects existing keys → prompts for backup
2. Generates two new 256-bit keys
3. Confirms before writing to user-level environment variables
4. Prints sample `config.json` snippet to enable the features

**Backup mode**: Saves current keys to `secret/keys_backup_<timestamp>.txt` with a note to store it securely. The file ACL is locked to the current user.

---

### 3. `security-check.ps1` — Security Configuration Checker

**Purpose**: Diagnose the current security posture — checks keys, config file, session encryption status, and Python dependencies.

```powershell
.\secret\security-check.ps1
```

Checks performed:
| Check | PASS | WARN | FAIL |
|-------|------|------|------|
| `NANOBOT_ENCRYPTION_KEY` valid (32 bytes, base64) | ✅ | not set | wrong length / invalid base64 |
| `NANOBOT_TRANSPORT_KEY` valid | ✅ | not set | wrong length / invalid base64 |
| `config.json` exists | ✅ | not found | — |
| `security.enableLogSanitization` | ✅ enabled | disabled | — |
| `security.enableSessionEncryption` | ✅ enabled | **disabled** | — |
| `security.enableTransportEncryption` | ✅ enabled | disabled | — |
| `security.secureFilePermissions` | ✅ enabled | disabled | — |
| `sessions/*.jsonl` encryption status | ✅ encrypted | **plaintext** | — |
| `cryptography` Python library | ✅ installed | — | **not installed** |

Exit advice: Run `setup_encryption.ps1` to fix failures/warnings.

---

### 4. `secret_envs.ps1` — Environment Variable Template

**Purpose**: Editable template for setting all sensitive environment variables in one place.

```powershell
notepad .\secret\secret_envs.ps1   # 1. Fill in real values
.\secret\secret_envs.ps1           # 2. Run to set env vars
```

Variables supported:
```
NANOBOT_ENCRYPTION_KEY
NANOBOT_TRANSPORT_KEY
NANOBOT_PROVIDERS__ANTHROPIC__API_KEY
NANOBOT_PROVIDERS__OPENAI__API_KEY
NANOBOT_PROVIDERS__OPENROUTER__API_KEY
NANOBOT_PROVIDERS__DEEPSEEK__API_KEY
NANOBOT_PROVIDERS__GROQ__API_KEY
TELEGRAM_BOT_TOKEN
```

Only non-empty values that don't match `REPLACE_WITH_*` are set. File is gitignored.

---

### 5. `start-secure.ps1` — Secure Gateway Launcher

**Purpose**: Run `nanobot gateway` only after validating that security prerequisites are met.

```powershell
.\secret\start-secure.ps1                # Basic launch
.\secret\start-secure.ps1 -- --config ..\config.json   # With args
```

Pre-flight checks:
- `NANOBOT_ENCRYPTION_KEY` is set (warns if missing — sessions will be plaintext)
- `NANOBOT_TRANSPORT_KEY` is set (warns if missing)
- `cryptography` library is importable (hard fail — exits if missing)

Behavior:
- All checks pass → launches directly
- Non-blocking warnings (missing keys) → prompts for confirmation before launch
- Hard failure (missing `cryptography`) → exits with error before attempting to run

---

### Quick-Start Checklist

```powershell
# Step 1: Generate keys
.\secret\generate_keys.ps1

# Step 2: Interactive setup (set env vars + backup)
.\secret\setup_encryption.ps1

# Step 3: Verify configuration
.\secret\security-check.ps1

# Step 4: Launch gateway (with security checks)
.\secret\start-secure.ps1
```

Or for a faster flow without interaction:
```powershell
.\secret\setup_encryption.ps1 -GenerateOnly   # Print keys
# (manually set the two env vars)
.\secret\security-check.ps1                    # Validate
.\secret\start-secure.ps1                     # Launch
```

---

## Running Tests

```bash
# Install dependencies
cd D:\AiTools\nanobot_org
uv sync

# Run all security tests
uv run python -m pytest tests/security/ -v
```

Expected: **42 passed, 2 skipped** (Windows skips Unix-only chmod tests).

---

## Not in Scope (Future Work)

- Docker seccomp/AppArmor profile tightening
- Rate limiting on API Server
- Config file keyring integration (OS credential manager)
- Automatic key rotation
