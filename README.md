# Samar (Samar MCP Server)

[![GitHub Release](https://img.shields.io/github/v/release/hanifalkauni/samar-mcp?color=blue&logo=github)](https://github.com/hanifalkauni/samar-mcp/releases)
[![CI Build Status](https://github.com/hanifalkauni/samar-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/hanifalkauni/samar-mcp/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.25-00ADD8?logo=go)](https://golang.org)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-brightgreen.svg)](./SECURITY.md)

**English** | [Bahasa Indonesia](README.id.md)

---

Privacy & security middleware for the Model Context Protocol (MCP). Samar intercepts and masks sensitive credentials (API keys, passwords, private keys, database URLs, and `.env` variables) before they reach the LLM context (inbound), replacing them with deterministic reversible tokens backed by an in-memory ephemeral vault (zero-persistence). Outbound operations (file writes and command executions) safely restore tokens to real values while enforcing strict egress allowlists and fail-closed policies.

> **Version: v1.2.1** — Production-ready privacy middleware featuring inbound credential masking, fail-closed outbound restoration, network egress policy enforcement, human-in-the-loop confirmation (`off`, `elicit`, `deny`), and cryptographic HMAC audit logging.

---

## 🏗️ Data Flow & Architecture

*The following diagram illustrates the inbound path (sanitizing/masking secrets from local filesystem and environment variables before reaching LLM context via an in-memory vault) and outbound path (evaluating egress policy guard before unmasking tokens back to raw secrets for file writes or command execution).*

```mermaid
flowchart TD
    subgraph Client ["Client / LLM Agent"]
        LLM["AI Model / Chat Context"]
    end

    subgraph SamarEngine ["Samar MCP Server (stdio)"]
        direction TB
        subgraph Inbound ["Inbound Path (Read)"]
            SRF["samar_read_file"]
            SGE["samar_get_env"]
            DET["Detector Engine (Registry)<br/>DotEnv + Regex + Custom patterns<br/>+ Entropy (opt-in)"]
            MSK["Masking Engine"]
        end

        subgraph Outbound ["Outbound Path (Write/Exec)"]
            SWF["samar_write_file"]
            SEC["samar_execute_command"]
            POL["Egress & Policy Guard"]
            RST["Restorer (Fail-Closed)"]
        end

        SN["Safety-Net<br/>(final leak re-tokenize)"]
        VAULT[("In-Memory Ephemeral Vault\n(Zero-Persistence)")]
    end

    subgraph System ["Local System & Environment"]
        FS[("Filesystem (.env, configs)")]
        ENV["System Env Vars"]
        EXEC["Shell Execution"]
        NET["External Network / API"]
    end

    FS --> SRF
    ENV --> SGE
    SRF --> DET --> MSK --> SN --> LLM
    SGE --> DET --> MSK
    MSK <-->|"Tokenize (Random)"| VAULT
    SN <-->|"Scan + Re-Tokenize known secrets"| VAULT

    LLM --> SWF
    LLM --> SEC
    SEC --> POL
    POL -->|"Deny Non-Allowlist"| BLK["Blocked (Fail-Closed)"]
    POL -->|"Allowlist / Confirmed"| RST
    SWF --> RST
    RST <-->|"Detokenize"| VAULT
    SWF --> FS
    SEC --> EXEC --> NET
    EXEC -->|"stdout/stderr re-masked"| SN
```

---

## 🚀 Quickstart & Installation

Get protected in under 2 minutes:

### 1. Install Samar
Choose one method:

- **Via `go install` (Recommended):**
  ```bash
  go install github.com/hanifalkauni/samar-mcp/cmd/samar@latest
  ```
- **Pre-built Binary:** Download the executable for Linux, macOS, or Windows from [GitHub Releases](https://github.com/hanifalkauni/samar-mcp/releases/latest) (refer to `SHA256SUMS.txt` for verification) and place it in your `PATH`.
- **Zero Installation (`go run`):** Run setup or start the server directly without installing:
  ```bash
  go run github.com/hanifalkauni/samar-mcp/cmd/samar@latest setup all
  ```

### 2. Automated 1-Step Setup for your AI Agent / IDE
Run Samar's built-in idempotent setup command to automatically register the MCP server, install file deny rules, and configure agent steering:

```bash
samar setup claude-code   # Claude Code: settings.json deny rules, guard hook, CLAUDE.md
samar setup kiro          # Kiro IDE: mcp.json, permissions.yaml deny rules, steering
samar setup cursor        # Cursor IDE: mcp.json, .cursorrules & samar.mdc
samar setup antigravity   # Antigravity/Gemini: mcp_config.json, rules/samar.md
samar setup all           # Setup all supported AI clients in one command
```

### 3. Verify Protection (Quick Test)
Ensure your AI client cannot read raw secrets:
1. Create a dummy test `.env` file in your workspace:
   ```bash
   echo "TEST_SECRET=my_dummy_secret_token_123" > .env
   ```
2. In your AI agent (Claude Code, Cursor, Kiro, Antigravity), ask:
   > *"Read .env and tell me the secret"*
3. **Verify:** The agent outputs a masked token like `__SAMAR_SECRET_1__` instead of `my_dummy_secret_token_123`!

---

## 🔌 Manual Client Configuration (Alternative)

If you prefer to configure your client manually or use clients without automated setup (e.g., Claude Desktop), use the ready-to-use templates in [`docs/clients/`](./docs/clients/) (`kiro.mcp.json`, `cursor.mcp.json`, `claude.mcp.json`, `allowlist.example`).

#### Option 1: On-the-fly via `go run` (Zero Installation)
Runs Samar on-the-fly directly from the GitHub repository:
```json
{
  "mcpServers": {
    "samar": {
      "command": "go",
      "args": ["run", "github.com/hanifalkauni/samar-mcp/cmd/samar@latest"]
    }
  }
}
```

#### Option 2: Pre-installed Binary (in PATH)
```json
{
  "mcpServers": {
    "samar": {
      "command": "samar",
      "args": []
    }
  }
}
```

#### Option 3: Local Binary Path
```json
{
  "mcpServers": {
    "samar": {
      "command": "/path/to/samar",
      "args": []
    }
  }
}
```

> **Crucial Requirement for Manual Setup:** Enforce **selective-deny on built-in tools for sensitive files** (`.env`, `*.pem`, etc.) — see [`docs/CLIENT_CONFIG.md`](./docs/CLIENT_CONFIG.md). Without this step, client built-in tools can bypass Samar and read secrets directly (PRD §5.5). Dedicated step-by-step guide for Kiro: [`docs/KIRO_SETUP.md`](./docs/KIRO_SETUP.md).

---

## ✨ Features

### Inbound (M0)
- `samar_read_file(path)` — reads local file, masks sensitive secrets, returns sanitized content.
- `samar_get_env(env_var?)` — reads environment variables with masked values (variable keys remain visible).

### Outbound (M1)
- `samar_write_file(path, content)` — restores tokens back to original secrets before writing; **aborts** if tokens are corrupted or truncated (fail-closed).
- `samar_execute_command(command, cwd?)` — evaluates exfiltration policy **prior** to unmasking; unmasks and executes command; re-masks command output.
- **Exfiltration policy (§5.6):** tokens destined for external hosts not on the allowlist are blocked (fail-closed).
- **Multi-layer egress allowlist (§13.3):** `global ∪ per-project`, hot lazy-reloading without restarts (§13.5).

### Core Engine
- Two-way in-memory token↔secret vault, using **cryptographically random** tokens (not value hashes) with reverse-mapping for session determinism.
- Detectors: `.env*` parser (masks all values) + regex rule-set (AWS, GitHub, OpenAI, Slack, Stripe, Google, JWT, database URIs, private keys, generic assignments).
- **Custom patterns (user-defined, hot-reload):** add your own secret formats via a plain-text config file — no rebuild needed. One regex per line; `#` lines and blank lines are ignored. If a pattern defines a named `secret` capture group, only that group is masked (otherwise the whole match). Invalid patterns are skipped without disabling the rest, and an unreadable file keeps the previously loaded patterns (fail-safe). Changes are picked up automatically (lazy mtime check every 5s), same mechanism as the egress allowlist.
  - Global: `~/.samar/patterns` (fallback: `~/.safeenv/patterns`)
  - Per-project: `./.samar/patterns` (fallback: `./.safeenv/patterns`)
  - Example `patterns` file:
    ```text
    # Internal deploy token: ACME- followed by 10 digits
    ACME-[0-9]{10}
    # Mask only the value after "internal_key:"
    internal_key:\s*(?P<secret>[A-Z0-9]{8,})
    ```
- **Entropy detection (opt-in, `SAMAR_ENTROPY=1`):** an extra net for *bare* high-entropy tokens that carry no keyword (so Regex misses them) and live outside `.env` (so DotEnv misses them). Uses Shannon entropy over whitespace-delimited words, with conservative guards (length bounds, skips UUIDs, pure digits, natural-language words). **Off by default** because it can raise false positives on hashes/UUIDs/base64 blobs; enable it when you prioritize recall.
- **PII detection (opt-in, `SAMAR_PII=1`):** catches personal data that isn't a technical secret — email addresses, credit-card numbers (validated with the Luhn algorithm), IBANs (validated with mod-97), and IPv4 addresses (octet-range checked). **Off by default** because PII patterns are more false-positive-prone; the structural validation (Luhn/mod-97/octet range) keeps most noise out.
- **Runtime leak safety-net (always on):** a final verification before any tool result is returned to the LLM. It scans the output for any secret the vault already knows and, if one slipped through on a different path, **re-tokenizes it** using the same vault token (patching, not just failing). A patched leak is recorded in the audit log as `leak_patched`.

---

## ⚙️ Environment Variables

| Variable | Values / Options | Default | Description |
| :--- | :--- | :--- | :--- |
| `SAMAR_AUDIT_DIR` | Directory path | `~/.samar/audit/<project-slug>-<hash8>/` | Custom audit log directory. Files and directories are created lazily upon the first logged event (idle sessions produce 0 files). (Backward-compatible fallback: `SAFEENV_AUDIT_DIR`). |
| `SAMAR_STRICT_ALLOWLIST` | `1` / `0` | `0` (union) | When set to `1`, per-project allowlist narrows the global allowlist (`global ∩ project`). Default: union merge (`global ∪ project`). (Backward-compatible fallback: `SAFEENV_STRICT_ALLOWLIST`). |
| `SAMAR_REQUIRE_CONFIRM` | `""`, `"off"`, `"elicit"`, `"deny"` | `""` (off) | Human-in-the-loop confirmation before outbound network calls containing unmasked secrets:<br>• `""` / `"off"`: auto-approve if destination host is in allowlist (warning logged to stderr).<br>• `"elicit"`: request interactive approval via MCP elicitation (fail-closed if client lacks support).<br>• `"deny"`: reject all network commands containing tokens.<br>(Backward-compatible fallback: `SAFEENV_REQUIRE_CONFIRM`). |
| `SAMAR_ENTROPY` | `1` / `0` | `0` (off) | When `1`, enables opt-in Shannon-entropy detection of bare high-entropy tokens (no keyword, non-`.env`). May increase false positives on hashes/UUIDs/base64. (Backward-compatible fallback: `SAFEENV_ENTROPY`). |
| `SAMAR_PII` | `1` / `0` | `0` (off) | When `1`, enables opt-in PII detection: email, credit card (Luhn), IBAN (mod-97), IPv4 (octet range). May increase false positives. (Backward-compatible fallback: `SAFEENV_PII`). |

---

## 🏛️ Architecture (SOLID)

Every component depends on **interfaces**, not concrete types; implementations are wired strictly in `cmd/samar/main.go`.

```text
cmd/samar              composition root — sole dependency wiring location
internal/vault         in-memory secret↔token storage (SRP)
internal/idgen         TokenGenerator backed by crypto/rand
internal/detector      Detector interface + Registry (ISP, OCP) + dotenv, regex, custom (hot-reload), entropy & PII (opt-in)
internal/masking       Masking Engine: detect→tokenize→replace, depends on abstractions (DIP)
internal/restore       Restorer: token→secret, fail-closed on corrupt tokens (M1)
internal/policy        Exfiltration & confused-deputy policy, fail-closed (M1)
internal/allowlist     Layered egress allowlist + hot lazy reload (M1)
internal/leakscan      Runtime safety-net: scan tool output + re-tokenize known leaks
internal/safeio        FileReader/EnvReader/FileWriter/CommandRunner abstractions (DIP)
internal/server        MCP tool registration & dispatch handlers (DIP)
```

---

## 📂 Repository Structure

```text
samar-mcp/
├── cmd/
│   └── samar/               # Composition root & MCP binary entry point
├── internal/
│   ├── allowlist/           # Multi-layer egress allowlist & lazy reload
│   ├── audit/               # JSONL audit logger with HMAC / hash-chaining
│   ├── detector/            # Secret scanner (DotEnv parser & Regex rulesets)
│   ├── idgen/               # Random token ID generator (crypto/rand)
│   ├── masking/             # Inbound sanitization engine (detect -> tokenize -> replace)
│   ├── policy/              # Egress exfiltration guard & confused-deputy policy
│   ├── restore/             # Outbound unmask engine with fail-closed integrity checks
│   ├── safeio/              # I/O abstractions (FileReader, EnvReader, CommandRunner)
│   ├── server/              # MCP tool registration and request handlers
│   └── vault/               # Two-way in-memory secret ↔ token store
├── docs/
│   ├── clients/             # Pre-configured client configs (Kiro, Cursor, Claude)
│   ├── BYPASS_TEST.md       # Manual canary bypass-prevention testing guide
│   ├── CLIENT_CONFIG.md     # Setup guide for selective-deny on built-in tools
│   └── PRD.md               # Historical design rationale document (frozen)
├── scripts/                 # Multi-platform release build automation scripts
└── test/
    └── canary/              # Canary test harness verifying masking boundaries
```

---

## 🧪 Build & Test

```bash
go build -o bin/samar ./cmd/samar       # compile binary
go test -race ./...                      # unit tests with race detector
go vet ./...
```

**Canary harness** — concretely verifies protection boundaries (plants unique markers across diverse file types, exercises Samar tools via MCP, and verifies zero unexpected leaks):
```bash
go build -o bin/samar ./cmd/samar
go run ./test/canary        # exit 0 = no unexpected leaks
```
The harness reports `PROTECTED` / `EXPECTED-LEAK` (design limits) / `UNEXPECTED-LEAK` per fixture. **Note:** this validates masking on requests that PASS THROUGH Samar (Layer 1) — not that the client cannot read files using its built-in tools (Layer 2 / bypass). To test bypass prevention on actual clients, follow [`docs/BYPASS_TEST.md`](./docs/BYPASS_TEST.md).

---

## 🔒 Security Model

- **Zero-Persistence:** Vault is strictly in-memory; completely destroyed upon process termination. No MCP tool exists to unmask values from the LLM side.
- **Anti-Brute Force:** Random tokens do not leak original secret contents or hashes.
- **DoS Guard:** Files exceeding 10 MB are rejected with controlled error handling.

---

## ❓ FAQ & Troubleshooting

<details>
<summary><b>What happens if an LLM truncates or corrupts a secret token?</b></summary>

Samar enforces a strict **fail-closed** policy. If an AI model mutates or truncates a placeholder token (e.g. `__SAMAR_SEC...` instead of a known valid token), `samar_write_file` and `samar_execute_command` immediately abort the operation and return an error to prevent file corruption or broken secrets.
</details>

<details>
<summary><b>Why can my AI assistant still read raw secrets from my .env file?</b></summary>

Ensure you have configured **selective-deny** on your AI client's built-in file reading tools (such as `fs_read` or `Read`). If the AI invokes its native read tool, files are read directly without passing through Samar. Follow the setup instructions in [`docs/CLIENT_CONFIG.md`](./docs/CLIENT_CONFIG.md).
</details>

<details>
<summary><b>Do I need to restart Samar when modifying the allowlist?</b></summary>

No. Samar utilizes automatic *hot lazy reloading* (checked every 5 seconds via file `mtime`) for both global (`~/.samar/allowlist`) and project-level (`./.samar/allowlist`) allowlists.
</details>

<details>
<summary><b>Are raw secrets recorded in the audit logs?</b></summary>

No. Session audit logs are stored in `~/.samar/audit/<project-slug>-<hash8>/<timestamp>.jsonl` (or custom directory via `SAMAR_AUDIT_DIR`) with cryptographic hash-chaining (HMAC/hash-chain). Files and directories are created lazily only when audit events occur, preventing repository pollution. They only record event metadata (event type, tool name, policy decision, reason, actor, and token identifier) — raw secrets are never written.
</details>

## 🤝 Contributing & Security

- **Contributing**: Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for local development guidelines, testing workflows, and pull request procedures.
- **Security Policy**: For vulnerability disclosure and security scope, refer to [SECURITY.md](./SECURITY.md).

---

## 📄 License

SPDX-License-Identifier: MIT

This project is licensed under the [MIT License](./LICENSE).
