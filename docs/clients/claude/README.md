# Claude Code Integration Guide

This guide ensures **100% automated credential masking** in **Claude Code**, completely closing the agent bypass hole where Claude Code might reach for built-in tools (`Read` or `Bash cat .env`).

---

## ⚡ Option 1: Automated 1-Step Setup (Recommended)

Samar provides an automated CLI command that configures Claude Code idempotently:

```bash
samar setup claude-code
```

### What this command does:
1. **Registers MCP Server**: Runs `claude mcp add --scope user samar -e SAMAR_STRICT_ALLOWLIST=0 -- <binary_path>` (or writes to `~/.claude.json`).
2. **Backs up Existing Settings**: Creates `~/.claude/settings.json.bak.<timestamp>` before any changes.
3. **Installs Secret-Guard Hook**: Places `~/.claude/hooks/guard-secrets.py` (executable mode `0755`).
4. **Applies Glob Deny Rules & Hooks**: Safely merges `permissions.deny` (`**/.env`, `**/*.pem`, etc.) and `hooks.PreToolUse` for `Bash` into `~/.claude/settings.json`.
5. **Appends Agent Instructions**: Appends the secret routing instructions to `~/.claude/CLAUDE.md`.

---

## 🛠️ Option 2: Manual Setup

If you prefer configuring Claude Code manually, follow these four steps:

### Step 1: Register Samar MCP Server
Claude Code does **not** read `mcpServers` from `~/.claude/settings.json`. Register it using the Claude CLI:

```bash
claude mcp add --scope user samar -e SAMAR_STRICT_ALLOWLIST=0 -- /ABS/PATH/samar
```

Or for a single project, place [`.mcp.json`](./.mcp.json) at your project root:
```json
{
  "mcpServers": {
    "samar": {
      "command": "/ABS/PATH/samar",
      "args": [],
      "env": {
        "SAMAR_STRICT_ALLOWLIST": "0"
      }
    }
  }
}
```

Verify the server connection:
```bash
claude mcp get samar   # -> Status: ✔ Connected
```

### Step 2: Install the Bash Secret-Guard Hook
Save [`guard-secrets.py`](./guard-secrets.py) to `~/.claude/hooks/guard-secrets.py`:

```bash
mkdir -p ~/.claude/hooks
cp guard-secrets.py ~/.claude/hooks/guard-secrets.py
chmod +x ~/.claude/hooks/guard-secrets.py
```

### Step 3: Configure `~/.claude/settings.json`
Merge the following into `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Edit(**/.env)",
      "Edit(**/.env.*)",
      "Write(**/.env)",
      "Write(**/.env.*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 $HOME/.claude/hooks/guard-secrets.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

### Step 4: Add Instructions to `~/.claude/CLAUDE.md`
Append the contents of [`CLAUDE.md`](./CLAUDE.md) to `~/.claude/CLAUDE.md` (or to your project's `CLAUDE.md`). This ensures that Claude Code and any subagents it spawns automatically choose `mcp__samar__*` tools without requiring the user to explicitly remind the agent in every prompt.

---

## 🧪 Verification Matrix

| Action | Built-in Behavior | With Samar Guard Hook |
| :--- | :--- | :--- |
| `cat .env`, `grep KEY .env.local` | ⚠️ Leaks plain secret | 🛑 Denied → auto-redirected to `mcp__samar__samar_read_file` |
| `source ./.env && npm run dev` | ⚠️ Leaks plain secret | 🛑 Denied → auto-redirected to `mcp__samar__samar_execute_command` |
| `cat ~/.ssh/id_rsa` | ⚠️ Leaks private key | 🛑 Denied |
| `cat .env.example` | Allowed | ✅ Allowed (safe template) |
| Normal code edits & tests | Allowed | ✅ Allowed |
