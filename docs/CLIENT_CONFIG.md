# Client Configuration — Closing the Bypass Path (PRD §5.5 / §13.1)

**English** | [Bahasa Indonesia](./CLIENT_CONFIG.id.md)

> **A hard requirement, not optional.** Samar's security guarantee is **void** if
> the AI client can still read files / run commands through its built-in tools.
> If the LLM calls the built-in `fs_read`/`execute_bash` instead of Samar's tools,
> secrets never pass through the masking engine and leak as-is.

Goal: ensure **all** file & shell I/O goes through Samar's tools
(`samar_read_file`, `samar_get_env`), and the client's **built-in** I/O tools are
disabled.

## Principle

| Path | Desired state |
| --- | --- |
| `samar_read_file`, `samar_get_env`, `samar_write_file`, `samar_execute_command` (Samar) | **ACTIVE** |
| Built-in read tool (`fs_read`/`Read`) on sensitive files | **DENY** (force through Samar) |
| Built-in write tool (`fs_write`/`Write`/`Edit`) on sensitive files | **DENY** |
| Built-in exec tool (`shell`/`Bash`/`execute_bash`) | **DENY/Supervised** (route to `samar_execute_command`) |

## Registering the Samar server (file locations verified Oct 2026)

Build first: `go build -o bin/samar ./cmd/samar`. Ready-to-use templates live in
`docs/clients/` (`kiro.mcp.json`, `cursor.mcp.json`, `claude.mcp.json`).

| Client | Config location | Disable/approve field | Env syntax |
| --- | --- | --- | --- |
| **Kiro** | `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (user) | `disabled`, `autoApprove`, `disabledTools` | `${VAR}` |
| **Cursor** | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) | none (configure in UI Settings) | `${env:VAR}` |
| **Claude Code** | `~/.claude/settings.json` → `mcpServers` | none (permission settings) | `${env:VAR}` |

The base shape is the same across all three: `mcpServers.<name>.{command,args,env}`.

### Disabling / restricting built-in tools — per-client steps

The mechanism differs per client (verified Oct 2026). A realistic note:
**fully denying** `fs_read`/Read will cripple the agent (it can't read code).
The practical approach: **deny built-in tools specifically for sensitive
files/paths** (`.env`, `*.pem`, `*.key`, secret dirs) so the agent is forced to
use Samar for those, then route execution through `samar_execute_command`. For
full isolation (deny all built-in read/write/exec), only do it if the agent is
truly meant to do I/O exclusively through Samar.

#### Kiro — `permissions.yaml` (deny-overrides)

Location: `~/.kiro/settings/permissions.yaml` (user) or workspace-scope.
`deny` always wins over `allow`. Capabilities: `fs_read`, `fs_write`, `shell`.

```yaml
rules:
  # Close the built-in path to sensitive files -> force through Samar.
  - capability: fs_read
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  - capability: fs_write
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  # Full isolation (optional, aggressive): disable the built-in shell entirely.
  # - capability: shell
    # effect: deny
```

Also: set **Settings → Agent → Agent Autonomy = Supervised** so built-in actions
still prompt for confirmation. The MCP `disabledTools` field does NOT disable
Kiro's built-in tools — it only applies to MCP server tools.

See also the dedicated step-by-step guide: [`KIRO_SETUP.md`](./KIRO_SETUP.md).

#### Claude Code — `~/.claude/settings.json` (`permissions.deny`)

`deny` → `ask` → `allow`; `deny` is a hard gate (no prompt/override).

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)", "Read(./.env.*)", "Read(./**/*.pem)", "Read(./**/*.key)",
      "Edit(./.env)", "Write(./.env)"
    ]
  }
}
```

For full isolation, add `"Bash(*)"` to `deny` (aggressive: disables all built-in
shell; make sure `samar_execute_command` covers your execution needs).

#### Cursor — UI Settings

Cursor has no config file field to disable built-in tools. Open
**Settings → (Features/Tools / Agent)** and turn off the built-in
filesystem/terminal tools there. Verify with the "Quick verification" steps below.

> **If a client offers no adequate deny mechanism:** Samar still runs, but the
> security model drops to *best-effort + disclosure* (the server prints a warning
> to stderr). Treat it as not yet safe for production secrets until the built-in
> path to sensitive files is genuinely closed.

## Quick verification

1. Run the server; confirm the security warning appears on stderr.
2. Ask the AI to read a test `.env` file containing a fake secret.
3. Confirm the output contains a `__SAMAR_SECRET_XXXX__` token, **not** the real
   value.
4. Try asking the AI to read the same file **without** naming a Samar tool. If
   the real value appears, the built-in tool is still active → close that path.

## Egress allowlist (outbound path)

`samar_execute_command` blocks sending secrets to external hosts not on the
allowlist (PRD §5.6). The host list (one per line, `#` for comments) is read from
two locations and reloaded automatically with no restart:

- **Global:** `~/.samar/allowlist` (fallback: `~/.safeenv/allowlist`)
- **Per-project:** `.samar/allowlist` (fallback: `.safeenv/allowlist`) at the project root

### Resolution modes (§13.3)

- **Union (default):** `effective = global ∪ per-project`.
- **Strict:** set env `SAMAR_STRICT_ALLOWLIST=1`. Per-project **narrows** the
  global → `effective = global ∩ per-project`. If the project file is empty/absent,
  strict falls back to the global list as-is. Use strict for projects that may
  only contact a subset of trusted organizational hosts.
