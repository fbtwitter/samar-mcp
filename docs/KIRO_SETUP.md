# Samar Setup Guide for Kiro IDE

**English** | [Bahasa Indonesia](./KIRO_SETUP.id.md)

A step-by-step guide to installing the Samar MCP Server in **Kiro IDE** so your
credentials are actually protected. For the cross-client overview see
[`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md); this document is Kiro-specific and concrete.

> **Keep the principle in mind:** registering the MCP server alone is **not
> enough**. Samar only masks I/O that **passes through its tools**. As long as
> Kiro's built-in tools (`fs_read`/`fs_write`) can read sensitive files directly,
> secrets leak unmasked. Step **2** (the deny rule) is what makes this protection
> real — it is not optional.

---

## Overview: 3 steps

| # | Step | Who | Status |
| :-- | :-- | :-- | :-- |
| 1 | Register the Samar server in `mcp.json` | Can be done by the agent | Required |
| 2 | Create `permissions.yaml` (deny built-in tools on sensitive files) | **Manual (you)** | **Required** |
| 3 | Set up the egress allowlist | Can be done by the agent | Optional (outbound) |

Step 2 must be manual: Kiro deliberately **forbids the AI agent from writing its
own permission files** (`~/.kiro/settings/` and `~/.kiro/workspace-roots/`). This
is the right guardrail — an agent must not be able to rewrite its own permission
boundaries.

---

## Prerequisites

Prepare the `samar` binary. Pick one:

- **Use the existing Windows release:**
  ```powershell
  Copy-Item .\dist\safeenv-windows-amd64.exe .\dist\samar.exe -Force
  .\dist\samar.exe --version   # should print a version, e.g. "samar 1.2.0"
  ```
- **Build from source:**
  ```powershell
  go build -o dist\samar.exe .\cmd\samar
  ```

Note the **absolute path** of the binary (e.g. `C:\MyProject\safeenv-mcp-server\dist\samar.exe`).

---

## Step 1 — Register the MCP server

Choose a scope:

- **Workspace** (active only when this project is open):
  `<project>\.kiro\settings\mcp.json`
- **User/global** (active across all workspaces):
  `~\.kiro\settings\mcp.json`

Contents (replace the `command` path with your absolute binary path; use `\\` in JSON):

```json
{
  "mcpServers": {
    "samar": {
      "command": "C:\\MyProject\\safeenv-mcp-server\\dist\\samar.exe",
      "args": [],
      "env": {
        "SAMAR_STRICT_ALLOWLIST": "0"
      },
      "disabled": false,
      "autoApprove": ["samar_read_file", "samar_get_env"]
    }
  }
}
```

> Kiro env expansion uses the `${VAR}` syntax (not `${env:VAR}`).
> `autoApprove` is limited to the **read** tools (safe); write/exec tools still
> prompt for confirmation. The MCP config's `disabledTools` does **not** disable
> Kiro's built-in tools — that's what Step 2 is for.

After saving, reconnect the server from the **MCP Server** panel in Kiro (or
restart Kiro). You should see `samar` connect with its 4 tools:
`samar_read_file`, `samar_get_env`, `samar_write_file`, `samar_execute_command`.

---

## Step 2 — Deny built-in tools on sensitive files (REQUIRED, manual)

Create a `permissions.yaml` file. Locations (both are **outside** the repo, per-user):

- **Global (recommended, protects every project):**
  `C:\Users\<you>\.kiro\settings\permissions.yaml`
- **Workspace only:**
  `C:\Users\<you>\.kiro\workspace-roots\<hash>\permissions.yaml`
  (Kiro generates `<hash>` automatically; easiest route is the "UI alternative" below.)

File contents:

```yaml
# Force sensitive-file I/O through Samar's tools by denying Kiro's built-in
# fs_read/fs_write on secret-bearing paths.
# Evaluation is deny-overrides: deny always wins over allow/ask.
rules:
  - capability: fs_read
    effect: deny
    match:
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "secrets/**"

  - capability: fs_write
    effect: deny
    match:
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "secrets/**"
```

How to create it (from a terminal OUTSIDE the Kiro agent, or any plain editor):

```powershell
notepad "$env:USERPROFILE\.kiro\settings\permissions.yaml"
```

**Glob note:** use the `**/` prefix so patterns match at any folder depth.
Patterns like `*.env` only match within a single path component.
`permissions.yaml` **adds to** Kiro's defaults — it does not replace them.

### UI alternative (easiest for workspace scope)

When the agent tries to read a `.env`, Kiro shows a permission prompt. Pick
**Deny → This workspace**. Kiro writes the rule into
`workspace-roots/<hash>/permissions.yaml` for you — no manual `<hash>` lookup.

### Full isolation (optional, aggressive)

If the agent should only do I/O through Samar, also deny the built-in `shell`
capability and route execution through `samar_execute_command`. Be careful: this
can cripple the agent's ability to run ordinary commands.

---

## Step 3 — Egress allowlist (outbound)

`samar_execute_command` blocks sending unmasked secrets to hosts not on the
allowlist (fail-closed). One host per line, `#` for comments, hot-reloaded every
~5 seconds with no restart.

- **Global:** `~\.samar\allowlist` (fallback: `~\.safeenv\allowlist`)
- **Per-project:** `.\.samar\allowlist` (fallback: `.\.safeenv\allowlist`)

Example `.\.samar\allowlist`:

```text
# Only hosts listed here may receive secrets via samar_execute_command.
# api.internal.example.com
# registry.corp.local
```

Resolution mode: **union** (default, `global ∪ project`) or **strict**
(`SAMAR_STRICT_ALLOWLIST=1`, `global ∩ project`).

---

## Verification

1. Reconnect/restart; confirm `samar` appears with its 4 tools, and that the
   security warning prints to stderr on server start.
2. Create a test `.env` with a fake secret, e.g. `API_KEY=sk-test-123456`.
3. Ask the agent to read it **via Samar** → output should be
   `__SAMAR_SECRET_...__`, not the real value.
4. Ask the agent to read the same file **normally** (built-in tool) → it should
   be **denied** by the deny rule. If the raw value shows up, Step 2 isn't active yet.

For a more thorough bypass test, see [`BYPASS_TEST.md`](./BYPASS_TEST.md).

---

## Troubleshooting

| Symptom | Cause & fix |
| :-- | :-- |
| `samar` doesn't appear in the tool list | Wrong `command` path / binary missing. Check with `samar.exe --version`. Reconnect the server. |
| AI still reads raw secrets from `.env` | Step 2 is missing / the glob doesn't match. Ensure `permissions.yaml` exists in `~/.kiro/settings/` and uses the `**/` prefix. |
| Agent can't write `permissions.yaml` | Intentional — Kiro forbids the agent from writing its permission files. Create it manually via a plain editor/terminal. |
| Network commands keep getting blocked | The target host isn't on the allowlist. Add it to `.samar/allowlist`. |
| Human-in-the-loop confirmation never appears | Set `SAMAR_REQUIRE_CONFIRM=elicit` (requires a client that supports MCP elicitation). |
