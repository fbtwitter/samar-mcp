#!/usr/bin/env python3
"""PreToolUse guard: blocks built-in Bash commands that touch secret files (.env*, *.pem, *.key,
SSH private keys, .envrc) and tells the agent to use the Samar MCP tools instead, so values get masked.
Templates (.env.example/.sample/.template/.dist) are allowed. Fail-open on internal errors."""
import json, re, sys

END = r"""(?=$|[\s'"`;|&)<>])"""
START = r"""(?:^|[\s'"`=/(<>])"""
TEMPLATE = re.compile(r"\.env\.(?:example|sample|template|dist)" + END)
SECRET = re.compile(
    START + r"\.env(?:[\w.-]+)?" + END          # .env, .env.local, .env.production
    + r"|[\w./~-]*\.(?:pem|key)" + END          # server.pem, private.key
    + r"|\bid_(?:rsa|ed25519|ecdsa|dsa)" + END  # SSH private keys
    + r"|\.(?:envrc|npmrc|netrc|pypirc)" + END  # direnv & package/network auth configs
    + r"|\b(?:mcp_config|claude_desktop_config|mcp)\.json" + END  # MCP server configs containing tokens
    + r"|\.mcp\.json" + END
)

def main():
    d = json.load(sys.stdin)
    if d.get("tool_name") != "Bash":
        return
    cmd = (d.get("tool_input") or {}).get("command", "")
    hits = [m.group(0).strip(" '\"`=/(<>") for m in SECRET.finditer(cmd)]
    hits = [h for h in hits if not TEMPLATE.search(h)]
    if not hits:
        return
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "Secret guard: this command touches secret file(s) " + ", ".join(sorted(set(hits)))
            + ". Do not use built-in Bash for these. Use the Samar MCP tools instead: "
            "mcp__samar__samar_read_file to read, mcp__samar__samar_get_env for env vars, "
            "mcp__samar__samar_write_file to write, mcp__samar__samar_execute_command to run commands.")}}))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(0)
