## Secrets — use Samar MCP

Any file or value that may contain secrets must go through the Samar MCP tools so values are masked before they reach the context. Never use built-in Read/Bash/Grep for these.

- Reading `.env*`, `*.pem`, `*.key`, SSH keys, or config/credential files: use `mcp__samar__samar_read_file`.
- Environment variables: use `mcp__samar__samar_get_env`, not `env`/`printenv`/`echo $VAR`.
- Writing files that contain `__SAMAR_SECRET_*__` tokens or secrets: use `mcp__samar__samar_write_file`.
- Shell commands that read or use secrets (`source .env`, scripts that need keys): use `mcp__samar__samar_execute_command`.
- Templates such as `.env.example` are fine with the built-in tools.
- This also applies to subagents: pass these rules to any agent you spawn.
