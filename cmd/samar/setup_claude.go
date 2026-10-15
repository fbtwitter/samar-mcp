package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var guardSecretsPy = strings.ReplaceAll(`#!/usr/bin/env python3
"""PreToolUse guard: blocks built-in Bash commands that touch secret files (.env*, *.pem, *.key,
SSH private keys, .envrc) and tells the agent to use the Samar MCP tools instead, so values get masked.
Templates (.env.example/.sample/.template/.dist) are allowed. Fail-open on internal errors."""
import json, re, sys

END = r"""(?=$|[\s'"@;|)<>])"""
START = r"""(?:^|[\s'"@=/(<>])"""
TEMPLATE = re.compile(r"\.env\.(?:example|sample|template|dist)" + END)
SECRET = re.compile(
    START + r"\.env(?:[\w.-]+)?" + END          # .env, .env.local, .env.production
    + r"|[\w./~-]*\.(?:pem|key)" + END          # server.pem, private.key
    + r"|\bid_(?:rsa|ed25519|ecdsa|dsa)" + END  # SSH private keys
    + r"|\.envrc" + END                          # direnv config
)

def main():
    d = json.load(sys.stdin)
    if d.get("tool_name") != "Bash":
        return
    cmd = (d.get("tool_input") or {}).get("command", "")
    hits = [m.group(0).strip(" '\"@=/(<>") for m in SECRET.finditer(cmd)]
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
`, "@", "`")

var claudeMdSnippet = strings.ReplaceAll(`
## Secrets — use Samar MCP

Any file or value that may contain secrets must go through the Samar MCP tools so values are masked before they reach the context. Never use built-in Read/Bash/Grep for these.

- Reading @.env*@, @*.pem@, @*.key@, SSH keys, or config/credential files: use @mcp__samar__samar_read_file@.
- Environment variables: use @mcp__samar__samar_get_env@, not @env@/@printenv@/@echo $VAR@.
- Writing files that contain @__SAMAR_SECRET_*__@ tokens or secrets: use @mcp__samar__samar_write_file@.
- Shell commands that read or use secrets (@source .env@, scripts that need keys): use @mcp__samar__samar_execute_command@.
- Templates such as @.env.example@ are fine with the built-in tools.
- This also applies to subagents: pass these rules to any agent you spawn.
`, "@", "`")

var defaultDenyRules = []string{
	"Read(**/.env)",
	"Read(**/.env.*)",
	"Read(**/*.pem)",
	"Read(**/*.key)",
	"Edit(**/.env)",
	"Edit(**/.env.*)",
	"Write(**/.env)",
	"Write(**/.env.*)",
}

// runSetupClaudeCode melakukan setup otomatis Claude Code secara idempoten.
func runSetupClaudeCode(targetDir string, binaryPath string) error {
	if targetDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("gagal mendapatkan user home dir: %w", err)
		}
		targetDir = filepath.Join(home, ".claude")
	}

	if binaryPath == "" {
		exe, err := os.Executable()
		if err == nil {
			binaryPath = exe
		} else {
			binaryPath = "samar"
		}
	}

	fmt.Println("🚀 Menyiapkan integrasi Samar MCP untuk Claude Code...")
	fmt.Printf("   Lokasi konfigurasi: %s\n", targetDir)

	// 1. Buat direktori hooks
	hooksDir := filepath.Join(targetDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("gagal membuat direktori %s: %w", hooksDir, err)
	}

	// 2. Tulis hook guard-secrets.py
	hookFile := filepath.Join(hooksDir, "guard-secrets.py")
	if err := os.WriteFile(hookFile, []byte(guardSecretsPy), 0o755); err != nil {
		return fmt.Errorf("gagal menulis hook %s: %w", hookFile, err)
	}
	fmt.Printf("✔ Hook PreToolUse guard terpasang: %s\n", hookFile)

	// 3. Update settings.json (dengan backup)
	settingsFile := filepath.Join(targetDir, "settings.json")
	if err := updateClaudeSettings(settingsFile, hookFile); err != nil {
		return fmt.Errorf("gagal memperbarui %s: %w", settingsFile, err)
	}
	fmt.Printf("✔ Deny rules & hook terdaftar di: %s\n", settingsFile)

	// 4. Update CLAUDE.md
	claudeMdFile := filepath.Join(targetDir, "CLAUDE.md")
	if err := updateClaudeMd(claudeMdFile); err != nil {
		return fmt.Errorf("gagal memperbarui %s: %w", claudeMdFile, err)
	}
	fmt.Printf("✔ Instruksi perutean agen ditambahkan ke: %s\n", claudeMdFile)

	// 5. Registrasi MCP server via CLI jika ada
	if _, err := exec.LookPath("claude"); err == nil {
		checkCmd := exec.Command("claude", "mcp", "get", "samar")
		if err := checkCmd.Run(); err == nil {
			fmt.Println("✔ Samar MCP server sudah terdaftar di Claude Code (Status: Connected).")
		} else {
			fmt.Println("⏳ Mendaftarkan Samar MCP server ke Claude Code via CLI...")
			addCmd := exec.Command("claude", "mcp", "add", "--scope", "user", "samar", "-e", "SAMAR_STRICT_ALLOWLIST=0", "--", binaryPath)
			if out, err := addCmd.CombinedOutput(); err != nil {
				fmt.Printf("⚠ Gagal menjalankan 'claude mcp add': %v\n  Output: %s\n", err, out)
				fmt.Printf("  Silakan jalankan manual: claude mcp add --scope user samar -e SAMAR_STRICT_ALLOWLIST=0 -- %s\n", binaryPath)
			} else {
				fmt.Println("✔ Berhasil mendaftarkan Samar MCP server ke Claude Code!")
			}
		}
	} else {
		fmt.Println("ℹ Perintah 'claude' tidak ditemukan di PATH.")
		fmt.Printf("  Jalankan perintah berikut saat Claude CLI terpasang:\n    claude mcp add --scope user samar -e SAMAR_STRICT_ALLOWLIST=0 -- %s\n", binaryPath)
	}

	fmt.Println("\n🎉 Setup Claude Code selesai! Semua pembacaan file sensitif (.env, *.pem, *.key) kini otomatis diarahkan ke Samar MCP.")
	return nil
}

func updateClaudeSettings(settingsFile, hookFile string) error {
	settings := make(map[string]any)

	if data, err := os.ReadFile(settingsFile); err == nil {
		// Buat backup sebelum modifikasi
		bakFile := fmt.Sprintf("%s.bak.%d", settingsFile, time.Now().Unix())
		_ = os.WriteFile(bakFile, data, 0o600)

		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("format JSON rusak pada %s: %w", settingsFile, err)
		}
	}

	// 1. Merge permissions.deny
	permMap, ok := settings["permissions"].(map[string]any)
	if !ok {
		permMap = make(map[string]any)
		settings["permissions"] = permMap
	}

	existingDeny, ok := permMap["deny"].([]any)
	if !ok {
		existingDeny = []any{}
	}

	seen := make(map[string]bool)
	for _, item := range existingDeny {
		if s, ok := item.(string); ok {
			seen[s] = true
		}
	}

	for _, rule := range defaultDenyRules {
		if !seen[rule] {
			existingDeny = append(existingDeny, rule)
			seen[rule] = true
		}
	}
	permMap["deny"] = existingDeny

	// 2. Merge hooks.PreToolUse
	hooksMap, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooksMap = make(map[string]any)
		settings["hooks"] = hooksMap
	}

	preToolUse, ok := hooksMap["PreToolUse"].([]any)
	if !ok {
		preToolUse = []any{}
	}

	hookPathSlash := filepath.ToSlash(hookFile)
	hasGuardHook := false

	for _, h := range preToolUse {
		if hm, ok := h.(map[string]any); ok {
			if hm["matcher"] == "Bash" {
				if innerList, ok := hm["hooks"].([]any); ok {
					for _, in := range innerList {
						if inm, ok := in.(map[string]any); ok {
							if cmd, ok := inm["command"].(string); ok && strings.Contains(cmd, "guard-secrets.py") {
								hasGuardHook = true
								break
							}
						}
					}
				}
			}
		}
	}

	if !hasGuardHook {
		newHook := map[string]any{
			"matcher": "Bash",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": "python3 " + hookPathSlash,
					"timeout": 10,
				},
			},
		}
		preToolUse = append(preToolUse, newHook)
		hooksMap["PreToolUse"] = preToolUse
	}

	formatted, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("gagal merapikan JSON: %w", err)
	}

	return os.WriteFile(settingsFile, append(formatted, '\n'), 0o600)
}

func updateClaudeMd(claudeMdFile string) error {
	existing := ""
	if data, err := os.ReadFile(claudeMdFile); err == nil {
		existing = string(data)
	}

	if strings.Contains(existing, "## Secrets — use Samar MCP") {
		return nil // Sudah ada, jangan duplikasi
	}

	var content strings.Builder
	if len(strings.TrimSpace(existing)) > 0 {
		content.WriteString(strings.TrimRight(existing, "\r\n"))
		content.WriteString("\n\n")
	}
	content.WriteString(strings.TrimSpace(claudeMdSnippet))
	content.WriteString("\n")

	return os.WriteFile(claudeMdFile, []byte(content.String()), 0o644)
}
