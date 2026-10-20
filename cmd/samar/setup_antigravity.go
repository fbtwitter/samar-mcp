package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var antigravityRuleMd = strings.ReplaceAll(`
# Samar MCP Privacy & Security Rules

Any file or command dealing with credentials, tokens, or secrets MUST use the Samar MCP tools so that values are masked before they reach the model context.

- Reading secrets (@.env*@, @*.pem@, @*.key@, SSH keys, credentials): use @samar_read_file@ (or @mcp_samar_samar_read_file@).
- Reading environment variables: use @samar_get_env@ (or @mcp_samar_samar_get_env@).
- Writing files containing tokens or secrets: use @samar_write_file@ (or @mcp_samar_samar_write_file@).
- Running shell commands that require secrets: use @samar_execute_command@ (or @mcp_samar_samar_execute_command@).
- Templates like @.env.example@ may use standard file read tools.
`, "@", "`")

// runSetupAntigravity melakukan setup integrasi Samar MCP untuk Google Antigravity / Gemini CLI secara otomatis & idempoten.
func runSetupAntigravity(targetDir, binaryPath string) error {
	if targetDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("gagal mendapatkan user home dir: %w", err)
		}
		targetDir = filepath.Join(home, ".gemini", "config")
	}

	binaryPath = resolveBinaryPath(binaryPath)

	fmt.Println("🚀 Menyiapkan integrasi Samar MCP untuk Google Antigravity (Gemini)...")
	fmt.Printf("   Lokasi konfigurasi: %s\n", targetDir)

	// 1. Update mcp_config.json
	mcpFile := filepath.Join(targetDir, "mcp_config.json")
	serverDef := map[string]any{
		"command": binaryPath,
		"args":    []any{},
		"env": map[string]any{
			"SAMAR_STRICT_ALLOWLIST": "0",
		},
	}

	if err := updateMCPServerJSON(mcpFile, "samar", serverDef); err != nil {
		return fmt.Errorf("gagal memperbarui mcp_config.json Antigravity: %w", err)
	}
	fmt.Printf("✔ Server Samar terdaftar di: %s\n", mcpFile)

	// 2. Pasang rules/samar.md
	rulesDir := filepath.Join(targetDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return fmt.Errorf("gagal membuat direktori rules %s: %w", rulesDir, err)
	}
	rulesFile := filepath.Join(rulesDir, "samar.md")
	if err := updateAntigravityRules(rulesFile); err != nil {
		return fmt.Errorf("gagal memperbarui rules Antigravity: %w", err)
	}
	fmt.Printf("✔ Aturan agen Antigravity terpasang di: %s\n", rulesFile)

	fmt.Println("\n🎉 Setup Antigravity selesai! Samar MCP kini aktif di mcp_config.json dan aturan privasi terpasang.")
	return nil
}

func updateAntigravityRules(rulesFile string) error {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(rulesFile, []byte(strings.TrimSpace(antigravityRuleMd)+"\n"), 0o644)
		}
		return err
	}

	if strings.Contains(string(data), "Samar MCP Privacy & Security Rules") {
		return nil
	}

	newContent := strings.TrimRight(string(data), "\r\n") + "\n" + antigravityRuleMd
	return os.WriteFile(rulesFile, []byte(newContent), 0o644)
}
