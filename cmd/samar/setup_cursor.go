package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var cursorRuleMdc = strings.ReplaceAll(`---
description: Samar MCP credential protection and secret masking rules
globs: "**/*"
alwaysApply: true
---

# Samar MCP Security Rules

Any file or command dealing with credentials, tokens, or secrets MUST use the Samar MCP tools so that values are masked before they reach the model context. Never use built-in terminal or file read tools on secret files.

- Reading secrets (@.env*@, @*.pem@, @*.key@, SSH keys, credentials): use @mcp__samar__samar_read_file@.
- Reading environment variables: use @mcp__samar__samar_get_env@.
- Writing files containing tokens or secrets: use @mcp__samar__samar_write_file@.
- Running shell commands that require secrets: use @mcp__samar__samar_execute_command@.
- Templates like @.env.example@ may use standard file read tools.
`, "@", "`")

// runSetupCursor melakukan setup integrasi Samar MCP untuk Cursor IDE secara otomatis & idempoten.
func runSetupCursor(targetDir, binaryPath string) error {
	var homeDir string
	if targetDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("gagal mendapatkan user home dir: %w", err)
		}
		targetDir = filepath.Join(homeDir, ".cursor")
	} else {
		homeDir = filepath.Dir(targetDir)
	}

	binaryPath = resolveBinaryPath(binaryPath)

	fmt.Println("🚀 Menyiapkan integrasi Samar MCP untuk Cursor IDE...")
	fmt.Printf("   Lokasi konfigurasi: %s\n", targetDir)

	// 1. Update mcp.json
	mcpFile := filepath.Join(targetDir, "mcp.json")
	serverDef := map[string]any{
		"command": binaryPath,
		"args":    []any{},
		"env": map[string]any{
			"SAMAR_STRICT_ALLOWLIST": "0",
		},
	}

	if err := updateMCPServerJSON(mcpFile, "samar", serverDef); err != nil {
		return fmt.Errorf("gagal memperbarui MCP config Cursor: %w", err)
	}
	fmt.Printf("✔ Server Samar terdaftar di: %s\n", mcpFile)

	// 2. Pasang rules/samar.mdc
	rulesDir := filepath.Join(targetDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return fmt.Errorf("gagal membuat direktori rules %s: %w", rulesDir, err)
	}
	mdcFile := filepath.Join(rulesDir, "samar.mdc")
	if err := updateCursorRules(mdcFile); err != nil {
		return fmt.Errorf("gagal memperbarui rules Cursor: %w", err)
	}
	fmt.Printf("✔ Aturan agen Cursor (MDC rule) terpasang di: %s\n", mdcFile)

	// 3. Update juga .cursorrules di root home jika relevan
	cursorRulesFile := filepath.Join(homeDir, ".cursorrules")
	_ = updateCursorDotRules(cursorRulesFile)

	fmt.Println("\n🎉 Setup Cursor selesai! Samar MCP kini terdaftar dan aturan pengalihan tool rahasia aktif.")
	return nil
}

func updateCursorRules(rulesFile string) error {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(rulesFile, []byte(cursorRuleMdc), 0o644)
		}
		return err
	}

	if strings.Contains(string(data), "Samar MCP Security Rules") {
		return nil
	}

	newContent := strings.TrimRight(string(data), "\r\n") + "\n\n" + cursorRuleMdc
	return os.WriteFile(rulesFile, []byte(newContent), 0o644)
}

func updateCursorDotRules(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(file, []byte(cursorRuleMdc), 0o644)
		}
		return err
	}

	if strings.Contains(string(data), "Samar MCP Security Rules") {
		return nil
	}

	newContent := strings.TrimRight(string(data), "\r\n") + "\n\n" + cursorRuleMdc
	return os.WriteFile(file, []byte(newContent), 0o644)
}
