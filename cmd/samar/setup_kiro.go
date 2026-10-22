package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var kiroPermissionsYaml = `# Force sensitive-file I/O through Samar's tools by denying Kiro's built-in
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
      - "**/mcp_config.json"
      - "**/.npmrc"
      - "**/.netrc"
      - "secrets/**"

  - capability: fs_write
    effect: deny
    match:
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "secrets/**"
`

var kiroSteeringSnippet = strings.ReplaceAll(`
# Samar MCP Credential Protection Rules

Any file or environment variable containing credentials, secrets, or API keys must be handled strictly via Samar MCP tools to ensure tokens are masked before reaching the model context:

- Reading secrets (@.env*@, @*.pem@, @*.key@, SSH keys, @mcp_config.json@, @mcp.json@, @.npmrc@, @.netrc@, credentials): use @samar_read_file@.
- Reading environment variables: use @samar_get_env@.
- Writing files containing secrets or tokens: use @samar_write_file@.
- Running commands requiring secrets: use @samar_execute_command@.
- Templates such as @.env.example@ may use standard file tools.
`, "@", "`")

// runSetupKiro melakukan setup integrasi Samar MCP untuk Kiro IDE secara otomatis & idempoten.
func runSetupKiro(targetDir, binaryPath string) error {
	var homeDir string
	if targetDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("gagal mendapatkan user home dir: %w", err)
		}
		targetDir = filepath.Join(homeDir, ".kiro", "settings")
	} else {
		homeDir = filepath.Dir(targetDir)
	}

	binaryPath = resolveBinaryPath(binaryPath)

	fmt.Println("🚀 Menyiapkan integrasi Samar MCP untuk Kiro IDE...")
	fmt.Printf("   Lokasi konfigurasi: %s\n", targetDir)

	// 1. Update mcp.json
	mcpFile := filepath.Join(targetDir, "mcp.json")
	serverDef := map[string]any{
		"command": binaryPath,
		"args":    []any{},
		"env": map[string]any{
			"SAMAR_STRICT_ALLOWLIST": "0",
		},
		"disabled":    false,
		"autoApprove": []any{"samar_read_file", "samar_get_env"},
	}

	if err := updateMCPServerJSON(mcpFile, "samar", serverDef); err != nil {
		return fmt.Errorf("gagal memperbarui MCP config Kiro: %w", err)
	}
	fmt.Printf("✔ Server Samar terdaftar di: %s\n", mcpFile)

	// 2. Pasang permissions.yaml deny rules
	permFile := filepath.Join(targetDir, "permissions.yaml")
	if err := updateKiroPermissions(permFile); err != nil {
		return fmt.Errorf("gagal memperbarui permissions Kiro: %w", err)
	}
	fmt.Printf("✔ Deny rules (fs_read/fs_write) terpasang di: %s\n", permFile)

	// 3. Pasang steering rule
	steeringDir := filepath.Join(homeDir, "steering")
	if err := os.MkdirAll(steeringDir, 0o755); err != nil {
		return fmt.Errorf("gagal membuat direktori steering %s: %w", steeringDir, err)
	}
	steeringFile := filepath.Join(steeringDir, "samar.md")
	if err := updateKiroSteering(steeringFile); err != nil {
		return fmt.Errorf("gagal memperbarui steering rule Kiro: %w", err)
	}
	fmt.Printf("✔ Instruksi agen Kiro ditambahkan ke: %s\n", steeringFile)

	fmt.Println("\n🎉 Setup Kiro selesai! File rahasia (.env, *.pem, *.key) kini terlindungi oleh deny rules & diarahkan ke Samar MCP.")
	return nil
}

func updateKiroPermissions(permFile string) error {
	data, err := os.ReadFile(permFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(permFile, []byte(kiroPermissionsYaml), 0o600)
		}
		return err
	}

	content := string(data)
	if strings.Contains(content, "**/.env") && strings.Contains(content, "capability: fs_read") {
		// Sudah ada aturan deny samar
		return nil
	}

	// Backup
	bakFile := fmt.Sprintf("%s.bak.%d", permFile, time.Now().Unix())
	_ = os.WriteFile(bakFile, data, 0o600)

	newContent := strings.TrimRight(content, "\r\n") + "\n\n" + kiroPermissionsYaml
	return os.WriteFile(permFile, []byte(newContent), 0o600)
}

func updateKiroSteering(steeringFile string) error {
	data, err := os.ReadFile(steeringFile)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(steeringFile, []byte(strings.TrimSpace(kiroSteeringSnippet)+"\n"), 0o644)
		}
		return err
	}

	if strings.Contains(string(data), "Samar MCP Credential Protection Rules") {
		return nil
	}

	newContent := strings.TrimRight(string(data), "\r\n") + "\n" + kiroSteeringSnippet
	return os.WriteFile(steeringFile, []byte(newContent), 0o644)
}
