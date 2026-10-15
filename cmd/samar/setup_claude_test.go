package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupClaudeCode_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()

	// Buat settings.json awal dengan konfigurasi user yang sudah ada
	initialSettings := map[string]any{
		"theme": "dark",
		"permissions": map[string]any{
			"deny": []any{"Read(/etc/passwd)"},
		},
	}
	initialBytes, _ := json.Marshal(initialSettings)
	_ = os.WriteFile(filepath.Join(tmpDir, "settings.json"), initialBytes, 0o600)

	// Buat CLAUDE.md awal dengan instruksi user yang sudah ada
	_ = os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# My Project Instructions\n"), 0o644)

	// Jalankan setup pertama kali
	if err := runSetupClaudeCode(tmpDir, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupClaudeCode run 1 failed: %v", err)
	}

	// 1. Verifikasi guard-secrets.py terpasang
	hookPath := filepath.Join(tmpDir, "hooks", "guard-secrets.py")
	if info, err := os.Stat(hookPath); err != nil {
		t.Fatalf("hook file %s tidak ditemukan: %v", hookPath, err)
	} else if info.Size() == 0 {
		t.Fatalf("hook file %s kosong", hookPath)
	}

	// 2. Verifikasi settings.json
	settingsData, err := os.ReadFile(filepath.Join(tmpDir, "settings.json"))
	if err != nil {
		t.Fatalf("gagal membaca settings.json: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(settingsData, &settings); err != nil {
		t.Fatalf("settings.json tidak valid: %v", err)
	}

	// Cek custom user setting tetap ada
	if settings["theme"] != "dark" {
		t.Errorf("setting awal 'theme' hilang!")
	}

	// Cek permissions.deny
	permMap := settings["permissions"].(map[string]any)
	denyList := permMap["deny"].([]any)
	foundUserDeny := false
	for _, item := range denyList {
		if item == "Read(/etc/passwd)" {
			foundUserDeny = true
		}
	}
	if !foundUserDeny {
		t.Errorf("rule user 'Read(/etc/passwd)' hilang dari deny list!")
	}
	if len(denyList) != 9 { // 1 user rule + 8 default rules
		t.Errorf("panjang deny list diharapkan 9, didapat %d", len(denyList))
	}

	// Cek hooks.PreToolUse
	hooksMap := settings["hooks"].(map[string]any)
	preToolUse := hooksMap["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Errorf("panjang PreToolUse diharapkan 1, didapat %d", len(preToolUse))
	}

	// 3. Verifikasi CLAUDE.md
	claudeMdBytes, err := os.ReadFile(filepath.Join(tmpDir, "CLAUDE.md"))
	if err != nil {
		t.Fatalf("gagal membaca CLAUDE.md: %v", err)
	}
	claudeMd := string(claudeMdBytes)
	if !strings.Contains(claudeMd, "# My Project Instructions") {
		t.Errorf("konten asli CLAUDE.md hilang!")
	}
	if !strings.Contains(claudeMd, "## Secrets — use Samar MCP") {
		t.Errorf("snippet Samar tidak ditemukan di CLAUDE.md!")
	}

	// Jalankan setup kedua kali (Uji Idempotency)
	if err := runSetupClaudeCode(tmpDir, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupClaudeCode run 2 failed: %v", err)
	}

	// Pastikan denyList dan preToolUse tidak menduplikasi
	settingsData2, _ := os.ReadFile(filepath.Join(tmpDir, "settings.json"))
	var settings2 map[string]any
	_ = json.Unmarshal(settingsData2, &settings2)
	permMap2 := settings2["permissions"].(map[string]any)
	denyList2 := permMap2["deny"].([]any)
	if len(denyList2) != 9 {
		t.Errorf("idempotency check gagal: panjang deny list berubah menjadi %d", len(denyList2))
	}

	hooksMap2 := settings2["hooks"].(map[string]any)
	preToolUse2 := hooksMap2["PreToolUse"].([]any)
	if len(preToolUse2) != 1 {
		t.Errorf("idempotency check gagal: panjang PreToolUse berubah menjadi %d", len(preToolUse2))
	}

	// Pastikan snippet CLAUDE.md tidak diduplikasi
	claudeMdBytes2, _ := os.ReadFile(filepath.Join(tmpDir, "CLAUDE.md"))
	if strings.Count(string(claudeMdBytes2), "## Secrets — use Samar MCP") != 1 {
		t.Errorf("idempotency check gagal: snippet Samar diduplikasi di CLAUDE.md!")
	}
}
