package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupKiro_Idempotent(t *testing.T) {
	tmpHome := t.TempDir()
	settingsDir := filepath.Join(tmpHome, "settings")
	_ = os.MkdirAll(settingsDir, 0o755)

	// Initial mcp.json with an existing server
	initialMcp := map[string]any{
		"mcpServers": map[string]any{
			"other-tool": map[string]any{
				"command": "other",
			},
		},
	}
	mcpBytes, _ := json.Marshal(initialMcp)
	_ = os.WriteFile(filepath.Join(settingsDir, "mcp.json"), mcpBytes, 0o600)

	// Initial permissions.yaml with custom user rule
	initialPerm := "rules:\n  - capability: shell\n    effect: ask\n"
	_ = os.WriteFile(filepath.Join(settingsDir, "permissions.yaml"), []byte(initialPerm), 0o600)

	// First run
	if err := runSetupKiro(settingsDir, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupKiro run 1 failed: %v", err)
	}

	// 1. Verify mcp.json
	data, err := os.ReadFile(filepath.Join(settingsDir, "mcp.json"))
	if err != nil {
		t.Fatalf("failed reading mcp.json: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("invalid mcp.json: %v", err)
	}
	servers := root["mcpServers"].(map[string]any)
	if servers["other-tool"] == nil {
		t.Errorf("existing server 'other-tool' was lost!")
	}
	samarSrv, ok := servers["samar"].(map[string]any)
	if !ok || samarSrv["command"] != "/path/to/samar" {
		t.Errorf("samar server configuration incorrect: %v", samarSrv)
	}

	// 2. Verify permissions.yaml
	permBytes, err := os.ReadFile(filepath.Join(settingsDir, "permissions.yaml"))
	if err != nil {
		t.Fatalf("failed reading permissions.yaml: %v", err)
	}
	permStr := string(permBytes)
	if !strings.Contains(permStr, "capability: shell") {
		t.Errorf("initial user rule lost from permissions.yaml")
	}
	if !strings.Contains(permStr, "capability: fs_read") || !strings.Contains(permStr, "**/.env") {
		t.Errorf("samar fs_read deny rules not added to permissions.yaml")
	}

	// 3. Second run (Idempotency)
	if err := runSetupKiro(settingsDir, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupKiro run 2 failed: %v", err)
	}

	permBytes2, _ := os.ReadFile(filepath.Join(settingsDir, "permissions.yaml"))
	if strings.Count(string(permBytes2), "capability: fs_read") != 1 {
		t.Errorf("idempotency check failed: duplicate rules in permissions.yaml")
	}
}

func TestSetupCursor_Idempotent(t *testing.T) {
	tmpCursor := t.TempDir()

	// Initial mcp.json
	initialMcp := map[string]any{
		"mcpServers": map[string]any{
			"existing": map[string]any{"command": "existing"},
		},
	}
	mcpBytes, _ := json.Marshal(initialMcp)
	_ = os.WriteFile(filepath.Join(tmpCursor, "mcp.json"), mcpBytes, 0o600)

	// First run
	if err := runSetupCursor(tmpCursor, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupCursor run 1 failed: %v", err)
	}

	// 1. Verify mcp.json
	data, err := os.ReadFile(filepath.Join(tmpCursor, "mcp.json"))
	if err != nil {
		t.Fatalf("failed reading mcp.json: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("invalid mcp.json: %v", err)
	}
	servers := root["mcpServers"].(map[string]any)
	if servers["existing"] == nil {
		t.Errorf("existing server lost")
	}
	if servers["samar"] == nil {
		t.Errorf("samar server not registered")
	}

	// 2. Verify rules/samar.mdc
	mdcFile := filepath.Join(tmpCursor, "rules", "samar.mdc")
	mdcBytes, err := os.ReadFile(mdcFile)
	if err != nil {
		t.Fatalf("failed reading samar.mdc: %v", err)
	}
	if !strings.Contains(string(mdcBytes), "Samar MCP Security Rules") {
		t.Errorf("samar rules content missing from samar.mdc")
	}

	// 3. Second run (Idempotency)
	if err := runSetupCursor(tmpCursor, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupCursor run 2 failed: %v", err)
	}

	mdcBytes2, _ := os.ReadFile(mdcFile)
	if strings.Count(string(mdcBytes2), "Samar MCP Security Rules") != 1 {
		t.Errorf("idempotency failed: duplicated rules in samar.mdc")
	}
}

func TestSetupAntigravity_Idempotent(t *testing.T) {
	tmpGemini := t.TempDir()

	// Initial mcp_config.json
	initialMcp := map[string]any{
		"mcpServers": map[string]any{
			"confluence": map[string]any{"command": "npx"},
		},
	}
	mcpBytes, _ := json.Marshal(initialMcp)
	_ = os.WriteFile(filepath.Join(tmpGemini, "mcp_config.json"), mcpBytes, 0o600)

	// First run
	if err := runSetupAntigravity(tmpGemini, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupAntigravity run 1 failed: %v", err)
	}

	// 1. Verify mcp_config.json
	data, err := os.ReadFile(filepath.Join(tmpGemini, "mcp_config.json"))
	if err != nil {
		t.Fatalf("failed reading mcp_config.json: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("invalid mcp_config.json: %v", err)
	}
	servers := root["mcpServers"].(map[string]any)
	if servers["confluence"] == nil {
		t.Errorf("existing server 'confluence' lost")
	}
	if servers["samar"] == nil {
		t.Errorf("samar server not registered in mcp_config.json")
	}

	// 2. Verify rules/samar.md
	ruleFile := filepath.Join(tmpGemini, "rules", "samar.md")
	ruleBytes, err := os.ReadFile(ruleFile)
	if err != nil {
		t.Fatalf("failed reading rules/samar.md: %v", err)
	}
	if !strings.Contains(string(ruleBytes), "Samar MCP Privacy & Security Rules") {
		t.Errorf("samar rules content missing from rules/samar.md")
	}

	// 3. Second run (Idempotency)
	if err := runSetupAntigravity(tmpGemini, "/path/to/samar"); err != nil {
		t.Fatalf("runSetupAntigravity run 2 failed: %v", err)
	}

	ruleBytes2, _ := os.ReadFile(ruleFile)
	if strings.Count(string(ruleBytes2), "Samar MCP Privacy & Security Rules") != 1 {
		t.Errorf("idempotency failed: duplicated rules in rules/samar.md")
	}
}
